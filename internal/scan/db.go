package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	// dbMediaType is the media type of the single layer in a trivy-db artifact.
	dbMediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"

	// Entries in dir: complete DBs are named dbPrefix plus the artifact digest,
	// downloads in progress start with tmpPrefix.
	dbPrefix  = "db-"
	tmpPrefix = "tmp-"
)

// New loads the newest DB in dir that opens, and removes the other DBs and unfinished
// downloads. repos are OCI refs for trivy-db, tried in order, e.g.
// "mirror.gcr.io/aquasec/trivy-db:2", "ghcr.io/aquasecurity/trivy-db:2".
//
// Trivy logs through slog.Default, and until slog.SetDefault is called its default
// handler buffers every record in memory. Call slog.SetDefault before using a Scanner.
func New(dir string, repos []string, log *slog.Logger) (*Scanner, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating DB directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading DB directory: %w", err)
	}

	s := &Scanner{dir: dir, repos: repos, log: log}
	type candidate struct {
		path string
		meta metadata.Metadata
	}
	var candidates []candidate
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		switch {
		case strings.HasPrefix(e.Name(), tmpPrefix):
			s.remove(path)
		case strings.HasPrefix(e.Name(), dbPrefix):
			meta, err := readMetadata(path)
			if err != nil {
				log.With("path", path, "err", err).Warn("removing invalid vulnerability DB")
				s.remove(path)
				continue
			}
			candidates = append(candidates, candidate{path, meta})
		}
	}
	// Newest first. Older DBs are only removed once a newer one has opened.
	slices.SortFunc(candidates, func(a, b candidate) int { return b.meta.UpdatedAt.Compare(a.meta.UpdatedAt) })
	for i, c := range candidates {
		if err := db.Init(c.path); err != nil {
			log.With("path", c.path, "err", err).Warn("removing vulnerability DB that fails to open")
			s.remove(c.path)
			continue
		}
		for _, older := range candidates[i+1:] {
			s.remove(older.path)
		}
		s.current, s.version = c.path, c.meta.UpdatedAt
		s.digest = strings.Replace(strings.TrimPrefix(filepath.Base(c.path), dbPrefix), "-", ":", 1)
		log.With("db_version", s.version, "digest", s.digest).Info("loaded vulnerability DB")
		break
	}
	return s, nil
}

// Update downloads a newer DB if the registry has one and swaps it in atomically. If the
// download or validation fails, the loaded DB stays in use. Returns whether it swapped.
//
// Repositories are tried in order until one succeeds. A DB is only swapped in if it is
// newer than the loaded one, so a lagging mirror never rolls the DB back.
func (s *Scanner) Update(ctx context.Context) (bool, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	var errs []error
	for _, repo := range s.repos {
		swapped, err := s.updateFrom(ctx, repo)
		if err == nil {
			return swapped, nil
		}
		s.log.With("repo", repo, "err", err).Warn("updating vulnerability DB")
		errs = append(errs, fmt.Errorf("%s: %w", repo, err))
	}
	return false, errors.Join(errs...)
}

// updateFrom downloads the DB from repo if its digest is new, and swaps it in if it is newer.
// The caller must hold s.updateMu.
func (s *Scanner) updateFrom(ctx context.Context, repo string) (bool, error) {
	art := oci.NewArtifact(repo, ftypes.RegistryOptions{})
	digest, err := art.Digest(ctx)
	if err != nil {
		return false, fmt.Errorf("resolving digest: %w", err)
	}
	if digest == s.digest {
		return false, nil
	}

	tmp, err := os.MkdirTemp(s.dir, tmpPrefix)
	if err != nil {
		return false, fmt.Errorf("creating download directory: %w", err)
	}
	defer s.remove(tmp) // no-op after the rename below

	if err := art.Download(ctx, tmp, oci.DownloadOption{MediaType: dbMediaType, Quiet: true}); err != nil {
		return false, fmt.Errorf("downloading: %w", err)
	}
	meta, err := readMetadata(tmp)
	if err != nil {
		return false, fmt.Errorf("validating download: %w", err)
	}

	log := s.log.With("repo", repo, "digest", digest, "db_version", meta.UpdatedAt)
	if !meta.UpdatedAt.After(s.DBVersion()) {
		log.Info("registry vulnerability DB is not newer than the loaded one")
		s.digest = digest
		return false, nil
	}

	dst := filepath.Join(s.dir, dbPrefix+strings.ReplaceAll(digest, ":", "-"))
	if err := os.Rename(tmp, dst); err != nil {
		return false, fmt.Errorf("moving download into place: %w", err)
	}
	if err := s.swap(dst, meta.UpdatedAt); err != nil {
		s.remove(dst)
		return false, err
	}
	s.digest = digest
	log.Info("swapped in new vulnerability DB")
	return true, nil
}

// swap closes the loaded DB and opens the one in dir. If dir fails to open, the
// previous DB is reopened. The previous DB's directory is removed after a successful swap.
func (s *Scanner) swap(dir string, version time.Time) error {
	s.mu.Lock()
	old := s.current
	if err := db.Close(); err != nil {
		s.log.With("err", err).Warn("closing vulnerability DB")
	}
	if err := db.Init(dir); err != nil {
		if old != "" {
			if rerr := db.Init(old); rerr != nil {
				s.log.With("path", old, "err", rerr).Error("reopening previous vulnerability DB")
				s.current, s.version = "", time.Time{}
			}
		}
		s.mu.Unlock()
		return fmt.Errorf("opening new DB: %w", err)
	}
	s.current, s.version = dir, version
	s.mu.Unlock()

	if old != "" {
		s.remove(old)
	}
	return nil
}

// readMetadata validates the DB in dir and returns its metadata.
func readMetadata(dir string) (metadata.Metadata, error) {
	meta, err := metadata.NewClient(dir).Get()
	if err != nil {
		return metadata.Metadata{}, fmt.Errorf("reading metadata: %w", err)
	}
	if meta.Version != trivydb.SchemaVersion {
		return metadata.Metadata{}, fmt.Errorf("unsupported schema version %d, want %d", meta.Version, trivydb.SchemaVersion)
	}
	if meta.UpdatedAt.IsZero() {
		return metadata.Metadata{}, errors.New("metadata has no UpdatedAt")
	}
	if _, err := os.Stat(trivydb.Path(dir)); err != nil {
		return metadata.Metadata{}, fmt.Errorf("checking DB file: %w", err)
	}
	return meta, nil
}

func (s *Scanner) remove(path string) {
	if err := os.RemoveAll(path); err != nil {
		s.log.With("path", path, "err", err).Warn("removing vulnerability DB directory")
	}
}
