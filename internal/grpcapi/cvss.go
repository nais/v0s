package grpcapi

import (
	"cmp"
	"slices"
	"strings"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/v0s"
	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

func cvssToProto(scores map[string]v0s.CVSS) []*v0sv1.Cvss {
	var out []*v0sv1.Cvss
	for source, c := range scores {
		version := "3.x"
		switch {
		case strings.HasPrefix(c.V3Vector, "CVSS:3.0/"):
			version = "3.0"
		case strings.HasPrefix(c.V3Vector, "CVSS:3.1/"):
			version = "3.1"
		}
		if entry := cvssEntry(source, version, c.V3Vector, c.V3Score); entry != nil {
			out = append(out, entry)
		}
		if entry := cvssEntry(source, "4.0", c.V40Vector, c.V40Score); entry != nil {
			out = append(out, entry)
		}
	}
	slices.SortFunc(out, func(a, b *v0sv1.Cvss) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Version, b.Version))
	})
	return out
}

func cvssEntry(source, version, vector string, score float64) *v0sv1.Cvss {
	if vector == "" && score == 0 {
		return nil
	}
	entry := &v0sv1.Cvss{Source: source, Version: version}
	if vector != "" {
		entry.Vector = &vector
	}
	if score > 0 && score <= 10 || score == 0 && zeroScoreVector(vector) {
		entry.Score = &score
	}
	return entry
}

// Trivy and older stored records use 0 for missing scores. Only a valid
// zero-impact vector establishes that a stored zero is a genuine score.
func zeroScoreVector(vector string) bool {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := cvss30.ParseVector(vector)
		return err == nil && v.BaseScore() == 0
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := cvss31.ParseVector(vector)
		return err == nil && v.BaseScore() == 0
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := cvss40.ParseVector(vector)
		return err == nil && v.Score() == 0
	default:
		return false
	}
}
