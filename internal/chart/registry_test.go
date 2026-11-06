package chart_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestChartPushReusesDockerRegistryLogin(t *testing.T) {
	t.Parallel()
	var authenticated atomic.Bool
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "oauth2accesstoken" || password != "test-token" {
			w.Header().Set("WWW-Authenticate", `Basic realm="chart-test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated.Store(true)
		// Prove authentication without implementing an OCI registry or storing artifacts.
		w.WriteHeader(http.StatusForbidden)
	}))
	defer registry.Close()

	dir := t.TempDir()
	const version = "0.1.0-auth-test"
	helm(t, "package", chartDir, "--version", version, "--app-version", version, "--destination", dir)
	host := strings.TrimPrefix(registry.URL, "http://")
	config := map[string]any{
		"auths": map[string]any{
			host: map[string]string{
				"auth": base64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:test-token")),
			},
		},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "docker-config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), "helm", "push", filepath.Join(dir, "v0s-"+version+".tgz"),
		"oci://"+host+"/feature", "--plain-http", "--registry-config", configPath).CombinedOutput()
	if err == nil {
		t.Fatal("test registry must reject artifact uploads")
	}
	if !authenticated.Load() {
		t.Fatalf("Helm did not use Docker's registry credentials: %v\n%s", err, out)
	}
}
