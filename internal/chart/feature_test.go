package chart_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"text/template"

	"go.yaml.in/yaml/v3"
)

func TestFeatureComputesRuntimeIdentityFromEnvironment(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(chartDir, "Feature.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var feature struct {
		Values map[string]struct {
			Config   *struct{}
			Computed struct{ Template string }
		}
	}
	if err := yaml.Unmarshal(data, &feature); err != nil {
		t.Fatal(err)
	}
	identity, ok := feature.Values["serviceAccountEmail"]
	if !ok || identity.Computed.Template == "" {
		t.Fatal("runtime identity must be computed from the provisioned Fasit environment")
	}
	if identity.Config != nil {
		t.Fatal("runtime identity must not require manual Fasit configuration")
	}
	tmpl, err := template.New("serviceAccountEmail").Funcs(template.FuncMap{
		"quote": strconv.Quote,
	}).Option("missingkey=error").Parse(identity.Computed.Template)
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"dev-management", "prod-management"} {
		t.Run(project, func(t *testing.T) {
			email := "v0s-sa@" + project + ".iam.gserviceaccount.com"
			var value bytes.Buffer
			if err := tmpl.Execute(&value, struct{ Env map[string]string }{
				Env: map[string]string{"v0s_serviceaccount_email": email},
			}); err != nil {
				t.Fatal(err)
			}
			var computed string
			if err := yaml.Unmarshal(value.Bytes(), &computed); err != nil {
				t.Fatal(err)
			}
			resources := render(t, chartDir, "--set-string", "serviceAccountEmail="+computed)
			var account struct {
				Metadata struct{ Annotations map[string]string }
			}
			decode(t, resources["ServiceAccount"], &account)
			if got := account.Metadata.Annotations["iam.gke.io/gcp-service-account"]; got != email {
				t.Fatalf("expected the environment's runtime identity %q, got %q", email, got)
			}
		})
	}
}
