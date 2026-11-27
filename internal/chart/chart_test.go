package chart_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const chartDir = "../../charts"

type containerSpec struct {
	Name, Image string
	Args        []string
	Env         []struct {
		Name, Value string
		ValueFrom   struct {
			SecretKeyRef struct{ Name, Key string } `yaml:"secretKeyRef"`
		} `yaml:"valueFrom"`
	}
	SecurityContext map[string]any `yaml:"securityContext"`
	VolumeMounts    []struct {
		MountPath string `yaml:"mountPath"`
	} `yaml:"volumeMounts"`
}

func databaseSecret(container containerSpec) string {
	for _, env := range container.Env {
		if env.Name == "DATABASE_URL" && env.ValueFrom.SecretKeyRef.Key == "uri" {
			return env.ValueFrom.SecretKeyRef.Name
		}
	}
	return ""
}

func helm(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm %v: %v\n%s\nRun mise install to install Helm.", args, err, out)
	}
	return out
}

func render(t *testing.T, chart string, overrides ...string) map[string]yaml.Node {
	t.Helper()
	args := []string{"template", "v0s-test", chart, "--namespace", "trusted-system", "-f", filepath.Join(chartDir, "ci/test-values.yaml")}
	args = append(args, overrides...)
	out := helm(t, args...)
	resources := make(map[string]yaml.Node)
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); errors.Is(err, io.EOF) {
			return resources
		} else if err != nil {
			t.Fatal(err)
		}
		var resource struct{ Kind string }
		if err := node.Decode(&resource); err != nil {
			t.Fatal(err)
		}
		if _, ok := resources[resource.Kind]; ok {
			t.Fatalf("unexpected duplicate resource kind %q", resource.Kind)
		}
		resources[resource.Kind] = node
	}
}

func decode(t *testing.T, node yaml.Node, out any) {
	t.Helper()
	if err := node.Decode(out); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentUsesNaisAPIAndExistingDatabase(t *testing.T) {
	t.Parallel()
	resources := render(t, chartDir, "--set", "database.clusterName=durable-db")
	var deployment struct {
		Spec struct {
			Strategy struct{ Type string }
			Template struct {
				Spec struct {
					ServiceAccountName           string         `yaml:"serviceAccountName"`
					AutomountServiceAccountToken *bool          `yaml:"automountServiceAccountToken"`
					SecurityContext              map[string]any `yaml:"securityContext"`
					Containers                   []containerSpec
					InitContainers               []containerSpec `yaml:"initContainers"`
				}
			}
		}
	}
	decode(t, resources["Deployment"], &deployment)
	pod := deployment.Spec.Template.Spec
	if deployment.Spec.Strategy.Type != "Recreate" {
		t.Fatal("old replicas must stop before schema migration")
	}
	if pod.ServiceAccountName != "v0s-test" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("expected a dedicated service account without a mounted Kubernetes API token")
	}
	if pod.SecurityContext["runAsNonRoot"] != true || pod.SecurityContext["runAsUser"] != 65532 {
		t.Fatalf("unexpected pod security context: %v", pod.SecurityContext)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("expected one container, got %d", len(pod.Containers))
	}
	container := pod.Containers[0]
	if container.Image != "europe-north1-docker.pkg.dev/nais-io/nais/images/v0s:chart-test" {
		t.Fatalf("unexpected image: %s", container.Image)
	}
	if container.SecurityContext["readOnlyRootFilesystem"] != true || container.SecurityContext["allowPrivilegeEscalation"] != false {
		t.Fatalf("unexpected container security context: %v", container.SecurityContext)
	}
	var api, database bool
	for _, env := range container.Env {
		switch env.Name {
		case "NAIS_API_GRPC_ADDRESS":
			api = env.Value == "nais-api:3001"
		case "DATABASE_URL":
			ref := env.ValueFrom.SecretKeyRef
			database = ref.Name == "durable-db-appuser" && ref.Key == "uri"
		}
	}
	if !api || !database {
		t.Fatal("expected Nais API inventory and the existing database's URI secret")
	}
	if len(pod.InitContainers) != 1 {
		t.Fatalf("expected one migration init container, got %d", len(pod.InitContainers))
	}
	migration := pod.InitContainers[0]
	if migration.Image != container.Image || !slices.Equal(migration.Args, []string{"migrate"}) ||
		len(migration.Env) != 1 || databaseSecret(migration) != "durable-db-app" {
		t.Fatal("migration must use the release image and only the owner database credentials")
	}
	if migration.SecurityContext["readOnlyRootFilesystem"] != true || migration.SecurityContext["allowPrivilegeEscalation"] != false {
		t.Fatal("migration must retain the restricted container security context")
	}
	var mounts []string
	for _, mount := range container.VolumeMounts {
		mounts = append(mounts, mount.MountPath)
	}
	if !slices.Contains(mounts, "/var/cache/v0s") || !slices.Contains(mounts, "/tmp") {
		t.Fatalf("scratch container lacks writable cache/temp mounts: %v", mounts)
	}
	wantKinds := []string{"Deployment", "FQDNNetworkPolicy", "NetworkPolicy", "PodMonitor", "Service", "ServiceAccount"}
	if got := slices.Sorted(maps.Keys(resources)); !slices.Equal(got, wantKinds) {
		t.Fatalf("unexpected chart resources: got %v, want %v", got, wantKinds)
	}
	var account struct {
		Metadata struct{ Annotations map[string]string }
	}
	decode(t, resources["ServiceAccount"], &account)
	if account.Metadata.Annotations["iam.gke.io/gcp-service-account"] != "v0s@example.invalid" {
		t.Fatalf("expected the configured runtime identity: %v", account.Metadata.Annotations)
	}
}

func TestDeploymentConfiguresEmailAttestationIdentities(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		overrides []string
		issuer    string
		domains   string
	}{
		{name: "default", issuer: "https://accounts.google.com"},
		{
			name:      "configured",
			overrides: []string{"--set", "attestation.emailIssuer=https://issuer.example", "--set", "attestation.allowedEmailDomains={nav.no,example.com}"},
			issuer:    "https://issuer.example",
			domains:   "nav.no,example.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var deployment struct {
				Spec struct {
					Template struct {
						Spec struct{ Containers []containerSpec }
					}
				}
			}
			decode(t, render(t, chartDir, tt.overrides...)["Deployment"], &deployment)
			env := map[string]string{}
			for _, e := range deployment.Spec.Template.Spec.Containers[0].Env {
				env[e.Name] = e.Value
			}
			issuer, ok := env["ATTESTATION_EMAIL_ISSUER"]
			if !ok || issuer != tt.issuer {
				t.Errorf("ATTESTATION_EMAIL_ISSUER = %q, want %q", issuer, tt.issuer)
			}
			domains, ok := env["ATTESTATION_ALLOWED_EMAIL_DOMAINS"]
			if !ok || domains != tt.domains {
				t.Errorf("ATTESTATION_ALLOWED_EMAIL_DOMAINS = %q, want %q", domains, tt.domains)
			}
		})
	}
}

func TestNetworkPolicyRestrictsCallersAndPermitsInventory(t *testing.T) {
	t.Parallel()
	resources := render(t, chartDir, "--set", "database.clusterName=durable-db")
	type peer struct {
		PodSelector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"podSelector"`
		NamespaceSelector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"namespaceSelector"`
	}
	var policy struct {
		Spec struct {
			Ingress []struct{ From []peer }
			Egress  []struct {
				To    []peer
				Ports []struct{ Port int }
			}
		}
	}
	decode(t, resources["NetworkPolicy"], &policy)
	if len(policy.Spec.Ingress) != 1 || len(policy.Spec.Ingress[0].From) != 1 {
		t.Fatal("expected only same-namespace ingress")
	}
	labels := policy.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels
	if labels["kubernetes.io/metadata.name"] != "trusted-system" {
		t.Fatalf("ingress must name the release namespace: %v", labels)
	}
	var api, database bool
	for _, egress := range policy.Spec.Egress {
		for _, to := range egress.To {
			for _, port := range egress.Ports {
				api = api || to.PodSelector.MatchLabels["app"] == "nais-api" && port.Port == 3001
				database = database || to.PodSelector.MatchLabels["cnpg.io/cluster"] == "durable-db" && port.Port == 5432
			}
		}
	}
	if !api || !database {
		t.Fatal("expected egress to Nais API and the configured database")
	}
}

func TestFeatureRequiresPlatformServices(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(chartDir, "Feature.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var feature struct {
		EnvironmentKinds []string `yaml:"environmentKinds"`
		Dependencies     []struct {
			AllOf []string `yaml:"allOf"`
		}
	}
	if err := yaml.Unmarshal(data, &feature); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(feature.EnvironmentKinds, []string{"management"}) {
		t.Fatalf("unexpected environments: %v", feature.EnvironmentKinds)
	}
	var required []string
	for _, dependency := range feature.Dependencies {
		required = append(required, dependency.AllOf...)
	}
	for _, name := range []string{"nais-api", "nais-netpols-management", "cloudnative-pg", "fqdn-policy", "monitoring-crds"} {
		if !slices.Contains(required, name) {
			t.Errorf("missing required feature %q", name)
		}
	}
}

func TestChartRejectsMissingRuntimeConfiguration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, override, message string }{
		{"image", "image.tag=", "Set image.tag"},
		{"runtime identity", "serviceAccountEmail=", "Set serviceAccountEmail"},
		{"database", "database.clusterName=", "Set database.clusterName"},
		{"trusted organizations", "github.organizations=", "Set github.organizations"},
		{"Trivy database sources", "trivyDBRepositories=", "Set trivyDBRepositories"},
		{"HTTPS egress", "networkPolicy.httpsHosts=", "Set networkPolicy.httpsHosts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := exec.CommandContext(t.Context(), "helm", "template", "v0s", chartDir,
				"-f", filepath.Join(chartDir, "ci/test-values.yaml"), "--set", test.override).CombinedOutput()
			if err == nil || !strings.Contains(string(out), test.message) {
				t.Fatalf("expected rejection containing %q, got %v\n%s", test.message, err, out)
			}
		})
	}
}

func TestPackagedChartUsesReleaseImageAndKeepsFeature(t *testing.T) {
	t.Parallel()
	const version = "2026-11-06-150000-abcdef0"
	dir := t.TempDir()
	helm(t, "package", chartDir, "--version", version, "--app-version", version, "--destination", dir)
	archive := filepath.Join(dir, "v0s-"+version+".tgz")
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var feature []byte
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "v0s/Feature.yaml" {
			feature, err = io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
		}
		if strings.HasPrefix(header.Name, "v0s/ci/") {
			t.Fatal("rendering fixtures must not be packaged for deployment")
		}
	}
	want, err := os.ReadFile(filepath.Join(chartDir, "Feature.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(feature, want) {
		t.Fatal("release chart must retain its Fasit feature definition")
	}
	resources := render(t, archive, "--set", "image.tag=")
	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers     []containerSpec
					InitContainers []containerSpec `yaml:"initContainers"`
				}
			}
		}
	}
	decode(t, resources["Deployment"], &deployment)
	containers := deployment.Spec.Template.Spec.Containers
	if len(containers) != 1 || !strings.HasSuffix(containers[0].Image, ":"+version) {
		t.Fatalf("packaged chart must use its release image: %v", containers)
	}
	init := deployment.Spec.Template.Spec.InitContainers
	if len(init) != 1 || init[0].Image != containers[0].Image {
		t.Fatal("packaged migration must use the same release image as runtime")
	}
}
