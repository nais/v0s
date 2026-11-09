package chart_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"go.yaml.in/yaml/v3"
)

func renderWithPostgreSQL(t *testing.T, chart string, overrides ...string) map[string]yaml.Node {
	t.Helper()
	args := []string{"template", "v0s-test", chart, "--namespace", "trusted-system",
		"-f", filepath.Join(chartDir, "ci/test-values.yaml"),
		"-f", filepath.Join(chartDir, "ci/postgresql-values.yaml")}
	args = append(args, overrides...)
	dec := yaml.NewDecoder(bytes.NewReader(helm(t, args...)))
	resources := make(map[string]yaml.Node)
	for {
		var node yaml.Node
		if err := dec.Decode(&node); errors.Is(err, io.EOF) {
			return resources
		} else if err != nil {
			t.Fatal(err)
		}
		var resource struct {
			Kind     string
			Metadata struct{ Name string }
		}
		decode(t, node, &resource)
		key := resource.Kind + "/" + resource.Metadata.Name
		if _, exists := resources[key]; exists {
			t.Fatalf("duplicate resource %s", key)
		}
		resources[key] = node
	}
}

func TestChartProvisionsRetainedDatabaseAndConnectsToIt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"v0s-db", "custom-db"} {
		t.Run(name, func(t *testing.T) {
			var overrides []string
			if name != "v0s-db" {
				overrides = append(overrides, "--set", "postgresql.fullnameOverride="+name)
			}
			// An unrelated external database setting must not change the managed connection.
			overrides = append(overrides, "--set", "database.clusterName=external-db")
			resources := renderWithPostgreSQL(t, chartDir, overrides...)
			var cluster struct {
				Metadata struct {
					Namespace   string
					Annotations map[string]string
				}
				Spec struct {
					Instances             int
					ImageName             string `yaml:"imageName"`
					EnableSuperuserAccess bool   `yaml:"enableSuperuserAccess"`
					Bootstrap             struct {
						InitDB struct{ Database, Owner string }
					}
					Storage struct {
						Size         string
						StorageClass string `yaml:"storageClass"`
					}
				}
			}
			decode(t, resources["Cluster/"+name], &cluster)
			if cluster.Metadata.Namespace != "trusted-system" || cluster.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
				t.Fatalf("database must belong to the release namespace and be retained: %+v", cluster.Metadata)
			}
			if cluster.Spec.Instances != 3 || cluster.Spec.Storage.Size != "10Gi" || cluster.Spec.Storage.StorageClass != "dynamic-rwo" {
				t.Fatalf("unexpected default database sizing: %+v", cluster.Spec)
			}
			if !strings.Contains(cluster.Spec.ImageName, "postgresql:18@sha256:") || cluster.Spec.EnableSuperuserAccess {
				t.Fatalf("expected pinned PostgreSQL 18 without superuser password access: %+v", cluster.Spec)
			}
			if cluster.Spec.Bootstrap.InitDB.Database != "v0s" || cluster.Spec.Bootstrap.InitDB.Owner != "v0s" {
				t.Fatalf("unexpected bootstrap database: %+v", cluster.Spec.Bootstrap)
			}
			var deployment struct {
				Spec struct {
					Template struct {
						Metadata struct{ Labels map[string]string }
						Spec     struct {
							Containers []struct {
								Env []struct {
									Name      string
									ValueFrom struct {
										SecretKeyRef struct{ Name, Key string } `yaml:"secretKeyRef"`
									} `yaml:"valueFrom"`
								}
							}
						}
					}
				}
			}
			decode(t, resources["Deployment/v0s-test"], &deployment)
			pod := deployment.Spec.Template
			if pod.Metadata.Labels["app.kubernetes.io/instance"] != "v0s-test" {
				t.Fatal("application must match the database's same-release ingress selector")
			}
			var connected bool
			for _, container := range pod.Spec.Containers {
				for _, env := range container.Env {
					ref := env.ValueFrom.SecretKeyRef
					connected = connected || env.Name == "DATABASE_URL" && ref.Name == name+"-app" && ref.Key == "uri"
				}
			}
			if !connected {
				t.Fatal("application must use the provisioned database's URI secret")
			}

			type peer struct {
				PodSelector struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"podSelector"`
			}
			var policy struct {
				Spec struct {
					PodSelector struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					} `yaml:"podSelector"`
					Ingress []struct {
						From  []peer
						Ports []struct{ Port int }
					}
					Egress []struct {
						To    []peer
						Ports []struct{ Port int }
					}
				}
			}
			decode(t, resources["NetworkPolicy/"+name], &policy)
			if policy.Spec.PodSelector.MatchLabels["cnpg.io/cluster"] != name {
				t.Fatal("database policy must select the provisioned cluster")
			}
			var allowed bool
			for _, ingress := range policy.Spec.Ingress {
				for _, from := range ingress.From {
					for _, port := range ingress.Ports {
						allowed = allowed || from.PodSelector.MatchLabels["app.kubernetes.io/instance"] == "v0s-test" && port.Port == 5432
					}
				}
			}
			if !allowed {
				t.Fatal("database policy must admit the application's release on PostgreSQL's port")
			}
			decode(t, resources["NetworkPolicy/v0s-test"], &policy)
			allowed = false
			for _, egress := range policy.Spec.Egress {
				for _, to := range egress.To {
					for _, port := range egress.Ports {
						allowed = allowed || to.PodSelector.MatchLabels["cnpg.io/cluster"] == name && port.Port == 5432
					}
				}
			}
			if !allowed {
				t.Fatal("application egress must target the provisioned cluster")
			}
		})
	}
}

func TestDatabasePoliciesUseComputedFasitAddresses(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(chartDir, "Feature.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var feature struct {
		Values map[string]struct {
			Computed struct{ Template string }
		}
	}
	if err := yaml.Unmarshal(data, &feature); err != nil {
		t.Fatal(err)
	}
	values := make(map[string]any)
	for _, path := range []string{"postgresql.networkPolicy.apiServerCidrs", "postgresql.networkPolicy.dnsCidrs"} {
		tmpl, err := template.New(path).Option("missingkey=error").Parse(feature.Values[path].Computed.Template)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := tmpl.Execute(&out, struct{ Env map[string]string }{
			Env: map[string]string{"apiserver_endpoint": "192.0.2.10", "svc_ip_cidr_range": "192.0.2.0/24"},
		}); err != nil {
			t.Fatal(err)
		}
		var cidrs []string
		if err := yaml.Unmarshal(out.Bytes(), &cidrs); err != nil {
			t.Fatal(err)
		}
		values[strings.TrimPrefix(path, "postgresql.networkPolicy.")] = cidrs
	}
	data, err = yaml.Marshal(map[string]any{"postgresql": map[string]any{"networkPolicy": values}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "computed-values.yaml")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	resources := renderWithPostgreSQL(t, chartDir, "-f", file)
	var policy struct {
		Spec struct {
			Egress []struct {
				To []struct {
					IPBlock struct{ CIDR string } `yaml:"ipBlock"`
				}
				Ports []struct{ Port int }
			}
		}
	}
	decode(t, resources["NetworkPolicy/v0s-db"], &policy)
	var api, dns bool
	for _, egress := range policy.Spec.Egress {
		for _, to := range egress.To {
			for _, port := range egress.Ports {
				api = api || to.IPBlock.CIDR == "192.0.2.10/32" && port.Port == 443
				dns = dns || to.IPBlock.CIDR == "192.0.2.0/24" && port.Port == 53
			}
		}
	}
	if !api || !dns {
		t.Fatalf("expected Fasit-computed API/DNS addresses: %+v", policy.Spec.Egress)
	}
}

func TestDatabaseProvisioningRejectsMissingNetworkAddresses(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"apiServerCidrs", "dnsCidrs"} {
		t.Run(field, func(t *testing.T) {
			out, err := exec.CommandContext(t.Context(), "helm", "template", "v0s", chartDir,
				"-f", filepath.Join(chartDir, "ci/test-values.yaml"),
				"-f", filepath.Join(chartDir, "ci/postgresql-values.yaml"),
				"--set", "postgresql.networkPolicy."+field+"=").CombinedOutput()
			if err == nil || !strings.Contains(string(out), field) {
				t.Fatalf("expected missing %s rejection, got %v\n%s", field, err, out)
			}
		})
	}
}

func TestPackagedReleaseIncludesPostgreSQLDependency(t *testing.T) {
	t.Parallel()
	const version = "2026-11-07-200000-abcdef0"
	dir := t.TempDir()
	helm(t, "package", chartDir, "--version", version, "--app-version", version, "--destination", dir)
	resources := renderWithPostgreSQL(t, filepath.Join(dir, "v0s-"+version+".tgz"), "--set", "image.tag=")
	if _, exists := resources["Cluster/v0s-db"]; !exists {
		t.Fatal("release must bundle its pinned database dependency for offline Fasit installation")
	}
}
