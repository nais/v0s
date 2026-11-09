package chart_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestDatabaseProvisioningNeedsNoClusterNetworkAddresses(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(chartDir, "Feature.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var feature struct {
		Values map[string]any
	}
	if err := yaml.Unmarshal(data, &feature); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"postgresql.networkPolicy.apiServerCidrs", "postgresql.networkPolicy.dnsCidrs"} {
		if _, exists := feature.Values[path]; exists {
			t.Errorf("Fasit must not require per-cluster network input %q", path)
		}
	}

	// The fixture enables provisioning without supplying any cluster addresses.
	resources := renderWithPostgreSQL(t, chartDir)
	if _, exists := resources["Cluster/v0s-db"]; !exists {
		t.Fatal("database provisioning must work without per-cluster network inputs")
	}
	var policy struct {
		Spec struct {
			Egress []struct {
				To []struct {
					IPBlock *struct{ CIDR string } `yaml:"ipBlock"`
				}
			}
		}
	}
	decode(t, resources["NetworkPolicy/v0s-db"], &policy)
	for _, egress := range policy.Spec.Egress {
		for _, to := range egress.To {
			if to.IPBlock != nil {
				t.Errorf("database policy must rely on platform DNS/API access, not per-cluster CIDR %q", to.IPBlock.CIDR)
			}
		}
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
