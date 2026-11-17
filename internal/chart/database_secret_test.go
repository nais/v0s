package chart_test

import "testing"

func TestProvidedRuntimeSecretIsNotProvisioned(t *testing.T) {
	t.Parallel()
	resources := renderWithPostgreSQL(t, chartDir, "--set", "postgresql.appUser.existingSecret=provided-rw")
	if _, exists := resources["Secret/provided-rw"]; exists {
		t.Fatal("an externally provided Secret must not be managed by the chart")
	}
	if _, exists := resources["Secret/v0s-db-appuser"]; exists {
		t.Fatal("no generated Secret is needed when credentials are supplied")
	}
	var cluster struct {
		Spec struct {
			Managed struct {
				Roles []struct {
					PasswordSecret struct{ Name string } `yaml:"passwordSecret"`
				}
			}
		}
	}
	decode(t, resources["Cluster/v0s-db"], &cluster)
	if roles := cluster.Spec.Managed.Roles; len(roles) != 1 || roles[0].PasswordSecret.Name != "provided-rw" {
		t.Fatal("CNPG must use the supplied runtime credentials")
	}
}

func TestIndependentDatabaseUsesSeparateSuppliedSecrets(t *testing.T) {
	t.Parallel()
	resources := render(t, chartDir, "--set", "database.runtimeSecretName=existing-rw", "--set", "database.migrationSecretName=existing-owner")
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
	pod := deployment.Spec.Template.Spec
	if databaseSecret(pod.Containers[0]) != "existing-rw" || databaseSecret(pod.InitContainers[0]) != "existing-owner" {
		t.Fatal("external database must allow separately named runtime and migration credentials")
	}
}
