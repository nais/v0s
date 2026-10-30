package kube_test

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseImageID(t *testing.T) {
	tests := []struct {
		name       string
		imageID    string
		image      string
		wantName   string
		wantDigest string
		wantOK     bool
	}{
		{name: "containerd", imageID: "europe-north1-docker.pkg.dev/nais/app@" + digestA, image: "europe-north1-docker.pkg.dev/nais/app:1", wantName: "europe-north1-docker.pkg.dev/nais/app", wantDigest: digestA, wantOK: true},
		{name: "docker-pullable", imageID: "docker-pullable://ghcr.io/nais/app@" + digestA, wantName: "ghcr.io/nais/app", wantDigest: digestA, wantOK: true},
		{name: "digest only takes repository from image", imageID: digestA, image: "ghcr.io/nais/app:v1", wantName: "ghcr.io/nais/app", wantDigest: digestA, wantOK: true},
		{name: "digest only with registry port", imageID: digestA, image: "registry:5000/app:v1", wantName: "registry:5000/app", wantDigest: digestA, wantOK: true},
		{name: "digest only with untagged image", imageID: digestA, image: "registry:5000/app", wantName: "registry:5000/app", wantDigest: digestA, wantOK: true},
		{name: "digest only with tag and digest in image", imageID: digestA, image: "ghcr.io/nais/app:v1@" + digestB, wantName: "ghcr.io/nais/app", wantDigest: digestA, wantOK: true},
		{name: "empty", imageID: "", image: "ghcr.io/nais/app:v1"},
		{name: "digest only without image", imageID: digestA},
		{name: "not a digest", imageID: "ghcr.io/nais/app:v1", image: "ghcr.io/nais/app:v1"},
		{name: "empty digest", imageID: "ghcr.io/nais/app@sha256:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, digest, ok := kube.ParseImageID(tt.imageID, tt.image)
			if name != tt.wantName || digest != tt.wantDigest || ok != tt.wantOK {
				t.Errorf("ParseImageID(%q, %q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.imageID, tt.image, name, digest, ok, tt.wantName, tt.wantDigest, tt.wantOK)
			}
		})
	}
}

func TestSnapshot(t *testing.T) {
	controller := true
	pod := func(name, app string, owner *metav1.OwnerReference, statuses ...corev1.ContainerStatus) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team", Labels: map[string]string{"other": "x"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses},
		}
		if app != "" {
			p.Labels["app"] = app
		}
		if owner != nil {
			p.OwnerReferences = []metav1.OwnerReference{*owner}
		}
		return p
	}
	status := func(container, imageID string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: container, Image: "ghcr.io/nais/" + container + ":v1", ImageID: imageID}
	}
	rs := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-123", Controller: &controller}

	api1 := pod("api-1", "api", rs, status("api", "ghcr.io/nais/api@"+digestA), status("proxy", "docker-pullable://ghcr.io/nais/proxy@"+digestB))
	api1.Status.InitContainerStatuses = []corev1.ContainerStatus{status("init", "ghcr.io/nais/init@"+digestA)}
	api1.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{status("debug", "ghcr.io/nais/debug@"+digestA)}
	api2 := pod("api-2", "api", rs, status("api", "ghcr.io/nais/api@"+digestA), status("proxy", "docker-pullable://ghcr.io/nais/proxy@"+digestB))
	job := pod("batch-1", "batch", &metav1.OwnerReference{Kind: "Job", Name: "batch", Controller: &controller}, status("batch", digestA))
	job.Status.Phase = corev1.PodSucceeded
	bare := pod("bare", "bare", &metav1.OwnerReference{Kind: "ConfigMap", Name: "not-a-controller"},
		status("bare", "ghcr.io/nais/bare@"+digestA), status("pending", ""))
	noApp := pod("no-app", "", rs, status("api", "ghcr.io/nais/api@"+digestA))

	client := fake.NewClientset([]runtime.Object{api1, api2, job, bare, noApp}...)
	w, err := kube.NewWatcherForClients(map[string]kubernetes.Interface{"dev": client}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := w.Snapshot("dev"); ok {
		t.Error("Snapshot before Run reported synced")
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- w.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	got := waitForSnapshot(t, w, "dev")
	want := []v0s.WorkloadImage{
		{Cluster: "dev", Namespace: "team", Workload: "api", Container: "api", OwnerKind: "ReplicaSet", ImageName: "ghcr.io/nais/api", Digest: digestA},
		{Cluster: "dev", Namespace: "team", Workload: "api", Container: "proxy", OwnerKind: "ReplicaSet", ImageName: "ghcr.io/nais/proxy", Digest: digestB},
		{Cluster: "dev", Namespace: "team", Workload: "bare", Container: "bare", OwnerKind: "", ImageName: "ghcr.io/nais/bare", Digest: digestA},
		{Cluster: "dev", Namespace: "team", Workload: "batch", Container: "batch", OwnerKind: "Job", ImageName: "ghcr.io/nais/batch", Digest: digestA},
	}
	sortWorkloadImages(got)
	if !slices.Equal(got, want) {
		t.Errorf("Snapshot(dev) =\n%v\nwant\n%v", got, want)
	}

	if _, ok := w.Snapshot("unknown"); ok {
		t.Error("Snapshot(unknown) reported synced")
	}
	if got := w.Clusters(); !slices.Equal(got, []string{"dev"}) {
		t.Errorf("Clusters() = %v, want [dev]", got)
	}
}

func waitForSnapshot(t *testing.T, w *kube.Watcher, cluster string) []v0s.WorkloadImage {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if images, ok := w.Snapshot(cluster); ok {
			return images
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cluster %s did not sync", cluster)
	return nil
}

func sortWorkloadImages(images []v0s.WorkloadImage) {
	slices.SortFunc(images, func(a, b v0s.WorkloadImage) int {
		return cmp.Or(
			cmp.Compare(a.Workload, b.Workload),
			cmp.Compare(a.Container, b.Container),
			cmp.Compare(a.Digest, b.Digest),
		)
	})
}
