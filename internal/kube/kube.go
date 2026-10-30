// Package kube observes which images run in which workloads, from pod status in every cluster.
package kube

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/nais/v0s"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// appLabel names the workload a pod belongs to. Pods without it are ignored.
const appLabel = "app"

// Watcher keeps an informer cache of pods for each cluster.
type Watcher struct {
	log      *slog.Logger
	clusters map[string]*cluster
}

type cluster struct {
	factory informers.SharedInformerFactory
	pods    cache.SharedIndexInformer
}

// NewWatcher creates informers for pods in every cluster. clusters maps cluster name to rest config.
func NewWatcher(clusters map[string]*rest.Config, log *slog.Logger) (*Watcher, error) {
	clients := make(map[string]kubernetes.Interface, len(clusters))
	for name, cfg := range clusters {
		c, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating client for cluster %s: %w", name, err)
		}
		clients[name] = c
	}
	return newWatcher(clients, log)
}

func newWatcher(clients map[string]kubernetes.Interface, log *slog.Logger) (*Watcher, error) {
	w := &Watcher{log: log, clusters: make(map[string]*cluster, len(clients))}
	for name, client := range clients {
		factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithTransform(stripPod))
		pods := factory.Core().V1().Pods().Informer()
		clusterLog := log.With("cluster", name)
		err := pods.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *cache.Reflector, err error) {
			clusterLog.With("err", err).Warn("watching pods")
		})
		if err != nil {
			return nil, fmt.Errorf("setting watch error handler for cluster %s: %w", name, err)
		}
		w.clusters[name] = &cluster{factory: factory, pods: pods}
	}
	return w, nil
}

// Run starts the informers and blocks until ctx is done.
func (w *Watcher) Run(ctx context.Context) error {
	for _, c := range w.clusters {
		c.factory.Start(ctx.Done())
	}
	<-ctx.Done()
	for _, c := range w.clusters {
		c.factory.Shutdown()
	}
	return nil
}

// Clusters lists the watched cluster names.
func (w *Watcher) Clusters() []string {
	return slices.Sorted(maps.Keys(w.clusters))
}

// Snapshot returns the workload images currently observed in cluster, and false if the cluster's
// informer has not synced (callers must not treat an unsynced snapshot as truth).
func (w *Watcher) Snapshot(clusterName string) ([]v0s.WorkloadImage, bool) {
	c, ok := w.clusters[clusterName]
	if !ok || !c.pods.HasSynced() {
		return nil, false
	}
	seen := map[v0s.WorkloadImage]bool{}
	var images []v0s.WorkloadImage
	for _, obj := range c.pods.GetStore().List() {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			continue
		}
		workload := pod.Labels[appLabel]
		if workload == "" {
			continue
		}
		ownerKind := ""
		if ref := metav1.GetControllerOf(pod); ref != nil {
			ownerKind = ref.Kind
		}
		for _, s := range pod.Status.ContainerStatuses {
			name, digest, ok := parseImageID(s.ImageID, s.Image)
			if !ok {
				if s.ImageID != "" {
					w.log.With("cluster", clusterName, "namespace", pod.Namespace, "pod", pod.Name, "container", s.Name).
						Debug("ignoring container with unparseable imageID")
				}
				continue
			}
			wi := v0s.WorkloadImage{
				Cluster:   clusterName,
				Namespace: pod.Namespace,
				Workload:  workload,
				Container: s.Name,
				OwnerKind: ownerKind,
				ImageName: name,
				Digest:    digest,
			}
			if !seen[wi] {
				seen[wi] = true
				images = append(images, wi)
			}
		}
	}
	return images, true
}

// parseImageID returns the repository and manifest digest of a container status. It accepts
// imageID forms "docker-pullable://repo@sha256:…", "repo@sha256:…" and "sha256:…". In the last
// form the repository is taken from image, without its tag or digest.
func parseImageID(imageID, image string) (name, digest string, ok bool) {
	if _, rest, found := strings.Cut(imageID, "://"); found {
		imageID = rest
	}
	name, digest, found := strings.Cut(imageID, "@")
	if !found {
		name, digest = repository(image), imageID
	}
	if name == "" || !strings.HasPrefix(digest, "sha256:") || len(digest) == len("sha256:") {
		return "", "", false
	}
	return name, digest, true
}

// repository strips the digest and tag from an image reference. A colon before the last slash is
// a registry port, not a tag.
func repository(image string) string {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// stripPod keeps only the pod fields Snapshot reads, so the cache stays small in large clusters.
func stripPod(obj any) (any, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	stripped := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			UID:             pod.UID,
			ResourceVersion: pod.ResourceVersion,
		},
	}
	if app, ok := pod.Labels[appLabel]; ok {
		stripped.Labels = map[string]string{appLabel: app}
	}
	if ref := metav1.GetControllerOf(pod); ref != nil {
		stripped.OwnerReferences = []metav1.OwnerReference{*ref}
	}
	if len(pod.Status.ContainerStatuses) > 0 {
		stripped.Status.ContainerStatuses = make([]corev1.ContainerStatus, len(pod.Status.ContainerStatuses))
		for i, s := range pod.Status.ContainerStatuses {
			stripped.Status.ContainerStatuses[i] = corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID}
		}
	}
	return stripped, nil
}

// googleScopes are the scopes GKE needs to authenticate a Google identity.
var googleScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
}

// ClusterConfigs builds rest configs for Nais clusters: remote clusters at
// https://apiserver.<cluster>.<tenant>.cloud.nais.io using Google credentials, and the in-cluster
// config for selfCluster if set.
func ClusterConfigs(tenant string, clusters []string, selfCluster string) (map[string]*rest.Config, error) {
	configs := make(map[string]*rest.Config, len(clusters)+1)
	if len(clusters) > 0 {
		ts, err := google.DefaultTokenSource(context.Background(), googleScopes...)
		if err != nil {
			return nil, fmt.Errorf("creating google token source: %w", err)
		}
		for _, name := range clusters {
			configs[name] = &rest.Config{
				Host: fmt.Sprintf("https://apiserver.%s.%s.cloud.nais.io", name, tenant),
				WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
					return &oauth2.Transport{Base: rt, Source: ts}
				},
			}
		}
	}
	if selfCluster != "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("creating in-cluster config: %w", err)
		}
		configs[selfCluster] = cfg
	}
	return configs, nil
}
