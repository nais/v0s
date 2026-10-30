package kube

import (
	"log/slog"

	"k8s.io/client-go/kubernetes"
)

// NewWatcherForClients creates a Watcher over existing clients, for tests with a fake clientset.
func NewWatcherForClients(clients map[string]kubernetes.Interface, log *slog.Logger) (*Watcher, error) {
	return newWatcher(clients, log)
}

var ParseImageID = parseImageID
