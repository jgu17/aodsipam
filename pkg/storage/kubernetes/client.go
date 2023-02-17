package kubernetes

import (
	"aodsipam/pkg/logging"
	"context"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client has info on how to connect to the kubernetes cluster
type Client struct {
	timeout time.Duration
	config  *rest.Config
}

func NewClient(timeout time.Duration) (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	return &Client{config: config, timeout: timeout}, nil
}

func NewRestConfigViaKubeconfig(kubeconfigPath string) (*rest.Config, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{}).ClientConfig()

	if err != nil {
		return nil, err
	}

	return config, nil
}

func (i *Client) ListPods(ctx context.Context) ([]v1.Pod, error) {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	crScheme := runtime.NewScheme()
	v1.AddToScheme(crScheme)

	cl, err := client.New(i.config, client.Options{
		Scheme: crScheme,
	})

	if err != nil {
		logging.Errorf("could not get Client", err)
		return nil, err
	}
	podList := &v1.PodList{}
	err = cl.List(ctxWithTimeout, podList)
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}
