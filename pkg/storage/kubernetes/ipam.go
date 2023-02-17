package kubernetes

import (
	"context"
	"fmt"
	"net"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"aodsipam/pkg/allocate"
	"aodsipam/pkg/logging"
	aodsipamtypes "aodsipam/pkg/types"
)

// NewKubernetesIPAM returns a new KubernetesIPAM Client configured to a kubernetes CRD backend
func NewKubernetesIPAM(containerID string, ipamConf aodsipamtypes.IPAMConfig) (*KubernetesIPAM, error) {
	var namespace string
	if cfg, err := clientcmd.LoadFromFile(ipamConf.Kubernetes.KubeConfigPath); err != nil {
		return nil, err
	} else if ctx, ok := cfg.Contexts[cfg.CurrentContext]; ok && ctx != nil {
		namespace = wbNamespaceFromCtx(ctx)
	} else {
		return nil, fmt.Errorf("k8s config: namespace not present in context")
	}

	config, err := NewRestConfigViaKubeconfig(ipamConf.Kubernetes.KubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed instantiating rest-config client: %v", err)
	}
	kubernetesClient := &Client{
		config: config,
	}

	k8sIPAM := newKubernetesIPAM(containerID, ipamConf, namespace, *kubernetesClient)
	return k8sIPAM, nil
}

// NewKubernetesIPAMWithNamespace returns a new KubernetesIPAM Client configured to a kubernetes CRD backend
func NewKubernetesIPAMWithNamespace(containerID string, ipamConf aodsipamtypes.IPAMConfig, namespace string) (*KubernetesIPAM, error) {
	k8sIPAM, err := NewKubernetesIPAM(containerID, ipamConf)
	if err != nil {
		return nil, err
	}
	k8sIPAM.namespace = namespace
	return k8sIPAM, nil
}

func newKubernetesIPAM(containerID string, ipamConf aodsipamtypes.IPAMConfig, namespace string, kubernetesClient Client) *KubernetesIPAM {
	return &KubernetesIPAM{
		Config:      ipamConf,
		containerID: containerID,
		namespace:   namespace,
		Client:      kubernetesClient,
	}
}

// KubernetesIPAM manages ip blocks in an kubernetes CRD backend
type KubernetesIPAM struct {
	Client
	Config      aodsipamtypes.IPAMConfig
	containerID string
	namespace   string
}

func NormalizeRange(ipRange string) string {
	// v6 filter
	normalized := strings.ReplaceAll(ipRange, ":", "-")
	// replace subnet cidr slash
	normalized = strings.ReplaceAll(normalized, "/", "-")
	return normalized
}

// Close partially implements the Store interface
func (i *KubernetesIPAM) Close() error {
	return nil
}

// IPManagement manages ip allocation and deallocation from a storage perspective
func IPManagement(ctx context.Context, mode int, ipamConf aodsipamtypes.IPAMConfig, client *KubernetesIPAM) ([]net.IPNet, error) {
	var newips []net.IPNet

	if ipamConf.PodName == "" {
		return newips, fmt.Errorf("IPAM client initialization error: no pod name")
	}

	logging.Debugf("Elected as leader, do processing")
	newips, err := IPManagementKubernetesUpdate(ctx, mode, client, ipamConf, client.containerID, ipamConf.GetPodRef())

	logging.Debugf("IPManagement: %v, %v", newips, err)
	return newips, err
}

func wbNamespaceFromCtx(ctx *clientcmdapi.Context) string {
	namespace := ctx.Namespace
	if namespace == "" {
		return metav1.NamespaceSystem
	}
	return namespace
}

// IPManagementKubernetesUpdate manages k8s updates
func IPManagementKubernetesUpdate(ctx context.Context, mode int, ipam *KubernetesIPAM, ipamConf aodsipamtypes.IPAMConfig,
	containerID string, podRef string) ([]net.IPNet, error) {
	logging.Debugf("IPManagement -- mode: %v / containerID: %v / podRef: %v", mode, containerID, podRef)

	var newips []net.IPNet
	var newip net.IPNet
	// Skip invalid modes
	switch mode {
	case aodsipamtypes.Allocate, aodsipamtypes.Deallocate:
	default:
		return newips, fmt.Errorf("got an unknown mode passed to IPManagement: %v", mode)
	}

	var err error

	switch mode {
	case aodsipamtypes.Allocate:
		newip, err = allocate.AssignIP(ctx, ipam.config, containerID, podRef)
		if err != nil {
			logging.Errorf("Error assigning IP: %v", err)
			return newips, err
		}

	case aodsipamtypes.Deallocate:
		_, err = allocate.DeallocateIP(ctx, ipam.config, containerID)
		if err != nil {
			logging.Errorf("Error deallocating IP: %v", err)
			return newips, err
		}
	}

	newips = append(newips, newip)

	return newips, err
}
