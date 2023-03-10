package types

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
)

// Datastore types
const (
	DefaultLeaderLeaseDuration    = 1500
	DefaultLeaderRenewDeadline    = 1000
	DefaultLeaderRetryPeriod      = 500
	AddTimeLimit                  = 2 * time.Minute
	DelTimeLimit                  = 1 * time.Minute
	DefaultOverlappingIPsFeatures = true
	DefaultSleepForRace           = 0
)

// Net is The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`
}

// NetConfList describes an ordered list of networks.
type NetConfList struct {
	CNIVersion string `json:"cniVersion,omitempty"`

	Name         string `json:"name,omitempty"`
	DisableCheck bool   `json:"disableCheck,omitempty"`
	Plugins      []*Net `json:"plugins,omitempty"`
}

type RangeConfiguration struct {
	OmitRanges []string `json:"exclude,omitempty"`
	Range      string   `json:"range"`
	RangeStart net.IP   `json:"range_start,omitempty"`
	RangeEnd   net.IP   `json:"range_end,omitempty"`
}

// IPAMConfig describes the expected json configuration for this plugin
type IPAMConfig struct {
	Name                     string
	Type                     string `json:"type"`
	NetworkArmId             string `json:"networkArmId"`
	HaksUuid                 string `json:"haksUuid"`
	ReleaseIp                string `json:"releaseIp"`
	LogFile                  string `json:"log_file"`
	LogLevel                 string `json:"log_level"`
	ReconcilerCronExpression string `json:"reconciler_cron_expression,omitempty"`
	SleepForRace             int    `json:"sleep_for_race,omitempty"`
	Gateway                  net.IP
	Kubernetes               KubernetesConfig `json:"kubernetes,omitempty"`
	ConfigurationPath        string           `json:"configuration_path"`
	PodName                  string
	PodNamespace             string
}

func (ic *IPAMConfig) UnmarshalJSON(data []byte) error {
	type IPAMConfigAlias struct {
		Name                     string
		Type                     string `json:"type"`
		NetworkArmId             string `json:"networkArmId"`
		HaksUuid                 string `json:"haksUuid"`
		ReleaseIp                string `json:"releaseIp"`
		LogFile                  string `json:"log_file"`
		LogLevel                 string `json:"log_level"`
		ReconcilerCronExpression string `json:"reconciler_cron_expression,omitempty"`
		SleepForRace             int    `json:"sleep_for_race,omitempty"`
		Gateway                  string
		Kubernetes               KubernetesConfig `json:"kubernetes,omitempty"`
		ConfigurationPath        string           `json:"configuration_path"`
		PodName                  string
		PodNamespace             string
	}

	ipamConfigAlias := IPAMConfigAlias{
		SleepForRace: DefaultSleepForRace,
	}
	if err := json.Unmarshal(data, &ipamConfigAlias); err != nil {
		return err
	}

	*ic = IPAMConfig{
		Name:                     ipamConfigAlias.Name,
		Type:                     ipamConfigAlias.Type,
		NetworkArmId:             ipamConfigAlias.NetworkArmId,
		HaksUuid:                 ipamConfigAlias.HaksUuid,
		ReleaseIp:                ipamConfigAlias.ReleaseIp,
		LogFile:                  ipamConfigAlias.LogFile,
		LogLevel:                 ipamConfigAlias.LogLevel,
		ReconcilerCronExpression: ipamConfigAlias.ReconcilerCronExpression,
		SleepForRace:             ipamConfigAlias.SleepForRace,
		Gateway:                  backwardsCompatibleIPAddress(ipamConfigAlias.Gateway),
		Kubernetes:               ipamConfigAlias.Kubernetes,
		ConfigurationPath:        ipamConfigAlias.ConfigurationPath,
		PodName:                  ipamConfigAlias.PodName,
		PodNamespace:             ipamConfigAlias.PodNamespace,
	}
	return nil
}

func (ic *IPAMConfig) GetPodRef() string {
	return fmt.Sprintf("%s/%s", ic.PodNamespace, ic.PodName)
}

func backwardsCompatibleIPAddress(ip string) net.IP {
	var ipAddr net.IP
	if sanitizedIP, err := sanitizeIP(ip); err == nil {
		ipAddr = sanitizedIP
	}
	return ipAddr
}

// IPAMEnvArgs are the environment vars we expect
type IPAMEnvArgs struct {
	cnitypes.CommonArgs
	IP                         cnitypes.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY                    cnitypes.UnmarshallableString `json:"gateway,omitempty"`
	K8S_POD_NAME               cnitypes.UnmarshallableString //revive:disable-line
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString //revive:disable-line
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString //revive:disable-line
}

// KubernetesConfig describes the kubernetes-specific configuration details
type KubernetesConfig struct {
	KubeConfigPath string `json:"kubeconfig,omitempty"`
	K8sAPIRoot     string `json:"k8s_api_root,omitempty"`
}

// Address is our standard address.
type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

// IPReservation is an address that has been reserved by this plugin
type IPReservation struct {
	IP          net.IP `json:"ip"`
	ContainerID string `json:"id"`
	PodRef      string `json:"podref,omitempty"`
	IsAllocated bool
}

func (ir IPReservation) String() string {
	return fmt.Sprintf("IP: %s is reserved for pod: %s", ir.IP.String(), ir.PodRef)
}

const (
	// Allocate operation identifier
	Allocate = 0
	// Deallocate operation identifier
	Deallocate = 1
)
