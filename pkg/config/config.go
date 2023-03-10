package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/imdario/mergo"

	"aodsipam/pkg/logging"
	"aodsipam/pkg/types"
)

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(bytes []byte, envArgs string, extraConfigPaths ...string) (*types.IPAMConfig, string, error) {

	var n types.Net
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", fmt.Errorf("LoadIPAMConfig - JSON Parsing Error: %s / bytes: %s", err, bytes)
	}

	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	} else if !isNetworkRelevant(n.IPAM) {
		return nil, "", NewInvalidPluginError(n.IPAM.Type)
	}

	if n.IPAM.NetworkArmId == "" {
		return nil, "", fmt.Errorf("IPAM config missing 'networkArmId' key")
	}

	if n.IPAM.HaksUuid == "" {
		return nil, "", fmt.Errorf("IPAM config missing 'haksUuid' key")
	}

	args := types.IPAMEnvArgs{}
	if err := cnitypes.LoadArgs(envArgs, &args); err != nil {
		return nil, "", fmt.Errorf("LoadArgs - CNI Args Parsing Error: %s", err)
	}
	n.IPAM.PodName = string(args.K8S_POD_NAME)
	n.IPAM.PodNamespace = string(args.K8S_POD_NAMESPACE)

	flatipam, foundflatfile, err := GetFlatIPAM(n.IPAM, extraConfigPaths...)
	if err != nil {
		return nil, "", err
	}
	// Now let's try to merge the configurations...
	// NB: Don't try to do any initialization before this point or it won't account for merged flat file.
	if err := mergo.Merge(&n, flatipam); err != nil {
		logging.Errorf("Merge error with flat file: %s", err)
	}

	// Logging
	if n.IPAM.LogFile != "" {
		logging.SetLogFile(n.IPAM.LogFile)
	}
	if n.IPAM.LogLevel != "" {
		logging.SetLogLevel(n.IPAM.LogLevel)
	}

	if foundflatfile != "" {
		logging.Debugf("Used defaults from parsed flat file config @ %s", foundflatfile)
	}
	logging.Debugf("flatipam@ %v", flatipam)

	if n.IPAM.Kubernetes.KubeConfigPath == "" {
		return nil, "", storageError()
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, n.CNIVersion, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func GetFlatIPAM(IPAM *types.IPAMConfig, extraConfigPaths ...string) (types.Net, string, error) {
	// Once we have our basics, let's look for our (optional) configuration file
	confdirs := []string{"/etc/kubernetes/cni/net.d/aodsipam.d/aodsipam.conf", "/etc/cni/net.d/aodsipam.d/aodsipam.conf", "/host/etc/cni/net.d/aodsipam.d/aodsipam.conf"}
	confdirs = append(confdirs, extraConfigPaths...)
	// We prefix the optional configuration path (so we look there first)

	if IPAM != nil {
		if IPAM.ConfigurationPath != "" {
			confdirs = append([]string{IPAM.ConfigurationPath}, confdirs...)
		}
	}

	// Cycle through the path and parse the JSON config
	flatipam := types.Net{}
	foundflatfile := ""
	for _, confpath := range confdirs {
		if pathExists(confpath) {
			jsonFile, err := os.Open(confpath)
			if err != nil {
				return flatipam, foundflatfile, fmt.Errorf("error opening flat configuration file @ %s with: %s", confpath, err)
			}

			defer jsonFile.Close()

			jsonBytes, err := ioutil.ReadAll(jsonFile)
			if err != nil {
				return flatipam, foundflatfile, fmt.Errorf("LoadIPAMConfig Flatfile (%s) - ioutil.ReadAll error: %s", confpath, err)
			}

			if err := json.Unmarshal(jsonBytes, &flatipam.IPAM); err != nil {
				return flatipam, foundflatfile, fmt.Errorf("LoadIPAMConfig Flatfile (%s) - JSON Parsing Error: %s / bytes: %s", confpath, err, jsonBytes)
			}

			foundflatfile = confpath
			return flatipam, foundflatfile, err
		}
	}
	var err error
	return flatipam, foundflatfile, err
}

func LoadIPAMConfiguration(bytes []byte, envArgs string, extraConfigPaths ...string) (*types.IPAMConfig, error) {
	pluginConfig, err := loadPluginConfig(bytes)
	if err != nil {
		return nil, err
	}

	if pluginConfig.Type == "" {
		pluginConfigList, err := loadPluginConfigList(bytes)
		if err != nil {
			return nil, err
		}

		pluginConfigList.Plugins[0].CNIVersion = pluginConfig.CNIVersion
		firstPluginBytes, err := json.Marshal(pluginConfigList.Plugins[0])
		if err != nil {
			return nil, err
		}
		ipamConfig, _, err := LoadIPAMConfig(firstPluginBytes, envArgs, extraConfigPaths...)
		if err != nil {
			return nil, err
		}
		return ipamConfig, nil
	}

	ipamConfig, _, err := LoadIPAMConfig(bytes, envArgs, extraConfigPaths...)
	if err != nil {
		return nil, err
	}
	return ipamConfig, nil
}

func loadPluginConfigList(bytes []byte) (*types.NetConfList, error) {
	var netConfList types.NetConfList
	if err := json.Unmarshal(bytes, &netConfList); err != nil {
		return nil, err
	}

	return &netConfList, nil
}

func loadPluginConfig(bytes []byte) (*cnitypes.NetConf, error) {
	var pluginConfig cnitypes.NetConf
	if err := json.Unmarshal(bytes, &pluginConfig); err != nil {
		return nil, err
	}
	return &pluginConfig, nil
}

func isNetworkRelevant(ipamConfig *types.IPAMConfig) bool {
	const relevantIPAMType = "aodsipam"
	return ipamConfig.Type == relevantIPAMType
}

type InvalidPluginError struct {
	ipamType string
}

func NewInvalidPluginError(ipamType string) *InvalidPluginError {
	return &InvalidPluginError{ipamType: ipamType}
}

func (e *InvalidPluginError) Error() string {
	return fmt.Sprintf("only interested in networks whose IPAM type is 'aodsipam'. This one was: %s", e.ipamType)
}

func storageError() error {
	return fmt.Errorf("you have not configured the storage engine (looks like you're using an invalid `kubernetes.kubeconfig` parameter in your config)")
}
