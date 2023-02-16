package main

import (
	"context"
	"fmt"
	"net"

	"aodsipam/pkg/allocate"
	"aodsipam/pkg/config"
	"aodsipam/pkg/logging"
	"aodsipam/pkg/storage/kubernetes"
	"aodsipam/pkg/types"
	"aodsipam/pkg/version"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMain(func(args *skel.CmdArgs) error {
		ipamConf, confVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
		if err != nil {
			logging.Errorf("IPAM configuration load failed: %s", err)
			return err
		}
		logging.Debugf("ADD - IPAM configuration successfully read: %+v", *ipamConf)
		ipam, err := kubernetes.NewKubernetesIPAM(args.ContainerID, *ipamConf)
		if err != nil {
			return logging.Errorf("failed to create Kubernetes IPAM manager: %v", err)
		}
		defer func() { safeCloseKubernetesBackendConnection(ipam) }()
		return cmdAdd(args, ipam, confVersion)
	},
		cmdCheck,
		func(args *skel.CmdArgs) error {
			ipamConf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
			if err != nil {
				logging.Errorf("IPAM configuration load failed: %s", err)
				return err
			}
			logging.Debugf("DEL - IPAM configuration successfully read: %+v", *ipamConf)

			ipam, err := kubernetes.NewKubernetesIPAM(args.ContainerID, *ipamConf)
			if err != nil {
				return logging.Errorf("IPAM client initialization error: %v", err)
			}
			defer func() { safeCloseKubernetesBackendConnection(ipam) }()
			return cmdDel(args, ipam)
		},
		cniversion.All,
		fmt.Sprintf("whereabouts %s", version.GetFullVersionWithRuntimeInfo()),
	)
}

func safeCloseKubernetesBackendConnection(ipam *kubernetes.KubernetesIPAM) {
	if err := ipam.Close(); err != nil {
		_ = logging.Errorf("failed to close the connection to the K8s backend: %v", err)
	}
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO
	return fmt.Errorf("CNI CHECK method is not implemented")
}

func cmdAdd(args *skel.CmdArgs, client *kubernetes.KubernetesIPAM, cniVersion string) error {
	// Initialize our result, and assign DNS & routing.
	result := &current.Result{}
	result.DNS = client.Config.DNS
	result.Routes = client.Config.Routes

	logging.Debugf("Beginning IPAM for ContainerID: %v", args.ContainerID)
	var newips []net.IPNet

	ctx, cancel := context.WithTimeout(context.Background(), types.AddTimeLimit)
	defer cancel()

	newips, err := kubernetes.IPManagement1(ctx, types.Allocate, client.Config, client)
	if err != nil {
		logging.Errorf("Error at storage engine: %s", err)
		return fmt.Errorf("error at storage engine: %w", err)
	}

	// 2023-02-15T03:52:38Z [debug] newips static3--------------------: [{192.168.2.225 ffffffff}]
	// ////2023-02-15T03:52:38Z [debug] result----------------------: &{ [] [{Version:4 Interface:<nil> Address:{IP:192.168.2.225 Mask:ffffffff} Gateway:<nil>}] [] {[]  [] []}}
	// 2023-02-15T03:38:15Z [debug] newips static4--------------------: [{192.168.2.225 ffffffff}]
	// ////2023-02-15T03:38:15Z [debug] result----------------------:  &{ [] [{Version:4 Interface:<nil> Address:{IP:192.168.2.225 Mask:ffffffff} Gateway:<nil>}] [] {[]  [] []}}
	// 2023-02-15T03:27:02Z [debug] newips static3--------------------: [{192.168.2.225 ffffffff}]
	// /////2023-02-15T03:27:02Z [debug] result----------------------: &{0.4.0 [] [{Version:4 Interface:<nil> Address:{IP:192.168.2.225 Mask:ffffffff} Gateway:<nil>}] [] {[]  [] []}}

	// newips = make([]net.IPNet, 1)

	// ipaddress := "192.168.2.225"
	// //mask := "fffffff0"

	// ipnet := net.IPNet{
	// 	IP:   net.ParseIP(ipaddress),
	// 	Mask: net.CIDRMask(32, 32),
	// }

	// newips := []net.IPNet{
	// 	ipnet,
	// }
	logging.Debugf("newips static3--------------------: %v", newips)

	var useVersion string
	for _, newip := range newips {
		// Determine if v4 or v6.
		if allocate.IsIPv4(newip.IP) {
			useVersion = "4"
		} else {
			useVersion = "6"
		}

		result.IPs = append(result.IPs, &current.IPConfig{
			Version: useVersion,
			Address: newip,
			Gateway: client.Config.Gateway})
	}

	// Assign all the static IP elements.
	for _, v := range client.Config.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Version: v.Version,
			Address: v.Address,
			Gateway: v.Gateway})
	}

	logging.Debugf("result----------------------: %v\n", result)
	return cnitypes.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs, client *kubernetes.KubernetesIPAM) error {
	logging.Debugf("Beginning delete for ContainerID: %v", args.ContainerID)

	ctx, cancel := context.WithTimeout(context.Background(), types.DelTimeLimit)
	defer cancel()

	_, err := kubernetes.IPManagement1(ctx, types.Deallocate, client.Config, client)
	if err != nil {
		logging.Verbosef("WARNING: Problem deallocating IP: %s", err)
	}

	return nil
}
