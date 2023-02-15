package main

import (
	"fmt"
	"net"
)

func main1() {

	ipaddress := "192.168.2.225"
	//mask := "fffffff0"

	ipnet := net.IPNet{
		IP:   net.ParseIP(ipaddress),
		Mask: net.CIDRMask(32, 32),
	}
	newips := []net.IPNet{
		ipnet,
	}

	fmt.Println(fmt.Sprintf("newips static4--------------------: %v", newips))
}
