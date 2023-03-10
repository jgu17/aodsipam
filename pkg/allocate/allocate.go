package allocate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"

	"aodsipam/pkg/logging"

	aodsipamtypes "aodsipam/pkg/types"

	"k8s.io/client-go/rest"
)

var (
	svcurl = "http://172.18.0.3:31177"
)

// AssignmentError defines an IP assignment error.
type AssignmentError struct {
	firstIP net.IP
	lastIP  net.IP
	ipnet   net.IPNet
}

type IPAddressObject struct {
	IpPoolName string `json:"ipPoolName"`
	Namespace  string `json:"namespace"`
	IpAddress  string `json:"ipAddress"`
	Subnet     string `json:"subnet"`
}

func (a AssignmentError) Error() string {
	return fmt.Sprintf("Could not allocate IP in range: ip: %v / - %v / range: %#v", a.firstIP, a.lastIP, a.ipnet)
}

// AssignIP assigns an IP using a range and a reserve list.
func AssignIP(ctx context.Context, ipamConf aodsipamtypes.IPAMConfig, config *rest.Config, containerID string, podRef string) (net.IPNet, error) {

	request := map[string]string{
		"networkArmId": ipamConf.NetworkArmId,
		"haksUuid":     ipamConf.HaksUuid,
		"releaseIp":    ipamConf.ReleaseIp,
		"podName":      ipamConf.PodName,
		"podNamespace": ipamConf.PodNamespace,
	}

	postBody, _ := json.Marshal(request)

	logging.Debugf("Allocate -- postBody: %v ", request)

	responseBody := bytes.NewBuffer(postBody)

	resp, err := http.Post(svcurl+"/getIPAddress", "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	logging.Debugf("Allocate -- responseBody: %v ", responseBody)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	logging.Debugf(sb)

	data_obj := IPAddressObject{}
	jsonErr := json.Unmarshal(body, &data_obj)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}
	logging.Debugf("ipaddress object: %v ", data_obj)

	_, ipnet, _ := net.ParseCIDR(data_obj.Subnet)

	newip := net.ParseIP(string(data_obj.IpAddress))

	return net.IPNet{IP: newip, Mask: ipnet.Mask}, nil
}

// DeallocateIP assigns an IP using a range and a reserve list.
func DeallocateIP(ctx context.Context, ipamConf aodsipamtypes.IPAMConfig, config *rest.Config, containerID string) (net.IP, error) {

	postBody, _ := json.Marshal(map[string]string{
		"networkArmId": ipamConf.NetworkArmId,
		"haksUuid":     ipamConf.HaksUuid,
		"releaseIp":    ipamConf.ReleaseIp,
		"podName":      ipamConf.PodName,
		"podNamespace": ipamConf.PodNamespace,
	})

	responseBody := bytes.NewBuffer(postBody)

	resp, err := http.Post(svcurl+"/deleteIPAddress", "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	logging.Debugf(sb)

	data_obj := IPAddressObject{}
	jsonErr := json.Unmarshal(body, &data_obj)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}
	logging.Debugf("ipaddress object: %v ", data_obj)

	return nil, nil
}

// IterateForDeallocation iterates overs currently reserved IPs and the deallocates given the container id.
func IterateForDeallocation(
	reservelist []aodsipamtypes.IPReservation,
	containerID string,
	matchingFunction func(reservation []aodsipamtypes.IPReservation, id string) int) ([]aodsipamtypes.IPReservation, net.IP, error) {

	foundidx := matchingFunction(reservelist, containerID)
	// Check if it's a valid index
	if foundidx < 0 {
		return reservelist, nil, fmt.Errorf("did not find reserved IP for container %v", containerID)
	}

	returnip := reservelist[foundidx].IP

	updatedreservelist := removeIdxFromSlice(reservelist, foundidx)
	return updatedreservelist, returnip, nil
}

func getMatchingIPReservationIndex(reservelist []aodsipamtypes.IPReservation, id string) int {
	foundidx := -1
	for idx, v := range reservelist {
		if v.ContainerID == id {
			foundidx = idx
			break
		}
	}
	return foundidx
}

func removeIdxFromSlice(s []aodsipamtypes.IPReservation, i int) []aodsipamtypes.IPReservation {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// byteSliceAdd adds ar1 to ar2
// note: ar1/ar2 should be 16-length array
func byteSliceAdd(ar1, ar2 []byte) ([]byte, error) {
	if len(ar1) != len(ar2) {
		return nil, fmt.Errorf("byteSliceAdd: bytes array mismatch: %v != %v", len(ar1), len(ar2))
	}
	carry := uint(0)

	sumByte := make([]byte, 16)
	for n := range ar1 {
		sum := uint(ar1[15-n]) + uint(ar2[15-n]) + carry
		carry = 0
		if sum > 255 {
			carry = 1
		}
		sumByte[15-n] = uint8(sum)
	}

	return sumByte, nil
}

// byteSliceSub subtracts ar2 from ar1. This function assumes that ar1 > ar2
// note: ar1/ar2 should be 16-length array
func byteSliceSub(ar1, ar2 []byte) ([]byte, error) {
	if len(ar1) != len(ar2) {
		return nil, fmt.Errorf("byteSliceSub: bytes array mismatch")
	}
	carry := int(0)

	sumByte := make([]byte, 16)
	for n := range ar1 {
		var sum int
		sum = int(ar1[15-n]) - int(ar2[15-n]) - carry
		if sum < 0 {
			sum = 0x100 - int(ar1[15-n]) - int(ar2[15-n]) - carry
			carry = 1
		} else {
			carry = 0
		}
		sumByte[15-n] = uint8(sum)
	}

	return sumByte, nil
}

func ipAddrToUint64(ip net.IP) uint64 {
	num := uint64(0)
	ipArray := []byte(ip)
	for n := range ipArray {
		num = num << 8
		num = uint64(ipArray[n]) + num
	}
	return num
}

func ipAddrFromUint64(num uint64) net.IP {
	idxByte := make([]byte, 16)
	i := num
	for n := range idxByte {
		idxByte[15-n] = byte(0xff & i)
		i = i >> 8
	}
	return net.IP(idxByte)
}

// IPGetOffset gets offset between ip1 and ip2. This assumes ip1 > ip2 (from IP representation point of view)
func IPGetOffset(ip1, ip2 net.IP) uint64 {
	if ip1.To4() == nil && ip2.To4() != nil {
		return 0
	}

	if ip1.To4() != nil && ip2.To4() == nil {
		return 0
	}

	if len([]byte(ip1)) != len([]byte(ip2)) {
		return 0
	}

	ipOffset, _ := byteSliceSub([]byte(ip1.To16()), []byte(ip2.To16()))
	return ipAddrToUint64(ipOffset)
}

// IPAddOffset show IP address plus given offset
func IPAddOffset(ip net.IP, offset uint64) net.IP {
	// Check IPv4 and its offset range
	if ip.To4() != nil && offset >= math.MaxUint32 {
		return nil
	}

	// make pseudo IP variable for offset
	idxIP := ipAddrFromUint64(offset)

	b, _ := byteSliceAdd([]byte(ip.To16()), []byte(idxIP))
	return net.IP(b)
}

// IterateForAssignment iterates given an IP/IPNet and a list of reserved IPs
func IterateForAssignment(ipnet net.IPNet, rangeStart net.IP, rangeEnd net.IP, reservelist []aodsipamtypes.IPReservation, excludeRanges []string, containerID string, podRef string) (net.IP, []aodsipamtypes.IPReservation, error) {
	firstip := rangeStart.To16()
	var lastip net.IP
	if rangeEnd != nil {
		lastip = rangeEnd.To16()
	} else {
		var err error
		firstip, lastip, err = GetIPRange(rangeStart, ipnet)
		if err != nil {
			logging.Errorf("GetIPRange request failed with: %v", err)
			return net.IP{}, reservelist, err
		}
	}
	logging.Debugf("IterateForAssignment input >> ip: %v | ipnet: %v | first IP: %v | last IP: %v", rangeStart, ipnet, firstip, lastip)

	reserved := make(map[string]bool)
	for _, r := range reservelist {
		reserved[r.IP.String()] = true
	}

	// excluded,            "192.168.2.229/30", "192.168.1.229/30",
	excluded := []*net.IPNet{}
	for _, v := range excludeRanges {
		_, subnet, _ := net.ParseCIDR(v)
		excluded = append(excluded, subnet)
	}

	// Iterate every IP address in the range
	var assignedip net.IP
	performedassignment := false
	endip := IPAddOffset(lastip, uint64(1))
	for i := firstip; !i.Equal(endip); i = IPAddOffset(i, uint64(1)) {
		// if already reserved, skip it
		if reserved[i.String()] {
			continue
		}

		// Lastly, we need to check if this IP is within the range of excluded subnets
		isAddrExcluded := false
		for _, subnet := range excluded {
			if subnet.Contains(i) {
				isAddrExcluded = true
				firstExcluded, _, _ := net.ParseCIDR(subnet.String())
				_, lastExcluded, _ := GetIPRange(firstExcluded, *subnet)
				if lastExcluded != nil {
					if i.To4() != nil {
						// exclude broadcast address
						i = IPAddOffset(lastExcluded, uint64(1))
					} else {
						i = lastExcluded
					}
					logging.Debugf("excluding %v and moving to the next available ip: %v", subnet, i)
				}
			}
		}
		if isAddrExcluded {
			continue
		}

		// Ok, this one looks like we can assign it!
		performedassignment = true

		assignedip = i
		logging.Debugf("Reserving IP: |%v|", assignedip.String()+" "+containerID)
		reservelist = append(reservelist, aodsipamtypes.IPReservation{IP: assignedip, ContainerID: containerID, PodRef: podRef})
		break
	}

	if !performedassignment {
		return net.IP{}, reservelist, AssignmentError{firstip, lastip, ipnet}
	}

	return assignedip, reservelist, nil
}

func mergeIPAddress(net, host []byte) ([]byte, error) {
	if len(net) != len(host) {
		return nil, fmt.Errorf("not matched")
	}
	addr := append([]byte{}, net...)
	for i := range net {
		addr[i] = net[i] | host[i]
	}
	return addr, nil
}

// GetIPRange returns the first and last IP in a range
func GetIPRange(ip net.IP, ipnet net.IPNet) (net.IP, net.IP, error) {
	mask := ipnet.Mask
	ones, bits := mask.Size()
	masklen := bits - ones

	// Error when the mask isn't large enough.
	if masklen < 2 {
		return nil, nil, fmt.Errorf("net mask is too short, must be 2 or more: %v", masklen)
	}

	// get network part
	network := ip.Mask(ipnet.Mask)
	// get bitmask for host
	hostMask := net.IPMask(append([]byte{}, ipnet.Mask...))
	for i, n := range hostMask {
		hostMask[i] = ^n
	}
	// get host part of ip
	first := ip.Mask(net.IPMask(hostMask))
	// if ip is just same as ipnet.IP, i.e. just network address,
	// increment it for start ip
	if ip.Equal(ipnet.IP) {
		first[len(first)-1] = 0x1
	}
	// calculate last byte
	last := hostMask
	// if IPv4 case, decrement 1 for broadcasting address
	if ip.To4() != nil {
		last[len(last)-1]--
	}
	// get first ip and last ip based on network part + host part
	firstIPbyte, _ := mergeIPAddress([]byte(network), first)
	lastIPbyte, _ := mergeIPAddress([]byte(network), last)
	firstIP := net.IP(firstIPbyte).To16()
	lastIP := net.IP(lastIPbyte).To16()

	return firstIP, lastIP, nil
}

// IsIPv4 checks if an IP is v4.
func IsIPv4(checkip net.IP) bool {
	return checkip.To4() != nil
}
