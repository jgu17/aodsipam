package allocate

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"aodsipam/pkg/logging"
	"aodsipam/pkg/types"

	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	ipamv1 "github.com/metal3-io/ip-address-manager/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AssignmentError defines an IP assignment error.
type AssignmentError struct {
	firstIP net.IP
	lastIP  net.IP
	ipnet   net.IPNet
}

func (a AssignmentError) Error() string {
	return fmt.Sprintf("Could not allocate IP in range: ip: %v / - %v / range: %#v", a.firstIP, a.lastIP, a.ipnet)
}

// AssignIP assigns an IP using a range and a reserve list.
func AssignIP(ctx context.Context, config *rest.Config, containerID string, podRef string) (net.IPNet, error) {

	crScheme := runtime.NewScheme()
	ipamv1.AddToScheme(crScheme)

	cl, err := client.New(config, client.Options{
		Scheme: crScheme,
	})

	if err != nil {
		logging.Errorf("could not get Client", err)
		return net.IPNet{}, err
	}

	foundIPPool := &ipamv1.IPPool{}
	err = cl.Get(ctx, apitypes.NamespacedName{Name: "l3network11-ipv4", Namespace: "default"}, foundIPPool)
	if err != nil {
		logging.Errorf("could not get foundIPPool", err)
		if apierrors.IsNotFound(err) {
			logging.Debugf("ip pool does not exist")
			return net.IPNet{}, err
		}
		logging.Errorf("could not get ippool", err)
		return net.IPNet{}, err
	}

	logging.Debugf("getting IP pool ---------- ippool: %v ", *foundIPPool)

	logging.Debugf("getting IP pool Subnet---------- ippool.subnet: %v ", string(*foundIPPool.Spec.Pools[0].Subnet))
	_, ipnet, _ := net.ParseCIDR(string(*foundIPPool.Spec.Pools[0].Subnet))

	logging.Debugf("getting IP pool MASK---------- ippool.MASK: %v ", ipnet.Mask)

	ipClaim := &ipamv1.IPClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "l3network-504-32eb7f2f-ipv4",
			Namespace: "default",
		},
		Spec: ipamv1.IPClaimSpec{
			Pool: corev1.ObjectReference{
				Name:      "l3network11-ipv4",
				Namespace: "default",
			},
		},
	}

	// IPClaim Status not getting updated when claim is in different namespace than pool
	logging.Debugf("Creating IP Claim -- ipClaim: %v ", ipClaim)

	err = createObject(cl, ctx, ipClaim)
	if err != nil {
		logging.Errorf("Error in creating ipclaim", err)
		return net.IPNet{}, err
	}

	logging.Debugf("IP Claim created and waiting for 30 second-- ipClaim: %v ", ipClaim)

	// Setup the basics here.

	//var timeout = flag.Int("timeout", 30, "timeout in seconds")

	// err = waitForIPClaim(ctx, cl, "default", "l3network-504-32eb7f2f-ipv4", time.Duration(*timeout)*time.Second)
	// if err != nil {
	// 	return net.IPNet{}, fmt.Errorf("The ipclaim never returned ip address")
	// }

	time.Sleep(10 * time.Second)

	err = cl.Get(ctx, apitypes.NamespacedName{Name: "l3network-504-32eb7f2f-ipv4", Namespace: "default"}, ipClaim)
	if err != nil {
		return net.IPNet{}, fmt.Errorf("Error in retriving the ipclaim")
	}

	if ipClaim.Status.Address == nil {
		return net.IPNet{}, fmt.Errorf("ipclaim did not return ip address")
	}

	logging.Debugf("performIPv4Allocation: foundIPClaim.Status.Address.Name: " + ipClaim.Status.Address.Name)
	rnClaimIPAddress := &ipamv1.IPAddress{}
	err = cl.Get(ctx, apitypes.NamespacedName{Namespace: ipClaim.Status.Address.Namespace, Name: ipClaim.Status.Address.Name}, rnClaimIPAddress)
	if err != nil {
		return net.IPNet{}, fmt.Errorf("Error in retriving the ipaddress")
	}
	logging.Debugf("rnClaimIPAddress.Spec.Address: %s", rnClaimIPAddress.Spec.Address)
	logging.Debugf("rnClaimIPAddress.Spec.Prefix: %d", rnClaimIPAddress.Spec.Prefix)
	fullClaim := string(rnClaimIPAddress.Spec.Address) + "/" + fmt.Sprint(rnClaimIPAddress.Spec.Prefix)
	logging.Debugf("fullClaim: %s", fullClaim)
	newip := net.ParseIP(string(rnClaimIPAddress.Spec.Address))

	return net.IPNet{IP: newip, Mask: ipnet.Mask}, nil
}

func createObject(cl client.Client, ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	err := cl.Create(ctx, obj.DeepCopyObject().(client.Object), opts...)
	logging.Errorf("could not createObject", err)
	if apierrors.IsAlreadyExists(err) {
		logging.Debugf("createIPv4Claim: ipclaim already exist: l3network-504-32eb7f2f-ipv4")
		return nil
	}
	return err
}

// DeallocateIP assigns an IP using a range and a reserve list.
func DeallocateIP(ctx context.Context, config *rest.Config, containerID string) (net.IP, error) {

	crScheme := runtime.NewScheme()
	ipamv1.AddToScheme(crScheme)

	cl, err := client.New(config, client.Options{
		Scheme: crScheme,
	})

	if err != nil {
		return nil, err
	}

	ipClaim := &ipamv1.IPClaim{}
	err = cl.Get(ctx, apitypes.NamespacedName{Name: "l3network-504-32eb7f2f-ipv4", Namespace: "default"}, ipClaim)
	if err != nil {
		return nil, fmt.Errorf("Error in retriving the ipclaim")
	}

	if ipClaim.Status.Address == nil {
		return nil, fmt.Errorf("ipclaim did not return ip address")
	}

	logging.Debugf("Deleting the ipclaim: " + ipClaim.Status.Address.Name)
	err = cl.Delete(ctx, ipClaim)
	if err != nil {
		return nil, fmt.Errorf("Error in deleting the ipclaim")
	}

	logging.Debugf("Deallocating given previously used IP: %v", ipClaim.Status.Address)

	return nil, nil
}

// return a condition function that indicates whether the given pod is
// currently running
func getIPAddress(ctx context.Context, cl client.Client, ipclaimName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		fmt.Printf(".") // progress bar!

		ipClaim := &ipamv1.IPClaim{}
		err := cl.Get(ctx, apitypes.NamespacedName{Name: ipclaimName, Namespace: "default"}, ipClaim)
		if err != nil {
			return false, err
		}

		if ipClaim.Status.Address == nil {
			return false, fmt.Errorf("ipclaim ran to completion")
		} else {
			return true, nil
		}
	}
}

// Poll up to timeout seconds for pod to enter running state.
// Returns an error if the pod never enters the running state.
func waitForIPClaim(ctx context.Context, cl client.Client, namespace, ipclaimName string, timeout time.Duration) error {
	return wait.PollImmediate(time.Second, timeout, getIPAddress(ctx, cl, ipclaimName, namespace))
}

// IterateForDeallocation iterates overs currently reserved IPs and the deallocates given the container id.
func IterateForDeallocation(
	reservelist []types.IPReservation,
	containerID string,
	matchingFunction func(reservation []types.IPReservation, id string) int) ([]types.IPReservation, net.IP, error) {

	foundidx := matchingFunction(reservelist, containerID)
	// Check if it's a valid index
	if foundidx < 0 {
		return reservelist, nil, fmt.Errorf("did not find reserved IP for container %v", containerID)
	}

	returnip := reservelist[foundidx].IP

	updatedreservelist := removeIdxFromSlice(reservelist, foundidx)
	return updatedreservelist, returnip, nil
}

func getMatchingIPReservationIndex(reservelist []types.IPReservation, id string) int {
	foundidx := -1
	for idx, v := range reservelist {
		if v.ContainerID == id {
			foundidx = idx
			break
		}
	}
	return foundidx
}

func removeIdxFromSlice(s []types.IPReservation, i int) []types.IPReservation {
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
func IterateForAssignment(ipnet net.IPNet, rangeStart net.IP, rangeEnd net.IP, reservelist []types.IPReservation, excludeRanges []string, containerID string, podRef string) (net.IP, []types.IPReservation, error) {
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
		reservelist = append(reservelist, types.IPReservation{IP: assignedip, ContainerID: containerID, PodRef: podRef})
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
