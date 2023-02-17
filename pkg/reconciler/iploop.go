package reconciler

import (
	"context"
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"

	"aodsipam/pkg/allocate"
	"aodsipam/pkg/logging"
	"aodsipam/pkg/storage"
	"aodsipam/pkg/storage/kubernetes"
	"aodsipam/pkg/types"
)

type ReconcileLooper struct {
	k8sClient           kubernetes.Client
	liveWhereaboutsPods map[string]podWrapper
	orphanedIPs         []OrphanedIPReservations
	requestTimeout      int
}

type OrphanedIPReservations struct {
	Pool        storage.IPPool
	Allocations []types.IPReservation
}

func NewReconcileLooper(ctx context.Context, timeout int) (*ReconcileLooper, error) {
	logging.Debugf("NewReconcileLooper - inferred connection data")

	k8sClient, err := kubernetes.NewClient(time.Duration(timeout) * time.Second)
	if err != nil {
		return nil, logging.Errorf("failed to instantiate the Kubernetes client: %+v", err)
	}
	return NewReconcileLooperWithClient(ctx, k8sClient, timeout)
}

func NewReconcileLooperWithClient(ctx context.Context, k8sClient *kubernetes.Client, timeout int) (*ReconcileLooper, error) {

	pods, err := k8sClient.ListPods(ctx)
	if err != nil {
		return nil, err
	}

	whereaboutsPodRefs := getPodRefsServedByWhereabouts(ipPools)
	looper := &ReconcileLooper{
		k8sClient:           *k8sClient,
		liveWhereaboutsPods: indexPods(pods, whereaboutsPodRefs),
		requestTimeout:      timeout,
	}

	if err := looper.findOrphanedIPsPerPool(ipPools); err != nil {
		return nil, err
	}

	return looper, nil
}

func (rl *ReconcileLooper) findOrphanedIPsPerPool(ipPools []storage.IPPool) error {
	for _, pool := range ipPools {
		orphanIP := OrphanedIPReservations{
			Pool: pool,
		}
		for _, ipReservation := range pool.Allocations() {
			logging.Debugf("the IP reservation: %s", ipReservation)
			if ipReservation.PodRef == "" {
				_ = logging.Errorf("pod ref missing for Allocations: %s", ipReservation)
				continue
			}
			if !rl.isPodAlive(ipReservation.PodRef, ipReservation.IP.String()) {
				logging.Debugf("pod ref %s is not listed in the live pods list", ipReservation.PodRef)
				orphanIP.Allocations = append(orphanIP.Allocations, ipReservation)
			}
		}
		if len(orphanIP.Allocations) > 0 {
			rl.orphanedIPs = append(rl.orphanedIPs, orphanIP)
		}
	}

	return nil
}

func (rl ReconcileLooper) isPodAlive(podRef string, ip string) bool {
	for livePodRef, livePod := range rl.liveWhereaboutsPods {
		if podRef == livePodRef {
			livePodIPs := livePod.ips
			logging.Debugf(
				"pod reference %s matches allocation; Allocation IP: %s; PodIPs: %s",
				livePodRef,
				ip,
				livePodIPs)
			_, isFound := livePodIPs[ip]
			return isFound || livePod.phase == v1.PodPending
		}
	}
	return false
}

func composePodRef(pod v1.Pod) string {
	return fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
}

func (rl ReconcileLooper) ReconcileIPPools(ctx context.Context) ([]net.IP, error) {
	matchByPodRef := func(reservations []types.IPReservation, podRef string) int {
		foundidx := -1
		for idx, v := range reservations {
			if v.PodRef == podRef {
				return idx
			}
		}
		return foundidx
	}

	var err error
	var totalCleanedUpIps []net.IP
	for _, orphanedIP := range rl.orphanedIPs {
		currentIPReservations := orphanedIP.Pool.Allocations()
		podRefsToDeallocate := findOutPodRefsToDeallocateIPsFrom(orphanedIP)
		var deallocatedIP net.IP
		for _, podRef := range podRefsToDeallocate {
			currentIPReservations, deallocatedIP, err = allocate.IterateForDeallocation(currentIPReservations, podRef, matchByPodRef)
			if err != nil {
				return nil, err
			}
		}

		logging.Debugf("Going to update the reserve list to: %+v", currentIPReservations)
		if err := orphanedIP.Pool.Update(ctx, currentIPReservations); err != nil {
			return nil, logging.Errorf("failed to update the reservation list: %v", err)
		}
		totalCleanedUpIps = append(totalCleanedUpIps, deallocatedIP)
	}

	return totalCleanedUpIps, nil
}

func findOutPodRefsToDeallocateIPsFrom(orphanedIP OrphanedIPReservations) []string {
	var podRefsToDeallocate []string
	for _, orphanedAllocation := range orphanedIP.Allocations {
		podRefsToDeallocate = append(podRefsToDeallocate, orphanedAllocation.PodRef)
	}
	return podRefsToDeallocate
}
