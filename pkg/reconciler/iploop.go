package reconciler

import (
	"context"
	"fmt"
	"net"
	"time"

	"aodsipam/pkg/allocate"
	"aodsipam/pkg/kubernetes"
	"aodsipam/pkg/logging"
	"aodsipam/pkg/types"

	v1 "k8s.io/api/core/v1"
)

type ReconcileLooper struct {
	k8sClient        kubernetes.Client
	liveAodsIpamPods map[string]podWrapper
	orphanedIPs      []OrphanedIPReservations
	requestTimeout   int
}

type OrphanedIPReservations struct {
	Allocations []types.IPReservation
}

func NewReconcileLooperWithKubeconfig(ctx context.Context, kubeconfigPath string, timeout int) (*ReconcileLooper, error) {
	logging.Debugf("NewReconcileLooper - Kubernetes config file located at: %s", kubeconfigPath)
	k8sClient, err := kubernetes.NewClientViaKubeconfig(kubeconfigPath, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, logging.Errorf("failed to instantiate the Kubernetes client: %+v", err)
	}
	return NewReconcileLooperWithClient(ctx, k8sClient, timeout)
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
	ipPools, err := k8sClient.ListIPPools(ctx)
	if err != nil {
		return nil, logging.Errorf("failed to retrieve all IP pools: %v", err)
	}

	pods, err := k8sClient.ListPods(ctx)
	if err != nil {
		return nil, err
	}

	aodsIpamPodRefs := getPodRefsServedByAodsIpam(ipPools)
	looper := &ReconcileLooper{
		k8sClient:        *k8sClient,
		liveAodsIpamPods: indexPods(pods, aodsIpamPodRefs),
		requestTimeout:   timeout,
	}

	if err := looper.findOrphanedIPsPerPool(ipPools); err != nil {
		return nil, err
	}

	if err := looper.findClusterWideIPReservations(ctx); err != nil {
		return nil, err
	}
	return looper, nil
}

func (rl ReconcileLooper) isPodAlive(podRef string, ip string) bool {
	for livePodRef, livePod := range rl.liveAodsIpamPods {
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

func (rl *ReconcileLooper) findClusterWideIPReservations(ctx context.Context) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(rl.requestTimeout)*time.Second)
	defer cancel()

	clusterWideIPReservations, err := rl.k8sClient.ListOverlappingIPs(ctxWithTimeout)
	if err != nil {
		return logging.Errorf("failed to list all OverLappingIPs: %v", err)
	}

	for _, clusterWideIPReservation := range clusterWideIPReservations {
		ip := clusterWideIPReservation.GetName()
		podRef := clusterWideIPReservation.Spec.PodRef

		if !rl.isPodAlive(podRef, ip) {
			logging.Debugf("pod ref %s is not listed in the live pods list", podRef)
			rl.orphanedClusterWideIPs = append(rl.orphanedClusterWideIPs, clusterWideIPReservation)
		}
	}

	return nil
}

func findOutPodRefsToDeallocateIPsFrom(orphanedIP OrphanedIPReservations) []string {
	var podRefsToDeallocate []string
	for _, orphanedAllocation := range orphanedIP.Allocations {
		podRefsToDeallocate = append(podRefsToDeallocate, orphanedAllocation.PodRef)
	}
	return podRefsToDeallocate
}
