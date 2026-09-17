//go:build linux

package tun

import (
	"errors"
	"net"
	"slices"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Kept separate from Android service setup so reconciliation can be tested
// without a VpnService or privileged netlink access.
func reconcileBypassRoutes(family int, current, desired []netlink.Route, deleteRoute, replaceRoute func(*netlink.Route) error) (int, error) {
	desiredByDestination := make(map[string]*netlink.Route, len(desired))
	for index := range desired {
		desiredByDestination[desired[index].Dst.String()] = &desired[index]
	}
	matched := make(map[string]bool, len(desired))
	var changed int
	for index := range current {
		currentRoute := &current[index]
		if currentRoute.Dst == nil {
			currentRoute.Dst = defaultDestination(family)
		}
		destination := currentRoute.Dst.String()
		desiredRoute, exists := desiredByDestination[destination]
		if exists && bypassRouteEquals(currentRoute, desiredRoute) {
			matched[destination] = true
			continue
		}
		// RouteReplace only overwrites a route with the same metric; a
		// current route with another metric would survive alongside it.
		// Delete a legacy kernel/RA route before replacing its protocol, so
		// Android's route observers receive RTM_DELROUTE for the old route.
		// They ignore RTM_NEWROUTE for our static replacement.
		if !exists || currentRoute.Priority != desiredRoute.Priority || currentRoute.Protocol != desiredRoute.Protocol {
			err := deleteRoute(currentRoute)
			if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				return changed, E.Cause(err, "delete bypass route ", currentRoute.Dst)
			}
			changed++
		}
	}
	for index := range desired {
		desiredRoute := &desired[index]
		if matched[desiredRoute.Dst.String()] {
			continue
		}
		err := replaceRoute(desiredRoute)
		if err != nil {
			return changed, E.Cause(err, "add bypass route ", desiredRoute.Dst)
		}
		changed++
	}
	return changed, nil
}

func bypassRouteEquals(left *netlink.Route, right *netlink.Route) bool {
	return left.Protocol == right.Protocol &&
		left.Type == right.Type &&
		left.MTU == right.MTU &&
		left.LinkIndex == right.LinkIndex &&
		left.Scope == right.Scope &&
		left.Priority == right.Priority &&
		left.Gw.Equal(right.Gw) &&
		routeSourceEquals(left.Src, right.Src)
}

func routeSourceEquals(left *net.IPNet, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.IP.Equal(right.IP) && slices.Equal(left.Mask, right.Mask)
}
