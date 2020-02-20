// Copyright 2019 the Kilo authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mesh

import (
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
)

// getIP returns a private and public IP address for the local node.
// It selects the private IP address in the following order:
// - private IP to which hostname resolves
// - private IP assigned to interface of default route
// - private IP assigned to local interface
// - public IP to which hostname resolves
// - public IP assigned to interface of default route
// - public IP assigned to local interface
// It selects the public IP address in the following order:
// - public IP to which hostname resolves
// - public IP assigned to interface of default route
// - public IP assigned to local interface
// - private IP to which hostname resolves
// - private IP assigned to interface of default route
// - private IP assigned to local interface
// - if no IP was found, return nil and an error.
func getIP(hostname string, ignoreIfaces ...int) (*net.IPNet, *net.IPNet, error) {
	ignore := make(map[string]struct{})
	for i := range ignoreIfaces {
		if ignoreIfaces[i] == 0 {
			// Only ignore valid interfaces.
			continue
		}
		iface, err := net.InterfaceByIndex(ignoreIfaces[i])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find interface %d: %v", ignoreIfaces[i], err)
		}
		ips, err := ipsForInterface(iface)
		if err != nil {
			return nil, nil, err
		}
		for _, ip := range ips {
			ignore[ip.String()] = struct{}{}
			ignore[oneAddressCIDR(ip.IP).String()] = struct{}{}
		}
	}
	var hostPriv, hostPub []*net.IPNet
	{
		// Check IPs to which hostname resolves first.
		ips := ipsForHostname(hostname)
		for _, ip := range ips {
			ok, mask, err := assignedToInterface(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to search locally assigned addresses: %v", err)
			}
			if !ok {
				continue
			}
			ip.Mask = mask
			if isPublic(ip) {
				hostPub = append(hostPub, ip)
				continue
			}
			hostPriv = append(hostPriv, ip)
		}
		sortIPs(hostPriv)
		sortIPs(hostPub)
	}

	var defaultPriv, defaultPub []*net.IPNet
	{
		// Check IPs on interface for default route next.
		iface, err := defaultInterface()
		if err != nil {
			return nil, nil, err
		}
		ips, err := ipsForInterface(iface)
		if err != nil {
			return nil, nil, err
		}
		for _, ip := range ips {
			if isLocal(ip.IP) {
				continue
			}
			if isPublic(ip) {
				defaultPub = append(defaultPub, ip)
				continue
			}
			defaultPriv = append(defaultPriv, ip)
		}
		sortIPs(defaultPriv)
		sortIPs(defaultPub)
	}

	var interfacePriv, interfacePub []*net.IPNet
	{
		// Finally look for IPs on all interfaces.
		ips, err := ipsForAllInterfaces()
		if err != nil {
			return nil, nil, err
		}
		for _, ip := range ips {
			if isLocal(ip.IP) {
				continue
			}
			if isPublic(ip) {
				interfacePub = append(interfacePub, ip)
				continue
			}
			interfacePriv = append(interfacePriv, ip)
		}
		sortIPs(interfacePriv)
		sortIPs(interfacePub)
	}

	var priv, pub, tmpPriv, tmpPub []*net.IPNet
	tmpPriv = append(tmpPriv, hostPriv...)
	tmpPriv = append(tmpPriv, defaultPriv...)
	tmpPriv = append(tmpPriv, interfacePriv...)
	tmpPub = append(tmpPub, hostPub...)
	tmpPub = append(tmpPub, defaultPub...)
	tmpPub = append(tmpPub, interfacePub...)
	for i := range tmpPriv {
		if _, ok := ignore[tmpPriv[i].String()]; ok {
			continue
		}
		priv = append(priv, tmpPriv[i])
	}
	for i := range tmpPub {
		if _, ok := ignore[tmpPub[i].String()]; ok {
			continue
		}
		pub = append(pub, tmpPub[i])
	}
	if len(priv) == 0 && len(pub) == 0 {
		return nil, nil, errors.New("no valid IP was found")
	}
	if len(priv) == 0 {
		priv = pub
	}
	if len(pub) == 0 {
		pub = priv
	}
	return priv[0], pub[0], nil
}

// sortIPs sorts IPs so the result is stable.
// It will first sort IPs by type, to prefer selecting
// IPs of the same type, and then by value.
func sortIPs(ips []*net.IPNet) {
	sort.Slice(ips, func(i, j int) bool {
		i4, j4 := ips[i].IP.To4(), ips[j].IP.To4()
		if i4 != nil && j4 == nil {
			return true
		}
		if j4 != nil && i4 == nil {
			return false
		}
		return ips[i].String() < ips[j].String()
	})
}

func assignedToInterface(ip *net.IPNet) (bool, net.IPMask, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return false, nil, fmt.Errorf("failed to list interfaces: %v", err)
	}
	// Sort the links for stability.
	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return false, nil, fmt.Errorf("failed to list addresses for %s: %v", link.Attrs().Name, err)
		}
		// Sort the IPs for stability.
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].String() < addrs[j].String()
		})
		for i := range addrs {
			if ip.IP.Equal(addrs[i].IP) {
				return true, addrs[i].Mask, nil
			}
		}
	}
	return false, nil, nil
}

func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
}

func isPublic(ip *net.IPNet) bool {
	// Check RFC 1918 addresses.
	if ip4 := ip.IP.To4(); ip4 != nil {
		switch true {
		// Check for 10.0.0.0/8.
		case ip4[0] == 10:
			return false
		// Check for 172.16.0.0/12.
		case ip4[0] == 172 && ip4[1]&0xf0 == 0x01:
			return false
		// Check for 192.168.0.0/16.
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	// Check RFC 4193 addresses.
	if len(ip.IP) == net.IPv6len {
		switch true {
		// Check for fd00::/8.
		case ip.IP[0] == 0xfd && ip.IP[1] == 0x00:
			return false
		default:
			return true
		}
	}
	return false
}

// ipsForHostname returns a slice of IPs to which the
// given hostname resolves.
func ipsForHostname(hostname string) []*net.IPNet {
	if ip := net.ParseIP(hostname); ip != nil {
		return []*net.IPNet{oneAddressCIDR(ip)}
	}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// Most likely the hostname is not resolvable.
		return nil
	}
	nets := make([]*net.IPNet, len(ips))
	for i := range ips {
		nets[i] = oneAddressCIDR(ips[i])
	}
	return nets
}

// ipsForAllInterfaces returns a slice of IPs assigned to all the
// interfaces on the host.
func ipsForAllInterfaces() ([]*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %v", err)
	}
	var nets []*net.IPNet
	for _, iface := range ifaces {
		ips, err := ipsForInterface(&iface)
		if err != nil {
			return nil, fmt.Errorf("failed to list addresses for %s: %v", iface.Name, err)
		}
		nets = append(nets, ips...)
	}
	return nets, nil
}

// ipsForInterface returns a slice of IPs assigned to the given interface.
func ipsForInterface(iface *net.Interface) ([]*net.IPNet, error) {
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, fmt.Errorf("failed to get link: %s", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses for %s: %v", iface.Name, err)
	}
	var ips []*net.IPNet
	for _, a := range addrs {
		if a.IPNet != nil {
			ips = append(ips, a.IPNet)
		}
	}
	return ips, nil
}

// interfacesForIP returns a slice of interfaces withthe given IP.
func interfacesForIP(ip *net.IPNet) ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %v", err)
	}
	var interfaces []net.Interface
	for _, iface := range ifaces {
		ips, err := ipsForInterface(&iface)
		if err != nil {
			return nil, fmt.Errorf("failed to list addresses for %s: %v", iface.Name, err)
		}
		for i := range ips {
			if ip.IP.Equal(ips[i].IP) {
				interfaces = append(interfaces, iface)
				break
			}
		}
	}
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interface has %s assigned", ip.String())
	}
	return interfaces, nil
}

// defaultInterface returns the interface for the default route of the host.
func defaultInterface() (*net.Interface, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0" {
			if route.LinkIndex <= 0 {
				return nil, errors.New("failed to determine interface of route")
			}
			return net.InterfaceByIndex(route.LinkIndex)
		}
	}

	return nil, errors.New("failed to find default route")
}

type allocator struct {
	bits    int
	ones    int
	cidr    *net.IPNet
	current net.IP
}

func newAllocator(cidr net.IPNet) *allocator {
	ones, bits := cidr.Mask.Size()
	current := make(net.IP, len(cidr.IP))
	copy(current, cidr.IP)
	if ip4 := current.To4(); ip4 != nil {
		current = ip4
	}

	return &allocator{
		bits:    bits,
		ones:    ones,
		cidr:    &cidr,
		current: current,
	}
}

func (a *allocator) next() *net.IPNet {
	if a.current == nil {
		return nil
	}
	for i := len(a.current) - 1; i >= 0; i-- {
		a.current[i]++
		// if we haven't overflowed, then we can exit.
		if a.current[i] != 0 {
			break
		}
	}
	if !a.cidr.Contains(a.current) {
		a.current = nil
	}
	ip := make(net.IP, len(a.current))
	copy(ip, a.current)

	return &net.IPNet{IP: ip, Mask: net.CIDRMask(a.ones, a.bits)}
}
