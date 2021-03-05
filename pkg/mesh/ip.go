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
	"net"
	"sort"
)

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

func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
}

func isPublic(ip net.IP) bool {
	// Check RFC 1918 addresses.
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		// Check for 10.0.0.0/8.
		case ip4[0] == 10:
			return false
		// Check for 172.16.0.0/12.
		case ip4[0] == 172 && ip4[1]&0xf0 != 0:
			return false
		// Check for 192.168.0.0/16.
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	// Check RFC 4193 addresses.
	if len(ip) == net.IPv6len {
		switch {
		// Check for fd00::/8.
		case ip[0] == 0xfd && ip[1] == 0x00:
			return false
		default:
			return true
		}
	}
	return false
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
