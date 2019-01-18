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

package iproute

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// RemoveInterface removes an interface.
func RemoveInterface(index int) error {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return fmt.Errorf("failed to get link: %s", err)
	}
	return netlink.LinkDel(link)
}

// Set sets the interface up or down.
func Set(index int, up bool) error {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return fmt.Errorf("failed to get link: %s", err)
	}
	if up {
		return netlink.LinkSetUp(link)
	}
	return netlink.LinkSetDown(link)
}

// SetAddress sets the IP address of an interface.
func SetAddress(index int, cidr *net.IPNet) error {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return fmt.Errorf("failed to get link: %s", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	l := len(addrs)
	for _, addr := range addrs {
		if addr.IP.Equal(cidr.IP) && addr.Mask.String() == cidr.Mask.String() {
			continue
		}
		if err := netlink.AddrDel(link, &addr); err != nil {
			return fmt.Errorf("failed to delete address: %s", err)
		}
		l--
	}
	// The only address left is the desired address, so quit.
	if l == 1 {
		return nil
	}
	return netlink.AddrReplace(link, &netlink.Addr{IPNet: cidr})
}
