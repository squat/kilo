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

//go:build linux
// +build linux

package wireguard

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// DefaultMTU is the the default MTU used by WireGuard.
const DefaultMTU = 1420

// WireGuardOverhead is the overhead in bytes added by WireGuard encapsulation (IPv4).
// IPv4 header (20) + UDP header (8) + WireGuard header (32) + WireGuard cookie (16) + padding (4) = 80.
const WireGuardOverhead = 80

type wgLink struct {
	a netlink.LinkAttrs
	t string
}

func (w wgLink) Attrs() *netlink.LinkAttrs {
	return &w.a
}

func (w wgLink) Type() string {
	return w.t
}

// New returns a WireGuard interface with the given name.
// If the interface exists, its index is returned.
// Otherwise, a new interface is created.
// The function also returns a boolean to indicate if the interface was created.
func New(name string, mtu uint) (int, bool, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return link.Attrs().Index, false, nil
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return 0, false, fmt.Errorf("failed to get links: %v", err)
	}
	wl := wgLink{a: netlink.NewLinkAttrs(), t: "wireguard"}
	wl.a.Name = name
	wl.a.MTU = int(mtu)
	if err := netlink.LinkAdd(wl); err != nil {
		return 0, false, fmt.Errorf("failed to create interface %s: %v", name, err)
	}
	link, err = netlink.LinkByName(name)
	if err != nil {
		return 0, false, fmt.Errorf("failed to get interface index: %v", err)
	}
	return link.Attrs().Index, true, nil
}

// SetMTU sets the MTU of the given interface if it differs from the current value.
func SetMTU(index int, mtu uint) error {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return fmt.Errorf("failed to get link: %v", err)
	}
	if link.Attrs().MTU == int(mtu) {
		return nil
	}
	return netlink.LinkSetMTU(link, int(mtu))
}
