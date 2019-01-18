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
	"bytes"
	"fmt"
	"os/exec"

	"github.com/vishvananda/netlink"
)

const (
	ipipHeaderSize = 20
	tunnelName     = "tunl0"
)

// NewIPIP creates an IPIP interface using the base interface
// to derive the tunnel's MTU.
func NewIPIP(baseIndex int) (int, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		// If we failed to find the tunnel, then it probably simply does not exist.
		cmd := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return 0, fmt.Errorf("failed to create IPIP tunnel: %s", stderr.String())
		}
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			return 0, fmt.Errorf("failed to get tunnel device: %v", err)
		}
	}

	base, err := netlink.LinkByIndex(baseIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to get base device: %v", err)
	}

	mtu := base.Attrs().MTU - ipipHeaderSize
	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return 0, fmt.Errorf("failed to set tunnel MTU: %v", err)
	}

	return link.Attrs().Index, nil
}
