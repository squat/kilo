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

package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
	ipamallocator "github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/go-kit/kit/log/level"
	"github.com/vishvananda/netlink"
)

const cniDeviceName = "kube-bridge"

// Try to get the CNI device index.
// Return 0 if not found and any error encountered.
func cniDeviceIndex() (int, error) {
	i, err := netlink.LinkByName(cniDeviceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return i.Attrs().Index, nil
}

// updateCNIConfig will try to update the local node's CNI config.
func (m *Mesh) updateCNIConfig() {
	m.mu.Lock()
	n := m.nodes[m.hostname]
	m.mu.Unlock()
	if n == nil || n.Subnet == nil {
		level.Debug(m.logger).Log("msg", "local node does not have a valid subnet assigned")
		return
	}

	cidr, err := getCIDRFromCNI(m.cniPath)
	if err != nil {
		level.Warn(m.logger).Log("msg", "failed to get CIDR from CNI file; overwriting it", "err", err.Error())
	}

	if ipNetsEqual(cidr, n.Subnet) {
		return
	}

	if cidr == nil {
		level.Info(m.logger).Log("msg", "CIDR in CNI file is empty")
	} else {
		level.Info(m.logger).Log("msg", "CIDR in CNI file is not empty; overwriting", "old", cidr.String(), "new", n.Subnet.String())
	}

	level.Info(m.logger).Log("msg", "setting CIDR in CNI file", "CIDR", n.Subnet.String())
	if err := setCIDRInCNI(m.cniPath, n.Subnet); err != nil {
		level.Warn(m.logger).Log("msg", "failed to set CIDR in CNI file", "err", err.Error())
	}
}

// getCIDRFromCNI finds the CIDR for the node from the CNI configuration file.
func getCIDRFromCNI(path string) (*net.IPNet, error) {
	var cidr net.IPNet
	var ic *ipamallocator.IPAMConfig

	cl, err := libcni.ConfListFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CNI config list file: %v", err)
	}
	for _, conf := range cl.Plugins {
		if conf.Network.IPAM.Type != "" {
			ic, _, err = ipamallocator.LoadIPAMConfig(conf.Bytes, "")
			if err != nil {
				return nil, fmt.Errorf("failed to read IPAM config from CNI config list file: %v", err)
			}
			for _, set := range ic.Ranges {
				for _, r := range set {
					cidr = net.IPNet(r.Subnet)
					if (&cidr).String() == "" {
						continue
					}
					// Return the first subnet we find.
					return &cidr, nil
				}
			}
		}
	}
	return nil, nil
}

// setCIDRInCNI sets the CIDR allocated to the node in the CNI configuration file.
func setCIDRInCNI(path string, cidr *net.IPNet) error {
	f, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read CNI config list file: %v", err)
	}
	raw := make(map[string]interface{})
	if err := json.Unmarshal(f, &raw); err != nil {
		return fmt.Errorf("failed to parse CNI config file: %v", err)
	}
	if _, ok := raw["plugins"]; !ok {
		return errors.New("failed to find plugins in CNI config file")
	}
	plugins, ok := raw["plugins"].([]interface{})
	if !ok {
		return errors.New("failed to parse plugins in CNI config file")
	}

	var found bool
	for i := range plugins {
		p, ok := plugins[i].(map[string]interface{})
		if !ok {
			return fmt.Errorf("failed to parse plugin %d in CNI config file", i)
		}
		if _, ok := p["ipam"]; !ok {
			continue
		}
		ipam, ok := p["ipam"].(map[string]interface{})
		if !ok {
			return errors.New("failed to parse IPAM configuration in CNI config file")
		}
		ipam["ranges"] = []ipamallocator.RangeSet{
			{
				{
					Subnet: types.IPNet(*cidr),
				},
			},
		}
		found = true
	}

	if !found {
		return errors.New("failed to set subnet CIDR in CNI config file; file appears invalid")
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("failed to marshal CNI config: %v", err)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		return fmt.Errorf("failed to write CNI config file to disk: %v", err)
	}
	return nil
}
