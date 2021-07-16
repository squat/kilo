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

// +build linux

package wireguard

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/vishvananda/netlink"
)

// DefaultMTU is the the default MTU used by WireGuard.
const DefaultMTU = 1420

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

// Keys generates a WireGuard private and public key-pair.
func Keys() ([]byte, []byte, error) {
	private, err := GenKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	public, err := PubKey(private)
	return private, public, err
}

// GenKey generates a WireGuard private key.
func GenKey() ([]byte, error) {
	key, err := exec.Command("wg", "genkey").Output()
	return bytes.Trim(key, "\n"), err
}

// PubKey generates a WireGuard public key for a given private key.
func PubKey(key []byte) ([]byte, error) {
	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe to stdin: %v", err)
	}

	go func() {
		defer stdin.Close()
		stdin.Write(key)
	}()

	public, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	return bytes.Trim(public, "\n"), nil
}

// SetConf applies a WireGuard configuration file to the given interface.
func SetConf(iface string, path string) error {
	cmd := exec.Command("wg", "setconf", iface, path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply the WireGuard configuration: %s", stderr.String())
	}
	return nil
}

// ShowConf gets the WireGuard configuration for the given interface.
func ShowConf(iface string) ([]byte, error) {
	cmd := exec.Command("wg", "showconf", iface)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to read the WireGuard configuration: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}

// ShowDump gets the WireGuard configuration and runtime information for the given interface.
func ShowDump(iface string) ([]byte, error) {
	cmd := exec.Command("wg", "show", iface, "dump")
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to read the WireGuard dump output: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}
