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

package wireguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"

	"github.com/vishvananda/netlink"
	"gopkg.in/ini.v1"
)

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

// New creates a new WireGuard interface.
func New(prefix string) (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, fmt.Errorf("failed to list links: %v", err)
	}
	max := 0
	re := regexp.MustCompile(fmt.Sprintf("^%s([0-9]+)$", prefix))
	for _, link := range links {
		if matches := re.FindStringSubmatch(link.Attrs().Name); len(matches) == 2 {
			i, err := strconv.Atoi(matches[1])
			if err != nil {
				// This should never happen.
				return 0, fmt.Errorf("failed to parse digits as an integer: %v", err)
			}
			if i >= max {
				max = i + 1
			}
		}
	}
	name := fmt.Sprintf("%s%d", prefix, max)
	wl := wgLink{a: netlink.NewLinkAttrs(), t: "wireguard"}
	wl.a.Name = name
	if err := netlink.LinkAdd(wl); err != nil {
		return 0, fmt.Errorf("failed to create interface %s: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("failed to get interface index: %v", err)
	}
	return link.Attrs().Index, nil
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
	return exec.Command("wg", "genkey").Output()
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
	return public, nil
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

// CompareConf compares two WireGuard configurations.
// It returns true if they are equal, false if they are not,
// and any error that was encountered.
// Note: CompareConf only goes one level deep, as WireGuard
// configurations are not nested further than that.
func CompareConf(a, b []byte) (bool, error) {
	iniA, err := ini.Load(a)
	if err != nil {
		return false, fmt.Errorf("failed to parse configuration: %v", err)
	}
	iniB, err := ini.Load(b)
	if err != nil {
		return false, fmt.Errorf("failed to parse configuration: %v", err)
	}
	secsA, secsB := iniA.SectionStrings(), iniB.SectionStrings()
	if len(secsA) != len(secsB) {
		return false, nil
	}
	sort.Strings(secsA)
	sort.Strings(secsB)
	var keysA, keysB []string
	var valsA, valsB []string
	for i := range secsA {
		if secsA[i] != secsB[i] {
			return false, nil
		}
		keysA, keysB = iniA.Section(secsA[i]).KeyStrings(), iniB.Section(secsB[i]).KeyStrings()
		if len(keysA) != len(keysB) {
			return false, nil
		}
		sort.Strings(keysA)
		sort.Strings(keysB)
		for j := range keysA {
			if keysA[j] != keysB[j] {
				return false, nil
			}
			valsA, valsB = iniA.Section(secsA[i]).Key(keysA[j]).Strings(","), iniB.Section(secsB[i]).Key(keysB[j]).Strings(",")
			if len(valsA) != len(valsB) {
				return false, nil
			}
			sort.Strings(valsA)
			sort.Strings(valsB)
			for k := range valsA {
				if valsA[k] != valsB[k] {
					return false, nil
				}
			}
		}
	}
	return true, nil
}
