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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

type section string
type key string

const (
	separator                      = "="
	dumpSeparator                  = "\t"
	dumpNone                       = "(none)"
	dumpOff                        = "off"
	interfaceSection       section = "Interface"
	peerSection            section = "Peer"
	listenPortKey          key     = "ListenPort"
	allowedIPsKey          key     = "AllowedIPs"
	endpointKey            key     = "Endpoint"
	persistentKeepaliveKey key     = "PersistentKeepalive"
	presharedKeyKey        key     = "PresharedKey"
	privateKeyKey          key     = "PrivateKey"
	publicKeyKey           key     = "PublicKey"
)

type dumpInterfaceIndex int

const (
	dumpInterfacePrivateKeyIndex = iota
	dumpInterfacePublicKeyIndex
	dumpInterfaceListenPortIndex
	dumpInterfaceFWMarkIndex
	dumpInterfaceLen
)

type dumpPeerIndex int

const (
	dumpPeerPublicKeyIndex = iota
	dumpPeerPresharedKeyIndex
	dumpPeerEndpointIndex
	dumpPeerAllowedIPsIndex
	dumpPeerLatestHandshakeIndex
	dumpPeerTransferRXIndex
	dumpPeerTransferTXIndex
	dumpPeerPersistentKeepaliveIndex
	dumpPeerLen
)

// Conf represents a WireGuard configuration file.
type Conf struct {
	Interface *Interface
	Peers     []*Peer
}

// Interface represents the `interface` section of a WireGuard configuration.
type Interface struct {
	ListenPort uint32
	PrivateKey []byte
}

// Peer represents a `peer` section of a WireGuard configuration.
type Peer struct {
	AllowedIPs          []*net.IPNet
	Endpoint            *Endpoint
	PersistentKeepalive int
	PresharedKey        []byte
	PublicKey           []byte
	// The following fields are part of the runtime information, not the configuration.
	LatestHandshake time.Time
}

// DeduplicateIPs eliminates duplicate allowed IPs.
func (p *Peer) DeduplicateIPs() {
	var ips []*net.IPNet
	seen := make(map[string]struct{})
	for _, ip := range p.AllowedIPs {
		if _, ok := seen[ip.String()]; ok {
			continue
		}
		ips = append(ips, ip)
		seen[ip.String()] = struct{}{}
	}
	p.AllowedIPs = ips
}

// Endpoint represents an `endpoint` key of a `peer` section.
type Endpoint struct {
	DNSOrIP
	Port uint32
}

// String prints the string representation of the endpoint.
func (e *Endpoint) String() string {
	if e == nil {
		return ""
	}
	dnsOrIP := e.DNSOrIP.String()
	if e.IP != nil && len(e.IP) == net.IPv6len {
		dnsOrIP = "[" + dnsOrIP + "]"
	}
	return dnsOrIP + ":" + strconv.FormatUint(uint64(e.Port), 10)
}

// Equal compares two endpoints.
func (e *Endpoint) Equal(b *Endpoint, DNSFirst bool) bool {
	if (e == nil) != (b == nil) {
		return false
	}
	if e != nil {
		if e.Port != b.Port {
			return false
		}
		if DNSFirst {
			// Check the DNS name first if it was resolved.
			if e.DNS != b.DNS {
				return false
			}
			if e.DNS == "" && !e.IP.Equal(b.IP) {
				return false
			}
		} else {
			// IPs take priority, so check them first.
			if !e.IP.Equal(b.IP) {
				return false
			}
			// Only check the DNS name if the IP is empty.
			if e.IP == nil && e.DNS != b.DNS {
				return false
			}
		}
	}

	return true
}

// DNSOrIP represents either a DNS name or an IP address.
// IPs, as they are more specific, are preferred.
type DNSOrIP struct {
	DNS string
	IP  net.IP
}

// String prints the string representation of the struct.
func (d DNSOrIP) String() string {
	if d.IP != nil {
		return d.IP.String()
	}
	return d.DNS
}

// Parse parses a given WireGuard configuration file and produces a Conf struct.
func Parse(buf []byte) *Conf {
	var (
		active  section
		kv      []string
		c       Conf
		err     error
		iface   *Interface
		i       int
		k       key
		line, v string
		peer    *Peer
		port    uint64
	)
	s := bufio.NewScanner(bytes.NewBuffer(buf))
	for s.Scan() {
		line = strings.TrimSpace(s.Text())
		// Skip comments.
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Line is a section title.
		if strings.HasPrefix(line, "[") {
			if peer != nil {
				c.Peers = append(c.Peers, peer)
				peer = nil
			}
			if iface != nil {
				c.Interface = iface
				iface = nil
			}
			active = section(strings.TrimSpace(strings.Trim(line, "[]")))
			switch active {
			case interfaceSection:
				iface = new(Interface)
			case peerSection:
				peer = new(Peer)
			}
			continue
		}
		kv = strings.SplitN(line, separator, 2)
		if len(kv) != 2 {
			continue
		}
		k = key(strings.TrimSpace(kv[0]))
		v = strings.TrimSpace(kv[1])
		switch active {
		case interfaceSection:
			switch k {
			case listenPortKey:
				port, err = strconv.ParseUint(v, 10, 32)
				if err != nil {
					continue
				}
				iface.ListenPort = uint32(port)
			case privateKeyKey:
				iface.PrivateKey = []byte(v)
			}
		case peerSection:
			switch k {
			case allowedIPsKey:
				err = peer.parseAllowedIPs(v)
				if err != nil {
					continue
				}
			case endpointKey:
				err = peer.parseEndpoint(v)
				if err != nil {
					continue
				}
			case persistentKeepaliveKey:
				i, err = strconv.Atoi(v)
				if err != nil {
					continue
				}
				peer.PersistentKeepalive = i
			case presharedKeyKey:
				peer.PresharedKey = []byte(v)
			case publicKeyKey:
				peer.PublicKey = []byte(v)
			}
		}
	}
	if peer != nil {
		c.Peers = append(c.Peers, peer)
	}
	if iface != nil {
		c.Interface = iface
	}
	return &c
}

// Bytes renders a WireGuard configuration to bytes.
func (c *Conf) Bytes() ([]byte, error) {
	var err error
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	if c.Interface != nil {
		if err = writeSection(buf, interfaceSection); err != nil {
			return nil, fmt.Errorf("failed to write interface: %v", err)
		}
		if err = writePKey(buf, privateKeyKey, c.Interface.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to write private key: %v", err)
		}
		if err = writeValue(buf, listenPortKey, strconv.FormatUint(uint64(c.Interface.ListenPort), 10)); err != nil {
			return nil, fmt.Errorf("failed to write listen port: %v", err)
		}
	}
	for i, p := range c.Peers {
		// Add newlines to make the formatting nicer.
		if i == 0 && c.Interface != nil || i != 0 {
			if err = buf.WriteByte('\n'); err != nil {
				return nil, err
			}
		}

		if err = writeSection(buf, peerSection); err != nil {
			return nil, fmt.Errorf("failed to write interface: %v", err)
		}
		if err = writeAllowedIPs(buf, p.AllowedIPs); err != nil {
			return nil, fmt.Errorf("failed to write allowed IPs: %v", err)
		}
		if err = writeEndpoint(buf, p.Endpoint); err != nil {
			return nil, fmt.Errorf("failed to write endpoint: %v", err)
		}
		if err = writeValue(buf, persistentKeepaliveKey, strconv.Itoa(p.PersistentKeepalive)); err != nil {
			return nil, fmt.Errorf("failed to write persistent keepalive: %v", err)
		}
		if err = writePKey(buf, presharedKeyKey, p.PresharedKey); err != nil {
			return nil, fmt.Errorf("failed to write preshared key: %v", err)
		}
		if err = writePKey(buf, publicKeyKey, p.PublicKey); err != nil {
			return nil, fmt.Errorf("failed to write public key: %v", err)
		}
	}
	return buf.Bytes(), nil
}

// Equal checks if two WireGuard configurations are equivalent.
func (c *Conf) Equal(b *Conf) bool {
	if (c.Interface == nil) != (b.Interface == nil) {
		return false
	}
	if c.Interface != nil {
		if c.Interface.ListenPort != b.Interface.ListenPort || !bytes.Equal(c.Interface.PrivateKey, b.Interface.PrivateKey) {
			return false
		}
	}
	if len(c.Peers) != len(b.Peers) {
		return false
	}
	sortPeers(c.Peers)
	sortPeers(b.Peers)
	for i := range c.Peers {
		if len(c.Peers[i].AllowedIPs) != len(b.Peers[i].AllowedIPs) {
			return false
		}
		sortCIDRs(c.Peers[i].AllowedIPs)
		sortCIDRs(b.Peers[i].AllowedIPs)
		for j := range c.Peers[i].AllowedIPs {
			if c.Peers[i].AllowedIPs[j].String() != b.Peers[i].AllowedIPs[j].String() {
				return false
			}
		}
		if !c.Peers[i].Endpoint.Equal(b.Peers[i].Endpoint, false) {
			return false
		}
		if c.Peers[i].PersistentKeepalive != b.Peers[i].PersistentKeepalive || !bytes.Equal(c.Peers[i].PresharedKey, b.Peers[i].PresharedKey) || !bytes.Equal(c.Peers[i].PublicKey, b.Peers[i].PublicKey) {
			return false
		}
	}
	return true
}

func sortPeers(peers []*Peer) {
	sort.Slice(peers, func(i, j int) bool {
		if bytes.Compare(peers[i].PublicKey, peers[j].PublicKey) < 0 {
			return true
		}
		return false
	})
}

func sortCIDRs(cidrs []*net.IPNet) {
	sort.Slice(cidrs, func(i, j int) bool {
		return cidrs[i].String() < cidrs[j].String()
	})
}

func writeAllowedIPs(buf *bytes.Buffer, ais []*net.IPNet) error {
	if len(ais) == 0 {
		return nil
	}
	var err error
	if err = writeKey(buf, allowedIPsKey); err != nil {
		return err
	}
	for i := range ais {
		if i != 0 {
			if _, err = buf.WriteString(", "); err != nil {
				return err
			}
		}
		if _, err = buf.WriteString(ais[i].String()); err != nil {
			return err
		}
	}
	return buf.WriteByte('\n')
}

func writePKey(buf *bytes.Buffer, k key, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	var err error
	if err = writeKey(buf, k); err != nil {
		return err
	}
	if _, err = buf.Write(b); err != nil {
		return err
	}
	return buf.WriteByte('\n')
}

func writeValue(buf *bytes.Buffer, k key, v string) error {
	var err error
	if err = writeKey(buf, k); err != nil {
		return err
	}
	if _, err = buf.WriteString(v); err != nil {
		return err
	}
	return buf.WriteByte('\n')
}

func writeEndpoint(buf *bytes.Buffer, e *Endpoint) error {
	if e == nil {
		return nil
	}
	var err error
	if err = writeKey(buf, endpointKey); err != nil {
		return err
	}
	if _, err = buf.WriteString(e.String()); err != nil {
		return err
	}
	return buf.WriteByte('\n')
}

func writeSection(buf *bytes.Buffer, s section) error {
	var err error
	if err = buf.WriteByte('['); err != nil {
		return err
	}
	if _, err = buf.WriteString(string(s)); err != nil {
		return err
	}
	if err = buf.WriteByte(']'); err != nil {
		return err
	}
	return buf.WriteByte('\n')
}

func writeKey(buf *bytes.Buffer, k key) error {
	var err error
	if _, err = buf.WriteString(string(k)); err != nil {
		return err
	}
	_, err = buf.WriteString(" = ")
	return err
}

var (
	errParseEndpoint = errors.New("could not parse Endpoint")
)

func (p *Peer) parseEndpoint(v string) error {
	var (
		kv      []string
		err     error
		ip, ip4 net.IP
		port    uint64
	)
	kv = strings.Split(v, ":")
	if len(kv) < 2 {
		return errParseEndpoint
	}
	port, err = strconv.ParseUint(kv[len(kv)-1], 10, 32)
	if err != nil {
		return err
	}
	d := DNSOrIP{}
	ip = net.ParseIP(strings.Trim(strings.Join(kv[:len(kv)-1], ":"), "[]"))
	if ip == nil {
		if len(validation.IsDNS1123Subdomain(kv[0])) != 0 {
			return errParseEndpoint
		}
		d.DNS = kv[0]
	} else {
		if ip4 = ip.To4(); ip4 != nil {
			d.IP = ip4
		} else {
			d.IP = ip.To16()
		}
	}

	p.Endpoint = &Endpoint{
		DNSOrIP: d,
		Port:    uint32(port),
	}
	return nil
}

func (p *Peer) parseAllowedIPs(v string) error {
	var (
		ai      *net.IPNet
		kv      []string
		err     error
		i       int
		ip, ip4 net.IP
	)

	kv = strings.Split(v, ",")
	for i = range kv {
		ip, ai, err = net.ParseCIDR(strings.TrimSpace(kv[i]))
		if err != nil {
			return err
		}
		if ip4 = ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		ai.IP = ip
		p.AllowedIPs = append(p.AllowedIPs, ai)
	}
	return nil
}

// ParseDump parses a given WireGuard dump and produces a Conf struct.
func ParseDump(buf []byte) (*Conf, error) {
	// from man wg, show section:
	// If dump is specified, then several lines are printed;
	// the first contains in order separated by tab: private-key, public-key, listen-port, fw‐mark.
	// Subsequent lines are printed for each peer and contain in order separated by tab:
	// public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.
	var (
		active section
		values []string
		c      Conf
		err    error
		iface  *Interface
		peer   *Peer
		port   uint64
		sec    int64
		pka    int
		line   int
	)
	// First line is Interface
	active = interfaceSection
	s := bufio.NewScanner(bytes.NewBuffer(buf))
	for s.Scan() {
		values = strings.Split(s.Text(), dumpSeparator)

		switch active {
		case interfaceSection:
			if len(values) < dumpInterfaceLen {
				return nil, fmt.Errorf("invalid interface line: missing fields (%d < %d)", len(values), dumpInterfaceLen)
			}
			iface = new(Interface)
			for i := range values {
				switch i {
				case dumpInterfacePrivateKeyIndex:
					iface.PrivateKey = []byte(values[i])
				case dumpInterfaceListenPortIndex:
					port, err = strconv.ParseUint(values[i], 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid interface line: error parsing listen-port: %w", err)
					}
					iface.ListenPort = uint32(port)
				}
			}
			c.Interface = iface
			// Next lines are Peers
			active = peerSection
		case peerSection:
			if len(values) < dumpPeerLen {
				return nil, fmt.Errorf("invalid peer line %d: missing fields (%d < %d)", line, len(values), dumpPeerLen)
			}
			peer = new(Peer)

			for i := range values {
				switch i {
				case dumpPeerPublicKeyIndex:
					peer.PublicKey = []byte(values[i])
				case dumpPeerPresharedKeyIndex:
					if values[i] == dumpNone {
						continue
					}
					peer.PresharedKey = []byte(values[i])
				case dumpPeerEndpointIndex:
					if values[i] == dumpNone {
						continue
					}
					err = peer.parseEndpoint(values[i])
					if err != nil {
						return nil, fmt.Errorf("invalid peer line %d: error parsing endpoint: %w", line, err)
					}
				case dumpPeerAllowedIPsIndex:
					if values[i] == dumpNone {
						continue
					}
					err = peer.parseAllowedIPs(values[i])
					if err != nil {
						return nil, fmt.Errorf("invalid peer line %d: error parsing allowed-ips: %w", line, err)
					}
				case dumpPeerLatestHandshakeIndex:
					if values[i] == "0" {
						// Use go zero value, not unix 0 timestamp.
						peer.LatestHandshake = time.Time{}
						continue
					}
					sec, err = strconv.ParseInt(values[i], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("invalid peer line %d: error parsing latest-handshake: %w", line, err)
					}
					peer.LatestHandshake = time.Unix(sec, 0)
				case dumpPeerPersistentKeepaliveIndex:
					if values[i] == dumpOff {
						continue
					}
					pka, err = strconv.Atoi(values[i])
					if err != nil {
						return nil, fmt.Errorf("invalid peer line %d: error parsing persistent-keepalive: %w", line, err)
					}
					peer.PersistentKeepalive = pka
				}
			}
			c.Peers = append(c.Peers, peer)
			peer = nil
		}
		line++
	}
	return &c, nil
}
