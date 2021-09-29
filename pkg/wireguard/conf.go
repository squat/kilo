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
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/apimachinery/pkg/util/validation"
)

type section string
type key string

const (
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

// Conf represents a WireGuard configuration file.
type Conf struct {
	wgtypes.Config
	// The Peers field is shadowed because every Peer needs the Endpoint field that contains a DNS endpoint.
	Peers []Peer
}

// WGConfig returns a wgytpes.Config from a Conf.
func (c Conf) WGConfig() wgtypes.Config {
	r := c.Config
	wgPs := make([]wgtypes.PeerConfig, len(c.Peers))
	for i, p := range c.Peers {
		wgPs[i] = p.PeerConfig
		if p.Endpoint.Resolved() {
			// We can ingore the error because we already checked if the Endpoint was resolved in the above line.
			wgPs[i].Endpoint, _ = p.Endpoint.UDPAddr(false)
		}
		wgPs[i].ReplaceAllowedIPs = true
	}
	r.Peers = wgPs
	r.ReplacePeers = true
	return r
}

// Endpoint represents a WireGuard endpoint.
type Endpoint struct {
	udpAddr *net.UDPAddr
	addr    string
}

// ParseEndpoint returns an Endpoint from a string.
// The input should look like "10.0.0.0:100", "[ff10::10]:100"
// or "example.com:100".
func ParseEndpoint(endpoint string) *Endpoint {
	if len(endpoint) == 0 {
		return nil
	}
	hostRaw, portRaw, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil
	}
	port, err := strconv.ParseUint(portRaw, 10, 32)
	if err != nil {
		return nil
	}
	if len(validation.IsValidPortNum(int(port))) != 0 {
		return nil
	}
	ip := net.ParseIP(hostRaw)
	if ip == nil {
		if len(validation.IsDNS1123Subdomain(hostRaw)) == 0 {
			return &Endpoint{
				addr: endpoint,
			}
		}
		return nil
	}
	// ResolveUDPAddr will not resolve the endpoint as long as a valid IP and port is given.
	// This should be the case here.
	u, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil
	}
	u.IP = cutIP(u.IP)
	return &Endpoint{
		udpAddr: u,
	}
}

// NewEndpointFromUDPAddr returns an Endpoint from a net.UDPAddr.
func NewEndpointFromUDPAddr(u *net.UDPAddr) *Endpoint {
	if u != nil {
		u.IP = cutIP(u.IP)
	}
	return &Endpoint{
		udpAddr: u,
	}
}

// NewEndpoint returns an Endpoint from a net.IP and port.
func NewEndpoint(ip net.IP, port int) *Endpoint {
	return &Endpoint{
		udpAddr: &net.UDPAddr{
			IP:   cutIP(ip),
			Port: port,
		},
	}
}

// Ready return true, if the Enpoint is ready.
// Ready means that an IP or DN and port exists.
func (e *Endpoint) Ready() bool {
	if e == nil {
		return false
	}
	return (e.udpAddr != nil && e.udpAddr.IP != nil && e.udpAddr.Port > 0) || len(e.addr) > 0
}

// Port returns the port of the Endpoint.
func (e *Endpoint) Port() int {
	if !e.Ready() {
		return 0
	}
	if e.udpAddr != nil {
		return e.udpAddr.Port
	}
	// We can ignore the errors here bacause the returned port will be "".
	// This will result to Port 0 after the conversion to and int.
	_, p, _ := net.SplitHostPort(e.addr)
	port, _ := strconv.ParseUint(p, 10, 32)
	return int(port)
}

// HasDNS returns true if the endpoint has a DN.
func (e *Endpoint) HasDNS() bool {
	return e != nil && e.addr != ""
}

// DNS returns the DN of the Endpoint.
func (e *Endpoint) DNS() string {
	if e == nil {
		return ""
	}
	_, s, _ := net.SplitHostPort(e.addr)
	return s
}

// Resolved returns true, if the DN of the Endpoint was resolved
// or if the Endpoint has a resolved endpoint.
func (e *Endpoint) Resolved() bool {
	return e != nil && e.udpAddr != nil
}

// UDPAddr returns the UDPAddr of the Endpoint. If resolve is false,
// UDPAddr() will not try to resolve a DN name, if the Endpoint is not yet resolved.
func (e *Endpoint) UDPAddr(resolve bool) (*net.UDPAddr, error) {
	if !e.Ready() {
		return nil, errors.New("Enpoint is not ready")
	}
	if e.udpAddr != nil {
		// Make a copy of the UDPAddr to protect it from modification outside this package.
		h := *e.udpAddr
		return &h, nil
	}
	if !resolve {
		return nil, errors.New("Endpoint is not resolved")
	}
	var err error
	if e.udpAddr, err = net.ResolveUDPAddr("udp", e.addr); err != nil {
		return nil, err
	}
	// Make a copy of the UDPAddr to protect it from modification outside this package.
	h := *e.udpAddr
	return &h, nil
}

// IP returns the IP address of the Enpoint or nil.
func (e *Endpoint) IP() net.IP {
	if !e.Resolved() {
		return nil
	}
	return e.udpAddr.IP
}

// String will return the endpoint as a string.
// If a DN exists, it will take prcedence over the resolved endpoint.
func (e *Endpoint) String() string {
	return e.StringOpt(true)
}

// StringOpt will return string of the Endpoint.
// If dnsFirst is false, the resolved Endpoint will
// take precedence over the DN.
func (e *Endpoint) StringOpt(dnsFirst bool) string {
	if e == nil {
		return ""
	}
	if e.udpAddr != nil && (!dnsFirst || e.addr == "") {
		return e.udpAddr.String()
	}
	return e.addr
}

// Peer represents a `peer` section of a WireGuard configuration.
type Peer struct {
	wgtypes.PeerConfig
	Endpoint *Endpoint
}

// DeduplicateIPs eliminates duplicate allowed IPs.
func (p *Peer) DeduplicateIPs() {
	var ips []net.IPNet
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

// Bytes renders a WireGuard configuration to bytes.
func (c Conf) Bytes() ([]byte, error) {
	var err error
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	if c.PrivateKey != nil {
		if err = writeSection(buf, interfaceSection); err != nil {
			return nil, fmt.Errorf("failed to write interface: %v", err)
		}
		if err = writePKey(buf, privateKeyKey, c.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to write private key: %v", err)
		}
		if err = writeValue(buf, listenPortKey, strconv.Itoa(*c.ListenPort)); err != nil {
			return nil, fmt.Errorf("failed to write listen port: %v", err)
		}
	}
	for i, p := range c.Peers {
		// Add newlines to make the formatting nicer.
		if i == 0 && c.PrivateKey != nil || i != 0 {
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
		if p.PersistentKeepaliveInterval == nil {
			p.PersistentKeepaliveInterval = new(time.Duration)
		}
		if err = writeValue(buf, persistentKeepaliveKey, strconv.FormatUint(uint64(*p.PersistentKeepaliveInterval/time.Second), 10)); err != nil {
			return nil, fmt.Errorf("failed to write persistent keepalive: %v", err)
		}
		if err = writePKey(buf, presharedKeyKey, p.PresharedKey); err != nil {
			return nil, fmt.Errorf("failed to write preshared key: %v", err)
		}
		if err = writePKey(buf, publicKeyKey, &p.PublicKey); err != nil {
			return nil, fmt.Errorf("failed to write public key: %v", err)
		}
	}
	return buf.Bytes(), nil
}

// Equal returns true if the Conf and wgtypes.Device are equal.
func (c *Conf) Equal(d *wgtypes.Device) (bool, string) {
	if c == nil || d == nil {
		return c == nil && d == nil, "nil values"
	}
	if c.ListenPort == nil || *c.ListenPort != d.ListenPort {
		return false, fmt.Sprintf("port: old=%q, new=\"%v\"", d.ListenPort, c.ListenPort)
	}
	if c.PrivateKey == nil || *c.PrivateKey != d.PrivateKey {
		return false, fmt.Sprintf("private key: old=\"%s...\", new=\"%s\"", d.PrivateKey.String()[0:5], c.PrivateKey.String()[0:5])
	}
	if len(c.Peers) != len(d.Peers) {
		return false, fmt.Sprintf("number of peers: old=%d, new=%d", len(d.Peers), len(c.Peers))
	}
	sortPeerConfigs(d.Peers)
	sortPeers(c.Peers)
	for i := range c.Peers {
		if len(c.Peers[i].AllowedIPs) != len(d.Peers[i].AllowedIPs) {
			return false, fmt.Sprintf("Peer %d allowed IP length: old=%d, new=%d", i, len(d.Peers[i].AllowedIPs), len(c.Peers[i].AllowedIPs))
		}
		sortCIDRs(c.Peers[i].AllowedIPs)
		sortCIDRs(d.Peers[i].AllowedIPs)
		for j := range c.Peers[i].AllowedIPs {
			if c.Peers[i].AllowedIPs[j].String() != d.Peers[i].AllowedIPs[j].String() {
				return false, fmt.Sprintf("Peer %d allowed IP: old=%q, new=%q", i, d.Peers[i].AllowedIPs[j].String(), c.Peers[i].AllowedIPs[j].String())
			}
		}
		if c.Peers[i].Endpoint == nil || d.Peers[i].Endpoint == nil {
			return c.Peers[i].Endpoint == nil && d.Peers[i].Endpoint == nil, "peer endpoints: nil value"
		}
		if c.Peers[i].Endpoint.StringOpt(false) != d.Peers[i].Endpoint.String() {
			return false, fmt.Sprintf("Peer %d endpoint: old=%q, new=%q", i, d.Peers[i].Endpoint.String(), c.Peers[i].Endpoint.StringOpt(false))
		}

		pki := time.Duration(0)
		if p := c.Peers[i].PersistentKeepaliveInterval; p != nil {
			pki = *p
		}
		psk := wgtypes.Key{}
		if p := c.Peers[i].PresharedKey; p != nil {
			psk = *p
		}
		if pki != d.Peers[i].PersistentKeepaliveInterval || psk != d.Peers[i].PresharedKey || c.Peers[i].PublicKey != d.Peers[i].PublicKey {
			return false, "persistent keepalive or pershared key"
		}
	}
	return true, ""
}

func sortPeerConfigs(peers []wgtypes.Peer) {
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].PublicKey.String() < peers[j].PublicKey.String() {
			return true
		}
		return false
	})
}

func sortPeers(peers []Peer) {
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].PublicKey.String() < peers[j].PublicKey.String() {
			return true
		}
		return false
	})
}

func sortCIDRs(cidrs []net.IPNet) {
	sort.Slice(cidrs, func(i, j int) bool {
		return cidrs[i].String() < cidrs[j].String()
	})
}

func cutIP(ip net.IP) net.IP {
	if i4 := ip.To4(); i4 != nil {
		return i4
	}
	return ip.To16()
}

func writeAllowedIPs(buf *bytes.Buffer, ais []net.IPNet) error {
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

func writePKey(buf *bytes.Buffer, k key, b *wgtypes.Key) error {
	// Print nothing if the public key was never initialized.
	if b == nil || (wgtypes.Key{}) == *b {
		return nil
	}
	var err error
	if err = writeKey(buf, k); err != nil {
		return err
	}
	if _, err = buf.Write([]byte(b.String())); err != nil {
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
	str := e.String()
	if str == "" {
		return nil
	}
	var err error
	if err = writeKey(buf, endpointKey); err != nil {
		return err
	}
	if _, err = buf.WriteString(str); err != nil {
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
