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

package iptables

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

const ipv6ModuleDisabledPath = "/sys/module/ipv6/parameters/disable"

func ipv6Disabled() (bool, error) {
	f, err := os.Open(ipv6ModuleDisabledPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	disabled := make([]byte, 1)
	if _, err = io.ReadFull(f, disabled); err != nil {
		return false, err
	}
	return disabled[0] == '1', nil
}

// Protocol represents an IP protocol.
type Protocol byte

const (
	// ProtocolIPv4 represents the IPv4 protocol.
	ProtocolIPv4 Protocol = iota
	// ProtocolIPv6 represents the IPv6 protocol.
	ProtocolIPv6
)

// GetProtocol will return a protocol from the length of an IP address.
func GetProtocol(ip net.IP) Protocol {
	if len(ip) == net.IPv4len || ip.To4() != nil {
		return ProtocolIPv4
	}
	return ProtocolIPv6
}

// Client represents any type that can administer iptables rules.
type Client interface {
	AppendUnique(table string, chain string, rule ...string) error
	Insert(table string, chain string, pos int, rule ...string) error
	Delete(table string, chain string, rule ...string) error
	Exists(table string, chain string, rule ...string) (bool, error)
	List(table string, chain string) ([]string, error)
	ClearChain(table string, chain string) error
	DeleteChain(table string, chain string) error
	NewChain(table string, chain string) error
	ListChains(table string) ([]string, error)
}

// Rule is an interface for interacting with iptables objects.
type Rule interface {
	Append(Client) error
	Prepend(Client) error
	Delete(Client) error
	Exists(Client) (bool, error)
	String() string
	Proto() Protocol
}

// rule represents an iptables rule.
type rule struct {
	table string
	chain string
	spec  []string
	proto Protocol
}

// NewRule creates a new iptables or ip6tables rule in the given table and chain
// depending on the given protocol.
func NewRule(proto Protocol, table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, proto}
}

// NewIPv4Rule creates a new iptables rule in the given table and chain.
func NewIPv4Rule(table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, ProtocolIPv4}
}

// NewIPv6Rule creates a new ip6tables rule in the given table and chain.
func NewIPv6Rule(table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, ProtocolIPv6}
}

func (r *rule) Prepend(client Client) error {
	if err := client.Insert(r.table, r.chain, 1, r.spec...); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}
	return nil
}

func (r *rule) Append(client Client) error {
	if err := client.AppendUnique(r.table, r.chain, r.spec...); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}
	return nil
}

func (r *rule) Delete(client Client) error {
	// Ignore the returned error as an error likely means
	// that the rule doesn't exist, which is fine.
	client.Delete(r.table, r.chain, r.spec...)
	return nil
}

func (r *rule) Exists(client Client) (bool, error) {
	return client.Exists(r.table, r.chain, r.spec...)
}

func (r *rule) String() string {
	if r == nil {
		return ""
	}
	spec := r.table + " -A " + r.chain
	for i, s := range r.spec {
		spec += " "
		// If this is the content of a comment, wrap the value in quotes.
		if i > 0 && r.spec[i-1] == "--comment" {
			spec += `"` + s + `"`
		} else {
			spec += s
		}
	}
	return spec
}

func (r *rule) Proto() Protocol {
	return r.proto
}

// chain represents an iptables chain.
type chain struct {
	table string
	chain string
	proto Protocol
}

// NewIPv4Chain creates a new iptables chain in the given table.
func NewIPv4Chain(table, name string) Rule {
	return &chain{table, name, ProtocolIPv4}
}

// NewIPv6Chain creates a new ip6tables chain in the given table.
func NewIPv6Chain(table, name string) Rule {
	return &chain{table, name, ProtocolIPv6}
}

func (c *chain) Prepend(client Client) error {
	return c.Append(client)
}

func (c *chain) Append(client Client) error {
	// Note: `ClearChain` creates a chain if it does not exist.
	if err := client.ClearChain(c.table, c.chain); err != nil {
		return fmt.Errorf("failed to add iptables chain: %v", err)
	}
	return nil
}

func (c *chain) Delete(client Client) error {
	// The chain must be empty before it can be deleted.
	if err := client.ClearChain(c.table, c.chain); err != nil {
		return fmt.Errorf("failed to clear iptables chain: %v", err)
	}
	// Ignore the returned error as an error likely means
	// that the chain doesn't exist, which is fine.
	client.DeleteChain(c.table, c.chain)
	return nil
}

func (c *chain) Exists(client Client) (bool, error) {
	// The code for "chain already exists".
	existsErr := 1
	err := client.NewChain(c.table, c.chain)
	se, ok := err.(statusExiter)
	switch {
	case err == nil:
		// If there was no error adding a new chain, then it did not exist.
		// Delete it and return false.
		client.DeleteChain(c.table, c.chain)
		return false, nil
	case ok && se.ExitStatus() == existsErr:
		return true, nil
	default:
		return false, err
	}
}

func (c *chain) String() string {
	if c == nil {
		return ""
	}
	return chainToString(c.table, c.chain)
}

func (c *chain) Proto() Protocol {
	return c.proto
}

func chainToString(table, chain string) string {
	return fmt.Sprintf("%s -N %s", table, chain)
}

// Controller is able to reconcile a given set of iptables rules.
type Controller struct {
	v4           Client
	v6           Client
	errors       chan error
	logger       log.Logger
	resyncPeriod time.Duration
	registerer   prometheus.Registerer

	sync.Mutex
	appendRules  []Rule
	prependRules []Rule
	subscribed   bool
}

// ControllerOption modifies the controller's configuration.
type ControllerOption func(h *Controller)

// WithLogger adds a logger to the controller.
func WithLogger(logger log.Logger) ControllerOption {
	return func(c *Controller) {
		c.logger = logger
	}
}

// WithResyncPeriod modifies how often the controller reconciles.
func WithResyncPeriod(resyncPeriod time.Duration) ControllerOption {
	return func(c *Controller) {
		c.resyncPeriod = resyncPeriod
	}
}

// WithClients adds iptables clients to the controller.
func WithClients(v4, v6 Client) ControllerOption {
	return func(c *Controller) {
		c.v4 = v4
		c.v6 = v6
	}
}

func WithRegisterer(registerer prometheus.Registerer) ControllerOption {
	return func(c *Controller) {
		c.registerer = registerer
	}
}

// New generates a new iptables rules controller.
// If no options are given, IPv4 and IPv6 clients
// will be instantiated using the regular iptables backend.
func New(opts ...ControllerOption) (*Controller, error) {
	c := &Controller{
		errors: make(chan error),
		logger: log.NewNopLogger(),
	}
	for _, o := range opts {
		o(c)
	}
	if c.v4 == nil {
		v4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return nil, fmt.Errorf("failed to create iptables IPv4 client: %v", err)
		}
		c.v4 = wrapWithMetrics(v4, "IPv4", c.registerer)
	}
	if c.v6 == nil {
		disabled, err := ipv6Disabled()
		if err != nil {
			return nil, fmt.Errorf("failed to check IPv6 status: %v", err)
		}
		if disabled {
			level.Info(c.logger).Log("msg", "IPv6 is disabled in the kernel; disabling the IPv6 iptables controller")
			c.v6 = &fakeClient{}
		} else {
			v6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
			if err != nil {
				return nil, fmt.Errorf("failed to create iptables IPv6 client: %v", err)
			}
			c.v6 = wrapWithMetrics(v6, "IPv6", c.registerer)
		}
	}
	return c, nil
}

// Run watches for changes to iptables rules and reconciles
// the rules against the desired state.
func (c *Controller) Run(stop <-chan struct{}) (<-chan error, error) {
	c.Lock()
	if c.subscribed {
		c.Unlock()
		return c.errors, nil
	}
	// Ensure a given instance only subscribes once.
	c.subscribed = true
	c.Unlock()
	go func() {
		t := time.NewTimer(c.resyncPeriod)
		defer close(c.errors)
		for {
			select {
			case <-t.C:
				if err := c.reconcile(); err != nil {
					nonBlockingSend(c.errors, fmt.Errorf("failed to reconcile rules: %v", err))
				}
				t.Reset(c.resyncPeriod)
			case <-stop:
				return
			}
		}
	}()
	return c.errors, nil
}

// reconcile makes sure that every rule is still in the backend.
// It does not ensure that the order in the backend is correct.
// If any rule is missing, that rule and all following rules are
// re-added.
func (c *Controller) reconcile() error {
	c.Lock()
	defer c.Unlock()
	var rc ruleCache
	if err := c.reconcileAppendRules(rc); err != nil {
		return err
	}
	return c.reconcilePrependRules(rc)
}

func (c *Controller) reconcileAppendRules(rc ruleCache) error {
	for i, r := range c.appendRules {
		ok, err := rc.exists(c.client(r.Proto()), r)
		if err != nil {
			return fmt.Errorf("failed to check if rule exists: %v", err)
		}
		if !ok {
			level.Info(c.logger).Log("msg", fmt.Sprintf("applying %d iptables rules", len(c.appendRules)-i))
			if err := c.resetFromIndex(i, c.appendRules); err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}
			break
		}
	}
	return nil
}

func (c *Controller) reconcilePrependRules(rc ruleCache) error {
	for _, r := range c.prependRules {
		ok, err := rc.exists(c.client(r.Proto()), r)
		if err != nil {
			return fmt.Errorf("failed to check if rule exists: %v", err)
		}
		if !ok {
			level.Info(c.logger).Log("msg", "prepending iptables rule")
			if err := r.Prepend(c.client(r.Proto())); err != nil {
				return fmt.Errorf("failed to prepend rule: %v", err)
			}
		}
	}
	return nil
}

// resetFromIndex re-adds all rules starting from the given index.
func (c *Controller) resetFromIndex(i int, rules []Rule) error {
	if i >= len(rules) {
		return nil
	}
	for j := i; j < len(rules); j++ {
		if err := rules[j].Delete(c.client(rules[j].Proto())); err != nil {
			return fmt.Errorf("failed to delete rule: %v", err)
		}
		if err := rules[j].Append(c.client(rules[j].Proto())); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
	}
	return nil
}

// deleteFromIndex deletes all rules starting from the given index.
func (c *Controller) deleteFromIndex(i int, rules *[]Rule) error {
	if i >= len(*rules) {
		return nil
	}
	for j := i; j < len(*rules); j++ {
		if err := (*rules)[j].Delete(c.client((*rules)[j].Proto())); err != nil {
			*rules = append((*rules)[:i], (*rules)[j:]...)
			return fmt.Errorf("failed to delete rule: %v", err)
		}
		(*rules)[j] = nil
	}
	*rules = (*rules)[:i]
	return nil
}

// Set idempotently overwrites any iptables rules previously defined
// for the controller with the given set of rules.
func (c *Controller) Set(rules RuleSet) error {
	c.Lock()
	defer c.Unlock()
	if err := c.setAppendRules(rules.AppendRules); err != nil {
		return err
	}
	return c.setPrependRules(rules.PrependRules)
}

func (c *Controller) setAppendRules(appendRules []Rule) error {
	var i int
	for ; i < len(appendRules); i++ {
		if i < len(c.appendRules) {
			if appendRules[i].String() != c.appendRules[i].String() {
				if err := c.deleteFromIndex(i, &c.appendRules); err != nil {
					return err
				}
			}
		}
		if i >= len(c.appendRules) {
			if err := appendRules[i].Append(c.client(appendRules[i].Proto())); err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}
			c.appendRules = append(c.appendRules, appendRules[i])
		}
	}
	err := c.deleteFromIndex(i, &c.appendRules)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %v", err)
	}
	return nil
}

func (c *Controller) setPrependRules(prependRules []Rule) error {
	for _, prependRule := range prependRules {
		if !containsRule(c.prependRules, prependRule) {
			if err := prependRule.Prepend(c.client(prependRule.Proto())); err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}
			c.prependRules = append(c.prependRules, prependRule)
		}
	}
	for _, existingRule := range c.prependRules {
		if !containsRule(prependRules, existingRule) {
			if err := existingRule.Delete(c.client(existingRule.Proto())); err != nil {
				return fmt.Errorf("failed to delete rule: %v", err)
			}
			c.prependRules = removeRule(c.prependRules, existingRule)
		}
	}
	return nil
}

func removeRule(rules []Rule, toRemove Rule) []Rule {
	ret := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.String() != toRemove.String() {
			ret = append(ret, rule)
		}
	}
	return ret
}

func containsRule(haystack []Rule, needle Rule) bool {
	for _, element := range haystack {
		if element.String() == needle.String() {
			return true
		}
	}
	return false
}

// CleanUp will clean up any rules created by the controller.
func (c *Controller) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	err := c.deleteFromIndex(0, &c.prependRules)
	if err != nil {
		return err
	}
	return c.deleteFromIndex(0, &c.appendRules)
}

func (c *Controller) client(p Protocol) Client {
	switch p {
	case ProtocolIPv4:
		return c.v4
	case ProtocolIPv6:
		return c.v6
	default:
		panic("unknown protocol")
	}
}

func nonBlockingSend(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

type RuleSet struct {
	AppendRules  []Rule // Rules to append to the chain - order matters.
	PrependRules []Rule // Rules to prepend to the chain - order does not matter.
}
