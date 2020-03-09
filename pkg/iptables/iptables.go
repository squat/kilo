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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

// Client represents any type that can administer iptables rules.
type Client interface {
	AppendUnique(table string, chain string, rule ...string) error
	Delete(table string, chain string, rule ...string) error
	Exists(table string, chain string, rule ...string) (bool, error)
	ClearChain(table string, chain string) error
	DeleteChain(table string, chain string) error
	NewChain(table string, chain string) error
}

// Rule is an interface for interacting with iptables objects.
type Rule interface {
	Add(Client) error
	Delete(Client) error
	Exists(Client) (bool, error)
	String() string
}

// rule represents an iptables rule.
type rule struct {
	table string
	chain string
	spec  []string
}

// NewRule creates a new iptables rule in the given table and chain.
func NewRule(table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec}
}

func (r *rule) Add(client Client) error {
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
	return fmt.Sprintf("%s_%s_%s", r.table, r.chain, strings.Join(r.spec, "_"))
}

// chain represents an iptables chain.
type chain struct {
	table string
	chain string
}

// NewChain creates a new iptables chain in the given table.
func NewChain(table, name string) Rule {
	return &chain{table, name}
}

func (c *chain) Add(client Client) error {
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
	return fmt.Sprintf("%s_%s", c.table, c.chain)
}

// Controller is able to reconcile a given set of iptables rules.
type Controller struct {
	client Client
	errors chan error

	sync.Mutex
	rules      []Rule
	subscribed bool
}

// New generates a new iptables rules controller.
// It expects an IP address length to determine
// whether to operate in IPv4 or IPv6 mode.
func New(ipLength int) (*Controller, error) {
	p := iptables.ProtocolIPv4
	if ipLength == net.IPv6len {
		p = iptables.ProtocolIPv6
	}
	client, err := iptables.NewWithProtocol(p)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables client: %v", err)
	}
	return &Controller{
		client: client,
		errors: make(chan error),
	}, nil
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
		defer close(c.errors)
		for {
			select {
			case <-time.After(5 * time.Second):
			case <-stop:
				return
			}
			if err := c.reconcile(); err != nil {
				nonBlockingSend(c.errors, fmt.Errorf("failed to reconcile rules: %v", err))
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
	for i, r := range c.rules {
		ok, err := r.Exists(c.client)
		if err != nil {
			return fmt.Errorf("failed to check if rule exists: %v", err)
		}
		if !ok {
			if err := c.resetFromIndex(i, c.rules); err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}
			break
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
		if err := rules[j].Delete(c.client); err != nil {
			return fmt.Errorf("failed to delete rule: %v", err)
		}
		if err := rules[j].Add(c.client); err != nil {
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
		if err := (*rules)[j].Delete(c.client); err != nil {
			return fmt.Errorf("failed to delete rule: %v", err)
		}
		(*rules)[j] = nil
	}
	*rules = (*rules)[:i]
	return nil
}

// Set idempotently overwrites any iptables rules previously defined
// for the controller with the given set of rules.
func (c *Controller) Set(rules []Rule) error {
	c.Lock()
	defer c.Unlock()
	var i int
	for ; i < len(rules); i++ {
		if i < len(c.rules) {
			if rules[i].String() != c.rules[i].String() {
				if err := c.deleteFromIndex(i, &c.rules); err != nil {
					return err
				}
			}
		}
		if i >= len(c.rules) {
			if err := rules[i].Add(c.client); err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}
			c.rules = append(c.rules, rules[i])
		}

	}
	return c.deleteFromIndex(i, &c.rules)
}

// CleanUp will clean up any rules created by the controller.
func (c *Controller) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	return c.deleteFromIndex(0, &c.rules)
}

func nonBlockingSend(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}
