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

package route

import (
	"errors"
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Table represents a routing table.
// Table can safely be used concurrently.
type Table struct {
	errors     chan error
	mu         sync.Mutex
	rs         map[string]interface{}
	subscribed bool

	// Make these functions fields to allow
	// for testing.
	addRoute func(*netlink.Route) error
	delRoute func(*netlink.Route) error
	addRule  func(*netlink.Rule) error
	delRule  func(*netlink.Rule) error
}

// NewTable generates a new table.
func NewTable() *Table {
	return &Table{
		errors:   make(chan error),
		rs:       make(map[string]interface{}),
		addRoute: netlink.RouteReplace,
		delRoute: func(r *netlink.Route) error {
			name := routeToString(r)
			if name == "" {
				return errors.New("attempting to delete invalid route")
			}
			routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
			if err != nil {
				return fmt.Errorf("failed to list routes before deletion: %v", err)
			}
			for _, route := range routes {
				if routeToString(&route) == name {
					return netlink.RouteDel(r)
				}
			}
			return nil
		},
		addRule: netlink.RuleAdd,
		delRule: func(r *netlink.Rule) error {
			name := ruleToString(r)
			if name == "" {
				return errors.New("attempting to delete invalid rule")
			}
			rules, err := netlink.RuleList(netlink.FAMILY_ALL)
			if err != nil {
				return fmt.Errorf("failed to list rules before deletion: %v", err)
			}
			for _, rule := range rules {
				if ruleToString(&rule) == name {
					return netlink.RuleDel(r)
				}
			}
			return nil
		},
	}
}

// Run watches for changes to routes and rules in the table and reconciles
// the table against the desired state.
func (t *Table) Run(stop <-chan struct{}) (<-chan error, error) {
	t.mu.Lock()
	if t.subscribed {
		t.mu.Unlock()
		return t.errors, nil
	}
	// Ensure a given instance only subscribes once.
	t.subscribed = true
	t.mu.Unlock()
	events := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(events, stop); err != nil {
		return t.errors, fmt.Errorf("failed to subscribe to route events: %v", err)
	}
	go func() {
		defer close(t.errors)
		for {
			var e netlink.RouteUpdate
			select {
			case e = <-events:
			case <-stop:
				return
			}
			switch e.Type {
			// Watch for deleted routes to reconcile this table's routes.
			case unix.RTM_DELROUTE:
				// Filter out invalid routes.
				if e.Route.Dst == nil {
					continue
				}
				t.mu.Lock()
				for k := range t.rs {
					switch r := t.rs[k].(type) {
					case *netlink.Route:
						// If any deleted route's destination matches a destination
						// in the table, reset the corresponding route just in case.
						if r.Dst.IP.Equal(e.Route.Dst.IP) && r.Dst.Mask.String() == e.Route.Dst.Mask.String() {
							if err := t.addRoute(r); err != nil {
								nonBlockingSend(t.errors, fmt.Errorf("failed add route: %v", err))
							}
						}
					}
				}
				t.mu.Unlock()
			}
		}
	}()
	return t.errors, nil
}

// CleanUp will clean up any routes and rules created by the instance.
func (t *Table) CleanUp() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.rs {
		switch r := t.rs[k].(type) {
		case *netlink.Route:
			if err := t.delRoute(r); err != nil {
				return fmt.Errorf("failed to delete route: %v", err)
			}
		case *netlink.Rule:
			if err := t.delRule(r); err != nil {
				return fmt.Errorf("failed to delete rule: %v", err)
			}
		}
		delete(t.rs, k)
	}
	return nil
}

// Set idempotently overwrites any routes and rules previously defined
// for the table with the given set of routes and rules.
func (t *Table) Set(routes []*netlink.Route, rules []*netlink.Rule) error {
	rs := make(map[string]interface{})
	for _, route := range routes {
		if route == nil {
			continue
		}
		rs[routeToString(route)] = route
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		rs[ruleToString(rule)] = rule
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.rs {
		if _, ok := rs[k]; !ok {
			switch r := t.rs[k].(type) {
			case *netlink.Route:
				if err := t.delRoute(r); err != nil {
					return fmt.Errorf("failed to delete route: %v", err)
				}
			case *netlink.Rule:
				if err := t.delRule(r); err != nil {
					return fmt.Errorf("failed to delete rule: %v", err)
				}
			}
			delete(t.rs, k)
		}
	}

	// When adding routes/rules, we need to compare against what is
	// actually on the Linux routing table. This is because
	// routes/rules can be deleted by the kernel due to interface churn
	// causing a situation where the controller thinks it has an item
	// that is not actually there.
	existing := make(map[string]interface{})
	existingRoutes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list existing routes: %v", err)
	}
	for k := range existingRoutes {
		existing[routeToString(&existingRoutes[k])] = &existingRoutes[k]
	}

	existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list existing rules: %v", err)
	}
	for k := range existingRules {
		existing[ruleToString(&existingRules[k])] = &existingRules[k]
	}

	for k := range rs {
		if _, ok := existing[k]; !ok {
			switch r := rs[k].(type) {
			case *netlink.Route:
				if err := t.addRoute(r); err != nil {
					return fmt.Errorf("failed to add route %q: %v", k, err)
				}
			case *netlink.Rule:
				if err := t.addRule(r); err != nil {
					return fmt.Errorf("failed to add rule %q: %v", k, err)
				}
			}
			t.rs[k] = rs[k]
		}
	}
	return nil
}

func nonBlockingSend(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

func routeToString(route *netlink.Route) string {
	if route == nil || route.Dst == nil {
		return ""
	}
	src := "-"
	if route.Src != nil {
		src = route.Src.String()
	}
	gw := "-"
	if route.Gw != nil {
		gw = route.Gw.String()
	}
	return fmt.Sprintf("dst: %s, via: %s, src: %s, dev: %d", route.Dst.String(), gw, src, route.LinkIndex)
}

func ruleToString(rule *netlink.Rule) string {
	if rule == nil || (rule.Src == nil && rule.Dst == nil) {
		return ""
	}
	src := "-"
	if rule.Src != nil {
		src = rule.Src.String()
	}
	dst := "-"
	if rule.Dst != nil {
		dst = rule.Dst.String()
	}
	return fmt.Sprintf("src: %s, dst: %s, table: %d, input: %s", src, dst, rule.Table, rule.IifName)
}
