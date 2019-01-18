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
	routes     map[string]*netlink.Route
	subscribed bool

	// Make these functions fields to allow
	// for testing.
	add func(*netlink.Route) error
	del func(*netlink.Route) error
}

// NewTable generates a new table.
func NewTable() *Table {
	return &Table{
		errors: make(chan error),
		routes: make(map[string]*netlink.Route),
		add:    netlink.RouteReplace,
		del: func(r *netlink.Route) error {
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
	}
}

// Run watches for changes to routes in the table and reconciles
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
				t.mu.Lock()
				for _, r := range t.routes {
					// If any deleted route's destination matches a destination
					// in the table, reset the corresponding route just in case.
					if r.Dst.IP.Equal(e.Route.Dst.IP) && r.Dst.Mask.String() == e.Route.Dst.Mask.String() {
						if err := t.add(r); err != nil {
							nonBlockingSend(t.errors, fmt.Errorf("failed add route: %v", err))
						}
					}
				}
				t.mu.Unlock()
			}
		}
	}()
	return t.errors, nil
}

// CleanUp will clean up any routes created by the instance.
func (t *Table) CleanUp() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, route := range t.routes {
		if err := t.del(route); err != nil {
			return fmt.Errorf("failed to delete route: %v", err)
		}
		delete(t.routes, k)
	}
	return nil
}

// Set idempotently overwrites any routes previously defined
// for the table with the given set of routes.
func (t *Table) Set(routes []*netlink.Route) error {
	r := make(map[string]*netlink.Route)
	for _, route := range routes {
		if route == nil {
			continue
		}
		r[routeToString(route)] = route
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.routes {
		if _, ok := r[k]; !ok {
			if err := t.del(t.routes[k]); err != nil {
				return fmt.Errorf("failed to delete route: %v", err)
			}
			delete(t.routes, k)
		}
	}
	for k := range r {
		if _, ok := t.routes[k]; !ok {
			if err := t.add(r[k]); err != nil {
				return fmt.Errorf("failed to add route %q: %v", routeToString(r[k]), err)
			}
			t.routes[k] = r[k]
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
