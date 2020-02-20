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
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSet(t *testing.T) {
	_, c1, err := net.ParseCIDR("10.2.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	_, c2, err := net.ParseCIDR("10.1.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	addRoute := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			backend[routeToString(r)] = r
			return nil
		}
	}
	delRoute := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			delete(backend, routeToString(r))
			return nil
		}
	}
	addRule := func(backend map[string]interface{}) func(*netlink.Rule) error {
		return func(r *netlink.Rule) error {
			backend[ruleToString(r)] = r
			return nil
		}
	}
	delRule := func(backend map[string]interface{}) func(*netlink.Rule) error {
		return func(r *netlink.Rule) error {
			delete(backend, ruleToString(r))
			return nil
		}
	}
	adderr := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			return errors.New(routeToString(r))
		}
	}
	for _, tc := range []struct {
		name     string
		routes   []*netlink.Route
		rules    []*netlink.Rule
		err      bool
		addRoute func(map[string]interface{}) func(*netlink.Route) error
		delRoute func(map[string]interface{}) func(*netlink.Route) error
		addRule  func(map[string]interface{}) func(*netlink.Rule) error
		delRule  func(map[string]interface{}) func(*netlink.Rule) error
	}{
		{
			name:     "empty",
			routes:   nil,
			rules:    nil,
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "single",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
			},
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "multiple",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
				{
					Dst: c2,
					Gw:  net.ParseIP("127.0.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
				{
					Src:   c2,
					Table: 2,
				},
			},
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name:     "err empty",
			routes:   nil,
			err:      false,
			addRoute: adderr,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "err",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
				{
					Dst: c2,
					Gw:  net.ParseIP("127.0.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
				{
					Src:   c2,
					Table: 2,
				},
			},
			err:      true,
			addRoute: adderr,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
	} {
		backend := make(map[string]interface{})
		table := NewTable()
		table.addRoute = tc.addRoute(backend)
		table.delRoute = tc.delRoute(backend)
		table.addRule = tc.addRule(backend)
		table.delRule = tc.delRule(backend)
		if err := table.Set(tc.routes, tc.rules); (err != nil) != tc.err {
			no := "no"
			if tc.err {
				no = "an"
			}
			t.Errorf("test case %q: got unexpected result: expected %s error, got %v", tc.name, no, err)
		}
		// If no error was expected, then compare the backend to the input.
		if !tc.err {
			for _, r := range tc.routes {
				r1 := backend[routeToString(r)]
				r2 := table.rs[routeToString(r)]
				if r != r1 || r != r2 {
					t.Errorf("test case %q: expected all routes to be equal: expected %v, got %v and %v", tc.name, r, r1, r2)
				}
			}
			for _, r := range tc.rules {
				r1 := backend[ruleToString(r)]
				r2 := table.rs[ruleToString(r)]
				if r != r1 || r != r2 {
					t.Errorf("test case %q: expected all rules to be equal: expected %v, got %v and %v", tc.name, r, r1, r2)
				}
			}
		}
	}
}

func TestCleanUp(t *testing.T) {
	_, c1, err := net.ParseCIDR("10.2.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	_, c2, err := net.ParseCIDR("10.1.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	addRoute := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			backend[routeToString(r)] = r
			return nil
		}
	}
	delRoute := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			delete(backend, routeToString(r))
			return nil
		}
	}
	addRule := func(backend map[string]interface{}) func(*netlink.Rule) error {
		return func(r *netlink.Rule) error {
			backend[ruleToString(r)] = r
			return nil
		}
	}
	delRule := func(backend map[string]interface{}) func(*netlink.Rule) error {
		return func(r *netlink.Rule) error {
			delete(backend, ruleToString(r))
			return nil
		}
	}
	delerr := func(backend map[string]interface{}) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			return errors.New(routeToString(r))
		}
	}
	for _, tc := range []struct {
		name     string
		routes   []*netlink.Route
		rules    []*netlink.Rule
		err      bool
		addRoute func(map[string]interface{}) func(*netlink.Route) error
		delRoute func(map[string]interface{}) func(*netlink.Route) error
		addRule  func(map[string]interface{}) func(*netlink.Rule) error
		delRule  func(map[string]interface{}) func(*netlink.Rule) error
	}{
		{
			name:     "empty",
			routes:   nil,
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "single",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
			},
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "multiple",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
				{
					Dst: c2,
					Gw:  net.ParseIP("127.0.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
				{
					Src:   c2,
					Table: 2,
				},
			},
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name:     "err empty",
			routes:   nil,
			err:      false,
			addRoute: addRoute,
			delRoute: delRoute,
			addRule:  addRule,
			delRule:  delRule,
		},
		{
			name: "err",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
				{
					Dst: c2,
					Gw:  net.ParseIP("127.0.0.1"),
				},
			},
			rules: []*netlink.Rule{
				{
					Src:   c1,
					Table: 1,
				},
				{
					Src:   c2,
					Table: 2,
				},
			},
			err:      true,
			addRoute: addRoute,
			delRoute: delerr,
			addRule:  addRule,
			delRule:  delRule,
		},
	} {
		backend := make(map[string]interface{})
		table := NewTable()
		table.addRoute = tc.addRoute(backend)
		table.delRoute = tc.delRoute(backend)
		table.addRule = tc.addRule(backend)
		table.delRule = tc.delRule(backend)
		if err := table.Set(tc.routes, tc.rules); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		if err := table.CleanUp(); (err != nil) != tc.err {
			no := "no"
			if tc.err {
				no = "an"
			}
			t.Errorf("test case %q: got unexpected result: expected %s error, got %v", tc.name, no, err)
		}
		// If no error was expected, then compare the backend to the input.
		if !tc.err {
			for _, r := range tc.routes {
				r1 := backend[routeToString(r)]
				r2 := table.rs[routeToString(r)]
				if r1 != nil || r2 != nil {
					t.Errorf("test case %q: expected all routes to be nil: expected nil, got %v and %v", tc.name, r1, r2)
				}
			}
		}
		if !tc.err {
			for _, r := range tc.rules {
				r1 := backend[ruleToString(r)]
				r2 := table.rs[ruleToString(r)]
				if r1 != nil || r2 != nil {
					t.Errorf("test case %q: expected all rules to be nil: expected nil, got %v and %v", tc.name, r1, r2)
				}
			}
		}
	}
}
