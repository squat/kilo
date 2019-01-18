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
	add := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			backend[routeToString(r)] = r
			return nil
		}
	}
	del := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			delete(backend, routeToString(r))
			return nil
		}
	}
	adderr := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			return errors.New(routeToString(r))
		}
	}
	for _, tc := range []struct {
		name   string
		routes []*netlink.Route
		err    bool
		add    func(map[string]*netlink.Route) func(*netlink.Route) error
		del    func(map[string]*netlink.Route) func(*netlink.Route) error
	}{
		{
			name:   "empty",
			routes: nil,
			err:    false,
			add:    add,
			del:    del,
		},
		{
			name: "single",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
			},
			err: false,
			add: add,
			del: del,
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
			err: false,
			add: add,
			del: del,
		},
		{
			name:   "err empty",
			routes: nil,
			err:    false,
			add:    adderr,
			del:    del,
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
			err: true,
			add: adderr,
			del: del,
		},
	} {
		backend := make(map[string]*netlink.Route)
		a := tc.add(backend)
		d := tc.del(backend)
		table := NewTable()
		table.add = a
		table.del = d
		if err := table.Set(tc.routes); (err != nil) != tc.err {
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
				r2 := table.routes[routeToString(r)]
				if r != r1 || r != r2 {
					t.Errorf("test case %q: expected all routes to be equal: expected %v, got %v and %v", tc.name, r, r1, r2)
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
	add := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			backend[routeToString(r)] = r
			return nil
		}
	}
	del := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			delete(backend, routeToString(r))
			return nil
		}
	}
	delerr := func(backend map[string]*netlink.Route) func(*netlink.Route) error {
		return func(r *netlink.Route) error {
			return errors.New(routeToString(r))
		}
	}
	for _, tc := range []struct {
		name   string
		routes []*netlink.Route
		err    bool
		add    func(map[string]*netlink.Route) func(*netlink.Route) error
		del    func(map[string]*netlink.Route) func(*netlink.Route) error
	}{
		{
			name:   "empty",
			routes: nil,
			err:    false,
			add:    add,
			del:    del,
		},
		{
			name: "single",
			routes: []*netlink.Route{
				{
					Dst: c1,
					Gw:  net.ParseIP("10.1.0.1"),
				},
			},
			err: false,
			add: add,
			del: del,
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
			err: false,
			add: add,
			del: del,
		},
		{
			name:   "err empty",
			routes: nil,
			err:    false,
			add:    add,
			del:    delerr,
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
			err: true,
			add: add,
			del: delerr,
		},
	} {
		backend := make(map[string]*netlink.Route)
		a := tc.add(backend)
		d := tc.del(backend)
		table := NewTable()
		table.add = a
		table.del = d
		if err := table.Set(tc.routes); err != nil {
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
				r2 := table.routes[routeToString(r)]
				if r1 != nil || r2 != nil {
					t.Errorf("test case %q: expected all routes to be nil: expected got %v and %v", tc.name, r1, r2)
				}
			}
		}
	}
}
