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
	"testing"
)

var rules = []Rule{
	&rule{"filter", "FORWARD", []string{"-s", "10.4.0.0/16", "-j", "ACCEPT"}, nil},
	&rule{"filter", "FORWARD", []string{"-d", "10.4.0.0/16", "-j", "ACCEPT"}, nil},
}

func newController() *Controller {
	return &Controller{
		rules: make(map[string]Rule),
	}
}

func TestSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{
			name:  "empty",
			rules: nil,
		},
		{
			name:  "single",
			rules: []Rule{rules[0]},
		},
		{
			name:  "multiple",
			rules: []Rule{rules[0], rules[1]},
		},
	} {
		backend := make(map[string]Rule)
		controller := newController()
		controller.client = fakeClient(backend)
		if err := controller.Set(tc.rules); err != nil {
			t.Fatalf("test case %q: got unexpected error: %v", tc.name, err)
		}
		for _, r := range tc.rules {
			r1 := backend[r.String()]
			r2 := controller.rules[r.String()]
			if r.String() != r1.String() || r.String() != r2.String() {
				t.Errorf("test case %q: expected all rules to be equal: expected %v, got %v and %v", tc.name, r, r1, r2)
			}
		}
	}
}

func TestCleanUp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{
			name:  "empty",
			rules: nil,
		},
		{
			name:  "single",
			rules: []Rule{rules[0]},
		},
		{
			name:  "multiple",
			rules: []Rule{rules[0], rules[1]},
		},
	} {
		backend := make(map[string]Rule)
		controller := newController()
		controller.client = fakeClient(backend)
		if err := controller.Set(tc.rules); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		if err := controller.CleanUp(); err != nil {
			t.Errorf("test case %q: got unexpected error: %v", tc.name, err)
		}
		for _, r := range tc.rules {
			r1 := backend[r.String()]
			r2 := controller.rules[r.String()]
			if r1 != nil || r2 != nil {
				t.Errorf("test case %q: expected all rules to be nil: expected got %v and %v", tc.name, r1, r2)
			}
		}
	}
}
