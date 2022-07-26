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

	"github.com/prometheus/client_golang/prometheus"
)

var rules = []Rule{
	NewIPv4Rule("filter", "FORWARD", "-s", "10.4.0.0/16", "-j", "ACCEPT"),
	NewIPv4Rule("filter", "FORWARD", "-d", "10.4.0.0/16", "-j", "ACCEPT"),
}

func TestSet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sets    [][]Rule
		out     []Rule
		actions []func(Client) error
	}{
		{
			name: "empty",
		},
		{
			name: "single",
			sets: [][]Rule{
				{rules[0]},
			},
			out: []Rule{rules[0]},
		},
		{
			name: "two rules",
			sets: [][]Rule{
				{rules[0], rules[1]},
			},
			out: []Rule{rules[0], rules[1]},
		},
		{
			name: "multiple",
			sets: [][]Rule{
				{rules[0], rules[1]},
				{rules[1]},
			},
			out: []Rule{rules[1]},
		},
		{
			name: "re-add",
			sets: [][]Rule{
				{rules[0], rules[1]},
			},
			out: []Rule{rules[0], rules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return rules[0].Delete(c)
				},
				func(c Client) error {
					return rules[1].Delete(c)
				},
			},
		},
		{
			name: "order",
			sets: [][]Rule{
				{rules[0], rules[1]},
			},
			out: []Rule{rules[0], rules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return rules[0].Delete(c)
				},
			},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		for i := range tc.sets {
			ruleSet := RuleSet{AppendRules: tc.sets[i]}
			if err := controller.Set(ruleSet); err != nil {
				t.Fatalf("test case %q: got unexpected error setting rule set %d: %v", tc.name, i, err)
			}
		}
		for i, f := range tc.actions {
			if err := f(controller.v4); err != nil {
				t.Fatalf("test case %q action %d: got unexpected error %v", tc.name, i, err)
			}
		}
		if err := controller.reconcile(); err != nil {
			t.Fatalf("test case %q: got unexpected error %v", tc.name, err)
		}
		if len(tc.out) != len(client.storage) {
			t.Errorf("test case %q: expected %d rules in storage, got %d", tc.name, len(tc.out), len(client.storage))
		} else {
			for i := range tc.out {
				if tc.out[i].String() != client.storage[i].String() {
					t.Errorf("test case %q: expected rule %d in storage to be equal: expected %v, got %v", tc.name, i, tc.out[i], client.storage[i])
				}
			}
		}
		if len(tc.out) != len(controller.appendRules) {
			t.Errorf("test case %q: expected %d rules in controller, got %d", tc.name, len(tc.out), len(controller.appendRules))
		} else {
			for i := range tc.out {
				if tc.out[i].String() != controller.appendRules[i].String() {
					t.Errorf("test case %q: expected rule %d in controller to be equal: expected %v, got %v", tc.name, i, tc.out[i], controller.appendRules[i])
				}
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
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		ruleSet := RuleSet{AppendRules: tc.rules}
		if err := controller.Set(ruleSet); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		if len(client.storage) != len(tc.rules) {
			t.Errorf("test case %q: expected %d rules in storage, got %d rules", tc.name, len(ruleSet.AppendRules), len(client.storage))
		}
		if err := controller.CleanUp(); err != nil {
			t.Errorf("test case %q: got unexpected error: %v", tc.name, err)
		}
		if len(client.storage) != 0 {
			t.Errorf("test case %q: expected storage to be empty, got %d rules", tc.name, len(client.storage))
		}
	}
}
