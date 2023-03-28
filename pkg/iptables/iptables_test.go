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

var appendRules = []Rule{
	NewIPv4Rule("filter", "FORWARD", "-s", "10.4.0.0/16", "-j", "ACCEPT"),
	NewIPv4Rule("filter", "FORWARD", "-d", "10.4.0.0/16", "-j", "ACCEPT"),
}

var prependRules = []Rule{
	NewIPv4Rule("filter", "FORWARD", "-s", "10.5.0.0/16", "-j", "DROP"),
	NewIPv4Rule("filter", "FORWARD", "-s", "10.6.0.0/16", "-j", "DROP"),
}

func TestSet(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sets       []RuleSet
		appendOut  []Rule
		prependOut []Rule
		storageOut []Rule
		actions    []func(Client) error
	}{
		{
			name: "empty",
		},
		{
			name: "single",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0]}},
			},
			appendOut:  []Rule{appendRules[0]},
			storageOut: []Rule{appendRules[0]},
		},
		{
			name: "two rules",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
		},
		{
			name: "multiple",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
				{appendRules: []Rule{appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[1]},
			storageOut: []Rule{appendRules[1]},
		},
		{
			name: "re-add",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return appendRules[0].Delete(c)
				},
				func(c Client) error {
					return appendRules[1].Delete(c)
				},
			},
		},
		{
			name: "order",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return appendRules[0].Delete(c)
				},
			},
		},
		{
			name: "append and prepend",
			sets: []RuleSet{
				{
					prependRules: []Rule{prependRules[0], prependRules[1]},
					appendRules:  []Rule{appendRules[0], appendRules[1]},
				},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			prependOut: []Rule{prependRules[0], prependRules[1]},
			storageOut: []Rule{prependRules[1], prependRules[0], appendRules[0], appendRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		for i := range tc.sets {
			if err := controller.Set(tc.sets[i]); err != nil {
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
		if len(tc.storageOut) != len(client.storage) {
			t.Errorf("test case %q: expected %d rules in storage, got %d", tc.name, len(tc.storageOut), len(client.storage))
		} else {
			for i := range tc.storageOut {
				if tc.storageOut[i].String() != client.storage[i].String() {
					t.Errorf("test case %q: expected rule %d in storage to be equal: expected %v, got %v", tc.name, i, tc.storageOut[i], client.storage[i])
				}
			}
		}
		if len(tc.appendOut) != len(controller.appendRules) {
			t.Errorf("test case %q: expected %d appendRules in controller, got %d", tc.name, len(tc.appendOut), len(controller.appendRules))
		} else {
			for i := range tc.appendOut {
				if tc.appendOut[i].String() != controller.appendRules[i].String() {
					t.Errorf("test case %q: expected appendRule %d in controller to be equal: expected %v, got %v", tc.name, i, tc.appendOut[i], controller.appendRules[i])
				}
			}
		}
		if len(tc.prependOut) != len(controller.prependRules) {
			t.Errorf("test case %q: expected %d prependRules in controller, got %d", tc.name, len(tc.prependOut), len(controller.prependRules))
		} else {
			for i := range tc.prependOut {
				if tc.prependOut[i].String() != controller.prependRules[i].String() {
					t.Errorf("test case %q: expected prependRule %d in controller to be equal: expected %v, got %v", tc.name, i, tc.prependOut[i], controller.prependRules[i])
				}
			}
		}
	}
}

func TestCleanUp(t *testing.T) {
	for _, tc := range []struct {
		name         string
		appendRules  []Rule
		prependRules []Rule
	}{
		{
			name:        "empty",
			appendRules: nil,
		},
		{
			name:        "single append",
			appendRules: []Rule{appendRules[0]},
		},
		{
			name:        "multiple append",
			appendRules: []Rule{appendRules[0], appendRules[1]},
		},
		{
			name:         "multiple append and prepend",
			appendRules:  []Rule{appendRules[0], appendRules[1]},
			prependRules: []Rule{prependRules[0], prependRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		ruleSet := RuleSet{appendRules: tc.appendRules, prependRules: tc.prependRules}
		if err := controller.Set(ruleSet); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		if len(client.storage) != len(tc.appendRules)+len(tc.prependRules) {
			t.Errorf("test case %q: expected %d rules in storage, got %d rules", tc.name, len(ruleSet.appendRules)+len(ruleSet.prependRules), len(client.storage))
		}
		if err := controller.CleanUp(); err != nil {
			t.Errorf("test case %q: got unexpected error: %v", tc.name, err)
		}
		if len(client.storage) != 0 {
			t.Errorf("test case %q: expected storage to be empty, got %d rules", tc.name, len(client.storage))
		}
	}
}

func TestReconcile(t *testing.T) {
	for _, tc := range []struct {
		name         string
		appendRules  []Rule
		prependRules []Rule
		storageOut   []Rule
	}{
		{
			name:         "append and prepend rules",
			appendRules:  []Rule{appendRules[0], appendRules[1]},
			prependRules: []Rule{prependRules[0], prependRules[1]},
			storageOut:   []Rule{prependRules[1], prependRules[0], appendRules[0], appendRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		controller.appendRules = tc.appendRules
		controller.prependRules = tc.prependRules

		err = controller.reconcile()
		if err != nil {
			t.Fatalf("test case %q: unexpected error during reconcile: %v", tc.name, err)
		}

		if len(tc.storageOut) != len(client.storage) {
			t.Errorf("test case %q: expected %d rules in storage, got %d", tc.name, len(tc.storageOut), len(client.storage))
		} else {
			for i := range tc.storageOut {
				if tc.storageOut[i].String() != client.storage[i].String() {
					t.Errorf("test case %q: expected rule %d in storage to be equal: expected %v, got %v", tc.name, i, tc.storageOut[i], client.storage[i])
				}
			}
		}
	}
}
