// Copyright 2021 the Kilo authors
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

func TestRuleCache(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []Rule
		check []Rule
		out   []bool
		calls uint64
	}{
		{
			name:  "empty",
			rules: nil,
			check: []Rule{appendRules[0]},
			out:   []bool{false},
			calls: 1,
		},
		{
			name:  "single negative",
			rules: []Rule{appendRules[1]},
			check: []Rule{appendRules[0]},
			out:   []bool{false},
			calls: 1,
		},
		{
			name:  "single positive",
			rules: []Rule{appendRules[1]},
			check: []Rule{appendRules[1]},
			out:   []bool{true},
			calls: 1,
		},
		{
			name:  "single chain",
			rules: []Rule{&chain{"nat", "KILO-NAT", ProtocolIPv4}},
			check: []Rule{&chain{"nat", "KILO-NAT", ProtocolIPv4}},
			out:   []bool{true},
			calls: 1,
		},
		{
			name:  "rule on chain means chain exists",
			rules: []Rule{appendRules[0]},
			check: []Rule{appendRules[0], &chain{"filter", "FORWARD", ProtocolIPv4}},
			out:   []bool{true, true},
			calls: 1,
		},
		{
			name:  "rule on chain does not mean table is fully populated",
			rules: []Rule{appendRules[0], &chain{"filter", "INPUT", ProtocolIPv4}},
			check: []Rule{appendRules[0], &chain{"filter", "OUTPUT", ProtocolIPv4}, &chain{"filter", "INPUT", ProtocolIPv4}},
			out:   []bool{true, false, true},
			calls: 2,
		},
		{
			name:  "multiple rules on chain",
			rules: []Rule{appendRules[0], appendRules[1]},
			check: []Rule{appendRules[0], appendRules[1], &chain{"filter", "FORWARD", ProtocolIPv4}},
			out:   []bool{true, true, true},
			calls: 1,
		},
		{
			name:  "checking rule on chain does not mean chain exists",
			rules: nil,
			check: []Rule{appendRules[0], &chain{"filter", "FORWARD", ProtocolIPv4}},
			out:   []bool{false, false},
			calls: 2,
		},
		{
			name:  "multiple chains on same table",
			rules: nil,
			check: []Rule{&chain{"filter", "INPUT", ProtocolIPv4}, &chain{"filter", "FORWARD", ProtocolIPv4}},
			out:   []bool{false, false},
			calls: 1,
		},
		{
			name:  "multiple chains on different table",
			rules: nil,
			check: []Rule{&chain{"filter", "INPUT", ProtocolIPv4}, &chain{"nat", "POSTROUTING", ProtocolIPv4}},
			out:   []bool{false, false},
			calls: 2,
		},
	} {
		controller := &Controller{}
		client := &fakeClient{}
		controller.v4 = client
		controller.v6 = client
		ruleSet := RuleSet{AppendRules: tc.rules}
		if err := controller.Set(ruleSet); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		// Reset the client's calls so we can examine how many times
		// the rule cache performs operations.
		client.calls = 0
		var rc ruleCache
		for i := range tc.check {
			ok, err := rc.exists(controller.client(tc.check[i].Proto()), tc.check[i])
			if err != nil {
				t.Fatalf("test case %q check %d: check should not fail: %v", tc.name, i, err)
			}
			if ok != tc.out[i] {
				t.Errorf("test case %q check %d: expected %t, got %t", tc.name, i, tc.out[i], ok)
			}
		}
		if client.calls != tc.calls {
			t.Errorf("test case %q: expected client to be called %d times, got %d", tc.name, tc.calls, client.calls)
		}
	}

}
