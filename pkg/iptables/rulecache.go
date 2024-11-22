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
	"fmt"
	"strings"
)

type ruleCacheFlag byte

const (
	exists ruleCacheFlag = 1 << iota
	populated
)

type isNotExistError interface {
	error
	IsNotExist() bool
}

// ruleCache is a lazy cache that can be used to
// check if a given rule or chain exists in an iptables
// table.
type ruleCache [2]map[string]ruleCacheFlag

func (rc *ruleCache) populateTable(c Client, proto Protocol, table string) error {
	// If the table already exists in the destination map,
	// exit early since it has already been populated.
	if rc[proto][table]&populated != 0 {
		return nil
	}
	cs, err := c.ListChains(table)
	if err != nil {
		return fmt.Errorf("failed to populate chains for table %q: %v", table, err)
	}
	rc[proto][table] = exists | populated
	for i := range cs {
		rc[proto][chainToString(table, cs[i])] |= exists
	}
	return nil
}

func (rc *ruleCache) populateChain(c Client, proto Protocol, table, chain string) error {
	// If the destination chain true, then it has already been populated.
	if rc[proto][chainToString(table, chain)]&populated != 0 {
		return nil
	}
	rs, err := c.List(table, chain)
	if err != nil {
		if existsErr, ok := err.(isNotExistError); ok && existsErr.IsNotExist() {
			rc[proto][chainToString(table, chain)] = populated
			return nil
		}
		return fmt.Errorf("failed to populate rules in chain %q for table %q: %v", chain, table, err)
	}
	for i := range rs {
		rc[proto][strings.Join([]string{table, rs[i]}, " ")] = exists
	}
	// If there are rules on the chain, then the chain exists too.
	if len(rs) > 0 {
		rc[proto][chainToString(table, chain)] = exists
	}
	rc[proto][chainToString(table, chain)] |= populated
	return nil
}

func (rc *ruleCache) populateRules(c Client, r Rule) error {
	// Ensure a map for the proto exists.
	if rc[r.Proto()] == nil {
		rc[r.Proto()] = make(map[string]ruleCacheFlag)
	}

	if ch, ok := r.(*chain); ok {
		return rc.populateTable(c, r.Proto(), ch.table)
	}

	ru := r.(*rule)
	return rc.populateChain(c, r.Proto(), ru.table, ru.chain)
}

func (rc *ruleCache) exists(c Client, r Rule) (bool, error) {
	// Exit early if the exact rule exists by name.
	if rc[r.Proto()][r.String()]&exists != 0 {
		return true, nil
	}

	// Otherwise, populate the respective rules.
	if err := rc.populateRules(c, r); err != nil {
		return false, err
	}

	return rc[r.Proto()][r.String()]&exists != 0, nil
}
