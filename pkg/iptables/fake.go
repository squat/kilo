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
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

type statusExiter interface {
	ExitStatus() int
}

var _ statusExiter = (*iptables.Error)(nil)
var _ statusExiter = statusError(0)

type statusError int

func (s statusError) Error() string {
	return fmt.Sprintf("%d", s)
}

func (s statusError) ExitStatus() int {
	return int(s)
}

type fakeClient map[string]Rule

var _ iptablesClient = fakeClient(nil)

func (f fakeClient) AppendUnique(table, chain string, spec ...string) error {
	r := &rule{table, chain, spec, nil}
	f[r.String()] = r
	return nil
}

func (f fakeClient) Delete(table, chain string, spec ...string) error {
	r := &rule{table, chain, spec, nil}
	delete(f, r.String())
	return nil
}

func (f fakeClient) Exists(table, chain string, spec ...string) (bool, error) {
	r := &rule{table, chain, spec, nil}
	_, ok := f[r.String()]
	return ok, nil
}

func (f fakeClient) ClearChain(table, name string) error {
	c := &chain{table, name, nil}
	for k := range f {
		if strings.HasPrefix(k, c.String()) {
			delete(f, k)
		}
	}
	f[c.String()] = c
	return nil
}

func (f fakeClient) DeleteChain(table, name string) error {
	c := &chain{table, name, nil}
	for k := range f {
		if strings.HasPrefix(k, c.String()) {
			return fmt.Errorf("cannot delete chain %s; rules exist", name)
		}
	}
	delete(f, c.String())
	return nil
}

func (f fakeClient) NewChain(table, name string) error {
	c := &chain{table, name, nil}
	if _, ok := f[c.String()]; ok {
		return statusError(1)
	}
	f[c.String()] = c
	return nil
}
