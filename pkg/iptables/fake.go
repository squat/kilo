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

type fakeClient struct {
	storage []Rule
}

var _ Client = &fakeClient{}

func (f *fakeClient) AppendUnique(table, chain string, spec ...string) error {
	exists, err := f.Exists(table, chain, spec...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	f.storage = append(f.storage, &rule{table, chain, spec})
	return nil
}

func (f *fakeClient) Delete(table, chain string, spec ...string) error {
	r := &rule{table, chain, spec}
	for i := range f.storage {
		if f.storage[i].String() == r.String() {
			copy(f.storage[i:], f.storage[i+1:])
			f.storage[len(f.storage)-1] = nil
			f.storage = f.storage[:len(f.storage)-1]
			break
		}
	}
	return nil
}

func (f *fakeClient) Exists(table, chain string, spec ...string) (bool, error) {
	r := &rule{table, chain, spec}
	for i := range f.storage {
		if f.storage[i].String() == r.String() {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeClient) ClearChain(table, name string) error {
	for i := range f.storage {
		r, ok := f.storage[i].(*rule)
		if !ok {
			continue
		}
		if table == r.table && name == r.chain {
			if err := f.Delete(table, name, r.spec...); err != nil {
				return nil
			}
		}
	}
	return f.DeleteChain(table, name)
}

func (f *fakeClient) DeleteChain(table, name string) error {
	for i := range f.storage {
		r, ok := f.storage[i].(*rule)
		if !ok {
			continue
		}
		if table == r.table && name == r.chain {
			return fmt.Errorf("cannot delete chain %s; rules exist", name)
		}
	}
	c := &chain{table, name}
	for i := range f.storage {
		if f.storage[i].String() == c.String() {
			copy(f.storage[i:], f.storage[i+1:])
			f.storage[len(f.storage)-1] = nil
			f.storage = f.storage[:len(f.storage)-1]
			break
		}
	}
	return nil
}

func (f *fakeClient) NewChain(table, name string) error {
	c := &chain{table, name}
	for i := range f.storage {
		if f.storage[i].String() == c.String() {
			return statusError(1)
		}
	}
	f.storage = append(f.storage, c)
	return nil
}
