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

package ipset

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
)

// Set represents an ipset.
// Set can safely be used concurrently.
type Set struct {
	errors     chan error
	hosts      map[string]struct{}
	mu         sync.Mutex
	name       string
	subscribed bool

	// Make these functions fields to allow
	// for testing.
	add func(string) error
	del func(string) error
}

func setExists(name string) (bool, error) {
	cmd := exec.Command("ipset", "list", "-n")
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("failed to check for set %s: %s", name, stderr.String())
	}
	return bytes.Contains(stdout.Bytes(), []byte(name)), nil
}

func hostInSet(set, name string) (bool, error) {
	cmd := exec.Command("ipset", "list", set)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("failed to check for host %s: %s", name, stderr.String())
	}
	return bytes.Contains(stdout.Bytes(), []byte(name)), nil
}

// New generates a new ipset.
func New(name string) *Set {
	return &Set{
		errors: make(chan error),
		hosts:  make(map[string]struct{}),
		name:   name,

		add: func(ip string) error {
			ok, err := hostInSet(name, ip)
			if err != nil {
				return err
			}
			if !ok {
				cmd := exec.Command("ipset", "add", name, ip)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to add host %s to set %s: %s", ip, name, stderr.String())
				}
			}
			return nil
		},
		del: func(ip string) error {
			ok, err := hostInSet(name, ip)
			if err != nil {
				return err
			}
			if ok {
				cmd := exec.Command("ipset", "del", name, ip)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to remove host %s from set %s: %s", ip, name, stderr.String())
				}
			}
			return nil
		},
	}
}

// Run watches for changes to the ipset and reconciles
// the ipset against the desired state.
func (s *Set) Run(stop <-chan struct{}) (<-chan error, error) {
	s.mu.Lock()
	if s.subscribed {
		s.mu.Unlock()
		return s.errors, nil
	}
	// Ensure a given instance only subscribes once.
	s.subscribed = true
	s.mu.Unlock()
	go func() {
		defer close(s.errors)
		for {
			select {
			case <-time.After(2 * time.Second):
			case <-stop:
				return
			}
			ok, err := setExists(s.name)
			if err != nil {
				nonBlockingSend(s.errors, err)
			}
			// The set does not exist so wait and try again later.
			if !ok {
				continue
			}
			s.mu.Lock()
			for h := range s.hosts {
				if err := s.add(h); err != nil {
					nonBlockingSend(s.errors, err)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s.errors, nil
}

// CleanUp will clean up any hosts added to the set.
func (s *Set) CleanUp() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.hosts {
		if err := s.del(h); err != nil {
			return err
		}
		delete(s.hosts, h)
	}
	return nil
}

// Set idempotently overwrites any hosts previously defined
// for the ipset with the given hosts.
func (s *Set) Set(hosts []net.IP) error {
	h := make(map[string]struct{})
	for _, host := range hosts {
		if host == nil {
			continue
		}
		h[host.String()] = struct{}{}
	}
	exists, err := setExists(s.name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.hosts {
		if _, ok := h[k]; !ok {
			if exists {
				if err := s.del(k); err != nil {
					return err
				}
			}
			delete(s.hosts, k)
		}
	}
	for k := range h {
		if _, ok := s.hosts[k]; !ok {
			if exists {
				if err := s.add(k); err != nil {
					return err
				}
			}
			s.hosts[k] = struct{}{}
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
