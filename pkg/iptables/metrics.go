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
	"github.com/prometheus/client_golang/prometheus"
)

type metricsClientWrapper struct {
	client           Client
	operationCounter *prometheus.CounterVec
}

func wrapWithMetrics(client Client, protocol string, registerer prometheus.Registerer) Client {
	labelNames := []string{
		"operation",
		"table",
		"chain",
	}
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "kilo_iptables_operations_total",
		Help:        "Number of iptables operations.",
		ConstLabels: prometheus.Labels{"protocol": protocol},
	}, labelNames)
	registerer.MustRegister(counter)
	return &metricsClientWrapper{client, counter}
}

func (m *metricsClientWrapper) AppendUnique(table string, chain string, rule ...string) error {
	m.operationCounter.With(prometheus.Labels{
		"operation": "AppendUnique",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.AppendUnique(table, chain, rule...)
}

func (m *metricsClientWrapper) Delete(table string, chain string, rule ...string) error {
	m.operationCounter.With(prometheus.Labels{
		"operation": "Delete",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.Delete(table, chain, rule...)
}

func (m *metricsClientWrapper) Exists(table string, chain string, rule ...string) (bool, error) {
	m.operationCounter.With(prometheus.Labels{
		"operation": "Exists",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.Exists(table, chain, rule...)
}

func (m *metricsClientWrapper) List(table string, chain string) ([]string, error) {
	m.operationCounter.With(prometheus.Labels{
		"operation": "List",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.List(table, chain)
}

func (m *metricsClientWrapper) ClearChain(table string, chain string) error {
	m.operationCounter.With(prometheus.Labels{
		"operation": "ClearChain",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.ClearChain(table, chain)
}

func (m *metricsClientWrapper) DeleteChain(table string, chain string) error {
	m.operationCounter.With(prometheus.Labels{
		"operation": "DeleteChain",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.DeleteChain(table, chain)
}

func (m *metricsClientWrapper) NewChain(table string, chain string) error {
	m.operationCounter.With(prometheus.Labels{
		"operation": "NewChain",
		"table":     table,
		"chain":     chain,
	}).Inc()
	return m.client.NewChain(table, chain)
}

func (m *metricsClientWrapper) ListChains(table string) ([]string, error) {
	m.operationCounter.With(prometheus.Labels{
		"operation": "ListChains",
		"table":     table,
		"chain":     "",
	}).Inc()
	return m.client.ListChains(table)
}
