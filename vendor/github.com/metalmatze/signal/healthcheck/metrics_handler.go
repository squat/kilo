// Copyright 2020 by the contributors.
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

package healthcheck

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

type metricsHandler struct {
	handler  Handler
	registry prometheus.Registerer
}

// NewMetricsHandler returns a healthy Handler that writes the current check status
// into the provided Prometheus registry.
func NewMetricsHandler(handler Handler, registry prometheus.Registerer) Handler {
	return &metricsHandler{
		handler:  handler,
		registry: registry,
	}
}

func (h *metricsHandler) AddLivenessCheck(name string, check Check) {
	h.handler.AddLivenessCheck(name, h.wrap(prometheus.Labels{"name": name, "check": "live"}, check))
}

func (h *metricsHandler) AddReadinessCheck(name string, check Check) {
	h.handler.AddReadinessCheck(name, h.wrap(prometheus.Labels{"name": name, "check": "ready"}, check))
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *metricsHandler) LiveEndpoint(w http.ResponseWriter, r *http.Request) {
	h.handler.LiveEndpoint(w, r)
}

func (h *metricsHandler) ReadyEndpoint(w http.ResponseWriter, r *http.Request) {
	h.handler.ReadyEndpoint(w, r)
}

func (h *metricsHandler) wrap(labels prometheus.Labels, check Check) Check {
	h.registry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name:        "healthcheck",
			Help:        "Indicates if check is healthy (1 is healthy, 0 is unhealthy)",
			ConstLabels: labels,
		},
		func() float64 {
			if check() != nil {
				return 0
			}
			return 1
		},
	))
	return check
}
