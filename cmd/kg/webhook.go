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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	kilo "github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/version"
)

var webhookCmd = &cobra.Command{
	Use: "webhook",
	PreRunE: func(c *cobra.Command, a []string) error {
		if c.HasParent() {
			return c.Parent().PreRunE(c, a)
		}
		return nil
	},
	Short: "webhook starts a HTTPS server to validate updates and creations of Kilo peers.",
	RunE:  webhook,
}

var (
	certPath    string
	keyPath     string
	metricsAddr string
	listenAddr  string
)

func init() {
	webhookCmd.Flags().StringVar(&certPath, "cert-file", "", "The path to a certificate file")
	webhookCmd.Flags().StringVar(&keyPath, "key-file", "", "The path to a key file")
	webhookCmd.Flags().StringVar(&metricsAddr, "listen-metrics", ":1107", "The metrics server will be listening to that address")
	webhookCmd.Flags().StringVar(&listenAddr, "listen", ":8443", "The webhook server will be listening to that address")
}

var deserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

var (
	validationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "admission_requests_total",
			Help: "The number of received admission reviews requests",
		},
		[]string{"operation", "response"},
	)
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "The number of received http requests",
		},
		[]string{"handler", "method"},
	)
	errorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "The total number of errors",
		},
	)
)

func validationHandler(w http.ResponseWriter, r *http.Request) {
	_ = level.Debug(logger).Log("msg", "handling request", "source", r.RemoteAddr)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorCounter.Inc()
		_ = level.Error(logger).Log("err", "failed to parse body from incoming request", "source", r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var admissionReview v1.AdmissionReview

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		errorCounter.Inc()
		msg := fmt.Sprintf("received Content-Type=%s, expected application/json", contentType)
		_ = level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	response := v1.AdmissionReview{}

	_, gvk, err := deserializer.Decode(body, nil, &admissionReview)
	if err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		_ = level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if *gvk != v1.SchemeGroupVersion.WithKind("AdmissionReview") {
		errorCounter.Inc()
		msg := "only API v1 is supported"
		_ = level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	response.SetGroupVersionKind(*gvk)
	response.Response = &v1.AdmissionResponse{
		UID: admissionReview.Request.UID,
	}

	rawExtension := admissionReview.Request.Object
	var peer kilo.Peer

	if err := json.Unmarshal(rawExtension.Raw, &peer); err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("could not unmarshal extension to peer spec: %v:", err)
		_ = level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if err := peer.Validate(); err == nil {
		_ = level.Debug(logger).Log("msg", "got valid peer spec", "spec", peer.Spec, "name", peer.Name)
		validationCounter.With(prometheus.Labels{"operation": string(admissionReview.Request.Operation), "response": "allowed"}).Inc()
		response.Response.Allowed = true
	} else {
		_ = level.Debug(logger).Log("msg", "got invalid peer spec", "spec", peer.Spec, "name", peer.Name)
		validationCounter.With(prometheus.Labels{"operation": string(admissionReview.Request.Operation), "response": "denied"}).Inc()
		response.Response.Result = &metav1.Status{
			Message: err.Error(),
		}
	}

	res, err := json.Marshal(response)
	if err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("failed to marshal response: %v", err)
		_ = level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(res); err != nil {
		_ = level.Error(logger).Log("err", err, "msg", "failed to write response")
	}
}

func metricsMiddleWare(path string, next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		requestCounter.With(prometheus.Labels{"method": r.Method, "handler": path}).Inc()
		next(w, r)
	}
}

func webhook(_ *cobra.Command, _ []string) error {
	if printVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}
	registry.MustRegister(
		errorCounter,
		validationCounter,
		requestCounter,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()
	var g run.Group
	g.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))
	{
		mm := http.NewServeMux()
		mm.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		msrv := &http.Server{
			Addr:    metricsAddr,
			Handler: mm,
		}

		g.Add(
			func() error {
				_ = level.Info(logger).Log("msg", "starting metrics server", "address", msrv.Addr)
				err := msrv.ListenAndServe()
				_ = level.Info(logger).Log("msg", "metrics server exited", "err", err)
				return err

			},
			func(err error) {
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					_ = level.Info(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					_ = level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
				_ = level.Info(logger).Log("msg", "shutting down metrics server gracefully")
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer func() {
					cancel()
				}()
				if err := msrv.Shutdown(ctx); err != nil {
					_ = level.Error(logger).Log("msg", "failed to shut down metrics server gracefully", "err", err.Error())
					_ = msrv.Close()
				}
			},
		)
	}

	{
		mux := http.NewServeMux()
		mux.HandleFunc("/validate", metricsMiddleWare("/validate", validationHandler))
		srv := &http.Server{
			Addr:    listenAddr,
			Handler: mux,
		}
		g.Add(
			func() error {
				_ = level.Info(logger).Log("msg", "starting webhook server", "address", srv.Addr)
				err := srv.ListenAndServeTLS(certPath, keyPath)
				_ = level.Info(logger).Log("msg", "webhook server exited", "err", err)
				return err
			},
			func(err error) {
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					_ = level.Info(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					_ = level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
				_ = level.Info(logger).Log("msg", "shutting down webhook server gracefully")
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer func() {
					cancel()
				}()
				if err := srv.Shutdown(ctx); err != nil {
					_ = level.Error(logger).Log("msg", "failed to shut down webhook server gracefully", "err", err.Error())
					_ = srv.Close()
				}
			},
		)
	}

	err := g.Run()
	var serr run.SignalError
	if ok := errors.As(err, &serr); ok {
		return nil
	}
	return err
}
