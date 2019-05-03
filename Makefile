export GO111MODULE=on
.PHONY: all push container clean container-name container-latest push-latest fmt lint test unit vendor header generate client deepcopy informer lister openapi

BINS := $(addprefix bin/,kg kgctl)
PROJECT := kilo
PKG := github.com/squat/$(PROJECT)
REGISTRY ?= index.docker.io
IMAGE ?= squat/$(PROJECT)

TAG := $(shell git describe --abbrev=0 --tags HEAD 2>/dev/null)
COMMIT := $(shell git rev-parse HEAD)
VERSION := $(COMMIT)
ifneq ($(TAG),)
    ifeq ($(COMMIT), $(shell git rev-list -n1 $(TAG)))
        VERSION := $(TAG)
    endif
endif
DIRTY := $(shell test -z "$$(git diff --shortstat 2>/dev/null)" || echo -dirty)
VERSION := $(VERSION)$(DIRTY)
LD_FLAGS := -ldflags '-X $(PKG)/pkg/version.Version=$(VERSION)'
SRC := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GO_FILES ?= $$(find . -name '*.go' -not -path './vendor/*')
GO_PKGS ?= $$(go list ./... | grep -v "$(PKG)/vendor")

CLIENT_GO_VERSION := release-11.0
CODE_GENERATOR_VERSION := release-1.14
KUBE_OPENAPI_VERSION := b3a7cee44
CLIENT_GEN_BINARY:=$(GOPATH)/bin/client-gen
DEEPCOPY_GEN_BINARY:=$(GOPATH)/bin/deepcopy-gen
INFORMER_GEN_BINARY:=$(GOPATH)/bin/informer-gen
LISTER_GEN_BINARY:=$(GOPATH)/bin/lister-gen
OPENAPI_GEN_BINARY:=$(GOPATH)/bin/openapi-gen

BUILD_IMAGE ?= golang:1.12.1-alpine

all: build

build: $(BINS)

generate: client deepcopy informer lister openapi

client: pkg/k8s/clientset/versioned/typed/kilo/v1alpha1/peer.go
pkg/k8s/clientset/versioned/typed/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go $(CLIENT_GEN_BINARY)
	$(CLIENT_GEN_BINARY) \
	--clientset-name versioned \
	--input-base "" \
	--input $(PKG)/pkg/k8s/apis/kilo/v1alpha1 \
	--output-base $(CURDIR) \
	--output-package $(PKG)/pkg/k8s/clientset \
	--go-header-file=.header \
	--logtostderr
	rm -r pkg/k8s/clientset
	mv $(PKG)/pkg/k8s/clientset pkg/k8s
	rm -r github.com
	go fmt ./pkg/k8s/clientset/...

deepcopy: pkg/k8s/apis/kilo/v1alpha1/zz_generated.deepcopy.go
pkg/k8s/apis/kilo/v1alpha1/zz_generated.deepcopy.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go $(DEEPCOPY_GEN_BINARY)
	$(DEEPCOPY_GEN_BINARY) \
	--input-dirs ./$(@D) \
	--go-header-file=.header \
	--logtostderr \
	--output-base $(CURDIR) \
	--output-file-base zz_generated.deepcopy
	mv $(PKG)/$@ $@ || true
	rm -r github.com || true
	go fmt $@

informer: pkg/k8s/informers/kilo/v1alpha1/peer.go
pkg/k8s/informers/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go $(INFORMER_GEN_BINARY)
	$(INFORMER_GEN_BINARY) \
	--input-dirs $(PKG)/pkg/k8s/apis/kilo/v1alpha1 \
	--go-header-file=.header \
	--logtostderr \
	--versioned-clientset-package $(PKG)/pkg/k8s/clientset/versioned \
	--listers-package $(PKG)/pkg/k8s/listers \
	--output-base $(CURDIR) \
	--output-package $(PKG)/pkg/k8s/informers \
	--single-directory
	rm -r pkg/k8s/informers
	mv $(PKG)/pkg/k8s/informers pkg/k8s
	rm -r github.com
	go fmt ./pkg/k8s/informers/...

lister: pkg/k8s/listers/kilo/v1alpha1/peer.go
pkg/k8s/listers/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go $(LISTER_GEN_BINARY)
	$(LISTER_GEN_BINARY) \
	--input-dirs $(PKG)/pkg/k8s/apis/kilo/v1alpha1 \
	--go-header-file=.header \
	--logtostderr \
	--output-base $(CURDIR) \
	--output-package $(PKG)/pkg/k8s/listers
	rm -r pkg/k8s/listers
	mv $(PKG)/pkg/k8s/listers pkg/k8s
	rm -r github.com
	go fmt ./pkg/k8s/listers/...

openapi: pkg/k8s/apis/kilo/v1alpha1/openapi_generated.go
pkg/k8s/apis/kilo/v1alpha1/openapi_generated.go: pkg/k8s/apis/kilo/v1alpha1/types.go $(OPENAPI_GEN_BINARY)
	$(OPENAPI_GEN_BINARY) \
	--input-dirs $(PKG)/$(@D),k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/api/core/v1 \
	--output-base $(CURDIR) \
	--output-package ./$(@D) \
	--logtostderr \
	--report-filename /dev/null \
	--go-header-file=.header
	go fmt $@

$(BINS): $(SRC) go.mod
	@mkdir -p bin
	@echo "building: $@"
	@docker run --rm \
	    -u $$(id -u):$$(id -g) \
	    -v $$(pwd):/$(PROJECT) \
	    -w /$(PROJECT) \
	    $(BUILD_IMAGE) \
	    /bin/sh -c " \
	        GOOS=linux \
	        GOCACHE=/$(PROJECT)/.cache \
		CGO_ENABLED=0 \
		go build -mod=vendor -o $@ \
		    $(LD_FLAGS) \
		    ./cmd/$(@F)/... \
	    "

fmt:
	@echo $(GO_PKGS)
	gofmt -w -s $(GO_FILES)

lint: header
	@echo 'go vet $(GO_PKGS)'
	@vet_res=$$(GO111MODULE=on go vet -mod=vendor $(GO_PKGS) 2>&1); if [ -n "$$vet_res" ]; then \
		echo ""; \
		echo "Go vet found issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review:"; \
		echo "$$vet_res"; \
		exit 1; \
	fi
	@echo 'golint $(GO_PKGS)'
	@lint_res=$$(golint $(GO_PKGS)); if [ -n "$$lint_res" ]; then \
		echo ""; \
		echo "Golint found style issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review:"; \
		echo "$$lint_res"; \
		exit 1; \
	fi
	@echo 'gofmt -d -s $(GO_FILES)'
	@fmt_res=$$(gofmt -d -s $(GO_FILES)); if [ -n "$$fmt_res" ]; then \
		echo ""; \
		echo "Gofmt found style issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review:"; \
		echo "$$fmt_res"; \
		exit 1; \
	fi

unit:
	go test -mod=vendor --race ./...

test: lint unit

header: .header
	@HEADER=$$(sed "s/YEAR/$$(date '+%Y')/" .header); \
	HEADER_LEN=$$(wc -l .header | awk '{print $$1}'); \
	FILES=; \
	for f in $(GO_FILES); do \
		for i in 0 1 2 3 4 5; do \
			FILE=$$(tail -n +$$i $$f | head -n $$HEADER_LEN); \
			[ "$$FILE" = "$$HEADER" ] && continue 2; \
		done; \
		FILES="$$FILES$$f "; \
	done; \
	if [ -n "$$FILES" ]; then \
		printf 'the following files are missing the license header: %s\n' "$$FILES"; \
		exit 1; \
	fi

container: .container-$(VERSION) container-name
.container-$(VERSION): $(BINS) Dockerfile
	@docker build -t $(IMAGE):$(VERSION) .
	@docker images -q $(IMAGE):$(VERSION) > $@

container-latest: .container-$(VERSION)
	@docker tag $(IMAGE):$(VERSION) $(IMAGE):latest
	@echo "container: $(IMAGE):latest"

container-name:
	@echo "container: $(IMAGE):$(VERSION)"

push: .push-$(VERSION) push-name
.push-$(VERSION): .container-$(VERSION)
	@docker push $(REGISTRY)/$(IMAGE):$(VERSION)
	@docker images -q $(IMAGE):$(VERSION) > $@

push-latest: container-latest
	@docker push $(REGISTRY)/$(IMAGE):latest
	@echo "pushed: $(IMAGE):latest"

push-name:
	@echo "pushed: $(IMAGE):$(VERSION)"

clean: container-clean bin-clean
	rm -r .cache

container-clean:
	rm -rf .container-* .push-*

bin-clean:
	rm -rf bin

vendor:
	go mod tidy
	go mod vendor

$(CLIENT_GEN_BINARY):
	go get k8s.io/code-generator/cmd/client-gen@$(CODE_GENERATOR_VERSION)

$(DEEPCOPY_GEN_BINARY):
	go get k8s.io/code-generator/cmd/deepcopy-gen@$(CODE_GENERATOR_VERSION)

$(INFORMER_GEN_BINARY):
	go get k8s.io/code-generator/cmd/informer-gen@$(CODE_GENERATOR_VERSION)

$(LISTER_GEN_BINARY):
	go get k8s.io/code-generator/cmd/lister-gen@$(CODE_GENERATOR_VERSION)

$(OPENAPI_GEN_BINARY):
	go get k8s.io/kube-openapi/cmd/openapi-gen@$(KUBE_OPENAPI_VERSION)
