export GO111MODULE=on
.PHONY: push container clean container-name container-latest push-latest fmt lint test unit vendor header generate client deepcopy informer lister openapi manifest manfest-latest manifest-annotate manifest manfest-latest manifest-annotate

ARCH ?= amd64
ALL_ARCH := amd64 arm arm64
DOCKER_ARCH := "" "arm v7" "arm64 v8"
IMAGE_ARCH := amd64 armhf arm64
BINS := $(addprefix bin/$(ARCH)/,kg kgctl)
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

CLIENT_GEN_BINARY := bin/client-gen
DEEPCOPY_GEN_BINARY := bin/deepcopy-gen
INFORMER_GEN_BINARY := bin/informer-gen
LISTER_GEN_BINARY := bin/lister-gen
OPENAPI_GEN_BINARY := bin/openapi-gen
GOLINT_BINARY := bin/golint

BUILD_IMAGE ?= golang:1.13.4-alpine

build: $(BINS)

build-%:
	@$(MAKE) --no-print-directory ARCH=$* build

container-latest-%:
	@$(MAKE) --no-print-directory ARCH=$* container-latest

container-%:
	@$(MAKE) --no-print-directory ARCH=$* container

push-latest-%:
	@$(MAKE) --no-print-directory ARCH=$* push-latest

push-%:
	@$(MAKE) --no-print-directory ARCH=$* push

all-build: $(addprefix build-, $(ALL_ARCH))

all-container: $(addprefix container-, $(ALL_ARCH))

all-push: $(addprefix push-, $(ALL_ARCH))

all-container-latest: $(addprefix container-latest-, $(ALL_ARCH))

all-push-latest: $(addprefix push-latest-, $(ALL_ARCH))

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
	rm -r pkg/k8s/clientset || true
	mv $(PKG)/pkg/k8s/clientset pkg/k8s
	rm -r github.com || true
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
	rm -r pkg/k8s/informers || true
	mv $(PKG)/pkg/k8s/informers pkg/k8s
	rm -r github.com || true
	go fmt ./pkg/k8s/informers/...

lister: pkg/k8s/listers/kilo/v1alpha1/peer.go
pkg/k8s/listers/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go $(LISTER_GEN_BINARY)
	$(LISTER_GEN_BINARY) \
	--input-dirs $(PKG)/pkg/k8s/apis/kilo/v1alpha1 \
	--go-header-file=.header \
	--logtostderr \
	--output-base $(CURDIR) \
	--output-package $(PKG)/pkg/k8s/listers
	rm -r pkg/k8s/listers || true
	mv $(PKG)/pkg/k8s/listers pkg/k8s
	rm -r github.com || true
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
	@mkdir -p bin/$(ARCH)
	@echo "building: $@"
	@docker run --rm \
	    -u $$(id -u):$$(id -g) \
	    -v $$(pwd):/$(PROJECT) \
	    -w /$(PROJECT) \
	    $(BUILD_IMAGE) \
	    /bin/sh -c " \
	        GOARCH=$(ARCH) \
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

lint: header $(GOLINT_BINARY)
	@echo 'go vet $(GO_PKGS)'
	@vet_res=$$(GO111MODULE=on go vet -mod=vendor $(GO_PKGS) 2>&1); if [ -n "$$vet_res" ]; then \
		echo ""; \
		echo "Go vet found issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review:"; \
		echo "$$vet_res"; \
		exit 1; \
	fi
	@echo '$(GOLINT_BINARY) $(GO_PKGS)'
	@lint_res=$$($(GOLINT_BINARY) $(GO_PKGS)); if [ -n "$$lint_res" ]; then \
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

container: .container-$(ARCH)-$(VERSION) container-name
.container-$(ARCH)-$(VERSION): $(BINS) Dockerfile
	@i=0; for a in $(ALL_ARCH); do [ "$$a" = $(ARCH) ] && break; i=$$((i+1)); done; \
	ia=""; \
	j=0; for a in $(IMAGE_ARCH); do [ "$$i" -eq "$$j" ] && ia="$$a" && break; j=$$((j+1)); done; \
	docker build -t $(IMAGE):$(ARCH)-$(VERSION) --build-arg FROM=multiarch/alpine:$$ia-v3.10 --build-arg GOARCH=$(ARCH) .
	@docker images -q $(IMAGE):$(ARCH)-$(VERSION) > $@

container-latest: .container-$(ARCH)-$(VERSION)
	@docker tag $(IMAGE):$(ARCH)-$(VERSION) $(IMAGE):$(ARCH)-latest
	@echo "container: $(IMAGE):$(ARCH)-latest"

container-name:
	@echo "container: $(IMAGE):$(ARCH)-$(VERSION)"

manifest: .manifest-$(VERSION) manifest-name
.manifest-$(VERSION): Dockerfile $(addprefix push-, $(ALL_ARCH))
	@docker manifest create --amend $(IMAGE):$(VERSION) $(addsuffix -$(VERSION), $(addprefix squat/$(PROJECT):, $(ALL_ARCH)))
	@$(MAKE) --no-print-directory manifest-annotate-$(VERSION)
	@docker manifest push $(IMAGE):$(VERSION) > $@

manifest-latest: Dockerfile $(addprefix push-latest-, $(ALL_ARCH))
	@docker manifest create --amend $(IMAGE):latest $(addsuffix -latest, $(addprefix squat/$(PROJECT):, $(ALL_ARCH)))
	@$(MAKE) --no-print-directory manifest-annotate-latest
	@docker manifest push $(IMAGE):latest
	@echo "manifest: $(IMAGE):latest"

manifest-annotate: manifest-annotate-$(VERSION)

manifest-annotate-%:
	@i=0; \
	for a in $(ALL_ARCH); do \
	    annotate=; \
	    j=0; for da in $(DOCKER_ARCH); do \
		if [ "$$j" -eq "$$i" ] && [ -n "$$da" ]; then \
		    annotate="docker manifest annotate $(IMAGE):$* $(IMAGE):$$a-$* --os linux --arch"; \
		    k=0; for ea in $$da; do \
			[ "$$k" = 0 ] && annotate="$$annotate $$ea"; \
			[ "$$k" != 0 ] && annotate="$$annotate --variant $$ea"; \
			k=$$((k+1)); \
		    done; \
		    $$annotate; \
		fi; \
		j=$$((j+1)); \
	    done; \
	    i=$$((i+1)); \
	done

manifest-name:
	@echo "manifest: $(IMAGE_ROOT):$(VERSION)"

push: .push-$(ARCH)-$(VERSION) push-name
.push-$(ARCH)-$(VERSION): .container-$(ARCH)-$(VERSION)
	@docker push $(REGISTRY)/$(IMAGE):$(ARCH)-$(VERSION)
	@docker images -q $(IMAGE):$(ARCH)-$(VERSION) > $@

push-latest: container-latest
	@docker push $(REGISTRY)/$(IMAGE):$(ARCH)-latest
	@echo "pushed: $(IMAGE):$(ARCH)-latest"

push-name:
	@echo "pushed: $(IMAGE):$(ARCH)-$(VERSION)"

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
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/client-gen

$(DEEPCOPY_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(INFORMER_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/informer-gen

$(LISTER_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/lister-gen

$(OPENAPI_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/kube-openapi/cmd/openapi-gen

$(GOLINT_BINARY):
	go build -mod=vendor -o $@ golang.org/x/lint/golint
