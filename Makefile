export GO111MODULE=on
.PHONY: push container clean container-name container-latest push-latest fmt lint test unit vendor header generate crd client deepcopy informer lister manifest manfest-latest manifest-annotate manifest manfest-latest manifest-annotate release gen-docs e2e

OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)
ALL_ARCH := amd64 arm arm64
DOCKER_ARCH := "amd64" "arm v7" "arm64 v8"
ifeq ($(OS),linux)
    BINS := bin/$(OS)/$(ARCH)/kg bin/$(OS)/$(ARCH)/kgctl
else
    BINS := bin/$(OS)/$(ARCH)/kgctl
endif
RELEASE_BINS := $(addprefix bin/release/kgctl-, $(addprefix linux-, $(ALL_ARCH)) darwin-amd64 darwin-arm64 windows-amd64)
PROJECT := kilo
PKG := github.com/squat/$(PROJECT)
REGISTRY ?= index.docker.io
IMAGE ?= squat/$(PROJECT)
FULLY_QUALIFIED_IMAGE := $(REGISTRY)/$(IMAGE)

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

CONTROLLER_GEN_BINARY := bin/controller-gen
CLIENT_GEN_BINARY := bin/client-gen
DOCS_GEN_BINARY := bin/docs-gen
DEEPCOPY_GEN_BINARY := bin/deepcopy-gen
INFORMER_GEN_BINARY := bin/informer-gen
LISTER_GEN_BINARY := bin/lister-gen
STATICCHECK_BINARY := bin/staticcheck
EMBEDMD_BINARY := bin/embedmd
KIND_BINARY := $(shell pwd)/bin/kind
KUBECTL_BINARY := $(shell pwd)/bin/kubectl
BASH_UNIT := $(shell pwd)/bin/bash_unit
BASH_UNIT_FLAGS :=

BUILD_IMAGE ?= golang:1.18.0
BASE_IMAGE ?= alpine:3.15

build: $(BINS)

build-%:
	@$(MAKE) --no-print-directory OS=$(word 1,$(subst -, ,$*)) ARCH=$(word 2,$(subst -, ,$*)) build

container-latest-%:
	@$(MAKE) --no-print-directory ARCH=$* container-latest

container-%:
	@$(MAKE) --no-print-directory ARCH=$* container

push-latest-%:
	@$(MAKE) --no-print-directory ARCH=$* push-latest

push-%:
	@$(MAKE) --no-print-directory ARCH=$* push

all-build: $(addprefix build-$(OS)-, $(ALL_ARCH))

all-container: $(addprefix container-, $(ALL_ARCH))

all-push: $(addprefix push-, $(ALL_ARCH))

all-container-latest: $(addprefix container-latest-, $(ALL_ARCH))

all-push-latest: $(addprefix push-latest-, $(ALL_ARCH))

generate: client deepcopy informer lister crd

crd: manifests/crds.yaml
manifests/crds.yaml: pkg/k8s/apis/kilo/v1alpha1/types.go $(CONTROLLER_GEN_BINARY)
	$(CONTROLLER_GEN_BINARY) crd \
	paths=./pkg/k8s/apis/kilo/... \
	output:crd:stdout > $@

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

gen-docs: generate docs/api.md docs/kg.md
docs/api.md: pkg/k8s/apis/kilo/v1alpha1/types.go $(DOCS_GEN_BINARY)
	$(DOCS_GEN_BINARY) $< > $@

$(BINS): $(SRC) go.mod
	@mkdir -p bin/$(word 2,$(subst /, ,$@))/$(word 3,$(subst /, ,$@))
	@echo "building: $@"
	@docker run --rm \
	    -u $$(id -u):$$(id -g) \
	    -v $$(pwd):/$(PROJECT) \
	    -w /$(PROJECT) \
	    $(BUILD_IMAGE) \
	    /bin/sh -c " \
	        GOARCH=$(word 3,$(subst /, ,$@)) \
	        GOOS=$(word 2,$(subst /, ,$@)) \
	        GOCACHE=/$(PROJECT)/.cache \
		CGO_ENABLED=0 \
		go build -mod=vendor -o $@ \
		    $(LD_FLAGS) \
		    ./cmd/$(@F)/... \
	    "

fmt:
	@echo $(GO_PKGS)
	gofmt -w -s $(GO_FILES)

lint: header $(STATICCHECK_BINARY)
	@echo 'go vet $(GO_PKGS)'
	@vet_res=$$(GO111MODULE=on go vet -mod=vendor $(GO_PKGS) 2>&1); if [ -n "$$vet_res" ]; then \
		echo ""; \
		echo "Go vet found issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review:"; \
		echo "$$vet_res"; \
		exit 1; \
	fi
	@echo '$(STATICCHECK_BINARY) $(GO_PKGS)'
	@lint_res=$$($(STATICCHECK_BINARY) $(GO_PKGS)); if [ -n "$$lint_res" ]; then \
		echo ""; \
		echo "Staticcheck found style issues. Please check the reported issues"; \
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

test: lint unit e2e

$(KIND_BINARY):
	curl -Lo $@ https://kind.sigs.k8s.io/dl/v0.11.1/kind-linux-$(ARCH)
	chmod +x $@

$(KUBECTL_BINARY):
	curl -Lo $@ https://dl.k8s.io/release/v1.21.0/bin/linux/$(ARCH)/kubectl
	chmod +x $@

$(BASH_UNIT):
	curl -Lo $@ https://raw.githubusercontent.com/pgrange/bash_unit/v1.7.2/bash_unit
	chmod +x $@

e2e: container $(KIND_BINARY) $(KUBECTL_BINARY) $(BASH_UNIT) bin/$(OS)/$(ARCH)/kgctl
	KILO_IMAGE=$(IMAGE):$(ARCH)-$(VERSION) KIND_BINARY=$(KIND_BINARY) KUBECTL_BINARY=$(KUBECTL_BINARY) KGCTL_BINARY=$(shell pwd)/bin/$(OS)/$(ARCH)/kgctl $(BASH_UNIT) $(BASH_UNIT_FLAGS) ./e2e/setup.sh ./e2e/full-mesh.sh ./e2e/location-mesh.sh ./e2e/multi-cluster.sh ./e2e/handlers.sh ./e2e/kgctl.sh ./e2e/teardown.sh

header: .header
	@HEADER=$$(cat .header); \
	HEADER_LEN=$$(wc -l .header | awk '{print $$1}'); \
	FILES=; \
	for f in $(GO_FILES); do \
		for i in 0 1 2 3 4 5; do \
			FILE=$$(t=$$(mktemp) && tail -n +$$i $$f > $$t && head -n $$HEADER_LEN $$t | sed "s/[0-9]\{4\}/YEAR/"); \
			[ "$$FILE" = "$$HEADER" ] && continue 2; \
		done; \
		FILES="$$FILES$$f "; \
	done; \
	if [ -n "$$FILES" ]; then \
		printf 'the following files are missing the license header: %s\n' "$$FILES"; \
		exit 1; \
	fi

tmp/help.txt: bin/$(OS)/$(ARCH)/kg
	mkdir -p tmp
	bin//$(OS)/$(ARCH)/kg --help 2>&1 | head -n -1 > $@

docs/kg.md: $(EMBEDMD_BINARY) tmp/help.txt
	$(EMBEDMD_BINARY) -w $@

website/docs/README.md: README.md
	rm -rf website/static/img/graphs
	find docs  -type f -name '*.md' | xargs -I{} sh -c 'cat $(@D)/$$(basename {} .md) > website/{}'
	find docs  -type f -name '*.md' | xargs -I{} sh -c 'cat {} >> website/{}'
	cat $(@D)/$$(basename $@ .md) > $@
	cat README.md >> $@
	cp -r docs/graphs website/static/img/
	sed -i 's/\.\/docs\///g' $@
	find $(@D)  -type f -name '*.md' | xargs -I{} sed -i 's/\.\/\(.\+\.\(svg\|png\)\)/\/img\/\1/g' {}
	sed -i 's/graphs\//\/img\/graphs\//g' $@
	# The next line is a workaround until mdx, docusaurus' markdown parser, can parse links with preceding brackets.
	sed -i  's/\[\]\(\[.*\](.*)\)/\&#91;\&#93;\1/g' website/docs/api.md

website/build/index.html: website/docs/README.md docs/api.md
	yarn --cwd website install
	yarn --cwd website build

container: .container-$(ARCH)-$(VERSION) container-name
.container-$(ARCH)-$(VERSION): bin/linux/$(ARCH)/kg Dockerfile
	@i=0; for a in $(ALL_ARCH); do [ "$$a" = $(ARCH) ] && break; i=$$((i+1)); done; \
	ia=""; iv=""; \
	j=0; for a in $(DOCKER_ARCH); do \
	    [ "$$i" -eq "$$j" ] && ia=$$(echo "$$a" | awk '{print $$1}') && iv=$$(echo "$$a" | awk '{print $$2}') && break; j=$$((j+1)); \
	done; \
	SHA=$$(docker manifest inspect $(BASE_IMAGE) | jq '.manifests[] | select(.platform.architecture == "'$$ia'") | if .platform | has("variant") then select(.platform.variant == "'$$iv'") else . end | .digest' -r); \
	docker build -t $(IMAGE):$(ARCH)-$(VERSION) --build-arg FROM=$(BASE_IMAGE)@$$SHA --build-arg GOARCH=$(ARCH) .
	@docker images -q $(IMAGE):$(ARCH)-$(VERSION) > $@

container-latest: .container-$(ARCH)-$(VERSION)
	@docker tag $(IMAGE):$(ARCH)-$(VERSION) $(FULLY_QUALIFIED_IMAGE):$(ARCH)-latest
	@echo "container: $(IMAGE):$(ARCH)-latest"

container-name:
	@echo "container: $(IMAGE):$(ARCH)-$(VERSION)"

manifest: .manifest-$(VERSION) manifest-name
.manifest-$(VERSION): Dockerfile $(addprefix push-, $(ALL_ARCH))
	@docker manifest create --amend $(FULLY_QUALIFIED_IMAGE):$(VERSION) $(addsuffix -$(VERSION), $(addprefix $(FULLY_QUALIFIED_IMAGE):, $(ALL_ARCH)))
	@$(MAKE) --no-print-directory manifest-annotate-$(VERSION)
	@docker manifest push $(FULLY_QUALIFIED_IMAGE):$(VERSION) > $@

manifest-latest: Dockerfile $(addprefix push-latest-, $(ALL_ARCH))
	@docker manifest rm $(FULLY_QUALIFIED_IMAGE):latest || echo no old manifest
	@docker manifest create --amend $(FULLY_QUALIFIED_IMAGE):latest $(addsuffix -latest, $(addprefix $(FULLY_QUALIFIED_IMAGE):, $(ALL_ARCH)))
	@$(MAKE) --no-print-directory manifest-annotate-latest
	@docker manifest push $(FULLY_QUALIFIED_IMAGE):latest
	@echo "manifest: $(IMAGE):latest"

manifest-annotate: manifest-annotate-$(VERSION)

manifest-annotate-%:
	@i=0; \
	for a in $(ALL_ARCH); do \
	    annotate=; \
	    j=0; for da in $(DOCKER_ARCH); do \
		if [ "$$j" -eq "$$i" ] && [ -n "$$da" ]; then \
		    annotate="docker manifest annotate $(FULLY_QUALIFIED_IMAGE):$* $(FULLY_QUALIFIED_IMAGE):$$a-$* --os linux --arch"; \
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
	@echo "manifest: $(IMAGE):$(VERSION)"

push: .push-$(ARCH)-$(VERSION) push-name
.push-$(ARCH)-$(VERSION): .container-$(ARCH)-$(VERSION)
ifneq ($(REGISTRY),index.docker.io)
	@docker tag $(IMAGE):$(ARCH)-$(VERSION) $(FULLY_QUALIFIED_IMAGE):$(ARCH)-$(VERSION)
endif
	@docker push $(FULLY_QUALIFIED_IMAGE):$(ARCH)-$(VERSION)
	@docker images -q $(IMAGE):$(ARCH)-$(VERSION) > $@

push-latest: container-latest
	@docker push $(FULLY_QUALIFIED_IMAGE):$(ARCH)-latest
	@echo "pushed: $(IMAGE):$(ARCH)-latest"

push-name:
	@echo "pushed: $(IMAGE):$(ARCH)-$(VERSION)"

release: $(RELEASE_BINS)
$(RELEASE_BINS):
	@make OS=$(word 2,$(subst -, ,$(@F))) ARCH=$(word 3,$(subst -, ,$(@F)))
	mkdir -p $(@D)
	cp bin/$(word 2,$(subst -, ,$(@F)))/$(word 3,$(subst -, ,$(@F)))/kgctl $@

clean: container-clean bin-clean
	rm -rf .cache

container-clean:
	rm -rf .container-* .manifest-* .push-*

bin-clean:
	rm -rf bin

vendor:
	go mod tidy
	go mod vendor

$(CONTROLLER_GEN_BINARY):
	go build -mod=vendor -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(CLIENT_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/client-gen

$(DEEPCOPY_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(INFORMER_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/informer-gen

$(LISTER_GEN_BINARY):
	go build -mod=vendor -o $@ k8s.io/code-generator/cmd/lister-gen

$(DOCS_GEN_BINARY): cmd/docs-gen/main.go
	go build -mod=vendor -o $@ ./cmd/docs-gen

$(STATICCHECK_BINARY):
	go build -mod=vendor -o $@ honnef.co/go/tools/cmd/staticcheck

$(EMBEDMD_BINARY):
	go build -mod=vendor -o $@ github.com/campoy/embedmd
