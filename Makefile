export GO111MODULE=on
.PHONY: all push container clean container-name container-latest push-latest fmt lint test unit vendor header

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

BUILD_IMAGE ?= golang:1.11.5-alpine

all: build

build: $(BINS)

$(BINS): $(SRC) go.mod
	@mkdir -p bin
	@echo "building: $@"
	@docker run --rm \
	    -u $$(id -u):$$(id -g) \
	    -v $$(pwd):/$(PROJECT) \
	    -w /$(PROJECT) \
	    $(BUILD_IMAGE) \
	    /bin/sh -c " \
	        rm -rf ./.cache && \
	        GOOS=linux \
	        GOCACHE=./.cache \
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
	FILES=; \
	for f in $(GO_FILES); do \
		FILE=$$(head -n $$(wc -l .header | awk '{print $$1}') $$f); \
		[ "$$FILE" != "$$HEADER" ] && FILES="$$FILES$$f "; \
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
