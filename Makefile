.PHONY: fmt lint test unit generate crd client deepcopy informer lister gen-docs e2e

PROJECT := kilo
PKG := github.com/squat/$(PROJECT)
GO_FILES ?= $$(find . -name '*.go' -not -path './vendor/*')
GO_PKGS ?= $$(go list ./... | grep -v "$(PKG)/vendor")

generate: client deepcopy informer lister crd

crd: manifests/crds.yaml
manifests/crds.yaml: pkg/k8s/apis/kilo/v1alpha1/types.go
	go tool controller-gen crd \
	paths=./pkg/k8s/apis/kilo/... \
	output:crd:stdout > $@
	yamlfmt --formatter indentless_arrays=true manifests/crds.yaml

client: pkg/k8s/clientset/versioned/typed/kilo/v1alpha1/peer.go
pkg/k8s/clientset/versioned/typed/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go
	go tool client-gen \
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
pkg/k8s/apis/kilo/v1alpha1/zz_generated.deepcopy.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go
	go tool deepcopy-gen \
	--input-dirs ./$(@D) \
	--go-header-file=.header \
	--logtostderr \
	--output-base $(CURDIR) \
	--output-file-base zz_generated.deepcopy
	mv $(PKG)/$@ $@ || true
	rm -r github.com || true
	go fmt $@

informer: pkg/k8s/informers/kilo/v1alpha1/peer.go
pkg/k8s/informers/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go
	go tool informer-gen \
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
pkg/k8s/listers/kilo/v1alpha1/peer.go: .header pkg/k8s/apis/kilo/v1alpha1/types.go
	go tool lister-gen \
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
docs/api.md: pkg/k8s/apis/kilo/v1alpha1/types.go
	go run ./cmd/docs-gen/... $< > $@

fmt:
	@echo $(GO_PKGS)
	gofmt -w -s $(GO_FILES)

lint:
	pre-commit run --all

unit:
	go test -mod=vendor --race ./...

test: lint unit e2e

e2e:
	KILO_IMAGE=squat/kilo:test bash_unit $(BASH_UNIT_FLAGS) ./e2e/setup.sh ./e2e/full-mesh.sh ./e2e/location-mesh.sh ./e2e/multi-cluster.sh ./e2e/handlers.sh ./e2e/kgctl.sh ./e2e/teardown.sh

docs/kg.md:
	go run ./cmd/kg/... --help | head -n -2 > help.txt
	go tool embedmd -w docs/kg.md

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
