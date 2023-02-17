IMG_TAG ?= latest
IMG_REPO ?= localhost/aodsipam

IMG := $(IMG_REPO):$(IMG_TAG)

OCI_BIN ?= docker

build:
	hack/build-go.sh

docker-build:
	docker build -t ${IMG} .

generate-api:
	hack/verify-codegen.sh
	rm -rf github.com

install-tools:
	hack/install-kubebuilder-tools.sh

test: build install-tools
	hack/test-go.sh

##@ Deployment

kind-load: KIND_CLUSTER ?= $(firstword $(shell kind get clusters))
kind-load:
	kind load docker-image ${IMG} --name $(KIND_CLUSTER)

deletepod:
	kubectl delete po testpod1 --force || true

install:
	kubectl create -f doc/crds || true

uninstall: deletepod
	kubectl delete -f doc/crds || true

deploycrd: uninstall install

deploy: docker-build kind-load install

redeploy: docker-build kind-load uninstall install