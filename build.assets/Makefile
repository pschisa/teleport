#
# This Makefile is used for producing official Teleport releases
#
ifneq ("$(wildcard /bin/bash)","")
SHELL := /bin/bash -o pipefail
endif
HOSTNAME=buildbox
SRCDIR=/go/src/github.com/gravitational/teleport
GOMODCACHE ?= /tmp/gomodcache
DOCKERFLAGS := --rm=true -v "$$(pwd)/../":$(SRCDIR) -v /tmp:/tmp -w $(SRCDIR) -h $(HOSTNAME) -e GOMODCACHE=$(GOMODCACHE)
ADDFLAGS ?=
BATSFLAGS :=
NOROOT=-u $$(id -u):$$(id -g)
KUBECONFIG ?=
TEST_KUBE ?=

OS ?= linux
ARCH ?= amd64
RUNTIME ?= go1.16.2
BORINGCRYPTO_RUNTIME=$(RUNTIME)b7
LIBBPF_VERSION ?= 0.3.1

UID := $$(id -u)
GID := $$(id -g)

PROTOC_VER ?= 3.6.1
PROTOC_PLATFORM := linux-x86_64
GOGO_PROTO_TAG ?= v1.3.2

BUILDBOX=quay.io/gravitational/teleport-buildbox:$(RUNTIME)
BUILDBOX_FIPS=quay.io/gravitational/teleport-buildbox-fips:$(RUNTIME)
BUILDBOX_CENTOS6=quay.io/gravitational/teleport-buildbox-centos6:$(RUNTIME)
BUILDBOX_ARM=quay.io/gravitational/teleport-buildbox-arm:$(RUNTIME)
BUILDBOX_ARM_FIPS=quay.io/gravitational/teleport-buildbox-arm-fips:$(RUNTIME)

# These variables are used to dynamically change the name of the buildbox Docker image used by the 'release'
# target. The other solution was to remove the 'buildbox' dependency from the 'release' target, but this would
# make it harder to run `make -C build.assets release` locally as the buildbox would not automatically be built.
BUILDBOX_NAME=$(BUILDBOX)
BUILDBOX_FIPS_NAME=$(BUILDBOX_FIPS)

DOCSBOX=quay.io/gravitational/next:main

ifneq ("$(KUBECONFIG)","")
DOCKERFLAGS := $(DOCKERFLAGS) -v $(KUBECONFIG):/mnt/kube/config -e KUBECONFIG=/mnt/kube/config -e TEST_KUBE=$(TEST_KUBE)
endif

# conditionally force the use of UID/GID 1000:1000 if we're running in Drone
ifeq ("$(DRONE)","true")
UID := 1000
GID := 1000
NOROOT := -u 1000:1000
# if running in CI and the GOCACHE environment variable is not set, set it to a sensible default
ifeq ("$(GOCACHE)",)
GOCACHE := /go/cache
endif
# pass external gocache path through to docker containers
DOCKERFLAGS := $(DOCKERFLAGS) -v $(GOCACHE):/go/cache -e GOCACHE=/go/cache
endif
export


#
# Build 'teleport' release inside a docker container
#
.PHONY:build
build: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) $(BUILDBOX) \
		make -C $(SRCDIR) ADDFLAGS='$(ADDFLAGS)' release

#
# Build 'teleport' release inside a docker container
#
.PHONY:build-binaries
build-binaries: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) $(BUILDBOX) \
		make -C $(SRCDIR) ADDFLAGS='$(ADDFLAGS)' full

#
# Build 'teleport' Enterprise release inside a docker container
#
.PHONY:build-enterprise-binaries
build-enterprise-binaries: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) $(BUILDBOX) \
		make -C $(SRCDIR)/e ADDFLAGS='$(ADDFLAGS)' VERSION=$(VERSION) GITTAG=v$(VERSION) full

#
# Build 'teleport' FIPS release inside a docker container
# This builds Enterprise binaries only.
#
.PHONY:build-binaries-fips
build-binaries-fips: buildbox-fips
	docker run $(DOCKERFLAGS) $(NOROOT) $(BUILDBOX_FIPS) \
		make -C $(SRCDIR)/e ADDFLAGS='$(ADDFLAGS)' VERSION=$(VERSION) GITTAG=v$(VERSION) FIPS=yes full

#
# Builds a Docker container which is used for building official Teleport binaries
# If running in CI and there is no image with the buildbox name:tag combination present locally,
# the image is pulled from the Docker repository. If this pull fails (i.e. when a new Go runtime is
# first used), the error is ignored and the buildbox is built using the Dockerfile.
#
.PHONY:buildbox
buildbox:
	if [[ "$(BUILDBOX_NAME)" == "$(BUILDBOX)" ]]; then \
		if [[ $${DRONE} == "true" ]] && ! docker inspect --type=image $(BUILDBOX) 2>&1 >/dev/null; then docker pull $(BUILDBOX) || true; fi; \
		docker build \
			--build-arg UID=$(UID) \
			--build-arg GID=$(GID) \
			--build-arg RUNTIME=$(RUNTIME) \
			--build-arg PROTOC_VER=$(PROTOC_VER) \
			--build-arg GOGO_PROTO_TAG=$(GOGO_PROTO_TAG) \
			--build-arg PROTOC_PLATFORM=$(PROTOC_PLATFORM) \
			--build-arg LIBBPF_VERSION=$(LIBBPF_VERSION) \
			--cache-from $(BUILDBOX) \
			--tag $(BUILDBOX) . ; \
	fi

#
# Builds a Docker buildbox for FIPS
#
.PHONY:buildbox-fips
buildbox-fips:
	if [[ "$(BUILDBOX_FIPS_NAME)" == "$(BUILDBOX_FIPS)" ]]; then \
		if [[ $${DRONE} == "true" ]] && ! docker inspect --type=image $(BUILDBOX_FIPS) 2>&1 >/dev/null; then docker pull $(BUILDBOX_FIPS) || true; fi; \
		docker build \
			--build-arg UID=$(UID) \
			--build-arg GID=$(GID) \
			--build-arg BORINGCRYPTO_RUNTIME=$(BORINGCRYPTO_RUNTIME) \
			--build-arg LIBBPF_VERSION=$(LIBBPF_VERSION) \
			--cache-from $(BUILDBOX_FIPS) \
			--tag $(BUILDBOX_FIPS) -f Dockerfile-fips . ; \
	fi

#
# Builds a Docker buildbox for CentOS 6 builds
#
.PHONY:buildbox-centos6
buildbox-centos6:
	@if [[ $${DRONE} == "true" ]] && ! docker inspect --type=image $(BUILDBOX_CENTOS6) 2>&1 >/dev/null; then docker pull $(BUILDBOX_CENTOS6) || true; fi;
	docker build \
		--build-arg UID=$(UID) \
		--build-arg GID=$(GID) \
		--build-arg RUNTIME=$(RUNTIME) \
		--cache-from $(BUILDBOX_CENTOS6) \
		--tag $(BUILDBOX_CENTOS6) -f Dockerfile-centos6 .

# CentOS 6 FIPS builds were removed in Teleport 7.0
# https://github.com/gravitational/teleport/issues/7207

#
# Builds a Docker buildbox for ARMv7/ARM64 builds
# ARM buildboxes use a regular Teleport buildbox as a base which already has a user
# with the correct UID and GID created, so those arguments are not needed here.
#
.PHONY:buildbox-arm
buildbox-arm: buildbox
	@if [[ $${DRONE} == "true" ]] && ! docker inspect --type=image $(BUILDBOX_ARM) 2>&1 >/dev/null; then docker pull $(BUILDBOX_ARM) || true; fi;
	docker build \
		--build-arg RUNTIME=$(RUNTIME) \
		--cache-from $(BUILDBOX) \
		--cache-from $(BUILDBOX_ARM) \
		--tag $(BUILDBOX_ARM) -f Dockerfile-arm .

#
# Builds a Docker buildbox for ARMv7/ARM64 FIPS builds
# ARM buildboxes use a regular Teleport buildbox as a base which already has a user
# with the correct UID and GID created, so those arguments are not needed here.
#
.PHONY:buildbox-arm-fips
buildbox-arm-fips: buildbox-fips
	@if [[ $${DRONE} == "true" ]] && ! docker inspect --type=image $(BUILDBOX_ARM_FIPS) 2>&1 >/dev/null; then docker pull $(BUILDBOX_ARM_FIPS) || true; fi;
	docker build \
		--build-arg RUNTIME=$(RUNTIME) \
		--cache-from $(BUILDBOX_FIPS) \
		--cache-from $(BUILDBOX_ARM_FIPS) \
		--tag $(BUILDBOX_ARM_FIPS) -f Dockerfile-arm-fips .

# grpc generates GRPC stubs from service definitions
.PHONY: grpc
grpc: buildbox
	docker run \
		$(DOCKERFLAGS) -t $(BUILDBOX) \
		make -C /go/src/github.com/gravitational/teleport buildbox-grpc

#
# Removes the docker image
#
.PHONY:clean
clean:
	docker image rm --force $(BUILDBOX)
	docker image rm --force $(DOCSBOX)
	GOMODCACHE=$(GOMODCACHE) go clean -modcache

#
# Runs tests inside a build container
#
.PHONY:test
test: buildbox
	docker run \
		--env TELEPORT_ETCD_TEST="yes" \
		$(DOCKERFLAGS) $(NOROOT) -t $(BUILDBOX) \
		/bin/bash -c \
		"examples/etcd/start-etcd.sh & sleep 1; \
		type gcloud 2>&1 >/dev/null || exit 1; \
		gcloud -q beta emulators firestore start --host-port=localhost:8618 & sleep 1; \
		ssh-agent > external.agent.tmp && source external.agent.tmp; \
		cd $(SRCDIR) && make TELEPORT_DEBUG=0 FLAGS='-cover -race' clean test"

.PHONY:test-root
test-root: buildbox
	docker run \
		--env TELEPORT_ETCD_TEST="yes" \
		$(DOCKERFLAGS) -t $(BUILDBOX) \
		/bin/bash -c \
		"examples/etcd/start-etcd.sh & sleep 1; \
		type gcloud 2>&1 >/dev/null || exit 1; \
		gcloud -q beta emulators firestore start --host-port=localhost:8618 & sleep 1; \
		ssh-agent > external.agent.tmp && source external.agent.tmp; \
		cd $(SRCDIR) && make TELEPORT_DEBUG=0 FLAGS='-cover -race' clean test-go-root"

.PHONY:test-sh
test-sh: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) -t $(BUILDBOX) \
		/bin/bash -c "make -C $(SRCDIR) BATSFLAGS=$(BATSFLAGS) test-sh"

.PHONY:integration
integration: buildbox
	docker run \
		--env TELEPORT_ETCD_TEST="yes" \
		$(DOCKERFLAGS) $(NOROOT) -t $(BUILDBOX) \
		/bin/bash -c \
		"examples/etcd/start-etcd.sh & sleep 1; \
		make -C $(SRCDIR) FLAGS='-cover' integration"

.PHONY:integration-root
integration-root: buildbox
	docker run $(DOCKERFLAGS) -t $(BUILDBOX) \
		/bin/bash -c "make -C $(SRCDIR) FLAGS='-cover' integration-root"

#
# Runs linters on new changes inside a build container.
#
.PHONY:lint
lint: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) -t $(BUILDBOX) \
		/bin/bash -c "make -C $(SRCDIR) lint"

#
# Starts shell inside the build container
#
.PHONY:enter
enter: buildbox
	docker run $(DOCKERFLAGS) -ti $(NOROOT) \
		-e HOME=$(SRCDIR)/build.assets -w $(SRCDIR) $(BUILDBOX) /bin/bash

#
# Create a Teleport package using the build container.
# Don't use this target directly; call named Makefile targets like release-amd64.
#
.PHONY:release
release: buildbox
	docker run $(DOCKERFLAGS) $(NOROOT) $(BUILDBOX_NAME) \
		/usr/bin/make release -e ADDFLAGS="$(ADDFLAGS)" OS=$(OS) ARCH=$(ARCH) RUNTIME=$(RUNTIME) REPRODUCIBLE=yes

# These are aliases used to make build commands uniform.
.PHONY: release-amd64
release-amd64:
	$(MAKE) release ARCH=amd64

.PHONY: release-amd64-fips
release-amd64-fips:
	$(MAKE) release-fips ARCH=amd64 FIPS=yes BUILDBOX_FIPS_NAME=$(BUILDBOX_FIPS)

.PHONY: release-386
release-386:
	$(MAKE) release ARCH=386

.PHONY: release-arm
release-arm: buildbox-arm
	$(MAKE) release ARCH=arm BUILDBOX_NAME=$(BUILDBOX_ARM)

.PHONY: release-arm64
release-arm64: buildbox-arm
	$(MAKE) release ARCH=arm64 BUILDBOX_NAME=$(BUILDBOX_ARM)

.PHONY: release-amd64-centos6
release-amd64-centos6: buildbox-centos6
	$(MAKE) release-centos6 ARCH=amd64

#
# Create a Teleport FIPS package using the build container.
# This is a special case because it only builds and packages the Enterprise FIPS binaries, no OSS.
# CI should not use this target, it should use named Makefile targets like release-amd64-fips.
#
.PHONY:release-fips
release-fips: buildbox-fips
	@if [ -z ${VERSION} ]; then echo "VERSION is not set"; exit 1; fi
	docker run $(DOCKERFLAGS) -i $(NOROOT) $(BUILDBOX_FIPS_NAME) \
		/usr/bin/make -C e release -e ADDFLAGS="$(ADDFLAGS)" OS=$(OS) ARCH=$(ARCH) RUNTIME=$(RUNTIME) FIPS=yes VERSION=$(VERSION) GITTAG=v$(VERSION) REPRODUCIBLE=yes

#
# Create a Teleport package for CentOS 6 using the build container.
#
.PHONY:release-centos6
release-centos6: buildbox-centos6
	docker run $(DOCKERFLAGS) -i $(NOROOT) $(BUILDBOX_CENTOS6) \
		/usr/bin/make release -e ADDFLAGS="$(ADDFLAGS)" OS=$(OS) ARCH=$(ARCH) RUNTIME=$(RUNTIME) REPRODUCIBLE=no

#
# Create a Windows Teleport package using the build container.
#
.PHONY:release-windows
release-windows: buildbox
	docker run $(DOCKERFLAGS) -i $(NOROOT) $(BUILDBOX) \
		/usr/bin/make release -e ADDFLAGS="$(ADDFLAGS)" OS=windows

#
# Run docs tester to detect problems.
#
.PHONY: docsbox
docsbox:
	if ! docker inspect --type=image $(DOCSBOX) 2>&1 >/dev/null; then docker pull $(DOCSBOX) || true; fi

.PHONY: test-docs
test-docs: DOCS_VERSION := $(shell grep -E ^VERSION $(MAKEFILE_ROOT_DIR)/Makefile | cut -d= -f2 | cut -d. -f1-2)
test-docs: docsbox
	docker run -i $(NOROOT) -v $$(pwd)/..:/src/content/$(DOCS_VERSION) $(DOCSBOX) \
		/bin/sh -c "yarn markdown-lint-external-links"
