GO ?= go

OCI_BIN  := $(BUILD_DIR)/elfuse-oci
OCI_SRCS := $(shell find cmd/oci -type f -name '*.go' ! -name '*_test.go' 2>/dev/null)
OCI_VERSION_FILE := $(BUILD_DIR)/.elfuse-oci-version

.PHONY: elfuse-oci oci-test oci-vet oci-fmt-check oci-lint oci-version-force

elfuse-oci: $(OCI_BIN)

# Rebuild only when command-line VERSION changes.
oci-version-force:

$(OCI_VERSION_FILE): oci-version-force | $(BUILD_DIR)
	$(Q)tmp="$@.$$$$.tmp"; \
	printf '%s\n' "$(VERSION)" > "$$tmp"; \
	cmp -s "$$tmp" "$@" 2>/dev/null || mv "$$tmp" "$@"; \
	rm -f "$$tmp"

# The directory prerequisite catches an incomplete OCI_SRCS list.
$(OCI_BIN): go.mod go.sum cmd/oci $(OCI_SRCS) $(VERSION_DEPS) \
		$(OCI_VERSION_FILE) | $(BUILD_DIR)
	@echo "  GO      $@"
	$(Q)rm -f $@
	$(Q)$(GO) build -ldflags "-X main.version=$(VERSION)" -o $@ ./cmd/oci

## Run elfuse-oci tests; set ELFUSE_OCI_NETTEST=1 for registry round-trip
oci-test:
	$(Q)$(GO) test -race ./cmd/oci/

oci-vet:
	$(Q)GOOS=darwin GOARCH=arm64 $(GO) vet ./cmd/oci/
	$(Q)GOOS=linux $(GO) vet ./cmd/oci/

# Use the selected Go toolchain's gofmt.
oci-fmt-check:
	$(Q)set -e; out=$$("$$($(GO) env GOROOT)/bin/gofmt" -l cmd/oci); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## Check elfuse-oci formatting and vet Darwin and Linux builds
oci-lint: oci-fmt-check oci-vet
