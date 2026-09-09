# Static analysis

.PHONY: lint analyze infer-uninit

CLANG_TIDY ?= clang-tidy
INFER ?= infer

# Missing-tool diagnostics, in the shape the verify-* targets already use:
# name the tool, name the install, fail on purpose. Without this a developer
# running lint/analyze/infer-uninit gets "make: clang-tidy: No such file or
# directory / Error 1", which reads like a broken Makefile rather than a
# missing dependency.
define require-tool
	@command -v $(1) >/dev/null 2>&1 || { \
		printf "  $(RED)%s not found$(RESET) (%s)\n" "$(1)" "$(2)"; \
		exit 1; \
	}
endef

## Run clang-tidy on all source files
lint: $(BUILD_DIR)/shim_blob.h $(BUILD_DIR)/version.h $(DISPATCH_HEADER)
	$(call require-tool,$(CLANG_TIDY),brew install llvm -- or set CLANG_TIDY=)
	@echo "  TIDY    src/"
	$(Q)$(CLANG_TIDY) $(ALL_SRCS) -- $(CFLAGS) -Isrc -I$(BUILD_DIR)

## Re-run Infer with the uninitialized-value checker that .inferconfig disables
infer-uninit: | $(BUILD_DIR)
	$(call require-tool,$(INFER),brew install infer -- or set INFER=)
	@echo "  INFER   uninitialized-value checker (disabled in .inferconfig)"
	@echo "          A count of 0 means the suppression is no longer needed and"
	@echo "          .inferconfig should be deleted. Anything else is the known"
	@echo "          false-positive class: Pulse cannot prove guest_copy's"
	@echo "          chunked loop fills its destination."
	@status=0; \
	$(INFER) run --keep-going --enable-issue-type PULSE_UNINITIALIZED_VALUE \
	    --results-dir $(BUILD_DIR)/infer-uninit \
	    -- $(MAKE) -B elfuse > $(BUILD_DIR)/infer-uninit.log 2>&1 || status=$$?; \
	if [ "$$status" -ne 0 ] && [ "$$status" -ne 2 ]; then \
		printf "  $(RED)FAILED$(RESET)   infer exited %s; this is an analysis\n" "$$status"; \
		printf "           failure, not an audit result. See $(BUILD_DIR)/infer-uninit.log\n"; \
		exit 1; \
	fi; \
	if [ ! -s $(BUILD_DIR)/infer-uninit/report.json ]; then \
		printf "  $(RED)FAILED$(RESET)   infer produced no report\n"; exit 1; \
	fi; \
	python3 -c "import json,sys; \
	    d=json.load(open('$(BUILD_DIR)/infer-uninit/report.json')); \
	    u=[x for x in d if x['bug_type']=='PULSE_UNINITIALIZED_VALUE']; \
	    print('  %d PULSE_UNINITIALIZED_VALUE finding(s) across %d file(s)' \
	          % (len(u), len({x['file'] for x in u})))"

## Run clang static analyzer (scan-build)
analyze:
	$(call require-tool,scan-build,brew install llvm)
	@echo "  SCAN    elfuse"
	$(Q)scan-build --use-cc=$(CC) $(MAKE) -B elfuse
