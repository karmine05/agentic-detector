# agentic-detector — cross-platform osquery extension build.
#
# `make build-all` produces the per-platform binaries named exactly as Fleet's
# TUF/agent_options mechanism expects (see README "Deploy via Fleet"):
#
#   build/agentic_detector_macos.ext          (universal: amd64 + arm64)
#   build/agentic_detector_linux.ext          (amd64)
#   build/agentic_detector_windows.ext.exe    (amd64)

BINARY  := agentic_detector
PKG     := ./cmd/agentic_detector
BUILD   := build
VERSION ?= 0.3.0
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all check build-all macos linux windows test vet fmt fmtcheck lint sec clean \
        run run-root osq-verify osq-verify-linux osq-verify-windows dist

all: check build-all

## ---- quality gates (run before pushing) ----
check: fmtcheck vet test

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmtcheck:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# Static analysis (parity with CodeQL/gosec in CI). Install:
#   go install github.com/securego/gosec/v2/cmd/gosec@latest
sec:
	gosec -severity medium ./...

## ---- cross-platform build ----
build-all: macos linux windows

macos:
	@mkdir -p $(BUILD)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD)/.macos_amd64 $(PKG)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD)/.macos_arm64 $(PKG)
	lipo -create -output $(BUILD)/$(BINARY)_macos.ext $(BUILD)/.macos_amd64 $(BUILD)/.macos_arm64
	@rm -f $(BUILD)/.macos_amd64 $(BUILD)/.macos_arm64
	@echo "built $(BUILD)/$(BINARY)_macos.ext"

linux:
	@mkdir -p $(BUILD)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD)/$(BINARY)_linux.ext $(PKG)
	@echo "built $(BUILD)/$(BINARY)_linux.ext"

windows:
	@mkdir -p $(BUILD)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD)/$(BINARY)_windows.ext.exe $(PKG)
	@echo "built $(BUILD)/$(BINARY)_windows.ext.exe"

# --- signing (run after build, before distribution) ---
# osquery refuses to autoload extensions that are world-writable or not owned by
# root/Administrator. Distribution signing is platform-specific:
#   macOS:   codesign -s "Developer ID Application: <ORG>" --options runtime \
#              build/agentic_detector_macos.ext
#            xcrun notarytool submit ... && xcrun stapler staple ...
#   Windows: signtool sign /fd SHA256 /a build/agentic_detector_windows.ext.exe

## ---- local run against osqueryi ----
# Requires osquery installed (`brew reinstall --cask osquery`).
# --allow_unsafe relaxes osquery's root-owned/non-world-writable extension check
# for local testing only. Run plain = your user (sees your home + your sockets);
# `make run-root` = root (sees all users + all sockets, like fleetd).
EXT_MAC := $(CURDIR)/$(BUILD)/$(BINARY)_macos.ext
# --extensions_require blocks osqueryi until our extension registers; without it,
# a one-shot `osqueryi "QUERY"` runs before async registration completes and
# reports "no such table". --extensions_timeout caps the wait.
OSQ_FLAGS := --allow_unsafe --extension "$(EXT_MAC)" --extensions_require=agentic_detector --extensions_timeout=10

# Shared one-shot sanity query — per-type row + running counts.
VERIFY_SQL := SELECT type, count(*) AS rows, sum(running) AS running FROM ai_tools GROUP BY type

run: macos
	osqueryi $(OSQ_FLAGS)

run-root: macos
	sudo osqueryi $(OSQ_FLAGS)

# One-shot sanity query (non-interactive) — loads the host-native .ext.
osq-verify: macos
	osqueryi $(OSQ_FLAGS) "$(VERIFY_SQL)"

# Cross-platform verify. osqueryi loads ONLY the host-native extension, so the
# linux/windows builds are verified by running osquery on (or emulating) those
# OSes. A clean container / fresh host has no AI tools installed, so an EMPTY
# result is a PASS: --extensions_require makes osqueryi exit non-zero if the
# extension fails to register, which is the real cross-platform signal here.
DOCKER      ?= docker
OSQUERY_IMG ?= osquery/osquery:latest
UNAME_S     := $(shell uname -s 2>/dev/null)
EXT_LINUX_HOST := $(CURDIR)/$(BUILD)/$(BINARY)_linux.ext

# Native osqueryi when on Linux; otherwise load the amd64 build inside a
# linux/amd64 osquery container (works on a macOS Docker host via emulation).
osq-verify-linux: linux
ifeq ($(UNAME_S),Linux)
	osqueryi --allow_unsafe --extension "$(EXT_LINUX_HOST)" \
	  --extensions_require=agentic_detector --extensions_timeout=10 "$(VERIFY_SQL)"
else
	@echo "not on Linux — loading the amd64 build in a linux/amd64 $(OSQUERY_IMG) container"
	$(DOCKER) run --rm --platform linux/amd64 -v "$(CURDIR)/$(BUILD)":/work:ro $(OSQUERY_IMG) \
	  osqueryi --allow_unsafe --extension /work/$(BINARY)_linux.ext \
	    --extensions_require=agentic_detector --extensions_timeout=10 "$(VERIFY_SQL)"
endif

# Windows containers cannot run on a macOS/Linux Docker host, so there is no
# cross-host path: this target runs natively on a Windows host (GNU Make sets
# OS=Windows_NT) and otherwise prints guidance and fails.
osq-verify-windows: windows
ifeq ($(OS),Windows_NT)
	osqueryi.exe --allow_unsafe --extension "$(CURDIR)/$(BUILD)/$(BINARY)_windows.ext.exe" \
	  --extensions_require=agentic_detector --extensions_timeout=10 "$(VERIFY_SQL)"
else
	@echo "osq-verify-windows must run on a Windows host (osqueryi.exe loads the"
	@echo "_windows.ext.exe build). Windows containers cannot run on a macOS/Linux"
	@echo "Docker host, so there is no cross-host path — run this target on Windows"
	@echo "or via a windows-latest CI runner. The binary still cross-builds here"
	@echo "with 'make windows'."
	@exit 1
endif

## ---- release artifacts ----
# `make dist` builds every platform binary and writes SHA256SUMS over them.
# Attach the build/ files to a GitHub release (see README "Download a build").
dist: build-all
	cd $(BUILD) && shasum -a 256 *.ext *.ext.exe > SHA256SUMS
	@echo "checksums:" && cat $(BUILD)/SHA256SUMS

clean:
	rm -rf $(BUILD)
