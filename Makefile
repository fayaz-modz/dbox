# Makefile for the dbox project

# --- Configuration ---
# The name of your final executable
EXECUTABLE := dbox

# The directory where binaries will be placed
BINDIR := bin

# Go build flags for creating smaller binaries (strip debug info and symbols)
LDFLAGS := -ldflags="-s -w"

# C compiler for native (amd64) builds.
CC_AMD64 := clang

# C cross-compiler for arm64 builds.
# This toolchain MUST be installed on your system.
# - Debian/Ubuntu: sudo apt-get install gcc-aarch64-linux-gnu
# - Fedora/RHEL:   sudo dnf install gcc-aarch64-linux-gnu
CC_ARM64 := aarch64-linux-gnu-gcc


# --- Android NDK Configuration (USER MUST CONFIGURE THIS) ---
# IMPORTANT: Update this path to your installed Android NDK location.
NDK_ROOT ?= $(HOME)/Android/Sdk/ndk/25.1.8937393
ANDROID_API_LEVEL ?= 21


# --- Targets ---

.PHONY: all help clean linux linux-amd64 linux-arm64 android static-musl

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Available Targets:"
	@echo "  all           Builds for common Linux platforms (amd64, arm64) and Android (arm64)."
	@echo "  linux         Builds Linux binaries (amd64, arm64) using the appropriate C toolchains."
	@echo "  linux-amd64   Builds for Linux x86_64 using clang."
	@echo "  linux-arm64   Builds for Linux aarch64 using a cross-compiler (e.g., aarch64-linux-gnu-gcc)."
	@echo "  static-musl   Builds a fully static, portable Linux binary (amd64) using musl-libc."
	@echo "  android       Builds a native binary for Android aarch64 using the NDK's clang."
	@echo "  clean         Removes the build directory ($(BINDIR))."
	@echo ""
	@echo "Prerequisites for 'linux-arm64':"
	@echo "  A cross-compiler toolchain is required. On Debian/Ubuntu, install it with:"
	@echo "  sudo apt-get install gcc-aarch64-linux-gnu"
	@echo ""


all: linux android

linux: linux-amd64 linux-arm64

# Builds for Linux amd64 using the native clang compiler.
linux-amd64:
	@echo "--> Building for Linux amd64 (using $(CC_AMD64), linked to system libc)..."
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=$(CC_AMD64) go build $(LDFLAGS) -o $(BINDIR)/$(EXECUTABLE)-linux-amd64 .

# Builds for Linux arm64 using the aarch64 cross-compiler.
linux-arm64:
	@echo "--> Building for Linux arm64 (using cross-compiler $(CC_ARM64))..."
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=$(CC_ARM64) go build $(LDFLAGS) -o $(BINDIR)/$(EXECUTABLE)-linux-arm64 .

# Builds a portable, fully static Go binary for Linux amd64 using musl-libc.
# This requires a musl-compatible toolchain (e.g., install 'musl-tools' on Debian/Ubuntu).
static-musl:
	@echo "--> Building for Linux amd64 (fully static with musl-libc)..."
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=$(CC_AMD64) go build \
		-tags musl \
		$(LDFLAGS) \
		-ldflags='-linkmode external -extldflags "-static"' \
		-o $(BINDIR)/$(EXECUTABLE)-linux-amd64-musl .

# Builds a native binary for Android arm64.
android:
ifeq ($(wildcard $(NDK_ROOT)),)
	@echo "ERROR: Android NDK not found at '$(NDK_ROOT)'."
	@echo "Please set the NDK_ROOT variable in the Makefile or on the command line."
	@exit 1
endif
	@echo "--> Building for Android arm64 (using NDK clang at $(NDK_ROOT))..."
	@mkdir -p $(BINDIR)
	$(eval TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64)
	$(eval ANDROID_CC := $(TOOLCHAIN)/bin/aarch64-linux-android$(ANDROID_API_LEVEL)-clang)
	CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC=$(ANDROID_CC) go build $(LDFLAGS) -o $(BINDIR)/$(EXECUTABLE)-android-arm64 .

clean:
	@echo "--> Cleaning up..."
	@rm -rf $(BINDIR)
