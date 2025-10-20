

# dbox - Container Management Tool

[![Build Status](https://img.shields.io/github/workflow/status/yourusername/dbox/CI)](https://github.com/yourusername/dbox/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/dbox)](https://goreportcard.com/report/github.com/yourusername/dbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight distrobox-like container management tool written in Go that provides a simple interface for managing OCI containers using crun or runc.

## Features

- 🐳 Pull images from OCI registries (Docker Hub, etc.)
- 📦 Create and manage containers with custom configurations
- 🔧 Custom setup scripts (run during or after container creation)
- 🎯 Built-in support for popular distros (Alpine, Ubuntu, Arch, Fedora, Kali, Debian)
- 🚀 Proxy to underlying runtime (crun/runc) with enhanced features
- ⚙️ Custom mount points, SSH setup, user management
- 📋 YAML or JSON configuration
- 📱 Native Android support
- 🔒 Static binary builds for enhanced security

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Examples](#examples)
- [Building](#building)
- [Comparison with Similar Tools](#comparison-with-similar-tools)
- [Troubleshooting](#troubleshooting)
- [Project Status](#project-status)
- [Contributing](#contributing)

## Quick Start

```bash
# Install dbox (see installation options below)
# Pull an image
dbox pull alpine:latest

# Create and run a container
dbox run -i alpine:latest -n my-container

# Execute commands in the container
dbox exec my-container /bin/sh
```

## Installation

### Prerequisites

- Go 1.21 or later
- crun or runc installed
- Root or appropriate permissions for container management

### From Binary

Download the latest binary from the [Releases](https://github.com/yourusername/dbox/releases) page.

### From Source

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go build -o dbox
sudo mv dbox /usr/local/bin/
```

### For Android

1. Download the Android binary from releases
2. Push to device:
   ```bash
   adb push dbox-android-arm64 /data/local/tmp/dbox
   adb shell "chmod +x /data/local/tmp/dbox"
   ```

### For Termux

```bash
pkg update && pkg upgrade
pkg install golang clang
git clone https://github.com/yourusername/dbox
cd dbox
go build -o dbox
```

## Configuration

Create a config file at `/etc/dbox/config.yaml` or specify with `-c` flag or `DBOX_CONFIG` env var:

```yaml
# /etc/dbox/config.yaml
runtime: /usr/bin/crun  # or /usr/bin/runc
runpath: /var/run/dbox
containers_path: /home/user/.local/share/dbox/containers

# Optional: Custom registries
registries:
  alpine: docker.io/library/alpine
  ubuntu: docker.io/library/ubuntu
  archlinux: docker.io/library/archlinux
  fedora: docker.io/library/fedora
  kali: docker.io/kalilinux/kali-rolling
  debian: docker.io/library/debian
```

## Usage

### Basic Commands

```bash
# Show configuration and runtime info
dbox info

# Pull an image
dbox pull alpine:latest
dbox pull ubuntu:22.04
dbox pull archlinux

# Create a container
dbox create -i alpine:latest -n my-alpine

# List containers
dbox list
dbox ls

# Start a container
dbox start my-alpine

# Execute commands in a container
dbox exec my-alpine /bin/sh
dbox exec my-alpine apk add vim

# Stop a container
dbox stop my-alpine

# Delete a container
dbox delete my-alpine
dbox rm -f my-alpine  # Force delete
```

### Advanced Commands

```bash
# Run a container in one step
dbox run -i ubuntu:22.04 -n dev-env -d

# Run with custom mounts
dbox run -i alpine -n test -v /host/path:/container/path

# Run with environment variables
dbox run -i alpine -n test -e VAR=value -e ANOTHER=value

# Create with custom configuration
dbox create -i ubuntu:22.04 -n dev --container-config config.json

# Run setup script
dbox setup my-container -s setup.sh

# View container logs
dbox logs my-container
dbox logs -f my-container  # Follow logs

# Clean image cache
dbox clean

# Run raw runtime commands
dbox raw list
dbox raw state my-container
```

## Examples

### Development Environment

```bash
# Create a development container with mounted workspace
dbox run -i ubuntu:22.04 -n dev-env -v ~/projects:/workspace

# Or create a persistent container with custom config
cat > dev-config.json << EOF
{
  "mounts": [
    {
      "source": "/home/user/projects",
      "destination": "/workspace",
      "options": ["rbind", "rw"]
    }
  ],
  "user": {
    "username": "dev",
    "wheel": true,
    "sudo": true
  }
}
EOF

dbox create -i ubuntu:22.04 -n dev --container-config dev-config.json
dbox start dev
dbox exec dev /bin/bash
```

### Penetration Testing Environment

```bash
# Create a Kali container for security testing
dbox pull kali
dbox run -i kali:latest -n pentest
dbox exec pentest /bin/bash
```

### Database Container

```bash
# Run a PostgreSQL container
dbox run -i postgres:14 -n db -e POSTGRES_PASSWORD=mypassword -v pgdata:/var/lib/postgresql/data
```

## Building

### Prerequisites

- Go 1.21 or later
- crun or runc installed
- For cross-compilation: appropriate C compilers

### Standard Build

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go build -o dbox
```

### Cross-Platform Builds

Use the provided Makefile for easy cross-compilation:

```bash
# Build for common platforms
make all

# Build for specific platforms
make linux-amd64
make linux-arm64
make android
make static-musl
```

### Manual Cross-Compilation

For Linux (static binary):
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dbox-linux-amd64 .
```

For Android:
```bash
# Set up NDK environment variables
export NDK_ROOT=$HOME/Android/Sdk/ndk/<version>
export API_LEVEL=21
export TOOLCHAIN=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64
export CC=$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang

# Build
CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -ldflags="-s -w" -o dbox-android-arm64 .
```

## Comparison with Similar Tools

| Feature | dbox | distrobox | podman | docker |
|---------|------|-----------|--------|--------|
| OCI Runtime | ✓ | ✓ | ✓ | ✓ |
| No Daemon | ✓ | ✓ | ✓ | ✗ |
| Rootless | ✓ | ✓ | ✓ | ✓ |
| Android Support | ✓ | ✗ | ✗ | ✗ |
| Static Binary | ✓ | ✗ | ✗ | ✗ |
| Setup Scripts | ✓ | ✓ | ✗ | Limited |
| Custom Mounts | ✓ | ✓ | ✓ | ✓ |

## Container Config Reference

The `container_config.json` supports:

```json
{
  "mounts": [
    {
      "source": "/host/path",
      "destination": "/container/path",
      "type": "bind",  // optional, defaults to "bind"
      "options": ["rbind", "rw"]  // optional
    }
  ],
  "ssh": {
    "enable": true,
    "port": 2222  // optional, defaults to 22
  },
  "user": {
    "username": "myuser",
    "password": "mypassword",  // optional
    "wheel": true,  // add to wheel group
    "sudo": true    // enable passwordless sudo
  }
}
```

## Environment Variables

- `DBOX_CONFIG`: Path to configuration file
- `DBOX_RUNTIME`: Override runtime path
- `DBOX_RUNPATH`: Override run path

## Directory Structure

```
~/.local/share/dbox/containers/
├── .images/              # Pulled images
│   └── alpine_latest/
│       ├── rootfs/
│       └── config.json
├── my-container/         # Container instance
│   ├── bundle/
│   │   ├── config.json
│   │   └── rootfs/
│   └── metadata.json
```

## Troubleshooting

### Permission Denied

Run with sudo or ensure your user has appropriate permissions:

```bash
sudo dbox create -i alpine -n test
```

### Container Won't Start

Check runtime status:

```bash
dbox info
dbox raw state my-container
```

### Network Errors on Android

If you encounter DNS resolution errors on Android:

1. Check Private DNS settings in Settings → Network & Internet → Private DNS
2. Try disabling VPNs or ad-blockers
3. Switch between Wi-Fi and mobile data

### Image Pull Fails

Check network connectivity and try specifying the full image reference:

```bash
ping docker.io
dbox pull docker.io/library/alpine:latest
```

### OverlayFS Issues

If you're on a filesystem without OverlayFS support:

```bash
dbox run -i alpine -n test --no-overlayfs
```

## Project Status

dbox is currently in **beta**. It's functional for basic container operations but may have bugs. The core features are implemented, but advanced features are still being developed.

- [x] Basic container operations (create, start, stop, delete)
- [x] Image management (pull, list)
- [x] Configuration management
- [x] Android support
- [x] Static binary builds
- [ ] Container networking
- [ ] Container updates
- [ ] GUI interface

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go test ./...
```

### Code Style

This project follows the Go standard formatting and linting guidelines. Please run `gofmt` and `golint` before submitting pull requests.

### Reporting Issues

Please report bugs and feature requests on the [Issues](https://github.com/yourusername/dbox/issues) page.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [distrobox](https://github.com/89luca89/distrobox)
- Uses [go-containerregistry](https://github.com/google/go-containerregistry) for image operations
- Built with [cobra](https://github.com/spf13/cobra) for CLI interface
