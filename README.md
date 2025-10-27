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
- 🔧 **NEW**: Custom init process support (e.g., `/sbin/init`)
- 🔒 **NEW**: Privileged container mode with full capabilities
- 🌐 **NEW**: Network namespace control (host, none, container)
- 💾 **NEW**: Full container mutability options
- 🔄 **NEW**: Container recreate command for fixing stopped containers
- 🖥️ **NEW**: TTY device allocation for init systems (`--tty` flag)
- ⚙️ **NEW**: Enhanced recreate command with full override support
- 📊 **NEW**: Container resource usage monitoring with CPU percentage, memory, PID, and cgroups info

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
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

# Execute commands in container
dbox exec my-container /bin/sh
```

## Installation

### Prerequisites

- Go 1.21 or later
- crun or runc installed
- Root or appropriate permissions for container management

### From Binary

Download latest binary from [Releases](https://github.com/yourusername/dbox/releases) page.

### From Source

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go build -o dbox
sudo mv dbox /usr/local/bin/
```

### For Android

1. Download Android binary from releases
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

# Recreate a container (fixes stopped containers, preserves data)
dbox recreate my-alpine

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

# Check container status
dbox status my-container

# Monitor container resource usage
dbox usage my-container
dbox usage my-container --pid      # Show PID information
dbox usage my-container --cgroup   # Show detailed cgroups info
dbox usage my-container --pid --cgroup  # Show all information

# Recreate container (fixes stopped containers)
dbox recreate my-container

# Enhanced recreate with overrides
dbox recreate my-container --tty                    # Add TTY devices
dbox recreate my-container --privileged            # Make privileged
dbox recreate my-container --image ubuntu:22.04    # Change image
dbox recreate my-container --init /bin/bash         # Change init process
dbox recreate my-container --memory 1g              # Add memory limit
dbox recreate my-container --net host              # Change network
```

## Advanced Features

### Custom Init Process

Override the default container init process:

```bash
# Run with /sbin/init instead of image default
dbox create -i alpine -n alpine-init --init /sbin/init
dbox start alpine-init
dbox exec alpine-init ps aux  # PID 1 should be /sbin/init

# Use with run command
dbox run -i alpine -n test --init /sbin/init
```

### TTY Device Allocation

Some init systems (like Alpine's OpenRC) require TTY device nodes. Use the `--tty` flag to allocate them:

```bash
# Create container with TTY devices (needed for /sbin/init on Alpine)
dbox create -i alpine -n alpine-tty --init /sbin/init --tty
dbox start alpine-tty

# Without --tty, you'll see errors like:
# "can't open /dev/tty1: No such file or directory"

# Use with run command
dbox run -i alpine -n test --init /sbin/init --tty

# Only use --tty when needed - it adds device overhead
dbox create -i ubuntu -n ubuntu-normal  # No --tty needed for most containers
```

### Privileged Containers

Run containers with full system capabilities:

```bash
# Create privileged container
dbox create -i alpine -n privileged-alpine --privileged
dbox start privileged-alpine

# Check capabilities
dbox exec privileged-alpine capsh --print

# Mount host filesystems
dbox exec privileged-alpine mount -t proc proc /proc
```

### Network Namespace Control

Control container network isolation:

```bash
# Share host network (default)
dbox create -i alpine -n host-net --net host

# Isolated network namespace
dbox create -i alpine -n isolated-net --net none

# Share network with another container
dbox create -i alpine -n shared-net --net container:other-container
```

### Full Container Mutability

Choose between overlayfs (default) or full filesystem copy:

```bash
# Use overlayfs (default, efficient)
dbox create -i alpine -n overlay-container

# Full filesystem copy (slower but fully mutable)
dbox create -i alpine -n mutable-container --no-overlayfs

# Changes persist across restarts with overlayfs upper layer
# For complete persistence, use --no-overlayfs
```

### Resource Limits

Control container resource usage:

```bash
# CPU limits (50% of one CPU core)
dbox create -i alpine -n cpu-limited --cpu-quota 50000 --cpu-period 100000

# Memory limits (512MB)
dbox create -i alpine -n mem-limited --memory 512m

# CPU shares (relative weight)
dbox create -i alpine -n cpu-shares --cpu-shares 2048

# Block IO weight
dbox create -i alpine -n io-weight --blkio-weight 500
```

### Enhanced Recreate Command

The `recreate` command can fix stopped containers and allows you to override any original setting:

```bash
# Basic recreate (preserves all original settings)
dbox recreate my-container

# Add TTY devices to existing container
dbox recreate my-container --tty

# Change multiple settings at once
dbox recreate my-container \
  --privileged \
  --memory 1g \
  --cpu-shares 2048 \
  --net host

# Change image and init process
dbox recreate my-container \
  --image ubuntu:22.04 \
  --init /sbin/init

# Add environment variables and mounts
dbox recreate my-container \
  -e NEW_VAR=value \
  -e ANOTHER=value \
  -v /host/path:/container/path

# Full recreation with all overrides
dbox recreate my-container \
  --image alpine:latest \
  --init /sbin/init \
  --tty \
  --privileged \
  --net host \
  --no-overlayfs \
  --memory 2g \
  --cpu-shares 1024 \
  -e EDITOR=vim \
  -v ~/projects:/workspace
```

**How recreate works:**
1. Reads original container configuration
2. Applies any flag overrides you provide
3. Preserves settings that aren't overridden
4. Stops and recreates the container with new settings
5. Preserves container data and filesystem changes

### Container Resource Usage Monitoring

Monitor running container resource consumption:

```bash
# Basic CPU and memory usage
dbox usage my-container

# Show PID information
dbox usage my-container --pid

# Show detailed cgroups information
dbox usage my-container --cgroup

# Show all available information
dbox usage my-container --pid --cgroup
```

**What the usage command shows:**
- **CPU Usage**: Total CPU time consumed by the container with current usage percentage
- **Memory Usage**: Current memory consumption (in MB)
- **PID**: Container process ID (when `--pid` flag is used)
- **Cgroup Info**: Detailed cgroups settings including limits and current values (when `--cgroup` flag is used)

**Example output:**
```
Container: my-container
CPU Usage: 12.34 seconds (5.67%)
Memory Usage: 256.78 MB
PID: 12345
Cgroup Path: /sys/fs/cgroup/.../my-container
CPU Max: max 100000
Memory Max: unlimited
PIDs Current: 1
PIDs Max: max
```

**CPU Percentage Calculation:**
The CPU percentage is calculated as: `(usage_time / elapsed_time) * 100 / cpu_count`
- Takes into account CPU limits set on the container
- Shows current utilization relative to available CPU resources
- Capped at 100% to avoid unrealistic values
- Automatically detects number of CPU cores available to the container

### Combined Advanced Usage

```bash
# Full system container with init, privileged, host networking
dbox create -i alpine -n system-container \
  --init /sbin/init \
  --privileged \
  --net host \
  --no-overlayfs

# Development environment with resource limits
dbox create -i ubuntu:22.04 -n dev-env \
  --init /sbin/init \
  --net host \
  --memory 2g \
  --cpu-shares 1024 \
  -v ~/projects:/workspace \
  -e EDITOR=vim

# Alpine system container with TTY support
dbox create -i alpine -n alpine-system \
  --init /sbin/init \
  --tty \
  --privileged \
  --net host

# Monitor resource usage of running containers
dbox usage system-container --pid --cgroup
dbox usage dev-env --cgroup

# Check CPU utilization percentage
dbox usage my-container  # Shows CPU time with percentage
dbox usage dev-env        # Monitor development container performance
```

## Examples

### System Container with Full Capabilities

```bash
# Create a system-like container
dbox create -i alpine -n system \
  --init /sbin/init \
  --privileged \
  --net host \
  --no-overlayfs

dbox start system

# Verify it's running like a real system
dbox exec system ps aux
dbox exec system systemctl status  # if systemd is available
dbox exec system ip addr show       # shows host network interfaces
```

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
# Create a privileged Kali container for security testing
dbox pull kali
dbox create -i kali:latest -n pentest --privileged --net host
dbox start pentest
dbox exec pentest /bin/bash

# Now you have full system access for security testing
dbox exec pentest nmap -sS localhost
dbox exec pentest tcpdump -i any
```

### Database Container

```bash
# Run a PostgreSQL container with resource limits
dbox run -i postgres:14 -n db \
  -e POSTGRES_PASSWORD=mypassword \
  -v pgdata:/var/lib/postgresql/data \
  --memory 1g \
  --cpu-shares 512
```

### Minimal Container with Custom Init

```bash
# Create minimal container with custom init script
cat > custom-init.sh << 'EOF'
#!/bin/sh
echo "Custom init starting..."
# Your custom initialization here
exec /bin/sh
EOF

chmod +x custom-init.sh

dbox create -i alpine -n minimal \
  --init /bin/sh \
  -v $(pwd)/custom-init.sh:/custom-init.sh

dbox start minimal
dbox exec minimal /custom-init.sh
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

Use provided Makefile for easy cross-compilation:

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
| Custom Init | ✓ | ✗ | Limited | Limited |
| Privileged Mode | ✓ | ✓ | ✓ | ✓ |
| Network Control | ✓ | ✓ | ✓ | ✓ |
| Resource Limits | ✓ | Limited | ✓ | ✓ |
| Usage Monitoring | ✓ | ✗ | ✓ | ✓ |

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
  },
  "resources": {
    "cpu_quota": 50000,        // CPU quota in microseconds
    "cpu_period": 100000,      // CPU period in microseconds
    "memory_limit": 536870912, // Memory limit in bytes (512MB)
    "memory_swap": 1073741824, // Memory+swap limit in bytes (1GB)
    "cpu_shares": 1024,        // CPU shares (relative weight)
    "blkio_weight": 500        // Block IO weight (10-1000)
  }
}
```

## Command Reference

### Global Flags

- `-c, --config`: Path to config file (or set `DBOX_CONFIG` env)
- `-h, --help`: Show help
- `--version`: Show version

### Create Command

```bash
dbox create [flags]

Required:
  -i, --image string        Image to use (e.g., alpine:latest)
  -n, --name string         Container name

Optional:
  --container-config string  Path to container_config.json
  --setup-script string      Setup script to run during creation
  --post-setup-script string Setup script to run after creation
  -e, --env strings         Set environment variables
  --no-overlayfs           Disable OverlayFS and copy rootfs
  --init string            Override init process (e.g., /sbin/init)
  --privileged             Run container in privileged mode
  --net string            Network namespace (host, none, or container:name)
  --cpu-quota int64       CPU quota in microseconds
  --cpu-period int64      CPU period in microseconds
  --memory int64          Memory limit in bytes
  --memory-swap int64     Memory+swap limit in bytes
  --cpu-shares int64      CPU shares (relative weight)
  --blkio-weight uint16   Block IO weight
  --tty                    Allocate TTY devices (needed for some init systems)
```

### Run Command

```bash
dbox run [flags]

Required:
  -i, --image string        Image to use (e.g., ubuntu:latest)

Optional:
  -n, --name string         Assign a name to the container
  --container-config string  Path to container_config.json
  -e, --env strings         Set environment variables
  -d, --detach             Run container in background
  --rm                     Auto-remove container when it exits
  -v, --volume strings     Bind mount volumes
  --no-overlayfs           Disable OverlayFS and copy rootfs
  --init string            Override init process
  --privileged             Run container in privileged mode
  --net string            Network namespace
  --cpu-quota int64       CPU quota in microseconds
  --cpu-period int64      CPU period in microseconds
  --memory int64          Memory limit in bytes
  --memory-swap int64     Memory+swap limit in bytes
  --cpu-shares int64      CPU shares (relative weight)
  --blkio-weight uint16   Block IO weight
  --tty                    Allocate TTY devices (needed for some init systems)
```

### Recreate Command

```bash
dbox recreate <container> [flags]

# Override any container setting during recreation:
  -i, --image string           Override image
  --container-config string     Override container_config.json
  --setup-script string         Override setup script
  --post-setup-script string    Override post-setup script
  -e, --env strings            Override environment variables
  --no-overlayfs               Override OverlayFS setting
  --init string                Override init process
  --privileged                 Override privileged mode
  --net string                 Override network namespace
  --cpu-quota int64           Override CPU quota
  --cpu-period int64          Override CPU period
  --memory int64               Override memory limit
  --memory-swap int64          Override memory+swap limit
  --cpu-shares int64           Override CPU shares
  --blkio-weight uint16        Override block IO weight
  --tty                        Override TTY device allocation
```

### Usage Command

```bash
dbox usage <container>       # Show CPU (with percentage) and memory usage
dbox usage <container> --pid      # Show PID information
dbox usage <container> --cgroup   # Show detailed cgroups information
dbox usage <container> --pid --cgroup  # Show all information
```

### Other Commands

```bash
dbox list                    # List containers
dbox start <container>       # Start container
dbox stop <container>        # Stop container
dbox delete <container>      # Delete container
dbox exec <container> <cmd>  # Execute command
dbox pull <image>           # Pull image
dbox logs <container>        # Show logs
dbox info                   # Show configuration
dbox clean                  # Clean image cache
dbox raw <args>             # Run raw runtime commands
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
│   ├── upper/           # OverlayFS upper layer (if using overlay)
│   ├── work/            # OverlayFS work directory
│   ├── merged/          # OverlayFS mount point
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
dbox status my-container
```

### Init Process Issues

If `/sbin/init` fails to start:

```bash
# Check if init exists in the image
dbox exec my-container ls -la /sbin/init

# Try alternative init systems
dbox create -i alpine -n test --init /bin/sh
dbox create -i ubuntu -n test --init /lib/systemd/systemd
```

### TTY Device Errors

If you see errors like "can't open /dev/tty1: No such file or directory":

```bash
# This happens when using init systems that expect TTY devices (like Alpine's OpenRC)
# Solution: Add --tty flag to create the required device nodes

dbox create -i alpine -n fixed --init /sbin/init --tty
dbox start fixed

# Or fix existing container with recreate
dbox recreate broken-container --tty

# Only use --tty when needed - most containers don't require it
dbox create -i ubuntu -n normal  # No --tty needed
```

### Privileged Container Issues

If privileged mode doesn't work:

```bash
# Check runtime supports privileged mode
dbox info

# Verify capabilities
dbox exec privileged-container capsh --print

# Check if seccomp is disabled
dbox exec privileged-container cat /proc/self/status | grep Seccomp
```

### Network Problems

If networking doesn't work:

```bash
# Try different network modes
dbox create -i alpine -n test --net host
dbox create -i alpine -n test --net none

# Check network interfaces
dbox exec test ip addr show
dbox exec test cat /proc/net/dev
```

### OverlayFS Issues

If you're on a filesystem without OverlayFS support:

```bash
dbox run -i alpine -n test --no-overlayfs
```

### Container Lifecycle Management

dbox provides robust container lifecycle management with data preservation:

```bash
# Normal workflow
dbox create -i alpine -n my-container
dbox start my-container
# ... use container ...
dbox stop my-container
dbox start my-container  # Works normally

# If container won't start after being stopped
dbox recreate my-container  # Fixes the issue, preserves data
dbox start my-container      # Now works again
```

### Container Issues

If containers have issues:

```bash
# First try - recreate (preserves data)
dbox recreate my-container

# Last resort - delete and recreate (loses data)
dbox delete my-container -f
dbox create -i alpine -n my-container
```

**Data Persistence:**

- **`recreate`**: Preserves all container data and configuration
- **`delete`**: Completely removes the container including all data

### Recreate Command

The `recreate` command fixes containers that won't start after being stopped:

```bash
# When a container fails to start with this error:
# "failed to start stopped container 'name': container 'name' is not running"

# Use recreate to fix it:
dbox recreate my-container

# Recreate does:
# 1. Stops container if running
# 2. Deletes from runtime (preserves filesystem)
# 3. Unmounts and remounts OverlayFS
# 4. Regenerates OCI config with original settings
# 5. Recreates container in runtime
# 6. Preserves all data in upper layer
```

### Resource Limit Issues

If containers don't respect resource limits:

```bash
# Check if cgroups v2 is available
mount | grep cgroup

# Verify limits are applied
dbox exec limited-container cat /sys/fs/cgroup/memory.max
dbox exec limited-container cat /sys/fs/cgroup/cpu.max
```

### CPU Percentage Issues

If CPU percentage seems inaccurate:

```bash
# CPU percentage is calculated as: (usage_time / elapsed_time) * 100 / cpu_count
# Common factors affecting accuracy:

# 1. Container start time detection
dbox usage my-container --cgroup  # Check cgroup path and timing

# 2. CPU limits affecting calculation
dbox exec my-container cat /sys/fs/cgroup/cpu.max

# 3. System CPU count vs container CPU allocation
dbox usage my-container --pid --cgroup  # Shows all relevant info

# Note: CPU percentage is capped at 100% and may take time to stabilize
# after container startup. Short-lived containers may show inaccurate percentages.
```

### Network Errors on Android

If you encounter DNS resolution errors on Android:

1. Check Private DNS settings in Settings → Network & Internet → Private DNS
2. Try disabling VPNs or ad-blockers
3. Switch between Wi-Fi and mobile data

### Image Pull Fails

Check network connectivity and try specifying full image reference:

```bash
ping docker.io
dbox pull docker.io/library/alpine:latest
```

## Project Status

dbox is currently in **beta**. It's functional for basic container operations but may have bugs. The core features are implemented, but advanced features are still being developed.

- [x] Basic container operations (create, start, stop, delete)
- [x] Image management (pull, list)
- [x] Configuration management
- [x] Android support
- [x] Static binary builds
- [x] Custom init process support
- [x] Privileged container mode
- [x] Network namespace control
- [x] Resource limits
- [x] Container mutability options
- [x] Container recreate functionality
- [x] Container resource usage monitoring
- [ ] Container networking (advanced)
- [ ] Container updates
- [ ] GUI interface
- [ ] Container snapshots
- [ ] Multi-architecture image support

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

This project follows Go standard formatting and linting guidelines. Please run `gofmt` and `golint` before submitting pull requests.

### Reporting Issues

Please report bugs and feature requests on the [Issues](https://github.com/yourusername/dbox/issues) page.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [distrobox](https://github.com/89luca89/distrobox)
- Uses [go-containerregistry](https://github.com/google/go-containerregistry) for image operations
- Built with [cobra](https://github.com/spf13/cobra) for CLI interface
- OCI runtime support via [crun](https://github.com/containers/crun) and [runc](https://github.com/opencontainers/runc)