# dbox - Container Management Tool

A lightweight distrobox-like container management tool written in Go that provides a simple interface for managing OCI containers using crun or runc.

## Quick Reference

```bash
# Basic workflow
dbox pull alpine:latest           # Pull image
dbox create -i alpine -n test    # Create container  
dbox start test                   # Start container
dbox exec test /bin/sh           # Execute commands
dbox stop test                   # Stop container
dbox delete test                 # Delete container

# One-step workflow
dbox run -i alpine -n test     # Create + start

# Management
dbox list                       # List containers
dbox status test                # Container details
dbox logs test                  # View logs
dbox usage test                 # Resource monitoring
dbox recreate test --privileged  # Fix/modify container

# Volume management
dbox volume ls                  # List volumes
dbox volume create data         # Create volume
dbox volume inspect data        # Inspect volume
dbox volume rm data             # Remove volume
```

## Features

- 🐳 Pull images from OCI registries (Docker Hub, etc.)
- 📦 Create and manage containers with custom configurations
- 🎯 Built-in support for popular distros (Alpine, Ubuntu, Arch, Fedora, Kali, Debian)
- 🚀 Proxy to underlying runtime (crun/runc) with enhanced features
- ⚙️ Custom mount points, SSH setup, user management
- 📋 YAML or JSON configuration
- 📱 Native Android support
- 🔒 Static binary builds for enhanced security
- 🔧 Custom init process support (e.g., `/sbin/init`)
- 🔒 Privileged container mode with full capabilities
- 🌐 Network namespace control (host, none, container)
- 💾 Full container mutability options (OverlayFS vs full copy)
- 🔄 Container recreate command for fixing stopped containers
- 🖥️ TTY device allocation for init systems (`--tty` flag)
- ⚙️ Enhanced recreate command with full override support
- 📊 Container resource usage monitoring with CPU percentage, memory, PID, and cgroups info
- 📝 Comprehensive logging with unified log files and real-time progress tracking
- 🔧 Raw runtime access for advanced debugging
- 🔄 Enhanced container status tracking (CREATING → READY → RUNNING → STOPPED)
- 📈 Real-time download progress with percentage indicators in logs
- 🛑 Container creation can be stopped during creation process (both foreground and background modes)
- 💾 Volume management with create, list, inspect, and remove operations
- 📊 JSON output support for data commands with `--json` flag
- 📋 Enhanced volume information display with creation timestamps

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Group Setup](#group-setup)
- [Configuration](#configuration)
- [Key Behavioral Changes](#key-behavioral-changes)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
- [Examples](#examples)
- [Command Reference](#command-reference)
- [Logging](#logging)
- [Building](#building)
- [Comparison with Similar Tools](#comparison-with-similar-tools)
- [Troubleshooting](#troubleshooting)
- [Project Status](#project-status)
- [Contributing](#contributing)

## Quick Start

```bash
# 1. Install dbox (see installation options below)
# 2. Set up the dbox group for Docker-like experience (see Group Setup section)
# 3. Pull an image
dbox pull alpine:latest

# 4. Create a container
dbox create -i alpine:latest -n my-container

# Start the container
dbox start my-container

# Execute commands in container
dbox exec my-container /bin/sh

# Or create and run in one step
dbox run -i alpine:latest -n my-container
```

## Installation

### Prerequisites

- Go 1.25 or later
- crun or runc installed
- **For Docker-like experience without sudo: Set up the `dbox` group** (see Group Setup section below)
- Root permissions only needed for initial group setup

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

**Important:** After installation, set up the dbox group for Docker-like permissions (see Group Setup section below).

## Group Setup (Recommended - Docker-style)

**This is the primary recommended way to run dbox without sudo**, providing a Docker-like experience. Set up a `dbox` group:

```bash
# Create dbox group
sudo groupadd dbox

# Add users to the dbox group (replace 'username' with actual usernames)
sudo usermod -aG dbox username
sudo usermod -aG dbox anotheruser

# Create system directories with proper permissions
sudo mkdir -p /var/run/dbox
sudo mkdir -p /var/lib/dbox/containers

# Set group ownership and permissions
sudo chgrp -R dbox /var/run/dbox
sudo chgrp -R dbox /var/lib/dbox
sudo chmod -R 775 /var/run/dbox
sudo chmod -R 775 /var/lib/dbox

# Optional: Set up user-specific directories
sudo chgrp -R dbox /home/username/.local/share/dbox 2>/dev/null || true
sudo chmod -R 775 /home/username/.local/share/dbox 2>/dev/null || true

# For system-wide usage, update config to use /var/lib/dbox/containers
sudo mkdir -p /etc/dbox
sudo tee /etc/dbox/config.yaml > /dev/null <<EOF
runtime: /usr/bin/crun
runpath: /var/run/dbox
containers_path: /var/lib/dbox/containers
EOF

# Log out and log back in for group changes to take effect
# Or run: newgrp dbox
```

After setup, users in the `dbox` group can run dbox commands without sudo.

## Configuration

Create a config file at `/etc/dbox/config.yaml` or specify with `-c` flag or `DBOX_CONFIG` env var:

```yaml
# /etc/dbox/config.yaml (system-wide, recommended for group setup)
runtime: /usr/bin/crun  # or /usr/bin/runc
runpath: /var/run/dbox
containers_path: /var/lib/dbox/containers

# Alternative: User-specific configuration
# runtime: /usr/bin/crun
# runpath: ~/.dbox/run
# containers_path: ~/.local/share/dbox/containers

# Optional: Custom registries
registries:
  alpine: docker.io/library/alpine
  ubuntu: docker.io/library/ubuntu
  archlinux: docker.io/library/archlinux
  fedora: docker.io/library/fedora
  kali: docker.io/kalilinux/kali-rolling
  debian: docker.io/library/debian
```

### Key Behavioral Changes

#### Container Lifecycle
- **Create vs Run**: `create` only sets up the container filesystem, `run` creates AND starts it
- **Start Behavior**: `start` runs containers in foreground by default (use `-d` for background)
- **Auto-recreation**: Stopped containers are automatically recreated when `start` is called
- **Log Management**: All container output is captured to unified log files

#### Command Changes
- **Enhanced recreate**: Can override ANY original container setting, automatically preserves OverlayFS configuration
- **Resource monitoring**: `usage` command shows CPU percentage and detailed cgroup info
- **Attach support**: `attach` command provides interactive shell access to running containers
- **Status command**: Shows comprehensive container information including log location
- **Raw access**: `raw` command allows direct runtime access for debugging
- **Improved status tracking**: Container list shows accurate states (CREATING, READY, RUNNING, STOPPED, UNKNOWN)
- **Progress visibility**: Download and extraction progress shown by default without `--verbose` flag

#### Filesystem Management
- **OverlayFS default**: Uses OverlayFS for efficient storage (disable with `--no-overlayfs`)
- **Automatic cleanup**: Proper unmounting and cleanup on container deletion
- **Progress indicators**: Shows progress for image pulls and filesystem operations with real-time percentage tracking
- **Enhanced logging**: Download progress and extraction status visible by default in logs

## Usage

### Basic Commands

```bash
# Show configuration and runtime info
dbox info

# Pull an image (shows real-time progress)
dbox pull alpine:latest
dbox pull ubuntu:22.04
dbox pull archlinux

# Create a container
dbox create -i alpine:latest -n my-alpine

# List containers (shows enhanced status: CREATING, READY, RUNNING, STOPPED, UNKNOWN)
dbox list
dbox ls

# Start a container
dbox start my-alpine

# Check container status
dbox status my-alpine

# Execute commands in a container
dbox exec my-alpine /bin/sh
dbox exec my-alpine apk add vim

# Stop a container (works even during creation)
dbox stop my-alpine

# Stop container creation in progress
dbox stop creating-container  # Works for both foreground and background creation

# Recreate a container (fixes stopped containers, preserves data)
dbox recreate my-alpine

# Delete a container
dbox delete my-alpine
dbox rm -f my-alpine  # Force delete

# Clean image cache
dbox clean

# Volume management
dbox volume ls
dbox volume create data-volume
dbox volume inspect data-volume
dbox volume rm data-volume
```

### Advanced Commands

```bash
# Run a container in one step (create + start)
dbox run -i ubuntu:22.04 -n dev-env -d

# Run with custom mounts
dbox run -i alpine -n test -v /host/path:/container/path

# Run with environment variables
dbox run -i alpine -n test -e VAR=value -e ANOTHER=value

# Create with custom configuration
dbox create -i ubuntu:22.04 -n dev --container-config config.json

# View container logs
dbox logs my-container
dbox logs -f my-container  # Follow logs

# Run raw runtime commands
dbox raw list
dbox raw state my-container

# Monitor container resource usage
dbox usage my-container
dbox usage my-container --pid      # Show PID information
dbox usage my-container --cgroup   # Show detailed cgroups info
dbox usage my-container --pid --cgroup  # Show all information

# Attach to running container
dbox attach my-container

# Volume management
dbox volume ls                    # List all volumes
dbox volume create app-data       # Create named volume
dbox volume inspect app-data      # Show volume details
dbox volume rm app-data           # Remove volume

# JSON output for data commands
dbox list --json                  # List containers in JSON format
dbox volume ls --json             # List volumes in JSON format
dbox status my-container --json   # Container status in JSON format

# Enhanced recreate with overrides
dbox recreate my-container --tty                    # Add TTY devices
dbox recreate my-container --privileged            # Make privileged
dbox recreate my-container --image ubuntu:22.04    # Change image
dbox recreate my-container --init /bin/bash         # Change init process
dbox recreate my-container --memory 1g              # Add memory limit
dbox recreate my-container --net host              # Change network
```

## Advanced Features

### Enhanced Progress Tracking

dbox provides real-time progress tracking for all operations without requiring verbose flags:

```bash
# Image pulls show download and extraction progress
dbox pull alpine:latest
# Output:
# Image not found locally, pulling automatically...
# Found 1 layers to extract
# Extracting 1 layers...
# Extracting layer 1/1...
#   Downloading data... [██████████████████████████████] 100.0% (3.6 MB / 3.6 MB)

# Container creation shows filesystem setup progress
dbox create -i alpine -n test
# Output:
# Setting up OverlayFS mount...
# Successfully created container 'test'
```

**Progress Features:**
- **Real-time download bars** with percentage and file size
- **Layer extraction tracking** showing current layer progress
- **Filesystem operation status** for OverlayFS setup
- **Always visible** - no `--verbose` flag required
- **Logged by default** - progress appears in container logs

### Container Status Tracking

dbox tracks containers through their complete lifecycle with detailed status states:

```bash
dbox list
# Output:
# CONTAINER_NAME       IMAGE           STATUS     CREATED
# -------------------- --------------- ---------- -------------------
# my-container         alpine          READY      2025-11-04
# running-container     ubuntu          RUNNING    2025-11-04
# stopped-container     fedora          STOPPED    2025-11-04
# creating-container   arch            CREATING   2025-11-04
# corrupted-container  debian          UNKNOWN    2025-11-04
```

**Status States:**
- **CREATING**: Container is being created and filesystem is being set up
- **READY**: Container created successfully, ready to be started
- **RUNNING**: Container is currently running
- **STOPPED**: Container is stopped but intact
- **UNKNOWN**: Container state cannot be determined (possibly corrupted)
- **CREATION_STOPPED**: Container creation was interrupted and stopped

**Status Transitions:**
```
CREATING → READY → RUNNING → STOPPED
    ↓         ↓        ↓        ↓
  UNKNOWN   UNKNOWN   UNKNOWN   CREATION_STOPPED
```

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
  --memory 2g \
  --cpu-shares 1024 \
  -e EDITOR=vim \
  -v ~/projects:/workspace
```

**How recreate works:**
1. Reads original container configuration
2. Automatically detects original OverlayFS setting (preserves filesystem type)
3. Applies any flag overrides you provide
4. Preserves settings that aren't overridden
5. Stops and recreates the container with new settings
6. Preserves container data and filesystem changes

**Note:** The `recreate` command automatically preserves the original OverlayFS setting to prevent conflicts between overlay and non-overlay filesystem types.

### Container Creation Stopping

dbox allows you to stop container creation during the creation process, regardless of whether you used the `-d` (detach) flag or not:

```bash
# Start container creation in foreground
dbox create -i alpine -n test-container

# In another terminal, stop the creation
dbox stop test-container

# Works for both foreground and background creation
dbox create -i ubuntu -n bg-container -d
dbox stop bg-container  # Stops background creation
```

**How Creation Stopping Works:**
- **Process Management**: Container creation runs in a separate process group for both foreground and background modes
- **PID Tracking**: The creation process ID is stored for termination
- **Clean Cleanup**: Automatically removes partial container files and updates status
- **Status Update**: Container status is set to `CREATION_STOPPED` for clarity

**Use Cases:**
- **Long Downloads**: Stop large image pulls that are taking too long
- **Mistakes**: Cancel accidental container creation
- **Resource Management**: Stop creation when system resources are needed
- **Testing**: Interrupt creation for testing purposes

**What Gets Cleaned Up:**
- Partial container filesystem
- Creation process PID files
- Container metadata (status updated to `CREATION_STOPPED`)
- Log files (preserved for debugging)

**Example Scenario:**
```bash
# Terminal 1: Start a large container creation
dbox create -i large-image:latest -n big-container
# Output: Creating container 'big-container' from image 'large-image:latest'...
# Output: Found 15 layers to extract...

# Terminal 2: Stop the creation
dbox stop big-container
# Output: Container 'big-container' creation stopped

# Check status
dbox list
# Output: big-container    large-image    CREATION_STOPPED    2025-11-04
```

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
  --net host

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
  --net host

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

- Go 1.25 or later
- crun or runc installed
- For cross-compilation: appropriate C compilers (clang for amd64, gcc-aarch64-linux-gnu for arm64)

### Standard Build

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go build -o dbox
```

### Using the Makefile

The provided Makefile simplifies building for multiple platforms:

```bash
# Show help
make help

# Build for all common platforms
make all

# Build for specific platforms
make linux-amd64      # Linux x86_64
make linux-arm64      # Linux ARM64  
make android          # Android (both arm64 and x86_64)
make android-arm64    # Android ARM64 only
make android-x86_64   # Android x86_64 only
make static-musl      # Static Linux binary with musl
```

### Manual Cross-Compilation

For Linux (static binary):
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dbox-linux-amd64 .
```

For Android:
```bash
# Set up NDK environment variables
export NDK_ROOT=$HOME/Android/Sdk/ndk/25.1.8937393  # Update version as needed
export API_LEVEL=21
export TOOLCHAIN=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64
export CC=$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang

# Build
CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -ldflags="-s -w" -o dbox-android-arm64 .
```

### Build Outputs

Built binaries are placed in the `bin/` directory:
- `dbox-linux-amd64` - Linux x86_64
- `dbox-linux-arm64` - Linux ARM64
- `dbox-android-arm64` - Android ARM64
- `dbox-android-x86_64` - Android x86_64
- `dbox-linux-amd64-musl` - Static Linux binary

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
| Unified Logging | ✓ | ✗ | ✓ | ✓ |
| Progress Tracking | ✓ | ✗ | Limited | Limited |
| Status States | ✓ | ✗ | ✓ | ✓ |
| Container Recreate | ✓ | ✗ | ✗ | ✗ |
| Creation Stopping | ✓ | ✗ | ✗ | ✗ |
| Raw Runtime Access | ✓ | ✗ | Limited | Limited |

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
- `--verbose`: Enable verbose output with debug messages
- `--json`: Output in JSON format for data commands

### Available Commands

#### **create** - Create a new container
```bash
dbox create [flags]

Required:
  -i, --image string        Image to use (e.g., alpine:latest)
  -n, --name string         Container name

Optional:
  --container-config string  Path to container_config.json

  -e, --env strings         Set environment variables
  --dns strings             DNS servers to use for image pulls
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
  --tty                   Allocate TTY devices (needed for some init systems)
```

#### **run** - Create and start a container in one step
```bash
dbox run [flags]

Required:
  -i, --image string        Image to use (e.g., ubuntu:latest)

Optional:
  -n, --name string         Assign a name to the container
  --container-config string  Path to container_config.json
  -e, --env strings         Set environment variables
  -d, --detach             Run container in background
  --dns strings            DNS servers to use for image pulls
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
  --tty                   Allocate TTY devices (needed for some init systems)
```

#### **start** - Start a created container
```bash
dbox start [container-name] [flags]
Optional:
  -d, --detach           Run in background (default is foreground)
```

#### **stop** - Stop a running container or container creation
```bash
dbox stop [container-name] [flags]
Optional:
  -f, --force           Force stop: container

# Can stop containers during creation process (both foreground and background modes)
# Works for containers in CREATING, RUNNING, or READY states
# Automatically cleans up partial creation files and updates status
```

#### **list** - List all containers
```bash
dbox list
# Alias: dbox ls
# Shows enhanced status: CREATING, READY, RUNNING, STOPPED, UNKNOWN
```

#### **exec** - Execute commands in a container
```bash
dbox exec [container-name] [command...]
```

#### **attach** - Attach to a running container
```bash
dbox attach [container-name]
```

#### **logs** - View container logs
```bash
dbox logs [container-name] [flags]
Optional:
  -f, --follow           Follow log output
```

#### **status** - Show detailed container status
```bash
dbox status [container-name]
```

#### **usage** - Monitor container resource usage
```bash
dbox usage [container-name] [flags]
Optional:
  --pid                  Show PID information
  --cgroup               Show detailed cgroups information
```

#### **recreate** - Recreate container (fixes stopped containers)
```bash
dbox recreate [container-name] [flags]

# Override any container setting during recreation:
  -i, --image string           Override image
  --container-config string     Override container_config.json

  -e, --env strings            Override environment variables
  --dns strings                DNS servers to use for image pulls
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

#### **delete** - Delete a container
```bash
dbox delete [container-name] [flags]
# Alias: dbox rm
Optional:
  -f, --force           Force delete running container
```

#### **pull** - Pull an image from registry
```bash
dbox pull [image] [flags]
Optional:
  --dns strings    DNS servers to use for image pulls
# Shows real-time download progress and extraction status by default
```

#### **script** - Run a script in an existing container
```bash
dbox script [container-name] [script-path]
```

#### **clean** - Clean image cache
```bash
dbox clean
```

#### **info** - Show configuration and runtime information
```bash
dbox info
```

#### **raw** - Run raw runtime commands
```bash
dbox raw [runtime-args...]
```

#### **completion** - Generate the autocompletion script for the specified shell
```bash
dbox completion [bash|zsh|fish]
```

#### **volume** - Manage volumes
```bash
dbox volume [command]

Available Commands:
  create      Create a volume
  inspect     Display detailed information on one or more volumes
  ls          List volumes
  rm          Remove one or more volumes

Examples:
  dbox volume ls                           # List all volumes
  dbox volume create data-volume           # Create a volume
  dbox volume inspect data-volume          # Inspect a volume
  dbox volume rm data-volume               # Remove a volume
  dbox volume create --driver local opts   # Create with options
  dbox volume rm -f data-volume            # Force remove volume
```

**Note:** Completion works best when dbox is run as a regular user (see Group Setup). For sudo usage, see the "Shell Completion with sudo" section in Troubleshooting.

## Environment Variables

- `DBOX_CONFIG`: Path to configuration file
- `DBOX_RUNTIME`: Override runtime path
- `DBOX_RUNPATH`: Override run path

## Logging

dbox provides comprehensive logging for all container operations:

### Unified Log Files
Each container has a unified log file that captures:
- Container stdout/stderr output
- Runtime operation logs
- dbox operation logs

Log files are located at: `/var/run/dbox/logs/[container-name].log`

### Log Management
```bash
# View container logs
dbox logs my-container

# Follow logs in real-time
dbox logs -f my-container

# Logs are automatically created when containers start
# Log location is shown in container status
dbox status my-container
```

### Log Format
```
[2025-01-30T10:15:30Z] DBOX: Creating container 'my-container' from image 'alpine'
[2025-01-30T10:15:30Z] DBOX: Image not found locally, pulling automatically...
Found 1 layers to extract
Extracting 1 layers...
Extracting layer 1/1...
  Downloading data... [██████████████████████████████] 100.0% (3.6 MB / 3.6 MB)
[2025-01-30T10:15:31Z] DBOX: Setting up OverlayFS mount...
[2025-01-30T10:15:31Z] DBOX: Successfully created container 'my-container'
[2025-01-30T10:15:32Z] DBOX: Starting container 'my-container'
[2025-01-30T10:15:33Z] DBOX: Successfully started container 'my-container'
Container output appears here...
```

### Log Cleanup
Logs are automatically cleaned up when containers are deleted. Manual log management:
```bash
# View log file location
ls -la /var/run/dbox/logs/

# Clean all logs (requires manual deletion)
sudo rm -rf /var/run/dbox/logs/*
```

## Directory Structure

**User-specific (default):**
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

**System-wide (with group setup):**
```
/var/lib/dbox/containers/
├── .images/              # Shared pulled images
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

**Recommended: Set up the dbox group** (see Group Setup section above for Docker-style permissions - this is the primary way to run dbox without sudo).

**Alternative: Run with sudo**
```bash
sudo dbox create -i alpine -n test
```

**Note:** If using sudo, shell completion may not work properly. See the section below for a workaround.

### Directory Permission Issues

dbox creates configuration and container directories automatically. If you encounter permission errors:

**Primary solution: Docker-style group setup** (see Group Setup section above - this is the recommended approach).

**Temporary workaround: Run with sudo**
```bash
sudo dbox create -i alpine -n test
```

**Alternative: Create directories manually with proper permissions**
```bash
# Create the default directories
sudo mkdir -p /var/run/dbox
sudo mkdir -p ~/.local/share/dbox/containers

# Set ownership to your user (replace 'username' with your actual username)
sudo chown -R username:username /var/run/dbox
sudo chown -R username:username ~/.local/share/dbox
```

**Last resort: Use custom config location**
```bash
# Create a config file in a location you own
mkdir -p ~/dbox-config
cat > ~/dbox-config/config.yaml << EOF
runtime: /usr/bin/crun
runpath: ~/dbox-config/run
containers_path: ~/dbox-config/containers
EOF

# Use the custom config
dbox -c ~/dbox-config/config.yaml create -i alpine -n test
```

**Option 4: Docker-style group setup (recommended)**
```bash
# Create dbox group
sudo groupadd dbox

# Add your user to the dbox group (replace 'username' with your actual username)
sudo usermod -aG dbox username

# Create the default directories with group ownership
sudo mkdir -p /var/run/dbox
sudo mkdir -p /var/lib/dbox/containers  # Alternative system-wide location

# Set group ownership and permissions
sudo chgrp -R dbox /var/run/dbox
sudo chgrp -R dbox /var/lib/dbox
sudo chmod -R 775 /var/run/dbox
sudo chmod -R 775 /var/lib/dbox

# For user-specific containers, set group ownership on user directories
sudo chgrp -R dbox ~/.local/share/dbox 2>/dev/null || true
sudo chmod -R 775 ~/.local/share/dbox 2>/dev/null || true

# If using systemd, you may need to configure the service
# Create /etc/systemd/system/dbox.service with appropriate group settings

# Log out and log back in for group changes to take effect
# Or run: newgrp dbox
```

After setting up the group, users in the `dbox` group can run dbox commands without sudo. You may need to update your config to use `/var/lib/dbox/containers` for system-wide container storage if preferred.

### Shell Completion with sudo

If you must use sudo but still want shell completion, you have two options:

**Option 1: Generate completion as regular user and install system-wide**
```bash
# Generate completion script as your regular user
dbox completion bash > ~/dbox-completion.bash

# Install system-wide (requires sudo)
sudo cp ~/dbox-completion.bash /etc/bash_completion.d/dbox
sudo chmod 644 /etc/bash_completion.d/dbox

# Or for manual sourcing
echo "source ~/dbox-completion.bash" >> ~/.bashrc
```

**Option 2: Use sudo with completion preserved**
```bash
# For bash, add this to your ~/.bashrc
complete -F _dbox dbox

# Generate the completion function
dbox completion bash | grep -A 100 "_dbox()" >> ~/.bashrc
```

**Option 3: Create a sudo wrapper script**
```bash
# Create a wrapper script
cat > ~/bin/dbox-sudo <<'EOF'
#!/bin/bash
exec sudo /usr/local/bin/dbox "$@"
EOF
chmod +x ~/bin/dbox-sudo

# Add to PATH and set up completion
export PATH="$HOME/bin:$PATH"
complete -F _dbox dbox-sudo
```

**For Zsh with sudo:**
```bash
# Create completion directory
mkdir -p ~/.zsh/completions

# Generate completion for zsh
dbox completion zsh > ~/.zsh/completions/_dbox

# Add to your ~/.zshrc (if not already present)
echo "fpath=(~/.zsh/completions \$fpath)" >> ~/.zshrc
echo "autoload -U compinit && compinit" >> ~/.zshrc

# Reload completion
exec zsh
```

**Note:** If fzf completion interferes, you may need to disable fzf completion for dbox:
```bash
# Add to ~/.zshrc to disable fzf for dbox
echo "zstyle ':fzf-tab:*' disabled-on 'dbox'" >> ~/.zshrc
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

dbox provides robust container lifecycle management with automatic recovery:

```bash
# Normal workflow
dbox create -i alpine -n my-container
dbox start my-container
# ... use container ...
dbox stop my-container
dbox start my-container  # Works normally

# If container won't start after being stopped
# dbox automatically recreates it during start
dbox start my-container  # Auto-fixes the issue, preserves data

# Manual recreate if needed
dbox recreate my-container
```

### Container Issues

If containers have issues:

```bash
# Check container status first
dbox status my-container

# View logs for errors
dbox logs my-container

# Recreate with overrides if needed
dbox recreate my-container --privileged

# Last resort - delete and recreate (loses data)
dbox delete my-container -f
dbox create -i alpine -n my-container
```

**Data Persistence:**

- **`recreate`**: Preserves all container data and configuration
- **`delete`**: Completely removes the container including all data
- **Auto-recreate**: `start` automatically fixes stopped containers

### Automatic Container Recovery

The `start` command automatically handles stopped containers:

```bash
# When a container fails to start with "stopped" status:
dbox start my-container

# dbox automatically:
# 1. Detects stopped container
# 2. Deletes from runtime (preserves filesystem)
# 3. Recreates container with original settings
# 4. Starts the container
# 5. Preserves all data in OverlayFS upper layer
```

### Enhanced Recreate Command

The `recreate` command can override any setting:

```bash
# Change multiple settings at once
dbox recreate my-container \
  --privileged \
  --memory 1g \
  --net host \
  --init /sbin/init

# View what changed
dbox status my-container
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

dbox is currently in **beta**. It's functional for basic container operations but may have bugs. The core features are implemented and tested.

### ✅ Implemented Features
- [x] Basic container operations (create, start, stop, delete)
- [x] Image management (pull, list, clean)
- [x] Configuration management (YAML/JSON)
- [x] Android support
- [x] Static binary builds
- [x] Custom init process support
- [x] Privileged container mode
- [x] Network namespace control
- [x] Resource limits (CPU, memory, block I/O)
- [x] Container mutability options (OverlayFS vs full copy)
- [x] Container recreate functionality with overrides
- [x] Container resource usage monitoring
- [x] Comprehensive logging system with real-time progress tracking
- [x] Enhanced container status tracking (CREATING → READY → RUNNING → STOPPED → UNKNOWN → CREATION_STOPPED)
- [x] Real-time download progress with percentage indicators
- [x] Container creation stopping (works for both foreground and background modes)
- [x] Raw runtime access
- [x] Container attach functionality
- [x] Setup script execution
- [x] Volume management (create, list, inspect, remove)
- [x] JSON output support for data commands
- [x] Enhanced volume information with creation timestamps
- [x] CLI refactoring with improved package structure

### 🚧 Planned Features
- [ ] Container networking (advanced)
- [ ] Container updates
- [ ] GUI interface
- [ ] Container snapshots
- [ ] Multi-architecture image support
- [ ] Container export/import
- [ ] Health checks
- [ ] Auto-restart policies
- [ ] Volume drivers beyond local
- [ ] Container metrics and monitoring dashboard
- [ ] Integration with container registries (push/pull)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go test ./...

# Build for development
go build -o dbox .

# Or use the Makefile for cross-platform builds
make help
make linux-amd64    # Build for current platform
make all           # Build for all platforms
```

### Code Style

This project follows Go standard formatting and linting guidelines. Please run `gofmt` before submitting pull requests.

### Project Structure

```
dbox/
├── cli/                    # CLI command definitions
│   ├── cli.go             # Main CLI commands (pull, run, create, etc.)
│   ├── container_cmds.go  # Container-specific commands
│   └── volume_cmd.go      # Volume management commands
├── config/                # Configuration management
├── container/             # Container lifecycle and management
├── image/                 # Image operations
├── logger/                # Logging utilities
├── runtime/               # OCI runtime integration
├── utils/                 # Utility functions
├── volume/                # Volume management
└── main.go               # Application entry point
```

### Reporting Issues

Please report bugs and feature requests on the [Issues](https://github.com/yourusername/dbox/issues) page.

When reporting issues, please include:
- dbox version (`dbox info`)
- Go version
- Runtime being used (crun/runc version)
- Operating system and architecture
- Full error message and steps to reproduce
- Configuration file (if relevant)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Recent Changes

### Latest Features
- **Volume Management**: Full volume lifecycle support with create, list, inspect, and remove operations
- **JSON Output**: Added `--json` flag for structured data output in list, status, and volume commands
- **Enhanced Volume Info**: Volume listings now include creation timestamps
- **CLI Refactoring**: Improved code organization with separated command packages
- **Native OverlayFS Detection**: Better filesystem compatibility with automatic fallback

### Recent Improvements
- Better error handling and null pointer safety
- Standardized display messages across commands
- Enhanced configuration management with example config
- Improved build system with better cross-compilation support

## Acknowledgments

- Inspired by [distrobox](https://github.com/89luca89/distrobox)
- Uses [go-containerregistry](https://github.com/google/go-containerregistry) for image operations
- Built with [cobra](https://github.com/spf13/cobra) for CLI interface
- OCI runtime support via [crun](https://github.com/containers/crun) and [runc](https://github.com/opencontainers/runc)
