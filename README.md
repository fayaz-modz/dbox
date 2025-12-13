# dbox - Container Management Tool

A lightweight distrobox-like container management tool written in Go that provides a simple interface for managing OCI containers using crun or runc.

## Quick Start

```bash
# Install
git clone https://github.com/yourusername/dbox
cd dbox
make dev

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
dbox version                    # Show version
```

## Features

- 🐳 Pull images from OCI registries (Docker Hub, etc.)
- 📦 Create and manage containers with custom configurations
- 🚀 Proxy to underlying runtime (crun/runc) with enhanced features
- 📱 Native Android support
- 🔒 Static binary builds for enhanced security
- 📊 JSON output support for data commands with `--json` flag
- 💾 Volume management with create, list, inspect, and remove operations
- 🔄 Container recreate command for fixing stopped containers
- 📈 Real-time download progress with percentage indicators
- 🖥️ TTY device allocation for init systems
- ⚙️ Resource limits (CPU, memory, block I/O)
- 📝 Comprehensive logging with unified log files

## Installation

### Prerequisites

- Go 1.25 or later
- crun or runc installed
- Root permissions only needed for initial group setup

### From Source

```bash
git clone https://github.com/yourusername/dbox
cd dbox
make dev
sudo mv dbox /usr/local/bin/
```

### Group Setup (Recommended - Docker-style)

Set up a `dbox` group for Docker-like permissions:

```bash
# Create dbox group
sudo groupadd dbox

# Add user to dbox group (replace 'username' with actual username)
sudo usermod -aG dbox username

# Create system directories with proper permissions
sudo mkdir -p /var/run/dbox
sudo mkdir -p /var/lib/dbox/containers
sudo mkdir -p /var/lib/dbox/volumes

# Set group ownership and permissions
sudo chgrp -R dbox /var/run/dbox
sudo chgrp -R dbox /var/lib/dbox
sudo chgrp -R dbox /var/lib/dbox/volumes
sudo chmod -R 775 /var/run/dbox
sudo chmod -R 775 /var/lib/dbox
sudo chmod -R 775 /var/lib/dbox/volumes

# Create system config
sudo mkdir -p /etc/dbox
sudo tee /etc/dbox/config.yaml > /dev/null <<EOF
runtime: /usr/bin/crun
runpath: /var/run/dbox
containers_path: /var/lib/dbox/containers
volumes_path: /var/lib/dbox/volumes
EOF

# Log out and log back in for group changes to take effect
```

After setup, users in the `dbox` group can run dbox commands without sudo.

## Configuration

Create a config file at `/etc/dbox/config.yaml` or specify with `-c` flag:

```yaml
runtime: /usr/bin/crun  # or /usr/bin/runc
runpath: /var/run/dbox
containers_path: /var/lib/dbox/containers
volumes_path: /var/lib/dbox/volumes

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

### Container Management

```bash
# Create and run containers
dbox create -i alpine:latest -n my-container
dbox start my-container
dbox run -i ubuntu:22.04 -n dev-env -d  # Create + start in background

# Execute commands
dbox exec my-container /bin/sh
dbox exec my-container apk add vim

# Container lifecycle
dbox stop my-container
dbox delete my-container
dbox recreate my-container --privileged  # Fix/modify container

# List and status
dbox list                              # List all containers
dbox status my-container                # Container details
dbox logs my-container                  # View logs
dbox logs -f my-container               # Follow logs
```

### Image Management

```bash
# Pull images (shows real-time progress)
dbox pull alpine:latest
dbox pull ubuntu:22.04

# List and manage images
dbox image ls                          # List images with usage info
dbox image ls --json                  # List images in JSON format
dbox image rm alpine:latest           # Remove specific image
dbox clean                            # Clean unused images
dbox clean --all                      # Clean all images
```

### Volume Management

```bash
# Volume operations
dbox volume ls                        # List volumes
dbox volume create data-volume         # Create volume
dbox volume inspect data-volume        # Inspect volume
dbox volume rm data-volume             # Remove volume
```

### Advanced Features

```bash
# Resource limits
dbox create -i alpine -n limited \
  --memory 512m \
  --cpu-shares 1024 \
  --cpu-quota 50000

# Privileged containers
dbox create -i alpine -n privileged --privileged

# Custom init process
dbox create -i alpine -n init-container --init /sbin/init --tty

# Network control
dbox create -i alpine -n host-net --net host
dbox create -i alpine -n isolated-net --net none

# Resource monitoring
dbox usage my-container
dbox usage my-container --pid --cgroup

# JSON output for automation
dbox list --json
dbox status my-container --json
dbox volume ls --json
dbox version --json
```

## Building

### Development Build

```bash
make dev          # Fast build for current platform (outputs to ./dbox)
```

### Production Builds

```bash
make help         # Show all build options
make linux-amd64  # Linux x86_64
make linux-arm64  # Linux ARM64
make android      # Android (both arm64 and x86_64)
make static-musl  # Static Linux binary
make all          # Build for all platforms
```

### Version Information

Build with custom version:

```bash
VERSION=1.0.0 make linux-amd64
```

Or manually with ldflags:

```bash
go build -ldflags="-X main.Version=1.0.0 -X main.Commit=abc123" -o dbox .
```

## JSON API

dbox provides stable JSON output for automation and integration. See [API.md](API.md) for complete API reference.

### Example JSON Outputs

```bash
# Container list
dbox list --json
{
  "containers": [
    {
      "name": "my-container",
      "image": "alpine:latest",
      "status": "RUNNING",
      "created": "2025-12-13T18:21:49Z",
      "type": "Container"
    }
  ]
}

# Version information
dbox version --json
{
  "dbox_version": "1.0.0",
  "runtime": "/usr/bin/crun",
  "runtime_version": "crun version 1.25.1...",
  "go_version": "1.25.3",
  "commit": "faae26e",
  "build_time": "2025-12-13T18:21:49Z"
}
```

## Command Reference

### Global Flags

- `-c, --config`: Path to config file (or set `DBOX_CONFIG` env)
- `--verbose`: Enable verbose output with debug messages
- `--json`: Output in JSON format for data commands

### Main Commands

| Command | Description |
|---------|-------------|
| `create` | Create a new container |
| `run` | Create and start a container in one step |
| `start` | Start a created container |
| `stop` | Stop a running container |
| `delete` | Delete a container |
| `list` | List all containers |
| `exec` | Execute commands in a container |
| `logs` | View container logs |
| `status` | Show detailed container status |
| `recreate` | Recreate container (fixes stopped containers) |
| `pull` | Pull an image from registry |
| `image` | Manage images |
| `volume` | Manage volumes |
| `usage` | Monitor container resource usage |
| `attach` | Attach to a running container |
| `info` | Show configuration and runtime information |
| `version` | Show version information |
| `clean` | Clean image cache |
| `raw` | Run raw runtime commands |
| `completion` | Generate shell completion scripts |

## Container Status States

- **CREATING**: Container is being created and filesystem is being set up
- **READY**: Container created successfully, ready to be started
- **RUNNING**: Container is currently running
- **STOPPED**: Container is stopped but intact
- **UNKNOWN**: Container state cannot be determined (possibly corrupted)
- **CREATION_STOPPED**: Container creation was interrupted and stopped

## Directory Structure

```
/var/lib/dbox/
├── containers/          # Container instances
│   └── my-container/
│       ├── bundle/      # OCI bundle
│       ├── upper/       # OverlayFS upper layer
│       ├── work/        # OverlayFS work directory
│       └── metadata.json
├── volumes/            # Named volumes
│   └── data-volume/
│       └── _data/
└── .images/            # Pulled images
    └── alpine_latest/
        ├── rootfs/
        └── config.json

/var/run/dbox/
├── logs/               # Container logs
│   └── my-container.log
└── ...                # Runtime files
```

## Troubleshooting

### Permission Denied

Set up the dbox group (see Group Setup section above) or run with sudo:

```bash
sudo dbox create -i alpine -n test
```

### Container Won't Start

Check runtime status and logs:

```bash
dbox info
dbox status my-container
dbox logs my-container
```

### Init Process Issues

Try alternative init processes:

```bash
dbox create -i alpine -n test --init /bin/sh
dbox create -i ubuntu -n test --init /lib/systemd/systemd
```

### TTY Device Errors

Add TTY devices for init systems that require them:

```bash
dbox create -i alpine -n test --init /sbin/init --tty
```

## Comparison with Similar Tools

| Feature | dbox | distrobox | podman | docker |
|---------|------|-----------|--------|--------|
| OCI Runtime | ✓ | ✓ | ✓ | ✓ |
| No Daemon | ✓ | ✓ | ✓ | ✗ |
| Rootless | ✓ | ✓ | ✓ | ✓ |
| Android Support | ✓ | ✗ | ✗ | ✗ |
| Static Binary | ✓ | ✗ | ✗ | ✗ |
| JSON API | ✓ | ✗ | ✓ | ✓ |
| Volume Management | ✓ | ✗ | ✓ | ✓ |
| Resource Limits | ✓ | Limited | ✓ | ✓ |

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/yourusername/dbox
cd dbox
go mod download
go test ./...

# Development build
make dev

# Run tests
go test ./...
```