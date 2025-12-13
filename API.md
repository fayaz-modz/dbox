# dbox API Reference

This document defines the stable JSON output format for dbox commands that support the `--json` flag.

## Global JSON Output Format

All JSON outputs follow these conventions:
- Objects use snake_case for field names
- Timestamps are in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
- Arrays are used for lists of items
- Null values are omitted unless explicitly required
- Error responses include an `error` field with a descriptive message

## Commands with JSON Output

### version

Display version information for dbox and its runtime.

**Command:** `dbox version --json`

**Response:**
```json
{
  "dbox_version": "1.0.0",
  "runtime": "/usr/bin/crun",
  "runtime_version": "crun version 1.25.1\ncommit: 156ae065d4a322d149c7307034f98d9637aa92a2\n...",
  "go_version": "1.25.3",
  "commit": "faae26e",
  "build_time": "2025-12-13T18:21:49Z"
}
```

**Fields:**
- `dbox_version` (string): Version of dbox
- `runtime` (string): Path to OCI runtime binary
- `runtime_version` (string): Full version output from runtime
- `go_version` (string): Go version used to build dbox
- `commit` (string): Git commit hash (or "dev" for development builds)
- `build_time` (string): Build timestamp (or "dev" for development builds)

---

### list

List all containers with their status and metadata.

**Command:** `dbox list --json`

**Response:**
```json
[
  {
    "container_name": "my-container",
    "image": "alpine:latest",
    "status": "RUNNING",
    "created": "2025-12-13"
  },
  {
    "container_name": "vm-container",
    "image": "ubuntu:22.04",
    "status": "READY",
    "created": "2025-12-13"
  }
]
```

**Fields:**
- Array of container objects with the following fields:
  - `container_name` (string): Container name
  - `image` (string): Image reference used to create container
  - `status` (string): Container status (always uppercase: CREATING, READY, RUNNING, STOPPED, UNKNOWN)
  - `created` (string): Creation date in YYYY-MM-DD format

---

### status

Show detailed status and configuration information for a specific container.

**Command:** `dbox status [container-name] --json`

**Response:**
```json
{
  "container": "my-container",
  "status": "RUNNING",
  "image": "alpine:latest",
  "type": "Container",
  "log_file": "/var/run/dbox/logs/my-container.log",
  "vm_config": {
    "ssh": "Enabled on port 2222",
    "hostname": "my-vm"
  }
}
```

**Fields:**
- `container` (string): Container name
- `status` (string): Current container status (always uppercase: CREATING, READY, RUNNING, STOPPED, UNKNOWN)
- `image` (string): Image reference
- `type` (string): Container type ("Container" or "VM Container")
- `log_file` (string): Path to container log file
- `vm_config` (object, optional): VM-specific configuration (only for VM containers)
  - `ssh` (string): SSH configuration info
  - `hostname` (string): VM hostname

---

### info

Show general configuration and runtime information.

**Command:** `dbox info --json`

**Response:**
```json
{
  "runtime": "/usr/bin/crun",
  "run_path": "/var/run/dbox",
  "containers_path": "/var/lib/dbox/containers",
  "volumes_path": "/var/lib/dbox/volumes",
  "runtime_version": "crun version 1.25.1\ncommit: 156ae065d4a322d149c7307034f98d9637aa92a2\n..."
}
```

**Fields:**
- `runtime` (string): Path to OCI runtime binary
- `run_path` (string): Runtime directory path
- `containers_path` (string): Containers storage directory
- `volumes_path` (string): Volumes storage directory
- `runtime_version` (string): Full version output from runtime

---

### volume ls

List all volumes with their metadata.

**Command:** `dbox volume ls --json`

**Response:**
```json
[
  {
    "name": "data-volume",
    "driver": "local",
    "mountpoint": "/var/lib/dbox/volumes/data-volume/_data",
    "created_at": "2025-12-13T18:21:49Z"
  },
  {
    "name": "app-data",
    "driver": "local",
    "mountpoint": "/var/lib/dbox/volumes/app-data/_data",
    "created_at": "2025-12-13T18:20:15Z"
  }
]
```

**Fields:**
- Array of volume objects with the following fields:
  - `name` (string): Volume name
  - `driver` (string): Volume driver (currently only "local")
  - `mountpoint` (string): Path where volume is mounted
  - `created_at` (string): Creation timestamp in RFC3339 format

---

### volume inspect

Display detailed information about one or more volumes.

**Command:** `dbox volume inspect [volume-name...] --json`

**Response:**
```json
{
  "name": "data-volume",
  "driver": "local",
  "created_at": "2025-12-13T18:21:49Z",
  "mountpoint": "/var/lib/dbox/volumes/data-volume/_data"
}
```

**Fields:**
- `name` (string): Volume name
- `driver` (string): Volume driver
- `created_at` (string): Creation timestamp in RFC3339 format
- `mountpoint` (string): Mount path

---

### image ls

List all available images with usage information.

**Command:** `dbox image ls --json`

**Response:**
```json
[
  {
    "name": "alpine_latest",
    "full_name": "alpine:latest",
    "size": "5.6 MB",
    "created": "2025-12-13",
    "used_by": ["my-container", "test-container"],
    "in_use": true
  },
  {
    "name": "ubuntu_22.04",
    "full_name": "ubuntu:22.04",
    "size": "72.8 MB",
    "created": "2025-12-13",
    "used_by": [],
    "in_use": false
  }
]
```

**Fields:**
- Array of image objects with the following fields:
  - `name` (string): Image name (sanitized for filesystem)
  - `full_name` (string): Full image reference
  - `size` (string): Image size in human-readable format
  - `created` (string): Creation date in YYYY-MM-DD format
  - `used_by` (array): List of container names using this image
  - `in_use` (boolean): Whether image is in use by any container

---

## Error Response Format

All commands may return error responses in this format:

```json
{
  "error": "Container 'my-container' does not exist"
}
```

**Fields:**
- `error` (string): Human-readable error message

## Status Values

Container status values are always uppercase and follow this enumeration:

- `CREATING`: Container is being created and filesystem is being set up
- `READY`: Container created successfully, ready to be started
- `RUNNING`: Container is currently running
- `STOPPED`: Container is stopped but intact
- `UNKNOWN`: Container state cannot be determined (possibly corrupted)

## Timestamp Format

Different commands use different timestamp formats:

- **RFC3339 format**: `YYYY-MM-DDTHH:MM:SSZ` (used by volume commands)
  - Example: `2025-12-13T18:21:49Z`
- **Date format**: `YYYY-MM-DD` (used by container and image list commands)
  - Example: `2025-12-13`

## Version Compatibility

This API reference applies to dbox version 1.0.0 and later. Fields marked as optional may not be present in older versions.

## Stability Guarantees

- **Stable**: Field names and types will not change in minor releases
- **Additive**: New fields may be added in minor releases
- **Deprecated**: Fields will be marked deprecated before removal in major releases
- **Error Format**: Error response format is stable across all commands