package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"

	. "dbox/config"
	. "dbox/logger"
	. "dbox/volume"
)

func (cm *ContainerManager) generateOCISpecUsingRuntime(bundlePath, imagePath, name string, opts *CreateOptions, runOpts *RunOptions, containerCfg *ContainerConfig, rootPathForSpec string) error {
	cmd := exec.Command(cm.cfg.Runtime, "spec")
	cmd.Dir = bundlePath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate base OCI spec: %v\nOutput: %s", err, string(output))
	}
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read generated config: %w", err)
	}
	var ociSpec spec.Spec
	if err := json.Unmarshal(data, &ociSpec); err != nil {
		return fmt.Errorf("failed to parse generated config: %w", err)
	}

	// Merge configurations with proper priority: default < container config < CLI flags
	mergedConfig := cm.mergeContainerConfigs(containerCfg, opts, runOpts)
	if ociSpec.Root == nil {
		ociSpec.Root = &spec.Root{}
	}
	ociSpec.Root.Path = rootPathForSpec
	ociSpec.Root.Readonly = false
	imageConfigPath := filepath.Join(imagePath, "config.json")
	imageData, err := os.ReadFile(imageConfigPath)
	if err != nil {
		return fmt.Errorf("could not read image config file from pull at %s: %w", imageConfigPath, err)
	}
	var imgConfig v1.ConfigFile
	if err := json.Unmarshal(imageData, &imgConfig); err != nil {
		return fmt.Errorf("could not parse image config file: %w", err)
	}
	if ociSpec.Process == nil {
		ociSpec.Process = &spec.Process{}
	}
	// Check for custom init process
	var initProcess string
	if opts != nil && opts.InitProcess != "" {
		initProcess = opts.InitProcess
	} else if runOpts != nil && runOpts.InitProcess != "" {
		initProcess = runOpts.InitProcess
	}

	if initProcess != "" {
		ociSpec.Process.Args = []string{initProcess}
	} else if runOpts != nil && len(runOpts.Command) > 0 {
		// Use custom command
		ociSpec.Process.Args = runOpts.Command
	} else {
		// Use image default command
		processArgs := append(imgConfig.Config.Entrypoint, imgConfig.Config.Cmd...)
		if len(processArgs) > 0 {
			ociSpec.Process.Args = processArgs
		}
	}
	if imgConfig.Config.WorkingDir != "" {
		ociSpec.Process.Cwd = imgConfig.Config.WorkingDir
	}
	envMap := make(map[string]string)
	for _, e := range ociSpec.Process.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	for _, e := range imgConfig.Config.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	var cliEnvs []string
	if opts != nil {
		cliEnvs = opts.Envs
	} else if runOpts != nil {
		cliEnvs = runOpts.Envs
	}
	for _, e := range cliEnvs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	var finalEnv []string
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}
	ociSpec.Process.Env = finalEnv

	if ociSpec.Process.Capabilities == nil {
		ociSpec.Process.Capabilities = &spec.LinuxCapabilities{}
	}
	// Check for privileged mode
	var privileged bool
	if opts != nil && opts.Privileged {
		privileged = opts.Privileged
	} else if runOpts != nil && runOpts.Privileged {
		privileged = runOpts.Privileged
	}

	// Check for network namespace
	var netNamespace string
	if opts != nil && opts.NetNamespace != "" {
		netNamespace = opts.NetNamespace
	} else if runOpts != nil && runOpts.NetNamespace != "" {
		netNamespace = runOpts.NetNamespace
	} else {
		netNamespace = "host" // default
	}

	capsToAdd := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID"}
	if privileged {
		// Add all capabilities for privileged mode
		capsToAdd = append(capsToAdd, "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE",
			"CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO", "CAP_SYS_TIME",
			"CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE",
			"CAP_SYS_TTY_CONFIG", "CAP_FOWNER", "CAP_SYS_CHROOT")
	}

	existingCaps := make(map[string]bool)
	for _, cap := range ociSpec.Process.Capabilities.Permitted {
		existingCaps[cap] = true
	}
	for _, cap := range capsToAdd {
		if !existingCaps[cap] {
			ociSpec.Process.Capabilities.Bounding = append(ociSpec.Process.Capabilities.Bounding, cap)
			ociSpec.Process.Capabilities.Effective = append(ociSpec.Process.Capabilities.Effective, cap)
			ociSpec.Process.Capabilities.Permitted = append(ociSpec.Process.Capabilities.Permitted, cap)
		}
	}

	if ociSpec.Linux != nil {
		// Handle network namespace
		if netNamespace == "host" {
			// Remove network namespace to share with host
			var newNamespaces []spec.LinuxNamespace
			for _, ns := range ociSpec.Linux.Namespaces {
				if ns.Type != spec.NetworkNamespace {
					newNamespaces = append(newNamespaces, ns)
				}
			}
			ociSpec.Linux.Namespaces = newNamespaces
		}

		// Remove seccomp for privileged mode
		if privileged {
			ociSpec.Linux.Seccomp = &spec.LinuxSeccomp{
				DefaultAction: spec.ActAllow,
			}
			ociSpec.Process.NoNewPrivileges = false
			// Remove readonly paths to allow writing to /proc/sys for network configuration
			ociSpec.Linux.ReadonlyPaths = nil
			// Make /sys writable for privileged containers
			for i := range ociSpec.Mounts {
				if ociSpec.Mounts[i].Destination == "/sys" {
					for j, opt := range ociSpec.Mounts[i].Options {
						if opt == "ro" {
							ociSpec.Mounts[i].Options[j] = "rw"
							break
						}
					}
				}
			}
			// Allow all devices for full permissions
			ociSpec.Linux.Resources.Devices = []spec.LinuxDeviceCgroup{
				{
					Allow:  true,
					Access: "rwm",
				},
			}
		}
	}

	// Set noNewPrivileges
	ociSpec.Process.NoNewPrivileges = !privileged

	ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
		Destination: "/tmp", Type: "tmpfs", Source: "tmpfs",
		Options: []string{"nosuid", "strictatime", "mode=1777", "size=65536k"},
	})
	ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
		Destination: "/dev/shm", Type: "tmpfs", Source: "shm",
		Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
	})

	// Add cgroup mount for privileged containers to allow service management
	if privileged {
		ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"rw", "nosuid", "nodev", "noexec", "relatime"},
		})
	}
	if mergedConfig != nil && mergedConfig.Mounts != nil {
		for _, m := range mergedConfig.Mounts {
			mount := spec.Mount{Destination: m.Destination, Source: m.Source, Type: m.Type, Options: m.Options}
			ociSpec.Mounts = append(ociSpec.Mounts, mount)
		}
	}

	if runOpts != nil && len(runOpts.Volumes) > 0 {
		if err := ApplyVolumesToSpec(&ociSpec, runOpts.Volumes, cm.cfg); err != nil {
			return err
		}
	} else if opts != nil && len(opts.Volumes) > 0 {
		if err := ApplyVolumesToSpec(&ociSpec, opts.Volumes, cm.cfg); err != nil {
			return err
		}
	}

	ociSpec.Hostname = name

	ociSpec.Process.Terminal = (runOpts != nil && runOpts.TTY)

	// Add TTY devices only if explicitly requested via --tty flag
	var needsTTYDevices bool
	if opts != nil {
		needsTTYDevices = opts.TTY
	} else if runOpts != nil {
		needsTTYDevices = runOpts.TTY
	}

	LogDebug("needsTTYDevices = %v", needsTTYDevices)

	if needsTTYDevices {
		LogDebug("Setting up TTY devices")
		if ociSpec.Linux == nil {
			ociSpec.Linux = &spec.Linux{}
		}
		if ociSpec.Linux.Resources == nil {
			ociSpec.Linux.Resources = &spec.LinuxResources{}
		}
		if ociSpec.Linux.Resources.Devices == nil {
			ociSpec.Linux.Resources.Devices = []spec.LinuxDeviceCgroup{}
		}

		// Add common TTY devices that Alpine init tries to access
		ttyDevices := []string{"tty1", "tty2", "tty3", "tty4", "tty5", "tty6"}
		for _, tty := range ttyDevices {
			// Add cgroup device permission
			ociSpec.Linux.Resources.Devices = append(ociSpec.Linux.Resources.Devices, spec.LinuxDeviceCgroup{
				Allow:  true,
				Access: "rwm",
				Type:   "c",
				Major:  pointerToInt64(4),
				Minor:  pointerToInt64(getTTYMinor(tty)),
			})

			// Add the actual device node to the spec
			minor := getTTYMinor(tty)
			major := int64(4)
			fileMode := os.FileMode(0600)
			uid := uint32(0)
			gid := uint32(0)
			ociSpec.Linux.Devices = append(ociSpec.Linux.Devices, spec.LinuxDevice{
				Path:     "/dev/" + tty,
				Type:     "c",
				Major:    major,
				Minor:    minor,
				FileMode: &fileMode,
				UID:      &uid,
				GID:      &gid,
			})
		}

		// Add bind mounts for TTY devices from host
		for _, tty := range ttyDevices {
			hostDevice := "/dev/" + tty
			containerDevice := "/dev/" + tty
			if _, err := os.Stat(hostDevice); err == nil {
				// Device exists on host, add bind mount with more permissive options
				ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
					Destination: containerDevice,
					Source:      hostDevice,
					Type:        "bind",
					Options:     []string{"bind", "rw"},
				})
				LogDebug("Added bind mount for %s", hostDevice)
			} else {
				LogDebug("Host device %s not found, skipping bind mount", hostDevice)
			}
		}
	}

	// Apply resource limits
	if ociSpec.Linux == nil {
		ociSpec.Linux = &spec.Linux{}
	}

	var resources *spec.LinuxResources
	if ociSpec.Linux.Resources == nil {
		resources = &spec.LinuxResources{}
		ociSpec.Linux.Resources = resources
	} else {
		resources = ociSpec.Linux.Resources
	}

	// Get resource limits from merged config (already has proper priority applied)
	var cpuQuota, cpuPeriod, memoryLimit, memorySwap, cpuShares int64
	var blkioWeight uint16

	if mergedConfig != nil && mergedConfig.Resources != nil {
		cpuQuota = mergedConfig.Resources.CPUQuota
		cpuPeriod = mergedConfig.Resources.CPUPeriod
		memoryLimit = mergedConfig.Resources.MemoryLimit
		memorySwap = mergedConfig.Resources.MemorySwap
		cpuShares = mergedConfig.Resources.CPUShares
		blkioWeight = mergedConfig.Resources.BlkioWeight
	}

	// Apply CPU limits
	if cpuQuota > 0 || cpuPeriod > 0 {
		if resources.CPU == nil {
			resources.CPU = &spec.LinuxCPU{}
		}
		if cpuQuota > 0 {
			resources.CPU.Quota = &cpuQuota
		}
		if cpuPeriod > 0 {
			period := uint64(cpuPeriod)
			resources.CPU.Period = &period
		}
	}

	if cpuShares > 0 {
		if resources.CPU == nil {
			resources.CPU = &spec.LinuxCPU{}
		}
		shares := uint64(cpuShares)
		resources.CPU.Shares = &shares
	}

	// Apply memory limits
	if memoryLimit > 0 || memorySwap > 0 {
		if resources.Memory == nil {
			resources.Memory = &spec.LinuxMemory{}
		}
		if memoryLimit > 0 {
			resources.Memory.Limit = &memoryLimit
		}
		if memorySwap > 0 {
			resources.Memory.Swap = &memorySwap
		}
	}

	// Apply block IO weight
	if blkioWeight > 0 {
		if resources.BlockIO == nil {
			resources.BlockIO = &spec.LinuxBlockIO{}
		}
		resources.BlockIO.Weight = &blkioWeight
	}

	// Save the merged container config to the container directory
	containerConfigPath := filepath.Join(filepath.Dir(configPath), "container_config.json")
	if mergedConfigData, err := json.MarshalIndent(mergedConfig, "", "  "); err == nil {
		os.WriteFile(containerConfigPath, mergedConfigData, 0644)
	}

	modifiedData, err := json.MarshalIndent(ociSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal modified config: %w", err)
	}
	return os.WriteFile(configPath, modifiedData, 0644)
}
