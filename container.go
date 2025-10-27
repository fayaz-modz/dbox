package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

type ContainerManager struct {
	cfg     *Config
	runtime *Runtime
	imgMgr  *ImageManager
}

func (cm *ContainerManager) Attach(name string) error {
	return cm.runtime.Exec(name, []string{"/bin/sh"})
}

type CreateOptions struct {
	Image           string
	Name            string
	ContainerConfig string
	SetupScript     string
	PostSetupScript string
	Envs            []string
	NoOverlayFS     bool
	CPUQuota        int64
	CPUPeriod       int64
	MemoryLimit     int64
	MemorySwap      int64
	CPUShares       int64
	BlkioWeight     uint16
	InitProcess     string
	Privileged      bool
	NetNamespace    string
}

type RunOptions struct {
	Image           string
	Name            string
	ContainerConfig string
	Envs            []string
	Detach          bool
	AutoRemove      bool
	Volumes         []string
	NoOverlayFS     bool
	CPUQuota        int64
	CPUPeriod       int64
	MemoryLimit     int64
	MemorySwap      int64
	CPUShares       int64
	BlkioWeight     uint16
	InitProcess     string
	Privileged      bool
	NetNamespace    string
}

func NewContainerManager(cfg *Config) *ContainerManager {
	return &ContainerManager{
		cfg:     cfg,
		runtime: NewRuntime(cfg),
		imgMgr:  NewImageManager(cfg),
	}
}

func (cm *ContainerManager) Run(opts *RunOptions) error {
	if opts.Name == "" {
		randomName, err := generateRandomName()
		if err != nil {
			return fmt.Errorf("failed to generate random name: %w", err)
		}
		opts.Name = randomName
		fmt.Printf("Assigning random name: %s\n", opts.Name)
	}

	containerPath := filepath.Join(cm.cfg.ContainersPath, opts.Name)

	if _, err := os.Stat(containerPath); !os.IsNotExist(err) {
		return fmt.Errorf("container with name '%s' already exists", opts.Name)
	}

	if err := os.MkdirAll(containerPath, 0755); err != nil {
		return fmt.Errorf("failed to create container directory: %w", err)
	}

	rootfsSource, err := cm.imgMgr.GetRootfs(opts.Image)
	if err != nil {
		if err := cm.imgMgr.Pull(opts.Image); err != nil {
			return fmt.Errorf("failed to pull image: %w", err)
		}
		rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
		if err != nil {
			return err
		}
	}
	imagePath := filepath.Dir(rootfsSource)
	bundlePath := containerPath
	var rootPathForSpec string

	if opts.NoOverlayFS {
		fmt.Println("OverlayFS disabled. Copying rootfs...")
		rootfsDest := filepath.Join(bundlePath, "rootfs")
		if err := os.MkdirAll(rootfsDest, 0755); err != nil {
			return fmt.Errorf("failed to create rootfs directory: %w", err)
		}
		if err := copyDirWithProgress(rootfsSource, rootfsDest); err != nil {
			return fmt.Errorf("failed to copy rootfs: %w", err)
		}
		rootPathForSpec = "rootfs"
	} else {
		fmt.Println("Setting up OverlayFS mount...")
		_, err := cm.mountOverlayFS(containerPath, rootfsSource)
		if err != nil {
			os.RemoveAll(containerPath)
			return fmt.Errorf("failed to prepare container filesystem: %w", err)
		}
		rootPathForSpec = "merged"
	}

	if opts.AutoRemove && !opts.Detach {
		defer func() {
			fmt.Printf("\nAuto-removing container %s...\n", opts.Name)
			// Ensure we stop it before deleting, just in case.
			cm.runtime.Stop(opts.Name, true)
			cm.Delete(opts.Name, true)
		}()
	}

	containerCfg, err := LoadContainerConfig(opts.ContainerConfig)
	if err != nil {
		return err
	}

	createOpts := &CreateOptions{Image: opts.Image, Name: opts.Name, Envs: opts.Envs}

	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, opts.Name, createOpts, opts, containerCfg, rootPathForSpec); err != nil {
		if !opts.NoOverlayFS {
			cm.unmountOverlayFS(containerPath)
		}
		os.RemoveAll(containerPath)
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	var logPath string
	var logger *DboxLogger
	if opts.Detach {
		logDir := filepath.Join(cm.cfg.RunPath, "logs")
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		logPath = filepath.Join(logDir, opts.Name+".log")
		logger = NewDboxLogger(logPath)
		defer logger.Close()

		logger.Log(fmt.Sprintf("Running container '%s' from image '%s'", opts.Name, opts.Image))
	}

	err = cm.runtime.Run(opts.Name, bundlePath, opts.Detach, logPath)
	if err != nil && logger != nil {
		logger.Log(fmt.Sprintf("Failed to run container '%s': %v", opts.Name, err))
	} else if logger != nil {
		logger.Log(fmt.Sprintf("Successfully started container '%s'", opts.Name))
	}
	if err != nil {
		// Since the run failed, we should clean up the assets we just created.
		// We use the robust Delete function for this.
		fmt.Printf("Run command failed. Forcing cleanup of container '%s'...\n", opts.Name)
		cm.Delete(opts.Name, true)
		return err
	}

	if opts.Detach {
		fmt.Println(opts.Name)
	}

	return nil
}

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
		capsToAdd = append(capsToAdd, "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
			"CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO", "CAP_SYS_TIME",
			"CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE")
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
			ociSpec.Linux.Seccomp = nil
		}
	}
	ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
		Destination: "/tmp", Type: "tmpfs", Source: "tmpfs",
		Options: []string{"nosuid", "strictatime", "mode=1777", "size=65536k"},
	})
	ociSpec.Mounts = append(ociSpec.Mounts, spec.Mount{
		Destination: "/dev/shm", Type: "tmpfs", Source: "shm",
		Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
	})
	if containerCfg != nil {
		for _, m := range containerCfg.Mounts {
			mount := spec.Mount{Destination: m.Destination, Source: m.Source, Type: m.Type, Options: m.Options}
			ociSpec.Mounts = append(ociSpec.Mounts, mount)
		}
	}

	if runOpts != nil {
		for _, vol := range runOpts.Volumes {
			parts := strings.SplitN(vol, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid volume format: %s. Must be host-path:container-path", vol)
			}
			hostPath, containerPath := parts[0], parts[1]
			mount := spec.Mount{
				Destination: containerPath, Source: hostPath, Type: "bind",
				Options: []string{"bind", "rw"},
			}
			ociSpec.Mounts = append(ociSpec.Mounts, mount)
		}
	}

	ociSpec.Hostname = name

	ociSpec.Process.Terminal = (runOpts != nil)

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

	// Get resource limits from options
	var cpuQuota, cpuPeriod, memoryLimit, memorySwap, cpuShares int64
	var blkioWeight uint16

	if opts != nil {
		cpuQuota = opts.CPUQuota
		cpuPeriod = opts.CPUPeriod
		memoryLimit = opts.MemoryLimit
		memorySwap = opts.MemorySwap
		cpuShares = opts.CPUShares
		blkioWeight = opts.BlkioWeight
	} else if runOpts != nil {
		cpuQuota = runOpts.CPUQuota
		cpuPeriod = runOpts.CPUPeriod
		memoryLimit = runOpts.MemoryLimit
		memorySwap = runOpts.MemorySwap
		cpuShares = runOpts.CPUShares
		blkioWeight = runOpts.BlkioWeight
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

	modifiedData, err := json.MarshalIndent(ociSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal modified config: %w", err)
	}
	return os.WriteFile(configPath, modifiedData, 0644)
}

func (cm *ContainerManager) Delete(name string, force bool) error {
	logPath := filepath.Join(cm.cfg.RunPath, "logs", name+".log")
	logger := NewDboxLogger(logPath)
	defer logger.Close()

	logger.Log(fmt.Sprintf("Deleting container '%s' (force=%v)", name, force))

	state, err := cm.runtime.State(name)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			fmt.Printf("Container '%s' not found in runtime. Proceeding with filesystem cleanup.\n", name)
		} else {
			return fmt.Errorf("could not determine state of container '%s': %w", name, err)
		}
	} else {
		switch state {
		case "running", "creating", "paused":
			if !force {
				return fmt.Errorf("cannot remove container '%s': container is %s. Stop the container before deletion or use --force", name, state)
			}
			fmt.Printf("Container '%s' is %s, stopping it due to --force flag...\n", name, state)
			if err := cm.runtime.Stop(name, true); err != nil {
				return fmt.Errorf("failed to stop container '%s' for forced deletion: %w", name, err)
			}
			if err := cm.runtime.Delete(name, false); err != nil {
				fmt.Printf("Warning: runtime delete command failed after stopping: %v. Proceeding with manual cleanup.\n", err)
			}

		case "stopped", "created":
			if err := cm.runtime.Delete(name, force); err != nil {
				fmt.Printf("Warning: runtime delete command failed: %v. Proceeding with manual cleanup.\n", err)
			}

		default:
			return fmt.Errorf("container '%s' is in an unknown state: '%s'. Cannot determine safe deletion path", name, state)
		}
	}

	if err := cm.cleanupContainerFiles(name); err != nil {
		return fmt.Errorf("failed to cleanup container files: %w", err)
	}

	fmt.Printf("Successfully deleted all assets for container '%s'.\n", name)
	logger.Log(fmt.Sprintf("Successfully deleted container '%s'", name))
	return nil
}

func (cm *ContainerManager) cleanupContainerFiles(name string) error {
	var cleanupErrors []string

	// Cleanup container directory
	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	if _, statErr := os.Stat(containerPath); !os.IsNotExist(statErr) {
		mergedPath := filepath.Join(containerPath, "merged")
		if _, statErr := os.Stat(mergedPath); statErr == nil {
			if err := cm.unmountOverlayFS(containerPath); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Sprintf("failed to unmount overlayfs: %v", err))
			}
		}

		// Complete cleanup
		if err := os.RemoveAll(containerPath); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("failed to remove container directory: %v", err))
		}
	}

	// Cleanup runtime state directory
	runtimeStatePath := filepath.Join(cm.cfg.RunPath, name)
	if _, statErr := os.Stat(runtimeStatePath); !os.IsNotExist(statErr) {
		if err := os.RemoveAll(runtimeStatePath); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("failed to remove runtime state directory: %v", err))
		}
	}

	// Cleanup log file
	logPath := filepath.Join(cm.cfg.RunPath, "logs", name+".log")
	if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
		cleanupErrors = append(cleanupErrors, fmt.Sprintf("failed to remove log file: %v", err))
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("cleanup warnings: %s", strings.Join(cleanupErrors, "; "))
	}

	return nil
}

func (cm *ContainerManager) unmountOverlayFS(containerPath string) error {
	mergedPath := filepath.Join(containerPath, "merged")

	// Check if path exists
	if _, err := os.Stat(mergedPath); os.IsNotExist(err) {
		return nil // Nothing to unmount
	}

	// Try lazy unmount first for busy filesystems
	cmd := exec.Command("umount", "-l", mergedPath)
	output, err := cmd.CombinedOutput()

	if err == nil {
		fmt.Printf("Info: successfully unmounted %s\n", mergedPath)
		return nil
	}

	// If lazy unmount fails, try regular unmount
	if strings.Contains(string(output), "not mounted") {
		fmt.Printf("Info: %s was already unmounted.\n", mergedPath)
		return nil
	}

	cmd = exec.Command("umount", mergedPath)
	output, err = cmd.CombinedOutput()

	if err == nil {
		fmt.Printf("Info: successfully unmounted %s\n", mergedPath)
		return nil
	}

	if strings.Contains(string(output), "not mounted") {
		fmt.Printf("Info: %s was already unmounted.\n", mergedPath)
		return nil
	}

	return fmt.Errorf("failed to unmount %s: %s (%w)", mergedPath, string(output), err)
}

func generateRandomName() (string, error) {
	adjectives := []string{"happy", "silly", "busy", "clever", "brave", "shiny", "witty"}
	nouns := []string{"gopher", "ferret", "panda", "whale", "badger", "rocket", "wizard"}
	adjIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	if err != nil {
		return "", err
	}
	nounIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%s", adjectives[adjIndex.Int64()], nouns[nounIndex.Int64()]), nil
}

func (cm *ContainerManager) Create(opts *CreateOptions) error {
	fmt.Printf("Creating container '%s' from image '%s'...\n", opts.Name, opts.Image)
	containerPath := filepath.Join(cm.cfg.ContainersPath, opts.Name)
	if _, err := os.Stat(containerPath); !os.IsNotExist(err) {
		return fmt.Errorf("container '%s' already exists", opts.Name)
	}
	if err := os.MkdirAll(containerPath, 0755); err != nil {
		return fmt.Errorf("failed to create container directory: %w", err)
	}
	rootfsSource, err := cm.imgMgr.GetRootfs(opts.Image)
	if err != nil {
		fmt.Printf("Image not found locally, pulling automatically...\n")
		if err := cm.imgMgr.Pull(opts.Image); err != nil {
			return fmt.Errorf("failed to pull image: %w", err)
		}
		rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("Using cached image...")
	}
	imagePath := filepath.Dir(rootfsSource)
	bundlePath := containerPath
	var rootPathForSpec string
	if opts.NoOverlayFS {
		fmt.Println("OverlayFS disabled. Copying rootfs...")
		rootfsDest := filepath.Join(bundlePath, "rootfs")
		if err := os.MkdirAll(rootfsDest, 0755); err != nil {
			return fmt.Errorf("failed to create rootfs directory: %w", err)
		}
		if err := copyDirWithProgress(rootfsSource, rootfsDest); err != nil {
			return fmt.Errorf("failed to copy rootfs: %w", err)
		}
		rootPathForSpec = "rootfs"
	} else {
		fmt.Println("Setting up OverlayFS mount...")
		_, err := cm.mountOverlayFS(containerPath, rootfsSource)
		if err != nil {
			os.RemoveAll(containerPath)
			return fmt.Errorf("failed to prepare container filesystem: %w", err)
		}
		rootPathForSpec = "merged"
	}
	containerCfg, err := LoadContainerConfig(opts.ContainerConfig)
	if err != nil {
		return err
	}
	fmt.Println("Generating OCI config...")
	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, opts.Name, opts, nil, containerCfg, rootPathForSpec); err != nil {
		if !opts.NoOverlayFS {
			cm.unmountOverlayFS(containerPath)
		}
		os.RemoveAll(containerPath)
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}
	metadata := map[string]string{"name": opts.Name, "image": opts.Image}
	metadataPath := filepath.Join(containerPath, "metadata.json")
	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataPath, metadataData, 0644)
	fmt.Println("Creating OCI container...")
	if err := cm.runtime.Create(opts.Name, bundlePath); err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	fmt.Printf("Container '%s' created successfully!\n", opts.Name)
	return nil
}

func (cm *ContainerManager) List() error {
	entries, err := os.ReadDir(cm.cfg.ContainersPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No containers found.")
			return nil
		}
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No containers found.")
		return nil
	}

	// Print header with proper column formatting
	fmt.Printf("%-20s %-15s %-10s %s\n", "CONTAINER_NAME", "IMAGE", "STATUS", "CREATED")
	fmt.Printf("%-20s %-15s %-10s %s\n", strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 10), strings.Repeat("-", 19))

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			containerName := entry.Name()
			metadataPath := filepath.Join(cm.cfg.ContainersPath, containerName, "metadata.json")

			// Get container info
			info, err := entry.Info()
			var createdTime string
			if err == nil {
				createdTime = info.ModTime().Format("2006-01-02")
			} else {
				createdTime = "unknown"
			}

			// Get metadata
			var imageName string
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata map[string]string
				if json.Unmarshal(data, &metadata) == nil {
					imageName = metadata["image"]
					if imageName == "" {
						imageName = "unknown"
					}
				} else {
					imageName = "unknown"
				}
			} else {
				imageName = "unknown"
			}

			// Get container status
			status := "unknown"
			if state, err := cm.runtime.State(containerName); err == nil {
				status = strings.ToUpper(state)
			} else {
				// Check if container directory exists but runtime doesn't know about it
				if _, err := os.Stat(filepath.Join(cm.cfg.ContainersPath, containerName)); err == nil {
					status = "STOPPED"
				}
			}

			fmt.Printf("%-20s %-15s %-10s %s\n", containerName, imageName, status, createdTime)
		}
	}
	return nil
}

func (cm *ContainerManager) Start(name string) error {
	logDir := filepath.Join(cm.cfg.RunPath, "logs")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, name+".log")

	// Reset log file for fresh start
	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to reset log file: %w", err)
	}

	logger := NewDboxLogger(logPath)
	defer logger.Close()

	logger.Log(fmt.Sprintf("Starting container '%s'", name))
	fmt.Printf("Starting container '%s' in background...\n", name)
	fmt.Printf("Logs will be available at: %s\n", logPath)

	err := cm.runtime.Start(name, logPath)
	if err != nil {
		logger.Log(fmt.Sprintf("Failed to start container '%s': %v", name, err))
	} else {
		logger.Log(fmt.Sprintf("Successfully started container '%s'", name))
	}

	return err
}

func (cm *ContainerManager) Stop(name string, force bool) error {
	logPath := filepath.Join(cm.cfg.RunPath, "logs", name+".log")
	logger := NewDboxLogger(logPath)
	defer logger.Close()

	logger.Log(fmt.Sprintf("Stopping container '%s' (force=%v)", name, force))
	err := cm.runtime.Stop(name, force)
	if err != nil {
		logger.Log(fmt.Sprintf("Failed to stop container '%s': %v", name, err))
	} else {
		logger.Log(fmt.Sprintf("Successfully stopped container '%s'", name))
	}

	return err
}

func (cm *ContainerManager) Recreate(name string) error {
	fmt.Printf("Recreating container '%s'...\n", name)

	// Get container path
	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	if _, err := os.Stat(containerPath); os.IsNotExist(err) {
		return fmt.Errorf("container '%s' does not exist", name)
	}

	// Read metadata to get image info
	metadataPath := filepath.Join(containerPath, "metadata.json")
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read container metadata: %w", err)
	}

	var metadata map[string]string
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return fmt.Errorf("failed to parse container metadata: %w", err)
	}

	imageName := metadata["image"]
	if imageName == "" {
		return fmt.Errorf("container metadata does not contain image information")
	}

	// Stop the container if it's running
	state, err := cm.runtime.State(name)
	if err == nil && (state == "running" || state == "creating" || state == "paused") {
		fmt.Printf("Stopping container '%s'...\n", name)
		if err := cm.runtime.Stop(name, true); err != nil {
			fmt.Printf("Warning: failed to stop container: %v\n", err)
		}
	}

	// Read and cache original config.json BEFORE unmounting
	originalConfigPath := filepath.Join(containerPath, "config.json")
	originalConfigData, err := os.ReadFile(originalConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read original config: %w", err)
	}

	var originalSpec spec.Spec
	if err := json.Unmarshal(originalConfigData, &originalSpec); err != nil {
		return fmt.Errorf("failed to parse original config: %w", err)
	}

	// Delete from runtime (but keep filesystem)
	if err := cm.runtime.Delete(name, true); err != nil {
		fmt.Printf("Warning: failed to delete from runtime: %v\n", err)
	}

	// Unmount overlayfs if mounted
	mergedPath := filepath.Join(containerPath, "merged")
	if _, err := os.Stat(mergedPath); err == nil {
		if err := cm.unmountOverlayFS(containerPath); err != nil {
			fmt.Printf("Warning: failed to unmount overlayfs: %v\n", err)
		}
	}

	// Get rootfs source
	rootfsSource, err := cm.imgMgr.GetRootfs(imageName)
	if err != nil {
		return fmt.Errorf("failed to get rootfs for image '%s': %w", imageName, err)
	}

	// Remount overlayfs
	fmt.Println("Remounting OverlayFS...")
	_, err = cm.mountOverlayFS(containerPath, rootfsSource)
	if err != nil {
		return fmt.Errorf("failed to remount overlayfs: %w", err)
	}

	// Load container config (if any)
	containerCfg, cfgErr := LoadContainerConfig("")
	if cfgErr != nil {
		return fmt.Errorf("failed to load container config: %w", cfgErr)
	}

	// Regenerate OCI spec
	bundlePath := containerPath
	imagePath := filepath.Dir(rootfsSource)
	rootPathForSpec := "merged"

	// Remove existing config.json to allow regeneration
	if _, err := os.Stat(originalConfigPath); err == nil {
		fmt.Printf("Removing existing config.json...\n")
		if err := os.Remove(originalConfigPath); err != nil {
			return fmt.Errorf("failed to remove existing config.json: %w", err)
		}
	}

	// Create options that preserve original settings
	createOpts := &CreateOptions{
		Name:       name,
		Image:      imageName,
		Privileged: false, // Will be determined from original config
	}

	// Check if original was privileged by looking at capabilities
	if originalSpec.Process != nil && originalSpec.Process.Capabilities != nil {
		privilegedCaps := []string{
			"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
			"CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO",
			"CAP_SYS_TIME", "CAP_AUDIT_CONTROL", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE",
		}

		hasPrivilegedCaps := false
		for _, privCap := range privilegedCaps {
			for _, cap := range originalSpec.Process.Capabilities.Permitted {
				if cap == privCap {
					hasPrivilegedCaps = true
					break
				}
			}
			if hasPrivilegedCaps {
				break
			}
		}
		createOpts.Privileged = hasPrivilegedCaps
	}

	// Check network namespace (host if no network namespace)
	if originalSpec.Linux != nil {
		hasNetworkNS := false
		for _, ns := range originalSpec.Linux.Namespaces {
			if ns.Type == spec.NetworkNamespace {
				hasNetworkNS = true
				break
			}
		}
		if !hasNetworkNS {
			createOpts.NetNamespace = "host"
		}
	}

	// Preserve init process if it was custom
	if originalSpec.Process != nil && len(originalSpec.Process.Args) > 0 {
		if originalSpec.Process.Args[0] != "/bin/sh" && originalSpec.Process.Args[0] != "/bin/bash" {
			createOpts.InitProcess = originalSpec.Process.Args[0]
		}
	}

	fmt.Println("Regenerating OCI config...")
	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, name, createOpts, nil, containerCfg, rootPathForSpec); err != nil {
		return fmt.Errorf("failed to regenerate OCI spec: %w", err)
	}

	// Recreate in runtime
	fmt.Println("Recreating OCI container...")
	if err := cm.runtime.Create(name, bundlePath); err != nil {
		return fmt.Errorf("failed to recreate container: %w", err)
	}

	fmt.Printf("Container '%s' recreated successfully!\n", name)
	return nil
}

func (cm *ContainerManager) Exec(name string, command []string) error {
	return cm.runtime.Exec(name, command)
}

func (cm *ContainerManager) RunSetupScript(name, scriptPath string) error {
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read setup script: %w", err)
	}
	containerPath := filepath.Join(cm.cfg.ContainersPath, name, "bundle", "rootfs", "tmp", "setup.sh")
	if err := os.WriteFile(containerPath, script, 0755); err != nil {
		return fmt.Errorf("failed to write script to container: %w", err)
	}
	return cm.runtime.Exec(name, []string{"/bin/sh", "/tmp/setup.sh"})
}

func (cm *ContainerManager) mountOverlayFS(containerPath, rootfsSource string) (string, error) {
	upperPath := filepath.Join(containerPath, "upper")
	workPath := filepath.Join(containerPath, "work")
	mergedPath := filepath.Join(containerPath, "merged")

	// Create overlay directories
	for _, p := range []string{upperPath, workPath, mergedPath} {
		if err := os.MkdirAll(p, 0755); err != nil {
			return "", fmt.Errorf("failed to create overlay directory %s: %w", p, err)
		}
	}

	// Verify source exists
	if _, err := os.Stat(rootfsSource); os.IsNotExist(err) {
		return "", fmt.Errorf("rootfs source does not exist: %s", rootfsSource)
	}

	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", rootfsSource, upperPath, workPath)
	cmd := exec.Command("mount", "-t", "overlay", "overlay", "-o", options, mergedPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to mount overlayfs: %s\n%v", string(output), err)
	}

	return mergedPath, nil
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func copyDirWithProgress(src, dst string) error {
	totalSize, err := getDirSize(src)
	if err != nil {
		return fmt.Errorf("could not calculate source size: %w", err)
	}

	var copiedBytes int64
	stopProgress := make(chan bool)
	progressDone := make(chan bool)

	// Progress reporter goroutine
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stopProgress:
				printCopyProgress(totalSize, totalSize)
				fmt.Println()
				return
			case <-ticker.C:
				currentBytes := atomic.LoadInt64(&copiedBytes)
				printCopyProgress(currentBytes, totalSize)
			}
		}
	}()

	// Copy files
	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		}
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}
		err = copyFile(path, targetPath, info.Mode())
		if err == nil {
			atomic.AddInt64(&copiedBytes, info.Size())
		}
		return err
	})

	// Stop progress reporter
	close(stopProgress)
	<-progressDone // Wait for progress goroutine to finish

	return err
}

func printCopyProgress(current, total int64) {
	if total <= 0 {
		return
	}
	percentage := float64(current) / float64(total) * 100
	barWidth := 30
	completedWidth := int(float64(barWidth) * float64(current) / float64(total))
	bar := strings.Repeat("█", completedWidth) + strings.Repeat("░", barWidth-completedWidth)
	fmt.Printf("\r  Copying... [%s] %.1f%% (%s / %s)", bar, percentage, formatBytes(uint64(current)), formatBytes(uint64(total)))
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	_, err = io.Copy(dstFile, srcFile)
	return err
}
