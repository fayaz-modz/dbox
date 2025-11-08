package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	. "dbox/config"
	. "dbox/logger"

	spec "github.com/opencontainers/runtime-spec/specs-go"
)

func (cm *ContainerManager) CreateContainer(opts *CreateOptions, logger *DboxLogger) error {
	containerPath := filepath.Join(cm.cfg.ContainersPath, opts.Name)
	if _, err := os.Stat(containerPath); !os.IsNotExist(err) {
		return fmt.Errorf("container '%s' already exists", opts.Name)
	}
	if err := os.MkdirAll(containerPath, 0755); err != nil {
		return fmt.Errorf("failed to create container directory: %w", err)
	}

	// Initialize container metadata with CREATING status
	metadata := map[string]string{
		"image":  opts.Image,
		"status": StatusCreating,
	}
	metadataPath := filepath.Join(containerPath, "metadata.json")
	if data, err := json.MarshalIndent(metadata, "", "  "); err == nil {
		os.WriteFile(metadataPath, data, 0644)
	}

	// Track cleanup state
	overlayMounted := false
	containerCreated := true

	// Cleanup function for failures
	cleanup := func() {
		if overlayMounted && !opts.NoOverlayFS {
			cm.unmountOverlayFS(containerPath)
		}
		if containerCreated {
			os.RemoveAll(containerPath)
		}
	}

	// Defer cleanup - will only run if we return with error
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r) // Re-panic after cleanup
		}
	}()

	LogVerbose("Checking for local image...")
	rootfsSource, err := cm.imgMgr.GetRootfs(opts.Image)
	if err != nil {
		LogVerbose("Image not found locally, pulling automatically...")
		logger.Log("Image not found locally, pulling automatically...")
		if err := cm.imgMgr.Pull(opts.Image, logger.LogFile); err != nil {
			logger.Log(fmt.Sprintf("Failed to pull image: %v", err))
			cleanup()
			return fmt.Errorf("failed to pull image: %w", err)
		}
		logger.Log("Image pulled successfully")
		rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
		if err != nil {
			cleanup()
			return err
		}
	} else {
		LogVerbose("Using cached image...")
		logger.Log("Using cached image")
	}
	imagePath := filepath.Dir(rootfsSource)
	bundlePath := containerPath
	var rootPathForSpec string
	if opts.NoOverlayFS {
		LogVerbose("OverlayFS disabled. Copying rootfs...")
		rootfsDest := filepath.Join(bundlePath, "rootfs")
		if err := os.MkdirAll(rootfsDest, 0755); err != nil {
			cleanup()
			return fmt.Errorf("failed to create rootfs directory: %w", err)
		}
		if err := copyDirWithProgress(rootfsSource, rootfsDest); err != nil {
			cleanup()
			return fmt.Errorf("failed to copy rootfs: %w", err)
		}
		rootPathForSpec = "rootfs"
	} else {
		logger.Log("Setting up OverlayFS mount...")
		_, err := cm.mountOverlayFS(containerPath, rootfsSource)
		if err != nil {
			cleanup()
			return fmt.Errorf("failed to prepare container filesystem: %w", err)
		}
		overlayMounted = true
		rootPathForSpec = "merged"
	}
	containerCfg, err := LoadContainerConfig(opts.ContainerConfig)
	if err != nil {
		cleanup()
		return err
	}
	LogVerbose("Generating OCI config...")
	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, opts.Name, opts, nil, containerCfg, rootPathForSpec); err != nil {
		cleanup()
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	// Store the creation options for later use by start/recreate
	optionsPath := filepath.Join(containerPath, "options.json")
	optionsData, err := json.MarshalIndent(opts, "", "  ")
	if err != nil {
		cleanup()
		return fmt.Errorf("failed to marshal options: %w", err)
	}
	if err := os.WriteFile(optionsPath, optionsData, 0644); err != nil {
		cleanup()
		return fmt.Errorf("failed to write options file: %w", err)
	}

	// Update status to READY after successful creation
	cm.updateContainerStatus(opts.Name, StatusReady)

	// Success - don't run cleanup
	containerCreated = false
	overlayMounted = false

	if logger != nil {
		logger.Log(fmt.Sprintf("Successfully created container '%s'", opts.Name))
	} else {
		LogInfo("Container '%s' created successfully!", opts.Name)
	}
	return nil
}

// createOptionsFromExisting attempts to recreate CreateOptions from existing container metadata and config
func (cm *ContainerManager) createOptionsFromExisting(containerPath string, opts *CreateOptions) error {
	// Read metadata
	metadataPath := filepath.Join(containerPath, "metadata.json")
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata map[string]string
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	opts.Name = metadata["name"]
	opts.Image = metadata["image"]

	// Read config.json to extract some options
	configPath := filepath.Join(containerPath, "config.json")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var ociSpec spec.Spec
	if err := json.Unmarshal(configData, &ociSpec); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Try to detect privileged mode
	if ociSpec.Process != nil && ociSpec.Process.Capabilities != nil {
		privilegedCaps := []string{
			"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
			"CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO",
			"CAP_SYS_TIME", "CAP_AUDIT_CONTROL", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE",
		}
		for _, cap := range ociSpec.Process.Capabilities.Permitted {
			if slices.Contains(privilegedCaps, cap) {
				opts.Privileged = true
				break
			}
		}
	}

	// Try to detect network namespace
	if ociSpec.Linux != nil {
		hasNetworkNS := false
		for _, ns := range ociSpec.Linux.Namespaces {
			if ns.Type == spec.NetworkNamespace {
				hasNetworkNS = true
				break
			}
		}
		if !hasNetworkNS {
			opts.NetNamespace = "host"
		}
	}

	// Try to detect init process
	if ociSpec.Process != nil && len(ociSpec.Process.Args) > 0 {
		if ociSpec.Process.Args[0] != "/bin/sh" && ociSpec.Process.Args[0] != "/bin/bash" {
			opts.InitProcess = ociSpec.Process.Args[0]
		}
	}

	// Try to detect TTY
	if ociSpec.Process != nil {
		opts.TTY = ociSpec.Process.Terminal
	}

	// Detect OverlayFS vs copy
	rootfsPath := filepath.Join(containerPath, "rootfs")
	if _, err := os.Stat(rootfsPath); err == nil {
		opts.NoOverlayFS = true
	} else {
		opts.NoOverlayFS = false
	}

	// Set defaults for other options
	opts.CPUQuota = 0
	opts.CPUPeriod = 0
	opts.MemoryLimit = 0
	opts.MemorySwap = 0
	opts.CPUShares = 0
	opts.BlkioWeight = 0
	opts.Envs = []string{}
	opts.ContainerConfig = ""

	return nil
}

func (cm *ContainerManager) Start(name string, detach bool) error {
	logDir := filepath.Join(cm.cfg.RunPath, "logs")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, name+".log")

	// Check if container is already running
	if state, err := cm.runtime.State(name); err == nil && state == "running" {
		fmt.Printf("Container '%s' is already running\n", name)
		return fmt.Errorf("container '%s' is already running", name)
	}

	// Check if container exists in filesystem
	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	if _, err := os.Stat(containerPath); os.IsNotExist(err) {
		return fmt.Errorf("container '%s' does not exist", name)
	}

	// Load stored options
	optionsPath := filepath.Join(containerPath, "options.json")
	optionsData, err := os.ReadFile(optionsPath)
	var opts CreateOptions
	if err != nil {
		// Backward compatibility: if options.json doesn't exist, try to create it from metadata
		if err := cm.createOptionsFromExisting(containerPath, &opts); err != nil {
			return fmt.Errorf("failed to read container options and backward compatibility failed: %w", err)
		}
		// Save the created options for future use
		if optionsData, err := json.MarshalIndent(&opts, "", "  "); err == nil {
			os.WriteFile(optionsPath, optionsData, 0644)
		}
	} else {
		if err := json.Unmarshal(optionsData, &opts); err != nil {
			return fmt.Errorf("failed to parse container options: %w", err)
		}
	}

	// Reset log file for fresh start (only when actually starting)
	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to reset log file: %w", err)
	}

	logger := NewDboxLogger(logPath)
	defer logger.Close()

	logger.Log(fmt.Sprintf("Starting container '%s'", name))

	if detach {
		fmt.Printf("Starting container '%s' in background...\n", name)
		fmt.Printf("Logs will be available at: %s\n", logPath)
	} else {
		fmt.Printf("Starting container '%s' in foreground...\n", name)
	}

	// Check and remount overlayfs if needed (only if container uses overlayfs)
	if !opts.NoOverlayFS {
		if !cm.isOverlayFSMounted(containerPath) {
			logger.Log(fmt.Sprintf("OverlayFS not mounted for '%s', attempting to remount", name))

			// Get rootfs source from image
			rootfsSource, err := cm.imgMgr.GetRootfs(opts.Image)
			if err != nil {
				return fmt.Errorf("failed to get rootfs for overlayfs remount: %w", err)
			}

			// Remount overlayfs
			_, err = cm.mountOverlayFS(containerPath, rootfsSource)
			if err != nil {
				return fmt.Errorf("failed to remount overlayfs: %w", err)
			}
			logger.Log(fmt.Sprintf("Successfully remounted OverlayFS for '%s'", name))
		} else {
			logger.Log(fmt.Sprintf("OverlayFS already mounted for '%s'", name))
		}
	}

	// Clean up any existing runtime state (ignore errors)
	logger.Log(fmt.Sprintf("Attempting to clean up any existing runtime state for '%s'", name))
	cm.runtime.Delete(name, true) // Ignore error

	// Update status to RUNNING when starting
	cm.updateContainerStatus(name, StatusRunning)

	// Use Run method which uses runc run
	err = cm.runtime.Run(name, containerPath, detach, logPath)
	if err != nil {
		// Update status back to READY if start failed
		cm.updateContainerStatus(name, StatusReady)
		logger.Log(fmt.Sprintf("Failed to start container '%s': %v", name, err))
		return err
	}

	logger.Log(fmt.Sprintf("Successfully started container '%s'", name))
	return nil
}

func (cm *ContainerManager) Stop(name string, force bool) error {
	LogInfo("Stopping container '%s' (force=%v)", name, force)
	logPath := filepath.Join(cm.cfg.RunPath, "logs", name+".log")
	logger := NewDboxLogger(logPath)
	defer logger.Close()

	// Check container status to handle different scenarios
	status, err := cm.getContainerStatus(name)
	if err == nil && status == StatusCreating {
		// Container is still being created - stop the creation process
		logger.Log(fmt.Sprintf("Container '%s' is being created, stopping creation process", name))
		return cm.stopContainerCreation(name, logger)
	}

	// Check if container is already stopped
	if state, err := cm.runtime.State(name); err == nil && state == "stopped" && !force {
		fmt.Printf("Container '%s' is already stopped\n", name)
		return fmt.Errorf("container '%s' is already stopped", name)
	}

	logger.Log(fmt.Sprintf("Stopping container '%s' (force=%v)", name, force))
	err = cm.runtime.Stop(name, force)
	if err != nil {
		logger.Log(fmt.Sprintf("Failed to stop container '%s': %v", name, err))
		LogDebug("Failed to stop container '%s': %v", name, err)
	} else {
		// Update status to STOPPED after successful stop
		cm.updateContainerStatus(name, StatusStopped)
		logger.Log(fmt.Sprintf("Successfully stopped container '%s'", name))
		LogDebug("Successfully stopped container '%s'", name)
	}

	// Unmount OverlayFS if it exists (ignore errors for containers without overlayfs)
	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	mergedPath := filepath.Join(containerPath, "merged")
	if _, err := os.Stat(mergedPath); err == nil {
		if unmountErr := cm.unmountOverlayFS(containerPath); unmountErr != nil {
			logger.Log(fmt.Sprintf("Warning: failed to unmount OverlayFS for '%s': %v", name, unmountErr))
			LogDebug("Failed to unmount OverlayFS for '%s': %v", name, unmountErr)
		} else {
			logger.Log(fmt.Sprintf("Successfully unmounted OverlayFS for '%s'", name))
			LogDebug("Successfully unmounted OverlayFS for '%s'", name)
		}
	}

	return err
}

func (cm *ContainerManager) Recreate(name string) error {
	LogInfo("Recreating container '%s'...", name)

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

	// Check if container is running - refuse to recreate if it is
	state, err := cm.runtime.State(name)
	if err == nil && (state == "running" || state == "creating" || state == "paused") {
		return fmt.Errorf("container '%s' is currently %s. Please stop the container before recreating it", name, state)
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
			if slices.Contains(originalSpec.Process.Capabilities.Permitted, privCap) {
				hasPrivilegedCaps = true
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

func (cm *ContainerManager) RecreateWithOptions(opts *RecreateOptions) error {
	fmt.Printf("Recreating container '%s' with overrides...\n", opts.Name)

	// Get container path
	containerPath := filepath.Join(cm.cfg.ContainersPath, opts.Name)
	if _, err := os.Stat(containerPath); os.IsNotExist(err) {
		return fmt.Errorf("container '%s' does not exist", opts.Name)
	}

	// Read current options
	optionsPath := filepath.Join(containerPath, "options.json")
	optionsData, err := os.ReadFile(optionsPath)
	if err != nil {
		return fmt.Errorf("failed to read container options: %w", err)
	}

	var currentOpts CreateOptions
	if err := json.Unmarshal(optionsData, &currentOpts); err != nil {
		return fmt.Errorf("failed to parse container options: %w", err)
	}

	// Merge overrides with current options
	if opts.Image != "" {
		currentOpts.Image = opts.Image
	}
	if opts.ContainerConfig != "" {
		currentOpts.ContainerConfig = opts.ContainerConfig
	}
	if len(opts.Envs) > 0 {
		currentOpts.Envs = opts.Envs
	}
	if len(opts.Volumes) > 0 {
		currentOpts.Volumes = opts.Volumes
	}
	if opts.CPUQuota != 0 {
		currentOpts.CPUQuota = opts.CPUQuota
	}
	if opts.CPUPeriod != 0 {
		currentOpts.CPUPeriod = opts.CPUPeriod
	}
	if opts.MemoryLimit != 0 {
		currentOpts.MemoryLimit = opts.MemoryLimit
	}
	if opts.MemorySwap != 0 {
		currentOpts.MemorySwap = opts.MemorySwap
	}
	if opts.CPUShares != 0 {
		currentOpts.CPUShares = opts.CPUShares
	}
	if opts.BlkioWeight != 0 {
		currentOpts.BlkioWeight = opts.BlkioWeight
	}
	if opts.InitProcess != "" {
		currentOpts.InitProcess = opts.InitProcess
	}
	if opts.Privileged {
		currentOpts.Privileged = opts.Privileged
	}
	if opts.NetNamespace != "" {
		currentOpts.NetNamespace = opts.NetNamespace
	}
	if opts.TTY {
		currentOpts.TTY = opts.TTY
	}

	// Check if container is running - don't recreate if it is
	state, err := cm.runtime.State(opts.Name)
	if err == nil && (state == "running" || state == "creating" || state == "paused") {
		return fmt.Errorf("container '%s' is currently %s. Please stop the container before recreating it", opts.Name, state)
	}

	// Update image if changed
	imageName := currentOpts.Image
	rootfsSource, err := cm.imgMgr.GetRootfs(imageName)
	if err != nil {
		// Create log file for pulling progress
		logDir := filepath.Join(cm.cfg.RunPath, "logs")
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		logPath := filepath.Join(logDir, opts.Name+".log")
		logger := NewDboxLogger(logPath)
		defer logger.Close()

		logger.Log(fmt.Sprintf("Pulling new image '%s' for container '%s'", imageName, opts.Name))
		if err := cm.imgMgr.Pull(imageName, logger.LogFile); err != nil {
			logger.Log(fmt.Sprintf("Failed to pull new image: %v", err))
			return fmt.Errorf("failed to pull new image: %w", err)
		}
		logger.Log("New image pulled successfully")
		rootfsSource, err = cm.imgMgr.GetRootfs(imageName)
		if err != nil {
			return err
		}
	}

	// Unmount overlayfs if mounted
	mergedPath := filepath.Join(containerPath, "merged")
	if _, err := os.Stat(mergedPath); err == nil {
		if err := cm.unmountOverlayFS(containerPath); err != nil {
			fmt.Printf("Warning: failed to unmount overlayfs: %v\n", err)
		}
	}

	// Remount overlayfs
	fmt.Println("Remounting OverlayFS...")
	_, err = cm.mountOverlayFS(containerPath, rootfsSource)
	if err != nil {
		return fmt.Errorf("failed to remount overlayfs: %w", err)
	}

	// Load container config
	containerCfg, cfgErr := LoadContainerConfig(currentOpts.ContainerConfig)
	if cfgErr != nil {
		return fmt.Errorf("failed to load container config: %w", cfgErr)
	}

	// Regenerate OCI spec
	bundlePath := containerPath
	imagePath := filepath.Dir(rootfsSource)
	rootPathForSpec := "merged"

	// Remove existing config.json to allow regeneration
	configPath := filepath.Join(containerPath, "config.json")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Removing existing config.json...\n")
		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to remove existing config.json: %w", err)
		}
	}

	fmt.Println("Regenerating OCI config...")
	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, opts.Name, &currentOpts, nil, containerCfg, rootPathForSpec); err != nil {
		return fmt.Errorf("failed to regenerate OCI spec: %w", err)
	}

	// Update stored options
	newOptionsData, err := json.MarshalIndent(&currentOpts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated options: %w", err)
	}
	if err := os.WriteFile(optionsPath, newOptionsData, 0644); err != nil {
		return fmt.Errorf("failed to write updated options: %w", err)
	}

	// Update metadata if image changed
	if imageName != "" {
		metadata := map[string]string{"name": opts.Name, "image": imageName}
		metadataPath := filepath.Join(containerPath, "metadata.json")
		metadataData, _ := json.MarshalIndent(metadata, "", "  ")
		os.WriteFile(metadataPath, metadataData, 0644)
	}

	fmt.Printf("Container '%s' recreated successfully!\n", opts.Name)
	return nil
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

	// Create log directory and file early for potential image pulling
	logDir := filepath.Join(cm.cfg.RunPath, "logs")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, opts.Name+".log")

	var logger *DboxLogger
	if opts.Detach {
		logger = NewDboxLogger(logPath)
		defer logger.Close()
		logger.Log(fmt.Sprintf("Running container '%s' from image '%s'", opts.Name, opts.Image))
	}

	// Track cleanup state
	overlayMounted := false
	containerCreated := true

	// Cleanup function for failures
	cleanup := func() {
		if overlayMounted && !opts.NoOverlayFS {
			cm.unmountOverlayFS(containerPath)
		}
		if containerCreated {
			os.RemoveAll(containerPath)
		}
	}

	// Defer cleanup - will only run if we return with error
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r) // Re-panic after cleanup
		}
	}()

	rootfsSource, err := cm.imgMgr.GetRootfs(opts.Image)
	if err != nil {
		var logFile *os.File
		if logger != nil {
			logFile = logger.LogFile
		}
		if err := cm.imgMgr.Pull(opts.Image, logFile); err != nil {
			if logger != nil {
				logger.Log(fmt.Sprintf("Failed to pull image: %v", err))
			}
			cleanup()
			return fmt.Errorf("failed to pull image: %w", err)
		}
		if logger != nil {
			logger.Log("Image pulled successfully")
		}
		rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
		if err != nil {
			cleanup()
			return err
		}
	}
	logPath = filepath.Join(logDir, opts.Name+".log")

	if opts.Detach {
		logger = NewDboxLogger(logPath)
		defer logger.Close()
		logger.Log(fmt.Sprintf("Running container '%s' from image '%s'", opts.Name, opts.Image))
	}

	// Track cleanup state
	overlayMounted = false
	containerCreated = true

	// Cleanup function for failures
	cleanup = func() {
		if overlayMounted && !opts.NoOverlayFS {
			cm.unmountOverlayFS(containerPath)
		}
		if containerCreated {
			os.RemoveAll(containerPath)
		}
	}

	// Defer cleanup - will only run if we return with error
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r) // Re-panic after cleanup
		}
	}()

	rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
	if err != nil {
		var logFile *os.File
		if logger != nil {
			logFile = logger.LogFile
		}
		if err := cm.imgMgr.Pull(opts.Image, logFile); err != nil {
			if logger != nil {
				logger.Log(fmt.Sprintf("Failed to pull image: %v", err))
			}
			cleanup()
			return fmt.Errorf("failed to pull image: %w", err)
		}
		if logger != nil {
			logger.Log("Image pulled successfully")
		}
		rootfsSource, err = cm.imgMgr.GetRootfs(opts.Image)
		if err != nil {
			cleanup()
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
			cleanup()
			return fmt.Errorf("failed to create rootfs directory: %w", err)
		}
		if err := copyDirWithProgress(rootfsSource, rootfsDest); err != nil {
			cleanup()
			return fmt.Errorf("failed to copy rootfs: %w", err)
		}
		rootPathForSpec = "rootfs"
	} else {
		fmt.Println("Setting up OverlayFS mount...")
		_, err := cm.mountOverlayFS(containerPath, rootfsSource)
		if err != nil {
			cleanup()
			return fmt.Errorf("failed to prepare container filesystem: %w", err)
		}
		overlayMounted = true
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
		cleanup()
		return err
	}

	createOpts := &CreateOptions{
		Image:        opts.Image,
		Name:         opts.Name,
		Envs:         opts.Envs,
		TTY:          opts.TTY,
		Privileged:   opts.Privileged,
		NetNamespace: opts.NetNamespace,
		InitProcess:  opts.InitProcess,
	}

	if err := cm.generateOCISpecUsingRuntime(bundlePath, imagePath, opts.Name, createOpts, opts, containerCfg, rootPathForSpec); err != nil {
		cleanup()
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	if opts.Detach {
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

	// Success - don't run cleanup
	containerCreated = false
	overlayMounted = false

	if opts.Detach {
		fmt.Println(opts.Name)
	}

	return nil
}

func (cm *ContainerManager) Exec(name string, command []string) error {
	return cm.runtime.Exec(name, command)
}
