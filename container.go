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
	if opts.Detach {
		logDir := filepath.Join(cm.cfg.RunPath, "logs")
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		logPath = filepath.Join(logDir, opts.Name+".log")
	}

	err = cm.runtime.Run(opts.Name, bundlePath, opts.Detach, logPath)
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
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate base OCI spec: %w", err)
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
	processArgs := append(imgConfig.Config.Entrypoint, imgConfig.Config.Cmd...)
	if len(processArgs) > 0 {
		ociSpec.Process.Args = processArgs
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
	capsToAdd := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID"}
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
		var newNamespaces []spec.LinuxNamespace
		for _, ns := range ociSpec.Linux.Namespaces {
			if ns.Type != spec.NetworkNamespace {
				newNamespaces = append(newNamespaces, ns)
			}
		}
		ociSpec.Linux.Namespaces = newNamespaces
		ociSpec.Linux.Seccomp = nil
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

	modifiedData, err := json.MarshalIndent(ociSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal modified config: %w", err)
	}
	return os.WriteFile(configPath, modifiedData, 0644)
}

func (cm *ContainerManager) Delete(name string, force bool) error {

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
			// If --force is used, stop the container before deleting.
			fmt.Printf("Container '%s' is %s, stopping it due to --force flag...\n", name, state)
			if err := cm.runtime.Stop(name, true); err != nil {
				return fmt.Errorf("failed to stop container '%s' for forced deletion: %w", name, err)
			}
			// Now that it's stopped, we can delete it via the runtime.
			if err := cm.runtime.Delete(name, false); err != nil { // No need to force the runtime delete now
				fmt.Printf("Warning: runtime delete command failed after stopping: %v. Proceeding with manual cleanup.\n", err)
			}

		case "stopped", "created":
			// Container is in a safe state to delete.
			if err := cm.runtime.Delete(name, force); err != nil {
				fmt.Printf("Warning: runtime delete command failed: %v. Proceeding with manual cleanup.\n", err)
			}

		default:
			return fmt.Errorf("container '%s' is in an unknown state: '%s'. Cannot determine safe deletion path", name, state)
		}
	}

	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	if _, statErr := os.Stat(containerPath); !os.IsNotExist(statErr) {
		mergedPath := filepath.Join(containerPath, "merged")
		if _, statErr := os.Stat(mergedPath); statErr == nil {
			if err := cm.unmountOverlayFS(containerPath); err != nil {
				fmt.Printf("Warning: failed to unmount overlayfs for %s: %v. Manual cleanup may be required.\n", name, err)
			}
		}
		if err := os.RemoveAll(containerPath); err != nil {
			fmt.Printf("Warning: failed to remove container directory %s: %v\n", containerPath, err)
		}
	}

	// Runtime state directory cleanup
	runtimeStatePath := filepath.Join(cm.cfg.RunPath, name)
	if _, statErr := os.Stat(runtimeStatePath); !os.IsNotExist(statErr) {
		if err := os.RemoveAll(runtimeStatePath); err != nil {
			fmt.Printf("Warning: failed to remove runtime state directory %s: %v\n", runtimeStatePath, err)
		}
	}

	// Log file cleanup
	logPath := filepath.Join(cm.cfg.RunPath, "logs", name+".log")
	if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("Warning: failed to remove log file %s: %v\n", logPath, err)
	}

	fmt.Printf("Successfully deleted all assets for container '%s'.\n", name)
	return nil
}

func (cm *ContainerManager) unmountOverlayFS(containerPath string) error {
	mergedPath := filepath.Join(containerPath, "merged")
	var lastErr error
	cmd := exec.Command("umount", mergedPath)
	output, err := cmd.CombinedOutput()

	if err == nil {
		fmt.Printf("Info: successfully unmounted %s\n", mergedPath)
		return nil
	}
	if strings.Contains(string(output), "not mounted") {
		fmt.Printf("Info: %s was already unmounted.\n", mergedPath)
		return nil
	}
	lastErr = fmt.Errorf("umount command failed: %s (%w)", string(output), err)
	return fmt.Errorf("unmount failed after multiple retries: %w", lastErr)
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
	fmt.Println("CONTAINER_NAME\tIMAGE")
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			metadataPath := filepath.Join(cm.cfg.ContainersPath, entry.Name(), "metadata.json")
			data, err := os.ReadFile(metadataPath)
			if err == nil {
				var metadata map[string]string
				json.Unmarshal(data, &metadata)
				fmt.Printf("%s\t%s\n", metadata["name"], metadata["image"])
			} else {
				fmt.Printf("%s\t<unknown>\n", entry.Name())
			}
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
	fmt.Printf("Starting container '%s' in background...\n", name)
	fmt.Printf("Logs will be available at: %s\n", logPath)
	return cm.runtime.Start(name, logPath)
}

func (cm *ContainerManager) Stop(name string, force bool) error {
	return cm.runtime.Stop(name, force)
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
	for _, p := range []string{upperPath, workPath, mergedPath} {
		if err := os.MkdirAll(p, 0755); err != nil {
			return "", fmt.Errorf("failed to create overlay directory %s: %w", p, err)
		}
	}
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", rootfsSource, upperPath, workPath)
	cmd := exec.Command("mount", "-t", "overlay", "overlay", "-o", options, mergedPath)
	if output, err := cmd.CombinedOutput(); err != nil {
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
	go func() {
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
	stopProgress <- true
	time.Sleep(50 * time.Millisecond)
	return err
}

func printCopyProgress(current, total int64) {
	if total <= 0 {
		return
	}
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	completedWidth := int(float64(barWidth) * float64(current) / float64(total))
	bar := strings.Repeat("=", completedWidth) + strings.Repeat(" ", barWidth-completedWidth)
	fmt.Printf("\r  Copying... [%s] %.2f%% (%s / %s)", bar, percentage, formatBytes(uint64(current)), formatBytes(uint64(total)))
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
