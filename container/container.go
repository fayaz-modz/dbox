package container

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "dbox/config"
	. "dbox/image"
	. "dbox/logger"
	. "dbox/runtime"
)

const (
	StatusCreating = "CREATING"
	StatusReady    = "READY"
	StatusRunning  = "RUNNING"
	StatusStopped  = "STOPPED"
	StatusUnknown  = "UNKNOWN"
)

func (cm *ContainerManager) Attach(name string) error {
	return cm.runtime.Exec(name, []string{"/bin/sh"})
}

func NewContainerManager(cfg *Config) *ContainerManager {
	return &ContainerManager{
		cfg:     cfg,
		runtime: NewRuntime(cfg),
		imgMgr:  NewImageManager(cfg),
	}
}

func (cm *ContainerManager) stopContainerCreation(name string, logger *DboxLogger) error {
	// Try to stop the creation process
	pidFile := filepath.Join(cm.cfg.RunPath, "logs", "."+name+".create.pid")
	processStopped := false

	if pidData, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(string(pidData)); err == nil {
			logger.Log(fmt.Sprintf("Found creation process PID %d, attempting to terminate process group", pid))

			// Try to terminate the process group (negative PID kills the entire group)
			if process, err := os.FindProcess(-pid); err == nil {
				// Send SIGTERM to the process group
				if err := process.Signal(syscall.SIGTERM); err != nil {
					logger.Log(fmt.Sprintf("Failed to send SIGTERM to process group %d: %v", -pid, err))
				} else {
					logger.Log(fmt.Sprintf("Sent SIGTERM to process group %d", -pid))
					processStopped = true

					// Wait a bit and check if process is still running
					time.Sleep(2 * time.Second)

					// Check if process still exists by sending signal 0
					if err := process.Signal(syscall.Signal(0)); err == nil {
						// Process still running, force kill the entire group
						logger.Log(fmt.Sprintf("Process group %d still running, sending SIGKILL", -pid))
						if err := process.Signal(syscall.SIGKILL); err != nil {
							logger.Log(fmt.Sprintf("Failed to send SIGKILL to process group %d: %v", -pid, err))
						} else {
							logger.Log(fmt.Sprintf("Sent SIGKILL to process group %d", -pid))
						}
					}
				}
			}
		}

		// Clean up PID file
		os.Remove(pidFile)
	}

	if !processStopped {
		logger.Log("No creation process found")
	}

	// Clean up partial container creation
	containerPath := filepath.Join(cm.cfg.ContainersPath, name)
	if _, err := os.Stat(containerPath); err == nil {
		logger.Log(fmt.Sprintf("Cleaning up partial container creation at %s", containerPath))
		if err := os.RemoveAll(containerPath); err != nil {
			logger.Log(fmt.Sprintf("Failed to clean up partial container: %v", err))
		} else {
			logger.Log("Successfully cleaned up partial container")
		}
	}

	// Update status to indicate creation was stopped
	cm.updateContainerStatus(name, "CREATION_STOPPED")
	logger.Log(fmt.Sprintf("Container '%s' creation stopped", name))
	fmt.Printf("Container '%s' creation stopped\n", name)

	return nil
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

func pointerToInt64(i int64) *int64 {
	return &i
}

func getTTYMinor(tty string) int64 {
	// Extract the number from ttyX format
	if len(tty) >= 4 && tty[:3] == "tty" {
		num := tty[3:]
		if num == "" {
			return 0
		}
		var minor int64
		fmt.Sscanf(num, "%d", &minor)
		return minor
	}
	return 0
}

func (cm *ContainerManager) Create(opts *CreateOptions, detach bool) error {
	// Create log directory and file
	logDir := filepath.Join(cm.cfg.RunPath, "logs")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, opts.Name+".log")

	// Create logger for both detached and foreground modes
	logger := NewDboxLogger(logPath)
	defer logger.Close()

	logger.Log(fmt.Sprintf("Creating container '%s' from image '%s'", opts.Name, opts.Image))

	if detach {
		fmt.Printf("Creating container '%s' in background...\n", opts.Name)
		fmt.Printf("Logs will be available at: %s\n", logPath)

		// Create a background process using exec.Command
		args := []string{
			"create-background",
			"--name", opts.Name,
			"--image", opts.Image,
			"--log-path", logPath,
		}

		// Add optional flags
		if opts.ContainerConfig != "" {
			args = append(args, "--container-config", opts.ContainerConfig)
		}
		if opts.NoOverlayFS {
			args = append(args, "--no-overlayfs")
		}
		if opts.InitProcess != "" {
			args = append(args, "--init", opts.InitProcess)
		}
		if opts.Privileged {
			args = append(args, "--privileged")
		}
		if opts.NetNamespace != "" {
			args = append(args, "--net", opts.NetNamespace)
		}
		if opts.TTY {
			args = append(args, "--tty")
		}
		for _, env := range opts.Envs {
			args = append(args, "--env", env)
		}
		if opts.CPUQuota != 0 {
			args = append(args, "--cpu-quota", fmt.Sprintf("%d", opts.CPUQuota))
		}
		if opts.CPUPeriod != 0 {
			args = append(args, "--cpu-period", fmt.Sprintf("%d", opts.CPUPeriod))
		}
		if opts.MemoryLimit != 0 {
			args = append(args, "--memory", fmt.Sprintf("%d", opts.MemoryLimit))
		}
		if opts.MemorySwap != 0 {
			args = append(args, "--memory-swap", fmt.Sprintf("%d", opts.MemorySwap))
		}
		if opts.CPUShares != 0 {
			args = append(args, "--cpu-shares", fmt.Sprintf("%d", opts.CPUShares))
		}
		if opts.BlkioWeight != 0 {
			args = append(args, "--blkio-weight", fmt.Sprintf("%d", opts.BlkioWeight))
		}

		cmd := exec.Command(os.Args[0], args...)

		// Set up process group for both foreground and background modes
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}

		// Redirect all output to /dev/null for the background process
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil

		// Start the background process
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start background creation process: %w", err)
		}

		// Store the background process PID for potential termination during creation
		pidFile := filepath.Join(cm.cfg.RunPath, "logs", "."+opts.Name+".create.pid")
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
			logger.Log(fmt.Sprintf("Warning: failed to write creation PID file: %v", err))
		}

		// Return immediately, leaving the process running in background
		return nil
	}

	// Foreground mode - run in background but wait for completion
	LogInfo("Creating container '%s' from image '%s'...", opts.Name, opts.Image)
	LogVerbose("Container path: %s", filepath.Join(cm.cfg.ContainersPath, opts.Name))

	// Create a background process for creation (same as detached mode)
	args := []string{
		"create-background",
		"--name", opts.Name,
		"--image", opts.Image,
		"--log-path", logPath,
	}

	// Add optional flags
	if opts.ContainerConfig != "" {
		args = append(args, "--container-config", opts.ContainerConfig)
	}
	if opts.NoOverlayFS {
		args = append(args, "--no-overlayfs")
	}
	if opts.InitProcess != "" {
		args = append(args, "--init", opts.InitProcess)
	}
	if opts.Privileged {
		args = append(args, "--privileged")
	}
	if opts.NetNamespace != "" {
		args = append(args, "--net", opts.NetNamespace)
	}
	if opts.TTY {
		args = append(args, "--tty")
	}
	for _, env := range opts.Envs {
		args = append(args, "--env", env)
	}
	if opts.CPUQuota != 0 {
		args = append(args, "--cpu-quota", fmt.Sprintf("%d", opts.CPUQuota))
	}
	if opts.CPUPeriod != 0 {
		args = append(args, "--cpu-period", fmt.Sprintf("%d", opts.CPUPeriod))
	}
	if opts.MemoryLimit != 0 {
		args = append(args, "--memory", fmt.Sprintf("%d", opts.MemoryLimit))
	}
	if opts.MemorySwap != 0 {
		args = append(args, "--memory-swap", fmt.Sprintf("%d", opts.MemorySwap))
	}
	if opts.CPUShares != 0 {
		args = append(args, "--cpu-shares", fmt.Sprintf("%d", opts.CPUShares))
	}
	if opts.BlkioWeight != 0 {
		args = append(args, "--blkio-weight", fmt.Sprintf("%d", opts.BlkioWeight))
	}

	cmd := exec.Command(os.Args[0], args...)

	// Set up process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Connect stdout and stderr to show output in foreground mode
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start the background process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start creation process: %w", err)
	}

	// Store the background process PID for potential termination
	pidFile := filepath.Join(cm.cfg.RunPath, "logs", "."+opts.Name+".create.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		logger.Log(fmt.Sprintf("Warning: failed to write creation PID file: %v", err))
	}

	// Wait for completion and show output (foreground behavior)
	if err := cmd.Wait(); err != nil {
		// Clean up PID file on error
		os.Remove(pidFile)
		return err
	}

	// Clean up PID file on success
	os.Remove(pidFile)
	return nil
}

func (cm *ContainerManager) GetContainerNames() ([]string, error) {
	entries, err := os.ReadDir(cm.cfg.ContainersPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			names = append(names, entry.Name())
		}
	}
	return names, nil
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
			var imageName, status string
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

			// Get metadata status first
			var metadataStatus string
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata map[string]string
				if json.Unmarshal(data, &metadata) == nil {
					metadataStatus = metadata["status"]
				}
			}

			// Check metadata status first for active states like CREATING and READY
			switch metadataStatus {
			case StatusCreating:
				status = StatusCreating
			case StatusReady:
				status = StatusReady
			default:
				// For other states, check runtime state for accurate status
				runtimeState, err := cm.runtime.State(containerName)
				if err != nil {
					// Check if container directory exists but runtime doesn't know about it
					if _, err := os.Stat(filepath.Join(cm.cfg.ContainersPath, containerName)); err == nil {
						status = StatusStopped
					} else {
						status = StatusUnknown
					}
				} else {
					status = strings.ToUpper(runtimeState)
				}
			}

			fmt.Printf("%-20s %-15s %-10s %s\n", containerName, imageName, status, createdTime)
		}
	}
	return nil
}
