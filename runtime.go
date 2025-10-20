package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type Runtime struct {
	cfg *Config
}

func NewRuntime(cfg *Config) *Runtime {
	return &Runtime{cfg: cfg}
}

func (r *Runtime) Create(containerID, bundlePath string) error {
	containerStateDir := filepath.Join(r.cfg.RunPath, containerID)
	consoleSocketPath := filepath.Join(containerStateDir, "console.sock")

	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"create",
		"--bundle", bundlePath,
		"--console-socket", consoleSocketPath,
		containerID,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trim the output for a cleaner error message
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}

	return nil
}

func (r *Runtime) Start(containerID, logPath string) error {
	args := []string{
		"--root", r.cfg.RunPath,
	}

	if logPath != "" {
		args = append(args, "--log", logPath, "--log-format", "json")
	}

	args = append(args, "start", containerID)

	cmd := exec.Command(r.cfg.Runtime, args...)

	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Step 2: Put the process in a new session to detach it from our terminal.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	return cmd.Start()
}

func (r *Runtime) Stop(containerID string) error {
	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"kill",
		containerID,
		"SIGTERM",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	// Wait for container to stop
	return r.waitForState(containerID, "stopped")
}

func (r *Runtime) Delete(containerID string, force bool) error {
	args := []string{
		"--root", r.cfg.RunPath,
		"delete",
	}

	if force {
		args = append(args, "--force")
	}

	args = append(args, containerID)

	cmd := exec.Command(r.cfg.Runtime, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete container: %s: %w", strings.TrimSpace(string(output)), err)
	}

	return nil // Success
}

func (r *Runtime) List() ([]string, error) {
	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"list",
		"--format", "json",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse the output to get container IDs
	// This is simplified; in production, parse JSON properly
	lines := strings.Split(string(output), "\n")
	var containers []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "ID") {
			containers = append(containers, strings.Fields(line)[0])
		}
	}

	return containers, nil
}

type containerState struct {
	Status string `json:"status"`
}

// State returns the container's status (e.g., "running", "stopped", "created").
func (r *Runtime) State(containerID string) (string, error) {
	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"state",
		containerID,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Include the command's output in the error for better debugging
		return "", fmt.Errorf("runtime state command failed for '%s': %s: %w", containerID, strings.TrimSpace(string(output)), err)
	}

	var state containerState
	if err := json.Unmarshal(output, &state); err != nil {
		return "", fmt.Errorf("failed to parse container state JSON: %w", err)
	}

	return state.Status, nil
}

func (r *Runtime) Exec(containerID string, command []string) error {
	args := []string{
		"--root", r.cfg.RunPath,
		"exec",
		"-t",
		containerID,
	}
	args = append(args, command...)

	cmd := exec.Command(r.cfg.Runtime, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// --- START OF MODIFICATION ---

func (r *Runtime) Run(containerID, bundlePath string, detach bool, logPath string) error {
	// Global options that must come BEFORE the subcommand.
	globalArgs := []string{
		"--root", r.cfg.RunPath,
	}

	// IMPORTANT: The --log flag is for the RUNTIME's logs, not the container's stdout/stderr.
	// We only set it if a path is provided, but it's not what captures the container output.
	if logPath != "" {
		// You might want a different file for runtime logs vs container output logs.
		// For simplicity, we'll let them co-mingle for now.
		runtimeLogPath := logPath + ".runtime"
		globalArgs = append(globalArgs, "--log", runtimeLogPath, "--log-format", "json")
	}

	args := globalArgs
	args = append(args, "run", "--bundle", bundlePath)
	// We DO NOT use the runtime's --detach flag. We handle detachment ourselves.

	args = append(args, containerID)
	cmd := exec.Command(r.cfg.Runtime, args...)

	if detach {
		// --- This is the new logic for detached mode ---
		if logPath == "" {
			return fmt.Errorf("log path must be provided for detached mode")
		}

		// 1. Open the log file that will capture the container's stdout and stderr.
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file for container: %w", err)
		}
		defer logFile.Close()

		cmd.Stdout = logFile
		cmd.Stderr = logFile

		// 2. We don't connect Stdin in detached mode.
		cmd.Stdin = nil

		// 3. This is the crucial step. By setting a new session ID, the process
		// is detached from our current terminal. When the `dbox run` command exits,
		// this child process will not be killed. It becomes a daemon.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		// 4. Use Start() instead of Run(). Start() begins the command and returns
		// immediately without waiting for it to complete.
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start container in detached mode: %w", err)
		}

		// The container is now running in the background, with its output piped to the log file.
		return nil

	} else {
		// For foreground mode, the existing logic is correct.
		// We connect stdio so the user can interact.
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// Use Run() here because we want to block until the container exits.
		return cmd.Run()
	}
}

// --- END OF MODIFICATION ---

func (r *Runtime) RunRaw(args []string) error {
	finalArgs := []string{"--root", r.cfg.RunPath}
	finalArgs = append(finalArgs, args...)

	cmd := exec.Command(r.cfg.Runtime, finalArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func (r *Runtime) Version() (string, error) {
	cmd := exec.Command(r.cfg.Runtime, "--root", r.cfg.RunPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (r *Runtime) waitForState(containerID, expectedState string) error {
	// Simplified implementation
	// In production, add timeout and polling
	return nil
}

func (r *Runtime) GetContainerPID(containerID string) (int, error) {
	stateFile := filepath.Join(r.cfg.RunPath, containerID, "state.json")

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read state file: %w", err)
	}

	// Parse PID from state JSON
	// Simplified - should use proper JSON parsing
	var pid int
	fmt.Sscanf(string(data), `{"pid":%d`, &pid)

	return pid, nil
}
