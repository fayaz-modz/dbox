package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Runtime struct {
	cfg *Config
}

func NewRuntime(cfg *Config) *Runtime {
	return &Runtime{cfg: cfg}
}

func (r *Runtime) Create(containerID, bundlePath string) error {
	parentDir := r.cfg.RunPath
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent runtime directory '%s': %w", parentDir, err)
	}

	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"create",
		"--bundle", bundlePath,
		containerID,
	)

	fmt.Printf("Running runtime create command: %s\n", cmd.String())

	// Use Start() and Wait() instead of CombinedOutput()
	// This can sometimes behave differently if the command is doing strange things with stdio.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start runtime create command: %w", err)
	}

	// Now wait for it to finish. This is where it will likely hang if the problem persists.
	return cmd.Wait()
}

func (r *Runtime) Start(containerID, logPath string) error {
	// Check container state first
	state, err := r.State(containerID)
	if err != nil {
		// If container doesn't exist in runtime, we need to recreate it
		if strings.Contains(err.Error(), "does not exist") {
			return fmt.Errorf("container '%s' exists but not in runtime. Use 'recreate' command to fix this", containerID)
		}
		return fmt.Errorf("failed to get container state: %w", err)
	}

	fmt.Printf("DEBUG: Container '%s' state: %s\n", containerID, state)

	// If container is already running, nothing to do
	if state == "running" {
		fmt.Printf("DEBUG: Container already running, nothing to do\n")
		return nil
	}

	// Find the container bundle path
	bundlePath := filepath.Join(r.cfg.ContainersPath, containerID)

	// For stopped or created containers, we need to delete and recreate to capture output properly
	if state == "stopped" || state == "created" {
		fmt.Printf("DEBUG: Container is in '%s' state, using Run() method for output capture\n", state)
		// Delete from runtime first
		deleteArgs := []string{"--root", r.cfg.RunPath, "delete", containerID}
		deleteCmd := exec.Command(r.cfg.Runtime, deleteArgs...)
		if err := deleteCmd.Run(); err != nil {
			return fmt.Errorf("failed to delete container for restart: %w", err)
		}

		// Now run with output capture
		fmt.Printf("DEBUG: Running container with bundle: %s, logPath: %s\n", bundlePath, logPath)
		return r.Run(containerID, bundlePath, true, logPath)
	}

	// For created containers, use regular start
	args := []string{"--root", r.cfg.RunPath}
	if logPath != "" {
		args = append(args, "--log", logPath, "--log-format", "json")
	}
	args = append(args, "start", containerID)

	cmd := exec.Command(r.cfg.Runtime, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// capture runtime output to log file if provided
	var logFile *os.File
	if logPath != "" {
		logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file for runtime output: %w", err)
		}
		defer logFile.Close()
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to start container '%s': %v", containerID, err)
	}
	return nil
}

func (r *Runtime) Stop(containerID string, force bool) error {
	signal := "SIGTERM"
	if force {
		signal = "SIGKILL"
	}

	cmd := exec.Command(
		r.cfg.Runtime,
		"--root", r.cfg.RunPath,
		"kill",
		containerID,
		signal,
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

func (r *Runtime) Run(containerID, bundlePath string, detach bool, logPath string) error {
	// Global options that must come BEFORE the subcommand.
	globalArgs := []string{
		"--root", r.cfg.RunPath,
	}

	if logPath != "" {
		globalArgs = append(globalArgs, "--log", logPath, "--log-format", "json")
	}

	args := globalArgs
	args = append(args, "run", "--bundle", bundlePath)

	args = append(args, containerID)
	cmd := exec.Command(r.cfg.Runtime, args...)

	if detach {
		if logPath == "" {
			return fmt.Errorf("log path must be provided for detached mode")
		}

		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file for container: %w", err)
		}
		defer logFile.Close()

		fmt.Printf("DEBUG: Redirecting container output to log file: %s\n", logPath)
		cmd.Stdout = logFile
		cmd.Stderr = logFile

		cmd.Stdin = nil

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		fmt.Printf("DEBUG: Starting detached container with command: %s\n", cmd.String())
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start container in detached mode: %w", err)
		}

		fmt.Printf("DEBUG: Container started successfully in detached mode\n")
		return nil

	} else {
		cmd.Stdin = os.Stdin

		// For foreground mode, capture to both console and log file
		if logPath != "" {
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return fmt.Errorf("failed to open log file for container: %w", err)
			}
			defer logFile.Close()

			// Create a multi-writer that writes to both stdout and log file
			cmd.Stdout = io.MultiWriter(os.Stdout, logFile)
			cmd.Stderr = io.MultiWriter(os.Stderr, logFile)
		} else {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}

		return cmd.Run()
	}
}

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
	const (
		maxRetries   = 30
		pollInterval = 1 * time.Second
		timeout      = 30 * time.Second
	)

	start := time.Now()

	for i := 0; i < maxRetries; i++ {
		state, err := r.State(containerID)
		if err != nil {
			// If container doesn't exist anymore, consider it stopped
			if strings.Contains(err.Error(), "does not exist") && expectedState == "stopped" {
				return nil
			}
			return fmt.Errorf("failed to get container state: %w", err)
		}

		if state == expectedState {
			return nil
		}

		// Check timeout
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout waiting for container '%s' to reach state '%s' (current: '%s')", containerID, expectedState, state)
		}

		time.Sleep(pollInterval)
	}

	return fmt.Errorf("container '%s' did not reach state '%s' after %d retries", containerID, expectedState, maxRetries)
}
