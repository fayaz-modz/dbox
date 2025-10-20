package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	args := []string{"--root", r.cfg.RunPath}
	if logPath != "" {
		args = append(args, "--log", logPath, "--log-format", "json")
	}
	args = append(args, "start", containerID)

	cmd := exec.Command(r.cfg.Runtime, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container '%s': %v\n%s", containerID, err, string(out))
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
		runtimeLogPath := logPath + ".runtime"
		globalArgs = append(globalArgs, "--log", runtimeLogPath, "--log-format", "json")
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

		cmd.Stdout = logFile
		cmd.Stderr = logFile

		cmd.Stdin = nil

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start container in detached mode: %w", err)
		}

		return nil

	} else {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
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
	// Simplified implementation
	// In production, add timeout and polling
	return nil
}
