package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ContainerUsage struct {
	CPUUsage    string
	MemoryUsage string
	PID         int
	CgroupPath  string
}

func (cm *ContainerManager) Usage(containerID string, showPID, showCgroup bool) error {
	// Check if container is running
	state, err := cm.runtime.State(containerID)
	if err != nil {
		return fmt.Errorf("failed to get container state: %w", err)
	}

	if state != "running" {
		fmt.Printf("Container '%s' is not running (state: %s)\n", containerID, state)
		return nil
	}

	// Get container cgroup path
	cgroupPath, err := cm.getCgroupPath(containerID)
	if err != nil {
		return fmt.Errorf("failed to get cgroup path: %w", err)
	}

	// Get CPU usage
	cpuUsage, err := cm.getCPUUsage(cgroupPath)
	if err != nil {
		fmt.Printf("Warning: failed to get CPU usage: %v\n", err)
		cpuUsage = "N/A"
	}

	// Get memory usage
	memoryUsage, err := cm.getMemoryUsage(cgroupPath)
	if err != nil {
		fmt.Printf("Warning: failed to get memory usage: %v\n", err)
		memoryUsage = "N/A"
	}

	// Display basic usage information
	fmt.Printf("Container: %s\n", containerID)
	fmt.Printf("CPU Usage: %s\n", cpuUsage)
	fmt.Printf("Memory Usage: %s\n", memoryUsage)

	// Show PID information if requested
	if showPID {
		pid, err := cm.getContainerPID(containerID)
		if err != nil {
			fmt.Printf("PID: N/A (%v)\n", err)
		} else {
			fmt.Printf("PID: %d\n", pid)
		}
	}

	// Show cgroup information if requested
	if showCgroup {
		fmt.Printf("Cgroup Path: %s\n", cgroupPath)
		if err := cm.showDetailedCgroupInfo(cgroupPath); err != nil {
			fmt.Printf("Warning: failed to get detailed cgroup info: %v\n", err)
		}
	}

	return nil
}

func (cm *ContainerManager) getCgroupPath(containerID string) (string, error) {
	// Get PID from runtime state using raw command
	cmd := exec.Command(cm.cfg.Runtime, "--root", cm.cfg.RunPath, "state", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get runtime state: %w", err)
	}

	var state struct {
		Pid int `json:"pid"`
	}
	if err := json.Unmarshal(output, &state); err != nil {
		return "", fmt.Errorf("failed to parse runtime state: %w", err)
	}

	if state.Pid > 0 {
		// Find cgroup path for this PID
		if cgroupPath, err := cm.findCgroupPathForPID(state.Pid); err == nil {
			return cgroupPath, nil
		}
	}

	// Fallback: try common cgroup v2 paths
	cgroupBase := "/sys/fs/cgroup"
	possiblePaths := []string{
		filepath.Join(cgroupBase, containerID),
		filepath.Join(cgroupBase, "dbox", containerID),
		filepath.Join(cgroupBase, "system.slice", "dbox-"+containerID+".slice"),
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("cgroup path not found for container %s", containerID)
}

func (cm *ContainerManager) findCgroupPathForPID(pid int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", err
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		if strings.Contains(line, "0::") {
			// cgroup v2 format: 0::/path/to/cgroup
			parts := strings.Split(line, "::")
			if len(parts) == 2 {
				return filepath.Join("/sys/fs/cgroup", parts[1]), nil
			}
		} else if strings.Contains(line, "cpu,cpuacct") {
			// cgroup v1 format
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				return filepath.Join("/sys/fs/cgroup/cpu", parts[2]), nil
			}
		}
	}

	return "", fmt.Errorf("cgroup path not found for PID %d", pid)
}

func (cm *ContainerManager) getCPUUsage(cgroupPath string) (string, error) {
	var usageSeconds float64
	var err error

	// Try cgroup v2 first
	cpuStatFile := filepath.Join(cgroupPath, "cpu.stat")
	if data, err := os.ReadFile(cpuStatFile); err == nil {
		lines := strings.SplitSeq(string(data), "\n")
		for line := range lines {
			if strings.HasPrefix(line, "usage_usec ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					usageUsec := parts[1]
					if usage, err := strconv.ParseFloat(usageUsec, 64); err == nil {
						usageSeconds = usage / 1000000
						break
					}
				}
			}
		}
	} else {
		// Try cgroup v1
		cpuacctFile := filepath.Join(cgroupPath, "cpuacct.usage")
		if data, err := os.ReadFile(cpuacctFile); err == nil {
			if usage, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
				usageSeconds = usage / 1000000000 // Convert from nanoseconds
			}
		}
	}

	if usageSeconds == 0 {
		return "", fmt.Errorf("CPU usage not available")
	}

	// Get CPU percentage
	cpuPercent, err := cm.getCPUPercentage(cgroupPath, usageSeconds)
	if err != nil {
		// If we can't get percentage, just return time
		return fmt.Sprintf("%.2f seconds", usageSeconds), nil
	}

	return fmt.Sprintf("%.2f seconds (%.2f%%)", usageSeconds, cpuPercent), nil
}

func (cm *ContainerManager) getCPUPercentage(cgroupPath string, usageSeconds float64) (float64, error) {
	// Get container start time to calculate the time window
	startTime, err := cm.getContainerStartTime(cgroupPath)
	if err != nil {
		return 0, err
	}

	// Calculate time elapsed since container started
	elapsedSeconds := time.Since(startTime).Seconds()
	if elapsedSeconds <= 0 {
		return 0, fmt.Errorf("invalid elapsed time")
	}

	// Get number of CPU cores available to the container
	cpuCount, err := cm.getCPUCount(cgroupPath)
	if err != nil {
		return 0, err
	}

	// Calculate CPU percentage: (usage_time / elapsed_time) * 100 / cpu_count
	cpuPercent := (usageSeconds / elapsedSeconds) * 100 / float64(cpuCount)

	// Cap at 100% to avoid showing unrealistic values
	if cpuPercent > 100 {
		cpuPercent = 100
	}

	return cpuPercent, nil
}

func (cm *ContainerManager) getContainerStartTime(cgroupPath string) (time.Time, error) {
	// Try to get container start time from cgroup creation time
	if stat, err := os.Stat(cgroupPath); err == nil {
		return stat.ModTime(), nil
	}

	// Fallback to current time (this will give inaccurate percentage)
	return time.Now(), nil
}

func (cm *ContainerManager) getCPUCount(cgroupPath string) (int, error) {
	// Try cgroup v2 cpu.max file
	cpuMaxFile := filepath.Join(cgroupPath, "cpu.max")
	if data, err := os.ReadFile(cpuMaxFile); err == nil {
		content := strings.TrimSpace(string(data))
		parts := strings.Fields(content)
		if len(parts) >= 2 {
			if parts[0] == "max" {
				// No limit, use system CPU count
				return runtime.NumCPU(), nil
			}
			if quota, err := strconv.Atoi(parts[0]); err == nil {
				if period, err := strconv.Atoi(parts[1]); err == nil && period > 0 {
					// Calculate CPU count from quota/period
					cpuCount := quota / period
					if cpuCount > 0 {
						return cpuCount, nil
					}
				}
			}
		}
	}

	// Try cgroup v1 cpu.cfs_quota_us and cpu.cfs_period_us
	quotaFile := filepath.Join(cgroupPath, "cpu.cfs_quota_us")
	periodFile := filepath.Join(cgroupPath, "cpu.cfs_period_us")

	if quotaData, err := os.ReadFile(quotaFile); err == nil {
		if periodData, err := os.ReadFile(periodFile); err == nil {
			quota := strings.TrimSpace(string(quotaData))
			period := strings.TrimSpace(string(periodData))

			if quotaVal, err := strconv.Atoi(quota); err == nil {
				if periodVal, err := strconv.Atoi(period); err == nil && periodVal > 0 {
					if quotaVal == -1 {
						// No limit, use system CPU count
						return runtime.NumCPU(), nil
					}
					cpuCount := quotaVal / periodVal
					if cpuCount > 0 {
						return cpuCount, nil
					}
				}
			}
		}
	}

	// Fallback to system CPU count
	return runtime.NumCPU(), nil
}

func (cm *ContainerManager) getMemoryUsage(cgroupPath string) (string, error) {
	// Try cgroup v2 first
	memCurrentFile := filepath.Join(cgroupPath, "memory.current")
	if data, err := os.ReadFile(memCurrentFile); err == nil {
		if current, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			currentMB := float64(current) / 1024 / 1024
			return fmt.Sprintf("%.2f MB", currentMB), nil
		}
	}

	// Try cgroup v1
	memUsageFile := filepath.Join(cgroupPath, "memory.usage_in_bytes")
	if data, err := os.ReadFile(memUsageFile); err == nil {
		if usage, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			usageMB := float64(usage) / 1024 / 1024
			return fmt.Sprintf("%.2f MB", usageMB), nil
		}
	}

	return "", fmt.Errorf("memory usage not available")
}

func (cm *ContainerManager) getContainerPID(containerID string) (int, error) {
	// Get PID from runtime state using raw command
	cmd := exec.Command(cm.cfg.Runtime, "--root", cm.cfg.RunPath, "state", containerID)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get runtime state: %w", err)
	}

	var state struct {
		Pid int `json:"pid"`
	}
	if err := json.Unmarshal(output, &state); err != nil {
		return 0, fmt.Errorf("failed to parse runtime state: %w", err)
	}

	return state.Pid, nil
}

func (cm *ContainerManager) showDetailedCgroupInfo(cgroupPath string) error {
	// Show CPU limits and settings
	if cpuMaxFile := filepath.Join(cgroupPath, "cpu.max"); fileExists(cpuMaxFile) {
		if data, err := os.ReadFile(cpuMaxFile); err == nil {
			fmt.Printf("CPU Max: %s\n", strings.TrimSpace(string(data)))
		}
	}

	// Show memory limits and settings
	if memMaxFile := filepath.Join(cgroupPath, "memory.max"); fileExists(memMaxFile) {
		if data, err := os.ReadFile(memMaxFile); err == nil {
			limit := strings.TrimSpace(string(data))
			if limit == "max" {
				fmt.Printf("Memory Max: unlimited\n")
			} else {
				if limitBytes, err := strconv.ParseUint(limit, 10, 64); err == nil {
					limitMB := float64(limitBytes) / 1024 / 1024
					fmt.Printf("Memory Max: %.2f MB\n", limitMB)
				}
			}
		}
	}

	// Show pids current and max
	if pidsCurrentFile := filepath.Join(cgroupPath, "pids.current"); fileExists(pidsCurrentFile) {
		if data, err := os.ReadFile(pidsCurrentFile); err == nil {
			fmt.Printf("PIDs Current: %s\n", strings.TrimSpace(string(data)))
		}
	}

	if pidsMaxFile := filepath.Join(cgroupPath, "pids.max"); fileExists(pidsMaxFile) {
		if data, err := os.ReadFile(pidsMaxFile); err == nil {
			max := strings.TrimSpace(string(data))
			if max == "max" {
				fmt.Printf("PIDs Max: unlimited\n")
			} else {
				fmt.Printf("PIDs Max: %s\n", max)
			}
		}
	}

	return nil
}
