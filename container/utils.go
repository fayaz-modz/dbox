package container

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"dbox/utils"
)

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
	fmt.Printf("\r  Copying... [%s] %.1f%% (%s / %s)", bar, percentage, utils.FormatBytes(uint64(current)), utils.FormatBytes(uint64(total)))
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (cm *ContainerManager) isOverlayFSMounted(containerPath string) bool {
	mergedPath := filepath.Join(containerPath, "merged")

	// Check if merged directory exists
	if _, err := os.Stat(mergedPath); os.IsNotExist(err) {
		return false
	}

	// Check if it's actually a mount point
	cmd := exec.Command("findmnt", "-n", "-o", "TARGET", mergedPath)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	isMounted := strings.TrimSpace(string(output)) == mergedPath

	// Additional check: try to access the filesystem
	if isMounted {
		if _, err := os.Stat(filepath.Join(mergedPath, "bin")); err != nil {
			// Mount exists but filesystem isn't accessible
			return false
		}
	}

	return isMounted
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

func (cm *ContainerManager) unmountOverlayFS(containerPath string) error {
	mergedPath := filepath.Join(containerPath, "merged")

	// Check if path exists
	if _, err := os.Stat(mergedPath); os.IsNotExist(err) {
		return nil // Nothing to unmount
	}

	// First check if it's actually mounted
	if !cm.isOverlayFSMounted(containerPath) {
		fmt.Printf("Info: %s is not mounted or not accessible\n", mergedPath)
		return nil
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
