package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dbox/utils"
)

// ListVolumes lists all volumes
func (cm *ContainerManager) ListVolumes() error {
	return cm.ListVolumesWithContext(nil)
}

// ListVolumesWithContext lists all volumes with optional context for JSON output
func (cm *ContainerManager) ListVolumesWithContext(ctx interface{}) error {
	volumesPath := cm.cfg.VolumesPath

	if _, err := os.Stat(volumesPath); os.IsNotExist(err) {
		utils.PrintEmptyState("volumes")
		return nil
	}

	entries, err := os.ReadDir(volumesPath)
	if err != nil {
		return fmt.Errorf("failed to read volumes directory: %w", err)
	}

	if len(entries) == 0 {
		utils.PrintEmptyState("volumes")
		return nil
	}

	var w *utils.TableFormatter
	if utils.IsJSONMode(ctx) {
		w = utils.NewJSONFormatter()
	} else {
		w = utils.NewTableFormatter()
	}
	w.AddHeader("NAME", "DRIVER", "MOUNTPOINT", "CREATED")

	for _, entry := range entries {
		if entry.IsDir() {
			volumePath := filepath.Join(volumesPath, entry.Name())
			metadataPath := filepath.Join(volumePath, "metadata.json")

			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata struct {
					Name       string `json:"name"`
					Driver     string `json:"driver"`
					Mountpoint string `json:"mountpoint"`
					CreatedAt  string `json:"created_at"`
				}
				if json.Unmarshal(data, &metadata) == nil {
					created := metadata.CreatedAt
					if created == "" {
						// Fallback to directory modification time if created_at is not present
						if info, err := entry.Info(); err == nil {
							created = info.ModTime().Format(time.RFC3339)
						} else {
							created = "unknown"
						}
					}
					w.AddRow(metadata.Name, metadata.Driver, metadata.Mountpoint, created)
				}
			} else {
				// Fallback for volumes without metadata
				dataPath := filepath.Join(volumePath, "_data")
				created := "unknown"
				if info, err := entry.Info(); err == nil {
					created = info.ModTime().Format(time.RFC3339)
				}
				w.AddRow(entry.Name(), "local", dataPath, created)
			}
		}
	}

	return w.Render()
	return nil
}

// InspectVolume displays detailed information about a volume
func (cm *ContainerManager) InspectVolume(volumeName string) error {
	return cm.InspectVolumeWithContext(volumeName, nil)
}

// InspectVolumeWithContext displays detailed information about a volume with optional context for JSON output
func (cm *ContainerManager) InspectVolumeWithContext(volumeName string, ctx interface{}) error {
	volumePath := filepath.Join(cm.cfg.VolumesPath, volumeName)

	if _, err := os.Stat(volumePath); os.IsNotExist(err) {
		return fmt.Errorf("volume '%s' not found", volumeName)
	}

	// Show volume metadata if it exists
	metadataPath := filepath.Join(volumePath, "metadata.json")
	if data, err := os.ReadFile(metadataPath); err == nil {
		var metadata struct {
			Name       string `json:"name"`
			Driver     string `json:"driver"`
			CreatedAt  string `json:"created_at"`
			Mountpoint string `json:"mountpoint"`
		}
		if json.Unmarshal(data, &metadata) == nil {
			if utils.IsJSONMode(ctx) {
				volumeInfo := map[string]interface{}{
					"name":       metadata.Name,
					"driver":     metadata.Driver,
					"created_at": metadata.CreatedAt,
					"mountpoint": metadata.Mountpoint,
				}
				return utils.PrintJSONData(volumeInfo)
			} else {
				utils.PrintSectionHeader("Volume Information")
				utils.PrintKeyValue("Name", metadata.Name)
				utils.PrintKeyValue("Driver", metadata.Driver)
				utils.PrintKeyValue("Created At", metadata.CreatedAt)
				utils.PrintKeyValue("Mountpoint", metadata.Mountpoint)
			}
		}
	} else {
		// Fallback for volumes without metadata
		dataPath := filepath.Join(volumePath, "_data")
		if utils.IsJSONMode(ctx) {
			volumeInfo := map[string]interface{}{
				"name":       volumeName,
				"driver":     "local",
				"mountpoint": dataPath,
			}
			return utils.PrintJSONData(volumeInfo)
		} else {
			utils.PrintSectionHeader("Volume Information")
			utils.PrintKeyValue("Name", volumeName)
			utils.PrintKeyValue("Driver", "local")
			utils.PrintKeyValue("Mountpoint", dataPath)
		}
	}

	return nil
}

// CreateVolume creates a new volume
func (cm *ContainerManager) CreateVolume(volumeName, driver string, opts []string) error {
	volumesPath := cm.cfg.VolumesPath

	if err := os.MkdirAll(volumesPath, 0755); err != nil {
		return fmt.Errorf("failed to create volumes directory: %w", err)
	}

	volumePath := filepath.Join(volumesPath, volumeName)

	if _, err := os.Stat(volumePath); !os.IsNotExist(err) {
		return fmt.Errorf("volume '%s' already exists", volumeName)
	}

	if err := os.Mkdir(volumePath, 0755); err != nil {
		return fmt.Errorf("failed to create volume directory: %w", err)
	}

	// Create _data directory
	dataPath := filepath.Join(volumePath, "_data")
	if err := os.Mkdir(dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create volume data directory: %w", err)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"name":       volumeName,
		"driver":     driver,
		"created_at": time.Now().Format(time.RFC3339),
		"mountpoint": dataPath,
	}

	metadataData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metadataPath := filepath.Join(volumePath, "metadata.json")
	if err := os.WriteFile(metadataPath, metadataData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	fmt.Printf("Created volume: %s\n", volumeName)
	fmt.Printf("Driver: %s\n", driver)
	fmt.Printf("Mountpoint: %s\n", dataPath)

	return nil
}

// isVolumeInUse checks if a volume is being used by any container
func (cm *ContainerManager) isVolumeInUse(volumeName string) (bool, string, error) {
	containers, err := cm.GetContainerNames()
	if err != nil {
		return false, "", err
	}

	volumePath := filepath.Join(cm.cfg.VolumesPath, volumeName, "_data")

	for _, containerName := range containers {
		containerPath := filepath.Join(cm.cfg.ContainersPath, containerName)

		// Check container's OCI spec for volume mounts
		configPath := filepath.Join(containerPath, "config.json")
		if data, err := os.ReadFile(configPath); err == nil {
			var ociSpec struct {
				Mounts []struct {
					Source      string   `json:"source"`
					Destination string   `json:"destination"`
					Type        string   `json:"type"`
					Options     []string `json:"options"`
				} `json:"mounts"`
			}
			if json.Unmarshal(data, &ociSpec) == nil {
				for _, mount := range ociSpec.Mounts {
					if mount.Source == volumePath || mount.Source == filepath.Join(cm.cfg.VolumesPath, volumeName) {
						return true, containerName, nil
					}
				}
			}
		}

		// Also check options.json for RunOptions volumes
		optionsPath := filepath.Join(containerPath, "options.json")
		if data, err := os.ReadFile(optionsPath); err == nil {
			var runOpts RunOptions
			if json.Unmarshal(data, &runOpts) == nil {
				for _, volSpec := range runOpts.Volumes {
					if strings.Contains(volSpec, volumeName) {
						// Parse the volume spec to check if it matches our volume
						if parts := strings.SplitN(volSpec, ":", 2); len(parts) >= 2 {
							hostPath := parts[0]
							if hostPath == volumeName || hostPath == volumePath {
								return true, containerName, nil
							}
						}
					}
				}
			}
		}
	}

	return false, "", nil
}

// RemoveVolume removes a volume
func (cm *ContainerManager) RemoveVolume(volumeName string, force bool) error {
	volumePath := filepath.Join(cm.cfg.VolumesPath, volumeName)

	if _, err := os.Stat(volumePath); os.IsNotExist(err) {
		return fmt.Errorf("volume '%s' not found", volumeName)
	}

	// Check if volume is in use by any container
	if !force {
		inUse, containerName, err := cm.isVolumeInUse(volumeName)
		if err != nil {
			return fmt.Errorf("failed to check volume usage: %w", err)
		}
		if inUse {
			return fmt.Errorf("volume '%s' is in use by container '%s'. Use --force to remove", volumeName, containerName)
		}
	}

	if err := os.RemoveAll(volumePath); err != nil {
		return fmt.Errorf("failed to remove volume: %w", err)
	}

	fmt.Printf("Removed volume: %s\n", volumeName)
	return nil
}
