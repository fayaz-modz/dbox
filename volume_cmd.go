package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func volumeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "volume",
		Short: "Manage volumes",
		Long:  "Manage container volumes and mounts",
	}

	cmd.AddCommand(
		volumeListCmd(),
		volumeInspectCmd(),
		volumeCreateCmd(),
		volumeRemoveCmd(),
	)

	return cmd
}

func volumeListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Short:   "List volumes",
		Aliases: []string{"list"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.ListVolumes()
		},
	}

	return cmd
}

func volumeInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [volume-name]",
		Short: "Display detailed information on one or more volumes",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			for _, volumeName := range args {
				if err := cm.InspectVolume(volumeName); err != nil {
					return err
				}
			}
			return nil
		},
	}

	return cmd
}

func volumeCreateCmd() *cobra.Command {
	var (
		driver string
		opts   []string
	)

	cmd := &cobra.Command{
		Use:   "create [volume-name]",
		Short: "Create a volume",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.CreateVolume(args[0], driver, opts)
		},
	}

	cmd.Flags().StringVar(&driver, "driver", "local", "Volume driver to use")
	cmd.Flags().StringArrayVar(&opts, "opt", []string{}, "Set driver specific options")

	return cmd
}

func volumeRemoveCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "rm [volume-name...]",
		Short:   "Remove one or more volumes",
		Aliases: []string{"remove"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			for _, volumeName := range args {
				if err := cm.RemoveVolume(volumeName, force); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force the removal of one or more volumes")

	return cmd
}

// Volume management methods to be added to ContainerManager

// ListVolumes lists all volumes
func (cm *ContainerManager) ListVolumes() error {
	volumesPath := cm.cfg.VolumesPath

	if _, err := os.Stat(volumesPath); os.IsNotExist(err) {
		fmt.Println("No volumes found")
		return nil
	}

	entries, err := os.ReadDir(volumesPath)
	if err != nil {
		return fmt.Errorf("failed to read volumes directory: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No volumes found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "VOLUME NAME\tDRIVER\tMOUNTPOINT")

	for _, entry := range entries {
		if entry.IsDir() {
			volumePath := filepath.Join(volumesPath, entry.Name())
			metadataPath := filepath.Join(volumePath, "metadata.json")

			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata struct {
					Name       string `json:"name"`
					Driver     string `json:"driver"`
					Mountpoint string `json:"mountpoint"`
				}
				if json.Unmarshal(data, &metadata) == nil {
					fmt.Fprintf(w, "%s\t%s\t%s\n", metadata.Name, metadata.Driver, metadata.Mountpoint)
				}
			} else {
				// Fallback for volumes without metadata
				dataPath := filepath.Join(volumePath, "_data")
				fmt.Fprintf(w, "%s\tlocal\t%s\n", entry.Name(), dataPath)
			}
		}
	}

	w.Flush()
	return nil
}

// InspectVolume displays detailed information about a volume
func (cm *ContainerManager) InspectVolume(volumeName string) error {
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
			fmt.Printf("{\n")
			fmt.Printf("  \"name\": \"%s\",\n", metadata.Name)
			fmt.Printf("  \"driver\": \"%s\",\n", metadata.Driver)
			fmt.Printf("  \"created_at\": \"%s\",\n", metadata.CreatedAt)
			fmt.Printf("  \"mountpoint\": \"%s\"\n", metadata.Mountpoint)
			fmt.Printf("}\n")
		}
	} else {
		// Fallback for volumes without metadata
		dataPath := filepath.Join(volumePath, "_data")
		fmt.Printf("{\n")
		fmt.Printf("  \"name\": \"%s\",\n", volumeName)
		fmt.Printf("  \"driver\": \"local\",\n")
		fmt.Printf("  \"mountpoint\": \"%s\"\n", dataPath)
		fmt.Printf("}\n")
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
