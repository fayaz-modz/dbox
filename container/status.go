package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (cm *ContainerManager) updateContainerStatus(containerName, status string) error {
	metadataPath := filepath.Join(cm.cfg.ContainersPath, containerName, "metadata.json")

	// Read existing metadata
	var metadata map[string]string
	if data, err := os.ReadFile(metadataPath); err == nil {
		json.Unmarshal(data, &metadata)
	} else {
		metadata = make(map[string]string)
	}

	// Update status
	metadata["status"] = status

	// Write back metadata
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataPath, data, 0644)
}

func (cm *ContainerManager) getContainerStatus(containerName string) (string, error) {
	metadataPath := filepath.Join(cm.cfg.ContainersPath, containerName, "metadata.json")

	// Read metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return "", err
	}

	var metadata map[string]string
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", err
	}

	status, exists := metadata["status"]
	if !exists {
		return "", fmt.Errorf("status not found in metadata")
	}

	return status, nil
}
