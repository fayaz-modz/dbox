package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// VolumeMount represents a parsed volume mount configuration
type VolumeMount struct {
	HostPath      string
	ContainerPath string
	Options       []string
}

// ParseVolume parses a volume specification string in the format "host-path:container-path[:options]"
// host-path can be either a absolute path or a volume name
func ParseVolume(volumeSpec string, cfg *Config) (*VolumeMount, error) {
	parts := strings.SplitN(volumeSpec, ":", 3)

	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid volume format: %s. Must be host-path:container-path[:options]", volumeSpec)
	}

	hostPath := parts[0]
	containerPath := parts[1]

	// Check if hostPath is a volume name (not an absolute path)
	if !strings.HasPrefix(hostPath, "/") {
		// It's a volume name, resolve it to the actual path
		volumePath := filepath.Join(cfg.VolumesPath, hostPath, "_data")
		if _, err := os.Stat(volumePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("volume '%s' not found", hostPath)
		}
		hostPath = volumePath
	}

	var options []string
	if len(parts) == 3 {
		options = strings.Split(parts[2], ",")
	} else {
		// Default options for bind mounts
		options = []string{"bind", "rw"}
	}

	return &VolumeMount{
		HostPath:      hostPath,
		ContainerPath: containerPath,
		Options:       options,
	}, nil
}

// ParseVolumes parses multiple volume specifications
func ParseVolumes(volumeSpecs []string, cfg *Config) ([]*VolumeMount, error) {
	var volumes []*VolumeMount

	for _, volSpec := range volumeSpecs {
		volume, err := ParseVolume(volSpec, cfg)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// ToOCIMount converts a VolumeMount to an OCI spec mount
func (v *VolumeMount) ToOCIMount() specs.Mount {
	return specs.Mount{
		Destination: v.ContainerPath,
		Source:      v.HostPath,
		Type:        "bind",
		Options:     v.Options,
	}
}

// ToOCIMounts converts a slice of VolumeMounts to OCI spec mounts
func ToOCIMounts(volumes []*VolumeMount) []specs.Mount {
	var mounts []specs.Mount
	for _, volume := range volumes {
		mounts = append(mounts, volume.ToOCIMount())
	}
	return mounts
}

// ApplyVolumesToSpec applies volume mounts to an OCI spec
func ApplyVolumesToSpec(ociSpec *specs.Spec, volumeSpecs []string, cfg *Config) error {
	if len(volumeSpecs) == 0 {
		return nil
	}

	volumes, err := ParseVolumes(volumeSpecs, cfg)
	if err != nil {
		return err
	}

	ociSpec.Mounts = append(ociSpec.Mounts, ToOCIMounts(volumes)...)
	return nil
}
