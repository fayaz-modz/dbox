package container

import (
	"dbox/config"
	"dbox/image"
	"dbox/runtime"
)

type ContainerManager struct {
	cfg     *config.Config
	runtime *runtime.Runtime
	imgMgr  *image.ImageManager
}

type CreateOptions struct {
	Image           string
	Name            string
	ContainerConfig string
	Envs            []string
	Volumes         []string
	NoOverlayFS     bool
	CPUQuota        int64
	CPUPeriod       int64
	MemoryLimit     int64
	MemorySwap      int64
	CPUShares       int64
	BlkioWeight     uint16
	InitProcess     string
	Privileged      bool
	NetNamespace    string
	TTY             bool
}

type RunOptions struct {
	Image           string
	Name            string
	ContainerConfig string
	Envs            []string
	Detach          bool
	AutoRemove      bool
	Volumes         []string
	Command         []string
	NoOverlayFS     bool
	CPUQuota        int64
	CPUPeriod       int64
	MemoryLimit     int64
	MemorySwap      int64
	CPUShares       int64
	BlkioWeight     uint16
	InitProcess     string
	Privileged      bool
	NetNamespace    string
	TTY             bool
}

type RecreateOptions struct {
	Name            string
	Image           string
	ContainerConfig string
	Envs            []string
	Volumes         []string
	CPUQuota        int64
	CPUPeriod       int64
	MemoryLimit     int64
	MemorySwap      int64
	CPUShares       int64
	BlkioWeight     uint16
	InitProcess     string
	Privileged      bool
	NetNamespace    string
	TTY             bool
}
