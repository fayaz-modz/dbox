package container

import (
	. "dbox/config"
)

// mergeContainerConfigs merges container configurations with proper priority:
// default config < container config file < CLI flags
func (cm *ContainerManager) mergeContainerConfigs(containerCfg *ContainerConfig, opts *CreateOptions, runOpts *RunOptions) *ContainerConfig {
	// Start with default config
	merged := &ContainerConfig{}

	// Apply container config file (if exists)
	if containerCfg != nil {
		if containerCfg.Mounts != nil {
			merged.Mounts = append([]Mount{}, containerCfg.Mounts...)
		}
		if containerCfg.SSH != nil {
			merged.SSH = &SSH{
				Enable: containerCfg.SSH.Enable,
				Port:   containerCfg.SSH.Port,
			}
		}
		if containerCfg.User != nil {
			merged.User = &User{
				Username: containerCfg.User.Username,
				Password: containerCfg.User.Password,
				Wheel:    containerCfg.User.Wheel,
				Sudo:     containerCfg.User.Sudo,
			}
		}
		if containerCfg.Resources != nil {
			merged.Resources = &Resources{
				CPUQuota:    containerCfg.Resources.CPUQuota,
				CPUPeriod:   containerCfg.Resources.CPUPeriod,
				MemoryLimit: containerCfg.Resources.MemoryLimit,
				MemorySwap:  containerCfg.Resources.MemorySwap,
				CPUShares:   containerCfg.Resources.CPUShares,
				BlkioWeight: containerCfg.Resources.BlkioWeight,
			}
		}
	}

	// Apply CLI flags (highest priority)
	var cliOpts *CreateOptions
	if opts != nil {
		cliOpts = opts
	} else if runOpts != nil {
		cliOpts = &CreateOptions{
			CPUQuota:    runOpts.CPUQuota,
			CPUPeriod:   runOpts.CPUPeriod,
			MemoryLimit: runOpts.MemoryLimit,
			MemorySwap:  runOpts.MemorySwap,
			CPUShares:   runOpts.CPUShares,
			BlkioWeight: runOpts.BlkioWeight,
		}
	}

	if cliOpts != nil {
		// Update resources with CLI overrides
		if merged.Resources == nil {
			merged.Resources = &Resources{}
		}

		if cliOpts.CPUQuota != 0 {
			merged.Resources.CPUQuota = cliOpts.CPUQuota
		}
		if cliOpts.CPUPeriod != 0 {
			merged.Resources.CPUPeriod = cliOpts.CPUPeriod
		}
		if cliOpts.MemoryLimit != 0 {
			merged.Resources.MemoryLimit = cliOpts.MemoryLimit
		}
		if cliOpts.MemorySwap != 0 {
			merged.Resources.MemorySwap = cliOpts.MemorySwap
		}
		if cliOpts.CPUShares != 0 {
			merged.Resources.CPUShares = cliOpts.CPUShares
		}
		if cliOpts.BlkioWeight != 0 {
			merged.Resources.BlkioWeight = cliOpts.BlkioWeight
		}
	}

	return merged
}
