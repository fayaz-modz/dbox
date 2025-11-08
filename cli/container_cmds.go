package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	. "dbox/config"
	. "dbox/container"
	. "dbox/image"
	. "dbox/logger"
)

func ListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all containers",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)
			return cm.List()
		},
	}
}

func CreateCmd(configPath string) *cobra.Command {
	var (
		image        string
		name         string
		containerCfg string
		envs         []string
		volumes      []string
		noOverlayFS  bool
		detach       bool
		dns          []string
		cpuQuota     int64
		cpuPeriod    int64
		memoryLimit  int64
		memorySwap   int64
		cpuShares    int64
		blkioWeight  uint16
		initProcess  string
		privileged   bool
		netNamespace string
		tty          bool
	)

	cmd := &cobra.Command{
		Use:   "create [flags]",
		Short: "Create a new container",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := cmd.Context().Value("config").(*Config)
			config.DNS = dns
			cm := NewContainerManager(config)

			opts := &CreateOptions{
				Image:           image,
				Name:            name,
				ContainerConfig: containerCfg,
				Envs:            envs,
				Volumes:         volumes,
				NoOverlayFS:     noOverlayFS,
				CPUQuota:        cpuQuota,
				CPUPeriod:       cpuPeriod,
				MemoryLimit:     memoryLimit,
				MemorySwap:      memorySwap,
				CPUShares:       cpuShares,
				BlkioWeight:     blkioWeight,
				InitProcess:     initProcess,
				Privileged:      privileged,
				NetNamespace:    netNamespace,
				TTY:             tty,
			}

			return cm.Create(opts, detach)
		},
	}

	cmd.Flags().StringVarP(&image, "image", "i", "", "Image to use (e.g., alpine:latest)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Container name")
	cmd.Flags().StringVar(&containerCfg, "container-config", "", "Path to container_config.json")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Set environment variables (e.g., -e FOO=bar)")
	cmd.Flags().BoolVar(&noOverlayFS, "no-overlayfs", false, "Disable OverlayFS and copy the rootfs (slower, but works on filesystems without overlay support)")
	cmd.Flags().StringArrayVar(&dns, "dns", []string{}, "DNS servers to use for image pulls (e.g., --dns 1.1.1.1 --dns 8.8.8.8)")
	cmd.Flags().Int64Var(&cpuQuota, "cpu-quota", 0, "CPU quota in microseconds (e.g., 50000 for 5% CPU)")
	cmd.Flags().Int64Var(&cpuPeriod, "cpu-period", 0, "CPU period in microseconds (default 100000)")
	cmd.Flags().Int64Var(&memoryLimit, "memory", 0, "Memory limit in bytes (e.g., 512m, 1g)")
	cmd.Flags().Int64Var(&memorySwap, "memory-swap", 0, "Memory+swap limit in bytes")
	cmd.Flags().Int64Var(&cpuShares, "cpu-shares", 0, "CPU shares (relative weight, 1024 default)")
	cmd.Flags().Uint16Var(&blkioWeight, "blkio-weight", 0, "Block IO weight (10-1000)")
	cmd.Flags().StringVar(&initProcess, "init", "", "Override init process (e.g., /sbin/init)")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Run container in privileged mode")
	cmd.Flags().StringVar(&netNamespace, "net", "host", "Network namespace (host, none, or container:name)")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY for interactive sessions")
	cmd.Flags().StringArrayVarP(&volumes, "volume", "v", []string{}, "Bind mount a volume (e.g., /host/path:/container/path or volume-name:/container/path)")
	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run container creation in background and log to file")

	cmd.RegisterFlagCompletionFunc("image", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var config *Config
		var err error
		config, err = LoadConfig(configPath)
		if err != nil {
			// Try local config.yaml
			config, err = LoadConfig("config.yaml")
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		}
		im := NewImageManager(config)
		images, err := im.List()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		// Convert sanitized names back to approximate image refs
		var imageRefs []string
		for _, img := range images {
			ref := strings.ReplaceAll(img, "_", "/")
			if lastSlash := strings.LastIndex(ref, "/"); lastSlash != -1 {
				ref = ref[:lastSlash] + ":" + ref[lastSlash+1:]
			}
			imageRefs = append(imageRefs, ref)
		}
		return imageRefs, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.MarkFlagRequired("image")
	cmd.MarkFlagRequired("name")

	return cmd
}

func CreateBackgroundCmd() *cobra.Command {
	var (
		name         string
		image        string
		logPath      string
		containerCfg string
		envs         []string
		noOverlayFS  bool
		dns          []string
		cpuQuota     int64
		cpuPeriod    int64
		memoryLimit  int64
		memorySwap   int64
		cpuShares    int64
		blkioWeight  uint16
		initProcess  string
		privileged   bool
		netNamespace string
		tty          bool
	)

	cmd := &cobra.Command{
		Use:    "create-background [flags]",
		Short:  "Internal command for background container creation",
		Hidden: true, // Hide from help
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)

			opts := &CreateOptions{
				Image:           image,
				Name:            name,
				ContainerConfig: containerCfg,
				Envs:            envs,
				NoOverlayFS:     noOverlayFS,
				CPUQuota:        cpuQuota,
				CPUPeriod:       cpuPeriod,
				MemoryLimit:     memoryLimit,
				MemorySwap:      memorySwap,
				CPUShares:       cpuShares,
				BlkioWeight:     blkioWeight,
				InitProcess:     initProcess,
				Privileged:      privileged,
				NetNamespace:    netNamespace,
				TTY:             tty,
			}

			// Create logger and run the actual creation
			logger := NewDboxLogger(logPath)
			defer logger.Close()

			// Clean up creation PID file when done
			pidFile := filepath.Join(cfg.RunPath, "logs", "."+name+".create.pid")
			defer os.Remove(pidFile)

			logger.Log(fmt.Sprintf("Creating container '%s' from image '%s'", name, image))

			if err := cm.CreateContainer(opts, logger); err != nil {
				logger.Log(fmt.Sprintf("Failed to create container '%s': %v", name, err))
				return err
			}

			logger.Log(fmt.Sprintf("Successfully created container '%s'", name))
			return nil
		},
	}

	// Flags (matching createCmd)
	cmd.Flags().StringVarP(&image, "image", "i", "", "Image to use (e.g., alpine:latest)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Container name")
	cmd.Flags().StringVar(&containerCfg, "container-config", "", "Path to container_config.json")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Set environment variables (e.g., -e FOO=bar)")
	cmd.Flags().BoolVar(&noOverlayFS, "no-overlayfs", false, "Disable OverlayFS and copy the rootfs (slower, but works on filesystems without overlay support)")
	cmd.Flags().StringArrayVar(&dns, "dns", []string{}, "DNS servers to use for image pulls (e.g., --dns 1.1.1.1 --dns 8.8.8.8)")
	cmd.Flags().Int64Var(&cpuQuota, "cpu-quota", 0, "CPU quota in microseconds (e.g., 50000 for 5% CPU)")
	cmd.Flags().Int64Var(&cpuPeriod, "cpu-period", 0, "CPU period in microseconds (default 100000)")
	cmd.Flags().Int64Var(&memoryLimit, "memory", 0, "Memory limit in bytes (e.g., 512m, 1g)")
	cmd.Flags().Int64Var(&memorySwap, "memory-swap", 0, "Memory+swap limit in bytes")
	cmd.Flags().Int64Var(&cpuShares, "cpu-shares", 0, "CPU shares (relative weight, 1024 default)")
	cmd.Flags().Uint16Var(&blkioWeight, "blkio-weight", 0, "Block IO weight (10-1000)")
	cmd.Flags().StringVar(&initProcess, "init", "", "Override init process (e.g., /sbin/init)")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Run container in privileged mode")
	cmd.Flags().StringVar(&netNamespace, "net", "host", "Network namespace (host, none, or container:name)")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY for interactive sessions")
	cmd.Flags().StringVar(&logPath, "log-path", "", "Path to log file")

	cmd.MarkFlagRequired("image")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("log-path")

	return cmd
}

func StartCmd() *cobra.Command {
	var detach bool

	cmd := &cobra.Command{
		Use:   "start [container-name]",
		Short: "Start a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)
			return cm.Start(args[0], detach)
		},
	}

	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run container in background (default is foreground)")
	return cmd
}

func StopCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "stop [container-name]",
		Short: "Stop a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)
			return cm.Stop(args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force stop the container")
	return cmd
}

func RecreateCmd() *cobra.Command {
	var (
		image        string
		containerCfg string
		envs         []string
		volumes      []string
		dns          []string
		cpuQuota     int64
		cpuPeriod    int64
		memoryLimit  int64
		memorySwap   int64
		cpuShares    int64
		blkioWeight  uint16
		initProcess  string
		privileged   bool
		netNamespace string
		tty          bool
	)

	cmd := &cobra.Command{
		Use:   "recreate [container-name]",
		Short: "Recreate a container (fixes stopped containers that won't start)",
		Long:  "Recreates a container using original settings, with optional overrides from flags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cfg.DNS = dns
			cm := NewContainerManager(cfg)

			opts := &RecreateOptions{
				Name:            args[0],
				Image:           image,
				ContainerConfig: containerCfg,
				Envs:            envs,
				Volumes:         volumes,
				CPUQuota:        cpuQuota,
				CPUPeriod:       cpuPeriod,
				MemoryLimit:     memoryLimit,
				MemorySwap:      memorySwap,
				CPUShares:       cpuShares,
				BlkioWeight:     blkioWeight,
				InitProcess:     initProcess,
				Privileged:      privileged,
				NetNamespace:    netNamespace,
				TTY:             tty,
			}

			return cm.RecreateWithOptions(opts)
		},
	}

	// Flags
	cmd.Flags().StringVarP(&image, "image", "i", "", "Override image (e.g., alpine:latest)")
	cmd.Flags().StringVar(&containerCfg, "container-config", "", "Override container_config.json")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Override environment variables (e.g., -e FOO=bar)")
	cmd.Flags().StringArrayVarP(&volumes, "volume", "v", []string{}, "Override volume mounts (e.g., -v /host/path:/container/path or volume-name:/container/path)")
	cmd.Flags().StringArrayVar(&dns, "dns", []string{}, "DNS servers to use for image pulls (e.g., --dns 1.1.1.1 --dns 8.8.8.8)")
	cmd.Flags().Int64Var(&cpuQuota, "cpu-quota", 0, "Override CPU quota in microseconds")
	cmd.Flags().Int64Var(&cpuPeriod, "cpu-period", 0, "Override CPU period in microseconds")
	cmd.Flags().Int64Var(&memoryLimit, "memory", 0, "Override memory limit in bytes")
	cmd.Flags().Int64Var(&memorySwap, "memory-swap", 0, "Override memory+swap limit in bytes")
	cmd.Flags().Int64Var(&cpuShares, "cpu-shares", 0, "Override CPU shares")
	cmd.Flags().Uint16Var(&blkioWeight, "blkio-weight", 0, "Override block IO weight")
	cmd.Flags().StringVar(&initProcess, "init", "", "Override init process")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Override privileged mode")
	cmd.Flags().StringVar(&netNamespace, "net", "host", "Override network namespace")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Override TTY devices allocation")

	return cmd
}

func ExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec [container-name] [command...]",
		Short: "Execute a command in a container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)
			return cm.Exec(args[0], args[1:])
		},
	}
}

func RunCmd() *cobra.Command {
	var (
		image        string
		name         string
		containerCfg string
		envs         []string
		detach       bool
		autoRemove   bool
		volumes      []string
		noOverlayFS  bool
		dns          []string
		cpuQuota     int64
		cpuPeriod    int64
		memoryLimit  int64
		memorySwap   int64
		cpuShares    int64
		blkioWeight  uint16
		initProcess  string
		privileged   bool
		netNamespace string
		tty          bool
	)

	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Run a command in a new container (similar to docker run)",
		Long:  "Creates and starts a container in one step. By default, it runs in the foreground. Use -d to detach.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cfg.DNS = dns
			cm := NewContainerManager(cfg)

			opts := &RunOptions{
				Image:           image,
				Name:            name,
				ContainerConfig: containerCfg,
				Envs:            envs,
				Detach:          detach,
				AutoRemove:      autoRemove,
				Volumes:         volumes,
				Command:         args,
				NoOverlayFS:     noOverlayFS,
				CPUQuota:        cpuQuota,
				CPUPeriod:       cpuPeriod,
				MemoryLimit:     memoryLimit,
				MemorySwap:      memorySwap,
				CPUShares:       cpuShares,
				BlkioWeight:     blkioWeight,
				InitProcess:     initProcess,
				Privileged:      privileged,
				NetNamespace:    netNamespace,
				TTY:             tty,
			}

			return cm.Run(opts)
		},
	}

	cmd.Flags().StringVarP(&image, "image", "i", "", "Image to use (e.g., ubuntu:latest)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Assign a name to the container")
	cmd.Flags().StringVar(&containerCfg, "container-config", "", "Path to container_config.json for mounts etc.")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Set environment variables (e.g., -e FOO=bar)")
	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run container in background and print container ID")
	cmd.Flags().BoolVar(&autoRemove, "rm", false, "Automatically remove the container when it exits (only in foreground mode)")
	cmd.Flags().StringArrayVarP(&volumes, "volume", "v", []string{}, "Bind mount a volume (e.g., /host/path:/container/path)")
	cmd.Flags().BoolVar(&noOverlayFS, "no-overlayfs", false, "Disable OverlayFS and copy the rootfs (slower, but works on filesystems without overlay support)")
	cmd.Flags().StringArrayVar(&dns, "dns", []string{}, "DNS servers to use for image pulls (e.g., --dns 1.1.1.1 --dns 8.8.8.8)")
	cmd.Flags().Int64Var(&cpuQuota, "cpu-quota", 0, "CPU quota in microseconds (e.g., 50000 for 5% CPU)")
	cmd.Flags().Int64Var(&cpuPeriod, "cpu-period", 0, "CPU period in microseconds (default 100000)")
	cmd.Flags().Int64Var(&memoryLimit, "memory", 0, "Memory limit in bytes (e.g., 512m, 1g)")
	cmd.Flags().Int64Var(&memorySwap, "memory-swap", 0, "Memory+swap limit in bytes")
	cmd.Flags().Int64Var(&cpuShares, "cpu-shares", 0, "CPU shares (relative weight, 1024 default)")
	cmd.Flags().Uint16Var(&blkioWeight, "blkio-weight", 0, "Block IO weight (10-1000)")
	cmd.Flags().StringVar(&initProcess, "init", "", "Override init process (e.g., /sbin/init)")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Run container in privileged mode")
	cmd.Flags().StringVar(&netNamespace, "net", "host", "Network namespace (host, none, or container:name)")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY for interactive sessions")
	cmd.MarkFlagRequired("image")

	return cmd
}

func DeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete [container-name]",
		Short:   "Delete a container",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			cm := NewContainerManager(cfg)
			return cm.Delete(args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete running container")
	return cmd
}
