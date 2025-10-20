package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	configPath string
	cfg        *Config
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dbox",
		Short: "A distrobox-like container management tool",
		Long:  "Manage OCI containers with crun/runc with advanced features",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return nil
		},
	}

	rootCmd.SilenceUsage = true

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
		getEnvOrDefault("DBOX_CONFIG", "/etc/dbox/config.yaml"),
		"Path to config file (or set DBOX_CONFIG env)")

	// Commands
	rootCmd.AddCommand(
		createCmd(),
		listCmd(),
		startCmd(),
		stopCmd(),
		deleteCmd(),
		execCmd(),
		pullCmd(),
		runCmd(),
		rawCmd(),
		logsCmd(),
		infoCmd(),
		setupCmd(),
		cleanCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func createCmd() *cobra.Command {
	var (
		image           string
		name            string
		containerCfg    string
		setupScript     string
		postSetupScript string
		envs            []string
		noOverlayFS     bool
	)

	cmd := &cobra.Command{
		Use:   "create [flags]",
		Short: "Create a new container",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)

			opts := &CreateOptions{
				Image:           image,
				Name:            name,
				ContainerConfig: containerCfg,
				SetupScript:     setupScript,
				PostSetupScript: postSetupScript,
			}

			return cm.Create(opts)
		},
	}

	cmd.Flags().StringVarP(&image, "image", "i", "", "Image to use (e.g., alpine:latest)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Container name")
	cmd.Flags().StringVar(&containerCfg, "container-config", "", "Path to container_config.json")
	cmd.Flags().StringVar(&setupScript, "setup-script", "", "Setup script to run during creation")
	cmd.Flags().StringVar(&postSetupScript, "post-setup-script", "", "Setup script to run after creation")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Set environment variables (e.g., -e FOO=bar)")
	cmd.Flags().BoolVar(&noOverlayFS, "no-overlayfs", false, "Disable OverlayFS and copy the rootfs (slower, but works on filesystems without overlay support)")
	cmd.MarkFlagRequired("image")
	cmd.MarkFlagRequired("name")

	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all containers",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.List()
		},
	}
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [container-name]",
		Short: "Start a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Start(args[0])
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [container-name]",
		Short: "Stop a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Stop(args[0])
		},
	}
}

func deleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete [container-name]",
		Short:   "Delete a container",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Delete(args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete running container")
	return cmd
}

func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec [container-name] [command...]",
		Short: "Execute a command in a container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Exec(args[0], args[1:])
		},
	}
}

func pullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull [image]",
		Short: "Pull an image from a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			im := NewImageManager(cfg)
			return im.Pull(args[0])
		},
	}
}

func runCmd() *cobra.Command {
	var (
		image        string
		name         string
		containerCfg string
		envs         []string
		detach       bool
		autoRemove   bool
		volumes      []string
		noOverlayFS  bool
	)

	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Run a command in a new container (similar to docker run)",
		Long:  "Creates and starts a container in one step. By default, it runs in the foreground. Use -d to detach.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)

			// The command to run inside the container can be passed after flags
			// Example: dbox run -i ubuntu -- /bin/echo "hello"
			// This part is an advanced feature, for now we'll use the image's default command.

			opts := &RunOptions{
				Image:           image,
				Name:            name,
				ContainerConfig: containerCfg,
				Envs:            envs,
				Detach:          detach,
				AutoRemove:      autoRemove,
				NoOverlayFS:     noOverlayFS,
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
	cmd.MarkFlagRequired("image")

	return cmd
}

func logsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs [container-name]",
		Short: "Fetch the logs of a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerName := args[0]
			logPath := filepath.Join(cfg.RunPath, "logs", containerName+".log")

			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				return fmt.Errorf("no logs found for container '%s' at %s", containerName, logPath)
			}

			var logCmd *exec.Cmd

			if follow {
				logCmd = exec.Command("tail", "-f", logPath)
			} else {
				logCmd = exec.Command("cat", logPath)
			}

			logCmd.Stdout = os.Stdout
			logCmd.Stderr = os.Stderr

			return logCmd.Run()
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	return cmd
}

func rawCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "raw [runtime-args...]",
		Short: "Run raw runtime commands (proxy to crun/runc)",
		Long:  "Directly proxies commands and arguments to the underlying OCI runtime (e.g., crun). Useful for advanced debugging.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt := NewRuntime(cfg)
			return rt.RunRaw(args)
		},
	}
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show configuration and runtime information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Configuration:\n")
			fmt.Printf("  Runtime: %s\n", cfg.Runtime)
			fmt.Printf("  Run Path: %s\n", cfg.RunPath)
			fmt.Printf("  Containers Path: %s\n", cfg.ContainersPath)

			rt := NewRuntime(cfg)
			version, err := rt.Version()
			if err != nil {
				fmt.Printf("  Runtime Version: error - %v\n", err)
			} else {
				fmt.Printf("  Runtime Version: %s\n", version)
			}

			return nil
		},
	}
}

func setupCmd() *cobra.Command {
	var scriptPath string

	cmd := &cobra.Command{
		Use:   "setup [container-name]",
		Short: "Run a setup script in an existing container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.RunSetupScript(args[0], scriptPath)
		},
	}

	cmd.Flags().StringVarP(&scriptPath, "script", "s", "", "Path to setup script")
	cmd.MarkFlagRequired("script")

	return cmd
}

func cleanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Delete the local image cache",
		Long:  "Removes the entire local image cache directory, forcing images to be re-pulled on next use.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			im := NewImageManager(cfg)
			return im.CleanCache()
		},
	}
	return cmd
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
