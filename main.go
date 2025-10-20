package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
		statusCmd(),
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
		attachCmd(),
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
	var force bool

	cmd := &cobra.Command{
		Use:   "stop [container-name]",
		Short: "Stop a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Stop(args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force stop the container")
	return cmd
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

func attachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attach [container-name]",
		Short: "Attach to a running VM container",
		Long: `Attach to a running VM-like container and get an interactive shell.
This is useful for VM containers that are running in the background.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Attach(args[0])
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [container-name]",
		Short: "Show detailed status of a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			rt := NewRuntime(cfg)

			// Get runtime state
			state, err := rt.State(name)
			if err != nil {
				fmt.Printf("Container: %s\n", name)
				fmt.Printf("Status: NOT FOUND or ERROR\n")
				fmt.Printf("Error: %v\n", err)

				// Check if it exists in filesystem
				containerPath := filepath.Join(cfg.ContainersPath, name)
				if _, statErr := os.Stat(containerPath); statErr == nil {
					fmt.Println("\nNote: Container directory exists but runtime has no record.")
					fmt.Println("This may indicate the container exited or crashed.")

					// Check logs
					logPath := filepath.Join(cfg.RunPath, "logs", name+".log")
					if _, logErr := os.Stat(logPath); logErr == nil {
						fmt.Printf("\nRecent logs from %s:\n", logPath)
						fmt.Println("---")
						tailCmd := exec.Command("tail", "-n", "20", logPath)
						tailCmd.Stdout = os.Stdout
						tailCmd.Run()
					}
				}
				return nil
			}

			fmt.Printf("Container: %s\n", name)
			fmt.Printf("Status: %s\n", strings.ToUpper(state))

			// Get metadata
			metadataPath := filepath.Join(cfg.ContainersPath, name, "metadata.json")
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata map[string]any
				if json.Unmarshal(data, &metadata) == nil {
					fmt.Printf("Image: %s\n", metadata["image"])
					if vmMode, ok := metadata["vm_mode"].(bool); ok && vmMode {
						fmt.Println("Type: VM Container")
						if vmConfig, ok := metadata["vm_config"].(map[string]any); ok {
							if enableSSH, ok := vmConfig["EnableSSH"].(bool); ok && enableSSH {
								fmt.Printf("SSH: Enabled on port %v\n", vmConfig["SSHPort"])
							}
							if hostname, ok := vmConfig["Hostname"].(string); ok && hostname != "" {
								fmt.Printf("Hostname: %s\n", hostname)
							}
						}
					}
				}
			}

			// Show log location
			logPath := filepath.Join(cfg.RunPath, "logs", name+".log")
			fmt.Printf("\nLog file: %s\n", logPath)

			if state == "running" {
				fmt.Println("\nTo attach: dbox attach", name)
				fmt.Println("To view logs: dbox logs", name)
				fmt.Println("To view init logs: dbox exec", name, "cat /var/log/dbox-init.log")
			}

			return nil
		},
	}
}
