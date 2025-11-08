package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	. "dbox/config"
	. "dbox/container"
	. "dbox/image"
	. "dbox/runtime"
)

func PullCmd(cfg *Config, configPath string) *cobra.Command {
	var dns []string

	cmd := &cobra.Command{
		Use:   "pull [image]",
		Short: "Pull an image from a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.DNS = dns
			im := NewImageManager(cfg)
			return im.Pull(args[0], nil)
		},
	}

	cmd.Flags().StringArrayVar(&dns, "dns", []string{}, "DNS servers to use for image pulls (e.g., --dns 1.1.1.1 --dns 8.8.8.8)")

	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
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
	}

	return cmd
}

func LogsCmd(cfg *Config) *cobra.Command {
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

			if follow {
				// Check if there's already a tail process for this container
				pidFile := filepath.Join(cfg.RunPath, "logs", "."+containerName+".tail.pid")
				if pidData, err := os.ReadFile(pidFile); err == nil {
					if pid, err := strconv.Atoi(string(pidData)); err == nil {
						// Check if process is still running
						if process, err := os.FindProcess(pid); err == nil {
							if err := process.Signal(syscall.Signal(0)); err == nil {
								return fmt.Errorf("log following already active for container '%s' (PID %d)", containerName, pid)
							}
						}
					}
					// Process not running, clean up stale PID file
					os.Remove(pidFile)
				}

				// Write PID file
				if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
					return fmt.Errorf("failed to write PID file: %w", err)
				}

				// Set up signal handling for cleanup
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

				// Open log file
				file, err := os.Open(logPath)
				if err != nil {
					os.Remove(pidFile)
					return fmt.Errorf("failed to open log file: %w", err)
				}
				defer file.Close()
				defer os.Remove(pidFile)

				// Read and follow the log file
				reader := bufio.NewReader(file)
				for {
					line, err := reader.ReadString('\n')
					if err == nil {
						fmt.Print(line)
					} else if err == io.EOF {
						// Check for signal
						select {
						case <-sigChan:
							return nil
						default:
							time.Sleep(100 * time.Millisecond)
							continue
						}
					} else {
						return err
					}
				}
			} else {
				// Non-follow mode, just cat the file
				logCmd := exec.Command("cat", logPath)
				logCmd.Stdout = os.Stdout
				logCmd.Stderr = os.Stderr
				return logCmd.Run()
			}
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	return cmd
}

func RawCmd(cfg *Config) *cobra.Command {
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

func InfoCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [container-name]",
		Short: "Show configuration and runtime information",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				// Show container creation options
				containerName := args[0]
				containerPath := filepath.Join(cfg.ContainersPath, containerName)

				// Check if container exists
				if _, err := os.Stat(containerPath); os.IsNotExist(err) {
					return fmt.Errorf("container '%s' does not exist", containerName)
				}

				// Read options.json file
				optionsPath := filepath.Join(containerPath, "options.json")
				optionsData, err := os.ReadFile(optionsPath)
				if err != nil {
					return fmt.Errorf("failed to read container options: %w", err)
				}

				var opts CreateOptions
				if err := json.Unmarshal(optionsData, &opts); err != nil {
					return fmt.Errorf("failed to parse container options: %w", err)
				}

				// Display container creation options
				fmt.Printf("Container '%s' Creation Options:\n", containerName)
				fmt.Printf("  Image: %s\n", opts.Image)
				fmt.Printf("  Name: %s\n", opts.Name)

				if opts.ContainerConfig != "" {
					fmt.Printf("  Container Config: %s\n", opts.ContainerConfig)
				}

				if len(opts.Envs) > 0 {
					fmt.Printf("  Environment Variables:\n")
					for _, env := range opts.Envs {
						fmt.Printf("    %s\n", env)
					}
				}

				fmt.Printf("  No OverlayFS: %t\n", opts.NoOverlayFS)
				fmt.Printf("  Privileged: %t\n", opts.Privileged)
				fmt.Printf("  Network Namespace: %s\n", opts.NetNamespace)
				fmt.Printf("  TTY: %t\n", opts.TTY)

				if opts.InitProcess != "" {
					fmt.Printf("  Init Process: %s\n", opts.InitProcess)
				}

				if len(opts.Volumes) > 0 {
					fmt.Printf("  Volumes:\n")
					for _, vol := range opts.Volumes {
						fmt.Printf("    %s\n", vol)
					}
				}

				// Resource limits
				if opts.CPUQuota != 0 || opts.CPUPeriod != 0 || opts.MemoryLimit != 0 ||
					opts.MemorySwap != 0 || opts.CPUShares != 0 || opts.BlkioWeight != 0 {
					fmt.Printf("  Resource Limits:\n")
					if opts.CPUQuota != 0 {
						fmt.Printf("    CPU Quota: %d microseconds\n", opts.CPUQuota)
					}
					if opts.CPUPeriod != 0 {
						fmt.Printf("    CPU Period: %d microseconds\n", opts.CPUPeriod)
					}
					if opts.MemoryLimit != 0 {
						fmt.Printf("    Memory Limit: %d bytes\n", opts.MemoryLimit)
					}
					if opts.MemorySwap != 0 {
						fmt.Printf("    Memory Swap: %d bytes\n", opts.MemorySwap)
					}
					if opts.CPUShares != 0 {
						fmt.Printf("    CPU Shares: %d\n", opts.CPUShares)
					}
					if opts.BlkioWeight != 0 {
						fmt.Printf("    Block IO Weight: %d\n", opts.BlkioWeight)
					}
				}

				return nil
			} else {
				// Show general configuration (original behavior)
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
			}
		},
	}

	// Add container name completion
	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		cm := NewContainerManager(cfg)
		names, err := cm.GetContainerNames()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}

	return cmd
}

func CleanCmd(cfg *Config) *cobra.Command {
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

func AttachCmd(cfg *Config) *cobra.Command {
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

func StatusCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status [container-name]",
		Short: "Show detailed status of a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			rt := NewRuntime(cfg)

			// First check metadata for stored status (like List command does)
			metadataPath := filepath.Join(cfg.ContainersPath, name, "metadata.json")
			var status string
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata map[string]string
				if json.Unmarshal(data, &metadata) == nil {
					status = metadata["status"]
				}
			}

			// Check metadata status first for active states like CREATING and READY
			switch status {
			case StatusCreating:
				// Keep CREATING status from metadata
			case StatusReady:
				// Keep READY status from metadata
			default:
				// For other states, check runtime state for accurate status
				runtimeState, err := rt.State(name)
				if err != nil {
					// Check if container directory exists but runtime doesn't know about it
					containerPath := filepath.Join(cfg.ContainersPath, name)
					if _, statErr := os.Stat(containerPath); statErr == nil {
						status = StatusStopped
					} else {
						fmt.Printf("Container: %s\n", name)
						fmt.Printf("Status: NOT FOUND\n")
						fmt.Printf("Error: %v\n", err)
						return nil
					}
				} else {
					status = strings.ToUpper(runtimeState)
				}
			}

			fmt.Printf("Container: %s\n", name)
			fmt.Printf("Status: %s\n", status)

			// Get metadata
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
			fmt.Printf("\nUnified log file: %s\n", logPath)
			if _, err := os.Stat(logPath); err == nil {
				fmt.Println("Log contains: Container output, Runtime logs, and Dbox operations")
			}

			if status == "RUNNING" {
				fmt.Println("\nTo attach: dbox attach", name)
				fmt.Println("To view logs: dbox logs", name)
				fmt.Println("To view init logs: dbox exec", name, "cat /var/log/dbox-init.log")
			}

			return nil
		},
	}
}

func UsageCmd(cfg *Config) *cobra.Command {
	var (
		showPID    bool
		showCgroup bool
	)

	cmd := &cobra.Command{
		Use:   "usage [container-id]",
		Short: "Show CPU, memory usage and optional PID/cgroups info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.Usage(args[0], showPID, showCgroup)
		},
	}

	cmd.Flags().BoolVar(&showPID, "pid", false, "Show PID information")
	cmd.Flags().BoolVar(&showCgroup, "cgroup", false, "Show detailed cgroups information")

	return cmd
}

func CompletionCmd(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:

  $ source <(dbox completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ dbox completion bash > /etc/bash_completion.d/dbox
  # macOS:
  $ dbox completion bash > /usr/local/etc/bash_completion.d/dbox

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ dbox completion zsh > "${fpath[1]}/_dbox"

  # You will need to start a new shell for this setup to take effect.
  # Or reload completion in current session:
  $ compinit

fish:

  $ dbox completion fish | source

  # To load completions for each session, execute once:
  $ dbox completion fish > ~/.config/fish/completions/dbox.fish
`,
		DisableAutoGenTag: true,
		ValidArgs:         []string{"bash", "zsh", "fish"},
		Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	}

	// Disable config loading for completion and its subcommands
	cmd.PersistentPreRunE = nil

	bashCmd := &cobra.Command{
		Use:   "bash",
		Short: "Generate the autocompletion script for bash",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenBashCompletion(cmd.OutOrStdout())
		},
	}
	bashCmd.PersistentPreRunE = nil

	zshCmd := &cobra.Command{
		Use:   "zsh",
		Short: "Generate the autocompletion script for zsh",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenZshCompletion(cmd.OutOrStdout())
		},
	}
	zshCmd.PersistentPreRunE = nil

	fishCmd := &cobra.Command{
		Use:   "fish",
		Short: "Generate the autocompletion script for fish",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenFishCompletion(cmd.OutOrStdout(), true)
		},
	}
	fishCmd.PersistentPreRunE = nil

	cmd.AddCommand(bashCmd, zshCmd, fishCmd)

	return cmd
}
