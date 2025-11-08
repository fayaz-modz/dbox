package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"dbox/cli"
	. "dbox/config"
)

var (
	configPath string
	verbose    bool
	cfg        *Config
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dbox",
		Short: "A distrobox-like container management tool",
		Long:  "Manage OCI containers with crun/runc with advanced features",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip config loading for completion command
			if cmd.Name() == "completion" || cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
				return nil
			}
			var err error
			cfg, err = LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			// Store config in command context
			cmd.SetContext(context.WithValue(cmd.Context(), "config", cfg))
			return nil
		},
	}

	rootCmd.SilenceUsage = true

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
		getEnvOrDefault("DBOX_CONFIG", "/etc/dbox/config.yaml"),
		"Path to config file (or set DBOX_CONFIG env)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output with debug messages")

	// Commands
	rootCmd.AddCommand(
		cli.CreateCmd(configPath),
		cli.CreateBackgroundCmd(),
		cli.ListCmd(),
		cli.StartCmd(),
		cli.StatusCmd(),
		cli.StopCmd(),
		cli.RecreateCmd(),
		cli.DeleteCmd(),
		cli.ExecCmd(),
		cli.PullCmd(configPath),
		cli.RunCmd(),
		cli.RawCmd(),
		cli.LogsCmd(),
		cli.InfoCmd(),
		cli.CleanCmd(),
		cli.AttachCmd(),
		cli.UsageCmd(),
		cli.VolumeCmd(),
		cli.CompletionCmd(rootCmd),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
