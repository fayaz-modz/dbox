package main

import (
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
		cli.CreateCmd(cfg, configPath),
		cli.CreateBackgroundCmd(cfg),
		cli.ListCmd(cfg),
		cli.StartCmd(cfg),
		cli.StatusCmd(cfg),
		cli.StopCmd(cfg),
		cli.RecreateCmd(cfg),
		cli.DeleteCmd(cfg),
		cli.ExecCmd(cfg),
		cli.PullCmd(cfg, configPath),
		cli.RunCmd(cfg),
		cli.RawCmd(cfg),
		cli.LogsCmd(cfg),
		cli.InfoCmd(cfg),
		cli.CleanCmd(cfg),
		cli.AttachCmd(cfg),
		cli.UsageCmd(cfg),
		cli.VolumeCmd(cfg),
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
