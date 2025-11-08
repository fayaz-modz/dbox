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
	cfg *Config
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

			// Get flag values from command
			configPath, _ := cmd.Flags().GetString("config")
			verbose, _ := cmd.Flags().GetBool("verbose")
			jsonOutput, _ := cmd.Flags().GetBool("json")

			var err error
			cfg, err = LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Store config and flags in command context
			ctx := context.WithValue(cmd.Context(), "config", cfg)
			ctx = context.WithValue(ctx, "verbose", verbose)
			ctx = context.WithValue(ctx, "json", jsonOutput)
			cmd.SetContext(ctx)
			return nil
		},
	}

	rootCmd.SilenceUsage = true

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c",
		getEnvOrDefault("DBOX_CONFIG", "/etc/dbox/config.yaml"),
		"Path to config file (or set DBOX_CONFIG env)")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output with debug messages")
	rootCmd.PersistentFlags().Bool("json", false, "Output in JSON format for data commands")

	// Commands
	rootCmd.AddCommand(
		cli.CreateCmd(""),
		cli.CreateBackgroundCmd(),
		cli.ListCmd(),
		cli.StartCmd(),
		cli.StatusCmd(),
		cli.StopCmd(),
		cli.RecreateCmd(),
		cli.DeleteCmd(),
		cli.ExecCmd(),
		cli.PullCmd(""),
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
