package main

import (
	"github.com/spf13/cobra"

	. "dbox/container"
)

func volumeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "volume",
		Short: "Manage volumes",
		Long:  "Manage container volumes and mounts",
	}

	cmd.AddCommand(
		volumeListCmd(),
		volumeInspectCmd(),
		volumeCreateCmd(),
		volumeRemoveCmd(),
	)

	return cmd
}

func volumeListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Short:   "List volumes",
		Aliases: []string{"list"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.ListVolumes()
		},
	}

	return cmd
}

func volumeInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [volume-name]",
		Short: "Display detailed information on one or more volumes",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			for _, volumeName := range args {
				if err := cm.InspectVolume(volumeName); err != nil {
					return err
				}
			}
			return nil
		},
	}

	return cmd
}

func volumeCreateCmd() *cobra.Command {
	var (
		driver string
		opts   []string
	)

	cmd := &cobra.Command{
		Use:   "create [volume-name]",
		Short: "Create a volume",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			return cm.CreateVolume(args[0], driver, opts)
		},
	}

	cmd.Flags().StringVar(&driver, "driver", "local", "Volume driver to use")
	cmd.Flags().StringArrayVar(&opts, "opt", []string{}, "Set driver specific options")

	return cmd
}

func volumeRemoveCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "rm [volume-name...]",
		Short:   "Remove one or more volumes",
		Aliases: []string{"remove"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := NewContainerManager(cfg)
			for _, volumeName := range args {
				if err := cm.RemoveVolume(volumeName, force); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force the removal of one or more volumes")

	return cmd
}
