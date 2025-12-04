package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	. "dbox/config"
	. "dbox/image"
	. "dbox/utils"
)

func ImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Manage images",
		Long:  "List, remove, and manage container images",
	}

	cmd.AddCommand(ImageLsCmd())
	cmd.AddCommand(ImageRmCmd())

	return cmd
}

func ImageLsCmd() *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List images",
		Long:  "List all downloaded images with their usage information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			ctx := cmd.Context()
			im := NewImageManager(cfg)

			images, err := im.ListDetailed()
			if err != nil {
				return fmt.Errorf("failed to list images: %w", err)
			}

			if len(images) == 0 {
				if quiet {
					return nil
				}
				PrintEmptyState("images")
				return nil
			}

			if quiet {
				for _, img := range images {
					fmt.Println(img.FullName)
				}
				return nil
			}

			if IsJSONMode(ctx) {
				return PrintJSONData(images)
			}

			// Use table formatter for normal output
			tf := NewTableFormatter()
			tf.AddHeader("image", "size", "created", "used_by")

			for _, img := range images {
				usedBy := ""
				if len(img.UsedBy) > 0 {
					usedBy = strings.Join(img.UsedBy, ", ")
				} else if img.InUse {
					usedBy = "in use"
				}
				tf.AddRow(img.FullName, img.Size, img.Created, usedBy)
			}

			return tf.Render()
		},
	}

	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Only show image names")

	return cmd
}

func ImageRmCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "rm [image...]",
		Short: "Remove one or more images",
		Long:  "Remove specified images. Use --force to remove images that are in use",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cmd.Context().Value("config").(*Config)
			im := NewImageManager(cfg)

			// Get detailed image information to check usage
			images, err := im.ListDetailed()
			if err != nil {
				return fmt.Errorf("failed to list images: %w", err)
			}

			// Create a map for quick lookup
			imageMap := make(map[string]*ImageInfo)
			for i := range images {
				imageMap[images[i].FullName] = &images[i]
				imageMap[images[i].Name] = &images[i] // Also allow short name lookup
			}

			var removedImages []string
			var errors []string

			for _, imageName := range args {
				imgInfo, exists := imageMap[imageName]
				if !exists {
					errors = append(errors, fmt.Sprintf("image '%s' not found", imageName))
					continue
				}

				// Check if image is in use
				if len(imgInfo.UsedBy) > 0 && !force {
					errors = append(errors, fmt.Sprintf("image '%s' is used by containers: %v (use --force to remove)", imageName, imgInfo.UsedBy))
					continue
				}

				if imgInfo.InUse && !force {
					errors = append(errors, fmt.Sprintf("image '%s' is currently in use (use --force to remove)", imageName))
					continue
				}

				// Remove the image
				if err := im.RemoveImage(imgInfo.Name); err != nil {
					errors = append(errors, fmt.Sprintf("failed to remove image '%s': %v", imageName, err))
					continue
				}

				removedImages = append(removedImages, imageName)
			}

			// Print results
			if len(removedImages) > 0 {
				for _, img := range removedImages {
					fmt.Printf("Removed: %s\n", img)
				}
			}

			if len(errors) > 0 {
				fmt.Println()
				for _, err := range errors {
					fmt.Printf("Error: %s\n", err)
				}
				return fmt.Errorf("encountered %d errors during image removal", len(errors))
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force removal of images in use")

	// Add completion for image names
	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg := cmd.Context().Value("config").(*Config)
		im := NewImageManager(cfg)
		images, err := im.ListDetailed()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var names []string
		for _, img := range images {
			names = append(names, img.FullName)
			names = append(names, img.Name)
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}

	return cmd
}
