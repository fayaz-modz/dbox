package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type ImageManager struct {
	cfg *Config
}

type progressReader struct {
	io.ReadCloser
	mu      sync.Mutex
	current int64
	total   int64
	prefix  string
}

// Read overrides the underlying Read method to update and print progress.
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.ReadCloser.Read(p)

	pr.mu.Lock()
	pr.current += int64(n)
	pr.printProgress()
	pr.mu.Unlock()

	return
}

// printProgress displays the download progress bar.
func (pr *progressReader) printProgress() {
	if pr.total <= 0 {
		return // Don't display if total size is unknown
	}

	percentage := float64(pr.current) / float64(pr.total) * 100
	barWidth := 40
	completedWidth := int(float64(barWidth) * (float64(pr.current) / float64(pr.total)))

	bar := strings.Repeat("=", completedWidth) + strings.Repeat(" ", barWidth-completedWidth)

	// Use carriage return `\r` to stay on the same line.
	fmt.Printf("\r%s [%s] %.2f%% (%s / %s)",
		pr.prefix,
		bar,
		percentage,
		formatBytes(uint64(pr.current)),
		formatBytes(uint64(pr.total)),
	)

	// When download is complete, print a newline to move to the next line.
	if pr.current >= pr.total {
		fmt.Println()
	}
}

// formatBytes is a helper to convert bytes to a human-readable string (KB, MB, GB).
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func NewImageManager(cfg *Config) *ImageManager {
	return &ImageManager{cfg: cfg}
}

type progressTransport struct {
	underlying http.RoundTripper
}

// RoundTrip is the core of the transport. It intercepts the request, gets the response,
// and wraps the response body with our progressReader if it's a layer blob.
func (pt *progressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := pt.underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// We only want to show progress for layer downloads (blobs).
	// A simple heuristic is to check if the URL path contains "/blobs/".
	if resp.ContentLength > 0 && strings.Contains(req.URL.Path, "/blobs/") {
		// Get a friendly prefix for the progress bar, e.g., "Downloading sha256:123ab..."
		digest := filepath.Base(req.URL.Path)
		var prefix string

		// Safely slice the digest string to prevent panics on short names.
		if len(digest) > 15 {
			prefix = fmt.Sprintf("  Downloading %s...", digest[:15])
		} else {
			prefix = fmt.Sprintf("  Downloading %s...", digest)
		}

		// Replace the original response body with our progress-tracking one.
		resp.Body = &progressReader{
			ReadCloser: resp.Body,
			total:      resp.ContentLength,
			prefix:     prefix,
		}
	}

	return resp, nil
}

func (im *ImageManager) Pull(imageRef string) error {
	fmt.Printf("Pulling image: %s\n", imageRef)

	imageRef = im.resolveImageRef(imageRef)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference: %w", err)
	}

	// --- START OF MODIFICATION ---
	customTransport := &progressTransport{
		underlying: http.DefaultTransport,
	}

	OS := runtime.GOOS
	if OS == "android" {
		OS = "linux"
	}
	platform := v1.Platform{
		OS:           OS,
		Architecture: runtime.GOARCH,
	}

	fmt.Printf("Requesting image for platform: %s/%s\n", platform.OS, platform.Architecture)

	// Pull the image using our custom transport.
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(customTransport), // <-- USE OUR TRANSPORT HERE
		remote.WithPlatform(platform),
	)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	imagePath := im.getImagePath(imageRef)
	if err := os.MkdirAll(imagePath, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	if err := im.exportImage(img, imagePath); err != nil {
		return fmt.Errorf("failed to export image: %w", err)
	}

	fmt.Printf("Successfully pulled: %s\n", imageRef)
	return nil
}

func (im *ImageManager) resolveImageRef(ref string) string {
	// Check if it's a short name
	if !strings.Contains(ref, "/") || strings.HasPrefix(ref, "localhost/") {
		// Try to resolve from configured registries
		parts := strings.SplitN(ref, ":", 2)
		distro := parts[0]
		tag := "latest"
		if len(parts) == 2 {
			tag = parts[1]
		}

		if fullRef, ok := im.cfg.Registries[distro]; ok {
			return fullRef + ":" + tag
		}
	}

	// Add default registry if no registry specified
	if !strings.Contains(ref, ".") && !strings.HasPrefix(ref, "localhost") {
		if !strings.Contains(ref, "/") {
			return "docker.io/library/" + ref
		}
		return "docker.io/" + ref
	}

	return ref
}

func (im *ImageManager) getImagePath(imageRef string) string {
	// Sanitize image ref for filesystem
	safeName := strings.ReplaceAll(imageRef, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	return filepath.Join(im.cfg.ContainersPath, ".images", safeName)
}

func (im *ImageManager) exportImage(img v1.Image, destPath string) error {
	// Get image layers
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get image layers: %w", err)
	}

	// Create rootfs directory
	rootfsPath := filepath.Join(destPath, "rootfs")
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		return err
	}

	// Extract each layer
	fmt.Printf("Extracting %d layers...\n", len(layers))
	for i, layer := range layers {
		fmt.Printf("  Layer %d/%d...\n", i+1, len(layers))
		if err := im.extractLayer(layer, rootfsPath); err != nil {
			return fmt.Errorf("failed to extract layer %d: %w", i, err)
		}
	}

	// Save image config
	configFile, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get image config: %w", err)
	}

	configPath := filepath.Join(destPath, "config.json")
	configData, err := json.MarshalIndent(configFile, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, configData, 0644)
}

func (im *ImageManager) extractLayer(layer v1.Layer, destPath string) error {
	rc, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer rc.Close()

	// Decompress gzip
	gr, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	defer gr.Close()

	// Extract tar
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destPath, header.Name)

		// Security check: prevent directory traversal
		if !strings.HasPrefix(target, filepath.Clean(destPath)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}

	return nil
}

func (im *ImageManager) GetRootfs(imageRef string) (string, error) {
	imageRef = im.resolveImageRef(imageRef)
	imagePath := im.getImagePath(imageRef)
	rootfsPath := filepath.Join(imagePath, "rootfs")

	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		return "", fmt.Errorf("image not found locally, please pull it first")
	}

	return rootfsPath, nil
}

func (im *ImageManager) List() ([]string, error) {
	imagesDir := filepath.Join(im.cfg.ContainersPath, ".images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var images []string
	for _, entry := range entries {
		if entry.IsDir() {
			images = append(images, entry.Name())
		}
	}

	return images, nil
}

func (im *ImageManager) CleanCache() error {
	cachePath := filepath.Join(im.cfg.ContainersPath, ".images")

	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		fmt.Println("Image cache is already clean (directory not found).")
		return nil
	}

	fmt.Printf("Removing image cache: %s\n", cachePath)

	if err := os.RemoveAll(cachePath); err != nil {
		return fmt.Errorf("failed to remove image cache directory: %w", err)
	}

	fmt.Println("Successfully cleaned image cache.")
	return nil
}
