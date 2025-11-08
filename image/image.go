package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	. "dbox/config"
	. "dbox/logger"
	. "dbox/utils"
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
	logFile *os.File
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
	barWidth := 30
	completedWidth := int(float64(barWidth) * (float64(pr.current) / float64(pr.total)))

	bar := strings.Repeat("█", completedWidth) + strings.Repeat("░", barWidth-completedWidth)

	progressMsg := fmt.Sprintf("%s [%s] %.1f%% (%s / %s)",
		pr.prefix,
		bar,
		percentage,
		FormatBytes(uint64(pr.current)),
		FormatBytes(uint64(pr.total)),
	)

	// Always show progress on stdout with carriage return
	fmt.Printf("\r%s", progressMsg)

	// When download is complete, print a newline to move to the next line.
	if pr.current >= pr.total {
		fmt.Println()
	}

	// Also write progress to log file (with newline for log readability)
	if pr.logFile != nil {
		pr.logFile.WriteString(progressMsg + "\n")
		pr.logFile.Sync()
	}
}

func NewImageManager(cfg *Config) *ImageManager {
	return &ImageManager{cfg: cfg}
}

type progressTransport struct {
	underlying http.RoundTripper
	logFile    *os.File
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
			logFile:    pt.logFile,
		}
	}

	return resp, nil
}

func (im *ImageManager) Pull(imageRef string, logFile *os.File) error {
	if logFile != nil {
		fmt.Fprintf(logFile, "Pulling image: %s\n", imageRef)
		logFile.Sync()
	} else {
		LogInfo("Pulling image: %s", imageRef)
	}
	LogVerbose("Resolving image reference...")
	imageRef = im.resolveImageRef(imageRef)
	LogVerbose("Resolved to: %s", imageRef)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference: %w", err)
	}

	// --- START OF MODIFICATION ---
	// Create optimized HTTP transport for faster downloads
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Set custom DNS resolver if specified
	if len(im.cfg.DNS) > 0 {
		dnsServer := im.cfg.DNS[0] + ":53"
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		dialer.Resolver = resolver
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	customTransport := &progressTransport{
		underlying: transport,
		logFile:    logFile,
	}

	OS := runtime.GOOS
	if OS == "android" {
		OS = "linux"
	}
	platform := v1.Platform{
		OS:           OS,
		Architecture: runtime.GOARCH,
	}

	LogVerbose("Requesting image for platform: %s/%s", platform.OS, platform.Architecture)

	// Pull the image using our custom transport.
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(customTransport), // <-- USE OUR TRANSPORT HERE
		remote.WithPlatform(platform),
		remote.WithJobs(runtime.NumCPU()*2), // Increase concurrent downloads
	)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	imagePath := im.getImagePath(imageRef)
	LogVerbose("Image path: %s", imagePath)
	if err := os.MkdirAll(imagePath, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	LogVerbose("Exporting image...")
	if err := im.exportImage(img, imagePath); err != nil {
		os.RemoveAll(imagePath) // Cleanup on failure
		return fmt.Errorf("failed to export image: %w", err)
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Successfully pulled: %s\n", imageRef)
		logFile.Sync()
	} else {
		LogInfo("Successfully pulled: %s", imageRef)
	}
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

	LogInfo("Found %d layers to extract", len(layers))

	// Create rootfs directory
	rootfsPath := filepath.Join(destPath, "rootfs")
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		return err
	}

	// Extract each layer
	LogInfo("Extracting %d layers...", len(layers))
	for i, layer := range layers {
		LogInfo("Extracting layer %d/%d...", i+1, len(layers))
		if err := im.extractLayer(layer, rootfsPath); err != nil {
			return fmt.Errorf("failed to extract layer %d: %w", i, err)
		}
	}

	// Save image config
	LogVerbose("Saving image config...")
	configFile, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get image config: %w", err)
	}

	configPath := filepath.Join(destPath, "config.json")
	configData, err := json.MarshalIndent(configFile, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return err
	}
	LogVerbose("Image config saved to: %s", configPath)
	return nil
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
	LogVerbose("Getting rootfs for image: %s", imageRef)
	imageRef = im.resolveImageRef(imageRef)
	imagePath := im.getImagePath(imageRef)
	rootfsPath := filepath.Join(imagePath, "rootfs")
	LogVerbose("Checking rootfs path: %s", rootfsPath)
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		LogVerbose("Image not found locally")
		return "", fmt.Errorf("image not found locally")
	}
	// Check if config.json exists, otherwise it's corrupted
	configPath := filepath.Join(imagePath, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		LogVerbose("Image corrupted (missing config.json), removing")
		os.RemoveAll(imagePath)
		return "", fmt.Errorf("image corrupted, cleaned up")
	}
	LogVerbose("Found local rootfs")
	return rootfsPath, nil
}

func (im *ImageManager) List() ([]string, error) {
	LogVerbose("Listing local images")
	imagesDir := filepath.Join(im.cfg.ContainersPath, ".images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			LogDebug("No images directory found")
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

	LogVerbose("Found %d local images", len(images))
	return images, nil
}

func (im *ImageManager) CleanCache() error {
	LogInfo("Cleaning image cache...")
	cachePath := filepath.Join(im.cfg.ContainersPath, ".images")
	LogVerbose("Cache path: %s", cachePath)

	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		LogInfo("Image cache is already clean (directory not found).")
		return nil
	}

	LogVerbose("Removing image cache: %s", cachePath)

	if err := os.RemoveAll(cachePath); err != nil {
		return fmt.Errorf("failed to remove image cache directory: %w", err)
	}

	LogInfo("Successfully cleaned image cache.")
	return nil
}
