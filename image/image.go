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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// getTerminalWidth returns the width of the terminal in columns
func getTerminalWidth() int {
	// First try to get terminal width from environment if stdout is not a terminal
	if !isTerminal() {
		if width := getEnvTerminalWidth(); width > 0 {
			return width
		}
	}

	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	output, err := cmd.Output()
	if err != nil {
		return 80 // fallback to 80 columns
	}

	parts := strings.Split(strings.TrimSpace(string(output)), " ")
	if len(parts) != 2 {
		return 80
	}

	width, err := strconv.Atoi(parts[1])
	if err != nil {
		return 80
	}

	return width
}

// isTerminal checks if stdout is connected to a terminal
func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// getEnvTerminalWidth tries to get terminal width from environment variables
func getEnvTerminalWidth() int {
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if width, err := strconv.Atoi(cols); err == nil {
			return width
		}
	}
	return 0
}

type progressReader struct {
	io.ReadCloser
	mu           sync.Mutex
	current      int64
	total        int64
	prefix       string
	logFile      *os.File
	firstPrinted bool
	lastUpdate   time.Time
	lastBytes    int64
	startTime    time.Time
}

// Read overrides the underlying Read method to update and print progress.
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.ReadCloser.Read(p)

	pr.mu.Lock()
	pr.current += int64(n)

	// Rate-limit progress updates: only update every 100ms or every 1MB
	now := time.Now()
	bytesSinceUpdate := pr.current - pr.lastBytes
	shouldUpdate := now.Sub(pr.lastUpdate) >= 100*time.Millisecond ||
		bytesSinceUpdate >= 1024*1024 ||
		pr.current >= pr.total

	if shouldUpdate {
		pr.printProgress()
		pr.lastUpdate = now
		pr.lastBytes = pr.current
	}

	pr.mu.Unlock()

	return
}

// printProgress displays the download progress bar.
func (pr *progressReader) printProgress() {
	if pr.total <= 0 {
		return // Don't display if total size is unknown
	}

	percentage := float64(pr.current) / float64(pr.total) * 100

	// Get terminal width for responsive progress bar (check every time)
	termWidth := getTerminalWidth()
	isTerm := isTerminal()

	// Print the first line (prefix) only once
	if !pr.firstPrinted {
		if termWidth < 50 {
			// Small terminal - include total size in first line
			totalStr := FormatBytes(uint64(pr.total))
			fmt.Printf("%s %s\n", pr.prefix, totalStr)
		} else {
			fmt.Printf("%s\n", pr.prefix)
		}
		pr.firstPrinted = true
	}

	var progressLine string

	if !isTerm {
		// Not a terminal - use simple line-by-line progress
		progressLine = fmt.Sprintf("Progress: %.1f%% (%s / %s)\n",
			percentage,
			FormatBytes(uint64(pr.current)),
			FormatBytes(uint64(pr.total)))
	} else if termWidth < 30 {
		// Very small terminal - just show percentage
		progressLine = fmt.Sprintf("\r%.1f%%", percentage)
	} else if termWidth < 50 {
		// Small terminal - show percentage bar without brackets and current size
		currentStr := FormatBytes(uint64(pr.current))

		// Calculate bar width (leave space for percentage and size info)
		sizeInfo := fmt.Sprintf("%.1f%% (%s)", percentage, currentStr)
		barWidth := max(termWidth-len(sizeInfo)-2, 3) // -2 for space after bar

		completedWidth := int(float64(barWidth) * (float64(pr.current) / float64(pr.total)))
		bar := strings.Repeat("█", completedWidth) + strings.Repeat("░", barWidth-completedWidth)

		progressLine = fmt.Sprintf("\r%s %s", bar, sizeInfo)
	} else {
		// Normal terminal - show full progress bar
		// Calculate progress bar width (leave space for percentage and size info)
		sizeInfo := fmt.Sprintf("%.1f%% (%s / %s)",
			percentage,
			FormatBytes(uint64(pr.current)),
			FormatBytes(uint64(pr.total)))
		barWidth := max(termWidth-len(sizeInfo)-3, 5)

		completedWidth := int(float64(barWidth) * (float64(pr.current) / float64(pr.total)))
		bar := strings.Repeat("█", completedWidth) + strings.Repeat("░", barWidth-completedWidth)

		progressLine = fmt.Sprintf("\r%s %s", bar, sizeInfo)
	}

	// Use carriage return to overwrite the second line only
	fmt.Print(progressLine)

	// Only force flush on completion or when not a terminal
	if pr.current >= pr.total || !isTerm {
		os.Stdout.Sync()
	}

	// When download is complete, print a newline to move to the next line.
	if pr.current >= pr.total {
		// Calculate and display average download speed
		totalTime := time.Since(pr.startTime).Seconds()
		if totalTime > 0 {
			// Calculate speed in MB/s (not Mbps)
			avgSpeedMBps := (float64(pr.total) / totalTime) / (1024 * 1024)
			LogVerbose("Download completed: %s in %.1fs (%.2f MB/s average)",
				FormatBytes(uint64(pr.total)), totalTime, avgSpeedMBps)
		}
		fmt.Println()
	}

	// Also write progress to log file (batch writes, only sync on completion)
	if pr.logFile != nil {
		if !pr.firstPrinted {
			pr.logFile.WriteString(pr.prefix + "\n")
		}
		// Remove \r for log and ensure newline for non-terminal mode
		logLine := progressLine
		strings.TrimPrefix(logLine, "\r")
		if !strings.HasSuffix(logLine, "\n") {
			logLine += "\n"
		}
		pr.logFile.WriteString(logLine)

		// Only sync log file on completion to reduce I/O overhead
		if pr.current >= pr.total {
			pr.logFile.Sync()
		}
	}

	// Also write progress to log file (with newline for log readability)
	if pr.logFile != nil {
		if !pr.firstPrinted {
			pr.logFile.WriteString(pr.prefix + "\n")
		}
		// Remove \r for log and ensure newline for non-terminal mode
		logLine := progressLine
		strings.TrimPrefix(logLine, "\r")
		if !strings.HasSuffix(logLine, "\n") {
			logLine += "\n"
		}
		pr.logFile.WriteString(logLine)
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
			lastUpdate: time.Now(),
			startTime:  time.Now(),
		}
	}

	return resp, nil
}

func (im *ImageManager) Pull(imageRef string, logFile *os.File, force bool) error {
	LogVerbose("Resolving image reference...")
	imageRef = im.resolveImageRef(imageRef)
	LogVerbose("Resolved to: %s", imageRef)

	// Check if image already exists
	if !force {
		if _, err := im.GetRootfs(imageRef); err == nil {
			if logFile != nil {
				fmt.Fprintf(logFile, "Image already exists: %s\n", imageRef)
				logFile.Sync()
			} else {
				LogInfo("Image already exists: %s", imageRef)
			}
			return nil
		}
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Pulling image: %s\n", imageRef)
		logFile.Sync()
	} else {
		LogInfo("Pulling image: %s", imageRef)
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference: %w", err)
	}

	// --- START OF MODIFICATION ---
	// Create optimized HTTP transport for faster downloads
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set TCP_NODELAY to disable Nagle's algorithm for better latency
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
				// Set socket buffer sizes for better throughput
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024) // 1MB receive buffer
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024*1024) // 1MB send buffer
			})
		},
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
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20, // Increased for better connection reuse
		MaxConnsPerHost:       20, // Limit concurrent connections per host
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false, // Enable compression for faster transfers
		ForceAttemptHTTP2:     true,  // Force HTTP/2 for better multiplexing
		// Additional optimizations for Docker Hub
		ProxyConnectHeader: map[string][]string{
			"User-Agent": {"dbox/1.0"},
		},
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
	LogVerbose("Starting image download with optimized transport...")
	LogVerbose("Using %d concurrent download jobs", max(runtime.NumCPU()*2, 4))
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(customTransport), // <-- USE OUR TRANSPORT HERE
		remote.WithPlatform(platform),
		remote.WithJobs(max(runtime.NumCPU()*4, 8)), // Increase concurrent downloads further
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
		// Try to resolve from configured registries first
		parts := strings.SplitN(ref, ":", 2)
		distro := parts[0]
		tag := "latest"
		if len(parts) == 2 {
			tag = parts[1]
		}

		if fullRef, ok := im.cfg.Registries[distro]; ok {
			return fullRef + ":" + tag
		}

		// Use standard Docker Hub for all images

		// Default to docker.io library
		return "docker.io/library/" + ref + ":" + tag
	}

	// Add default registry if no registry specified
	if !strings.Contains(ref, ".") && !strings.HasPrefix(ref, "localhost") {
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

	// Create rootfs directory with proper permissions
	rootfsPath := filepath.Join(destPath, "rootfs")
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		return err
	}
	// Ensure we have write permissions
	if err := os.Chmod(rootfsPath, 0755); err != nil {
		LogVerbose("Warning: could not set permissions on %s: %v", rootfsPath, err)
	}

	// Extract layers in parallel for better performance
	LogInfo("Extracting %d layers in parallel...", len(layers))

	// Use a semaphore to limit concurrent extractions
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	var extractErr error
	var errMu sync.Mutex

	for i, layer := range layers {
		wg.Add(1)
		go func(idx int, l v1.Layer) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			LogInfo("Extracting layer %d/%d...", idx+1, len(layers))
			if err := im.extractLayer(l, rootfsPath); err != nil {
				errMu.Lock()
				if extractErr == nil {
					extractErr = fmt.Errorf("failed to extract layer %d: %w", idx, err)
				}
				errMu.Unlock()
			}
		}(i, layer)
	}

	wg.Wait()

	if extractErr != nil {
		return extractErr
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

// ImageInfo represents detailed information about an image
type ImageInfo struct {
	Name     string   `json:"name"`
	FullName string   `json:"full_name"`
	Size     string   `json:"size"`
	Created  string   `json:"created"`
	UsedBy   []string `json:"used_by,omitempty"`
	InUse    bool     `json:"in_use"`
}

func (im *ImageManager) ListDetailed() ([]ImageInfo, error) {
	LogVerbose("Listing detailed local images")
	imagesDir := filepath.Join(im.cfg.ContainersPath, ".images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			LogDebug("No images directory found")
			return []ImageInfo{}, nil
		}
		return nil, err
	}

	// Get container information to determine image usage
	containerUsage, err := im.getImageUsage()
	if err != nil {
		LogVerbose("Failed to get image usage: %v", err)
		containerUsage = make(map[string][]string)
	}

	var images []ImageInfo
	for _, entry := range entries {
		if entry.IsDir() {
			imageName := entry.Name()
			fullName := im.getImageFullName(imageName)

			// Get image size and creation time
			size, created, err := im.getImageStats(imageName)
			if err != nil {
				LogVerbose("Failed to get stats for image %s: %v", imageName, err)
				size = "unknown"
				created = "unknown"
			}

			// Check if image is in use
			usedBy, inUse := containerUsage[imageName]
			if !inUse {
				// Also check by full name
				usedBy, inUse = containerUsage[fullName]
			}

			images = append(images, ImageInfo{
				Name:     imageName,
				FullName: fullName,
				Size:     size,
				Created:  created,
				UsedBy:   usedBy,
				InUse:    inUse,
			})
		}
	}

	LogVerbose("Found %d local images", len(images))
	return images, nil
}

func (im *ImageManager) getImageFullName(safeName string) string {
	// Convert sanitized name back to full image reference
	fullName := strings.ReplaceAll(safeName, "_", "/")
	if lastColon := strings.LastIndex(fullName, "_"); lastColon != -1 {
		fullName = fullName[:lastColon] + ":" + fullName[lastColon+1:]
	}
	return fullName
}

func (im *ImageManager) getImageStats(imageName string) (string, string, error) {
	imagePath := filepath.Join(im.cfg.ContainersPath, ".images", imageName)

	info, err := os.Stat(imagePath)
	if err != nil {
		return "", "", err
	}

	// Calculate directory size
	var size int64
	err = filepath.Walk(imagePath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			size += fi.Size()
		}
		return nil
	})

	if err != nil {
		return "", "", err
	}

	return FormatBytes(uint64(size)), info.ModTime().Format("2006-01-02"), nil
}

func (im *ImageManager) getImageUsage() (map[string][]string, error) {
	containersDir := im.cfg.ContainersPath
	entries, err := os.ReadDir(containersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}

	usage := make(map[string][]string)

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			containerName := entry.Name()
			metadataPath := filepath.Join(containersDir, containerName, "metadata.json")

			// Read container metadata to get image reference
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata map[string]string
				if json.Unmarshal(data, &metadata) == nil {
					if imageRef, ok := metadata["image"]; ok && imageRef != "" {
						// Resolve image reference to get the sanitized name
						resolvedRef := im.resolveImageRef(imageRef)
						safeName := strings.ReplaceAll(resolvedRef, "/", "_")
						safeName = strings.ReplaceAll(safeName, ":", "_")

						usage[safeName] = append(usage[safeName], containerName)
						usage[resolvedRef] = append(usage[resolvedRef], containerName)
						usage[imageRef] = append(usage[imageRef], containerName)
					}
				}
			}
		}
	}

	// Mark images as in use if they have containers
	for imageRef := range usage {
		if len(usage[imageRef]) > 0 {
			// This will be used to mark all variations of the image name as in use
		}
	}

	return usage, nil
}

func (im *ImageManager) RemoveImage(imageName string) error {
	LogInfo("Removing image: %s", imageName)

	// Get full image name for logging
	fullName := im.getImageFullName(imageName)
	LogVerbose("Full image name: %s", fullName)

	// Check if image is in use
	usage, err := im.getImageUsage()
	if err != nil {
		return fmt.Errorf("failed to check image usage: %w", err)
	}

	if usedBy, inUse := usage[imageName]; inUse && len(usedBy) > 0 {
		return fmt.Errorf("image '%s' is used by containers: %v", fullName, usedBy)
	}

	if usedBy, inUse := usage[fullName]; inUse && len(usedBy) > 0 {
		return fmt.Errorf("image '%s' is used by containers: %v", fullName, usedBy)
	}

	// Remove image directory
	imagePath := filepath.Join(im.cfg.ContainersPath, ".images", imageName)
	LogVerbose("Removing image directory: %s", imagePath)

	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		return fmt.Errorf("image '%s' not found", fullName)
	}

	if err := os.RemoveAll(imagePath); err != nil {
		return fmt.Errorf("failed to remove image directory: %w", err)
	}

	LogInfo("Successfully removed image: %s", fullName)
	return nil
}

func (im *ImageManager) CleanUnusedImages() error {
	LogInfo("Cleaning unused images...")

	images, err := im.ListDetailed()
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	var removedImages []string
	var errors []string

	for _, img := range images {
		if !img.InUse && len(img.UsedBy) == 0 {
			if err := im.RemoveImage(img.Name); err != nil {
				errors = append(errors, fmt.Sprintf("failed to remove image '%s': %v", img.FullName, err))
			} else {
				removedImages = append(removedImages, img.FullName)
			}
		}
	}

	// Log results
	if len(removedImages) > 0 {
		LogInfo("Removed %d unused images:", len(removedImages))
		for _, img := range removedImages {
			LogInfo("  - %s", img)
		}
	}

	if len(errors) > 0 {
		LogVerbose("Encountered %d errors during cleanup:", len(errors))
		for _, err := range errors {
			LogVerbose("  - %s", err)
		}
	}

	if len(removedImages) == 0 && len(errors) == 0 {
		LogInfo("No unused images found.")
	}

	return nil
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
