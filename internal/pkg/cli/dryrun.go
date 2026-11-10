package cli

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/docker/go-units"
	"go.podman.io/image/v5/types"

	"github.com/openshift/oc-mirror/v2/internal/pkg/api/v2alpha1"
	"github.com/openshift/oc-mirror/v2/internal/pkg/archive"
	"github.com/openshift/oc-mirror/v2/internal/pkg/consts"
	"github.com/openshift/oc-mirror/v2/internal/pkg/emoji"
	"github.com/openshift/oc-mirror/v2/internal/pkg/image"
	"github.com/openshift/oc-mirror/v2/internal/pkg/mirror"
)

func (o *ExecutorSchema) DryRun(ctx context.Context, cs v2alpha1.CollectorSchema) error {
	allImages := cs.AllImages
	outDir := filepath.Join(o.Opts.Global.WorkingDir, dryRunOutDir)
	os.RemoveAll(outDir)

	err := o.MakeDir.makeDirAll(outDir, 0755)
	if err != nil {
		o.Log.Error(" %v ", err)
		return err
	}

	// Inspect each source once, retaining mapping digests even if sizing fails.
	var inspections []dryRunImageInspection
	manifestListDigests := make(map[string][]string)
	if o.Manifest != nil {
		inspections = o.inspectImages(ctx, cs)
		if o.Opts.IsDryRunManifestLists {
			for _, inspection := range inspections {
				if inspection.Error != nil {
					o.Log.Warn("unable to inspect manifest for %s: %v", inspection.Source, inspection.Error)
				}
				manifestListDigests[inspection.Source] = inspection.Digests
			}
		}
	}

	if err := o.writeDryRunMapping(ctx, allImages, manifestListDigests, outDir); err != nil {
		return err
	}

	// Generate cluster resources in dry-run mode (skip for mirror-to-disk since target registry is unknown)
	if !o.Opts.IsMirrorToDisk() {
		if err := o.generateClusterResources(ctx, allImages); err != nil {
			o.Log.Warn("Cluster resources generation failed (dry-run mode): %v", err)
		}
	}

	// Size estimation (appended AFTER existing output for backward compatibility)
	if o.Manifest != nil {
		o.logSizeReport(o.estimateDryRunSize(cs, inspections))
	}

	return nil
}

// writeDryRunMapping generates the mapping file for all images and, for the
// mirror-to-disk workflow, the missing-images file. It reports cache
// availability counts via the logger.
func (o *ExecutorSchema) writeDryRunMapping(ctx context.Context, allImages []v2alpha1.CopyImageSchema, manifestListDigests map[string][]string, outDir string) error {
	mappingTxtFilePath := filepath.Join(outDir, mappingFile)
	mappingTxtFile, err := os.Create(mappingTxtFilePath)
	if err != nil {
		return fmt.Errorf("failed to create mapping file: %w", err)
	}
	defer mappingTxtFile.Close()

	nbMissingImgs := 0
	nbAvailableImgs := 0
	var buff bytes.Buffer
	var missingImgsBuff bytes.Buffer
	for _, img := range allImages {
		missing := o.processImageForDryRun(ctx, img, manifestListDigests, &buff, &missingImgsBuff)
		if missing {
			nbMissingImgs++
		} else if o.Opts.IsMirrorToDisk() {
			nbAvailableImgs++
		}
	}

	if _, err := mappingTxtFile.Write(buff.Bytes()); err != nil {
		return err
	}
	if nbMissingImgs > 0 {
		if err := o.writeMissingImagesFile(outDir, missingImgsBuff.Bytes(), nbMissingImgs, len(allImages)); err != nil {
			return err
		}
	}

	if nbAvailableImgs > 0 {
		o.Log.Info("all %d images required for mirroring are available in local cache. You may proceed with mirroring from disk to disconnected registry", nbAvailableImgs)
	}
	o.Log.Info(emoji.PageFacingUp+" list of all images for mirroring in : %s", mappingTxtFilePath)
	return nil
}

// estimateDryRunSize builds the dry-run size report for the current workflow mode.
func (o *ExecutorSchema) estimateDryRunSize(cs v2alpha1.CollectorSchema, inspections []dryRunImageInspection) dryRunSizeReport {
	allImages := cs.AllImages
	if o.Opts.IsDiskToMirror() {
		// d2m: all Sources are local-cache; size comes from archive tarballs on disk.
		report := dryRunSizeReport{ImageCount: len(allImages)}
		tarballSize, tarballErr := computeTarballFilesSize(o.Opts.Global.From)
		if tarballErr != nil {
			o.Log.Warn("unable to read archive for size estimate; tarball size excluded")
			report.SizeUnavailable = true
			return report
		}
		if o.Opts.Global.From != "" && tarballSize == 0 {
			o.Log.Warn("no archive tar files found; size estimate does not include tarball")
		}
		report.TotalSize = tarballSize
		return report
	}

	// m2m/m2d: use descriptors collected by the combined inspection pass.
	report := computeSizeReport(inspections)
	report.TotalSize = adjustSizeForWorkflow(report.TotalSize, o.Opts.Mode, inspections, allImages)
	return report
}

func (o *ExecutorSchema) writeMissingImagesFile(outDir string, data []byte, nbMissing, total int) error {
	missingImgsFilePath := filepath.Join(outDir, missingImgsFile)
	if err := os.WriteFile(missingImgsFilePath, data, 0644); err != nil { //nolint: gosec // no sensitive data in file and it must be readable by others
		return fmt.Errorf("error writing missing images file: %w", err)
	}
	o.Log.Warn(emoji.Warning+"  %d/%d images necessary for mirroring are not available in the cache.", nbMissing, total)
	o.Log.Warn("List of missing images in : %s.\nplease re-run the mirror to disk process", missingImgsFilePath)
	return nil
}

type subDigestEntry struct{ source, dest string }

func (o *ExecutorSchema) processImageForDryRun(ctx context.Context, img v2alpha1.CopyImageSchema, manifestListDigests map[string][]string, buff, missingImgsBuff *bytes.Buffer) bool {
	buff.WriteString(img.Source + "=" + img.Destination + "\n")

	subDigestEntries := o.writeSubDigestEntries(img, manifestListDigests, buff)

	if !o.Opts.IsMirrorToDisk() {
		return false
	}
	exists, err := o.Mirror.Check(ctx, img.Destination, o.Opts, false)
	if err != nil {
		o.Log.Debug("unable to check existence of %s in local cache: %v", img.Destination, err)
	}
	if err != nil || !exists {
		missingImgsBuff.WriteString(img.Source + "=" + img.Destination + "\n")
		for _, sub := range subDigestEntries {
			missingImgsBuff.WriteString(sub.source + "=" + sub.dest + "\n")
		}
		return true
	}
	return false
}

func (o *ExecutorSchema) writeSubDigestEntries(img v2alpha1.CopyImageSchema, manifestListDigests map[string][]string, buff *bytes.Buffer) []subDigestEntry {
	manifestDigests := manifestListDigests[img.Origin]
	if len(manifestDigests) == 0 {
		manifestDigests = manifestListDigests[img.Source]
	}
	if len(manifestDigests) == 0 {
		return nil
	}
	sourceBase, _, _ := strings.Cut(img.Source, "@")
	entries := make([]subDigestEntry, 0, len(manifestDigests))
	for _, digest := range manifestDigests {
		subSource := sourceBase + "@" + digest
		subDest := subDigestDestination(img.Destination, digest)
		buff.WriteString(subSource + "=" + subDest + "\n")
		entries = append(entries, subDigestEntry{source: subSource, dest: subDest})
	}
	return entries
}

// subDigestDestination returns a digest-pinned destination for a sub-digest entry.
// For docker:// destinations, it strips the tag and appends the sub-digest to avoid
// destination overwrites when multiple architectures map to the same tag.
// For non-docker destinations (oci:, dir:, etc.), the destination is returned as-is.
func subDigestDestination(dest string, digest string) string {
	if !strings.HasPrefix(dest, consts.DockerProtocol) {
		return dest
	}
	destSpec, err := image.ParseRef(dest)
	if err != nil {
		return dest
	}
	return destSpec.Transport + destSpec.Name + "@" + digest
}

func (o *ExecutorSchema) newSystemContextForSource(source string) (*types.SystemContext, error) {
	sysCtx, err := o.Opts.SrcImage.NewSystemContext()
	if err != nil {
		return nil, fmt.Errorf("error creating system context: %w", err)
	}
	if isLocalCacheSource(source, o.Opts.LocalStorageFQDN) {
		sysCtx.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
	}
	return sysCtx, nil
}

type dryRunImageInspection struct {
	Source    string
	Digests   []string
	Blobs     []types.BlobInfo
	Error     error
	SizeError error
	platforms []v2alpha1.InstancePlatformFilter
	size      bool
}

type dryRunSizeReport struct {
	TotalSize       int64
	ImageCount      int
	Errors          []error
	SizeUnavailable bool
}

// inspectionTasks groups sources while retaining the union of all requested
// platforms. Any unrestricted request means all platforms must be sized.
func (o *ExecutorSchema) inspectionTasks(cs v2alpha1.CollectorSchema) []dryRunImageInspection {
	var tasks []dryRunImageInspection
	seen := make(map[string]int)
	for _, img := range cs.AllImages {
		size := !o.Opts.IsDiskToMirror() && !isLocalCacheSource(img.Source, o.Opts.LocalStorageFQDN)
		if !size && !o.Opts.IsDryRunManifestLists {
			continue
		}
		idx, found := seen[img.Source]
		if !found {
			idx = len(tasks)
			seen[img.Source] = idx
			tasks = append(tasks, dryRunImageInspection{Source: img.Source})
		}
		task := &tasks[idx]
		if !size {
			continue
		}
		platforms := cs.PlatformFilters[img.Origin]
		switch {
		case !task.size:
			task.platforms = append([]v2alpha1.InstancePlatformFilter(nil), platforms...)
		case len(platforms) == 0:
			task.platforms = nil
		case len(task.platforms) > 0:
			for _, platform := range platforms {
				if !slices.Contains(task.platforms, platform) {
					task.platforms = append(task.platforms, platform)
				}
			}
		}
		task.size = true
	}
	return tasks
}

// inspectImages is the only concurrent inspection pass. Each source is inspected
// once for both mapping and sizing, with independently reported sizing failures.
func (o *ExecutorSchema) inspectImages(ctx context.Context, cs v2alpha1.CollectorSchema) []dryRunImageInspection {
	results := o.inspectionTasks(cs)
	if len(results) > 0 {
		o.Log.Info(emoji.LeftPointingMagnifyingGlass+" inspecting %d images for mapping and size metadata...", len(results))
	}
	var wg sync.WaitGroup

	parallelism := o.Opts.ParallelImages
	if parallelism <= 0 {
		parallelism = maxParallelImageDownloads
	}
	semaphore := make(chan struct{}, parallelism)

	for i := range results {
		if err := ctx.Err(); err != nil {
			results[i].Error = err
			continue
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			results[i].Error = ctx.Err()
			continue
		}
		wg.Add(1)
		go func(result *dryRunImageInspection) {
			defer wg.Done()
			defer func() { <-semaphore }()
			sysCtx, err := o.newSystemContextForSource(result.Source)
			if err != nil {
				result.Error = err
				return
			}
			inspection, err := o.Manifest.InspectImage(ctx, sysCtx, result.Source, result.platforms, result.size)
			result.Digests, result.Blobs = inspection.ManifestListDigests, inspection.Blobs
			result.Error, result.SizeError = err, inspection.SizeError
		}(&results[i])
	}
	wg.Wait()
	return results
}

// computeSizeReport deduplicates blobs globally and computes the total unique
// compressed content size. Errored images are recorded
func computeSizeReport(results []dryRunImageInspection) dryRunSizeReport {
	var report dryRunSizeReport
	blobSeen := make(map[string]int64)
	for _, r := range results {
		if !r.size {
			continue // mapping-only inspection; sizing uses the archive or skips the local cache
		}
		err := r.Error
		if err == nil {
			err = r.SizeError
		}
		if err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("%s: %w", r.Source, err))
			continue
		}
		report.ImageCount++
		for _, blob := range r.Blobs {
			blobSeen[blob.Digest.String()] = blob.Size
		}
	}
	report.TotalSize = sumMapValues(blobSeen)
	return report
}

// logSizeReport prints the size estimation summary, including any images that failed sizing.
func (o *ExecutorSchema) logSizeReport(report dryRunSizeReport) {
	o.Log.Info("📊 Dry-run size estimate:")
	switch {
	case report.SizeUnavailable:
		o.Log.Info("Total estimated size: unavailable")
	case len(report.Errors) > 0:
		o.Log.Info("Total estimated size: %s (%d bytes; incomplete)", units.HumanSize(float64(report.TotalSize)), report.TotalSize)
	default:
		o.Log.Info("Total estimated size: %s (%d bytes)", units.HumanSize(float64(report.TotalSize)), report.TotalSize)
	}
	o.Log.Info("Images: %d", report.ImageCount)
	if len(report.Errors) > 0 {
		o.Log.Warn("%d image(s) could not be sized:", len(report.Errors))
		for _, e := range report.Errors {
			o.Log.Warn("  %v", e)
		}
	}
}

// isLocalCacheSource reports whether source's registry authority equals localStorageFQDN.
// Substring checks on the full reference are unsafe: a remote host like
// "notmirror.local:55000" contains "mirror.local:55000".
func isLocalCacheSource(source, localStorageFQDN string) bool {
	if localStorageFQDN == "" {
		return false
	}
	spec, err := image.ParseRef(source)
	if err != nil {
		return false
	}
	return spec.Domain == localStorageFQDN
}

// adjustSizeForWorkflow adjusts the raw unique blob size based on workflow:
//
//   - m2m: image content + local cache (operator catalogs only)
//   - m2d: image content × 2 (cache + tarball coexist on disk)
//
// Disk-to-mirror is handled separately by measuring archive files on disk.
func adjustSizeForWorkflow(rawSize int64, mode string, results []dryRunImageInspection, images []v2alpha1.CopyImageSchema) int64 {
	switch mode {
	case mirror.MirrorToMirror:
		return saturatingAdd(rawSize, computeOperatorCatalogCacheSize(results, images))
	case mirror.MirrorToDisk:
		return saturatingAdd(rawSize, rawSize)
	default:
		return rawSize
	}
}

// computeOperatorCatalogCacheSize returns the deduplicated blob size of operator catalog images only.
// In m2m, catalogs are cached locally for the rebuild/delete workflow in addition to being pushed to the target registry.
// Matching is done by Source key to avoid fragile index-based correlation.
func computeOperatorCatalogCacheSize(results []dryRunImageInspection, images []v2alpha1.CopyImageSchema) int64 {
	catalogSources := make(map[string]bool, len(images))
	for _, img := range images {
		if img.Type.IsOperatorCatalog() {
			catalogSources[img.Source] = true
		}
	}
	var catalogs []dryRunImageInspection
	for _, r := range results {
		if catalogSources[r.Source] {
			catalogs = append(catalogs, r)
		}
	}
	return computeSizeReport(catalogs).TotalSize
}

func sumMapValues(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total = saturatingAdd(total, v)
	}
	return total
}

// saturatingAdd adds sizes without wrapping past MaxInt64.
func saturatingAdd(a, b int64) int64 {
	a, b = max(a, 0), max(b, 0)
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

var mirrorTarPattern = regexp.MustCompile(archive.MirrorArchiveFileRegexp)

// computeTarballFilesSize measures the total size of existing mirror_NNNNNN.tar files in the given directory.
// Used for d2m to get the exact tarball size.
func computeTarballFilesSize(fromDir string) (int64, error) {
	if fromDir == "" {
		return 0, nil
	}
	dir := strings.TrimPrefix(fromDir, consts.FileProtocol)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("unable to read archive directory %s: %w", dir, err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !mirrorTarPattern.MatchString(e.Name()) {
			continue
		}
		// os.Stat follows symlinks so a mirror_NNNNNN.tar link contributes the
		// target tarball size (matches how the archive reader opens the path).
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			return 0, fmt.Errorf("unable to stat archive file: %w", err)
		}
		if info.IsDir() {
			continue
		}
		total = saturatingAdd(total, info.Size())
	}
	return total, nil
}
