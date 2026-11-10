package manifest

import (
	"context"
	"fmt"

	digest "github.com/opencontainers/go-digest"
	cimage "go.podman.io/image/v5/image"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/transports/alltransports"
	"go.podman.io/image/v5/types"

	"github.com/openshift/oc-mirror/v2/internal/pkg/api/v2alpha1"
	"github.com/openshift/oc-mirror/v2/internal/pkg/mirror"
)

// ImageManifest fetches manifest bytes without downloading config or layer blobs.
// The expected digest, if specified by the reference or instanceDigest, is validated
// before returning. The source is closed before returning.
func (o Manifest) ImageManifest(ctx context.Context, sourceCtx *types.SystemContext, imgRef string, instanceDigest *digest.Digest) ([]byte, string, error) {
	srcRef, err := alltransports.ParseImageName(imgRef)
	if err != nil {
		return nil, "", fmt.Errorf("invalid source name %s: %w", imgRef, err)
	}
	img, err := srcRef.NewImageSource(ctx, sourceCtx)
	if err != nil {
		return nil, "", fmt.Errorf("error when creating a new image source: %w", err)
	}
	defer img.Close()

	return cimage.UnparsedInstance(img, instanceDigest).Manifest(ctx)
}

// parseBlobSizes returns config/layer descriptors without downloading blobs.
// Unknown sizes make sizing fail rather than silently underestimating the image.
func parseBlobSizes(manifestBytes []byte, mimeType string) ([]types.BlobInfo, error) {
	parsed, err := manifest.FromBlob(manifestBytes, mimeType)
	if err != nil {
		return nil, fmt.Errorf("error parsing manifest: %w", err)
	}
	var blobs []types.BlobInfo
	for _, layer := range parsed.LayerInfos() {
		blobs = append(blobs, layer.BlobInfo)
	}
	if cfg := parsed.ConfigInfo(); cfg.Digest != "" {
		blobs = append(blobs, cfg)
	}
	for _, blob := range blobs {
		if blob.Size < 0 {
			return nil, fmt.Errorf("unknown size for blob %s", blob.Digest)
		}
	}
	return blobs, nil
}

// InspectImage fetches the top-level manifest once for both mapping and sizing.
// Mapping includes every top-level instance; sizing only resolves selected,
// non-attestation instances. With includeBlobSizes=false no children are fetched.
func (o Manifest) InspectImage(ctx context.Context, sourceCtx *types.SystemContext, imgRef string, platformFilters []v2alpha1.InstancePlatformFilter, includeBlobSizes bool) (ImageInspection, error) {
	var result ImageInspection
	manifestBytes, mimeType, err := o.ImageManifest(ctx, sourceCtx, imgRef, nil)
	if err != nil {
		return result, fmt.Errorf("error fetching manifest for %s: %w", imgRef, err)
	}

	if !manifest.MIMETypeIsMultiImage(mimeType) {
		if includeBlobSizes {
			result.Blobs, result.SizeError = parseBlobSizes(manifestBytes, mimeType)
		}
		return result, nil
	}

	list, err := manifest.ListFromBlob(manifestBytes, mimeType)
	if err != nil {
		return result, fmt.Errorf("error parsing manifest list for %s: %w", imgRef, err)
	}

	for _, instance := range list.Instances() {
		result.ManifestListDigests = append(result.ManifestListDigests, instance.String())
	}
	if includeBlobSizes {
		result.Blobs, result.SizeError = o.blobSizesFromManifestList(ctx, sourceCtx, imgRef, list, platformFilters)
	}
	return result, nil
}

func shouldSizeManifestInstance(inst manifest.ListUpdate, allowedPlatforms map[string]bool) bool {
	if inst.ReadOnly.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
		return false
	}
	if len(allowedPlatforms) == 0 {
		return true
	}
	// Match copy.InstancePlatforms: nil platform does not match a concrete os/arch.
	if inst.ReadOnly.Platform == nil {
		return false
	}
	_, allowed := allowedPlatforms[inst.ReadOnly.Platform.OS+"/"+inst.ReadOnly.Platform.Architecture]
	return allowed
}

func (o Manifest) blobSizesFromManifestList(ctx context.Context, sourceCtx *types.SystemContext, imgRef string, list manifest.List, platformFilters []v2alpha1.InstancePlatformFilter) ([]types.BlobInfo, error) {
	allowedPlatforms := make(map[string]bool, len(platformFilters))
	for _, pf := range platformFilters {
		// Keys select platforms; values track whether each one was found.
		allowedPlatforms[pf.String()] = false
	}

	var allBlobs []types.BlobInfo

	for _, instanceDigest := range list.Instances() {
		inst, instErr := list.Instance(instanceDigest)
		if instErr != nil {
			return nil, fmt.Errorf("reading manifest instance %s: %w", instanceDigest, instErr)
		}
		if !shouldSizeManifestInstance(inst, allowedPlatforms) {
			continue
		}
		if platform := inst.ReadOnly.Platform; platform != nil && len(platformFilters) > 0 {
			allowedPlatforms[platform.OS+"/"+platform.Architecture] = true
		}

		subBytes, subMime, subErr := o.ImageManifest(ctx, sourceCtx, imgRef, &instanceDigest)
		if subErr != nil {
			return nil, fmt.Errorf("fetching manifest instance %s: %w", instanceDigest, subErr)
		}

		subBlobs, parseErr := parseBlobSizes(subBytes, subMime)
		if parseErr != nil {
			return nil, fmt.Errorf("sizing manifest instance %s: %w", instanceDigest, parseErr)
		}
		allBlobs = append(allBlobs, subBlobs...)
	}
	for _, platform := range platformFilters {
		if !allowedPlatforms[platform.String()] {
			return nil, fmt.Errorf("no instances found for platform %s", platform.String())
		}
	}
	return allBlobs, nil
}

func (o Manifest) ImageDigest(ctx context.Context, sourceCtx *types.SystemContext, imgRef string) (string, error) {
	if err := mirror.ReexecIfNecessaryForImages(imgRef); err != nil {
		return "", fmt.Errorf("reexec mirror: %w", err)
	}

	manifestBytes, _, err := o.ImageManifest(ctx, sourceCtx, imgRef, nil)
	if err != nil {
		return "", fmt.Errorf("get manifest: %w", err)
	}

	digest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return "", fmt.Errorf("get manifest digest: %w", err)
	}

	return digest.Encoded(), nil
}
