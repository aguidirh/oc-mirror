package archive

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"

	"github.com/openshift/oc-mirror/v2/internal/pkg/image"
	"github.com/openshift/oc-mirror/v2/internal/pkg/mirror"
)

type ImageBlobGatherer struct {
	BlobsGatherer
	opts *mirror.CopyOptions
}

type toBeDefine struct {
	imgRef         string
	sourceCtx      *types.SystemContext
	manifestBytes  []byte
	mimeType       string
	digest         digest.Digest
	copySignatures bool
}

func NewImageBlobGatherer(opts *mirror.CopyOptions) *ImageBlobGatherer {
	return &ImageBlobGatherer{
		opts: opts,
	}
}

// TODO ALEX - ignore the images rebuilt (OSUS, CATALOG, OTHER?)
// TODO - use the flag instead of hardcoding values
// TODO change the map to map[string]struct{}
// TODO create a struct to reduce the arguments passed
// TODO add comments to the funcs
func (o *ImageBlobGatherer) GatherBlobs(ctx context.Context, imgRef string) (blobs map[string]string, retErr error) {
	blobs = map[string]string{}

	// we are always gathering blobs from the local cache registry - skipping tls verification
	// TODO ALEX check if this is not changing the global var
	sourceCtx, err := o.opts.SrcImage.NewSystemContext()
	if err != nil {
		return nil, err
	}
	sourceCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)

	manifestBytes, mime, err := imageManifest(ctx, sourceCtx, imgRef, nil)
	if err != nil {
		return nil, err
	}

	digest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("error to get the digest of the image manifest %w", err)
	}
	blobs[digest.String()] = ""

	tbd := toBeDefine{imgRef: imgRef, sourceCtx: sourceCtx, manifestBytes: manifestBytes, mimeType: mime, digest: digest, copySignatures: !o.opts.RemoveSignatures}

	if manifest.MIMETypeIsMultiImage(mime) {
		return multiArchBlobs(ctx, tbd)
	} else {
		return singleArchBlobs(ctx, tbd)
	}
}

func imageManifest(ctx context.Context, sourceCtx *types.SystemContext, imgRef string, instanceDigest *digest.Digest) ([]byte, string, error) {
	srcRef, err := alltransports.ParseImageName(imgRef)
	if err != nil {
		return nil, "", fmt.Errorf("invalid source name %s: %w", imgRef, err)
	}

	img, err := srcRef.NewImageSource(ctx, sourceCtx)
	if err != nil {
		return nil, "", fmt.Errorf("error when creating a new image source %w", err)
	}
	defer img.Close()

	bytesManifest, mime, err := img.GetManifest(ctx, instanceDigest)
	if err != nil {
		return nil, "", fmt.Errorf("error to get the image manifest and mime type %w", err)
	}

	return bytesManifest, mime, nil
}

func multiArchBlobs(ctx context.Context, tbd toBeDefine) (map[string]string, error) {
	blobs := map[string]string{}
	manifestList, err := manifest.ListFromBlob(tbd.manifestBytes, tbd.mimeType)
	if err != nil {
		return nil, fmt.Errorf("error to get the manifest list %w", err)
	}

	if tbd.copySignatures {
		// TODO ALEX maybe this one is not needed - it duplicates the sigs when the manifest list is creted inthe correct way (one image manifest per arch + manifest list)
		sigBlobs, err := imageSignatureBlobs(ctx, tbd.digest, tbd.imgRef, tbd.sourceCtx)
		if err != nil {
			return nil, err
		}
		for _, digest := range sigBlobs {
			blobs[digest] = ""
		}
	}

	digests := manifestList.Instances()
	for _, digest := range digests {
		blobs[digest.String()] = ""
		singleTbd := tbd

		singleTbd.manifestBytes, singleTbd.mimeType, err = imageManifest(ctx, tbd.sourceCtx, tbd.imgRef, &digest)
		if err != nil {
			return nil, err
		}

		singleArchBlobs, err := singleArchBlobs(ctx, singleTbd)
		if err != nil {
			return nil, err
		}

		maps.Copy(blobs, singleArchBlobs)
	}

	return blobs, nil
}

func singleArchBlobs(ctx context.Context, tbd toBeDefine) (map[string]string, error) {
	blobs := map[string]string{}
	manifestBlobs, err := imageBlobs(tbd.manifestBytes, tbd.mimeType)
	if err != nil {
		return nil, err
	}

	if tbd.copySignatures {
		sigBlobs, err := imageSignatureBlobs(ctx, tbd.digest, tbd.imgRef, tbd.sourceCtx)
		if err != nil {
			return nil, err
		}
		manifestBlobs = append(manifestBlobs, sigBlobs...)
	}

	for _, digest := range manifestBlobs {
		blobs[digest] = ""
	}

	return blobs, nil
}

func imageBlobs(manifestBytes []byte, mimeType string) ([]string, error) {
	blobs := []string{}
	singleArchManifest, err := manifest.FromBlob(manifestBytes, mimeType)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling manifest: %w", err)
	}
	for _, layer := range singleArchManifest.LayerInfos() {
		blobs = append(blobs, layer.Digest.String())
	}
	blobs = append(blobs, singleArchManifest.ConfigInfo().Digest.String())
	return blobs, nil
}

func imageSignatureBlobs(ctx context.Context, signedDigest digest.Digest, imgRef string, sourceCtx *types.SystemContext) ([]string, error) {
	var ref image.ImageSpec
	tag, err := sigstoreAttachmentTag(signedDigest)
	if err != nil {
		return nil, err
	}

	if ref, err = image.ParseRef(imgRef); err != nil {
		return nil, err
	}
	ref = ref.SetTag(tag)

	manifestBytes, mime, err := imageManifest(ctx, sourceCtx, ref.ReferenceWithTransport, nil)
	if err != nil {
		return nil, err
	}

	signatureDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("error to get the digest of the signature manifest %w", err)
	}

	sigBlobs, err := imageBlobs(manifestBytes, mime)
	if err != nil {
		return nil, err
	}

	sigBlobs = append(sigBlobs, signatureDigest.String())

	return sigBlobs, nil
}

// sigstoreAttachmentTag returns a sigstore attachment tag for the specified digest.
func sigstoreAttachmentTag(d digest.Digest) (string, error) {
	if err := d.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest %w", err)
	}
	return strings.Replace(d.String(), ":", "-", 1) + ".sig", nil
}
