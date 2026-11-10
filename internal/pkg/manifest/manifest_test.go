package manifest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/types"

	"github.com/openshift/oc-mirror/v2/internal/pkg/api/v2alpha1"
	"github.com/openshift/oc-mirror/v2/internal/pkg/consts"
)

// manifestOnlyRegistry intentionally serves no config or layer blobs. This
// demonstrates that fetching and sizing a manifest only needs its descriptors.
func manifestOnlyRegistry(t *testing.T, raw []byte) (string, *atomic.Int32) {
	t.Helper()
	var manifestRequests, blobRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v2/test/manifests/"):
			manifestRequests.Add(1)
			w.Header().Set("Content-Type", specv1.MediaTypeImageManifest)
			_, _ = w.Write(raw)
		default:
			blobRequests.Add(1)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		assert.Zero(t, blobRequests.Load(), "inspection must not fetch config or layer blobs")
	})
	return consts.DockerProtocol + strings.TrimPrefix(server.URL, "https://") + "/test", &manifestRequests
}

func TestImageManifestValidatesDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(consts.TestFolder, "image-manifest.json"))
	require.NoError(t, err)
	expectedDigest := digest.FromBytes(raw)

	for _, tc := range []struct {
		name       string
		instance   bool
		mismatched bool
	}{
		{name: "matching top-level digest"},
		{name: "mismatched top-level digest", mismatched: true},
		{name: "matching instance digest", instance: true},
		{name: "mismatched instance digest", instance: true, mismatched: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := raw
			if tc.mismatched {
				// Still valid JSON, but not the bytes identified by expectedDigest.
				response = append(append([]byte(nil), raw...), '\n')
			}
			ref, requests := manifestOnlyRegistry(t, response)
			var instanceDigest *digest.Digest
			if tc.instance {
				ref += ":latest"
				instanceDigest = &expectedDigest
			} else {
				ref += "@" + expectedDigest.String()
			}

			got, mime, err := (&Manifest{}).ImageManifest(context.Background(),
				&types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue}, ref, instanceDigest)
			if tc.mismatched {
				require.ErrorContains(t, err, "Manifest does not match provided manifest digest")
			} else {
				require.NoError(t, err)
				assert.Equal(t, raw, got)
				assert.Equal(t, specv1.MediaTypeImageManifest, mime)
			}
			expectedRequests := 1
			if tc.instance {
				// The Docker transport reads the primary manifest when opening
				// a source, then fetches the explicitly requested child.
				expectedRequests++
			}
			assert.EqualValues(t, expectedRequests, requests.Load())
		})
	}
}

func TestInspectImageUsesImageManifestWithoutPullingBlobs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(consts.TestFolder, "image-manifest.json"))
	require.NoError(t, err)
	ref, requests := manifestOnlyRegistry(t, raw)
	ref += "@" + digest.FromBytes(raw).String()
	sys := &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue}
	m := &Manifest{}
	inspection, err := m.InspectImage(context.Background(), sys, ref, nil, true)
	require.NoError(t, err)
	require.NoError(t, inspection.SizeError)
	require.Len(t, inspection.Blobs, 7)
	var total int64
	for _, blob := range inspection.Blobs {
		assert.NotEmpty(t, blob.Digest)
		assert.NotEmpty(t, blob.MediaType)
		total += blob.Size
	}
	assert.EqualValues(t, 144979560, total)
	assert.EqualValues(t, 1, requests.Load(), "inspection and sizing use a single manifest response")
}

func TestInspectImageCombinesMappingAndSizing(t *testing.T) {
	leaf, err := os.ReadFile(filepath.Join(consts.TestFolder, "image-manifest.json"))
	require.NoError(t, err)
	amd64Digest := digest.FromBytes(leaf)
	arm64Leaf := append(append([]byte(nil), leaf...), '\n')
	arm64Digest := digest.FromBytes(arm64Leaf)
	attestationDigest := digest.FromString("unavailable attestation")
	index := specv1.Index{MediaType: specv1.MediaTypeImageIndex}
	index.SchemaVersion = 2
	index.Manifests = []specv1.Descriptor{
		{MediaType: specv1.MediaTypeImageManifest, Digest: amd64Digest, Size: int64(len(leaf)), Platform: &specv1.Platform{OS: "linux", Architecture: "amd64"}},
		{MediaType: specv1.MediaTypeImageManifest, Digest: arm64Digest, Size: int64(len(arm64Leaf)), Platform: &specv1.Platform{OS: "linux", Architecture: "arm64"}},
		{MediaType: specv1.MediaTypeImageManifest, Digest: attestationDigest, Size: 10, Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
	}
	root, err := json.Marshal(index)
	require.NoError(t, err)
	rootDigest := digest.FromBytes(root)
	wantDigests := []string{amd64Digest.String(), arm64Digest.String(), attestationDigest.String()}

	for _, tc := range []struct {
		name        string
		size        bool
		filtered    bool
		absent      bool
		missing     bool
		corrupt     bool
		corruptRoot bool
		wantBlobs   int
		wantChild   int32
	}{
		{name: "mapping only"},
		{name: "all real platforms", size: true, wantBlobs: 14, wantChild: 2},
		{name: "filtered sizing preserves all mapping digests", size: true, filtered: true, wantBlobs: 7, wantChild: 1},
		{name: "missing requested platform preserves mapping", size: true, filtered: true, absent: true, wantChild: 1},
		{name: "missing child preserves mapping", size: true, filtered: true, missing: true, wantChild: 1},
		{name: "corrupt child preserves mapping", size: true, filtered: true, corrupt: true, wantChild: 1},
		{name: "corrupt root rejects mapping", size: true, corruptRoot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rootRequests, childRequests, blobRequests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case "/v2/test/manifests/" + rootDigest.String():
					rootRequests.Add(1)
					w.Header().Set("Content-Type", specv1.MediaTypeImageIndex)
					_, _ = w.Write(root)
					if tc.corruptRoot {
						_, _ = w.Write([]byte("\n"))
					}
				case "/v2/test/manifests/" + amd64Digest.String():
					childRequests.Add(1)
					if tc.missing {
						http.NotFound(w, r)
						return
					}
					w.Header().Set("Content-Type", specv1.MediaTypeImageManifest)
					_, _ = w.Write(leaf)
					if tc.corrupt {
						_, _ = w.Write([]byte("\n"))
					}
				case "/v2/test/manifests/" + arm64Digest.String():
					childRequests.Add(1)
					w.Header().Set("Content-Type", specv1.MediaTypeImageManifest)
					_, _ = w.Write(arm64Leaf)
				default:
					blobRequests.Add(1)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			ref := consts.DockerProtocol + strings.TrimPrefix(server.URL, "https://") + "/test@" + rootDigest.String()
			var filters []v2alpha1.InstancePlatformFilter
			if tc.filtered {
				filters = []v2alpha1.InstancePlatformFilter{{OS: "linux", Architecture: "amd64"}}
			}
			if tc.absent {
				filters = append(filters, v2alpha1.InstancePlatformFilter{OS: "linux", Architecture: "s390x"})
			}
			result, err := (&Manifest{}).InspectImage(context.Background(),
				&types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue}, ref, filters, tc.size)
			if tc.corruptRoot {
				require.ErrorContains(t, err, "Manifest does not match provided manifest digest")
				assert.Empty(t, result.ManifestListDigests)
			} else {
				require.NoError(t, err)
				assert.Equal(t, wantDigests, result.ManifestListDigests)
				if tc.missing || tc.corrupt || tc.absent {
					require.Error(t, result.SizeError)
					if tc.absent {
						assert.ErrorContains(t, result.SizeError, "no instances found for platform linux/s390x")
					} else {
						assert.ErrorContains(t, result.SizeError, amd64Digest.String())
					}
				} else {
					require.NoError(t, result.SizeError)
				}
			}
			assert.Len(t, result.Blobs, tc.wantBlobs)
			// InspectImage reads the root once; each separately opened Docker
			// source also reads its primary manifest before fetching a child.
			assert.EqualValues(t, 1+tc.wantChild, rootRequests.Load())
			assert.Equal(t, tc.wantChild, childRequests.Load())
			assert.Zero(t, blobRequests.Load(), "no config, layer, or attestation downloads")
		})
	}
}
