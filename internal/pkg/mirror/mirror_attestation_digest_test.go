package mirror

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	specv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/transports/alltransports"
	"go.podman.io/image/v5/types"
)

// CLID-360: attestation inspection must validate pinned manifests too, not just
// the manifests read through the manifest package's ImageManifest method.
func TestFilterAttestationInstancesValidatesManifestDigest(t *testing.T) {
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	expected := digest.FromBytes(raw)
	for _, corrupt := range []bool{false, true} {
		name := "matching digest"
		if corrupt {
			name = "mismatched digest"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", specv1.MediaTypeImageIndex)
				_, _ = w.Write(raw)
				if corrupt {
					_, _ = w.Write([]byte("\n"))
				}
			}))
			defer server.Close()
			ref, err := alltransports.ParseImageName("docker://" + strings.TrimPrefix(server.URL, "https://") + "/test@" + expected.String())
			require.NoError(t, err)
			filter, err := filterAttestationInstances(context.Background(), ref, &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue})
			if corrupt {
				require.ErrorContains(t, err, "Manifest does not match provided manifest digest")
			} else {
				require.NoError(t, err)
			}
			require.Nil(t, filter)
		})
	}
}
