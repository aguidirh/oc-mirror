# Manifest-only image inspection

Experimental alternative for [PR #1626](https://github.com/openshift/oc-mirror/pull/1626),
based on commit `39847c02`. The combined-pass refactor is optional and separate
from the digest-validation change for CLID-360; these ideas can be adopted
independently.

Dry-run mapping and sizing now share one inspection per source:

```text
DryRun -> inspectImages -> InspectImage
  -> ImageManifest -> UnparsedInstance(...).Manifest(ctx)
  -> ListFromBlob for an index:
       retain all instance digests for mapping
       fetch selected child manifests through ImageManifest for sizing
  -> FromBlob -> ConfigInfo + LayerInfos -> []types.BlobInfo
```

`ImageManifest` remains the only fetching entry point in the manifest package.
It validates expected digests and closes the source before returning. Child
digests are passed through the transport-neutral instance argument. No config
or layer blobs are downloaded.

There is no transport-specific reference rewriting. Opening a Docker source for
a child can also fetch its parent; the single pass removes duplicate application
inspection, not all transport-level requests.

The combined pass replaces the separate mapping/sizing passes and their custom
cross-call cache. A child-sizing error is returned separately from mapping
digests, so mappings are preserved even when the size report is incomplete.
Shared sources combine their platform requirements; an unrestricted request
includes all platforms. Disk-to-mirror still measures archive files and only
inspects top-level manifests when manifest-list mapping is requested.

Tasks and results share one CLI-local record; reports use ordinary errors rather
than additional ImageSetConfiguration API types.

CLI aggregation and workflow formulas are unchanged. Unknown blob sizes and
missing requested platforms make the report incomplete. Zero-sized blobs are
valid. Manifest/index bytes are not added to the estimate.

## CLID-360

The ticket requests digest validation when reading manifests from untrusted
sources. Both v2 fetching locations (`Manifest.ImageManifest` and
`mirror.filterAttestationInstances`) now use `UnparsedInstance(...).Manifest()`.
Deprecated v1 code is unchanged. Validation checks an expected digest when one
exists; a mutable tag alone does not provide a trusted digest.

Tests cover the combined pass, descriptor-only sizing, missing/tampered
children, preservation of mapping digests, and rejection of tampered top-level
manifests in both v2 fetching locations.
