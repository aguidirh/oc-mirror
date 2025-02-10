package operator

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"github.com/openshift/oc-mirror/v2/internal/pkg/api/v2alpha1"
	"github.com/openshift/oc-mirror/v2/internal/pkg/image"
	clog "github.com/openshift/oc-mirror/v2/internal/pkg/log"
	"github.com/operator-framework/operator-registry/alpha/action"
	"github.com/operator-framework/operator-registry/alpha/declcfg"
	"github.com/operator-framework/operator-registry/alpha/property"
	filter "github.com/sherine-k/catalog-filter/pkg/filter/mirror-config/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var internalLog clog.PluggableLoggerInterface

type catalogHandler struct {
	Log clog.PluggableLoggerInterface
}

type OperatorCatalog struct {
	// Packages is a map that stores the packages in the operator catalog.
	// The key is the package name and the value is the corresponding declcfg.Package object.
	Packages map[string]declcfg.Package
	// Channels is a map that stores the channels for each package in the operator catalog.
	// The key is the package name and the value is a slice of declcfg.Channel objects.
	Channels map[string][]declcfg.Channel
	// ChannelEntries is a map that stores the channel entries (Bundle names) for each channel and package in the operator catalog.
	// The first key is the package name, the second key is the channel name, and the third key is the bundle name (or channel entry name).
	// The value is the corresponding declcfg.ChannelEntry object.
	ChannelEntries map[string]map[string]map[string]declcfg.ChannelEntry
	// BundlesByPkgAndName is a map that stores the bundles for each package and bundle name in the operator catalog.
	// The first key is the package name, the second key is the bundle name, and the value is the corresponding declcfg.Bundle object.
	// This map allows quick access to the bundles based on the package and bundle name.
	BundlesByPkgAndName map[string]map[string]declcfg.Bundle
}

func setInternalLog(log clog.PluggableLoggerInterface) {
	if internalLog == nil {
		internalLog = log
	}
}

func (o catalogHandler) getDeclarativeConfig(filePath string) (*declcfg.DeclarativeConfig, error) {
	setInternalLog(o.Log)
	return declcfg.LoadFS(context.Background(), os.DirFS(filePath))
}

func saveDeclarativeConfig(fbc declcfg.DeclarativeConfig, path string) error {
	return declcfg.WriteFS(fbc, path, declcfg.WriteJSON, ".json")
}

func filterFromImageSetConfig(iscCatalogFilter v2alpha1.Operator) (filter.FilterConfiguration, error) {
	catFilter := filter.FilterConfiguration{
		TypeMeta: v1.TypeMeta{
			Kind:       "FilterConfiguration",
			APIVersion: "olm.operatorframework.io/filter/mirror/v1alpha1",
		},
		Packages: []filter.Package{},
	}
	if len(iscCatalogFilter.Packages) > 0 {
		for _, op := range iscCatalogFilter.Packages {
			p := filter.Package{
				Name: op.Name,
			}
			if op.DefaultChannel != "" {
				p.DefaultChannel = op.DefaultChannel
			}
			if op.MinVersion != "" {
				p.VersionRange = ">=" + op.MinVersion
			}
			if op.MaxVersion != "" {
				p.VersionRange += " <=" + op.MaxVersion
			}
			if len(op.Channels) > 0 {
				p.Channels = []filter.Channel{}
				for _, ch := range op.Channels {
					filterChan := filter.Channel{
						Name: ch.Name,
					}

					if ch.MinVersion != "" {
						filterChan.VersionRange = ">=" + ch.MinVersion
					}
					if ch.MaxVersion != "" {
						filterChan.VersionRange += " <=" + ch.MaxVersion
					}
					p.Channels = append(p.Channels, filterChan)
				}
			}
			catFilter.Packages = append(catFilter.Packages, p)
		}
	}
	return catFilter, catFilter.Validate()
}

func filterCatalog(ctx context.Context, operatorCatalog declcfg.DeclarativeConfig, iscCatalogFilter v2alpha1.Operator) (*declcfg.DeclarativeConfig, error) {
	config, err := filterFromImageSetConfig(iscCatalogFilter)
	if err != nil {
		return nil, err
	}
	ctlgFilter := filter.NewMirrorFilter(config, []filter.FilterOption{filter.InFull(iscCatalogFilter.Full)}...)
	return ctlgFilter.FilterCatalog(ctx, &operatorCatalog)
}

func (o catalogHandler) getCatalog(filePath string) (OperatorCatalog, error) {
	setInternalLog(o.Log)
	cfg, err := declcfg.LoadFS(context.Background(), os.DirFS(filePath))

	operatorCatalog := newOperatorCatalog()

	// OCPBUGS-36445 ensure we skip invalid catalogs
	// avoiding SIGSEGV violation
	if err != nil {
		catalog := strings.Split(filePath, "hold-operator/")
		if len(catalog) <= 1 {
			catalog = []string{"", filePath}
		}
		o.Log.Warn("[GetCatalog] invalid catalog %s : SKIPPING", catalog[1])
		return operatorCatalog, nil
	}

	for _, p := range cfg.Packages {
		operatorCatalog.Packages[p.Name] = p
	}

	for _, c := range cfg.Channels {
		operatorCatalog.Channels[c.Package] = append(operatorCatalog.Channels[c.Package], c)
		for _, e := range c.Entries {
			if _, ok := operatorCatalog.ChannelEntries[c.Package]; !ok {
				operatorCatalog.ChannelEntries[c.Package] = make(map[string]map[string]declcfg.ChannelEntry)
			}
			if _, ok := operatorCatalog.ChannelEntries[c.Package][c.Name]; !ok {
				operatorCatalog.ChannelEntries[c.Package][c.Name] = make(map[string]declcfg.ChannelEntry)
			}

			operatorCatalog.ChannelEntries[c.Package][c.Name][e.Name] = e
		}

	}

	for _, b := range cfg.Bundles {
		if _, ok := operatorCatalog.BundlesByPkgAndName[b.Package]; !ok {
			operatorCatalog.BundlesByPkgAndName[b.Package] = make(map[string]declcfg.Bundle)
		}

		if _, ok := operatorCatalog.BundlesByPkgAndName[b.Package][b.Name]; !ok {
			operatorCatalog.BundlesByPkgAndName[b.Package][b.Name] = b
		}
	}

	return operatorCatalog, err
}

func (o catalogHandler) filterRelatedImagesFromCatalog(operatorCatalog OperatorCatalog, ctlgInIsc v2alpha1.Operator, copyImageSchemaMap *v2alpha1.CopyImageSchemaMap) (map[string][]v2alpha1.RelatedImage, error) {
	setInternalLog(o.Log)

	relatedImages := make(map[string][]v2alpha1.RelatedImage)

	if len(ctlgInIsc.Packages) == 0 {
		for operatorName := range operatorCatalog.Packages {

			operatorConfig := parseOperatorCatalogByOperator(operatorName, operatorCatalog)

			ri, err := getRelatedImages(operatorName, operatorConfig, v2alpha1.IncludePackage{}, ctlgInIsc.Full, copyImageSchemaMap)

			if err != nil {
				return relatedImages, err
			}

			maps.Copy(relatedImages, ri)
		}
	} else {
		for _, iscOperator := range ctlgInIsc.Packages {
			operatorConfig := parseOperatorCatalogByOperator(iscOperator.Name, operatorCatalog)
			if operatorConfig.BundlesByPkgAndName[iscOperator.Name] == nil {
				o.Log.Warn("[OperatorImageCollector] package %s not found in catalog %s", iscOperator.Name, ctlgInIsc.Catalog)
				continue
			}
			ri, err := getRelatedImages(iscOperator.Name, operatorConfig, iscOperator, ctlgInIsc.Full, copyImageSchemaMap)
			if err != nil {
				return relatedImages, err
			}
			if len(ri) == 0 {
				o.Log.Warn("[OperatorImageCollector] no bundles matching filtering for %s in catalog %s", iscOperator.Name, ctlgInIsc.Catalog)
				continue
			}

			maps.Copy(relatedImages, ri)
		}
	}

	if o.Log.GetLevel() == "debug" {
		for k := range relatedImages {
			o.Log.Debug("bundle after filtered : %s", k)
		}
	}

	return relatedImages, nil
}

func (o catalogHandler) getRelatedImagesFromCatalog(dc *declcfg.DeclarativeConfig, copyImageSchemaMap *v2alpha1.CopyImageSchemaMap, renderBundles bool) (map[string][]v2alpha1.RelatedImage, error) {
	setInternalLog(o.Log)

	relatedImages := make(map[string][]v2alpha1.RelatedImage)

	bundleStartTime := time.Now()

	for _, bundle := range dc.Bundles {

		// r := action.Render{
		// 	Refs:           []string{"quay.io/community-operator-pipeline-prod/argocd-operator@sha256:16c2cced24ae17315939b4e09e36396184634a9b86b8a2288ef93f4536caf861", "quay.io/community-operator-pipeline-prod/argocd-operator@sha256:c7664e237434bb51d0af2a702e9089da7e90aca468ab964872d06c9e86b9d561", "quay.io/community-operator-pipeline-prod/argocd-operator@sha256:b174047d566b280c58501a9b37daadc8ccebac2347de0c9124e42ab10d725ebe"},
		// 	AllowedRefMask: action.RefBundleImage,
		// }

		//Rendering the entire catalog at once, does not work, only the head get the bundle metadata
		// r := action.Render{
		// 	Refs: []string{"/home/aguidi/go/src/github.com/aguidirh/oc-mirror/alex-tests/ocpbugs-42313/working-dir/operator-catalogs/community-operator-index/1bdcaec6e7f78fe642cd720fbadea3622adfa3c81f4b571863b453d0cd266a8c/catalog-config/configs/argocd-operator"},
		// 	// AllowedRefMask: action.RefBundleImage,
		// }

		if renderBundles {
			var found bool
			for _, p := range bundle.Properties {
				if p.Type == property.TypeBundleObject {
					found = true
				}
			}

			if !found {
				r := action.Render{
					Refs:           []string{bundle.Image},
					AllowedRefMask: action.RefBundleImage,
				}

				testdc, err := r.Run(context.Background())
				if err != nil {
					o.Log.Error("error rendering bundle: %s", err.Error())
				} else {
					bundle = testdc.Bundles[0]
				}
			}
		}

		// err = saveDeclarativeConfig(*testdc, "/home/aguidi/go/src/github.com/aguidirh/oc-mirror/alex-tests/bundle-cfg-test/"+bundle.Name)

		ris := handleRelatedImages(bundle, bundle.Package, copyImageSchemaMap)
		relatedImages[bundle.Name] = ris
	}

	bundleEndTime := time.Now()
	bundleExecTime := bundleEndTime.Sub(bundleStartTime)
	o.Log.Info("bundle collection time     : %v", bundleExecTime)

	return relatedImages, nil
}

func newOperatorCatalog() OperatorCatalog {
	operatorConfig := OperatorCatalog{
		Packages:            make(map[string]declcfg.Package),
		Channels:            make(map[string][]declcfg.Channel),
		ChannelEntries:      make(map[string]map[string]map[string]declcfg.ChannelEntry),
		BundlesByPkgAndName: make(map[string]map[string]declcfg.Bundle),
	}

	return operatorConfig
}

func parseOperatorCatalogByOperator(operatorName string, operatorCatalog OperatorCatalog) OperatorCatalog {
	operatorConfig := newOperatorCatalog()
	operatorConfig.Packages[operatorName] = operatorCatalog.Packages[operatorName]
	operatorConfig.Channels[operatorName] = operatorCatalog.Channels[operatorName]
	operatorConfig.ChannelEntries[operatorName] = operatorCatalog.ChannelEntries[operatorName]
	operatorConfig.BundlesByPkgAndName[operatorName] = operatorCatalog.BundlesByPkgAndName[operatorName]

	return operatorConfig
}

func getRelatedImages(operatorName string, operatorConfig OperatorCatalog, iscOperator v2alpha1.IncludePackage, full bool, copyImageSchemaMap *v2alpha1.CopyImageSchemaMap) (map[string][]v2alpha1.RelatedImage, error) {
	invalid, err := isInvalidFiltering(iscOperator, full)
	if invalid {
		return nil, err
	}

	relatedImages := make(map[string][]v2alpha1.RelatedImage)
	var filteredBundles []string
	defaultChannel := operatorConfig.Packages[operatorName].DefaultChannel

	switch {
	case len(iscOperator.Channels) > 0:
		for _, iscChannel := range iscOperator.Channels {
			internalLog.Debug("found channel : %v", iscChannel)
			chEntries := operatorConfig.ChannelEntries[operatorName][iscChannel.Name]
			bundles, err := filterBundles(chEntries, iscChannel.IncludeBundle.MinVersion, iscChannel.IncludeBundle.MaxVersion, full)
			if err != nil {
				internalLog.Error(errorSemver, err)
			}
			internalLog.Debug("adding bundles : %s", bundles)
			filteredBundles = append(filteredBundles, bundles...)
		}
	default:
		chEntries := operatorConfig.ChannelEntries[operatorName][defaultChannel]
		bundles, err := filterBundles(chEntries, iscOperator.MinVersion, iscOperator.MaxVersion, full)

		if err != nil {
			internalLog.Error(errorSemver, err)
		}
		internalLog.Debug("adding bundles : %s", bundles)
		filteredBundles = append(filteredBundles, bundles...)
	}

	for _, bundle := range operatorConfig.BundlesByPkgAndName[operatorName] {
		if full {
			if len(filteredBundles) > 0 && len(iscOperator.Channels) > 0 {
				if slices.Contains(filteredBundles, bundle.Name) {
					relatedImages[bundle.Name] = handleRelatedImages(bundle, operatorName, copyImageSchemaMap)
				}
			} else {
				relatedImages[bundle.Name] = handleRelatedImages(bundle, operatorName, copyImageSchemaMap)
			}
		} else {
			if slices.Contains(filteredBundles, bundle.Name) {
				relatedImages[bundle.Name] = handleRelatedImages(bundle, operatorName, copyImageSchemaMap)
			}
		}
	}

	return relatedImages, nil
}

func isInvalidFiltering(pkg v2alpha1.IncludePackage, full bool) (bool, error) {
	invalid := (len(pkg.Channels) > 0 && (pkg.MinVersion != "" || pkg.MaxVersion != "")) ||
		full && (pkg.MinVersion != "" || pkg.MaxVersion != "")
	if invalid {
		return invalid, fmt.Errorf("cannot use channels/full and min/max versions at the same time")
	}
	return false, nil
}

func filterBundles(channelEntries map[string]declcfg.ChannelEntry, min string, max string, full bool) ([]string, error) {
	var minVersion, maxVersion semver.Version
	var err error

	if min != "" {
		minVersion, err = semver.ParseTolerant(min)
		if err != nil {
			return nil, err
		}
	}

	if max != "" {
		maxVersion, err = semver.ParseTolerant(max)
		if err != nil {
			return nil, err
		}
	}

	var filtered []string
	currentHead := semver.MustParse("0.0.0")
	var currentHeadName string
	preReleases := make(map[string]declcfg.ChannelEntry)

	for _, chEntry := range channelEntries {

		version, err := getChannelEntrySemVer(chEntry.Name)
		// OCPBUGS-33081
		// if we get a semver error just skip this bundle
		if err != nil {
			continue
		}

		if isPreRelease(version) {
			pre := make([]string, len(version.Pre))
			for i, pr := range version.Pre {
				pre[i] = pr.String()
			}
			preString := strings.Join(pre, ".")

			preReleases[fmt.Sprintf("%d.%d.%d-%s", version.Major, version.Minor, version.Patch, preString)] = chEntry
		}

		// preReleases that skip the current head of a channel should be considered as head.
		// even if from the semver perspective, they are LT(currentHead)
		if version.GT(currentHead) {
			currentHead = version
			currentHeadName = chEntry.Name
		}

		//Include this bundle to the filtered list if:
		// * its version is prerelease of an already included bundle
		// * its version is between min and max (both defined)
		// * its version is greater than min (defined), and no max is defined (which means up to channel head)
		// * its version is under max (defined) and no min is defined
		if (min == "" || version.GTE(minVersion)) && (max == "" || version.LTE(maxVersion)) {
			// In case full == false and min and max are empty, do not include this bundle:
			// this is the case where there is no filtering, and where only the channel's head shall be included in the output filter.
			if min == "" && max == "" && !full {
				continue
			}
			filtered = append(filtered, chEntry.Name)
		}
	}

	if len(preReleases) > 0 {
		for version, chEntry := range preReleases {
			if isPreReleaseHead(chEntry, currentHeadName) {
				currentHeadName = chEntry.Name

			}

			if isPreReleaseOfFilteredVersion(version, chEntry.Name, filtered) {
				filtered = append(filtered, chEntry.Name)
			}
		}
	}

	if min == "" && max == "" && currentHead.String() != "0.0.0" && !full {
		return []string{currentHeadName}, nil
	}

	return filtered, nil
}

func getChannelEntrySemVer(chEntryName string) (semver.Version, error) {
	nameSplit := strings.Split(chEntryName, ".")
	if len(nameSplit) < 4 {
		return semver.Version{}, fmt.Errorf("incorrect version format %s ", chEntryName)
	}

	version, err := semver.ParseTolerant(strings.Join(nameSplit[1:], "."))
	if err != nil {
		return semver.Version{}, fmt.Errorf("%s %v", chEntryName, err)
	}

	return version, err
}

func isPreRelease(version semver.Version) bool {
	return len(version.Pre) > 0
}

func isPreReleaseHead(channelEntry declcfg.ChannelEntry, currentHead string) bool {
	return slices.Contains(channelEntry.Skips, currentHead) || channelEntry.Replaces == currentHead
}

func isPreReleaseOfFilteredVersion(version string, chEntryName string, filteredVersions []string) bool {
	if slices.Contains(filteredVersions, chEntryName) {
		return false
	}

	for _, filteredVersion := range filteredVersions {
		if strings.Contains(filteredVersion, strings.Split(version, "-")[0]) {
			return true
		}
	}

	return false
}

func handleRelatedImages(bundle declcfg.Bundle, operatorName string, copyImageSchemaMap *v2alpha1.CopyImageSchemaMap) []v2alpha1.RelatedImage {
	var relatedImages []v2alpha1.RelatedImage

	for _, ri := range bundle.RelatedImages {
		if strings.Contains(ri.Image, "oci://") {
			internalLog.Warn("%s 'oci' is not supported in operator catalogs : SKIPPING", ri.Image)
			continue
		}
		relateImage := v2alpha1.RelatedImage{}
		if ri.Image == bundle.Image {
			relateImage.Name = ri.Name
			relateImage.Image = ri.Image
			relateImage.Type = v2alpha1.TypeOperatorBundle
		} else {
			relateImage.Name = ri.Name
			relateImage.Image = ri.Image
			relateImage.Type = v2alpha1.TypeOperatorRelatedImage
		}

		imgSpec, err := image.ParseRef(ri.Image)
		if err != nil {
			internalLog.Warn("error parsing image %s : %v", ri.Image, err)
		}

		operators := copyImageSchemaMap.OperatorsByImage[imgSpec.ReferenceWithTransport]

		if _, found := operators[operatorName]; !found {
			if operators == nil {
				copyImageSchemaMap.OperatorsByImage[imgSpec.ReferenceWithTransport] = make(map[string]struct{})
			}
			copyImageSchemaMap.OperatorsByImage[imgSpec.ReferenceWithTransport][operatorName] = struct{}{}
		}

		bundles := copyImageSchemaMap.BundlesByImage[imgSpec.ReferenceWithTransport]
		if _, found := bundles[bundle.Name]; !found {
			if bundles == nil {
				copyImageSchemaMap.BundlesByImage[imgSpec.ReferenceWithTransport] = make(map[string]string)
			}
			copyImageSchemaMap.BundlesByImage[imgSpec.ReferenceWithTransport][bundle.Image] = bundle.Name
		}

		relatedImages = append(relatedImages, relateImage)
	}

	return relatedImages
}
