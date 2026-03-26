package version

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

// VersionOption is a functional option for NewVersionInfo
type VersionOption func(*versionOptions)

type versionOptions struct {
	forServer bool
}

// Server returns a VersionOption that excludes CheckBundle
// from version info, as these are managed on the client side in client/server mode.
func Server() VersionOption {
	return func(o *versionOptions) {
		o.forServer = true
	}
}

func NewVersionInfo(cacheDir string, opts ...VersionOption) types.VersionInfo {
	var options versionOptions
	for _, opt := range opts {
		opt(&options)
	}

	var pbMeta *types.BundleMetadata

	// Skip CheckBundle for server mode as it is managed on the client side
	if !options.forServer {
		pc, err := policy.NewClient(cacheDir, false, "")
		if err != nil {
			log.Debug("Failed to instantiate policy client", log.Err(err))
		}
		if pc != nil && err == nil {
			ctx := log.WithContextPrefix(context.TODO(), log.PrefixMisconfiguration)
			pbMetaRaw, err := pc.GetMetadata(ctx)

			if err != nil {
				log.Debug("Failed to get policy metadata", log.Err(err))
			} else {
				pbMeta = &types.BundleMetadata{
					Digest:       pbMetaRaw.Digest,
					DownloadedAt: pbMetaRaw.DownloadedAt.UTC(),
				}
			}
		}
	}

	return types.VersionInfo{
		Version:     app.Version(),
		CheckBundle: pbMeta,
	}
}
