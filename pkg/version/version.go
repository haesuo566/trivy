package version

import (
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
	return types.VersionInfo{
		Version: app.Version(),
	}
}
