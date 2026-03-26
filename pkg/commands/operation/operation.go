package operation

import (
	"context"
	"sync"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
)

var mu sync.Mutex

// InitBuiltinChecks downloads the built-in policies and loads them
func InitBuiltinChecks(ctx context.Context, client *policy.Client, skipUpdate bool, registryOpts ftypes.RegistryOptions) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, "checks-client")

	var err error

	if skipUpdate {
		log.InfoContext(ctx, "No downloadable checks were loaded as --skip-check-update is enabled, loading from existing cache...")

		path := client.BuiltinChecksPath()
		_, _, err := misconf.CheckPathExists(path)
		if err != nil {
			return "", xerrors.Errorf("failed to check cache: %w", err)
		}
		return path, nil
	}

	needsUpdate, err := client.NeedsUpdate(ctx, registryOpts)
	if err != nil {
		return "", xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update the checks bundle")
		log.InfoContext(ctx, "Downloading the checks bundle...")
		if err = client.DownloadBuiltinChecks(ctx, registryOpts); err != nil {
			return "", xerrors.Errorf("failed to download checks bundle: %w", err)
		}
	} else {
		log.InfoContext(ctx,
			"Using existing checks from cache",
			log.String("path", client.BuiltinChecksPath()),
		)
	}

	return client.BuiltinChecksPath(), nil
}

func Exit(opts flag.Options, failedResults bool, m types.Metadata) error {
	if opts.ExitOnEOL != 0 && m.OS != nil && m.OS.Eosl {
		log.Error("Detected EOL OS", log.String("family", string(m.OS.Family)),
			log.String("version", m.OS.Name))
		return &types.ExitError{Code: opts.ExitOnEOL}
	}

	if opts.ExitCode != 0 && failedResults {
		return &types.ExitError{Code: opts.ExitCode}
	}
	return nil
}
