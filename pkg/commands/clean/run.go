package clean

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func Run(ctx context.Context, opts flag.Options) error {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	if !opts.CleanAll && !opts.CleanScanCache {
		return xerrors.New("no clean option is specified")
	}

	if opts.CleanAll {
		opts.CleanScanCache = true
	}

	return nil
}
