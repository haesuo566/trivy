package report

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/report/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SchemaVersion = 2
)

// Write writes the result to output, format as passed in argument
func Write(ctx context.Context, report types.Report, option flag.Options) (err error) {
	output, cleanup, err := option.OutputWriter(ctx)
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			err = multierror.Append(err, cerr)
		}
	}()

	var writer Writer
	switch option.Format {
	case types.FormatCycloneDX:
		// TODO: support xml format option with cyclonedx writer
		writer = cyclonedx.NewWriter(output, option.AppVersion)
	case types.FormatSPDX, types.FormatSPDXJSON:
		writer = spdx.NewWriter(output, option.AppVersion, option.Format)
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	if err = writer.Write(ctx, report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}

// Writer defines the result write operation
type Writer interface {
	Write(context.Context, types.Report) error
}
