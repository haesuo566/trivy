package k8s

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Write writes the results in the give format
func Write(ctx context.Context, k8sreport report.Report, option report.Option) error {
	k8sreport.PrintErrors()

	switch option.Format {
	case types.FormatCycloneDX:
		w := report.NewCycloneDXWriter(option.Output, cdx.BOMFileFormatJSON, option.APIVersion)
		return w.Write(ctx, k8sreport.BOM)
	}
	return nil
}
