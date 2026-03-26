package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMapSpecCheckIDToFilteredResults(t *testing.T) {
	checkIDs := map[types.Scanner][]string{
		types.MisconfigScanner: {
			"KSV012",
			"1.2.31",
			"1.2.32",
		},
		types.VulnerabilityScanner: {
			"CVE-9999-9999",
			"VULN-CRITICAL",
		},
	}
	tests := []struct {
		name     string
		checkIDs map[types.Scanner][]string
		result   types.Result
		want     map[string]types.Results
	}{
		{
			name:     "misconfiguration",
			checkIDs: checkIDs,
			result: types.Result{
				Target: "target",
				Class:  types.ClassConfig,
				Type:   ftypes.Kubernetes,
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:     "KSV012",
						Status: types.MisconfStatusFailure,
					},
					{
						ID:     "KSV013",
						Status: types.MisconfStatusFailure,
					},
					{
						ID:     "1.2.31",
						Status: types.MisconfStatusFailure,
					},
				},
			},
			want: map[string]types.Results{
				"KSV012": {
					{
						Target: "target",
						Class:  types.ClassConfig,
						Type:   ftypes.Kubernetes,
						MisconfSummary: &types.MisconfSummary{
							Successes: 0,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								ID:     "KSV012",
								Status: types.MisconfStatusFailure,
							},
						},
					},
				},
				"1.2.31": {
					{
						Target: "target",
						Class:  types.ClassConfig,
						Type:   ftypes.Kubernetes,
						MisconfSummary: &types.MisconfSummary{
							Successes: 0,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								ID:     "1.2.31",
								Status: types.MisconfStatusFailure,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := spec.MapSpecCheckIDToFilteredResults(tt.result, tt.checkIDs)
			assert.Equalf(t, tt.want, got, "MapSpecCheckIDToFilteredResults()")
		})
	}
}
