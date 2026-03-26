package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReport_ColumnHeading(t *testing.T) {
	allScanners := types.Scanners{
		types.VulnerabilityScanner,
		types.MisconfigScanner,
		types.RBACScanner,
	}

	tests := []struct {
		name             string
		scanners         types.Scanners
		availableColumns []string
		want             []string
	}{
		{
			name:             "filter workload columns",
			scanners:         allScanners,
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				VulnerabilitiesColumn,
				MisconfigurationsColumn,
			},
		},
		{
			name:             "filter rbac columns",
			scanners:         allScanners,
			availableColumns: RoleColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				RbacAssessmentColumn,
			},
		},
		{
			name:             "filter infra columns",
			scanners:         allScanners,
			availableColumns: InfraColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				VulnerabilitiesColumn,
				MisconfigurationsColumn,
			},
		},
		{
			name:             "config column only",
			scanners:         types.Scanners{types.MisconfigScanner},
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				MisconfigurationsColumn,
			},
		},
		{
			name:             "vuln column only",
			scanners:         types.Scanners{types.VulnerabilityScanner},
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				VulnerabilitiesColumn,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			column := ColumnHeading(tt.scanners, tt.availableColumns)
			if !assert.Equal(t, tt.want, column) {
				t.Error(fmt.Errorf("TestReport_ColumnHeading want %v got %v", tt.want, column))
			}
		})
	}
}
