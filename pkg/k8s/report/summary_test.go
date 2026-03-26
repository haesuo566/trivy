package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReport_ColumnHeading(t *testing.T) {
	tests := []struct {
		name             string
		scanners         types.Scanners
		availableColumns []string
		want             []string
	}{
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
