package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type TableWriter struct {
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string

}

const (
	NamespaceColumn         = "Namespace"
	ResourceColumn          = "Resource"
	VulnerabilitiesColumn   = "Vulnerabilities"
	MisconfigurationsColumn = "Misconfigurations"
	RbacAssessmentColumn = "RBAC Assessment"
)

func WorkloadColumns() []string {
	return []string{
		VulnerabilitiesColumn,
		MisconfigurationsColumn,
	}
}

func RoleColumns() []string {
	return []string{RbacAssessmentColumn}
}

func InfraColumns() []string {
	return []string{
		VulnerabilitiesColumn,
		MisconfigurationsColumn,
	}
}

func (tw TableWriter) Write(ctx context.Context, report Report) error {
	switch tw.Report {
	case SummaryReport:
		writer := NewSummaryWriter(tw.Output, tw.Severities, tw.ColumnHeading)
		return writer.Write(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary"`, tw.Report)
	}
}

// updateTargetContext add context namespace, kind and name to the target
func updateTargetContext(r *Resource) {
	targetName := fmt.Sprintf("namespace: %s, %s: %s", r.Namespace, strings.ToLower(r.Kind), r.Name)
	if r.Kind == "NodeComponents" || r.Kind == "NodeInfo" {
		targetName = fmt.Sprintf("node: %s", r.Name)
	}
	for i := range r.Report.Results {
		r.Report.Results[i].Target = targetName
	}
}
