package flag

import (
	"slices"
	"strings"

	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// e.g. config yaml:
//
//	format: cyclonedx
//	severity: HIGH,CRITICAL
var (
	FormatFlag = Flag[string]{
		Name:          "format",
		ConfigName:    "format",
		Shorthand:     "f",
		Default:       string(types.FormatCycloneDX),
		Values:        xstrings.ToStringSlice(types.SupportedFormats),
		Usage:         "format",
		TelemetrySafe: true,
	}
	ReportFormatFlag = Flag[string]{
		Name:       "report",
		ConfigName: "report",
		Default:    "all",
		Values: []string{
			"all",
			"summary",
		},
		Usage:         "specify a report format for the output",
		TelemetrySafe: true,
	}
	IgnoreFileFlag = Flag[string]{
		Name:       "ignorefile",
		ConfigName: "ignorefile",
		Default:    result.DefaultIgnoreFile,
		Usage:      "specify .trivyignore file",
	}
	IgnorePolicyFlag = Flag[string]{
		Name:       "ignore-policy",
		ConfigName: "ignore-policy",
		Usage:      "specify the Rego file path to evaluate each vulnerability",
	}
	ExitCodeFlag = Flag[int]{
		Name:          "exit-code",
		ConfigName:    "exit-code",
		Usage:         "specify exit code when any security issues are found",
		TelemetrySafe: true,
	}
	ExitOnEOLFlag = Flag[int]{
		Name:          "exit-on-eol",
		ConfigName:    "exit-on-eol",
		Usage:         "exit with the specified code when the OS reaches end of service/life",
		TelemetrySafe: true,
	}
	OutputFlag = Flag[string]{
		Name:       "output",
		ConfigName: "output",
		Shorthand:  "o",
		Usage:      "output file name",
	}
	SeverityFlag = Flag[[]string]{
		Name:          "severity",
		ConfigName:    "severity",
		Shorthand:     "s",
		Default:       dbTypes.SeverityNames,
		Values:        dbTypes.SeverityNames,
		Usage:         "severities of security issues to be displayed",
		TelemetrySafe: true,
	}
	ComplianceFlag = Flag[string]{
		Name:       "compliance",
		ConfigName: "scan.compliance",
		Usage:      "compliance report to generate",
	}
)

// ReportFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlagGroup struct {
	Format       *Flag[string]
	ReportFormat *Flag[string]
	IgnoreFile   *Flag[string]
	IgnorePolicy *Flag[string]
	ExitCode     *Flag[int]
	ExitOnEOL    *Flag[int]
	Output       *Flag[string]
	Severity     *Flag[[]string]
	Compliance   *Flag[string]
}

type ReportOptions struct {
	Format       types.Format
	ReportFormat string
	IgnoreFile   string
	ExitCode     int
	ExitOnEOL    int
	IgnorePolicy string
	Output       string
	Severities   []dbTypes.Severity
	Compliance   spec.ComplianceSpec
}

func NewReportFlagGroup() *ReportFlagGroup {
	return &ReportFlagGroup{
		Format:       FormatFlag.Clone(),
		ReportFormat: ReportFormatFlag.Clone(),
		IgnoreFile:   IgnoreFileFlag.Clone(),
		IgnorePolicy: IgnorePolicyFlag.Clone(),
		ExitCode:     ExitCodeFlag.Clone(),
		ExitOnEOL:    ExitOnEOLFlag.Clone(),
		Output:       OutputFlag.Clone(),
		Severity:     SeverityFlag.Clone(),
		Compliance:   ComplianceFlag.Clone(),
	}
}

func (f *ReportFlagGroup) Name() string {
	return "Report"
}

func (f *ReportFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Format,
		f.ReportFormat,
		f.IgnoreFile,
		f.IgnorePolicy,
		f.ExitCode,
		f.ExitOnEOL,
		f.Output,
		f.Severity,
		f.Compliance,
	}
}

func (f *ReportFlagGroup) ToOptions(opts *Options) error {
	format := types.Format(f.Format.Value())

	cs, err := loadComplianceTypes(f.Compliance.Value())
	if err != nil {
		return xerrors.Errorf("unable to load compliance spec: %w", err)
	}

	if viper.IsSet(f.IgnoreFile.ConfigName) && !fsutils.FileExists(f.IgnoreFile.Value()) {
		return xerrors.Errorf("ignore file not found: %s", f.IgnoreFile.Value())
	}

	opts.ReportOptions = ReportOptions{
		Format:       format,
		ReportFormat: f.ReportFormat.Value(),
		IgnoreFile:   f.IgnoreFile.Value(),
		ExitCode:     f.ExitCode.Value(),
		ExitOnEOL:    f.ExitOnEOL.Value(),
		IgnorePolicy: f.IgnorePolicy.Value(),
		Output:       f.Output.Value(),
		Severities:   toSeverity(f.Severity.Value()),
		Compliance:   cs,
	}
	return nil
}

func loadComplianceTypes(compliance string) (spec.ComplianceSpec, error) {
	if compliance != "" && !slices.Contains(types.SupportedCompliances, compliance) && !strings.HasPrefix(compliance, "@") {
		return spec.ComplianceSpec{}, xerrors.Errorf("unknown compliance : %v", compliance)
	}

	cs, err := spec.GetComplianceSpec(compliance, cache.DefaultDir())
	if err != nil {
		return spec.ComplianceSpec{}, xerrors.Errorf("spec loading from file system error: %w", err)
	}

	return cs, nil
}

func toSeverity(severity []string) []dbTypes.Severity {
	if len(severity) == 0 {
		return nil
	}
	severities := xslices.Map(severity, func(s string) dbTypes.Severity {
		// Note that there is no need to check the error here
		// since the severity value is already validated in the flag parser.
		sev, _ := dbTypes.NewSeverity(s)
		return sev
	})
	log.Debug("Parsed severities", log.Any("severities", severities))
	return severities
}
