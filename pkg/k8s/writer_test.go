package k8s

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	deployOrionWithVulns = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
					{
						VulnerabilityID: "CVE-2022-2222",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
					{
						VulnerabilityID: "CVE-2022-3333",
						Vulnerability:   dbTypes.Vulnerability{Severity: "HIGH"},
					},
					{
						VulnerabilityID: "CVE-2022-4444",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-5555",
						Vulnerability:   dbTypes.Vulnerability{Severity: "UNKNOWN"},
					},
					{
						VulnerabilityID: "CVE-2022-6666",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-7777",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
				},
			},
		},
	}

	deployOrionWithSingleVuln = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						PkgID:           "foo/bar@v0.0.1",
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
				},
			},
		},
		Report: types.Report{
			Results: types.Results{
				{
					Class: types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							PkgName:          "foo/bar",
							VulnerabilityID:  "CVE-2022-1111",
							InstalledVersion: "v0.0.1",
							FixedVersion:     "v0.0.2",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-1111",
							Vulnerability:    dbTypes.Vulnerability{Severity: "LOW"},
						},
					},
				},
			},
		},
	}
)

func TestReportWrite_Table(t *testing.T) {
	allSeverities := []dbTypes.Severity{
		dbTypes.SeverityUnknown,
		dbTypes.SeverityLow,
		dbTypes.SeverityMedium,
		dbTypes.SeverityHigh,
		dbTypes.SeverityCritical,
	}

	tests := []struct {
		name           string
		report         report.Report
		opt            report.Option
		scanners       types.Scanners
		severities     []dbTypes.Severity
		reportType     string
		expectedOutput string
	}{
		{
			name: "Only vuln, all severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithVulns},
			},
			scanners:   types.Scanners{types.VulnerabilityScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────────┬───────────────────┐
│ Namespace │   Resource   │  Vulnerabilities  │
│           │              ├───┬───┬───┬───┬───┤
│           │              │ C │ H │ M │ L │ U │
├───────────┼──────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/orion │ 2 │ 1 │ 2 │ 1 │ 1 │
└───────────┴──────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │  Vulnerabilities  │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRIVY_DISABLE_VEX_NOTICE", "true")
			output := bytes.Buffer{}

			opt := report.Option{
				Format:     "table",
				Report:     tc.reportType,
				Output:     &output,
				Scanners:   tc.scanners,
				Severities: tc.severities,
			}

			err := Write(t.Context(), tc.report, opt)
			require.NoError(t, err)
			got := stripAnsi(output.String())
			got = strings.ReplaceAll(got, "\r\n", "\n")
			assert.Equal(t, tc.expectedOutput, got, tc.name)
		})
	}
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegexp = regexp.MustCompile(ansi)

func stripAnsi(str string) string {
	return strings.TrimSpace(ansiRegexp.ReplaceAllString(str, ""))
}
