package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		format     types.Format
		ignoreFile string
		exitCode   int
		exitOnEOSL bool
		ignorePolicy string
		output     string
		severities string
		debug      bool
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.ReportOptions
		wantErr  string
		wantLogs []string
	}{
		{
			name:   "happy default (without flags)",
			fields: fields{},
			want:   flag.ReportOptions{},
		},
		{
			name: "happy path with cyclonedx",
			fields: fields{
				severities: "CRITICAL",
				format:     "cyclonedx",
			},
			want: flag.ReportOptions{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				Format:     types.FormatCycloneDX,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			level := log.LevelWarn
			if tt.fields.debug {
				level = log.LevelDebug
			}
			out := newLogger(level)

			setValue(flag.FormatFlag.ConfigName, string(tt.fields.format))
			setValue(flag.IgnoreFileFlag.ConfigName, tt.fields.ignoreFile)
			setValue(flag.IgnorePolicyFlag.ConfigName, tt.fields.ignorePolicy)
			setValue(flag.ExitCodeFlag.ConfigName, tt.fields.exitCode)
			setValue(flag.ExitOnEOLFlag.ConfigName, tt.fields.exitOnEOSL)
			setValue(flag.OutputFlag.ConfigName, tt.fields.output)
			setValue(flag.SeverityFlag.ConfigName, tt.fields.severities)
			// Assert options
			f := &flag.ReportFlagGroup{
				Format:       flag.FormatFlag.Clone(),
				IgnoreFile:   flag.IgnoreFileFlag.Clone(),
				IgnorePolicy: flag.IgnorePolicyFlag.Clone(),
				ExitCode:     flag.ExitCodeFlag.Clone(),
				ExitOnEOL:    flag.ExitOnEOLFlag.Clone(),
				Output:       flag.OutputFlag.Clone(),
				Severity:     flag.SeverityFlag.Clone(),
			}

			flags := flag.Flags{f}
			got, err := flags.ToOptions(nil)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.EqualExportedValues(t, tt.want, got.ReportOptions)

			// Assert log messages
			assert.Equal(t, tt.wantLogs, out.Messages(), tt.name)
		})
	}

	t.Run("Error on non existing ignore file", func(t *testing.T) {
		t.Cleanup(viper.Reset)

		setValue(flag.IgnoreFileFlag.ConfigName, "doesntexist")
		f := &flag.ReportFlagGroup{
			IgnoreFile: flag.IgnoreFileFlag.Clone(),
		}

		flags := flag.Flags{f}
		_, err := flags.ToOptions(nil)
		assert.ErrorContains(t, err, "ignore file not found: doesntexist")
	})
}
