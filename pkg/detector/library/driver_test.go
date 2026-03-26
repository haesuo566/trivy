package library_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestDriver_Detect(t *testing.T) {
	type args struct {
		pkgName string
		pkgVer  string
	}
	tests := []struct {
		name     string
		fixtures []string
		libType  ftypes.LangType
		args     args
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/php.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.2.6",
			},
			want: nil,
		},
		{
			name: "case-sensitive go package",
			fixtures: []string{
				"testdata/fixtures/go.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.GoModule,
			args: args{
				pkgName: "github.com/Masterminds/vcs",
				pkgVer:  "v1.13.1",
			},
			want: nil,
		},
		{
			name: "julia package",
			fixtures: []string{
				"testdata/fixtures/julia.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Julia,
			args: args{
				pkgName: "HTTP",
				pkgVer:  "1.10.16",
			},
			want: nil,
		},
		{
			name:     "non-prefixed buckets",
			fixtures: []string{"testdata/fixtures/php-without-prefix.yaml"},
			libType:  ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.2.6",
			},
			want: nil,
		},
		{
			name: "no patched versions in the advisory",
			fixtures: []string{
				"testdata/fixtures/php.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.4.6",
			},
			want: nil,
		},
		{
			name: "no vulnerable versions in the advisory",
			fixtures: []string{
				"testdata/fixtures/ruby.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Bundler,
			args: args{
				pkgName: "activesupport",
				pkgVer:  "4.1.1",
			},
			want: nil,
		},
		{
			name:     "no vulnerability",
			fixtures: []string{"testdata/fixtures/php.yaml"},
			libType:  ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.4.7",
			},
		},
		{
			name:     "malformed JSON",
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			libType:  ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "5.1.5",
			},
		},
		{
			name: "duplicated version in advisory",
			fixtures: []string{
				"testdata/fixtures/pip.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.PythonPkg,
			args: args{
				pkgName: "Django",
				pkgVer:  "4.2.1",
			},
			want: nil,
		},
		{
			name: "Custom data for vulnerability",
			fixtures: []string{
				"testdata/fixtures/go-custom-data.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.GoBinary,
			args: args{
				pkgName: "github.com/docker/docker",
				pkgVer:  "23.0.14",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			driver, ok := library.NewDriver(tt.libType)
			require.True(t, ok)

			got, err := driver.DetectVulnerabilities("", tt.args.pkgName, tt.args.pkgVer)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			// Compare
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
