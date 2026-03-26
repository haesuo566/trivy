package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key               string
		artifactVersion   int
		analyzerVersions  analyzer.Versions
		hookVersions      map[string]int
		skipFiles         []string
		skipDirs          []string
		patterns          []string
		detectionPriority types.DetectionPriority
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				key:             "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				artifactVersion: 1,
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:9ac2cf39c18b5c936694820bc9c380dd8c74d33484ebd08183c5620215a1d33c",
		},
		{
			name: "with disabled analyzer",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 0,
						"redhat": 2,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:d63724cc72729edd3c81205739d64fcb414a4e6345dd4dde7f0fe6bdd56bedf9",
		},
		{
			name: "with empty slice file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{},
			},
			want: "sha256:9f7afa4d27c4c4f371dc6bb47bcc09e7a4a00b1d870e8156f126e35d8f6522e6",
		},
		{
			name: "with single empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{""},
			},
			want: "sha256:bcfc5da13ef9bf0b85e719584800a010063474546f1051a781b78bd83de01102",
		},
		{
			name: "with single non empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{"test"},
			},
			want: "sha256:8c9750b8eca507628417f21d7db707a7876d2e22c3e75b13f31a795af4051c57",
		},
		{
			name: "with non empty followed by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{
					"test",
					"",
				},
			},
			want: "sha256:71abf09bf1422531e2838db692b80f9b9f48766f56b7d3d02aecdb36b019e103",
		},
		{
			name: "with non empty preceded by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{
					"",
					"test",
				},
			},
			want: "sha256:71abf09bf1422531e2838db692b80f9b9f48766f56b7d3d02aecdb36b019e103",
		},
		{
			name: "skip files and dirs",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				skipFiles: []string{"app/deployment.yaml"},
				skipDirs:  []string{"usr/java"},
			},
			want: "sha256:363f70f4ee795f250873caea11c2fc94ef12945444327e7e2f8a99e3884695e0",
		},
		{
			name: "detection priority",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				skipFiles:         []string{"app/deployment.yaml"},
				skipDirs:          []string{"usr/java"},
				detectionPriority: types.PriorityComprehensive,
			},
			want: "sha256:2f1c898271e84f4382cd48ae7533069cc3dc656c2d688ac108f5db1a0d9fd393",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactOpt := artifact.Option{
				FilePatterns:      tt.args.patterns,
				DetectionPriority: tt.args.detectionPriority,

				WalkerOption: walker.Option{
					SkipFiles: tt.args.skipFiles,
					SkipDirs:  tt.args.skipDirs,
				},
			}
			got, err := CalcKey(tt.args.key, tt.args.artifactVersion, tt.args.analyzerVersions, tt.args.hookVersions, artifactOpt)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
