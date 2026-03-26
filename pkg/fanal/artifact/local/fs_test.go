package local

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/uuid"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"

	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name              string
		fields            fields
		setupCache        func(t *testing.T) cache.Cache
		artifactOpt       artifact.Option
		disabledAnalyzers []analyzer.Type
		disabledHandlers  []types.HandlerType
		wantBlobs         []cachetest.WantBlob
		want              artifact.Reference
		wantErr           string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata/alpine",
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: types.Packages{
									{
										ID:         "musl@1.1.24-r2",
										Name:       "musl",
										Version:    "1.1.24-r2",
										SrcName:    "musl",
										SrcVersion: "1.1.24-r2",
										Licenses:   []string{"MIT"},
										Maintainer: "Timo Teräs <timo.teras@iki.fi>",
										Arch:       "x86_64",
										Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
										InstalledFiles: []string{
											"lib/libc.musl-x86_64.so.1",
											"lib/ld-musl-x86_64.so.1",
										},
										AnalyzedBy: analyzer.TypeApk,
									},
								},
							},
						},
					},
				},
			},
			want: artifact.Reference{
				Name: "host",
				Type: types.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata/alpine",
			},
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeAlpine,
					analyzer.TypeApk,
					analyzer.TypePip,
					analyzer.TypeNpmPkgLock,
				},
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
			},
			want: artifact.Reference{
				Name: "host",
				Type: types.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata/alpine",
			},
			setupCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutBlob: true,
				})
			},
			wantErr: "PutBlob failed",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "walk dir error",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
										AnalyzedBy: analyzer.TypePip,
									},
								},
							},
						},
					},
				},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: types.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "happy path with single file using relative path",
			fields: fields{
				dir: "./testdata/requirements.txt",
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
										AnalyzedBy: analyzer.TypePip,
									},
								},
							},
						},
					},
				},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: types.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "git repository: artifact type is changed to repository",
			fields: fields{
				dir: "../../../../internal/gittest/testdata/test-repo",
			},
			wantBlobs: []cachetest.WantBlob{
				{
					// Cache key is based on commit hash (8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35)
					ID: "sha256:d37c788d6fe832712cce9020943746b8764c04f7e323ed4ad68de36c5bf7d846",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
			},
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: types.TypeRepository,
				ID:   "sha256:d37c788d6fe832712cce9020943746b8764c04f7e323ed4ad68de36c5bf7d846",
				BlobIDs: []string{
					"sha256:d37c788d6fe832712cce9020943746b8764c04f7e323ed4ad68de36c5bf7d846",
				},
				RepoMetadata: artifact.RepoMetadata{
					RepoURL:   "https://github.com/aquasecurity/trivy-test-repo/",
					Branch:    "main",
					Tags:      []string{"v0.0.1"},
					Commit:    "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
					CommitMsg: "Update README.md",
					Author:    "Teppei Fukuda <knqyf263@gmail.com>",
					Committer: "GitHub <noreply@github.com>",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cachetest.NewCache(t, tt.setupCache)

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(t.Context())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			cachetest.AssertBlobs(t, c, tt.wantBlobs)
		})
	}
}

// recordingWalker wraps an existing walker and records which paths were walked
// recordingWalker wraps an existing walker and records which paths were walked
type recordingWalker struct {
	base        Walker
	walkedRoots []string
}

func newRecordingWalker(base Walker) *recordingWalker {
	return &recordingWalker{
		base: base,
	}
}

func (w *recordingWalker) Walk(root string, option walker.Option, walkFn walker.WalkFunc) error {
	w.walkedRoots = append(w.walkedRoots, filepath.ToSlash(root))
	// Call the original walker
	return w.base.Walk(root, option, walkFn)
}

// TestArtifact_AnalysisStrategy tests the different analysis strategies
func TestArtifact_AnalysisStrategy(t *testing.T) {
	// Use testdata/alpine directly
	testDir := "testdata/alpine"

	tests := []struct {
		name              string
		disabledAnalyzers []analyzer.Type
		wantRoots         []string
	}{
		{
			name:              "static paths",
			disabledAnalyzers: []analyzer.Type{analyzer.TypePip},
			wantRoots: []string{
				"testdata/alpine/etc/alpine-release",
				"testdata/alpine/lib/apk/db/installed",
				"testdata/alpine/usr/lib/apk/db/installed",
			},
		},
		{
			name: "traversing root dir",
			wantRoots: []string{
				testDir, // only the root directory is walked
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new artifact with the recording walker
			baseWalker := walker.NewFS()
			rw := newRecordingWalker(baseWalker)

			// Create artifact with recording walker
			a, err := NewArtifact(testDir, cache.NewMemoryCache(), rw, artifact.Option{
				DisabledAnalyzers: tt.disabledAnalyzers,
			})
			require.NoError(t, err)

			// Run the inspection
			_, err = a.Inspect(t.Context())
			require.NoError(t, err)

			// Check if the walked roots match the expected roots
			assert.ElementsMatch(t, tt.wantRoots, rw.walkedRoots)
		})
	}
}

func Test_sanitizeRemoteURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "https with user:pass",
			in:   "https://user:token@github.com/org/repo.git",
			want: "https://github.com/org/repo.git",
		},
		{
			name: "port in authority with userinfo",
			in:   "https://user:pass@host:8443/repo.git",
			want: "https://host:8443/repo.git",
		},
		{
			name: "http with username only",
			in:   "http://user@github.com/org/repo",
			want: "http://github.com/org/repo",
		},
		{
			name: "double scheme after userinfo",
			in:   "https://gitlab-ci-token:glcbt-64_QwERTyuiOp-AsD2NgCJ7@example.com/gitrepo.git",
			want: "https://example.com/gitrepo.git",
		},
		{
			name: "ssh scheme with username",
			in:   "ssh://git@github.com/org/repo.git",
			want: "ssh://github.com/org/repo.git",
		},
		{
			name: "scp-like ssh unchanged",
			in:   "git@github.com:org/repo.git",
			want: "git@github.com:org/repo.git",
		},
		{
			name: "already clean https",
			in:   "https://github.com/org/repo.git",
			want: "https://github.com/org/repo.git",
		},
		{
			name: "no scheme left as-is",
			in:   "github.com/org/repo.git",
			want: "github.com/org/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeRemoteURL(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}
