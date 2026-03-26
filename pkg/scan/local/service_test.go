package local

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	muslPkg = ftypes.Package{
		Name:       "musl",
		Version:    "1.2.3",
		SrcName:    "musl",
		SrcVersion: "1.2.3",
		Licenses:   []string{"MIT"},
		Layer: ftypes.Layer{
			DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "d9a73c7459d27809",
			PURL: &packageurl.PackageURL{
				Type:      "apk",
				Namespace: "alpine",
				Name:      "musl",
				Version:   "1.2.3",
				Qualifiers: packageurl.Qualifiers{
					packageurl.Qualifier{
						Key:   "distro",
						Value: "3.11",
					},
				},
			},
		},
	}
	libunistring5Pkg = ftypes.Package{
		Name:       "libunistring5",
		Version:    "1.1-2build1.1",
		SrcName:    "libunistring5",
		SrcVersion: "1.1-2build1.1",
		Licenses:   []string{"GFDL-NIV-1.2+"},
	}
	railsPkg = ftypes.Package{
		Name:    "rails",
		Version: "4.0.2",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "49be2edc1596dd5d",
			PURL: &packageurl.PackageURL{
				Type:    "gem",
				Name:    "rails",
				Version: "4.0.2",
			},
		},
	}
	innocentPkg = ftypes.Package{
		Name:    "innocent",
		Version: "1.2.3",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "50b49e415e6a2f59",
			PURL: &packageurl.PackageURL{
				Type:    "gem",
				Name:    "innocent",
				Version: "1.2.3",
			},
		},
	}
	uuidPkg = ftypes.Package{
		Name:     "github.com/google/uuid",
		Version:  "1.6.0",
		FilePath: "",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"LGPL"},
	}
	urllib3Pkg = ftypes.Package{
		Name:     "urllib3",
		Version:  "3.2.1",
		FilePath: "/usr/lib/python/site-packages/urllib3-3.2.1/METADATA",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"text://(c) 2015 Continuum Analytics, Inc."},
	}
	menuinstPkg = ftypes.Package{
		Name:     "menuinst",
		Version:  "2.0.2",
		FilePath: "opt/conda/lib/python3.11/site-packages/menuinst-2.0.2.dist-info/METADATA",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"text://(c) 2016 Continuum Analytics, Inc. / http://continuum.io All Rights Reserved"},
	}

	laravelPkg = ftypes.Package{
		Name:         "laravel/framework",
		Version:      "6.0.0",
		Relationship: ftypes.RelationshipDirect,
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "ba565db6c74968e3",
			PURL: &packageurl.PackageURL{
				Type:      "composer",
				Namespace: "laravel",
				Name:      "framework",
				Version:   "6.0.0",
			},
		},
	}
	guzzlePkg = ftypes.Package{
		Name:         "guzzlehttp/guzzle",
		Version:      "7.9.2",
		Relationship: ftypes.RelationshipIndirect,
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "791b71e6f31e53a5",
			PURL: &packageurl.PackageURL{
				Type:      "composer",
				Namespace: "guzzlehttp",
				Name:      "guzzle",
				Version:   "7.9.2",
			},
		},
	}
)

func TestScanner_Scan(t *testing.T) {
	type args struct {
		target   string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name       string
		args       args
		fixtures   []string
		setupCache func(t *testing.T) cache.Cache
		want       types.ScanResponse
		wantErr    string
	}{
		{
			name: "happy path",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{railsPkg},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "alpine:latest (alpine 3.11)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Alpine,
						Packages: ftypes.Packages{
							muslPkg,
						},
					},
					{
						Target: "/app/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: ftypes.Packages{
							railsPkg,
						},
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path with OS rewriting",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
					Distro: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "alpine:latest (alpine 3.11)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Alpine,
						Packages: ftypes.Packages{
							muslPkg,
						},
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path license scanner (exclude language-specific packages)",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.LicenseScanner},
					LicenseFull:      true,
					PkgTypes: []string{
						types.PkgTypeOS,
					},
					LicenseCategories: map[ftypes.LicenseCategory][]string{
						ftypes.CategoryNotice: {
							"MIT",
							"GFDL-1.2-no-invariants", // License before normalization
							// 	"GFDL-1.2-no-invariants-or-later", // License after normalization
						},
					},
				},
			},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{
								muslPkg,
								libunistring5Pkg,
							},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.PythonPkg,
							FilePath: "",
							Packages: []ftypes.Package{
								urllib3Pkg,
								menuinstPkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "OS Packages",
						Class:  types.ClassLicense,
						Licenses: []types.DetectedLicense{
							{
								Severity:   "LOW",
								Category:   "notice",
								PkgName:    libunistring5Pkg.Name,
								Name:       "GFDL-NIV-1.2+",
								Confidence: 1,
							},
							{
								Severity:   "LOW",
								Category:   "notice",
								PkgName:    muslPkg.Name,
								Name:       "MIT",
								Confidence: 1,
							},
						},
					},
					{
						Target: "Loose File License(s)",
						Class:  types.ClassLicenseFile,
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   false,
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path license scanner (exclude OS packages)",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.LicenseScanner},
					LicenseFull:      true,
					PkgTypes: []string{
						types.PkgTypeLibrary,
					},
					LicenseCategories: map[ftypes.LicenseCategory][]string{
						ftypes.CategoryNotice: {
							"MIT",
							"text://\\(c\\) 2015.*",
							"text://.* 2016 Continuum.*",
						},
					},
				},
			},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{
								muslPkg,
								libunistring5Pkg,
							},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.GoModule,
							FilePath: "/app/go.mod",
							Packages: []ftypes.Package{
								uuidPkg,
							},
						},
						{
							Type:     ftypes.PythonPkg,
							FilePath: "",
							Packages: []ftypes.Package{
								urllib3Pkg,
								menuinstPkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "/app/go.mod",
						Class:  types.ClassLicense,
						Licenses: []types.DetectedLicense{
							{
								Severity:   "UNKNOWN",
								Category:   "unknown",
								PkgName:    uuidPkg.Name,
								FilePath:   "/app/go.mod",
								Name:       "LGPL",
								Confidence: 1,
								Link:       "",
							},
						},
					},
					{
						Target: "Python",
						Class:  types.ClassLicense,
						Licenses: []types.DetectedLicense{
							{
								Severity:   "LOW",
								Category:   "notice",
								PkgName:    urllib3Pkg.Name,
								FilePath:   "/usr/lib/python/site-packages/urllib3-3.2.1/METADATA",
								Name:       "CUSTOM License: (c) 2015 Continuum...",
								Text:       "(c) 2015 Continuum Analytics, Inc.",
								Confidence: 1,
							},
							{
								Severity:   "LOW",
								Category:   "notice",
								PkgName:    menuinstPkg.Name,
								FilePath:   "opt/conda/lib/python3.11/site-packages/menuinst-2.0.2.dist-info/METADATA",
								Name:       "CUSTOM License: (c) 2016 Continuum...",
								Text:       "(c) 2016 Continuum Analytics, Inc. / http://continuum.io All Rights Reserved",
								Confidence: 1,
							},
						},
					},
					{
						Target: "Loose File License(s)",
						Class:  types.ClassLicenseFile,
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   false,
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path with empty os",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app1/Gemfile.lock",
							Packages: []ftypes.Package{
								innocentPkg, // no vulnerability
							},
						},
						{
							Type:     ftypes.Bundler,
							FilePath: "/app2/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg, // one vulnerability
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "/app1/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: ftypes.Packages{
							innocentPkg,
						},
					},
					{
						Target: "/app2/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: ftypes.Packages{
							railsPkg,
						},
					},
				},
				OS: ftypes.OS{},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path, empty file paths (e.g. Scanned SBOM)",
			args: args{
				target:   "./result.cdx",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes:            []string{types.PkgTypeLibrary},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
						{
							Type:     ftypes.Composer,
							FilePath: "",
							Packages: []ftypes.Package{
								laravelPkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								Name:       railsPkg.Name,
								Version:    railsPkg.Version,
								Identifier: railsPkg.Identifier,
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
					{
						Target: "",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Composer,
						Packages: []ftypes.Package{
							{
								Name:         laravelPkg.Name,
								Version:      laravelPkg.Version,
								Identifier:   laravelPkg.Identifier,
								Relationship: ftypes.RelationshipDirect,
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with no package",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					Applications: []ftypes.Application{
						{
							Type:     "bundler",
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target: "alpine:latest (alpine 3.11)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Alpine,
					},
					{
						Target: "/app/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: ftypes.Packages{
							railsPkg,
						},
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path with unsupported os",
			args: args{
				target:   "fedora:27",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					OS: ftypes.OS{
						Family: "fedora",
						Name:   "27",
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target:   "/app/Gemfile.lock",
						Class:    types.ClassLangPkg,
						Type:     ftypes.Bundler,
						Packages: ftypes.Packages{railsPkg},
					},
				},
				OS: ftypes.OS{
					Family: "fedora",
					Name:   "27",
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
					},
				},
			},
		},
		{
			name: "happy path with a scratch image",
			args: args{
				target:   "busybox:latest",
				layerIDs: []string{"sha256:a6d503001157aedc826853f9b67f26d35966221b158bff03849868ae4a821116"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:a6d503001157aedc826853f9b67f26d35966221b158bff03849868ae4a821116", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS:            ftypes.OS{},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: nil,
			},
		},
		{
			name: "happy path with only language-specific package detection, excluding direct packages",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33"},
				options: types.ScanOptions{
					PkgTypes: []string{types.PkgTypeLibrary},
					PkgRelationships: []ftypes.Relationship{
						ftypes.RelationshipUnknown,
						ftypes.RelationshipRoot,
						ftypes.RelationshipIndirect,
					},
					Scanners:            types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Size:          1000,
					DiffID:        "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     "bundler",
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
						{
							Type:     "composer",
							FilePath: "/app/composer-lock.json",
							Packages: []ftypes.Package{
								laravelPkg, // will be excluded
								guzzlePkg,
							},
						},
					},
				}))
				return c
			},
			want: types.ScanResponse{
				Results: types.Results{
					{
						Target:   "/app/Gemfile.lock",
						Class:    types.ClassLangPkg,
						Type:     ftypes.Bundler,
						Packages: ftypes.Packages{railsPkg},
					},
					{
						Target:   "/app/composer-lock.json",
						Class:    types.ClassLangPkg,
						Type:     ftypes.Composer,
						Packages: ftypes.Packages{guzzlePkg},
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
				},
				Layers: ftypes.Layers{
					{
						Size:   1000,
						DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
					},
				},
			},
		},
		{
			name: "sad path: ApplyLayers returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: 0,
				}))
				return c
			},
			wantErr: "failed to apply layers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := tt.setupCache(t)
			a := applier.NewApplier(c)
			s := NewService(a, ospkg.NewScanner(), langpkg.NewScanner())

			gotResponse, err := s.Scan(t.Context(), tt.args.target, "", tt.args.layerIDs, tt.args.options)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, gotResponse)
		})
	}
}
