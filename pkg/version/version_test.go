package version

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNewVersionInfo(t *testing.T) {
	tests := []struct {
		name string
		opts []VersionOption
		want types.VersionInfo
	}{
		{
			name: "default",
			opts: nil,
			want: types.VersionInfo{
				Version: "dev",
				CheckBundle: &types.BundleMetadata{
					Digest:       "sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43",
					DownloadedAt: time.Date(2023, 7, 23, 16, 40, 33, 122462000, time.UTC),
				},
			},
		},
		{
			name: "server mode excludes CheckBundle",
			opts: []VersionOption{Server()},
			want: types.VersionInfo{
				Version:     "dev",
				CheckBundle: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVersionInfo("testdata/testcache", tt.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersionInfo_String(t *testing.T) {
	want := `Version: dev
Check Bundle:
  Digest: sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43
  DownloadedAt: 2023-07-23 16:40:33.122462 +0000 UTC
`
	got := NewVersionInfo("testdata/testcache")
	assert.Equal(t, want, got.String())
}
