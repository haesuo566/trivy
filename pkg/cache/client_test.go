package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		opts     cache.Options
		wantType any
		wantErr  string
	}{
		{
			name: "fs backend",
			opts: cache.Options{
				Backend:  "fs",
				CacheDir: "/tmp/cache",
			},
			wantType: cache.FSCache{},
		},
		{
			name: "unknown backend",
			opts: cache.Options{
				Backend: "unknown",
			},
			wantErr: "unknown cache type",
		},
		{
			name: "invalid redis URL",
			opts: cache.Options{
				Backend: "redis://invalid-url:foo/bar",
			},
			wantErr: "failed to parse Redis URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup, err := cache.New(tt.opts)
			defer cleanup()

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, c)
			assert.IsType(t, tt.wantType, c)
		})
	}
}

func TestNewType(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		wantType cache.Type
	}{
		{
			name:     "fs backend",
			backend:  "fs",
			wantType: cache.TypeFS,
		},
		{
			name:     "empty backend",
			backend:  "",
			wantType: cache.TypeFS,
		},
		{
			name:     "unknown backend",
			backend:  "unknown",
			wantType: cache.TypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.NewType(tt.backend)
			assert.Equal(t, tt.wantType, got)
		})
	}
}
