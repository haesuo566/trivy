package types

import (
	"fmt"
	"time"
)

// BundleMetadata holds policy bundle metadata.
// This is a lightweight alternative to policy.Metadata to avoid importing
// pkg/policy which has dependencies incompatible with wasip1/wasm.
type BundleMetadata struct {
	Digest       string
	DownloadedAt time.Time
}

func (m BundleMetadata) String() string {
	return fmt.Sprintf(`Check Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}

// VersionInfo holds version information for Trivy and its databases.
type VersionInfo struct {
	Version     string          `json:",omitempty"`
	CheckBundle *BundleMetadata `json:",omitempty"`
}

func (v VersionInfo) String() string {
	output := fmt.Sprintf("Version: %s\n", v.Version)
	if v.CheckBundle != nil {
		output += v.CheckBundle.String()
	}
	return output
}
