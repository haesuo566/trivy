package types

import (
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint: goimports

	"github.com/aquasecurity/trivy/pkg/fanal/image/name"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

// TrivyInfo contains Trivy-specific information
type TrivyInfo struct {
	Version string      `json:",omitempty"` // Client version
	Server  VersionInfo `json:",omitzero"`  // Server info (client/server mode only)
}

// Report represents a scan result
type Report struct {
	SchemaVersion int       `json:",omitempty"`
	Trivy         TrivyInfo `json:",omitzero"`
	ReportID      string    `json:",omitempty"` // Unique identifier for this scan report
	CreatedAt     time.Time `json:",omitzero"`

	// ArtifactID uniquely identifies the scanned artifact.
	// For container images: hash(ImageID + Registry + Repository) - ensures same image in different repos have different IDs
	// For repositories: hash(RepoURL + Commit) or hash(Path + Commit) for local repos
	// For filesystems: empty string
	// For other artifact types: empty string
	ArtifactID string `json:",omitempty"`

	ArtifactName string              `json:",omitempty"`
	ArtifactType ftypes.ArtifactType `json:",omitempty"`
	Metadata     Metadata            `json:",omitzero"`
	Results      Results             `json:",omitempty"`

	// parsed SBOM
	BOM *core.BOM `json:"-"` // Just for internal usage, not exported in JSON
}

// Metadata represents a metadata of artifact
type Metadata struct {
	Size int64      `json:",omitempty"`
	OS   *ftypes.OS `json:",omitempty"`

	// Container image
	ImageID     string         `json:",omitempty"`
	DiffIDs     []string       `json:",omitempty"`
	RepoTags    []string       `json:",omitempty"`
	RepoDigests []string       `json:",omitempty"`
	Reference   name.Reference `json:",omitzero"`
	ImageConfig v1.ConfigFile  `json:",omitzero"`
	Layers      ftypes.Layers  `json:",omitzero"`

	// Git repository
	RepoURL   string   `json:",omitzero"`
	Branch    string   `json:",omitzero"`
	Tags      []string `json:",omitzero"`
	Commit    string   `json:",omitzero"`
	CommitMsg string   `json:",omitzero"`
	Author    string   `json:",omitzero"`
	Committer string   `json:",omitzero"`
}

// Results to hold list of Result
type Results []Result

type ResultClass string
type Format string

const (
	ClassUnknown     ResultClass = "unknown"
	ClassOSPkg       ResultClass = "os-pkgs"      // For detected packages and vulnerabilities in OS packages
	ClassLangPkg     ResultClass = "lang-pkgs"    // For detected packages and vulnerabilities in language-specific packages
	ClassLicense     ResultClass = "license"      // For detected package licenses
	ClassLicenseFile ResultClass = "license-file" // For detected licenses in files

	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
	FormatSPDXJSON  Format = "spdx-json"
)

var (
	SupportedFormats = []Format{
		FormatCycloneDX,
		FormatSPDX,
		FormatSPDXJSON,
	}
	SupportedSBOMFormats = []Format{
		FormatCycloneDX,
		FormatSPDX,
		FormatSPDXJSON,
	}
)

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                     `json:"Target"`
	Class             ResultClass                `json:"Class,omitempty"`
	Type              ftypes.TargetType          `json:"Type,omitempty"`
	Packages          []ftypes.Package           `json:"Packages,omitempty"`
	Vulnerabilities []DetectedVulnerability `json:"Vulnerabilities,omitempty"`
	Licenses        []DetectedLicense      `json:"Licenses,omitempty"`

	// ModifiedFindings holds a list of findings that have been modified from their original state.
	// This can include vulnerabilities that have been marked as ignored, not affected, or have had
	// their severity adjusted. It's still in an experimental stage and may change in the future.
	ModifiedFindings []ModifiedFinding `json:"ExperimentalModifiedFindings,omitempty"`
}

func (r *Result) IsEmpty() bool {
	return len(r.Packages) == 0 && len(r.Vulnerabilities) == 0 &&
		len(r.Licenses) == 0 && len(r.ModifiedFindings) == 0
}

// Failed returns whether the result includes any vulnerabilities or licenses
func (results Results) Failed() bool {
	for _, r := range results {
		if len(r.Vulnerabilities) > 0 {
			return true
		}
		if len(r.Licenses) > 0 {
			return true
		}
	}
	return false
}
