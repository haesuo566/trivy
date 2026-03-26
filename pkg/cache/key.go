package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func CalcKey(id string, artifactVersion int, analyzerVersions analyzer.Versions, hookVersions map[string]int, artifactOpt artifact.Option) (string, error) {
	// Sort options for consistent results
	artifactOpt.Sort()

	h := sha256.New()

	// Write ID, analyzer/handler versions, skipped files/dirs and file patterns
	keyBase := struct {
		ID                string
		ArtifactVersion   int `json:",omitzero"`
		AnalyzerVersions  analyzer.Versions
		HookVersions      map[string]int
		SkipFiles         []string
		SkipDirs          []string
		FilePatterns      []string                `json:",omitempty"`
		DetectionPriority types.DetectionPriority `json:",omitempty"`
	}{
		id,
		artifactVersion,
		analyzerVersions,
		hookVersions,
		artifactOpt.WalkerOption.SkipFiles,
		artifactOpt.WalkerOption.SkipDirs,
		artifactOpt.FilePatterns,
		artifactOpt.DetectionPriority,
	}

	if err := json.NewEncoder(h).Encode(keyBase); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

