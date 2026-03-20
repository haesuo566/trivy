package library

import (
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewDriver returns a driver according to the library type
func NewDriver(libType ftypes.LangType) (Driver, bool) {
	var eco ecosystem.Type
	var comparer compare.Comparer

	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		eco = ecosystem.RubyGems
		comparer = rubygems.Comparer{}
	case ftypes.RustBinary, ftypes.Cargo:
		eco = ecosystem.Cargo
		comparer = compare.GenericComparer{}
	case ftypes.Composer, ftypes.ComposerVendor:
		eco = ecosystem.Composer
		comparer = compare.GenericComparer{}
	case ftypes.GoBinary, ftypes.GoModule:
		eco = ecosystem.Go
		comparer = compare.GenericComparer{}
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		eco = ecosystem.Maven
		comparer = maven.Comparer{}
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.Bun, ftypes.NodePkg, ftypes.JavaScript:
		eco = ecosystem.Npm
		comparer = npm.Comparer{}
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		eco = ecosystem.NuGet
		comparer = compare.GenericComparer{}
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv, ftypes.PyLock:
		eco = ecosystem.Pip
		comparer = pep440.Comparer{}
	case ftypes.Pub:
		eco = ecosystem.Pub
		comparer = compare.GenericComparer{}
	case ftypes.Hex:
		eco = ecosystem.Erlang
		comparer = compare.GenericComparer{}
	case ftypes.Conan:
		eco = ecosystem.Conan
		// Only semver can be used for version ranges
		// https://docs.conan.io/en/latest/versioning/version_ranges.html
		comparer = compare.GenericComparer{}
	case ftypes.Swift:
		// Swift uses semver
		// https://www.swift.org/package-manager/#importing-dependencies
		eco = ecosystem.Swift
		comparer = compare.GenericComparer{}
	case ftypes.Cocoapods:
		// CocoaPods uses RubyGems version specifiers
		// https://guides.cocoapods.org/making/making-a-cocoapod.html#cocoapods-versioning-specifics
		eco = ecosystem.Cocoapods
		comparer = rubygems.Comparer{}
	case ftypes.CondaPkg, ftypes.CondaEnv:
		log.Warn("Conda package is supported for SBOM, not for vulnerability scanning")
		return Driver{}, false
	case ftypes.Bitnami:
		eco = ecosystem.Bitnami
		comparer = bitnami.Comparer{}
	case ftypes.K8sUpstream:
		eco = ecosystem.Kubernetes
		comparer = compare.GenericComparer{}
	case ftypes.Julia:
		eco = ecosystem.Julia
		comparer = compare.GenericComparer{}
	default:
		log.Warn("The library type is not supported for vulnerability scanning",
			log.String("type", string(libType)))
		return Driver{}, false
	}
	return Driver{
		ecosystem: eco,
		comparer:  comparer,
	}, true
}

// Driver represents security advisories for each programming language
type Driver struct {
	ecosystem ecosystem.Type
	comparer  compare.Comparer
}

// Type returns the driver ecosystem
func (d *Driver) Type() string {
	return string(d.ecosystem)
}

// DetectVulnerabilities returns empty results as vulnerability scanning has been removed.
func (d *Driver) DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	return nil, nil
}

