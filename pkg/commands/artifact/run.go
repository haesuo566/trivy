package artifact

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/notification"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TargetKind represents what kind of artifact Trivy scans
type TargetKind string

const (
	TargetContainerImage TargetKind = "image"
	TargetFilesystem     TargetKind = "fs"
	TargetRootfs         TargetKind = "rootfs"
	TargetRepository     TargetKind = "repo"
	TargetSBOM           TargetKind = "sbom"
	TargetVM             TargetKind = "vm"
	TargetK8s            TargetKind = "k8s"
)

var SkipScan = errors.New("skip subsequent processes")

// InitializeScanService defines the initialize function signature of scan service
type InitializeScanService func(context.Context, ScannerConfig) (scan.Service, func(), error)

type ScannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	CacheOptions cache.Options

	// Artifact options
	ArtifactOption artifact.Option
}

type Runner interface {
	// ScanImage scans an image
	ScanImage(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanFilesystem scans a filesystem
	ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRootfs scans rootfs
	ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRepository scans repository
	ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanSBOM scans SBOM
	ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanVM scans VM
	ScanVM(ctx context.Context, opts flag.Options) (types.Report, error)
	// Filter filter a report
	Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error)
	// Report a writes a report
	Report(ctx context.Context, opts flag.Options, report types.Report) error
	// Close closes runner
	Close(ctx context.Context) error
}

type runner struct {
	initializeScanService InitializeScanService
	versionChecker        *notification.VersionChecker
}

type RunnerOption func(*runner)

// WithInitializeService takes a custom service initialization function.
// It is useful when Trivy is imported as a library.
func WithInitializeService(f InitializeScanService) RunnerOption {
	return func(r *runner) {
		r.initializeScanService = f
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(ctx context.Context, cliOptions flag.Options, targetKind TargetKind, opts ...RunnerOption) (_ Runner, err error) {
	r := &runner{}
	for _, opt := range opts {
		opt(r)
	}

	defer func() {
		if err != nil {
			if cErr := r.Close(ctx); cErr != nil {
				log.ErrorContext(ctx, "failed to close runner: %s", cErr)
			}
		}
	}()

	r.versionChecker = notification.NewVersionChecker(string(targetKind), &cliOptions)

	// Make a silent attempt to check for updates in the background
	// only do this if the user has not disabled notices or is running
	// in quiet mode
	if r.versionChecker != nil {
		r.versionChecker.RunUpdateCheck(ctx)
	}

	return r, nil
}

// Close closes everything
func (r *runner) Close(ctx context.Context) error {
	// silently check if there is notifications
	if r.versionChecker != nil {
		r.versionChecker.PrintNotices(ctx, os.Stderr)
	}

	return nil
}

func (r *runner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanService
	switch {
	case opts.Input != "":
		// Scan image tarball in standalone mode
		s = archiveStandaloneScanService
	default:
		// Scan container image in standalone mode
		s = imageStandaloneScanService
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable scanning of individual package and SBOM files
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	return r.scanFS(ctx, opts)
}

func (r *runner) ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeLockfiles...)

	return r.scanFS(ctx, opts)
}

func (r *runner) scanFS(ctx context.Context, opts flag.Options) (types.Report, error) {
	return r.scanArtifact(ctx, opts, filesystemStandaloneScanService)
}

func (r *runner) ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Do not scan OS packages
	opts.PkgTypes = []string{types.PkgTypeLibrary}

	// Disable the OS analyzers, individual package analyzers and SBOM analyzer
	opts.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	return r.scanArtifact(ctx, opts, repositoryStandaloneScanService)
}

func (r *runner) ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error) {
	return r.scanArtifact(ctx, opts, sbomStandaloneScanService)
}

func (r *runner) ScanVM(ctx context.Context, opts flag.Options) (types.Report, error) {
	// TODO: Does VM scan disable lock file..?
	opts.DisabledAnalyzers = analyzer.TypeLockfiles
	return r.scanArtifact(ctx, opts, vmStandaloneScanService)
}

func (r *runner) scanArtifact(ctx context.Context, opts flag.Options, initializeService InitializeScanService) (types.Report, error) {
	if r.initializeScanService != nil {
		initializeService = r.initializeScanService
	}
	report, err := r.scan(ctx, opts, initializeService)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func (r *runner) Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error) {
	// Filter results
	if err := result.Filter(ctx, report, opts.FilterOpts()); err != nil {
		return types.Report{}, xerrors.Errorf("filtering error: %w", err)
	}
	return report, nil
}

func (r *runner) Report(ctx context.Context, opts flag.Options, report types.Report) error {
	if err := pkgReport.Write(ctx, report, opts); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}
	return nil
}

// Run performs artifact scanning
func Run(ctx context.Context, opts flag.Options, targetKind TargetKind) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	if opts.GenerateDefaultConfig {
		log.Info("Writing the default config to trivy-default.yaml...")

		hiddenFlags := flag.HiddenFlags()
		// Viper does not have the ability to remove flags.
		// So we only save the necessary flags and set these flags after viper.Reset
		v := viper.New()
		for _, k := range viper.AllKeys() {
			// Skip the `GenerateDefaultConfigFlag` flags to avoid errors with default config file.
			// Also don't keep removed or deprecated flags to avoid confusing users.
			if k == flag.GenerateDefaultConfigFlag.ConfigName || slices.Contains(hiddenFlags, k) {
				continue
			}
			v.Set(k, viper.Get(k))
		}

		return v.SafeWriteConfigAs("trivy-default.yaml")
	}

	// Run the application
	report, err := run(ctx, opts, targetKind)
	if err != nil {
		return xerrors.Errorf("run error: %w", err)
	}

	return operation.Exit(opts, report.Results.Failed(), report.Metadata)
}

func run(ctx context.Context, opts flag.Options, targetKind TargetKind) (types.Report, error) {
	// Perform validation checks
	checkOptions(ctx, opts, targetKind)

	r, err := NewRunner(ctx, opts, targetKind)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return types.Report{}, nil
		}
		return types.Report{}, xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	scans := map[TargetKind]func(context.Context, flag.Options) (types.Report, error){
		TargetContainerImage: r.ScanImage,
		TargetFilesystem:     r.ScanFilesystem,
		TargetRootfs:         r.ScanRootfs,
		TargetRepository:     r.ScanRepository,
		TargetSBOM:           r.ScanSBOM,
		TargetVM:             r.ScanVM,
	}

	scanFunction, exists := scans[targetKind]
	if !exists {
		return types.Report{}, xerrors.Errorf("unknown target kind: %s", targetKind)
	}

	// 1. Scan the artifact
	report, err := scanFunction(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("%s scan error: %w", targetKind, err)
	}

	// 2. Filter the results
	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return types.Report{}, xerrors.Errorf("filter error: %w", err)
	}

	// 3. Report the results
	if err = r.Report(ctx, opts, report); err != nil {
		return types.Report{}, xerrors.Errorf("report error: %w", err)
	}

	return report, nil
}

// checkOptions performs various checks on scan options and shows warnings
func checkOptions(ctx context.Context, opts flag.Options, targetKind TargetKind) {
	// Check SBOM to SBOM scanning with package filtering flags
	// For SBOM-to-SBOM scanning (for example, to add vulnerabilities to the SBOM file), we should not modify the scanned file.
	// cf. https://github.com/aquasecurity/trivy/pull/9439#issuecomment-3295533665
	if targetKind == TargetSBOM && slices.Contains(types.SupportedSBOMFormats, opts.Format) &&
		(!slices.Equal(opts.PkgTypes, types.PkgTypes) || !slices.Equal(opts.PkgRelationships, ftypes.Relationships)) {
		log.Warn("'--pkg-types' and '--pkg-relationships' options will be ignored when scanning SBOM and outputting SBOM format.")
	}
}

func disabledAnalyzers(opts flag.Options) []analyzer.Type {
	// Specified analyzers to be disabled depending on scanning modes
	// e.g. The 'image' subcommand should disable the lock file scanning.
	analyzers := opts.DisabledAnalyzers
	// It doesn't analyze apk commands by default.
	if !opts.ScanRemovedPkgs {
		analyzers = append(analyzers, analyzer.TypeApkCommand)
	}

	// Do not analyze programming language packages when not running in 'library'
	if !slices.Contains(opts.PkgTypes, types.PkgTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}

	// Scanning file headers and license files is expensive.
	// It is performed only when '--scanners license' and '--license-full' are specified together.
	if !opts.Scanners.Enabled(types.LicenseScanner) || !opts.LicenseFull {
		analyzers = append(analyzers, analyzer.TypeLicenseFile)
	}

	// Parsing jar files requires Java-db client
	// But we don't create client if vulnerability analysis is disabled and SBOM format is not used
	// We need to disable jar analyzer to avoid errors
	// TODO disable all languages that don't contain license information for this case
	if !opts.Scanners.Enabled(types.VulnerabilityScanner) && !slices.Contains(types.SupportedSBOMFormats, opts.Format) {
		analyzers = append(analyzers, analyzer.TypeJar)
	}

	// Misconfiguration scanning on container image config is removed, disable Dockerfile history analyzer.
	analyzers = append(analyzers, analyzer.TypeHistoryDockerfile)

	// Skip executable file analysis if Rekor isn't a specified SBOM source.
	if !slices.Contains(opts.SBOMSources, types.SBOMSourceRekor) {
		analyzers = append(analyzers, analyzer.TypeExecutable)
	}

	// Disable RPM archive analyzer unless the environment variable is set
	// TODO: add '--enable-analyzers' and delete this environment variable
	if os.Getenv("TRIVY_EXPERIMENTAL_RPM_ARCHIVE") == "" {
		analyzers = append(analyzers, analyzer.TypeRpmArchive)
	}

	return analyzers
}

func (r *runner) initScannerConfig(ctx context.Context, opts flag.Options) (ScannerConfig, types.ScanOptions, error) {
	target := opts.Target
	if opts.Input != "" {
		target = opts.Input
	}

	scanOptions := opts.ScanOpts()

	if len(opts.ImageConfigScanners) != 0 {
		log.WithPrefix(log.PrefixContainerImage).Info("Container image config scanners", log.Any("scanners", opts.ImageConfigScanners))
	}

	if opts.Scanners.Enabled(types.SBOMScanner) {
		logger := log.WithPrefix(log.PrefixPackage)
		logger.Debug("Package types", log.Any("types", scanOptions.PkgTypes))
		logger.Debug("Package relationships", log.Any("relationships", scanOptions.PkgRelationships))
	}

	if opts.Scanners.Enabled(types.VulnerabilityScanner) {
		log.WithPrefix(log.PrefixVulnerability).Info("Vulnerability scanning is enabled")
	}

	if opts.Scanners.Enabled(types.LicenseScanner) {
		logger := log.WithPrefix(log.PrefixLicense)
		if opts.LicenseFull {
			logger.Info("Full license scanning is enabled")
		} else {
			logger.Info("License scanning is enabled")
		}
	}

	// SPDX and CycloneDX need to calculate digests for package files
	var fileChecksum bool
	if opts.Format == types.FormatSPDXJSON || opts.Format == types.FormatSPDX || opts.Format == types.FormatCycloneDX {
		fileChecksum = true
	}

	// Disable the post handler for filtering system file when detection priority is comprehensive.
	disabledHandlers := lo.Ternary(opts.DetectionPriority == ftypes.PriorityComprehensive,
		[]ftypes.HandlerType{ftypes.SystemFileFilteringPostHandler}, nil)

	return ScannerConfig{
		Target:       target,
		CacheOptions: opts.CacheOpts(),
		ArtifactOption: artifact.Option{
			DisabledAnalyzers: disabledAnalyzers(opts),
			DisabledHandlers:  disabledHandlers,
			FilePatterns:      opts.FilePatterns,
			Parallel:          opts.Parallel,
			Offline:           opts.OfflineScan,
			NoProgress:        opts.Quiet,
			Insecure:          opts.Insecure,
			RepoBranch:        opts.RepoBranch,
			RepoCommit:        opts.RepoCommit,
			RepoTag:           opts.RepoTag,
			SBOMSources:       opts.SBOMSources,
			RekorURL:          opts.RekorURL,
			AWSRegion:         opts.Region,
			AWSEndpoint:       opts.Endpoint,
			FileChecksum:      fileChecksum,
			DetectionPriority: opts.DetectionPriority,

			// For image scanning
			ImageOption: ftypes.ImageOptions{
				RegistryOptions: opts.RegistryOpts(),
				DockerOptions: ftypes.DockerOptions{
					Host: opts.DockerHost,
				},
				PodmanOptions: ftypes.PodmanOptions{
					Host: opts.PodmanHost,
				},
				ImageSources: opts.ImageSources,
				MaxImageSize: opts.MaxImageSize,
			},

			// For license scanning
			LicenseScannerOption: analyzer.LicenseScannerOption{
				Full:                      opts.LicenseFull,
				ClassifierConfidenceLevel: opts.LicenseConfidenceLevel,
			},

			// For file walking
			WalkerOption: walker.Option{
				SkipFiles: opts.SkipFiles,
				SkipDirs:  opts.SkipDirs,
			},
		},
	}, scanOptions, nil
}

func (r *runner) scan(ctx context.Context, opts flag.Options, initializeService InitializeScanService) (types.Report, error) {
	scannerConfig, scanOptions, err := r.initScannerConfig(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}
	s, cleanup, err := initializeService(ctx, scannerConfig)
	if err != nil {
		return types.Report{}, xerrors.Errorf("unable to initialize a scan service: %w", err)
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}
	return report, nil
}

