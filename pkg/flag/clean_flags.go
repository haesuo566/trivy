package flag

var (
	CleanAll = Flag[bool]{
		Name:       "all",
		Shorthand:  "a",
		ConfigName: "clean.all",
		Usage:      "remove all caches",
	}
	CleanScanCache = Flag[bool]{
		Name:       "scan-cache",
		ConfigName: "clean.scan-cache",
		Usage:      "remove scan cache (container and VM image analysis results)",
	}
	CleanChecksBundle = Flag[bool]{
		Name:       "checks-bundle",
		ConfigName: "clean.checks-bundle",
		Usage:      "remove checks bundle",
	}
)

type CleanFlagGroup struct {
	CleanAll          *Flag[bool]
	CleanScanCache    *Flag[bool]
	CleanChecksBundle *Flag[bool]
}

type CleanOptions struct {
	CleanAll          bool
	CleanScanCache    bool
	CleanChecksBundle bool
}

func NewCleanFlagGroup() *CleanFlagGroup {
	return &CleanFlagGroup{
		CleanAll:          CleanAll.Clone(),
		CleanScanCache:    CleanScanCache.Clone(),
		CleanChecksBundle: CleanChecksBundle.Clone(),
	}
}

func (fg *CleanFlagGroup) Name() string {
	return "Clean"
}

func (fg *CleanFlagGroup) Flags() []Flagger {
	return []Flagger{
		fg.CleanAll,
		fg.CleanScanCache,
		fg.CleanChecksBundle,
	}
}

func (fg *CleanFlagGroup) ToOptions(opts *Options) error {
	opts.CleanOptions = CleanOptions{
		CleanAll:          fg.CleanAll.Value(),
		CleanChecksBundle: fg.CleanChecksBundle.Value(),
		CleanScanCache:    fg.CleanScanCache.Value(),
	}
	return nil
}
