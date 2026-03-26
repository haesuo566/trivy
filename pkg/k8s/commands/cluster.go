package commands

import (
	"context"

	"golang.org/x/xerrors"

	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var artifacts []*k8sArtifacts.Artifact
	var err error
	switch opts.Format {
	case types.FormatCycloneDX:
		artifacts, err = trivyk8s.New(cluster).ListClusterBomInfo(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	default:
		k8sOpts := []trivyk8s.K8sOption{
			trivyk8s.WithExcludeNamespaces(opts.ExcludeNamespaces),
			trivyk8s.WithIncludeNamespaces(opts.IncludeNamespaces),
			trivyk8s.WithExcludeKinds(opts.ExcludeKinds),
			trivyk8s.WithIncludeKinds(opts.IncludeKinds),
			trivyk8s.WithExcludeOwned(opts.ExcludeOwned),
		}
		artifacts, err = trivyk8s.New(cluster, k8sOpts...).ListArtifacts(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts error: %w", err)
		}
	}

	if !opts.DisableNodeCollector && !opts.Quiet {
		log.InfoContext(ctx, "Node scanning is enabled")
		log.InfoContext(ctx, "If you want to disable Node scanning via an in-cluster Job, please try '--disable-node-collector' to disable the Node-Collector job.")
	}
	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}


