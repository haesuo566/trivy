package main

import (
	"context"
	"errors"
	"os"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

func main() {
	if err := run(); err != nil {
		var exitError *types.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.Code)
		}

		var userErr *types.UserError
		if errors.As(err, &userErr) {
			log.Fatal("Error", log.Err(userErr))
		}

		log.Fatal("Fatal error", log.Err(err))
	}
}

func run() error {
	// Ensure cleanup on exit
	defer commands.Cleanup()

	// Set up signal handling for graceful shutdown
	ctx := commands.NotifyContext(context.Background())

	return commands.Run(ctx)
}
