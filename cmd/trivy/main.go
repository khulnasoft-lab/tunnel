package main

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/khulnasoft/tunnel/pkg/commands"
	"github.com/khulnasoft/tunnel/pkg/log"
	"github.com/khulnasoft/tunnel/pkg/plugin"
)

var (
	version = "dev"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Trivy behaves as the specified plugin.
	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		if !plugin.IsPredefined(runAsPlugin) {
			return xerrors.Errorf("unknown plugin: %s", runAsPlugin)
		}
		if err := plugin.RunWithArgs(context.Background(), runAsPlugin, os.Args[1:]); err != nil {
			return xerrors.Errorf("plugin error: %w", err)
		}
		return nil
	}

	app := commands.NewApp(version)
	if err := app.Execute(); err != nil {
		return err
	}
	return nil
}
