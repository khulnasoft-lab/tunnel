//go:build wireinject
// +build wireinject

package server

import (
	"github.com/google/wire"

	"github.com/khulnasoft/tunnel/pkg/fanal/cache"
)

func initializeScanServer(localArtifactCache cache.Cache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}
