//go:build wireinject
// +build wireinject

package main

import (
	"log/slog"

	"github.com/GoYoko/web"
	"github.com/google/wire"

	"github.com/chaitin/MonkeyCode/backend/config"
	v1 "github.com/chaitin/MonkeyCode/backend/internal/scanner/handler/http/v1"
	"github.com/chaitin/MonkeyCode/backend/pkg/version"
)

type Server struct {
	web     *web.Web
	config  *config.Config
	logger  *slog.Logger
	handler *v1.ScannerHandler
	version *version.VersionInfo
}

func newServer() (*Server, error) {
	wire.Build(
		wire.Struct(new(Server), "*"),
		AppSet,
	)
	return &Server{}, nil
}
