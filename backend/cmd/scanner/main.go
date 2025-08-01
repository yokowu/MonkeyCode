package main

import (
	"context"

	"github.com/GoYoko/web"
	"github.com/GoYoko/web/locale"
	"github.com/google/wire"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/text/language"

	"github.com/chaitin/MonkeyCode/backend/config"
	"github.com/chaitin/MonkeyCode/backend/errcode"
	mid "github.com/chaitin/MonkeyCode/backend/internal/middleware"
	v1 "github.com/chaitin/MonkeyCode/backend/internal/scanner/handler/http/v1"
	"github.com/chaitin/MonkeyCode/backend/pkg/logger"
	"github.com/chaitin/MonkeyCode/backend/pkg/service"
	"github.com/chaitin/MonkeyCode/backend/pkg/version"
)

func main() {
	s, err := newServer()
	if err != nil {
		panic(err)
	}

	s.version.Print()
	s.web.PrintRoutes()
	s.logger.With("config", s.config).Debug("config")

	svc := service.NewService(service.WithPprof())
	svc.Add(s)
	if err := svc.Run(); err != nil {
		panic(err)
	}
}

// Name implements service.Servicer.
func (s *Server) Name() string {
	return "Scanner Server"
}

// Start implements service.Servicer.
func (s *Server) Start() error {
	return s.web.Run(s.config.Server.Addr)
}

// Stop implements service.Servicer.
func (s *Server) Stop() error {
	return s.web.Echo().Shutdown(context.Background())
}

var AppSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "Logger"),
	config.Init,
	logger.NewLogger,
	NewWeb,
	v1.NewScannerHandler,
	version.NewVersionInfo,
)

func NewWeb(cfg *config.Config) *web.Web {
	w := web.New()
	l := locale.NewLocalizerWithFile(language.Chinese, errcode.LocalFS, []string{"locale.zh.toml"})
	w.SetLocale(l)
	w.Use(mid.RequestID())
	if cfg.Debug {
		w.Use(middleware.Logger())
	}
	return w
}
