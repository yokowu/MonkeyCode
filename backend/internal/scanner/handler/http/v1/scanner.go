package v1

import (
	"log/slog"
	"strings"

	"github.com/GoYoko/web"

	"github.com/chaitin/MonkeyCode/backend/db/task"
	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/pkg/scan"
)

type ScannerHandler struct {
	logger *slog.Logger
}

func NewScannerHandler(
	w *web.Web,
	logger *slog.Logger,
) *ScannerHandler {
	s := &ScannerHandler{
		logger: logger,
	}

	g := w.Group("/api/v1/scan")
	g.POST("", web.BindHandler(s.Scan))

	return s
}

func (s *ScannerHandler) Scan(ctx *web.Context, req domain.CreateSecurityScanningReq) error {
	rule := strings.ToLower(string(req.Language))
	result, err := scan.Scan(req.Workspace, rule)
	if err != nil {
		s.logger.With("id", task.ID).With("error", err).ErrorContext(ctx.Request().Context(), "failed to scan")
		return err
	}
	return ctx.Success(result)
}
