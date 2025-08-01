package usecase

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/chaitin/MonkeyCode/backend/config"
	"github.com/chaitin/MonkeyCode/backend/consts"
	"github.com/chaitin/MonkeyCode/backend/db"
	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/pkg/cvt"
	"github.com/chaitin/MonkeyCode/backend/pkg/queuerunner"
	"github.com/chaitin/MonkeyCode/backend/pkg/request"
	"github.com/chaitin/MonkeyCode/backend/pkg/scan"
)

type ProxyUsecase struct {
	repo        domain.ProxyRepo
	modelRepo   domain.ModelRepo
	logger      *slog.Logger
	queuerunner *queuerunner.QueueRunner[domain.CreateSecurityScanningReq]
	client      *request.Client
}

func NewProxyUsecase(
	repo domain.ProxyRepo,
	modelRepo domain.ModelRepo,
	logger *slog.Logger,
	cfg *config.Config,
	redis *redis.Client,
) domain.ProxyUsecase {
	client := request.NewClient("http", "monkeycode-scanner", 15*time.Second)
	client.SetDebug(cfg.Debug)
	p := &ProxyUsecase{
		repo:        repo,
		modelRepo:   modelRepo,
		logger:      logger.With("module", "ProxyUsecase"),
		queuerunner: queuerunner.NewQueueRunner[domain.CreateSecurityScanningReq](cfg, redis, logger),
		client:      client,
	}
	go p.queuerunner.Run(context.Background())
	return p
}

func (p *ProxyUsecase) Record(ctx context.Context, record *domain.RecordParam) error {
	return p.repo.Record(ctx, record)
}

// SelectModelWithLoadBalancing implements domain.ProxyUsecase.
func (p *ProxyUsecase) SelectModelWithLoadBalancing(modelName string, modelType consts.ModelType) (*domain.Model, error) {
	model, err := p.modelRepo.GetWithCache(context.Background(), modelType)
	if err != nil {
		return nil, err
	}
	return cvt.From(model, &domain.Model{}), nil
}

func (p *ProxyUsecase) ValidateApiKey(ctx context.Context, key string) (*domain.ApiKey, error) {
	apiKey, err := p.repo.ValidateApiKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return cvt.From(apiKey, &domain.ApiKey{}), nil
}

func (p *ProxyUsecase) AcceptCompletion(ctx context.Context, req *domain.AcceptCompletionReq) error {
	return p.repo.AcceptCompletion(ctx, req)
}

func (p *ProxyUsecase) Report(ctx context.Context, req *domain.ReportReq) error {
	var model *db.Model
	var err error
	if req.Action == consts.ReportActionNewTask {
		model, err = p.modelRepo.GetWithCache(context.Background(), consts.ModelTypeLLM)
		if err != nil {
			p.logger.With("fn", "Report").With("error", err).ErrorContext(ctx, "failed to get model")
			return err
		}
	}
	return p.repo.Report(ctx, model, req)
}

func (p *ProxyUsecase) CreateSecurityScanning(ctx context.Context, req *domain.CreateSecurityScanningReq) (string, error) {
	return p.queuerunner.Enqueue(ctx, *req, p.TaskHandle)
}

func (p *ProxyUsecase) TaskHandle(ctx context.Context, task *queuerunner.Task[domain.CreateSecurityScanningReq]) error {
	p.logger.With("id", task.ID).DebugContext(ctx, "task started")

	resp, err := request.Post[request.Response[scan.Result]](p.client, "/api/v1/scan", task.Data)
	if err != nil {
		p.logger.With("id", task.ID).With("error", err).ErrorContext(ctx, "failed to post")
		return err
	}

	p.logger.With("id", task.ID).With("result", resp.Data).DebugContext(ctx, "task done")
	return nil
}
