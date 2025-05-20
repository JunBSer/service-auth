package app

import (
	"context"
	"github.com/JunBSer/service-auth/internal/config"
	"github.com/JunBSer/service-auth/pkg/logger"
)

func Run(cfg *config.Config) {
	ctx := context.Background()

	mainLogger := logger.New(cfg.App.ServiceName, cfg.Logger.LogLvl)

	mainLogger.Info(ctx, "Starting auth-service...")
}
