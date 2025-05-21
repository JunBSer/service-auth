package app

import (
	"context"
	"errors"
	"github.com/JunBSer/service-auth/internal/config"
	"github.com/JunBSer/service-auth/internal/repository/session_repository"
	"github.com/JunBSer/service-auth/internal/repository/token_blacklist_repository"
	"github.com/JunBSer/service-auth/internal/repository/user_cache_repository"
	"github.com/JunBSer/service-auth/internal/repository/user_storage_repository"
	"github.com/JunBSer/service-auth/internal/service"
	myGrpc "github.com/JunBSer/service-auth/internal/transport/grpc"
	"github.com/JunBSer/service-auth/pkg/db/postgres"
	"github.com/JunBSer/service-auth/pkg/db/redis"
	"github.com/JunBSer/service-auth/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"os"
	"os/signal"
	"syscall"
)

func MustRun(cfg *config.Config) {
	ctx := context.Background()

	mainLogger := logger.New(cfg.App.ServiceName, cfg.Logger.LogLvl)

	mainLogger.Info(ctx, "Starting auth-service...")

	Db, err := postgres.New(cfg.DB, &mainLogger)
	if err != nil {
		panic(err)
	}

	redisClient, err := redis.New(cfg.Redis, mainLogger)
	if err != nil {
		panic(err)
	}

	userRepo := user_storage_repository.NewUserRepo(Db, mainLogger)
	userCache := user_cache_repository.NewCacheRepo(&mainLogger, cfg.App.CacheExpire, redisClient)
	sessionRepo := session_repository.NewSessionsRepo(Db, &mainLogger, cfg.Session.MaxLifetime, cfg.Session.MaxSessionCnt)
	blackList := token_blacklist_repository.NewBlacklist(&mainLogger, cfg.Token.AccessTokenExpireTime, redisClient)

	tokenService := service.NewTokenService(&mainLogger, cfg.App.Secret, cfg.Token.AccessTokenExpireTime, cfg.Token.RefreshTokenExpireTime)
	authService := service.NewAuthService(userRepo, sessionRepo, blackList, userCache, tokenService, mainLogger)

	service := myGrpc.NewService(authService)

	srv, err := myGrpc.New(cfg.GRPC, mainLogger, service)
	if err != nil {
		panic(err)
	}

	graceCh := make(chan os.Signal, 2)
	signal.Notify(graceCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		err := srv.Start()

		if err != nil {
			if errors.Is(err, grpc.ErrServerStopped) {
				mainLogger.Info(context.Background(), "gRpc server stopped", zap.Error(err))
			} else {
				mainLogger.Error(context.Background(), "Error to start gRPC server", zap.Error(err))
			}
		}
	}()

	sig := <-graceCh
	mainLogger.Info(ctx, "Shutting down...", zap.String("signal", sig.String()))

	srv.Stop()

	err = redisClient.CloseDB()
	if err != nil {
		mainLogger.Error(context.Background(), "Failed to close redis connection", zap.Error(err))
	}

	err = Db.CloseDB()
	if err != nil {
		mainLogger.Error(context.Background(), "Failed to close db connection", zap.Error(err))
	}
}
