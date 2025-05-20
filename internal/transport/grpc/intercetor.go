package grpc

import (
	"context"
	"github.com/JunBSer/service-auth/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func WithLoggerInterceptor(lg logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		lg.Info(ctx, "Started processing request", zap.String("method: ", info.FullMethod))
		resp, err := handler(ctx, req)
		if err != nil {
			lg.Debug(ctx, "Failed processing request", zap.String("method: ", info.FullMethod))
			return resp, err
		}
		lg.Debug(ctx, "Completed processing request", zap.String("method: ", info.FullMethod))
		return resp, err
	}
}
