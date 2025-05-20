package grpc

import (
	"context"
	"fmt"
	"github.com/JunBSer/service-auth/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

type Config struct {
	Host string `env:"GRPC_HOST" envDefault:"0.0.0.0"`
	Port string `env:"GRPC_PORT" envDefault:"50051"`
}

type Server struct {
	grpc     *grpc.Server
	listener net.Listener
	lg       *logger.Logger
}

func New(cfg Config, log logger.Logger) (*Server, error) {
	ctx := context.Background()

	log.Info(ctx, "Creating gRPC server...")

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%s", cfg.Host, cfg.Port))
	if err != nil {
		log.Error(ctx, "Error to create listener", zap.Error(err))
		return nil, err
	}

	opts := []grpc.ServerOption{grpc.ChainUnaryInterceptor(WithLoggerInterceptor(log))}

	grpcServer := grpc.NewServer(opts...)

	log.Info(ctx, "Created gRPC server", zap.String("host: ", cfg.Host), zap.String("port: ", cfg.Port))

	return &Server{grpc: grpcServer, listener: lis, lg: &log}, nil
}

func (srv *Server) Start() error {
	(*srv.lg).Info(context.Background(), "Starting gRPC server...")

	err := srv.grpc.Serve(srv.listener)

	return err
}

func (srv *Server) Stop() {
	(*srv.lg).Info(context.Background(), "Stopping gRPC server...")
	srv.grpc.GracefulStop()
}

//Use it in grace shut
//if err != nil {
//	if errors.Is(err, grpc.ErrServerStopped) {
//		(*srv.lg).Info(context.Background(), "gRpc server stopped", zap.Error(err))
//	} else {
//		(*srv.lg).Info(context.Background(), "Error to start gRPC server", zap.Error(err))
//	}
//}
