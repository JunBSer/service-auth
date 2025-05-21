package redis

import (
	"context"
	"fmt"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"time"
)

type Config struct {
	Host     string `env:"REDIS_HOST" env-default:"host.docker.internal"`
	Port     int    `env:"REDIS_PORT" env-default:"6379"`
	Password string `env:"REDIS_PASSWORD" env-default:"password"`
}
type Client struct {
	Cli *redis.Client
}

func New(cfg Config, log logger.Logger) (*Client, error) {
	const op = "redis.NewClient"

	db := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Ping(ctx).Err(); err != nil {
		log.Error(
			context.Background(),
			"failed to connect to redis server: ",
			zap.Error(err),
			zap.String("caller", op),
		)

		return nil, err
	}

	return &Client{
		Cli: db,
	}, nil
}

func (db *Client) CloseDB() error {
	return db.Cli.Close()
}
