package user_cache_repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"

	"github.com/JunBSer/service-auth/internal/domain/models"
	db "github.com/JunBSer/service-auth/pkg/db/redis"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CacheRepository interface {
	Get(id uuid.UUID) (*models.UserInfo, error)
	AddToCache(reg *models.UserInfo) error
	RemoveFromCache(userID uuid.UUID) error
}

type CacheRepo struct {
	Log        logger.Logger
	Expiration time.Duration
	cli        *db.Client
}

const (
	cacheKeyPrefix = "user:"
	opTimeout      = 3 * time.Second
)

func NewCacheRepo(log *logger.Logger, expiration time.Duration, cli *db.Client) *CacheRepo {
	return &CacheRepo{
		Log:        *log,
		Expiration: expiration,
		cli:        cli,
	}
}

func (c *CacheRepo) Get(id uuid.UUID) (*models.UserInfo, error) {
	const op = "CacheRepo.Get"
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	key := cacheKeyPrefix + id.String()
	data, err := c.cli.Cli.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, models.ErrCacheMiss
		}
		c.Log.Error(ctx, "failed to get from cache",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("key", key),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var user models.UserInfo
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		c.Log.Error(ctx, "failed to unmarshal user data",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("key", key),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (c *CacheRepo) AddToCache(user *models.UserInfo) error {
	const op = "CacheRepo.AddToCache"
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	key := cacheKeyPrefix + user.ID.String()
	data, err := json.Marshal(user)
	if err != nil {
		c.Log.Error(ctx, "failed to marshal user data",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("key", key),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := c.cli.Cli.SetEx(ctx, key, data, c.Expiration).Err(); err != nil {
		c.Log.Error(ctx, "failed to set cache",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("key", key),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (c *CacheRepo) RemoveFromCache(userID uuid.UUID) error {
	const op = "CacheRepo.RemoveFromCache"
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	key := cacheKeyPrefix + userID.String()
	if err := c.cli.Cli.Del(ctx, key).Err(); err != nil {
		c.Log.Error(ctx, "failed to delete from cache",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("key", key),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
