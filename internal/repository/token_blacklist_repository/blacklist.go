package token_blacklist_repository

import (
	"context"
	"github.com/JunBSer/service-auth/pkg/db/redis"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"time"
)

type BlacklistRepository interface {
	AddToBlacklist(sessionID uuid.UUID) error
	RemoveFromBlacklist(sessionID uuid.UUID) error
	IsBlacklisted(sessionID uuid.UUID) (bool, error)
}

type Blacklist struct {
	AccessLifetime time.Duration
	Cli            *redis.Client
	log            logger.Logger
}

func NewBlacklist(log *logger.Logger, accessLifetime time.Duration, cli *redis.Client) *Blacklist {
	return &Blacklist{
		AccessLifetime: accessLifetime,
		Cli:            cli,
		log:            *log,
	}
}

func (b *Blacklist) AddToBlacklist(sessionID uuid.UUID) error {
	const op = "Blacklist.AddToBlacklist"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := b.Cli.Cli.SetEx(ctx, sessionID.String(), "true", b.AccessLifetime).Err(); err != nil {
		b.log.Error(
			ctx,
			"failed to add to blacklist",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("sessionID", sessionID.String()),
		)
		return err
	}

	return nil
}

func (b *Blacklist) RemoveFromBlacklist(sessionID uuid.UUID) error {
	const op = "Blacklist.RemoveFromBlacklist"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := b.Cli.Cli.Del(ctx, sessionID.String()).Err(); err != nil {
		b.log.Error(
			ctx,
			"failed to remove from blacklist",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("sessionID", sessionID.String()),
		)
		return err
	}

	return nil
}

func (b *Blacklist) IsBlacklisted(sessionID uuid.UUID) (bool, error) {
	const op = "Blacklist.IsBlacklisted"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := b.Cli.Cli.Exists(ctx, sessionID.String()).Result()
	if err != nil {
		b.log.Error(
			ctx,
			"failed to check blacklist",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("sessionID", sessionID.String()),
		)
		return false, err
	}

	return result > 0, nil
}
