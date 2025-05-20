package user_cache_repository

import (
	"github.com/JunBSer/service-auth/internal/domain/models"
	"github.com/google/uuid"
)

type CacheRepository interface {
	Get(id uuid.UUID) (*models.UserInfo, error)
	AddToCache(reg *models.UserInfo) error
	RemoveFromCache(sessionID uuid.UUID) error
}
