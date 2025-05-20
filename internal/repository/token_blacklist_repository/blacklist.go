package token_blacklist_repository

import "github.com/google/uuid"

type BlacklistRepository interface {
	AddToBlacklist(sessionID uuid.UUID) error
	RemoveFromBlacklist(sessionID uuid.UUID) error
	IsBlacklisted(sessionID uuid.UUID) (bool, error)
}
