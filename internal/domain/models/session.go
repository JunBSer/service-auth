package models

import (
	"github.com/google/uuid"
	"time"
)

type Session struct {
	ID           uuid.UUID `db:"session_id"`
	UserID       uuid.UUID `db:"user_id"`
	RefreshToken string    `db:"refresh_token"`
	CreatedAt    time.Time `db:"created_at"`
	ExpiresAt    time.Time `db:"expires_at"`
}

type SessionReg struct {
	ID           uuid.UUID `db:"session_id"`
	UserID       uuid.UUID `db:"user_id"`
	RefreshToken string    `db:"refresh_token"`
}
