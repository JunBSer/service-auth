package models

import (
	"errors"
	"github.com/google/uuid"
	"time"
)

var ErrCacheMiss = errors.New("cache miss")

// User represents db row
type User struct {
	ID        uuid.UUID `db:"user_id"`
	Name      string    `db:"name"`
	Email     string    `db:"email"`
	PassHash  string    `db:"pass_hash"`
	IsAdmin   bool      `db:"is_admin"`
	CreatedAt time.Time `db:"created_at"`
}

// UserRes  uses for grpc response contract
type UserInfo struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

type UserChInfo struct {
	ID       uuid.UUID
	Name     string
	Email    string
	IsAdmin  bool
	Password string
}

type UserReg struct {
	Name     string
	Email    string
	Password string
}

type UserCrInfo struct {
	Name     string
	Email    string
	IsAdmin  bool
	Password string
}

func (u User) UserToInfo() *UserInfo {
	return &UserInfo{
		ID:        u.ID,
		Name:      u.Name,
		Email:     u.Email,
		IsAdmin:   u.IsAdmin,
		CreatedAt: u.CreatedAt,
	}
}
