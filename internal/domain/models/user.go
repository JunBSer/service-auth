package models

import (
	"github.com/google/uuid"
	"time"
)

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
	ID        uuid.UUID
	Name      string
	Email     string
	IsAdmin   bool
	CreatedAt time.Time
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
