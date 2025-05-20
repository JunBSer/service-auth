package session_repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/JunBSer/service-auth/internal/domain/models"
	"github.com/JunBSer/service-auth/pkg/db/postgres"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"time"
)

type SessionRepository interface {
	AddSession(session models.SessionReg) (uuid.UUID, error)
	DeleteSession(sessionID uuid.UUID) error

	GetSessionCount(usrID uuid.UUID) (int, error)
	DeleteEarliestSession(usrID uuid.UUID) error
	IsSessionExists(sessionID uuid.UUID) (bool, error)
	GetAllUserSessions(usrID uuid.UUID) ([]models.SessionReg, error)
	DeleteAllUsSessions(usrID uuid.UUID) error
	GetSessionByID(sessionID uuid.UUID) (*models.SessionReg, error)
	RefreshSessionToken(refreshToken string, sessionID uuid.UUID) error
}

type SessionsRepo struct {
	DB              *postgres.DB
	log             logger.Logger
	SessionDuration time.Duration
	MaxSessionCnt   int
}

var (
	ErrorNotFound = fmt.Errorf("session not found")
)

func NewSessionsRepo(db *postgres.DB, log logger.Logger, sessDuration time.Duration, maxSessionCnt int) *SessionsRepo {
	return &SessionsRepo{
		DB:              db,
		log:             log,
		SessionDuration: sessDuration,
		MaxSessionCnt:   maxSessionCnt,
	}
}

func (repo *SessionsRepo) AddSession(session models.SessionReg) (uuid.UUID, error) {
	const op = "SessionsRepo.AddSession"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tx, err := repo.DB.Db.BeginTxx(ctx, nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}
	defer tx.Rollback()

	expiresAt := time.Now().Add(repo.SessionDuration)

	addSessionQuery := `
        INSERT INTO sessions (session_id, user_id, refresh_token, expires_at)
        VALUES (:session_id, :user_id, :refresh_token, :expires_at)
        RETURNING session_id;
    `

	fullSession := models.Session{
		ID:           session.ID,
		UserID:       session.UserID,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    expiresAt,
	}

	var insertedID uuid.UUID
	stmt, err := tx.PrepareNamedContext(ctx, addSessionQuery)
	if err != nil {
		repo.log.Error(ctx, "failed to prepare query",
			zap.Error(err),
			zap.String("caller", op),
		)
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	if err := stmt.GetContext(ctx, &insertedID, fullSession); err != nil {
		repo.log.Error(ctx, "failed to insert session",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", session.UserID),
		)
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	count, err := repo.getSessionCountTx(tx, session.UserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	if count > repo.MaxSessionCnt {
		if err := repo.deleteEarliestSessionTx(tx, session.UserID); err != nil {
			return uuid.Nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	return insertedID, nil
}

func (repo *SessionsRepo) getSessionCountTx(tx *sqlx.Tx, userID uuid.UUID) (int, error) {
	query := `
        SELECT COUNT(*) 
        FROM sessions 
        WHERE user_id = $1
    `

	var count int
	err := tx.QueryRowxContext(context.Background(), query, userID).Scan(&count)
	return count, err
}

func (repo *SessionsRepo) deleteEarliestSessionTx(tx *sqlx.Tx, userID uuid.UUID) error {
	query := `
        DELETE FROM sessions
        WHERE session_id IN (
            SELECT session_id
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at ASC
            LIMIT 1
        )
    `

	_, err := tx.ExecContext(context.Background(), query, userID)
	return err
}

func (repo *SessionsRepo) DeleteSession(sessionID uuid.UUID) error {
	const op = "SessionsRepo.DeleteSession"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `DELETE FROM sessions WHERE session_id = $1`
	res, err := repo.DB.Db.ExecContext(ctx, query, sessionID)
	if err != nil {
		repo.log.Error(ctx, "failed to delete session",
			zap.Error(err),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("%s: %w", op, ErrorNotFound)
	}

	return nil
}

func (repo *SessionsRepo) GetSessionCount(userID uuid.UUID) (int, error) {
	const op = "SessionsRepo.GetSessionCount"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var count int
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = $1`

	err := repo.DB.Db.QueryRowxContext(ctx, query, userID).Scan(&count)
	if err != nil {
		repo.log.Error(ctx, "failed to count sessions",
			zap.Error(err),
			zap.String("caller", op),
		)
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return count, nil
}

func (repo *SessionsRepo) DeleteEarliestSession(userID uuid.UUID) error {
	const op = "SessionsRepo.DeleteEarliestSession"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `
        DELETE FROM sessions
        WHERE session_id IN (
            SELECT session_id
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at ASC
            LIMIT 1
        )
    `

	res, err := repo.DB.Db.ExecContext(ctx, query, userID)
	if err != nil {
		repo.log.Error(ctx, "failed to delete earliest session",
			zap.Error(err),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("%s: %w", op, ErrorNotFound)
	}

	return nil
}

func (repo *SessionsRepo) IsSessionExists(sessionID uuid.UUID) (bool, error) {
	const op = "SessionsRepo.IsSessionExists"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var exists bool
	query := `
        SELECT EXISTS(
            SELECT 1 
            FROM sessions 
            WHERE session_id = $1
        )
    `

	err := repo.DB.Db.QueryRowxContext(ctx, query, sessionID).Scan(&exists)
	if err != nil {
		repo.log.Error(ctx, "failed to check session existence",
			zap.Error(err),
			zap.String("caller", op),
		)
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return exists, nil
}

func (repo *SessionsRepo) GetAllUserSessions(userID uuid.UUID) ([]models.SessionReg, error) {
	const op = "SessionsRepo.GetAllUserSessions"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `
        SELECT session_id, user_id, refresh_token
        FROM sessions
        WHERE user_id = $1
        ORDER BY created_at DESC
    `

	var sessions []models.SessionReg
	err := repo.DB.Db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		repo.log.Error(ctx, "failed to get user sessions",
			zap.Error(err),
			zap.String("caller", op),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return sessions, nil
}

func (repo *SessionsRepo) DeleteAllUserSessions(userID uuid.UUID) error {
	const op = "SessionsRepo.DeleteAllUserSessions"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := repo.DB.Db.ExecContext(ctx, query, userID)
	if err != nil {
		repo.log.Error(ctx, "failed to delete all user sessions",
			zap.Error(err),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (repo *SessionsRepo) GetSessionByID(sessionID uuid.UUID) (*models.SessionReg, error) {
	const op = "SessionsRepo.GetSessionByID"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var session models.SessionReg
	query := `
        SELECT session_id, user_id, refresh_token
        FROM sessions
        WHERE session_id = $1
    `

	err := repo.DB.Db.GetContext(ctx, &session, query, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrorNotFound)
		}
		repo.log.Error(ctx, "failed to get session",
			zap.Error(err),
			zap.String("caller", op),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &session, nil
}

func (repo *SessionsRepo) RefreshSessionToken(refreshToken string, sessionID uuid.UUID) error {
	const op = "SessionsRepo.RefreshSessionToken"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `
        UPDATE sessions
        SET 
            refresh_token = $1,
            expires_at = $2
        WHERE session_id = $3
    `

	expiresAt := time.Now().Add(repo.SessionDuration)
	_, err := repo.DB.Db.ExecContext(ctx, query, refreshToken, expiresAt, sessionID)
	if err != nil {
		repo.log.Error(ctx, "failed to refresh session token",
			zap.Error(err),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
