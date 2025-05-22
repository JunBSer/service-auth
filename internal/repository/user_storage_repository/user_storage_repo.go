package user_storage_repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/JunBSer/service-auth/internal/domain/models"
	"github.com/JunBSer/service-auth/pkg/db/postgres"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type UserRepository interface {
	Register(reg *models.UserReg) (uuid.UUID, error)
	IsUserExist(email string) (uuid.UUID, error)
	CheckUserCredentials(userID uuid.UUID, password string) error
	IsUserAdmin(userID uuid.UUID) (bool, error)
	ChangePassword(newPassword string, userID uuid.UUID) error
	GetUserInfo(userID uuid.UUID) (*models.UserInfo, error)
	ListUsers(page int, limit int) ([]*models.UserInfo, error)

	GetUser(userID uuid.UUID) (*models.User, error)
	CreateUser(user *models.UserCrInfo) (uuid.UUID, error)
	DeleteUser(userID uuid.UUID) error
	UpdateUser(userID uuid.UUID, user *models.UserChInfo) error
}

var (
	ErrorNotFound        = errors.New("user not found")
	ErrorInvalidParams   = errors.New("invalid request parameters")
	ErrorInvalidPassword = errors.New("invalid password")
)

type UserRepo struct {
	DB  *postgres.DB
	log logger.Logger
}

func NewUserRepo(db *postgres.DB, log logger.Logger) *UserRepo {
	return &UserRepo{
		DB:  db,
		log: log,
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (repo *UserRepo) validateRegisterFields(reg *models.UserReg) error {
	if reg == nil {
		return ErrorInvalidParams
	}

	if reg.Email == "" {
		return ErrorInvalidParams
	}

	if reg.Name == "" {
		return ErrorInvalidParams
	}

	if reg.Password == "" {
		return ErrorInvalidParams
	}

	return nil
}

func (repo *UserRepo) fillUserFields(user *models.UserCrInfo) (*models.User, error) {
	const op = "UserRepo.fillUserFields"

	passHash, err := hashPassword(user.Password)
	if err != nil {
		repo.log.Error(context.Background(), "Error while hashing password", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	newUser := &models.User{
		ID:        uuid.New(),
		Name:      user.Name,
		Email:     user.Email,
		PassHash:  passHash,
		IsAdmin:   user.IsAdmin,
		CreatedAt: time.Time{},
	}

	return newUser, nil
}
func (repo *UserRepo) CreateUser(user *models.UserCrInfo) (uuid.UUID, error) {
	const op = "Repo.CreateUser"

	err := repo.validateRegisterFields(&models.UserReg{
		Name:     user.Name,
		Email:    user.Email,
		Password: user.Password,
	})

	if err != nil {
		repo.log.Error(context.Background(), "Error while checking request data", zap.Error(err), zap.String("caller", op))
		return uuid.Nil, err
	}

	newUser, err := repo.fillUserFields(user)
	if err != nil {
		repo.log.Error(context.Background(), "Error while filling user data", zap.Error(err), zap.String("caller", op))
		return uuid.Nil, err
	}

	err = repo.AddUser(newUser)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				repo.log.Error(context.Background(), "Email already exists", zap.Error(err))
				return uuid.Nil, errors.New("email already exists")
			}
		}

		repo.log.Error(context.Background(), "Error while filling user data", zap.Error(err))
		return uuid.Nil, err
	}

	return newUser.ID, nil

}

func (repo *UserRepo) Register(reg *models.UserReg) (uuid.UUID, error) {
	const op = "Repo.Register"

	err := repo.validateRegisterFields(reg)
	if err != nil {
		repo.log.Error(context.Background(), "Error while checking request data", zap.Error(err), zap.String("caller", op))
		return uuid.Nil, err
	}

	newUser, err := repo.fillUserFields(&models.UserCrInfo{
		Name:     reg.Name,
		Email:    reg.Email,
		IsAdmin:  false,
		Password: reg.Password,
	})

	if err != nil {
		repo.log.Error(context.Background(), "Error while filling user data", zap.Error(err))
		return uuid.Nil, err
	}

	err = repo.AddUser(newUser)
	if err != nil {
		repo.log.Error(context.Background(), "Error while adding user", zap.Error(err), zap.String("caller", op))
		var pgErr *pq.Error
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				repo.log.Error(context.Background(), "Email already exists", zap.Error(err))
				return uuid.Nil, errors.New("email already exists")
			}
		}
		return uuid.Nil, err
	}

	return newUser.ID, nil
}

func (repo *UserRepo) AddUser(userInfo *models.User) error {
	const op = "UserRepo.AddUser"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addUserQuery := `
    INSERT INTO users (user_id, name, email, pass_hash, is_admin)
    VALUES (:user_id, :name, :email, :pass_hash, :is_admin)
    RETURNING created_at;
`

	stmt, err := repo.DB.Db.PrepareNamed(addUserQuery)
	if err != nil {
		return fmt.Errorf("%s: prepare failed: %w", op, err)
	}
	defer stmt.Close()

	err = stmt.GetContext(ctx, userInfo, userInfo)
	if err != nil {
		repo.log.Error(context.Background(), "failed to insert user",
			zap.String("caller", op),
			zap.Error(err),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (repo *UserRepo) GetUserInfo(userID uuid.UUID) (*models.UserInfo, error) {
	const op = "UserRepo.GetUserInfo"

	userInfo := &models.UserInfo{}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	getUserQuery := `
        SELECT 
            user_id, 
            name, 
            email, 
            is_admin, 
            created_at
        FROM users
        WHERE user_id = $1
    `
	err := repo.DB.Db.QueryRowContext(ctx, getUserQuery, userID).Scan(
		&userInfo.ID,
		&userInfo.Name,
		&userInfo.Email,
		&userInfo.IsAdmin,
		&userInfo.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrorNotFound
		}

		repo.log.Error(context.Background(), "failed to get user info",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", userID),
		)

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return userInfo, nil

}

func (repo *UserRepo) DeleteUser(userID uuid.UUID) error {
	const op = "UserRepo.DeleteUser"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	deleteUserQuery := `
        DELETE FROM users 
        WHERE user_id = $1
    `

	result, err := repo.DB.Db.ExecContext(ctx, deleteUserQuery, userID)
	if err != nil {
		repo.log.Error(ctx, "failed to delete user",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrorNotFound
	}

	return nil
}

func (repo *UserRepo) IsUserExist(email string) (uuid.UUID, error) {
	const op = "UserRepo.IsUserExist"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var userID uuid.UUID
	query := `SELECT user_id FROM users WHERE email = $1`

	err := repo.DB.Db.QueryRowContext(ctx, query, email).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, nil
		}
		repo.log.Error(ctx, "failed to check user existence",
			zap.Error(err),
			zap.String("caller", op),
			zap.String("email", email),
		)
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	return userID, nil
}

func (repo *UserRepo) CheckUserCredentials(userID uuid.UUID, password string) error {
	const op = "UserRepo.CheckUserCredentials"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var storedHash string
	query := `SELECT pass_hash FROM users WHERE user_id = $1`

	err := repo.DB.Db.QueryRowContext(ctx, query, userID).Scan(&storedHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrorNotFound
		}
		repo.log.Error(ctx, "failed to get password hash",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", userID),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	if !checkPasswordHash(password, storedHash) {
		return ErrorInvalidPassword
	}

	return nil
}

func (repo *UserRepo) IsUserAdmin(userID uuid.UUID) (bool, error) {
	const op = "UserRepo.IsUserAdmin"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var isAdmin bool
	query := `SELECT is_admin FROM users WHERE user_id = $1`

	err := repo.DB.Db.QueryRowContext(ctx, query, userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrorNotFound
		}
		repo.log.Error(ctx, "failed to check admin status",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", userID),
		)
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (repo *UserRepo) ChangePassword(newPassword string, userID uuid.UUID) error {
	const op = "UserRepo.ChangePassword"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	newHash, err := hashPassword(newPassword)
	if err != nil {
		repo.log.Error(ctx, "failed to hash new password",
			zap.Error(err),
			zap.String("caller", op),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	query := `UPDATE users SET pass_hash = $1 WHERE user_id = $2`
	result, err := repo.DB.Db.ExecContext(ctx, query, newHash, userID)
	if err != nil {
		repo.log.Error(ctx, "failed to update password",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", userID),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrorNotFound
	}

	return nil
}

func (repo *UserRepo) ListUsers(page int, limit int) ([]*models.UserInfo, error) {
	const op = "UserRepo.ListUsers"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	offset := (page - 1) * limit
	query := `
        SELECT 
            user_id, 
            name, 
            email, 
            is_admin, 
            created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
    `

	rows, err := repo.DB.Db.QueryxContext(ctx, query, limit, offset)
	if err != nil {
		repo.log.Error(ctx, "failed to list users",
			zap.Error(err),
			zap.String("caller", op),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var users []*models.UserInfo
	for rows.Next() {
		var user models.User
		if err := rows.StructScan(&user); err != nil {
			repo.log.Error(ctx, "failed to scan user",
				zap.Error(err),
				zap.String("op", op),
			)
			continue
		}
		users = append(users, user.UserToInfo())
	}

	return users, nil
}

func (repo *UserRepo) GetUser(userID uuid.UUID) (*models.User, error) {
	const op = "UserRepo.GetUser"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var user models.User
	query := `SELECT * FROM users WHERE user_id = $1`

	err := repo.DB.Db.QueryRowxContext(ctx, query, userID).StructScan(&user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrorNotFound
		}
		repo.log.Error(ctx, "failed to get user",
			zap.Error(err),
			zap.String("caller", op),
			zap.Any("user_id", userID),
		)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (repo *UserRepo) UpdateUser(userID uuid.UUID, user *models.UserChInfo) error {
	const op = "UserRepo.UpdateUser"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if userID == uuid.Nil {
		return fmt.Errorf("%s: invalid user ID", op)
	}

	tx, err := repo.DB.Db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer tx.Rollback()

	if user.Name != "" || user.Email != "" {
		query := `
            UPDATE users 
            SET 
                name = COALESCE(NULLIF($1, ''), name), 
                email = COALESCE(NULLIF($2, ''), email) 
            WHERE user_id = $3
        `
		_, err := tx.ExecContext(ctx, query, user.Name, user.Email, userID)
		if err != nil {
			repo.log.Error(ctx, "failed to update user info",
				zap.Error(err),
				zap.String("caller", op),
				zap.Any("user_id", userID),
			)
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	if user.Password != "" {
		newHash, err := hashPassword(user.Password)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		_, err = tx.ExecContext(ctx,
			"UPDATE users SET pass_hash = $1 WHERE user_id = $2",
			newHash, userID,
		)
		if err != nil {
			repo.log.Error(ctx, "failed to update password",
				zap.Error(err),
				zap.String("caller", op),
				zap.Any("user_id", userID),
			)
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	_, err = tx.ExecContext(ctx,
		"UPDATE users SET is_admin = $1 WHERE user_id = $2",
		user.IsAdmin, userID,
	)
	if err != nil {
		repo.log.Error(ctx, "failed to update admin status",
			zap.Error(err),
			zap.String("op", op),
			zap.Any("user_id", userID),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
