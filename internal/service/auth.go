package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/JunBSer/service-auth/internal/domain/models"
	"github.com/JunBSer/service-auth/internal/repository/session_repository"
	"github.com/JunBSer/service-auth/internal/repository/token_blacklist_repository"
	"github.com/JunBSer/service-auth/internal/repository/user_cache_repository"
	"github.com/JunBSer/service-auth/internal/repository/user_storage_repository"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AuthService struct {
	uRepo     user_storage_repository.UserRepository
	sessions  session_repository.SessionRepository
	blacklist token_blacklist_repository.BlacklistRepository
	cacheRepo user_cache_repository.CacheRepository
	tkn       TokenService
	log       logger.Logger
}

func NewAuthService(
	uRepo user_storage_repository.UserRepository,
	sessions session_repository.SessionRepository,
	blacklist token_blacklist_repository.BlacklistRepository,
	cache user_cache_repository.CacheRepository,
	tkn TokenService,
	log logger.Logger) *AuthService {
	return &AuthService{uRepo, sessions, blacklist, cache, tkn, log}
}

// Methods that dont need auth middleware

func (srv *AuthService) GenerateTokenPair(userID uuid.UUID, sessionID uuid.UUID, isAdmin bool) (string, string, error) {
	const op = "Auth.GenerateTokenPair"

	rTkn, err := srv.tkn.GenerateRT(userID, sessionID)
	if err != nil {
		srv.log.Error(context.Background(), "Error to generate refresh token", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	aTkn, err := srv.tkn.GenerateAT(userID, sessionID, isAdmin)
	if err != nil {
		srv.log.Error(context.Background(), "Error to generate access token", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	return aTkn, rTkn, nil
}

func (srv *AuthService) CleanAllUsrSessions(userID uuid.UUID) error {
	const op = "Auth.CleanAllUsrSessions"

	sessions, err := srv.sessions.GetAllUserSessions(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting sessions", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.sessions.DeleteAllUserSessions(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while deleting sessions", zap.Error(err), zap.String("caller", op))
		return err
	}

	for _, session := range sessions {
		err = srv.blacklist.AddToBlacklist(session.ID)
		if err != nil {
			srv.log.Error(context.Background(), "Error occurred while adding to blacklist", zap.Error(err), zap.String("caller", op))
		}
	}

	return nil
}

func (srv *AuthService) Register(email string, password string, name string) (uuid.UUID, error) {
	const op = "Auth.Register"

	userID, err := srv.uRepo.Register(&models.UserReg{
		Name:     name,
		Email:    email,
		Password: password,
	})

	if err != nil {
		srv.log.Error(context.Background(), "Failed to register user", zap.Error(err), zap.String("caller", op))
	}
	return userID, err
}

func (srv *AuthService) Login(email string, password string) (string, string, error) {
	const op = "Auth.Login"

	userID, err := srv.uRepo.IsUserExist(email)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking an existence", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	err = srv.uRepo.CheckUserCredentials(userID, password)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking user credentials", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	sessionID := uuid.New()

	isAdmin, err := srv.uRepo.IsUserAdmin(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking user admin", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	aTkn, rTkn, err := srv.GenerateTokenPair(userID, sessionID, isAdmin)
	if err != nil {
		return "", "", err
	}

	_, err = srv.sessions.AddSession(models.SessionReg{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: rTkn,
	})

	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while adding session", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	return aTkn, rTkn, nil
}

func (srv *AuthService) ValidateToken(token string, tokenType byte) (uuid.UUID, error) {
	const op = "Auth.ValidateToken"

	var userID, sessionID uuid.UUID
	var err error

	if tokenType == JWT {
		userID, sessionID, err = srv.tkn.ValidateJWToken(token)
	} else {
		userID, sessionID, err = srv.tkn.ValidateRToken(token)
	}

	if err != nil {
		srv.log.Error(context.Background(), "Error occurred ", zap.Error(err), zap.String("caller", op))
		return uuid.Nil, err
	}

	if tokenType == JWT {
		isBlacklisted, err := srv.blacklist.IsBlacklisted(sessionID)
		if err != nil {
			srv.log.Error(context.Background(), "Error occurred while checking blacklist", zap.Error(err), zap.String("caller", op))
			return uuid.Nil, err
		}

		if isBlacklisted {
			srv.log.Error(context.Background(), "Blacklisted session", zap.String("caller", op), zap.String("sessionID", sessionID.String()))
			return uuid.Nil, errors.New("blacklisted session")
		}
	} else {
		isExists, err := srv.sessions.IsSessionExists(sessionID)
		if err != nil {
			srv.log.Error(context.Background(), "Error occurred while checking sessions", zap.Error(err), zap.String("caller", op))
			return uuid.Nil, err
		}

		if !isExists {
			return uuid.Nil, errors.New("session not found")
		}

		session, err := srv.sessions.GetSessionByID(sessionID)
		if err != nil {
			srv.log.Error(context.Background(), "Error occurred while getting session", zap.Error(err), zap.String("caller", op))
			return uuid.Nil, err
		}

		if session.RefreshToken != token {
			srv.log.Error(context.Background(), "Invalid token", zap.String("caller", op), zap.String("sessionID", sessionID.String()))
			return uuid.Nil, errors.New("invalid token")
		}
	}

	return userID, nil
}

func (srv *AuthService) RefreshToken(refreshToken string) (string, string, error) {
	const op = "Auth.RefreshToken"

	userID, err := srv.ValidateToken(refreshToken, RT)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while validating token", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	isAdmin, err := srv.uRepo.IsUserAdmin(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking user admin", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	sessionID, err := srv.tkn.GetSessionIDFromRToken(refreshToken)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting session ID", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	aTkn, rTkn, err := srv.GenerateTokenPair(userID, sessionID, isAdmin)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while generating token", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}

	err = srv.sessions.RefreshSessionToken(rTkn, sessionID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while refreshing session", zap.Error(err), zap.String("caller", op))
		return "", "", err
	}
	return aTkn, rTkn, nil
}

func (srv *AuthService) DeleteAccount(accessToken string, password string) error {
	const op = "Auth.DeleteAccount"

	userID, err := srv.ValidateToken(accessToken, JWT)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while validating token", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.uRepo.CheckUserCredentials(userID, password)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking credentials", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.uRepo.DeleteUser(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while deleting user", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.CleanAllUsrSessions(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while cleaning all sessions", zap.Error(err), zap.String("caller", op))
		return err
	}
	return nil
}

func (srv *AuthService) UpdateProfile(accessToken string, email string, name string) (*models.UserInfo, error) {
	const op = "Auth.UpdateProfile"

	usrID, err := srv.ValidateToken(accessToken, JWT)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while validating token", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	isAdmin, err := srv.uRepo.IsUserAdmin(usrID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	err = srv.uRepo.UpdateUser(usrID, &models.UserChInfo{
		ID:       usrID,
		Name:     name,
		Email:    email,
		IsAdmin:  isAdmin,
		Password: "",
	})

	if err := srv.cacheRepo.RemoveFromCache(usrID); err != nil {
		srv.log.Debug(context.Background(), "Failed to invalidate cache",
			zap.Error(err), zap.String("caller", op))
	}

	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while updating user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	userInfo, err := srv.uRepo.GetUserInfo(usrID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	return userInfo, nil
}

func (srv *AuthService) ChangePassword(oldPassword string, newPassword string, accessToken string) error {
	const op = "Auth.ChangePassword"

	userID, err := srv.ValidateToken(accessToken, JWT)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while validating token", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.uRepo.CheckUserCredentials(userID, oldPassword)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while checking user", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.uRepo.ChangePassword(newPassword, userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while changing password", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.CleanAllUsrSessions(userID)
	if err != nil {
		srv.log.Error(context.Background(), fmt.Sprintf("Error occurred while cleaning all usr's sessions: %s", err.Error()))
		return err
	}

	return nil
}

// need auth

func (srv *AuthService) Logout(refreshToken string) error {
	const op = "Auth.Logout"
	sessionID, err := srv.tkn.GetSessionIDFromRToken(refreshToken)
	if err != nil {
		srv.log.Error(context.Background(), "Failed to get session ID from refresh token", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.sessions.DeleteSession(sessionID)
	if err != nil {
		srv.log.Error(context.Background(), "Failed to delete session", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.blacklist.AddToBlacklist(sessionID)
	if err != nil {
		srv.log.Error(context.Background(), "Failed to add to blacklist", zap.Error(err), zap.String("caller", op))
	}
	return nil
}

//admin panel also with auth

func (srv *AuthService) CreateUser(usrInfo *models.UserCrInfo) (*models.UserInfo, error) {
	const op = "Auth.CreateUser"

	newUsrId, err := srv.uRepo.CreateUser(usrInfo)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while creating user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	usr, err := srv.uRepo.GetUser(newUsrId)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	return &models.UserInfo{
		ID:        usr.ID,
		Name:      usr.Name,
		Email:     usr.Email,
		IsAdmin:   usr.IsAdmin,
		CreatedAt: usr.CreatedAt,
	}, nil

}

func (srv *AuthService) GetUser(userID string) (*models.UserInfo, error) {
	const op = "Auth.GetUser"

	usrID, err := uuid.Parse(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while parsing uuid", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	cachedUser, err := srv.cacheRepo.Get(usrID)
	if err == nil && cachedUser != nil {
		return cachedUser, nil
	}

	usr, err := srv.uRepo.GetUser(usrID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	if err := srv.cacheRepo.AddToCache(usr.UserToInfo()); err != nil {
		srv.log.Debug(context.Background(), "Failed to cache user",
			zap.Error(err), zap.String("caller", op))
	}

	return &models.UserInfo{
		ID:        usr.ID,
		Name:      usr.Name,
		Email:     usr.Email,
		IsAdmin:   usr.IsAdmin,
		CreatedAt: usr.CreatedAt,
	}, nil
}

func (srv *AuthService) DeleteUser(userID string) error {
	const op = "Auth.DeleteUser"

	usrID, err := uuid.Parse(userID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while parsing uuid", zap.Error(err), zap.String("caller", op))
		return err
	}

	err = srv.uRepo.DeleteUser(usrID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while deleting user", zap.Error(err), zap.String("caller", op))
		return err
	}

	if err := srv.cacheRepo.RemoveFromCache(usrID); err != nil {
		srv.log.Debug(context.Background(), "Failed to invalidate cache",
			zap.Error(err), zap.String("caller", op))
	}

	return nil
}

func (srv *AuthService) ListUsers(page int, limit int) ([]*models.UserInfo, error) {
	const op = "Auth.ListUsers"

	users, err := srv.uRepo.ListUsers(page, limit)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while listing users", zap.Error(err), zap.String("caller", op))
		return nil, err
	}
	return users, nil
}

func (srv *AuthService) UpdateUser(newInfo *models.UserChInfo) (*models.UserInfo, error) {
	const op = "Auth.UpdateUser"

	err := srv.uRepo.UpdateUser(newInfo.ID, newInfo)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while updating user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	if err := srv.cacheRepo.RemoveFromCache(newInfo.ID); err != nil {
		srv.log.Debug(context.Background(), "Failed to invalidate cache",
			zap.Error(err), zap.String("caller", op))
	}

	userInfo, err := srv.uRepo.GetUser(newInfo.ID)
	if err != nil {
		srv.log.Error(context.Background(), "Error occurred while getting user", zap.Error(err), zap.String("caller", op))
		return nil, err
	}

	return &models.UserInfo{
		ID:        userInfo.ID,
		Name:      userInfo.Name,
		Email:     userInfo.Email,
		IsAdmin:   userInfo.IsAdmin,
		CreatedAt: userInfo.CreatedAt,
	}, nil

}
