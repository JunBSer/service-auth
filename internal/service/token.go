package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"time"
)

const (
	JWT = iota
	RT
)

type TokenService interface {
	GenerateAT(userID uuid.UUID, sessionID uuid.UUID, isAdmin bool) (string, error)
	GenerateRT(userID uuid.UUID, sessionID uuid.UUID) (string, error)

	ValidateJWToken(token string) (uuid.UUID, uuid.UUID, error)
	ValidateRToken(token string) (uuid.UUID, uuid.UUID, error)

	GetSessionIDFromRToken(refreshToken string) (uuid.UUID, error)
}

type TokenServ struct {
	log               logger.Logger
	jwtValidationTime time.Duration
	rtValidationTime  time.Duration
	secret            []byte
}

type jwtCustomClaims struct {
	UserID    string `json:"sub"`
	SessionID string `json:"jti"`
	IsAdmin   bool   `json:"isAdmin"`
	jwt.StandardClaims
}

type rtCustomClaims struct {
	UserID    string `json:"sub"`
	SessionID string `json:"jti"`
	jwt.StandardClaims
}

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenNotValidYet = errors.New("token not active yet")
)

func NewTokenService(log logger.Logger, secret string, jwtValid, rtValid time.Duration) *TokenServ {
	return &TokenServ{
		log:               log,
		secret:            []byte(secret),
		jwtValidationTime: jwtValid,
		rtValidationTime:  rtValid,
	}
}

func (srv *TokenServ) GenerateAT(userID uuid.UUID, sessionID uuid.UUID, isAdmin bool) (string, error) {
	const op = "TokenServ.GenerateAT"

	claims := &jwtCustomClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		IsAdmin:   isAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(srv.jwtValidationTime).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "auth-service",
		},
	}

	aTkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := aTkn.SignedString(srv.secret)
	if err != nil {
		srv.log.Error(context.Background(), "Error signing token", zap.Error(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (srv *TokenServ) GenerateRT(userID uuid.UUID, sessionID uuid.UUID) (string, error) {
	const op = "TokenServ.GenerateRT"

	claims := &rtCustomClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(srv.rtValidationTime).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "auth-service",
		},
	}

	rTkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := rTkn.SignedString(srv.secret)
	if err != nil {
		srv.log.Error(context.Background(), "Error signing token", zap.Error(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil

}

func (srv *TokenServ) validateToken(tokenStr string, claims jwt.Claims) (*jwt.Token, error) {
	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("invalid algorithm")
		}
		return srv.secret, nil
	})

	if err != nil {
		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				srv.log.Error(context.Background(), "malformed token", zap.Error(err))
				return nil, ErrInvalidToken
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				return nil, ErrTokenExpired
			case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
				return nil, ErrTokenNotValidYet
			default:
				srv.log.Error(context.Background(), "token validation error", zap.Error(err))
				return nil, ErrInvalidToken
			}
		}
		return nil, err
	}

	if tkn == nil || !tkn.Valid {
		return nil, ErrInvalidToken
	}

	if tkn.Method.Alg() != jwt.SigningMethodHS256.Alg() {
		return nil, fmt.Errorf("unexpected signing method: %s", tkn.Header["alg"])
	}

	return tkn, nil
}

func (srv *TokenServ) ValidateJWToken(token string) (uuid.UUID, uuid.UUID, error) {
	const op = "TokenServ.ValidateJWTToken"

	jwtClaims := &jwtCustomClaims{}

	_, err := srv.validateToken(token, jwtClaims)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	if jwtClaims.Issuer != "auth-service" {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	userID, err := uuid.Parse(jwtClaims.UserID)
	if err != nil {
		srv.log.Error(context.Background(), "invalid user ID format",
			zap.String("op", op),
			zap.Error(err))
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidToken, err)
	}

	sessionID, err := uuid.Parse(jwtClaims.SessionID)
	if err != nil {
		srv.log.Error(context.Background(), "invalid session ID format",
			zap.String("op", op),
			zap.Error(err))
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidToken, err)
	}

	return userID, sessionID, nil
}

func (srv *TokenServ) ValidateRToken(token string) (uuid.UUID, uuid.UUID, error) {
	const op = "TokenServ.ValidateRTToken"

	rtClaims := &rtCustomClaims{}

	_, err := srv.validateToken(token, rtClaims)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	if rtClaims.Issuer != "auth-service" {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	userID, err := uuid.Parse(rtClaims.UserID)
	if err != nil {
		srv.log.Error(context.Background(), "invalid user ID format",
			zap.String("op", op),
			zap.Error(err))
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidToken, err)
	}

	sessionID, err := uuid.Parse(rtClaims.SessionID)
	if err != nil {
		srv.log.Error(context.Background(), "invalid session ID format",
			zap.String("op", op),
			zap.Error(err))
		return uuid.Nil, uuid.Nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidToken, err)
	}

	return userID, sessionID, nil
}

func (srv *TokenServ) GetSessionIDFromRToken(token string) (uuid.UUID, error) {
	const op = "TokenServ.GetSessionIDFromToken"

	rtClaims := &rtCustomClaims{}

	_, err := srv.validateToken(token, rtClaims)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	if rtClaims.Issuer != "auth-service" {
		return uuid.Nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	sessionID, err := uuid.Parse(rtClaims.SessionID)
	if err != nil {
		srv.log.Error(context.Background(), "invalid session ID format",
			zap.String("op", op),
			zap.Error(err))
		return uuid.Nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidToken, err)
	}

	return sessionID, nil
}
