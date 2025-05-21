package postgres

import (
	"context"
	"fmt"
	"github.com/JunBSer/service-auth/pkg/logger"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

type PGConfig struct {
	Port     string `env:"POSTGRES_PORT" envDefault:"5432"`
	Host     string `env:"POSTGRES_HOST" envDefault:"localhost"`
	User     string `env:"POSTGRES_USER" envDefault:"postgres"`
	Password string `env:"POSTGRES_PASSWORD" envDefault:"postgres"`
	DB       string `env:"POSTGRES_DB" envDefault:"postgres"`
}

type DB struct {
	Db *sqlx.DB
}

func New(config PGConfig, log *logger.Logger) (*DB, error) {
	const op = "Postgres.New"
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable host=%s port=%s", config.User, config.Password, config.DB, config.Host, config.Port)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		(*log).Error(context.Background(), fmt.Sprintf("Error connecting to database: %v", err), zap.String("caller", op))
	}

	if _, err := db.Conn(context.Background()); err != nil {
		(*log).Error(context.Background(), fmt.Sprintf("Error connecting to connect: %v", err), zap.String("caller", op))
	}

	return &DB{Db: db}, nil
}

func (db *DB) CloseDB() error {
	return db.Db.Close()
}
