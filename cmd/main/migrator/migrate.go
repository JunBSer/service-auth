package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/ilyakaznacheev/cleanenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type DbConfig struct {
	Host     string `env:"POSTGRES_HOST" env-required:"true"`
	User     string `env:"POSTGRES_USER" env-required:"true"`
	Password string `env:"POSTGRES_PASSWORD" env-required:"true"`
	Name     string `env:"POSTGRES_DB" env-required:"true"`
	Port     string `env:"POSTGRES_PORT" env-required:"true"`
	SSLMode  string `env:"POSTGRES_SSL_MODE" env-default:"disable"`
}

type AdminConfig struct {
	Name     string `env:"ADMIN_NAME" env-required:"true"`
	Email    string `env:"ADMIN_EMAIL" env-required:"true"`
	Password string `env:"ADMIN_PASSWORD" env-required:"true"`
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to config file (env format)")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	if configPath == "" {
		panic("Missing CONFIG_PATH")
	}

	var dbCfg DbConfig
	var adminCfg AdminConfig

	if err := cleanenv.ReadEnv(&dbCfg); err != nil {
		log.Fatalf("Error reading db config: %v", err)
	}
	if err := cleanenv.ReadEnv(&adminCfg); err != nil {
		log.Fatalf("Error reading admin config: %v", err)
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(adminCfg.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error while hashing admin password: %v", err)
	}

	adminID := uuid.New()

	dsn := fmt.Sprintf(
		"user=%s password=%s host=%s dbname=%s port=%s sslmode=%s",
		dbCfg.User, dbCfg.Password, dbCfg.Host, dbCfg.Name, dbCfg.Port, dbCfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Error while connection to db: %v", err)
	}
	defer db.Close()

	migrationDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		dbCfg.User, dbCfg.Password, dbCfg.Host, dbCfg.Port, dbCfg.Name, dbCfg.SSLMode,
	)
	m, err := migrate.New(
		"file://migrations",
		migrationDSN,
	)
	if err != nil {
		log.Fatalf("Error to create migrations: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("Error to apply migrations: %v", err)
	}

	query := `
		INSERT INTO users (id, name, email, pass_hash, is_admin, created_at)
		VALUES ($1, $2, $3, $4, TRUE, NOW())
		ON CONFLICT (email) DO NOTHING;
	`
	res, err := db.ExecContext(context.Background(), query,
		adminID, adminCfg.Name, adminCfg.Email, passHash,
	)
	if err != nil {
		log.Fatalf("Error while executing db query: %v", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		log.Fatalf("Error in aprooving query: %v", err)
	}

	if rows == 0 {
		log.Println("There is already admin with such parameters")
	} else {
		log.Println("Administrator created successfully!")
	}
}
