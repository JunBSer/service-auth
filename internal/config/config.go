package config

import (
	"flag"
	"github.com/JunBSer/service-auth/internal/transport/grpc"
	"github.com/JunBSer/service-auth/pkg/db/postgres"
	"github.com/JunBSer/service-auth/pkg/db/redis"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"time"
)

type (
	Config struct {
		DB      postgres.PGConfig
		App     App
		Logger  Log
		Redis   redis.Config
		Token   TokenConfig
		Session SessionConfig
		Admin   AdminConfig
		GRPC    grpc.Config
	}

	TokenConfig struct {
		AccessTokenExpireTime  time.Duration `env:"ACCESS_TOKEN_EXPIRE"`
		RefreshTokenExpireTime time.Duration `env:"REFRESH_TOKEN_EXPIRE"`
	}

	SessionConfig struct {
		MaxLifetime   time.Duration `env:"SESSION_DURATION"`
		MaxSessionCnt int           `env:"MAX_SESSION_CNT"`
	}

	App struct {
		ServiceName string        `env:"SERVICE_NAME" envDefault:"Unnamed_Service"`
		Version     string        `env:"VERSION" envDefault:"1.0.0"`
		Secret      string        `env:"SECRET_KEY"`
		CacheExpire time.Duration `env:"CACHE_EXPIRE"`
	}

	AdminConfig struct {
		AdminName   string `env:"ADMIN_NAME"`
		AdminEmail  string `env:"ADMIN_EMAIL"`
		AdminPasswd string `env:"ADMIN_PASSWORD"`
	}

	Log struct {
		LogLvl string `env:"LOGGER_LEVEL" envDefault:"info"`
	}
)

func MustLoad() *Config {
	configPath := fetchConfigPath()
	if configPath == "" {
		panic("config file path is empty")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("config path is empty: " + err.Error())
	}

	return &cfg
}

func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
