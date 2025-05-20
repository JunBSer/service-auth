package config

import (
	"flag"
	"github.com/JunBSer/service-auth/pkg/db/postgres"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
)

type (
	Config struct {
		DB     postgres.PGConfig
		App    App
		Logger Log
	}

	App struct {
		ServiceName string `env:"SERVICE_NAME" envDefault:"Unnamed_Service"`
		Version     string `env:"VERSION" envDefault:"1.0.0"`
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
