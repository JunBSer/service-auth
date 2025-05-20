package main

import (
	"github.com/JunBSer/service-auth/internal/app"
	"github.com/JunBSer/service-auth/internal/config"
)

func main() {
	cfg := config.MustLoad()
	app.Run(cfg)
}
