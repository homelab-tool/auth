package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/homelab-tool/auth/internal"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true})

	log.Info().Msg("starting auth service")

	app, err := internal.CreateApp()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create app")
	}

	go func() {
		if err := app.Router.Start(":1337"); err != nil {
			log.Error().Err(err).Msg("server error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("shutting down")
	app.DB.Close()
}
