package logutil

import (
	"context"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/samber/mo"
)

var _, Lg = InitLogger(context.Background(), LoggerOptions{})

type LoggerOptions struct {
	Level  mo.Option[zerolog.Level]
	Format mo.Option[string]
	Color  mo.Option[string]
}

func InitGlobalLogger(
	ctx context.Context,
	opts LoggerOptions,
) context.Context {
	logLvl := opts.Level.OrElse(zerolog.FatalLevel)
	zerolog.SetGlobalLevel(logLvl)
	opts.Level = mo.Some(logLvl)
	ctx, lg := InitLogger(ctx, opts)
	log.Logger = lg
	return ctx
}

func InitLogger(
	ctx context.Context,
	opts LoggerOptions,
) (context.Context, zerolog.Logger) {
	// zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	lg := zerolog.New(os.Stderr).With().
		Timestamp().
		Stack().
		Caller().
		Logger()
	lg.Level(opts.Level.OrElse(zerolog.FatalLevel))

	doConsole := false
	logFmt := opts.Format.OrElse("auto")
	out := os.Stderr
	isTerm := isatty.IsTerminal(out.Fd())
	switch strings.TrimSpace(strings.ToLower(logFmt)) {
	case "", "auto":
		doConsole = isTerm
	case "console":
		doConsole = true
	default:
		lg.Fatal().Msgf("unknown log format: %q", logFmt)

	}

	if doConsole {
		doColor := false
		switch strings.ToLower(opts.Color.OrElse("auto")) {
		case "", "auto":
			doColor = isTerm
		case "always":
			doColor = true
		case "never":
			doColor = false
		}
		lg = lg.Output(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = out
			w.NoColor = !doColor
		}))
	}

	return lg.WithContext(ctx), lg
}
