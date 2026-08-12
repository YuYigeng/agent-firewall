package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/YuYigeng/agent-firewall/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	app := &cli.App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(app.Run(ctx, os.Args[1:]))
}
