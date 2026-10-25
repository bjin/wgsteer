// Command wgsteer keeps one WireGuard client peer on the best of
// several equivalent UDP endpoints.
//
// Exit codes: 0 clean stop (SIGTERM/SIGINT) or -help, 1 invalid flags or a
// startup failure, 3 event-loop watchdog.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/bjin/wgsteer/internal/daemon"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := daemon.ParseFlags(os.Args[1:], daemon.DefaultConfig(), os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wgsteer:", err)
		return 1
	}
	logging := daemon.NewLogging(os.Stderr, cfg.LogLevel)
	if err := daemon.Run(cfg, logging); err != nil {
		return 1
	}
	return 0
}
