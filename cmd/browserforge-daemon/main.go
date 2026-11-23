package main

import (
	"fmt"
	"os"
	"strings"

	"browserforge/internal/daemon"
	"browserforge/internal/proxyfwd"
	"browserforge/internal/store"
)

// browserforge-daemon is a silent (-H=windowsgui) foreground host process with a native
// Windows system tray icon and minimalist local status panel.
func main() {
	if len(os.Args) >= 2 && os.Args[1] == "_forwarder" {
		if err := proxyfwd.RunSubprocess(); err != nil {
			fmt.Fprintln(os.Stderr, "forwarder error:", err)
			os.Exit(1)
		}
		return
	}

	dataDir := ""
	noTray := false
	quiet := false
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--data-dir" && i+1 < len(os.Args):
			dataDir = os.Args[i+1]
			i++
		case strings.HasPrefix(os.Args[i], "--data-dir="):
			dataDir = strings.TrimPrefix(os.Args[i], "--data-dir=")
		case os.Args[i] == "--no-tray":
			noTray = true
		case os.Args[i] == "--quiet":
			quiet = true
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		os.Exit(1)
	}
	if existing, err := daemon.Probe(st.DataDir); err == nil && existing != nil {
		if !quiet && !noTray {
			showAlreadyRunningDialog(existing.PID, existing.Port)
		}
		os.Exit(0)
	}

	srv, err := daemon.NewServer(st)
	if err != nil {
		os.Exit(1)
	}

	if noTray {
		if err := srv.Serve(); err != nil {
			os.Exit(1)
		}
		return
	}

	go func() {
		_ = srv.Serve()
	}()
	runTray(srv, st.DataDir)
	_ = srv.Close()
}
