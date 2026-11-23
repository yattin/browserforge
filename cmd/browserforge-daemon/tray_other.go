//go:build !windows

package main

import "browserforge/internal/daemon"

func runTray(srv *daemon.Server, _ string) {
	<-srv.Done()
}

func showAlreadyRunningDialog(_, _ int) {}
