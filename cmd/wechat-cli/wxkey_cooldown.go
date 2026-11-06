package main

import (
	"os"
	"path/filepath"
	"time"
)

// Every CLI invocation is a new process, so an in-memory retry interval never
// stops a failing automatic wxkey run from costing seconds on each read. A
// failure stamp in the state directory carries the cooldown across processes.
const wxkeyFailureCooldown = 10 * time.Minute

func wxkeyFailureStamp(kind string) string {
	dir, err := appStateDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "wxkey-"+kind+"-failed")
}

// wxkeyCoolingDown reports whether an automatic wxkey run of this kind failed
// recently, and when the cooldown ends.
func wxkeyCoolingDown(kind string) (time.Time, bool) {
	path := wxkeyFailureStamp(kind)
	if path == "" {
		return time.Time{}, false
	}
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	until := st.ModTime().Add(wxkeyFailureCooldown)
	return until, time.Now().Before(until)
}

func markWxkeyFailed(kind string) {
	path := wxkeyFailureStamp(kind)
	if path == "" || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, nil, 0o600)
	now := time.Now()
	_ = os.Chtimes(path, now, now)
}

func clearWxkeyFailed(kind string) {
	if path := wxkeyFailureStamp(kind); path != "" {
		_ = os.Remove(path)
	}
}
