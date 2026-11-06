package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r266-tech/wx-cli/v2/internal/config"
	"github.com/r266-tech/wx-cli/v2/internal/wxkey"
)

// Each CLI call is a fresh process; a failing automatic wxkey run must not be
// retried by the next process until the cooldown passes.
func TestFailedWxkeySetupCoolsDownAcrossProcesses(t *testing.T) {
	t.Setenv("WECHAT_CLI_STATE_DIR", t.TempDir())
	t.Setenv("WECHAT_CLI_STRICT_READ_ONLY", "0")
	old := runWxkeySetup
	t.Cleanup(func() { runWxkeySetup = old })
	calls := 0
	runWxkeySetup = func() (*wxkey.SetupResult, string, error) {
		calls++
		return nil, "denied", errors.New("wxkey setup failed: task_for_pid denied")
	}
	if !wxkey.SetupSupported() {
		t.Skip("automatic wxkey setup is not supported on this platform")
	}
	for i := 0; i < 2; i++ {
		s := &server{cfg: &config.Config{}}
		err := s.refreshKeysFromWxkey("no enc_key for salt abc")
		if err == nil {
			t.Fatal("refresh unexpectedly succeeded")
		}
		if i == 1 && !strings.Contains(err.Error(), "failed recently") {
			t.Fatalf("second process did not report the cooldown: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("wxkey ran %d times across two processes, want 1", calls)
	}
}

func TestDBFilesMissingKeysNamesUnreadableDatabases(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, salt byte) {
		path := filepath.Join(root, "db_storage", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(bytes.Repeat([]byte{salt}, 16), 0, 0), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("session/session.db", 1)
	write("message/message_resource.db", 2)
	write("message/message_0.db.factory/old/message_0.db", 3)
	cfg := &config.Config{DBRoot: root, Keys: map[string]string{hex.EncodeToString(bytes.Repeat([]byte{1}, 16)): "k"}}
	got := dbFilesMissingKeys(cfg)
	if len(got) != 1 || got[0] != "message/message_resource.db" {
		t.Fatalf("missing keys = %#v, want only message/message_resource.db", got)
	}
}
