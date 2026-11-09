//go:build windows

package wxkey

import (
	"crypto/aes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyImageKeyAgainstJPEGTemplate(t *testing.T) {
	var key [16]byte
	copy(key[:], "0123456789abcdef")
	plain := [aes.BlockSize]byte{0xff, 0xd8, 0xff, 0xe0, 0x11, 0x22, 0x33, 0x44}
	for i := 8; i < len(plain); i++ {
		plain[i] = byte(i)
	}
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	template := make([]byte, aes.BlockSize)
	cipher.Encrypt(template, plain[:])
	if !verifyImageKey(key, [][]byte{template}) {
		t.Fatal("synthetic JPEG template was not accepted")
	}
	var wrong [16]byte
	copy(wrong[:], "fedcba9876543210")
	if verifyImageKey(wrong, [][]byte{template}) {
		t.Fatal("wrong image key was accepted")
	}
}

func TestScanImageCandidatesAcceptsBoundedASCIIKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	buf := append([]byte("prefix "), key...)
	buf = append(buf, []byte(" suffix")...)
	plain := [aes.BlockSize]byte{0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	template := make([]byte, aes.BlockSize)
	cipher.Encrypt(template, plain[:])
	got, candidates, ok := scanImageCandidates(buf, [][]byte{template}, map[[16]byte]bool{})
	if !ok || string(got[:]) != string(key) || candidates != 1 {
		t.Fatalf("scan result = key %q candidates %d ok %v", got, candidates, ok)
	}
}

func TestRunImageKeyMissingTemplateGuidesViewOriginal(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "msg", "attach"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := runImageKey(root)
	if err == nil || !strings.Contains(err.Error(), "查看原图") {
		t.Fatalf("missing-template error = %v, want View Original guidance", err)
	}
}
