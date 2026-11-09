//go:build windows

package wxkey

import (
	"crypto/aes"
	"encoding/binary"
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

func TestImageFormatRejectsMalformedBMHeader(t *testing.T) {
	malformed := []byte{'B', 'M', 0x14, 0x45, 0x00, 0x00, 0, 0, 0, 0, 0x36, 0, 0, 0, 0x14, 0}
	if got := imageFormat(malformed); got != "" {
		t.Fatalf("malformed BMP header detected as %q", got)
	}

	valid := make([]byte, aes.BlockSize)
	valid[0], valid[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(valid[2:6], 54)
	binary.LittleEndian.PutUint32(valid[10:14], 54)
	binary.LittleEndian.PutUint16(valid[14:16], 40)
	if got := imageFormat(valid); got != "bmp" {
		t.Fatalf("valid BMP header detected as %q", got)
	}
}

func TestScanImageCandidatesContinuesAfterFalseCandidate(t *testing.T) {
	goodKey := []byte("0123456789abcdef")
	falseKey := []byte("fedcba9876543210")
	plain := [aes.BlockSize]byte{0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	cipher, err := aes.NewCipher(goodKey)
	if err != nil {
		t.Fatal(err)
	}
	template := make([]byte, aes.BlockSize)
	cipher.Encrypt(template, plain[:])
	if verifyImageKey([16]byte(falseKey), [][]byte{template}) {
		t.Fatal("false candidate unexpectedly passed image validation")
	}
	buf := append([]byte("prefix "), falseKey...)
	buf = append(buf, '!')
	buf = append(buf, goodKey...)
	buf = append(buf, []byte(" suffix")...)
	got, candidates, ok := scanImageCandidates(buf, [][]byte{template}, map[[16]byte]bool{})
	if !ok || string(got[:]) != string(goodKey) || candidates != 2 {
		t.Fatalf("scan result = key %q candidates %d ok %v, want good key after false candidate", got, candidates, ok)
	}
}

func TestRunImageKeyMissingTemplateGuidesDesktopImageLoad(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "msg", "attach"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := runImageKey(root)
	if err == nil || !strings.Contains(err.Error(), "open an image in the desktop client") {
		t.Fatalf("missing-template error = %v, want desktop image loading guidance", err)
	}
}
