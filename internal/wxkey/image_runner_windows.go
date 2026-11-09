//go:build windows

package wxkey

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const (
	imageV2HeaderLen   = 6
	imageV2DataOffset  = 15
	imageV2TemplateLen = 16
	imageScanChunkSize = 2 << 20
	imageScanMaxRegion = 50 << 20
	imagePageReadWrite = 0x04
	imagePageWriteCopy = 0x08
	imagePageExecRW    = 0x40
	imagePageExecWC    = 0x80
	imagePageNoCache   = 0x200
	imagePageWriteComb = 0x400
)

var imageV2Header = [...]byte{0x07, 0x08, 'V', '2', 0x08, 0x07}

// runImageKey implements the Windows image-key path in-process. The key is
// intentionally returned only to the caller and is never printed by this
// package; the caller persists it through the existing protected config path.
func runImageKey(root string) (*ImageKeyResult, string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, "", errors.New("Windows image-key scan requires a WeChat account root")
	}
	attachDir := filepath.Join(root, "msg", "attach")
	templates, err := imageV2Templates(attachDir)
	if err != nil {
		return nil, "", err
	}
	if len(templates) == 0 {
		return nil, "", fmt.Errorf("no WeChat V4 image templates found under %s; keep Windows WeChat logged in, open an image in the desktop client and wait for it to finish loading; if the client offers an original/download/save action, use it once, then retry", attachDir)
	}

	// Keep Toolhelp's process enumeration order for image scanning. Windows
	// usually reports the main Weixin.exe before its renderer/utility children;
	// image keys can disappear before a full multi-process scan completes.
	procs, err := windowsImageTargetProcesses()
	if err != nil {
		return nil, "", err
	}
	if len(procs) == 0 {
		return nil, "", errors.New("no running Weixin.exe/WeChat.exe process found; keep Windows WeChat logged in, open an image in the desktop client and wait for it to finish loading; if the client offers an original/download/save action, use it once, then retry")
	}

	deadline := time.Now().Add(imageScanTimeout())
	var totalRegions int
	var totalBytes uint64
	var totalCandidates int
	var lastErr error
	for _, proc := range procs {
		key, regions, bytesScanned, candidates, err := scanImageProcess(proc.pid, templates, deadline)
		totalRegions += regions
		totalBytes += bytesScanned
		totalCandidates += candidates
		if err != nil {
			lastErr = err
			continue
		}
		return &ImageKeyResult{
			Key:            string(key[:]),
			TemplateFile:   attachDir,
			TemplateSource: "local_v4_dat",
			Regions:        regions,
			BytesScanned:   bytesScanned,
			Candidates:     candidates,
		}, fmt.Sprintf("Windows image-key scan OK: verified image key from PID %d\n", proc.pid), nil
	}
	return nil, "", fmt.Errorf("Windows WeChat process memory did not contain a verifiable V4 image key (templates=%d regions=%d bytes=%d candidates=%d: %v)", len(templates), totalRegions, totalBytes, totalCandidates, lastErr)
}

func windowsImageTargetProcesses() ([]windowsProcess, error) {
	if raw := firstEnv("WECHAT_CLI_WECHAT_PID", "WX_MCP_WECHAT_PID"); raw != "" {
		var out []windowsProcess
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			if part == "" {
				continue
			}
			pid, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parse WECHAT_CLI_WECHAT_PID=%q: %w", raw, err)
			}
			out = append(out, windowsProcess{pid: uint32(pid), exe: "env"})
		}
		return out, nil
	}
	names := map[string]bool{"weixin.exe": true, "wechat.exe": true}
	if raw := firstEnv("WECHAT_CLI_WECHAT_PROCESS", "WX_MCP_WECHAT_PROCESS"); raw != "" {
		names = map[string]bool{}
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			if !strings.HasSuffix(part, ".exe") {
				part += ".exe"
			}
			names[part] = true
		}
	}
	all, err := windowsEnumerateProcesses()
	if err != nil {
		return nil, err
	}
	currentPID := windowsCurrentPID()
	var out []windowsProcess
	for _, p := range all {
		if p.pid != currentPID && names[strings.ToLower(p.exe)] {
			out = append(out, p)
		}
	}
	return out, nil
}

func imageScanTimeout() time.Duration {
	for _, name := range []string{"WECHAT_CLI_IMAGE_KEY_SCAN_TIMEOUT", "WX_MCP_IMAGE_KEY_SCAN_TIMEOUT"} {
		if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
				return d
			}
		}
	}
	return 30 * time.Second
}

func imageV2Templates(attachDir string) ([][]byte, error) {
	return imageV2TemplatesWithSuffix(attachDir, "_t.dat")
}

func imageV2TemplatesWithSuffix(attachDir, suffix string) ([][]byte, error) {
	if _, err := os.Stat(attachDir); err != nil {
		return nil, fmt.Errorf("inspect image attachment directory %s: %w", attachDir, err)
	}
	var templates [][]byte
	seen := map[string]bool{}
	examined := 0
	err := filepath.WalkDir(attachDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, suffix) {
			return nil
		}
		examined++
		data, err := os.ReadFile(path)
		if err != nil || len(data) < imageV2DataOffset+imageV2TemplateLen || !bytes.Equal(data[:imageV2HeaderLen], imageV2Header[:]) {
			if examined >= 64 && len(templates) > 0 {
				return filepath.SkipAll
			}
			return nil
		}
		template := append([]byte(nil), data[imageV2DataOffset:imageV2DataOffset+imageV2TemplateLen]...)
		id := hex.EncodeToString(template)
		if !seen[id] {
			seen[id] = true
			templates = append(templates, template)
		}
		if len(templates) >= 3 || (examined >= 64 && len(templates) > 0) {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 && suffix == "_t.dat" {
		return imageV2TemplatesWithSuffix(attachDir, ".dat")
	}
	return templates, nil
}

func scanImageProcess(pid uint32, templates [][]byte, deadline time.Time) ([16]byte, int, uint64, int, error) {
	var zero [16]byte
	h, _, err := procOpenProcess.Call(processVMRead|processQueryInformation, 0, uintptr(pid))
	if h == 0 {
		return zero, 0, 0, 0, err
	}
	defer procCloseHandle.Call(h)
	var regions int
	var bytesScanned uint64
	var candidates int
	const maxUserAddress = uintptr(0x00007fffffffffff)
	for addr := uintptr(0); addr < maxUserAddress; {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return zero, regions, bytesScanned, candidates, errWindowsKeyScanDeadline
		}
		var info windowsMemoryBasicInformation
		r, _, _ := procVirtualQueryEx.Call(h, addr, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		if r == 0 {
			addr += 0x10000
			continue
		}
		next := info.BaseAddress + info.RegionSize
		if next <= addr {
			break
		}
		if imageReadableRegion(info) && info.RegionSize <= imageScanMaxRegion {
			regions++
			key, scanned, found, ok, scanErr := scanImageRegion(h, info.BaseAddress, info.RegionSize, templates, deadline)
			bytesScanned += scanned
			candidates += found
			if scanErr != nil {
				return zero, regions, bytesScanned, candidates, scanErr
			}
			if ok {
				return key, regions, bytesScanned, candidates, nil
			}
		}
		addr = next
	}
	return zero, regions, bytesScanned, candidates, errors.New("no verifiable image key")
}

func scanImageRegion(process uintptr, base, size uintptr, templates [][]byte, deadline time.Time) ([16]byte, uint64, int, bool, error) {
	var zero [16]byte
	seen := map[[16]byte]bool{}
	var scanned uint64
	var candidates int
	const overlap = 31
	for offset := uintptr(0); offset < size; {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return zero, scanned, candidates, false, errWindowsKeyScanDeadline
		}
		chunk := imageScanChunkSize
		if remain := size - offset; remain < uintptr(chunk) {
			chunk = int(remain)
		}
		buf := make([]byte, chunk)
		var got uintptr
		r, _, _ := procReadProcessMemory.Call(process, base+offset, uintptr(unsafe.Pointer(&buf[0])), uintptr(chunk), uintptr(unsafe.Pointer(&got)))
		if r != 0 && got > 0 {
			buf = buf[:got]
			scanned += uint64(got)
			if key, found, ok := scanImageCandidates(buf, templates, seen); ok {
				return key, scanned, candidates + found, true, nil
			} else {
				candidates += found
			}
		}
		if chunk <= overlap {
			break
		}
		offset += uintptr(chunk - overlap)
	}
	return zero, scanned, candidates, false, nil
}

func scanImageCandidates(buf []byte, templates [][]byte, seen map[[16]byte]bool) ([16]byte, int, bool) {
	var zero [16]byte
	found := 0
	for _, n := range []int{32, 16} {
		for start := 0; start+n <= len(buf); start++ {
			if (start > 0 && isASCIIAlphaNumeric(buf[start-1])) || (start+n < len(buf) && isASCIIAlphaNumeric(buf[start+n])) {
				continue
			}
			if !allASCIIAlphaNumeric(buf[start : start+n]) {
				continue
			}
			var key [16]byte
			copy(key[:], buf[start:start+16])
			if seen[key] {
				continue
			}
			seen[key] = true
			found++
			if verifyImageKey(key, templates) {
				return key, found, true
			}
		}
	}
	return zero, found, false
}

func verifyImageKey(key [16]byte, templates [][]byte) bool {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		return false
	}
	for _, template := range templates {
		if len(template) != aes.BlockSize {
			return false
		}
		var plain [aes.BlockSize]byte
		cipher.Decrypt(plain[:], template)
		if imageFormat(plain[:]) == "" {
			return false
		}
	}
	return true
}

func imageFormat(data []byte) string {
	switch {
	case len(data) >= 4 && string(data[:4]) == "wxgf":
		// WeChat's HEVC image container (used by some original images).
		return "hevc"
	case validJPEGHeader(data):
		return "jpg"
	case validPNGHeader(data):
		return "png"
	case validGIFHeader(data):
		return "gif"
	case validBMPHeader(data):
		return "bmp"
	case validWEBPHeader(data):
		return "webp"
	case validTIFFHeader(data):
		return "tif"
	default:
		return ""
	}
}

// The scanner only decrypts one AES block from each V2 attachment. Validate
// enough of each format's fixed header to reject random magic-byte collisions
// without requiring a full image decode during process-memory scanning.
func validJPEGHeader(data []byte) bool {
	return len(data) >= 4 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff && data[3] != 0x00 && data[3] != 0xff
}

func validPNGHeader(data []byte) bool {
	return len(data) >= 16 && string(data[:8]) == "\x89PNG\r\n\x1a\n" && binary.BigEndian.Uint32(data[8:12]) == 13 && string(data[12:16]) == "IHDR"
}

func validGIFHeader(data []byte) bool {
	if len(data) < 10 || (string(data[:6]) != "GIF87a" && string(data[:6]) != "GIF89a") {
		return false
	}
	return binary.LittleEndian.Uint16(data[6:8]) > 0 && binary.LittleEndian.Uint16(data[8:10]) > 0
}

func validBMPHeader(data []byte) bool {
	if len(data) < 16 || string(data[:2]) != "BM" {
		return false
	}
	fileSize := binary.LittleEndian.Uint32(data[2:6])
	pixelOffset := binary.LittleEndian.Uint32(data[10:14])
	dibSize := binary.LittleEndian.Uint16(data[14:16])
	if fileSize < 26 || pixelOffset < 26 || pixelOffset > fileSize {
		return false
	}
	switch dibSize {
	case 12, 40, 52, 56, 108, 124:
		return true
	default:
		return false
	}
}

func validWEBPHeader(data []byte) bool {
	return len(data) >= 12 && string(data[:4]) == "RIFF" && binary.LittleEndian.Uint32(data[4:8]) >= 4 && string(data[8:12]) == "WEBP"
}

func validTIFFHeader(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	switch {
	case data[0] == 'I' && data[1] == 'I' && binary.LittleEndian.Uint16(data[2:4]) == 42:
		return binary.LittleEndian.Uint32(data[4:8]) >= 8 && binary.LittleEndian.Uint32(data[4:8])%2 == 0
	case data[0] == 'M' && data[1] == 'M' && binary.BigEndian.Uint16(data[2:4]) == 42:
		return binary.BigEndian.Uint32(data[4:8]) >= 8 && binary.BigEndian.Uint32(data[4:8])%2 == 0
	default:
		return false
	}
}

func imageReadableRegion(info windowsMemoryBasicInformation) bool {
	if info.State != memCommit || info.RegionSize == 0 || info.Protect&pageNoAccess != 0 || info.Protect&pageGuard != 0 {
		return false
	}
	base := info.Protect &^ (imagePageNoCache | imagePageWriteComb | pageGuard)
	return base == imagePageReadWrite || base == imagePageWriteCopy || base == imagePageExecRW || base == imagePageExecWC
}

func allASCIIAlphaNumeric(data []byte) bool {
	for _, c := range data {
		if !isASCIIAlphaNumeric(c) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
