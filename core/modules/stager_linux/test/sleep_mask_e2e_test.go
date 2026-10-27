//go:build linux && cgo

package shellcode_stager

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCAgentSleepMask runs a locally embedded C agent through stager_linux,
// lets its first check-in fail so it enters the sleep mask, and inspects the
// stopped-looking process from the test: the agent ELF must be gone from
// memory while the mask runs, then restored and functional enough to check in.
func TestCAgentSleepMask(t *testing.T) {
	requireCAgentE2E(t)

	tmpDir, err := os.MkdirTemp("", "c_agent_mask_e2e_*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set up C2 config/certs but deliberately do not start the servers yet.
	httpPort := setupCAgentWorkspace(t, tmpDir)
	res := buildCAgentResult(t, tmpDir, "shellcode", true)
	agentArgv := buildLocalStager(t, tmpDir, res.OutputFile, "raw")

	var out bytes.Buffer
	cmd := exec.Command(agentArgv[0], agentArgv[1:]...)
	cmd.Env = append(os.Environ(), "HOME="+tmpDir)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stager: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	doneChan := make(chan error, 1)
	go func() { doneChan <- cmd.Wait() }()

	pid := cmd.Process.Pid
	marker := []byte("unsupported command\n")

	// Wait until the agent's anonymous ELF copies are mapped and then all
	// disappear behind the first failed check-in's sleep mask. Malasada can
	// leave more than one anonymous ELF copy (the mapped segments and its
	// decompressed SO buffer), so every one must be masked.
	var originals map[uint64][]byte
	masked := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if len(originals) == 0 {
			if has, _ := procMemContains(pid, marker, true); has {
				bases := findAnonymousELFs(pid)
				if len(bases) > 0 {
					originals = make(map[uint64][]byte, len(bases))
					for _, b := range bases {
						page := make([]byte, 4096)
						if err := readProcMem(pid, b, page); err == nil {
							originals[b] = page
						}
					}
				}
			}
		}
		if len(originals) > 0 {
			masked = true
			for b, original := range originals {
				cur := make([]byte, len(original))
				if err := readProcMem(pid, b, cur); err != nil || bytes.Equal(cur, original) {
					masked = false
					break
				}
			}
			if masked {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(originals) == 0 {
		t.Fatalf("agent ELF copies never appeared in the stager process.\nOutput:\n%s", out.String())
	}
	if !masked {
		t.Fatalf("agent image was never masked.\nOutput:\n%s", out.String())
	}

	// While masked, no agent plaintext string and no anonymous agent ELF may
	// remain. The stager mask stub itself lives in a different mapping.
	if has, err := procMemContains(pid, marker, true); err != nil {
		t.Fatalf("scan masked process: %v", err)
	} else if has {
		t.Fatalf("agent plaintext marker still present while masked")
	}
	if bases := findAnonymousELFs(pid); len(bases) > 0 {
		t.Fatalf("anonymous ELFs are still visible while masked: %#x", bases)
	}

	// Let the masked sleep finish. Start the C2 now: the next retry must see a
	// restored image and check in, which also proves the XOR was reversible.
	defer startCAgentC2(t, httpPort)()
	agent := waitForCAgentCheckin(t, doneChan, &out, 60*time.Second)

	if has, _ := procMemContains(pid, marker, true); !has {
		t.Fatalf("agent plaintext marker did not return after the mask")
	}
	if got := runC2Command(t, agent, doneChan, &out, "pwd"); !strings.Contains(got, "current working directory:") {
		t.Fatalf("agent command after mask = %q", got)
	}

	// After the command the agent closes its idle tunnel and must re-enter the
	// masked state for the rest of the beacon interval.
	reMasked := false
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if len(findAnonymousELFs(pid)) == 0 {
			reMasked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !reMasked {
		t.Fatalf("agent did not return to masked sleep after the command.\nOutput:\n%s", out.String())
	}
}

type procMap struct {
	start uint64
	end   uint64
	perms string
	path  string
}

func readProcMaps(pid int) ([]procMap, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	var maps []procMap
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		parts := strings.SplitN(fields[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[0], 16, 64)
		end, err2 := strconv.ParseUint(parts[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		path := ""
		if len(fields) > 5 {
			path = strings.Join(fields[5:], " ")
		}
		maps = append(maps, procMap{start: start, end: end, perms: fields[1], path: path})
	}
	return maps, nil
}

func readProcMem(pid int, addr uint64, buf []byte) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.ReadAt(buf, int64(addr))
	return err
}

func findAnonymousELFs(pid int) []uint64 {
	maps, err := readProcMaps(pid)
	if err != nil {
		return nil
	}
	var bases []uint64
	for _, m := range maps {
		if m.path != "" || !strings.HasPrefix(m.perms, "r") || m.end-m.start < 4 {
			continue
		}
		var magic [4]byte
		if readProcMem(pid, m.start, magic[:]) == nil &&
			magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
			bases = append(bases, m.start)
		}
	}
	return bases
}

func procMemContains(pid int, needle []byte, anonymousOnly bool) (bool, error) {
	maps, err := readProcMaps(pid)
	if err != nil {
		return false, err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return false, err
	}
	defer f.Close()

	const chunk = 1 << 20
	overlap := len(needle) - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, chunk)
	for _, m := range maps {
		if !strings.HasPrefix(m.perms, "r") || (anonymousOnly && m.path != "") {
			continue
		}
		for off := m.start; off < m.end; {
			n := uint64(chunk)
			if m.end-off < n {
				n = m.end - off
			}
			if _, err := f.ReadAt(buf[:n], int64(off)); err != nil {
				break // unreadable tail/gap; move to the next mapping
			}
			if bytes.Contains(buf[:n], needle) {
				return true, nil
			}
			if n <= uint64(overlap) {
				break
			}
			off += n - uint64(overlap)
		}
	}
	return false, nil
}
