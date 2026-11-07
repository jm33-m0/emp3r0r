package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestHandleJobOutputReturnsOwnedSlice(t *testing.T) {
	prev := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = prev })

	jobID := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(jobs.LogPath(jobID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jobs.LogPath(jobID), []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	setJobOwner(jobID, "operator-1")
	t.Cleanup(func() { operatorJobOwners.Delete(jobID) })

	rec := jobOutputRequest(t, "operator-1", def.JobOutputRequest{
		JobID: jobID,
		Limit: 5,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp def.JobOutputResponse
	if err := cbor.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Output != "hello" {
		t.Fatalf("output = %q", resp.Output)
	}
	if resp.Size != int64(len("hello world")) {
		t.Fatalf("size = %d", resp.Size)
	}
	if !resp.Truncated {
		t.Fatal("expected a truncated slice")
	}
}

func TestHandleJobOutputRejectsOtherOperator(t *testing.T) {
	prev := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = prev })

	jobID := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(jobs.LogPath(jobID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jobs.LogPath(jobID), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	setJobOwner(jobID, "operator-1")
	t.Cleanup(func() { operatorJobOwners.Delete(jobID) })

	rec := jobOutputRequest(t, "operator-2", def.JobOutputRequest{JobID: jobID})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleJobOutputRejectsInvalidID(t *testing.T) {
	prev := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = prev })

	rec := jobOutputRequest(t, "operator-1", def.JobOutputRequest{
		JobID: "../../../etc/passwd",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func jobOutputRequest(t *testing.T, operator string, req def.JobOutputRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/operator/job_output", bytes.NewReader(body))
	httpReq.RemoteAddr = "127.0.0.1:12345"
	httpReq.Header.Set("operator_session", operator)
	rec := httptest.NewRecorder()
	handleJobOutput(rec, httpReq)
	return rec
}

func TestShouldPersistJobResponse(t *testing.T) {
	cases := []struct {
		name string
		msg  def.MsgTunData
		want bool
	}{
		{"user command", def.MsgTunData{CmdSlice: []string{"!ps"}}, true},
		{"module", def.MsgTunData{CmdSlice: []string{"!custom_module", "--mod_name", "x"}}, true},
		{"completion listing", def.MsgTunData{CmdSlice: []string{def.C2CmdListDir}}, false},
		{"completion stat", def.MsgTunData{CmdSlice: []string{def.C2CmdStat}}, false},
		{"quiet", def.MsgTunData{CmdSlice: []string{def.C2CmdListTokens, "--quiet"}}, false},
	}
	for _, tc := range cases {
		if got := shouldPersistJobResponse(&tc.msg); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
