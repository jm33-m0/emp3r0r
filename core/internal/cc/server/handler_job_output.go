package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	defaultJobOutputLimit = 64 << 10
	maxJobOutputLimit     = 4 << 20
)

// handleJobOutput returns a bounded slice of a job's persisted output. The
// caller must be the operator that owns the job, so one operator cannot read
// another's command results. Job IDs are UUIDs; canonicalizing before the
// owner lookup and path join also rules out traversal through the job ID.
func handleJobOutput(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleJobOutput panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()

	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
		return
	}
	operation, err := DecodeCBORBody[def.JobOutputRequest](wrt, req)
	if err != nil {
		auditOperatorAction(operatorID, "job_output_denied", "", "invalid request body")
		return
	}
	parsed, err := uuid.Parse(strings.TrimSpace(operation.JobID))
	if err != nil {
		badID := operation.JobID
		if len(badID) > 256 {
			badID = badID[:256]
		}
		auditOperatorAction(operatorID, "job_output_denied", badID, "job_id is not a UUID")
		http.Error(wrt, "job_id must be a UUID", http.StatusBadRequest)
		return
	}
	jobID := parsed.String()

	owner, ok := getJobOwner(jobID)
	if !ok || owner != operatorID {
		auditOperatorAction(operatorID, "job_output_denied", jobID, "not owner")
		http.Error(wrt, "job not found", http.StatusForbidden)
		return
	}

	f, err := os.Open(jobs.LogPath(jobID))
	if err != nil {
		if os.IsNotExist(err) {
			auditOperatorAction(operatorID, "job_output_missing", jobID, "output file not found")
			http.Error(wrt, "job output not found", http.StatusNotFound)
			return
		}
		auditOperatorAction(operatorID, "job_output_denied", jobID, "open failed")
		logging.Errorf("handleJobOutput: open %s: %v", jobID, err)
		http.Error(wrt, "read job output", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		logging.Errorf("handleJobOutput: stat %s: %v", jobID, err)
		http.Error(wrt, "read job output", http.StatusInternalServerError)
		return
	}
	size := info.Size()

	limit := operation.Limit
	if limit <= 0 {
		limit = defaultJobOutputLimit
	}
	if limit > maxJobOutputLimit {
		limit = maxJobOutputLimit
	}
	offset := operation.Offset
	if operation.Tail {
		offset = size - limit
	}
	if offset < 0 {
		offset = 0
	}
	if offset > size {
		offset = size
	}
	n := size - offset
	if n > limit {
		n = limit
	}
	if n < 0 {
		n = 0
	}

	buf := make([]byte, n)
	if n > 0 {
		read, readErr := f.ReadAt(buf, offset)
		if readErr != nil && readErr != io.EOF {
			logging.Errorf("handleJobOutput: read %s: %v", jobID, readErr)
			http.Error(wrt, "read job output", http.StatusInternalServerError)
			return
		}
		buf = buf[:read]
	}

	resp := def.JobOutputResponse{
		JobID:     jobID,
		Output:    string(buf),
		Size:      size,
		Truncated: offset > 0 || offset+int64(len(buf)) < size,
	}
	auditOperatorAction(operatorID, "job_output", jobID, fmt.Sprintf("offset=%d limit=%d", offset, limit))

	wrt.Header().Set("Content-Type", "application/cbor")
	if err := cbor.NewEncoder(wrt).Encode(resp); err != nil {
		logging.Errorf("handleJobOutput: encode response: %v", err)
	}
}
