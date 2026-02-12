package jobs

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// Jobs holds all jobs, key is JobID
	Jobs sync.Map
)

// CreateJob creates a new job and saves it to Jobs map
func CreateJob(name, module, agentTag string) *def.Job {
	job := &def.Job{
		ID:       uuid.NewString(),
		Name:     name,
		AgentTag: agentTag,
		Module:   module,
		Created:  time.Now(),
		Status:   def.JobStatusPending,
	}

	Jobs.Store(job.ID, job)
	return job
}

// GetJob retrieves a job by ID
func GetJob(id string) *def.Job {
	if val, ok := Jobs.Load(id); ok {
		return val.(*def.Job)
	}
	return nil
}

// HandleOutput appends output to job's log file or prints to console
func HandleOutput(jobID string, output []byte) {
	job := GetJob(jobID)
	if job == nil {
		return
	}

	// Update LastSeen? No, that's done in AgentHandler

	// If job is "Foreground" (Interactive), usually handled by the caller of job (e.g. infinite loop in waiting)
	// But here we can log everything to file for persistence

	// Ensure job directory exists
	jobDir := filepath.Join(live.EmpWorkSpace, "jobs")
	if _, err := os.Stat(jobDir); os.IsNotExist(err) {
		os.MkdirAll(jobDir, 0700)
	}

	// Append to log file
	logPath := filepath.Join(jobDir, fmt.Sprintf("%s.log", jobID))
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		// Sanitize output before logging
		sanitizedOutput := util.StripANSI(string(output))
		f.WriteString(sanitizedOutput)
	}
}

// GetJobs returns a list of all jobs
func GetJobs() []*def.Job {
	var jobs []*def.Job
	Jobs.Range(func(key, value interface{}) bool {
		jobs = append(jobs, value.(*def.Job))
		return true
	})
	return jobs
}

// KillJob kills a job
// This is a placeholder, as we need to support cancelling contexts in the future
func KillJob(jobID string) error {
	job := GetJob(jobID)
	if job == nil {
		return fmt.Errorf("job %s not found", jobID)
	}
	// TODO: cancel context
	job.Status = def.JobStatusFailed
	return nil
}
