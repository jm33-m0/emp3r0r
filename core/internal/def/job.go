package def

import "time"

// JobStatus represents the state of a job
type JobStatus int

const (
	// JobStatusPending job is created but not yet running
	JobStatusPending JobStatus = iota
	// JobStatusRunning job is currently executing
	JobStatusRunning
	// JobStatusCompleted job has finished successfully
	JobStatusCompleted
	// JobStatusFailed job failed to execute or finished with error
	JobStatusFailed
)

// Job represents a task execution on an agent
type Job struct {
	ID          string    `json:"id"`           // UUID
	Name        string    `json:"name"`         // "nmap scan", "interactive shell", "get root"
	AgentTag    string    `json:"agent_tag"`    // Target agent tag
	Module      string    `json:"module"`       // "mod_cmd", "mod_shell"
	Args        []string  `json:"args"`         // Arguments passed to the module
	Created     time.Time `json:"created"`      // When the job was created
	Finished    time.Time `json:"finished"`     // When the job finished
	Status      JobStatus `json:"status"`       // Current status of the job
	Error       string    `json:"error"`        // Error message if failed
	OutputPaths []string  `json:"output_paths"` // Where logs are stored (e.g., "jobs/<id>.log")
}
