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
	ID          string    `cbor:"1,keyasint"`  // UUID
	Name        string    `cbor:"2,keyasint"`  // "nmap scan", "interactive shell", "get root"
	AgentTag    string    `cbor:"3,keyasint"`  // Target agent tag
	Module      string    `cbor:"4,keyasint"`  // "mod_cmd", "mod_shell"
	Args        []string  `cbor:"5,keyasint"`  // Arguments passed to the module
	Created     time.Time `cbor:"6,keyasint"`  // When the job was created
	Finished    time.Time `cbor:"7,keyasint"`  // When the job finished
	Status      JobStatus `cbor:"8,keyasint"`  // Current status of the job
	Error       string    `cbor:"9,keyasint"`  // Error message if failed
	OutputPaths []string  `cbor:"10,keyasint"` // Where logs are stored (e.g., "jobs/<id>.log")
}
