package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
)

// CmdJobs list and manage jobs
func CmdJobs(c *console.Console) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "Manage jobs",
		Run: func(cmd *cobra.Command, args []string) {
			jobID, _ := cmd.Flags().GetString("id")
			if jobID != "" {
				// Show job details
				job := jobs.GetJob(jobID)
				if job == nil {
					logging.Errorf("Job %s not found", jobID)
					return
				}
				logging.Infof("Job ID: %s", job.ID)
				logging.Infof("Name: %s", job.Name)
				logging.Infof("Agent: %s", job.AgentTag)
				logging.Infof("Module: %s", job.Module)
				logging.Infof("Status: %d", job.Status)
				logging.Infof("Created: %s", job.Created)
				return
			}

			// List all jobs based on filters
			allJobs := jobs.GetJobs()

			// Build table
			tdata := [][]string{}
			header := []string{"ID", "Name", "Target", "Module", "Status", "Created"}

			for _, job := range allJobs {
				statusStr := "Unknown"
				switch job.Status {
				case def.JobStatusPending:
					statusStr = "Pending"
				case def.JobStatusRunning:
					statusStr = "Running"
				case def.JobStatusCompleted:
					statusStr = "Completed"
				case def.JobStatusFailed:
					statusStr = "Failed"
				}

				tdata = append(tdata, []string{
					job.ID,
					job.Name,
					job.AgentTag,
					job.Module,
					statusStr,
					job.Created.Format("15:04:05"),
				})
			}

			table := cli.BuildTable(header, tdata)
			logging.Infof("\n%s", table)
		},
	}
	cmd.Flags().String("id", "", "Job ID to inspect")

	// Kill command
	killCmd := &cobra.Command{
		Use:   "kill",
		Short: "Kill a job",
		Run: func(cmd *cobra.Command, args []string) {
			jobID, _ := cmd.Flags().GetString("id")
			if jobID == "" {
				logging.Errorf("Please specify job ID")
				return
			}
			err := jobs.KillJob(jobID)
			if err != nil {
				logging.Errorf("Failed to kill job: %v", err)
				return
			}
			logging.Successf("Job %s killed", jobID)
		},
	}
	killCmd.Flags().String("id", "", "Job ID to kill")
	cmd.AddCommand(killCmd)

	return cmd
}
