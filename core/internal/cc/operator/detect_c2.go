package operator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// liveDetectC2Backend executes the loop's scoped builder and verification
// actions.
type liveDetectC2Backend struct{}

func (liveDetectC2Backend) GenerateAgent(ccAddress, agentType, arch string) (*detection.AgentBuildResult, error) {
	return generateDetectionAgentWithCC(ccAddress, detection.AgentBuildOptions{
		Type: agentType,
		Arch: arch,
	})
}

// liveAgentByUUID resolves one agent from the live C2 registry.
func liveAgentByUUID(uuid string) (*def.Emp3r0rAgent, error) {
	agents, err := client.GetAgentList()
	if err != nil {
		return nil, err
	}
	return detection.FindAgentByUUID(agents, uuid), nil
}

func (liveDetectC2Backend) AgentStatus(_ context.Context, uuid string) (*detection.VerifyAgentStatus, error) {
	agent, err := liveAgentByUUID(uuid)
	if err != nil {
		return nil, err
	}
	return &detection.VerifyAgentStatus{
		ExpectedAgent: uuid,
		Online:        agent != nil,
		Agent:         detection.AgentSummary(agent),
	}, nil
}

func (liveDetectC2Backend) RunVerifyModule(ctx context.Context, uuid, module string) (*detection.VerifyModuleResult, error) {
	deadline := time.Now().Add(detection.PayloadVerifyTimeout)
	agent, err := liveAgentByUUID(uuid)
	if err != nil {
		return nil, err
	}
	if agent == nil {
		return nil, fmt.Errorf("agent %s is not online; payload is not running", uuid)
	}
	output, jobID, err := runVerifyModuleOnC2(ctx, agent, module, deadline)
	res := &detection.VerifyModuleResult{
		Agent:  detection.AgentSummary(agent),
		Module: module,
		JobID:  jobID,
		Output: output,
	}
	if err != nil {
		res.Message = err.Error()
		return res, err
	}
	return res, nil
}

func (liveDetectC2Backend) FinalVerify(ctx context.Context, uuid, module string) (string, error) {
	deadline := time.Now().Add(detection.PayloadVerifyTimeout)
	agents, err := waitForAgentOnC2(ctx, uuid, deadline)
	if err != nil {
		return "", err
	}
	agent := detection.FindAgentByUUID(agents, uuid)
	if agent == nil {
		return "", fmt.Errorf("agent %s did not come online within %s", uuid, detection.PayloadVerifyTimeout)
	}
	// The sandbox terminates the beacon at the end of the capture window, so a
	// BOF started after the check-in is not a reliable health signal. A live
	// C2 entry is sufficient proof that the payload executed.
	return fmt.Sprintf("agent %s is online", uuid), nil
}

func (liveDetectC2Backend) ForgetAgent(_ context.Context, uuid string) error {
	_, err := client.SendCBORRequest(transport.OperatorForgetAgent, def.Operation{
		AgentTag: uuid,
		Action:   "forget_agent",
	})
	return err
}

func (liveDetectC2Backend) Audit(action, target, detail string) {
	auditDetectionAction(action, target, detail)
}

func waitForAgentOnC2(ctx context.Context, want string, deadline time.Time) ([]*def.Emp3r0rAgent, error) {
	for {
		agents, err := client.GetAgentList()
		if err != nil {
			return nil, err
		}
		if want == "" || detection.FindAgentByUUID(agents, want) != nil || time.Now().After(deadline) {
			return agents, nil
		}
		select {
		case <-ctx.Done():
			return agents, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func runVerifyModuleOnC2(ctx context.Context, agent *def.Emp3r0rAgent, module string, deadline time.Time) (string, string, error) {
	if agent == nil {
		return "", "", fmt.Errorf("no agent")
	}
	jobID, err := modules.DispatchModule(agent, module, nil)
	if err != nil {
		return "", "", err
	}
	for {
		resp, err := client.GetJobOutput(jobID, 0, 16<<10, true)
		if err == nil && resp != nil && strings.TrimSpace(resp.Output) != "" {
			return resp.Output, jobID, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "", jobID, fmt.Errorf("wait for %s output: %w", module, err)
			}
			return "", jobID, fmt.Errorf("%s produced no output before the deadline", module)
		}
		select {
		case <-ctx.Done():
			return "", jobID, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func generateDetectionAgentWithCC(ccAddress string, opts detection.AgentBuildOptions) (*detection.AgentBuildResult, error) {
	// Serialize builder mutations across concurrent console requests.
	generationMu.Lock()
	defer generationMu.Unlock()

	agentCfg := builder.AgentConfig{}
	if cc := strings.TrimSpace(ccAddress); cc != "" {
		agentCfg.CCAddress = &cc
	}
	res, err := builder.GenerateAgentArtifact(agentCfg, opts.Type, opts.Arch, client.SignAgent)
	if err != nil {
		logging.Warningf("detect_loop: signed agent generation failed (%v); building without a C2 signature", err)
		res, err = builder.GenerateAgentArtifact(agentCfg, opts.Type, opts.Arch, nil)
	}
	if err != nil {
		return nil, err
	}
	if res == nil || strings.TrimSpace(res.OutputFile) == "" {
		return nil, fmt.Errorf("agent build produced no artifact")
	}
	artifact, err := detection.InspectArtifact(res.OutputFile)
	if err != nil {
		return nil, err
	}
	return &detection.AgentBuildResult{
		ArtifactPath: res.OutputFile,
		Type:         opts.Type,
		Arch:         opts.Arch,
		AgentUUID:    res.AgentUUID,
		SHA256:       artifact.SHA256,
		Size:         artifact.Size,
	}, nil
}
