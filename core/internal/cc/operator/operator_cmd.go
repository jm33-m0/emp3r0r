package operator

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/posener/h2conn"
	"github.com/spf13/cobra"
)

func sendCBORRequest(url string, data any) ([]byte, error) {
	// Encode data to CBOR
	cborData, err := cbor.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	// Create request with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Send HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(cborData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Add("operator_session", OPERATOR_SESSION)

	resp, err := OperatorHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed, status code: %d, url: %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// operatorSendCommand2Agent sends a command to an agent through the mTLS C2 operator server
// Runs asynchronously to avoid blocking the console
func operatorSendCommand2Agent(cmd, cmdID, agentTag string) error {
	if cmdID == "" {
		cmdID = uuid.NewString()
	}
	operation := def.Operation{
		AgentTag:  agentTag,
		Action:    "command",
		Command:   &cmd,
		CommandID: &cmdID,
	}

	// Record command time immediately
	live.CmdTimeMutex.Lock()
	live.CmdTime[cmdID] = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")
	live.CmdTimeMutex.Unlock()

	// Send command asynchronously to avoid blocking
	go func() {
		url := fmt.Sprintf("%s/%s", OperatorRootURL, transport.OperatorSendCommand)
		_, err := sendCBORRequest(url, operation)
		if err != nil {
			logging.Errorf("Failed to send command to agent %s: %v", agentTag, err)
		}
	}()

	return nil
}

func cmdSetActiveAgent(cmd *cobra.Command, args []string) {
	operation := def.Operation{
		AgentTag: args[0],
		Action:   "command",
	}

	url := fmt.Sprintf("%s/%s", OperatorRootURL, transport.OperatorSetActiveAgent)
	body, err := sendCBORRequest(url, operation)
	if err != nil {
		logging.Errorf("Failed to set active agent: %v", err)
		return
	}

	var agent *def.Emp3r0rAgent
	if err := cbor.Unmarshal(body, &agent); err != nil {
		logging.Errorf("Failed to unmarshal active agent: %v", err)
		return
	}
	live.ActiveAgent = agent
	if live.ActiveAgent.Tag == "" {
		logging.Errorf("Failed to set active agent: empty data from server")
		return
	}
	logging.Successf("Now targeting %s", live.ActiveAgent.Tag)

	// Update tmux window title to show active agent
	setTitleErr := cli.TmuxSetWindowTitle(fmt.Sprintf("#[fg=cyan]%s", live.ActiveAgent.Name), cli.CommandPane.WindowID)
	if setTitleErr != nil {
		logging.Warningf("Failed to set tmux window title: %v", setTitleErr)
	}
}

func cmdListAgents(_ *cobra.Command, _ []string) {
	err := refreshAgentList()
	if err != nil {
		logging.Errorf("Failed to list agents: %v", err)
		return
	}
	cli.TmuxSwitchWindow(cli.AgentListPane.WindowID)
}

func getAgentListFromServer() error {
	url := fmt.Sprintf("%s/%s", OperatorRootURL, transport.OperatorListConnectedAgents)
	body, err := sendCBORRequest(url, nil)
	if err != nil {
		return fmt.Errorf("failed to list agents: %v", err)
	}

	var agents []*def.Emp3r0rAgent
	if err := cbor.Unmarshal(body, &agents); err != nil {
		return fmt.Errorf("failed to unmarshal agents: %v", err)
	}
	live.AgentList = agents
	// Update active agent pointer to avoid staleness
	if live.ActiveAgent != nil {
		for _, a := range agents {
			if a.UUID == live.ActiveAgent.UUID {
				live.ActiveAgent = a
				break
			}
		}
	}

	return nil
}

// connectMsgTun connects to the operator message tunnel
func connectMsgTun() (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	h2 := h2conn.Client{
		Client: OperatorHTTPClient,
		Header: http.Header{
			"operator_session": {OPERATOR_SESSION},
		},
	}
	url := fmt.Sprintf("%s/%s", OperatorRootURL, transport.OperatorMsgTunnel)
	ctx, cancel = context.WithCancel(context.Background())
	conn, resp, err := h2.Connect(ctx, url)
	if err != nil {
		err = fmt.Errorf("connect to message tunnel: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status code: %d", resp.StatusCode)
		return
	}
	logging.Successf("Connected to %s, session ID is %s", url, OPERATOR_SESSION)

	return
}

func msgTunHandler() {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("msgTunHandler panicked: %v", r)
		}
	}()
	time.Sleep(3 * time.Second)
	retryDelay := 5 * time.Second
	maxRetryDelay := 5 * time.Minute

	for {
		conn, ctx, cancel, err := connectMsgTun()
		if err != nil {
			logging.Errorf("Failed to connect to message tunnel: %v, retrying in %v", err, retryDelay)
			time.Sleep(retryDelay)
			// Exponential backoff
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
			continue
		}

		decoder := cbor.NewDecoder(bufio.NewReader(conn))

		// Channel to receive decode results
		msgCh := make(chan *def.MsgTunData, 10)
		errCh := make(chan error, 1)

		// Single goroutine to continuously read messages
		go func() {
			for {
				msg := new(def.MsgTunData)
				if err := decoder.Decode(msg); err != nil {
					errCh <- err
					return
				}
				msgCh <- msg
			}
		}()

		// Keep reading messages from the tunnel
		connectionBroken := false

		for ctx.Err() == nil {
			select {
			case msg := <-msgCh:
				processAgentData(msg)
				// Reset retry delay on successful message
				retryDelay = 5 * time.Second
			case err := <-errCh:
				if errors.Is(err, io.EOF) {
					logging.Warningf("Message tunnel closed")
				} else {
					logging.Errorf("Failed to decode message: %v", err)
				}
				connectionBroken = true
				goto reconnect
			case <-ctx.Done():
				logging.Debugf("Context cancelled, exiting message tunnel")
				goto reconnect
			}
		}

	reconnect:
		cancel()
		conn.Close()

		if connectionBroken {
			logging.Infof("Message tunnel disconnected, reconnecting in %v", retryDelay)
			time.Sleep(retryDelay)
			// Exponential backoff
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
		} else {
			time.Sleep(retryDelay)
		}
	}
}
