package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
	"github.com/spf13/cobra"
)

var (
	// askSession keeps the conversation across `ask` invocations in this
	// console. It is process-local: nothing is persisted, and switching
	// targets resets it.
	askSession = &assistant.Session{}

	// askBusy prevents two streamed answers from interleaving.
	askBusy atomic.Bool

	// askWG lets tests wait for the background answer. Production never waits.
	askWG sync.WaitGroup
)

type askRequest struct {
	question string
	jobID    string
	last     bool
	module   string
	reset    bool
	model    string
}

func askCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ask [question]",
		GroupID: "util",
		Short:   "Ask the operator assistant about modules or command output",
		Long: "Ask a configured OpenAI-compatible model about modules, their flags, " +
			"or a job's output. The answer streams below the prompt; the console " +
			"stays usable. The assistant can read the module registry, the selected " +
			"target, and cached/persisted job results. It never executes a command; " +
			"review_command only validates and renders one.\n\n" +
			"Configuration: ~/.emp3r0r/assistant.json (see docs/ASSISTANT.md).",
		Example: "ask --last \"what stands out?\"\n" +
			"ask --job 1a2b3c4d-... \"summarise the LDAP results\"\n" +
			"ask --module sa_ldapsearch \"how do I search for kerberoastable users?\"",
		Args: cobra.ArbitraryArgs,
		Run:  runAsk,
	}
	cmd.Flags().String("job", "", "Analyse a job by UUID")
	cmd.Flags().Bool("last", false, "Analyse the most recently dispatched job")
	cmd.Flags().String("module", "", "Include a module's help in the context")
	cmd.Flags().Bool("reset", false, "Clear the conversation history")
	cmd.Flags().String("model", "", "Override the configured model for this question")
	return cmd
}

// runAsk copies the flags and returns immediately. The answer is produced and
// printed by a goroutine so the console prompt stays responsive.
func runAsk(cmd *cobra.Command, args []string) {
	req := askRequest{question: strings.TrimSpace(strings.Join(args, " "))}
	req.jobID, _ = cmd.Flags().GetString("job")
	req.last, _ = cmd.Flags().GetBool("last")
	req.module, _ = cmd.Flags().GetString("module")
	req.reset, _ = cmd.Flags().GetBool("reset")
	req.model, _ = cmd.Flags().GetString("model")

	if !askBusy.CompareAndSwap(false, true) {
		printAssistantLine("assistant is still answering; wait for it to finish")
		return
	}
	askWG.Add(1)
	go func() {
		defer askWG.Done()
		defer askBusy.Store(false)
		defer func() {
			if r := recover(); r != nil {
				printAssistantLine(fmt.Sprintf("assistant panic: %v", r))
			}
		}()
		askInBackground(req)
	}()
}

func askInBackground(req askRequest) {
	cfg, err := assistant.LoadConfig(assistant.ConfigPath())
	if err != nil {
		printAssistantLine("assistant config: " + err.Error())
		return
	}
	if strings.TrimSpace(req.model) != "" {
		cfg.Model = strings.TrimSpace(req.model)
	}
	if req.reset {
		askSession.Reset()
		printAssistantLine("assistant history cleared")
	}
	if _, err := os.Stat(assistant.ConfigPath()); os.IsNotExist(err) {
		printAssistantLine(fmt.Sprintf("assistant: no %s; using %s (%s)",
			assistant.ConfigPath(), cfg.Endpoint(), cfg.Model))
	}
	if cfg.AllowRemote {
		printAssistantLine("assistant: remote endpoint " + cfg.Endpoint() + "; command output may leave this host")
	}
	printAssistantLine("assistant: " + cfg.Model)

	jobID := strings.TrimSpace(req.jobID)
	if req.last && jobID == "" {
		jobID = live.LastJobID()
		if jobID == "" {
			printAssistantLine("assistant: no recent job to analyse")
			return
		}
	}
	moduleName := strings.TrimSpace(req.module)

	var contextParts []string
	if moduleName != "" {
		info, err := assistant.DescribeModule(moduleName)
		if err != nil {
			printAssistantLine("assistant: " + err.Error())
			return
		}
		b, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			printAssistantLine("assistant: module help: " + err.Error())
			return
		}
		contextParts = append(contextParts, "[module "+moduleName+"]\n"+string(b))
	}
	if jobID != "" {
		printAssistantLine("assistant: analysing job " + jobID)
		summary, err := assistant.SummarizeJob(jobID, cfg.MaxResultBytes)
		if err != nil {
			printAssistantLine("assistant: job " + jobID + ": " + err.Error())
			return
		}
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			printAssistantLine("assistant: job summary: " + err.Error())
			return
		}
		contextParts = append(contextParts, "[job "+jobID+" summary]\n"+string(b))
	}

	question := strings.TrimSpace(req.question)
	if question == "" {
		switch {
		case jobID != "":
			question = "Analyse this command output: what stands out, what does it mean, and what should I do next?"
		case moduleName != "":
			question = "Explain this module: what it does, when to use it, and how to invoke it."
		default:
			printAssistantLine("usage: ask <question> [--job UUID | --last] [--module NAME]")
			return
		}
	}

	prompt := question
	if len(contextParts) > 0 {
		prompt = strings.Join(contextParts, "\n\n") + "\n\n[question]\n" + question
	}
	const maxPromptBytes = 48 << 10
	if len(prompt) > maxPromptBytes {
		prompt = prompt[:maxPromptBytes]
	}

	harness, err := assistant.New(cfg)
	if err != nil {
		printAssistantLine("assistant: " + err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	printer := &streamPrinter{}
	target := agents.MustGetActiveAgent()
	text, err := harness.Ask(ctx, askSession, target, prompt, printer.Write)
	printer.Flush()
	if err != nil {
		printAssistantLine("assistant: " + err.Error())
		return
	}
	if !printer.Printed() {
		if strings.TrimSpace(text) == "" {
			text = "(empty response)"
		}
		printer.PrintLine(text)
	}
}

// streamPrinter streams model deltas into the agent output pane. It never
// touches the console input pane: the operator can keep typing while the model
// generates. Deltas are buffered until a newline or a small character budget so
// the pane is not written once per token.
type streamPrinter struct {
	mu      sync.Mutex
	buf     strings.Builder
	printed bool
}

func (p *streamPrinter) Write(delta string) {
	if delta == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Flush every provider delta. Buffering until 200 characters made a slow
	// model look stalled; the pane write is cheap and the prompt pane is not
	// involved.
	p.buf.WriteString(delta)
	p.flushLocked()
}

func (p *streamPrinter) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushLocked()
	if p.printed {
		ensurePaneNewline()
	}
}

func (p *streamPrinter) PrintLine(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.printed = true
	writePaneLine(text)
}

func (p *streamPrinter) Printed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.printed
}

func (p *streamPrinter) flushLocked() {
	chunk := p.buf.String()
	p.buf.Reset()
	if strings.TrimSpace(chunk) == "" {
		return
	}
	p.printed = true
	writePaneChunk(chunk)
}

// outputPane is the tmux agent output pane. Assistant text goes here, never to
// the command prompt pane.
var (
	outputPane      io.Writer
	outputPaneMu    sync.Mutex
	outputAtLineEnd = true
)

// SetOutputPane routes assistant output to the agent output pane.
func SetOutputPane(w io.Writer) {
	outputPaneMu.Lock()
	outputPane = w
	outputAtLineEnd = true
	outputPaneMu.Unlock()
}

// writePaneChunk writes a streamed fragment without adding a newline.
func writePaneChunk(text string) {
	text = sanitize.SanitizeText(text)
	if text == "" {
		return
	}
	outputPaneMu.Lock()
	defer outputPaneMu.Unlock()
	if outputPane != nil {
		if _, err := io.WriteString(outputPane, text); err == nil {
			outputAtLineEnd = strings.HasSuffix(text, "\n")
			return
		}
	}
	logging.Infof("%s", strings.TrimRight(text, "\n"))
}

// ensurePaneNewline terminates a stream that ended without a newline, so later
// log lines do not append to the model's last line.
func ensurePaneNewline() {
	outputPaneMu.Lock()
	defer outputPaneMu.Unlock()
	if outputPane != nil && !outputAtLineEnd {
		if _, err := io.WriteString(outputPane, "\n"); err == nil {
			outputAtLineEnd = true
		}
	}
}

// writePaneLine writes one complete line, first terminating any stream that is
// still mid-line so the two never run together.
func writePaneLine(line string) {
	// Preserve intentional indentation (tool blocks), drop trailing
	// whitespace so the pane does not accumulate blank space.
	line = strings.TrimRight(sanitize.SanitizeText(line), " \t\r\n")
	if strings.TrimSpace(line) == "" {
		return
	}
	outputPaneMu.Lock()
	defer outputPaneMu.Unlock()
	if outputPane != nil {
		prefix := ""
		if !outputAtLineEnd {
			prefix = "\n"
		}
		if _, err := io.WriteString(outputPane, prefix+line+"\n"); err == nil {
			outputAtLineEnd = true
			return
		}
	}
	logging.Infof("%s", line)
}

// printAssistantLine is the console-facing line printer for assistant status,
// results.
func printAssistantLine(line string) {
	writePaneLine(line)
}
