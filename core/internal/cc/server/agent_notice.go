package server

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// agentConnectedNotice renders a detailed, operator-facing summary of an agent
// that has just connected, for the "knock knock" notification.
//
// The result is a plain-text block built only from agent-supplied metadata.
// Every field is sanitized at the trust boundary (SanitizeAgentMetadata) and
// the whole block is sanitized again by operatorBroadcastPrintf before it
// reaches the operator. The output pane runs a plain reader (emp3r0r-cat), so
// this text is only ever displayed, never executed.
func agentConnectedNotice(a *def.Emp3r0rAgent) string {
	if a == nil {
		return "Knock knock — an agent is online"
	}

	proc := ""
	if a.Process != nil {
		proc = fmt.Sprintf("%s (pid=%d, ppid=%d", a.Process.Cmdline, a.Process.PID, a.Process.PPID)
		if a.Process.Parent != "" {
			proc += ", parent=" + a.Process.Parent
		}
		proc += ")"
	}

	arch := a.Arch
	if a.GOArch != "" && a.GOArch != a.Arch {
		arch = fmt.Sprintf("%s (binary %s/%s)", a.Arch, a.GOOS, a.GOArch)
	}

	privilege := ""
	if a.HasRoot {
		privilege = "root"
	}

	// P2P only when the mesh is actually active; "direct" means no P2P.
	p2p := strings.TrimSpace(strings.Join(nonEmptyStrings(a.P2PTransport, a.P2PRelayPort, a.MeshGossipPort), " "))
	if a.MeshRoute != "" && a.MeshRoute != "direct" {
		if p2p != "" {
			p2p = a.MeshRoute + " — " + p2p
		} else {
			p2p = a.MeshRoute
		}
	}

	fields := []struct{ label, value string }{
		{"ID", a.Tag},
		{"Name", a.Name},
		{"OS", a.OS},
		{"Kernel", a.Kernel},
		{"Arch", arch},
		{"Host", a.Hostname},
		{"User", a.User},
		{"Privilege", privilege},
		{"Groups", a.Groups},
		{"IPs", strings.Join(a.IPs, ", ")},
		{"From", a.From},
		{"Transport", a.Transport},
		{"P2P", p2p},
		{"Container", a.Container},
		{"Process", proc},
		{"Uptime", a.Uptime},
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\nKnock knock — agent %s is online\n", util.SanitizeOneLine(a.Tag))
	for _, f := range fields {
		// Sanitize each value here as well: the caller may not have gone through
		// the trust boundary, and a single-line, escape-free value keeps the
		// multi-line layout intact. operatorBroadcastPrintf sanitizes again.
		v := util.SanitizeOneLine(f.value)
		if v == "" || v == "N/A" {
			continue
		}
		fmt.Fprintf(&b, "  %-10s %s\n", f.label+":", v)
	}
	return b.String()
}

// nonEmptyStrings returns only the non-empty strings from in, preserving order.
func nonEmptyStrings(in ...string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && s != "N/A" {
			out = append(out, s)
		}
	}
	return out
}
