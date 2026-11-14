package detection

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"
)

// displayEndpoint formats a captured endpoint without assuming an IP family.
func displayEndpoint(host string, port int64) string {
	return host + ":" + strconv.FormatInt(port, 10)
}

// persistedFindings returns the stored findings for a trace and whether they
// have already been computed. Findings are materialized because both the loop
// and the read-only SQL tool query them, and because recomputing them for every
// inspection would repeat the same scans.
func (t *TelemetryDB) persistedFindings(ctx context.Context, traceID int64) ([]Finding, bool, error) {
	var computed int
	if err := t.db.QueryRowContext(ctx,
		`SELECT findings_computed FROM traces WHERE id = ?`, traceID).Scan(&computed); err != nil {
		return nil, false, fmt.Errorf("load telemetry trace %d: %w", traceID, err)
	}
	if computed == 0 {
		return nil, false, nil
	}
	rows, err := t.db.QueryContext(ctx, `
		SELECT severity, rule, indicator, detail FROM findings
		WHERE trace_pk = ?
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, rule, indicator`, traceID)
	if err != nil {
		return nil, false, fmt.Errorf("read telemetry findings: %w", err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var finding Finding
		if err := rows.Scan(&finding.Severity, &finding.Rule, &finding.Indicator, &finding.Detail); err != nil {
			return nil, false, fmt.Errorf("scan telemetry finding: %w", err)
		}
		finding.Stage = StageTelemetry
		finding.Tool = "telemetry"
		finding.Executes = true
		sanitizeFindingText(&finding)
		out = append(out, finding)
	}
	return out, true, rows.Err()
}

func (t *TelemetryDB) saveFindings(ctx context.Context, traceID int64, findings []Finding) error {
	var payloadID sql.NullInt64
	if err := t.db.QueryRowContext(ctx,
		`SELECT payload_id FROM traces WHERE id = ?`, traceID).Scan(&payloadID); err != nil {
		return fmt.Errorf("load trace payload: %w", err)
	}
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin telemetry findings: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE trace_pk = ?`, traceID); err != nil {
		return fmt.Errorf("replace telemetry findings: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings(trace_pk, payload_id, stage, tool, severity, rule, indicator, detail, signal, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'signal', ?)`)
	if err != nil {
		return fmt.Errorf("prepare telemetry findings: %w", err)
	}
	defer stmt.Close()
	now := time.Now().UTC().UnixMilli()
	for _, finding := range findings {
		if _, err := stmt.ExecContext(ctx, traceID, payloadID, string(finding.Stage), finding.Tool,
			finding.Severity, finding.Rule, finding.Indicator, finding.Detail, now); err != nil {
			return fmt.Errorf("store telemetry finding: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE traces SET findings_count = ?, findings_computed = 1 WHERE id = ?`,
		len(findings), traceID); err != nil {
		return fmt.Errorf("mark telemetry findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry findings: %w", err)
	}
	return nil
}
