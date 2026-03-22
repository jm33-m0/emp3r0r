package agents

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	_ "modernc.org/sqlite"
)

// AgentDB is the global database connection
var AgentDB *sql.DB

var (
	sessionEpochMu sync.RWMutex
	// sessionEpoch identifies the running C2 process for duplicate-session checks.
	sessionEpoch = fmt.Sprintf("%d", time.Now().UnixNano())
)

// ErrSessionAlreadyActive indicates a duplicate live session for the same UUID.
var ErrSessionAlreadyActive = errors.New("session already active")

const sessionStaleWindow = 15 * time.Minute

func staleThresholdUnix(now int64) int64 {
	return now - int64(sessionStaleWindow/time.Second)
}

func currentSessionEpoch() string {
	sessionEpochMu.RLock()
	defer sessionEpochMu.RUnlock()
	return sessionEpoch
}

func encodeSessionID(raw string) string {
	return currentSessionEpoch() + ":" + raw
}

func sessionEpochFromID(sessionID string) string {
	parts := strings.SplitN(sessionID, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// ReconcileSessionsOnStartup purges stale persisted sessions and returns count
// of active sessions that can be resumed by this server process.
func ReconcileSessionsOnStartup() (active, purged int64, err error) {
	if AgentDB == nil {
		return 0, 0, fmt.Errorf("database not initialized")
	}

	now := time.Now().Unix()
	staleThreshold := staleThresholdUnix(now)

	res, err := AgentDB.Exec("DELETE FROM agent_sessions WHERE last_heartbeat <= ?", staleThreshold)
	if err != nil {
		return 0, 0, fmt.Errorf("purge stale sessions: %v", err)
	}
	purged, _ = res.RowsAffected()

	err = AgentDB.QueryRow("SELECT COUNT(*) FROM agent_sessions").Scan(&active)
	if err != nil {
		return 0, purged, fmt.Errorf("count active sessions: %v", err)
	}

	return active, purged, nil
}

// InitAgentDB initializes the SQLite database and creates tables if they don't exist
func InitAgentDB(dbPath string) error {
	var err error
	AgentDB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %v", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := AgentDB.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("enable WAL: %v", err)
	}

	// Test connection
	if err := AgentDB.Ping(); err != nil {
		return fmt.Errorf("ping database: %v", err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		uuid TEXT PRIMARY KEY,
		tag TEXT NOT NULL,
		uuid_sig TEXT NOT NULL,
		public_key TEXT NOT NULL,
		hostname TEXT,
		os TEXT,
		arch TEXT,
		user TEXT,
		ip_addresses TEXT,
		last_seen INTEGER,
		first_seen INTEGER,
		connection_count INTEGER DEFAULT 1,
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS agent_sessions (
		uuid TEXT PRIMARY KEY,
		session_id TEXT NOT NULL,
		session_start INTEGER NOT NULL,
		last_heartbeat INTEGER NOT NULL,
		remote_addr TEXT,
		FOREIGN KEY (uuid) REFERENCES agents(uuid)
	);

	CREATE TABLE IF NOT EXISTS agent_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL,
		event_type TEXT NOT NULL,
		old_value TEXT,
		new_value TEXT,
		timestamp INTEGER NOT NULL,
		FOREIGN KEY (uuid) REFERENCES agents(uuid)
	);

	CREATE INDEX IF NOT EXISTS idx_agent_history_uuid ON agent_history(uuid);
	CREATE INDEX IF NOT EXISTS idx_agent_history_timestamp ON agent_history(timestamp);
	`

	if _, err := AgentDB.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %v", err)
	}

	logging.Successf("Agent database initialized: %s", dbPath)
	return nil
}

// IsSessionActive checks if an agent has an active session in the database
// An active session is one created within the last 15 minutes (stale session timeout)
func IsSessionActive(uuid string) (bool, error) {
	if AgentDB == nil {
		return false, fmt.Errorf("database not initialized")
	}
	now := time.Now().Unix()
	staleThreshold := staleThresholdUnix(now)

	query := `SELECT COUNT(*) FROM agent_sessions WHERE uuid = ? AND last_heartbeat > ?`
	var count int
	err := AgentDB.QueryRow(query, uuid, staleThreshold).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("query session: %v", err)
	}
	return count > 0, nil
}

// StartSession creates or updates a session record for an agent
// Returns an error if a session already exists (duplicate prevention)
func StartSession(uuid, sessionID, remoteAddr string) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	now := time.Now().Unix()
	staleThreshold := staleThresholdUnix(now)
	encodedSessionID := encodeSessionID(sessionID)

	tx, err := AgentDB.Begin()
	if err != nil {
		return fmt.Errorf("begin session tx: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Garbage-collect stale session for this UUID, then attempt strict insert.
	if _, err = tx.Exec("DELETE FROM agent_sessions WHERE uuid = ? AND last_heartbeat <= ?", uuid, staleThreshold); err != nil {
		return fmt.Errorf("delete stale session: %v", err)
	}

	var existingSessionID string
	lookupErr := tx.QueryRow("SELECT session_id FROM agent_sessions WHERE uuid = ?", uuid).Scan(&existingSessionID)
	if lookupErr != nil && lookupErr != sql.ErrNoRows {
		return fmt.Errorf("lookup existing session: %v", lookupErr)
	}

	if lookupErr == nil {
		existingEpoch := sessionEpochFromID(existingSessionID)
		if existingEpoch == currentSessionEpoch() {
			return fmt.Errorf("%w: %s", ErrSessionAlreadyActive, uuid)
		}
		// Session persisted from a previous C2 process. Atomically take ownership.
		_, err = tx.Exec(`UPDATE agent_sessions
			SET session_id = ?, session_start = ?, last_heartbeat = ?, remote_addr = ?
			WHERE uuid = ?`, encodedSessionID, now, now, remoteAddr, uuid)
		if err != nil {
			return fmt.Errorf("resume session: %v", err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit session tx: %v", err)
		}
		return nil
	}

	query := `INSERT INTO agent_sessions (uuid, session_id, session_start, last_heartbeat, remote_addr)
	          VALUES (?, ?, ?, ?, ?)`

	_, err = tx.Exec(query, uuid, encodedSessionID, now, now, remoteAddr)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "constraint") {
			return fmt.Errorf("%w: %s", ErrSessionAlreadyActive, uuid)
		}
		return fmt.Errorf("insert session: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit session tx: %v", err)
	}

	return nil
}

// UpdateSessionHeartbeat updates the last heartbeat timestamp for an active session
func UpdateSessionHeartbeat(uuid string) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	now := time.Now().Unix()
	query := `UPDATE agent_sessions SET last_heartbeat = ? WHERE uuid = ?`
	_, err := AgentDB.Exec(query, now, uuid)
	return err
}

// EndSession removes a session record for an agent
func EndSession(uuid string) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := AgentDB.Exec("DELETE FROM agent_sessions WHERE uuid = ?", uuid)
	return err
}

// CloseAgentDB closes the database connection
func CloseAgentDB() error {
	if AgentDB != nil {
		return AgentDB.Close()
	}
	return nil
}

// StoredAgent represents an agent record from the database
type StoredAgent struct {
	UUID            string
	Tag             string
	UUIDSig         string
	PublicKey       string
	Hostname        string
	OS              string
	Arch            string
	User            string
	IPAddresses     string
	LastSeen        int64
	FirstSeen       int64
	ConnectionCount int
	CreatedAt       int64
}

// GetStoredAgent retrieves an agent from the database by UUID
func GetStoredAgent(uuid string) (*StoredAgent, error) {
	if AgentDB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `SELECT uuid, tag, uuid_sig, public_key, hostname, os, arch, user, ip_addresses, 
	          last_seen, first_seen, connection_count, created_at 
	          FROM agents WHERE uuid = ?`

	var agent StoredAgent
	err := AgentDB.QueryRow(query, uuid).Scan(
		&agent.UUID,
		&agent.Tag,
		&agent.UUIDSig,
		&agent.PublicKey,
		&agent.Hostname,
		&agent.OS,
		&agent.Arch,
		&agent.User,
		&agent.IPAddresses,
		&agent.LastSeen,
		&agent.FirstSeen,
		&agent.ConnectionCount,
		&agent.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Agent not found
	}
	if err != nil {
		return nil, fmt.Errorf("query agent: %v", err)
	}

	return &agent, nil
}

// RecordAgentCheckin records or updates an agent check-in in the database
func RecordAgentCheckin(agent *def.Emp3r0rAgent) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	now := time.Now().Unix()
	ipAddresses := strings.Join(agent.IPs, ",")

	// Check if agent exists
	existing, err := GetStoredAgent(agent.UUID)
	if err != nil {
		return fmt.Errorf("check existing agent: %v", err)
	}

	if existing == nil {
		// New agent - insert
		query := `INSERT INTO agents (uuid, tag, uuid_sig, public_key, hostname, os, arch, user, 
		          ip_addresses, last_seen, first_seen, connection_count, created_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`

		_, err := AgentDB.Exec(query,
			agent.UUID,
			agent.Tag,
			agent.UUIDSig,
			agent.PublicKey,
			agent.Hostname,
			agent.OS,
			agent.Arch,
			agent.User,
			ipAddresses,
			now,
			now,
			now,
		)
		if err != nil {
			return fmt.Errorf("insert agent: %v", err)
		}

		// Record history
		if err := recordHistory(agent.UUID, live.RuntimeConfig.C2Routes.Checkin, "", "First connection", now); err != nil {
			logging.Warningf("Failed to record history: %v", err)
		}

		logging.Infof("New agent recorded in database: %s", agent.UUID)
	} else {
		if existing.PublicKey != "" && agent.PublicKey != "" && existing.PublicKey != agent.PublicKey {
			return fmt.Errorf("immutable identity violation: public key mismatch for %s", agent.UUID)
		}
		if existing.UUIDSig != "" && agent.UUIDSig != "" && existing.UUIDSig != agent.UUIDSig {
			return fmt.Errorf("immutable identity violation: uuid signature mismatch for %s", agent.UUID)
		}

		// Existing agent — update everything EXCEPT public_key (pinned at first registration,
		// never rotated per security policy).
		query := `UPDATE agents SET tag = ?, hostname = ?, os = ?, arch = ?,
		          user = ?, ip_addresses = ?, last_seen = ?, connection_count = connection_count + 1
		          WHERE uuid = ?`

		_, err := AgentDB.Exec(query,
			agent.Tag,
			agent.Hostname,
			agent.OS,
			agent.Arch,
			agent.User,
			ipAddresses,
			now,
			agent.UUID,
		)
		if err != nil {
			return fmt.Errorf("update agent: %v", err)
		}
	}

	return nil
}

// GetPinnedIdentity returns the persisted trust baseline for an agent UUID.
// Security decisions must use this DB state, not in-memory projections.
func GetPinnedIdentity(uuid string) (publicKey, uuidSig string, found bool, err error) {
	stored, err := GetStoredAgent(uuid)
	if err != nil {
		return "", "", false, err
	}
	if stored == nil {
		return "", "", false, nil
	}
	return stored.PublicKey, stored.UUIDSig, true, nil
}

// DetectAgentChanges compares incoming agent data with stored data and logs changes
func DetectAgentChanges(agent *def.Emp3r0rAgent) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	stored, err := GetStoredAgent(agent.UUID)
	if err != nil {
		return fmt.Errorf("get stored agent: %v", err)
	}

	if stored == nil {
		// New agent, no changes to detect
		return nil
	}

	now := time.Now().Unix()
	ipAddresses := strings.Join(agent.IPs, ",")

	if stored.Hostname != agent.Hostname {
		logging.Warningf("Agent %s hostname changed: %s → %s",
			util.SanitizeOneLine(agent.UUID),
			util.SanitizeOneLine(stored.Hostname),
			util.SanitizeOneLine(agent.Hostname),
		)
		if err := recordHistory(agent.UUID, "property_change",
			fmt.Sprintf("hostname:%s", stored.Hostname),
			fmt.Sprintf("hostname:%s", agent.Hostname), now); err != nil {
			logging.Warningf("Failed to record hostname change: %v", err)
		}
	}

	if stored.OS != agent.OS {
		logging.Warningf("Agent %s OS changed: %s → %s",
			util.SanitizeOneLine(agent.UUID),
			util.SanitizeOneLine(stored.OS),
			util.SanitizeOneLine(agent.OS),
		)
		if err := recordHistory(agent.UUID, "property_change",
			fmt.Sprintf("os:%s", stored.OS),
			fmt.Sprintf("os:%s", agent.OS), now); err != nil {
			logging.Warningf("Failed to record OS change: %v", err)
		}
	}

	if stored.User != agent.User {
		logging.Warningf("Agent %s user changed: %s → %s",
			util.SanitizeOneLine(agent.UUID),
			util.SanitizeOneLine(stored.User),
			util.SanitizeOneLine(agent.User),
		)
		if err := recordHistory(agent.UUID, "property_change",
			fmt.Sprintf("user:%s", stored.User),
			fmt.Sprintf("user:%s", agent.User), now); err != nil {
			logging.Warningf("Failed to record user change: %v", err)
		}
	}

	if stored.IPAddresses != ipAddresses {
		logging.Infof("Agent %s IP addresses changed: %s → %s",
			util.SanitizeOneLine(agent.UUID),
			util.SanitizeOneLine(stored.IPAddresses),
			util.SanitizeOneLine(ipAddresses),
		)
		if err := recordHistory(agent.UUID, "property_change",
			fmt.Sprintf("ips:%s", stored.IPAddresses),
			fmt.Sprintf("ips:%s", ipAddresses), now); err != nil {
			logging.Warningf("Failed to record IP change: %v", err)
		}
	}

	if stored.PublicKey != agent.PublicKey {
		logging.Warningf("Agent %s public key changed (key_rotation detected): pinned=%s new=%s",
			util.SanitizeOneLine(agent.UUID),
			util.SanitizeOneLine(stored.PublicKey[:min(len(stored.PublicKey), 16)]),
			util.SanitizeOneLine(agent.PublicKey[:min(len(agent.PublicKey), 16)]),
		)
		if err := recordHistory(agent.UUID, "key_rotation",
			stored.PublicKey,
			agent.PublicKey, now); err != nil {
			logging.Warningf("Failed to record key rotation: %v", err)
		}
	}

	return nil
}

// RemoveAgent removes an agent from the database
func RemoveAgent(uuid string) error {
	if AgentDB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Delete session first to guarantee clean lifecycle state after forget.
	if _, err := AgentDB.Exec("DELETE FROM agent_sessions WHERE uuid = ?", uuid); err != nil {
		return fmt.Errorf("delete agent session: %v", err)
	}

	// Delete history first (foreign key constraint)
	if _, err := AgentDB.Exec("DELETE FROM agent_history WHERE uuid = ?", uuid); err != nil {
		return fmt.Errorf("delete agent history: %v", err)
	}

	// Delete agent
	result, err := AgentDB.Exec("DELETE FROM agents WHERE uuid = ?", uuid)
	if err != nil {
		return fmt.Errorf("delete agent: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %v", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found: %s", uuid)
	}

	logging.Successf("Agent %s removed from database", uuid)

	// Also clear from in-memory maps to ensure PINNED KEYS are forgotten.
	live.AgentControlMap.Range(func(key, value any) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == uuid {
			live.AgentControlMap.Delete(key)
			return false
		}
		return true
	})
	for i, a := range live.AgentList {
		if a.UUID == uuid {
			live.AgentList = append(live.AgentList[:i], live.AgentList[i+1:]...)
			break
		}
	}

	return nil
}

// GetAgentHistory retrieves historical events for an agent
func GetAgentHistory(uuid string, limit int) ([]map[string]any, error) {
	if AgentDB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `SELECT event_type, old_value, new_value, timestamp 
	          FROM agent_history 
	          WHERE uuid = ? 
	          ORDER BY timestamp DESC 
	          LIMIT ?`

	rows, err := AgentDB.Query(query, uuid, limit)
	if err != nil {
		return nil, fmt.Errorf("query history: %v", err)
	}
	defer rows.Close()

	var history []map[string]any
	for rows.Next() {
		var eventType, oldValue, newValue string
		var timestamp int64

		if err := rows.Scan(&eventType, &oldValue, &newValue, &timestamp); err != nil {
			return nil, fmt.Errorf("scan history row: %v", err)
		}

		history = append(history, map[string]any{
			"event_type": eventType,
			"old_value":  oldValue,
			"new_value":  newValue,
			"timestamp":  timestamp,
			"time":       time.Unix(timestamp, 0).Format(time.RFC3339),
		})
	}

	return history, nil
}

// recordHistory is a helper function to record an event in the history table
func recordHistory(uuid, eventType, oldValue, newValue string, timestamp int64) error {
	query := `INSERT INTO agent_history (uuid, event_type, old_value, new_value, timestamp)
	          VALUES (?, ?, ?, ?, ?)`

	_, err := AgentDB.Exec(query, uuid, eventType, oldValue, newValue, timestamp)
	return err
}
