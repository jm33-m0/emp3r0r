package agents

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	_ "modernc.org/sqlite"
)

// AgentDB is the global database connection
var AgentDB *sql.DB

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

	query := `SELECT uuid, tag, public_key, hostname, os, arch, user, ip_addresses, 
	          last_seen, first_seen, connection_count, created_at 
	          FROM agents WHERE uuid = ?`

	var agent StoredAgent
	err := AgentDB.QueryRow(query, uuid).Scan(
		&agent.UUID,
		&agent.Tag,
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
		query := `INSERT INTO agents (uuid, tag, public_key, hostname, os, arch, user, 
		          ip_addresses, last_seen, first_seen, connection_count, created_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`

		_, err := AgentDB.Exec(query,
			agent.UUID,
			agent.Tag,
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
		if err := recordHistory(agent.UUID, "checkin", "", "First connection", now); err != nil {
			logging.Warningf("Failed to record history: %v", err)
		}

		logging.Infof("New agent recorded in database: %s", agent.UUID)
	} else {
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
