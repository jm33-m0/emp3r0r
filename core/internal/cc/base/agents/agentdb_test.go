package agents

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func setupTestDB(t *testing.T) string {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_agents.db")

	err := InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	return dbPath
}

func TestInitAgentDB(t *testing.T) {
	dbPath := setupTestDB(t)
	defer CloseAgentDB()

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// Verify AgentDB is not nil
	if AgentDB == nil {
		t.Error("AgentDB is nil after initialization")
	}
}

func TestRecordAgentCheckin(t *testing.T) {
	setupTestDB(t)
	defer CloseAgentDB()

	agent := &def.Emp3r0rAgent{
		UUID:      "test-uuid-123",
		Tag:       "test-agent",
		PublicKey: "test-public-key",
		Hostname:  "test-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "testuser",
		IPs:       []string{"192.168.1.100"},
	}

	// Record first check-in
	err := RecordAgentCheckin(agent)
	if err != nil {
		t.Fatalf("Failed to record agent check-in: %v", err)
	}

	// Retrieve agent
	stored, err := GetStoredAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Failed to get stored agent: %v", err)
	}

	if stored == nil {
		t.Fatal("Stored agent is nil")
	}

	// Verify stored data
	if stored.UUID != agent.UUID {
		t.Errorf("UUID mismatch: expected %s, got %s", agent.UUID, stored.UUID)
	}

	if stored.Tag != agent.Tag {
		t.Errorf("Tag mismatch: expected %s, got %s", agent.Tag, stored.Tag)
	}

	if stored.PublicKey != agent.PublicKey {
		t.Errorf("PublicKey mismatch: expected %s, got %s", agent.PublicKey, stored.PublicKey)
	}

	if stored.ConnectionCount != 1 {
		t.Errorf("Expected connection count 1, got %d", stored.ConnectionCount)
	}
}

func TestRecordAgentCheckin_MultipleCheckins(t *testing.T) {
	setupTestDB(t)
	defer CloseAgentDB()

	agent := &def.Emp3r0rAgent{
		UUID:      "test-uuid-456",
		Tag:       "test-agent-2",
		PublicKey: "test-public-key-2",
		Hostname:  "test-host-2",
		OS:        "linux",
		Arch:      "amd64",
		User:      "testuser",
		IPs:       []string{"192.168.1.101"},
	}

	// Record multiple check-ins
	for i := 0; i < 5; i++ {
		err := RecordAgentCheckin(agent)
		if err != nil {
			t.Fatalf("Failed to record check-in %d: %v", i+1, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify connection count
	stored, err := GetStoredAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Failed to get stored agent: %v", err)
	}

	if stored.ConnectionCount != 5 {
		t.Errorf("Expected connection count 5, got %d", stored.ConnectionCount)
	}
}

func TestDetectAgentChanges(t *testing.T) {
	setupTestDB(t)
	defer CloseAgentDB()

	// Initial agent
	agent := &def.Emp3r0rAgent{
		UUID:      "test-uuid-789",
		Tag:       "test-agent-3",
		PublicKey: "original-key",
		Hostname:  "original-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "originaluser",
		IPs:       []string{"192.168.1.102"},
	}

	// Record initial check-in
	err := RecordAgentCheckin(agent)
	if err != nil {
		t.Fatalf("Failed to record initial check-in: %v", err)
	}

	// Modify agent properties
	agent.PublicKey = "new-key"
	agent.Hostname = "new-host"
	agent.User = "newuser"
	agent.IPs = []string{"192.168.1.103"}

	// Detect changes
	err = DetectAgentChanges(agent)
	if err != nil {
		t.Fatalf("Failed to detect changes: %v", err)
	}

	// Verify history was recorded
	history, err := GetAgentHistory(agent.UUID, 100)
	if err != nil {
		t.Fatalf("Failed to get agent history: %v", err)
	}

	if len(history) == 0 {
		t.Fatal("No history entries found")
	}

	// Count event types (key_rotation and property_change)
	keyRotationFound := false
	propertyChangesFound := 0

	for _, entry := range history {
		eventType, ok := entry["event_type"].(string)
		if !ok {
			continue
		}

		switch eventType {
		case "key_rotation":
			keyRotationFound = true
		case "property_change":
			propertyChangesFound++
		}
	}

	if !keyRotationFound {
		t.Error("Expected key_rotation event not found in history")
	}

	// We changed hostname, user, and IPs (3 property changes)
	if propertyChangesFound < 3 {
		t.Errorf("Expected at least 3 property_change events, got %d", propertyChangesFound)
	}
}

func TestRemoveAgent(t *testing.T) {
	setupTestDB(t)
	defer CloseAgentDB()

	agent := &def.Emp3r0rAgent{
		UUID:      "test-uuid-remove",
		Tag:       "test-agent-remove",
		PublicKey: "test-key",
		Hostname:  "test-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "testuser",
		IPs:       []string{"192.168.1.104"},
	}

	// Record agent
	err := RecordAgentCheckin(agent)
	if err != nil {
		t.Fatalf("Failed to record agent: %v", err)
	}

	// Verify agent exists
	stored, err := GetStoredAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Failed to get agent: %v", err)
	}
	if stored == nil {
		t.Fatal("Agent not found before removal")
	}

	// Remove agent
	err = RemoveAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Failed to remove agent: %v", err)
	}

	// Verify agent was removed
	stored, err = GetStoredAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Error checking removed agent: %v", err)
	}
	if stored != nil {
		t.Error("Agent still exists after removal")
	}
}

func TestGetStoredAgent_NotFound(t *testing.T) {
	setupTestDB(t)
	defer CloseAgentDB()

	// Try to get non-existent agent
	stored, err := GetStoredAgent("non-existent-uuid")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if stored != nil {
		t.Error("Expected nil for non-existent agent")
	}
}

func TestDatabasePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persistence_test.db")

	// Initialize and add agent
	err := InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	agent := &def.Emp3r0rAgent{
		UUID:      "persistence-test-uuid",
		Tag:       "persistence-agent",
		PublicKey: "persistence-key",
		Hostname:  "persistence-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "testuser",
		IPs:       []string{"192.168.1.105"},
	}

	err = RecordAgentCheckin(agent)
	if err != nil {
		t.Fatalf("Failed to record agent: %v", err)
	}

	// Close database
	CloseAgentDB()

	// Reopen database
	err = InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer CloseAgentDB()

	// Verify agent persisted
	stored, err := GetStoredAgent(agent.UUID)
	if err != nil {
		t.Fatalf("Failed to get agent after reopen: %v", err)
	}

	if stored == nil {
		t.Fatal("Agent not found after database reopen")
	}

	if stored.UUID != agent.UUID {
		t.Errorf("UUID mismatch after persistence: expected %s, got %s", agent.UUID, stored.UUID)
	}
}
