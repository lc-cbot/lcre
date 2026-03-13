package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/model"
)

func TestEnrichmentCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-enrichment-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert enrichment
	now := time.Now().Truncate(time.Second)
	err = db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: now,
		RawOutput: `{"rules": {}}`,
	})
	if err != nil {
		t.Fatalf("failed to insert enrichment: %v", err)
	}

	// Query all enrichments
	enrichments, err := db.QueryEnrichments("")
	if err != nil {
		t.Fatalf("failed to query enrichments: %v", err)
	}
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(enrichments))
	}
	if enrichments[0].Tool != "capa" {
		t.Errorf("expected tool 'capa', got '%s'", enrichments[0].Tool)
	}

	// Query by tool name
	enrichments, err = db.QueryEnrichments("capa")
	if err != nil {
		t.Fatalf("failed to query by tool: %v", err)
	}
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment for capa, got %d", len(enrichments))
	}

	// Query non-existent tool
	enrichments, err = db.QueryEnrichments("nonexistent")
	if err != nil {
		t.Fatalf("failed to query non-existent: %v", err)
	}
	if len(enrichments) != 0 {
		t.Errorf("expected 0 enrichments for nonexistent tool, got %d", len(enrichments))
	}
}

func TestCapabilitiesCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-capabilities-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	caps := []model.Capability{
		{
			Name:      "create process",
			Namespace: "host-interaction/process/create",
			AttackIDs: []string{"T1106"},
			MBCIDs:    []string{"C0017"},
		},
		{
			Name:      "encrypt data using AES",
			Namespace: "data-manipulation/encryption/aes",
			AttackIDs: []string{"T1486"},
		},
	}

	err = db.InsertCapabilities(caps)
	if err != nil {
		t.Fatalf("failed to insert capabilities: %v", err)
	}

	// Query all
	results, err := db.QueryCapabilities("", "")
	if err != nil {
		t.Fatalf("failed to query all capabilities: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(results))
	}

	// Query by namespace prefix
	results, err = db.QueryCapabilities("host-interaction", "")
	if err != nil {
		t.Fatalf("failed to query by namespace: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 capability in host-interaction, got %d", len(results))
	}

	// Query by name pattern
	results, err = db.QueryCapabilities("", "encrypt")
	if err != nil {
		t.Fatalf("failed to query by name: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 capability matching 'encrypt', got %d", len(results))
	}

	// Verify ATT&CK IDs survived the round-trip
	if len(results[0].AttackIDs) != 1 || results[0].AttackIDs[0] != "T1486" {
		t.Errorf("ATT&CK IDs didn't round-trip: %v", results[0].AttackIDs)
	}
}

func TestPackerDetectionsCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-packer-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	dets := []model.PackerDetection{
		{Type: "compiler", Name: "GCC", Version: "11.2"},
		{Type: "packer", Name: "UPX", Version: "3.96", String: "UPX(3.96)[NRV2B]"},
	}

	err = db.InsertPackerDetections(dets)
	if err != nil {
		t.Fatalf("failed to insert packer detections: %v", err)
	}

	// Query all
	results, err := db.QueryPackerDetections("")
	if err != nil {
		t.Fatalf("failed to query all: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(results))
	}

	// Query by type
	results, err = db.QueryPackerDetections("packer")
	if err != nil {
		t.Fatalf("failed to query by type: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 packer detection, got %d", len(results))
	}
	if results[0].Name != "UPX" {
		t.Errorf("expected UPX, got %s", results[0].Name)
	}
}

func TestClearEnrichment(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-clear-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert capa enrichment + capabilities
	db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: time.Now(),
		RawOutput: "{}",
	})
	db.InsertCapabilities([]model.Capability{
		{Name: "test cap", Namespace: "test"},
	})

	// Clear capa enrichment
	err = db.ClearEnrichment("capa")
	if err != nil {
		t.Fatalf("failed to clear: %v", err)
	}

	// Verify enrichment gone
	enrichments, _ := db.QueryEnrichments("capa")
	if len(enrichments) != 0 {
		t.Error("enrichment not cleared")
	}

	// Verify capabilities gone
	caps, _ := db.QueryCapabilities("", "")
	if len(caps) != 0 {
		t.Error("capabilities not cleared")
	}
}

func TestClearEnrichmentDiec(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-clear-diec-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	db.InsertEnrichment(model.Enrichment{Tool: "diec", Timestamp: time.Now(), RawOutput: "{}"})
	db.InsertPackerDetections([]model.PackerDetection{
		{Type: "compiler", Name: "GCC", Version: "11"},
	})

	if err := db.ClearEnrichment("diec"); err != nil {
		t.Fatalf("failed to clear diec: %v", err)
	}

	enrichments, _ := db.QueryEnrichments("diec")
	if len(enrichments) != 0 {
		t.Error("diec enrichment not cleared")
	}
	dets, _ := db.QueryPackerDetections("")
	if len(dets) != 0 {
		t.Error("packer detections not cleared")
	}
}

func TestClearEnrichmentFloss(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-clear-floss-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert both native strings and floss strings
	db.InsertStrings([]model.ExtractedString{
		{Value: "native_string", Offset: 100, Section: ".data", Encoding: "ascii"},
		{Value: "floss_decoded", Offset: 200, Section: "floss:decoded", Encoding: "utf-8"},
		{Value: "floss_stack", Offset: 300, Section: "floss:stack", Encoding: "ascii"},
	})
	db.InsertEnrichment(model.Enrichment{Tool: "floss", Timestamp: time.Now(), RawOutput: "{}"})

	if err := db.ClearEnrichment("floss"); err != nil {
		t.Fatalf("failed to clear floss: %v", err)
	}

	// Floss enrichment row should be gone
	enrichments, _ := db.QueryEnrichments("floss")
	if len(enrichments) != 0 {
		t.Error("floss enrichment not cleared")
	}

	// Floss strings should be gone, but native strings should survive
	strings, total, err := db.QueryStrings("", 100, 0)
	if err != nil {
		t.Fatalf("failed to query strings: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 remaining string (native), got %d", total)
	}
	if len(strings) != 1 || strings[0].Value != "native_string" {
		t.Errorf("expected native_string to survive, got %v", strings)
	}
}

func TestClearEnrichmentUnknownTool(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-clear-unknown-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	db.InsertEnrichment(model.Enrichment{Tool: "peframe", Timestamp: time.Now(), RawOutput: `{"some":"data"}`})

	if err := db.ClearEnrichment("peframe"); err != nil {
		t.Fatalf("failed to clear unknown tool: %v", err)
	}

	enrichments, _ := db.QueryEnrichments("peframe")
	if len(enrichments) != 0 {
		t.Error("unknown tool enrichment not cleared")
	}
}

func TestEnrichmentOverwrite(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-overwrite-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert first version
	db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: time.Now(),
		RawOutput: `{"version": 1}`,
	})

	// Overwrite with second version (INSERT OR REPLACE)
	err = db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: time.Now(),
		RawOutput: `{"version": 2}`,
	})
	if err != nil {
		t.Fatalf("failed to overwrite enrichment: %v", err)
	}

	// Should have exactly 1 row, not 2
	enrichments, _ := db.QueryEnrichments("capa")
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment after overwrite, got %d", len(enrichments))
	}
	if enrichments[0].RawOutput != `{"version": 2}` {
		t.Errorf("expected version 2 after overwrite, got %s", enrichments[0].RawOutput)
	}
}

func TestEnrichmentCaseNormalization(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-case-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert with uppercase tool name
	err = db.InsertEnrichment(model.Enrichment{
		Tool:      "CAPA",
		Timestamp: time.Now(),
		RawOutput: `{"rules": {}}`,
	})
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	// Should be stored as lowercase
	enrichments, _ := db.QueryEnrichments("")
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(enrichments))
	}
	if enrichments[0].Tool != "capa" {
		t.Errorf("expected tool stored as 'capa', got '%s'", enrichments[0].Tool)
	}

	// Query with uppercase should find it
	enrichments, _ = db.QueryEnrichments("CAPA")
	if len(enrichments) != 1 {
		t.Errorf("expected uppercase query to find enrichment, got %d results", len(enrichments))
	}

	// Query with mixed case should find it
	enrichments, _ = db.QueryEnrichments("Capa")
	if len(enrichments) != 1 {
		t.Errorf("expected mixed-case query to find enrichment, got %d results", len(enrichments))
	}
}

func TestCapabilitiesNilIDsRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-nil-ids-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert capability with nil slices (no ATT&CK, no MBC)
	err = db.InsertCapabilities([]model.Capability{
		{Name: "no ids", Namespace: "test"},
	})
	if err != nil {
		t.Fatalf("failed to insert capability with nil IDs: %v", err)
	}

	// Round-trip: query it back
	results, err := db.QueryCapabilities("", "")
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(results))
	}

	// Should get empty slices (not nil) thanks to emptyIfNil storing "[]"
	cap := results[0]
	if cap.AttackIDs == nil {
		t.Error("expected non-nil AttackIDs after round-trip (should be empty slice)")
	}
	if len(cap.AttackIDs) != 0 {
		t.Errorf("expected 0 AttackIDs, got %d", len(cap.AttackIDs))
	}
	if cap.MBCIDs == nil {
		t.Error("expected non-nil MBCIDs after round-trip (should be empty slice)")
	}
	if len(cap.MBCIDs) != 0 {
		t.Errorf("expected 0 MBCIDs, got %d", len(cap.MBCIDs))
	}
}
