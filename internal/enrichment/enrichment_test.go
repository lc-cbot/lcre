package enrichment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapaParser(t *testing.T) {
	capaJSON := `{
		"rules": {
			"create process": {
				"meta": {
					"name": "create process",
					"namespace": "host-interaction/process/create",
					"authors": ["author@example.com"],
					"scopes": {"static": "function", "dynamic": "process"},
					"att&ck": [{"technique": "Execution", "subtechnique": "", "id": "T1106"}],
					"mbc": [{"objective": "Process", "behavior": "Create Process", "id": "C0017"}]
				},
				"source": "test"
			},
			"encrypt data": {
				"meta": {
					"name": "encrypt data using AES",
					"namespace": "data-manipulation/encryption/aes",
					"authors": ["test"],
					"scopes": {"static": "basic block"},
					"att&ck": [{"technique": "Data Encrypted for Impact", "subtechnique": "", "id": "T1486"}],
					"mbc": []
				},
				"source": "test"
			}
		}
	}`

	result, err := parseFromString(t, "capa", capaJSON)
	if err != nil {
		t.Fatalf("failed to parse capa output: %v", err)
	}

	if len(result.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(result.Capabilities))
	}

	// Find the "create process" capability
	var found bool
	for _, cap := range result.Capabilities {
		if cap.Name == "create process" {
			found = true
			if cap.Namespace != "host-interaction/process/create" {
				t.Errorf("expected namespace 'host-interaction/process/create', got '%s'", cap.Namespace)
			}
			if len(cap.AttackIDs) != 1 || cap.AttackIDs[0] != "T1106" {
				t.Errorf("expected ATT&CK ID T1106, got %v", cap.AttackIDs)
			}
			if len(cap.MBCIDs) != 1 || cap.MBCIDs[0] != "C0017" {
				t.Errorf("expected MBC ID C0017, got %v", cap.MBCIDs)
			}
		}
	}
	if !found {
		t.Error("'create process' capability not found in results")
	}
}

func TestDIECParser(t *testing.T) {
	// Real diec --json output: {"detects": [{"filetype": "...", "values": [...]}]}
	diecJSON := `{
		"detects": [
			{
				"filetype": "PE64",
				"parentfilepart": "Header",
				"values": [
					{
						"type": "Linker",
						"name": "Microsoft Linker",
						"string": "Linker: Microsoft Linker(14.16.27412)",
						"version": "14.16.27412"
					},
					{
						"type": "Compiler",
						"name": "Microsoft Visual C/C++",
						"string": "Compiler: Microsoft Visual C/C++(19.16.27412)[LTCG/C]",
						"version": "19.16.27412"
					}
				]
			}
		]
	}`

	result, err := parseFromString(t, "diec", diecJSON)
	if err != nil {
		t.Fatalf("failed to parse diec output: %v", err)
	}

	if len(result.Detections) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(result.Detections))
	}

	if result.Detections[0].Type != "Linker" {
		t.Errorf("expected type 'Linker', got '%s'", result.Detections[0].Type)
	}
	if result.Detections[1].Name != "Microsoft Visual C/C++" {
		t.Errorf("expected name 'Microsoft Visual C/C++', got '%s'", result.Detections[1].Name)
	}
}

func TestDIECParserMultipleFileGroups(t *testing.T) {
	// diec output with multiple file groups (e.g., SFX with embedded archive)
	diecJSON := `{
		"detects": [
			{
				"filetype": "PE32",
				"values": [
					{"type": "Compiler", "name": "GCC", "string": "GCC(8.3.0)", "version": "8.3.0"}
				]
			},
			{
				"filetype": "ZIP",
				"values": [
					{"type": "Archive", "name": "ZIP", "string": "Archive: ZIP(2.0)", "version": "2.0"}
				]
			}
		]
	}`

	result, err := parseFromString(t, "diec", diecJSON)
	if err != nil {
		t.Fatalf("failed to parse multi-group diec output: %v", err)
	}

	if len(result.Detections) != 2 {
		t.Fatalf("expected 2 detections across groups, got %d", len(result.Detections))
	}
	if result.Detections[0].Name != "GCC" {
		t.Errorf("expected name 'GCC', got '%s'", result.Detections[0].Name)
	}
	if result.Detections[1].Name != "ZIP" {
		t.Errorf("expected name 'ZIP', got '%s'", result.Detections[1].Name)
	}
}

func TestDIECParserEmptyDetects(t *testing.T) {
	diecJSON := `{"detects": []}`

	result, err := parseFromString(t, "diec", diecJSON)
	if err != nil {
		t.Fatalf("failed to parse empty diec output: %v", err)
	}
	if len(result.Detections) != 0 {
		t.Errorf("expected 0 detections, got %d", len(result.Detections))
	}
}

func TestFLOSSParser(t *testing.T) {
	flossJSON := `{
		"strings": {
			"static_strings": [
				{"string": "kernel32.dll", "offset": 100, "encoding": "ascii"}
			],
			"stack_strings": [
				{"string": "secret_key_123", "offset": 200, "encoding": "utf-8"}
			],
			"tight_strings": [
				{"string": "config.dat", "offset": 300, "encoding": "ascii"}
			],
			"decoded_strings": [
				{"string": "http://evil.com/c2", "offset": 400, "encoding": "utf-16le"},
				{"string": "password123", "offset": 500, "encoding": "ascii"}
			]
		}
	}`

	result, err := parseFromString(t, "floss", flossJSON)
	if err != nil {
		t.Fatalf("failed to parse floss output: %v", err)
	}

	// FLOSS parser imports stack, tight, and decoded strings — not static
	// (static strings are redundant with native extraction)
	if len(result.Strings) != 4 {
		t.Fatalf("expected 4 strings (1 stack + 1 tight + 2 decoded), got %d", len(result.Strings))
	}

	// Check that sections are tagged correctly
	for _, s := range result.Strings {
		if s.Section == "" {
			t.Errorf("string '%s' has empty section, expected floss:* prefix", s.Value)
		}
	}
}

func TestCapaParserAttackKey(t *testing.T) {
	// Newer capa versions use "attack" instead of "att&ck"
	capaJSON := `{
		"rules": {
			"link function at runtime": {
				"meta": {
					"name": "link function at runtime on Windows",
					"namespace": "linking/runtime-linking",
					"authors": ["test@example.com"],
					"scopes": {"static": "instruction", "dynamic": "call"},
					"attack": [{"tactic": "Execution", "technique": "Shared Modules", "subtechnique": "", "id": "T1129"}],
					"mbc": []
				},
				"source": "test"
			}
		}
	}`

	result, err := parseFromString(t, "capa", capaJSON)
	if err != nil {
		t.Fatalf("failed to parse capa output with 'attack' key: %v", err)
	}

	if len(result.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(result.Capabilities))
	}
	if len(result.Capabilities[0].AttackIDs) != 1 || result.Capabilities[0].AttackIDs[0] != "T1129" {
		t.Errorf("expected ATT&CK ID T1129 via 'attack' key, got %v", result.Capabilities[0].AttackIDs)
	}
}

func TestUnknownToolPreservesRawJSON(t *testing.T) {
	rawJSON := `{"some": "data", "nested": {"key": "value"}}`

	result, err := parseFromString(t, "unknown_tool", rawJSON)
	if err != nil {
		t.Fatalf("failed to parse unknown tool output: %v", err)
	}

	if result.RawJSON != rawJSON {
		t.Error("raw JSON not preserved for unknown tool")
	}
	if len(result.Capabilities) != 0 {
		t.Error("unexpected capabilities for unknown tool")
	}
}

func TestDIECParserWithWarningPrefix(t *testing.T) {
	// Real diec output often has warning lines before the JSON
	diecOutput := `[!] Heuristic scan is disabled. Use '--heuristicscan' to enable
{
	"detects": [
		{
			"filetype": "PE64",
			"values": [
				{"type": "Compiler", "name": "GCC", "string": "GCC(10.0)", "version": "10.0"}
			]
		}
	]
}`

	result, err := parseFromString(t, "diec", diecOutput)
	if err != nil {
		t.Fatalf("failed to parse diec output with warning prefix: %v", err)
	}
	if len(result.Detections) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(result.Detections))
	}
	if result.Detections[0].Name != "GCC" {
		t.Errorf("expected name 'GCC', got '%s'", result.Detections[0].Name)
	}
}

func TestDedicatedParserRejectsNonJSON(t *testing.T) {
	// Dedicated parsers (capa, diec, floss) still require JSON
	_, err := parseFromString(t, "capa", "not json at all")
	if err == nil {
		t.Error("expected error for non-JSON input to capa parser, got nil")
	}
}

func TestUnknownToolAcceptsPlainText(t *testing.T) {
	plainText := `ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64`

	result, err := parseFromString(t, "readelf", plainText)
	if err != nil {
		t.Fatalf("expected plain text to be accepted for unknown tool, got error: %v", err)
	}

	if result.RawJSON != plainText {
		t.Error("raw text output not preserved")
	}
	if len(result.Capabilities) != 0 {
		t.Error("unexpected capabilities for text-only tool")
	}
	if len(result.Detections) != 0 {
		t.Error("unexpected detections for text-only tool")
	}
}

func TestCapaParserEmptyRules(t *testing.T) {
	result, err := parseFromString(t, "capa", `{"rules": {}}`)
	if err != nil {
		t.Fatalf("failed to parse empty capa rules: %v", err)
	}
	if len(result.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(result.Capabilities))
	}
}

func TestCapaParserMinimalRule(t *testing.T) {
	// Rule with no authors, no ATT&CK, no MBC — only name and namespace
	capaJSON := `{
		"rules": {
			"minimal": {
				"meta": {
					"name": "minimal rule",
					"namespace": "test",
					"authors": [],
					"scopes": {"static": "", "dynamic": ""},
					"att&ck": [],
					"mbc": []
				},
				"source": "test"
			}
		}
	}`
	result, err := parseFromString(t, "capa", capaJSON)
	if err != nil {
		t.Fatalf("failed to parse minimal capa rule: %v", err)
	}
	if len(result.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(result.Capabilities))
	}
	cap := result.Capabilities[0]
	if cap.Name != "minimal rule" {
		t.Errorf("expected name 'minimal rule', got '%s'", cap.Name)
	}
	if cap.Author != "" {
		t.Errorf("expected empty author, got '%s'", cap.Author)
	}
	if len(cap.AttackIDs) != 0 {
		t.Errorf("expected no ATT&CK IDs, got %v", cap.AttackIDs)
	}
	if len(cap.MBCIDs) != 0 {
		t.Errorf("expected no MBC IDs, got %v", cap.MBCIDs)
	}
}

func TestFLOSSParserIntegerFunction(t *testing.T) {
	// Real floss output has "function" as an integer (address), not a string.
	// This is the bug that json.RawMessage fixed.
	flossJSON := `{
		"strings": {
			"static_strings": [],
			"stack_strings": [
				{"string": "decoded_secret", "offset": 42, "encoding": "ascii", "function": 6442546304}
			],
			"tight_strings": [],
			"decoded_strings": [
				{"string": "another_secret", "offset": 99, "encoding": "utf-8", "function": "sub_401000"}
			]
		}
	}`
	result, err := parseFromString(t, "floss", flossJSON)
	if err != nil {
		t.Fatalf("failed to parse floss with integer function field: %v", err)
	}
	if len(result.Strings) != 2 {
		t.Fatalf("expected 2 strings, got %d", len(result.Strings))
	}
	if result.Strings[0].Value != "decoded_secret" {
		t.Errorf("expected 'decoded_secret', got '%s'", result.Strings[0].Value)
	}
}

func TestFLOSSParserEmptySections(t *testing.T) {
	flossJSON := `{
		"strings": {
			"static_strings": [],
			"stack_strings": [],
			"tight_strings": [],
			"decoded_strings": []
		}
	}`
	result, err := parseFromString(t, "floss", flossJSON)
	if err != nil {
		t.Fatalf("failed to parse empty floss output: %v", err)
	}
	if len(result.Strings) != 0 {
		t.Errorf("expected 0 strings, got %d", len(result.Strings))
	}
}

func TestExtractJSONArrayWithPrefix(t *testing.T) {
	// Some tools output a JSON array with warning text before it
	input := []byte("WARNING: something\n[{\"key\": \"value\"}]")
	result := extractJSON(input)
	if result == nil {
		t.Fatal("extractJSON returned nil for array with prefix")
	}
	if string(result) != `[{"key": "value"}]` {
		t.Errorf("expected array JSON, got '%s'", string(result))
	}
}

func TestExtractJSONNoValidJSON(t *testing.T) {
	result := extractJSON([]byte("this is just plain text with no JSON"))
	if result != nil {
		t.Errorf("expected nil for non-JSON input, got '%s'", string(result))
	}
}

func TestExtractJSONAlreadyValid(t *testing.T) {
	input := []byte(`{"valid": true}`)
	result := extractJSON(input)
	if string(result) != string(input) {
		t.Errorf("expected input returned as-is, got '%s'", string(result))
	}
}

func TestParseToolOutputFileNotFound(t *testing.T) {
	_, err := ParseToolOutput("capa", "/nonexistent/path/file.json")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// parseFromString is a test helper that writes data to a temp file and parses it.
func parseFromString(t *testing.T, tool, data string) (*Result, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "output.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return nil, err
	}
	return ParseToolOutput(tool, path)
}
