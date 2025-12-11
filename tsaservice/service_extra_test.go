package tsaservice

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestVerifyEUDSS(t *testing.T) {
	// 1. Read the info.txt file
	content, err := os.ReadFile("../eudss/info.txt")
	if err != nil {
		t.Fatalf("Failed to read info.txt: %v", err)
	}

	// 2. Parse the file to extract the certificate
	// The file contains a URL on the first line, then a blank line, then JSON.
	// We need to find the start of the JSON object.
	lines := strings.Split(string(content), "\n")
	var jsonPart string
	for i, line := range lines {
		if strings.TrimSpace(line) == "{" {
			// Join with empty string to handle multiline string literal in info.txt
			// provided existing newlines are not meaningful for other fields (which is true for JSON structure)
			jsonPart = strings.Join(lines[i:], "")
			break
		}
	}

	if jsonPart == "" {
		t.Fatal("Could not find JSON part in info.txt")
	}

	// We can reuse the struct defined in service.go or a simplified one
	var req EUDSSVerifyCertificateRequest
	if err := json.Unmarshal([]byte(jsonPart), &req); err != nil {
		t.Fatalf("Failed to parse JSON from info.txt: %v", err)
	}

	cert := req.Certificate.EncodedCertificate
	if cert == "" {
		t.Fatal("Certificate not found in info.txt")
	}

	// 3. Initialize the service
	svc, err := NewTSAService("", "", "", "")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// 4. Call VerifyEUDSS
	resp, err := svc.VerifyEUDSS([]byte(cert))
	if err != nil {
		t.Fatalf("VerifyEUDSS failed: %v", err)
	}

	// 5. Validate success status (implied by err == nil, but let's be sure about the content if needed,
	// though the requirement is just 'successful status' which usually means the HTTP call didn't return error
	// and VerifyEUDSS returns error on non-200)

	// 6. Validate response is JSON
	if !json.Valid(resp) {
		t.Error("Response is not valid JSON")
	}
}
