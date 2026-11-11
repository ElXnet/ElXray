package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrototypeDoesNotLeakRawHWIDOrGrantPayload(t *testing.T) {
	const input = `{"profileId":"12345678-1234-4abc-8def-123456789abc","hwid":"machine-demo-01"}`
	var output bytes.Buffer
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "machine-demo-01") {
		t.Fatal("raw device HWID leaked in output")
	}
	var result deviceResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.PayloadAuthorized || result.Status != "observed-only" ||
		len(result.HWIDFingerprint) != 64 {
		t.Fatalf("demo incorrectly claims authorization: %+v", result)
	}
	output.Reset()
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var another deviceResult
	if err := json.Unmarshal(output.Bytes(), &another); err != nil {
		t.Fatal(err)
	}
	if result != another {
		t.Fatal("same supported device changed identity")
	}
}

func TestPrototypeRejectsUntrustedOrMultipleJSONObjects(t *testing.T) {
	for _, input := range []string{
		`{"profileId":"oops","hwid":"device"}`,
		`{"profileId":"12345678-1234-4abc-8def-123456789abc","hwid":""}`,
		`{"profileId":"12345678-1234-4abc-8def-123456789abc","hwid":"x","authorized":true}`,
		`{"profileId":"12345678-1234-4abc-8def-123456789abc","hwid":"x"} {}`,
		strings.Repeat("x", 4098),
		`{"profileId":"12345678-1234-4abc-8def-123456789abc","hwid":"x"}` + strings.Repeat(" ", 4096),
	} {
		if err := run(strings.NewReader(input), &bytes.Buffer{}); err == nil {
			t.Fatalf("untrusted input accepted: %q", input)
		}
	}
}
