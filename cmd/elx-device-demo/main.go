// elx-device-demo exercises the client-side UUID+HWID representation.
// It is not a VPN client and it never authorizes network traffic.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/elxdevice"
)

type deviceInput struct {
	ProfileID string `json:"profileId"`
	HWID      string `json:"hwid"`
}

type deviceResult struct {
	ProfileID         string `json:"profileId"`
	HWIDFingerprint   string `json:"hwidFingerprint"`
	Status            string `json:"status"`
	PayloadAuthorized bool   `json:"payloadAuthorized"`
}

func run(input io.Reader, output io.Writer) error {
	if input == nil || output == nil {
		return errors.New("input and output required")
	}
	// Reject oversized input instead of silently accepting valid JSON
	// followed by bytes beyond an io.LimitReader boundary.
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.New("device input exceeds 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request deviceInput
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("invalid device input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing or oversized device input")
	}
	key, err := elxdevice.Parse(request.ProfileID, request.HWID)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(deviceResult{
		ProfileID:         strings.ToLower(request.ProfileID),
		HWIDFingerprint:   key.HWIDFingerprint(),
		Status:            "observed-only",
		PayloadAuthorized: false,
	})
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "device identity demo:", err)
		os.Exit(1)
	}
}
