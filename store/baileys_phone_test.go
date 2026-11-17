// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"strings"
	"testing"
)

// Some third-party exports serialize "Phone" as a bare JSON number instead of a string.
func TestImportBaileysJSONNumericPhone(t *testing.T) {
	numeric := strings.Replace(testBaileysJSON, `"Phone":"23280202340"`, `"Phone":23280202340`, 1)
	if numeric == testBaileysJSON {
		t.Fatal("fixture did not contain the expected Phone field")
	}

	device, err := ImportBaileysJSON(numeric)
	if err != nil {
		t.Fatalf("ImportBaileysJSON failed with numeric Phone: %v", err)
	}
	if device.ID.User != "23280202340" || device.ID.Device != 1 {
		t.Errorf("JID: got %s, want 23280202340:1@s.whatsapp.net", device.ID)
	}

	// Without me.id the JID falls back to Phone, which must come out as the exact digits.
	noMeID := strings.Replace(numeric, `"id":"23280202340:1@s.whatsapp.net"`, `"id":""`, 1)
	if noMeID == numeric {
		t.Fatal("fixture did not contain the expected me.id field")
	}
	device, err = ImportBaileysJSON(noMeID)
	if err != nil {
		t.Fatalf("ImportBaileysJSON failed with numeric Phone and empty me.id: %v", err)
	}
	if device.ID.User != "23280202340" || device.ID.Device != 0 {
		t.Errorf("fallback JID: got %s, want 23280202340@s.whatsapp.net", device.ID)
	}
}

func TestBaileysStringRejectsInvalid(t *testing.T) {
	for _, in := range []string{`true`, `{}`, `[]`} {
		var s baileysString
		if err := s.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("expected error for %s, got %q", in, s)
		}
	}
	for in, want := range map[string]string{`null`: "", `"8613800000000"`: "8613800000000", `916006302379`: "916006302379"} {
		var s baileysString
		if err := s.UnmarshalJSON([]byte(in)); err != nil || string(s) != want {
			t.Errorf("UnmarshalJSON(%s) = %q, %v; want %q", in, s, err, want)
		}
	}
}

// Export must keep writing Phone as a JSON string for compatibility with Baileys.
func TestExportBaileysJSONPhoneIsString(t *testing.T) {
	device, err := ImportBaileysJSON(testBaileysJSON)
	if err != nil {
		t.Fatalf("ImportBaileysJSON failed: %v", err)
	}
	out, err := ExportBaileysJSON(device)
	if err != nil {
		t.Fatalf("ExportBaileysJSON failed: %v", err)
	}
	if !strings.Contains(out, `"Phone": "23280202340"`) {
		t.Errorf("exported Phone is not a JSON string:\n%s", out)
	}
}
