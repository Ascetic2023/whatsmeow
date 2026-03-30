// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"bytes"
	"encoding/json"
	"testing"
)

const testBaileysJSON = `{"noiseKey":{"private":{"data":"sJudX1ApwK/Zfk7rcz0Ggs8fddG8sumt3JcXzFbE3mk=","type":"Buffer"},"public":{"data":"Zhd0vcBmd6+clDr677GQV/8uAU66cPz7AHWxa6CV6Sc=","type":"Buffer"}},"advSecretKey":"LjGnhpxD66Bpq6twdTglMNTcd6gtc8+dOptUc6wSQJA=","accountSyncCounter":0,"firstUnuploadedPreKeyId":61,"routingInfo":{"data":"CAsIDQgJ","type":"Buffer"},"nextPreKeyId":61,"pairingEphemeralKeyPair":{"private":{"data":"cOY00FlZBWyOBiEkIk1qURT1Otx9MqdwRHGVqiIr80c=","type":"Buffer"},"public":{"data":"GlgPVBzQv0sytMlWXEFAFGCB9GBeS/We3Qi4Yf3pcT8=","type":"Buffer"}},"lastAccountSyncTimestamp":1774524610,"registered":true,"platform":"smba","myAppStateKeyId":"AAAAAEkt","processedHistoryMessages":[],"lastPropHash":"3ml1jS","signedIdentityKey":{"private":{"data":"UDJQ+RzjbzO9GysXFFouwHWO2xMUvibhTCTTMwxp2XI=","type":"Buffer"},"public":{"data":"Hhbd0La0xn76UHpqyDAbOr6iwaeF1BGB+CVTKSihgh0=","type":"Buffer"}},"signedPreKey":{"signature":{"data":"2zrOUl8gZxcd5VgltEQGw+HvsmF65ByyDhuObFt7TTfyc8b0q6g9rd+UF74bBuqk3wrVm5AQX8kx5rtzbFMbDA==","type":"Buffer"},"keyId":1,"keyPair":{"private":{"data":"cJnGBaSfT4VV29ayXFNs7KG4Wg9Xux9HtzZxAHb4/ko=","type":"Buffer"},"public":{"data":"Z5xTZkNEMhfo7oEj1srg1JqTuiQe1eplO3yviqRXZj4=","type":"Buffer"}}},"Phone":"23280202340","registrationId":20,"me":{"lid":"257363802116289:1@lid","name":"SADLISH BBY","id":"23280202340:1@s.whatsapp.net"},"pairingCode":"77773333","accountSettings":{"unarchiveChats":false},"account":{"deviceSignature":"EmykRGyUiVUqbOfTe6fxJLjvRBZvUxCWR6pmpeXFW9sdCHrjks5UFnd1KtkipZHAlDqOsxXsthxiSwQxCzfvBw==","details":"CNDZn8wDELmxlM4GGAEgACgA","accountSignature":"V4NH8sLNjOtWeAV2H3+0IyxTvHlWi+k+fTOLJZSFOESHZnpvIbMTJQG1z63hwsb77CXEDqGTfuFy2pIzpD+uCA==","accountSignatureKey":"q2QxuhTNwVJOLDl098uV2uakimFgMddiSBXJxupqT18="},"signalIdentities":[{"identifier":{"name":"23280202340:1@s.whatsapp.net","deviceId":0},"identifierKey":{"data":"BatkMboUzcFSTiw5dPfLldrmpIphYDHXYkgVycbqak9f","type":"Buffer"}}]}`

func TestImportBaileysJSON(t *testing.T) {
	device, err := ImportBaileysJSON(testBaileysJSON)
	if err != nil {
		t.Fatalf("ImportBaileysJSON failed: %v", err)
	}

	// JID
	if device.ID.User != "23280202340" {
		t.Errorf("User: got %s, want 23280202340", device.ID.User)
	}
	if device.ID.Device != 1 {
		t.Errorf("Device: got %d, want 1", device.ID.Device)
	}
	if device.ID.Server != "s.whatsapp.net" {
		t.Errorf("Server: got %s, want s.whatsapp.net", device.ID.Server)
	}

	// LID
	if device.LID.User != "257363802116289" {
		t.Errorf("LID User: got %s, want 257363802116289", device.LID.User)
	}

	// PushName
	if device.PushName != "SADLISH BBY" {
		t.Errorf("PushName: got %q, want %q", device.PushName, "SADLISH BBY")
	}

	// Platform
	if device.Platform != "smba" {
		t.Errorf("Platform: got %q, want %q", device.Platform, "smba")
	}

	// RegistrationID
	if device.RegistrationID != 20 {
		t.Errorf("RegistrationID: got %d, want 20", device.RegistrationID)
	}

	// Keys should be non-nil with 32-byte values
	if device.NoiseKey == nil || device.NoiseKey.Pub == nil || device.NoiseKey.Priv == nil {
		t.Fatal("NoiseKey is incomplete")
	}
	if device.IdentityKey == nil || device.IdentityKey.Pub == nil || device.IdentityKey.Priv == nil {
		t.Fatal("IdentityKey is incomplete")
	}

	// SignedPreKey
	if device.SignedPreKey == nil {
		t.Fatal("SignedPreKey is nil")
	}
	if device.SignedPreKey.KeyID != 1 {
		t.Errorf("SignedPreKey.KeyID: got %d, want 1", device.SignedPreKey.KeyID)
	}
	if device.SignedPreKey.Signature == nil {
		t.Error("SignedPreKey.Signature is nil")
	}

	// AdvSecretKey
	if len(device.AdvSecretKey) != 32 {
		t.Errorf("AdvSecretKey: expected 32 bytes, got %d", len(device.AdvSecretKey))
	}

	// Account
	if device.Account == nil {
		t.Fatal("Account is nil")
	}
	if len(device.Account.Details) == 0 {
		t.Error("Account.Details is empty")
	}
	if len(device.Account.AccountSignature) != 64 {
		t.Errorf("Account.AccountSignature: expected 64, got %d", len(device.Account.AccountSignature))
	}
	if len(device.Account.AccountSignatureKey) != 32 {
		t.Errorf("Account.AccountSignatureKey: expected 32, got %d", len(device.Account.AccountSignatureKey))
	}
	if len(device.Account.DeviceSignature) != 64 {
		t.Errorf("Account.DeviceSignature: expected 64, got %d", len(device.Account.DeviceSignature))
	}
}

func TestExportBaileysJSON(t *testing.T) {
	device := makeTestDevice()
	device.PushName = "Test User"
	device.LID = makeTestDevice().LID // has LID set from makeTestDevice

	exported, err := ExportBaileysJSON(device)
	if err != nil {
		t.Fatalf("ExportBaileysJSON failed: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(exported), &parsed); err != nil {
		t.Fatalf("exported JSON is invalid: %v", err)
	}

	// Check key fields exist
	if _, ok := parsed["noiseKey"]; !ok {
		t.Error("missing noiseKey")
	}
	if _, ok := parsed["signedIdentityKey"]; !ok {
		t.Error("missing signedIdentityKey")
	}
	if _, ok := parsed["signedPreKey"]; !ok {
		t.Error("missing signedPreKey")
	}
	if parsed["registrationId"] != float64(12345) {
		t.Errorf("registrationId: got %v, want 12345", parsed["registrationId"])
	}
	if parsed["registered"] != true {
		t.Error("registered should be true")
	}

	// me.name
	me := parsed["me"].(map[string]any)
	if me["name"] != "Test User" {
		t.Errorf("me.name: got %v, want Test User", me["name"])
	}
}

func TestBaileysRoundTrip(t *testing.T) {
	// Import real Baileys JSON
	device, err := ImportBaileysJSON(testBaileysJSON)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Export back to JSON
	exported, err := ExportBaileysJSON(device)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Re-import
	device2, err := ImportBaileysJSON(exported)
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	// Verify all keys match
	if *device2.NoiseKey.Priv != *device.NoiseKey.Priv {
		t.Error("NoiseKey.Priv mismatch")
	}
	if *device2.IdentityKey.Priv != *device.IdentityKey.Priv {
		t.Error("IdentityKey.Priv mismatch")
	}
	if *device2.SignedPreKey.Priv != *device.SignedPreKey.Priv {
		t.Error("SignedPreKey.Priv mismatch")
	}
	if device2.RegistrationID != device.RegistrationID {
		t.Error("RegistrationID mismatch")
	}
	if !bytes.Equal(device2.AdvSecretKey, device.AdvSecretKey) {
		t.Error("AdvSecretKey mismatch")
	}
	if device2.ID.String() != device.ID.String() {
		t.Errorf("JID mismatch: %s vs %s", device2.ID.String(), device.ID.String())
	}
	if !bytes.Equal(device2.Account.Details, device.Account.Details) {
		t.Error("Account.Details mismatch")
	}
}

func TestBaileysToTransferCode(t *testing.T) {
	// Import Baileys JSON → export as six-segment code
	device, err := ImportBaileysJSON(testBaileysJSON)
	if err != nil {
		t.Fatalf("ImportBaileysJSON failed: %v", err)
	}

	code, err := ExportTransferCode(device)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	// Re-import from six-segment code
	device2, err := ImportTransferCode(code)
	if err != nil {
		t.Fatalf("ImportTransferCode failed: %v", err)
	}

	// Core keys should match
	if *device2.NoiseKey.Priv != *device.NoiseKey.Priv {
		t.Error("NoiseKey mismatch after Baileys→TransferCode conversion")
	}
	if *device2.IdentityKey.Priv != *device.IdentityKey.Priv {
		t.Error("IdentityKey mismatch after Baileys→TransferCode conversion")
	}
	if device2.ID.User != device.ID.User {
		t.Error("Phone mismatch")
	}
}
