// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

func makeTestDevice() *Device {
	noiseKey := keys.NewKeyPair()
	identityKey := keys.NewKeyPair()
	signedPreKey := identityKey.CreateSignedPreKey(42)
	jid := types.JID{User: "8613800138000", Device: 2, Server: types.DefaultUserServer}

	return &Device{
		NoiseKey:       noiseKey,
		IdentityKey:    identityKey,
		SignedPreKey:   signedPreKey,
		RegistrationID: 12345,
		AdvSecretKey:   bytes.Repeat([]byte{0xAB}, 32),
		ID:             &jid,
		Account: &waAdv.ADVSignedDeviceIdentity{
			Details:             []byte{10, 2, 8, 1},
			AccountSignatureKey: bytes.Repeat([]byte{0xCC}, 32),
			AccountSignature:    bytes.Repeat([]byte{0xDD}, 64),
			DeviceSignature:     bytes.Repeat([]byte{0xEE}, 64),
		},
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	original := makeTestDevice()
	code, err := ExportTransferCode(original)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	// Verify comma-separated six-segment format
	segments := strings.Split(code, ",")
	if len(segments) != 6 {
		t.Fatalf("expected 6 segments, got %d", len(segments))
	}
	if segments[0] != "8613800138000" {
		t.Errorf("segment 1: expected phone number, got %q", segments[0])
	}

	restored, err := ImportTransferCode(code)
	if err != nil {
		t.Fatalf("ImportTransferCode failed: %v", err)
	}

	// NoiseKey round-trip
	if *restored.NoiseKey.Pub != *original.NoiseKey.Pub {
		t.Error("NoiseKey public key mismatch")
	}
	if *restored.NoiseKey.Priv != *original.NoiseKey.Priv {
		t.Error("NoiseKey private key mismatch")
	}

	// IdentityKey round-trip
	if *restored.IdentityKey.Pub != *original.IdentityKey.Pub {
		t.Error("IdentityKey public key mismatch")
	}
	if *restored.IdentityKey.Priv != *original.IdentityKey.Priv {
		t.Error("IdentityKey private key mismatch")
	}

	// JID round-trip
	if restored.ID.User != original.ID.User {
		t.Errorf("JID User mismatch: got %s, want %s", restored.ID.User, original.ID.User)
	}
	if restored.ID.Device != original.ID.Device {
		t.Errorf("JID Device mismatch: got %d, want %d", restored.ID.Device, original.ID.Device)
	}

	// RegistrationID round-trip
	if restored.RegistrationID != original.RegistrationID {
		t.Errorf("RegistrationID mismatch: got %d, want %d", restored.RegistrationID, original.RegistrationID)
	}

	// AdvSecretKey round-trip
	if !bytes.Equal(restored.AdvSecretKey, original.AdvSecretKey) {
		t.Error("AdvSecretKey mismatch")
	}

	// SignedPreKey is regenerated with same KeyID (but different random key pair)
	if restored.SignedPreKey == nil {
		t.Fatal("SignedPreKey is nil")
	}
	if restored.SignedPreKey.KeyID != original.SignedPreKey.KeyID {
		t.Errorf("SignedPreKey KeyID mismatch: got %d, want %d", restored.SignedPreKey.KeyID, original.SignedPreKey.KeyID)
	}
	if restored.SignedPreKey.Pub == nil || restored.SignedPreKey.Priv == nil {
		t.Error("SignedPreKey keys are nil")
	}
	if restored.SignedPreKey.Signature == nil {
		t.Error("SignedPreKey Signature is nil")
	}

	// Account should be empty but non-nil
	if restored.Account == nil {
		t.Fatal("Account is nil")
	}
}

func TestExportFormat(t *testing.T) {
	device := makeTestDevice()
	code, err := ExportTransferCode(device)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	segments := strings.Split(code, ",")

	// Segment 2-5 should be valid base64 encoding 32 bytes each
	for i := 1; i <= 4; i++ {
		data, err := base64.StdEncoding.DecodeString(segments[i])
		if err != nil {
			t.Errorf("segment %d: invalid base64: %v", i+1, err)
		}
		if len(data) != 32 {
			t.Errorf("segment %d: expected 32 bytes, got %d", i+1, len(data))
		}
	}

	// Segment 6 should be valid base64
	seg6, err := base64.StdEncoding.DecodeString(segments[5])
	if err != nil {
		t.Errorf("segment 6: invalid base64: %v", err)
	}
	// Should contain phone + '#' + 42 bytes
	expectedPrefix := "8613800138000#"
	if !strings.HasPrefix(string(seg6), expectedPrefix) {
		t.Errorf("segment 6: expected prefix %q, got %q...", expectedPrefix, string(seg6[:min(len(seg6), 20)]))
	}
}

func TestImportExternalCode(t *testing.T) {
	// Real-world format from external tool
	code := "19549193970,bD7XmH3mLWOQ2ogQDXX7P2JY8QSnYH69x3kn5pAVQmo=,yPhLJnlAKlONQvMWFx3f91whxyXDWQoaIjMFa8gI8FM=,xm8owsrVPS2qr15t/bddWovaWrkadyqG9kodCHUuu2c=,6BeKN2Oz5V3nmhmCD46DtbWVMCHbAdXgiHf1YYYRG0Q=,bnwjalkTFzuW2STTlT1iog=="

	device, err := ImportTransferCode(code)
	if err != nil {
		t.Fatalf("ImportTransferCode failed: %v", err)
	}

	// Verify phone
	if device.ID.User != "19549193970" {
		t.Errorf("phone: got %s, want 19549193970", device.ID.User)
	}

	// NoiseKey should match segment 2 public key
	expectedNoisePub, _ := base64.StdEncoding.DecodeString("bD7XmH3mLWOQ2ogQDXX7P2JY8QSnYH69x3kn5pAVQmo=")
	if !bytes.Equal(device.NoiseKey.Pub[:], expectedNoisePub) {
		t.Error("NoiseKey.Pub mismatch")
	}

	// IdentityKey should match segment 4 public key
	expectedIdentityPub, _ := base64.StdEncoding.DecodeString("xm8owsrVPS2qr15t/bddWovaWrkadyqG9kodCHUuu2c=")
	if !bytes.Equal(device.IdentityKey.Pub[:], expectedIdentityPub) {
		t.Error("IdentityKey.Pub mismatch")
	}

	// External format — seg6 not our format, so defaults used
	// Device should still have valid defaults
	if device.SignedPreKey == nil {
		t.Fatal("SignedPreKey should be generated")
	}
	if device.Account == nil {
		t.Fatal("Account should be non-nil")
	}
	if len(device.AdvSecretKey) != 32 {
		t.Errorf("AdvSecretKey: expected 32 bytes, got %d", len(device.AdvSecretKey))
	}
	if device.RegistrationID == 0 {
		t.Log("RegistrationID is 0 (may be random default)")
	}
}

func TestExportTransferCode_NilDevice(t *testing.T) {
	_, err := ExportTransferCode(nil)
	if err == nil {
		t.Fatal("expected error for nil device")
	}
}

func TestExportTransferCode_NoJID(t *testing.T) {
	device := makeTestDevice()
	device.ID = nil
	_, err := ExportTransferCode(device)
	if err == nil {
		t.Fatal("expected error for device with no JID")
	}
}

func TestImportTransferCode_WrongSegmentCount(t *testing.T) {
	_, err := ImportTransferCode("only,three,segments")
	if err == nil {
		t.Fatal("expected error for wrong segment count")
	}
}

func TestImportTransferCode_InvalidBase64(t *testing.T) {
	_, err := ImportTransferCode("12345,!!!,valid,valid,valid,valid")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestImportTransferCode_WrongKeyLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
	_, err := ImportTransferCode("12345," + short + "," + valid + "," + valid + "," + valid + "," + valid)
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestImportTransferCode_EmptyPhone(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
	_, err := ImportTransferCode("," + valid + "," + valid + "," + valid + "," + valid + "," + valid)
	if err == nil {
		t.Fatal("expected error for empty phone")
	}
}
