// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

func makeTestDevice() *Device {
	noiseKey := keys.NewKeyPair()
	identityKey := keys.NewKeyPair()
	signedPreKey := identityKey.CreateSignedPreKey(42)
	jid := types.JID{User: "8613800138000", Device: 2, Server: types.DefaultUserServer}
	lid := types.JID{User: "123456", Device: 1, Server: types.HiddenUserServer}
	advDetails := []byte{10, 2, 8, 1, 16, 100, 24, 1}

	return &Device{
		NoiseKey:       noiseKey,
		IdentityKey:    identityKey,
		SignedPreKey:   signedPreKey,
		RegistrationID: 12345,
		AdvSecretKey:   bytes.Repeat([]byte{0xAB}, 32),
		ID:             &jid,
		LID:            lid,
		Account: &waAdv.ADVSignedDeviceIdentity{
			Details:             advDetails,
			AccountSignatureKey: bytes.Repeat([]byte{0xCC}, 32),
			AccountSignature:    bytes.Repeat([]byte{0xDD}, 64),
			DeviceSignature:     bytes.Repeat([]byte{0xEE}, 64),
		},
		Platform:              "Chrome (Linux)",
		FacebookUUID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
		LIDMigrationTimestamp: 1711612800,
	}
}

func TestExportImportTransferCode(t *testing.T) {
	original := makeTestDevice()
	code, err := ExportTransferCode(original)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	// Verify six-segment format
	segments := splitTransferCode(code)
	if len(segments) != 6 {
		t.Fatalf("expected 6 segments, got %d", len(segments))
	}

	restored, err := ImportTransferCode(code)
	if err != nil {
		t.Fatalf("ImportTransferCode failed: %v", err)
	}

	// Compare keys
	if *restored.NoiseKey.Priv != *original.NoiseKey.Priv {
		t.Error("NoiseKey private key mismatch")
	}
	if *restored.NoiseKey.Pub != *original.NoiseKey.Pub {
		t.Error("NoiseKey public key mismatch")
	}
	if *restored.IdentityKey.Priv != *original.IdentityKey.Priv {
		t.Error("IdentityKey private key mismatch")
	}
	if *restored.IdentityKey.Pub != *original.IdentityKey.Pub {
		t.Error("IdentityKey public key mismatch")
	}
	if *restored.SignedPreKey.Priv != *original.SignedPreKey.Priv {
		t.Error("SignedPreKey private key mismatch")
	}
	if *restored.SignedPreKey.Pub != *original.SignedPreKey.Pub {
		t.Error("SignedPreKey public key mismatch")
	}
	if restored.SignedPreKey.KeyID != original.SignedPreKey.KeyID {
		t.Errorf("SignedPreKey KeyID mismatch: got %d, want %d", restored.SignedPreKey.KeyID, original.SignedPreKey.KeyID)
	}
	if *restored.SignedPreKey.Signature != *original.SignedPreKey.Signature {
		t.Error("SignedPreKey Signature mismatch")
	}
	if restored.RegistrationID != original.RegistrationID {
		t.Errorf("RegistrationID mismatch: got %d, want %d", restored.RegistrationID, original.RegistrationID)
	}
	if !bytes.Equal(restored.AdvSecretKey, original.AdvSecretKey) {
		t.Error("AdvSecretKey mismatch")
	}

	// Compare JID/LID
	if restored.ID.String() != original.ID.String() {
		t.Errorf("JID mismatch: got %s, want %s", restored.ID.String(), original.ID.String())
	}
	if restored.LID.String() != original.LID.String() {
		t.Errorf("LID mismatch: got %s, want %s", restored.LID.String(), original.LID.String())
	}

	// Compare Account
	if !bytes.Equal(restored.Account.Details, original.Account.Details) {
		t.Error("Account.Details mismatch")
	}
	if !bytes.Equal(restored.Account.AccountSignatureKey, original.Account.AccountSignatureKey) {
		t.Error("Account.AccountSignatureKey mismatch")
	}
	if !bytes.Equal(restored.Account.AccountSignature, original.Account.AccountSignature) {
		t.Error("Account.AccountSignature mismatch")
	}
	if !bytes.Equal(restored.Account.DeviceSignature, original.Account.DeviceSignature) {
		t.Error("Account.DeviceSignature mismatch")
	}

	// Compare metadata
	if restored.Platform != original.Platform {
		t.Errorf("Platform mismatch: got %q, want %q", restored.Platform, original.Platform)
	}
	if restored.FacebookUUID != original.FacebookUUID {
		t.Errorf("FacebookUUID mismatch: got %s, want %s", restored.FacebookUUID, original.FacebookUUID)
	}
	if restored.LIDMigrationTimestamp != original.LIDMigrationTimestamp {
		t.Errorf("LIDMigrationTimestamp mismatch: got %d, want %d", restored.LIDMigrationTimestamp, original.LIDMigrationTimestamp)
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

func TestImportTransferCode_InvalidBase64(t *testing.T) {
	_, err := ImportTransferCode("!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestImportTransferCode_CorruptedChecksum(t *testing.T) {
	device := makeTestDevice()
	code, err := ExportTransferCode(device)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	// Flip a character in the first segment to corrupt the data
	runes := []rune(code)
	for i, r := range runes {
		if r != '.' {
			if r == 'A' {
				runes[i] = 'B'
			} else {
				runes[i] = 'A'
			}
			break
		}
	}
	corrupted := string(runes)

	_, err = ImportTransferCode(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted transfer code")
	}
}

func TestImportTransferCode_TooShort(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	_, err := ImportTransferCode(short)
	if err == nil {
		t.Fatal("expected error for too-short transfer code")
	}
}

func TestImportTransferCode_WrongVersion(t *testing.T) {
	device := makeTestDevice()
	code, err := ExportTransferCode(device)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}

	// Decode, change version byte, re-encode with correct checksum
	joined := strings.ReplaceAll(code, ".", "")
	data, _ := base64.RawURLEncoding.DecodeString(joined)
	payload := data[:len(data)-4]
	payload[0] = 99 // wrong version

	checksum := crc32.ChecksumIEEE(payload)
	checksumBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBuf, checksum)
	newData := append(payload, checksumBuf...)

	reencoded := base64.RawURLEncoding.EncodeToString(newData)
	_, err = ImportTransferCode(reencoded)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestExportTransferCode_ZeroFacebookUUID(t *testing.T) {
	device := makeTestDevice()
	device.FacebookUUID = uuid.Nil
	code, err := ExportTransferCode(device)
	if err != nil {
		t.Fatalf("ExportTransferCode failed: %v", err)
	}
	restored, err := ImportTransferCode(code)
	if err != nil {
		t.Fatalf("ImportTransferCode failed: %v", err)
	}
	if restored.FacebookUUID != uuid.Nil {
		t.Errorf("expected nil UUID, got %s", restored.FacebookUUID)
	}
}
