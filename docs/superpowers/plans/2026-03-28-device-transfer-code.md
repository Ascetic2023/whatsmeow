# Device Transfer Code (Six-Segment) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable exporting a paired device's identity as a six-segment transfer code and importing it on another system to resume the session without re-pairing.

**Architecture:** Add `ExportTransferCode` / `ImportTransferCode` functions to the `store` package. Binary serialization packs all device identity fields (keys, ADV, JID, metadata) into a compact byte stream with a version byte and CRC32 checksum. The bytes are base64url-encoded and split into 6 segments delimited by `-`.

**Tech Stack:** Go stdlib (`encoding/binary`, `encoding/base64`, `hash/crc32`), existing `keys` and `types` packages.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `store/transfer.go` | `ExportTransferCode()` and `ImportTransferCode()` functions, binary serialization helpers |
| Create | `store/transfer_test.go` | Round-trip tests, edge cases, error handling tests |

---

### Task 1: Binary Serialization — Write the Failing Test

**Files:**
- Create: `store/transfer_test.go`

- [ ] **Step 1: Write the round-trip test**

Create `store/transfer_test.go`:

```go
// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"bytes"
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd e:\work\whatsmeow && go test -v -run TestExportImportTransferCode ./store/`
Expected: FAIL — `ExportTransferCode` and `ImportTransferCode` not defined.

- [ ] **Step 3: Commit skeleton test**

```bash
cd e:\work\whatsmeow
git add store/transfer_test.go
git commit -m "test: add failing round-trip test for device transfer code"
```

---

### Task 2: Binary Serialization — Implement Export

**Files:**
- Create: `store/transfer.go`

- [ ] **Step 4: Write the ExportTransferCode implementation**

Create `store/transfer.go`:

```go
// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

const transferCodeVersion = 1

// ExportTransferCode serializes the device identity into a six-segment transfer code.
// Only the device identity is exported (keys, ADV, JID, metadata).
// Signal sessions, pre-keys, sender keys, and app state are NOT included.
func ExportTransferCode(device *Device) (string, error) {
	if device == nil {
		return "", fmt.Errorf("device is nil")
	}
	if device.ID == nil {
		return "", fmt.Errorf("device has no JID")
	}
	if device.NoiseKey == nil || device.NoiseKey.Priv == nil {
		return "", fmt.Errorf("device has no noise key")
	}
	if device.IdentityKey == nil || device.IdentityKey.Priv == nil {
		return "", fmt.Errorf("device has no identity key")
	}
	if device.SignedPreKey == nil || device.SignedPreKey.Priv == nil || device.SignedPreKey.Signature == nil {
		return "", fmt.Errorf("device has no signed pre-key")
	}
	if device.Account == nil {
		return "", fmt.Errorf("device has no account")
	}

	data := marshalDeviceIdentity(device)

	checksum := crc32.ChecksumIEEE(data)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, checksum)
	data = append(data, buf...)

	encoded := base64.RawURLEncoding.EncodeToString(data)
	return formatSixSegments(encoded), nil
}

func marshalDeviceIdentity(device *Device) []byte {
	var buf []byte

	// Version
	buf = append(buf, transferCodeVersion)

	// Fixed-size key material (32+32+32+4+64+4+32 = 200 bytes)
	buf = append(buf, device.NoiseKey.Priv[:]...)
	buf = append(buf, device.IdentityKey.Priv[:]...)
	buf = append(buf, device.SignedPreKey.Priv[:]...)
	buf = appendUint32(buf, device.SignedPreKey.KeyID)
	buf = append(buf, device.SignedPreKey.Signature[:]...)
	buf = appendUint32(buf, device.RegistrationID)
	buf = append(buf, device.AdvSecretKey...)

	// ADV fields (32+64+64 fixed + variable Details)
	buf = append(buf, device.Account.AccountSignatureKey...)
	buf = append(buf, device.Account.AccountSignature...)
	buf = append(buf, device.Account.DeviceSignature...)
	buf = appendLenPrefixed(buf, device.Account.Details)

	// JID and LID as strings
	buf = appendLenPrefixed(buf, []byte(device.ID.String()))
	buf = appendLenPrefixed(buf, []byte(device.LID.String()))

	// Platform
	buf = appendLenPrefixed(buf, []byte(device.Platform))

	// FacebookUUID (16 bytes)
	uuidBytes, _ := device.FacebookUUID.MarshalBinary()
	buf = append(buf, uuidBytes...)

	// LIDMigrationTimestamp (8 bytes)
	buf = appendInt64(buf, device.LIDMigrationTimestamp)

	return buf
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendInt64(buf []byte, v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return append(buf, b...)
}

func appendLenPrefixed(buf []byte, data []byte) []byte {
	buf = appendUint16(buf, uint16(len(data)))
	return append(buf, data...)
}

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return append(buf, b...)
}

func formatSixSegments(encoded string) string {
	segLen := (len(encoded) + 5) / 6
	segments := make([]string, 0, 6)
	for i := 0; i < len(encoded); i += segLen {
		end := i + segLen
		if end > len(encoded) {
			end = len(encoded)
		}
		segments = append(segments, encoded[i:end])
	}
	return strings.Join(segments, "-")
}

func splitTransferCode(code string) []string {
	return strings.Split(code, "-")
}
```

- [ ] **Step 5: Run test to verify it still fails (Import not yet implemented)**

Run: `cd e:\work\whatsmeow && go test -v -run TestExportImportTransferCode ./store/`
Expected: FAIL — `ImportTransferCode` not defined. But compilation of `transfer.go` should succeed.

- [ ] **Step 6: Commit export implementation**

```bash
cd e:\work\whatsmeow
git add store/transfer.go
git commit -m "feat(store): add ExportTransferCode for device identity serialization"
```

---

### Task 3: Binary Deserialization — Implement Import

**Files:**
- Modify: `store/transfer.go`

- [ ] **Step 7: Add ImportTransferCode to transfer.go**

Append to `store/transfer.go`:

```go
// ImportTransferCode deserializes a six-segment transfer code back into a Device.
// The returned Device has no store interfaces set — the caller must attach it
// to a Container (via Container.PutDevice) before use.
func ImportTransferCode(code string) (*Device, error) {
	joined := strings.ReplaceAll(code, "-", "")
	data, err := base64.RawURLEncoding.DecodeString(joined)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(data) < 5 {
		return nil, fmt.Errorf("transfer code too short")
	}

	// Verify CRC32 checksum (last 4 bytes)
	payload := data[:len(data)-4]
	expectedChecksum := binary.BigEndian.Uint32(data[len(data)-4:])
	actualChecksum := crc32.ChecksumIEEE(payload)
	if expectedChecksum != actualChecksum {
		return nil, fmt.Errorf("checksum mismatch: transfer code is corrupted")
	}

	return unmarshalDeviceIdentity(payload)
}

func unmarshalDeviceIdentity(data []byte) (*Device, error) {
	r := &byteReader{data: data}

	// Version
	version, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if version != transferCodeVersion {
		return nil, fmt.Errorf("unsupported transfer code version: %d", version)
	}

	device := &Device{}
	device.SignedPreKey = &keys.PreKey{}

	// NoiseKey (32 bytes private)
	noisePriv, err := r.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read noise key: %w", err)
	}
	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))

	// IdentityKey (32 bytes private)
	identityPriv, err := r.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity key: %w", err)
	}
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityPriv))

	// SignedPreKey (32 bytes private + 4 bytes KeyID + 64 bytes signature)
	preKeyPriv, err := r.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-key: %w", err)
	}
	device.SignedPreKey.KeyPair = *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(preKeyPriv))

	keyID, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-key ID: %w", err)
	}
	device.SignedPreKey.KeyID = keyID

	preKeySig, err := r.readBytes(64)
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-key signature: %w", err)
	}
	device.SignedPreKey.Signature = (*[64]byte)(preKeySig)

	// RegistrationID (4 bytes)
	regID, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read registration ID: %w", err)
	}
	device.RegistrationID = regID

	// AdvSecretKey (32 bytes)
	advKey, err := r.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read adv secret key: %w", err)
	}
	device.AdvSecretKey = advKey

	// ADV fields
	var account waAdv.ADVSignedDeviceIdentity

	accountSigKey, err := r.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read account signature key: %w", err)
	}
	account.AccountSignatureKey = accountSigKey

	accountSig, err := r.readBytes(64)
	if err != nil {
		return nil, fmt.Errorf("failed to read account signature: %w", err)
	}
	account.AccountSignature = accountSig

	deviceSig, err := r.readBytes(64)
	if err != nil {
		return nil, fmt.Errorf("failed to read device signature: %w", err)
	}
	account.DeviceSignature = deviceSig

	advDetails, err := r.readLenPrefixed()
	if err != nil {
		return nil, fmt.Errorf("failed to read adv details: %w", err)
	}
	account.Details = advDetails
	device.Account = &account

	// JID
	jidBytes, err := r.readLenPrefixed()
	if err != nil {
		return nil, fmt.Errorf("failed to read JID: %w", err)
	}
	jid, err := types.ParseJID(string(jidBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JID: %w", err)
	}
	device.ID = &jid

	// LID
	lidBytes, err := r.readLenPrefixed()
	if err != nil {
		return nil, fmt.Errorf("failed to read LID: %w", err)
	}
	lid, err := types.ParseJID(string(lidBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse LID: %w", err)
	}
	device.LID = lid

	// Platform
	platformBytes, err := r.readLenPrefixed()
	if err != nil {
		return nil, fmt.Errorf("failed to read platform: %w", err)
	}
	device.Platform = string(platformBytes)

	// FacebookUUID (16 bytes)
	fbUUIDBytes, err := r.readBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to read facebook UUID: %w", err)
	}
	var fbUUID uuid.UUID
	if err := fbUUID.UnmarshalBinary(fbUUIDBytes); err != nil {
		return nil, fmt.Errorf("failed to parse facebook UUID: %w", err)
	}
	device.FacebookUUID = fbUUID

	// LIDMigrationTimestamp (8 bytes)
	lidMigTS, err := r.readInt64()
	if err != nil {
		return nil, fmt.Errorf("failed to read LID migration timestamp: %w", err)
	}
	device.LIDMigrationTimestamp = lidMigTS

	return device, nil
}

// byteReader is a simple sequential byte reader with bounds checking.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("unexpected end of data at offset %d", r.pos)
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *byteReader) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("unexpected end of data at offset %d (need %d bytes)", r.pos, n)
	}
	b := make([]byte, n)
	copy(b, r.data[r.pos:r.pos+n])
	r.pos += n
	return b, nil
}

func (r *byteReader) readUint16() (uint16, error) {
	b, err := r.readBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *byteReader) readUint32() (uint32, error) {
	b, err := r.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *byteReader) readInt64() (int64, error) {
	b, err := r.readBytes(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

func (r *byteReader) readLenPrefixed() ([]byte, error) {
	length, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	return r.readBytes(int(length))
}
```

- [ ] **Step 8: Run test to verify round-trip passes**

Run: `cd e:\work\whatsmeow && go test -v -run TestExportImportTransferCode ./store/`
Expected: PASS

- [ ] **Step 9: Commit import implementation**

```bash
cd e:\work\whatsmeow
git add store/transfer.go
git commit -m "feat(store): add ImportTransferCode for device identity deserialization"
```

---

### Task 4: Error Handling Tests

**Files:**
- Modify: `store/transfer_test.go`

- [ ] **Step 10: Add error case tests**

Append to `store/transfer_test.go`:

```go
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
		if r != '-' {
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
	joined := strings.ReplaceAll(code, "-")
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
```

Note: The `TestImportTransferCode_WrongVersion` test uses `strings.ReplaceAll(code, "-")` — this needs to be `strings.ReplaceAll(code, "-", "")`. Also needs additional imports `"encoding/base64"`, `"encoding/binary"`, `"hash/crc32"`, `"strings"`.

Update the import block at the top of `store/transfer_test.go` to:

```go
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
```

And fix the `ReplaceAll` call:
```go
joined := strings.ReplaceAll(code, "-", "")
```

- [ ] **Step 11: Run all tests**

Run: `cd e:\work\whatsmeow && go test -v -run TestExportTransferCode,TestImportTransferCode ./store/`
Expected: ALL PASS

- [ ] **Step 12: Commit error handling tests**

```bash
cd e:\work\whatsmeow
git add store/transfer_test.go
git commit -m "test(store): add error handling tests for transfer code"
```

---

### Task 5: Build Verification

- [ ] **Step 13: Run full build**

Run: `cd e:\work\whatsmeow && go build -v ./...`
Expected: Clean build, no errors.

- [ ] **Step 14: Run full test suite**

Run: `cd e:\work\whatsmeow && go test -v ./store/`
Expected: ALL PASS

- [ ] **Step 15: Run vet**

Run: `cd e:\work\whatsmeow && go vet ./store/`
Expected: No issues.

---

## Usage Example (for reference, not a task)

```go
// Export on system A
device, _ := container.GetFirstDevice(ctx)
code, err := store.ExportTransferCode(device)
// code looks like: "AbCdEf...12-GhIjKl...34-MnOpQr...56-StUvWx...78-YzAbCd...90-EfGhIj...12"
fmt.Println(code) // display 6 segments to user

// Import on system B
restored, err := store.ImportTransferCode(code)
// Attach to a container and save
restored.Container = container
err = container.PutDevice(ctx, restored)
// Now create client with this device
client := whatsmeow.NewClient(restored, nil)
err = client.Connect()
```

## Limitations (document in code comments)

1. Only device identity is exported — Signal sessions, sender keys, pre-keys, and app state are NOT included.
2. After import, existing E2E sessions must be re-established (first message to each contact triggers this automatically).
3. Both systems must NOT connect simultaneously with the same device identity.
4. The transfer code contains private key material — treat it as a secret.
