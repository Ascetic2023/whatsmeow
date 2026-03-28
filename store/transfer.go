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
//
// After importing on another system, existing E2E sessions must be re-established
// (the first message to each contact triggers this automatically).
// Both systems must NOT connect simultaneously with the same device identity.
// The transfer code contains private key material — treat it as a secret.
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

// ImportTransferCode deserializes a six-segment transfer code back into a Device.
// The returned Device has no store interfaces set — the caller must attach it
// to a Container (via Container.PutDevice) before use.
func ImportTransferCode(code string) (*Device, error) {
	joined := strings.ReplaceAll(code, ".", "")
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

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return append(buf, b...)
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
	return strings.Join(segments, ".")
}

func splitTransferCode(code string) []string {
	return strings.Split(code, ".")
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
