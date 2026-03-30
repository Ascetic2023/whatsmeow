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
	"strings"

	mathRand "math/rand/v2"

	"go.mau.fi/util/random"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// ExportTransferCode exports the device identity as a six-segment transfer code
// in the industry-standard comma-separated format:
//
//	phone,identityPub,identityPriv,messagePub,messagePriv,deviceData
//
// Field mapping:
//   - Segment 1: Phone number (Device.ID.User)
//   - Segment 2: Noise public key (base64) — called "Identity Public Key" in the ecosystem
//   - Segment 3: Noise private key (base64) — called "Identity Private Key"
//   - Segment 4: Signal identity public key (base64) — called "Message Public Key"
//   - Segment 5: Signal identity private key (base64) — called "Message Private Key"
//   - Segment 6: Packed device data (base64) — RegistrationID, device number, AdvSecretKey, etc.
//
// Only the device identity is exported. Signal sessions, sender keys, and app state are NOT included.
// After importing on another system, E2E sessions will be re-established automatically on first message.
// The transfer code contains private key material — treat it as a secret.
func ExportTransferCode(device *Device) (string, error) {
	if device == nil {
		return "", fmt.Errorf("device is nil")
	}
	if device.ID == nil {
		return "", fmt.Errorf("device has no JID")
	}
	if device.NoiseKey == nil || device.NoiseKey.Pub == nil || device.NoiseKey.Priv == nil {
		return "", fmt.Errorf("device has no noise key")
	}
	if device.IdentityKey == nil || device.IdentityKey.Pub == nil || device.IdentityKey.Priv == nil {
		return "", fmt.Errorf("device has no identity key")
	}

	b64 := base64.StdEncoding.EncodeToString

	seg1 := device.ID.User
	seg2 := b64(device.NoiseKey.Pub[:])
	seg3 := b64(device.NoiseKey.Priv[:])
	seg4 := b64(device.IdentityKey.Pub[:])
	seg5 := b64(device.IdentityKey.Priv[:])
	seg6 := b64(packSegment6(device))

	return strings.Join([]string{seg1, seg2, seg3, seg4, seg5, seg6}, ","), nil
}

// packSegment6 encodes extra device metadata into the sixth segment.
// Format: phone_ascii + '#' + registrationID(4B) + device(2B) + preKeyID(4B) + advSecretKey(32B)
func packSegment6(device *Device) []byte {
	var buf []byte
	buf = append(buf, []byte(device.ID.User)...)
	buf = append(buf, '#')

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, device.RegistrationID)
	buf = append(buf, b...)

	d := make([]byte, 2)
	binary.BigEndian.PutUint16(d, device.ID.Device)
	buf = append(buf, d...)

	k := make([]byte, 4)
	if device.SignedPreKey != nil {
		binary.BigEndian.PutUint32(k, device.SignedPreKey.KeyID)
	}
	buf = append(buf, k...)

	advKey := make([]byte, 32)
	copy(advKey, device.AdvSecretKey)
	buf = append(buf, advKey...)

	return buf
}

// ImportTransferCode imports a six-segment transfer code and returns a Device.
// The returned Device has no store interfaces set — the caller must attach it
// to a Container (via Container.PutDevice) before use.
//
// Supports codes exported by whatsmeow and other WhatsApp libraries.
// Fields not present in the transfer code are auto-generated:
//   - SignedPreKey: Generated and signed with the imported IdentityKey
//   - Account: Empty ADVSignedDeviceIdentity
//   - LID: Empty (populated automatically after connection)
//
// If the sixth segment uses a format from a different tool, RegistrationID and
// Device number will use defaults. The caller can override them on the returned Device.
func ImportTransferCode(code string) (*Device, error) {
	segments := strings.Split(code, ",")
	if len(segments) != 6 {
		return nil, fmt.Errorf("expected 6 comma-separated segments, got %d", len(segments))
	}

	phone := strings.TrimSpace(segments[0])
	if phone == "" {
		return nil, fmt.Errorf("segment 1 (phone) is empty")
	}

	noisePub, noisePriv, err := decodeKeyPairSegments(segments[1], segments[2], "identity")
	if err != nil {
		return nil, err
	}
	identityPub, identityPriv, err := decodeKeyPairSegments(segments[3], segments[4], "message")
	if err != nil {
		return nil, err
	}

	seg6Data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(segments[5]))
	if err != nil {
		return nil, fmt.Errorf("segment 6 (device data): invalid base64: %w", err)
	}

	device := &Device{}

	// Reconstruct key pairs from private keys (public keys are derived via curve25519)
	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityPriv))

	// Verify the derived public keys match what was explicitly provided
	if *device.NoiseKey.Pub != *(*[32]byte)(noisePub) {
		return nil, fmt.Errorf("noise key mismatch: derived public key does not match segment 2")
	}
	if *device.IdentityKey.Pub != *(*[32]byte)(identityPub) {
		return nil, fmt.Errorf("identity key mismatch: derived public key does not match segment 4")
	}

	// Parse segment 6
	regID, deviceNum, preKeyID, advSecretKey := unpackSegment6(seg6Data, phone)
	device.RegistrationID = regID
	device.AdvSecretKey = advSecretKey

	// Build JID
	jid := types.JID{
		User:   phone,
		Device: deviceNum,
		Server: types.DefaultUserServer,
	}
	device.ID = &jid

	// Generate SignedPreKey (signed by IdentityKey)
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(preKeyID)

	// Empty Account — not needed for login, only used during initial pairing HMAC verification
	device.Account = &waAdv.ADVSignedDeviceIdentity{}

	return device, nil
}

// decodeKeyPairSegments decodes a base64 public+private key pair from two segments.
func decodeKeyPairSegments(pubSeg, privSeg, name string) (pub, priv []byte, err error) {
	pub, err = base64.StdEncoding.DecodeString(strings.TrimSpace(pubSeg))
	if err != nil {
		return nil, nil, fmt.Errorf("%s public key: invalid base64: %w", name, err)
	}
	if len(pub) != 32 {
		return nil, nil, fmt.Errorf("%s public key: expected 32 bytes, got %d", name, len(pub))
	}

	priv, err = base64.StdEncoding.DecodeString(strings.TrimSpace(privSeg))
	if err != nil {
		return nil, nil, fmt.Errorf("%s private key: invalid base64: %w", name, err)
	}
	if len(priv) != 32 {
		return nil, nil, fmt.Errorf("%s private key: expected 32 bytes, got %d", name, len(priv))
	}

	return pub, priv, nil
}

// unpackSegment6 extracts structured data from the sixth segment.
// If the data matches our format (phone + '#' + 42 bytes), all fields are extracted.
// Otherwise, sensible defaults are used.
func unpackSegment6(data []byte, phone string) (regID uint32, deviceNum uint16, preKeyID uint32, advSecretKey []byte) {
	// Defaults
	regID = mathRand.Uint32()
	deviceNum = 0
	preKeyID = 1
	advSecretKey = random.Bytes(32)

	prefix := phone + "#"
	if len(data) <= len(prefix) || string(data[:len(prefix)]) != prefix {
		return
	}

	rest := data[len(prefix):]

	// Our format: regID(4B) + device(2B) + preKeyID(4B) + advSecretKey(32B) = 42 bytes
	if len(rest) >= 42 {
		regID = binary.BigEndian.Uint32(rest[0:4])
		deviceNum = binary.BigEndian.Uint16(rest[4:6])
		preKeyID = binary.BigEndian.Uint32(rest[6:10])
		advSecretKey = make([]byte, 32)
		copy(advSecretKey, rest[10:42])
		return
	}

	// Partial/external format — extract what we can
	if len(rest) >= 4 {
		regID = binary.BigEndian.Uint32(rest[0:4])
	}
	if len(rest) >= 6 {
		deviceNum = binary.BigEndian.Uint16(rest[4:6])
	}
	return
}
