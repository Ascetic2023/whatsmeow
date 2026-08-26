// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.mau.fi/util/random"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// regCredsInt accepts a JSON number or a quoted numeric string, since some
// exports serialize numeric fields (e.g. registrationID) as strings.
type regCredsInt uint32

func (i *regCredsInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `" `)
	if s == "" || s == "null" {
		*i = 0
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid integer %q: %w", s, err)
	}
	*i = regCredsInt(n)
	return nil
}

// regCreds is the flat "phone-number registration" JSON export format:
// Noise static keypair, Signal identity keypair, signed pre-key and the
// device parameters submitted to WhatsApp's registration API. All key
// material is base64 (std encoding) as bare strings.
//
// Unlike Baileys creds.json (see ImportBaileysJSON), this format does NOT
// carry the ADV signed device identity (account.*) or advSecretKey.
type regCreds struct {
	ClientStaticPrivateKey string      `json:"clientStaticPrivateKey"`
	IdentityPrivateKey     string      `json:"identityPrivateKey"`
	SignPreKeyID           regCredsInt `json:"signPreKeyID"`
	SignPreKeyPrivateKey   string      `json:"signPreKeyPrivateKey"`
	SignPreKeySignature    string      `json:"signPreKeySignature"`
	RegistrationID         regCredsInt `json:"registrationID"`

	JID   string `json:"jid"`
	In    string `json:"in"`
	Phone string `json:"phone"`

	Platform     string `json:"platform"`
	Manufacturer string `json:"manufacturer"`
	Device       string `json:"device"`
}

func decodeB64Key32(name, s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("invalid %s: expected 32 bytes, got %d", name, len(raw))
	}
	return (*[32]byte)(raw), nil
}

// ImportRegistrationCredsJSON imports the flat phone-number registration JSON
// export and returns a Device. The returned Device has no store interfaces set
// — the caller must attach it to a Container (via Container.PutDevice) before
// use.
//
// NOTE: this format does not include the ADV signed device identity or
// advSecretKey. A fresh random advSecretKey is generated so the Device is
// storable, and Account is left nil. Depending on how the credentials were
// produced, whatsmeow may still need to complete an ADV pairing handshake on
// first connect before the device is fully usable.
func ImportRegistrationCredsJSON(jsonData string) (*Device, error) {
	var creds regCreds
	if err := json.Unmarshal([]byte(jsonData), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	device := &Device{}

	// NoiseKey (Noise protocol client static keypair)
	noisePriv, err := decodeB64Key32("clientStaticPrivateKey", creds.ClientStaticPrivateKey)
	if err != nil {
		return nil, err
	}
	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*noisePriv)

	// IdentityKey (Signal identity keypair)
	identityPriv, err := decodeB64Key32("identityPrivateKey", creds.IdentityPrivateKey)
	if err != nil {
		return nil, err
	}
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*identityPriv)

	// SignedPreKey
	preKeyPriv, err := decodeB64Key32("signPreKeyPrivateKey", creds.SignPreKeyPrivateKey)
	if err != nil {
		return nil, err
	}
	preKeySig, err := base64.StdEncoding.DecodeString(creds.SignPreKeySignature)
	if err != nil {
		return nil, fmt.Errorf("invalid signPreKeySignature: %w", err)
	}
	if len(preKeySig) != 64 {
		return nil, fmt.Errorf("invalid signPreKeySignature: expected 64 bytes, got %d", len(preKeySig))
	}
	device.SignedPreKey = &keys.PreKey{
		KeyPair:   *keys.NewKeyPairFromPrivateKey(*preKeyPriv),
		KeyID:     uint32(creds.SignPreKeyID),
		Signature: (*[64]byte)(preKeySig),
	}

	// RegistrationID
	device.RegistrationID = uint32(creds.RegistrationID)

	// JID: prefer explicit jid, fall back to the input number.
	number := creds.JID
	if number == "" {
		number = creds.In
	}
	if number == "" {
		number = creds.Phone
	}
	if number == "" {
		return nil, fmt.Errorf("no device ID: jid, in and phone are all empty")
	}
	// Accept both a bare number ("917756009601") and a full JID string.
	if strings.ContainsRune(number, '@') {
		jid, err := types.ParseJID(number)
		if err != nil {
			return nil, fmt.Errorf("invalid jid %q: %w", number, err)
		}
		device.ID = &jid
	} else {
		jid := types.JID{User: number, Server: types.DefaultUserServer}
		device.ID = &jid
	}

	// Platform (best-effort from the registration device fields).
	if creds.Platform != "" {
		device.Platform = creds.Platform
	} else if creds.Manufacturer != "" {
		device.Platform = creds.Manufacturer
	}

	// This format carries no ADV account identity or advSecretKey.
	// Generate a fresh advSecretKey so the Device is storable; Account stays nil.
	device.AdvSecretKey = random.Bytes(32)

	return device, nil
}
