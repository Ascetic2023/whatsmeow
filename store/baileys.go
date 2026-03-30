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

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// Baileys JSON creds.json structures

type baileysBuffer struct {
	Data string `json:"data"`
	Type string `json:"type"`
}

func newBuffer(data []byte) baileysBuffer {
	return baileysBuffer{Data: base64.StdEncoding.EncodeToString(data), Type: "Buffer"}
}

func (b *baileysBuffer) Decode() ([]byte, error) {
	if b.Data == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(b.Data)
}

type baileysKeyPair struct {
	Private baileysBuffer `json:"private"`
	Public  baileysBuffer `json:"public"`
}

type baileysSignedPreKey struct {
	Signature baileysBuffer  `json:"signature"`
	KeyID     uint32         `json:"keyId"`
	KeyPair   baileysKeyPair `json:"keyPair"`
}

type baileysAccount struct {
	DeviceSignature     string `json:"deviceSignature"`
	Details             string `json:"details"`
	AccountSignature    string `json:"accountSignature"`
	AccountSignatureKey string `json:"accountSignatureKey"`
}

type baileysMe struct {
	LID  string `json:"lid"`
	Name string `json:"name"`
	ID   string `json:"id"`
}

type baileysAccountSettings struct {
	UnarchiveChats bool `json:"unarchiveChats"`
}

type baileysCreds struct {
	NoiseKey                baileysKeyPair      `json:"noiseKey"`
	SignedIdentityKey       baileysKeyPair      `json:"signedIdentityKey"`
	SignedPreKey            baileysSignedPreKey  `json:"signedPreKey"`
	RegistrationID          uint32              `json:"registrationId"`
	AdvSecretKey            string              `json:"advSecretKey"`
	Account                 baileysAccount      `json:"account"`
	Me                      baileysMe           `json:"me"`
	Phone                   string              `json:"Phone"`
	Platform                string              `json:"platform"`
	PairingEphemeralKeyPair *baileysKeyPair     `json:"pairingEphemeralKeyPair,omitempty"`
	PairingCode             string              `json:"pairingCode,omitempty"`
	RoutingInfo             *baileysBuffer      `json:"routingInfo,omitempty"`
	Registered              bool                `json:"registered"`
	AccountSyncCounter      int                 `json:"accountSyncCounter"`
	FirstUnuploadedPreKeyId int                 `json:"firstUnuploadedPreKeyId"`
	NextPreKeyId            int                 `json:"nextPreKeyId"`
	LastAccountSyncTimestamp int64              `json:"lastAccountSyncTimestamp"`
	LastPropHash            string              `json:"lastPropHash,omitempty"`
	MyAppStateKeyId         string              `json:"myAppStateKeyId,omitempty"`
	ProcessedHistoryMessages []any              `json:"processedHistoryMessages"`
	AccountSettings         baileysAccountSettings `json:"accountSettings"`
	SignalIdentities        []any               `json:"signalIdentities"`
}

// ExportBaileysJSON exports the device identity as a Baileys-compatible creds.json.
// The output can be used directly as Baileys' auth state credentials.
func ExportBaileysJSON(device *Device) (string, error) {
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
	if device.SignedPreKey == nil || device.SignedPreKey.Priv == nil || device.SignedPreKey.Signature == nil {
		return "", fmt.Errorf("device has no signed pre-key")
	}

	b64 := base64.StdEncoding.EncodeToString

	creds := baileysCreds{
		NoiseKey: baileysKeyPair{
			Private: newBuffer(device.NoiseKey.Priv[:]),
			Public:  newBuffer(device.NoiseKey.Pub[:]),
		},
		SignedIdentityKey: baileysKeyPair{
			Private: newBuffer(device.IdentityKey.Priv[:]),
			Public:  newBuffer(device.IdentityKey.Pub[:]),
		},
		SignedPreKey: baileysSignedPreKey{
			Signature: newBuffer(device.SignedPreKey.Signature[:]),
			KeyID:     device.SignedPreKey.KeyID,
			KeyPair: baileysKeyPair{
				Private: newBuffer(device.SignedPreKey.Priv[:]),
				Public:  newBuffer(device.SignedPreKey.Pub[:]),
			},
		},
		RegistrationID: device.RegistrationID,
		AdvSecretKey:   b64(device.AdvSecretKey),
		Me: baileysMe{
			ID:   device.ID.String(),
			Name: device.PushName,
		},
		Phone:      device.ID.User,
		Platform:   device.Platform,
		Registered: true,

		FirstUnuploadedPreKeyId: int(device.SignedPreKey.KeyID) + 1,
		NextPreKeyId:            int(device.SignedPreKey.KeyID) + 1,

		ProcessedHistoryMessages: []any{},
		SignalIdentities:         []any{},
	}

	// LID
	if !device.LID.IsEmpty() {
		creds.Me.LID = device.LID.String()
	}

	// Account (ADV)
	if device.Account != nil {
		creds.Account = baileysAccount{
			Details:             b64(device.Account.Details),
			AccountSignature:    b64(device.Account.AccountSignature),
			AccountSignatureKey: b64(device.Account.AccountSignatureKey),
			DeviceSignature:     b64(device.Account.DeviceSignature),
		}
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}

// ImportBaileysJSON imports a Baileys creds.json and returns a Device.
// The returned Device has no store interfaces set — the caller must attach it
// to a Container (via Container.PutDevice) before use.
//
// This preserves all fields including Account, SignedPreKey, RegistrationID,
// and AdvSecretKey — unlike six-segment transfer codes which lose these fields.
func ImportBaileysJSON(jsonData string) (*Device, error) {
	var creds baileysCreds
	if err := json.Unmarshal([]byte(jsonData), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	device := &Device{}

	// NoiseKey
	noisePriv, err := creds.NoiseKey.Private.Decode()
	if err != nil || len(noisePriv) != 32 {
		return nil, fmt.Errorf("invalid noiseKey.private")
	}
	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))

	// IdentityKey (signedIdentityKey)
	identityPriv, err := creds.SignedIdentityKey.Private.Decode()
	if err != nil || len(identityPriv) != 32 {
		return nil, fmt.Errorf("invalid signedIdentityKey.private")
	}
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityPriv))

	// SignedPreKey
	preKeyPriv, err := creds.SignedPreKey.KeyPair.Private.Decode()
	if err != nil || len(preKeyPriv) != 32 {
		return nil, fmt.Errorf("invalid signedPreKey.keyPair.private")
	}
	preKeySig, err := creds.SignedPreKey.Signature.Decode()
	if err != nil || len(preKeySig) != 64 {
		return nil, fmt.Errorf("invalid signedPreKey.signature")
	}
	device.SignedPreKey = &keys.PreKey{
		KeyPair:   *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(preKeyPriv)),
		KeyID:     creds.SignedPreKey.KeyID,
		Signature: (*[64]byte)(preKeySig),
	}

	// RegistrationID
	device.RegistrationID = creds.RegistrationID

	// AdvSecretKey
	device.AdvSecretKey, err = base64.StdEncoding.DecodeString(creds.AdvSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid advSecretKey: %w", err)
	}

	// JID from me.id
	if creds.Me.ID != "" {
		jid, err := types.ParseJID(creds.Me.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid me.id: %w", err)
		}
		device.ID = &jid
	} else if creds.Phone != "" {
		jid := types.JID{User: creds.Phone, Server: types.DefaultUserServer}
		device.ID = &jid
	} else {
		return nil, fmt.Errorf("no device ID: both me.id and Phone are empty")
	}

	// LID
	if creds.Me.LID != "" {
		lid, err := types.ParseJID(creds.Me.LID)
		if err != nil {
			return nil, fmt.Errorf("invalid me.lid: %w", err)
		}
		device.LID = lid
	}

	// PushName
	device.PushName = creds.Me.Name

	// Platform
	device.Platform = creds.Platform

	// Account (ADV)
	var account waAdv.ADVSignedDeviceIdentity
	if creds.Account.Details != "" {
		account.Details, err = base64.StdEncoding.DecodeString(creds.Account.Details)
		if err != nil {
			return nil, fmt.Errorf("invalid account.details: %w", err)
		}
	}
	if creds.Account.AccountSignature != "" {
		account.AccountSignature, err = base64.StdEncoding.DecodeString(creds.Account.AccountSignature)
		if err != nil {
			return nil, fmt.Errorf("invalid account.accountSignature: %w", err)
		}
	}
	if creds.Account.AccountSignatureKey != "" {
		account.AccountSignatureKey, err = base64.StdEncoding.DecodeString(creds.Account.AccountSignatureKey)
		if err != nil {
			return nil, fmt.Errorf("invalid account.accountSignatureKey: %w", err)
		}
	}
	if creds.Account.DeviceSignature != "" {
		account.DeviceSignature, err = base64.StdEncoding.DecodeString(creds.Account.DeviceSignature)
		if err != nil {
			return nil, fmt.Errorf("invalid account.deviceSignature: %w", err)
		}
	}
	device.Account = &account

	return device, nil
}
