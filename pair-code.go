// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.mau.fi/util/random"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"go.mau.fi/whatsmeow/util/keys"
)

// PairClientType is the type of client to use with PairCode.
// The type is automatically filled based on store.DeviceProps.PlatformType (which is what QR login uses).
type PairClientType string

const (
	PairClientUnknown        PairClientType = "0"
	PairClientChrome         PairClientType = "1"
	PairClientEdge           PairClientType = "2"
	PairClientFirefox        PairClientType = "3"
	PairClientIE             PairClientType = "4"
	PairClientOpera          PairClientType = "5"
	PairClientSafari         PairClientType = "6"
	PairClientElectron       PairClientType = "7"
	PairClientUWP            PairClientType = "8"
	PairClientOtherWebClient PairClientType = "9"
	PairClientMacOS          PairClientType = "c"
	PairClientAndroid        PairClientType = "e"
)

var notNumbers = regexp.MustCompile("[^0-9]")

// ErrInvalidPairCode is returned when a custom pair code has an invalid format.
var ErrInvalidPairCode = fmt.Errorf("pair code must be exactly 8 digits (e.g. 77778888 or 7777-8888)")

type pendingPairCode struct {
	keyPair      *keys.KeyPair
	ephemeralKey []byte
	linkingCode  string
}

type phoneLinkingCache struct {
	jid         types.JID
	keyPair     *keys.KeyPair
	linkingCode string
	pairingRef  string
}

// normalizePairCode strips dashes and validates that the code is exactly 8 digits.
// Returns the normalized 8-digit string or an error.
func normalizePairCode(code string) (string, error) {
	digits := notNumbers.ReplaceAllString(code, "")
	if len(digits) != 8 {
		return "", ErrInvalidPairCode
	}
	return digits, nil
}

func generateCompanionEphemeralKey(customCode string) (ephemeralKeyPair *keys.KeyPair, ephemeralKey []byte, encodedLinkingCode string) {
	ephemeralKeyPair = keys.NewKeyPair()
	salt := random.Bytes(32)
	iv := random.Bytes(16)
	if customCode != "" {
		encodedLinkingCode = customCode
	} else {
		linkingCode := random.Bytes(5)
		// 将 5 字节转换为 8 位纯数字码 (00000000-99999999)
		num := uint64(linkingCode[0])<<32 | uint64(linkingCode[1])<<24 | uint64(linkingCode[2])<<16 | uint64(linkingCode[3])<<8 | uint64(linkingCode[4])
		encodedLinkingCode = fmt.Sprintf("%08d", num%100000000)
	}
	linkCodeKey := pbkdf2.Key([]byte(encodedLinkingCode), salt, 2<<16, 32, sha256.New)
	linkCipherBlock, _ := aes.NewCipher(linkCodeKey)
	encryptedPubkey := ephemeralKeyPair.Pub[:]
	cipher.NewCTR(linkCipherBlock, iv).XORKeyStream(encryptedPubkey, encryptedPubkey)
	ephemeralKey = make([]byte, 80)
	copy(ephemeralKey[0:32], salt)
	copy(ephemeralKey[32:48], iv)
	copy(ephemeralKey[48:80], encryptedPubkey)
	return
}

// GeneratePairCode generates a pairing code locally without any network calls.
// The code is stored internally and can later be sent to the server with [Client.SendPairCode].
// This allows you to display the code to the user before registering it with the server.
//
// An optional custom code can be provided (e.g. "7777-8888" or "77778888").
// It must be exactly 8 digits. If omitted or empty, a random code is generated.
//
// Returns the formatted pairing code (XXXX-XXXX).
func (cli *Client) GeneratePairCode(customCode ...string) (string, error) {
	if cli == nil {
		return "", ErrClientIsNil
	}
	var normalized string
	if len(customCode) > 0 && customCode[0] != "" {
		var err error
		normalized, err = normalizePairCode(customCode[0])
		if err != nil {
			return "", err
		}
	}
	ephemeralKeyPair, ephemeralKey, encodedLinkingCode := generateCompanionEphemeralKey(normalized)
	cli.pendingPairCode = &pendingPairCode{
		keyPair:      ephemeralKeyPair,
		ephemeralKey: ephemeralKey,
		linkingCode:  encodedLinkingCode,
	}
	return encodedLinkingCode[0:4] + "-" + encodedLinkingCode[4:8], nil
}

// SendPairCode sends a previously generated pairing code (from [Client.GeneratePairCode]) to the server.
//
// You must connect the client and wait for `*events.QR` before calling this.
// The pairing code has a ~160-second time limit from the WebSocket connection.
//
// See [Client.PairPhone] for a convenience method that generates and sends in one call.
func (cli *Client) SendPairCode(ctx context.Context, phone string, showPushNotification bool, clientType PairClientType, clientDisplayName string) error {
	if cli == nil {
		return ErrClientIsNil
	}
	pending := cli.pendingPairCode
	if pending == nil {
		return fmt.Errorf("no pending pair code, call GeneratePairCode first")
	}
	phone = notNumbers.ReplaceAllString(phone, "")
	if len(phone) <= 6 {
		return ErrPhoneNumberTooShort
	} else if strings.HasPrefix(phone, "0") {
		return ErrPhoneNumberIsNotInternational
	}
	jid := types.NewJID(phone, types.DefaultUserServer)
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "link_code_companion_reg",
			Attrs: waBinary.Attrs{
				"jid":   jid,
				"stage": "companion_hello",

				"should_show_push_notification": strconv.FormatBool(showPushNotification),
			},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_wrapped_companion_ephemeral_pub", Content: pending.ephemeralKey},
				{Tag: "companion_server_auth_key_pub", Content: cli.Store.NoiseKey.Pub[:]},
				{Tag: "companion_platform_id", Content: string(clientType)},
				{Tag: "companion_platform_display", Content: clientDisplayName},
				{Tag: "link_code_pairing_nonce", Content: []byte{0}},
			},
		}},
	})
	if err != nil {
		return err
	}
	pairingRefNode, ok := resp.GetOptionalChildByTag("link_code_companion_reg", "link_code_pairing_ref")
	if !ok {
		return &ElementMissingError{Tag: "link_code_pairing_ref", In: "code link registration response"}
	}
	pairingRef, ok := pairingRefNode.Content.([]byte)
	if !ok {
		return fmt.Errorf("unexpected type %T in content of link_code_pairing_ref tag", pairingRefNode.Content)
	}
	cli.phoneLinkingCache = &phoneLinkingCache{
		jid:         jid,
		keyPair:     pending.keyPair,
		linkingCode: pending.linkingCode,
		pairingRef:  string(pairingRef),
	}
	cli.pendingPairCode = nil
	return nil
}

// PairPhone generates a pairing code and sends it to the server in one call.
// This is a convenience method that calls [Client.GeneratePairCode] followed by [Client.SendPairCode].
//
// You must connect the client normally before calling this (which means you'll also receive a QR code
// event, but that can be ignored when doing code pairing). You should also wait for `*events.QR` before
// calling this to ensure the connection is fully established. If using [Client.GetQRChannel], wait for
// the first item in the channel. Alternatively, sleeping for a second after calling Connect will probably work too.
//
// The exact expiry of pairing codes is unknown, but QR codes are always generated and the login websocket is closed
// after the QR codes run out, which means there's a 160-second time limit. It is recommended to generate the pairing
// code immediately after connecting to the websocket to have the maximum time.
//
// The clientType parameter must be one of the PairClient* constants, but which one doesn't matter.
// The client display name must be formatted as `Browser (OS)`, and only common browsers/OSes are allowed
// (the server will validate it and return 400 if it's wrong).
//
// See https://faq.whatsapp.com/1324084875126592 for more info
func (cli *Client) PairPhone(ctx context.Context, phone string, showPushNotification bool, clientType PairClientType, clientDisplayName string) (string, error) {
	code, err := cli.GeneratePairCode()
	if err != nil {
		return "", err
	}
	err = cli.SendPairCode(ctx, phone, showPushNotification, clientType, clientDisplayName)
	if err != nil {
		return "", err
	}
	return code, nil
}

func (cli *Client) tryHandleCodePairNotification(ctx context.Context, parentNode *waBinary.Node) {
	err := cli.handleCodePairNotification(ctx, parentNode)
	if err != nil {
		cli.Log.Errorf("Failed to handle code pair notification: %s", err)
	}
}

func (cli *Client) handleCodePairNotification(ctx context.Context, parentNode *waBinary.Node) error {
	node, ok := parentNode.GetOptionalChildByTag("link_code_companion_reg")
	if !ok {
		return &ElementMissingError{
			Tag: "link_code_companion_reg",
			In:  "notification",
		}
	}
	linkCache := cli.phoneLinkingCache
	if linkCache == nil {
		return fmt.Errorf("received code pair notification without a pending pairing")
	}
	cli.paired.Store(false)
	linkCodePairingRef, _ := node.GetChildByTag("link_code_pairing_ref").Content.([]byte)
	if string(linkCodePairingRef) != linkCache.pairingRef {
		return fmt.Errorf("pairing ref mismatch in code pair notification")
	}
	wrappedPrimaryEphemeralPub, ok := node.GetChildByTag("link_code_pairing_wrapped_primary_ephemeral_pub").Content.([]byte)
	if !ok {
		return &ElementMissingError{
			Tag: "link_code_pairing_wrapped_primary_ephemeral_pub",
			In:  "notification",
		}
	} else if len(wrappedPrimaryEphemeralPub) < 80 {
		return fmt.Errorf("unexpected length of link_code_pairing_wrapped_primary_ephemeral_pub: %d", len(wrappedPrimaryEphemeralPub))
	}
	primaryIdentityPub, ok := node.GetChildByTag("primary_identity_pub").Content.([]byte)
	if !ok {
		return &ElementMissingError{
			Tag: "primary_identity_pub",
			In:  "notification",
		}
	}

	advSecretRandom := random.Bytes(32)
	keyBundleSalt := random.Bytes(32)
	keyBundleNonce := random.Bytes(12)

	// Decrypt the primary device's ephemeral public key, which was encrypted with the 8-character pairing code,
	// then compute the DH shared secret using our ephemeral private key we generated earlier.
	primarySalt := wrappedPrimaryEphemeralPub[0:32]
	primaryIV := wrappedPrimaryEphemeralPub[32:48]
	primaryEncryptedPubkey := wrappedPrimaryEphemeralPub[48:80]
	linkCodeKey := pbkdf2.Key([]byte(linkCache.linkingCode), primarySalt, 2<<16, 32, sha256.New)
	linkCipherBlock, err := aes.NewCipher(linkCodeKey)
	if err != nil {
		return fmt.Errorf("failed to create link cipher: %w", err)
	}
	primaryDecryptedPubkey := make([]byte, 32)
	cipher.NewCTR(linkCipherBlock, primaryIV).XORKeyStream(primaryDecryptedPubkey, primaryEncryptedPubkey)
	ephemeralSharedSecret, err := curve25519.X25519(linkCache.keyPair.Priv[:], primaryDecryptedPubkey)
	if err != nil {
		return fmt.Errorf("failed to compute ephemeral shared secret: %w", err)
	}

	// Encrypt and wrap key bundle containing our identity key, the primary device's identity key and the randomness used for the adv key.
	keyBundleEncryptionKey := hkdfutil.SHA256(ephemeralSharedSecret, keyBundleSalt, []byte("link_code_pairing_key_bundle_encryption_key"), 32)
	keyBundleCipherBlock, err := aes.NewCipher(keyBundleEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create key bundle cipher: %w", err)
	}
	keyBundleGCM, err := cipher.NewGCM(keyBundleCipherBlock)
	if err != nil {
		return fmt.Errorf("failed to create key bundle GCM: %w", err)
	}
	plaintextKeyBundle := concatBytes(cli.Store.IdentityKey.Pub[:], primaryIdentityPub, advSecretRandom)
	encryptedKeyBundle := keyBundleGCM.Seal(nil, keyBundleNonce, plaintextKeyBundle, nil)
	wrappedKeyBundle := concatBytes(keyBundleSalt, keyBundleNonce, encryptedKeyBundle)

	// Compute the adv secret key (which is used to authenticate the pair-success event later)
	identitySharedKey, err := curve25519.X25519(cli.Store.IdentityKey.Priv[:], primaryIdentityPub)
	if err != nil {
		return fmt.Errorf("failed to compute identity shared key: %w", err)
	}
	advSecretInput := append(append(ephemeralSharedSecret, identitySharedKey...), advSecretRandom...)
	advSecret := hkdfutil.SHA256(advSecretInput, nil, []byte("adv_secret"), 32)
	cli.Store.AdvSecretKey = advSecret

	_, err = cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "link_code_companion_reg",
			Attrs: waBinary.Attrs{
				"jid":   linkCache.jid,
				"stage": "companion_finish",
			},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_wrapped_key_bundle", Content: wrappedKeyBundle},
				{Tag: "companion_identity_public", Content: cli.Store.IdentityKey.Pub[:]},
				{Tag: "link_code_pairing_ref", Content: linkCodePairingRef},
			},
		}},
	})
	return err
}
