package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"

	"github.com/davecgh/go-spew/spew"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func getWrapper(key []byte) (*aead.Wrapper, error) {
	root := aead.NewWrapper(nil)
	root.SetConfig(map[string]string{"key_id": "root"})
	if err := root.SetAESGCMKeyBytes(key); err != nil {
		return nil, fmt.Errorf("SetAESGCMKeyBytes: %s", err)
	}
	return root, nil
}

func aeadFromKey(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func decryptInternal(path string, gcm cipher.AEAD, ciphertext []byte) ([]byte, error) {
	// Capture the parts
	nonce := ciphertext[5 : 5+gcm.NonceSize()]
	raw := ciphertext[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	// Attempt to open
	switch ciphertext[4] {
	case vault.AESGCMVersion1:
		return gcm.Open(out, nonce, raw, nil)
	case vault.AESGCMVersion2:
		aad := []byte(nil)
		if path != "" {
			aad = []byte(path)
		}
		return gcm.Open(out, nonce, raw, aad)
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}
}
func decryptTarget(cipher []byte, key []byte, path string) ([]byte, error) {

	aeadKey, err := aeadFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("aeadFromKey: %s", err)

	}
	clear, err := decryptInternal(path, aeadKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %s", err)
	}

	log.Debugf("Clear=%s", spew.Sdump(clear))
	return clear, nil

}
func decryptTargetWrapped(target string, unsealkey []byte) ([]byte, error) {

	ciphertext, err := ioutil.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s", err)
	}

	ciphertextBin, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", ciphertext))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %s", err)
	}
	se := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(ciphertextBin, se); err != nil {
		return nil, fmt.Errorf("proto Unmarshal %s", err)
	}

	log.Debugf("EncryptedBlobInfo:%s", spew.Sdump(se))

	aeadWrapper, err := getWrapper(unsealkey)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s", err)
	}

	clear, err := aeadWrapper.Decrypt(context.Background(), se, nil)
	if err != nil {
		return nil, fmt.Errorf("aeadWrapper.Decrypt: %s", err)
	}
	log.Debugf("Clear=%s", spew.Sdump(clear))
	return clear, nil

}

func decryptWithKeyring(kr *Keyring, cipher []byte, path string) (clear []byte, err error) {

	term := binary.BigEndian.Uint32(cipher[:4])
	log.Debugf("Looking for term:%d", term)
	termKey, ok := kr.keys[term]
	if !ok || termKey == nil {
		return nil, fmt.Errorf("no term key found")
	}
	return decryptTarget(cipher, termKey.Value, path)
}
