package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/davecgh/go-spew/spew"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/shamir"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	version = "0.1"
)

var keyring = "AAAAAQJSY9Nn8nJFtfSvi7Sr80twobxsyNgnH8h/f0kyfFFkH+ipHbgTYublyDAtxrKEDOB8yq8DfRPZJ66wPHpw/vSJfuaX/bnb+9qEL+rnIKSGpnIXMbS1kC/TPaYFYVRlZjDTJ2hOpGcva/4jWlvvpqcrOuwQ2Su4msZ/KmaljKt4IwNv5C+tsA9Eclj6fqUx6TH6uusLX+Su9BN7uMBBatnWX6DyOobDaMsBvYFFKnc4lLaeFQi8JtWIfGPpMr/lTkvl/29LkW/4yIk1TiFVCQ3GDqEkRobGlpSH23DwnYNpmKlaRvquN0vNIS4Hb/a0Lwjd4Rpj0WE8qasDVNFDhSW45ueKUtxyAiuBLBj+AYtHhSDvlAbkJeLEjMRzSnYB4k87FwcRGJRziwrEhkmYtC0="

var unsealKeys = []string{
	"iZwzZvh3F49rANs4JqdHbppY23Zbv9UrXtzwUAfeeAoO",
	"0WZmOXEyBW72R9Uc4uQMJdxazuUmQEKEmXJkEsg82zhq",
	"hh1Q+SfDLk0+atGZOLEeDkt3nqdDxQhhGVBSQgYDpmqJ",
	"YSagOWuLqfyZ13KmSfSJV95qCFQrW8oDwEtmNQnLkbDQ",
	"6wbabZ5czUMOsA+xOlg/VHr/P5wD3+U7bOrWonMZMRiK",
}
var MasterKey *[]byte
var UnsealKey *[]byte

func getWrapper(key []byte) (*aead.Wrapper, error) {
	root := aead.NewWrapper(nil)
	root.SetConfig(map[string]string{"key_id": "root"})
	if err := root.SetAESGCMKeyBytes(key); err != nil {
		return nil, fmt.Errorf("SetAESGCMKeyBytes: %w", err)
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

func readStoredKeys() ([]byte, error) {
	value, err := ioutil.ReadFile("tmp/data/core/hsm/barrier-unseal-keys")
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}
	pe, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", value))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %w", err)
	}

	blobInfo := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(pe, blobInfo); err != nil {
		return nil, fmt.Errorf("failed to proto decode stored keys: %s", err)
	}
	aeadWrapper, err := getWrapper(*MasterKey)
	if err != nil {
		return nil, fmt.Errorf("getWrapper: %w", err)
	}

	pt, err := aeadWrapper.Decrypt(context.Background(), blobInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt keys for storage: %s", err)
	}
	// Decode the barrier entry
	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return nil, fmt.Errorf("failed to decode stored keys: %v", err)
	}
	log.Debugf("key:%s", spew.Sdump(keys[0]))
	return keys[0], nil
}

func decryptTarget(target string, path string) ([]byte, error) {

	ciphertext, err := ioutil.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	ciphertextBin, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", ciphertext))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %w", err)
	}
	log.Debugf("ciphertextBin: %s", spew.Sdump(ciphertextBin))
	aeadKey, err := aeadFromKey(*UnsealKey)
	if err != nil {
		return nil, fmt.Errorf("aeadFromKey: %w", err)

	}
	clear, err := decryptInternal(path, aeadKey, ciphertextBin)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	log.Debugf("Clear=%s", spew.Sdump(clear))
	return clear, nil

}
func decryptTargetWrapped(target string) ([]byte, error) {

	ciphertext, err := ioutil.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	ciphertextBin, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", ciphertext))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %w", err)
	}
	se := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(ciphertextBin, se); err != nil {
		return nil, fmt.Errorf("proto Unmarshal %w", err)
	}

	log.Debugf("EncryptedBlobInfo:%s", spew.Sdump(se))

	aeadWrapper, err := getWrapper(*UnsealKey)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	clear, err := aeadWrapper.Decrypt(context.Background(), se, nil)
	if err != nil {
		return nil, fmt.Errorf("aeadWrapper.Decrypt: %w", err)
	}
	log.Debugf("Clear=%s", spew.Sdump(clear))
	return clear, nil

}
func main_() int {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)
	log.Infof("Starting version %s", version)
	fmt.Printf("keyring=%s\nunsealkeys=%s", spew.Sdump(keyring), spew.Sdump(unsealKeys))

	var unsealKeysBins [][]byte
	for _, v := range unsealKeys {
		tmpBin, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			log.Fatalf("Error decoding base64 key:%s", err)
			return 1
		}
		unsealKeysBins = append(unsealKeysBins, tmpBin)
	}
	masterKey, err := shamir.Combine(unsealKeysBins)
	if err != nil {
		log.Fatalf("failed to generate key from shares: %s", err)
	}
	log.Infof("Master key")
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(masterKey))

	MasterKey = &masterKey

	unsealKey, err := readStoredKeys()
	if err != nil {
		log.Fatalf("failed to decrypt unseal keys: %s", err)
		return 1
	}
	log.Debugf("Unseal keys:%s", spew.Sdump(unsealKey))
	UnsealKey = &unsealKey

	keyRingJSON, err := decryptTarget("tmp/data/core/keyring", "core/keyring")

	if err != nil {
		log.Fatalf("Error decrypting Keyring:%s", err)
		return 1
	}

	log.Debugf("Keyring:%s", keyRingJSON)
	return 0

}

func main() {
	os.Exit(main_())
}
