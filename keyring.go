package main

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/vault"
)

type Keyring struct {
	masterKey      []byte
	keys           map[uint32]*vault.Key
	activeTerm     uint32
	rotationConfig vault.KeyRotationConfig
	//vault.Keyring
}

// NewKeyring creates a new keyring
func NewKeyring() *Keyring {
	k := &Keyring{
		keys:       make(map[uint32]*vault.Key),
		activeTerm: 0,
		rotationConfig: vault.KeyRotationConfig{
			MaxOperations: int64(3_865_470_566),
		},
	}
	return k
}

// DeserializeKeyring is used to deserialize and return a new keyring
func DeserializeKeyring(buf []byte) (*Keyring, error) {
	// Deserialize the keyring
	var enc vault.EncodedKeyring
	if err := jsonutil.DecodeJSON(buf, &enc); err != nil {
		return nil, fmt.Errorf("deserialization failed: %s", err)
	}

	// Create a new keyring
	k := NewKeyring()
	k.masterKey = enc.MasterKey
	k.rotationConfig = enc.RotationConfig
	k.rotationConfig.Sanitize()
	for _, key := range enc.Keys {
		k.keys[key.Term] = key
		if key.Term > k.activeTerm {
			k.activeTerm = key.Term
		}
	}
	return k, nil
}
