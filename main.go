package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/vault/shamir"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	version = "0.3"
)

func readStoredKeys(barrierKeys []byte, masterkey []byte) ([]byte, error) {
	blobInfo := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(barrierKeys, blobInfo); err != nil {
		return nil, fmt.Errorf("failed to proto decode stored keys: %s", err)
	}
	aeadWrapper, err := getWrapper(masterkey)
	if err != nil {
		return nil, fmt.Errorf("getWrapper: %s", err)
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

func getBinValue(target string) (ciphertext []byte, err error) {
	ciphertext, err = ioutil.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s", err)
	}

	ciphertextBin, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", ciphertext))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %s", err)
	}
	log.Debugf("ciphertextBin: %s", spew.Sdump(ciphertextBin))
	return ciphertextBin, nil
}
func main_() int {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{})
	log.Infof("Vault-decrypt starting version %s", version)

	barrierUnsealKeysPath := flag.String("barrier-unseal-keys", "tmp/data/core/hsm/barrier-unseal-keys", "Path to a file with the base64 encrypted value of the barrier unseal keys")
	keyRingPath := flag.String("key-ring", "tmp/data/core/keyring", "Path to a file with the base64 encrypted value of the keyring")
	encryptedKeyPath := flag.String("encrypted-file", "", "Path to the file to decrypt")
	encryptedKeyVaultPath := flag.String("encrypted-vault-path", "", "Logical path inside Vault storage to the key")
	unsealKeysPath := flag.String("unseal-keys", "", "Path to a file with the unseal keys, one per line")
	debug := flag.Bool("debug", false, "Enable debug output (optional)")
	flag.Parse()

	if len(os.Args) < 10 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	//Read unseal keys from file
	unsealKeysText, err := ioutil.ReadFile(*unsealKeysPath)
	if err != nil {
		log.Fatalf("ReadFile: %s", err)
		return 1
	}
	unsealKeys := strings.Split(string(unsealKeysText), "\n")
	if unsealKeys[len(unsealKeys)-1] == "" {
		unsealKeys = unsealKeys[:len(unsealKeys)-1]
	}
	log.Debugf("Unseal keys=%s", spew.Sdump(unsealKeys))
	//Decode base64 shamir keys and combine them
	var unsealKeysBins [][]byte
	for _, v := range unsealKeys {
		tmpBin, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			log.Fatalf("Error decoding base64 key:%s", err)
			return 1
		}
		unsealKeysBins = append(unsealKeysBins, tmpBin)
	}
	var masterKey []byte
	if len(unsealKeysBins) > 1 {
		masterKey, err = shamir.Combine(unsealKeysBins)
		if err != nil {
			log.Fatalf("failed to generate key from shares: %s", err)
		}
	} else {
		masterKey = unsealKeysBins[0]
	}
	log.Debugf("Master key: %s", base64.StdEncoding.EncodeToString(masterKey))

	//Read barrier unseal key
	barrierKeys, err := getBinValue(*barrierUnsealKeysPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	unsealKey, err := readStoredKeys(barrierKeys, masterKey)
	if err != nil {
		log.Fatalf("failed to decrypt unseal keys: %s", err)
		return 1
	}
	log.Debugf("Unseal keys:%s", spew.Sdump(unsealKey))

	//Read keyring and decrypt it
	keyRingBin, err := getBinValue(*keyRingPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	keyRingJSON, err := decryptTarget(keyRingBin, unsealKey, "core/keyring")

	if err != nil {
		log.Fatalf("Error decrypting Keyring:%s", err)
		return 1
	}
	log.Debugf("Keyring:%s", keyRingJSON)
	keyring, err := DeserializeKeyring(keyRingJSON)
	if err != nil {
		log.Fatalf("failed to generate key from shares: %s", err)
	}

	log.Debugf("Keyring deserialized:%s", spew.Sdump(keyring))

	//Decrypt with keyring
	cipherBin, err := getBinValue(*encryptedKeyPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	clear, err := decryptWithKeyring(keyring, cipherBin, *encryptedKeyVaultPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	log.Infof("Decrypted data:%s", spew.Sdump(clear))

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, clear, "", "\t")
	if error != nil {
		log.Println("JSON parse error: ", error)
		return 1
	}

	fmt.Printf("%s", prettyJSON.String())
	return 0

}

func main() {
	os.Exit(main_())
}
