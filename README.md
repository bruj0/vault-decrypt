# vault-decrypt
This utility will decrypt any value from Vault storage provided you have the unseal keys.
It currently only works in the open source version of Vault and was tested with version 1.7

# Usage

```
❯ ./vault-decrypt
INFO[0000] Vault-decrypt starting version 0.2
  -barrier-unseal-keys string
        Path to a file with the base64 encrypted value of the barrier unseal keys (default "tmp/data/core/hsm/barrier-unseal-keys")
  -debug
        Enable debug output (optional)
  -encrypted-file string
        Path to the file to decrypt
  -encrypted-vault-path string
        Logical path inside Vault storage to the key
  -key-ring string
        Path to a file with the base64 encrypted value of the keyring (default "tmp/data/core/keyring")

v ❯ ./vault-decrypt -barrier-unseal-keys tmp/data/core/hsm/barrier-unseal-keys -encrypted-file tmp/data/sys/expire/id/auth/token/create/h6a3062800e8bcf65bf874510eea86e90d1348f672a6805ad9cd458d472a4878f -encrypted-vault-path sys/expire/id/auth/token/create/h6a3062800e8bcf65bf874510eea86e90d1348f672a6805ad9cd458d472a4878f -k
ey-ring tmp/data/core/keyring
INFO[0000] Vault-decrypt starting version 0.2
INFO[0000] Decrypted data:([]uint8) (len=888 cap=892) {
 00000000  7b 22 6c 65 61 73 65 5f  69 64 22 3a 22 61 75 74  |{"lease_id":"aut|
..
 00000370  73 69 6f 6e 22 3a 31 7d                           |sion":1}|
}
{
        "lease_id": "auth/token/create/h6a3062800e8bcf65bf874510eea86e90d1348f672a6805ad9cd458d472a4878f",
        "client_token": "s.3gzwGxHLiB5cWnOTSG4626LT",
 ...
        "version": 1
}⏎
```
