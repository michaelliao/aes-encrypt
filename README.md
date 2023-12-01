# aes-encrypt

A simple command line tool for AES encryption and decryption.

Here is the encryption process:

```mermaid
flowchart
    Pwd[Password]
    Msg[Message]
    Key(Pbkdf2 Key)
    RS[Random Salt]
    Enc(Encrypted Data)
    IV[Random IV]

    Pwd -->|generate| Key
    RS -->|generate| Key
    Msg --> |AES-256-CBC| Enc
    Key --> |AES-256-CBC| Enc
    IV --> |AES-256-CBC| Enc
```

## Usage

To encrypt a message, type:

```
$ node aes.mjs encrypt my-secret.json
```

Enter password:

```
password: hello12345
```

Then type messages:

```
type messages (type EOF to end):
Hello, this is a secret file!
Using AES encryption!
EOF
```

Enter `EOF` to indicate the end of the message, and the encrypted data will be saved as a JSON file:

```
encrypted data saved: my-secret.json
{
  "hash-alg": "sha256",
  "message-iv-hash": "2fb92934a7b17cafef3a5e29212b0bd73ee035d80294bdaa16fdeb34742eaa46",
  "encrypt-alg": "aes-256-cbc",
  "encrypt-iv": "31d09b20a0fce0ab572653b41c7fba56",
  "encrypt-data": "48f307ba5b51fc73c4843ec6524ee07b239d9e0d7af76cfec2affaf5035a3d0534f67d7643872f143eebd2abbc9e27bb81f0383b5d1f5c132b0d8afa194c56dd",
  "pbkdf2-salt": "923a3c3f1372cf7b9cdc254473a1ee4e64b33fa07fc32130e6dbc40199b04326",
  "pbkdf2-iterations": 999999
}
```

To decrypt a message, type:

```
$ node aes.mjs decrypt my-secret.json 
```

Enter password (don't use the weak password):

```
password: hello12345
```

If the password entered is correct, the decrypted message will be displayed:

```
Decrypted ok:
Hello, this is a secret file!
Using AES encryption!
```

## Notes

- Don't use weak password.

- The password and the original message are entered via the keyboard and are never stored.

- The encrypted JSON files can be securely backed up anywhere.

- Executable program is not provided to prevent malicious tampering, please install [Node.js](https://nodejs.org) and download the [source file](https://github.com/michaelliao/aes-encrypt/blob/master/aes.mjs) from GitHub and verify by yourself.

- It is recommended to run it offline and close the console window when the program end.
