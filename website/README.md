# Web Version

Web implementation of the group encryption system using Neurai (WIF) keys and AES-256 to use with DePIN messaging. 

In this web-based test, you can try encrypting text using the public keys of various Neurai addresses, which can only be decrypted by the private keys of those addresses.

This is the basis of how Neurai DePIN Messaging works.

### Secure Aspects

- **AES-256:** 256-bit symmetric encryption (military-grade standard)
- **ECDH:** Secure key exchange using elliptic curve
- **Perfect Forward Secrecy:** Each message uses a unique ephemeral key
- **No backend:** Everything is processed in the browser (total privacy)


## Features

- **AES-256 encryption** - Military-grade security
- **Neurai WIF keys** - Compatible with standard Neurai keys
- **ECDH with secp256k1** - Bitcoin's elliptic curve
- **No backend** - All encryption happens in the browser
- **Total privacy** - Keys never leave your device

##  How to Use

### Option 1: Open directly
Simply open `index.html` in your modern web browser.

## Usage Guide

### Encrypt a Message

1. Go to the **"🔒 Encrypt Message"** tab
2. Enter your **Neurai private key (WIF)**
   - Example: `Ky9XaATe9BQkDiQ4SV24m7jfwaX6NWPTzYmHrnjwiF9kDsB5SYw9`
3. Enter the **recipients' public keys** (one per line)
   - Format: 66 hexadecimal characters
   - Example: `03891325b880ef885b533bde2005ae4cec2515d76fc75b00cba6e3a700f00b16fa`
4. Write your **message**
5. Click **"🔒 Encrypt Message"**
6. **Copy the generated JSON** and send it to recipients

### Decrypt a Message

1. Go to the **"🔓 Decrypt Message"** tab
2. Enter your **Neurai private key (WIF)**
3. Paste the **encrypted message JSON**
4. Click **"🔓 Decrypt Message"**
5. Read your decrypted message!

## Test Keys

### Alice (Sender)
- **Private:** `Ky9XaATe9BQkDiQ4SV24m7jfwaX6NWPTzYmHrnjwiF9kDsB5SYw9`
- **Public:** `03891325b880ef885b533bde2005ae4cec2515d76fc75b00cba6e3a700f00b16fa`

### Bob (Recipient)
- **Private:** `L497y1vxt4QZjEVWNSFDUm2Zk2aKxueK8uF86vC4idY8bohMMgfL`
- **Public:** `0214d1dc04b083d8ef72166b9b88a5e3723537c874b7f923bb23f5b9abd412ef8c`

### Charlie (Recipient)
- **Private:** `L1SWnTnp9wYAYHeudy5TGkmSdCfLU2WhAH7aERB5KBFNxnjcMaqA`
- **Public:** `03002783a1c63e5815eed9305e4965e3a7cd2da46776d02023e7ada3351e5788ef`

## JavaScript Libraries (CDN)


1. **[elliptic.js](https://github.com/indutny/elliptic)** (v6.5.4)
   - Elliptic curve cryptography (ECDSA/ECDH)
   - secp256k1 curve (same as Bitcoin)

2. **[crypto-js](https://github.com/brix/crypto-js)** (v4.1.1)
   - AES-256-CBC for symmetric encryption
   - SHA-256 for key derivation

3. **[bs58](https://github.com/cryptocoinjs/bs58)** (v5.0.0)
   - Base58 encoding/decoding
   - Required for decoding WIF keys

4. **[NeuraiKey](https://github.com/NeuraiProject/neurai-key)** (v2.8.5)
   - Required for encoding / decoding Neurai addresses.

---

## How It Works

### Encryption (Alice → Bob, Charlie, David)

1. **Ephemeral key generation**
   - A random ECDSA key pair is created (only for this message)

2. **Message encryption**
   - The message is encrypted ONCE with AES-256-CBC
   - The AES key is derived from the ephemeral private key using SHA-256

3. **Key distribution (ECDH)**
   - For each recipient:
     - Calculate: `shared_secret = recipient_public_key × ephemeral_private_key`
     - The ephemeral key is encrypted with a key derived from the shared secret
   - Result: N encrypted keys (one per recipient)

### Decryption (Bob receives the message)

1. **Reverse ECDH**
   - Bob calculates: `shared_secret = ephemeral_public_key × his_private_key`
   - This is the SAME secret that Alice calculated

2. **Ephemeral key recovery**
   - Bob decrypts his copy of the ephemeral key using the shared secret

3. **Message decryption**
   - Bob uses the ephemeral key to decrypt the message
