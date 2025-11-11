/**
 * crypto-utils.js
 * Cryptography utilities for DePIN group messaging using Neurai keys
 */

// Constants
const AES_IV = '00000000000000000000000000000000'; // Fixed IV for AES-CBC
const AES_KEY_SIZE = 256; // AES-256
const CURVE_NAME = 'secp256k1';
const CURRENT_VERSION = '1.0';
const CIPHER_ALGORITHM = 'AES-CBC-256';

/**
 * Function to get EC instance (lazy initialization)
 * @returns {Object} Elliptic curve instance
 */
function getEC() {
    if (!window.ecInstance) {
        console.log('Attempting to initialize EC...');
        console.log('typeof elliptic:', typeof elliptic);
        console.log('window.elliptic:', typeof window.elliptic);

        // Try to get elliptic from different sources
        let EC;

        if (typeof elliptic !== 'undefined' && elliptic.ec) {
            // elliptic from CDN
            console.log('✅ Using elliptic from global variable');
            EC = elliptic.ec;
        } else if (typeof window.elliptic !== 'undefined' && window.elliptic.ec) {
            // elliptic in window
            console.log('✅ Using elliptic from window.elliptic');
            EC = window.elliptic.ec;
        } else {
            // Last attempt: search in global object
            console.error('❌ elliptic not found anywhere');
            console.log('Available global variables:', Object.keys(window).filter(k => k.toLowerCase().includes('ellip')));
            throw new Error('The elliptic library is not loaded. Make sure to include: <script src="https://cdn.jsdelivr.net/npm/elliptic@6.5.4/dist/elliptic.min.js"></script>');
        }

        console.log(`Creating EC instance with ${CURVE_NAME}...`);
        window.ecInstance = new EC(CURVE_NAME);
        console.log('✅ EC initialized correctly');
    }
    return window.ecInstance;
}

/**
 * Decodes a Neurai WIF private key using NeuraiKey
 * @param {string} wif - Private key in WIF format
 * @returns {Object} - {privateKey: Uint8Array, compressed: boolean}
 */
function decodeWIF(wif) {
    try {
        // Determine network based on WIF prefix
        // Neurai mainnet: starts with 'K' or 'L' (compressed) or '5' (uncompressed)
        // Neurai testnet: starts with 'c' (compressed) or '9' (uncompressed)
        let network = 'xna'; // mainnet by default
        
        if (wif.startsWith('c') || wif.startsWith('9')) {
            network = 'xna-test'; // testnet
        }
        
        // Use NeuraiKey to get address and private key from WIF
        const addressData = NeuraiKey.getAddressByWIF(network, wif);
        
        // Convert private key hex to Uint8Array
        const privateKeyHex = addressData.privateKey;
        const privateKeyBytes = new Uint8Array(privateKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        
        // Determine if compressed (WIF starting with K, L or c are compressed)
        const compressed = wif.startsWith('K') || wif.startsWith('L') || wif.startsWith('c');
        
        return {
            privateKey: privateKeyBytes,
            compressed: compressed
        };
    } catch (error) {
        throw new Error('WIF decoding error: ' + error.message);
    }
}

/**
 * Decodes a compressed public key (hex format)
 * @param {string} pubHex - Public key in compressed hex format (66 characters)
 * @returns {Object} - Elliptic curve point
 */
function decodeCompressedPublicKey(pubHex) {
    try {
        if (pubHex.length !== 66) {
            throw new Error(`Incorrect length: expected 66, received ${pubHex.length}`);
        }
        
        const pubBytes = hexToBytes(pubHex);
        const prefix = pubBytes[0];
        const x = pubBytes.slice(1);
        
        // Create point from compressed bytes
        const ec = getEC();
        const key = ec.keyFromPublic(pubBytes);
        return key.getPublic();
    } catch (error) {
        throw new Error(`Public key decoding error: ${error.message}`);
    }
}

/**
 * Encrypts a message for multiple recipients
 * @param {string} senderWIF - Sender's WIF private key
 * @param {Array<string>} recipientPubKeys - Array of recipients' public keys
 * @param {string} plaintext - Message to encrypt
 * @returns {Object} - Encrypted message
 */
function encryptGroupMessage(senderWIF, recipientPubKeys, plaintext) {
    try {
        const ec = getEC();
        
        // Decode sender's private key
        const senderDecoded = decodeWIF(senderWIF);
        const senderKey = ec.keyFromPrivate(senderDecoded.privateKey);
        const senderPubKey = senderKey.getPublic();
        
        // Generate ephemeral key
        const ephemeralKey = ec.genKeyPair();
        const ephemeralPrivate = ephemeralKey.getPrivate();
        const ephemeralPublic = ephemeralKey.getPublic();
        
        // Derive AES-256 key from ephemeral key
        const ephemeralBytes = ephemeralPrivate.toArray('be', 32);
        const messageKeyMaterial = CryptoJS.lib.WordArray.create(ephemeralBytes);
        const aesKey = CryptoJS.SHA256(messageKeyMaterial); // 32 bytes for AES-256
        
        // Encrypt message with AES-256-CBC
        const plaintextBytes = CryptoJS.enc.Utf8.parse(plaintext);
        const encrypted = CryptoJS.AES.encrypt(plaintextBytes, aesKey, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: CryptoJS.enc.Hex.parse(AES_IV)
        });
        
        const ciphertext = encrypted.ciphertext.toString();
        
        // Encrypt ephemeral key for each recipient
        const encryptedKeys = {};
        
        for (const recipientPubHex of recipientPubKeys) {
            const recipientPubKey = decodeCompressedPublicKey(recipientPubHex);
            
            // ECDH: shared secret
            const sharedSecret = recipientPubKey.mul(ephemeralPrivate);
            const sharedX = sharedSecret.getX().toArray('be', 32);
            
            // Derive wrap key AES-256
            const sharedSecretWA = CryptoJS.lib.WordArray.create(sharedX);
            const wrapKey = CryptoJS.SHA256(sharedSecretWA); // 32 bytes for AES-256
            
            // Encrypt the message key (32 bytes)
            const keyToWrap = CryptoJS.lib.WordArray.create(ephemeralBytes);
            const wrappedKey = CryptoJS.AES.encrypt(keyToWrap, wrapKey, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            });
            
            encryptedKeys[recipientPubHex] = wrappedKey.ciphertext.toString();
        }
        
        // Prepare encrypted message
        return {
            version: CURRENT_VERSION,
            sender_pubkey: publicKeyToHex(senderPubKey, true),
            ephemeral_public: publicKeyToHex(ephemeralPublic, true),
            ciphertext: ciphertext,
            encrypted_keys: encryptedKeys,
            cipher: CIPHER_ALGORITHM
        };
        
    } catch (error) {
        throw new Error(`Encryption error: ${error.message}`);
    }
}

/**
 * Decrypts a group message
 * @param {Object} encryptedMsg - Encrypted message
 * @param {string} recipientWIF - Recipient's WIF private key
 * @returns {string} - Decrypted message
 */
function decryptGroupMessage(encryptedMsg, recipientWIF) {
    try {
        const ec = getEC();
        // Decode recipient's private key
        const recipientDecoded = decodeWIF(recipientWIF);
        const recipientKey = ec.keyFromPrivate(recipientDecoded.privateKey);
        const recipientPubKey = recipientKey.getPublic();
        const recipientPubHex = publicKeyToHex(recipientPubKey, true);
        
        // Verify that this recipient is authorized
        if (!(recipientPubHex in encryptedMsg.encrypted_keys)) {
            throw new Error(
                `You are not authorized to decrypt this message.\n` +
                `Your public key: ${recipientPubHex}\n` +
                `Authorized keys: ${Object.keys(encryptedMsg.encrypted_keys).join(', ')}`
            );
        }
        
        // Reconstruct ephemeral public key
        const ephemeralPublic = decodeCompressedPublicKey(encryptedMsg.ephemeral_public);
        
        // ECDH: shared secret
        const sharedSecret = ephemeralPublic.mul(recipientKey.getPrivate());
        const sharedX = sharedSecret.getX().toArray('be', 32);
        
        // Derive wrap key AES-256
        const sharedSecretWA = CryptoJS.lib.WordArray.create(sharedX);
        const wrapKey = CryptoJS.SHA256(sharedSecretWA); // 32 bytes
        
        // Decrypt the message key
        const encryptedKeyHex = encryptedMsg.encrypted_keys[recipientPubHex];
        const encryptedKeyWA = CryptoJS.enc.Hex.parse(encryptedKeyHex);
        
        const unwrappedKey = CryptoJS.AES.decrypt(
            { ciphertext: encryptedKeyWA },
            wrapKey,
            {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            }
        );
        
        // Derive AES-256 key from key material
        const aesKey = CryptoJS.SHA256(unwrappedKey); // 32 bytes
        
        // Decrypt the message
        const ciphertextWA = CryptoJS.enc.Hex.parse(encryptedMsg.ciphertext);
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: ciphertextWA },
            aesKey,
            {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: CryptoJS.enc.Hex.parse(AES_IV)
            }
        );
        
        return decrypted.toString(CryptoJS.enc.Utf8);
        
    } catch (error) {
        throw new Error(`Decryption error: ${error.message}`);
    }
}

/**
 * Converts a public key point to hex format
 * @param {Object} pubKey - Elliptic curve point
 * @param {boolean} compressed - If it should be compressed
 * @returns {string} - Public key in hex format
 */
function publicKeyToHex(pubKey, compressed = true) {
    return pubKey.encode('hex', compressed);
}

/**
 * Converts hex string to Uint8Array
 * @param {string} hex - Hexadecimal string
 * @returns {Uint8Array} - Byte array
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Gets public key and address from a WIF private key
 * @param {string} wif - Private key in WIF format
 * @returns {Object} - {publicKey: string, address: string}
 */
function getPublicKeyFromWIF(wif) {
    try {
        // Determine the network
        let network = 'xna';
        if (wif.startsWith('c') || wif.startsWith('9')) {
            network = 'xna-test';
        }

        // Use NeuraiKey to get the complete information
        const addressData = NeuraiKey.getAddressByWIF(network, wif);

        // Convert private key hex to bytes for elliptic to get public key
        const privateKeyHex = addressData.privateKey;
        const privateKeyBytes = new Uint8Array(privateKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        // Use elliptic to get the public key
        const ec = getEC();
        const key = ec.keyFromPrivate(privateKeyBytes);
        const publicKeyHex = publicKeyToHex(key.getPublic(), true);

        return {
            publicKey: publicKeyHex,
            address: addressData.address
        };
    } catch (error) {
        throw new Error(`Public key retrieval error: ${error.message}`);
    }
}
