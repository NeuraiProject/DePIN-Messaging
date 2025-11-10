/**
 * app.js
 * User interface logic
 */

// Global variables
let lastEncryptedMessage = null;

/**
 * Switches between tabs
 */
function showTab(evt, tabName) {
    // Hide all tabs
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(btn => btn.classList.remove('active'));
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    const sourceButton = evt?.currentTarget || evt?.target;
    if (sourceButton) {
        sourceButton.classList.add('active');
    }
}

/**
 * Toggle password field visibility
 */
function toggleVisibility(evt, fieldId) {
    const field = document.getElementById(fieldId);
    const button = evt?.currentTarget || evt?.target;

    if (!field || !button) {
        return;
    }

    if (field.type === 'password') {
        field.type = 'text';
        button.textContent = '🙈 Hide';
    } else {
        field.type = 'password';
        button.textContent = '👁️ Show';
    }
}

/**
 * Updates sender's public key display
 */
document.getElementById('sender-wif')?.addEventListener('input', function() {
    const wif = this.value.trim();
    const display = document.getElementById('sender-pubkey-display');
    
    if (!wif) {
        display.innerHTML = '';
        display.classList.remove('success', 'error', 'info-box--stacked');
        display.style.display = 'none';
        return;
    }
    
    try {
        const result = getPublicKeyFromWIF(wif);
        display.innerHTML = `
            <span class="info-box__label">✅ Your Neurai address</span>
            <code class="info-box__value">${escapeHtml(result.address)}</code>
            <span class="info-box__label">Your public key</span>
            <code class="info-box__value">${escapeHtml(result.publicKey)}</code>
        `;
        display.classList.remove('error');
        display.classList.add('success', 'info-box--stacked');
        display.style.display = 'flex';
    } catch (error) {
        display.innerHTML = `<strong>❌ Error:</strong> ${error.message}`;
        display.classList.remove('success');
        display.classList.add('error');
        display.classList.remove('info-box--stacked');
        display.style.display = 'flex';
    }
});

/**
 * Updates recipient's public key display
 */
document.getElementById('recipient-wif')?.addEventListener('input', function() {
    const wif = this.value.trim();
    const display = document.getElementById('recipient-pubkey-display');
    
    if (!wif) {
        display.innerHTML = '';
        display.classList.remove('success', 'error', 'info-box--stacked');
        display.style.display = 'none';
        return;
    }
    
    try {
        const result = getPublicKeyFromWIF(wif);
        display.innerHTML = `
            <span class="info-box__label">✅ Your Neurai address</span>
            <code class="info-box__value">${escapeHtml(result.address)}</code>
            <span class="info-box__label">Your public key</span>
            <code class="info-box__value">${escapeHtml(result.publicKey)}</code>
        `;
        display.classList.remove('error');
        display.classList.add('success', 'info-box--stacked');
        display.style.display = 'flex';
    } catch (error) {
        display.innerHTML = `<strong>❌ Error:</strong> ${error.message}`;
        display.classList.remove('success');
        display.classList.add('error');
        display.classList.remove('info-box--stacked');
        display.style.display = 'flex';
    }
});

/**
 * Updates recipient counter
 */
document.getElementById('recipients')?.addEventListener('input', function() {
    const lines = this.value.trim().split('\n').filter(line => line.trim().length > 0);
    const display = document.getElementById('recipients-count');
    
    if (lines.length === 0) {
        display.innerHTML = '';
        return;
    }
    
    let validCount = 0;
    let invalidCount = 0;
    
    lines.forEach(line => {
        const pubKey = line.trim();
        if (pubKey.length === 66 && /^[0-9a-fA-F]+$/.test(pubKey)) {
            validCount++;
        } else {
            invalidCount++;
        }
    });
    
    if (invalidCount > 0) {
        display.innerHTML = `<strong>⚠️ ${validCount} valid, ${invalidCount} invalid</strong>`;
        display.classList.add('error');
        display.classList.remove('success');
    } else {
        display.innerHTML = `<strong>✅ ${validCount} recipient${validCount !== 1 ? 's' : ''}</strong>`;
        display.classList.remove('error');
        display.classList.add('success');
    }
});

/**
 * Encrypts a message
 */
function encryptMessage() {
    const resultBox = document.getElementById('encrypt-result');
    resultBox.innerHTML = '';
    resultBox.classList.remove('show', 'success', 'error');
    
    try {
        // Get values
        const senderWIF = document.getElementById('sender-wif').value.trim();
        const recipientsText = document.getElementById('recipients').value.trim();
        const plaintext = document.getElementById('plaintext').value.trim();
        
        // Validate
        if (!senderWIF) {
            throw new Error('You must enter your WIF private key');
        }
        
        if (!recipientsText) {
            throw new Error('You must enter at least one recipient public key');
        }
        
        if (!plaintext) {
            throw new Error('Message cannot be empty');
        }
        
        // Process recipients
        const recipients = recipientsText.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
        
        if (recipients.length === 0) {
            throw new Error('You must enter at least one valid public key');
        }
        
        // Validate public keys
        recipients.forEach((pubKey, index) => {
            if (pubKey.length !== 66) {
                throw new Error(`Recipient ${index + 1}: key must be 66 characters (has ${pubKey.length})`);
            }
            if (!/^[0-9a-fA-F]+$/.test(pubKey)) {
                throw new Error(`Recipient ${index + 1}: key must be hexadecimal`);
            }
        });
        
        // Encrypt
        const encryptedMsg = encryptGroupMessage(senderWIF, recipients, plaintext);
        lastEncryptedMessage = encryptedMsg;
        
        // Show result
        resultBox.innerHTML = `
            <h3>✅ Message Encrypted Successfully</h3>
            <p class="result-meta"><strong>Recipients:</strong> ${recipients.length}</p>
            <p class="result-meta"><strong>Ciphertext size:</strong> ${encryptedMsg.ciphertext.length} hex characters</p>
            <p class="result-meta"><strong>Algorithm:</strong> ${encryptedMsg.cipher}</p>
            
            <div class="result-actions">
                <h4 class="result-meta">Encrypted Message JSON:</h4>
                <button class="copy-button" onclick="copyToClipboard(event, 'encrypted-json-output')">📋 Copy JSON</button>
            </div>
            <pre id="encrypted-json-output">${JSON.stringify(encryptedMsg, null, 2)}</pre>
            
            <p style="margin-top: 20px;">
                <strong>Recipients can use the "Decrypt Message" tab with their WIF private key.</strong>
            </p>
        `;
        resultBox.classList.add('show', 'success');
        
    } catch (error) {
        resultBox.innerHTML = `
            <h3>❌ Encryption Error</h3>
            <p>${error.message}</p>
        `;
        resultBox.classList.add('show', 'error');
    }
}

/**
 * Decrypts a message
 */
function decryptMessage() {
    const resultBox = document.getElementById('decrypt-result');
    resultBox.innerHTML = '';
    resultBox.classList.remove('show', 'success', 'error');
    
    try {
        // Get values
        const recipientWIF = document.getElementById('recipient-wif').value.trim();
        const encryptedJSON = document.getElementById('encrypted-json').value.trim();
        
        // Validate
        if (!recipientWIF) {
            throw new Error('You must enter your WIF private key');
        }
        
        if (!encryptedJSON) {
            throw new Error('You must paste the encrypted message JSON');
        }
        
        // Parse JSON
        let encryptedMsg;
        try {
            encryptedMsg = JSON.parse(encryptedJSON);
        } catch (e) {
            throw new Error('Invalid JSON: ' + e.message);
        }
        
        // Validate structure
        if (!encryptedMsg.version || !encryptedMsg.ephemeral_public || 
            !encryptedMsg.ciphertext || !encryptedMsg.encrypted_keys) {
            throw new Error('Invalid JSON: missing required fields');
        }
        
        // Decrypt
        const plaintext = decryptGroupMessage(encryptedMsg, recipientWIF);

        // Show result
        const senderPubKey = encryptedMsg.sender_pubkey || 'N/A';
        const recipientInfo = getPublicKeyFromWIF(recipientWIF);

        // Derivar dirección del emisor desde su clave pública usando NeuraiKey
        let senderAddress = 'N/A';
        try {
            if (senderPubKey !== 'N/A') {
                senderAddress = NeuraiKey.publicKeyToAddress('xna', senderPubKey);
            }
        } catch (error) {
            console.error('Error deriving sender address:', error);
            senderAddress = 'Error: ' + error.message;
        }

        resultBox.innerHTML = `
            <h3>✅ Message Decrypted Successfully</h3>

            <div class="info-box success info-box--stacked">
                <span class="info-box__label">Sender Neurai address:</span>
                <code class="info-box__value">${escapeHtml(senderAddress)}</code>
            </div>

            <div class="info-box success info-box--stacked">
                <span class="info-box__label">Sender public key:</span>
                <code class="info-box__value">${escapeHtml(senderPubKey)}</code>
            </div>

            <div class="info-box success info-box--stacked">
                <span class="info-box__label">Your Neurai address:</span>
                <code class="info-box__value">${escapeHtml(recipientInfo.address)}</code>
            </div>

            <div class="info-box success info-box--stacked">
                <span class="info-box__label">Your public key:</span>
                <code class="info-box__value">${escapeHtml(recipientInfo.publicKey)}</code>
            </div>

            <h4 class="decrypted">📨 Decrypted Message:</h4>
            <div style="background: white; padding: 20px; border-radius: 10px; border: 2px solid #48bb78; margin-top: 10px;">
                <p style="font-size: 1.2em; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(plaintext)}</p>
            </div>
        `;
        resultBox.classList.add('show', 'success');
        
    } catch (error) {
        resultBox.innerHTML = `
            <h3>❌ Decryption Error</h3>
            <p style="white-space: pre-wrap;">${escapeHtml(error.message)}</p>
        `;
        resultBox.classList.add('show', 'error');
    }
}

/**
 * Copies text to clipboard
 */
function copyToClipboard(evt, elementId) {
    const element = document.getElementById(elementId);
    const text = element?.textContent ?? '';

    if (!text) {
        alert('Copy error: No content to copy');
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        const button = evt?.currentTarget || evt?.target;
        if (!button) {
            return;
        }
        const originalText = button.textContent;
        button.textContent = '✅ Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    }).catch(err => {
        alert('Copy error: ' + err);
    });
}

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Loads example data for quick testing
 */
function loadExampleData() {
    document.getElementById('sender-wif').value = 'Ky9XaATe9BQkDiQ4SV24m7jfwaX6NWPTzYmHrnjwiF9kDsB5SYw9';
    document.getElementById('recipients').value = 
        '0214d1dc04b083d8ef72166b9b88a5e3723537c874b7f923bb23f5b9abd412ef8c\n' +
        '03002783a1c63e5815eed9305e4965e3a7cd2da46776d02023e7ada3351e5788ef';
    document.getElementById('plaintext').value = 'Hello people! This is a test message for DePIN group encryption using Neurai keys.';
    
    // Trigger events to update displays
    document.getElementById('sender-wif').dispatchEvent(new Event('input'));
    document.getElementById('recipients').dispatchEvent(new Event('input'));
}

// Add example button
window.addEventListener('load', () => {
    const header = document.querySelector('header');
    const exampleBtn = document.createElement('button');
    exampleBtn.textContent = '🧪 Load Example Data';
    exampleBtn.className = 'btn-small';
    exampleBtn.style.marginTop = '10px';
    exampleBtn.style.background = '#f59e0b';
    exampleBtn.style.color = '#ffffff';
    exampleBtn.style.fontWeight = '600';
    exampleBtn.style.border = 'none';
    exampleBtn.style.boxShadow = '0 4px 12px rgba(245, 158, 11, 0.3)';
    exampleBtn.style.position = 'relative';
    exampleBtn.style.zIndex = '10';
    exampleBtn.onmouseover = () => {
        exampleBtn.style.background = '#d97706';
        exampleBtn.style.transform = 'translateY(-2px)';
        exampleBtn.style.boxShadow = '0 6px 16px rgba(245, 158, 11, 0.4)';
    };
    exampleBtn.onmouseout = () => {
        exampleBtn.style.background = '#f59e0b';
        exampleBtn.style.transform = 'translateY(0)';
        exampleBtn.style.boxShadow = '0 4px 12px rgba(245, 158, 11, 0.3)';
    };
    exampleBtn.onclick = loadExampleData;
    header.appendChild(exampleBtn);
});
