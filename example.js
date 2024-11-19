const saturnin = require('./build/Release/saturnin'); // Import the Saturnin cipher
const sat = new saturnin.Saturnin();  // Create a new Saturnin cipher instance

// Example buffers for message, associated data (ad), nonce, and key
const message = Buffer.from('This is the test message');  // Message to encrypt
const ad = Buffer.alloc(0);  // Associated data (empty for now)

// Use 'let' to allow reassignment
let nonce = Buffer.alloc(saturnin.NONCE_SIZE); 
let key = Buffer.alloc(saturnin.KEY_SIZE);  

console.log(saturnin.NONCE_SIZE);
console.log(saturnin.KEY_SIZE);

key = Buffer.from('12345678901234561234567890123456');  // Set the key to a proper value
// Set the key to a proper value

// Regular encryption/decryption using CTR mode
for (let i = 1; i <= 1; i++) {
    // Increment nonce to ensure uniqueness in each iteration
    nonce = Buffer.from('1234567890123456');  
    nonce.writeUInt32LE(i, nonce.length - 4);
    
    // Encrypt the message using the CTR mode
    const encrypted = sat.encrypt(message, ad, nonce, key);
    console.log(`Encrypted (Hex) - Iteration ${i}: ${encrypted.toString('hex')}`);
    
    // Decrypt the encrypted message using the same parameters
    const decrypted = sat.decrypt(encrypted, ad, nonce, key);
    console.log(`Decrypted - Iteration ${i}: ${decrypted.toString()}`);
}

// Hashing the message (CTR mode is typically not used for hashing, but here's a demonstration)
const hash = sat.hash(message);
console.log(`Hash of message: ${hash.toString('hex')}`);

// Short message encryption and decryption (CTR mode should apply here as well)
const shortMessage = Buffer.from('Short');
const shortEncrypted = sat.shortEncrypt(shortMessage, ad, nonce, key);
console.log(`Short Message Encrypted (Hex): ${shortEncrypted.toString('hex')}`);
const shortDecrypted = sat.shortDecrypt(shortEncrypted, ad, nonce, key);
console.log(`Short Message Decrypted: ${shortDecrypted.toString()}`);
