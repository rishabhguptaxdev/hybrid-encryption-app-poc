import forge from 'node-forge';
import { Buffer } from 'buffer';

/**
 * Decrypts the RSA-encrypted symmetric AES key using your server's private key.
 * CLIENT sends this key as a base64-encoded string after encrypting the base64-encoded key using RSA.
 *
 * @param {string} rsaEncryptedKeyBase64 - Base64-encoded RSA-encrypted AES key
 * @param {string} serverPrivateKeyPemBase64 - Base64-encoded PEM string of your RSA private key
 * @returns {string} - The raw 32-byte AES key (binary format)
 */
export const decryptSymmetricKeyWithRSA = (rsaEncryptedKeyBase64, serverPrivateKeyPemBase64) => {
  const privateKeyPem = Buffer.from(serverPrivateKeyPemBase64, 'base64').toString('utf8');
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  // Decode the incoming encrypted key from base64 to binary
  const rsaEncryptedBytes = forge.util.decode64(rsaEncryptedKeyBase64);

  // Decrypt the RSA-encrypted data to get the base64-encoded AES key
  const aesKeyBase64 = privateKey.decrypt(rsaEncryptedBytes, 'RSAES-PKCS1-V1_5');

  // Decode base64 to get the original 32-byte binary key
  return Buffer.from(aesKeyBase64, 'base64').toString('binary');
};

/**
 * Decrypts the AES-encrypted payload using the provided 32-byte symmetric key.
 * The encrypted payload contains base64-encoded JSON before AES encryption.
 *
 * @param {string} aesEncryptedPayloadBase64 - AES-encrypted payload in base64
 * @param {string} aesSymmetricKey - 32-byte AES key in binary format
 * @param {string} iv - Initialization Vector (default is fixed 16-byte value)
 * @returns {Object} - Decrypted original JSON payload
 */
export const decryptPayloadWithAES = (aesEncryptedPayloadBase64, aesSymmetricKey, iv = '1234567890123456') => {
  const encryptedBytes = forge.util.decode64(aesEncryptedPayloadBase64);

  const decipher = forge.cipher.createDecipher('AES-CBC', aesSymmetricKey);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(encryptedBytes, 'raw'));

  if (!decipher.finish()) throw new Error('AES decryption failed');

  // Convert decrypted output to base64 string, then decode that to JSON
  const base64Decoded = Buffer.from(decipher.output.getBytes(), 'utf8').toString();
  return JSON.parse(Buffer.from(base64Decoded, 'base64').toString('utf8'));
};

/**
 * Encrypts a raw 32-byte AES key using CLIENT's public RSA key.
 * The AES key is first base64-encoded before RSA encryption.
 *
 * @param {string} clientPublicKeyPemBase64 - CLIENT's public key (PEM format, base64-encoded)
 * @param {string} aesSymmetricKey - 32-byte AES key in binary
 * @returns {string} - RSA-encrypted AES key (base64-encoded)
 */
export const encryptSymmetricKeyWithRSA = (clientPublicKeyPemBase64, aesSymmetricKey) => {
  if (aesSymmetricKey.length !== 32) throw new Error('AES key must be 32 bytes');

  const aesKeyBase64 = Buffer.from(aesSymmetricKey, 'binary').toString('base64');
  const publicKeyPem = Buffer.from(clientPublicKeyPemBase64, 'base64').toString('utf8');
  const publicKey = forge.pki.certificateFromPem(publicKeyPem).publicKey;

  const rsaEncrypted = publicKey.encrypt(aesKeyBase64, 'RSAES-PKCS1-V1_5');
  return forge.util.encode64(rsaEncrypted);
};

/**
 * Encrypts a JSON payload using a 32-byte AES key (AES/CBC/PKCS5Padding).
 * The JSON is first base64-encoded, then encrypted.
 *
 * @param {Object|string} jsonPayload - The original payload (object or string)
 * @param {string} aesSymmetricKey - 32-byte AES key in binary
 * @param {string} iv - Initialization Vector (default is fixed 16-byte value)
 * @returns {string} - AES-encrypted payload in base64
 */
export const encryptPayloadWithAES = (jsonPayload, aesSymmetricKey, iv = '1234567890123456') => {
  const jsonString = typeof jsonPayload === 'string' ? jsonPayload : JSON.stringify(jsonPayload);
  const base64EncodedJson = Buffer.from(jsonString, 'utf8').toString('base64');

  const cipher = forge.cipher.createCipher('AES-CBC', aesSymmetricKey);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(base64EncodedJson, 'utf8'));
  cipher.finish();

  return forge.util.encode64(cipher.output.getBytes());
};

/**
 * Wrapper to decrypt a full incoming payload from CLIENT using RSA + AES
 *
 * @param {Object} payload - { RequestEncryptedValue, GWSymmetricKeyEncryptedValue }
 * @returns {Object} - Decrypted original JSON payload
 */
export const decryptFullClientPayload = (payload) => {
  const { GWSymmetricKeyEncryptedValue, RequestEncryptedValue } = payload;
  const aesKey = decryptSymmetricKeyWithRSA(GWSymmetricKeyEncryptedValue, process.env.SERVER_PRIVATE_KEY);
  return decryptPayloadWithAES(RequestEncryptedValue, aesKey);
};

/**
 * Wrapper to encrypt a response JSON for CLIENT using AES + RSA
 *
 * @param {Object} responseData - JSON response to encrypt
 * @returns {Object} - Encrypted payload with { ResponseEncryptedValue, SymmetricKeyEncryptedValue }
 */
export const encryptFullClientPayload = (responseData) => {
  const aesKey = forge.random.getBytesSync(32);
  const encryptedPayload = encryptPayloadWithAES(responseData, aesKey);
  const encryptedKey = encryptSymmetricKeyWithRSA(process.env.CLIENT_PUBLIC_KEY, aesKey);
  return {
    ResponseEncryptedValue: encryptedPayload,
    SymmetricKeyEncryptedValue: encryptedKey,
  };
};
