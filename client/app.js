import axios from "axios";
import dotenv from "dotenv";
import forge from "node-forge";
import {
  encryptPayloadWithAES,
  encryptSymmetricKeyWithRSA,
  decryptSymmetricKeyWithRSA,
  decryptPayloadWithAES,
} from "./encryptionUtils.js";

dotenv.config();

// CLIENT's public key in base64 PEM format (used to encrypt symmetric key)
const CLIENT_PUBLIC_KEY_BASE64 = process.env.SERVER_PUBLIC_KEY;

// Your client’s private RSA key in base64 PEM format (used to decrypt response)
const CLIENT_PRIVATE_KEY_BASE64 = process.env.CLIENT_PRIVATE_KEY;

// Sample payload to send
const samplePayload = {
  userId: "123456",
  name: "John Doe",
  email: "john.doe@example.com",
};

async function sendEncryptedRequest() {
  try {
    // Step 1: Generate a 32-byte AES key
    const aesSymmetricKey = forge.random.getBytesSync(32);

    // Step 2: Encrypt the payload with AES
    const RequestEncryptedValue = encryptPayloadWithAES(samplePayload, aesSymmetricKey);

    // Step 3: Encrypt the AES key with CLIENT’s public RSA key
    const GWSymmetricKeyEncryptedValue = encryptSymmetricKeyWithRSA(
      CLIENT_PUBLIC_KEY_BASE64,
      aesSymmetricKey
    );

    // Step 4: Send encrypted request to server
    const response = await axios.post("http://localhost:3000/requestAnalyticsEnc", {
      RequestEncryptedValue,
      GWSymmetricKeyEncryptedValue,
    });

    console.log("🔐 Raw encrypted response from server:", response.data);

    // Step 5: Decrypt response AES key using your private RSA key
    const responseSymmetricKey = decryptSymmetricKeyWithRSA(
      response.data.SymmetricKeyEncryptedValue,
      CLIENT_PRIVATE_KEY_BASE64
    );

    // Step 6: Decrypt actual response payload using the decrypted AES key
    const decryptedResponse = decryptPayloadWithAES(
      response.data.ResponseEncryptedValue,
      responseSymmetricKey
    );

    console.log("✅ Decrypted response:", decryptedResponse);
  } catch (error) {
    console.error("❌ Error during encrypted request:", error.message);
  }
}

sendEncryptedRequest();
