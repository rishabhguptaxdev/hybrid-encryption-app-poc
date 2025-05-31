import express from 'express';
import dotenv from 'dotenv';
import { decryptFullClientPayload, encryptFullClientPayload } from './encryptionUtils.js';

dotenv.config();
const app = express();
app.use(express.json());
 
app.post('/requestAnalyticsEnc', async (req, res) => {
  try {
    const decryptedBody = decryptFullClientPayload(req.body);
    console.log('Decrypted Request:', decryptedBody);

    // Mocked processing logic
    const result = { status: 'success', data: decryptedBody };
    const encryptedResponse = encryptFullClientPayload(result);

    res.json(encryptedResponse);
  } catch (err) {
    console.error('Error in /requestAnalyticsEnc:', err.message);
    res.status(409).json({ error: 'Error processing encrypted request' });
  }
});

app.post('/getAnalyticsEnc', async (req, res) => {
  try {
    const decryptedBody = decryptFullClientPayload(req.body);
    console.log('Decrypted Request:', decryptedBody);

    const result = {
      status: 'ok',
      info: 'Sample analytics data',
      received: decryptedBody,
    };
    const encryptedResponse = encryptFullClientPayload(result);

    res.json(encryptedResponse);
  } catch (err) {
    console.error('Error in /getAnalyticsEnc:', err.message);
    res.status(409).json({ error: 'Error processing encrypted request' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔐 CLIENT Crypto API running on http://localhost:${PORT}`);
});
