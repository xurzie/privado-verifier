const express = require('express');
const cors = require('cors');
const qrcode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { verifyProof } = require('@iden3/js-iden3-auth');
const { generateProofRequest } = require('./utils/proofRequests');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const PORT = 8000;
const HOST = 'https://e4c40dc3f7f7.ngrok-free.app'; // ← укажи свой ngrok-URL

const proofStatus = new Map();

// Отдача index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// 📦 JSON отдача для iden3comm
app.get('/api/proof-request', (req, res) => {
  const requestId = req.query.requestId;
  if (!requestId) return res.status(400).send({ error: 'Missing requestId' });

  const proofRequest = generateProofRequest(requestId, HOST);
  res.setHeader('Content-Type', 'application/json');
  res.json(proofRequest);
});

// 🧾 Генерация QR и ссылки
app.get('/api/request', async (req, res) => {
  const requestId = uuidv4();

  const rawRequestUri = `${HOST}/api/proof-request?requestId=${requestId}`;
  const encodedRequestUri = encodeURIComponent(rawRequestUri);
  const fullUri = `iden3comm://?request_uri=${encodedRequestUri}`;

  const qr = await qrcode.toDataURL(fullUri);

  proofStatus.set(requestId, { verified: null });

  res.send({ qr, requestId, requestUri: fullUri });
});

// 📥 Приём JWZ-доказательства
app.post('/api/callback', async (req, res) => {
  try {
    const { body } = req;
    const requestId = req.query.requestId;

    console.log('📥 Получен JWZ-доказ:', body);

    const result = await verifyProof(body);
    const isVerified = result?.verified === true;

    proofStatus.set(requestId, { verified: isVerified });

    console.log(isVerified ? '✅ Proof valid' : '❌ Proof invalid');
    res.status(isVerified ? 200 : 400).send({ ok: isVerified });
  } catch (e) {
    console.error('💥 Ошибка валидации:', e.message);
    res.status(500).send({ ok: false, error: e.message });
  }
});

// 🔍 Статус верификации
app.get('/status/:requestId', (req, res) => {
  const result = proofStatus.get(req.params.requestId);
  if (result && result.verified !== null) {
    res.send(result);
  } else {
    res.sendStatus(204); // Нет результата пока
  }
});

app.listen(PORT, () => {
  console.log(`✅ Verifier running at ${HOST}`);
});
