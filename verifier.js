const path = require("path");
const express = require("express");
const { auth, resolver } = require("@iden3/js-iden3-auth");
const getRawBody = require("raw-body");
const cors = require("cors");
const qrcode = require("qrcode");

const app = express();
const port = 8080;

app.use(express.static(path.join(__dirname, "static"))); // index.html и QR
app.use(cors());

app.get("/api/sign-in", async (req, res) => {
  console.log("📥 GET /api/sign-in");
  await getAuthRequest(req, res);
});

app.post("/api/callback", async (req, res) => {
  console.log("📬 POST /api/callback");
  await callback(req, res);
});

app.listen(port, () => {
  console.log(`✅ Verifier running on http://localhost:${port}`);
});

// ======= КОНФІГ =======
const NGROK_URL = "https://bc0538c49ab4.ngrok-free.app"; // ⚠️ заміни, коли новий
const CALLBACK_PATH = "/api/callback";
const SESSION_ID = "1"; // як рядок
const SIGNIN_PATH = "/api/sign-in";
const AUDIENCE = "did:iden3:privado:main:2SeSki4yyingxX8GoYPAnFdNJKsj5v2HtaA3W5EHiU";
const KEY_DIR = "../keys"; // де .zkey / wasm / verification_key.json

const requestMap = new Map();

// ======= QR та auth-запит =======
async function getAuthRequest(req, res) {
  const callbackUri = `${NGROK_URL}${CALLBACK_PATH}?sessionId=${SESSION_ID}`;
  const request = auth.createAuthorizationRequest("Login with PrivadoID", AUDIENCE, callbackUri);

  const proofRequest = {
    id: 1,
    circuitId: "credentialAtomicQuerySigV2",
    query: {
      allowedIssuers: ["*"],
      type: "KYCAgeCredential",
      context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: { $lt: 20070714 }, // старше 18
      },
    },
  };

  request.body.scope = [...(request.body.scope || []), proofRequest];

  // зберігаємо в Map
  requestMap.set(SESSION_ID, request);

  // тепер генеруємо QR
  const requestUri = `${NGROK_URL}${SIGNIN_PATH}`; // УВАГА: QR → sign-in
  const encoded = encodeURIComponent(requestUri);
  const iden3Uri = `iden3comm://?request_uri=${encoded}`;
  const qr = await qrcode.toDataURL(iden3Uri);

  res.status(200).json({ qr }); // фронт підставить
}

// ======= Обробка callback =======
async function callback(req, res) {
  const sessionId = req.query.sessionId;
  if (!sessionId || !requestMap.has(sessionId)) {
    return res.status(400).json({ error: "Invalid session ID" });
  }

  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  const resolvers = {
    "polygon:amoy": new resolver.EthStateResolver(
      "https://rpc-amoy.polygon.technology",
      "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"
    ),
    "privado:main": new resolver.EthStateResolver(
      "https://rpc-mainnet.privado.id",
      "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"
    ),
  };

  const verifier = await auth.Verifier.newVerifier({
    stateResolver: resolvers,
    circuitsDir: path.join(__dirname, KEY_DIR),
    ipfsGatewayURL: "https://ipfs.io",
  });

  try {
    const authRequest = requestMap.get(sessionId);
    const opts = { AcceptedStateTransitionDelay: 5 * 60 * 1000 }; // 5 хв
    const authResponse = await verifier.fullVerify(tokenStr, authRequest, opts);
    return res.status(200).json(authResponse);
  } catch (err) {
    console.error("💥 Verification error:", err);
    return res.status(500).json({ error: err.message });
  }
}
