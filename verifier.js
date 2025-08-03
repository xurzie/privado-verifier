const path = require("path");
const express = require("express");
const { auth, resolver } = require("@iden3/js-iden3-auth");
const getRawBody = require("raw-body");
const cors = require("cors");
const qrcode = require("qrcode");
const { v4: uuidv4 } = require("uuid");

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

app.get("/api/status", (req, res) => {
  const sessionId = req.query.sessionId;
  if (!sessionId) return res.status(400).json({ error: "No sessionId provided" });

  const result = verificationResults.get(sessionId);
  if (result === undefined) {
    return res.status(200).json({ verified: null }); // ожидаем
  }

  return res.status(200).json({ verified: result }); // true / false
});

app.listen(port, () => {
  console.log(`✅ Verifier running on http://localhost:${port}`);
});

// ======= КОНФІГ =======
const NGROK_URL = "https://96b42d28782f.ngrok-free.app"; // ⚠️ заміни кожен раз при запуску
const CALLBACK_PATH = "/api/callback";
const SESSION_ID = "1";
const AUDIENCE = "did:iden3:privado:main:2SeSki4yyingxX8GoYPAnFdNJKsj5v2HtaA3W5EHiU";
const KEY_DIR = "D:/WORK/privado-verifier/keys/";

const requestMap = new Map();
const verificationResults = new Map(); // 🆕

// ======= QR та auth-запит =======
async function getAuthRequest(req, res) {
  const callbackUrl = `${NGROK_URL}${CALLBACK_PATH}?sessionId=${SESSION_ID}`;
  const id = uuidv4();

  const proofRequest = {
    id: 1,
    circuitId: "credentialAtomicQuerySigV2",
    query: {
      allowedIssuers: ["*"],
      type: "KYCAgeCredential",
      context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: { $lt: 20070714 },
      },
    },
  };

  const request = auth.createAuthorizationRequest("Login with PrivadoID", AUDIENCE, callbackUrl);
  request.body.scope = [...(request.body.scope || []), proofRequest];

  requestMap.set(SESSION_ID, request);

  res.status(200).json({ ...request, sessionId: SESSION_ID });
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

  console.log("🛠️ circuitsDir =", KEY_DIR);
  const authRequest = requestMap.get(sessionId);
  console.log("🛠️ circuitId =", authRequest?.body?.scope?.[0]?.circuitId);

  const verifier = await auth.Verifier.newVerifier({
    stateResolver: resolvers,
    circuitsDir: KEY_DIR,
    ipfsGatewayURL: "https://ipfs.io",
  });

  try {
    const opts = { AcceptedStateTransitionDelay: 5 * 60 * 1000 };
    const authResponse = await verifier.fullVerify(tokenStr, authRequest, opts);

    verificationResults.set(sessionId, true); // ✅ успешно
    return res.status(200).json(authResponse);
  } catch (err) {
    console.error("💥 Verification error:", err);
    verificationResults.set(sessionId, false); // ❌ ошибка
    return res.status(500).json({ error: err.message });
  }
}
