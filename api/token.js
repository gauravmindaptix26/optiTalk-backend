import { buildZegoToken } from "../zegoToken.js";

const sanitizeUserId = (raw) =>
  String(raw ?? "")
    .trim()
    .toLowerCase()
    // Keep IDs within Zego's Web login limit and allowed character set.
    .replace(/[^a-z0-9._-]/g, "_")
    .replace(/@/g, "_")
    .slice(0, 32);

let jwks = null;

async function getJose() {
  // jose v5 is ESM-only
  return await import("jose");
}

async function verifyAuth0Token(req) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) throw new Error("Missing Authorization bearer token");

  const domain = process.env.AUTH0_DOMAIN;
  const audience = process.env.AUTH0_AUDIENCE || process.env.AUTH0_CLIENT_ID;

  if (!domain) throw new Error("AUTH0_DOMAIN not configured");
  if (!audience) throw new Error("AUTH0_AUDIENCE or AUTH0_CLIENT_ID not configured");

  const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const issuer = `https://${cleanDomain}/`;

  const { createRemoteJWKSet, jwtVerify } = await getJose();

  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`));
  }

  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  return payload;
}

const getAllowedOrigin = (req) => {
  const configured = process.env.FRONTEND_ORIGIN || "*";
  const origins = configured
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  if (origins.includes("*")) return "*";

  const reqOrigin = req.headers.origin;
  if (reqOrigin && origins.includes(reqOrigin)) return reqOrigin;

  return origins[0] || "*";
};

function applyCors(req, res, methods = ["GET"]) {
  const origin = getAllowedOrigin(req);
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", `${methods.join(",")},OPTIONS`);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (origin !== "*") {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
}

export default async function handler(req, res) {
  applyCors(req, res, ["GET", "POST"]);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const claims = await verifyAuth0Token(req);
    const userID = sanitizeUserId(claims.email || claims.sub);

    if (!userID) {
      return res.status(400).json({ error: "Could not derive userID from Auth0 token" });
    }

    console.log(`[Token] Generating Zego token for userID="${userID}" (email=${claims.email})`);
    const token = buildZegoToken(userID);
    console.log(`[Token] Token generated successfully, length=${token.length}`);
    return res.status(200).json({ token, userID });
  } catch (e) {
    console.error(`[Token] Error:`, e);
    const msg = e?.message || "Token generation failed";
    const status =
      msg.includes("Authorization") ? 401 :
      msg.includes("JWT") || msg.includes("issuer") || msg.includes("audience") ? 401 :
      500;

    return res.status(status).json({ error: msg });
  }
}

