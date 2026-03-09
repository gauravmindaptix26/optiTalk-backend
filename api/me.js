import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STORE_DIR = path.join(__dirname, "..", "data");
const STORE_PATH = path.join(STORE_DIR, "users.json");

const sanitizeUserId = (raw) =>
  String(raw ?? "")
    .trim()
    .toLowerCase()
    // Keep IDs within Zego's Web login limit and allowed character set.
    .replace(/[^a-z0-9._-]/g, "_")
    .replace(/@/g, "_")
    .slice(0, 32);

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

function applyCors(req, res) {
  const origin = getAllowedOrigin(req);
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (origin !== "*") {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
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

  const { createRemoteJWKSet, jwtVerify } = await import("jose");
  const jwks = createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`));

  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  return payload;
}

function ensureStore() {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  if (!fs.existsSync(STORE_PATH)) fs.writeFileSync(STORE_PATH, "[]", "utf8");
}

function readUsers() {
  try {
    ensureStore();
    const raw = fs.readFileSync(STORE_PATH, "utf8");
    return JSON.parse(raw || "[]");
  } catch {
    return [];
  }
}

function writeUsers(users) {
  try {
    ensureStore();
    fs.writeFileSync(STORE_PATH, JSON.stringify(users, null, 2), "utf8");
  } catch {
    // ignore write failures
  }
}

export default async function handler(req, res) {
  applyCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const claims = await verifyAuth0Token(req);
    const userId = sanitizeUserId(claims.email || claims.sub);
    if (!userId) throw new Error("Could not derive userId");

    const { email, name, picture } = req.body || {};
    const now = Date.now();
    const entry = {
      userId,
      email: email || claims.email || "",
      name: name || claims.name || claims.email || userId,
      picture: picture || claims.picture || "",
      lastSeen: now,  // ✅ ALWAYS update to current time on each login
    };

    const users = readUsers();
    const existingIdx = users.findIndex((u) => u.userId === userId);
    
    if (existingIdx >= 0) {
      console.log(`[User Sync] Updating existing user "${entry.name}" (${userId}) - lastSeen=${new Date(now).toLocaleString()}`);
      users[existingIdx] = { ...users[existingIdx], ...entry };
    } else {
      console.log(`[User Sync] Creating NEW user "${entry.name}" (${userId}) - lastSeen=${new Date(now).toLocaleString()}`);
      users.push(entry);
    }
    
    writeUsers(users);
    console.log(`[User Sync] ✅ User sync successful. Total users: ${users.length}`);
    return res.status(200).json({ ok: true, user: entry });
  } catch (e) {
    console.error(`[User Sync] ❌ Error:`, e?.message);
    const status = e.message?.includes("Missing Authorization") ? 401 : 500;
    return res.status(status).json({ error: e?.message || "Sync failed" });
  }
}
