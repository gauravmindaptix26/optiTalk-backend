import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRemoteJWKSet, jwtVerify } from "jose";

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

let jwks = null;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STORE_PATH = path.join(__dirname, "..", "data", "users.json");
const STORE_DIR = path.dirname(STORE_PATH);

async function verifyAuth0Token(req) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) throw new Error("Missing Authorization bearer token");

  const domain = process.env.AUTH0_DOMAIN;
  const audience = process.env.AUTH0_AUDIENCE || process.env.AUTH0_CLIENT_ID;
  if (!domain) throw new Error("AUTH0_DOMAIN not configured");
  if (!audience) throw new Error("AUTH0_AUDIENCE or AUTH0_CLIENT_ID not configured");

  const issuer = `https://${domain}/`;
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`));
  }

  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  return payload;
}

function readUsers() {
  try {
    if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
    if (!fs.existsSync(STORE_PATH)) return [];
    const raw = fs.readFileSync(STORE_PATH, "utf8");
    return JSON.parse(raw || "[]");
  } catch {
    return [];
  }
}

export default function handler(req, res) {
  applyCors(req, res, ["GET"]);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });

  (async () => {
    try {
      const claims = await verifyAuth0Token(req);
      const requester = sanitizeUserId(claims.email || claims.sub || "");
      const q = String(req.query.q || "").trim().toLowerCase();

      const users = readUsers();

      // ✅ CRITICAL FIX: Only return users who have ACTUALLY logged in
      // A user has "logged in" if their lastSeen is recent (within last 24 hours)
      // OR if they have a Zego token generated (which happens during login)
      const ONE_HOUR_AGO = Date.now() - (60 * 60 * 1000);
      const now = new Date().toLocaleTimeString();
      console.log(`[Users Search] Query="${q}", Requester="${requester}", Time filter: ${new Date(ONE_HOUR_AGO).toLocaleString()}`);
      
      const filtered = (users || [])
        .filter((u) => {
          const uid = sanitizeUserId(u.email || u.userId || "");
          // Exclude self and users who haven't logged in recently
          if (!uid || uid === requester) return false;
          // Only include users who were active in last hour (recently logged in)
          if (!u.lastSeen || u.lastSeen < ONE_HOUR_AGO) {
            console.log(`  [FILTERED OUT] "${u.name}" (lastSeen=${new Date(u.lastSeen).toLocaleString()})`);
            return false;
          }
          console.log(`  [INCLUDED] "${u.name}" (lastSeen=${new Date(u.lastSeen).toLocaleString()})`);
          return true;
        })
        .filter((u) => {
          if (!q) return true;
          const name = (u.name || "").toLowerCase();
          const email = (u.email || "").toLowerCase();
          return name.includes(q) || email.includes(q);
        });

      const sorted = filtered.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));

      const results = sorted.slice(0, 20).map((u) => ({
        userID: sanitizeUserId(u.email || u.userId || ""),
        name: u.name || u.email || u.userId,
        email: u.email || "",
        picture: u.picture || "",
      }));

      console.log(`[Users Result] Found ${results.length} users matching query. Results:`, 
        results.map(r => `${r.name} (${r.userID})`).join(", "));

      return res.status(200).json({ results });
    } catch (e) {
      const status = e.message?.includes("Missing Authorization") ? 401 : 500;
      return res.status(status).json({ error: e.message || "User search failed" });
    }
  })();
}
