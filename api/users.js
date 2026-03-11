import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRemoteJWKSet, jwtVerify } from "jose";

const ONLINE_WINDOW_MS = 5 * 60 * 1000;
const RECENT_WINDOW_MS = 24 * 60 * 60 * 1000;

const sanitizeUserId = (raw) =>
  String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "_")
    .replace(/@/g, "_")
    .slice(0, 32);

const getAllowedOrigin = (req) => {
  const configured = process.env.FRONTEND_ORIGIN || "*";
  const origins = configured
    .split(",")
    .map((o) => o.trim().replace(/\/$/, ""))
    .filter(Boolean);
  if (origins.includes("*")) return "*";
  const reqOrigin = (req.headers.origin || "").replace(/\/$/, "");
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

function getPresenceMeta(lastSeen) {
  const lastSeenNumber = Number(lastSeen || 0);
  if (!lastSeenNumber) {
    return {
      presence: "unknown",
      isOnline: false,
      sortBucket: 2,
    };
  }

  const age = Date.now() - lastSeenNumber;
  if (age <= ONLINE_WINDOW_MS) {
    return {
      presence: "online",
      isOnline: true,
      sortBucket: 0,
    };
  }

  if (age <= RECENT_WINDOW_MS) {
    return {
      presence: "recent",
      isOnline: false,
      sortBucket: 1,
    };
  }

  return {
    presence: "offline",
    isOnline: false,
    sortBucket: 2,
  };
}

export default function handler(req, res) {
  applyCors(req, res, ["GET"]);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  (async () => {
    try {
      const claims = await verifyAuth0Token(req);
      const requester = sanitizeUserId(claims.email || claims.sub || "");
      const q = String(req.query.q || "").trim().toLowerCase();
      const normalizedQuery = sanitizeUserId(q);
      const users = readUsers();

      const filtered = (users || [])
        .map((user) => {
          const userID = sanitizeUserId(user.userId || user.email || "");
          if (!userID || userID === requester) return null;

          const name = user.name || user.email || user.userId || userID;
          const email = user.email || "";
          if (q) {
            const nameValue = String(name).toLowerCase();
            const emailValue = String(email).toLowerCase();
            const userIdValue = String(user.userId || userID).toLowerCase();
            const normalizedEmail = sanitizeUserId(email);
            const matchesQuery =
              nameValue.includes(q) ||
              emailValue.includes(q) ||
              userIdValue.includes(q) ||
              (normalizedQuery && userID.includes(normalizedQuery)) ||
              (normalizedQuery && normalizedEmail.includes(normalizedQuery));

            if (!matchesQuery) return null;
          }

          const presenceMeta = getPresenceMeta(user.lastSeen);
          return {
            userID,
            name,
            email,
            picture: user.picture || "",
            lastSeen: Number(user.lastSeen || 0),
            presence: presenceMeta.presence,
            isOnline: presenceMeta.isOnline,
            sortBucket: presenceMeta.sortBucket,
          };
        })
        .filter(Boolean);

      const sorted = filtered.sort((a, b) => {
        if (a.sortBucket !== b.sortBucket) return a.sortBucket - b.sortBucket;
        return (b.lastSeen || 0) - (a.lastSeen || 0);
      });

      const results = sorted.slice(0, 20).map(({ sortBucket, ...user }) => user);

      console.log(
        `[Users Result] Found ${results.length} users for "${q}".`,
        results.map((user) => `${user.name} [${user.presence}]`).join(", "),
      );

      return res.status(200).json({ results });
    } catch (e) {
      const status = e.message?.includes("Missing Authorization") ? 401 : 500;
      return res.status(status).json({ error: e.message || "User search failed" });
    }
  })();
}
