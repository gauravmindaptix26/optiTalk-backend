import crypto from "node:crypto";

function rndNum(min, max) {
  return Math.ceil(min + (max - min) * Math.random());
}

function makeRandomIv() {
  const chars = "0123456789abcdefghijklmnopqrstuvwxyz";
  let iv = "";
  for (let i = 0; i < 16; i++) {
    iv += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return iv;
}

function getAlgorithm(secret) {
  const keyLen = secret.length; // secret is Buffer
  if (keyLen === 16) return "aes-128-cbc";
  if (keyLen === 24) return "aes-192-cbc";
  if (keyLen === 32) return "aes-256-cbc";
  throw new Error("Invalid AES key length (must be 16/24/32 bytes)");
}

function aesEncrypt(plainText, secret, iv) {
  const algorithm = getAlgorithm(secret);
  const ivBuf = Buffer.from(iv);
  const cipher = crypto.createCipheriv(algorithm, secret, ivBuf);
  return Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
}

// Token04 generator (Zego spec)
export function generateToken04(appId, userID, secret, effectiveTimeInSeconds, payload = "") {
  if (!appId || typeof appId !== "number") throw new Error("appID invalid");
  if (!userID || typeof userID !== "string") throw new Error("userID invalid");
  if (!Buffer.isBuffer(secret)) throw new Error("secret must be a Buffer");
  if (!effectiveTimeInSeconds || typeof effectiveTimeInSeconds !== "number")
    throw new Error("effectiveTimeInSeconds invalid");

  const createTime = Math.floor(Date.now() / 1000);

  const tokenInfo = {
    app_id: appId,
    user_id: userID,
    nonce: rndNum(-2147483648, 2147483647),
    ctime: createTime,
    expire: createTime + effectiveTimeInSeconds,
    payload: payload || "",
  };

  const plainText = JSON.stringify(tokenInfo);
  const iv = makeRandomIv();
  const encryptBuf = aesEncrypt(plainText, secret, iv);

  const b1 = new Uint8Array(8);
  const b2 = new Uint8Array(2);
  const b3 = new Uint8Array(2);

  new DataView(b1.buffer).setBigInt64(0, BigInt(tokenInfo.expire), false);
  new DataView(b2.buffer).setUint16(0, iv.length, false);
  new DataView(b3.buffer).setUint16(0, encryptBuf.byteLength, false);

  const buf = Buffer.concat([
    Buffer.from(b1),
    Buffer.from(b2),
    Buffer.from(iv),
    Buffer.from(b3),
    Buffer.from(encryptBuf),
  ]);

  return "04" + buf.toString("base64");
}

// Helper for API endpoints
export function buildZegoToken(userID) {
  const appId = Number(process.env.ZEGO_APP_ID);
  const rawSecret = (process.env.ZEGO_SERVER_SECRET || "").trim();
  const expireSeconds = Number(process.env.ZEGO_TOKEN_EXPIRE_SECONDS || 3600);

  if (!appId) throw new Error("ZEGO_APP_ID missing/invalid");
  if (!rawSecret) throw new Error("ZEGO_SERVER_SECRET missing");
  if (!userID) throw new Error("userID missing");

  // Use server secret exactly as provided (Zego gives a 32-byte string for AES-256)
  // Do NOT hex-decode; decoding trims it to 16 bytes and produces invalid tokens (50111).
  const secret = Buffer.from(rawSecret, "utf8");
  if (![16, 24, 32].includes(secret.length)) {
    throw new Error(`ZEGO_SERVER_SECRET must be 16/24/32 bytes, got ${secret.length}`);
  }

  return generateToken04(appId, userID, secret, expireSeconds, "");
}
