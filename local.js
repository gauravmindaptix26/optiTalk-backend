import express from "express";
import dotenv from "dotenv";
import health from "./api/health.js";
import token from "./api/token.js";
import users from "./api/users.js";
import me from "./api/me.js";

dotenv.config();

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "optiTalk-backend",
    message: "Backend is live",
    routes: {
      health: "/api/health",
      token: "/api/token",
      users: "/api/users",
      me: "/api/me",
    },
  });
});

app.get("/api/health", (req, res) => health(req, res));
app.get("/api/token", (req, res) => token(req, res));
app.options("/api/token", (req, res) => token(req, res));
app.get("/api/users", (req, res) => users(req, res));
app.post("/api/me", (req, res) => me(req, res));
app.options("/api/me", (req, res) => me(req, res));
app.options("/api/users", (req, res) => users(req, res));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Local backend running: http://localhost:${PORT}`);
});
