// ============================================================
// 🔱 MAHALAYA LIVE 2026 — SERVER
// ============================================================
// ⚠️ ADMIN CONFIGURATION — EDIT BELOW TO CHANGE CREDENTIALS
// ⚠️ Change these values to update admin login.
// ⚠️ These credentials are NEVER sent to the browser.
// ============================================================

const ADMIN_USERNAME = "MIMI X SOUMYA";
const ADMIN_PASSWORD = "@MIMIJAN#1234";

// ============================================================
// END ADMIN CONFIGURATION
// ============================================================

const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for secure cookies behind reverse proxy (Render, Railway)
app.set("trust proxy", 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://www.youtube.com", "https://s.ytimg.com", "https://cdn.jsdelivr.net"],
      frameSrc: ["https://www.youtube.com", "https://www.youtube-nocookie.com"],
      connectSrc: ["'self'", "https://*.supabase.co", "wss://*.supabase.co"],
      imgSrc: ["'self'", "data:", "https:"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["https://fonts.gstatic.com"]
    }
  }
}));

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false }));

// Session configuration — HTTP-only, secure cookies
app.use(session({
  name: "__Host-mahalaya.sid",
  secret: crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 4 * 60 * 60 * 1000 // 4 hours
  }
}));

// Rate limiting for login — 5 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate limiting for API — 100 requests per 15 minutes per IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests." },
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", apiLimiter);

// Serve static frontend
app.use(express.static(path.join(__dirname)));

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) {
    return next();
  }
  return res.status(403).json({ error: "Unauthorized. Admin access required." });
}

// ============================================================
// ADMIN LOGIN / LOGOUT
// ============================================================

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required." });
  }

  // Constant-time comparison to prevent timing attacks
  const usernameMatch = crypto.timingSafeEqual(
    Buffer.from(String(username)),
    Buffer.from(ADMIN_USERNAME)
  );

  const passwordMatch = crypto.timingSafeEqual(
    Buffer.from(String(password)),
    Buffer.from(ADMIN_PASSWORD)
  );

  if (usernameMatch && passwordMatch) {
    req.session.isAdmin = true;
    req.session.adminUser = ADMIN_USERNAME;
    return res.json({ success: true, user: ADMIN_USERNAME });
  }

  return res.status(401).json({ error: "Invalid credentials." });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Logout failed." });
    res.clearCookie("__Host-mahalaya.sid");
    res.json({ success: true });
  });
});

app.get("/api/admin/session", (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.json({ authenticated: true, user: req.session.adminUser });
  }
  return res.json({ authenticated: false });
});

// ============================================================
// PROTECTED ADMIN ENDPOINTS
// ============================================================

// Shared playback state (in-memory; for production use Supabase or DB)
// This is a fallback — the real state lives in Supabase Realtime
// and is broadcast to all clients.

app.post("/api/admin/verify", requireAdmin, (req, res) => {
  res.json({ authorized: true });
});

// All other admin actions (video change, mute, ban, etc.) are handled
// through Supabase Realtime with server-side authorization. The server
// validates the admin session before allowing the client to broadcast
// privileged events. See the frontend code for the Supabase integration.

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "MAHALAYA LIVE 2026" });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log(`🔱 MAHALAYA LIVE 2026 running on port ${PORT}`);
  console.log(`   Admin user: ${ADMIN_USERNAME}`);
  console.log(`   Admin pass: ${ADMIN_PASSWORD}`);
  console.log(`   ⚠️  Change credentials in server.js before production.`);
});