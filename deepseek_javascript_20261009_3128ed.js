// ============================================================
// 🔱 MAHALAYA LIVE 2026 — SERVER (FIXED)
// ============================================================

// ============================================================
// ⚠️⚠️ ADMIN CONFIGURATION — EDIT HERE TO CHANGE CREDENTIALS ⚠️⚠️
// ============================================================
const ADMIN_USERNAME = "MIMI X SOUMYA";
const ADMIN_PASSWORD = "@MIMIJAN#1234";
// ============================================================
// END ADMIN CONFIGURATION
// ============================================================

// Session secret — change this to any long random string.
// Keeping it fixed means admin sessions survive server restarts.
const SESSION_SECRET = "mahalaya-live-2026-change-this-secret-string-please-xyz";

const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Detect HTTPS environment (Render, Railway, or explicit override)
const isHttps =
  process.env.NODE_ENV === "production" ||
  process.env.RENDER === "true" ||
  process.env.FORCE_SECURE_COOKIES === "true";

app.set("trust proxy", 1);

// Security headers — relaxed CSP so YouTube + Supabase CDN load properly
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://www.youtube.com",
          "https://s.ytimg.com",
          "https://cdn.jsdelivr.net"
        ],
        frameSrc: [
          "https://www.youtube.com",
          "https://www.youtube-nocookie.com"
        ],
        connectSrc: [
          "'self'",
          "https://*.supabase.co",
          "wss://*.supabase.co",
          "https://www.youtube.com"
        ],
        imgSrc: ["'self'", "data:", "https:"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["https://fonts.gstatic.com"],
        mediaSrc: ["'self'", "https://www.youtube.com"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false }));

// Session — regular cookie name (no __Host- prefix, works on HTTP + HTTPS)
app.use(
  session({
    name: "mahalaya.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isHttps,
      sameSite: "lax",
      maxAge: 4 * 60 * 60 * 1000 // 4 hours
    }
  })
);

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: { error: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", apiLimiter);

// Serve static frontend
app.use(express.static(path.join(__dirname)));

// ============================================================
// SAFE CONSTANT-TIME COMPARE (handles unequal lengths)
// ============================================================
function safeCompare(a, b) {
  const hmacKey = crypto.createHmac("sha256", SESSION_SECRET);
  const aHash = hmacKey.copy().update(String(a)).digest();
  const bHash = hmacKey.copy().update(String(b)).digest();
  return crypto.timingSafeEqual(aHash, bHash);
}

// ============================================================
// ADMIN MIDDLEWARE
// ============================================================
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) return next();
  return res.status(403).json({ error: "Unauthorized." });
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required." });
  }

  const usernameMatch = safeCompare(username, ADMIN_USERNAME);
  const passwordMatch = safeCompare(password, ADMIN_PASSWORD);

  if (usernameMatch && passwordMatch) {
    req.session.isAdmin = true;
    req.session.adminUser = ADMIN_USERNAME;
    return req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({ error: "Session error. Try again." });
      }
      return res.json({ success: true, user: ADMIN_USERNAME });
    });
  }

  return res.status(401).json({ error: "Invalid credentials." });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("mahalaya.sid");
    res.json({ success: true });
  });
});

app.get("/api/admin/session", (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.json({ authenticated: true, user: req.session.adminUser });
  }
  return res.json({ authenticated: false });
});

app.post("/api/admin/verify", requireAdmin, (req, res) => {
  res.json({ authorized: true, user: req.session.adminUser });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "MAHALAYA LIVE 2026", https: isHttps });
});

// Fallback — serve index.html for any unknown GET
app.get("*", (req, res, next) => {
  if (req.method !== "GET") return next();
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`🔱 MAHALAYA LIVE 2026 running on port ${PORT}`);
  console.log(`   HTTPS mode: ${isHttps}`);
  console.log(`   Admin user: ${ADMIN_USERNAME}`);
  console.log(`   ⚠️  Change admin credentials in server.js before public launch.`);
});