// ============================================================
// 🔱 MAHALAYA LIVE 2026 — SERVER (FIXED v3)
// ============================================================

// ============================================================
// ⚠️⚠️ ADMIN CONFIGURATION — EDIT HERE TO CHANGE CREDENTIALS ⚠️⚠️
// ============================================================
const ADMIN_USERNAME = "MIMI X SOUMYA";
const ADMIN_PASSWORD = "@MIMIJAN#1234";
// ============================================================
// END ADMIN CONFIGURATION
// ============================================================

// Session secret — change to any long random string.
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
// ✅ FIXED SAFE COMPARE
// Previous version called hmacKey.copy() which does NOT exist
// on Node's Hmac object → TypeError → HTTP 500.
// Now we create a FRESH HMAC for each input. Both digests are
// always 32 bytes (SHA-256), so timingSafeEqual never throws.
// ============================================================
function safeCompare(a, b) {
  const aHash = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(a))
    .digest();
  const bHash = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(b))
    .digest();
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
  try {
    const body = req.body || {};
    const username = body.username;
    const password = body.password;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }

    const okUser = safeCompare(username, ADMIN_USERNAME);
    const okPass = safeCompare(password, ADMIN_PASSWORD);

    if (!okUser || !okPass) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    req.session.isAdmin = true;
    req.session.adminUser = ADMIN_USERNAME;

    req.session.save((err) => {
      if (err) {
        console.error("[Session save error]", err);
        return res.status(500).json({ error: "Session save failed." });
      }
      return res.json({ success: true, user: ADMIN_USERNAME });
    });
  } catch (e) {
    console.error("[Login error]", e);
    return res.status(500).json({ error: "Server error: " + e.message });
  }
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

// ============================================================
// GLOBAL ERROR HANDLER — prevents silent 500s
// ============================================================
app.use((err, req, res, next) => {
  console.error("[Global error]", err);
  if (!res.headersSent) {
    res.status(500).json({ error: "Server error." });
  }
});

app.listen(PORT, () => {
  console.log(`🔱 MAHALAYA LIVE 2026 running on port ${PORT}`);
  console.log(`   HTTPS mode: ${isHttps}`);
  console.log(`   Admin user: ${ADMIN_USERNAME}`);
  console.log(`   ⚠️  Change admin credentials in server.js before public launch.`);
});
