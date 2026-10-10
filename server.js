// ============================================================
// MAHALAYA LIVE 2026 — SERVER
// Persistent shared state is stored in Supabase Postgres.
// ============================================================
// All sensitive values are provided through Render Environment Variables.
// Never commit admin credentials or session secrets to a public repository.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
if (!ADMIN_USERNAME || !ADMIN_PASSWORD || SESSION_SECRET.length < 32) {
  console.error("Missing/weak server secrets. Set ADMIN_USERNAME, ADMIN_PASSWORD, and SESSION_SECRET in Render Environment Variables.");
  process.exit(1);
}

const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const isHttps = process.env.NODE_ENV === "production" || process.env.RENDER === "true" || process.env.FORCE_SECURE_COOKIES === "true";
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://www.youtube.com", "https://s.ytimg.com", "https://cdn.jsdelivr.net"],
    frameSrc: ["https://www.youtube.com", "https://www.youtube-nocookie.com"],
    connectSrc: ["'self'", "https://*.supabase.co", "wss://*.supabase.co", "https://www.youtube.com"],
    imgSrc: ["'self'", "data:", "https:"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["https://fonts.gstatic.com"],
    mediaSrc: ["'self'", "https://www.youtube.com"]
  } }, crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: "mahalaya.sid", secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: isHttps, sameSite: "lax", maxAge: 4 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: { error: "Too many login attempts. Try again in 15 minutes." }, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 1200, standardHeaders: true, legacyHeaders: false });
app.use("/api/", apiLimiter);

function safeCompare(a, b) {
  const ah = crypto.createHmac("sha256", SESSION_SECRET).update(String(a)).digest();
  const bh = crypto.createHmac("sha256", SESSION_SECRET).update(String(b)).digest();
  return crypto.timingSafeEqual(ah, bh);
}
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) return next();
  return res.status(403).json({ error: "Admin login required." });
}
function dbConfigured() { return Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY); }
function requireDb(req, res, next) {
  if (!dbConfigured()) return res.status(503).json({ error: "Persistent database is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the server and run the SQL setup from README.md." });
  next();
}
async function dbRequest(table, query = "", options = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${table}${query ? `?${query}` : ""}`;
  const response = await fetch(url, {
    method: options.method || "GET",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: options.prefer || "return=representation",
      ...(options.headers || {})
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const raw = await response.text();
  let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = raw; }
  if (!response.ok) {
    const message = data && (data.message || data.error_description || data.hint) || `Database request failed (${response.status})`;
    const err = new Error(message); err.status = response.status; throw err;
  }
  return data;
}
const defaultState = () => ({ id: 1, playback: { videoId: null, playing: false, positionSeconds: 0, durationSeconds: 0, playlistIndex: -1, updatedAt: Date.now() }, playlist: [], background_url: "", updated_at: new Date().toISOString() });
async function saveState(s) {
  const row = {
    id: 1,
    playback: { ...(s.playback || {}), updatedAt: Date.now() },
    playlist: Array.isArray(s.playlist) ? s.playlist.slice(0, 20) : [],
    background_url: typeof s.background_url === "string" ? s.background_url.slice(0, 2000) : "",
    updated_at: new Date().toISOString()
  };
  const data = await dbRequest("mahalaya_state", "on_conflict=id", { method: "POST", prefer: "resolution=merge-duplicates,return=representation", body: row });
  return Array.isArray(data) && data[0] ? data[0] : row;
}
async function getState() {
  const rows = await dbRequest("mahalaya_state", "id=eq.1&select=*");
  if (rows && rows[0]) return rows[0];
  return await saveState(defaultState());
}
async function advanceIfEnded(row) {
  const p = row.playback || {};
  const playlist = Array.isArray(row.playlist) ? row.playlist : [];
  if (!p.videoId || !p.playing || !Number.isFinite(Number(p.durationSeconds)) || Number(p.durationSeconds) <= 0) return row;
  const elapsed = Math.max(0, (Date.now() - Number(p.updatedAt || Date.now())) / 1000);
  const expected = Number(p.positionSeconds || 0) + elapsed;
  if (expected < Number(p.durationSeconds) - 2) return row;
  let idx = Number.isInteger(p.playlistIndex) ? p.playlistIndex : playlist.findIndex(v => v.videoId === p.videoId);
  if (idx < 0) idx = playlist.findIndex(v => v.videoId === p.videoId);
  if (idx < 0 || idx + 1 >= playlist.length) {
    const paused = { ...p, positionSeconds: Number(p.durationSeconds), playing: false, updatedAt: Date.now() };
    return await saveState({ ...row, playback: paused });
  }
  const nextIndex = idx + 1;
  const next = playlist[nextIndex];
  return await saveState({ ...row, playback: { videoId: next.videoId, playing: true, positionSeconds: 0, durationSeconds: Number(next.durationSeconds || 0), playlistIndex: nextIndex, updatedAt: Date.now() } });
}
function validVideoId(id) { return typeof id === "string" && /^[A-Za-z0-9_-]{11}$/.test(id); }
function safeText(value, max = 300) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Username and password required." });
  if (!safeCompare(username, ADMIN_USERNAME) || !safeCompare(password, ADMIN_PASSWORD)) return res.status(401).json({ error: "Invalid credentials." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Session could not be created." });
    req.session.isAdmin = true;
    req.session.adminUser = ADMIN_USERNAME;
    req.session.save(saveErr => saveErr ? res.status(500).json({ error: "Session save failed." }) : res.json({ success: true, user: ADMIN_USERNAME }));
  });
});
app.post("/api/admin/logout", (req, res) => req.session.destroy(() => { res.clearCookie("mahalaya.sid"); res.json({ success: true }); }));
app.get("/api/admin/session", (req, res) => res.json(req.session && req.session.isAdmin ? { authenticated: true, user: req.session.adminUser } : { authenticated: false }));
app.post("/api/admin/verify", requireAdmin, (req, res) => res.json({ authorized: true, user: req.session.adminUser }));
app.get("/api/health", (req, res) => res.json({ status: "ok", service: "MAHALAYA LIVE 2026", persistentDatabaseConfigured: dbConfigured(), https: isHttps }));

// Persistent playback state, playlist, and background settings.
app.get("/api/state", requireDb, async (req, res) => {
  try {
    let row = await getState();
    row = await advanceIfEnded(row);
    let playback = row.playback || defaultState().playback;
    // Return a current-position snapshot, not the stale position from the last admin poll.
    // This is what lets late visitors seek correctly after the admin disconnects.
    if (playback.videoId && playback.playing) {
      const now = Date.now();
      const elapsed = Math.max(0, (now - Number(playback.updatedAt || now)) / 1000);
      playback = { ...playback, positionSeconds: Math.min(Number(playback.durationSeconds || 86400), Number(playback.positionSeconds || 0) + elapsed), updatedAt: now };
    }
    res.set("Cache-Control", "no-store");
    res.json({ playback, playlist: row.playlist || [], backgroundUrl: row.background_url || "", updatedAt: row.updated_at });
  } catch (e) { console.error("[state read]", e.message); res.status(503).json({ error: "Could not load shared state. Check database setup." }); }
});
app.post("/api/state", requireDb, requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const playback = body.playback || {};
    if (playback.videoId !== null && playback.videoId !== undefined && !validVideoId(playback.videoId)) return res.status(400).json({ error: "Invalid video ID." });
    const playlist = Array.isArray(body.playlist) ? body.playlist.slice(0, 20).filter(v => v && validVideoId(v.videoId)).map((v, i) => ({ videoId: v.videoId, title: safeText(v.title, 100) || `Video ${i + 1}`, durationSeconds: Math.max(0, Math.min(86400, Number(v.durationSeconds) || 0)) })) : [];
    const row = await saveState({ playback: { videoId: playback.videoId || null, playing: Boolean(playback.playing), positionSeconds: Math.max(0, Math.min(86400, Number(playback.positionSeconds) || 0)), durationSeconds: Math.max(0, Math.min(86400, Number(playback.durationSeconds) || 0)), playlistIndex: Number.isInteger(playback.playlistIndex) ? playback.playlistIndex : -1 }, playlist, background_url: safeText(body.backgroundUrl, 2000) });
    res.json({ success: true, playback: row.playback, playlist: row.playlist, backgroundUrl: row.background_url });
  } catch (e) { console.error("[state write]", e.message); res.status(503).json({ error: "Could not save shared state. Check database setup." }); }
});

// A guest may report a YouTube duration for the currently selected queued video;
// this cannot change the selected video or playback controls.
app.post("/api/video-duration", requireDb, async (req, res) => {
  try {
    const { videoId } = req.body || {};
    const durationSeconds = Number(req.body && req.body.durationSeconds);
    if (!validVideoId(videoId) || !Number.isFinite(durationSeconds) || durationSeconds < 1 || durationSeconds > 86400) return res.status(400).json({ error: "Invalid video duration." });
    const row = await getState();
    const inQueue = (row.playlist || []).some(v => v.videoId === videoId);
    if (!inQueue && (!row.playback || row.playback.videoId !== videoId)) return res.status(403).json({ error: "Video is not in the shared playlist." });
    const playlist = (row.playlist || []).map(v => v.videoId === videoId ? { ...v, durationSeconds } : v);
    let playback = row.playback;
    if (playback && playback.videoId === videoId) {
      const now = Date.now();
      const elapsed = playback.playing ? Math.max(0, (now - Number(playback.updatedAt || now)) / 1000) : 0;
      playback = { ...playback, positionSeconds: Math.min(durationSeconds, Number(playback.positionSeconds || 0) + elapsed), durationSeconds, updatedAt: now };
    }
    await saveState({ ...row, playback, playlist });
    res.json({ success: true });
  } catch (e) { console.error("[duration]", e.message); res.status(503).json({ error: "Could not save video duration." }); }
});

// Persistent live chat.
app.get("/api/chat", requireDb, async (req, res) => {
  try {
    const rows = await dbRequest("mahalaya_messages", "kind=eq.chat&select=*&order=created_at.desc&limit=100");
    res.set("Cache-Control", "no-store");
    res.json((rows || []).reverse().map(r => ({ id: r.id, name: r.name, text: r.text, time: new Date(r.created_at).getTime(), isAdmin: r.is_admin })));
  } catch (e) { console.error("[chat read]", e.message); res.status(503).json({ error: "Could not load chat history." }); }
});
app.post("/api/chat", requireDb, async (req, res) => {
  try {
    const isAdmin = Boolean(req.session && req.session.isAdmin);
    const name = safeText(req.body && req.body.name, 24);
    const text = safeText(req.body && req.body.text, 300);
    if ((!name && !isAdmin) || !text) return res.status(400).json({ error: "Name and message are required." });
    const row = { id: crypto.randomUUID(), kind: "chat", name: isAdmin ? ADMIN_USERNAME : name, text, is_admin: isAdmin, created_at: new Date().toISOString() };
    const result = await dbRequest("mahalaya_messages", "", { method: "POST", body: row });
    const saved = Array.isArray(result) && result[0] ? result[0] : row;
    res.json({ success: true, message: { id: saved.id, name: saved.name, text: saved.text, time: new Date(saved.created_at).getTime(), isAdmin: saved.is_admin } });
  } catch (e) { console.error("[chat write]", e.message); res.status(503).json({ error: "Could not save message." }); }
});
app.delete("/api/chat/:id", requireDb, requireAdmin, async (req, res) => {
  try { await dbRequest("mahalaya_messages", `id=eq.${encodeURIComponent(req.params.id)}&kind=eq.chat`, { method: "DELETE", prefer: "return=minimal" }); res.json({ success: true }); }
  catch (e) { console.error("[chat delete]", e.message); res.status(503).json({ error: "Could not delete message." }); }
});

// Video comments and likes (kept separate from the live chat).
app.get("/api/comments", requireDb, async (req, res) => {
  try {
    const videoId = safeText(req.query.videoId, 11);
    if (!validVideoId(videoId)) return res.json([]);
    const rows = await dbRequest("mahalaya_messages", `kind=eq.comment&video_id=eq.${encodeURIComponent(videoId)}&select=*&order=created_at.desc&limit=100`);
    res.json((rows || []).reverse().map(r => ({ id: r.id, name: r.name, text: r.text, time: new Date(r.created_at).getTime(), isAdmin: r.is_admin })));
  } catch (e) { console.error("[comments read]", e.message); res.status(503).json({ error: "Could not load comments." }); }
});
app.post("/api/comments", requireDb, async (req, res) => {
  try {
    const isAdmin = Boolean(req.session && req.session.isAdmin);
    const name = safeText(req.body && req.body.name, 24), text = safeText(req.body && req.body.text, 300), videoId = safeText(req.body && req.body.videoId, 11);
    if ((!name && !isAdmin) || !text || !validVideoId(videoId)) return res.status(400).json({ error: "Video, name and comment are required." });
    const row = { id: crypto.randomUUID(), kind: "comment", video_id: videoId, name: isAdmin ? ADMIN_USERNAME : name, text, is_admin: isAdmin, created_at: new Date().toISOString() };
    const result = await dbRequest("mahalaya_messages", "", { method: "POST", body: row });
    const saved = Array.isArray(result) && result[0] ? result[0] : row;
    res.json({ success: true, comment: { id: saved.id, name: saved.name, text: saved.text, time: new Date(saved.created_at).getTime(), isAdmin: saved.is_admin } });
  } catch (e) { console.error("[comment write]", e.message); res.status(503).json({ error: "Could not save comment." }); }
});
app.get("/api/likes", requireDb, async (req, res) => {
  try {
    const videoId = safeText(req.query.videoId, 11);
    if (!validVideoId(videoId)) return res.json({ count: 0 });
    const rows = await dbRequest("mahalaya_likes", `video_id=eq.${encodeURIComponent(videoId)}&select=id`);
    res.json({ count: (rows || []).length });
  } catch (e) { console.error("[likes read]", e.message); res.status(503).json({ error: "Could not load likes." }); }
});
app.post("/api/likes", requireDb, async (req, res) => {
  try {
    const videoId = safeText(req.body && req.body.videoId, 11), visitorId = safeText(req.body && req.body.visitorId, 80);
    if (!validVideoId(videoId) || !/^[A-Za-z0-9_-]{12,80}$/.test(visitorId)) return res.status(400).json({ error: "Invalid like request." });
    const existing = await dbRequest("mahalaya_likes", `video_id=eq.${encodeURIComponent(videoId)}&visitor_id=eq.${encodeURIComponent(visitorId)}&select=id`);
    if (existing && existing.length) {
      await dbRequest("mahalaya_likes", `video_id=eq.${encodeURIComponent(videoId)}&visitor_id=eq.${encodeURIComponent(visitorId)}`, { method: "DELETE", prefer: "return=minimal" });
      return res.json({ liked: false });
    }
    await dbRequest("mahalaya_likes", "on_conflict=video_id,visitor_id", { method: "POST", prefer: "resolution=ignore-duplicates,return=minimal", body: { id: crypto.randomUUID(), video_id: videoId, visitor_id: visitorId, created_at: new Date().toISOString() } });
    res.json({ liked: true });
  } catch (e) { console.error("[like write]", e.message); res.status(503).json({ error: "Could not update like." }); }
});

// Serve only the frontend document. Do NOT expose server.js, package.json, or README.md
// through express.static(), because server.js contains the configured admin credentials.
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  // The project has an inline single-file frontend; unknown browser paths fall back to it.
  res.sendFile(path.join(__dirname, "index.html"));
});
app.use((err, req, res, next) => { console.error("[server error]", err); if (!res.headersSent) res.status(500).json({ error: "Server error." }); });
app.listen(PORT, () => console.log(`MAHALAYA LIVE 2026 running on port ${PORT}; persistent DB configured: ${dbConfigured()}; admin: ${ADMIN_USERNAME}`));
