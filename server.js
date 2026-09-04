/**
 * Skill Mate — Media & API backend (deploy on Render)
 * -----------------------------------------------------
 * Responsibilities:
 *  - Receives images/videos from the frontend and stores them on local disk (/data or ./storage)
 *  - Keeps a media index (media_index) in Supabase so nothing is lost when Render sleeps/restarts
 *  - On cold start (or GET /api/restore) it rebuilds the local store from the Supabase index
 *  - Optional proxy endpoints for requests/applications and an admin stats endpoint
 */
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const STORAGE = process.env.STORAGE_DIR || path.join(__dirname, "storage");
const INDEX_FILE = path.join(STORAGE, "_index.json");
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const JWT_SECRET = String(process.env.JWT_SECRET || "");
const TOKEN_TTL = 12 * 60 * 60 * 1000;
const MEDIA_PRUNE_INTERVAL_MS = 6 * 60 * 60 * 1000; // how often the migrate/wipe rotation checks for due media

fs.mkdirSync(STORAGE, { recursive: true });

// Small retry/backoff wrapper for Supabase calls. Network hiccups or a
// momentarily-throttled project (e.g. mid Disk-IO-budget recovery) used to
// surface as a hard failure on the first try; this retries transient errors
// a few times with increasing delay before giving up for real.
async function withRetry(fn, { attempts = 3, baseDelayMs = 400, label = "supabase call" } = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const result = await fn();
      if (result?.error) throw result.error;
      return result;
    } catch (e) {
      lastErr = e;
      const transient = /timeout|fetch failed|ECONNRESET|ETIMEDOUT|network|too many|rate/i.test(e?.message || "");
      if (i === attempts - 1 || !transient) break;
      const delay = baseDelayMs * Math.pow(2, i);
      console.warn(`${label} failed (attempt ${i + 1}/${attempts}), retrying in ${delay}ms:`, e.message);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

const supabase =
  process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY
    ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
    : null;

// Optional second Supabase project, intended for media/storage-related data.
// Keep its service key server-side only. If these variables are empty, the
// backend falls back to the primary Supabase project for media_index.
const storageSupabase =
  process.env.SUPABASE_STORAGE_URL && process.env.SUPABASE_STORAGE_SERVICE_KEY
    ? createClient(process.env.SUPABASE_STORAGE_URL, process.env.SUPABASE_STORAGE_SERVICE_KEY)
    : supabase;

const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
const RESEND_FROM = String(process.env.RESEND_FROM || process.env.SMTP_FROM || "").trim();
const BREVO_API_KEY = String(process.env.BREVO_API_KEY || "").trim();
const BREVO_FROM = String(process.env.BREVO_FROM || process.env.SMTP_FROM || "").trim();

/* ---------- Supabase Storage (replaces base64-in-Postgres) ----------
 * Files now go into a Storage bucket as real bytes. Postgres only ever
 * holds a lightweight metadata row (no more multi-MB base64 text columns) —
 * this is the actual fix for the Disk IO / storage bloat the base64
 * approach was causing.
 */
const MEDIA_BUCKET = process.env.MEDIA_BUCKET || "media";

async function ensureBucket(client, bucket) {
  if (!client) return;
  try {
    const { data, error } = await client.storage.listBuckets();
    if (error) throw error;
    if (!(data || []).some((b) => b.name === bucket)) {
      const { error: createErr } = await client.storage.createBucket(bucket, { public: true, fileSizeLimit: 40 * 1024 * 1024 });
      if (createErr && !/already exists/i.test(createErr.message || "")) throw createErr;
      console.log(`created storage bucket "${bucket}"`);
    }
  } catch (e) { console.warn(`bucket check/create failed for "${bucket}":`, e.message); }
}
async function uploadToBucket(client, bucket, storagePath, buf, mime) {
  const { error } = await client.storage.from(bucket).upload(storagePath, buf, { contentType: mime, upsert: true });
  if (error) throw error;
  const { data } = client.storage.from(bucket).getPublicUrl(storagePath);
  return data.publicUrl;
}
async function downloadFromBucket(client, bucket, storagePath) {
  const { data, error } = await client.storage.from(bucket).download(storagePath);
  if (error) throw error;
  return Buffer.from(await data.arrayBuffer());
}
async function deleteFromBucket(client, bucket, storagePath) {
  if (!client) return;
  try { await client.storage.from(bucket).remove([storagePath]); } catch (e) { console.warn("bucket delete failed:", e.message); }
}

const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: +(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
    })
  : null;

const allowedOrigins = String(process.env.ALLOWED_ORIGIN || "*").split(",").map(x=>x.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => { if(!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) return cb(null,true); cb(new Error("origin not allowed")); } }));
app.use(express.json({ limit: "60mb" }));
app.use("/files", express.static(STORAGE, { maxAge: "7d" }));

/* ---------- local index helpers ---------- */
function readIndex() {
  try { return JSON.parse(fs.readFileSync(INDEX_FILE, "utf8")); } catch { return []; }
}
function writeIndex(list) { fs.writeFileSync(INDEX_FILE, JSON.stringify(list, null, 2)); }

/* ---------- admin authentication ---------- */
function makeAdminToken(){
  if(!JWT_SECRET) throw new Error("JWT_SECRET is not configured");
  const header=Buffer.from(JSON.stringify({alg:"HS256",typ:"JWT"})).toString("base64url");
  const payload=Buffer.from(JSON.stringify({sub:"admin",email:ADMIN_EMAIL,iat:Math.floor(Date.now()/1000),exp:Math.floor((Date.now()+TOKEN_TTL)/1000)})).toString("base64url");
  const input=header+"."+payload;
  const sig=crypto.createHmac("sha256",JWT_SECRET).update(input).digest("base64url");
  return input+"."+sig;
}
function validAdminToken(token){
  try{
    const parts=String(token||"").split(".");
    if(parts.length!==3 || !JWT_SECRET) return false;
    const [header,payload,sig]=parts;
    const expected=crypto.createHmac("sha256",JWT_SECRET).update(header+"."+payload).digest("base64url");
    const A=Buffer.from(sig), B=Buffer.from(expected);
    if(A.length!==B.length || !crypto.timingSafeEqual(A,B)) return false;
    const p=JSON.parse(Buffer.from(payload,"base64url").toString("utf8"));
    return p.sub==="admin" && p.email===ADMIN_EMAIL && p.exp>Math.floor(Date.now()/1000);
  }catch{return false}
}
function requireAdmin(req,res,next){
  const auth=String(req.headers.authorization||"");
  const token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(validAdminToken(token)) return next();
  return res.status(401).json({error:"unauthorized"});
}


app.post("/api/admin/login", (req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(!ADMIN_EMAIL || !ADMIN_PASSWORD || !JWT_SECRET) return res.status(503).json({error:"admin authentication is not configured"});
  function safeEqual(a,b){const A=Buffer.from(String(a)),B=Buffer.from(String(b));if(A.length!==B.length)return false;return crypto.timingSafeEqual(A,B);}
  if(!safeEqual(email,ADMIN_EMAIL) || !safeEqual(password,ADMIN_PASSWORD)) return res.status(401).json({error:"invalid credentials"});
  res.json({ok:true, token:makeAdminToken(), expires_in:TOKEN_TTL});
});
/* ---------- health ---------- */
app.get("/", (_req, res) => res.json({ service: "Skill Mate media API", ok: true, files: readIndex().length }));
app.get("/api/health", (_req, res) => res.json({ ok: true, uptime: process.uptime() }));

/* ---------- database diagnostics ---------- */
app.get("/api/db-check", async (_req, res) => {
  const report = {
    supabase_client_configured: !!supabase,
    supabase_url_set: !!process.env.SUPABASE_URL,
    supabase_service_key_set: !!process.env.SUPABASE_SERVICE_KEY,
    tables: {}
  };
  if (!supabase) {
    report.error = "SUPABASE_URL or SUPABASE_SERVICE_KEY is missing on the backend — set both in Render env vars.";
    return res.json(report);
  }
  const tables = [
    "profiles", "requests", "applications", "saved", "reports",
    "messages", "reviews", "verification_requests", "featured_requests",
    "referrals", "withdrawals", "announcements", "activity_log",
    "email_codes", "media_index", "social_videos", "social_updates", "social_follows", "social_likes", "social_saves", "social_comments"
  ];
  for (const t of tables) {
    const entry = { readable: false, read_error: null, row_count: null };
    try {
      const { count, error } = await supabase.from(t).select("*", { count: "exact", head: true });
      if (error) entry.read_error = { code: error.code, message: error.message, hint: error.hint || null };
      else { entry.readable = true; entry.row_count = count; }
    } catch (e) { entry.read_error = { message: e.message }; }
    report.tables[t] = entry;
  }
  res.json(report);
});

app.get("/api/db-write-test", async (_req, res) => {
  if (!supabase) return res.json({ ok: false, error: "Supabase not configured on backend" });
  const testId = "debug-" + crypto.randomUUID();
  const testProfile = { id: testId, name: "DB Check Test", email: `db-check-${Date.now()}@example.com`, role: "apprentice" };
  const insertResult = await supabase.from("profiles").insert(testProfile).select("*");
  if (insertResult.error) {
    return res.json({ ok: false, step: "insert", error: { code: insertResult.error.code, message: insertResult.error.message, hint: insertResult.error.hint || null, details: insertResult.error.details || null } });
  }
  const deleteResult = await supabase.from("profiles").delete().eq("id", testId);
  res.json({ ok: true, inserted: insertResult.data, cleanup_ok: !deleteResult.error, cleanup_error: deleteResult.error ? deleteResult.error.message : null });
});

/* ---------- upload ---------- */
// category: "profile" | "listing" | "application" | "receipt" | "social" | "other"
// "profile" and "listing" are permanently exempt from the 15/20-day rotation below.
const PROTECTED_CATEGORIES = new Set(["profile", "listing"]);

app.post("/api/media", async (req, res) => {
  try {
    const { filename, mime, data, owner, category } = req.body || {};
    if (!data || !mime) return res.status(400).json({ error: "data and mime are required" });
    const base64 = String(data).includes(",") ? String(data).split(",")[1] : data;
    const buf = Buffer.from(base64, "base64");
    if (buf.length > 40 * 1024 * 1024) return res.status(413).json({ error: "file too large (40MB max)" });
    if (!supabase) return res.status(503).json({ error: "database is not configured" });

    const id = crypto.randomUUID();
    const ext = (path.extname(filename || "") || "." + (mime.split("/")[1] || "bin")).slice(0, 8);
    const storagePath = id + ext;
    const safeCategory = typeof category === "string" && category.trim() ? category.trim() : "other";

    // Bytes go to DB1's Storage bucket — not into a Postgres column.
    const publicUrl = await withRetry(
      () => uploadToBucket(supabase, MEDIA_BUCKET, storagePath, buf, mime),
      { label: `storage upload (${id})` }
    );

    // Postgres only stores this small metadata row.
    const record = {
      id, filename: filename || storagePath, mime, owner: owner || null, category: safeCategory,
      size: buf.length, bucket: MEDIA_BUCKET, storage_path: storagePath, url: publicUrl,
      created_at: new Date().toISOString()
    };
    await withRetry(() => supabase.from("media_index").insert(record), { label: `media_index insert (${id})` });

    res.json(record);
  } catch (e) {
    console.error(e); res.status(500).json({ error: "upload failed" });
  }
});

/* ---------- list ---------- */
// Legacy items (uploaded before this change) still live in the local index
// with a local file on Render's disk. New items live only as metadata rows
// in DB1/DB2, backed by Storage — merge both so nothing goes missing.
async function listAllMedia() {
  const legacy = readIndex();
  const seen = new Set(legacy.map((m) => m.id));
  const out = [...legacy];
  const sources = [supabase, storageSupabase !== supabase ? storageSupabase : null].filter(Boolean);
  for (const client of sources) {
    try {
      const { data, error } = await client.from("media_index").select("id,filename,mime,owner,category,size,bucket,storage_path,url,created_at").not("storage_path", "is", null);
      if (error) throw error;
      for (const rec of data || []) { if (!seen.has(rec.id)) { out.push(rec); seen.add(rec.id); } }
    } catch (e) { console.warn("listAllMedia source failed:", e.message); }
  }
  return out;
}
app.get("/api/media", async (_req, res) => res.json(await listAllMedia()));

app.get("/api/media/:id", async (req, res) => {
  const legacyRec = readIndex().find((m) => m.id === req.params.id);
  if (legacyRec) return res.sendFile(path.join(STORAGE, legacyRec.stored));
  // Not a legacy local file — look it up as a bucket-based metadata row and
  // redirect straight to Supabase's public URL (no proxying through Render).
  for (const client of [supabase, storageSupabase !== supabase ? storageSupabase : null].filter(Boolean)) {
    const { data } = await client.from("media_index").select("url").eq("id", req.params.id).maybeSingle();
    if (data?.url) return res.redirect(302, data.url);
  }
  res.status(404).json({ error: "not found" });
});

/* ---------- delete (admin) ---------- */
app.delete("/api/media/:id", async (req, res) => {
  const auth=String(req.headers.authorization||"");
  const token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(!validAdminToken(token)) return res.status(401).json({ error: "unauthorized" });

  // Legacy path: local file + base64 mirror.
  const idx = readIndex(); const legacyRec = idx.find((m) => m.id === req.params.id);
  if (legacyRec) {
    try { fs.unlinkSync(path.join(STORAGE, legacyRec.stored)); } catch {}
    writeIndex(idx.filter((m) => m.id !== req.params.id));
    if (supabase) await supabase.from("media_index").delete().eq("id", req.params.id);
    if (storageSupabase && storageSupabase !== supabase) await storageSupabase.from("media_index").delete().eq("id", req.params.id);
    return res.json({ ok: true });
  }

  // Bucket path: could be in DB1's bucket or DB2's bucket depending on rotation stage.
  for (const [client, label] of [[supabase, "DB1"], [storageSupabase !== supabase ? storageSupabase : null, "DB2"]]) {
    if (!client) continue;
    const { data } = await client.from("media_index").select("bucket,storage_path").eq("id", req.params.id).maybeSingle();
    if (data) {
      await deleteFromBucket(client, data.bucket || MEDIA_BUCKET, data.storage_path);
      await client.from("media_index").delete().eq("id", req.params.id);
      return res.json({ ok: true, removed_from: label });
    }
  }
  res.status(404).json({ error: "not found" });
});

/* ---------- email verification (signup) ---------- */
function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post("/api/send-verification", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "a valid email is required" });
    if (!supabase) return res.status(500).json({ error: "verification storage not configured (Supabase not set up)" });

    const code = genCode();
    const expires_at = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await supabase.from("email_codes").delete().eq("email", email);
    const { error } = await supabase.from("email_codes").insert({ email, code, expires_at });
    if (error) throw error;

    if (RESEND_API_KEY && RESEND_FROM) {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: RESEND_FROM,
          to: [email],
          subject: "Your Skill Mate verification code",
          text: `Your Skill Mate verification code is ${code}. It expires in 15 minutes.`,
          html: `<p>Your Skill Mate verification code is:</p><h2 style="letter-spacing:4px">${code}</h2><p>It expires in 15 minutes.</p>`
        })
      });
      if (!response.ok) {
        const details = await response.text().catch(() => "");
        throw new Error("email provider rejected the request" + (details ? `: ${details.slice(0,300)}` : ""));
      }
      return res.json({ ok: true, sent: true });
    }

    if (BREVO_API_KEY && BREVO_FROM) {
      const response = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": BREVO_API_KEY,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          sender: { email: BREVO_FROM, name: "Skill Mate" },
          to: [{ email }],
          subject: "Your Skill Mate verification code",
          textContent: `Your Skill Mate verification code is ${code}. It expires in 15 minutes.`,
          htmlContent: `<p>Your Skill Mate verification code is:</p><h2 style="letter-spacing:4px">${code}</h2><p>It expires in 15 minutes.</p>`
        })
      });
      if (!response.ok) {
        const details = await response.text().catch(() => "");
        throw new Error("email provider rejected the request" + (details ? `: ${details.slice(0,300)}` : ""));
      }
      return res.json({ ok: true, sent: true });
    }

    if (mailer) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: "Your Skill Mate verification code",
        text: `Your Skill Mate verification code is ${code}. It expires in 15 minutes.`,
        html: `<p>Your Skill Mate verification code is:</p><h2 style="letter-spacing:4px">${code}</h2><p>It expires in 15 minutes.</p>`
      });
      return res.json({ ok: true, sent: true });
    }

    return res.status(503).json({ error: "email delivery is not configured" });
  } catch (e) {
    console.error(e); res.status(500).json({ error: "failed to send verification code" });
  }
});

app.post("/api/verify-code", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();
    if (!email || !code) return res.status(400).json({ error: "email and code are required" });
    if (!supabase) return res.status(500).json({ error: "verification storage not configured (Supabase not set up)" });

    const { data, error } = await supabase.from("email_codes").select("*").eq("email", email).maybeSingle();
    if (error) throw error;
    if (!data || data.code !== code) return res.status(400).json({ error: "Incorrect code" });
    if (new Date(data.expires_at) < new Date()) return res.status(400).json({ error: "Code expired — request a new one" });

    await supabase.from("email_codes").delete().eq("email", email);
    res.json({ ok: true, verified: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: "verification failed" });
  }
});

/* ---------- restore after sleep/restart ---------- */
// A file may currently live in DB1's index (not yet migrated) or DB2's index
// (already migrated at day 15, still visible on-site until the day-35 wipe).
// Restore must check both so nothing goes missing from the site mid-rotation.
async function restoreFromSupabase() {
  if (!supabase && !storageSupabase) return { restored: 0, note: "no database configured" };
  const idx = readIndex(); const have = new Set(idx.map((m) => m.id)); let restored = 0;
  const sources = [];
  if (supabase) sources.push(supabase.from("media_index").select("*").order("created_at"));
  if (storageSupabase && storageSupabase !== supabase) sources.push(storageSupabase.from("media_index").select("*").order("created_at"));
  const results = await Promise.all(sources.map((q) => q.catch((e) => ({ error: e }))));
  for (const r of results) {
    if (r.error) { console.warn("restore source failed:", r.error.message); continue; }
    for (const rec of r.data || []) {
      const target = path.join(STORAGE, rec.stored);
      if (!fs.existsSync(target) && rec.data_base64) {
        fs.writeFileSync(target, Buffer.from(rec.data_base64, "base64")); restored++;
      }
      if (!have.has(rec.id)) {
        const { data_base64, ...meta } = rec; idx.push(meta); have.add(rec.id);
      }
    }
  }
  idx.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  writeIndex(idx);
  return { restored, count: idx.length };
}
app.get("/api/restore", async (_req, res) => res.json(await restoreFromSupabase()));

/* ---------- TikTok import: metadata only, TikTok hosts the actual video ---------- */
function extractTikTokVideoId(html, url) {
  const fromHtml = /data-video-id="(\d+)"/.exec(html || "");
  if (fromHtml) return fromHtml[1];
  const fromUrl = /\/video\/(\d+)/.exec(url || "");
  return fromUrl ? fromUrl[1] : null;
}
app.get("/api/tiktok/oembed", async (req, res) => {
  try {
    const link = String(req.query.url || "").trim();
    if (!/^https?:\/\/(www\.|vm\.|vt\.)?tiktok\.com\//i.test(link)) {
      return res.status(400).json({ error: "Please paste a valid TikTok video link" });
    }
    const r = await withRetry(
      async () => {
        const resp = await fetch(`https://www.tiktok.com/oembed?url=${encodeURIComponent(link)}`);
        if (!resp.ok) throw new Error(`TikTok oEmbed returned ${resp.status}`);
        return { data: await resp.json() };
      },
      { label: "tiktok oembed" }
    );
    const data = r.data;
    const videoId = extractTikTokVideoId(data.html, link);
    if (!videoId) return res.status(422).json({ error: "Could not read a video ID from that link" });
    res.json({
      tiktok_video_id: videoId,
      tiktok_url: link,
      author_name: data.author_name || null,
      author_url: data.author_url || null,
      title: data.title || null,
      thumbnail_url: data.thumbnail_url || null
    });
  } catch (e) {
    console.error("tiktok oembed failed:", e.message);
    res.status(502).json({ error: "Couldn't reach TikTok for that link — check it's public and try again" });
  }
});

/* ---------- retention: DB1 -> DB2 rotation ----------
 * profile pictures and listing photos are exempt and stay in DB1 forever.
 * Everything else:
 *   day 0-15:  lives only in DB1 (as usual)
 *   day 15:    row is moved from DB1 to DB2 (deleted from DB1, inserted
 *              into DB2). The local file + local index entry are left
 *              untouched, so the site keeps serving it exactly as before —
 *              this step only changes which database backs it up.
 *   day 15+20 (=35 total): DB2 permanently deletes the row AND the local
 *              file is removed — this is the real, final deletion.
 * Non-media account data (profiles, requests, etc.) is never touched here.
 */
const MEDIA_MIGRATE_AFTER_DAYS = Number(process.env.MEDIA_MIGRATE_AFTER_DAYS || 15);
const MEDIA_WIPE_AFTER_DAYS = Number(process.env.MEDIA_WIPE_AFTER_DAYS || 20);

async function migrateAgedMediaToDB2() {
  if (!supabase) return { moved: 0, note: "DB1 not configured" };
  const cutoff = new Date(Date.now() - MEDIA_MIGRATE_AFTER_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await withRetry(
    () => supabase.from("media_index").select("*").lt("created_at", cutoff),
    { label: "DB1 select for migration" }
  ).catch((e) => ({ error: e }));
  if (error) { console.warn("migration select failed:", error.message); return { moved: 0, error: error.message }; }

  const eligible = (data || []).filter((rec) => !PROTECTED_CATEGORIES.has(rec.category || "other"));
  let moved = 0, healedFromBase64 = 0;
  for (const rec of eligible) {
    try {
      const originalCreatedAt = rec.created_at;
      let bucket = rec.bucket || MEDIA_BUCKET;
      let storagePath = rec.storage_path;

      if (!storagePath && rec.data_base64) {
        // Legacy row still carrying a base64 blob — convert it to real
        // Storage bytes right now instead of copying the blob again. This
        // is what clears out the pre-existing base64 bloat over time.
        const buf = Buffer.from(rec.data_base64, "base64");
        const ext = path.extname(rec.filename || rec.stored || "") || "." + (String(rec.mime || "").split("/")[1] || "bin");
        storagePath = rec.id + ext;
        await uploadToBucket(supabase, MEDIA_BUCKET, storagePath, buf, rec.mime);
        healedFromBase64++;
      }
      if (!storagePath) { console.warn(`skipping migration for ${rec.id}: no storage_path and no data_base64 to convert`); continue; }

      if (storageSupabase) {
        const buf = await withRetry(() => downloadFromBucket(supabase, bucket, storagePath), { label: `DB1 bucket download (${rec.id})` });
        const targetBucket = MEDIA_BUCKET;
        const publicUrl = await withRetry(() => uploadToBucket(storageSupabase, targetBucket, storagePath, buf, rec.mime), { label: `DB2 bucket upload (${rec.id})` });
        await withRetry(() => storageSupabase.from("media_index").upsert({
          id: rec.id, filename: rec.filename, mime: rec.mime, owner: rec.owner, category: rec.category || "other",
          size: rec.size || buf.length, bucket: targetBucket, storage_path: storagePath, url: publicUrl,
          original_created_at: originalCreatedAt, created_at: new Date().toISOString()
        }), { label: `DB2 media_index insert (${rec.id})` });
      }
      await deleteFromBucket(supabase, bucket, storagePath);
      await withRetry(() => supabase.from("media_index").delete().eq("id", rec.id), { label: `DB1 delete (${rec.id})` });
      moved++;
    } catch (e) {
      console.warn(`migration failed for media ${rec.id}:`, e.message);
    }
  }
  const result = { checked: (data || []).length, exempt_skipped: (data || []).length - eligible.length, moved, healed_from_base64: healedFromBase64, ran_at: new Date().toISOString() };
  console.log("media DB1->DB2 migration:", result);
  return result;
}

async function finalWipeFromDB2() {
  if (!storageSupabase) return { wiped: 0, note: "DB2 not configured" };
  const cutoff = new Date(Date.now() - MEDIA_WIPE_AFTER_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await withRetry(
    () => storageSupabase.from("media_index").select("*").lt("created_at", cutoff),
    { label: "DB2 select for final wipe" }
  ).catch((e) => ({ error: e }));
  if (error) { console.warn("final wipe select failed:", error.message); return { wiped: 0, error: error.message }; }

  const eligible = (data || []).filter((rec) => !PROTECTED_CATEGORIES.has(rec.category || "other"));
  const idx = readIndex();
  const idxById = new Map(idx.map((m) => [m.id, m]));
  let wiped = 0;
  for (const rec of eligible) {
    try {
      if (rec.storage_path) {
        await deleteFromBucket(storageSupabase, rec.bucket || MEDIA_BUCKET, rec.storage_path);
      }
      await withRetry(() => storageSupabase.from("media_index").delete().eq("id", rec.id), { label: `DB2 final delete (${rec.id})` });
      const local = idxById.get(rec.id);
      if (local) { try { fs.unlinkSync(path.join(STORAGE, local.stored)); } catch {} idxById.delete(rec.id); }
      wiped++;
    } catch (e) {
      console.warn(`final wipe failed for media ${rec.id}:`, e.message);
    }
  }
  if (wiped) writeIndex([...idxById.values()]);
  const result = { checked: (data || []).length, exempt_skipped: (data || []).length - eligible.length, wiped, ran_at: new Date().toISOString() };
  console.log("media DB2 final wipe:", result);
  return result;
}

async function runMediaRotation() {
  const migrate = await migrateAgedMediaToDB2().catch((e) => ({ error: e.message }));
  const wipe = await finalWipeFromDB2().catch((e) => ({ error: e.message }));
  return { migrate, wipe };
}
// Run once shortly after boot (after restore has had a chance to run), then on a recurring schedule.
setTimeout(() => runMediaRotation().catch((e) => console.warn("initial media rotation failed:", e.message)), 30 * 1000);
setInterval(() => runMediaRotation().catch((e) => console.warn("scheduled media rotation failed:", e.message)), MEDIA_PRUNE_INTERVAL_MS);

app.post("/api/admin/media/prune", requireAdmin, async (_req, res) => {
  try { res.json({ ok: true, ...(await runMediaRotation()) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get("/api/admin/media/stats", requireAdmin, async (_req, res) => {
  const idx = await listAllMedia();
  const migrateCutoff = Date.now() - MEDIA_MIGRATE_AFTER_DAYS * 24 * 60 * 60 * 1000;
  const eligible = idx.filter((m) => !PROTECTED_CATEGORIES.has(m.category || "other"));
  const dueToMigrate = eligible.filter((m) => new Date(m.created_at).getTime() < migrateCutoff);
  const legacyBase64Count = readIndex().filter((m) => !m.storage_path).length;
  res.json({
    total: idx.length,
    total_bytes: idx.reduce((s, m) => s + (m.size || 0), 0),
    protected_profile_or_listing: idx.length - eligible.length,
    due_to_migrate_or_wiped_soon: dueToMigrate.length,
    legacy_local_disk_items: legacyBase64Count,
    migrate_after_days: MEDIA_MIGRATE_AFTER_DAYS,
    wipe_after_days_in_db2: MEDIA_WIPE_AFTER_DAYS
  });
});

/* ---------- admin stats ---------- */
app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  const media = readIndex();
  const out = { media: media.length, bytes: media.reduce((s, m) => s + (m.size || 0), 0) };
  if (supabase) {
    const t = async (n) => (await supabase.from(n).select("id", { count: "exact", head: true })).count || 0;
    out.profiles = await t("profiles"); out.requests = await t("requests");
    out.applications = await t("applications"); out.reports = await t("reports");
    out.social_videos = await t("social_videos"); out.social_updates = await t("social_updates"); out.social_follows = await t("social_follows");
  }
  res.json(out);
});



/* ---------- admin / moderation API ---------- */
app.get("/api/admin/users/:id", requireAdmin, async (req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  const uid=req.params.id;
  const tables=["profiles","requests","applications","reports","messages","reviews","verification_requests","featured_requests","referrals","withdrawals","activity_log"];
  try{
    const results={};
    for(const table of tables){
      let q=supabase.from(table).select("*");
      if(table==="profiles") q=q.eq("id",uid);
      else if(table==="requests"||table==="verification_requests"||table==="featured_requests"||table==="withdrawals"||table==="activity_log") q=q.eq("user_id",uid);
      else if(table==="referrals") q=q.or(`referrer_id.eq.${uid},referred_id.eq.${uid}`);
      else if(table==="applications"||table==="reports") q=q.eq("user_id",uid);
      else if(table==="reviews") q=q.or(`reviewer_id.eq.${uid},reviewee_id.eq.${uid}`);
      else if(table==="messages") q=q.or(`user_id.eq.${uid},sender_id.eq.${uid},recipient_id.eq.${uid}`);
      const {data,error}=await q.order("created_at",{ascending:false});
      if(error) throw error;
      results[table]=data||[];
    }
    const safeProfile=(results.profiles||[]).map(({password,...rest})=>rest);
    results.profiles=safeProfile;
    res.json({ok:true,user:results.profiles?.[0]||null, data:results});
  }catch(e){console.error(e);res.status(500).json({error:"failed to load account audit"});}
});

app.post("/api/admin/users/:id/social-followers", requireAdmin, async (req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  const raw=req.body?.followers;
  const isReset=raw===null||raw===undefined||raw==="";
  const followers=Number(raw);
  if(!isReset && (!Number.isFinite(followers)||followers<0||followers>1000000000)) return res.status(400).json({error:"followers must be a non-negative number"});
  const patch={social_followers_override:isReset?null:Math.floor(followers)};
  const {data,error}=await supabase.from("profiles").update(patch).eq("id",req.params.id).select("*").maybeSingle();
  if(error) return res.status(500).json({error:error.message});
  if(!data) return res.status(404).json({error:"profile not found"});
  await supabase.from("activity_log").insert({id:crypto.randomUUID(),user_id:req.params.id,action:"admin_social_followers_changed",details:{followers:patch.social_followers_override}});
  res.json({ok:true,user:data});
});

app.post("/api/admin/users/:id/status", requireAdmin, async (req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  const patch={};
  if(typeof req.body?.verified==="boolean") patch.verified=req.body.verified;
  if(typeof req.body?.status==="string" && ["active","banned","suspended","deleted"].includes(req.body.status)) patch.status=req.body.status;
  if(!Object.keys(patch).length) return res.status(400).json({error:"no status change supplied"});
  const {data,error}=await supabase.from("profiles").update(patch).eq("id",req.params.id).select("*").maybeSingle();
  if(error) return res.status(500).json({error:error.message});
  await supabase.from("activity_log").insert({id:crypto.randomUUID(),user_id:req.params.id,action:"admin_account_status_changed",details:patch});
  res.json({ok:true,user:data});
});

app.post("/api/admin/announcements", requireAdmin, async (req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  const title=String(req.body?.title||"").trim(), message=String(req.body?.message||"").trim();
  if(!title||!message) return res.status(400).json({error:"title and message are required"});
  const row={id:crypto.randomUUID(),title,message,force:!!req.body?.force,target_user_id:req.body?.target_user_id||null,status:"published",created_at:new Date().toISOString()};
  const {data,error}=await supabase.from("announcements").insert(row).select("*").single();
  if(error) return res.status(500).json({error:error.message});
  res.json({ok:true,announcement:data});
});

app.post("/api/admin/reset-local", requireAdmin, async (_req,res)=>{
  res.json({ok:true,scope:"browser-local",message:"Use the admin console to clear local browser test data."});
});

/* ---------- social moderation API ---------- */
app.get("/api/admin/social", requireAdmin, async (_req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  try{
    const [videos,updates,comments]=await Promise.all([supabase.from("social_videos").select("*").order("created_at",{ascending:false}),supabase.from("social_updates").select("*").order("created_at",{ascending:false}),supabase.from("social_comments").select("*").order("created_at",{ascending:false})]);
    for(const x of [videos,updates,comments]) if(x.error) throw x.error;
    res.json({ok:true,videos:videos.data||[],updates:updates.data||[],comments:comments.data||[]});
  }catch(e){res.status(500).json({error:e.message});}
});
app.post("/api/admin/social/:type/:id/status", requireAdmin, async (req,res)=>{
  if(!supabase) return res.status(503).json({error:"database is not configured"});
  const table=req.params.type==="video"?"social_videos":req.params.type==="update"?"social_updates":"";
  if(!table) return res.status(400).json({error:"invalid social content type"});
  const status=["published","removed"].includes(req.body?.status)?req.body.status:"published";
  const {data,error}=await supabase.from(table).update({status}).eq("id",req.params.id).select("*").maybeSingle();
  if(error) return res.status(500).json({error:error.message});
  res.json({ok:true,data});
});

/* ---------- keep-alive ping target ---------- */
app.get("/api/ping", (_req, res) => res.send("pong"));

app.listen(PORT, "0.0.0.0", async () => {
  console.log("Skill Mate backend listening on " + PORT);
  await ensureBucket(supabase, MEDIA_BUCKET);
  if (storageSupabase && storageSupabase !== supabase) await ensureBucket(storageSupabase, MEDIA_BUCKET);
  const r = await restoreFromSupabase();
  console.log("cold-start restore:", r);
});
