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

fs.mkdirSync(STORAGE, { recursive: true });

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
app.post("/api/media", async (req, res) => {
  try {
    const { filename, mime, data, owner } = req.body || {};
    if (!data || !mime) return res.status(400).json({ error: "data and mime are required" });
    const base64 = String(data).includes(",") ? String(data).split(",")[1] : data;
    const buf = Buffer.from(base64, "base64");
    if (buf.length > 40 * 1024 * 1024) return res.status(413).json({ error: "file too large (40MB max)" });

    const id = crypto.randomUUID();
    const ext = (path.extname(filename || "") || "." + (mime.split("/")[1] || "bin")).slice(0, 8);
    const stored = id + ext;
    fs.writeFileSync(path.join(STORAGE, stored), buf);

    const record = {
      id, filename: filename || stored, stored, mime, owner: owner || null,
      size: buf.length, url: `/files/${stored}`, created_at: new Date().toISOString()
    };
    const idx = readIndex(); idx.push(record); writeIndex(idx);

    // Mirror to Supabase so files can be restored after a sleep/restart
    if (storageSupabase) {
      await storageSupabase.from("media_index").insert({ ...record, data_base64: base64 }).then(
        () => {}, (e) => console.warn("supabase mirror failed", e.message)
      );
    }
    res.json(record);
  } catch (e) {
    console.error(e); res.status(500).json({ error: "upload failed" });
  }
});

/* ---------- list ---------- */
app.get("/api/media", (_req, res) => res.json(readIndex()));
app.get("/api/media/:id", (req, res) => {
  const rec = readIndex().find((m) => m.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  res.sendFile(path.join(STORAGE, rec.stored));
});

/* ---------- delete (admin) ---------- */
app.delete("/api/media/:id", async (req, res) => {
  const auth=String(req.headers.authorization||"");
  const token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(!validAdminToken(token)) return res.status(401).json({ error: "unauthorized" });
  const idx = readIndex(); const rec = idx.find((m) => m.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  try { fs.unlinkSync(path.join(STORAGE, rec.stored)); } catch {}
  writeIndex(idx.filter((m) => m.id !== req.params.id));
  if (storageSupabase) await storageSupabase.from("media_index").delete().eq("id", req.params.id);
  res.json({ ok: true });
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
async function restoreFromSupabase() {
  if (!storageSupabase) return { restored: 0, note: "storage database not configured" };
  const { data, error } = await storageSupabase.from("media_index").select("*").order("created_at");
  if (error) { console.warn(error.message); return { restored: 0, error: error.message }; }
  const idx = readIndex(); const have = new Set(idx.map((m) => m.id)); let restored = 0;
  for (const rec of data || []) {
    const target = path.join(STORAGE, rec.stored);
    if (!fs.existsSync(target) && rec.data_base64) {
      fs.writeFileSync(target, Buffer.from(rec.data_base64, "base64")); restored++;
    }
    if (!have.has(rec.id)) {
      const { data_base64, ...meta } = rec; idx.push(meta); have.add(rec.id);
    }
  }
  idx.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  writeIndex(idx);
  return { restored, count: idx.length };
}
app.get("/api/restore", async (_req, res) => res.json(await restoreFromSupabase()));

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
  const r = await restoreFromSupabase();
  console.log("cold-start restore:", r);
});
