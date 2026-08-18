/* Motion Brawler — accounts and cloud saves.
 *
 * Zero dependencies: talks to an Upstash/Vercel KV store over its REST
 * API with plain fetch, so there is nothing to npm install and no build
 * step. If no store is connected the endpoint reports "off" and the game
 * keeps playing from local storage instead of breaking.
 *
 * Passwords are scrypt-hashed with a per-user salt. The session is an
 * HMAC-signed token in an httpOnly cookie, so page scripts cannot read it.
 */
const crypto = require("crypto");

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || "";
const KV_TOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || "";
const SECRET = process.env.AUTH_SECRET || KV_TOK;
const READY = !!(KV_URL && KV_TOK);
const DAY = 86400e3;

async function kv(cmd) {
  const r = await fetch(KV_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + KV_TOK, "Content-Type": "application/json" },
    body: JSON.stringify(cmd)
  });
  if (!r.ok) throw new Error("store " + r.status);
  return (await r.json()).result;
}

const norm = u => String(u || "").trim().toLowerCase();
const validName = u => /^[a-z0-9_]{3,16}$/.test(u);

function hash(pw, salt) {
  return crypto.scryptSync(String(pw), salt, 32).toString("hex");
}
function sign(name) {
  const exp = Date.now() + 30 * DAY;
  const body = name + "." + exp;
  const mac = crypto.createHmac("sha256", SECRET).update(body).digest("hex").slice(0, 32);
  return body + "." + mac;
}
function verify(token) {
  const p = String(token || "").split(".");
  if (p.length !== 3) return null;
  const [name, exp, mac] = p;
  const want = crypto.createHmac("sha256", SECRET).update(name + "." + exp).digest("hex").slice(0, 32);
  if (mac.length !== want.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  if (Date.now() > +exp) return null;
  return name;
}
function readCookie(req, key) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(";").map(s => s.trim()).find(s => s.startsWith(key + "="));
  return hit ? decodeURIComponent(hit.slice(key.length + 1)) : "";
}
function setSession(res, token) {
  const bits = ["mb_session=" + encodeURIComponent(token), "Path=/", "HttpOnly",
                "SameSite=Lax", "Max-Age=" + 30 * 86400];
  if (process.env.VERCEL) bits.push("Secure");
  res.setHeader("Set-Cookie", bits.join("; "));
}

async function body(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let raw = "";
  for await (const chunk of req) raw += chunk;
  try { return JSON.parse(raw || "{}"); } catch (e) { return {}; }
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const action = (req.query && req.query.a) || "me";

  if (!READY) {
    return res.status(200).json({ ok: false, off: true,
      reason: "No database connected to this project yet." });
  }

  try {
    if (action === "register" || action === "login") {
      const b = await body(req);
      const name = norm(b.username);
      if (!validName(name))
        return res.status(400).json({ ok: false, error: "Username must be 3-16 letters, numbers or underscores." });
      if (String(b.password || "").length < 6)
        return res.status(400).json({ ok: false, error: "Password must be at least 6 characters." });

      const key = "mb:user:" + name;
      const existing = await kv(["GET", key]);

      if (action === "register") {
        if (existing) return res.status(409).json({ ok: false, error: "That username is taken." });
        const salt = crypto.randomBytes(16).toString("hex");
        const rec = { name, email: String(b.email || "").slice(0, 120),
                      salt, pass: hash(b.password, salt),
                      data: b.data || null, created: Date.now() };
        await kv(["SET", key, JSON.stringify(rec)]);
        setSession(res, sign(name));
        return res.status(200).json({ ok: true, username: name, data: rec.data });
      }

      if (!existing) return res.status(401).json({ ok: false, error: "No account with that username." });
      const rec = JSON.parse(existing);
      if (hash(b.password, rec.salt) !== rec.pass)
        return res.status(401).json({ ok: false, error: "Wrong password." });
      setSession(res, sign(name));
      return res.status(200).json({ ok: true, username: name, data: rec.data });
    }

    if (action === "logout") {
      res.setHeader("Set-Cookie", "mb_session=; Path=/; HttpOnly; Max-Age=0");
      return res.status(200).json({ ok: true });
    }

    const who = verify(readCookie(req, "mb_session"));
    if (!who) return res.status(200).json({ ok: false, anon: true });

    if (action === "save") {
      const b = await body(req);
      const raw = await kv(["GET", "mb:user:" + who]);
      if (!raw) return res.status(404).json({ ok: false, error: "Account missing." });
      const rec = JSON.parse(raw);
      rec.data = b.data || rec.data;
      rec.updated = Date.now();
      await kv(["SET", "mb:user:" + who, JSON.stringify(rec)]);
      if (rec.data && typeof rec.data.rp === "number")
        await kv(["ZADD", "mb:board", String(rec.data.rp), who]);
      return res.status(200).json({ ok: true });
    }

    if (action === "board") {
      const rows = await kv(["ZRANGE", "mb:board", "0", "9", "REV", "WITHSCORES"]) || [];
      const out = [];
      for (let i = 0; i < rows.length; i += 2) out.push({ name: rows[i], rp: +rows[i + 1] });
      return res.status(200).json({ ok: true, board: out });
    }

    const raw = await kv(["GET", "mb:user:" + who]);
    if (!raw) return res.status(200).json({ ok: false, anon: true });
    return res.status(200).json({ ok: true, username: who, data: JSON.parse(raw).data });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
};
