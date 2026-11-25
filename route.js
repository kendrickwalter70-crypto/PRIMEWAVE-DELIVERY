// PRIMEWAVE DELIVERY backend for Cloudflare Pages.
// Save this file in your repository as:  functions/api/[[route]].js
// It needs one KV storage binding named PW (explained in the setup steps).

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const enc = new TextEncoder();
const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array((h.match(/../g) || []).map((x) => parseInt(x, 16)));
const ITER = 10000; // kept modest so it fits the free plan's 10 ms CPU limit
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, k, 256));
}
async function newAuth(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: toHex(salt), hash: toHex(await hashPw(pw, salt)) };
}
const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };
const same = async (rec, pw) => eq(await hashPw(pw, fromHex(rec.salt)), fromHex(rec.hash));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

export async function onRequest({ request, env }) {
  const kv = env.PW;
  if (!kv) return J({ error: "storage not connected" }, 500);
  const get = (k) => kv.get(k, "json");
  const put = (k, v) => kv.put(k, JSON.stringify(v));
  const route = new URL(request.url).pathname.replace(/^\/api\/?/, "");
  const envPw = env.ADMIN_PASSWORD || "";
  let auth = await get("auth");
  const needSetup = !auth && !envPw;

  if (route === "public" && request.method === "GET") {
    const pub = (await get("public")) || {};
    return J({ pub: pub.pub, settings: pub.settings, setup: needSetup });
  }
  if (request.method !== "POST") return J({ error: "not found" }, 404);

  let b = {};
  try { b = await request.json(); } catch (e) { return J({ error: "bad request" }, 400); }

  if (route === "setup") {
    if (!needSetup) return J({ error: "already set up" }, 403);
    if (typeof b.password !== "string" || b.password.length < 8) return J({ error: "short" }, 400);
    await put("auth", await newAuth(b.password));
    await put("private", { orders: Array.isArray(b.orders) ? b.orders : [], settings: b.settings || null });
    await put("meta", { savedAt: Date.now(), publishedAt: 0 });
    return J({ ok: true });
  }

  const pw = typeof b.password === "string" ? b.password : "";
  let ok = false;
  if (auth) ok = await same(auth, pw);
  else if (envPw && eq(enc.encode(pw), enc.encode(envPw))) { auth = await newAuth(pw); await put("auth", auth); ok = true; }
  if (!ok) { await wait(600); return J({ error: "unauthorized" }, 401); }

  const meta = (await get("meta")) || { savedAt: 0, publishedAt: 0 };

  if (route === "login") {
    const p = await get("private");
    return J({ ok: true, orders: p ? p.orders : null, settings: p ? p.settings : null, dirty: meta.savedAt > meta.publishedAt });
  }
  if (route === "save") {
    if (!Array.isArray(b.orders)) return J({ error: "bad request" }, 400);
    await put("private", { orders: b.orders, settings: b.settings || null });
    await put("meta", { ...meta, savedAt: Date.now() });
    return J({ ok: true });
  }
  if (route === "publish") {
    if (!Array.isArray(b.pub)) return J({ error: "bad request" }, 400);
    await put("public", { pub: b.pub, settings: b.settings || null });
    await put("meta", { ...meta, publishedAt: Date.now() + 1 });
    return J({ ok: true });
  }
  if (route === "password") {
    if (typeof b.next !== "string" || b.next.length < 8) return J({ error: "short" }, 400);
    await put("auth", await newAuth(b.next));
    return J({ ok: true });
  }
  return J({ error: "not found" }, 404);
}
