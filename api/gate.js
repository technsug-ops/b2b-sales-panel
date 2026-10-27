// Access gate for the B2B Sales Panel demo.
// POST /api/gate  { action: "login", code }                 -> { ok, token }
// POST /api/gate  { action: "verify", token }               -> { ok }
// POST /api/gate  { action: "create", admin, label, ttlHours } -> { ok, code, expires }
// POST /api/gate  { action: "list", admin }                 -> { ok, codes: [...] }
// POST /api/gate  { action: "revoke", admin, id }           -> { ok }
//
// Master code: permanent, SHA-256 compared against GATE_MASTER_HASH.
// One-time codes: stored in Vercel Blob (codes.json); burned on first successful login.

import { put, list } from '@vercel/blob';
import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';

const BLOB_PATH = 'gate/codes.json';
const MASTER_HASH = process.env.GATE_MASTER_HASH || '';
const ADMIN_SECRET = process.env.GATE_ADMIN_SECRET || '';
const SESSION_HOURS = 12;

const sha = s => createHash('sha256').update(String(s)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

function makeToken(sub) {
  const exp = Date.now() + SESSION_HOURS * 3600e3;
  const payload = Buffer.from(JSON.stringify({ sub, exp })).toString('base64url');
  const sig = createHmac('sha256', ADMIN_SECRET + MASTER_HASH).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(tok) {
  if (!tok || typeof tok !== 'string' || !tok.includes('.')) return null;
  const [payload, sig] = tok.split('.');
  const expect = createHmac('sha256', ADMIN_SECRET + MASTER_HASH).update(payload).digest('base64url');
  if (!safeEq(sig, expect)) return null;
  try { const d = JSON.parse(Buffer.from(payload, 'base64url').toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}

async function loadCodes() {
  try {
    const { blobs } = await list({ prefix: BLOB_PATH, limit: 1 });
    if (!blobs.length) return [];
    const r = await fetch(blobs[0].url, { cache: 'no-store' });
    if (!r.ok) return [];
    return await r.json();
  } catch { return []; }
}
async function saveCodes(codes) {
  await put(BLOB_PATH, JSON.stringify(codes), { access: 'public', addRandomSuffix: false, contentType: 'application/json', cacheControlMaxAge: 0 });
}
function genCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = n => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join('');
  return `${part(4)}-${part(4)}`;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'POST only' });
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};
  const { action } = body;

  if (action === 'verify') {
    const d = verifyToken(body.token);
    return res.status(200).json({ ok: !!d, sub: d?.sub || null });
  }

  if (action === 'login') {
    const code = String(body.code || '').trim();
    if (!code) return res.status(400).json({ ok: false, error: 'empty' });
    if (MASTER_HASH && safeEq(sha(code), MASTER_HASH)) {
      return res.status(200).json({ ok: true, token: makeToken('master'), kind: 'master' });
    }
    const norm = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    const codes = await loadCodes();
    const now = Date.now();
    const hit = codes.find(c => !c.usedAt && c.expires > now && safeEq(c.hash, sha(norm)));
    if (!hit) return res.status(401).json({ ok: false, error: 'invalid' });
    hit.usedAt = now;
    hit.usedUa = String(req.headers['user-agent'] || '').slice(0, 120);
    await saveCodes(codes);
    return res.status(200).json({ ok: true, token: makeToken(hit.id), kind: 'once', label: hit.label });
  }

  // admin actions
  if (!ADMIN_SECRET || !safeEq(String(body.admin || ''), ADMIN_SECRET)) {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  const codes = await loadCodes();

  if (action === 'create') {
    const ttl = Math.min(Math.max(Number(body.ttlHours) || 48, 1), 24 * 30);
    const code = genCode();
    const entry = { id: 'c_' + Date.now().toString(36) + randomInt(1e6).toString(36), label: String(body.label || '').slice(0, 80), hash: sha(code.replace(/-/g, '')), created: Date.now(), expires: Date.now() + ttl * 3600e3, usedAt: null };
    codes.unshift(entry);
    await saveCodes(codes.slice(0, 500));
    return res.status(200).json({ ok: true, code, id: entry.id, expires: entry.expires, label: entry.label });
  }
  if (action === 'list') {
    return res.status(200).json({ ok: true, codes: codes.map(({ hash, usedUa, ...c }) => ({ ...c, usedUa })) });
  }
  if (action === 'revoke') {
    const i = codes.findIndex(c => c.id === body.id);
    if (i < 0) return res.status(404).json({ ok: false, error: 'not found' });
    codes[i].expires = 0; codes[i].revoked = Date.now();
    await saveCodes(codes);
    return res.status(200).json({ ok: true });
  }
  return res.status(400).json({ ok: false, error: 'unknown action' });
}
