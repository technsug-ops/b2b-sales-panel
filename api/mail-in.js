// Eingehende E-Mails (Resend Inbound, Webhook "email.received").
// Antwortadresse beim Versand: <tenant>.<ref>@MAIL_IN_DOMAIN  → die Antwort landet im richtigen Auftrag / in der richtigen Preisanfrage.
// Signatur: Svix-Header (svix-id, svix-timestamp, svix-signature) mit RESEND_WEBHOOK_SECRET (whsec_…).
import { put, get } from '@vercel/blob';
import { createHmac, timingSafeEqual } from 'node:crypto';

const TENANTS = ['aydemir', 'ug-alu', 'sirius', 'laggner'];
const LEGACY = {};
const pth = (T, kind) => T === 'aydemir' && LEGACY[kind] ? LEGACY[kind] : `gate/t/${T}/${kind}.json`;
async function loadJson(path) {
  try { const r = await get(path, { access: 'private', useCache: false }); if (!r) return null; return JSON.parse(await new Response(r.stream).text()); }
  catch (e) { if (e && e.name === 'BlobNotFoundError') return null; throw e; }
}
async function saveJson(path, data) {
  await put(path, JSON.stringify(data), { access: 'private', addRandomSuffix: false, allowOverwrite: true, contentType: 'application/json' });
}
async function rawBody(req) {
  // req.body nicht anfassen: der Getter würde den Stream lesen und die Signaturprüfung unmöglich machen
  const chunks = []; for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)); return Buffer.concat(chunks).toString('utf8');
}
function verify(raw, h, secret) {
  const id = h['svix-id'], ts = h['svix-timestamp'], sig = h['svix-signature'];
  if (!id || !ts || !sig || !secret) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const exp = createHmac('sha256', key).update(`${id}.${ts}.${raw}`).digest();
  return String(sig).split(' ').some(p => { const b = Buffer.from(p.split(',')[1] || '', 'base64'); return b.length === exp.length && timingSafeEqual(b, exp); });
}
const strip = h => String(h || '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\n{3,}/g, '\n\n').trim();
// Zitierten Verlauf abschneiden („Am … schrieb …“, „-----Original“, „>“-Zeilen)
const clip = t => String(t || '').split(/\n(?:Am .{5,120}schrieb|On .{5,120}wrote|-{2,} ?(?:Original|Ursprüngliche)|From: |Von: )/)[0].split('\n').filter(l => !/^>/.test(l)).join('\n').trim();

export const config = { api: { bodyParser: false } };
export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') return res.status(405).json({ ok: false });
    const raw = await rawBody(req);
    if (!verify(raw, req.headers, process.env.RESEND_WEBHOOK_SECRET || '')) return res.status(401).json({ ok: false, error: 'signature' });
    const evt = JSON.parse(raw);
    if (evt.type !== 'email.received') return res.status(200).json({ ok: true, ignored: evt.type });
    const d = evt.data || {}; const KEY = process.env.RESEND_API_KEY || '';
    let full = {};
    if (KEY && d.email_id) { const r = await fetch('https://api.resend.com/emails/receiving/' + encodeURIComponent(d.email_id), { headers: { Authorization: 'Bearer ' + KEY } }); if (r.ok) full = await r.json(); }
    const rcpt = [...(d.to || []), ...(d.received_for || []), ...(full.to || [])].map(x => String(x).toLowerCase());
    let T = process.env.MAIL_IN_TENANT || 'laggner', ref = '';
    for (const a of rcpt) { const m = a.match(/^([a-z0-9-]+)\.([a-z0-9-]{3,24})@/); if (m && TENANTS.includes(m[1])) { T = m[1]; ref = m[2].toUpperCase(); break; } }
    const subject = String(d.subject || full.subject || '').slice(0, 200);
    if (!ref) { const m = subject.match(/\b((?:[ATM]-[A-Z0-9]{4,12})|PA-\d{3,6}|SF-\d{2}-\d{4})\b/); if (m) ref = m[1]; }
    const text = clip(full.text || strip(full.html)).slice(0, 6000);
    const P = pth(T, 'mails'); const L = (await loadJson(P)) || [];
    if (L.some(m => m.id === d.email_id)) return res.status(200).json({ ok: true, dup: true });
    L.unshift({ id: d.email_id, dir: 'in', ref, from: String(d.from || full.from || '').slice(0, 200), to: rcpt.slice(0, 5), subject, text,
      atts: (d.attachments || full.attachments || []).slice(0, 10).map(a => ({ id: a.id, filename: String(a.filename || '').slice(0, 120), type: a.content_type, size: a.size || null })),
      at: Date.now(), seen: false, auth: full.authentication ? { spf: full.authentication.spf, dkim: full.authentication.dkim } : null });
    await saveJson(P, L.slice(0, 3000));
    return res.status(200).json({ ok: true, tenant: T, ref });
  } catch (e) { console.error(e); return res.status(500).json({ ok: false, error: 'server' }); }
}
