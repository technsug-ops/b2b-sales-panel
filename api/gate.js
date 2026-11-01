// Access gate for the B2B Sales Panel demo.
// POST /api/gate  { action: "login", code }                 -> { ok, token }
// POST /api/gate  { action: "verify", token }               -> { ok }
// POST /api/gate  { action: "create", admin, label, ttlHours, target:{tenant, area:"team"|"partner", role|pid,door} } -> { ok, code, expires }
//   A one-time code is bound to one company (tenant) and one access (team role or one partner account).
//   It only works at that company's entrance and lands with exactly those rights.
// POST /api/gate  { action: "list", admin }                 -> { ok, codes: [...] }
// POST /api/gate  { action: "revoke", admin, id }           -> { ok }
// POST /api/gate  { action: "tpass", token, old, pass }      -> team member changes own password (old sessions end)
// POST /api/gate  { action: "plogin", door:"network", user, pass } -> partner login (type from account)
// POST /api/gate  { action: "pcreds_sync|pcreds_reset|pcreds_toggle", token(hq) } -> partner credentials (Firmenzentrale only)
//
// Master code: permanent, SHA-256 compared against GATE_MASTER_HASH.
// One-time codes: stored in Vercel Blob (codes.json); burned on first successful login.

import { put, get, del } from '@vercel/blob';
import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';

const BLOB_PATH = 'gate/codes.json';
const NOTES_PATH = 'gate/notes.json';
const CREDS_PATH = 'gate/partners.json';
const HQ_HASH = process.env.GATE_HQ_HASH || '';
const DOORS = ['partner', 'freelancer', 'leadgen', 'distributor'];
const TEAM_PATH = 'gate/team.json';
const TCFG_PATH = 'gate/tenant-t1.json';
const F2 = ['program', 'terr', 'cust', 'quotes', 'credit', 'returns'];
const ADDONS = ['orders', 'stock', 'install', 'projects', 'sites', 'hr', 'invoices', 'pricing', 'perf', ...F2, 'auftrag', 'mietkal', 'sortiment', 'zumiet', 'flotte', 'mietabr', 'boerse', 'uebergabe', 'wartung', 'telematik', 'firmenkd', 'baucheck', 'schulung', 'bewert'];
const PTYPES = ['leadgen', 'freelancer', 'partner', 'distributor'];
const RENT_ONLY = ['auftrag', 'mietkal', 'sortiment', 'zumiet', 'flotte', 'mietabr', 'boerse', 'uebergabe', 'wartung', 'telematik', 'firmenkd', 'baucheck', 'schulung', 'bewert'];
const DEFAULT_TCFG = { features: ADDONS.filter(x => x !== 'invoices' && !RENT_ONLY.includes(x)), types: { leadgen: { on: true, label: '' }, freelancer: { on: true, label: '' }, partner: { on: true, label: '' }, distributor: { on: true, label: '' } } };
const ROLES_PATH = 'gate/roles.json';
// ---- tenants: aydemir keeps its original blob paths; others live under gate/t/<slug>/
const TENANTS = ['aydemir', 'ug-alu', 'sirius', 'laggner'];
const tenantOf = b => (TENANTS.includes(String(b && b.tenant || '')) ? String(b.tenant) : 'aydemir');
const LEGACY = { team: TEAM_PATH, roles: ROLES_PATH, creds: CREDS_PATH, tcfg: TCFG_PATH };
const pth = (T, kind) => T === 'aydemir' && LEGACY[kind] ? LEGACY[kind] : `gate/t/${T}/${kind}.json`;
const RENT_MIG = [[2, ['mietkal', 'zumiet', 'flotte', 'mietabr', 'boerse', 'uebergabe', 'bewert']], [3, ['wartung']], [4, ['telematik', 'firmenkd', 'baucheck', 'schulung']], [5, ['sortiment']], [6, ['auftrag']]];
const RENT_V = 6;
const TENANT_DEFAULT_CFG = { 'ug-alu': { features: ['orders', 'stock', 'install', 'sites', 'hr', 'invoices', 'pricing', 'perf', ...F2], types: DEFAULT_TCFG.types }, sirius: { features: ['orders', 'stock', 'pricing', 'perf', ...F2], types: DEFAULT_TCFG.types }, laggner: { features: ['orders', 'stock', 'install', 'invoices', 'pricing', 'perf', ...F2, 'auftrag', 'mietkal', 'sortiment', 'zumiet', 'flotte', 'mietabr', 'boerse', 'uebergabe', 'wartung', 'telematik', 'firmenkd', 'baucheck', 'schulung', 'bewert'], types: DEFAULT_TCFG.types } };
const tcfgDefault = T => TENANT_DEFAULT_CFG[T] || DEFAULT_TCFG;
// packages: partners (sub-dealers) and team users a tenant may open; 0 = unlimited; per-tenant override in cfg.limits
const PLAN_LIMITS = { Starter: { partners: 25, users: 5 }, Business: { partners: 100, users: 15 }, Group: { partners: 0, users: 0 } };
const PLAN_DEFAULT = { aydemir: 'Group', 'ug-alu': 'Starter', sirius: 'Business', laggner: 'Group' };
function limitsOf(cfg, T) { const plan = PLAN_LIMITS[cfg && cfg.plan] ? cfg.plan : (PLAN_DEFAULT[T] || 'Starter'); const o = (cfg && cfg.limits) || {}; return { plan, partners: Number.isFinite(+o.partners) && o.partners !== '' && o.partners != null ? +o.partners : PLAN_LIMITS[plan].partners, users: Number.isFinite(+o.users) && o.users !== '' && o.users != null ? +o.users : PLAN_LIMITS[plan].users }; }
// a token's tenant (tokens minted before tenancy belong to aydemir)
const tokTenant = d => d && (d.ten || 'aydemir');
const PERMS = ['partners', 'leads', 'projects', 'orders', 'install', 'dam', 'settings', 'hr', 'creds', 'team', 'acct', 'prices', 'rent', 'garage', 'drive', 'web'];
const BUILTIN_ROLES = [
  { key: 'gf', name: 'Geschäftsführer', perms: PERMS.slice(), builtin: true, locked: true },
  { key: 'tech', name: 'Technik-Verantwortlicher', perms: ['partners', 'leads', 'projects', 'orders', 'dam', 'settings', 'creds'], builtin: true },
  { key: 'staff', name: 'Verwaltung', perms: ['partners', 'leads', 'projects', 'orders', 'dam'], builtin: true },
  { key: 'mitarbeiter', name: 'Mitarbeiter (nur Mein Bereich)', perms: [], builtin: true },
  { key: 'monteur', name: 'Monteur (nur Montage)', perms: ['install'], builtin: true },
  { key: 'hr', name: 'Personalabteilung', perms: ['hr'], builtin: true },
  { key: 'buchhaltung', name: 'Buchhaltung', perms: ['acct'], builtin: true },
];
// Laggner: Rollen für Vermietung (Büro, Disposition, Werkstatt, Fahrer, Außendienst, Marketing, Web-Admin)
const LAGGNER_ROLES = [{"key": "buero", "name": "Büro / Innendienst & Disposition", "perms": ["leads", "orders", "rent", "acct", "dam", "drive", "garage"], "builtin": true}, {"key": "vermietung", "name": "Vermietung / Mietberatung", "perms": ["rent", "leads", "orders"], "builtin": true}, {"key": "werkstatt", "name": "Werkstatt / Garage", "perms": ["garage", "drive"], "builtin": true}, {"key": "fahrer", "name": "Fahrer", "perms": ["drive"], "builtin": true}, {"key": "aussendienst", "name": "Außendienst / Vertrieb", "perms": ["leads", "partners", "rent"], "builtin": true}, {"key": "marketing", "name": "Marketing", "perms": ["dam", "web", "leads"], "builtin": true}, {"key": "webadmin", "name": "Web-Admin", "perms": ["web", "settings", "dam"], "builtin": true}];
async function loadRoles(T = 'aydemir') {
  const RP = pth(T, 'roles');
  let r = await loadJson(RP);
  if (!r) { r = BUILTIN_ROLES.map(x => ({ ...x, fixMa: true, migratedProjects: true })); await saveJson(RP, r); }
  let changed = false;
  for (const b of BUILTIN_ROLES) if (!r.some(x => x.key === b.key)) { r.push({ ...b, fixMa: true, migratedProjects: true, migratedInstall: true }); changed = true; }
  if (T === 'laggner') for (const b of LAGGNER_ROLES) { const x = r.find(y => y.key === b.key); if (x && (b.key === 'buero' || b.key === 'vermietung') && !x.lag2) { x.name = b.name; x.perms = b.perms.slice(); x.lag2 = true; changed = true; } }
  if (T === 'laggner') for (const b of LAGGNER_ROLES) if (!r.some(x => x.key === b.key)) { r.push({ ...b, fixMa: true, migratedProjects: true, migratedInstall: true }); changed = true; }
  for (const x of r) if (!x.migratedInstall) { if (x.perms.includes('orders') && !x.perms.includes('install')) x.perms.push('install'); x.migratedInstall = true; changed = true; }
  for (const x of r) { if (x.key === 'gf' && x.perms.length !== PERMS.length) { x.perms = PERMS.slice(); changed = true; } if (x.key === 'mitarbeiter' && !x.fixMa) { x.perms = x.perms.filter(p => p !== 'projects'); x.fixMa = true; changed = true; }
    if (x.builtin && x.key !== 'mitarbeiter' && !x.migratedProjects) { if (!x.perms.includes('projects')) x.perms.push('projects'); x.migratedProjects = true; changed = true; } }
  if (changed) await saveJson(RP, r);
  return r;
}
const docPath = (T, id) => `gate/t/${T}/docs/${id}`;
async function docBuf(T, id) { try { const r = await get(docPath(T, id), { access: 'private', useCache: false }); if (!r) return null; return Buffer.from(await new Response(r.stream).arrayBuffer()); } catch (e) { return null; } }
async function permsOf(sub, T = 'aydemir') {
  if (sub === 'hq') return PERMS.slice();
  const c = /^t:c_[a-z0-9]+:([a-z0-9-]+)$/.exec(String(sub || ''));
  if (c) { const roles = await loadRoles(T); const role = roles.find(x => x.key === c[1]); return role ? role.perms : []; }
  const m = /^t:(\d+):([a-z0-9-]+)$/.exec(String(sub || ''));
  if (!m) return null;
  const team = await loadTeam(T); const mem = team.find(x => x.id === Number(m[1]));
  if (!mem || !mem.active) return null;
  const roles = await loadRoles(T); const role = roles.find(x => x.key === mem.role);
  return role ? role.perms : [];
}
const SEED_TEAM = [
  { id: 1, name: 'Geschäftsführung', role: 'gf', user: 'geschaeftsfuehrung', pass: 'Aydemir-GF-2026' },
  { id: 2, name: 'Technik-Verantwortlicher', role: 'tech', user: 'technik', pass: 'Aydemir-Tech-2026' },
  { id: 3, name: 'Verwaltung', role: 'staff', user: 'verwaltung', pass: 'Aydemir-Team-2026' },
  { id: 4, name: 'Mehmet K.', role: 'monteur', user: 'mehmet', pass: 'Aydemir-Mont-2026' },
  { id: 5, name: 'Selin A. (Personal)', role: 'hr', user: 'personal', pass: 'Aydemir-HR-2026' },
];
const SEEDS = { aydemir: SEED_TEAM, 'ug-alu': [
  { id: 1, name: 'Geschäftsführung', role: 'gf', user: 'geschaeftsfuehrung', pass: 'UGAlu-GF-2026' },
  { id: 2, name: 'Vertrieb', role: 'staff', user: 'vertrieb', pass: 'UGAlu-Team-2026' },
  { id: 3, name: 'Montageleitung', role: 'monteur', user: 'montage', pass: 'UGAlu-Mont-2026' },
  { id: 4, name: 'Buchhaltung', role: 'buchhaltung', user: 'buchhaltung', pass: 'UGAlu-Buha-2026' },
], sirius: [
  { id: 1, name: 'Directie', role: 'gf', user: 'geschaeftsfuehrung', pass: 'Sirius-GF-2026' },
  { id: 2, name: 'Verkoop binnendienst', role: 'staff', user: 'verkoop', pass: 'Sirius-Team-2026' },
], laggner: [
  { id: 1, name: 'Geschäftsführung', role: 'gf', user: 'geschaeftsfuehrung', pass: 'Laggner-GF-2026' },
  { id: 2, name: 'Disposition Heidenheim', role: 'vermietung', user: 'disposition', pass: 'Laggner-Dispo-2026' },
  { id: 3, name: 'Fahrer / Einweisung', role: 'fahrer', user: 'fahrer', pass: 'Laggner-Fahrer-2026' },
  { id: 4, name: 'Buchhaltung', role: 'buchhaltung', user: 'buchhaltung', pass: 'Laggner-Buha-2026' },
] };
async function loadTeam(T = 'aydemir') {
  const TP = pth(T, 'team');
  let t = await loadJson(TP);
  if (!t) { t = SEEDS[T].map(x => ({ id: x.id, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() })); await saveJson(TP, t); }
  let tc = false;
  for (const x of t) if ((x.user === 'mehmet' || x.user === 'montage') && x.role === 'mitarbeiter' && !x.roleMig) { x.role = 'monteur'; x.roleMig = true; tc = true; }
  if (T === 'aydemir' && !t.some(x => x.user === 'personal')) { const x = SEED_TEAM[4]; t.push({ id: Math.max(0, ...t.map(m => m.id)) + 1, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() }); tc = true; }
  if (T === 'ug-alu' && !t.some(x => x.user === 'buchhaltung')) { const x = SEEDS['ug-alu'][3]; t.push({ id: Math.max(0, ...t.map(m => m.id)) + 1, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() }); tc = true; }
  if (T === 'laggner') for (const x of t) if (!x.lagRole && ((x.user === 'disposition' && x.role === 'staff') || (x.user === 'fahrer' && x.role === 'monteur'))) { x.role = x.user === 'fahrer' ? 'fahrer' : 'vermietung'; x.lagRole = true; tc = true; }
  if (T === 'laggner') for (const x of t) if (x.user === 'disposition' && x.role === 'vermietung' && !x.lag2) { x.role = 'buero'; x.lag2 = true; tc = true; }
  if (tc) await saveJson(TP, t);
  if (T === 'aydemir' && !t.some(x => x.user === 'mehmet')) { const x = SEED_TEAM[3]; t.push({ id: Math.max(0, ...t.map(m => m.id)) + 1, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() }); await saveJson(TP, t); }
  return t;
}
const publicMember = m => ({ id: m.id, name: m.name, role: m.role, user: m.user, active: m.active, created: m.created, lastLogin: m.lastLogin || null, logins: m.logins || 0 });
// who may manage partner credentials: Geschäftsführung + Technik

const MASTER_HASH = process.env.GATE_MASTER_HASH || '';
const ADMIN_SECRET = process.env.GATE_ADMIN_SECRET || '';
const SESSION_HOURS = 12;

const sha = s => createHash('sha256').update(String(s)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

function makeToken(sub, expCap, ten, extra) {
  let exp = Date.now() + SESSION_HOURS * 3600e3;
  if (expCap && expCap < exp) exp = expCap;
  const payload = Buffer.from(JSON.stringify({ sub, exp, iat: Date.now(), ...(ten ? { ten } : {}), ...(extra || {}) })).toString('base64url');
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
    const res = await get(BLOB_PATH, { access: 'private', useCache: false });
    if (!res) return [];
    const text = await new Response(res.stream).text();
    const data = JSON.parse(text);
    return Array.isArray(data) ? data : [];
  } catch (e) { if (e && e.name === 'BlobNotFoundError') return []; throw e; }
}
async function saveCodes(codes) {
  await put(BLOB_PATH, JSON.stringify(codes), { access: 'private', addRandomSuffix: false, allowOverwrite: true, contentType: 'application/json' });
}
async function loadJson(path) {
  try { const r = await get(path, { access: 'private', useCache: false }); if (!r) return null; return JSON.parse(await new Response(r.stream).text()); }
  catch (e) { if (e && e.name === 'BlobNotFoundError') return null; throw e; }
}
async function saveJson(path, data) {
  await put(path, JSON.stringify(data), { access: 'private', addRandomSuffix: false, allowOverwrite: true, contentType: 'application/json' });
}
const WORDS = ['Zelt', 'Regen', 'Stahl', 'Halle', 'Wasser', 'Montage', 'Planke', 'Anker', 'Wolke', 'Tanne', 'Kiesel', 'Falke', 'Brise', 'Felsen', 'Linde', 'Quelle'];
function genPassword() { return `${WORDS[randomInt(WORDS.length)]}-${String(randomInt(10000)).padStart(4, '0')}-${WORDS[randomInt(WORDS.length)].toLowerCase()}`; }
function slug(s) { return String(s).toLowerCase().replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24); }
const publicCred = c => ({ id: c.id, name: c.name, doors: c.doors, user: c.user, pass: c.pass, active: c.active, created: c.created, lastLogin: c.lastLogin || null, logins: c.logins || 0 });

function genCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = n => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join('');
  return `${part(4)}-${part(4)}`;
}

export default async function handler(req, res) {
  try { return await main(req, res); } catch (e) { console.error(e); return res.status(500).json({ ok: false, error: 'server', detail: String(e && e.message || e).slice(0, 200) }); }
}
async function main(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'POST only' });
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};
  const { action } = body;
  const T = tenantOf(body);
  // tenant-bound subjects (team t:, partner p:) only count inside their own tenant
  const scoped = d => d && /^[tp]:/.test(String(d.sub)) ? (tokTenant(d) === T ? d : null) : d;
  // a suspended customer (tenant) loses every login: team, partner, bound codes; the TechNS console keeps working
  const isSusp = async t => !!(((await loadJson(pth(t, 'status'))) || {}).suspended);
  const SUSP = { ok: false, error: 'suspended' };
  if (['plogin', 'tlogin', 'tpass'].includes(action) || (action && (action.startsWith('team_') || action.startsWith('pcreds_')))) { if (await isSusp(T)) return res.status(403).json(SUSP); }

  // Auftragsmanagement (Mandant): Anfragen von der Website/Online-Buchung landen hier; Team liest und bearbeitet
  if (action === 'inq_add') {
    const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
    if (s(body.hp, 10)) return res.status(200).json({ ok: true });
    const q = body.q || {};
    const name = s(q.name, 80), firma = s(q.firma, 120), tel = s(q.tel, 40), mail = s(q.mail, 120);
    if (!name && !firma) return res.status(400).json({ ok: false, error: 'input' });
    if (!tel && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) return res.status(400).json({ ok: false, error: 'contact' });
    const P = pth(T, 'auftraege'); const L = (await loadJson(P)) || [];
    if (L.filter(x => x.at > Date.now() - 3600e3 && /^web|online/.test(x.src)).length > 60) return res.status(429).json({ ok: false, error: 'rate' });
    const id = 'A-' + Date.now().toString(36).toUpperCase().slice(-6) + randomInt(10);
    const it = { id, at: Date.now(), upd: Date.now(), src: ['web', 'online'].includes(body.src) ? body.src : 'web', st: 'neu', brand: s(body.brand, 4),
      kunde: { firma, name, tel, mail }, plz: s(q.plz, 10), ort: s(q.ort, 60), kat: s(q.kat, 60), geraet: s(q.geraet, 160), type: s(q.type, 20),
      von: s(q.von, 20), bis: s(q.bis, 20), start: +q.start || null, end: +q.end || null, mode: s(q.mode, 12), ah: s(q.ah, 12), info: s(q.info, 1500), preis: +q.preis || null,
      log: [{ t: Date.now(), by: body.src === 'online' ? 'Online-Buchung' : 'Website', txt: 'Anfrage eingegangen' }] };
    L.unshift(it); await saveJson(P, L.slice(0, 2000));
    return res.status(200).json({ ok: true, id });
  }
  if (action === 'auf_list' || action === 'auf_save') {
    const d = scoped(verifyToken(body.token));
    if (!d || !(d.sub === 'master' || /^t:/.test(String(d.sub)))) return res.status(403).json({ ok: false, error: 'forbidden' });
    const P = pth(T, 'auftraege'); let L = (await loadJson(P)) || [];
    if (action === 'auf_save') {
      const items = Array.isArray(body.items) ? body.items.slice(0, 50) : [body.item];
      for (const it of items) {
        if (!it || typeof it !== 'object' || !/^[A-Z]-[A-Z0-9]{3,12}$/.test(String(it.id || ''))) continue;
        const raw = JSON.stringify(it); if (raw.length > 60000) continue;
        const i = L.findIndex(x => x.id === it.id); const cur = i >= 0 ? L[i] : null;
        if (cur && (cur.upd || 0) > (it.upd || 0) + 1000) continue;          // neuere Fassung auf dem Server gewinnt
        const nx = { ...it, upd: Math.max(Date.now(), it.upd || 0) };
        if (i >= 0) L[i] = nx; else L.unshift(nx);
      }
      await saveJson(P, L.slice(0, 2000));
    }
    return res.status(200).json({ ok: true, list: L });
  }
  // Marktanalyse (Marktchancen je Stadt): Analyse-Datei + Einstellungen liegen privat im Blob, nur Rechte „web“ (Geschäftsführung, Marketing, Web-Admin)
  if (['markt_get', 'markt_put', 'markt_cfg'].includes(action)) {
    const d = scoped(verifyToken(body.token));
    if (!d || !(d.sub === 'master' || /^t:/.test(String(d.sub)))) return res.status(403).json({ ok: false, error: 'forbidden' });
    if (d.sub !== 'master') { const pm = await permsOf(d.sub, T); if (!pm || !pm.includes('web')) return res.status(403).json({ ok: false, error: 'forbidden' }); }
    const PH = pth(T, 'markt-file'), PC = pth(T, 'markt-cfg');
    if (action === 'markt_get') {
      const [f, c] = await Promise.all([body.noFile ? null : loadJson(PH), loadJson(PC)]);
      return res.status(200).json({ ok: true, file: f, cfg: c || {} });
    }
    if (action === 'markt_put') {
      const html = String(body.html || '');
      if (html.length > 3e6 || !/const DATA=\{/.test(html) || !/\nconst CH=\{/.test(html)) return res.status(400).json({ ok: false, error: 'format' });
      const f = { html, name: String(body.name || '').slice(0, 120), at: Date.now(), by: String(body.by || '').slice(0, 80) };
      await saveJson(PH, f); return res.status(200).json({ ok: true, at: f.at });
    }
    // markt_cfg: Gewichte, Partner-Kandidaten
    const c = (await loadJson(PC)) || {}; const inc = body.cfg || {};
    const num = (v, a, b) => { const n = Number(v); return Number.isFinite(n) ? Math.min(b, Math.max(a, n)) : undefined; };
    if ('w' in inc) { if (inc.w && typeof inc.w === 'object') { c.w = {}; for (const [k, v] of Object.entries(inc.w).slice(0, 12)) { const n = num(v, 0, 3); if (n !== undefined) c.w[String(k).slice(0, 40)] = n; } } else delete c.w; }
    if ('reach' in inc) { if (inc.reach && typeof inc.reach === 'object') { c.reach = {}; for (const k of ['m1', 'm2', 'm3', 'f2', 'f3']) { const n = num(inc.reach[k], 0, 300); if (n !== undefined) c.reach[k] = n; } } else delete c.reach; }
    if (Array.isArray(inc.cands)) c.cands = inc.cands.slice(0, 200).map(x => ({ n: String(x.n || '').slice(0, 80), k: String(x.k || '').slice(0, 80), st: ['offen', 'kontaktiert', 'gewonnen', 'verworfen'].includes(x.st) ? x.st : 'offen', note: String(x.note || '').slice(0, 300), at: Number(x.at) || Date.now() })).filter(x => x.n);
    c.at = Date.now(); await saveJson(PC, c); return res.status(200).json({ ok: true, cfg: c });
  }
  // Preismodell (Staffel, Transportmatrix) + Verbund-Richtpreise (z. B. Systemlift): privat im Blob. Lesen: alle mit Vermiet-/Angebotsrechten; Ändern: Geschäftsführung/Abrechnung
  if (['tarif_get', 'tarif_put', 'richt_put', 'richt_del'].includes(action)) {
    const d = scoped(verifyToken(body.token));
    if (!d || !(d.sub === 'master' || /^t:/.test(String(d.sub)))) return res.status(403).json({ ok: false, error: 'forbidden' });
    let pm = null; if (d.sub !== 'master') { pm = await permsOf(d.sub, T); if (!pm || !['leads', 'orders', 'rent', 'acct', 'web'].some(x => pm.includes(x))) return res.status(403).json({ ok: false, error: 'forbidden' }); }
    const canEdit = !pm || ['acct', 'web'].some(x => pm.includes(x));
    const PT = pth(T, 'tarif'), PR = pth(T, 'richt');
    if (action === 'tarif_get') { const [t, r] = await Promise.all([loadJson(PT), loadJson(PR)]); return res.status(200).json({ ok: true, tarif: t || null, richt: r || null, edit: canEdit }); }
    if (!canEdit) return res.status(403).json({ ok: false, error: 'forbidden' });
    if (action === 'richt_del') { await saveJson(PR, null); return res.status(200).json({ ok: true }); }
    const raw = action === 'tarif_put' ? body.tarif : body.richt; const js = JSON.stringify(raw || null);
    if (!raw || typeof raw !== 'object' || js.length > 200000) return res.status(400).json({ ok: false, error: 'format' });
    if (action === 'richt_put' && (raw.kind !== 'verbund-richtpreise' || !Array.isArray(raw.cats))) return res.status(400).json({ ok: false, error: 'format' });
    const o = JSON.parse(js); o.at = Date.now(); await saveJson(action === 'tarif_put' ? PT : PR, o); return res.status(200).json({ ok: true, at: o.at });
  }
  // Dokumente (Datenblätter, Anleitungen, Prüfberichte): privat im Blob, als Anhang für E-Mails
  if (['doc_list', 'doc_put', 'doc_del', 'doc_get'].includes(action)) {
    const d = scoped(verifyToken(body.token));
    if (!d || !(d.sub === 'master' || /^t:/.test(String(d.sub)))) return res.status(403).json({ ok: false, error: 'forbidden' });
    let pm = null; if (d.sub !== 'master') { pm = await permsOf(d.sub, T); if (!pm || !['leads', 'orders', 'rent', 'acct', 'dam', 'web'].some(x => pm.includes(x))) return res.status(403).json({ ok: false, error: 'forbidden' }); }
    const canEdit = !pm || ['dam', 'web', 'rent'].some(x => pm.includes(x));
    const P = pth(T, 'docs'); const L = (await loadJson(P)) || [];
    if (action === 'doc_list') return res.status(200).json({ ok: true, list: L, edit: canEdit });
    const D = L.find(x => x.id === String(body.id || ''));
    if (action === 'doc_get') { if (!D) return res.status(404).json({ ok: false }); const b = await docBuf(T, D.id); if (!b) return res.status(404).json({ ok: false }); return res.status(200).json({ ok: true, mime: D.mime, name: D.name, data: b.toString('base64') }); }
    if (!canEdit) return res.status(403).json({ ok: false, error: 'forbidden' });
    if (action === 'doc_del') { if (!D) return res.status(404).json({ ok: false }); try { await del(docPath(T, D.id)); } catch (e) {} await saveJson(P, L.filter(x => x.id !== D.id)); return res.status(200).json({ ok: true }); }
    const mime = String(body.mime || ''); if (!/^(application\/pdf|image\/(png|jpeg|webp))$/.test(mime)) return res.status(400).json({ ok: false, error: 'type' });
    const buf = Buffer.from(String(body.data || ''), 'base64'); if (!buf.length || buf.length > 3_100_000) return res.status(400).json({ ok: false, error: 'size' });
    const id = 'd' + Date.now().toString(36) + randomInt(1e6).toString(36);
    await put(docPath(T, id), buf, { access: 'private', addRandomSuffix: false, allowOverwrite: true, contentType: mime });
    const doc = { id, name: String(body.name || 'Dokument').replace(/[^\w äöüÄÖÜß.,()+-]/g, '').slice(0, 100) || 'Dokument', cat: String(body.cat || 'datenblatt').slice(0, 20), types: (Array.isArray(body.types) ? body.types : []).map(String).slice(0, 20), units: (Array.isArray(body.units) ? body.units : []).map(x => String(x).slice(0, 30)).slice(0, 20), valid: /^\d{4}-\d{2}-\d{2}$/.test(String(body.valid || '')) ? String(body.valid) : '', mime, size: buf.length, at: Date.now(), by: String(body.by || '').slice(0, 60) };
    L.unshift(doc); await saveJson(P, L.slice(0, 500)); return res.status(200).json({ ok: true, doc });
  }
  // E-Mail (Resend): Versand aus dem Auftrag, Antworten kommen über /api/mail-in zurück
  if (['mail_cfg', 'mail_send', 'mail_list', 'mail_seen', 'mail_assign', 'mail_tpl', 'mail_tpl_save'].includes(action)) {
    const d = scoped(verifyToken(body.token));
    if (!d || !(d.sub === 'master' || /^t:/.test(String(d.sub)))) return res.status(403).json({ ok: false, error: 'forbidden' });
    if (d.sub !== 'master') { const pm = await permsOf(d.sub, T); if (!pm || !['leads', 'orders', 'rent', 'acct'].some(x => pm.includes(x))) return res.status(403).json({ ok: false, error: 'forbidden' }); }
    const KEY = process.env.RESEND_API_KEY || '', FROM = process.env.MAIL_FROM || '', IN = process.env.MAIL_IN_DOMAIN || '';
    if (action === 'mail_tpl' || action === 'mail_tpl_save') { const TP = pth(T, 'mailtpl'); let TL = (await loadJson(TP)) || [];
      if (action === 'mail_tpl_save') { const x = body.tpl || {}; const id = /^u[\w]{3,20}$/.test(String(x.id || '')) ? String(x.id) : 'u' + Date.now().toString(36);
        if (body.del) TL = TL.filter(t => t.id !== id);
        else { const t = { id, kind: String(x.kind || 'an').slice(0, 20), n: String(x.n || 'Vorlage').slice(0, 80), s: String(x.s || '').slice(0, 200), t: String(x.t || '').slice(0, 8000), by: String(body.by || '').slice(0, 60), at: Date.now() }; TL = [t, ...TL.filter(y => y.id !== id)].slice(0, 200); }
        await saveJson(TP, TL); }
      return res.status(200).json({ ok: true, list: TL }); }
    const P = pth(T, 'mails');
    if (action === 'mail_cfg') return res.status(200).json({ ok: true, send: !!(KEY && FROM), inbound: !!IN, from: FROM.replace(/^.*<|>.*$/g, '') });
    const L = (await loadJson(P)) || [];
    const okRef = r => /^[A-Za-z0-9-]{3,24}$/.test(String(r || ''));
    if (action === 'mail_list') {
      const ref = String(body.ref || '');
      const out = L.filter(m => !ref || m.ref === ref || (m.refs || []).includes(ref)).slice(0, 200);
      return res.status(200).json({ ok: true, list: out, unseen: L.filter(m => m.dir === 'in' && !m.seen).length });
    }
    if (action === 'mail_assign') { const m = L.find(x => x.id === String(body.id || '')); if (!m) return res.status(404).json({ ok: false }); m.ref = okRef(body.ref) ? String(body.ref) : ''; await saveJson(P, L); return res.status(200).json({ ok: true, mail: m }); }
    if (action === 'mail_seen') { const ids = new Set((body.ids || []).map(String)); let n = 0; for (const m of L) if (ids.has(m.id) && !m.seen) { m.seen = Date.now(); n++; } if (n) await saveJson(P, L); return res.status(200).json({ ok: true }); }
    // mail_send
    if (!KEY || !FROM) return res.status(200).json({ ok: false, error: 'not_configured' });
    const s = (v, n) => String(v == null ? '' : v).slice(0, n);
    const em = /^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$/;
    const to = (Array.isArray(body.to) ? body.to : String(body.to || '').split(/[,;]/)).map(x => String(x).trim()).filter(Boolean).slice(0, 10);
    const cc = (Array.isArray(body.cc) ? body.cc : String(body.cc || '').split(/[,;]/)).map(x => String(x).trim()).filter(Boolean).slice(0, 5);
    if (!to.length || ![...to, ...cc].every(x => em.test(x))) return res.status(400).json({ ok: false, error: 'address' });
    const subject = s(body.subject, 200).replace(/[\r\n]/g, ' '), text = s(body.text, 20000);
    if (!subject || !text) return res.status(400).json({ ok: false, error: 'input' });
    const ref = okRef(body.ref) ? String(body.ref) : '';
    const atts = (Array.isArray(body.attach) ? body.attach : []).slice(0, 6).filter(a => a && /^[\w .()-]{1,80}\.pdf$/i.test(String(a.filename || '')) && typeof a.content === 'string' && a.content.length < 3_000_000);
    if (Array.isArray(body.docs) && body.docs.length) { const DL = (await loadJson(pth(T, 'docs'))) || []; let tot = atts.reduce((a, x) => a + x.content.length, 0);
      for (const id of body.docs.slice(0, 8)) { const D = DL.find(x => x.id === String(id)); if (!D) continue; const b = await docBuf(T, D.id); if (!b) continue; const c = b.toString('base64'); if (tot + c.length > 28_000_000) break; tot += c.length;
        const ext = D.mime === 'application/pdf' ? '.pdf' : D.mime === 'image/png' ? '.png' : D.mime === 'image/webp' ? '.webp' : '.jpg'; atts.push({ filename: (D.name.replace(/\.(pdf|png|jpe?g|webp)$/i, '') + ext).slice(0, 100), content: c }); } }
    if (L.filter(m => m.dir === 'out' && m.at > Date.now() - 3600e3).length > 200) return res.status(429).json({ ok: false, error: 'rate' });
    const replyTo = IN && ref ? `${T}.${ref.toLowerCase()}@${IN}` : undefined;
    const html = '<div style="font:14px/1.5 Arial,sans-serif;color:#1a1a1a;white-space:pre-line">' + text.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])) + '</div>';
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM, to, cc: cc.length ? cc : undefined, subject, text, html, reply_to: replyTo, attachments: atts.map(a => ({ filename: a.filename, content: a.content })), headers: ref ? { 'X-B2B-Ref': ref } : undefined }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.id) return res.status(200).json({ ok: false, error: 'provider', detail: s(j.message || j.name || r.status, 200) });
    const m = { id: j.id, dir: 'out', ref, kind: s(body.kind, 20), to, cc, subject, text: text.slice(0, 6000), atts: atts.map(a => a.filename), at: Date.now(), by: s(body.by, 80), replyTo: replyTo || '' };
    L.unshift(m); await saveJson(P, L.slice(0, 3000));
    return res.status(200).json({ ok: true, mail: m });
  }
  // Website-Anfragen (Startseite): öffentlich schreiben, nur TechNS-Konsole liest
  if (action === 'contact') {
    const s = v => String(v || '').replace(/[\u0000-\u001f]/g, ' ').trim();
    if (s(body.hp)) return res.status(200).json({ ok: true });            // Honeypot
    const name = s(body.name).slice(0, 80), firma = s(body.firma).slice(0, 120), email = s(body.email).slice(0, 120), msg = s(body.msg).slice(0, 1500);
    const branche = s(body.branche).slice(0, 40), groesse = s(body.groesse).slice(0, 10), lang = s(body.lang).slice(0, 2);
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || body.consent !== true) return res.status(400).json({ ok: false, error: 'input' });
    const P = 'gate/techns/contacts.json'; const L = (await loadJson(P)) || [];
    if (L.filter(x => x.at > Date.now() - 3600e3).length > 30) return res.status(429).json({ ok: false, error: 'rate' });
    L.unshift({ id: 'W-' + Date.now().toString(36).toUpperCase(), at: Date.now(), name, firma, email, branche, groesse, msg, lang, st: 'neu' });
    await saveJson(P, L.slice(0, 500));
    return res.status(200).json({ ok: true });
  }
  if (action === 'contact_list' || action === 'contact_set') {
    const d = verifyToken(body.token);
    if (!d || d.sub !== 'master') return res.status(403).json({ ok: false, error: 'forbidden' });
    const P = 'gate/techns/contacts.json'; const L = (await loadJson(P)) || [];
    if (action === 'contact_set') { const x = L.find(v => v.id === body.id); if (x) { x.st = ['neu', 'kontaktiert', 'erledigt'].includes(body.st) ? body.st : x.st; await saveJson(P, L); } }
    return res.status(200).json({ ok: true, list: L });
  }

  if (action === 'tenant_status_list' || action === 'tenant_status_set') {
    const d = verifyToken(body.token);
    if (!d || d.sub !== 'master') return res.status(403).json({ ok: false, error: 'forbidden' });
    if (action === 'tenant_status_set') {
      const t = String(body.target || '');
      if (!TENANTS.includes(t)) return res.status(400).json({ ok: false, error: 'target' });
      await saveJson(pth(t, 'status'), { suspended: !!body.suspended, reason: String(body.reason || '').slice(0, 200), at: Date.now() });
    }
    const out = {}; for (const t of TENANTS) out[t] = (await loadJson(pth(t, 'status'))) || { suspended: false };
    return res.status(200).json({ ok: true, status: out });
  }

  if (action === 'notes_get' || action === 'notes_set') {
    const d = verifyToken(body.token);
    if (!d || d.sub !== 'master') return res.status(403).json({ ok: false, error: 'forbidden' });
    if (action === 'notes_get') {
      try { const r = await get(NOTES_PATH, { access: 'private', useCache: false }); if (!r) return res.status(200).json({ ok: true, notes: '', updated: null }); const j = JSON.parse(await new Response(r.stream).text()); return res.status(200).json({ ok: true, ...j }); }
      catch (e) { if (e && e.name === 'BlobNotFoundError') return res.status(200).json({ ok: true, notes: '', updated: null }); throw e; }
    }
    const notes = String(body.notes || '').slice(0, 50000);
    await put(NOTES_PATH, JSON.stringify({ notes, updated: Date.now() }), { access: 'private', addRandomSuffix: false, allowOverwrite: true, contentType: 'application/json' });
    return res.status(200).json({ ok: true, updated: Date.now() });
  }

  if (action === 'verify') {
    const d = scoped(verifyToken(body.token));
    if (d && (/^[tp]:/.test(String(d.sub)) || d.sub === 'hq') && await isSusp(T)) return res.status(200).json(SUSP);
    const perms = d && String(d.sub).startsWith('t:') ? await permsOf(d.sub, T) : undefined;
    if (d && String(d.sub).startsWith('t:') && perms === null) return res.status(200).json({ ok: false });
    { const mm = d && /^t:(\d+):/.exec(String(d.sub)); if (mm) { const mem = (await loadTeam(T)).find(x => x.id === Number(mm[1])); if (mem && mem.pwAt && !(d.iat >= mem.pwAt)) return res.status(200).json({ ok: false, error: 'pw_changed' }); } }
    return res.status(200).json({ ok: !!d, sub: d?.sub || null, exp: d?.exp || null, once: !!(d && d.once), perms, tenant: d ? (d.ten || (/^[tp]:/.test(String(d.sub)) ? 'aydemir' : null)) : null });
  }

  if (action === 'plogin') {
    // single partner entrance ("network"); legacy per-type doors still accepted
    const asked = String(body.door || 'network'); const user = String(body.user || '').trim().toLowerCase(); const pass = String(body.pass || '');
    if ((asked !== 'network' && !DOORS.includes(asked)) || !user || !pass) return res.status(400).json({ ok: false, error: 'empty' });
    const creds = (await loadJson(pth(T, 'creds'))) || [];
    const c = creds.find(x => x.user === user);
    if (!c || !c.active || !safeEq(c.pass, pass) || (asked !== 'network' && !c.doors.includes(asked))) return res.status(401).json({ ok: false, error: 'invalid' });
    const tc = (await loadJson(pth(T, 'tcfg'))) || tcfgDefault(T);
    const isOn = d => !(tc.types && tc.types[d] && tc.types[d].on === false);
    const door = asked === 'network' ? (c.doors.filter(d => DOORS.includes(d)).find(isOn) || null) : (isOn(asked) ? asked : null);
    if (!door) return res.status(403).json({ ok: false, error: 'door_off' });
    c.lastLogin = Date.now(); c.logins = (c.logins || 0) + 1; c.lastDoor = door;
    await saveJson(pth(T, 'creds'), creds);
    return res.status(200).json({ ok: true, token: makeToken('p:' + c.id + ':' + door, null, T), kind: 'partner', pid: c.id, door, tenant: T });
  }

  if (action === 'tenant_cfg_get') {
    const c = (await loadJson(pth(T, 'tcfg'))) || tcfgDefault(T);
    // UG-Alu booked the accounting module (10/2026)
    // prices & conditions and partner performance are on for every tenant (10/2026)
    // partner-programme, territories, customer protection, quotes, credit, returns: on for every tenant (10/2026)
    if (c.updated && !c.migF2) { for (const f of F2) if (!c.features.includes(f)) c.features.push(f); c.migF2 = true; await saveJson(pth(T, 'tcfg'), c); }
    if (c.updated && !c.migPP) { for (const f of ['pricing', 'perf']) if (!c.features.includes(f)) c.features.push(f); c.migPP = true; await saveJson(pth(T, 'tcfg'), c); }
    // Laggner: Mietkalender + Fremdanmietung als Module (10/2026)
    // Laggner: neue Vermietungsmodule je Version nur EINMAL ergänzen – abgeschaltete Module bleiben aus
    if (T === 'laggner' && c.updated && (c.migRentV || 0) < RENT_V) { for (const [v, fs] of RENT_MIG) if ((c.migRentV || 0) < v) for (const f of fs) if (!c.features.includes(f)) c.features.push(f); c.migRent = true; c.migRentV = RENT_V; await saveJson(pth(T, 'tcfg'), c); }
    if (T === 'ug-alu' && c.updated && !c.migInv) { if (!c.features.includes('invoices')) c.features.push('invoices'); c.migInv = true; await saveJson(pth(T, 'tcfg'), c); }
    return res.status(200).json({ ok: true, cfg: c, tenant: T, suspended: await isSusp(T) });
  }
  if (action === 'tenant_cfg_set') {
    const d = verifyToken(body.token);
    if (!d || d.sub !== 'master') return res.status(403).json({ ok: false, error: 'forbidden' });
    const inp = body.cfg || {};
    const features = (inp.features || []).filter(x => ADDONS.includes(x));
    const types = {};
    for (const k of PTYPES) { const t = (inp.types || {})[k] || {}; types[k] = { on: t.on !== false, label: String(t.label || '').slice(0, 30) }; }
    if (!PTYPES.some(k => types[k].on)) return res.status(400).json({ ok: false, error: 'notype' });
    const plan = PLAN_LIMITS[inp.plan] ? inp.plan : (PLAN_DEFAULT[T] || 'Starter');
    const lim = {}; for (const k of ['partners', 'users']) { const v = inp.limits && inp.limits[k]; if (v !== undefined && v !== null && v !== '') lim[k] = Math.max(0, Math.min(100000, Math.floor(+v) || 0)); }
    const cfg = { features, types, plan, ...(Object.keys(lim).length ? { limits: lim } : {}), updated: Date.now(), migInv: true, migPP: true, migF2: true, migRent: true, migRentV: RENT_V };
    await saveJson(pth(T, 'tcfg'), cfg);
    return res.status(200).json({ ok: true, cfg });
  }

  if (action === 'tlogin') {
    const user = String(body.user || '').trim().toLowerCase(); const pass = String(body.pass || '');
    if (!user || !pass) return res.status(400).json({ ok: false, error: 'empty' });
    const team = await loadTeam(T);
    const m = team.find(x => x.user === user);
    if (!m || !m.active || !safeEq(m.hash, sha(pass))) return res.status(401).json({ ok: false, error: 'invalid' });
    m.lastLogin = Date.now(); m.logins = (m.logins || 0) + 1; await saveJson(pth(T, 'team'), team);
    const roles = await loadRoles(T); const role = roles.find(x => x.key === m.role) || { name: m.role, perms: [] };
    return res.status(200).json({ ok: true, token: makeToken('t:' + m.id + ':' + m.role, null, T), kind: 'team', tenant: T, role: m.role, roleName: role.name, perms: role.perms, name: m.name, user: m.user });
  }

  if (action === 'tpass') {
    // own password: needs the current one; sessions issued before the change are ended
    const d = scoped(verifyToken(body.token));
    const mm = d && /^t:(\d+):/.exec(String(d.sub));
    if (!mm) return res.status(403).json({ ok: false, error: 'forbidden' });
    const team = await loadTeam(T); const m = team.find(x => x.id === Number(mm[1]));
    if (!m || !m.active) return res.status(403).json({ ok: false, error: 'forbidden' });
    if (m.pwAt && !(d.iat >= m.pwAt)) return res.status(403).json({ ok: false, error: 'pw_changed' });
    const old = String(body.old || ''), nw = String(body.pass || '');
    if (!safeEq(m.hash, sha(old))) return res.status(401).json({ ok: false, error: 'old' });
    if (nw.length < 10 || nw.length > 128 || !/[A-Za-zÄÖÜäöüß]/.test(nw) || !/\d/.test(nw)) return res.status(400).json({ ok: false, error: 'weak' });
    if (nw === old) return res.status(400).json({ ok: false, error: 'same' });
    m.hash = sha(nw); m.pwAt = Date.now(); await saveJson(pth(T, 'team'), team);
    return res.status(200).json({ ok: true, token: makeToken(d.sub, null, T) });
  }

  if (action && action.startsWith('team_')) {
    const d = scoped(verifyToken(body.token));
    if (!d || !((await permsOf(d.sub, T)) || []).includes('team')) return res.status(403).json({ ok: false, error: 'forbidden' });
    const team = await loadTeam(T); const roles = await loadRoles(T); const TEAMP = pth(T, 'team'), ROLESP = pth(T, 'roles'); const roleKeys = roles.map(x => x.key);
    if (action === 'team_list') return res.status(200).json({ ok: true, team: team.map(publicMember), roles, perms: PERMS });
    if (action === 'team_role_save') {
      const perms = (body.perms || []).filter(x => PERMS.includes(x)); const name = String(body.name || '').trim().slice(0, 40);
      if (!name) return res.status(400).json({ ok: false, error: 'name' });
      let r = roles.find(x => x.key === body.key);
      if (r) { if (r.locked) return res.status(400).json({ ok: false, error: 'locked' }); r.name = name; r.perms = perms; }
      else { let k = slug(name) || 'rolle'; let kk = k; let n = 2; while (roleKeys.includes(kk)) kk = k + '-' + n++; r = { key: kk, name, perms }; roles.push(r); }
      await saveJson(ROLESP, roles);
      return res.status(200).json({ ok: true, roles });
    }
    if (action === 'team_role_delete') {
      const r = roles.find(x => x.key === body.key);
      if (!r || r.builtin) return res.status(400).json({ ok: false, error: 'builtin' });
      if (team.some(x => x.role === r.key)) return res.status(400).json({ ok: false, error: 'inuse' });
      await saveJson(ROLESP, roles.filter(x => x.key !== r.key));
      return res.status(200).json({ ok: true });
    }
    if (action === 'team_add') {
      const L = limitsOf((await loadJson(pth(T, 'tcfg'))) || tcfgDefault(T), T);
      if (L.users && team.length >= L.users) return res.status(403).json({ ok: false, error: 'limit', limit: L.users, plan: L.plan });
      const role = roleKeys.includes(body.role) ? body.role : 'staff'; const name = String(body.name || '').trim().slice(0, 60) || 'Mitarbeiter';
      let u = slug(body.user || name) || 'user'; let k = u; let n = 2; while (team.some(x => x.user === k)) k = u + '-' + n++;
      const pass = genPassword(); const m = { id: Math.max(0, ...team.map(x => x.id)) + 1, name, role, user: k, hash: sha(pass), active: true, created: Date.now() };
      team.push(m); await saveJson(TEAMP, team);
      return res.status(200).json({ ok: true, member: publicMember(m), pass });
    }
    const m = team.find(x => x.id === Number(body.id));
    if (!m) return res.status(404).json({ ok: false, error: 'not found' });
    if (action === 'team_reset') { const pass = genPassword(); m.hash = sha(pass); m.pwAt = Date.now(); await saveJson(TEAMP, team); return res.status(200).json({ ok: true, member: publicMember(m), pass }); }
    if (action === 'team_toggle') { if (d.sub === 't:' + m.id + ':' + m.role) return res.status(400).json({ ok: false, error: 'self' }); m.active = !m.active; await saveJson(TEAMP, team); return res.status(200).json({ ok: true, member: publicMember(m) }); }
    if (action === 'team_role') { m.role = roleKeys.includes(body.role) ? body.role : m.role; await saveJson(TEAMP, team); return res.status(200).json({ ok: true, member: publicMember(m) }); }
    return res.status(400).json({ ok: false, error: 'unknown action' });
  }

  if (action && action.startsWith('pcreds_')) {
    const d = scoped(verifyToken(body.token));
    if (!d || !((await permsOf(d.sub, T)) || []).includes('creds')) return res.status(403).json({ ok: false, error: 'forbidden' });
    const CP = pth(T, 'creds');
    let creds = (await loadJson(CP)) || [];
    if (action === 'pcreds_sync') {
      const list = Array.isArray(body.partners) ? body.partners.slice(0, 500) : [];
      const used = new Set(creds.map(c => c.user));
      for (const p of list) {
        const id = Number(p.id); const doors = (p.doors || []).filter(x => DOORS.includes(x));
        let c = creds.find(x => x.id === id);
        if (!c) {
          let u = slug(p.name) || 'partner' + id; let k = u; let n = 2; while (used.has(k)) k = u + '-' + n++; used.add(k);
          creds.push({ id, name: String(p.name).slice(0, 80), doors, user: k, pass: genPassword(), active: true, created: Date.now() });
        } else { c.name = String(p.name).slice(0, 80); c.doors = doors; }
      }
      await saveJson(CP, creds);
      return res.status(200).json({ ok: true, creds: creds.map(publicCred) });
    }
    const c = creds.find(x => x.id === Number(body.id));
    if (!c) return res.status(404).json({ ok: false, error: 'not found' });
    if (action === 'pcreds_reset') c.pass = genPassword();
    else if (action === 'pcreds_toggle') c.active = !c.active;
    else return res.status(400).json({ ok: false, error: 'unknown action' });
    await saveJson(CP, creds);
    return res.status(200).json({ ok: true, cred: publicCred(c) });
  }

  if (action === 'login') {
    const code = String(body.code || '').trim();
    if (!code) return res.status(400).json({ ok: false, error: 'empty' });
    if (MASTER_HASH && safeEq(sha(code), MASTER_HASH)) {
      return res.status(200).json({ ok: true, token: makeToken('master'), kind: 'master' });
    }
    if (HQ_HASH && safeEq(sha(code), HQ_HASH)) {
      if (await isSusp('aydemir')) return res.status(403).json(SUSP);
      return res.status(200).json({ ok: true, token: makeToken('hq'), kind: 'hq' });
    }
    const norm = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    const codes = await loadCodes();
    const now = Date.now();
    const hit = codes.find(c => !c.usedAt && c.expires > now && safeEq(c.hash, sha(norm)));
    if (!hit) return res.status(401).json({ ok: false, error: 'invalid' });
    const tg = hit.target || null;
    const area = String(body.area || '');
    if (tg) {
      // bound code: only at its own company and entrance; a wrong entrance does not burn it
      const want = tg.area === 'partner' ? 'network' : 'staff';
      if (tg.tenant !== T || (area && area !== want)) return res.status(409).json({ ok: false, error: 'wrong_place', tenant: tg.tenant, area: tg.area });
      if (await isSusp(T)) return res.status(403).json(SUSP);
    }
    hit.usedAt = now;
    hit.usedUa = String(req.headers['user-agent'] || '').slice(0, 120);
    await saveCodes(codes);
    if (tg && tg.area === 'team') {
      const roles = await loadRoles(T); const role = roles.find(x => x.key === tg.role) || { key: tg.role, name: tg.role, perms: [] };
      return res.status(200).json({ ok: true, token: makeToken('t:' + hit.id + ':' + role.key, hit.expires, T, { once: 1 }), kind: 'team', tenant: T, role: role.key, roleName: role.name, perms: role.perms, name: hit.label || 'Gast', user: 'code', exp: hit.expires });
    }
    if (tg && tg.area === 'partner') {
      return res.status(200).json({ ok: true, token: makeToken('p:' + tg.pid + ':' + tg.door, hit.expires, T, { once: 1 }), kind: 'partner', tenant: T, pid: tg.pid, door: tg.door, exp: hit.expires });
    }
    return res.status(200).json({ ok: true, token: makeToken(hit.id, hit.expires), kind: 'once', label: hit.label, exp: hit.expires });
  }

  // admin actions
  if (!ADMIN_SECRET || !safeEq(String(body.admin || ''), ADMIN_SECRET)) {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  const codes = await loadCodes();

  if (action === 'create') {
    const ttl = Math.min(Math.max(Number(body.ttlHours) || 48, 0.25), 24 * 30);
    const code = genCode();
    const t0 = body.target || {};
    if (!TENANTS.includes(t0.tenant) || !['team', 'partner'].includes(t0.area)) return res.status(400).json({ ok: false, error: 'target' });
    const target = t0.area === 'team'
      ? { tenant: t0.tenant, area: 'team', role: String(t0.role || '').replace(/[^a-z0-9-]/g, '').slice(0, 30) || 'staff', roleName: String(t0.roleName || '').slice(0, 60) }
      : { tenant: t0.tenant, area: 'partner', pid: Number(t0.pid) || 0, door: PTYPES.includes(t0.door) ? t0.door : 'partner', pname: String(t0.pname || '').slice(0, 80) };
    if (target.area === 'partner' && !target.pid) return res.status(400).json({ ok: false, error: 'target' });
    const entry = { id: 'c_' + Date.now().toString(36) + randomInt(1e6).toString(36), label: String(body.label || '').slice(0, 80), target, hash: sha(code.replace(/-/g, '')), created: Date.now(), expires: Date.now() + ttl * 3600e3, usedAt: null };
    codes.unshift(entry);
    await saveCodes(codes.slice(0, 500));
    return res.status(200).json({ ok: true, code, id: entry.id, expires: entry.expires, label: entry.label, target });
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
