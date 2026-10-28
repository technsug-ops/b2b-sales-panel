// Access gate for the B2B Sales Panel demo.
// POST /api/gate  { action: "login", code }                 -> { ok, token }
// POST /api/gate  { action: "verify", token }               -> { ok }
// POST /api/gate  { action: "create", admin, label, ttlHours } -> { ok, code, expires }
// POST /api/gate  { action: "list", admin }                 -> { ok, codes: [...] }
// POST /api/gate  { action: "revoke", admin, id }           -> { ok }
// POST /api/gate  { action: "plogin", door:"network", user, pass } -> partner login (type from account)
// POST /api/gate  { action: "pcreds_sync|pcreds_reset|pcreds_toggle", token(hq) } -> partner credentials (Firmenzentrale only)
//
// Master code: permanent, SHA-256 compared against GATE_MASTER_HASH.
// One-time codes: stored in Vercel Blob (codes.json); burned on first successful login.

import { put, get } from '@vercel/blob';
import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';

const BLOB_PATH = 'gate/codes.json';
const NOTES_PATH = 'gate/notes.json';
const CREDS_PATH = 'gate/partners.json';
const HQ_HASH = process.env.GATE_HQ_HASH || '';
const DOORS = ['partner', 'freelancer', 'leadgen', 'distributor'];
const TEAM_PATH = 'gate/team.json';
const TCFG_PATH = 'gate/tenant-t1.json';
const ADDONS = ['orders', 'stock', 'install', 'projects', 'sites', 'hr'];
const PTYPES = ['leadgen', 'freelancer', 'partner', 'distributor'];
const DEFAULT_TCFG = { features: ADDONS.slice(), types: { leadgen: { on: true, label: '' }, freelancer: { on: true, label: '' }, partner: { on: true, label: '' }, distributor: { on: true, label: '' } } };
const ROLES_PATH = 'gate/roles.json';
const PERMS = ['partners', 'leads', 'projects', 'orders', 'dam', 'settings', 'hr', 'creds', 'team'];
const BUILTIN_ROLES = [
  { key: 'gf', name: 'Geschäftsführer', perms: PERMS.slice(), builtin: true, locked: true },
  { key: 'tech', name: 'Technik-Verantwortlicher', perms: ['partners', 'leads', 'projects', 'orders', 'dam', 'settings', 'creds'], builtin: true },
  { key: 'staff', name: 'Verwaltung', perms: ['partners', 'leads', 'projects', 'orders', 'dam'], builtin: true },
  { key: 'mitarbeiter', name: 'Mitarbeiter (nur Mein Bereich)', perms: [], builtin: true },
];
async function loadRoles() {
  let r = await loadJson(ROLES_PATH);
  if (!r) { r = BUILTIN_ROLES.map(x => ({ ...x })); await saveJson(ROLES_PATH, r); }
  let changed = false;
  if (!r.some(x => x.key === 'mitarbeiter')) { r.push({ ...BUILTIN_ROLES[3] }); changed = true; }
  for (const x of r) { if (x.key === 'gf' && x.perms.length !== PERMS.length) { x.perms = PERMS.slice(); changed = true; } if (x.builtin && !x.migratedProjects) { if (!x.perms.includes('projects')) x.perms.push('projects'); x.migratedProjects = true; changed = true; } }
  if (changed) await saveJson(ROLES_PATH, r);
  return r;
}
async function permsOf(sub) {
  if (sub === 'hq') return PERMS.slice();
  const m = /^t:(\d+):([a-z0-9-]+)$/.exec(String(sub || ''));
  if (!m) return null;
  const team = await loadTeam(); const mem = team.find(x => x.id === Number(m[1]));
  if (!mem || !mem.active) return null;
  const roles = await loadRoles(); const role = roles.find(x => x.key === mem.role);
  return role ? role.perms : [];
}
const SEED_TEAM = [
  { id: 1, name: 'Geschäftsführung', role: 'gf', user: 'geschaeftsfuehrung', pass: 'Aydemir-GF-2026' },
  { id: 2, name: 'Technik-Verantwortlicher', role: 'tech', user: 'technik', pass: 'Aydemir-Tech-2026' },
  { id: 3, name: 'Verwaltung', role: 'staff', user: 'verwaltung', pass: 'Aydemir-Team-2026' },
  { id: 4, name: 'Mehmet K.', role: 'mitarbeiter', user: 'mehmet', pass: 'Aydemir-Mont-2026' },
];
async function loadTeam() {
  let t = await loadJson(TEAM_PATH);
  if (!t) { t = SEED_TEAM.map(x => ({ id: x.id, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() })); await saveJson(TEAM_PATH, t); }
  if (!t.some(x => x.user === 'mehmet')) { const x = SEED_TEAM[3]; t.push({ id: Math.max(0, ...t.map(m => m.id)) + 1, name: x.name, role: x.role, user: x.user, hash: sha(x.pass), active: true, created: Date.now() }); await saveJson(TEAM_PATH, t); }
  return t;
}
const publicMember = m => ({ id: m.id, name: m.name, role: m.role, user: m.user, active: m.active, created: m.created, lastLogin: m.lastLogin || null, logins: m.logins || 0 });
// who may manage partner credentials: Geschäftsführung + Technik

const MASTER_HASH = process.env.GATE_MASTER_HASH || '';
const ADMIN_SECRET = process.env.GATE_ADMIN_SECRET || '';
const SESSION_HOURS = 12;

const sha = s => createHash('sha256').update(String(s)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

function makeToken(sub, expCap) {
  let exp = Date.now() + SESSION_HOURS * 3600e3;
  if (expCap && expCap < exp) exp = expCap;
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
    const d = verifyToken(body.token);
    const perms = d && String(d.sub).startsWith('t:') ? await permsOf(d.sub) : undefined;
    if (d && String(d.sub).startsWith('t:') && perms === null) return res.status(200).json({ ok: false });
    return res.status(200).json({ ok: !!d, sub: d?.sub || null, exp: d?.exp || null, perms });
  }

  if (action === 'plogin') {
    // single partner entrance ("network"); legacy per-type doors still accepted
    const asked = String(body.door || 'network'); const user = String(body.user || '').trim().toLowerCase(); const pass = String(body.pass || '');
    if ((asked !== 'network' && !DOORS.includes(asked)) || !user || !pass) return res.status(400).json({ ok: false, error: 'empty' });
    const creds = (await loadJson(CREDS_PATH)) || [];
    const c = creds.find(x => x.user === user);
    if (!c || !c.active || !safeEq(c.pass, pass) || (asked !== 'network' && !c.doors.includes(asked))) return res.status(401).json({ ok: false, error: 'invalid' });
    const tc = (await loadJson(TCFG_PATH)) || DEFAULT_TCFG;
    const isOn = d => !(tc.types && tc.types[d] && tc.types[d].on === false);
    const door = asked === 'network' ? (c.doors.filter(d => DOORS.includes(d)).find(isOn) || null) : (isOn(asked) ? asked : null);
    if (!door) return res.status(403).json({ ok: false, error: 'door_off' });
    c.lastLogin = Date.now(); c.logins = (c.logins || 0) + 1; c.lastDoor = door;
    await saveJson(CREDS_PATH, creds);
    return res.status(200).json({ ok: true, token: makeToken('p:' + c.id + ':' + door), kind: 'partner', pid: c.id, door });
  }

  if (action === 'tenant_cfg_get') {
    const c = (await loadJson(TCFG_PATH)) || DEFAULT_TCFG;
    return res.status(200).json({ ok: true, cfg: c });
  }
  if (action === 'tenant_cfg_set') {
    const d = verifyToken(body.token);
    if (!d || d.sub !== 'master') return res.status(403).json({ ok: false, error: 'forbidden' });
    const inp = body.cfg || {};
    const features = (inp.features || []).filter(x => ADDONS.includes(x));
    const types = {};
    for (const k of PTYPES) { const t = (inp.types || {})[k] || {}; types[k] = { on: t.on !== false, label: String(t.label || '').slice(0, 30) }; }
    if (!PTYPES.some(k => types[k].on)) return res.status(400).json({ ok: false, error: 'notype' });
    const cfg = { features, types, updated: Date.now() };
    await saveJson(TCFG_PATH, cfg);
    return res.status(200).json({ ok: true, cfg });
  }

  if (action === 'tlogin') {
    const user = String(body.user || '').trim().toLowerCase(); const pass = String(body.pass || '');
    if (!user || !pass) return res.status(400).json({ ok: false, error: 'empty' });
    const team = await loadTeam();
    const m = team.find(x => x.user === user);
    if (!m || !m.active || !safeEq(m.hash, sha(pass))) return res.status(401).json({ ok: false, error: 'invalid' });
    m.lastLogin = Date.now(); m.logins = (m.logins || 0) + 1; await saveJson(TEAM_PATH, team);
    const roles = await loadRoles(); const role = roles.find(x => x.key === m.role) || { name: m.role, perms: [] };
    return res.status(200).json({ ok: true, token: makeToken('t:' + m.id + ':' + m.role), kind: 'team', role: m.role, roleName: role.name, perms: role.perms, name: m.name, user: m.user });
  }

  if (action && action.startsWith('team_')) {
    const d = verifyToken(body.token);
    if (!d || !((await permsOf(d.sub)) || []).includes('team')) return res.status(403).json({ ok: false, error: 'forbidden' });
    const team = await loadTeam(); const roles = await loadRoles(); const roleKeys = roles.map(x => x.key);
    if (action === 'team_list') return res.status(200).json({ ok: true, team: team.map(publicMember), roles, perms: PERMS });
    if (action === 'team_role_save') {
      const perms = (body.perms || []).filter(x => PERMS.includes(x)); const name = String(body.name || '').trim().slice(0, 40);
      if (!name) return res.status(400).json({ ok: false, error: 'name' });
      let r = roles.find(x => x.key === body.key);
      if (r) { if (r.locked) return res.status(400).json({ ok: false, error: 'locked' }); r.name = name; r.perms = perms; }
      else { let k = slug(name) || 'rolle'; let kk = k; let n = 2; while (roleKeys.includes(kk)) kk = k + '-' + n++; r = { key: kk, name, perms }; roles.push(r); }
      await saveJson(ROLES_PATH, roles);
      return res.status(200).json({ ok: true, roles });
    }
    if (action === 'team_role_delete') {
      const r = roles.find(x => x.key === body.key);
      if (!r || r.builtin) return res.status(400).json({ ok: false, error: 'builtin' });
      if (team.some(x => x.role === r.key)) return res.status(400).json({ ok: false, error: 'inuse' });
      await saveJson(ROLES_PATH, roles.filter(x => x.key !== r.key));
      return res.status(200).json({ ok: true });
    }
    if (action === 'team_add') {
      const role = roleKeys.includes(body.role) ? body.role : 'staff'; const name = String(body.name || '').trim().slice(0, 60) || 'Mitarbeiter';
      let u = slug(body.user || name) || 'user'; let k = u; let n = 2; while (team.some(x => x.user === k)) k = u + '-' + n++;
      const pass = genPassword(); const m = { id: Math.max(0, ...team.map(x => x.id)) + 1, name, role, user: k, hash: sha(pass), active: true, created: Date.now() };
      team.push(m); await saveJson(TEAM_PATH, team);
      return res.status(200).json({ ok: true, member: publicMember(m), pass });
    }
    const m = team.find(x => x.id === Number(body.id));
    if (!m) return res.status(404).json({ ok: false, error: 'not found' });
    if (action === 'team_reset') { const pass = genPassword(); m.hash = sha(pass); await saveJson(TEAM_PATH, team); return res.status(200).json({ ok: true, member: publicMember(m), pass }); }
    if (action === 'team_toggle') { if (d.sub === 't:' + m.id + ':' + m.role) return res.status(400).json({ ok: false, error: 'self' }); m.active = !m.active; await saveJson(TEAM_PATH, team); return res.status(200).json({ ok: true, member: publicMember(m) }); }
    if (action === 'team_role') { m.role = roleKeys.includes(body.role) ? body.role : m.role; await saveJson(TEAM_PATH, team); return res.status(200).json({ ok: true, member: publicMember(m) }); }
    return res.status(400).json({ ok: false, error: 'unknown action' });
  }

  if (action && action.startsWith('pcreds_')) {
    const d = verifyToken(body.token);
    if (!d || !((await permsOf(d.sub)) || []).includes('creds')) return res.status(403).json({ ok: false, error: 'forbidden' });
    let creds = (await loadJson(CREDS_PATH)) || [];
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
      await saveJson(CREDS_PATH, creds);
      return res.status(200).json({ ok: true, creds: creds.map(publicCred) });
    }
    const c = creds.find(x => x.id === Number(body.id));
    if (!c) return res.status(404).json({ ok: false, error: 'not found' });
    if (action === 'pcreds_reset') c.pass = genPassword();
    else if (action === 'pcreds_toggle') c.active = !c.active;
    else return res.status(400).json({ ok: false, error: 'unknown action' });
    await saveJson(CREDS_PATH, creds);
    return res.status(200).json({ ok: true, cred: publicCred(c) });
  }

  if (action === 'login') {
    const code = String(body.code || '').trim();
    if (!code) return res.status(400).json({ ok: false, error: 'empty' });
    if (MASTER_HASH && safeEq(sha(code), MASTER_HASH)) {
      return res.status(200).json({ ok: true, token: makeToken('master'), kind: 'master' });
    }
    if (HQ_HASH && safeEq(sha(code), HQ_HASH)) {
      return res.status(200).json({ ok: true, token: makeToken('hq'), kind: 'hq' });
    }
    const norm = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    const codes = await loadCodes();
    const now = Date.now();
    const hit = codes.find(c => !c.usedAt && c.expires > now && safeEq(c.hash, sha(norm)));
    if (!hit) return res.status(401).json({ ok: false, error: 'invalid' });
    hit.usedAt = now;
    hit.usedUa = String(req.headers['user-agent'] || '').slice(0, 120);
    await saveCodes(codes);
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
