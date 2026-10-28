// Image pass-through for tenant demo sites (customer-approved images only).
// GET /api/img?u=<absolute image URL on an allow-listed customer host>
const ALLOW = ['static.ug-alu.de', 'www.ug-alu.de', 'images.ug-alu.de'];
const EXT = /\.(jpe?g|png|webp|avif)$/i;

export default async function handler(req, res) {
  try {
    const raw = String((req.query && req.query.u) || '');
    let url;
    try { url = new URL(raw); } catch { return res.status(400).end('bad url'); }
    if (url.protocol !== 'https:' || !ALLOW.includes(url.hostname) || !EXT.test(url.pathname)) return res.status(403).end('forbidden');
    const r = await fetch(url.href, { redirect: 'error', headers: { 'user-agent': 'B2B-Easy-Demo/1.0' } });
    if (!r.ok) return res.status(r.status).end('upstream ' + r.status);
    const type = r.headers.get('content-type') || 'image/jpeg';
    if (!type.startsWith('image/')) return res.status(415).end('not an image');
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > 6 * 1024 * 1024) return res.status(413).end('too large');
    res.setHeader('Content-Type', type);
    res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=604800, stale-while-revalidate=86400');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    return res.status(200).send(buf);
  } catch (e) {
    return res.status(502).end('error');
  }
}
