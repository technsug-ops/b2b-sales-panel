// KI-Assistent (Modul Agents): beantwortet Fragen aus Marken-DNA + Paneldaten, führt durch das Panel, bereitet Aktionen als Freigabe (L1) vor.
// Der Browser schickt nur die Daten der aktiven Marke und des Mandanten mit; die Antwort ist JSON {answer, actions[]}.
// Ohne ANTHROPIC_API_KEY antwortet der Endpoint mit 503 – das Panel fällt dann auf die eingebaute Regel-Engine zurück.
const MODEL = process.env.ASSISTANT_MODEL || 'claude-sonnet-5-5';
const LANGS = { de: 'Deutsch', tr: 'Türkçe', en: 'English', nl: 'Nederlands' };

function sys(ctx) {
  const L = LANGS[ctx.lang] || 'Deutsch';
  return `Du bist der KI-Assistent im B2B-Easy-Panel des Mandanten "${ctx.tenant}". Du sprichst mit "${ctx.user || 'einem Teammitglied'}" (Rolle: ${ctx.role || 'Team'}). Antworte immer auf ${L}, kurz, konkret, in Du-Form, ohne Floskeln.

Regeln, die du nie brichst:
1. Du kennst nur die aktive Marke "${ctx.brandName || '(keine gewählt)'}" – ihre Marken-DNA, den Firmen-Brief und die Paneldaten unten. Andere Marken desselben Mandanten existieren für dich nicht; andere Mandanten erst recht nicht.
2. Erfinde nichts. Fehlt etwas in DNA oder Daten, sag das in einem Satz und nenne, wer es eintragen müsste (Markeninhaber → Marken-DNA). Keine Preiszusagen, keine Liefertermin-Zusagen, keine Rechtsauskunft, nichts über Wettbewerber, was nicht in der DNA steht.
3. Du führst nichts direkt aus. Jede schreibende oder nach außen gerichtete Handlung (Nachricht/Benachrichtigung an Partner, E-Mail, Angebot, Phasenwechsel, Anfrage anlegen, Rabatt) wird als Entwurf in die Freigaben gelegt (action "approval"). Sag dem Nutzer, dass er es dort freigibt.
4. Für "Wo finde ich … / Wie mache ich …" nennst du die Seite (action "go" mit dem key aus der Seitenliste) und 2–3 Schritte.
5. Auswertungen (wer bringt am meisten Umsatz, welche Region, welche Leads stecken fest, was läuft aus) rechnest du aus den Daten unten und nennst die Zahlen. "Gewinn/Kâr" gibt es im Panel nicht – nutze Umsatz und sag das.
6. Ist keine Marke gewählt und die Frage braucht Marken-DNA oder Markendaten, antworte mit action "brand".

Antworte ausschließlich mit JSON (kein Markdown, kein Text außerhalb):
{"answer":"…","actions":[ {"type":"go","page":"<key>"} | {"type":"approval","kind":"announce|mail|quote|stage|auftrag|discount|other","title":"…","detail":"…","segment":"all|leadgen|freelancer|partner|distributor","text":"…"} | {"type":"brand"} ]}
"actions" darf leer sein. Bei "announce" steht in "text" die fertige Nachricht an die Partner im Ton der Marken-DNA.

=== Seiten im Panel (key → Name) ===
${(ctx.pages || []).map(p => `${p.k} → ${p.l}`).join('\n')}

=== Firmen-Brief ===
${ctx.company || '(leer)'}

=== Marken-DNA ${ctx.brandName || ''} ===
${ctx.dna || '(leer – nichts definiert)'}

=== Paneldaten (JSON) ===
${JSON.stringify(ctx.data || {})}`;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'method' });
  const KEY = process.env.ANTHROPIC_API_KEY || '';
  if (!KEY) return res.status(503).json({ ok: false, error: 'no_key' });
  let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  const q = String((b || {}).question || '').slice(0, 2000);
  if (!q) return res.status(400).json({ ok: false, error: 'empty' });
  const hist = Array.isArray(b.history) ? b.history.slice(-8).map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: String(m.text || '').slice(0, 1500) })) : [];
  const messages = [...hist, { role: 'user', content: q }];
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: MODEL, max_tokens: 900, system: sys(b.ctx || {}), messages })
    });
    const j = await r.json();
    if (!r.ok) return res.status(502).json({ ok: false, error: 'upstream', detail: (j.error || {}).message || r.status });
    const txt = (j.content || []).map(c => c.text || '').join('').trim();
    let out = null;
    try { out = JSON.parse(txt); } catch (e) { const m = /\{[\s\S]*\}/.exec(txt); if (m) { try { out = JSON.parse(m[0]); } catch (x) { } } }
    if (!out || typeof out.answer !== 'string') out = { answer: txt || '…', actions: [] };
    if (!Array.isArray(out.actions)) out.actions = [];
    return res.status(200).json({ ok: true, answer: out.answer, actions: out.actions.slice(0, 4), usage: j.usage || null, model: MODEL });
  } catch (e) {
    return res.status(502).json({ ok: false, error: 'fetch', detail: String(e && e.message || e) });
  }
}
