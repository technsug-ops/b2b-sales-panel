/* Mietkalender (Demo): Gerätetyp + Stunden = Preis, Lieferung/Abholung durch Fahrer mit Disposition.
   Daten: window.MK (Typen, Depots, Fahrer) aus build.py. Buchungen: Demo-Seed + localStorage (nur dieser Browser). */
(function () {
  'use strict';
  var MK = window.MK; if (!MK) return;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var H = 3600e3, MIN = 60e3, DAY = 24 * H;
  var DAY_FROM = 6, DAY_TO = 20;            // sichtbarer Tagesbereich im Kalender
  var DRV_FROM = 6, DRV_TO = 19;            // Arbeitszeit Fahrer
  var CHECK = 30 * MIN;                     // Prüfung/Reinigung nach Rückkehr
  var UNLOAD = 30 * MIN, LOAD = 20 * MIN;   // Abladen + Einweisung / Aufladen
  var esc = function (s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var eur = function (n) { return (Math.round(n * 100) / 100).toLocaleString('de-DE', { minimumFractionDigits: 0, maximumFractionDigits: 2 }) + ' €'; };
  var pad = function (n) { return (n < 10 ? '0' : '') + n; };
  var hm = function (t) { var d = new Date(t); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  var WD = ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'];
  var dlab = function (t) { var d = new Date(t); return WD[d.getDay()] + ' ' + pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.'; };
  var dayStart = function (t) { var d = new Date(t); d.setHours(0, 0, 0, 0); return d.getTime(); };
  var at = function (day, h) { return dayStart(day) + h * H; };
  var monday = function (t) { var d = new Date(dayStart(t)); var w = (d.getDay() + 6) % 7; return d.getTime() - w * DAY; };
  var overlap = function (a1, a2, b1, b2) { return a1 < b2 && b1 < a2; };
  /* Planungswoche: ab Samstag zählt schon die Folgewoche */
  var nextWork = function () { var t = Date.now() + DAY; while (new Date(t).getDay() === 0) t += DAY; return t; };
  var BASE = (function () { var d = new Date().getDay(); return monday(d === 6 || d === 0 ? Date.now() + 2 * DAY : Date.now()); })();

  var TYPES = MK.types, TYPE = {}; TYPES.forEach(function (t) { TYPE[t.id] = t; });
  var UNITS = []; TYPES.forEach(function (t) { t.units.forEach(function (u) { UNITS.push({ id: u.id, type: t.id, depot: u.depot }); }); });
  var DEPOT = {}; MK.depots.forEach(function (d) { DEPOT[d.id] = d; });
  var DRIVERS = MK.drivers;

  /* ---------- Entfernung nach PLZ-Region (Schwerpunkt der 2-stelligen PLZ-Region, Luftlinie × 1,3 – Demo-Näherung) */
  function km(plz, depotId) {
    plz = String(plz || '').replace(/\D/g, '');
    if (plz.length !== 5) return null;
    var c = MK.plz3[plz.slice(0, 3)] || MK.plz2[plz.slice(0, 2)] || MK.plz1[plz[0]], d = DEPOT[depotId];
    var R = 6371, toR = Math.PI / 180, dLa = (c[0] - d.lat) * toR, dLo = (c[1] - d.lon) * toR;
    var a = Math.sin(dLa / 2) * Math.sin(dLa / 2) + Math.cos(d.lat * toR) * Math.cos(c[0] * toR) * Math.sin(dLo / 2) * Math.sin(dLo / 2);
    return Math.max(5, Math.round(2 * R * Math.asin(Math.sqrt(a)) * 1.3));
  }
  function zoneOf(k) { return k == null ? null : MK.zones.filter(function (z) { return k <= z.km; })[0] || MK.zones[MK.zones.length - 1]; }
  function driveMin(k) { return Math.max(20, Math.round(k / 60 * 60 / 5) * 5); }
  /* Einheiten des Typs nach Entfernung zur Baustelle sortiert */
  function unitsByDistance(typeId, plz) {
    return UNITS.filter(function (u) { return u.type === typeId; }).map(function (u) { var k = km(plz, u.depot); return { u: u, km: k, z: zoneOf(k) }; })
      .sort(function (a, b) { return (a.km == null ? 1e9 : a.km) - (b.km == null ? 1e9 : b.km); });
  }

  /* ---------- Preis */
  function price(typeId, start, end, mode, z) {
    var t = TYPE[typeId], r = t.rate, lines = [], hours = (end - start) / H;
    if (!(hours > 0)) return null;
    var miete = 0, label = '';
    if (dayStart(start) === dayStart(end - 1)) {
      var h = Math.max(2, Math.ceil(hours * 2) / 2), opts = [['Stundentarif ' + String(h).replace('.', ',') + ' h × ' + eur(r.std), h * r.std]];
      if (hours <= 5) opts.push(['Halbtagestarif (bis 5 h)', r.halb]);
      opts.push(['Tagestarif', r.tag]);
      opts.sort(function (a, b) { return a[1] - b[1]; }); label = opts[0][0]; miete = opts[0][1];
    } else {
      var days = 0, sun = 0;
      for (var d = dayStart(start); d < end; d += DAY) { if (new Date(d).getDay() === 0) sun++; else days++; }
      var wk = Math.floor(days / 6), rest = days - wk * 6;
      miete = wk * r.woche + Math.min(rest * r.tag, rest ? r.woche : 0);
      label = (wk ? wk + ' × Wochentarif' + (rest ? ' + ' : '') : '') + (rest ? rest + ' × Tagestarif' : '') + (sun ? ' (Sonntag frei)' : '');
    }
    lines.push([t.name + ' – ' + label, miete]);
    if (mode === 'bediener') {
      var bh = 0;
      for (var d2 = dayStart(start); d2 < end; d2 += DAY) { if (new Date(d2).getDay() === 0) continue; var a = Math.max(start, d2), b = Math.min(end, d2 + DAY); bh += Math.min(9, Math.max(0, (b - a) / H)); }
      bh = Math.max(4, Math.ceil(bh * 2) / 2);
      lines.push(['Bediener ' + String(bh).replace('.', ',') + ' h × ' + eur(MK.bediener), bh * MK.bediener]);
    }
    if (mode !== 'abhol' && t.transport !== 'selbst') {
      if (!z) lines.push(['Transport – bitte PLZ angeben', 0]);
      else if (z.n === 4) lines.push(['Transport Fernzone – Preis nach Entfernung im Angebot', 0]);
      else { var f = t.transport === 'tief' ? z.tief : z.anh; lines.push(['Lieferung + Abholung ' + z.name + ' (2 × ' + eur(f) + ')', 2 * f]); }
    } else if (t.transport === 'selbst' && mode !== 'abhol' && z) {
      lines.push(['Überführung ' + (mode === 'bediener' ? 'durch Bediener' : 'durch Fahrer') + ' (' + z.name + ')', z.n === 4 ? 0 : 2 * z.anh]);
    }
    lines.push(['Haftungsbeschränkung (8 %)', Math.round(miete * 0.08)]);
    var sum = lines.reduce(function (s, l) { return s + l[1]; }, 0);
    return { lines: lines, net: sum, vat: sum * 0.19, gross: sum * 1.19 };
  }

  /* ---------- Buchungen + Planung */
  var KEY = 'laggner-mietkalender-v1';
  var BOOK = [];
  function freeUnit(typeId, a, b, ignore, only) {
    var us = UNITS.filter(function (u) { return u.type === typeId && (!only || u.id === only); });
    for (var i = 0; i < us.length; i++) {
      var busy = BOOK.some(function (k) { return k.unit === us[i].id && k !== ignore && overlap(a, b, k.mA, k.mB); });
      if (!busy) return us[i];
    }
    return null;
  }
  function freeDriver(cls, a, b) {
    for (var i = 0; i < DRIVERS.length; i++) {
      var d = DRIVERS[i];
      if (cls === 'tief' && d.cls !== 'tief') continue;
      var busy = BOOK.some(function (k) { return (k.dDel === d.id && overlap(a, b, k.delA, k.delB)) || (k.dPick === d.id && overlap(a, b, k.pickA, k.pickB)); });
      if (!busy) return d;
    }
    return null;
  }
  function inShift(a, b) { var d = dayStart(a); return new Date(a).getDay() !== 0 && a >= d + DRV_FROM * H && b <= d + DRV_TO * H; }
  /* Liefer-/Abholfenster suchen: möglichst knapp vor Mietbeginn bzw. ab Mietende, sonst Vortag-Abend/Folgetag-Morgen */
  function planDelivery(cls, start, drive) {
    var dur = 2 * drive + UNLOAD;
    for (var arrive = start; arrive > start - 3 * DAY; arrive -= 30 * MIN) {
      var a = arrive - drive - UNLOAD, b = a + dur;
      if (!inShift(a, b) || (!SEEDING && a < Date.now())) continue;
      var d = freeDriver(cls, a, b); if (d) return { a: a, b: b, arrive: arrive - UNLOAD, driver: d, early: dayStart(arrive) !== dayStart(start) };
    }
    return null;
  }
  function planPickup(cls, end, drive) {
    var dur = 2 * drive + LOAD;
    for (var arrive = end; arrive < end + 3 * DAY; arrive += 30 * MIN) {
      var a = arrive - drive, b = a + dur;
      if (!inShift(a, b)) continue;
      var d = freeDriver(cls, a, b); if (d) return { a: a, b: b, arrive: arrive, driver: d, late: dayStart(arrive) !== dayStart(end) };
    }
    return null;
  }
  var SEEDING = false;
  function plan(req) {
    var t = TYPE[req.type], res = { ok: false, req: req };
    if (!(req.end > req.start)) { res.err = 'Mietende muss nach Mietbeginn liegen.'; return res; }
    if (!SEEDING && req.start < Date.now()) { res.err = 'Mietbeginn liegt in der Vergangenheit.'; return res; }
    var plzOk = String(req.plz || '').replace(/\D/g, '').length === 5;
    if (!plzOk && req.mode !== 'abhol') { res.err = 'Bitte gültige Postleitzahl (5-stellig) angeben.'; return res; }
    var needDriver = req.mode !== 'abhol', cls = t.transport === 'tief' ? 'tief' : 'anh', why = '';
    var cands = unitsByDistance(req.type, req.plz);
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i], z = c.z, drive = c.km != null ? driveMin(c.km) * MIN : 0, del = null, pick = null;
      if (needDriver && z && z.n === 4) { why = 'Fernzone (' + c.km + ' km): Lieferung als Tieflader-Tour nach Absprache – bitte Mietanfrage stellen.'; continue; }
      if (req.mode === 'bediener') {
        var d = freeDriver('anh', req.start - drive - UNLOAD, req.end + drive);
        if (!d || !inShift(req.start - drive - UNLOAD, req.start) ) { why = d ? 'Bediener-Einsätze beginnen frühestens ' + (DRV_FROM) + ':00 Uhr ab Niederlassung.' : 'Kein Bediener im gewünschten Zeitraum frei.'; continue; }
        del = { a: req.start - drive - UNLOAD, b: req.start, arrive: req.start - UNLOAD, driver: d }; pick = { a: req.end, b: req.end + drive, arrive: req.end, driver: d };
      } else if (needDriver) {
        del = planDelivery(t.transport === 'selbst' ? 'anh' : cls, req.start, drive); pick = planPickup(t.transport === 'selbst' ? 'anh' : cls, req.end, drive);
        if (!del || !pick) { why = 'Kein Fahrer mit passendem Fahrzeug (' + (cls === 'tief' ? 'Tieflader' : 'Transporter/Anhänger') + ') frei.'; continue; }
        if (!SEEDING && del.a < Date.now()) { why = 'Lieferung bis zum gewünschten Mietbeginn nicht mehr möglich.'; continue; }
      }
      var mA = needDriver ? del.a : req.start - 30 * MIN, mB = (needDriver ? pick.b : req.end + 30 * MIN) + CHECK;
      if (!freeUnit(req.type, mA, mB, null, c.u.id)) { why = why || 'Kein ' + t.name + ' in diesem Zeitraum frei.'; continue; }
      res.ok = true; res.unit = c.u; res.mA = mA; res.mB = mB; res.del = del; res.pick = pick; res.drive = drive; res.km = c.km; res.zone = z; res.depot = c.u.depot;
      res.price = price(req.type, req.start, req.end, req.mode, needDriver ? z : null);
      return res;
    }
    res.err = why || 'Kein ' + t.name + ' in diesem Zeitraum frei.'; return res;
  }
  function commit(p, kunde, seed) {
    var k = { id: (seed ? 'S' : 'W') + '-' + (5200 + BOOK.length), type: p.req.type, unit: p.unit.id, kunde: kunde, plz: p.req.plz, mode: p.req.mode,
      start: p.req.start, end: p.req.end, mA: p.mA, mB: p.mB, net: p.price ? p.price.net : 0, seed: !!seed };
    if (p.del) { k.dDel = p.del.driver.id; k.delA = p.del.a; k.delB = p.del.b; k.arrive = p.del.arrive; }
    if (p.pick) { k.dPick = p.pick.driver.id; k.pickA = p.pick.a; k.pickB = p.pick.b; k.pickArrive = p.pick.arrive; }
    BOOK.push(k); return k;
  }
  function suggest(req) {
    var out = [];
    for (var s = req.start + 30 * MIN; s < req.start + 5 * DAY && out.length < 3; s += 30 * MIN) {
      var hh = new Date(s).getHours() + new Date(s).getMinutes() / 60; if (hh < 7 || hh > 16 || new Date(s).getDay() === 0) continue;
      var r = Object.assign({}, req, { start: s, end: s + (req.end - req.start) });
      if (plan(r).ok) { out.push(r); s += 3 * H; }
    }
    return out;
  }

  /* ---------- Seed (relativ zur aktuellen Woche, mit derselben Planungslogik erzeugt) */
  function seed() {
    var mo = BASE, list = MK.seed; SEEDING = true;
    list.forEach(function (s) {
      var st = at(mo + s.d * DAY, s.h), en = s.days ? at(mo + (s.d + s.days) * DAY, s.eh) : at(mo + s.d * DAY, s.eh);
      var p = plan({ type: s.t, start: st, end: en, plz: s.plz, mode: s.m });
      if (p.ok) commit(p, s.k, true); else if (window.console) console.warn('Seed', s.t, p.err);
    });
    SEEDING = false;
  }
  function load() {
    seed();
    try { var x = JSON.parse(localStorage.getItem(KEY) || '[]'); x.forEach(function (k) { if (k.end > Date.now() - 14 * DAY) BOOK.push(k); }); } catch (e) {}
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(BOOK.filter(function (k) { return !k.seed; }))); } catch (e) {} }

  /* ---------- UI: Buchen */
  var st = { tab: 'buchen', week: monday(nextWork()), type: MK.defaultType, last: null };
  var view = $('#mkView');
  function tabs() { $$('.mk-tabs button').forEach(function (b) { b.setAttribute('aria-selected', String(b.dataset.tab === st.tab)); }); }
  function timeOpts(sel) { var o = ''; for (var h = 6; h <= 20; h++) for (var m = 0; m < 60; m += 30) { if (h === 20 && m) continue; var v = pad(h) + ':' + pad(m); o += '<option' + (v === sel ? ' selected' : '') + '>' + v + '</option>'; } return o; }
  function dateVal(t) { var d = new Date(t); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function parseDT(dv, tv) { var p = dv.split('-'), q = tv.split(':'); return new Date(+p[0], +p[1] - 1, +p[2], +q[0], +q[1]).getTime(); }

  function availStrip(typeId) {
    var t = TYPE[typeId], mo = st.week, html = '<div class="mk-av" role="grid" aria-label="Verfügbarkeit ' + esc(t.name) + '"><div class="mk-av-h"><span></span>';
    for (var h = 6; h < 20; h += 2) html += '<span>' + h + '</span>';
    html += '</div>';
    for (var d = 0; d < 6; d++) {
      var day = mo + d * DAY; html += '<div class="mk-av-r"><b>' + dlab(day) + '</b>';
      for (var h2 = 6; h2 < 20; h2++) {
        var a = at(day, h2), b = a + H, n = t.units.length;
        var busy = BOOK.filter(function (k) { return k.type === typeId && overlap(a, b, k.mA, k.mB); }).map(function (k) { return k.unit; });
        var free = n - Array.from(new Set(busy)).length, past = b < Date.now();
        var cls = past ? 'past' : free === 0 ? 'none' : free < n ? 'some' : 'all';
        html += '<button type="button" class="mk-c ' + cls + '" data-t="' + a + '" ' + (past ? 'disabled' : '') + ' title="' + dlab(day) + ' ' + pad(h2) + ':00 – ' + free + ' von ' + n + ' frei"><span class="sr">' + free + '</span></button>';
      }
      html += '</div>';
    }
    return html + '<p class="mk-legend"><i class="all"></i>alle frei <i class="some"></i>teilweise belegt <i class="none"></i>ausgebucht · Klick setzt den Mietbeginn</p></div>';
  }

  function renderBuchen() {
    if (!st.form) {  // Startvorschlag: erster freier Termin ab dem nächsten Werktag 8 Uhr
      var s0 = at(nextWork(), 8), r0 = { type: st.type, start: s0, end: s0 + 8 * H, plz: '89518', mode: 'liefer' };
      if (!plan(r0).ok) { var sg0 = suggest(r0); if (sg0[0]) r0 = sg0[0]; }
      st.form = { d1: dateVal(r0.start), t1: hm(r0.start), d2: dateVal(r0.end), t2: hm(r0.end), plz: '89518', mode: 'liefer' };
      st.week = monday(r0.start);
    }
    var t = TYPE[st.type], f = st.form || {};
    var d0 = f.date || dateVal(nextWork());
    view.innerHTML = '<div class="mk-book">' +
      '<form class="card mk-form" id="mkForm">' +
      '<label>Gerätetyp<select id="mkType">' + MK.kats.map(function (k) { return '<optgroup label="' + esc(k.name) + '">' + TYPES.filter(function (x) { return x.kat === k.slug; }).map(function (x) { return '<option value="' + x.id + '"' + (x.id === st.type ? ' selected' : '') + '>' + esc(x.name) + ' · ' + x.units.length + ' Stk.</option>'; }).join('') + '</optgroup>'; }).join('') + '</select></label>' +
      '<div class="mk-rate"><img src="assets/img/' + t.pic + '.webp" alt="" width="120" height="84"><div><b>' + esc(t.name) + '</b><small>' + esc(t.info) + '</small><span>' + eur(t.rate.std) + '/Std · ' + eur(t.rate.halb) + ' Halbtag · ' + eur(t.rate.tag) + '/Tag · ' + eur(t.rate.woche) + '/Woche</span></div></div>' +
      '<div class="grid2"><label>Mietbeginn<input type="date" id="mkD1" value="' + (f.d1 || d0) + '" required></label><label>Uhrzeit<select id="mkT1">' + timeOpts(f.t1 || '08:00') + '</select></label></div>' +
      '<div class="grid2"><label>Mietende<input type="date" id="mkD2" value="' + (f.d2 || f.d1 || d0) + '" required></label><label>Uhrzeit<select id="mkT2">' + timeOpts(f.t2 || '16:00') + '</select></label></div>' +
      '<label>PLZ der Baustelle<input id="mkPlz" inputmode="numeric" maxlength="5" placeholder="z. B. 89518" value="' + esc(f.plz || '89518') + '"></label>' +
      '<fieldset class="mk-mode"><legend>Logistik</legend>' +
      [['liefer', 'Lieferung & Abholung durch unseren Fahrer'], ['abhol', 'Selbstabholung in der Niederlassung'], ['bediener', 'Mit Bediener (Fahrer bleibt vor Ort)']].map(function (m) { return '<label class="chk"><input type="radio" name="mkMode" value="' + m[0] + '"' + ((f.mode || 'liefer') === m[0] ? ' checked' : '') + (m[0] === 'abhol' && t.transport === 'tief' ? ' disabled' : '') + '> ' + m[1] + '</label>'; }).join('') +
      (t.transport === 'tief' ? '<p class="muted small">Dieses Gerät wird per Tieflader geliefert – keine Selbstabholung.</p>' : '') +
      (t.transport === 'selbst' ? '<p class="muted small">Lkw-Bühne: Überführung durch unseren Fahrer oder Abholung mit Führerschein ' + esc(t.fs) + '.</p>' : '') + '</fieldset>' +
      '</form>' +
      '<div class="mk-side"><h2 class="h-sm">Verfügbarkeit · ' + esc(t.name) + '</h2><div class="mk-weeknav"><button type="button" class="btn ghost sm" data-wk="-1">← Woche</button><span>' + dlab(st.week) + ' – ' + dlab(st.week + 5 * DAY) + '</span><button type="button" class="btn ghost sm" data-wk="1">Woche →</button></div>' + availStrip(st.type) +
      '<div id="mkResult" aria-live="polite"></div></div></div>';
    $('#mkType').onchange = function () { st.type = this.value; st.form = readForm(); renderBuchen(); };
    $$('#mkForm input, #mkForm select').forEach(function (el) { if (el.id !== 'mkType') el.addEventListener('change', calc); });
    $('#mkPlz').addEventListener('input', calc);
    $$('.mk-c').forEach(function (c) { c.onclick = function () { var a = +c.dataset.t, dur = Math.max(H, readReq().end - readReq().start); var f2 = readForm(); f2.d1 = dateVal(a); f2.t1 = hm(a); var e2 = a + dur; f2.d2 = dateVal(e2); f2.t2 = hm(e2); st.form = f2; renderBuchen(); }; });
    $$('[data-wk]').forEach(function (b) { b.onclick = function () { st.week += (+b.dataset.wk) * 7 * DAY; st.form = readForm(); renderBuchen(); }; });
    calc();
  }
  function readForm() { return { d1: $('#mkD1').value, t1: $('#mkT1').value, d2: $('#mkD2').value, t2: $('#mkT2').value, plz: $('#mkPlz').value, mode: ($('[name=mkMode]:checked') || {}).value || 'liefer' }; }
  function readReq() { var f = readForm(); return { type: st.type, start: parseDT(f.d1, f.t1), end: parseDT(f.d2, f.t2), plz: f.plz, mode: f.mode }; }
  function logisticsHtml(p) {
    var r = p.req, rows = [], dep = DEPOT[p.depot] ? DEPOT[p.depot].name : '';
    if (p.del) rows.push(['del', p.del.a, 'Abfahrt ' + dep + ' · ' + esc(p.del.driver.name) + ' (' + esc(p.del.driver.veh) + ')'], ['del', p.del.arrive, 'Ankunft Baustelle, Abladen und Einweisung' + (p.del.early ? ' – Anlieferung am Vortag' : '')]);
    else if (r.mode === 'abhol') rows.push(['del', r.start - 30 * MIN, 'Übergabe in der Niederlassung ' + esc(DEPOT[p.unit.depot].name) + ' (Einweisung 30 min)']);
    rows.push(['rent', r.start, 'Mietbeginn']); rows.push(['rent', r.end, 'Mietende']);
    if (p.pick) rows.push(['pick', p.pick.arrive, 'Abholung durch ' + esc(p.pick.driver.name) + (p.pick.late ? ' – am Folgetag' : '')], ['pick', p.pick.b, 'Zurück in ' + dep + ', danach Prüfung']);
    else if (r.mode === 'abhol') rows.push(['pick', r.end + 30 * MIN, 'Rückgabe in der Niederlassung']);
    rows.sort(function (a, b) { return a[1] - b[1]; });
    return '<ol class="mk-log">' + rows.map(function (x) { return '<li class="' + x[0] + '"><time>' + dlab(x[1]) + ' ' + hm(x[1]) + '</time><span>' + x[2] + '</span></li>'; }).join('') + '</ol>';
  }
  function calc() {
    var req = readReq(), box = $('#mkResult'), p = plan(req);
    st.last = p;
    if (!p.ok) {
      var sg = p.err && !/PLZ|Postleitzahl|Mietende|Fernzone|Vergangenheit/.test(p.err) ? suggest(req) : [];
      box.innerHTML = '<div class="card mk-warn"><b>Nicht möglich:</b> ' + esc(p.err || '') + (sg.length ? '<p>Freie Alternativen:</p><div class="chips">' + sg.map(function (r) { return '<button type="button" class="btn ghost sm" data-alt="' + r.start + '">' + dlab(r.start) + ' ' + hm(r.start) + '</button>'; }).join('') + '</div>' : '') + '</div>';
      $$('[data-alt]', box).forEach(function (b) { b.onclick = function () { var a = +b.dataset.alt, dur = req.end - req.start, f = readForm(); f.d1 = dateVal(a); f.t1 = hm(a); f.d2 = dateVal(a + dur); f.t2 = hm(a + dur); st.form = f; st.week = monday(a); renderBuchen(); }; });
      return;
    }
    var pr = p.price;
    box.innerHTML = '<div class="card mk-price"><h3>Ihr Preis (Demo)</h3><table>' + pr.lines.map(function (l) { return '<tr><td>' + esc(l[0]) + '</td><td>' + (l[1] ? eur(l[1]) : '–') + '</td></tr>'; }).join('') +
      '<tr class="sum"><td>Summe netto</td><td>' + eur(pr.net) + '</td></tr><tr><td>zzgl. 19 % MwSt.</td><td>' + eur(pr.vat) + '</td></tr><tr class="sum"><td>Gesamt brutto</td><td>' + eur(pr.gross) + '</td></tr></table>' +
      '<p class="muted small">Gerät ' + esc(p.unit.id) + ' · Niederlassung ' + esc(DEPOT[p.unit.depot].name) + (p.zone && p.req.mode !== 'abhol' ? ' · ' + esc(p.zone.name) + ' · ca. ' + p.km + ' km, ' + Math.round(p.drive / MIN) + ' min Fahrt' : '') + '</p>' +
      '<h3>Ablauf</h3>' + logisticsHtml(p) +
      '<div class="mk-cta"><input id="mkKunde" placeholder="Firma (für die Demo)" aria-label="Firma"><button type="button" class="btn big" id="mkBook" data-track="request_submit">Verbindlich anfragen</button></div><p class="muted small">Demo: Die Buchung wird nur in diesem Browser gespeichert und erscheint sofort in der Disposition.</p></div>';
    $('#mkBook').onclick = function () {
      var k = commit(p, ($('#mkKunde').value || 'Demo-Kunde').slice(0, 40)); save();
      (window.dataLayer = window.dataLayer || []).push({ event: 'request_submit', via: 'mietkalender', typ: req.type });
      box.innerHTML = '<div class="card done"><h3>Danke – Anfrage ' + esc(k.id) + ' ist eingeplant.</h3><p>' + esc(TYPE[k.type].name) + ', ' + dlab(k.start) + ' ' + hm(k.start) + ' bis ' + dlab(k.end) + ' ' + hm(k.end) + ' · ' + eur(k.net) + ' netto.</p><p><button type="button" class="btn ghost sm" id="mkToDispo">In der Disposition ansehen</button></p></div>';
      $('#mkToDispo').onclick = function () { st.tab = 'dispo'; st.week = monday(k.start); st.hl = k.id; render(); };
      $$('.mk-av').forEach(function (n) { n.outerHTML = availStrip(st.type); });
    };
  }

  /* ---------- UI: Disposition (Gantt) */
  function xOf(t, mo) {
    var d = Math.floor((dayStart(t) - mo) / DAY); if (d < 0) return 0; if (d > 5) return 6;
    var h = (t - dayStart(t)) / H; h = Math.min(Math.max(h, DAY_FROM), DAY_TO);
    return d + (h - DAY_FROM) / (DAY_TO - DAY_FROM);
  }
  function bar(a, b, mo, cls, label, title, id) {
    var x1 = xOf(a, mo), x2 = xOf(b, mo); if (x2 - x1 <= 0.002) return '';
    return '<span class="mk-bar ' + cls + (st.hl && st.hl === id ? ' hl' : '') + '" style="left:' + (x1 / 6 * 100) + '%;width:' + ((x2 - x1) / 6 * 100) + '%" title="' + esc(title) + '" data-id="' + esc(id || '') + '">' + esc(label) + '</span>';
  }
  function renderDispo() {
    var mo = st.week, end = mo + 6 * DAY, wk = BOOK.filter(function (k) { return overlap(mo, end, Math.min(k.mA, k.delA || k.mA), Math.max(k.mB, k.pickB || k.mB)); });
    var head = '<div class="mk-g-row mk-g-head"><span class="mk-g-lab">KW ' + kw(mo) + '</span><div class="mk-g-track">' + [0, 1, 2, 3, 4, 5].map(function (d) { return '<span class="mk-g-day" style="left:' + (d / 6 * 100) + '%;width:' + (100 / 6) + '%">' + dlab(mo + d * DAY) + '<small>6–20 Uhr</small></span>'; }).join('') + '</div></div>';
    var nowX = xOf(Date.now(), mo), nowLine = Date.now() > mo && Date.now() < end ? '<span class="mk-now" style="left:' + (nowX / 6 * 100) + '%"></span>' : '';
    var rows = '<div class="mk-g-sec">Geräte</div>' + UNITS.map(function (u) {
      var bs = wk.filter(function (k) { return k.unit === u.id; }).map(function (k) {
        var t = TYPE[k.type], s = '';
        if (k.delA) s += bar(k.mA, k.start, mo, 'trans', '', 'Lieferung ' + k.id + ' · ' + hm(k.delA) + '–' + hm(k.delB), k.id);
        s += bar(k.start, k.end, mo, 'rent' + (k.mode === 'bediener' ? ' op' : ''), k.kunde, k.id + ' · ' + k.kunde + ' · ' + t.name + ' · ' + dlab(k.start) + ' ' + hm(k.start) + ' – ' + dlab(k.end) + ' ' + hm(k.end) + ' · PLZ ' + k.plz + (k.mode === 'bediener' ? ' · mit Bediener' : k.mode === 'abhol' ? ' · Selbstabholung' : ''), k.id);
        s += bar(k.end, k.mB, mo, 'trans', '', 'Rücktransport + Prüfung ' + k.id, k.id);
        return s;
      }).join('');
      return '<div class="mk-g-row"><span class="mk-g-lab"><b>' + esc(TYPE[u.type].short) + '</b><small>' + esc(u.id) + ' · ' + esc(DEPOT[u.depot].name) + '</small></span><div class="mk-g-track">' + bs + nowLine + '</div></div>';
    }).join('') + '<div class="mk-g-sec">Fahrer &amp; Fahrzeuge</div>' + DRIVERS.map(function (d) {
      var bs = wk.map(function (k) {
        var s = '';
        if (k.dDel === d.id) s += bar(k.delA, k.delB, mo, k.mode === 'bediener' ? 'op' : 'del', '↓ ' + TYPE[k.type].short, 'Lieferung ' + k.id + ' · ' + TYPE[k.type].name + ' → PLZ ' + k.plz + ' · ' + hm(k.delA) + '–' + hm(k.delB), k.id);
        if (k.mode === 'bediener' && k.dDel === d.id) s += bar(k.start, k.end, mo, 'op', 'Bediener ' + k.kunde, 'Bediener-Einsatz ' + k.id, k.id);
        if (k.dPick === d.id) s += bar(k.pickA, k.pickB, mo, k.mode === 'bediener' ? 'op' : 'pick', '↑ ' + TYPE[k.type].short, 'Abholung ' + k.id + ' · PLZ ' + k.plz + ' · ' + hm(k.pickA) + '–' + hm(k.pickB), k.id);
        return s;
      }).join('');
      return '<div class="mk-g-row"><span class="mk-g-lab"><b>' + esc(d.name) + '</b><small>' + esc(d.veh) + '</small></span><div class="mk-g-track">' + bs + nowLine + '</div></div>';
    }).join('');
    var util = UNITS.length ? Math.round(wk.reduce(function (s, k) { return s + Math.max(0, Math.min(k.end, end) - Math.max(k.start, mo)); }, 0) / (UNITS.length * 6 * (DAY_TO - DAY_FROM) * H) * 100) : 0;
    var umsatz = wk.reduce(function (s, k) { return s + (k.net || 0); }, 0);
    var tours = wk.reduce(function (s, k) { return s + (k.dDel ? 1 : 0) + (k.dPick && k.mode !== 'bediener' ? 1 : 0); }, 0);
    view.innerHTML = '<div class="mk-weeknav"><button type="button" class="btn ghost sm" data-wk="-1">← Woche</button><span>' + dlab(mo) + ' – ' + dlab(mo + 5 * DAY) + '</span><button type="button" class="btn ghost sm" data-wk="1">Woche →</button><button type="button" class="btn ghost sm" data-wk="0">Heute</button></div>' +
      '<div class="three mk-kpi"><div class="card"><b class="num">' + wk.length + '</b><span>Mietvorgänge in der Woche</span></div><div class="card"><b class="num">' + tours + '</b><span>Fahrer-Touren (Liefern/Abholen)</span></div><div class="card"><b class="num">' + eur(umsatz) + '</b><span>Mietumsatz netto (Demo)</span></div></div>' +
      '<p class="mk-legend"><i class="rent"></i>Miete beim Kunden <i class="trans"></i>Transport / Prüfung <i class="del"></i>Lieferung <i class="pick"></i>Abholung <i class="op"></i>Bediener-Einsatz · Auslastung Geräte ' + util + ' %</p>' +
      '<div class="mk-gantt" tabindex="0" aria-label="Dispositionsplan">' + head + rows + '</div><div id="mkDet"></div>';
    $$('[data-wk]').forEach(function (b) { b.onclick = function () { var v = +b.dataset.wk; st.week = v ? st.week + v * 7 * DAY : monday(nextWork()); renderDispo(); }; });
    $$('.mk-bar').forEach(function (b) { b.onclick = function () { st.hl = b.dataset.id; detail(b.dataset.id); $$('.mk-bar').forEach(function (x) { x.classList.toggle('hl', x.dataset.id === st.hl); }); }; });
    if (st.hl) detail(st.hl);
  }
  function detail(id) {
    var k = BOOK.filter(function (x) { return x.id === id; })[0], box = $('#mkDet'); if (!k || !box) return;
    var drv = function (i) { var d = DRIVERS.filter(function (x) { return x.id === i; })[0]; return d ? d.name + ' (' + d.veh + ')' : '–'; };
    box.innerHTML = '<div class="card mk-detail"><h3>' + esc(k.id) + ' · ' + esc(k.kunde) + '</h3><table>' +
      [['Gerät', TYPE[k.type].name + ' · ' + k.unit], ['Miete', dlab(k.start) + ' ' + hm(k.start) + ' – ' + dlab(k.end) + ' ' + hm(k.end)], ['Baustelle', 'PLZ ' + k.plz], ['Logistik', k.mode === 'bediener' ? 'mit Bediener' : k.mode === 'abhol' ? 'Selbstabholung' : 'Lieferung & Abholung'],
        ['Lieferung', k.delA ? dlab(k.delA) + ' ' + hm(k.delA) + '–' + hm(k.delB) + ' · ' + drv(k.dDel) : '–'], ['Abholung', k.pickA ? dlab(k.pickA) + ' ' + hm(k.pickA) + '–' + hm(k.pickB) + ' · ' + drv(k.dPick) : '–'],
        ['Gerät blockiert', dlab(k.mA) + ' ' + hm(k.mA) + ' – ' + dlab(k.mB) + ' ' + hm(k.mB)], ['Netto (Demo)', eur(k.net || 0)]].map(function (r) { return '<tr><th scope="row">' + r[0] + '</th><td>' + esc(r[1]) + '</td></tr>'; }).join('') + '</table>' +
      (k.seed ? '' : '<button type="button" class="btn ghost sm" id="mkDel">Stornieren</button>') + '</div>';
    var del = $('#mkDel'); if (del) del.onclick = function () { BOOK = BOOK.filter(function (x) { return x !== k; }); save(); st.hl = null; renderDispo(); };
  }
  function kw(t) { var d = new Date(t + 3 * DAY); var y = new Date(d.getFullYear(), 0, 4); return 1 + Math.round(((d - y) / DAY - 3 + (y.getDay() + 6) % 7) / 7); }

  /* ---------- UI: Preisliste */
  function renderPreise() {
    view.innerHTML = '<div class="tw"><table class="mk-pl"><thead><tr><th>Gerät</th><th>Stück</th><th>pro Std.<small>min. 2 h</small></th><th>Halbtag<small>bis 5 h</small></th><th>Tag<small>bis 9 h</small></th><th>Woche<small>6 Tage</small></th><th>Transport</th></tr></thead><tbody>' +
      MK.kats.map(function (k) { var ts = TYPES.filter(function (x) { return x.kat === k.slug; }); return ts.length ? '<tr class="grp"><td colspan="7">' + esc(k.name) + '</td></tr>' + ts.map(function (t) { return '<tr><td><b>' + esc(t.name) + '</b><small>' + esc(t.info) + '</small></td><td>' + t.units.length + '</td><td>' + eur(t.rate.std) + '</td><td>' + eur(t.rate.halb) + '</td><td>' + eur(t.rate.tag) + '</td><td>' + eur(t.rate.woche) + '</td><td>' + ({ tief: 'Tieflader', anh: 'Transporter/Anhänger', selbst: 'fährt selbst' })[t.transport] + '</td></tr>'; }).join('') : ''; }).join('') +
      '</tbody></table></div><h2 class="h-sm">Transport je Fahrt (Lieferung oder Abholung)</h2><div class="tw"><table class="mk-pl"><thead><tr><th>Zone</th><th>Fahrzeit einfach</th><th>Transporter/Anhänger</th><th>Tieflader</th></tr></thead><tbody>' +
      MK.zones.map(function (z) { return '<tr><td>' + esc(z.name) + '<small>' + esc(z.info) + '</small></td><td>' + (z.n === 4 ? 'nach Tour' : 'bis ca. ' + driveMin(z.km) + ' min') + '</td><td>' + (z.n === 4 ? 'auf Anfrage' : eur(z.anh)) + '</td><td>' + (z.n === 4 ? 'auf Anfrage' : eur(z.tief)) + '</td></tr>'; }).join('') +
      '</tbody></table></div><p class="muted">Bediener ' + eur(MK.bediener) + '/Std. (mind. 4 h). Sonntag mietfrei bei Mehrtagesmiete. Haftungsbeschränkung 8 % der Miete. Alle Preise Demo, netto zzgl. MwSt.</p>' +
      '<h2 class="h-sm">So plant der Kalender</h2><ul class="plain"><li>Die nächstgelegene Niederlassung mit freiem Gerät liefert; Entfernung aus der PLZ-Region (Demo-Näherung).</li><li>Lieferung endet spätestens zum Mietbeginn: Abfahrt = Mietbeginn − Fahrzeit − 30 min Abladen/Einweisung.</li><li>Abholung beginnt zum Mietende; das Gerät ist bis zur Rückkehr in die Niederlassung plus 30 min Prüfung blockiert.</li><li>Fahrer arbeiten Mo–Sa 6–19 Uhr. Liegt der Mietbeginn davor, wird am Vortag angeliefert; endet die Miete danach, wird am Folgetag abgeholt.</li><li>Geräte über 3,5 t brauchen einen Tieflader-Fahrer; ist keiner frei, schlägt der Kalender die nächsten freien Termine vor.</li><li>Mit Bediener bleibt der Fahrer während der ganzen Miete beim Kunden.</li></ul>';
  }

  function render() { tabs(); if (st.tab === 'buchen') renderBuchen(); else if (st.tab === 'dispo') renderDispo(); else renderPreise(); }
  $$('.mk-tabs button').forEach(function (b) { b.onclick = function () { st.tab = b.dataset.tab; render(); }; });
  load();
  st.dispoWeek = BASE;
  try { var h = /tab=(\w+)/.exec(location.hash); if (h) st.tab = h[1]; } catch (e) {}
  render();
  window.__mk = { BOOK: BOOK, plan: plan, price: price };
})();
