/* Laggner Demo – Navigation, Filter, Mietanfrage, Tracking-Events (dataLayer) */
(function(){
  var $=function(s,r){return (r||document).querySelector(s)},$$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
  function track(ev,data){try{window.dataLayer.push(Object.assign({event:ev},data||{}))}catch(e){}}

  /* Menü */
  var bg=$('#burger'),nav=$('#mainnav');
  if(bg&&nav){bg.addEventListener('click',function(){var o=nav.classList.toggle('open');bg.setAttribute('aria-expanded',String(o))})}

  /* Tracking: Telefon, E-Mail, Datenblatt */
  document.addEventListener('click',function(e){var a=e.target.closest('[data-track]');if(!a)return;var t=a.getAttribute('data-track');
    if(t==='file_download'){e.preventDefault();track('file_download',{file:a.getAttribute('data-file')});a.textContent='Datenblatt folgt (Demo)';return}
    track(t,{href:a.getAttribute('href')||''})});

  /* Kategoriefilter */
  var f=$('#filter');
  if(f){var grid=$('#ggrid'),cnt=$('#fCount'),empty=$('#fEmpty');
    function apply(){var h=$('#fHoehe').value,an=$('#fAntrieb').value,n=0;
      $$('.gcard',grid).forEach(function(c){var ah=+c.dataset.ah,ok=true;
        if(h){var p=h.split('-');ok=ah>+p[0]-0.01&&ah<=+p[1]}
        if(ok&&an)ok=c.dataset.antrieb===an;
        c.hidden=!ok;if(ok)n++});
      cnt.textContent=n+(n===1?' Gerät':' Geräte');empty.hidden=n>0}
    f.addEventListener('change',apply);f.addEventListener('reset',function(){setTimeout(apply,0)});
    try{var sp=new URLSearchParams(location.search);if(sp.get('hoehe')){var m={'bis 12 m':'0-12','12–20 m':'12-20','20–35 m':'20-35','35–60 m':'35-60','über 60 m':'60-999'}[sp.get('hoehe')];if(m){$('#fHoehe').value=m;apply()}}}catch(e){}}

  /* Startseiten-Schnellsuche: Kategorie gewählt → Kategorieseite, sonst Anfrage */
  var hf=$('#heroForm');
  if(hf){hf.addEventListener('submit',function(e){var k=$('#heroKat').value;if(k){e.preventDefault();var q=new URLSearchParams(new FormData(hf));q.delete('kat');location.href='mietgeraete/'+k+'.html?'+q.toString()}})}

  /* Mietanfrage */
  var rq=$('#rq');
  if(rq){var G=window.LAGGNER_GERAETE||[],L=window.LAGGNER_LAENDER||{},step=1,steps=$$('.step',rq),st=$$('#stepper li');
    var kat=$('#rKat'),ger=$('#rGer'),plz=$('#rPlz'),zust=$('#rZust');
    function fillGer(){var k=kat.value;ger.innerHTML='<option value="">noch offen – bitte beraten</option>'+G.filter(function(g){return g.kat===k}).map(function(g){return '<option value="'+g.slug+'">'+g.name+'</option>'}).join('')}
    kat.addEventListener('change',fillGer);
    /* Vorbelegung aus URL (?kat=…&plz=… oder #geraet=…) */
    try{var sp=new URLSearchParams(location.search);if(sp.get('kat')){kat.value=sp.get('kat')}if(sp.get('plz'))plz.value=sp.get('plz');if(sp.get('hoehe'))$('#rAh').value=sp.get('hoehe');
      var h=/geraet=([a-z0-9-]+)/.exec(location.hash);if(h){var g=G.filter(function(x){return x.slug===h[1]})[0];if(g){kat.value=g.kat;fillGer();ger.value=g.slug;if(g.ah)$('#rAh').value=g.ah+' m'}}else fillGer()}catch(e){fillGer()}
    /* Zuständigkeit nach PLZ */
    function zustText(){var v=plz.value.replace(/\D/g,'');var C=window.SITE_CFG||{plzLen:5};if(v.length<C.plzLen){zust.textContent='';zust.className='hint';return}
      var hit=null,best=0;Object.keys(L).forEach(function(k){L[k].plz.forEach(function(p){if(v.indexOf(p)===0&&p.length>best){best=p.length;hit=L[k]}})});
      if(!hit){zust.textContent=C.out||'PLZ außerhalb Deutschlands – wir prüfen die Lieferung individuell.';zust.className='hint';return}
      zust.textContent=hit.typ==='nl'?'Zuständig: Niederlassung in '+hit.name+' – Lieferung meist am nächsten Werktag.':(C.lg?C.lg.replace('{name}',hit.name):'Liefergebiet '+hit.name+' – Lieferung aus Süddeutschland oder über Partner, Ansprechpartner Zentrale Heidenheim.');zust.className='hint ok'}
    plz.addEventListener('input',zustText);zustText();
    /* Datum: Mietende nicht vor Beginn */
    var von=$('#rVon'),bis=$('#rBis');var today=new Date().toISOString().slice(0,10);von.min=today;bis.min=today;
    von.addEventListener('change',function(){bis.min=von.value;if(bis.value&&bis.value<von.value)bis.value=von.value});
    function valid(fs){var ok=true;$$('input,select',fs).forEach(function(i){i.classList.add('touched');if(!i.checkValidity())ok=false});return ok}
    function show(n){step=n;steps.forEach(function(s){s.hidden=+s.dataset.step!==n});st.forEach(function(li,i){li.className=i+1<n?'done':i+1===n?'on':''});$('.step:not([hidden]) legend',rq).scrollIntoView({block:'start',behavior:'smooth'})}
    rq.addEventListener('click',function(e){if(e.target.closest('[data-next]')){var fs=e.target.closest('.step');if(valid(fs)){if(step===1)track('request_start',{via:'form'});show(step+1)}}
      if(e.target.closest('[data-prev]'))show(step-1)});
    rq.addEventListener('submit',function(e){e.preventDefault();var fs=e.target.querySelector('.step:not([hidden])');if(!valid(fs))return;
      var d=new FormData(rq),gname=ger.options[ger.selectedIndex].text,kname=kat.options[kat.selectedIndex].text;
      track('request_submit',{kat:kat.value,geraet:ger.value,plz:d.get('plz')});track('request_complete');
      $('#rqSum').textContent=(ger.value?gname:kname)+' · PLZ '+d.get('plz')+' · '+d.get('von')+' bis '+d.get('bis')+(d.get('bediener')?' · mit Bediener':'');
      rq.hidden=true;$('#stepper').hidden=true;$('#rqDone').hidden=false;$('#rqDone').scrollIntoView({block:'start'})});
  }
})();
