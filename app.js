/*
 * Laudo — coleta em campo (app de tablet, funciona offline)
 *
 * - Os campos do formulário vêm da planilha (Schema.gs) e ficam guardados no tablet.
 * - Os casos ficam cifrados no aparelho (AES-GCM, chave derivada do PIN) até a sincronização.
 * - O app só colhe dados: o laudo é gerado no computador, pelo formulário da planilha.
 */
'use strict';
const APP_VERSION = '1.0.1';
const PURGE_AFTER_MS = 24 * 3600 * 1000;  // remove do tablet casos sincronizados há mais de 24 h
const NOTAS_KEY = '__notas';              // caderno de anotações gerais (não é coluna da planilha)

const $ = s => document.querySelector(s);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function btn(text, cls, fn) { const b = el('button', 'btn' + (cls ? ' ' + cls : ''), text); b.type = 'button'; b.onclick = fn; return b; }
function p2(n) { return ('0' + n).slice(-2); }
function quando(ts) { const d = new Date(ts); return p2(d.getDate()) + '/' + p2(d.getMonth() + 1) + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()); }
function todayIso() { const d = new Date(); return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()); }

/* ============================ armazenamento (IndexedDB) ============================ */
let DB = null;
function idbOpen() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('laudoCampo', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => { DB = r.result; res(); };
    r.onerror = () => rej(r.error);
  });
}
function idbReq(mode, fn) {
  return new Promise((res, rej) => { const r = fn(DB.transaction('kv', mode).objectStore('kv')); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
}
const idb = {
  get: k => idbReq('readonly', s => s.get(k)),
  set: (k, v) => idbReq('readwrite', s => s.put(v, k)),
  del: k => idbReq('readwrite', s => s.delete(k)),
  keys: () => idbReq('readonly', s => s.getAllKeys()),
  clear: () => idbReq('readwrite', s => s.clear())
};

/* ============================ criptografia ============================ */
let KEY = null;
async function derive(pin, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, KEY, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: iv, ct: ct };
}
async function unseal(box) {
  if (!box) return null;
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: box.iv }, KEY, box.ct);
  return JSON.parse(new TextDecoder().decode(pt));
}
async function putS(k, obj) { await idb.set(k, await seal(obj)); }
async function getS(k) { return unseal(await idb.get(k)); }

/* ============================ estado ============================ */
let CFG = null;        // { u: endereço de sincronização, k: chave }
let CACHE = null;      // { schema, presets, semQuesitos, quesitosPadrao, cid, records, ts }
let CASES = {};        // id -> caso
let CUR = null;        // caso aberto no formulário

function novoCaso() {
  return { id: crypto.randomUUID(), data: {}, q: { none: false, itens: [] }, ink: {}, baseStamp: '', isNew: true, dirty: false, inkDirty: false, updatedAt: Date.now(), syncedAt: 0 };
}
function rotuloCaso(c) { return (c.data['Número do Processo'] || 'sem número') + ' — ' + (c.data['Nome do Requerido'] || 'sem nome'); }
async function saveCase(c) { await putS('case:' + c.id, c); }
async function removeCase(id) {
  const ks = await idb.keys();
  for (const k of ks) if (k === 'case:' + id || String(k).indexOf('ink:' + id + ':') === 0) await idb.del(k);
  delete CASES[id];
}
async function loadAll() {
  CFG = await getS('cfg'); CACHE = await getS('cache'); CASES = {};
  const ks = await idb.keys();
  for (const k of ks) if (String(k).indexOf('case:') === 0) { const c = await getS(k); if (c) CASES[c.id] = c; }
  // limpeza: casos já sincronizados e sem alterações há mais de 24 h saem do aparelho
  for (const id of Object.keys(CASES)) {
    const c = CASES[id];
    if (!c.dirty && !c.inkDirty && c.uploadedAt && Date.now() - c.uploadedAt > PURGE_AFTER_MS) await removeCase(id);
  }
}

/* ============================ comunicação com a planilha ============================ */
async function api(req, cfg) {
  cfg = cfg || CFG;
  if (!cfg) throw new Error('O tablet ainda não foi configurado.');
  const ctl = new AbortController(); const to = setTimeout(() => ctl.abort(), 90000);
  let r;
  try {
    r = await fetch(cfg.u, { method: 'POST', redirect: 'follow', signal: ctl.signal, headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(Object.assign({ key: cfg.k }, req)) });
  } catch (e) { throw new Error('Sem conexão com a planilha. Os dados continuam guardados no tablet.'); }
  finally { clearTimeout(to); }
  let j;
  try { j = await r.json(); } catch (e) { throw new Error('Resposta inesperada da planilha (HTTP ' + r.status + '). Confira o código de configuração.'); }
  return j;
}
function lerCodigo(txt) {
  try {
    const b = String(txt).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const o = JSON.parse(decodeURIComponent(escape(atob(b))));
    if (/^https:\/\/|^http:\/\/localhost[:\/]/.test(o.u) && o.k) return { u: o.u, k: o.k };
  } catch (e) { /* inválido */ }
  return null;
}
async function atualizarCache(cfg) {
  const r = await api({ action: 'init' }, cfg);
  if (!r.ok) throw new Error(r.mensagem || 'A planilha recusou o acesso.');
  CACHE = { schema: r.schema, presets: r.presets || [], semQuesitos: r.semQuesitos, quesitosPadrao: r.quesitosPadrao || [], cid: r.cid || { rows: [], longos: {} }, records: r.records || [], version: r.version, ts: Date.now() };
  await putS('cache', CACHE);
}

/** Envia um caso. Devolve { ok } ou { conflito } ou lança erro de conexão. */
async function syncCase(c, force) {
  const req = { action: 'save', id: c.id, data: c.data, quesitos: JSON.stringify(c.q || {}), baseStamp: c.baseStamp || '', force: !!force };
  const r = await api(req);
  if (!r.ok) { if (r.erro === 'conflito') return { conflito: true }; throw new Error(r.mensagem || 'Falha ao salvar na planilha.'); }
  c.baseStamp = r.stamp; c.isNew = false; c.dirty = false;
  if (c.inkDirty) {
    const pdf = await inkPdf(c);
    if (pdf) {
      const a = await api({ action: 'ink', id: c.id, pdf: b64(pdf) });
      if (!a.ok) throw new Error(a.mensagem || 'Dados salvos, mas as anotações manuscritas não foram enviadas.');
    }
    c.inkDirty = false;
  }
  c.syncedAt = Date.now(); c.uploadedAt = c.syncedAt; // só casos ENVIADOS pelo tablet entram na limpeza automática
  await saveCase(c);
  return { ok: true };
}
function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }

/* ============================ telas ============================ */
const app = () => $('#app');
function shell(title, right) {
  const a = app(); a.innerHTML = '';
  const h = el('header', 'top'); h.appendChild(el('h1', null, title));
  const st = el('span', 'st'); st.id = 'net'; h.appendChild(st);
  (right || []).forEach(b => h.appendChild(b));
  a.appendChild(h);
  const m = el('main'); a.appendChild(m);
  updNet();
  return m;
}
function updNet() { const n = $('#net'); if (n) n.textContent = navigator.onLine ? 'online' : 'sem internet'; }
window.addEventListener('online', updNet); window.addEventListener('offline', updNet);
function msgBox(parent, kind, text, botoes) {
  let box = parent.querySelector(':scope > .msgs'); if (!box) { box = el('div', 'msgs'); parent.insertBefore(box, parent.firstChild); }
  box.innerHTML = '';
  if (!text) return;
  const d = el('div', 'msg ' + kind, text);
  if (botoes && botoes.length) { const r = el('div', 'row'); botoes.forEach(b => r.appendChild(b)); d.appendChild(r); }
  box.appendChild(d); window.scrollTo(0, 0);
}

/* ---------- bloqueio por PIN ---------- */
async function telaPin() {
  const meta = await idb.get('meta');
  const m = shell('Laudo — coleta em campo'); const c = el('div', 'card center'); m.appendChild(c);
  c.appendChild(el('h2', null, meta ? 'Digite o PIN' : 'Crie um PIN para este tablet'));
  if (!meta) c.appendChild(el('div', 'hint', 'O PIN protege os dados guardados no aparelho. Ele é pedido uma vez; o tablet fica desbloqueado até você tocar em "Bloquear". Use ao menos 6 caracteres (números ou uma frase curta). Se for esquecido, os dados ainda não sincronizados se perdem.'));
  const i1 = el('input'); i1.type = 'password'; i1.autocomplete = 'off'; i1.placeholder = 'PIN'; i1.id = 'pin1'; c.appendChild(i1);
  let i2 = null;
  if (!meta) { i2 = el('input'); i2.type = 'password'; i2.autocomplete = 'off'; i2.placeholder = 'Repita o PIN'; i2.id = 'pin2'; i2.style.marginTop = '8px'; c.appendChild(i2); }
  const go = btn(meta ? 'Desbloquear' : 'Criar PIN', 'primary', async () => {
    const pin = i1.value;
    if (!meta) {
      if (pin.length < 6) return msgBox(c, 'err', 'Use ao menos 6 caracteres.');
      if (pin !== i2.value) return msgBox(c, 'err', 'Os dois PINs não coincidem.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      KEY = await derive(pin, salt);
      await idb.set('meta', { salt: salt, check: await seal({ ok: true }) });
    } else {
      go.disabled = true;
      KEY = await derive(pin, meta.salt);
      try { await unseal(meta.check); } catch (e) { KEY = null; go.disabled = false; i1.value = ''; return msgBox(c, 'err', 'PIN incorreto.'); }
    }
    await idb.set('sess', KEY); // mantém o tablet desbloqueado até "Bloquear" (a chave não pode ser extraída do navegador)
    await loadAll();
    CFG ? telaInicio() : telaConfig();
  });
  go.style.marginTop = '12px'; c.appendChild(go);
  i1.addEventListener('keydown', e => { if (e.key === 'Enter' && meta) go.click(); });
  if (meta) {
    const z = el('button', 'clear', 'Esqueci o PIN (apagar tudo neste tablet)'); z.type = 'button'; z.style.display = 'block'; z.style.marginTop = '14px';
    z.onclick = async () => { if (confirm('Apagar TODOS os dados guardados neste tablet, inclusive casos ainda não sincronizados?')) { await idb.clear(); location.reload(); } };
    c.appendChild(z);
  }
  i1.focus();
}
/** Bloqueio manual: o PIN só volta a ser pedido depois disto (não há bloqueio automático). */
async function bloquear() { await flushSave(); await idb.del('sess'); KEY = null; CFG = null; CACHE = null; CASES = {}; CUR = null; telaPin(); }
document.addEventListener('visibilitychange', () => { if (document.hidden) flushSave(); });

/* ---------- configuração ---------- */
function telaConfig() {
  const m = shell('Configurar', CFG ? [hbtn('Voltar', telaInicio)] : []); const c = el('div', 'card'); m.appendChild(c);
  c.appendChild(el('h2', null, 'Ligar este tablet à planilha'));
  c.appendChild(el('div', 'hint', 'No computador, abra a planilha e use o menu Laudo > "Tablet: mostrar código de configuração". Cole o código abaixo. É preciso estar com internet.'));
  const t = el('textarea', 'big'); t.id = 'cfgCode'; t.placeholder = 'Código de configuração'; c.appendChild(t);
  const b = btn('Conectar', 'primary', async () => {
    const cfg = lerCodigo(t.value);
    if (!cfg) return msgBox(c, 'err', 'Código inválido. Copie o código inteiro, sem cortar.');
    b.disabled = true; b.textContent = 'Conectando…';
    try { await atualizarCache(cfg); CFG = cfg; await putS('cfg', CFG); telaInicio('Tablet conectado à planilha.'); }
    catch (e) { b.disabled = false; b.textContent = 'Conectar'; msgBox(c, 'err', e.message); }
  });
  b.style.marginTop = '10px'; c.appendChild(b);
  if (CFG) {
    const c2 = el('div', 'card'); m.appendChild(c2); c2.appendChild(el('h2', null, 'Este tablet'));
    c2.appendChild(el('div', 'hint', 'App versão ' + APP_VERSION + '. Formulário da planilha versão ' + ((CACHE && CACHE.version) || '?') + ', baixado em ' + (CACHE ? quando(CACHE.ts) : '—') + '.'));
    const r = el('div', 'row'); c2.appendChild(r);
    r.appendChild(btn('Bloquear agora', '', bloquear));
    r.appendChild(btn('Apagar tudo neste tablet', 'danger', async () => { if (confirm('Apagar TODOS os dados deste tablet, inclusive casos não sincronizados e o PIN?')) { await idb.clear(); location.reload(); } }));
  }
}
function hbtn(text, fn) { const b = el('button', null, text); b.type = 'button'; b.onclick = fn; return b; }

/* ---------- início: casos no tablet e na planilha ---------- */
function estado(c) {
  if (c.isNew && !c.syncedAt) return ['pend', 'não enviado'];
  if (c.dirty || c.inkDirty) return ['pend', 'alterações não enviadas'];
  return ['ok', 'sincronizado ' + quando(c.syncedAt)];
}
function telaInicio(aviso) {
  CUR = null;
  const m = shell('Laudo — coleta em campo', [hbtn('Bloquear', bloquear), hbtn('Configurar', telaConfig)]);
  const c = el('div', 'card'); m.appendChild(c);
  const top = el('div', 'row'); c.appendChild(top);
  top.appendChild(btn('+ Novo caso', 'primary', () => { const n = novoCaso(); CASES[n.id] = n; telaForm(n); }));
  const pend = Object.values(CASES).filter(x => x.dirty || x.inkDirty || (x.isNew && !x.syncedAt));
  const bs = btn('Sincronizar tudo (' + pend.length + ')', '', () => sincronizarLista(pend, m)); bs.id = 'btnSyncAll'; bs.disabled = !pend.length; top.appendChild(bs);
  c.appendChild(el('h3', null, 'Casos neste tablet'));
  const lista = Object.values(CASES).sort((a, b) => b.updatedAt - a.updatedAt);
  if (!lista.length) c.appendChild(el('div', 'hint', 'Nenhum caso guardado neste tablet.'));
  lista.forEach(x => {
    const row = el('div', 'case'); const l = el('div', 'lbl', rotuloCaso(x)); const e = estado(x); l.appendChild(el('span', 'tag ' + e[0], e[1])); row.appendChild(l);
    row.appendChild(btn('Abrir', 'small primary', () => telaForm(x)));
    row.appendChild(btn('Enviar', 'small', () => sincronizarLista([x], m)));
    row.appendChild(btn('Remover', 'small danger', async () => {
      const p = x.dirty || x.inkDirty || (x.isNew && !x.syncedAt);
      if (!confirm(p ? 'Este caso tem dados NÃO enviados à planilha. Removê-lo do tablet apaga esses dados. Continuar?' : 'Remover este caso do tablet? (Ele continua na planilha.)')) return;
      await removeCase(x.id); telaInicio();
    }));
    c.appendChild(row);
  });

  const c2 = el('div', 'card'); m.appendChild(c2);
  const h = el('div', 'row'); h.appendChild(el('h2', null, 'Casos na planilha')); c2.appendChild(h);
  c2.appendChild(el('div', 'hint', 'Lista baixada em ' + (CACHE ? quando(CACHE.ts) : '—') + '. Baixe antes de sair os casos que vai continuar em campo.'));
  c2.appendChild(btn('Atualizar lista e formulário', 'small', async function () {
    this.disabled = true; this.textContent = 'Atualizando…';
    try { await atualizarCache(); telaInicio('Lista e formulário atualizados.'); } catch (e) { telaInicio(); msgBox($('main'), 'err', e.message); }
  }));
  ((CACHE && CACHE.records) || []).filter(r => !CASES[r.id]).forEach(r => {
    const row = el('div', 'case'); row.appendChild(el('div', 'lbl', r.label));
    row.appendChild(btn('Baixar', 'small', async function () {
      this.disabled = true;
      try {
        const g = await api({ action: 'get', id: r.id });
        if (!g.ok) throw new Error(g.mensagem || 'Não foi possível baixar.');
        const n = novoCaso(); n.id = r.id; n.isNew = false; n.baseStamp = g.stamp || ''; n.syncedAt = Date.now();
        n.data = dadosDoRegistro(g.data); n.q = lerQuesitos(g.quesitos, g.data['Resposta aos quesitos']);
        CASES[n.id] = n; await saveCase(n); telaInicio('Caso baixado para o tablet.');
      } catch (e) { this.disabled = false; msgBox(m, 'err', e.message); }
    }));
    c2.appendChild(row);
  });
  if (aviso) msgBox(m, 'ok', aviso);
}
function dadosDoRegistro(rec) { const d = {}; allFields().forEach(f => { if (f.type !== 'quesitos') d[f.key.trim()] = rec[f.key.trim()] || ''; }); return d; }

async function sincronizarLista(lista, m) {
  if (!navigator.onLine) return msgBox(m, 'warn', 'Sem internet. Os dados continuam guardados no tablet; sincronize quando houver conexão.');
  let ok = 0; const falhas = [], conflitos = [];
  msgBox(m, 'warn', 'Sincronizando…');
  for (const c of lista) {
    try { const r = await syncCase(c, false); if (r.conflito) conflitos.push(c); else ok++; }
    catch (e) { falhas.push(rotuloCaso(c) + ': ' + e.message); }
  }
  telaInicio();
  const mm = $('main');
  if (conflitos.length) {
    const c = conflitos[0];
    return msgBox(mm, 'warn', 'O caso "' + rotuloCaso(c) + '" foi alterado na planilha depois de baixado para o tablet. Enviar a versão do tablet substitui o que está na planilha.', [
      btn('Enviar a versão do tablet', 'small primary', async () => { try { await syncCase(c, true); telaInicio('Caso enviado.'); } catch (e) { msgBox($('main'), 'err', e.message); } }),
      btn('Não enviar agora', 'small', () => telaInicio())
    ]);
  }
  if (falhas.length) return msgBox(mm, 'err', (ok ? ok + ' caso(s) enviado(s). ' : '') + 'Falhou: ' + falhas.join(' | '));
  msgBox(mm, 'ok', ok + ' caso(s) enviado(s) à planilha. O laudo é gerado no computador.');
}

/* ============================ formulário ============================ */
let SCHEMA = [], QST = { none: false, itens: [] }, RESTORING = false, saveTimer = null, curSec = 0;
const ORIGENS = ['Juízo', 'Ministério Público', 'Requerente', 'Requerido', 'Outros'];
const ORIGEM_TXT = { 'Juízo': 'Quesitos do Juízo:', 'Ministério Público': 'Quesitos do Ministério Público:', 'Requerente': 'Quesitos da parte requerente:', 'Requerido': 'Quesitos da parte requerida:', 'Outros': 'Outros quesitos:' };

function allFields() { const o = []; ((CACHE && CACHE.schema) || []).forEach(s => s.fields.forEach(f => o.push(f))); return o; }
function findField(key) { return allFields().filter(f => f.key === key)[0]; }
function inputs(f) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + f._id + '"]')); }
function otherBox(f) { return document.querySelector('textarea[data-other="' + f._id + '"]'); }

function telaForm(c) {
  CUR = c; SCHEMA = CACHE.schema; curSec = 0;
  const m = shell(rotuloCaso(c), [hbtn('Casos', async () => { await flushSave(); telaInicio(); })]);
  const nav = el('nav', 'steps'); nav.id = 'steps'; m.appendChild(nav);
  const form = el('div'); form.id = 'form'; m.appendChild(form);
  let idx = 0;
  SCHEMA.forEach((sec, si) => {
    const card = el('div', 'card sec'); card.dataset.i = si; card.appendChild(el('h2', null, sec.title));
    if (si === 0 && (CACHE.presets || []).length) card.appendChild(perfis());
    let lastGroup = null;
    sec.fields.forEach(f => {
      f._id = 'f' + (idx++);
      if (f.group && f.group !== lastGroup) {
        const h = el('h3'); h.appendChild(el('span', null, f.group)); h.appendChild(bulkSelect(sec.fields.filter(x => x.group === f.group))); card.appendChild(h);
        if (f.type === 'checkbox' && f.join === 'slash') card.appendChild(el('div', 'hint', 'É possível marcar dois graus vizinhos por domínio. "Sem prejuízo" não combina com os demais.'));
      }
      lastGroup = f.group || null;
      card.appendChild(f.type === 'quesitos' ? renderQuesitos(f) : renderField(f));
    });
    form.appendChild(card);
  });
  // caderno de anotações gerais
  const nc = el('div', 'card sec'); nc.dataset.i = SCHEMA.length; nc.appendChild(el('h2', null, 'Anotações gerais (caneta)'));
  nc.appendChild(el('div', 'hint', 'Folhas livres para anotar durante a entrevista. Vão para a pasta do caso em PDF, junto com as anotações feitas nos campos.'));
  const nw = el('div'); nc.appendChild(nw); makeInk(NOTAS_KEY, 'Anotações gerais', nw, true); form.appendChild(nc);

  const bar = el('div', 'bar');
  const bp = btn('◀ Anterior', '', () => irPara(curSec - 1)); bp.id = 'bPrev';
  const info = el('div', 'info'); info.id = 'saveInfo';
  const bn = btn('Próxima ▶', 'primary', () => irPara(curSec + 1)); bn.id = 'bNext';
  bar.appendChild(bp); bar.appendChild(info); bar.appendChild(bn); app().appendChild(bar);

  form.addEventListener('input', touched); form.addEventListener('change', touched);
  fillForm(c);
  setupCid(); setupIdade();
  irPara(0);
}
function nSecs() { return SCHEMA.length + 1; }
function irPara(i) {
  if (i < 0 || i >= nSecs()) return;
  curSec = i;
  document.querySelectorAll('.sec').forEach(s => s.classList.toggle('cur', +s.dataset.i === i));
  $('#bPrev').disabled = i === 0; $('#bNext').disabled = i === nSecs() - 1;
  desenhaSteps(); window.scrollTo(0, 0);
  window.dispatchEvent(new Event('resize')); // redimensiona a área de caneta da seção exibida
}
function faltam(sec) {
  let n = 0;
  sec.fields.forEach(f => {
    if (!f.required) return;
    const w = $('#w_' + f._id); let vazio;
    if (f.type === 'quesitos') vazio = !!quesitosPendentes();
    else { const v = getVal(f); vazio = (!v || (Array.isArray(v) && !v.length)) && !((CUR.ink[f.key] || 0) > 0 && f.type === 'textarea'); }
    if (w) w.classList.toggle('missing', vazio);
    if (vazio) n++;
  });
  return n;
}
function desenhaSteps() {
  const nav = $('#steps'); if (!nav) return; nav.innerHTML = '';
  SCHEMA.forEach((sec, i) => {
    const b = el('button', i === curSec ? 'cur' : '', sec.title.replace(/^(\d+)\.\s*/, '$1. ').split(' (')[0]); b.type = 'button';
    const n = faltam(sec); if (n) b.appendChild(el('span', 'n', String(n))); else b.classList.add('done');
    b.onclick = () => irPara(i); nav.appendChild(b);
  });
  const b = el('button', curSec === SCHEMA.length ? 'cur' : '', 'Anotações'); b.type = 'button'; b.onclick = () => irPara(SCHEMA.length); nav.appendChild(b);
  const cur = nav.querySelector('.cur'); if (cur && cur.scrollIntoView) cur.scrollIntoView({ inline: 'center', block: 'nearest' });
}

function perfis() {
  const w = el('div', 'field'); w.appendChild(el('label', 't', 'Preenchimento rápido (perfil)'));
  const r = el('div', 'row'); const s = el('select', 'f'); s.id = 'presetSel'; s.style.flex = '1 1 260px'; s.style.width = 'auto';
  const o0 = el('option', null, '— escolha um perfil —'); o0.value = ''; s.appendChild(o0);
  CACHE.presets.forEach(p => { const o = el('option', null, p.nome); o.value = p.id; s.appendChild(o); });
  const b = btn('Aplicar', 'small', () => {
    const p = CACHE.presets.filter(x => x.id === s.value)[0]; if (!p) return;
    Object.keys(p.valores).forEach(k => { const f = findField(k); if (!f) return; RESTORING = true; setVal(f, p.valores[k]); RESTORING = false; $('#w_' + f._id).classList.add('preset'); });
    s.value = ''; touched(); desenhaSteps();
    msgBox($('main'), 'warn', 'Perfil "' + p.nome + '" aplicado. Os campos preenchidos por ele ficam em amarelo até serem conferidos: o perfil não substitui o exame.');
  });
  b.id = 'btnPreset'; r.appendChild(s); r.appendChild(b); w.appendChild(r); return w;
}
function bulkSelect(fields) {
  const s = el('select'); const o0 = el('option', null, 'Marcar todos como…'); o0.value = ''; s.appendChild(o0);
  fields[0].options.forEach(o => { const op = el('option', null, o); op.value = o; s.appendChild(op); });
  s.onchange = () => { if (!s.value) return; fields.forEach(f => { setVal(f, s.value); unmark(f); }); s.value = ''; touched(); };
  return s;
}
function unmark(f) { const w = $('#w_' + f._id); if (w && !RESTORING) w.classList.remove('preset'); }

function renderField(f) {
  const w = el('div', 'field'); w.id = 'w_' + f._id;
  const lab = el('label', 't', f.label); if (f.required) lab.appendChild(el('span', 'req', ' *')); w.appendChild(lab);
  if (f.type === 'text') { const i = el('input'); i.type = 'text'; i.id = f._id; w.appendChild(i); }
  else if (f.type === 'date') { const d = el('input'); d.type = 'date'; d.id = f._id; w.appendChild(d); }
  else if (f.type === 'textarea') {
    const modes = el('div', 'modes'); const bt = el('button', 'on', 'Teclado'); bt.type = 'button'; const bc = el('button', null, 'Caneta'); bc.type = 'button';
    modes.appendChild(bt); modes.appendChild(bc); w.appendChild(modes);
    const t = el('textarea', 'big'); t.id = f._id; w.appendChild(t);
    const pane = el('div'); pane.style.display = 'none'; w.appendChild(pane);
    let ink = null;
    const modo = caneta => {
      bt.classList.toggle('on', !caneta); bc.classList.toggle('on', caneta);
      t.style.display = caneta ? 'none' : ''; pane.style.display = caneta ? '' : 'none';
      if (caneta) { if (!ink) ink = makeInk(f.key, f.label, pane, false); ink.resize(); }
    };
    bt.onclick = () => modo(false); bc.onclick = () => modo(true);
    w._modo = modo; w._badge = () => { const n = CUR.ink[f.key] || 0; bc.textContent = n ? 'Caneta (' + n + ' pág.)' : 'Caneta'; };
  } else {
    const box = el('div', 'opts' + (f.options.length && f.options.every(o => o.length < 24) && f.type === 'radio' ? ' inline' : ''));
    const kind = f.type === 'radio' ? 'radio' : 'checkbox';
    f.options.forEach(o => {
      const l = el('label'); const inp = el('input'); inp.type = kind; inp.name = f._id; inp.value = o;
      if (kind === 'checkbox' && f.excl && f.excl.length) inp.addEventListener('change', () => { if (inp.checked) desmarcaIncompativeis(f, o); });
      l.appendChild(inp); l.appendChild(el('span', null, o)); box.appendChild(l);
    });
    if (f.other) {
      const ol = el('div', 'other'); const oi = el('input'); oi.type = kind; oi.name = f._id; oi.value = '__other__';
      const ot = el('textarea'); ot.placeholder = 'Outro:'; ot.setAttribute('data-other', f._id);
      ot.addEventListener('input', () => { oi.checked = ot.value.trim() !== ''; });
      const lbl = el('label'); lbl.appendChild(oi); lbl.appendChild(el('span', null, 'Outro:')); ol.appendChild(lbl); ol.appendChild(ot); box.appendChild(ol);
    }
    w.appendChild(box);
    if (kind === 'radio' && !f.required) { const c = el('button', 'clear', 'limpar escolha'); c.type = 'button'; c.onclick = () => { setVal(f, ''); touched(); }; w.appendChild(c); }
  }
  if (f.hint) w.appendChild(el('div', 'hint', f.hint));
  w.addEventListener('input', () => unmark(f)); w.addEventListener('change', () => unmark(f));
  return w;
}
function desmarcaIncompativeis(f, valor) {
  f.excl.forEach(g => { if (g.indexOf(valor) < 0) return; inputs(f).forEach(i => { if (i.value !== valor && g.indexOf(i.value) >= 0) i.checked = false; }); });
}

function getVal(f) {
  if (f.type === 'quesitos') return quesitosTexto();
  if (f.type === 'text' || f.type === 'date' || f.type === 'textarea') return $('#' + f._id).value.trim();
  const out = [];
  inputs(f).forEach(i => { if (!i.checked) return; if (i.value === '__other__') { const o = otherBox(f).value.trim(); if (o) out.push(o); } else out.push(i.value); });
  return f.type === 'radio' ? (out[0] || '') : out;
}
function setVal(f, str) {
  if (Array.isArray(str)) str = str.join(' | ');
  str = str == null ? '' : String(str);
  if (f.type === 'quesitos') return;
  if (f.type === 'date') { const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(str); $('#' + f._id).value = m ? m[3] + '-' + m[2] + '-' + m[1] : str; return; }
  if (f.type === 'text' || f.type === 'textarea') { $('#' + f._id).value = str; return; }
  const wanted = f.type === 'checkbox' ? str.split(' | ').map(s => s.trim()).filter(Boolean) : (str ? [str] : []);
  const ob = otherBox(f); if (ob) ob.value = '';
  inputs(f).forEach(i => { i.checked = false; });
  const others = [];
  wanted.forEach(v => { const hit = inputs(f).filter(i => i.value === v)[0]; if (hit) hit.checked = true; else others.push(v); });
  if (others.length && ob) { ob.value = others.join(' / '); const oi = inputs(f).filter(i => i.value === '__other__')[0]; if (oi) oi.checked = true; }
}
/** Mesmo formato gravado na planilha: listas unidas por " | ", datas em dd/mm/aaaa. */
function collectFlat() {
  const o = {};
  allFields().forEach(f => {
    let v = getVal(f); if (Array.isArray(v)) v = v.map(s => String(s).replace(/\|/g, '/').trim()).filter(Boolean).join(' | ');
    if (f.type === 'date') { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v); if (m) v = m[3] + '/' + m[2] + '/' + m[1]; }
    o[f.key.trim()] = v;
  });
  return o;
}
function fillForm(c) {
  RESTORING = true;
  allFields().forEach(f => {
    if (f.type === 'quesitos') return;
    setVal(f, c.data[f.key.trim()]);
    if (f.type === 'date' && f.today && !$('#' + f._id).value) $('#' + f._id).value = todayIso();
    const w = $('#w_' + f._id); if (w._badge) w._badge();
  });
  QST = c.q && Array.isArray(c.q.itens) ? { none: !!c.q.none, itens: c.q.itens.map(i => ({ o: i.o || 'Outros', q: i.q || '', r: i.r || '' })) } : { none: false, itens: [] };
  drawQuesitos();
  RESTORING = false;
}

/* ---------- gravação automática no tablet ---------- */
function touched() {
  if (RESTORING || !CUR) return;
  CUR.dirty = true; clearTimeout(saveTimer); saveTimer = setTimeout(flushSave, 700);
  const s = $('#saveInfo'); if (s) s.textContent = 'gravando…';
}
async function flushSave() {
  clearTimeout(saveTimer);
  if (!CUR || !KEY || !$('#form')) return;
  CUR.data = collectFlat(); CUR.q = QST; CUR.updatedAt = Date.now();
  await saveCase(CUR);
  const s = $('#saveInfo'); if (s) s.textContent = 'Guardado no tablet às ' + quando(Date.now()).slice(6) + (CUR.dirty || CUR.inkDirty ? ' — ainda não enviado' : '');
  const h = $('header.top h1'); if (h) h.textContent = rotuloCaso(CUR);
  desenhaSteps();
}

/* ---------- idade ---------- */
function setupIdade() {
  const f = findField('DN'); if (!f) return;
  const box = el('div', 'hint'); $('#w_' + f._id).appendChild(box);
  const upd = () => {
    const a = $('#' + f._id).value, fp = findField('Data da Perícia'), b = fp ? $('#' + fp._id).value : '';
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(a), n = /^(\d{4})-(\d{2})-(\d{2})$/.exec(b || todayIso());
    if (!m || !n) { box.textContent = ''; return; }
    const idade = n[1] - m[1] - ((n[2] + n[3]) < (m[2] + m[3]) ? 1 : 0);
    box.textContent = 'Idade ' + (b ? 'na data da perícia' : 'hoje') + ': ' + idade + ' anos' + (idade < 18 ? ' — menor de 18, confira a data' : '') + (idade > 120 || idade < 0 ? ' — data improvável' : '');
    box.style.color = (idade < 18 || idade > 120) ? 'var(--err)' : '';
  };
  ['DN', 'Data da Perícia'].forEach(k => { const x = findField(k); if (x) $('#' + x._id).addEventListener('change', upd); });
  upd();
}

/* ---------- quesitos ---------- */
let qList = null, qNone = null;
function renderQuesitos(f) {
  const w = el('div', 'field'); w.id = 'w_' + f._id;
  const lab = el('label', 't', f.label); lab.appendChild(el('span', 'req', ' *')); w.appendChild(lab);
  const l = el('label', 'chk'); qNone = el('input'); qNone.type = 'checkbox'; l.appendChild(qNone); l.appendChild(el('span', null, CACHE.semQuesitos)); w.appendChild(l);
  qList = el('div'); w.appendChild(qList);
  const acts = el('div', 'row'); acts.style.marginTop = '8px';
  acts.appendChild(btn('+ Adicionar quesito', 'small', () => { QST.none = false; QST.itens.push({ o: QST.itens.length ? QST.itens[QST.itens.length - 1].o : 'Juízo', q: '', r: '' }); drawQuesitos(); touched(); }));
  const pad = CACHE.quesitosPadrao || [];
  if (pad.length) acts.appendChild(btn('Inserir quesitos-padrão (' + pad.length + ')', 'small', () => { QST.none = false; pad.forEach(x => QST.itens.push({ o: normOrigem(x.origem), q: x.quesito, r: x.resposta })); drawQuesitos(); touched(); }));
  w.appendChild(acts);
  qNone.onchange = () => { QST.none = qNone.checked; drawQuesitos(); };
  return w;
}
function normOrigem(s) {
  s = String(s || '').toLowerCase();
  if (/ju[ií]z/.test(s)) return 'Juízo'; if (/minist|^mp/.test(s)) return 'Ministério Público';
  if (/requerente|autor/.test(s)) return 'Requerente'; if (/requerid|curador|r[eé]u/.test(s)) return 'Requerido'; return 'Outros';
}
function drawQuesitos() {
  if (!qList) return;
  qNone.checked = !!QST.none; qList.innerHTML = '';
  if (QST.none) return;
  let n = 0, last = null;
  QST.itens.forEach((it, i) => {
    if (it.o !== last) { n = 0; last = it.o; } n++;
    const b = el('div', 'q'); const top = el('div', 'topq'); const so = el('select');
    ORIGENS.forEach(o => { const op = el('option', null, o); op.value = o; so.appendChild(op); });
    so.value = it.o; so.onchange = () => { it.o = so.value; drawQuesitos(); touched(); };
    const rm = el('button', 'clear', 'remover'); rm.type = 'button'; rm.style.marginLeft = 'auto'; rm.onclick = () => { QST.itens.splice(i, 1); drawQuesitos(); touched(); };
    top.appendChild(el('b', null, n + '.')); top.appendChild(so); top.appendChild(rm); b.appendChild(top);
    const tq = el('textarea'); tq.placeholder = 'Quesito (pergunta)'; tq.value = it.q; tq.oninput = () => { it.q = tq.value; };
    const tr = el('textarea'); tr.placeholder = 'Resposta'; tr.value = it.r; tr.oninput = () => { it.r = tr.value; };
    b.appendChild(tq); b.appendChild(tr); qList.appendChild(b);
  });
}
function quesitosTexto() {
  if (QST.none) return CACHE.semQuesitos;
  const out = []; let last = null, n = 0;
  QST.itens.forEach(it => {
    const q = it.q.trim(), r = it.r.trim(); if (!q && !r) return;
    if (!q) { if (out.length) out.push(''); out.push(r); last = null; return; }
    if (it.o !== last) { if (out.length) out.push(''); out.push(ORIGEM_TXT[it.o] || ORIGEM_TXT.Outros); last = it.o; n = 0; }
    n++; out.push(n + '. ' + q); out.push('Resposta: ' + r);
  });
  return out.join('\n');
}
function lerQuesitos(json, texto) {
  let st = null; try { st = json ? JSON.parse(json) : null; } catch (e) { st = null; }
  if (st && Array.isArray(st.itens)) return { none: !!st.none, itens: st.itens };
  texto = String(texto || '').trim();
  if (!texto) return { none: false, itens: [] };
  if (texto.replace(/\.$/, '') === CACHE.semQuesitos) return { none: true, itens: [] };
  return { none: false, itens: [{ o: 'Outros', q: '', r: texto }] };
}
function quesitosPendentes() {
  if (QST.none) return '';
  const v = QST.itens.filter(i => i.q.trim() || i.r.trim());
  if (!v.length) return 'sem quesitos';
  return v.some(i => i.q.trim() && !i.r.trim()) ? 'quesito sem resposta' : '';
}

/* ---------- CID (busca local) ---------- */
function cidNorm(s) { let c = String(s).toUpperCase().replace(/\s+/g, '').replace(/\.$/, ''); if (/^[A-Z]\d{3}$/.test(c)) c = c.slice(0, 3) + '.' + c.slice(3); return c; }
function semAcento(s) { return String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, ''); }
function cidBusca(q) {
  const T = CACHE.cid.rows; q = String(q || '').trim(); if (q.length < 2) return [];
  const out = [];
  if (/^[A-Za-z]\d/.test(q)) { const code = cidNorm(q); for (let i = 0; i < T.length && out.length < 12; i++) if (T[i][0].indexOf(code) === 0) out.push(T[i]); }
  else { const toks = semAcento(q).split(/\s+/).filter(Boolean); for (let i = 0; i < T.length && out.length < 12; i++) { const r = T[i]; if (!r[2]) r[2] = semAcento(r[0] + ' ' + r[1]); if (toks.every(k => r[2].indexOf(k) >= 0)) out.push(r); } }
  return out;
}
function cidDescricao(texto) {
  const codes = []; (String(texto || '').match(/\b[A-Za-z]\d{2}(?:\.\d{1,2}|\d)?\b/g) || []).forEach(m => { const c = cidNorm(m); if (codes.indexOf(c) < 0) codes.push(c); });
  const map = {}; CACHE.cid.rows.forEach(r => { map[r[0]] = r[1]; }); const L = CACHE.cid.longos || {};
  const itens = []; codes.forEach(c => { const cat = c.slice(0, 3), d = map[c] || map[cat]; if (d) itens.push({ c: c, d: d, l: L[c] || L[cat] || '' }); });
  const fim = s => /[.!?]$/.test(s) ? s : s + '.';
  if (itens.length === 1 && itens[0].l) return itens[0].l;
  if (itens.some(i => i.l)) return itens.map(i => i.c + ' – ' + fim(i.d) + (i.l ? ' ' + fim(i.l) : '')).join('\n');
  return itens.map(i => i.c + ' – ' + i.d).join('; ');
}
function setupCid() {
  const fCid = findField('Discussão - Considerações diagnósticas - CID'), fDesc = findField('Discussão - Descrição CID'); if (!fCid || !fDesc) return;
  const inp = $('#' + fCid._id), desc = $('#' + fDesc._id), wrap = $('#w_' + fCid._id);
  wrap.appendChild(el('div', 'hint', 'Digite o código (ex.: F70.1) ou parte do nome da doença. A "Descrição do CID" é preenchida se estiver vazia.'));
  const box = el('div', 'sug'); wrap.appendChild(box); let lastAuto = '';
  const fill = () => { const t = cidDescricao(inp.value); if (t && (!desc.value.trim() || desc.value === lastAuto)) { desc.value = t; lastAuto = t; touched(); } };
  inp.addEventListener('input', () => {
    box.innerHTML = ''; const p = inp.value.split(/[,;]/);
    cidBusca(p[p.length - 1].trim()).forEach(it => {
      const b = el('button', null, it[0] + ' – ' + it[1]); b.type = 'button';
      b.onclick = () => { const parts = inp.value.split(/([,;])/); parts[parts.length - 1] = (parts.length > 1 ? ' ' : '') + it[0]; inp.value = parts.join(''); box.innerHTML = ''; fill(); touched(); };
      box.appendChild(b);
    });
  });
  inp.addEventListener('change', fill);
}

/* ============================ anotações à caneta ============================ */
const PW = 1000, PH = 1414; // página lógica (proporção A4)
function inkKey(id, key, i) { return 'ink:' + id + ':' + key + ':' + i; }

/**
 * Área de escrita com várias páginas. Só a caneta escreve; o dedo rola a tela
 * (a menos que "Dedo desenha" esteja ligado). Cada página é guardada cifrada, separadamente.
 */
function makeInk(key, label, parent, aberto) {
  const caso = CUR; let page = 0, strokes = [], tool = 'pen', finger = false, cur = null, saveT = null, loaded = false;
  const bar = el('div', 'inkbar');
  const mk = (t, fn) => { const b = el('button', null, t); b.type = 'button'; b.onclick = fn; bar.appendChild(b); return b; };
  const bPen = mk('Caneta', () => setTool('pen')), bEr = mk('Borracha', () => setTool('eraser'));
  mk('Desfazer', () => { if (strokes.length) { strokes.pop(); redraw(); changed(); } });
  mk('Limpar página', () => { if (strokes.length && confirm('Apagar tudo desta página?')) { strokes = []; redraw(); changed(); } });
  const bPrev = mk('◀', () => go(page - 1)); const pg = el('span', 'pg'); bar.appendChild(pg); const bNext = mk('▶', () => go(page + 1));
  mk('+ Página', () => go(count()));
  const bF = mk('Dedo desenha: não', () => { finger = !finger; bF.textContent = 'Dedo desenha: ' + (finger ? 'sim' : 'não'); bF.classList.toggle('on', finger); });
  parent.appendChild(bar);
  const cv = el('canvas', 'ink'); cv.dataset.key = key; parent.appendChild(cv); const ctx = cv.getContext('2d');
  function count() { return Math.max(caso.ink[key] || 0, 1); }
  function setTool(t) { tool = t; bPen.classList.toggle('on', t === 'pen'); bEr.classList.toggle('on', t === 'eraser'); }
  function label2() { pg.textContent = 'pág. ' + (page + 1) + '/' + count(); bPrev.disabled = page === 0; bNext.disabled = page >= count() - 1; }
  function resize() {
    const w = cv.clientWidth; if (!w) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.style.height = Math.round(w * PH / PW) + 'px'; cv.width = Math.round(w * dpr); cv.height = Math.round(w * PH / PW * dpr);
    redraw();
  }
  function seg(c, k, a, b) { c.lineWidth = Math.max(0.6, 2.6 * k * (0.35 + 1.1 * (b[2] || 0.5))); c.beginPath(); c.moveTo(a[0] * k, a[1] * k); c.lineTo(b[0] * k, b[1] * k); c.stroke(); }
  function redraw() {
    const k = cv.width / PW; ctx.clearRect(0, 0, cv.width, cv.height); ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.strokeStyle = '#10243e';
    strokes.forEach(s => drawStroke(ctx, k, s));
  }
  function drawStroke(c, k, s) {
    if (s.length === 3) { c.fillStyle = '#10243e'; c.beginPath(); c.arc(s[0] * k, s[1] * k, 1.6 * k, 0, 6.3); c.fill(); return; }
    for (let i = 3; i < s.length; i += 3) seg(c, k, [s[i - 3], s[i - 2], s[i - 1] / 100], [s[i], s[i + 1], s[i + 2] / 100]);
  }
  async function load() { strokes = (await getS(inkKey(caso.id, key, page))) || []; loaded = true; redraw(); label2(); }
  async function persist() {
    clearTimeout(saveT);
    await putS(inkKey(caso.id, key, page), strokes);
    if ((caso.ink[key] || 0) < page + 1 && strokes.length) caso.ink[key] = page + 1;
    caso.inkDirty = true; caso.updatedAt = Date.now(); await saveCase(caso);
    const w = parent.closest('.field'); if (w && w._badge) w._badge();
    const s = $('#saveInfo'); if (s) s.textContent = 'Anotação guardada no tablet às ' + quando(Date.now()).slice(6) + ' — ainda não enviada';
    label2();
  }
  function changed() { clearTimeout(saveT); saveT = setTimeout(persist, 500); }
  async function go(i) { if (i < 0 || i > count()) return; if (saveT) await persist(); if (i >= count()) caso.ink[key] = i + 1; page = i; await load(); }
  function pos(e) { const r = cv.getBoundingClientRect(); return [Math.round((e.clientX - r.left) / r.width * PW * 10) / 10, Math.round((e.clientY - r.top) / r.height * PH * 10) / 10, Math.round((e.pressure || 0.5) * 100)]; }
  function erase(p) { const n = strokes.length; strokes = strokes.filter(s => { for (let i = 0; i < s.length; i += 3) if (Math.abs(s[i] - p[0]) < 16 && Math.abs(s[i + 1] - p[1]) < 16) return false; return true; }); if (strokes.length !== n) { redraw(); changed(); } }
  let scrollY = null;
  cv.addEventListener('pointerdown', e => {
    if (!loaded) return;
    const desenha = e.pointerType === 'pen' || e.pointerType === 'mouse' || finger;
    if (!desenha) { scrollY = e.clientY; return; }
    e.preventDefault(); try { cv.setPointerCapture(e.pointerId); } catch (x) { /* ponteiro já liberado */ }
    const p = pos(e);
    if (tool === 'eraser' || (e.buttons & 32)) { cur = 'erase'; erase(p); return; }
    cur = [p[0], p[1], p[2]];
  });
  cv.addEventListener('pointermove', e => {
    if (scrollY != null && e.pointerType === 'touch' && !finger) { window.scrollBy(0, scrollY - e.clientY); scrollY = e.clientY; return; }
    if (!cur) return; e.preventDefault();
    const evs = e.getCoalescedEvents ? e.getCoalescedEvents() : [e]; const k = cv.width / PW;
    (evs.length ? evs : [e]).forEach(ev => {
      const p = pos(ev);
      if (cur === 'erase') return erase(p);
      const n = cur.length; if (Math.abs(p[0] - cur[n - 3]) < 1.2 && Math.abs(p[1] - cur[n - 2]) < 1.2) return;
      ctx.lineCap = 'round'; ctx.strokeStyle = '#10243e'; seg(ctx, k, [cur[n - 3], cur[n - 2], cur[n - 1] / 100], [p[0], p[1], p[2] / 100]);
      cur.push(p[0], p[1], p[2]);
    });
  });
  const fim = () => { scrollY = null; if (!cur) return; if (cur !== 'erase') { strokes.push(cur); if (cur.length === 3) redraw(); changed(); } cur = null; };
  cv.addEventListener('pointerup', fim); cv.addEventListener('pointercancel', fim);
  window.addEventListener('resize', () => { if (cv.isConnected && cv.clientWidth) resize(); });
  setTool('pen'); load().then(() => { if (aberto || cv.clientWidth) resize(); });
  return { resize: resize, flush: persist };
}

/* ---------- PDF das anotações (gerado no próprio tablet) ---------- */
async function inkPdf(caso) {
  const fields = allFields().filter(f => f.type === 'textarea').map(f => [f.key, f.label]).concat([[NOTAS_KEY, 'Anotações gerais']]);
  const W = 1240, H = 1754, jpgs = [];
  const total = fields.reduce((n, f) => n + (caso.ink[f[0]] || 0), 0);
  for (const f of fields) {
    const n = caso.ink[f[0]] || 0;
    for (let i = 0; i < n; i++) {
      const st = (await getS(inkKey(caso.id, f[0], i))) || [];
      if (!st.length) continue;
      const c = document.createElement('canvas'); c.width = W; c.height = H; const x = c.getContext('2d');
      x.fillStyle = '#fff'; x.fillRect(0, 0, W, H); x.fillStyle = '#333'; x.font = '22px sans-serif';
      x.fillText(rotuloCaso(caso), 24, 30); x.fillText(f[1] + ' — pág. ' + (i + 1) + '/' + n + ' — exportado em ' + quando(Date.now()), 24, 56);
      x.strokeStyle = '#999'; x.lineWidth = 1; x.beginPath(); x.moveTo(20, 66); x.lineTo(W - 20, 66); x.stroke();
      x.save(); x.translate(20, 70); x.lineCap = 'round'; x.strokeStyle = '#10243e'; const k = 1.19;
      st.forEach(s => {
        if (s.length === 3) { x.fillStyle = '#10243e'; x.beginPath(); x.arc(s[0] * k, s[1] * k, 2, 0, 6.3); x.fill(); return; }
        for (let j = 3; j < s.length; j += 3) { x.lineWidth = Math.max(0.8, 2.6 * k * (0.35 + 1.1 * (s[j + 2] / 100 || 0.5))); x.beginPath(); x.moveTo(s[j - 3] * k, s[j - 2] * k); x.lineTo(s[j] * k, s[j + 1] * k); x.stroke(); }
      });
      x.restore();
      const blob = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.82));
      jpgs.push(new Uint8Array(await blob.arrayBuffer()));
    }
  }
  if (!total || !jpgs.length) return null;
  return pdfDeJpegs(jpgs, W, H);
}
/** Monta um PDF mínimo com uma imagem JPEG por página (A4). */
function pdfDeJpegs(jpgs, w, h) {
  const enc = new TextEncoder(), parts = [], offs = []; let len = 0;
  const add = x => { const u = typeof x === 'string' ? enc.encode(x) : x; parts.push(u); len += u.length; };
  const obj = (n, body) => { offs[n] = len; add(n + ' 0 obj\n' + body + '\nendobj\n'); };
  add('%PDF-1.4\n%âãÏÓ\n');
  const n = jpgs.length, kids = [];
  for (let i = 0; i < n; i++) kids.push((3 + i * 3) + ' 0 R');
  obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
  obj(2, '<< /Type /Pages /Count ' + n + ' /Kids [' + kids.join(' ') + '] >>');
  jpgs.forEach((j, i) => {
    const p = 3 + i * 3, c = p + 1, im = p + 2, cont = 'q 595 0 0 842 0 0 cm /Im0 Do Q';
    obj(p, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /XObject << /Im0 ' + im + ' 0 R >> >> /Contents ' + c + ' 0 R >>');
    obj(c, '<< /Length ' + cont.length + ' >>\nstream\n' + cont + '\nendstream');
    offs[im] = len; add(im + ' 0 obj\n<< /Type /XObject /Subtype /Image /Width ' + w + ' /Height ' + h + ' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ' + j.length + ' >>\nstream\n'); add(j); add('\nendstream\nendobj\n');
  });
  const tot = 3 + n * 3, xref = len;
  let x = 'xref\n0 ' + tot + '\n0000000000 65535 f \n';
  for (let i = 1; i < tot; i++) x += ('0000000000' + offs[i]).slice(-10) + ' 00000 n \n';
  add(x + 'trailer\n<< /Size ' + tot + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n');
  const out = new Uint8Array(len); let o = 0; parts.forEach(u => { out.set(u, o); o += u.length; });
  return out;
}

/* ============================ partida ============================ */
(async function start() {
  if ('serviceWorker' in navigator) {
    const tinha = !!navigator.serviceWorker.controller;
    // quando chega uma versão nova do app, recarrega sozinho (desde que não haja um caso aberto)
    navigator.serviceWorker.addEventListener('controllerchange', () => { if (tinha && !CUR) location.reload(); });
    try { await navigator.serviceWorker.register('sw.js'); } catch (e) { /* segue sem cache offline */ }
  }
  if (navigator.storage && navigator.storage.persist) { try { await navigator.storage.persist(); } catch (e) { /* opcional */ } }
  if (!window.crypto || !crypto.subtle || !window.indexedDB) { app().textContent = 'Este navegador não oferece os recursos necessários (abra pelo Chrome, em endereço https).'; return; }
  await idbOpen();
  // sessão mantida: se o tablet já foi desbloqueado e não houve "Bloquear", entra direto
  const meta = await idb.get('meta'), sess = await idb.get('sess');
  if (meta && sess) {
    KEY = sess;
    try { await unseal(meta.check); await loadAll(); return CFG ? telaInicio() : telaConfig(); } catch (e) { KEY = null; await idb.del('sess'); }
  }
  telaPin();
})();
