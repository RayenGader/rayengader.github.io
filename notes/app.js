'use strict';
/*
 * Carnet : les notes vivent dans un fichier JSON d'un dépôt GitHub PRIVÉ.
 * La page (publique) ne contient aucune note : elle les lit et les écrit
 * via l'API GitHub avec un token fine-grained limité à ce seul dépôt.
 */
(() => {

// --- pure:start (fonctions sans DOM, testables) -------------------------
const COLORS = ['yellow', 'pink', 'mint', 'lilac', 'blue'];

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function inline(text) {
  let s = esc(text);
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  s = s.replace(/(^|[\s(])(https?:\/\/[^\s<]*[^\s<.,;:!?)])/g,
    (m, pre, url) => `${pre}<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`);
  return s;
}

function listItem(text) {
  const kv = text.match(/^\*\*(.+?)\*\*\s*:?\s*(.*)$/);
  if (kv) return `<li class="kv"><b>${inline(kv[1])}</b><span>${inline(kv[2])}</span></li>`;
  return `<li><span>${inline(text)}</span></li>`;
}

function md(src) {
  const lines = String(src || '').replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  let para = [];
  let list = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${para.map(inline).join('<br>')}</p>`); para = []; } };
  const flushList = () => { if (list.length) { out.push(`<ul>${list.map(listItem).join('')}</ul>`); list = []; } };
  const flush = () => { flushPara(); flushList(); };

  for (let i = 0; i < lines.length; i++) {
    const tr = lines[i].trim();
    let m;
    if (tr.startsWith('```')) {
      flush();
      const label = tr.slice(3).trim();
      const code = [];
      i++;
      while (i < lines.length && lines[i].trim() !== '```') { code.push(lines[i]); i++; }
      out.push(
        `<div class="code"><div class="code-head"><span>${esc(label || 'code')}</span>` +
        `<button type="button" class="copy" data-act="copy">copier</button></div>` +
        `<pre>${esc(code.join('\n'))}</pre></div>`);
    } else if (!tr) {
      flush();
    } else if ((m = tr.match(/^[-*]\s+(.*)$/))) {
      flushPara(); list.push(m[1]);
    } else if ((m = tr.match(/^>\s?(.*)$/))) {
      flush(); out.push(`<p class="callout">${inline(m[1])}</p>`);
    } else if ((m = tr.match(/^!\s?(.*)$/))) {
      flush(); out.push(`<p class="warn">${inline(m[1])}</p>`);
    } else if (/^https?:\/\/\S+$/.test(tr)) {
      flush();
      const shown = tr.replace(/^https?:\/\//, '');
      out.push(
        `<div class="link"><a href="${esc(tr)}" target="_blank" rel="noopener noreferrer">${esc(shown)}</a>` +
        `<button type="button" class="copy" data-act="copy" data-copy="${esc(tr)}">copier le lien</button></div>`);
    } else {
      flushList(); para.push(lines[i].trim());
    }
  }
  flush();
  return out.join('');
}

function uid() {
  if (globalThis.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'n' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

function normalizeNote(n, i) {
  const now = Date.now();
  return {
    id: typeof n.id === 'string' && n.id ? n.id.slice(0, 64) : uid(),
    title: String(n.title ?? '').slice(0, 80),
    tag: String(n.tag ?? '').slice(0, 40),
    color: COLORS.includes(n.color) ? n.color : 'yellow',
    body: String(n.body ?? ''),
    pinned: n.pinned === true,
    created: Number.isFinite(n.created) ? n.created : now + i,
    updated: Number.isFinite(n.updated) ? n.updated : now
  };
}

function normalize(data) {
  const list = Array.isArray(data) ? data : (data && Array.isArray(data.notes) ? data.notes : []);
  const seen = new Set();
  const notes = [];
  list.forEach((n, i) => {
    if (!n || typeof n !== 'object') return;
    const note = normalizeNote(n, i);
    if (seen.has(note.id)) note.id = uid();
    seen.add(note.id);
    notes.push(note);
  });
  return { version: 1, notes };
}

function fold(s) {
  return String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

function b64enc(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function b64dec(b64) {
  const bin = atob(String(b64).replace(/\s/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
// --- pure:end -------------------------------------------------------------

if (typeof document === 'undefined') {
  globalThis.__carnet = { md, esc, normalize, fold, b64enc, b64dec };
  return;
}

const $ = (s, r = document) => r.querySelector(s);
const API = 'https://api.github.com';
const AUTH_KEY = 'carnet.auth.v1';
const ICON = {
  pin: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16v6M8 3h8l-1.2 6.5L18 13v2H6v-2l3.2-3.5z"/></svg>',
  edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17z"/></svg>',
  del: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13"/></svg>'
};

let auth = null;              // { repo, path, token, branch }
let state = { version: 1, notes: [] };
let sha = null;               // sha du fichier distant
let unsynced = [];            // opérations pas encore écrites sur GitHub
let flushing = false;
let filterTag = '';
let query = '';
let editingId = null;
let editorSnapshot = '';

// ---------- stockage du token ----------
function loadAuth() {
  for (const get of [() => localStorage, () => sessionStorage]) {
    try { const v = get().getItem(AUTH_KEY); if (v) return JSON.parse(v); } catch (e) { /* stockage indisponible */ }
  }
  return null;
}
function saveAuth(a, remember) {
  clearAuth();
  try { (remember ? localStorage : sessionStorage).setItem(AUTH_KEY, JSON.stringify(a)); } catch (e) { /* ignoré */ }
}
function clearAuth() {
  try { localStorage.removeItem(AUTH_KEY); } catch (e) { /* ignoré */ }
  try { sessionStorage.removeItem(AUTH_KEY); } catch (e) { /* ignoré */ }
}

// ---------- API GitHub ----------
class AuthError extends Error {}

async function gh(path, opts = {}) {
  const headers = { Authorization: 'Bearer ' + auth.token, Accept: 'application/vnd.github+json' };
  if (opts.body) headers['Content-Type'] = 'application/json';
  try {
    return await fetch(API + path, { method: opts.method || 'GET', headers, body: opts.body });
  } catch (e) {
    throw new Error('Pas de connexion à GitHub. Vérifie ton réseau.');
  }
}
function repoPath() {
  const [o, r] = auth.repo.split('/');
  return `/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}`;
}
function filePath() {
  return repoPath() + '/contents/' + auth.path.split('/').map(encodeURIComponent).join('/');
}

async function checkRepo() {
  const res = await gh(repoPath());
  if (res.status === 401) throw new AuthError('GitHub refuse ce token. Vérifie-le ou crée-en un nouveau.');
  if (res.status === 403 || res.status === 404) throw new AuthError(`Dépôt « ${auth.repo} » introuvable, ou le token n'y a pas accès.`);
  if (!res.ok) throw new Error(`GitHub a répondu ${res.status}. Réessaie dans un instant.`);
  const info = await res.json();
  auth.branch = info.default_branch || 'main';
  return info;
}

async function fetchRemote() {
  const res = await gh(`${filePath()}?ref=${encodeURIComponent(auth.branch)}&_=${Date.now()}`);
  if (res.status === 404) return { data: { version: 1, notes: [] }, sha: null };
  if (res.status === 401) throw new AuthError('Ta session a expiré. Reconnecte-toi.');
  if (!res.ok) throw new Error(`Lecture des notes impossible (${res.status}).`);
  const j = await res.json();
  let data;
  try { data = JSON.parse(b64dec(j.content || '')); }
  catch (e) { throw new Error(`Le fichier ${auth.path} n'est pas un JSON valide.`); }
  return { data: normalize(data), sha: j.sha };
}

async function putRemote(data, message) {
  const body = { message, content: b64enc(JSON.stringify(data, null, 2) + '\n'), branch: auth.branch };
  if (sha) body.sha = sha;
  const res = await gh(filePath(), { method: 'PUT', body: JSON.stringify(body) });
  if (res.ok) { sha = (await res.json()).content.sha; return true; }
  if (res.status === 409 || res.status === 422) return false;   // le fichier a changé ailleurs
  if (res.status === 401) throw new AuthError('Ta session a expiré. Reconnecte-toi.');
  if (res.status === 403 || res.status === 404) throw new Error('Le token ne peut pas écrire : il faut la permission Contents « Read and write ».');
  throw new Error(`Enregistrement refusé par GitHub (${res.status}).`);
}

// ---------- synchronisation ----------
function commit(op, message) {
  unsynced.push({ op, message });
  state = op(structuredClone(state));
  render();
  flush();
}

async function flush() {
  if (flushing || !unsynced.length) return;
  flushing = true;
  setStatus('saving');
  try {
    while (unsynced.length) {
      const batch = unsynced.length;
      const message = batch === 1 ? unsynced[0].message : `carnet : ${batch} modifications`;
      let ok = await putRemote(state, message);
      if (!ok) {
        // Quelqu'un (un autre appareil) a modifié le fichier : on rejoue nos changements par-dessus.
        const remote = await fetchRemote();
        sha = remote.sha;
        state = unsynced.reduce((s, u) => u.op(s), remote.data);
        render();
        ok = await putRemote(state, message);
        if (!ok) throw new Error('Conflit avec une autre modification. Recharge depuis GitHub.');
      }
      unsynced.splice(0, batch);
    }
    setStatus('ok');
  } catch (e) {
    if (e instanceof AuthError) { logout(e.message); return; }
    setStatus('error', e.message);
  } finally {
    flushing = false;
  }
}

function setStatus(kind, detail) {
  const el = $('#status');
  el.dataset.state = kind;
  el.textContent = kind === 'ok' ? 'enregistré sur GitHub'
    : kind === 'saving' ? 'enregistrement…'
    : 'pas enregistré · réessayer';
  el.title = detail || '';
  if (kind === 'error' && detail) toast(detail);
}

// ---------- rendu ----------
function noteHTML(n) {
  return `<article class="note ${n.color}${n.pinned ? ' pinned' : ''}" data-id="${esc(n.id)}">
  <div class="note-head">
    <span class="tag">${esc(n.tag)}</span>
    <div class="note-tools">
      <button type="button" class="ic" data-act="pin" aria-pressed="${n.pinned}" aria-label="${n.pinned ? 'Désépingler' : 'Épingler en haut'}" title="${n.pinned ? 'Désépingler' : 'Épingler en haut'}">${ICON.pin}</button>
      <button type="button" class="ic" data-act="edit" aria-label="Modifier" title="Modifier">${ICON.edit}</button>
      <button type="button" class="ic" data-act="del" aria-label="Supprimer" title="Supprimer">${ICON.del}</button>
    </div>
  </div>
  <h2>${esc(n.title || 'sans titre')}</h2>
  <div class="note-body">${md(n.body)}</div>
  <div class="confirm" hidden>Supprimer ce post-it ?
    <button type="button" class="btn small primary" data-act="del-yes">supprimer</button>
    <button type="button" class="btn small ghost" data-act="del-no">garder</button>
  </div>
</article>`;
}

function render() {
  const tags = [...new Set(state.notes.map(n => n.tag).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'fr'));
  if (filterTag && !tags.includes(filterTag)) filterTag = '';
  $('#tags').innerHTML = tags.length
    ? ['', ...tags].map(t => `<button type="button" class="chip" data-tag="${esc(t)}" aria-pressed="${t === filterTag}">${t ? esc(t) : 'toutes'}</button>`).join('')
    : '';
  $('#tag-list').innerHTML = tags.map(t => `<option value="${esc(t)}"></option>`).join('');

  const q = fold(query.trim());
  const shown = state.notes
    .filter(n => (!filterTag || n.tag === filterTag) && (!q || fold(`${n.title} ${n.tag} ${n.body}`).includes(q)))
    .sort((a, b) => (Number(b.pinned) - Number(a.pinned)) || (a.created - b.created));
  $('#grid').innerHTML = shown.map(noteHTML).join('');
  $('#empty').hidden = state.notes.length > 0;
  $('#nores').hidden = state.notes.length === 0 || shown.length > 0;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
}

async function copyText(text, btn) {
  const label = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'copié !';
  } catch (e) {
    const node = btn.closest('.code')?.querySelector('pre') || btn.closest('.link')?.querySelector('a');
    if (node) { const r = document.createRange(); r.selectNodeContents(node); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }
    btn.textContent = 'sélectionné';
  }
  setTimeout(() => { btn.textContent = label; }, 1500);
}

// ---------- écrans ----------
function showLogin(message) {
  $('#boot').hidden = true;
  $('#main').hidden = true;
  $('#login').hidden = false;
  const err = $('#l-error');
  err.textContent = message || '';
  err.hidden = !message;
  if (auth && auth.repo) $('#l-repo').value = auth.repo;
  $('#l-token').value = '';
  $('#l-token').focus();
}

async function open(a, remember) {
  auth = { repo: a.repo.trim(), path: a.path || 'notes.json', token: a.token.trim() };
  const info = await checkRepo();
  const remote = await fetchRemote();
  state = remote.data;
  sha = remote.sha;
  unsynced = [];
  if (remember !== undefined) saveAuth({ repo: auth.repo, path: auth.path, token: auth.token }, remember);
  $('#public-warn').hidden = info.private !== false;
  $('#boot').hidden = true;
  $('#login').hidden = true;
  $('#main').hidden = false;
  render();
  setStatus('ok');
}

function logout(message) {
  clearAuth();
  const repo = auth && auth.repo;
  auth = repo ? { repo } : null;
  state = { version: 1, notes: [] };
  sha = null;
  unsynced = [];
  $('#grid').innerHTML = '';
  showLogin(message);
}

// ---------- éditeur ----------
function editorValues() {
  return {
    title: $('#f-title').value.trim(),
    tag: $('#f-tag').value.trim(),
    color: (document.querySelector('input[name="f-color"]:checked') || {}).value || 'yellow',
    body: $('#f-body').value.replace(/\s+$/, '')
  };
}

function openEditor(id) {
  const n = id ? state.notes.find(x => x.id === id) : null;
  editingId = n ? n.id : null;
  $('#ed-title').textContent = n ? 'modifier le post-it' : 'nouveau post-it';
  $('#f-title').value = n ? n.title : '';
  $('#f-tag').value = n ? n.tag : (filterTag || '');
  $('#f-body').value = n ? n.body : '';
  const color = n ? n.color : 'yellow';
  document.querySelectorAll('input[name="f-color"]').forEach(r => { r.checked = r.value === color; });
  setTab('write');
  $('#ed-dirty').hidden = true;
  editorSnapshot = JSON.stringify(editorValues());
  $('#editor').showModal();
  $('#f-title').focus();
}

function editorDirty() { return JSON.stringify(editorValues()) !== editorSnapshot; }

function closeEditor(force) {
  if (!force && editorDirty()) { $('#ed-dirty').hidden = false; return; }
  $('#editor').close();
}

function setTab(tab) {
  const preview = tab === 'preview';
  document.querySelectorAll('.tabs [data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === tab)));
  $('#f-body').hidden = preview;
  $('#f-preview').hidden = !preview;
  if (preview) {
    const v = editorValues();
    $('#f-preview').className = `note-body preview note ${v.color}`;
    $('#f-preview').innerHTML = md(v.body) || '<p class="warn">Rien à afficher pour l\'instant.</p>';
  }
}

function saveEditor() {
  const v = editorValues();
  if (!v.title) { $('#f-title').focus(); return; }
  const id = editingId || uid();
  const isNew = !editingId;
  const now = Date.now();
  commit(s => {
    const n = s.notes.find(x => x.id === id);
    if (n) Object.assign(n, v, { updated: now });
    else s.notes.push({ id, ...v, pinned: false, created: now, updated: now });
    return s;
  }, `carnet : ${isNew ? 'ajoute' : 'modifie'} « ${v.title} »`);
  $('#editor').close();
  if (isNew) {
    filterTag = filterTag && filterTag !== v.tag ? '' : filterTag;
    query = ''; $('#search').value = '';
    render();
  }
  const el = document.querySelector(`.note[data-id="${CSS.escape(id)}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash');
  }
}

// ---------- import / export ----------
function exportNotes() {
  const blob = new Blob([JSON.stringify(state, null, 2) + '\n'], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `carnet-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function importNotes(file) {
  let incoming;
  try { incoming = normalize(JSON.parse(await file.text())).notes; }
  catch (e) { toast('Ce fichier n\'est pas un JSON de carnet valide.'); return; }
  const ids = new Set(state.notes.map(n => n.id));
  const fresh = incoming.filter(n => !ids.has(n.id));
  if (!fresh.length) { toast('Rien de nouveau : ces notes sont déjà dans le carnet.'); return; }
  commit(s => {
    const have = new Set(s.notes.map(n => n.id));
    fresh.forEach(n => { if (!have.has(n.id)) s.notes.push(structuredClone(n)); });
    return s;
  }, `carnet : importe ${fresh.length} note(s)`);
  toast(`${fresh.length} note(s) importée(s).`);
}

// ---------- événements ----------
$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('#l-submit');
  btn.disabled = true; btn.textContent = 'ouverture…';
  $('#l-error').hidden = true;
  try {
    await open({ repo: $('#l-repo').value, token: $('#l-token').value }, $('#l-remember').checked);
  } catch (err) {
    showLogin(err.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Ouvrir mon carnet';
  }
});

$('#new-btn').addEventListener('click', () => openEditor());
$('#search').addEventListener('input', e => { query = e.target.value; render(); });
$('#status').addEventListener('click', () => { if ($('#status').dataset.state === 'error') flush(); });

$('#tags').addEventListener('click', e => {
  const b = e.target.closest('[data-tag]');
  if (!b) return;
  filterTag = b.dataset.tag;
  render();
});

const menu = $('#menu');
$('#menu-btn').addEventListener('click', e => {
  e.stopPropagation();
  menu.hidden = !menu.hidden;
  $('#menu-btn').setAttribute('aria-expanded', String(!menu.hidden));
});
document.addEventListener('click', e => {
  if (!menu.hidden && !e.target.closest('.menu')) { menu.hidden = true; $('#menu-btn').setAttribute('aria-expanded', 'false'); }
});

document.addEventListener('click', async e => {
  const m = e.target.closest('[data-menu]');
  if (m) {
    menu.hidden = true;
    $('#menu-btn').setAttribute('aria-expanded', 'false');
    const act = m.dataset.menu;
    if (act === 'new') openEditor();
    if (act === 'export') exportNotes();
    if (act === 'import') $('#import-file').click();
    if (act === 'logout') logout();
    if (act === 'reload') {
      if (unsynced.length) { toast('Attends la fin de l\'enregistrement.'); return; }
      try { const r = await fetchRemote(); state = r.data; sha = r.sha; render(); toast('Carnet rechargé.'); }
      catch (err) { if (err instanceof AuthError) logout(err.message); else toast(err.message); }
    }
    return;
  }

  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  if (act === 'copy') {
    const text = btn.dataset.copy ?? btn.closest('.code')?.querySelector('pre')?.textContent ?? '';
    copyText(text, btn);
    return;
  }
  const card = btn.closest('.note[data-id]');
  if (!card) return;
  const id = card.dataset.id;
  const note = state.notes.find(n => n.id === id);
  if (!note) return;
  if (act === 'edit') openEditor(id);
  if (act === 'pin') {
    const value = !note.pinned;
    commit(s => { const n = s.notes.find(x => x.id === id); if (n) n.pinned = value; return s; },
      `carnet : ${value ? 'épingle' : 'désépingle'} « ${note.title} »`);
  }
  if (act === 'del') { card.querySelector('.confirm').hidden = false; card.querySelector('[data-act="del-no"]').focus(); }
  if (act === 'del-no') card.querySelector('.confirm').hidden = true;
  if (act === 'del-yes') {
    commit(s => { s.notes = s.notes.filter(x => x.id !== id); return s; }, `carnet : supprime « ${note.title} »`);
    toast('Post-it supprimé.');
  }
});

$('#import-file').addEventListener('change', e => {
  const f = e.target.files && e.target.files[0];
  if (f) importNotes(f);
  e.target.value = '';
});

$('#ed-form').addEventListener('submit', e => { e.preventDefault(); saveEditor(); });
$('#ed-cancel').addEventListener('click', () => closeEditor(false));
$('#ed-discard').addEventListener('click', () => closeEditor(true));
$('#ed-keep').addEventListener('click', () => { $('#ed-dirty').hidden = true; $('#f-body').focus(); });
$('#editor').addEventListener('cancel', e => { if (editorDirty()) { e.preventDefault(); $('#ed-dirty').hidden = false; } });
$('#editor').addEventListener('click', e => { const t = e.target.closest('[data-tab]'); if (t) setTab(t.dataset.tab); });
$('#editor').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); saveEditor(); }
});
$('#f-body').addEventListener('keydown', e => {
  if (e.key === 'Tab' && !e.shiftKey) {
    e.preventDefault();
    const t = e.target, a = t.selectionStart, b = t.selectionEnd;
    t.value = t.value.slice(0, a) + '  ' + t.value.slice(b);
    t.selectionStart = t.selectionEnd = a + 2;
  }
});

document.addEventListener('keydown', e => {
  if ($('#main').hidden || $('#editor').open || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.target.closest('input, textarea, select, [contenteditable]')) return;
  if (e.key === '/') { e.preventDefault(); $('#search').focus(); }
  if (e.key === 'n') { e.preventDefault(); openEditor(); }
});

window.addEventListener('online', () => flush());
window.addEventListener('beforeunload', e => { if (unsynced.length) { e.preventDefault(); e.returnValue = ''; } });

// ---------- démarrage ----------
(async () => {
  const saved = loadAuth();
  if (!saved || !saved.token) { showLogin(); return; }
  try { await open(saved); }
  catch (err) {
    auth = { repo: saved.repo };
    if (err instanceof AuthError) clearAuth();
    showLogin(err.message);
  }
})();

})();
