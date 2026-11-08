'use strict';

const MAX_ROWS = 5000;
const state = {
  files: [],
  deselected: new Set(),
  fieldsTimer: null,
  stream: null,
  searchSeq: 0,
};

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [key, val] of Object.entries(props)) {
    if (val === false || val === null || val === undefined) continue;
    if (key === 'class') node.className = val;
    else if (key === 'text') node.textContent = val;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), val);
    else node.setAttribute(key, val === true ? '' : val);
  }
  for (const kid of kids) node.append(kid);
  return node;
}

function setStatus(text, kind = '') {
  const s = $('#status');
  s.textContent = text;
  s.className = 'status' + (kind ? ' ' + kind : '');
}

async function api(path, params) {
  const res = await fetch(path + '?' + params.toString(), { credentials: 'same-origin' });
  let body = null;
  try { body = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new Error((body && body.error) || ('Request failed with status ' + res.status));
  return body;
}

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + units[i];
}

/* ---------- Files ---------- */

function selectedFileParams() {
  const params = new URLSearchParams();
  if (state.deselected.size === 0) return params;      // empty means every readable file
  for (const f of state.files) {
    if (f.readable && !state.deselected.has(f.id)) params.append('file', f.id);
  }
  return params;
}

function selectionIsEmpty() {
  return state.files.every(f => !f.readable || state.deselected.has(f.id));
}

async function loadFiles() {
  const data = await api('/api/files', new URLSearchParams());
  state.files = data.files;
  $('#title').textContent = data.host;
  renderFiles();
}

function renderFiles() {
  const filter = $('#files-filter').value.trim().toLowerCase();
  const list = $('#files');
  list.replaceChildren();
  for (const f of state.files) {
    if (filter && !f.id.toLowerCase().includes(filter)) continue;
    const id = 'f-' + btoa(unescape(encodeURIComponent(f.id))).replace(/[^A-Za-z0-9]/g, '');
    const box = el('input', {
      type: 'checkbox', id, disabled: !f.readable,
      checked: f.readable && !state.deselected.has(f.id),
      onchange: (ev) => {
        if (ev.target.checked) state.deselected.delete(f.id); else state.deselected.add(f.id);
        fieldsSoon();
      },
    });
    const size = f.readable ? fmtSize(f.size) : 'no read access';
    list.append(el('li', { class: f.readable ? '' : 'denied' },
      box, el('label', { for: id, text: f.id }), el('span', { class: 'size', text: size })));
  }
}

function setAllFiles(on) {
  const filter = $('#files-filter').value.trim().toLowerCase();
  for (const f of state.files) {
    if (filter && !f.id.toLowerCase().includes(filter)) continue;
    if (on) state.deselected.delete(f.id); else state.deselected.add(f.id);
  }
  renderFiles();
  fieldsSoon();
}

/* ---------- Fields ---------- */

function fieldsSoon() {
  clearTimeout(state.fieldsTimer);
  state.fieldsTimer = setTimeout(loadFields, 400);
}

async function loadFields() {
  const list = $('#fields');
  if (selectionIsEmpty()) { list.replaceChildren(); return; }
  try {
    const data = await api('/api/fields', selectedFileParams());
    renderFields(data.fields);
  } catch (err) {
    list.replaceChildren(el('li', { class: 'note', text: err.message }));
  }
}

function renderFields(fields) {
  const list = $('#fields');
  list.replaceChildren();
  for (const f of fields) {
    const values = el('ul', { hidden: true });
    for (const [val, count] of f.values) {
      values.append(el('li', {},
        el('button', {
          type: 'button', title: 'Add ' + f.name + '=' + val + ' to the search',
          onclick: () => addTerm(f.name, val, false),
        }, el('span', { class: 'v', text: val }), el('span', { class: 'count', text: String(count) }))));
    }
    const name = el('button', {
      type: 'button', class: 'name', 'aria-expanded': 'false',
      onclick: (ev) => {
        const open = values.hidden;
        values.hidden = !open;
        ev.currentTarget.setAttribute('aria-expanded', String(open));
        if (open && f.values.length === 0) {
          addTerm(f.name, '*', false);   // fields without value lists filter on "has this field"
          values.hidden = true;
        }
      },
    }, el('span', { text: f.name }), el('span', { class: 'count', text: String(f.count) }));
    list.append(el('li', {}, name, values));
  }
}

/* ---------- Query building ---------- */

function quoteValue(v) {
  if (v === '*' || /^[^\s"\\]+$/.test(v)) return v;
  return '"' + v.replace(/(["\\])/g, '\\$1') + '"';
}

function addTerm(field, value, negate) {
  const term = (negate ? '-' : '') + field + '=' + quoteValue(value);
  const q = $('#q');
  const current = q.value.trim();
  if (!current.split(/\s+/).includes(term)) q.value = current ? current + ' ' + term : term;
  runSearch();
}

/* ---------- Results ---------- */

const ERR_HINT = /\b(error|fail(ed|ure|ures)?|denied|critical|fatal|panic|refused)\b/i;
const WARN_HINT = /\bwarn(ing)?\b/i;

function severityClass(f) {
  const sev = f.severity;
  if (sev) {
    if (['emerg', 'alert', 'crit', 'err'].includes(sev)) return 'sev-err';
    if (sev === 'warning') return 'sev-warn';
    return '';
  }
  const text = f.message || '';
  if (ERR_HINT.test(text)) return 'sev-err';
  if (WARN_HINT.test(text)) return 'sev-warn';
  return '';
}

function baseName(path) {
  const i = path.lastIndexOf('/');
  return i < 0 ? path : path.slice(i + 1);
}

function fmtTime(rec) {
  if (rec.f.timestamp) return rec.f.timestamp;
  return rec.t ? new Date(rec.t * 1000).toLocaleString() : '';
}

function makeEntry(rec) {
  const f = rec.f;
  const prog = f.program ? (f.pid ? f.program + '[' + f.pid + ']' : f.program) : '';
  const row = el('div', {
    class: 'row', role: 'button', tabindex: '0', 'aria-expanded': 'false',
  },
    el('span', { class: 'time', text: fmtTime(rec) }),
    el('span', { class: 'file', title: f.file, text: baseName(f.file || '') }),
    el('span', { class: 'host', text: f.host || '' }),
    el('span', { class: 'prog', title: prog, text: prog }),
    el('span', { class: 'msg', text: f.message || rec.raw }));
  const entry = el('li', { class: 'entry ' + severityClass(f) }, row);
  const toggle = () => {
    const open = !entry.classList.contains('open');
    entry.classList.toggle('open', open);
    row.setAttribute('aria-expanded', String(open));
    const existing = $('.detail', entry);
    if (open && !existing) entry.append(makeDetail(rec));
    else if (existing) existing.hidden = !open;
  };
  row.addEventListener('click', toggle);
  row.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); }
  });
  return entry;
}

function makeDetail(rec) {
  const dl = el('dl');
  for (const [name, value] of Object.entries(rec.f)) {
    dl.append(
      el('dt', { text: name }),
      el('dd', { text: value }),
      el('dd', { class: 'pm' },
        el('button', {
          type: 'button', title: 'Only show ' + name + '=' + value, 'aria-label': 'Include ' + name + ' ' + value,
          onclick: () => addTerm(name, value, false), text: '+',
        }),
        ' ',
        el('button', {
          type: 'button', title: 'Hide ' + name + '=' + value, 'aria-label': 'Exclude ' + name + ' ' + value,
          onclick: () => addTerm(name, value, true), text: '\u2212',
        })));
  }
  return el('div', { class: 'detail' }, el('pre', { text: rec.raw }), dl);
}

function renderResults(records) {
  const list = $('#results');
  const frag = document.createDocumentFragment();
  for (const rec of records) frag.append(makeEntry(rec));
  list.replaceChildren(frag);
  $('#empty').hidden = records.length > 0;
}

function prependLive(rec) {
  const list = $('#results');
  list.prepend(makeEntry(rec));
  $('#empty').hidden = true;
  while (list.children.length > MAX_ROWS) list.lastElementChild.remove();
}

/* ---------- Search ---------- */

function buildParams(forStream) {
  const params = selectedFileParams();
  params.set('q', $('#q').value);
  if (!forStream) {
    params.set('limit', $('#limit').value);
    const last = $('#range').value;
    if (last) params.set('last', last);
  }
  return params;
}

function syncUrl() {
  const p = new URLSearchParams();
  if ($('#q').value) p.set('q', $('#q').value);
  if ($('#range').value) p.set('range', $('#range').value);
  if ($('#limit').value !== '500') p.set('limit', $('#limit').value);
  history.replaceState(null, '', p.toString() ? '?' + p.toString() : location.pathname);
}

async function runSearch() {
  const seq = ++state.searchSeq;
  syncUrl();
  if (selectionIsEmpty()) {
    setStatus('Select at least one readable file.', 'error');
    return;
  }
  const wasLive = state.stream !== null;
  stopLive(false);
  setStatus('Searching.');
  try {
    const data = await api('/api/search', buildParams(false));
    if (seq !== state.searchSeq) return;
    renderResults(data.records);
    let msg = data.records.length.toLocaleString() + ' records from ' + data.files + ' files. Scanned '
      + data.scanned.toLocaleString() + ' lines in ' + data.elapsed + ' s.';
    let kind = '';
    if (data.truncated) {
      msg += ' The scan stopped at its time or line limit, so older matches may be missing. Narrow the time range or add terms.';
      kind = 'warn';
    } else if (data.limit_reached) {
      msg += ' Showing the newest matches only.';
    }
    setStatus(msg, kind);
    if (wasLive) startLive();
  } catch (err) {
    if (seq !== state.searchSeq) return;
    setStatus(err.message, 'error');
    $('#live').setAttribute('aria-pressed', 'false');
  }
}

/* ---------- Live ---------- */

function startLive() {
  if (selectionIsEmpty()) return;
  stopLive(false);
  const src = new EventSource('/api/stream?' + buildParams(true).toString());
  state.stream = src;
  $('#live').setAttribute('aria-pressed', 'true');
  src.onopen = () => setStatus('Live. New lines appear at the top.');
  src.onmessage = (ev) => {
    try { prependLive(JSON.parse(ev.data)); } catch (e) { /* ignore malformed event */ }
  };
  src.addEventListener('skipped', (ev) => {
    setStatus('Live. ' + ev.data + ' lines were skipped because they arrived faster than they can be shown. Narrow the search.', 'warn');
  });
  src.onerror = () => {
    if (src.readyState === EventSource.CLOSED) {
      stopLive(false);
      setStatus('Live stream closed by the server. Sign in again or reload the page.', 'error');
    } else {
      setStatus('Live connection lost. Reconnecting.', 'warn');
    }
  };
}

function stopLive(announce) {
  if (state.stream) { state.stream.close(); state.stream = null; }
  $('#live').setAttribute('aria-pressed', 'false');
  if (announce) setStatus('Live stopped.');
}

/* ---------- Setup ---------- */

function init() {
  const p = new URLSearchParams(location.search);
  $('#q').value = p.get('q') || '';
  if (p.get('range')) $('#range').value = p.get('range');
  if (p.get('limit')) $('#limit').value = p.get('limit');

  $('#search').addEventListener('submit', (ev) => { ev.preventDefault(); runSearch(); });
  $('#live').addEventListener('click', () => {
    if (state.stream) stopLive(true);
    else { $('#live').setAttribute('aria-pressed', 'true'); startLive(); }
  });
  $('#files-filter').addEventListener('input', renderFiles);
  $('#files-all').addEventListener('click', () => setAllFiles(true));
  $('#files-none').addEventListener('click', () => setAllFiles(false));
  document.addEventListener('keydown', (ev) => {
    const tag = (ev.target.tagName || '').toLowerCase();
    if (ev.key === '/' && tag !== 'input' && tag !== 'select' && tag !== 'textarea') {
      ev.preventDefault();
      $('#q').focus();
    }
  });

  loadFiles()
    .then(() => { loadFields(); return runSearch(); })
    .catch((err) => setStatus(err.message, 'error'));
}

init();
