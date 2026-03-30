// ── Crypto helpers ────────────────────────────────────────────────
function hexRand(byteCount) {
  const arr = new Uint8Array(byteCount);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const pairs = hex.match(/.{2}/g) || [];
  return pairs.map(h => parseInt(h, 16));
}

function toBase64(hex) {
  const bytes = hexToBytes(hex);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function toBase64URL(hex) {
  return toBase64(hex).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function toUUIDv4(hex) {
  const h = hex.substring(0, 32);
  return [
    h.slice(0, 8), '-',
    h.slice(8, 12), '-',
    '4' + h.slice(13, 16), '-',
    ((parseInt(h[16], 16) & 0x3 | 0x8)).toString(16) + h.slice(17, 20), '-',
    h.slice(20, 32)
  ].join('');
}

async function sha256Hex(hex) {
  const bytes = new Uint8Array(hexToBytes(hex));
  const buf   = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}

// ── Format helpers ────────────────────────────────────────────────
function applyFormat(hex, fmt, charLen) {
  const safeLen = Math.floor(parseInt(charLen) / 2) * 2;
  const h = hex.substring(0, safeLen);
  if (fmt === 'hex')       return h;
  if (fmt === 'base64')    return toBase64(h);
  if (fmt === 'base64url') return toBase64URL(h);
  if (fmt === 'uuid')      return toUUIDv4(hex.substring(0, 32));
  return h;
}

function getEntropy(fmt, len) {
  if (fmt === 'uuid') return '122 bit';
  return (Math.floor(parseInt(len) / 2) * 8) + ' bit';
}

// ── State ─────────────────────────────────────────────────────────
let currentRaw = '';

// ── Generate ─────────────────────────────────────────────────────
async function generate() {
  try {
    const fmt = document.getElementById('fmt').value;
    const len = document.getElementById('len').value;

    // 160 bytes = 320 hex chars. Non-overlapping regions:
    // [0..128]   token / jwt / hmac  (64 bytes)
    // [128..192] AES-256 key         (32 bytes)
    // [192..224] AES IV              (16 bytes)
    // [224..288] API key secret      (32 bytes)
    const raw = hexRand(160);
    currentRaw = raw;

    const main = applyFormat(raw, fmt, len);

    // Update main token display
    const mainEl = document.getElementById('mainToken');
    mainEl.textContent = main;
    mainEl.classList.remove('new');
    void mainEl.offsetWidth;
    mainEl.classList.add('new');

    const card = document.getElementById('mainCard');
    card.classList.remove('flash-anim');
    void card.offsetWidth;
    card.classList.add('flash-anim');

    document.getElementById('entBadge').textContent = getEntropy(fmt, len);
    document.getElementById('statLen').textContent  = main.length + ' chars';
    document.getElementById('statTime').textContent = new Date().toLocaleTimeString('id-ID');

    // Strength bar — always 4/4 for CSPRNG (visual reassurance)
    const colors = ['var(--pink)', 'var(--amber)', 'var(--cyan)', 'var(--green)'];
    for (let i = 1; i <= 4; i++) {
      document.getElementById('s' + i).style.background = colors[i - 1];
    }

    // Derived values
    const tokenSec = raw.substring(0, 128);
    const jwtSec   = toBase64URL(tokenSec);
    const hmacKey  = tokenSec;
    const aesKey   = raw.substring(128, 192);
    const aesIV    = raw.substring(192, 224);
    const apiKey   = 'sk_live_' + raw.substring(224, 288);

    document.getElementById('dJwt').textContent  = jwtSec;
    document.getElementById('dHmac').textContent = hmacKey;
    document.getElementById('dAes').textContent  = aesKey;
    document.getElementById('dIv').textContent   = aesIV;
    document.getElementById('dApi').textContent  = apiKey;
    document.getElementById('dSha').textContent  = 'menghitung…';

    sha256Hex(tokenSec)
      .then(h  => { document.getElementById('dSha').textContent = h; })
      .catch(() => { document.getElementById('dSha').textContent = '⚠ butuh HTTPS'; });

    // ENV block
    const envLines = [
      `# Generated: ${new Date().toISOString()}`,
      `TOKEN_SECRET=${tokenSec}`,
      `JWT_SECRET=${jwtSec}`,
      `HMAC_KEY=${hmacKey}`,
      `AES_256_KEY=${aesKey}`,
      `AES_IV=${aesIV}`,
      `API_KEY=${apiKey}`
    ].join('\n');
    document.getElementById('dEnv').textContent = envLines;

    // Clear batch
    document.getElementById('batchArea').innerHTML = '';
    document.getElementById('batchLbl').style.display = 'none';

  } catch (err) {
    showToast('⚠ Error: ' + err.message);
    console.error(err);
  }
}

// ── Batch ─────────────────────────────────────────────────────────
function generateBatch() {
  const count = parseInt(document.getElementById('batchCount').value);
  const fmt   = document.getElementById('fmt').value;
  const len   = document.getElementById('len').value;
  const area  = document.getElementById('batchArea');
  const lbl   = document.getElementById('batchLbl');

  area.innerHTML = '';
  lbl.style.display = 'flex';

  for (let i = 0; i < count; i++) {
    const raw = hexRand(64);
    const val = applyFormat(raw, fmt, len);
    const id  = 'bv' + i;

    const div = document.createElement('div');
    div.className = 'batch-item';
    div.style.animationDelay = (i * 25) + 'ms';

    const nSpan = document.createElement('span');
    nSpan.className = 'batch-n';
    nSpan.textContent = String(i + 1).padStart(2, '0');

    const vSpan = document.createElement('span');
    vSpan.className = 'batch-v';
    vSpan.id = id;
    vSpan.textContent = val;

    const btn = document.createElement('button');
    btn.className = 'btn-sm';
    btn.textContent = 'copy';
    btn.addEventListener('click', () => copyById(id, btn));

    div.append(nSpan, vSpan, btn);
    area.appendChild(div);
  }

  area.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Copy utilities ────────────────────────────────────────────────
function copyById(elId, btn) {
  const val = (document.getElementById(elId)?.textContent || '').trim();
  if (!val || val === '—' || val.startsWith('menghitung')) {
    showToast('⚠ Belum ada nilai untuk disalin');
    return;
  }
  copyText(val, btn);
}

function copyText(text, btn) {
  const done = () => {
    showToast('✓ Tersalin ke clipboard');
    if (btn) markCopied(btn);
  };

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    if (document.execCommand('copy')) cb();
    else showToast('⚠ Gagal. Salin manual dengan Ctrl+A → Ctrl+C');
  } catch (e) {
    showToast('⚠ Gagal. Salin manual.');
  } finally {
    document.body.removeChild(ta);
  }
}

function markCopied(btn) {
  const orig = btn.textContent;
  btn.textContent = '✓';
  btn.classList.add('ok');
  setTimeout(() => { btn.textContent = orig; btn.classList.remove('ok'); }, 1800);
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('show');
  void t.offsetWidth;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

// ── Export .env ───────────────────────────────────────────────────
function downloadEnv() {
  const content = document.getElementById('dEnv').textContent.trim();
  if (!content || content === '—') { showToast('⚠ Generate token dulu!'); return; }
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: '.env.example' });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('✓ .env.example berhasil diunduh');
}

// ── Event listeners (NO inline handlers) ─────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // Buttons
  document.getElementById('btnGen').addEventListener('click', generate);

  document.getElementById('btnCopyAll').addEventListener('click', () => {
    const main = document.getElementById('mainToken').textContent.trim();
    const env  = document.getElementById('dEnv').textContent.trim();
    if (!main || main === '—') { showToast('⚠ Generate token dulu!'); return; }
    copyText('# TOKEN_SECRET\n' + main + '\n\n' + env, document.getElementById('btnCopyAll'));
  });

  document.getElementById('btnBatch').addEventListener('click', generateBatch);
  document.getElementById('btnExport').addEventListener('click', downloadEnv);

  document.getElementById('copyMainBtn').addEventListener('click', () => {
    copyById('mainToken', document.getElementById('copyMainBtn'));
  });

  // Selects
  document.getElementById('fmt').addEventListener('change', generate);
  document.getElementById('len').addEventListener('change', generate);

  // Delegate copy for all derived cards
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => copyById(btn.dataset.copy, btn));
  });

  // Keyboard shortcut: Ctrl/Cmd + Enter → generate
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      generate();
    }
  });

  // Copyright footer — auto-update year
  const copyrightEl = document.getElementById('copyright-text');
  if (copyrightEl) copyrightEl.textContent = `© ${new Date().getFullYear()} KingSyah`;

  // Initial generate on load
  generate();
});
