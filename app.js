// ─── Crypto Utilities ────────────────────────────────────────────
function hexRand(byteCount) {
  const arr = new Uint8Array(byteCount);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) return [];
  const pairs = hex.match(/.{2}/g);
  if (!pairs) return [];
  return pairs.map(h => parseInt(h, 16));
}

function toBase64(hex) {
  const bytes = hexToBytes(hex);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
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
  const hashBuf = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuf), b => b.toString(16).padStart(2, '0')).join('');
}

// ─── State ───────────────────────────────────────────────────────
let rawHex64  = '';
let rawHex128 = '';

// ─── Generate ────────────────────────────────────────────────────
function getFormatted(hexStr, fmt, charLen) {
  const safeLen = Math.floor(parseInt(charLen) / 2) * 2;
  if (fmt === 'hex')       return hexStr.substring(0, safeLen);
  if (fmt === 'base64')    return toBase64(hexStr.substring(0, safeLen));
  if (fmt === 'base64url') return toBase64URL(hexStr.substring(0, safeLen));
  if (fmt === 'uuid')      return toUUIDv4(hexStr.substring(0, 32));
  return hexStr.substring(0, safeLen);
}

function calcEntropy(fmt, len) {
  if (fmt === 'uuid') return '122 bit';
  return (Math.floor(parseInt(len) / 2) * 8) + ' bit';
}

// FIX: wrapped in try-catch so errors are never silent
// FIX: 160 bytes so all derived values use non-overlapping regions
async function generate() {
  try {
    const fmt = document.getElementById('fmt').value;
    const len = document.getElementById('len').value;

    // 160 bytes = 320 hex chars — region map (no overlaps):
    // TOKEN_SECRET / JWT / HMAC : 0..128   (64 bytes, shared by design)
    // AES_256_KEY               : 128..192 (32 bytes)
    // AES_IV                    : 192..224 (16 bytes)
    // API_KEY secret            : 224..288 (32 bytes)
    const raw  = hexRand(160);
    rawHex128  = raw;
    rawHex64   = raw.substring(0, 128);

    const mainVal = getFormatted(raw, fmt, len);

    const mainEl = document.getElementById('main-token');
    mainEl.textContent = mainVal;
    mainEl.classList.remove('flash');
    void mainEl.offsetWidth;
    mainEl.classList.add('flash');

    const card = document.getElementById('main-card');
    card.classList.remove('fresh');
    void card.offsetWidth;
    card.classList.add('fresh');

    document.getElementById('entropy-badge').textContent = calcEntropy(fmt, len);
    document.getElementById('stat-len').textContent      = mainVal.length + ' chars';
    document.getElementById('stat-time').textContent     = new Date().toLocaleTimeString('id-ID');

    const tokenSecret = raw.substring(0, 128);
    const jwtSecret   = toBase64URL(tokenSecret);
    const hmacKey     = tokenSecret;
    const aesKey      = raw.substring(128, 192);
    const aesIV       = raw.substring(192, 224);
    const apiKey      = 'sk_' + raw.substring(224, 288);

    document.getElementById('d-jwt').textContent  = jwtSecret;
    document.getElementById('d-hmac').textContent = hmacKey;
    document.getElementById('d-aes').textContent  = aesKey;
    document.getElementById('d-iv').textContent   = aesIV;
    document.getElementById('d-api').textContent  = apiKey;
    document.getElementById('d-sha').textContent  = 'menghitung...';

    sha256Hex(tokenSecret)
      .then(hash => { document.getElementById('d-sha').textContent = hash; })
      .catch(()  => { document.getElementById('d-sha').textContent = '⚠ butuh HTTPS'; });

    const envLines = [
      `# Generated: ${new Date().toISOString()}`,
      `TOKEN_SECRET=${tokenSecret}`,
      `JWT_SECRET=${jwtSecret}`,
      `HMAC_KEY=${hmacKey}`,
      `AES_256_KEY=${aesKey}`,
      `AES_IV=${aesIV}`,
      `API_KEY=${apiKey}`
    ].join('\n');
    document.getElementById('d-env').textContent = envLines;

    document.getElementById('batch-area').innerHTML = '';
    document.getElementById('batch-label').style.display = 'none';

  } catch (err) {
    showToast('⚠ Error: ' + err.message);
    console.error('generate() failed:', err);
  }
}

// ─── Batch ───────────────────────────────────────────────────────
function generateBatch() {
  const count = parseInt(document.getElementById('batch-count').value);
  const fmt   = document.getElementById('fmt').value;
  const len   = document.getElementById('len').value;
  const area  = document.getElementById('batch-area');
  const label = document.getElementById('batch-label');

  area.innerHTML = '';
  label.style.display = 'flex';

  for (let i = 0; i < count; i++) {
    const rawH = hexRand(64);
    const val  = getFormatted(rawH, fmt, len);
    const id   = 'b' + i;

    const div = document.createElement('div');
    div.className = 'batch-item animate-in';
    div.style.animationDelay = (i * 30) + 'ms';

    const numSpan = document.createElement('span');
    numSpan.className = 'batch-num';
    numSpan.textContent = String(i + 1).padStart(2, '0');

    const valSpan = document.createElement('span');
    valSpan.className = 'batch-val';
    valSpan.id = id;
    valSpan.textContent = val;

    // FIX: type="button" agar tidak trigger page refresh
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-sm';
    btn.id = 'cb' + i;
    btn.textContent = 'copy';
    btn.onclick = () => copyEl(id, 'cb' + i);

    div.appendChild(numSpan);
    div.appendChild(valSpan);
    div.appendChild(btn);
    area.appendChild(div);
  }

  area.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Copy Utilities ──────────────────────────────────────────────
function copyEl(elId, btnId) {
  const el = document.getElementById(elId);
  if (!el) return;
  // FIX: guard agar tidak copy placeholder "—" atau "menghitung..."
  const val = el.textContent.trim();
  if (!val || val === '—' || val === 'menghitung...') {
    showToast('⚠ Tidak ada yang bisa disalin');
    return;
  }
  copyText(val, btnId);
}

function copyText(text, btnId) {
  const markCopied = () => {
    if (btnId) {
      const btn = document.getElementById(btnId);
      if (btn) {
        btn.textContent = '✓';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'copy';
          btn.classList.remove('copied');
        }, 1500);
      }
    }
    showToast('✓ Tersalin ke clipboard');
  };

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(markCopied).catch(() => fallbackCopy(text, markCopied));
  } else {
    fallbackCopy(text, markCopied);
  }
}

// FIX: fallback copy dengan error handling yang benar
function fallbackCopy(text, callback) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    const ok = document.execCommand('copy');
    if (ok) callback();
    else showToast('⚠ Gagal menyalin. Salin manual.');
  } catch (err) {
    showToast('⚠ Gagal menyalin. Salin manual.');
  } finally {
    document.body.removeChild(ta);
  }
}

function copyAll() {
  const main = document.getElementById('main-token').textContent.trim();
  const env  = document.getElementById('d-env').textContent.trim();
  if (!main || main === '—') { showToast('⚠ Generate token dulu!'); return; }
  copyText('# TOKEN_SECRET MAIN\n' + main + '\n\n' + env, null);
}

// FIX: showToast selalu pakai msg eksplisit + force reflow agar animasi tidak stuck
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg || '✓ Tersalin ke clipboard';
  t.classList.remove('show');
  void t.offsetWidth;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

// ─── Export .env ─────────────────────────────────────────────────
function downloadEnv() {
  const content = document.getElementById('d-env').textContent.trim();
  if (!content || content === '—') { showToast('⚠ Generate token dulu!'); return; }
  try {
    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = '.env.example';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('✓ File .env.example diunduh');
  } catch (err) {
    showToast('⚠ Download gagal: ' + err.message);
  }
}

// ─── Keyboard Shortcut ───────────────────────────────────────────
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    generate();
  }
});

// ─── Init ────────────────────────────────────────────────────────
generate();

const copyrightEl = document.getElementById('copyright-text');
if (copyrightEl) copyrightEl.textContent = `© ${new Date().getFullYear()} KingSyah`;
