'use strict';

const STORAGE_KEY = 'boring-vault-record';
const LEAVE_GRACE_MS = 30 * 1000;
const REVEAL_MS = 120 * 1000;
const DEFAULT_SUM_COUNT = 30; // Also applies to vaults sealed before sums existed.
const PASSWORD_LENGTH = 24;
const PASSWORD_ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789-_!?';

const $ = (id) => document.getElementById(id);
const SCREENS = ['setup', 'sealing', 'sealed', 'waiting', 'typing', 'sums', 'reveal'];

let activeWorker = null;
let wakeLock = null;
let hiddenAt = null;
let revealTimer = null;
let session = null; // { lines, sums, answer, index, sumIndex } while an unlock is in progress.

function show(name) {
  for (const screen of SCREENS) $(screen).hidden = screen !== name;
  window.scrollTo(0, 0);
}

function loadRecord() {
  try {
    return { sumCount: DEFAULT_SUM_COUNT, ...JSON.parse(localStorage.getItem(STORAGE_KEY)) };
  } catch {
    return null;
  }
}

function saveRecord(record) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
}

function isValidRecord(record) {
  return Boolean(record) && record.version === 1 &&
    [record.n, record.base, record.salt, record.iv, record.ciphertext].every((v) => typeof v === 'string' && /^[0-9a-f]+$/.test(v)) &&
    record.n.length === 512 && record.salt.length === 64 && record.iv.length === 24 &&
    record.ciphertext.length >= 34 && record.ciphertext.length % 2 === 0 &&
    Number.isSafeInteger(record.squarings) && record.squarings > 0 &&
    Number.isInteger(record.lineCount) && record.lineCount > 0 && record.lineCount <= 500 &&
    (record.sumCount === undefined || (Number.isInteger(record.sumCount) && record.sumCount >= 0 && record.sumCount <= 500));
}

// Covers every field that decryption depends on, so one changed character shows up at import.
async function recordChecksum(record) {
  const fields = [record.n, record.base, record.squarings, record.salt, record.iv, record.ciphertext].join('|');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(fields));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function runJob(message, onUpdate) {
  stopWorker();
  return new Promise((resolve, reject) => {
    const worker = new Worker('worker.js');
    activeWorker = worker;
    worker.onerror = (event) => {
      stopWorker();
      reject(new Error(event.message));
    };
    worker.onmessage = ({ data }) => {
      if (data.type === 'done') {
        stopWorker();
        resolve(data.result);
      } else if (data.type === 'error') {
        stopWorker();
        reject(new Error(data.message));
      } else if (onUpdate) {
        onUpdate(data);
      }
    };
    worker.postMessage(message);
  });
}

function stopWorker() {
  if (activeWorker) activeWorker.terminate();
  activeWorker = null;
}

async function keepScreenOn() {
  if (wakeLock || !navigator.wakeLock) return;
  try {
    wakeLock = await navigator.wakeLock.request('screen');
    wakeLock.addEventListener('release', () => { wakeLock = null; });
  } catch {
    // Not fatal: the screen note asks the user to set Auto-Lock to Never.
  }
}

function letScreenSleep() {
  if (wakeLock) wakeLock.release().catch(() => {});
  wakeLock = null;
}

function generatePassword() {
  while (true) {
    const chars = [];
    while (chars.length < PASSWORD_LENGTH) {
      const [byte] = crypto.getRandomValues(new Uint8Array(1));
      // Rejection sampling keeps every character equally likely.
      if (byte < 256 - (256 % PASSWORD_ALPHABET.length)) chars.push(PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length]);
    }
    const password = chars.join('');
    if (/[a-z]/.test(password) && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[-_!?]/.test(password)) return password;
  }
}

function formatDuration(ms) {
  const minutes = Math.ceil(ms / 60000);
  return minutes <= 1 ? 'about a minute' : `about ${minutes} minutes`;
}

// Runs inside the tap itself, which is when iOS allows a copy.
function copyWithSelection(text) {
  const buffer = document.createElement('textarea');
  buffer.className = 'copy-buffer';
  buffer.value = text;
  buffer.readOnly = true;
  document.body.append(buffer);
  try {
    buffer.focus();
    buffer.setSelectionRange(0, text.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    buffer.remove();
  }
}

async function writeToClipboard(text) {
  if (copyWithSelection(text)) return true;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

async function copyText(text, button, failureLabel = 'Copy failed') {
  const original = button.textContent;
  const copied = await writeToClipboard(text);
  button.textContent = copied ? 'Copied' : failureLabel;
  setTimeout(() => { button.textContent = original; }, copied ? 1500 : 4000);
  return copied;
}

async function copyBackup(event) {
  const backup = localStorage.getItem(STORAGE_KEY);
  const copied = await copyText(backup, event.target);
  $('backup-manual').hidden = copied;
  if (!copied) {
    $('backup-output').value = backup;
    $('backup-output').focus();
    $('backup-output').select();
  }
}

// Setup

function showSetup(message) {
  $('setup-error').textContent = message || '';
  $('install-note').hidden = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
  show('setup');
}

async function sealVault(event) {
  event.preventDefault();
  const secret = {
    items: [
      { label: $('label-1').value.trim() || 'Password 1', password: $('password-1').value },
      { label: $('label-2').value.trim() || 'Password 2', password: $('password-2').value },
    ],
  };
  const minutes = Number($('minutes').value);
  const lineCount = Number($('line-count').value);
  const sumCount = Number($('sum-count').value);
  show('sealing');
  try {
    const record = await runJob({ job: 'seal', secret, minutes, lineCount, sumCount }, (update) => {
      if (update.type === 'status') $('sealing-status').textContent = update.text;
    });
    record.checksum = await recordChecksum(record);
    saveRecord(record);
    $('setup-form').reset();
    showSealed('Sealed. Save a sealed backup now: if iOS clears this app’s data, the backup is the only copy.');
  } catch (error) {
    showSetup(`Sealing failed: ${error.message}`);
  }
}

// Notes can wrap long text or curl the quotes. A backup has no meaningful whitespace.
function parseBackup(text) {
  try {
    return JSON.parse(text.replace(/\s/g, '').replace(/[“”„]/g, '"'));
  } catch {
    return null;
  }
}

async function importBackup() {
  const record = parseBackup($('backup-input').value);
  if (!isValidRecord(record)) {
    $('setup-error').textContent = 'That isn’t a complete sealed backup. Nothing was restored.';
    return;
  }
  if (record.checksum && record.checksum !== await recordChecksum(record)) {
    $('setup-error').textContent = 'This backup has been changed or damaged, so it couldn’t open. Nothing was restored.';
    return;
  }
  const hadChecksum = Boolean(record.checksum);
  saveRecord(record);
  $('backup-input').value = '';
  showSealed(hadChecksum
    ? 'Backup restored and checked: it’s identical to what was sealed.'
    : 'Backup restored. It’s from an older version with no checksum, so compare the fingerprint below with the original vault’s.');
}

// Sealed

async function showFingerprint(record) {
  const checksum = await recordChecksum(record);
  $('sealed-fingerprint').textContent = `${checksum.slice(0, 4)} ${checksum.slice(4, 8)}`;
  // Vaults sealed before checksums existed get one, so their future backups can be checked.
  if (!record.checksum) saveRecord({ ...record, checksum });
}

function showSealed(message) {
  const record = loadRecord();
  if (!isValidRecord(record)) {
    showSetup();
    return;
  }
  session = null;
  hiddenAt = null;
  stopWorker();
  letScreenSleep();
  $('sealed-message').textContent = message || '';
  $('sealed-message').hidden = !message;
  $('sealed-minutes').textContent = String(record.minutes);
  $('sealed-lines').textContent = String(record.lineCount);
  $('sealed-sums').textContent = String(record.sumCount);
  $('backup-manual').hidden = true;
  $('backup-output').value = '';
  $('sealed-date').textContent = new Date(record.createdAt).toLocaleDateString();
  $('delete-panel').hidden = true;
  $('delete-confirm').value = '';
  showFingerprint(record);
  show('sealed');
}

function deleteVault() {
  if ($('delete-confirm').value !== 'DELETE') return;
  localStorage.removeItem(STORAGE_KEY);
  showSetup();
}

// Unlocking

async function startUnlock() {
  const record = loadRecord();
  session = { index: 0, sumIndex: 0, lines: null, sums: null, answer: null };
  hiddenAt = null;
  $('wait-bar').style.width = '0%';
  $('wait-percent').textContent = '0%';
  $('wait-remaining').textContent = 'Estimating…';
  show('waiting');
  keepScreenOn();
  const startedAt = Date.now();
  try {
    const { answer, lines, sums } = await runJob({ job: 'solve', record }, ({ type, done, total }) => {
      if (type !== 'progress') return;
      const fraction = done / total;
      $('wait-bar').style.width = `${(fraction * 100).toFixed(1)}%`;
      $('wait-percent').textContent = `${Math.floor(fraction * 100)}%`;
      if (fraction > 0.001) {
        $('wait-remaining').textContent = `${formatDuration((Date.now() - startedAt) * (1 - fraction) / fraction)} left`;
      }
    });
    if (!session) return;
    session.answer = answer;
    session.lines = lines;
    session.sums = sums;
    showTyping();
  } catch (error) {
    showSealed(`Unlock failed: ${error.message}`);
  }
}

function showTyping() {
  const { index, lines } = session;
  $('line-counter').textContent = `Line ${index + 1} of ${lines.length}`;
  $('line-bar').style.width = `${(index / lines.length) * 100}%`;
  $('line-target').textContent = lines[index];
  $('line-input').value = '';
  $('line-note').textContent = '';
  show('typing');
  $('line-input').focus();
}

function checkLine() {
  if (!session || session.index >= session.lines.length) return; // Already decrypting.
  const input = $('line-input');
  const target = session.lines[session.index];
  if (input.value === target) {
    session.index += 1;
    if (session.index < session.lines.length) showTyping();
    else if (session.sums.length > 0) showSum();
    else revealPasswords();
  } else if (!target.startsWith(input.value)) {
    input.value = '';
    $('line-note').textContent = 'Typo. Start this line again.';
  } else {
    $('line-note').textContent = '';
  }
}

function showSum() {
  const { sumIndex, sums } = session;
  $('sum-counter').textContent = `Sum ${sumIndex + 1} of ${sums.length}`;
  $('sum-bar').style.width = `${(sumIndex / sums.length) * 100}%`;
  $('sum-target').textContent = sums[sumIndex].join(' + ');
  $('sum-input').value = '';
  $('sum-note').textContent = '';
  show('sums');
  $('sum-input').focus();
}

function checkSum() {
  if (!session || session.sumIndex >= session.sums.length) return; // Already decrypting.
  const input = $('sum-input');
  const expected = String(session.sums[session.sumIndex].reduce((total, term) => total + term, 0));
  if (input.value.length < expected.length) {
    $('sum-note').textContent = '';
  } else if (input.value === expected) {
    session.sumIndex += 1;
    if (session.sumIndex < session.sums.length) showSum();
    else revealPasswords();
  } else {
    input.value = '';
    $('sum-note').textContent = 'Wrong. Try this sum again.';
  }
}

async function revealPasswords() {
  const record = loadRecord();
  try {
    const secret = await runJob({ job: 'open', record, answer: session.answer });
    session = null;
    hiddenAt = null;
    letScreenSleep();
    renderReveal(secret);
  } catch {
    showSealed('The passwords couldn’t be decrypted, so this vault or backup is damaged.');
  }
}

function renderReveal(secret) {
  const list = $('reveal-list');
  list.replaceChildren();
  for (const { label, password } of secret.items) {
    const item = document.createElement('div');
    item.className = 'secret';
    const name = document.createElement('div');
    name.className = 'secret-label';
    name.textContent = label;
    const value = document.createElement('code');
    value.textContent = password;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary';
    button.textContent = 'Copy';
    button.addEventListener('click', () => copyText(password, button, 'Press and hold the password to copy'));
    item.append(name, value, button);
    list.append(item);
  }
  const deadline = Date.now() + REVEAL_MS;
  const tick = () => {
    const left = deadline - Date.now();
    if (left <= 0) {
      lockAfterReveal();
      return;
    }
    $('reveal-countdown').textContent = `Locks again in ${Math.ceil(left / 1000)} seconds`;
  };
  tick();
  revealTimer = setInterval(tick, 1000);
  show('reveal');
}

function lockAfterReveal() {
  clearInterval(revealTimer);
  revealTimer = null;
  $('reveal-list').replaceChildren();
  showSealed('Locked again.');
}

// Leaving the app

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (session) hiddenAt = Date.now();
    return;
  }
  if (session && hiddenAt && Date.now() - hiddenAt > LEAVE_GRACE_MS) {
    showSealed('You left the app for too long, so the unlock started over.');
    return;
  }
  hiddenAt = null;
  if (session) keepScreenOn();
});

// Blocks the shortcuts around retyping.
for (const type of ['paste', 'drop', 'copy', 'cut', 'contextmenu']) {
  $('line-input').addEventListener(type, (event) => event.preventDefault());
  $('sum-input').addEventListener(type, (event) => event.preventDefault());
}
$('line-input').addEventListener('input', checkLine);
$('sum-input').addEventListener('input', checkSum);

$('setup-form').addEventListener('submit', sealVault);
$('import-button').addEventListener('click', importBackup);
$('generate-1').addEventListener('click', () => { $('password-1').value = generatePassword(); });
$('generate-2').addEventListener('click', () => { $('password-2').value = generatePassword(); });
$('start-unlock').addEventListener('click', startUnlock);
$('copy-backup').addEventListener('click', copyBackup);
$('show-delete').addEventListener('click', () => { $('delete-panel').hidden = false; });
$('delete-button').addEventListener('click', deleteVault);
$('cancel-wait').addEventListener('click', () => showSealed());
$('cancel-typing').addEventListener('click', () => showSealed());
$('cancel-sums').addEventListener('click', () => showSealed());
$('lock-now').addEventListener('click', lockAfterReveal);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});

showSealed();
