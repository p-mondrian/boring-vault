'use strict';

const STORAGE_KEY = 'boring-vault-record';
const PROGRESS_KEY = 'boring-vault-progress';
// 2048-bit squarings per second for optimised GMP on an Apple M4 (measured at 1.96 million), plus margin
// for hand-tuned code. The wait is set against this rate, so a fast computer can't finish under the minimum.
const FAST_COMPUTER_RATE = 2500000;
const LEAVE_GRACE_MS = 30 * 1000;
const REVEAL_MS = 120 * 1000;
const DEFAULT_SUM_COUNT = 30; // Also applies to vaults sealed before sums existed.
const PASSWORD_LENGTH = 24;
const PASSWORD_ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789-_!?';

const $ = (id) => document.getElementById(id);
const SCREENS = ['setup', 'sealing', 'sealed', 'waiting', 'typing', 'sums', 'reveal'];

let activeJob = null; // { worker, reject }
let wakeLock = null;
let hiddenAt = null;
let revealTimer = null;
let session = null; // { stage, lines, sums, answer, index, sumIndex } while an unlock is in progress.
let deviceRate = null; // This device's squarings per second, measured once per launch.
let measuring = null;

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

function loadProgress(record) {
  try {
    const progress = JSON.parse(localStorage.getItem(PROGRESS_KEY));
    if (progress && progress.salt === record.salt && Number.isSafeInteger(progress.done) &&
      progress.done > 0 && progress.done <= record.squarings && /^[0-9a-f]+$/.test(progress.value)) return progress;
  } catch {
    // Treated as no progress.
  }
  return null;
}

function saveProgress(record, done, value) {
  try {
    localStorage.setItem(PROGRESS_KEY, JSON.stringify({ salt: record.salt, done, value }));
  } catch {
    // Not fatal: the wait just can't resume after the app closes.
  }
}

function clearProgress() {
  localStorage.removeItem(PROGRESS_KEY);
}

function isValidRecord(record) {
  return Boolean(record) && record.version === 1 &&
    [record.n, record.base, record.salt, record.iv, record.ciphertext].every((v) => typeof v === 'string' && /^[0-9a-f]+$/.test(v)) &&
    record.n.length === 512 && record.salt.length === 64 && record.iv.length === 24 &&
    record.ciphertext.length >= 34 && record.ciphertext.length % 2 === 0 &&
    Number.isSafeInteger(record.squarings) && record.squarings > 0 &&
    Number.isInteger(record.lineCount) && record.lineCount > 0 && record.lineCount <= 500 &&
    (record.sumCount === undefined || (Number.isInteger(record.sumCount) && record.sumCount >= 0 && record.sumCount <= 500)) &&
    (record.deviceRate === undefined || (Number.isFinite(record.deviceRate) && record.deviceRate > 0));
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
    activeJob = { worker, reject };
    const finish = () => {
      if (activeJob && activeJob.worker === worker) activeJob = null;
      worker.terminate();
    };
    worker.onerror = (event) => {
      finish();
      reject(new Error(event.message));
    };
    worker.onmessage = ({ data }) => {
      if (data.type === 'done') {
        finish();
        resolve(data.result);
      } else if (data.type === 'error') {
        finish();
        reject(new Error(data.message));
      } else if (onUpdate) {
        onUpdate(data);
      }
    };
    worker.postMessage(message);
  });
}

// Rejects the stopped job's promise, so nothing waits on a worker that's gone.
function stopWorker() {
  if (!activeJob) return;
  activeJob.worker.terminate();
  activeJob.reject(new Error('Stopped.'));
  activeJob = null;
}

function measureDevice() {
  if (deviceRate) return Promise.resolve(deviceRate);
  if (!measuring) {
    measuring = runJob({ job: 'measure' }).then(({ rate }) => {
      deviceRate = rate;
      return rate;
    });
    measuring.catch(() => { measuring = null; });
  }
  return measuring;
}

function squaringsFor(minutes) {
  return Math.max(1, Math.ceil(FAST_COMPUTER_RATE * minutes * 60));
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
  if (ms < 60000) return `${Math.max(1, Math.round(ms / 1000))} s`;
  const minutes = Math.round(ms / 60000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
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
  updateEstimate();
  measureDevice().then(updateEstimate, updateEstimate);
}

function updateEstimate() {
  const minutes = Number($('minutes').value);
  if (!deviceRate) {
    $('phone-estimate').textContent = 'Measuring this phone’s speed…';
  } else if (!(minutes > 0)) {
    $('phone-estimate').textContent = '';
  } else {
    $('phone-estimate').textContent = `On this phone, the wait will take about ${formatDuration(squaringsFor(minutes) / deviceRate * 1000)}.`;
  }
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
    $('sealing-status').textContent = 'Measuring this phone’s speed…';
    const rate = await measureDevice();
    const squarings = squaringsFor(minutes);
    const record = await runJob({ job: 'seal', secret, squarings, deviceRate: rate, lineCount, sumCount }, (update) => {
      if (update.type === 'status') $('sealing-status').textContent = update.text;
    });
    record.checksum = await recordChecksum(record);
    saveRecord(record);
    clearProgress();
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
  clearProgress();
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
  const phoneMs = record.deviceRate ? record.squarings / record.deviceRate * 1000 : record.minutes * 60000;
  $('sealed-phone').textContent = `about ${formatDuration(phoneMs)}`;
  $('sealed-fast').textContent = `at least ${formatDuration(record.squarings / FAST_COMPUTER_RATE * 1000)}`;
  const progress = loadProgress(record);
  $('start-unlock').textContent = progress
    ? `Resume unlocking (${Math.floor(progress.done / record.squarings * 100)}% waited)`
    : 'Start unlocking';
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
  clearProgress();
  showSetup();
}

// Unlocking

function showWaitProgress(fraction) {
  $('wait-bar').style.width = `${(fraction * 100).toFixed(1)}%`;
  $('wait-percent').textContent = `${Math.floor(fraction * 100)}%`;
}

async function startUnlock() {
  const record = loadRecord();
  const resume = loadProgress(record);
  const current = { stage: 'wait', index: 0, sumIndex: 0, lines: null, sums: null, answer: null };
  session = current;
  hiddenAt = null;
  const startDone = resume ? resume.done : 0;
  showWaitProgress(startDone / record.squarings);
  $('wait-remaining').textContent = 'Estimating…';
  show('waiting');
  keepScreenOn();
  const startedAt = Date.now();
  try {
    const { answer, lines, sums } = await runJob({ job: 'solve', record, resume }, ({ type, done, total, value }) => {
      if (type !== 'progress') return;
      if (value) saveProgress(record, done, value);
      showWaitProgress(done / total);
      const elapsed = Date.now() - startedAt;
      if (elapsed > 3000 && done > startDone) {
        $('wait-remaining').textContent = `about ${formatDuration((total - done) * elapsed / (done - startDone))} left`;
      }
    });
    if (session !== current) return;
    // Keeps the finished wait if the lines or sums have to start over.
    saveProgress(record, record.squarings, answer);
    current.stage = 'type';
    current.answer = answer;
    current.lines = lines;
    current.sums = sums;
    showTyping();
  } catch (error) {
    if (session !== current) return;
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
  const current = session;
  try {
    const secret = await runJob({ job: 'open', record, answer: current.answer });
    if (session !== current) return;
    clearProgress();
    session = null;
    hiddenAt = null;
    letScreenSleep();
    renderReveal(secret);
  } catch {
    if (session !== current) return;
    clearProgress();
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
  // Leaving during the wait only pauses it; leaving during the lines or sums starts those over.
  if (session && session.stage === 'type' && hiddenAt && Date.now() - hiddenAt > LEAVE_GRACE_MS) {
    showSealed('You left for more than 30 seconds, so the lines and sums start over. Your finished wait is kept.');
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
$('cancel-wait').addEventListener('click', () => showSealed('Paused. Progress up to the last 10 seconds is saved.'));
$('cancel-typing').addEventListener('click', () => showSealed('Stopped. Your finished wait is kept.'));
$('cancel-sums').addEventListener('click', () => showSealed('Stopped. Your finished wait is kept.'));
$('minutes').addEventListener('input', updateEstimate);
$('lock-now').addEventListener('click', lockAfterReveal);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});

showSealed();
