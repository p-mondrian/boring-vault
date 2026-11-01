'use strict';

// Time-lock puzzle (Rivest, Shamir, Wagner, 1996).
// Sealing knows the factors of n, so it can jump straight to the answer.
// Unlocking does not, so it must perform all T modular squarings one by one.

const FORMAT_VERSION = 1;
const PRIME_BITS = 1024;
const CALIBRATION_MS = 3000;
const WORDS_PER_LINE = 6;
const TERMS_PER_SUM = 3;

const WORDS = ('acorn anchor apron attic autumn badge bakery ballot bamboo banjo barley barrel basket beacon beaver bench ' +
  'bicycle biscuit blanket bobbin bottle bracket breeze bridge bucket budget bundle butter button cabin cable candle ' +
  'canvas carpet carton castle cattle cellar cement chapel cherry chisel cider circle clover cobalt collar copper ' +
  'cotton cradle crayon cricket culvert curtain cushion dairy desert diesel dinner dollar donkey drawer dustpan ' +
  'easel elbow engine envelope fabric faucet feather fence ferry fiddle filter flannel folder forest fossil fountain ' +
  'gallon garage garden garlic gasket gravel grocer gutter hammer harbor harness hazel helmet hinge hockey hollow ' +
  'invoice island jacket kettle kitchen ladder lantern laundry ledger lemon lentil lever linen locker lumber magnet ' +
  'mallet maple marble meadow mitten molasses mortar muffin mustard napkin needle nickel notebook nutmeg oatmeal ' +
  'orchard paddle pantry parcel parsley pasture pebble pedal pencil pepper pillow pickle pigeon pitcher plank pliers ' +
  'plumber pocket pulley pumpkin quarry quiver radish railing receipt ribbon river rubber saddle salmon sandal ' +
  'satchel sawdust scissors shovel shutter sickle signal silver sink skillet socket spatula spindle spinach sponge ' +
  'stapler stencil stool suitcase sweater table tackle teapot thimble thistle timber toaster tomato towel tractor ' +
  'trellis trolley trowel tunnel turnip umbrella valley velvet walnut wagon washer whistle wicker willow window yarn').split(' ');

const SMALL_PRIMES = (() => {
  const primes = [];
  for (let i = 3; primes.length < 400; i += 2) {
    if (primes.every((p) => i % p !== 0)) primes.push(i);
  }
  return primes.map(BigInt);
})();

const encoder = new TextEncoder();

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
}

function bytesToBig(bytes) {
  return BigInt('0x' + bytesToHex(bytes));
}

function bigToBytes(value, length) {
  return hexToBytes(value.toString(16).padStart(length * 2, '0'));
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  for (const bit of exponent.toString(2)) {
    result = (result * result) % modulus;
    if (bit === '1') result = (result * base) % modulus;
  }
  return result;
}

function isProbablePrime(n, rounds = 24) {
  for (const p of SMALL_PRIMES) {
    if (n % p === 0n) return n === p;
  }
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1;
  }
  const byteLength = PRIME_BITS / 8;
  witness: for (let i = 0; i < rounds; i++) {
    const a = 2n + bytesToBig(randomBytes(byteLength)) % (n - 3n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witness;
    }
    return false;
  }
  return true;
}

function randomPrime() {
  const topBits = 3n << BigInt(PRIME_BITS - 2); // Keeps n at a full 2048 bits.
  while (true) {
    const candidate = bytesToBig(randomBytes(PRIME_BITS / 8)) | topBits | 1n;
    if (isProbablePrime(candidate)) return candidate;
  }
}

function measureSquaringRate(n) {
  let value = 2n + bytesToBig(randomBytes(PRIME_BITS / 4)) % (n - 2n);
  let count = 0;
  const start = performance.now();
  let elapsed = 0;
  while (elapsed < CALIBRATION_MS) {
    for (let i = 0; i < 64; i++) value = (value * value) % n;
    count += 64;
    elapsed = performance.now() - start;
  }
  return count / (elapsed / 1000);
}

async function hkdfBaseKey(answer) {
  return crypto.subtle.importKey('raw', bigToBytes(answer, PRIME_BITS / 4), 'HKDF', false, ['deriveKey', 'deriveBits']);
}

async function deriveAesKey(answer, salt) {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('boring-vault aes v1') },
    await hkdfBaseKey(answer),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// The lines come from the puzzle answer, so nobody sees them before the wait is over.
async function deriveLines(answer, salt, lineCount) {
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('boring-vault lines v1') },
    await hkdfBaseKey(answer),
    lineCount * WORDS_PER_LINE * 16,
  );
  const view = new DataView(bits);
  const lines = [];
  for (let line = 0; line < lineCount; line++) {
    const words = [];
    for (let word = 0; word < WORDS_PER_LINE; word++) {
      words.push(WORDS[view.getUint16((line * WORDS_PER_LINE + word) * 2) % WORDS.length]);
    }
    lines.push(words.join(' '));
  }
  return lines;
}

// Same idea as the lines: each sum is three two-digit numbers, hidden until the wait is over.
async function deriveSums(answer, salt, sumCount) {
  if (sumCount === 0) return [];
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('boring-vault sums v1') },
    await hkdfBaseKey(answer),
    sumCount * TERMS_PER_SUM * 16,
  );
  const view = new DataView(bits);
  const sums = [];
  for (let sum = 0; sum < sumCount; sum++) {
    const terms = [];
    for (let term = 0; term < TERMS_PER_SUM; term++) {
      terms.push(10 + view.getUint16((sum * TERMS_PER_SUM + term) * 2) % 90);
    }
    sums.push(terms);
  }
  return sums;
}

async function seal({ secret, minutes, lineCount, sumCount }) {
  postMessage({ type: 'status', text: 'Generating the puzzle…' });
  const p = randomPrime();
  let q = randomPrime();
  while (q === p) q = randomPrime();
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  postMessage({ type: 'status', text: 'Measuring this phone’s speed…' });
  const rate = measureSquaringRate(n);
  const squarings = Math.max(1, Math.ceil(rate * minutes * 60));

  postMessage({ type: 'status', text: 'Encrypting…' });
  const base = 2n + bytesToBig(randomBytes(PRIME_BITS / 4)) % (n - 2n);
  const answer = modPow(base, modPow(2n, BigInt(squarings), phi), n);

  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    await deriveAesKey(answer, salt),
    encoder.encode(JSON.stringify(secret)),
  );

  return {
    version: FORMAT_VERSION,
    n: n.toString(16),
    base: base.toString(16),
    squarings,
    minutes,
    lineCount,
    sumCount,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(ciphertext)),
    createdAt: new Date().toISOString(),
  };
}

async function solve({ record }) {
  const n = BigInt('0x' + record.n);
  let value = BigInt('0x' + record.base);
  let lastReport = 0;
  for (let i = 0; i < record.squarings; i++) {
    value = (value * value) % n;
    if ((i & 255) === 0) {
      const now = performance.now();
      if (now - lastReport > 500) {
        lastReport = now;
        postMessage({ type: 'progress', done: i, total: record.squarings });
      }
    }
  }
  const salt = hexToBytes(record.salt);
  const lines = await deriveLines(value, salt, record.lineCount);
  const sums = await deriveSums(value, salt, record.sumCount);
  return { answer: value.toString(16), lines, sums };
}

async function open({ record, answer }) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: hexToBytes(record.iv) },
    await deriveAesKey(BigInt('0x' + answer), hexToBytes(record.salt)),
    hexToBytes(record.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

const JOBS = { seal, solve, open };

self.onmessage = async ({ data }) => {
  try {
    postMessage({ type: 'done', result: await JOBS[data.job](data) });
  } catch (error) {
    postMessage({ type: 'error', message: String(error && error.message || error) });
  }
};
