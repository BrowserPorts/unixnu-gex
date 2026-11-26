// The owner of the lazy files for a page's own source (fs.js
// `setLazySource`): every program's read of a lazy file asks here, through
// the control buffer's slots (hosts/browser/js/lazy-cache.mjs), and waits;
// this asks the page's module for the bytes, or takes them from what the
// module handed over ahead (`ctx.put`), and writes them into the kernel's
// memory, where the reader wanted them. Where the bytes come from, how they
// are fetched, kept or decoded is the module's.
//
// In: { ctl: SharedArrayBuffer, memory: the kernel's WebAssembly.Memory,
//       module: the source's URL, data, port: the source's MessagePort }
// Out: { kind: 'ready', ok, why? } once.

import { SLOTS, HEAD, SLOT, ASKED, TAKEN, WRITING, DONE } from '../../hosts/browser/js/lazy-cache.mjs';

/** Bytes handed over ahead, by key: [{ at, bytes, left }] (`left`: bytes not
 *  read yet; at 0 the piece is let go). */
const ahead = new Map();

function put(key, offset, bytes) {
  if (typeof key !== 'string') throw new TypeError('put: a key');
  if (!Number.isSafeInteger(offset) || offset < 0) throw new TypeError('put: an offset');
  if (!(bytes instanceof Uint8Array)) throw new TypeError('put: bytes, a Uint8Array');
  if (!bytes.length) return;
  const list = ahead.get(key) ?? ahead.set(key, []).get(key);
  list.push({ at: offset, bytes, left: bytes.length });
}

/** `len` bytes of `key` at `from` from what was put, or null. */
function fromAhead(key, from, len) {
  const list = ahead.get(key);
  if (!list) return null;
  const i = list.findIndex((p) => p.at <= from && from + len <= p.at + p.bytes.length);
  if (i < 0) return null;
  const p = list[i];
  const out = p.bytes.subarray(from - p.at, from - p.at + len);
  p.left -= len;
  if (p.left <= 0) {
    list.splice(i, 1);
    if (!list.length) ahead.delete(key);
  }
  return out;
}

self.onmessage = async ({ data: m }) => {
  let source;
  try {
    source = await import(/* @vite-ignore */ m.module);
    if (typeof source.read !== 'function') throw new Error(`${m.module} exports no read(key, offset, length)`);
    if (typeof Atomics.waitAsync !== 'function') throw new Error('no Atomics.waitAsync');
    await source.init?.({ data: m.data, port: m.port, put });
  } catch (e) {
    self.postMessage({ kind: 'ready', ok: false, why: String(e?.message ?? e) });
    return;
  }
  self.postMessage({ kind: 'ready', ok: true });
  const ctl = new Int32Array(m.ctl);
  const raw = new Uint8Array(m.ctl);
  const busy = new Set();
  const serve = async (i) => {
    const base = (HEAD + i * SLOT) / 4;
    if (Atomics.compareExchange(ctl, base, ASKED, TAKEN) !== ASKED) {
      busy.delete(i);
      return;
    }
    const len = ctl[base + 3] >>> 0, dst = ctl[base + 2] >>> 0, kl = ctl[base + 4];
    const from = new Float64Array(m.ctl, HEAD + i * SLOT + 24, 1)[0];
    // As the kernel keeps it, `/=KEY` (fs.js addTar).
    const key = new TextDecoder().decode(raw.slice(HEAD + i * SLOT + 32, HEAD + i * SLOT + 32 + kl)).replace(/^\/=/, '');
    let bytes = fromAhead(key, from, len);
    if (!bytes) {
      try {
        const got = await source.read(key, from, len);
        const b = got instanceof Uint8Array ? got : ArrayBuffer.isView(got) ? new Uint8Array(got.buffer, got.byteOffset, got.byteLength) : got instanceof ArrayBuffer ? new Uint8Array(got) : null;
        if (!b || b.length < len) throw new Error(`read(${key}, ${from}, ${len}) gave ${b ? `${b.length} bytes` : 'no bytes'}`);
        bytes = b.subarray(0, len);
      } catch (e) {
        console.warn(`[lazy-source] ${e?.message ?? e}`);
      }
    }
    if (Atomics.compareExchange(ctl, base, TAKEN, WRITING) === TAKEN) {
      if (bytes) new Uint8Array(m.memory.buffer, dst, len).set(bytes);
      ctl[base + 1] = bytes ? len : -1;
      Atomics.store(ctl, base, DONE);
      Atomics.notify(ctl, base);
    }
    busy.delete(i);
  };
  for (;;) {
    const seen = Atomics.load(ctl, 0);
    for (let i = 0; i < SLOTS; i++) {
      if (Atomics.load(ctl, (HEAD + i * SLOT) / 4) === ASKED && !busy.has(i)) {
        busy.add(i);
        serve(i);
      }
    }
    const w = Atomics.waitAsync(ctl, 0, seen);
    if (w.async) await w.value;
  }
};
