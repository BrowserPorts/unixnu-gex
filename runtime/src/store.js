// `Store`: an OPFSFilesystem's store edited while no system holds it, from
// a dedicated Worker (a sync access handle is only had there). The format
// and every change to it are gex-store's (crates/gex-store, as store.wasm,
// hosts/store); this hands it the store file's handle and holds the store's
// Web Lock, the one a System takes (blocks.mjs `claimStore`), for as long as
// the Store is open.
//
// Paths are the guest's, absolute. A listing is the store's records: what
// the page or a run wrote, removed or changed of the sources, not the
// sources themselves. What is written is the next boot's once `commit()`
// has written it as a generation.

import { claimStore, openHandle, handleOp, storeDir, STORE_FILE, NOSPACE } from '../../hosts/browser/js/blocks.mjs';
import files from './runtime-files.js';

/** fs.js's: the kernel's blocks of an OPFSFilesystem, and how large a file
 *  stays in its record. */
const BLOCK = 65536;
const INLINE = 16384;
/** How much of a file goes to store.wasm at a time. */
const PIECE = 16 << 20;

const ASSETS = typeof __GEX_RUNTIME_ASSETS__ === 'undefined' ? '../files/out/' : __GEX_RUNTIME_ASSETS__;
const DEFAULT_BASE = () => (ASSETS === null ? new URL('/', globalThis.location?.href).href : new URL(ASSETS, import.meta.url).href);

const ERRNO = { 2: 'ENOENT', 5: 'EIO', 6: 'ENXIO', 17: 'EEXIST', 20: 'ENOTDIR', 21: 'EISDIR', 22: 'EINVAL', 27: 'EFBIG', 28: 'ENOSPC', 16: 'EBUSY' };
const fail = (what, errno, path) => Object.assign(new Error(`${what}: ${ERRNO[errno] ?? `errno ${errno}`}${path ? `: ${path}` : ''}`), { code: ERRNO[errno] ?? 'EIO', errno });
const FOUND = ['fresh', 'restored', 'fell-back'];

let compiled = null;
function moduleFor(url) {
  compiled ??= new Map();
  if (!compiled.has(url)) {
    const m = WebAssembly.compileStreaming(fetch(url));
    m.catch(() => compiled.delete(url));
    compiled.set(url, m);
  }
  return compiled.get(url);
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/** store.wasm instantiated over `handles` (its stores 0 and 1), a copy's
 *  progress to `onProgress`, which stops it by returning false. */
async function instantiate(mod, handles, onProgress = () => true) {
  let memory = null;
  const { exports: x } = await WebAssembly.instantiate(mod, {
    store: {
      // blocks.mjs answers the kernel's store the same way: every count
      // checked, anything short a failure.
      io: (which, op, offset, ptr, len) => {
        const r = handleOp(handles[which], true, memory, op, Number(offset), ptr, len);
        if (r === NOSPACE) return -28;
        return r < 0 ? -5 : 0;
      },
      progress: (done, total) => (onProgress(done, total) === false ? 0 : 1),
    },
  });
  memory = x.memory;
  return x;
}

/** The store `name`'s file, made if missing, and its sync access handle
 *  (tried again while a system or Store just closed lets it go). */
async function storeFile(name) {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle(storeDir(name), { create: true });
  const fh = await dir.getFileHandle(STORE_FILE, { create: true });
  return { fh, h: await openHandle(fh) };
}

/** store.wasm's module for `Store.open`'s and `Store.copy`'s options. */
function wasmModule({ baseUrl, wasm }) {
  if (wasm instanceof WebAssembly.Module) return wasm;
  const own = baseUrl == null ? files?.['gex/store.wasm'] : undefined;
  return moduleFor(String(wasm ?? own ?? new URL('gex/store.wasm', new URL(baseUrl ?? DEFAULT_BASE(), globalThis.location?.href)).href));
}

const checkName = (what, name) => {
  name = String(name ?? '');
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) throw new TypeError(`${what}: name the store (letters, digits, . _ -)`);
  return name;
};
const inWorker = (what) => {
  if (typeof FileSystemFileHandle !== 'function' || !('createSyncAccessHandle' in FileSystemFileHandle.prototype)) {
    throw new Error(`${what}: a store is edited from a dedicated Worker (a sync access handle is had only there)`);
  }
};

export class Store {
  #name;
  #x;
  #fh;
  #h;
  #claim;
  #found;
  #closed = false;

  constructor(name, x, fh, h, claim, found) {
    this.#name = name;
    this.#x = x;
    this.#fh = fh;
    this.#h = h;
    this.#claim = claim;
    this.#found = found;
  }

  /**
   * The store `name` (an OPFSFilesystem's), open for editing in this
   * Worker. `wait`: until another page or Worker lets it go (`signal` stops
   * the wait), else EBUSY at once. `baseUrl`: where gex/store.wasm is, as
   * System's; `wasm` a URL or a compiled module instead. EIO when the store
   * keeps something no generation of which reads: it is never written then.
   */
  static async open(name, { wait = false, signal, baseUrl, wasm } = {}) {
    name = checkName('Store.open', name);
    inWorker('Store.open');
    const mod = await wasmModule({ baseUrl, wasm });
    const claim = await claimStore(name, { wait, signal });
    if (!claim) throw fail('Store.open', 16, `the store ${name} is open in another tab`);
    let h = null;
    try {
      const f = await storeFile(name);
      h = f.h;
      const x = await instantiate(mod, [h]);
      const found = x.st_open(BLOCK, INLINE);
      if (found < 0) throw fail('Store.open', -found, name);
      return new Store(name, x, f.fh, h, claim, FOUND[found]);
    } catch (e) {
      h?.close();
      claim.release();
      throw e;
    }
  }

  /**
   * The store `from` copied into `to`, replacing what `to` held, while
   * neither is open. Raw (the default): the store file's bytes, 16 MiB at
   * a time, written in place, so the copy needs no room beyond its own.
   * Compacting (`compact`, or any `only`): the records at or under the
   * paths in `only` (every record when none), their files' bytes packed
   * into a new store and its records written as one generation; what the
   * filter leaves out is not in the copy. `onProgress(done, total)` in
   * bytes; `signal` stops it, leaving `to` unusable (erase it). `wait`, as
   * `open`'s, for both stores.
   */
  static async copy(from, to, { only, compact = !!only?.length, onProgress, signal, wait = false, baseUrl, wasm } = {}) {
    from = checkName('Store.copy', from);
    to = checkName('Store.copy', to);
    if (from === to) throw new TypeError('Store.copy: a store is not copied into itself');
    inWorker('Store.copy');
    const mod = compact ? await wasmModule({ baseUrl, wasm }) : null;
    const claims = [];
    const handles = [];
    try {
      for (const name of [from, to]) {
        const c = await claimStore(name, { wait, signal });
        if (!c) throw fail('Store.copy', 16, `the store ${name} is open in another tab`);
        claims.push(c);
      }
      for (const name of [from, to]) handles.push((await storeFile(name)).h);
      const [src, dst] = handles;
      const stop = () => signal?.aborted;
      if (!compact) {
        const size = src.getSize();
        const buf = new Uint8Array(PIECE);
        for (let at = 0; at < size;) {
          if (stop()) throw signal.reason ?? new DOMException('Store.copy stopped', 'AbortError');
          const n = src.read(buf.subarray(0, Math.min(PIECE, size - at)), { at });
          if (!n) throw fail('Store.copy', 5, from);
          // A short count is a failure (blocks.mjs): no room, a dead handle.
          if (dst.write(buf.subarray(0, n), { at }) !== n) throw fail('Store.copy', 28, to);
          at += n;
          onProgress?.(at, size);
        }
        dst.truncate(size);
        dst.flush();
        return;
      }
      dst.truncate(0);
      const x = await instantiate(mod, handles, (done, total) => (stop() ? false : (onProgress?.(done, total), true)));
      let r = x.st_open(BLOCK, INLINE);
      if (r < 0) throw fail('Store.copy', -r, from);
      r = x.st_open_dest(BLOCK, INLINE);
      if (r < 0) throw fail('Store.copy', -r, to);
      const list = enc.encode((only ?? []).join('\n'));
      const p = x.st_alloc(list.length);
      new Uint8Array(x.memory.buffer, p, list.length).set(list);
      r = x.st_copy(p, list.length);
      x.st_dealloc(p, list.length);
      // A compacted store ends at its last block, not where it was grown to.
      const len = x.st_dest_len();
      x.st_close_dest();
      if (r >= 0 && len > 0) {
        dst.truncate(len);
        dst.flush();
      }
      x.st_close();
      if (r === -125) throw signal?.reason ?? new DOMException('Store.copy stopped', 'AbortError');
      if (r < 0) throw fail('Store.copy', -r, to);
    } finally {
      for (const h of handles) h.close();
      for (const c of claims) c.release();
    }
  }

  /** Forget the store `name`: its file removed, once no one holds it. */
  static async erase(name, { wait = true, signal } = {}) {
    const claim = await claimStore(name, { wait, signal });
    if (!claim) throw fail('Store.erase', 16, `the store ${name} is open in another tab`);
    try {
      const root = await navigator.storage.getDirectory();
      // A system or Store just closed lets the file go a moment later.
      for (let i = 0; ; i++) {
        try {
          return await root.removeEntry(storeDir(name), { recursive: true });
        } catch (e) {
          if (e?.name === 'NotFoundError') return;
          if (e?.name !== 'NoModificationAllowedError' || i >= 100) throw e;
          await new Promise((r) => setTimeout(r, 100));
        }
      }
    } finally {
      claim.release();
    }
  }

  get name() { return this.#name; }

  /** What the open read: 'fresh' (nothing kept), 'restored' (the newest
   *  generation) or 'fell-back' (the newest was torn: the one before). */
  get found() { return this.#found; }

  /** The generation read, or last written. */
  get generation() { return this.#live().st_generation(); }

  #live() {
    if (this.#closed) throw new Error(`Store ${this.#name}: closed`);
    return this.#x;
  }

  /** `fn(ptr, len)` with `s` (a string or bytes) in store.wasm's memory. */
  #with(s, fn) {
    const x = this.#live();
    const b = typeof s === 'string' ? enc.encode(s) : s;
    const p = x.st_alloc(b.length);
    try {
      new Uint8Array(x.memory.buffer, p, b.length).set(b);
      return fn(p, b.length);
    } finally {
      x.st_dealloc(p, b.length);
    }
  }

  #text(n) {
    return dec.decode(new Uint8Array(this.#x.memory.buffer, this.#x.st_out(), n));
  }

  #check(what, r, path) {
    if (r < 0) throw fail(what, -r, path);
    return r;
  }

  static #entry([path, type, size, mode, mtime]) {
    return { path, type, size, mode, mtime: mtime * 1000 };
  }

  /** Every record at or under `prefix`, in path order: `{ path, type,
   *  size, mode, mtime (ms) }`, `type` one of 'file', 'directory',
   *  'symlink', 'gone' (a path of the sources removed), 'attrs' (a file of
   *  the sources, its mode changed), 'lazy' (fetched from a URL). */
  list(prefix = '/') {
    const n = this.#check('list', this.#with(prefix, (p, l) => this.#x.st_list(p, l)), prefix);
    return JSON.parse(this.#text(n)).map(Store.#entry);
  }

  /** The record at `path`, as `list` gives it; ENOENT for none. */
  stat(path) {
    const n = this.#check('stat', this.#with(path, (p, l) => this.#x.st_stat(p, l)), path);
    return Store.#entry(JSON.parse(this.#text(n)));
  }

  readlink(path) {
    const n = this.#check('readlink', this.#with(path, (p, l) => this.#x.st_readlink(p, l)), path);
    return this.#text(n);
  }

  /**
   * The file at `path` as a Blob that reads its bytes only when asked: the
   * slices of the store file they are in. The editor never writes over a
   * block a generation names, but the browser lets a slice of a file be
   * read only while the file is as it was when the slice was taken (Chrome
   * 157: a `write` and `commit` after it, and the slice throws
   * NotReadableError). Read it before changing the store, or take
   * `read`'s bytes instead.
   */
  async blob(path) {
    const x = this.#live();
    const n = this.#with(path, (p, l) => x.st_runs(p, l));
    if (n === -22) return new Blob([this.read(path)]);
    const runs = JSON.parse(this.#text(this.#check('blob', n, path)));
    const file = await this.#fh.getFile();
    return new Blob(runs.map(([off, len]) => (off < 0 ? new Uint8Array(len) : file.slice(off, off + len))));
  }

  /** The file's bytes, or `length` of them from `offset`. */
  read(path, { offset = 0, length } = {}) {
    const size = this.stat(path).size;
    const want = Math.max(0, Math.min(length ?? size - offset, size - offset));
    const out = new Uint8Array(want);
    const x = this.#live();
    for (let at = 0; at < want;) {
      const n = Math.min(PIECE, want - at);
      const dst = x.st_alloc(n);
      try {
        const got = this.#check('read', this.#with(path, (p, l) => x.st_read(p, l, BigInt(offset + at), dst, n)), path);
        out.set(new Uint8Array(x.memory.buffer, dst, got), at);
        if (got < n) return out.subarray(0, at + got);
        at += got;
      } finally {
        x.st_dealloc(dst, n);
      }
    }
    return out;
  }

  /**
   * Write `data` (bytes, a string, or a Blob, read a piece at a time) into
   * the file at `path`: replacing it (`offset` 0 and `truncate`, the
   * default), or at `offset`. `mode` for a new file (0o644), `mtime` ms.
   */
  async write(path, data, { offset = 0, truncate = offset === 0, mode = 0o644, mtime = Date.now() } = {}) {
    const x = this.#live();
    const secs = Math.floor(mtime / 1000);
    const size = data instanceof Blob ? data.size : (typeof data === 'string' ? (data = enc.encode(data)) : (data = data instanceof ArrayBuffer ? new Uint8Array(data) : data)).length;
    let first = true;
    for (let at = 0; first || at < size; first = false) {
      const n = Math.min(PIECE, size - at);
      const piece = data instanceof Blob ? new Uint8Array(await data.slice(at, at + n).arrayBuffer()) : data.subarray(at, at + n);
      const src = x.st_alloc(n);
      try {
        new Uint8Array(x.memory.buffer, src, n).set(piece);
        this.#check('write', this.#with(path, (p, l) => x.st_write(p, l, BigInt(offset + at), src, n, mode, secs, first && truncate ? 1 : 0)), path);
      } finally {
        x.st_dealloc(src, n);
      }
      at += n;
    }
  }

  /** The record at `path` and every one under it gone. `hide`: what the
   *  sources have there is removed too (a 'gone' record). */
  remove(path, { hide = false } = {}) {
    this.#check('remove', this.#with(path, (p, l) => this.#x.st_remove(p, l, hide ? 1 : 0)), path);
  }

  mkdir(path, { mode = 0o755, mtime = Date.now() } = {}) {
    this.#check('mkdir', this.#with(path, (p, l) => this.#x.st_mkdir(p, l, mode, Math.floor(mtime / 1000))), path);
  }

  symlink(target, path) {
    this.#check('symlink', this.#with(target, (t, tl) => this.#with(path, (p, l) => this.#x.st_symlink(t, tl, p, l))), path);
  }

  chmod(path, mode) {
    this.#check('chmod', this.#with(path, (p, l) => this.#x.st_chmod(p, l, mode)), path);
  }

  /** The records at and under `from` moved to `to`. */
  rename(from, to) {
    this.#check('rename', this.#with(from, (a, al) => this.#with(to, (b, bl) => this.#x.st_rename(a, al, b, bl))), from);
  }

  /** What changed written as the next generation (every record, when
   *  `checkpoint`): whether one was written. */
  commit({ checkpoint = false } = {}) {
    return this.#check('commit', this.#live().st_commit(checkpoint ? 1 : 0), this.#name) === 1;
  }

  /** Let the store go: what was not committed is dropped. */
  close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#x.st_close();
    this.#h.close();
    this.#claim.release();
  }
}
