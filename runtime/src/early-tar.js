// A tar laid while it downloads, the guest started before its end (fs.js
// `addTar(src, { early: true })`): an archive whose first entry is its index
// (INDEX_PATH; the records of hosts/kernel `k_fs_seed`: every directory,
// file, link, mode and time) is named whole at once, and its files' bytes
// come in as they are unpacked (kfs.js `#layEarly`): a program's use of a
// file not yet in waits for it, a lookup or `stat` never does. An archive
// without an index is laid part by part as it arrives, the guest started
// once it is all in (kfs.js `#layStream`).
import { TarStream } from './host/tar.js';
import { isZstd, zstdDecoder } from './host/zfetch.js';

/** The index's path: the archive's first entry. */
export const INDEX_PATH = '/.gex-index';
/** The most file bytes in one part laid: a file a program waits for is laid
 *  within a megabyte of its arrival. */
const PART_BYTES = 1 << 20;

/** The archive's bytes as a stream: a ReadableStream, a Response, a Blob,
 *  bytes, or a URL fetched. */
async function body(src) {
  if (src instanceof ReadableStream) return src;
  if (typeof Response === 'function' && src instanceof Response) {
    if (!src.ok) throw new Error(`tar ${src.url}: ${src.status} ${src.statusText}`);
    return src.body;
  }
  if (typeof Blob === 'function' && src instanceof Blob) return src.stream();
  if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
    const b = src instanceof ArrayBuffer ? new Uint8Array(src) : new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
    return new ReadableStream({ start(c) { c.enqueue(b); c.close(); } });
  }
  if (typeof src === 'string' || src instanceof URL) {
    const href = new URL(src, globalThis.location?.href).href;
    const r = await fetch(href);
    if (!r.ok) throw new Error(`tar ${href}: ${r.status} ${r.statusText}`);
    return r.body;
  }
  throw new TypeError('addTar early: a stream, a Response, a Blob, bytes or a URL');
}

/** The layer kfs.js lays as an image (`stream`, `streamIndex`): its parts
 *  as they are unpacked, its index once the first entry is in (null for an
 *  archive without one). */
export function earlyLayer(src) {
  const queue = [];
  let wake = null, finished = false, failure = null;
  let index = null, indexFound;
  const indexSeen = new Promise((r) => { indexFound = r; });
  const ts = new TarStream();
  const kick = () => { const w = wake; wake = null; w?.(); };
  const put = (t) => {
    const ix = t.files[INDEX_PATH];
    if (ix) {
      delete t.files[INDEX_PATH];
      delete t.modes[INDEX_PATH];
      delete t.mtimes[INDEX_PATH];
      // The index names every directory and link: theirs go unread.
      if (!index) { index = ix.slice(); ts.skipLinks = true; }
    }
    // The first entry decides: an index or none.
    if (!index && (Object.keys(t.files).length || t.dirs.length)) indexFound(null);
    else if (index) indexFound(index);
    if (!t.dirs.length && !Object.keys(t.files).length && !Object.keys(t.links).length && !Object.keys(t.hard).length
      && !Object.keys(t.mtimes).length && !Object.keys(t.xattrs).length && !Object.keys(t.modes).length) return;
    queue.push(t);
    kick();
  };
  (async () => {
    const reader = (await body(src)).getReader();
    let z = null, first = true;
    const sink = (piece) => {
      ts.push(piece);
      // The index alone first, so the guest may start at once.
      if (!index || ts.pending >= PART_BYTES) put(ts.take());
    };
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value?.length) continue;
        if (first) {
          first = false;
          if (isZstd(value)) z = (await zstdDecoder()).stream();
        }
        if (z) z.push(value, sink);
        else sink(value);
      }
    } finally {
      z?.end();
    }
    ts.end();
    put(ts.take());
    finished = true;
  })().catch((e) => { failure = e; }).finally(() => { indexFound(index); kick(); });
  async function* parts() {
    for (;;) {
      if (queue.length) { yield queue.shift(); continue; }
      if (failure) throw failure;
      if (finished) return;
      await new Promise((r) => { wake = r; });
    }
  }
  return { image: true, early: true, stream: parts(), streamIndex: indexSeen };
}
