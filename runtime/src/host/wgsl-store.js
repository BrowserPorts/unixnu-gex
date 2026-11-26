// The WGSL translation cache's records in this browser (IndexedDB 'gex-wgsl-cache', store
// 'blobs'), for mesa-gl.js. A cache's key (its Mesa build's glue URL) holds the base
// record, and each run that has translated since holds a record of its own under
// `${key}#${session}`: only what that run translated (Mesa's fresh entries), rewritten as it
// grows. A run saves its few new translations, never the whole cache again, while a game plays
// (a whole dump of up to 32 MiB every 5 s was work on the page's thread mid-frame). The next run
// loads the base and every run's record, then folds them into one new base, once, at its start.

const DB = 'gex-wgsl-cache';
const STORE = 'blobs';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
}

/** Run `work(store)` in one transaction; resolves with what it returns once that has committed. */
async function inTx(mode, work) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let out;
      tx.oncomplete = () => resolve(out);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? new Error('aborted'));
      Promise.resolve(work(tx.objectStore(STORE))).then((v) => { out = v; }, (e) => { tx.abort(); reject(e); });
    });
  } finally {
    db.close();
  }
}

const request = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

const isRun = (key, k) => typeof k === 'string' && k.startsWith(`${key}#`);

/** The base record and every run's record of cache `key`: `[[k, blob], ...]`, the base first. */
export function readAll(key) {
  return inTx('readonly', async (store) => {
    const keys = (await request(store.getAllKeys())).filter((k) => k === key || isRun(key, k));
    keys.sort((a, b) => (a === key ? -1 : b === key ? 1 : a < b ? -1 : 1));
    const out = [];
    for (const k of keys) out.push([k, await request(store.get(k))]);
    return out;
  });
}

/** `whole` as the base record of cache `key`, and its runs' records gone: in one transaction. */
export function fold(key, whole) {
  return inTx('readwrite', async (store) => {
    const runs = (await request(store.getAllKeys())).filter((k) => isRun(key, k));
    if (whole) store.put(whole, key);
    for (const k of runs) store.delete(k);
    return runs.length;
  });
}

/** This run's record of cache `key`, replaced by `blob` (what it has translated so far). */
export function saveRun(runKey, blob) {
  return inTx('readwrite', (store) => { store.put(blob, runKey); });
}

/** A key for this run's record of cache `key`. */
export const runKey = (key) => `${key}#${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
