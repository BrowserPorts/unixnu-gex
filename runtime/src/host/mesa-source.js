// Mesa's files for the GL device (mesa-gl.js `loadFromSource`) from the
// page's own source (MesaGl's `source`, or app.js's `mesaSource` over a
// site's pack): the glue (`gex-wgpu-replay.js`), the module and its cold
// part, each fetched once however many ask for it. Without a source the
// device fetches them itself from the system's baseUrl.

/** Mesa's files, by the names the device asks for. */
export const MESA_FILES = ['gex-wgpu-replay.js', 'gex-wgpu-replay.wasm', 'gex-wgpu-replay.deferred.wasm'];

/**
 * A site's source (app.js): `at(rel)` is a file's URL; `entry(href)` its
 * pack entry or null; `packed(href, entry)` its bytes from the pack (the
 * site's .zst and the page's cache). A file not packed comes as the plain
 * file, and one the site has not (no cold part in an unsplit build) is
 * null. The result is `source(name)`: a promise of the bytes or null.
 */
export function mesaSource(at, entry, packed, { fetch: get = (u) => fetch(u) } = {}) {
  const got = new Map();
  return (name) => {
    if (!got.has(name)) {
      const p = (async () => {
        const href = at(`gex/${name}`);
        const z = await entry(href);
        if (z) return packed(href, z);
        const r = await get(href);
        if (r.status === 404) return null;
        if (!r.ok) throw new Error(`${href}: ${r.status}`);
        return new Uint8Array(await r.arrayBuffer());
      })();
      got.set(name, p);
      // A failure is not kept: the next ask tries again.
      p.catch(() => got.delete(name));
    }
    return got.get(name);
  };
}

/**
 * The files a device is handed from `source` (compositor.js `hostGl`), by
 * name, or null to leave it all to the device's own fetches. The glue and
 * the module are enough: a build with no cold part has none to give.
 */
export async function mesaSources(source) {
  const got = await Promise.all(MESA_FILES.map((n) => Promise.resolve().then(() => source(n)).catch(() => null)));
  if (!got[0] || !got[1]) return null;
  return Object.fromEntries(MESA_FILES.map((n, i) => [n, got[i]]));
}
