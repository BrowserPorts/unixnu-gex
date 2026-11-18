/**
 * Which Wine a run starts game controllers for (run-program.js
 * `controllersWine`)?
 *
 * A 64-bit Wine with controllers has SDL beside its loader. A run of the
 * loader itself starts them, as before; so does a run that starts Wine from a
 * launch script (Stellite runs /bin/sh with one), from the build's loader that
 * start() passes as `wine`. A Wine without SDL, or no Wine, starts none.
 *
 * Usage: node test/fixtures/page/wine-controllers.mjs
 */
import { pathToFileURL as gexPathToFileURL } from 'node:url';
import { join as gexJoin } from 'node:path';
const GEX_ROOT = process.env.GEX_ROOT || gexJoin(import.meta.dirname, '..', '..', '..');
const { controllersWine } = await import(gexPathToFileURL(gexJoin(GEX_ROOT, 'page/src/run-program.js')).href);

let failed = 0;
const check = (what, got, want) => {
  const ok = got === want;
  console.log(`${ok ? 'ok' : 'FAIL'} ${what}${ok ? '' : ` (${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
  if (!ok) failed++;
};
const bundle = (...paths) => (p) => paths.includes(p);
const w64 = bundle('/wine64/bin/libSDL2-2.0.so.0');

check('the loader itself, SDL beside it', controllersWine('/wine64/bin/wine', null, w64), '/wine64/bin/wine');
check('a launch script, the build\'s loader named', controllersWine('/bin/sh', '/wine64/bin/wine', w64), '/wine64/bin/wine');
check('a launch script, no loader named', controllersWine('/bin/sh', null, w64), null);
check('a launch script, a loader without SDL', controllersWine('/bin/sh', '/w3/lib/wine/i386-unix/wine', w64), null);
check('a named program that is not Wine', controllersWine('/bin/sh', '/bin/busybox', w64), null);
check('the loader itself wins over a named one', controllersWine('/wine64/bin/wine', '/other/bin/wine', w64), '/wine64/bin/wine');

if (failed) {
  console.error(`wine controllers check FAILED: ${failed}`);
  process.exit(1);
}
