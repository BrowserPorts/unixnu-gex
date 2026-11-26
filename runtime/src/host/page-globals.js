// The runtime's globals, set from the page's switches (System's `debug`).
// Internal, not the runtime's API.
import { pageOptions } from '../../../hosts/browser/js/options.mjs';

/**
 * The runtime's globals from its switches (`get(name)`): what gex.mjs,
 * runtime.js and the Workers read. One list, for the library and the test
 * page; its own module so a test can drive it without a page.
 */
export function setGlobals(get, b = {}) {
  // The switches every page takes (hosts/browser/js/options.mjs).
  pageOptions(get);
  // The guest's architecture: x86 unless the build says aarch64 (a Linux
  // tree of Debian's arm64 packages), which picks the aarch64 shim, seed and
  // kernel (runtime.js).
  globalThis.GEX_ARCH = b.arch === 'aarch64' ? 'aarch64' : 'x86';
  if (get('heartbeat')) globalThis.GEX_HEARTBEAT = Number(get('heartbeat'));
  if (get('mem64') === '1' || b.mem64) globalThis.GEX_MEM64 = 1;
  // The function JIT: off by default (it doubles a 32-bit Wine program's
  // start-up). `fjit=1` translates each function at its first miss, on the
  // thread that missed; `fjit=hot` leaves the first run to tier-1 and
  // translates what the safepoint's samples find hot on a helper Worker of
  // the process; `fjit=hotsync` is that with the translation inline (fjit.rs
  // `gex_set_fjit`'s numbers: 3 and 5).
  const fjit = get('fjit');
  if (fjit !== null && fjit !== '0') globalThis.GEX_FJIT = { hot: 3, hotsync: 5 }[fjit] ?? (Number(fjit) || 1);
  if (get('elfunits') && get('cgen') !== '0') globalThis.GEX_ELF_UNITS = get('elfunits');
  if (get('pins')) globalThis.GEX_PINS = get('pins');
  if (get('dense') === '0') globalThis.GEX_DENSE = 0;
  if (get('dense') === '2') globalThis.GEX_DENSE = 2;
  // cgen=1|2 (prefer|require units), the unguarded flavour unless unguarded=0.
  // icallcount=1: the counting flavour of units (16), whose run prints the
  // indirect-call profile (cgen.rs gex_icall_dump; GEX_CGEN_ICALL_COUNT=1 units).
  // cgen=0 is off: no unit of any kind, the ELF objects' among them.
  const cgen = get('cgen');
  if (cgen && cgen !== '0') globalThis.GEX_CGEN = Number(cgen) | (get('unguarded') === '0' ? 0 : 4) | (get('icallcount') === '1' ? 16 : 0);
  if (get('cgenurl')) globalThis.GEX_CGEN_URL = get('cgenurl');
  // cgenzst=1: each unit's module is served as KEY/c.wasm.zst, decoded before it is compiled.
  if (get('cgenzst') === '1') globalThis.GEX_CGEN_ZST = 1;
  if (get('aot') === '1') globalThis.GEX_NO_JIT = 1;
  if (get('aot')) globalThis.GEX_AOT = 1;
  globalThis.GEX_UNIT_CACHE = get('unitcache') !== null ? Number(get('unitcache')) : 1;
}
