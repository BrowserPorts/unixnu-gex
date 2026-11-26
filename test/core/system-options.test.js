// System's units and mem64 options (core/system-mem64 runs a program with
// mem64): `mem64` and `units`' `jit: false`, `providers` and `stateful`
// reach the runtime as gex's own switches do (GEX_NO_JIT, the provider
// sources, the stateful list), and a malformed one is a TypeError before the page's one system is taken.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], arches: ['x86'], images: ['busybox'], timeout: 120 };

export default async function (t) {
  const { eq, check, timeout } = t;
  const bad = (o) => { try { new System({ baseUrl: t.baseUrl, ...o }); return null; } catch (e) { return e; } };
  check('units without a url', bad({ units: { require: true } }) instanceof TypeError);
  check('an unknown units option', bad({ units: { url: '/u', jti: false } }) instanceof TypeError);
  check('providers not [{ name, source }]', bad({ units: { url: '/u', providers: [{ name: 'a' }] } }) instanceof TypeError);
  check('stateful not { dll: file }', bad({ units: { url: '/u', stateful: { 'a=b.dll': 'f' } } }) instanceof TypeError);

  const units = new URL(t.work('no-units/'), globalThis.location?.href ?? 'file:///').href;
  const sys = new System({
    baseUrl: t.baseUrl,
    debug: t.debug(),
    mem64: true,
    units: { url: units, jit: false, providers: [{ name: 'fmod', source: 'int x;' }, { name: 'zz', source: 'int y;' }], stateful: { 'a.dll': 'stateful/a.wasm', 'b.dll': 'stateful/b.wasm' } },
  });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  // Boot only: with no units and no translation, no program could run.
  await timeout(sys.boot(), 60000, 'boot');
  const q = new URLSearchParams(globalThis.GEX_PAGE_SEARCH ?? '');
  eq('jit: false is the switch aot=1', q.get('aot'), '1');
  eq('and units at their url', q.get('cgenurl'), units.replace(/\/*$/, ''));
  eq('mem64: the switch', q.get('mem64'), '1');
  eq('the providers, each name and source', globalThis.GEX_PROVIDER_SOURCES, 'fmod\nint x;\0zz\nint y;');
  eq('the stateful list', globalThis.GEX_STATEFUL, 'a.dll=stateful/a.wasm,b.dll=stateful/b.wasm');
  eq('translation off in the runtime', globalThis.GEX_NO_JIT, 1);
  eq('a 64-bit memory for every program', globalThis.GEX_MEM64, 1);
  await sys.shutdown();
}
