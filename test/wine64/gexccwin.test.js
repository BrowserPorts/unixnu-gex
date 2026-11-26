// gexcc-win programs (native wasm modules beside their .exe) on 64-bit
// Wine under gexc, without the door, with the gexcc-win install
// GEX_TEST_GEXCC_WIN (fixtures/wine64, fixtures/wine/src):
// - cxxcatch: an indirect call inside a catch block, a rethrow, a try in a
//   catch; cxxthr: throws and thread_local data on several threads;
// - vtdecl: a vtable emitted in an object where one virtual's result type
//   is incomplete (clang's placeholder `void ()` declaration), and a
//   function of that result whose address is passed as an argument, both
//   defined in another object: it links (no thunk made through the
//   placeholder) and both calls return the struct;
// - dllimps: calls of DLL functions Wine's own native modules do not import;
// - timerproc: timer procedures, the program's own and comctl32's, through
//   DispatchMessage, a message box's loop and the menu loop;
// - lresult: negative and 64-bit LRESULTs through user32's message calls
//   from a program that names no import libraries, as MinGW programs do;
// - cbfault: a wild read in a window procedure under a user callback is an
//   access violation its vectored handler sees, and the process goes on;
// - ptval: user32 calls taking a POINT by value, directly and through
//   GetProcAddress's pointers;
// - imagebase: &__ImageBase is the program's module handle (GexIcall reads
//   __gexw_image_base at each use).
// - selfaddr: GetModuleHandleExW(FROM_ADDRESS) on the program's own data,
//   zeroed data and function is the program's module;
// - exitshape: native calls of a native DLL's exports through GetProcAddress's
//   pointers (guest addresses, out through the guest) agree with calls
//   through its table for every shape conv.h has;
// - bigdata: 24 MiB of zeroed data, more than the page's PE data window
//   for builtins' data exports holds: its ends written and read, and the
//   program's module;
// - fontset: IDWriteFontSet::GetMatchingFonts by family, weight, stretch
//   and style, on the system set (Tahoma bold first when asked for bold)
//   and on a set of a font file in memory;
// - modcase: the program and its module installed under other case
//   (ModCase.exe, ModCase.exe.wasm) than the name its .wasmref gives
//   (modcase.exe.wasm): the module found without case, as Windows finds
//   files;
// - prelude: a one-step C++ compile and link gets the program's own
//   -include, then gexcc-win's prelude;
// - wkdata: weak undefined data links and its address is null; weak data
//   a DLL defines (wkdll) reads the DLL's;
// - wkfunc: weak undefined functions are null, not stubs (C's weak
//   declaration, C++'s thread_local init function, a DLL's weak reference);
//   a strong reference to the same name in another module still fails to
//   link, and a stubbed strong one is never null, natively or on the page;
// - fficall: libffi (-lffi): ffi_call to a DLL's functions as native values
//   and as GetProcAddress's guest ones, mixed scalars and structs by value,
//   a variadic call; closures refused (FFI_BAD_ABI);
// - missimp: an import no DLL exports, bound to a stub (listed at the
//   link): the program runs, and a call of it ends the process as Wine's
//   stubs do;
// - bigrelocs: more addresses in data than one function of their
//   relocations applies within the engines' function size limit (pelink
//   splits it);
// - hostdatacc: hostdata.c's statics, gex's memory outside every image;
// - shmview-same, -whole, -shifted: two views of one section in one
//   process (Firefox's Shmem with e10s off) are one range, records handed
//   through them under section churn read back as written, and ended
//   threads' TLS chunks no longer show as Wine's memory; shmview-based: a
//   view at an address asked for, a separate copy (expected); shmview-rdonly:
//   a read-only first view and a read-write second, one range, written
//   through the second (it reports read-write: one range, one protection,
//   an expected gap); shmview-big: a page viewed at the start of a 256 MiB
//   section and one at 200 MiB, one range;
// - owndll: a program linked against its own DLL's import library, the
//   DLL's exports its default-visibility symbols: calls, a struct by value,
//   the DLL's int and struct written and read on both sides;
// - wmain0, wmain3: wmain(void) and wmain(argc, argv, envp);
// - xthr: a just-loaded DLL's function called by a thread with no system
//   call since; xhoist: a call loop's hoisted ICALL bound while another
//   thread loads a DLL and points the loop into it.
// - sigadapt: calls through declarations whose types are not the
//   functions' (a K&R definition called with arguments, a missing argument,
//   i64 for i32 both ways, void against a value) adapted at the link with
//   Windows x64's slot semantics and listed with GEX_WCC_VERBOSE; sigrefuse:
//   an int where the callee reads a double is refused;
// - defdll: a .def with an export named twice, data without DATA and an
//   export named `name`.
// The null driver where a window is made.
import { gexccWin } from './cases.mjs';
import { wine64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], images: ['win-progs'], timeout: 2400 };

export default async function (t) {
  const w = wine64(t, { door: 0 });
  await gexccWin(t, w);
  w.clean();
}
