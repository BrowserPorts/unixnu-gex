#!/usr/bin/env python3
"""mingwlibs.py MINGW_W64_CRT: mingw-w64-crt's static libraries that are only
libsrc/*.c (the GUID libraries: uuid, dxguid, strmiids, locationapi ...), one
line each: NAME KIND FILE..., KIND 'dll' where MinGW's libNAME.a is also the
DLL's import library (ksuser, windowscodecs, shell32: the static GUIDs beside
the imports), else 'static'. install.sh builds them for a mingw-headers
install; gexcc-win links -lNAME to them and, for 'dll', imports the DLL too.
ws2_32's objects are in libgexcc-win.a already. Not dinput: its data
formats are data in section .text (ATTRIBUTE_TEXT_SECTION), which wasm has
no place for."""
import os, re, sys

crt = sys.argv[1]
text = open(os.path.join(crt, 'Makefile.am')).read().replace('\\\n', ' ')
for m in re.finditer(r'^src_lib(\w+)\s*=(.*)$', text, re.M):
    name, files = m.group(1), m.group(2).split()
    if name in ('ws2_32', 'dinput') or not files or not all(f.startswith('libsrc/') and f.endswith('.c') for f in files):
        continue
    dll = any(os.path.exists(os.path.join(crt, d, name + ext))
              for d in ('lib64', 'lib-common') for ext in ('.def', '.def.in'))
    print(name, 'dll' if dll else 'static', *files)
