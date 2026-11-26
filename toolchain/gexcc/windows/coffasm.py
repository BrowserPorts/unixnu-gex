#!/usr/bin/env python3
"""coffasm.py IN OUT: preprocessed assembly written for a COFF (MinGW)
assembler, as the wasm assembler takes it. Only data assembles for wasm (data
blobs: .incbin'd tables, embedded resources); code fails there, loudly.

- `.section NAME, "FLAGS"` with COFF flags (d, r, w, n, s, i...) becomes
  `.section NAME,"",@`: a wasm data segment of that name.
- A label defined in a data section without a `.size` gets one, up to the
  next label in that section or the section's end: wasm data symbols have a
  size, COFF ones don't.
- COFF-only directives (.def/.scl/.type N/.endef, .seh_*, .linkonce) are
  dropped."""
import re, sys

src = open(sys.argv[1]).read().split('\n')
out = []
sized = set(m.group(1) for l in src for m in [re.match(r'\s*\.size\s+([^\s,]+)', l)] if m)
open_label = None  # the data label waiting for its size


def close():
    global open_label
    if open_label:
        out.append('.size %s, . - %s' % (open_label, open_label))
        open_label = None


in_data = False
for line in src:
    s = line.split('#', 1)[0].split('//', 1)[0].strip() if not line.lstrip().startswith('#') else ''
    m = re.match(r'\.section\s+([^\s,]+)\s*(?:,\s*"([^"]*)"\s*)?(.*)$', s)
    if m:
        close()
        name, flags, rest = m.groups()
        if '@' not in s and (flags is None or re.fullmatch(r'[bdnrswiyx]*', flags)):
            out.append('.section %s,"",@' % name)
        else:
            out.append(line)
        in_data = True
        continue
    if re.match(r'\.(text|data|bss|rodata)\b', s):
        close()
        in_data = s.startswith(('.data', '.rodata', '.bss'))
        out.append(line)
        continue
    if re.match(r'\.(def|scl|endef|seh_\w+|linkonce)\b', s) or re.match(r'\.type\s+-?\d+\s*;?$', s):
        continue
    m = re.match(r'([A-Za-z_.$@][\w.$@]*):', s)
    if m and in_data and not m.group(1).startswith('.L'):
        close()
        out.append(line)
        if m.group(1) not in sized:
            open_label = m.group(1)
        continue
    out.append(line)
close()
open(sys.argv[2], 'w').write('\n'.join(out))
