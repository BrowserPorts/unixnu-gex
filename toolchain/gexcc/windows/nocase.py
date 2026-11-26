#!/usr/bin/env python3
"""nocase.py OUT.yaml DIR...: a clang VFS overlay (-ivfsoverlay) over the
header trees DIR... that matches their names regardless of case, as Windows
does: a source's <Rpc.h> is rpc.h. Names the overlay doesn't list (a header
added later) still resolve as spelled. The overlay holds absolute paths:
an install tree that moves needs install.sh run again."""
import json
import os
import sys


def tree(d):
    out = []
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if os.path.isdir(p):
            out.append({'name': n, 'type': 'directory', 'contents': tree(p)})
        elif n.endswith(('.h', '.hpp', '.hxx', '.inl', '.idl', '.rh')) or '.' not in n:
            out.append({'name': n, 'type': 'file', 'external-contents': os.path.abspath(p)})
    return out


roots = [{'name': os.path.abspath(d), 'type': 'directory', 'contents': tree(d)} for d in sys.argv[2:]]
with open(sys.argv[1], 'w') as f:
    json.dump({'version': 0, 'case-sensitive': 'false', 'roots': roots}, f)
