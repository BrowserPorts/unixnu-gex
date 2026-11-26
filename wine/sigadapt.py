"""Signature adapters for a relocatable wasm object (wcc64 -r).

A call whose declaration's type is not its callee's: wasm-ld links it to a
local stub `signature_mismatch:NAME` that traps. On the target ABI the call
works: Windows x64 (and i386's cdecl) pass arguments by position, in
registers and stack slots, and a callee reads the slots it declares. So the
stub is replaced by an adapter with those slot semantics, calling NAME's
definition:
- an argument the callee doesn't declare is dropped;
- one it declares that the caller doesn't pass is 0 (undefined on x64);
- an integer of the other width is truncated, or zero-extended as a 32-bit
  register write is;
- a result the caller doesn't take is dropped; one it takes that the callee
  doesn't give is 0.
Refused, left to the caller as errors: an integer against a float (another
register file) or floats of two widths in one slot, multiple results,
non-number types, a caller typed `() -> void` against a callee with
parameters (clang's placeholder for a vtable slot whose type it could not
convert; its real type is unknown), the shape of a struct returned through
an sret pointer against a value (one side void with one more leading i64
parameter), and a name with no definition in the object. Not seen at all: a
small struct by value (1, 2, 4 or 8 bytes) is in a register on x64 but a
pointer in wasm's C ABI, and against a scalar of the same width the two
slots look alike; wasm's types can't show it.

An address taken through the mismatched declaration stays the function's
own (only calls go through the adapter).

adapt(path) rewrites the object in place: each adapter is a new function at
the end of the code section, the stub's symbol now names it, and the stub
keeps a symbol of its own. Code offsets don't move (the relocations name
symbols), except by the code section's count growing, which shifts every
reloc.CODE offset alike. Returns [(name, caller_sig, callee_sig, None or
the refusal's reason)].
"""
import struct

I32, I64, F32, F64 = 0x7f, 0x7e, 0x7d, 0x7c
TN = {I32: 'i32', I64: 'i64', F32: 'f32', F64: 'f64'}
SYM_UNDEFINED, SYM_LOCAL, SYM_EXPLICIT_NAME = 0x10, 0x02, 0x40
# relocation types that carry an addend
ADDEND = {3, 4, 5, 8, 9, 11, 14, 15, 16, 17, 21, 22, 23, 25}
R_FUNCTION_INDEX_LEB = 0
R_TYPE_INDEX_LEB = 6


def uleb(b, i):
    r = sh = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << sh; sh += 7
        if not x & 0x80:
            return r, i


def sleb(b, i):
    r = sh = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << sh; sh += 7
        if not x & 0x80:
            if x & 0x40:
                r -= 1 << sh
            return r, i


def enc_u(v, pad=0):
    out = bytearray()
    while True:
        x = v & 0x7f; v >>= 7
        if v or pad > len(out) + 1:
            out.append(x | 0x80)
        else:
            out.append(x)
            return bytes(out)


def enc_s(v):
    out = bytearray()
    while True:
        x = v & 0x7f; v >>= 7
        if (v == 0 and not x & 0x40) or (v == -1 and x & 0x40):
            out.append(x)
            return bytes(out)
        out.append(x | 0x80)


def name(b, i):
    n, i = uleb(b, i)
    return b[i:i + n].decode('utf-8', 'surrogateescape'), i + n


def enc_name(s):
    s = s.encode('utf-8', 'surrogateescape')
    return enc_u(len(s)) + s


def sections(b):
    assert b[:4] == b'\0asm', 'not a wasm module'
    out, i = [], 8
    while i < len(b):
        sid = b[i]; n, j = uleb(b, i + 1)
        p = b[j:j + n]; i = j + n
        cname = None
        if sid == 0:
            cname, k = name(p, 0)
            p = p[k:]
        out.append([sid, cname, p])
    return out


def write(b0, secs):
    out = bytearray(b0[:8])
    for sid, cname, p in secs:
        body = (enc_name(cname) + p) if sid == 0 else p
        out += bytes([sid]) + enc_u(len(body)) + body
    return bytes(out)


def sig_str(s):
    return '(%s) -> %s' % (', '.join(TN.get(t, hex(t)) for t in s[0]),
                           ', '.join(TN.get(t, hex(t)) for t in s[1]) or 'void')


def plan(caller, callee):
    """The adapter's body (without locals and end), or a refusal."""
    (cp, cr), (dp, dr) = caller, callee
    if any(t not in TN for t in cp + cr + dp + dr):
        return None, 'a type that is not a number'
    if len(cr) > 1 or len(dr) > 1:
        return None, 'multiple results'
    if not cp and not cr and dp:
        return None, 'a caller typed () -> void (clang\'s placeholder of an unknown type)'
    if bool(cr) != bool(dr):
        v, o = (cp, dp) if not cr else (dp, cp)
        if len(v) == len(o) + 1 and v[0] == I64:
            return None, 'the shape of a struct returned through an sret pointer'
    code = bytearray()
    for k, t in enumerate(dp):
        if k < len(cp):
            c = cp[k]
            code += b'\x20' + enc_u(k)  # local.get
            if c == t:
                pass
            elif c == I64 and t == I32:
                code += b'\xa7'  # i32.wrap_i64
            elif c == I32 and t == I64:
                code += b'\xad'  # i64.extend_i32_u
            elif {c, t} <= {F32, F64}:
                return None, 'floats of two widths in parameter %d' % (k + 1)
            else:
                return None, 'an integer against a float in parameter %d' % (k + 1)
        else:
            code += {I32: b'\x41\x00', I64: b'\x42\x00', F32: b'\x43' + bytes(4), F64: b'\x44' + bytes(8)}[t]
    call_at = len(code) + 1
    code += b'\x10' + bytes(5)  # call NAME (index and relocation below)
    if dr and not cr:
        code += b'\x1a'  # drop
    elif cr and not dr:
        code += {I32: b'\x41\x00', I64: b'\x42\x00', F32: b'\x43' + bytes(4), F64: b'\x44' + bytes(8)}[cr[0]]
    elif cr and dr and cr[0] != dr[0]:
        c, t = cr[0], dr[0]
        if t == I64 and c == I32:
            code += b'\xa7'
        elif t == I32 and c == I64:
            code += b'\xad'
        elif {c, t} <= {F32, F64}:
            return None, 'floats of two widths in the result'
        else:
            return None, 'an integer against a float in the result'
    return (bytes(code), call_at), None


def adapt(path, names=None):
    b = open(path, 'rb').read()
    secs = sections(b)
    by = {}
    for k, s in enumerate(secs):
        by[s[1] if s[0] == 0 else s[0]] = k
    if 'linking' not in by or 10 not in by:
        return []
    # types
    types = []
    p = secs[by[1]][2] if 1 in by else b''
    if p:
        n, i = uleb(p, 0)
        for _ in range(n):
            assert p[i] == 0x60; i += 1
            m, i = uleb(p, i); par = list(p[i:i + m]); i += m
            m, i = uleb(p, i); res = list(p[i:i + m]); i += m
            types.append((par, res))
    # function types: imports, then the function section
    ftypes = []
    nimp_kind = {0: 0, 2: 0, 4: 0, 5: 0}  # function, global, tag, table imports
    if 2 in by:
        p = secs[by[2]][2]; n, i = uleb(p, 0)
        for _ in range(n):
            _, i = name(p, i); _, i = name(p, i)
            kind = p[i]; i += 1
            if kind == 0:
                t, i = uleb(p, i); ftypes.append(t); nimp_kind[0] += 1
            elif kind == 1:
                i += 1; fl, i = uleb(p, i); _, i = uleb(p, i)
                if fl & 1: _, i = uleb(p, i)
                nimp_kind[5] += 1
            elif kind == 2:
                fl, i = uleb(p, i); _, i = uleb(p, i)
                if fl & 1: _, i = uleb(p, i)
            elif kind == 3:
                i += 2; nimp_kind[2] += 1
            elif kind == 4:
                i += 1; _, i = uleb(p, i); nimp_kind[4] += 1
    nimp = len(ftypes)
    fsec = secs[by[3]][2]; n, i = uleb(fsec, 0)
    for _ in range(n):
        t, i = uleb(fsec, i); ftypes.append(t)
    # the symbol table
    lk = secs[by['linking']][2]
    ver, i = uleb(lk, 0)
    subs = []
    while i < len(lk):
        st = lk[i]; ln, j = uleb(lk, i + 1)
        subs.append([st, lk[j:j + ln]]); i = j + ln
    sti = [k for k, s in enumerate(subs) if s[0] == 8]
    if not sti:
        return []
    sp = subs[sti[0]][1]
    nsym, i = uleb(sp, 0)
    # [kind, flags, index or None, name, raw bytes (None once changed)].
    # A symbol whose index is an import of its kind is undefined whatever its
    # flags: wasm-ld -r writes a weak import (__main_argc_argv, after main's
    # own mismatch with crt_main.o from an archive) without UNDEFINED
    syms = []
    for _ in range(nsym):
        start = i
        kind = sp[i]; i += 1
        fl, i = uleb(sp, i)
        if kind in (0, 2, 4, 5):
            idx, i = uleb(sp, i)
            nm = None
            if fl & SYM_EXPLICIT_NAME or not (fl & SYM_UNDEFINED or idx < nimp_kind[kind]):
                nm, i = name(sp, i)
            elif idx < nimp_kind[kind]:
                fl |= SYM_UNDEFINED
            syms.append([kind, fl, idx, nm, sp[start:i]])
        else:
            if kind == 1:
                nm, i = name(sp, i)
                if not fl & SYM_UNDEFINED:
                    _, i = uleb(sp, i); _, i = uleb(sp, i); _, i = uleb(sp, i)
            else:
                _, i = uleb(sp, i); nm = None
            syms.append([kind, fl, None, nm, sp[start:i]])
    # import names for undefined functions without an explicit name
    defined = {}
    for k, s in enumerate(syms):
        if s[0] == 0 and not s[1] & SYM_UNDEFINED and not s[1] & SYM_LOCAL and s[3]:
            defined[s[3]] = k
    stubs = [k for k, s in enumerate(syms) if s[0] == 0 and s[1] & SYM_LOCAL and not s[1] & SYM_UNDEFINED
             and (s[3] or '').startswith('signature_mismatch:')]
    result, made = [], []
    for k in stubs:
        nm = syms[k][3][len('signature_mismatch:'):]
        if names is not None and nm not in names:
            continue
        caller = types[ftypes[syms[k][2]]]
        if nm not in defined:
            result.append((nm, sig_str(caller), '?', 'no definition in the object'))
            continue
        target = syms[defined[nm]][2]
        callee = types[ftypes[target]]
        body, why = plan(caller, callee)
        result.append((nm, sig_str(caller), sig_str(callee), why))
        if body:
            made.append((k, defined[nm], target, body))
    if not made:
        return result
    # append the adapters
    code = secs[by[10]][2]
    ncode, c0 = uleb(code, 0)
    nfun, f0 = uleb(fsec, 0)
    newf = fsec[f0:]
    newc = bytearray(code[c0:])
    relocs_new = []
    nfuncs = nimp + nfun
    for j, (k, dsym, target, (body, call_at)) in enumerate(made):
        fidx = nfuncs + j
        newf += enc_u(ftypes[syms[k][2]])
        b2 = bytearray(b'\x00' + body + b'\x0b')  # no locals
        b2[1 + call_at:1 + call_at + 5] = enc_u(target, pad=5)
        fn = enc_u(len(b2)) + b2
        # offset of the call's index within the section: count, the bodies so far, this one's size
        relocs_new.append((len(newc) + len(enc_u(len(b2))) + 1 + call_at, dsym))
        newc += fn
        # the stub's symbol names the adapter; the stub keeps one of its own
        old = syms[k][2]
        syms[k][2] = fidx
        syms[k][4] = None
        syms.append([0, SYM_LOCAL, old, 'signature_mismatch_trap:' + nm, None])
    cnt = enc_u(ncode + len(made))
    delta = len(cnt) - c0
    secs[by[10]][2] = cnt + bytes(newc)
    relocs_new = [(o + len(cnt), s) for o, s in relocs_new]
    secs[by[3]][2] = enc_u(nfun + len(made)) + bytes(newf)
    # the symbol table again
    out = bytearray(enc_u(len(syms)))
    for kind, fl, idx, nm, raw in syms:
        if raw is not None:
            out += raw
            continue
        out += bytes([kind]) + enc_u(fl) + enc_u(idx)
        if not fl & SYM_UNDEFINED or fl & SYM_EXPLICIT_NAME:
            out += enc_name(nm)
    subs[sti[0]][1] = bytes(out)
    secs[by['linking']][2] = enc_u(ver) + b''.join(bytes([st]) + enc_u(len(sb)) + sb for st, sb in subs)
    # The relocations: reloc.CODE shifted by the count's growth and the
    # adapters' calls added; in every section, an address taken through the
    # mismatched declaration (any relocation but a call) names the
    # definition again, not the adapter: the function itself, its own entry
    # thunk and facts, equal to a pointer taken where its type is known
    retarget = {k: dsym for k, dsym, _, _ in made}
    code_index = by[10]
    have_code = False
    for s in secs:
        if not (s[0] == 0 and s[1] and s[1].startswith('reloc.')):
            continue
        p = s[2]
        si, i = uleb(p, 0); n, i = uleb(p, i)
        code = si == code_index
        ents = bytearray()
        for _ in range(n):
            ty = p[i]; i += 1
            off, i = uleb(p, i); ix, i = uleb(p, i)
            # (R_WASM_TYPE_INDEX_LEB's index is a type's, not a symbol's)
            if ty not in (R_FUNCTION_INDEX_LEB, R_TYPE_INDEX_LEB) and ix in retarget:
                ix = retarget[ix]
            e = bytes([ty]) + enc_u(off + (delta if code else 0)) + enc_u(ix)
            if ty in ADDEND:
                ad, i = sleb(p, i); e += enc_s(ad)
            ents += e
        if code:
            have_code = True
            for o, sy in relocs_new:
                ents += bytes([R_FUNCTION_INDEX_LEB]) + enc_u(o) + enc_u(sy)
            n += len(relocs_new)
        s[2] = enc_u(si) + enc_u(n) + bytes(ents)
    if not have_code:
        ents = b''.join(bytes([R_FUNCTION_INDEX_LEB]) + enc_u(o) + enc_u(sy) for o, sy in relocs_new)
        secs.append([0, 'reloc.CODE', enc_u(code_index) + enc_u(len(relocs_new)) + ents])
    open(path, 'wb').write(write(b, secs))
    return result


if __name__ == '__main__':
    import sys
    for r in adapt(sys.argv[1]):
        print('%s: %s calls %s: %s' % (r[0], r[1], r[2], r[3] or 'adapted'))
