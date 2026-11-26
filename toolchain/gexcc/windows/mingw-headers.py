#!/usr/bin/env python3
"""mingw-headers.py MINGW_HEADERS_SRC OUT: mingw-w64's headers (its
mingw-w64-headers directory: include/, crt/, ddk/) installed for gexcc-win's
Windows x64 programs, which clang compiles for wasm64 with x64's data model.

The headers choose layouts by the target's macros (__x86_64__, _AMD64_,
_M_AMD64 ...), which the wasm64 target does not predefine and programs
must not see (they would take their x86 code paths). Their tests are
answered by a private macro instead, __GEXW_SDK_X64__, which gexcc-win
defines; the headers' own definitions of the target macros are dropped.
The headers whose x64 parts are x86 code (inline asm, x86 intrinsics) keep
their generic paths or are replaced by include-mingw-pre/ (intrin-impl.h's
intrinsics in portable C). A front end that is x86_64 itself (the wasm32-as-i386
plan's end state) needs none of this rewriting, only the overlays."""
import json, os, re, shutil, sys

SRC, OUT = sys.argv[1], sys.argv[2]

# kept as they are: their x64 paths are x86 code (math.h's x64 paths are C)
KEEP = {'crt/intrin.h', 'crt/excpt.h', 'include/psdk_inc/intrin-impl.h'}

ARCH = r'(?:__x86_64__|__x86_64|_AMD64_|_M_AMD64|_M_X64)'
TEST = re.compile(r'defined\s*\(\s*' + ARCH + r'\s*\)|defined\s+' + ARCH + r'\b')
IFDEF = re.compile(r'^(\s*#\s*if)(n?)def\s+' + ARCH + r'\b')
DEFINE = re.compile(r'^\s*#\s*define\s+' + ARCH + r'\b.*$')

# x86 code inside headers that are otherwise rewritten: (file, old, new)
EDITS = [
    # x86intrin.h and emmintrin.h are clang's x86 intrinsics; the fences and
    # the rest winnt.h names are include-mingw-pre's intrin-impl.h
    ('include/winnt.h', '# include <x86intrin.h>\n', ''),
    ('include/winnt.h', '#include <emmintrin.h>\n', ''),
    # __debugbreak and __fastfail: wasm traps
    ('crt/_mingw.h.in', '  __asm__ __volatile__("int {$}3":);', '  __builtin_trap();'),
    ('crt/_mingw.h.in', '  __asm__ __volatile__("int {$}0x29"::"c"(_Code));', '  (void)_Code; __builtin_trap();'),
]


def ipproto_enum(text):
    """winsock2.h's IPPROTO_* as the Windows SDK has them: the IPPROTO enum
    (ws2def.h's there), each name a macro of itself, which programs written
    for the SDK define again (CPython's socketmodule.c)."""
    names = re.findall(r'^#define (IPPROTO_\w+) (\d+)$', text, re.M)
    if not names:
        return text
    text = re.sub(r'^#define (IPPROTO_\w+) (\d+)$', r'#define \1 \1', text, flags=re.M)
    enum = 'typedef enum {\n' + ''.join('  %s = %s,\n' % n for n in names) + '} IPPROTO, *PIPROTO;\n'
    first = re.search(r'^#define IPPROTO_', text, re.M).start()
    return text[:first] + enum + text[first:]


def winrt_bool(text):
    # WinRT's boolean as C++ bool in template arguments, as the Windows SDK's
    # headers have it: widl writes boolean (unsigned char), and IReference<boolean>
    # is then IReference<BYTE> defined twice
    text = re.sub(r'<boolean ([,>])', r'<bool \1', text)
    return text.replace('<boolean,', '<bool,').replace(',boolean >', ',bool >').replace(',boolean,', ',bool,')


METHOD = re.compile(r'(    virtual ([\w ]+?\**) STDMETHODCALLTYPE (\w+?)(_+)\(\n(.*?)\)( const)? = 0;\n)', re.S)


def cxx_overloads(text):
    # widl names a C++ overload X_ (X__ for the next) beside X, where the
    # Windows SDK's headers have overloads: X as an inline overload
    # forwarding to it, in the same interface (no vtable change)
    def block(b):
        body = b.group(1)
        names = set(re.findall(r'STDMETHODCALLTYPE (\w+)\(', body))

        def add(m):
            whole, ret, base, us, params, const = m.groups()
            if base not in names or '(' in params:
                return whole
            ps = [p.strip() for p in params.split(',') if p.strip()]
            args = [re.search(r'(\w+)\s*(?:\[[^]]*\])?$', p).group(1) for p in ps]
            fwd = '%s%s(%s)' % (base, us, ', '.join(args))
            return whole + '    %s %s(%s)%s { %s%s; }\n\n' % (
                ret, base, ', '.join(ps), const or '', '' if ret == 'void' else 'return ', fwd)
        return b.group(0).replace(body, METHOD.sub(add, body))
    return re.sub(r'#if defined\(__cplusplus\) && !defined\(CINTERFACE\)\nMIDL_INTERFACE\("[^"]*"\)\n\w+ : public \w+\n\{\n(.*?)\n\};', block, text, flags=re.S)


def rewrite(text):
    out = []
    for line in text.split('\n'):
        if re.match(r'\s*#', line):
            if DEFINE.match(line):
                line = '/* (gexcc-win: not defined) ' + line.strip().replace('*/', '* /') + ' */'
            else:
                line = IFDEF.sub(lambda m: '%s%s %sdefined(__GEXW_SDK_X64__)' % (m.group(1), '', '!' if m.group(2) else ''), line)
                line = TEST.sub('defined(__GEXW_SDK_X64__)', line)
        out.append(line)
    return '\n'.join(out)


# (written beside OUT and swapped in, so compiles reading OUT never see it half made)
FINAL, OUT = OUT, OUT.rstrip('/') + '.new'
if os.path.exists(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)
for sub, dest in (('include', ''), ('crt', ''), ('ddk/include', '')):
    base = os.path.join(SRC, sub)
    for root, dirs, files in os.walk(base):
        for f in files:
            if not f.endswith(('.h', '.hxx', '.inl', '.h.in', '.rh')) and '.' in f:
                continue
            rel = os.path.relpath(os.path.join(root, f), base)
            key = os.path.join(sub.split('/')[0], rel)
            o = os.path.join(OUT, dest, rel[:-3] if rel.endswith('.h.in') else rel)
            os.makedirs(os.path.dirname(o), exist_ok=True)
            text = open(os.path.join(root, f), encoding='latin-1').read()
            if rel.endswith('.h.in'):
                text = text.replace('@DEFAULT_MSVCRT_VERSION@', '0xE00').replace('@DEFAULT_WIN32_WINNT@', '0xa00')
            if key not in KEEP:
                text = rewrite(text)
            if key.startswith('include/') and 'STDMETHODCALLTYPE' in text and re.search(r'STDMETHODCALLTYPE \w+_\(', text):
                text = cxx_overloads(text)
            if key == 'include/winsock2.h':
                text = ipproto_enum(text)
            if re.match(r'include/windows\.[\w.]+\.h$', key):
                text = winrt_bool(text)
            for f2, old, new in EDITS:
                if f2 == key:
                    assert old in text, (key, old)
                    text = text.replace(old, new)
            open(o, 'w', encoding='latin-1').write(text)

# Windows' file names have no case: a source's <Rpc.h> is rpc.h. A clang
# VFS overlay (-ivfsoverlay) over the headers that matches names regardless
# of case, as gexcc-win passes it.
def tree(d, final):
    out = []
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if os.path.isdir(p):
            out.append({'name': n, 'type': 'directory', 'contents': tree(p, os.path.join(final, n))})
        else:
            out.append({'name': n, 'type': 'file', 'external-contents': os.path.join(final, n)})
    return out


final = os.path.abspath(FINAL)
json.dump({'version': 0, 'case-sensitive': 'false', 'roots': [{'name': final, 'type': 'directory', 'contents': tree(OUT, final)}]},
          open(os.path.join(OUT, 'nocase.yaml'), 'w'))

OLD = FINAL.rstrip('/') + '.old'
if os.path.exists(OLD):
    shutil.rmtree(OLD)
if os.path.exists(FINAL):
    os.rename(FINAL, OLD)
os.rename(OUT, FINAL)
if os.path.exists(OLD):
    shutil.rmtree(OLD)
