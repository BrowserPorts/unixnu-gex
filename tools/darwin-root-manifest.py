#!/usr/bin/env python3
"""A Darwin root (GEX_DARWIN_ROOT, as gexc's --sysroot reads it) as the
page's filesystem takes a tree without copying it: a tar of what is not a
regular file's bytes (directories, symbolic links, hard links' second
names), with each entry's extended attributes (the guest's recorded
owners, `user.gex.darwin.attrs`), and a lazy list of the regular files,
each read by URL when first opened. A regular file with an extended
attribute goes in the tar whole, as the lazy list has no attributes.

    darwin-root-manifest.py ROOT URL-BASE OUT-TAR OUT-LAZY

URL-BASE is where the page reads ROOT's files: a file's URL is URL-BASE and
its path below ROOT.
"""
import json
import os
import stat
import sys
import tarfile
import urllib.parse


def _libc_xattrs():
    """listxattr and getxattr: os's where it has them (Linux), else the C
    library's (macOS, whose take an options word: XATTR_NOFOLLOW)."""
    if hasattr(os, 'listxattr'):
        return (lambda p: os.listxattr(p, follow_symlinks=False),
                lambda p, n: os.getxattr(p, n, follow_symlinks=False))
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.getxattr.restype = ctypes.c_ssize_t
    nofollow = 1

    def names(p):
        b = os.fsencode(p)
        n = libc.listxattr(b, None, 0, nofollow)
        if n < 0:
            raise OSError(ctypes.get_errno(), p)
        buf = ctypes.create_string_buffer(n)
        n = libc.listxattr(b, buf, n, nofollow)
        if n < 0:
            raise OSError(ctypes.get_errno(), p)
        return [x.decode('utf-8', 'surrogateescape') for x in buf.raw[:n].split(b'\0') if x]

    def value(p, name):
        b, nb = os.fsencode(p), name.encode('utf-8', 'surrogateescape')
        n = libc.getxattr(b, nb, None, 0, 0, nofollow)
        if n < 0:
            raise OSError(ctypes.get_errno(), p)
        buf = ctypes.create_string_buffer(n)
        n = libc.getxattr(b, nb, buf, n, 0, nofollow)
        if n < 0:
            raise OSError(ctypes.get_errno(), p)
        return buf.raw[:n]

    return names, value


LISTXATTR, GETXATTR = _libc_xattrs()


def xattrs(path):
    out = {}
    try:
        names = LISTXATTR(path)
    except OSError:
        return out
    for n in names:
        if n.startswith('user.'):
            try:
                out[n] = GETXATTR(path, n)
            except OSError:
                pass
    return out


def main():
    root, base, out_tar, out_lazy = sys.argv[1:5]
    root = os.path.realpath(root)
    lazy = []
    seen = {}
    others = []
    with tarfile.open(out_tar, 'w', format=tarfile.PAX_FORMAT) as tar:
        def add(rel, st, kind, link='', data=None, attrs=None):
            ti = tarfile.TarInfo(rel)
            ti.mode = stat.S_IMODE(st.st_mode)
            ti.mtime = int(st.st_mtime)
            ti.uid, ti.gid = 0, 0
            ti.type = kind
            ti.linkname = link
            if attrs:
                ti.pax_headers = {f'SCHILY.xattr.{k}': v.decode('utf-8', 'surrogateescape') for k, v in attrs.items()}
            if data is not None:
                ti.size = len(data)
                import io
                tar.addfile(ti, io.BytesIO(data))
            else:
                tar.addfile(ti)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            filenames.sort()
            reld = os.path.relpath(dirpath, root)
            if reld != '.':
                add(reld, os.lstat(dirpath), tarfile.DIRTYPE, attrs=xattrs(dirpath))
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                rel = os.path.relpath(p, root)
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    add(rel, st, tarfile.SYMTYPE, link=os.readlink(p), attrs=xattrs(p))
                elif stat.S_ISDIR(st.st_mode):
                    # (a link to a directory was taken above; os.walk
                    # visits the directory itself in its turn)
                    continue
                elif stat.S_ISREG(st.st_mode):
                    key = (st.st_dev, st.st_ino)
                    if st.st_nlink > 1 and key in seen:
                        add(rel, st, tarfile.LNKTYPE, link=seen[key])
                        continue
                    seen[key] = rel
                    a = xattrs(p)
                    if a:
                        with open(p, 'rb') as f:
                            add(rel, st, tarfile.REGTYPE, data=f.read(), attrs=a)
                    else:
                        url = base + urllib.parse.quote(rel)
                        lazy.append(['/' + rel, st.st_size, url, stat.S_IMODE(st.st_mode), int(st.st_mtime)])
                else:
                    # A socket, fifo or device node: not a file the page's
                    # tree can hold. Said, below.
                    others.append(rel)
    with open(out_lazy, 'w') as f:
        json.dump(lazy, f, separators=(',', ':'))
    print(f'{len(lazy)} lazy files')
    for o in others:
        print(f'left out (not a file, directory or link): {o}', file=sys.stderr)


if __name__ == '__main__':
    main()
