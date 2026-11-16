#!/usr/bin/env python3
"""Write AppleImage4's Cryptex1 trust anchor from a kernelcache, for a Darwin boot payload.

AppleImage4 (com.apple.security.AppleImage4) embeds its Image4 root
certificates in its __TEXT,__const, each followed by its length as a 64-bit
word at the next 8-byte boundary, which the trust store's anchor loaders
read with it. CHIP_CRYPTEX1_BOOT_AP's decode implementation loads the one
at ADDRESS ("Apple DDI Secure Boot Root CA - G1"; 0xfffffff0052d4640 in
21H461's iPad7,1 kernelcache, the default).

The certificate's length is its DER header's (a SEQUENCE with a definite
length); it must be inside the kext's __TEXT,__const and equal to the length
word after it. It is written as img4_anchor.der with its SHA-256.

The kernelcache is the decompressed Mach-O: a prelinked one (its kexts in
__PRELINK_TEXT, named by __PRELINK_INFO), or a fileset (LC_FILESET_ENTRY).

usage: darwin-img4-anchor.py KERNELCACHE OUTDIR [ADDRESS]
"""
import hashlib
import importlib.util
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('sandbox_blobs', os.path.join(HERE, 'darwin-sandbox-blobs.py'))
kcmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kcmod)
kcmod.BUNDLE = 'com.apple.security.AppleImage4'

DEFAULT = 0xfffffff0052d4640


def die(msg):
    sys.exit('darwin-img4-anchor: ' + msg)


def der_length(b):
    """A definite-length SEQUENCE's whole length from its header."""
    if len(b) < 2 or b[0] != 0x30:
        die('no SEQUENCE at the anchor\'s address')
    if b[1] < 0x80:
        return 2 + b[1]
    n = b[1] & 0x7f
    if n == 0 or n > 4:
        die('the anchor\'s SEQUENCE has no definite length')
    return 2 + n + int.from_bytes(b[2:2 + n], 'big')


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__.strip().splitlines()[-1])
    path, out = sys.argv[1:3]
    address = int(sys.argv[3], 0) if len(sys.argv) == 4 else DEFAULT
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != struct.pack('<I', kcmod.MH_MAGIC_64):
        die('%s is not a decompressed 64-bit kernelcache' % path)
    kc = kcmod.Kernelcache(data)
    kext = kc.kext()
    const = kext.sections.get(('__TEXT', '__const'))
    if not const:
        die('AppleImage4 has no __TEXT,__const')
    n = der_length(kc.read(address, 8))
    if not (const[0] <= address and address + n + 8 <= const[0] + const[1]):
        die('the anchor at %#x (%d bytes) is not in AppleImage4\'s __TEXT,__const' % (address, n))
    word = (address + n + 7) & ~7
    stored = struct.unpack('<Q', kc.read(word, 8))[0]
    if stored != n:
        die('the length word at %#x is %d, not the certificate\'s %d' % (word, stored, n))
    cert = kc.read(address, n)
    os.makedirs(out, exist_ok=True)
    dest = os.path.join(out, 'img4_anchor.der')
    with open(dest, 'wb') as f:
        f.write(cert)
    print('img4_anchor.der  %#x  %d bytes  sha256 %s' % (address, n, hashlib.sha256(cert).hexdigest()))


if __name__ == '__main__':
    main()
