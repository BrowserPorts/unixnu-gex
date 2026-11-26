#!/bin/sh
# The members of a tar listing (stdin, `tar -t`'s) whose path equals another
# member's but for letter case, every one of each such set, one a line: what
# an unpack leaves out (`tar -x -X FILE`) so that it holds the same files on a
# case-insensitive disk as on a case-sensitive one. Linux's UAPI headers have
# eight such sets, all netfilter's (xt_CONNMARK.h, a target, beside
# xt_connmark.h, a match), in Debian's linux-libc-dev
# (toolchain/debian-package.sh) and in the musl cross toolchains' own include
# folders (the Makefile's toolchains). Keeping one of a set would be worse
# than keeping neither: on a case-insensitive disk an include of the other
# name finds it and reads the wrong header, where now it fails to compile.
# Nothing gex builds includes them.
#
#   tar -t ... | toolchain/case-pairs.sh > FILE
#
# A folder is listed with a trailing slash and compared without it; a folder
# left out takes what is under it.
sed 's#/$##' |
  awk '{ k = tolower($0); n[k]++; m[k] = m[k] $0 "\n" } END { for (k in n) if (n[k] > 1) printf "%s", m[k] }'
