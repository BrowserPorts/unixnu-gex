# unixnu-gex

unixnu-gex is [stellite-gex](https://github.com/BrowserPorts/stellite-gex)
with a Darwin personality: XNU's system call interface, ported into gex's
kernel, so that the userland of iPadOS 17.7.11 (build 21H461), as it ships
for the iPad7,1, runs on gex unmodified. gex runs programs by translating
their machine code to WebAssembly and running it against its own kernel,
written in Rust.

- Parent: [stellite-gex](https://github.com/BrowserPorts/stellite-gex),
  Stellite's fork of [HeyPuter/gex](https://github.com/HeyPuter/gex)
- Sibling: [android-gex](https://github.com/BrowserPorts/android-gex), the
  same base with an Android personality
- Used with: [UniXNU](https://github.com/BrowserPorts/UniXNU), which builds
  the GPU driver plugin, [WebMetal](https://github.com/BrowserPorts/WebMetal)
  (Metal on WebGPU) and [AirWgsl](https://github.com/BrowserPorts/AirWgsl)
  (the AIR to WGSL compiler). WebMetal and AirWgsl are submodules here, at
  `third_party/WebMetal` and `third_party/AirWgsl`.

The Darwin work is on the branch `darwin`. The rest of the tree is
stellite-gex, whose README covers the Linux and Windows support, the page and
Wine.

## Where it stands

Darwin programs run under gex's native host, `gexc`, which runs the
translated program on wasmtime. A boot runs launchd through its early boot
tasks and stops at the Secure Enclave. It does not reach a user interface.
The browser host (`hosts/browser`) does not start Darwin processes yet.

## What it adds

A Darwin process enters the kernel with `svc #0x80` and the call number in
x16. A positive number is a BSD system call, a negative one a Mach trap. A
BSD call with a Linux counterpart is renumbered onto gex's own dispatch, with
its flags and structures translated, and the rest are answered by Darwin
code. Results go back as XNU returns them.

The kernel side is in `crates/gex-kernel/src/darwin/`, one module per
subsystem, most naming in their header the XNU source they port:

- **System calls and Mach.** The BSD call table, the Mach traps, ports and
  rights, `mach_msg`, kernel object ports, the MIG server, exception ports,
  semaphores, timers and vouchers.
- **Processes and threads.** `execve` and `posix_spawn` for Mach-O images,
  libpthread's kernel side (psynch and the workqueue), credentials, personas,
  coalitions, resource limits and `proc_info`.
- **Signals, scheduling state and memory.** XNU's arm64 signal frame, task
  and thread policy, the task's VM map, the commpage, the shared region,
  memorystatus and POSIX shared memory.
- **Files, kqueue, terminals and sockets.** The `getattrlist` family,
  `clonefile`, extended attributes, guarded descriptors, file ports, kqueue
  and its filters, ttys and ptys, and Darwin's socket structures and options.
- **Security.** The MAC framework with AMFI and Sandbox as its policies: code
  signatures, entitlements, trust caches, launch constraints, and compiled
  Sandbox profiles with their evaluation.
- **IOKit, the display and IOSurface.** The registry, the GPU's accelerator
  service, the framebuffer and `IOSurfaceRoot`, each with its user clients.
- **Storage and boot.** APFS volumes read and written, a restore model that
  builds a disk image as a device's restore does (`gexc darwin-disk0`), an
  NVRAM store, and the kernel side of a Secure Enclave interface.

Outside the kernel crate:

- Mach-O loading and the dyld shared cache (`crates/gex-ld`)
- the A64 cryptographic extension (`crates/gex-abi`)
- an ARMv7-A (AArch32) front end (`crates/gex-isa-a32`, `gex-lift-a32`,
  `gex-a32`, `hosts/a32`)
- the GPU: WebMetal's host executor, run by `gexc` on a native WebGPU
  implementation (`crates/gexc/src/host_webmetal`), and by the page in a
  Worker on the browser's WebGPU (`hosts/metal`)

`docs/darwin.md` has the notes module by module, what the test suite
covers, and the known gaps.

## How it is written

- **Ported from the source.** The modules port XNU at the tag
  `xnu-10063.141.1` and keep its structures, limits, error paths and
  ordering.
- **Gaps fail loudly.** What a program asks for that is not implemented is
  reported on stderr, once per kind per process, as
  `[gex:<pid>] Darwin: not implemented: <what>`, and the call fails with the
  error its path chooses. Nothing is answered with a substitute.
- **Strict mode.** With `GEX_DARWIN_STRICT=1` the first such report stops the
  process.

## Building

You need the Rust toolchain that `rust-toolchain.toml` names and a C++17
compiler. The native host links the host's EGL and GLES. On macOS that is
Mesa's, found under Homebrew's prefix or under the prefix `GEX_MESA_PREFIX`
names.

```sh
cargo build --release -p gexc
```

That builds `target/release/gexc`, for AArch64 guests, which is what Darwin
programs are.

The GPU needs gexc's `webmetal` feature and a native WebGPU implementation.
`WEBGPU_NATIVE` is `dawn` or `wgpu-native`, and `WEBGPU_NATIVE_DIR` is its
install root, with `include/webgpu/webgpu.h` and `lib/`.

WebMetal and AirWgsl also take data about the A10X from the device's own
system software, which is not in their repositories: you produce it from
your own root with their tools, as their READMEs describe, and the build
fails, naming what is missing, without it. `WEBMETAL_PROFILE` is the device
profile, `WEBMETAL_AGX_TEXTURE_FORMATS` the driver's texture format table and
`AIRWGSL_INTRINSICS` AirWgsl's intrinsic table.

```sh
git submodule update --init third_party/WebMetal third_party/AirWgsl
WEBMETAL_PROFILE=<profile.toml> WEBMETAL_AGX_TEXTURE_FORMATS=<formats.rs> AIRWGSL_INTRINSICS=<intrinsics.toml> \
WEBGPU_NATIVE=dawn WEBGPU_NATIVE_DIR=<dawn> cargo build --release -p gexc --features webmetal
target/release/gexc webmetal-info
```

`gexc webmetal-info` names the implementation a build runs on. Without the
feature, Metal's requests to the accelerator are reported as having no
executor to run them.

## What you supply

This repository ships no iPadOS files and nothing of Apple's. To run more
than the static test programs you supply your own, from your own copy of
iPadOS 17.7.11 (21H461) for the iPad7,1:

- a root filesystem
- a boot payload: what the boot loader and the kernelcache would give the
  kernel
- a disk image built from them with `gexc darwin-disk0`

The tests take them through environment variables (`GEX_DARWIN_ROOT`,
`GEX_DARWIN_BOOT`, `GEX_DARWIN_DISK0`), which the header of
`tests/darwin/run.sh` describes.

## Running a program

`gexc run` recognises a thin 64-bit Mach-O file and runs it on the Darwin
personality. A static program needs no root. A dynamic program starts in
dyld, read from the root, and needs `--sysroot`. Place the program inside the
root so that its own path resolves in the guest.

```sh
GEX_DARWIN_BOOT=<boot> target/release/gexc run \
    --sysroot <root> <root>/var/tmp/my-tool arg1 arg2
```

AMFI runs only trusted code, as on iOS. A program of your own runs once it is
signed (ad hoc is enough) and its cdhash is in the boot payload's trust
cache, which `tools/darwin-trust-cache.py` adds.

The other `gexc run` options (`--strace`, `--env`, `--cwd` and the rest in
`gexc help`) apply as they do to Linux programs. `gexc dsc-info` prints what
gex reads from a dyld shared cache.

## Running the tests

The test programs are C, built with Xcode's iOS toolchain, so building them
needs macOS with Xcode and its iOS SDK.

```sh
sh tests/darwin/build.sh
sh tests/darwin/run.sh            # every program
sh tests/darwin/run.sh hello      # some, by name
```

`run.sh` runs each program under gexc and compares its output and exit status
with what it expects. A program whose inputs are not supplied is skipped, or
fails when it was asked for by name. The programs that use the GPU need a
gexc built with `webmetal`, and WebMetal's plugin bundle as UniXNU's
`scripts/build-web-metal-plugin.py` builds it from the WebMetal commit
`third_party/WebMetal` pins, named by `GEX_DARWIN_WEBMETAL`. The executor
refuses a plugin whose wire protocol differs from its own.
`hosts/metal/tests/check_page.py`, which checks the page's GPU Worker in a
browser, also takes `WEBMETAL_REFERENCE`: a run of WebMetal's reference
harness on real Metal, which its reference cases compare with.

The kernel's and the loader's unit tests run with `cargo test -p gex-kernel`
and `cargo test -p gex-ld`.

## Layout

The Darwin work, beside the parent's tree:

| path | what it is |
|------|------------|
| `crates/gex-kernel/src/darwin/` | the Darwin personality, one module per subsystem |
| `crates/gex-ld/src/macho.rs`, `dsc.rs` | Mach-O loading, and the dyld shared cache |
| `crates/gex-isa-a32`, `gex-lift-a32`, `gex-a32`, `hosts/a32` | the AArch32 front end |
| `crates/gexc/src/darwin_run.rs` | `gexc run` for a Mach-O file |
| `crates/gexc/src/host_webmetal/` | WebMetal's executor on the native host |
| `hosts/metal/` | the page's GPU Worker: WebMetal's executor on the browser's WebGPU |
| `third_party/WebMetal`, `third_party/AirWgsl` | the submodules, at pinned commits |
| `tests/darwin/` | the test programs, and the scripts that build and run them |
| `tools/darwin-*.py` | generators and helpers for the Darwin personality (`docs/darwin.md`, Tools) |
| `docs/darwin.md` | the Darwin personality's reference notes and known gaps |

## Licence

GNU Affero General Public License, version 3 only (`LICENSE`). gex is
Copyright (C) 2026 Puter Technologies Inc. Third-party code keeps its own
licence, and `NOTICE` lists it. WebMetal and AirWgsl carry their own
`LICENSE` and `NOTICE` files.

## Contributing

This repository takes no pull requests and no issues. Both are turned off
for the BrowserPorts organisation.
