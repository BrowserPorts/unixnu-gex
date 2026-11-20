# The Darwin personality

Reference notes on unixnu-gex's Darwin personality: what each part of the
kernel ports, the principles it follows, the tools, what the test suite
covers, and the known gaps. The README gives the overview, building and
running.

## The personality

A Darwin process enters the kernel with `svc #0x80` and the call number in
x16. The number says which part of the kernel answers: a positive number is
a BSD system call, a negative one a Mach trap, and `0x80000000` the
machine-dependent calls (the thread's TSD pointer). A BSD call with a Linux
counterpart is renumbered onto gex's own dispatch, its flags and structures
translated; the rest are answered by Darwin code. Results go back as XNU
returns them: the value in x0 with the carry flag clear, or a Darwin errno in
x0 with the carry flag set. A Mach trap returns its `kern_return_t` in x0.

A process sees iOS's machine: 16 KiB pages, the address space exec lays
out, the commpage, and the iPad7,1's identity in `sysctl`, the host
routines and the device tree.

The address space is XNU's for this device (`load_machfile`,
`create_unix_stack`, `vm_shared_region_enter`). The map runs from the main
image to `0x4_5800_0000` (`ARM64_MAX_OFFSET_DEVICE_LARGE`: the device has
more than 3 GB). The main image is slid by a random 1 to 1023 16 KiB pages
and 0, 1 or 2 32 MiB sections, its 4 GiB `__PAGEZERO` extended to it; dyld
goes right after the main image's end, by 1 to 255 pages of its own (and
moves itself into its copy in the shared cache); the main stack's top is
`USRSTACK64` (`0x1_6fe0_0000`) less the main image's slide. A release
kernel slides every image: `_POSIX_SPAWN_DISABLE_ASLR` is ignored. The
shared region, `0x1_8000_0000` for `0x1_8000_0000`, is one read-only
entry, the system's, one per environment (`shregion.rs`): a task enters
its environment's at exec, made empty if there is none, and a fork's child
its parent's. The first dyld to find its region empty (launchd's, at boot)
maps the dyld shared cache into it with `shared_region_map_and_slide_2_np`,
passing the cache's `maxSlide`, and the kernel slides the cache once below
it, on a 16 KiB boundary, relocating the slid mappings by their slide
info; every task in the region sees it, and every task after enters it as
it is. An unused region is kept two minutes. When pid 1 is the kernel's
own, standing in for launchd, the boot's region holds what launchd's dyld
mapped at boot: the cache's files, on the OS cryptex's graft (with its
trust cache loaded, as the boot left them), preflighted and their code signatures added as dyld
does, and the same mapping call made with dyld's arguments.
`/sbin/launchd` as the first program finds its region empty. libmalloc's nano
allocator, in a process exec engages it for (a spawn with
`_POSIX_SPAWN_NANO_ALLOCATOR`, as an app's is), takes the 512 MiB after
the shared region.

The kernel side is in `crates/gex-kernel/src/darwin/`, one module per
subsystem, most naming in their header the XNU source they port:

- **System calls.** The BSD call table, generated from XNU's
  `syscalls.master` (`sysno.rs`); renumbering onto the canonical dispatch
  (`bsd.rs`); the calls with no Linux counterpart (`kern.rs`); errno numbers
  (`errno.rs`); and the calls a release kernel settles before doing any
  work (`fixedcalls.rs`).
- **Mach traps and IPC.** The traps (`mach.rs`); ports, port sets, rights,
  name spaces and notifications (`ipc/`); `mach_msg` and `mach_msg2`, with
  port rights and out-of-line data (`mach_msg.rs`); kernel object ports and
  the MIG server for the host, task, thread, `mach_port`, `vm_map` and
  `mach_vm`, clock, voucher and IOKit routines (`kobject.rs`, `mig.rs`);
  exception ports and delivery to handlers (`exception.rs`, `triage.rs`);
  semaphores (`sema.rs`), Mach timers (`mk_timer.rs`), eventlinks
  (`eventlink.rs`), vouchers with the bank and importance attribute managers
  (`voucher.rs`), IPC importance (`importance.rs`), and thread state
  (`threadstate.rs`).
- **Processes and threads.** `execve` with the Mach-O, fat and interpreter
  activators, and the new image's stack with its `apple[]` strings
  (`execve.rs`, `exec.rs`); `posix_spawn` with file actions, port actions
  and attributes (`spawn.rs`); `wait4` and `waitid` (`exit.rs`);
  libpthread's kernel side: `bsdthread_*` and `ulock` (`thread.rs`), psynch,
  ported from libpthread's `kern_synch.c` (`psynch.rs`), and the workqueue
  that runs libdispatch's threads (`workq.rs`); kernel waits (`wait.rs`);
  credentials (`cred.rs`), personas (`persona.rs`), coalitions
  (`coalition.rs`), resource limits (`rlimit.rs`), exit reasons
  (`reason.rs`), `proc_info` (`procinfo.rs`) and `kern.proc` (`kinfo.rs`).
- **Signals.** Dispositions, XNU's arm64 signal frame and `sigreturn`
  (`signal.rs`), job control (`jobctl.rs`) and interval timers
  (`itimer.rs`).
- **Scheduling state.** Task and thread policy: app type, role, QoS and
  priority (`taskpolicy.rs`, `threadpolicy.rs`, `priority.rs`,
  `procpolicy.rs`); the CPU usage monitor (`cpumon.rs`); work intervals
  (`workinterval.rs`); the scheduler's load averages and Mach factor
  (`sched.rs`); and the kernel's thread calls, which fire timers
  (`timer.rs`). Priorities and QoS are computed as XNU computes them;
  running the threads is the host's job.
- **Memory.** The task's VM map entries (`vm.rs`); `mmap`, `madvise` and
  `mach_vm_behavior_set` (`mman.rs`); `map_with_linking_np` and the dyld
  pager's fixups (`mwl.rs`); the commpage (`commpage.rs`); the
  `phys_footprint` ledger and `TASK_VM_INFO` (`footprint.rs`);
  memorystatus and the jetsam bands (`memorystatus.rs`); POSIX shared
  memory (`shm.rs`).
- **Files.** Name, mode and time changes and `getdirentries64`
  (`fsops.rs`); the `getattrlist` family (`attrlist.rs`, `attrcall.rs`);
  `clonefile` and `exchangedata` (`clonefile.rs`); extended attributes
  (`xattr.rs`); `pathconf` (`pathconf.rs`); the file security calls
  (`filesec.rs`); advisory locks (`lockf.rs`); guarded descriptors
  (`guarded.rs`); file ports (`fileport.rs`); asynchronous I/O (`aio.rs`);
  pipes (`pipe.rs`); `select` (`select.rs`); `ioctl` (`ioctl.rs`); POSIX
  semaphores (`psem.rs`); and `/dev` as an iOS kernel makes it
  (`devfs.rs`).
- **kqueue.** File kqueues, the workqueue's kqueue and workloops
  (`kevent.rs`), and their filters (`kfilt.rs`): `EVFILT_READ`, `WRITE`,
  `VNODE`, `PROC`, `SIGNAL`, `TIMER`, `USER`, `MACHPORT`, `MEMORYSTATUS` and
  `WORKLOOP`.
- **Terminals.** `struct tty`, its character lists and the termios line
  discipline (`tty.rs`, `clist.rs`); `/dev/ptmx` and its replicas, the BSD
  ptys and `/dev/tty` (`ptmx.rs`, `ttydev.rs`); sessions and controlling
  terminals (`ctty.rs`); `/dev/console`, which goes to the terminal
  `TIOCCONS` made the console's or to the kernel's console terminal `km`,
  whose output is the console's (`km.rs`). The host's standard error shows
  that output as the device's serial port carries it with the `serial`
  boot-arg's output on; the device boots with no boot-args (`pe.rs`).
- **Sockets.** Darwin's address structures, flags and option numbers
  (`sockaddr.rs`); socket-level options (`sockopt.rs`); the socket layer's
  refusals (`sockerr.rs`); Unix-domain stream sockets' sends and receives
  with the descriptors they carry, over XNU's socket buffer accounting
  (`unixsock.rs`, `sockbuf.rs`). As in upstream gex, an internet socket's
  connection is carried by the host. The inet6 domain's UDP and TCP
  sockets as `inet6sw`'s lookup makes them, and `lo0`'s IPv6 addresses
  as `in6_control` checks and keeps them, from the `::1` the kernel gives
  it at boot (`inet6.rs`).
- **Security.** The MAC framework's checks, with AMFI and Sandbox as its
  policies (`mac.rs`); AMFI's decisions on code signatures, task ports, JIT
  and executable mappings (`amfi.rs`); AMFI's launch constraints, at exec
  and spawn, and its library validation and library load constraints
  (`launchcon.rs`), with the lightweight code requirements they are
  written in and the CoreEntitlements objects those are (`lwcr.rs`);
  embedded code signatures and entitlements (`codesign.rs`); trust caches
  (`trustcache.rs`): the static one, and those AMFI loads at run time
  (`__mac_syscall` 101) for a caller whose
  `com.apple.private.pmap.load-trust-cache` entitlement allows the type.
  Sandbox's
  compiled profiles and their evaluation (`sandbox.rs`), the sandboxes a
  process gets from its exec or `sandbox_init` (`sandboxes.rs`), and
  AppleMatch, the regular expression engine those profiles use
  (`applematch.rs`).
- **IOKit.** The registry's `IODeviceTree` plane, built from the device's
  own device tree, with the APFS volumes its file system table names
  published as services, reached through IOKit's MIG routines (`iokit.rs`).
  Each open of a service makes its own user client. The GPU's accelerator
  presents as the device's, AGXG9G's `AGXAcceleratorG9G_A0` (`accel/`).
  - Its classes and its user clients' are the device's. The device client
    (type 1) is `AGXDeviceUserClient`, with IOGPUFamily's methods; the
    memory information client is type 33. The WebMetal connection (type 0)
    presents as a device client and carries WebMetal's wire protocol to
    the host executor (`accel/wire.rs`, `accel/host.rs`): a control
    request is read from the caller's memory and answered when the
    executor is done, through `fetch_reply` when its reply does not fit;
    a command buffer's stream is read in place at its commit; and events
    ring the doorbell `register_event_port` set, as IOKit's async
    completion. gexc runs the executor (`crates/gexc/src/host_webmetal/`,
    its `webmetal` build): one host thread owning one WebGPU device for
    the whole system, reaching each connection's task's memory, and the
    kernel's IOSurfaces through the executor's surface table.
  - Its properties are its personality's and matching's, what
    `IOGPU::start` sets and the strings AGXG9G's start sets: as on the
    device, `MetalPluginName` is `AGXMetalA10` and `MetalPluginClassName`
    `AGXA10XDevice`, the names the WebMetal plugin is installed under.
  - It sits on its providers in the `IOService` plane, as the device
    matches and publishes them over its device tree (`platform.rs`): the platform expert `AppleARMPE` on the
    `IOPlatformExpertDevice`, the `IOPlatformDevice` nub of arm-io, its
    driver `AppleT8011IO`, and the `AppleARMIODevice` nub of arm-io's sgx.
  - The shipped Sandbox profiles decide by those classes and by that
    ancestry.
- **The display.** The framebuffer presents as the device's,
  AppleMobileDispH9G's `AppleCLCD` (an `IOMobileFramebuffer`), on the
  `AppleARMIODevice` nub of arm-io's disp0, with IOMobileGraphicsFamily's
  `IOMobileFramebufferUserClient` (`iomfb/`).
  - The panel's mode is the one disp0's `display-timing-info` gives, and its
    vertical blanks come one frame apart: two subframes of disp0's
    `subframe-duration-nclks`, counted from boot.
  - A swap is begun, ended with the transaction IOMobileFramebuffer.framework
    builds, checked as the family's `swap_submit` and the pipe's
    `verify_swap` check it, and queued. The vertical blank after it is
    pending makes it the displayed swap, and the one it replaces retires.
    Swap waits wait for those steps.
  - A displayed swap's layers go to the embedder's presentation sink as the
    surfaces hold them: their bytes, pixel format, plane geometry and
    rectangles, unconverted. `GEX_DARWIN_FRAMES` makes gexc's sink record
    them into a directory.
  - No vertical blank message is sent: on this device the kext sends none.
- **IOSurface.** `IOSurfaceRoot` and its user client as the device's
  IOSurface kext has them (`iosurface/`): surfaces created, looked up by id
  and by send right, locked with their seeds, their values, use counts and
  purgeability, and the records and graphics comm page the root shares with
  every client. A surface's memory is the kernel's, and each task that maps
  it has a view of it, brought up to date when the task locks the surface
  and sent back when it unlocks; a store outside a lock is caught by the
  page's protection and kept. libkern's binary serialization, which its
  methods carry, is `osserialize.rs`.
- **sysctl.** The kernel's nodes (`sysctl_nodes.rs`) and the values this
  kernel has for them (`sysctl.rs`).

Outside the kernel crate:

- `crates/gex-ld/src/macho.rs` loads Mach-O images as `parse_machfile`
  places them: a position-independent image, and dyld, moved by its slide,
  dyld after the main image. A Darwin process's own tables (its dispatch
  directory and page protections) are kept inside its `__PAGEZERO`
  (`gex_abi::DARWIN_DISPATCH_DIR64`), so that its address space is XNU's.
- `crates/gex-ld/src/dsc.rs` reads the dyld shared cache, its subcaches and
  their slide info.
- `crates/gex-abi/src/crypto.rs` computes the A64 cryptographic extension
  (AES, SHA-1, SHA-256 and the polynomial multiplies), which translated code
  calls; corecrypto uses these instructions without asking.
- `crates/gexc/src/darwin_run.rs` is `gexc run` for a Mach-O file, and
  `crates/gexc/src/dsc_info.rs` is `gexc dsc-info`.
- `hosts/native/src/darwin_image.rs` loads a program and its dyld, for the
  first program and for `execve`.

## Principles

- **Ported from the source.** The modules port XNU at the tag the profile
  pins, `xnu-10063.141.1`, name the files they follow, and keep XNU's
  structures, limits, error paths and ordering. The BSD call table is generated from
  that tag's `syscalls.master` under the iPhoneOS RELEASE configuration
  (`tools/darwin-gen-sysno.py`). psynch and the workqueue follow
  libpthread's kernel side. AMFI, Sandbox, AppleMatch and libTrustCache,
  which have no published source, follow the device's own behaviour.
- **Measured where the source is silent.** Where behaviour belongs to the
  filesystem rather than to XNU, the values come from a real APFS volume:
  what a clone keeps, `pathconf`'s answers, `select` on vnodes, and the
  attributes `getattrlist` reports.
- **Gaps fail loudly.** Whatever a program asks for that is not implemented
  is reported on stderr, once per kind per process:

  ```
  [gex:<pid>] Darwin: not implemented: <what>
  ```

  The call then fails with the error its path chooses: an unknown BSD call
  is ENOSYS, a Mach trap that is not implemented is `KERN_FAILURE`, and a
  Sandbox question the evaluator cannot answer is EPERM. A few paths go on
  where XNU would and name in the report what they could not supply (a
  signal frame's fault syndrome, for one). A trap number that does not
  exist raises `EXC_SYSCALL`, as on XNU, and becomes SIGSYS. Under
  `--strace` every occurrence is reported, not only the first.
- **Strict mode.** With `GEX_DARWIN_STRICT=1`, the first report stops the
  process: when the call returns, it is killed with SIGSYS, and gexc prints

  ```
  [gex:<pid>] GEX_DARWIN_STRICT: stopping at pc <pc>: <what>
  ```

## Tools

The scripts in `tools/` make the generated tables and the boot payload's
files from inputs you give them, and write where you say. Each prints its
usage with `--help`. Each was checked on build 21H461.

- `darwin-gen-sysno.py (--tag TAG | --xnu DIR) [-o OUT]`: the BSD call
  table (`sysno.rs`) from XNU's `syscalls.master`, at a tag of Apple's
  open-source XNU (fetched) or in an XNU checkout, under the iPhoneOS
  RELEASE configuration.
- `darwin-sysctl-nodes.py [--label LABEL] KERNELCACHE OUT`: the kernel's
  built-in sysctl nodes (`sysctl_nodes.rs`) from a decompressed
  kernelcache's `__init_entry_set`.
- `darwin-sandbox-blobs.py KERNELCACHE OUTDIR`: the Sandbox kext's platform
  profile and its builtin and protobox collections (`sandbox_profile.bin`,
  `sandbox_builtin.bin`, `sandbox_protobox.bin`), found where the kext's
  `policy_init` loads them and checked as its loader checks them.
- `darwin-img4-anchor.py KERNELCACHE OUTDIR ADDRESS`: AppleImage4's
  Cryptex1 trust anchor at ADDRESS (`img4_anchor.der`), checked against the
  length the kext stores after it.
- `darwin-trust-cache.py -o BUNDLE [--static FILE | --bundle FILE]
  [--category CAT:MACHO]... [MACHO...]`: a trust cache bundle
  (`TrustCache`), a static trust cache's module with the cdhashes of signed
  Mach-O files added.
- `darwin-volume-attrs.py MOUNTPOINT -o SPEC`: the owners, modes and file
  flags of a mounted volume's files (`SystemVolume.attrs`), in mtree(5)'s
  layout.

`sysno.rs` and `sysctl_nodes.rs` are committed, generated; the header of
`sysno.rs` names the command that regenerates it, and
`darwin-sysctl-nodes.py --help` gives the one for `sysctl_nodes.rs`.

## Status

### What the suite covers

Each program in `tests/darwin/src/` checks one area against XNU's rules and
prints a line `run.sh` expects. Five are static (`hello-static`,
`bsd-carry`, `commpage`, `exclusive-pair`, `aes`); the rest run through
dyld and libSystem from the device's shared cache.

| area | programs |
|------|----------|
| entry, the commpage and the CPU | `hello-static`, `bsd-carry`, `commpage`, `exclusive-pair`, `aes`, `hello`, `apple`, `pages`, `pagezero` |
| clocks and the host | `timebase`, `boottime`, `machclock`, `hoststat`, `loadavg`, `atmflag`, `sysctlnodes` |
| threads and synchronization | `pthread`, `pshared`, `psem`, `thcwd`, `threadsuspend`, `threadstate`, `threadpolicy`, `taskthreads`, `workinterval`, `eventlink` |
| libdispatch, CoreFoundation, XPC | `dispatch`, `dispatch-signal`, `wlqos`, `cfrunloop`, `xpc-anon` |
| processes | `fork`, `exec`, `spawn`, `spawnfa`, `spawnports`, `setexec`, `setexecbad`, `startsusp`, `wait`, `sigchld`, `nocldwait`, `exitreason`, `procknote`, `jobctl`, `pidhold`, `tasksuspend` |
| identity and process information | `creds`, `persona`, `killperm`, `uniqueid`, `procinfo`, `kernproc`, `fdinfo`, `fpinfo`, `ipcfd`, `coalition` |
| policy and resources | `taskpolicy`, `priority`, `procpolicy`, `cpumon`, `rlimit`, `rlimitctl`, `cputime`, `vtimer`, `itimer`, `memlimit` |
| signals and exceptions | `sighandler`, `sigthread`, `sigwait`, `sigio`, `procmask`, `excports`, `excdeliver`, `efault`, `protect` |
| Mach IPC | `portrefs`, `crosstask`, `taskname`, `readports`, `extractright`, `sonce`, `rcvlarge`, `guardesc`, `circular`, `voucherx`, `importance`, `lockimp`, `watchport` |
| memory | `layout`, `shregion`, `stackfb`, `mmapflags`, `madvise`, `msync`, `mlock`, `vmregion`, `vmcopy`, `vmwx`, `jit` |
| files | `fsops`, `pathrules`, `pathconf`, `statino`, `statfsino`, `dirino`, `setattr`, `xattr`, `clone`, `renameswap`, `lockf`, `lastclose`, `guarded`, `fileport`, `filesec`, `openmode`, `vectored`, `aio`, `fixedcalls`, `ioctl`, `realdev` |
| kqueue, poll and pipes | `kq-pipe`, `vnode`, `vnextend`, `select`, `poll`, `pipe`, `timeouts` |
| terminals and `/dev` | `pty`, `ptyjob`, `ptyclose`, `bsdpty`, `ttyinfo`, `ttydead`, `ttydrain`, `fcntltty`, `revoke`, `devfs`, `devattr`, `console` |
| sockets | `sockerr`, `sockevent`, `sockname`, `sockopts`, `halfclose`, `nosigpipe`, `dgrambuf`, `streambuf`, `inet6` |
| code signing and IOKit | `codesig`, `amfi`, `launchcon`, `policy`, `iokit`, `ioreg`, `iosurface`, `iosurfacex`, `iogpudev`, `accel`, `accelr`, `iomfb`, `iomfbmain` |
| the GPU (WebMetal) | `metalwire`, `metal` |

The suite runs single programs and the processes they create. None of it
boots launchd or runs an app.

### Known gaps

What follows is grouped from the kernel's own "not implemented" reports and
the limits its comments state. It is a summary, not the full list: the code
is the reference (search `crates/gex-kernel/src/` for
`darwin_unimplemented`, `note_unimplemented` and `Unported`).

- **The browser.** The page runs no Darwin process yet. Its GPU Worker
  serves the ring, but no kernel in the page sends on it yet: the browser
  host's side of the accelerator, the IOSurface table and the
  presentation sink waits for Darwin processes in the page. The display's
  canvas shows a frame of one layer covering the panel, `BGRA` exactly and
  `b3a8` on an `rgba16float` canvas (each 10-bit code as its nearest half
  float); it refuses other formats, blending, scaling and transforms, and
  a browser without `rgba16float` canvases (Firefox 151) refuses `b3a8`.
- **Code signing.** Besides the static trust cache, only the boot
  cryptexes' are loaded; loading one at run time through AMFI's user
  client is not implemented. CMS signatures (CoreTrust and amfid) are not
  implemented. AMFI's `__mac_syscall` calls for local signing, trust cache
  loading and launch constraints are reported.
- **Launch constraints.** A requirement on a fact this kernel cannot
  supply is decided only when every value the fact could have gives the
  same answer; otherwise it is reported and the launch refused. Those
  facts are `on-authorized-authapfs-volume` (APFS's authorization of a
  volume is not modelled), `on-system-volume` for a file under a bind
  mount, and every fact of pid 1 but `is-init-proc` when pid 1 is the
  kernel's own rather than launchd. Of the volumes a booted system mounts
  after the kernel's, the mount list has only the Preboot volume: a file
  under `/private/var` is on the system volume here.
  Library validation of an OOP-JIT mapping is reported.
- **Sandbox.** A process gets its sandbox as the kext gives it: at exec
  from its `seatbelt-profiles` entitlement, its spawn's Sandbox attributes,
  the platform profile's choice for apps, or its executable's protobox
  profile; or by `sandbox_init` with a builtin profile. The platform
  profile, then the process's, decide the checks that are wired, an exec's
  process-exec* and process-exec-interpreter among them; Sandbox's other
  hooks (the other vnode checks among them) are not called. A process's
  Unix calls, Mach traps and kernel MIG routines are filtered by the masks
  its sandbox (or, with none, the platform profile) gives it, as XNU
  filters them; the socket calls, IOKit's opens and its property reads
  are checked where XNU checks them. A class walk of an IORegistry entry
  whose class this registry does not know (the device tree's nubs, and
  the drivers between them) is reported. Not ported, and reported where the kext would act: the
  profiles of the `com.apple.private.sandbox.profile` entitlements,
  containers and containermanagerd's upcall, the extensions of the
  `com.apple.security.exception.*` entitlements, matching an extension
  filter against an object, Mach message filtering, filters whose
  facts the kernel does not have, some `sandbox_check` filter types,
  `sandbox_check` of another process's operation, and Sandbox's other
  `__mac_syscall` calls.
- **IOKit.** The registry holds the device tree, the internal storage's
  stack (the PCIe root complex and root port, the NVMe controller, its
  root namespace, its block storage driver, disk0, the GPT and its
  partition, APFS's scheme, medium, container and volumes, and each
  medium's BSD client, with the media wired into the `IODeviceTree` plane
  as the drivers wire them), IOSurfaceRoot, the GPU's accelerator and the
  display's framebuffer, with the drivers and nubs on their paths to the
  root. Facts only the device gives (the NVMe controller's strings and
  geometry, the GPT's GUIDs and layout, the container's UUID) are
  stand-ins that gexc names on stderr at start.
  These are reported:
  - opening any other driver;
  - those drivers' other nubs and clients;
  - device tree entries no driver here made a nub of, as `IOService`
    entries;
  - properties those drivers set in their start or probe, and an entry's
    whole table (`io_registry_entry_get_properties_bin_buf`) where it
    lacks them: the storage media's tables are whole (their open state
    live), but the volumes lack what their superblocks give, the PCI nubs
    what their configuration space gives, the controller what its
    registers and NAND commands give, and the drivers their I/O counters;
    the controller's other namespaces and objects are not modelled;
    `IOClassNameOverride`, which only IOSkywalkFamily sets, is missing
    everywhere;
  - IOGPU selectors and traps that make IOGPU objects, and AGXG9G's own
    selectors;
  - the framebuffer's user client selectors other than the swap's (begin,
    end, wait, cancel, cancel all), the display's size, id and main-display
    query, the default surface, the debug flags, the absolute time, the
    notification switch and the color remap mode, and a displayed surface's
    send right;
  - the pipe's runtime properties registered with starting values not yet
    worked out (the framebuffer publishes each it registers; the names it
    never registers are answered missing);
  - framebuffer frame information and CRC notifications, and its power
    assertions;
  - swaps whose layers the pipe would scale, rotate, or read from YCbCr,
    compressed or passthrough formats, with active or exclusion regions,
    kept on screen, carrying user data or of kind 9, and swap waits with a
    timeout;
  - a swap that reaches the glass with no presentation sink installed, or
    that the embedder's sink cannot show;
  - in a gexc built without its `webmetal` feature, WebMetal requests,
    which have no executor to run them; with it, what the executor
    reports it does not implement or cannot honor (its statuses 2 and 3),
    a call on a connection from a task that did not open it, the
    executor's IOSurface shared events (which the kernel does not have),
    and an IOSurface with an `IOSurfaceOffset` given to the GPU;
  - matching dictionaries of kinds not handled.
- **Mach.** The trap `clock_sleep`; MIG routines not in `mig.rs`
  (`processor_set_tasks` among them, with the processor set ports), and
  some `task_info`, `thread_info`, `host_statistics` and `task_policy_get`
  flavors; another process's task ports by its pid where the policies
  allow them: `task_for_pid`'s and `debug_control_port_for_pid`'s (past
  AMFI only with Developer Mode, or for `debug_control_port_for_pid` with
  `com.apple.private.debug_port`), and `task_read_for_pid`'s and
  `task_inspect_for_pid`'s (another task's task access port, its upcall,
  and its read and inspect ports); a fault's exception
  (`EXC_BAD_ACCESS` and the like) sent to a handler the program set, which
  is reported and taken as a signal instead; telling an `EXC_CRASH` handler
  of a death outside a system call; corpses
  (`EXC_CORPSE_NOTIFY`, and the corpse an `EXC_RESOURCE` or simulated
  `EXC_GUARD` would make); handlers of `EXCEPTION_IDENTITY_PROTECTED`
  behavior; hardware breakpoints, watchpoints and single step.
- **Address space.** gex's 64-bit memory is 16 GiB (V8's memory64 cap),
  so a task's map is held only to `0x3_ffff_4000`, not XNU's
  `0x4_5800_0000` (`0xf_c000_0000` for a jumbo map): above it are the
  commpage's alias, to `0x4_0000_0000` (where a program reads the commpage
  and the device has unmapped space), and the memory's end. A fixed
  mapping that reaches past `0x3_ffff_4000`, and an anywhere one with no
  room below it, is reported and fails; a random address (`MAP_JIT`,
  `VM_FLAGS_RANDOM_ADDR`) is drawn below it. The shared region pager's
  slide info versions 1 and 4 are reported; a region's root directory is
  always the root vnode's (no `chroot`); and the owner the mapping call
  requires to be root is the caller, as `stat` reports every file's.
- **Memory.** Purgeable memory, 4 GB chunks and other `mach_vm_allocate`
  and `mach_vm_map` flags not handled, `MAP_TPRO`, reuse advice on a
  region a fork left copy-on-write, the freezer, and the
  `memorystatus_control` commands that need a memory model. A POSIX shared
  memory object is copied into each mapping, so its mappings agree only at
  `msync` and `munmap`, and a second mapping is reported. Memory pressure is
  never posted: the level stays normal.
- **Files and devices.** The filesystems keep no file owners and no access
  control lists, so the `chown` family and ACLs are refused and reported.
  Also reported: `mount`, `mkfifo` and `mknod`, `F_PREALLOCATE`,
  data protection classes, `fsgetpath` by object id, resource fork offsets,
  `RENAME_SECLUDE`, and opening a device whose driver is not modelled.
- **Memory size.** The device's DRAM (iBoot's `memSizeActual`:
  `hw.memsize_physical`, `scale_setup`, the mbuf pool's tier that sets
  `udp_recvspace`, IOGPU's sizes) and the memory the kernel manages, the
  DRAM less iBoot's carveouts (`memSize`, `max_mem`: `hw.memsize`,
  `host_basic_info`, memorystatus, the user wire limit, IOSurface's
  allocation limit) are 4 GiB each until `sysctl hw.memsize_physical
  hw.memsize` on the device measures them.
- **Sockets.** Interface `ioctl`s know only `lo0`. An inet6 socket's
  protocol calls (binding, connecting, sending, receiving, its name,
  `shutdown`, `fstat`, the `IPPROTO_IPV6` and protocol-level options),
  raw and ICMPv6 sockets, and IPv6 addresses whose routes, on-link
  prefixes or finite lifetimes the kernel would keep are reported. Out-of-band data,
  `SO_LINGER`, `SO_DONTROUTE`, `SO_OOBINLINE`, address sharing
  (`SO_REUSEADDR`, `SO_REUSEPORT`) when a bind is refused, keepalive probes
  on a connection the host carries, broadcast datagrams, a socket's owner
  (`so_pgid`), descriptors in a Unix datagram socket's control messages,
  `EVFILT_SOCK`, `EVFILT_EXCEPT` on a socket, and socket `ioctl`s not
  handled are reported.
- **Processes and signals.** Darwin signals with no Linux number, `ptrace`
  requests not handled, `wait4`'s resource usage, `settid`, cancelling a
  thread blocked in a BSD call, process-shared psynch objects and ulocks in
  memory another process maps, `__mac_execve` with a label, and
  `posix_spawn` with a subsystem root path or an audit session port action.
- **Accounting.** What needs ledgers the kernel does not keep: a
  coalition's resource usage, the CPU monitor's actions on a violation, the
  task-wide CPU limit, the wakeups monitor, workloop CPU limits, and the
  pmap's and compressor's ledgers in `TASK_VM_INFO` (resident, internal,
  external, reusable and compressed sizes and their peaks, the footprint's
  peak, decompressions, swap-ins), and `proc_pid_rusage`'s fields that
  need them: the interrupt and platform-idle wakeups that a thread call's
  signal or message to another task made, page-ins, disk I/O, logical
  writes, the CPMU's instructions and cycles, and a bank bill while a
  thread that adopted it runs (its time and that time by each thread's
  effective QoS, its other wakeups from interrupt context and the
  platform-idle ones among them, runnable time, wirings, resident pages,
  footprint and its peaks, another process's, the bank's bills, start, end
  and reaped children's sums are kept; the energy fields are 0, as T8011's
  kernel, with no energy counter, leaves them). On a host
  without per-thread clocks, the virtual timers, `RLIMIT_CPU`, the CPU
  monitor, the workqueue's quantum and `getrusage`'s and
  `proc_pid_rusage`'s times are reported; on one that cannot say which
  pages are a task's, `phys_footprint` is.
- **Terminals.** Terminal `ioctl`s not handled, an `fcntl` that would sleep
  in the driver, calls that would wait for a revoke to finish, and parts of
  `revoke` itself. The console's window size (`km`'s, from the boot video
  console's size, which iBoot's boot arguments give), and a `TIOCCONS` that
  reaches `km` (XNU locks its terminal twice and panics).
- **Other.** `EVFILT_FS`, `NOTE_WL_SYNC_IPC` on a workloop, writes to the
  `sysctl` nodes that only have a fixed value here, the nodes this kernel
  has no value for, and some `proc_info` flavors and `iopolicysys` types.
