//! A Darwin (Mach-O) program's image as exec loads it (`load_machfile`):
//! the executable at its random slide, dyld right after it by a slide of its
//! own when it names one, and what the kernel takes from them (the
//! platform, the signature, `LC_MAIN`'s stack size, dyld's image list). For
//! a host's first program and for an `execve` alike, on every host.

use gex_ld::Program;

/// What loading found.
pub struct DarwinImage {
    pub program: Program,
    /// `LC_BUILD_VERSION`'s platform and SDK.
    pub platform: (u32, u32),
    /// `LC_CODE_SIGNATURE`'s blob.
    pub code_signature: Option<Vec<u8>>,
    /// `LC_MAIN`'s stack size (0: the default).
    pub stacksize: u64,
    /// `LC_LOAD_DYLINKER`'s path.
    pub dylinker: Option<String>,
    /// dyld's `dyld_all_image_infos` (its `__all_image_info`, slid): what
    /// the kernel records as the task's dyld info.
    pub dyld_infos: u64,
    /// Its size (`load_result.all_image_info_size`).
    pub dyld_infos_size: u64,
    /// The main thread's stack top (`load_result.user_stack`): `USRSTACK64`
    /// less the executable's slide.
    pub user_stack: u64,
    /// The stack pointer an `LC_UNIXTHREAD` names (`load_threadstack`'s
    /// custom stack): 0 for none.
    pub thread_stack: u64,
}

/// Load the Mach-O executable `bytes` (one slice), with its dyld read by
/// `read` (a guest path), at the slides `load_machfile` draws. An error
/// says what could not be loaded and why.
pub fn load(bytes: &[u8], name: &str, read: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Result<DarwinImage, String> {
    use super::exec;
    let slides = exec::Slides::draw();
    let (m, exe) = gex_ld::macho::load(bytes, slides.main).map_err(|e| format!("loading {name}: {e}"))?;
    // load_main and load_unixthread: the stack slides down by the image's
    // slide (none for an image that is not position independent).
    let user_stack = exec::user_stack(exe.bias);
    let code_signature = m.code_signature.and_then(|(o, n)| bytes.get(o as usize..(o as usize).checked_add(n as usize)?)).map(<[u8]>::to_vec);
    let stacksize = match &m.entry {
        Some(gex_ld::macho::Entry::Main { stacksize, .. }) => *stacksize,
        _ => 0,
    };
    let thread_stack = match &m.entry {
        Some(gex_ld::macho::Entry::Thread { sp, .. }) => *sp,
        _ => 0,
    };
    let (mut dyld_infos, mut dyld_infos_size) = (0, 0);
    let interp = match &m.dylinker {
        None => None,
        Some(dyld) => {
            let dbytes = read(dyld).map_err(|e| format!("{name} names {dyld}: {e}"))?;
            if !gex_ld::macho::is_macho(&dbytes) {
                return Err(format!("{dyld} is not a Mach-O file"));
            }
            let dm = gex_ld::macho::parse(&dbytes).map_err(|e| format!("loading {dyld}: {e}"))?;
            let slide = gex_ld::macho::dylinker_slide(&dm, slides.dyld, gex_ld::macho::max_vm_addr(&exe));
            let (dm, di) = gex_ld::macho::load_parsed(dm, &dbytes, slide).map_err(|e| format!("loading {dyld}: {e}"))?;
            if let Some(s) = dm.section("__DATA_DIRTY", "__all_image_info").or_else(|| dm.section("__DATA", "__all_image_info")) {
                dyld_infos = s.addr.wrapping_add(di.bias);
                dyld_infos_size = s.size;
            }
            Some(di)
        }
    };
    Ok(DarwinImage {
        program: Program { exe, interp, direct: None },
        platform: (m.platform.unwrap_or(0), m.sdk.unwrap_or(0)),
        code_signature,
        stacksize,
        dylinker: m.dylinker.clone(),
        dyld_infos,
        dyld_infos_size,
        user_stack,
        thread_stack,
    })
}

/// `MH_EXECUTE`, `MH_DYLINKER`, and the header flags `MH_DYLDLINK` and
/// `MH_PIE` (`mach-o/loader.h`).
const MH_EXECUTE: u32 = 0x2;
const MH_DYLINKER: u32 = 0x7;
const MH_DYLDLINK: u32 = 0x4;
const MH_PIE: u32 = 0x0020_0000;
/// `CPU_TYPE_X86_64` and `CPU_TYPE_ARM64` (`mach/machine.h`).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// `parse_machfile`'s check of the executable's header (xnu-10063
/// mach_loader.c, the image at depth 1, as a RELEASE kernel builds it,
/// the web device's): an `MH_EXECUTE` that names dyld (`MH_DYLDLINK`)
/// must be position independent where `pie_required` says (arm64 always);
/// one that does not, a static executable, is refused but for x86_64
/// (and under Rosetta, which iOS does not have), its `#if !(DEVELOPMENT ||
/// DEBUG)`; any other file type at that depth is refused. Each refusal is
/// `LOAD_FAILURE`, which exec's `load_return_to_errno` makes `EBADEXEC`.
/// What the header said, for a refused one; `None` for one it lets
/// through, or a slice too short to hold a header (the load says why).
pub fn exec_header_refused(slice: &[u8]) -> Option<String> {
    let w = |o: usize| slice.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let (Some(cputype), Some(filetype), Some(flags)) = (w(4), w(12), w(24)) else { return None };
    match filetype {
        MH_EXECUTE if flags & MH_DYLDLINK != 0 => (flags & MH_PIE == 0 && cputype == CPU_TYPE_ARM64).then(|| "a dynamic executable that is not position independent (MH_PIE), which arm64 requires (pie_required)".to_string()),
        MH_EXECUTE if cputype == CPU_TYPE_X86_64 => None,
        MH_EXECUTE => Some("a static executable (no MH_DYLDLINK), which only a DEVELOPMENT or DEBUG kernel loads".to_string()),
        MH_DYLINKER => Some("dyld itself as the executable (MH_DYLINKER at depth 1)".to_string()),
        t => Some(format!("a Mach-O file of type {t:#x}, not an executable")),
    }
}

impl crate::syscalls::Kernel {
    /// `load_machfile` of the image an exec or a spawn activated
    /// (`img`'s slice of its file), as `exec_mach_imgact` calls it:
    /// the image, or the errno its failure is (`EIO` for a file that cannot
    /// be read, `EBADEXEC` for `parse_machfile`'s `LOAD_FAILURE` and for a
    /// signature that is not valid, `EBADMACHO` for a file that does not
    /// load) and why.
    pub fn darwin_load_image(&self, img: &super::execve::Image) -> Result<DarwinImage, (crate::errno::Errno, String)> {
        use super::errno::{EBADEXEC, EBADMACHO};
        let Some(bytes) = self.read_file(&img.path) else { return Err((crate::errno::Errno::EIO, format!("cannot read {}", img.path))) };
        let Some(slice) = bytes.get(img.arch_offset as usize..(img.arch_offset + img.arch_size) as usize) else {
            return Err((EBADMACHO, format!("{}'s slice is past its end", img.path)));
        };
        if let Some(why) = exec_header_refused(slice) {
            return Err((EBADEXEC, format!("{}: {why}", img.path)));
        }
        let read = |p: &str| self.read_file(p).ok_or_else(|| format!("cannot read {p}"));
        let loaded = load(slice, &img.path, &read).map_err(|e| (EBADMACHO, e))?;
        if let Some(cs) = &loaded.code_signature {
            super::codesign::validate_csblob(cs).map_err(|_| (EBADEXEC, format!("{}'s code signature is not valid", img.path)))?;
        }
        Ok(loaded)
    }

    /// A spawn's child whose image did not load, in its spawner's call
    /// (`exec_activate_image`'s error in `posix_spawn`): ended as that
    /// call's failure ends it, `exit1(p, 1)` with `P_LIST_DEADPARENT` and
    /// `p_posix_spawn_failed` (`proc_prepareexit`'s critical exit, which a
    /// crash behavior of PANIC_ON_EXIT or _SPAWN_FAIL makes a panic), its
    /// task ended, its descriptors closed, and gone unseen by its parent.
    pub fn darwin_spawn_load_failed(&mut self) {
        self.dtask.spawn_failed = true;
        self.darwin_critical_exit(1);
        self.darwin_task_terminate();
        self.close_all_fds();
        self.procs.reap(self.pid);
    }
}

#[cfg(test)]
mod tests {
    use super::exec_header_refused;

    fn header(cputype: u32, filetype: u32, flags: u32) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        h[4..8].copy_from_slice(&cputype.to_le_bytes());
        h[12..16].copy_from_slice(&filetype.to_le_bytes());
        h[24..28].copy_from_slice(&flags.to_le_bytes());
        h
    }

    /// parse_machfile's switch on a RELEASE kernel: a dynamic position
    /// independent arm64 executable loads; a static one, one not position
    /// independent, dyld and any other file type do not.
    #[test]
    fn a_release_kernel_loads_only_dynamic_pie_executables() {
        const ARM64: u32 = 0x0100_000c;
        assert_eq!(exec_header_refused(&header(ARM64, 2, 0x0020_0085)), None);
        assert!(exec_header_refused(&header(ARM64, 2, 0x0020_0001)).unwrap().contains("static"));
        assert!(exec_header_refused(&header(ARM64, 2, 0x85)).unwrap().contains("MH_PIE"));
        assert!(exec_header_refused(&header(ARM64, 7, 0x85)).is_some());
        assert!(exec_header_refused(&header(ARM64, 6, 0x0020_0085)).is_some());
        // x86_64 static executables are allowed (not iOS's, but as written).
        assert_eq!(exec_header_refused(&header(0x0100_0007, 2, 0)), None);
        assert_eq!(exec_header_refused(&[0u8; 8]), None);
    }
}
