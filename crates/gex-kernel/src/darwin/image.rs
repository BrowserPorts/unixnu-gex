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
