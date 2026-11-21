//! Where the Darwin kernel's own words go: what it reports as not
//! implemented or refused, its strict-mode stops, the console's output
//! (`km`) and the machine's end.
//!
//! A native host's standard error is the default. A host whose standard
//! error is nowhere (the browser's wasm, where `eprintln!` writes nothing)
//! sets its own sink ([`set_sink`]) before the kernel runs a Darwin
//! process, so that nothing it says is lost.

use std::io::Write;

static SINK: std::sync::OnceLock<fn(&[u8])> = std::sync::OnceLock::new();

/// Send everything the kernel says to `f`; false when a sink is set
/// already.
pub fn set_sink(f: fn(&[u8])) -> bool {
    SINK.set(f).is_ok()
}

/// Say `bytes`, as they are.
pub fn write(bytes: &[u8]) {
    match SINK.get() {
        Some(f) => f(bytes),
        None => {
            let mut e = std::io::stderr().lock();
            let _ = e.write_all(bytes);
            let _ = e.flush();
        }
    }
}

/// `eprintln!` through [`write`].
#[macro_export]
macro_rules! darwin_say {
    ($($t:tt)*) => {
        $crate::darwin::report::write(format!("{}\n", format_args!($($t)*)).as_bytes())
    };
}
