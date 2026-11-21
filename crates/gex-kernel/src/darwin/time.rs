//! The clocks the Darwin kernel reads: a monotonic one, which the
//! counter (`mach_absolute_time`), the thread calls' deadlines and every
//! timed wait are measured on, and the calendar.
//!
//! The host gives them ([`set_clock`]). A native host's are the system's
//! (`std::time`), which is the default; a target whose standard library has
//! no clock (the browser's wasm) must set its own before the kernel reads
//! either, and a read before it is a panic naming what is missing.

use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The host's clocks: the monotonic clock's reading since an origin of the
/// host's choosing, and the calendar's since the epoch.
#[derive(Clone, Copy)]
pub struct Clock {
    pub monotonic: fn() -> Duration,
    pub realtime: fn() -> Duration,
}

static CLOCK: std::sync::OnceLock<Clock> = std::sync::OnceLock::new();

/// Install the host's clocks, before the kernel first reads one. A second
/// call is refused (false): every reading must come from one clock.
pub fn set_clock(c: Clock) -> bool {
    CLOCK.set(c).is_ok()
}

fn clock() -> Clock {
    if let Some(c) = CLOCK.get() {
        return *c;
    }
    #[cfg(not(target_family = "wasm"))]
    {
        *CLOCK.get_or_init(|| Clock { monotonic: std_monotonic, realtime: std_realtime })
    }
    #[cfg(target_family = "wasm")]
    {
        panic!("the Darwin kernel read a clock, and this host set none (darwin::time::set_clock)")
    }
}

#[cfg(not(target_family = "wasm"))]
fn std_monotonic() -> Duration {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    ORIGIN.get_or_init(std::time::Instant::now).elapsed()
}

#[cfg(not(target_family = "wasm"))]
fn std_realtime() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
}

/// The calendar time now (`SystemTime::now`, from the host's clock).
pub fn realtime() -> SystemTime {
    UNIX_EPOCH + (clock().realtime)()
}

/// A reading of the monotonic clock, as `std::time::Instant` is one, with
/// its arithmetic. Kept as the reading plus [`BIAS`], so that an instant a
/// while before the clock's origin is one, as a system clock's is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

/// How far after its own zero the clock's origin is.
const BIAS: Duration = Duration::from_secs(1 << 32);

impl Instant {
    pub fn now() -> Instant {
        Instant(BIAS + (clock().monotonic)())
    }

    /// The time from `earlier` to this one; zero when `earlier` is later.
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(*self)
    }

    pub fn checked_add(&self, d: Duration) -> Option<Instant> {
        self.0.checked_add(d).map(Instant)
    }

    pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
        self.0.checked_sub(d).map(Instant)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, d: Duration) -> Instant {
        self.checked_add(d).expect("overflow when adding a duration to an instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;
    fn sub(self, d: Duration) -> Instant {
        self.checked_sub(d).expect("overflow when subtracting a duration from an instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}
