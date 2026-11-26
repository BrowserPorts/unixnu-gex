// The browser's time zone for a program's environment. A guest has no
// zoneinfo files unless its tree ships them, and its libc is then on UTC: a
// POSIX TZ string with this year's rules (posix-tz.js) needs none, and Wine
// takes its clock and the Windows zone it matches from the libc's localtime.
import { posixTz } from './host/posix-tz.js';

/**
 * `{ TZ, WINEGEX_TZNAME }` for the browser's zone (`TZ` its rules as a POSIX
 * string; `WINEGEX_TZNAME` the zone's name, which Wine names its Windows
 * zone by), or `{}` when the browser names none or its rules do not fit one
 * string. Nothing is set: the page puts them in the `env` it spawns with,
 * or leaves them out for a tree with zoneinfo of its own.
 */
export function hostTimeZone() {
  let zone = null;
  try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { /* none */ }
  const tz = zone ? posixTz(zone) : null;
  return tz ? { TZ: tz, WINEGEX_TZNAME: zone } : {};
}
