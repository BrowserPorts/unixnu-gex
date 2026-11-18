// A surface's glass, frame and caption icon reach the compositor
// (fixtures/page/wl-glass.mjs).

import { join } from 'node:path';
import { checks, FIXTURES } from '../lib/checks.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 120 };

export default (t) => checks(t, join(FIXTURES, 'page', 'wl-glass.mjs'));
