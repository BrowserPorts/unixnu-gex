// A GL recording (?glcapture=1) is whole once the last process it recorded
// exits (fixtures/page/gl-capture.mjs).

import { join } from 'node:path';
import { checks, FIXTURES } from '../lib/checks.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 60 };

export default (t) => checks(t, join(FIXTURES, 'page', 'gl-capture.mjs'));
