// A run that starts Wine from a launch script gets the build's Wine's game
// controllers (fixtures/page/wine-controllers.mjs).

import { join } from 'node:path';
import { checks, FIXTURES } from '../lib/checks.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 60 };

export default (t) => checks(t, join(FIXTURES, 'page', 'wine-controllers.mjs'));
