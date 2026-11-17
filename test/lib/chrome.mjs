// The browser the runtime tests, the Wine page harness and the recorder
// drive, and its flags for this host.
//
//   chromePath()            CHROME, else this platform's Chromium or Chrome
//   hostAngle               ANGLE on the machine's GPU, the backend WebGPU takes
//                           too (a canvas both read needs one): Vulkan on Linux,
//                           Metal on macOS
//   vulkanFeature           Chromium's Vulkan, which WebGPU takes on Linux (none
//                           on macOS)
//   headlessScreen(w, h)    a headless browser's screen of w x h: ozone's
//                           headless platform on Linux; macOS's headless mode
//                           takes the window size alone

import { existsSync } from 'node:fs';

const mac = process.platform === 'darwin';

export function chromePath() {
  if (process.env.CHROME) return process.env.CHROME;
  if (mac) {
    for (const p of ['/Applications/Chromium.app/Contents/MacOS/Chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']) {
      if (existsSync(p)) return p;
    }
  }
  return '/usr/bin/chromium';
}

export const hostAngle = mac ? '--use-angle=metal' : '--use-angle=vulkan';

export const vulkanFeature = mac ? [] : ['--enable-features=Vulkan'];

export function headlessScreen(width, height) {
  const size = `--window-size=${width},${height}`;
  return mac ? [size] : ['--ozone-platform=headless', `--ozone-override-screen-size=${width},${height}`, size];
}
