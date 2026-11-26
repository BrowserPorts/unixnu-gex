import type { System } from './index';
import type { WindowEnv } from './windows-host';

/** The whole desktop in one canvas, composited on WebGPU. Made before boot. */
export declare class CompositorWindows extends EventTarget {
  /** `background`: the desktop behind the windows, a colour ('#rrggbb') or `{ color, image (a URL
   *  or Blob), anchor }` (the edge of the image that always shows). */
  constructor(sys: System, options: {
    canvas: HTMLCanvasElement; /** Default: the canvas sized and followed in device pixels at the real devicePixelRatio. A number: that scale, sized by the page. */ scale?: number | 'auto'; x11?: 'rootless' | 'rootful' | null;
    background?: string | { color?: string; image?: string | URL | Blob; anchor?: 'top' | 'center' | 'bottom' };
  });
  get env(): WindowEnv;
  /** The output's new size, in device pixels. */
  resize(width: number, height: number): void;
  /** `pixels: false`: without the hash of what is shown. */
  describe(options?: { pixels?: boolean }): Promise<unknown>;
}
