import type { System } from './index';
import type { CompositorWindows } from './windows-compositor';

/** A window a drop names: its title, its client and surface, the point in it. */
export interface DropWindow {
  title: string;
  client: number;
  surface: number;
  x: number;
  y: number;
}

export interface DropOptions {
  /** Where it was dropped (the event's clientX and clientY): the window there is dragged onto. */
  x?: number;
  y?: number;
  /** The guest directory to copy into (absolute, made if missing); default a new /tmp/drops/N. */
  dir?: string | null;
  /** A guest directory the copy moves into when no window takes it. */
  fallback?: string | null;
  /** Stops the copy and takes back what it wrote. */
  signal?: AbortSignal;
  onProgress?(p: { done: number; total: number; files: number; filesDone: number; name: string }): void;
}

export interface DropResult {
  path: string;
  files: number;
  bytes: number;
  ms: number;
  window: DropWindow | null;
  /** Whether the window's program took the drop. */
  accepted: boolean;
  /** Where the top-level files and folders are now. */
  paths: string[];
}

/** Files and folders dropped on the page, copied into the guest and dragged onto the window
 *  under the point. The default build only. */
export declare class HostDrop {
  constructor(sys: System, options?: { windows?: CompositorWindows | null });
  /** The window at a page point, or null. */
  windowAt(x: number, y: number): Promise<DropWindow | null>;
  /** Call it in the drop event's handler, before anything there awaits. */
  drop(data: DataTransfer | DataTransferItemList | FileList | File[], options?: DropOptions): Promise<DropResult>;
}
