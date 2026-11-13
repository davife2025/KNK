import { constants } from 'node:fs';
import { lstat, open, readdir, readlink, realpath } from 'node:fs/promises';
import path from 'node:path';

// Directories never worth scanning. .git is read through readRel/listRel instead, never walked.
export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'target', 'vendor', 'venv', '.venv', '__pycache__', '.tox', 'coverage', '.turbo']);

export interface FileEntry {
  abs: string;
  rel: string; // always '/'-separated
  size: number;
}
export interface SymlinkEntry {
  rel: string;
  target: string;
  escapes: boolean;
}
export interface WalkResult {
  files: FileEntry[];
  symlinks: SymlinkEntry[];
  truncated: boolean;
}

export const isInside = (root: string, p: string): boolean => {
  const r = path.relative(root, p);
  return r === '' || (r !== '..' && !r.startsWith(`..${path.sep}`) && !path.isAbsolute(r));
};
const toRel = (root: string, abs: string) => path.relative(root, abs).split(path.sep).join('/');

/**
 * Lists regular files under root WITHOUT following symlinks. A repo that plants a link to ~/.ssh/id_rsa must not
 * get it read, so links are recorded (and flagged when they point outside) but never traversed.
 */
export async function walk(root: string, o: { maxFiles?: number; maxDepth?: number } = {}): Promise<WalkResult> {
  const maxFiles = o.maxFiles ?? 5000;
  const maxDepth = o.maxDepth ?? 10;
  const real = await realpath(root);
  const out: WalkResult = { files: [], symlinks: [], truncated: false };
  const queue: { dir: string; depth: number }[] = [{ dir: real, depth: 0 }];

  while (queue.length > 0) {
    const { dir, depth } = queue.shift()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1)); // deterministic output
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) {
        let target = '';
        try {
          target = await readlink(abs);
        } catch {
          /* unreadable link: still recorded */
        }
        out.symlinks.push({ rel: toRel(real, abs), target, escapes: !isInside(real, path.resolve(dir, target)) });
      } else if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && depth < maxDepth) queue.push({ dir: abs, depth: depth + 1 });
      } else if (e.isFile()) {
        if (out.files.length >= maxFiles) {
          out.truncated = true;
          return out;
        }
        try {
          out.files.push({ abs, rel: toRel(real, abs), size: (await lstat(abs)).size });
        } catch {
          /* vanished */
        }
      }
    }
  }
  return out;
}

/** Reads a regular file as text. Returns null for symlinks, FIFOs, devices, binaries and unreadable files. */
export async function readTextSafe(abs: string, maxBytes: number): Promise<{ text: string; truncated: boolean } | null> {
  let fh;
  try {
    if (!(await lstat(abs)).isFile()) return null;
    // O_NOFOLLOW closes the swap-for-a-symlink race; O_NONBLOCK stops a swapped-in FIFO from hanging the scan.
    fh = await open(abs, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const buf = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await fh.read(buf, 0, maxBytes + 1, 0);
    const slice = buf.subarray(0, Math.min(bytesRead, maxBytes));
    if (slice.subarray(0, 8192).includes(0)) return null; // binary
    return { text: slice.toString('utf8'), truncated: bytesRead > maxBytes };
  } catch {
    return null;
  } finally {
    await fh?.close().catch(() => {});
  }
}

/** True only if every directory on the way is a real directory, not a symlink (lstat, never stat). */
async function realChain(root: string, segments: string[]): Promise<boolean> {
  let cur = root;
  for (const s of segments) {
    cur = path.join(cur, s);
    try {
      if (!(await lstat(cur)).isDirectory()) return false;
    } catch {
      return false;
    }
  }
  return true;
}

/** Reads root/segments... refusing symlinked parent directories (O_NOFOLLOW alone only guards the last component). */
export async function readRel(root: string, ...segments: string[]) {
  if (!(await realChain(root, segments.slice(0, -1)))) return null;
  return readTextSafe(path.join(root, ...segments), 200_000);
}

export async function listRel(root: string, ...segments: string[]): Promise<string[]> {
  if (!(await realChain(root, segments))) return [];
  try {
    return await readdir(path.join(root, ...segments));
  } catch {
    return [];
  }
}
