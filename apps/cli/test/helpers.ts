import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach } from 'vitest';

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

export async function tmp(prefix = 'knk-test-'): Promise<string> {
  const d = await mkdtemp(path.join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

/** Builds a directory from { 'rel/path': 'content' }. Never executes anything. */
export async function makeRepo(files: Record<string, string | Buffer>, links: Record<string, string> = {}): Promise<string> {
  const root = await tmp('knk-repo-');
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content);
  }
  for (const [rel, target] of Object.entries(links)) {
    const abs = path.join(root, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await symlink(target, abs);
  }
  return root;
}

export function mkfifo(p: string): boolean {
  try {
    execFileSync('mkfifo', [p]);
    return true;
  } catch {
    return false;
  }
}

export const TOKEN = `ghp_${'a'.repeat(36)}`;
