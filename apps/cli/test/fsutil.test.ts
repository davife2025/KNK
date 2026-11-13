import { mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { isInside, listRel, readRel, readTextSafe, walk } from '../src/fsutil.js';
import { makeRepo, mkfifo, tmp } from './helpers.js';

describe('walk', () => {
  it('lists regular files with "/"-separated relative paths, in a stable order, skipping heavy directories', async () => {
    const root = await makeRepo({ 'b.txt': '1', 'a.txt': '2', 'src/x.js': '3', 'node_modules/p/i.js': '4', '.git/config': '5', 'dist/o.js': '6', '.vscode/tasks.json': '7' });
    const w = await walk(root);
    expect(w.files.map((f) => f.rel)).toEqual(['a.txt', 'b.txt', '.vscode/tasks.json', 'src/x.js']);
    expect(w.truncated).toBe(false);
  });

  it('never follows symlinks, and says which ones leave the repository', async () => {
    const outside = await makeRepo({ 'secret.txt': 'TOP-SECRET', 'dir/inner.txt': 'x' });
    const root = await makeRepo({ 'ok.txt': 'ok', 'real/in.txt': 'in' }, { 'to-file': path.join(outside, 'secret.txt'), 'to-dir': path.join(outside, 'dir'), 'inside-link': 'real/in.txt', dangling: '/nonexistent/path' });
    const w = await walk(root);
    expect(w.files.map((f) => f.rel)).toEqual(['ok.txt', 'real/in.txt']); // nothing reached through a link
    const by = Object.fromEntries(w.symlinks.map((s) => [s.rel, s.escapes]));
    expect(by).toEqual({ 'to-file': true, 'to-dir': true, 'inside-link': false, dangling: true });
  });

  it('stops at the file and depth limits and reports truncation', async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 20; i++) files[`f${String(i).padStart(2, '0')}.txt`] = 'x';
    const root = await makeRepo({ ...files, 'a/b/c/deep.txt': 'x' });
    expect(await walk(root, { maxFiles: 5 })).toMatchObject({ truncated: true, files: { length: 5 } });
    const shallow = await walk(root, { maxDepth: 1 });
    expect(shallow.files.some((f) => f.rel.endsWith('deep.txt'))).toBe(false);
  });
});

describe('readTextSafe', () => {
  it('reads text and reports truncation', async () => {
    const root = await makeRepo({ 'a.txt': 'hello world' });
    expect(await readTextSafe(path.join(root, 'a.txt'), 100)).toEqual({ text: 'hello world', truncated: false });
    expect(await readTextSafe(path.join(root, 'a.txt'), 5)).toEqual({ text: 'hello', truncated: true });
  });

  it('refuses binaries, directories, symlinks and missing files', async () => {
    const root = await makeRepo({ 'bin.dat': Buffer.from([0x68, 0x00, 0x69]), 'real.txt': 'x', 'd/f.txt': 'x' }, { link: 'real.txt' });
    for (const p of ['bin.dat', 'd', 'link', 'missing.txt']) expect(await readTextSafe(path.join(root, p), 100), p).toBeNull();
  });

  it('does not hang on a named pipe (a repo can contain one)', async () => {
    const root = await tmp();
    if (!mkfifo(path.join(root, 'pipe'))) return; // not available on this platform
    expect(await readTextSafe(path.join(root, 'pipe'), 100)).toBeNull();
    expect((await walk(root)).files).toEqual([]);
  });
});

describe('readRel / listRel', () => {
  it('read normally', async () => {
    const root = await makeRepo({ '.git/hooks/pre-commit': 'echo hi', '.git/config': '[core]' });
    expect(await listRel(root, '.git', 'hooks')).toEqual(['pre-commit']);
    expect((await readRel(root, '.git', 'hooks', 'pre-commit'))?.text).toBe('echo hi');
  });

  it('refuse a symlinked parent directory, which O_NOFOLLOW alone would not catch', async () => {
    const outside = await makeRepo({ 'hooks/id_rsa': 'TOP-SECRET' });
    const root = await tmp();
    await symlink(outside, path.join(root, '.git')); // .git -> outside dir
    expect(await listRel(root, '.git', 'hooks')).toEqual([]);
    expect(await readRel(root, '.git', 'hooks', 'id_rsa')).toBeNull();

    const root2 = await tmp();
    await mkdir(path.join(root2, '.git'));
    await symlink(path.join(outside, 'hooks'), path.join(root2, '.git', 'hooks')); // .git/hooks -> outside dir
    expect(await listRel(root2, '.git', 'hooks')).toEqual([]);
    expect(await readRel(root2, '.git', 'hooks', 'id_rsa')).toBeNull();
    await writeFile(path.join(root2, '.git', 'config'), '[core]'); // a normal file beside it still works
    expect((await readRel(root2, '.git', 'config'))?.text).toBe('[core]');
  });
});

describe('isInside', () => {
  it('handles edge cases', () => {
    expect(isInside('/r', '/r')).toBe(true);
    expect(isInside('/r', '/r/a/b')).toBe(true);
    expect(isInside('/r', '/r/..foo')).toBe(true); // a name that merely starts with dots
    expect(isInside('/r', '/r/../x')).toBe(false);
    expect(isInside('/r', '/rx')).toBe(false);
    expect(isInside('/r', '/etc/passwd')).toBe(false);
  });
});
