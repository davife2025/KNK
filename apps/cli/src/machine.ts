import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

export interface MachineHit {
  type: string;
  display: string; // like ~/.aws/credentials. Never contains file contents.
  loose: boolean; // readable by group or others
}

interface Target {
  type: string;
  rel: string[];
  dir?: boolean;
  test?: RegExp; // a presence check only; matched text is never kept
}

const TARGETS: Target[] = [
  { type: 'aws', rel: ['.aws', 'credentials'] },
  { type: 'npm', rel: ['.npmrc'], test: /_authToken\s*=\s*(?!\$\{)\S+/ },
  { type: 'git', rel: ['.git-credentials'] },
  { type: 'netrc', rel: ['.netrc'], test: /\bpassword\b/ },
  { type: 'kubernetes', rel: ['.kube', 'config'], test: /\b(token|client-key-data):/ },
  { type: 'docker', rel: ['.docker', 'config.json'], test: /"auth"\s*:\s*"[^"]+"/ },
  { type: 'gcloud', rel: ['.config', 'gcloud', 'application_default_credentials.json'] },
  { type: 'solana', rel: ['.config', 'solana', 'id.json'] },
  { type: 'near', rel: ['.near-credentials'], dir: true },
  { type: 'ethereum_keystore', rel: ['.ethereum', 'keystore'], dir: true },
];

/**
 * Looks for well-known credential files and reports their type and permissions. It reads a file only to check that a
 * token is present, and never keeps or prints content. This is awareness for the developer, not a signal sent to KNK
 * unless they opt in, because ordinary developers legitimately have these files.
 */
export async function scanMachine(home: string, platform: NodeJS.Platform = process.platform): Promise<MachineHit[]> {
  const hits: MachineHit[] = [];
  const loose = (mode: number) => platform !== 'win32' && (mode & 0o077) !== 0;
  const show = (parts: string[]) => `~/${parts.join('/')}`;

  for (const t of TARGETS) {
    const p = path.join(home, ...t.rel);
    try {
      const st = await stat(p);
      if (t.dir) {
        if (st.isDirectory() && (await readdir(p)).length > 0) hits.push({ type: t.type, display: show(t.rel), loose: loose(st.mode) });
      } else if (st.isFile()) {
        if (t.test && !t.test.test((await readFile(p, 'utf8')).slice(0, 64_000))) continue;
        hits.push({ type: t.type, display: show(t.rel), loose: loose(st.mode) });
      }
    } catch {
      /* not present or unreadable */
    }
  }
  try {
    for (const name of await readdir(path.join(home, '.ssh'))) {
      if (!/^id_/.test(name) || name.endsWith('.pub')) continue;
      const st = await stat(path.join(home, '.ssh', name));
      if (st.isFile()) hits.push({ type: 'ssh_key', display: show(['.ssh', name]), loose: loose(st.mode) });
    }
  } catch {
    /* no .ssh */
  }
  return hits;
}
