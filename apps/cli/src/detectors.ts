import path from 'node:path';
import { redact, runStaticAnalysis } from '@knk/detect';
import type { ArtifactKind, Severity } from '@knk/shared';
import { isInside, listRel, readRel, readTextSafe, type FileEntry, type WalkResult } from './fsutil.js';

export type Review = 'always' | 'if_flagged';

export interface LocalFinding {
  id: string;
  title: string;
  severity: Severity;
  rel: string;
  line?: number;
  detail?: string;
}
export interface Candidate {
  kind: ArtifactKind;
  rel: string;
  label: string;
  content: string;
  review: Review; // always: code that runs on its own, so it is always reviewed. if_flagged: only when something looks off.
  truncated: boolean;
  findings: LocalFinding[];
}
export interface SecretHit {
  rel: string;
  types: string[];
  count: number;
}
export interface Detection {
  candidates: Candidate[];
  findings: LocalFinding[];
  secrets: SecretHit[];
}

const MAX_FILE = 200_000;
export const MAX_CONTENT = 40_000; // matches the API limit

/** JSON with comments and trailing commas, which VS Code and dev container files allow. Throws on invalid input. */
export function parseJsonc(text: string): unknown {
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i]!;
    const n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') {
        out += n ?? '';
        i += 2;
        continue;
      }
      if (c === '"') inStr = false;
      i++;
    } else if (c === '"') {
      inStr = true;
      out += c;
      i++;
    } else if (c === '/' && n === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (c === '/' && n === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
    } else {
      out += c;
      i++;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
}

const lineOf = (text: string, index: number) => text.slice(0, Math.max(0, index)).split('\n').length;
const SCRIPT_FILE = /[\w@./-]+\.(?:js|cjs|mjs|ts|sh|bash|py|ps1)\b/g;
const URL_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/\S+/gi;
/** Script files a command line refers to. URLs are removed first so https://x.test/a.sh is not mistaken for a path. */
export const scriptFiles = (script: string): string[] => [...new Set(script.replace(URL_TEXT, ' ').match(SCRIPT_FILE) ?? [])];

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare'];
const INSTALLER_NAME = /^(install|setup|bootstrap|postinstall|preinstall)\.(sh|bash|ps1|bat|cmd|py|js)$/i;
const AI_JSON = ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', '.claude/settings.json', '.claude/settings.local.json'];
const AI_MD = ['CLAUDE.md', 'AGENTS.md', '.cursorrules', '.github/copilot-instructions.md'];
const OVERRIDE = [
  /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts?)/i,
  /do\s+not\s+(?:tell|inform|mention|reveal|show)[^.\n]{0,40}\b(?:user|developer|human)\b/i,
  /(?:silently|secretly|without\s+(?:telling|asking|informing|notifying))[^.\n]{0,60}\b(?:run|execute|install|send|upload|curl|download)\b/i,
];
const SECRET_FILE = /^(\.env(\..+)?|\.npmrc|\.pypirc|\.netrc|credentials(\..+)?\.json|id_(rsa|dsa|ecdsa|ed25519)|.+\.(pem|key|p12|pfx))$/i;
const EXAMPLE_FILE = /\.(example|sample|template|dist)$/i;
const matchesPath = (rel: string, p: string) => rel === p || rel.endsWith(`/${p}`);

/**
 * Finds what matters in a repository without executing, following or modifying anything.
 * Every read refuses symlinks. Only code that runs on its own is marked for review.
 */
export async function detect(root: string, w: WalkResult): Promise<Detection> {
  const candidates = new Map<string, Candidate>();
  const findings: LocalFinding[] = [];
  const secrets: SecretHit[] = [];
  const byAbs = new Map(w.files.map((f) => [f.abs, f]));
  const read = (f: FileEntry) => readTextSafe(f.abs, MAX_FILE);

  const add = (kind: ArtifactKind, rel: string, label: string, text: string, truncated: boolean, review: Review, local: LocalFinding[] = []) => {
    const existing = candidates.get(rel); // one candidate per file, however many detectors found it
    if (existing) {
      if (review === 'always') existing.review = 'always';
      return;
    }
    const content = text.slice(0, MAX_CONTENT);
    const stat = runStaticAnalysis(kind, content).findings.map((f): LocalFinding => ({ id: f.id, title: f.title, severity: f.severity, rel, line: f.line, detail: f.detail }));
    candidates.set(rel, { kind, rel, label, content, review, truncated: truncated || text.length > MAX_CONTENT, findings: [...local, ...stat] });
  };
  const flag = (id: string, title: string, severity: Severity, rel: string, line?: number, detail?: string): LocalFinding => ({ id, title, severity, rel, line, detail });

  // 1. install lifecycle scripts and the files they run
  for (const f of w.files.filter((x) => path.posix.basename(x.rel) === 'package.json')) {
    const r = await read(f);
    if (!r) continue;
    let pkg: { name?: unknown; scripts?: unknown };
    try {
      pkg = JSON.parse(r.text) as typeof pkg;
    } catch {
      continue;
    }
    const scripts = pkg && typeof pkg.scripts === 'object' && pkg.scripts ? (pkg.scripts as Record<string, unknown>) : {};
    const picked = Object.fromEntries(LIFECYCLE.filter((k) => typeof scripts[k] === 'string').map((k) => [k, scripts[k] as string]));
    if (Object.keys(picked).length === 0) continue;
    // Send only the lifecycle scripts, not the whole manifest: minimal disclosure.
    add('repo_manifest', f.rel, 'install lifecycle scripts', JSON.stringify({ name: typeof pkg.name === 'string' ? pkg.name : undefined, scripts: picked }, null, 2), r.truncated, 'always');

    for (const script of Object.values(picked)) {
      for (const ref of scriptFiles(script)) {
        const abs = path.resolve(path.dirname(f.abs), ref);
        if (!isInside(root, abs)) {
          findings.push(flag('local.script_escapes_repo', 'An install script runs a file outside the repository', 'medium', f.rel, undefined, ref));
          continue;
        }
        const target = byAbs.get(abs); // only regular files the walker saw, so no symlink and no traversal
        const tr = target && (await read(target));
        if (target && tr) add(/\.(sh|bash|ps1|py)$/.test(ref) ? 'install_script' : 'source_file', target.rel, 'script run on install', tr.text, tr.truncated, 'always');
      }
    }
  }

  // 2. installer-named files
  for (const f of w.files) {
    const name = path.posix.basename(f.rel);
    const depth = f.rel.split('/').length;
    if (!(name === 'setup.py' && depth === 1) && !(depth <= 3 && INSTALLER_NAME.test(name))) continue;
    const r = await read(f);
    if (r) add(/\.js$/.test(name) ? 'source_file' : 'install_script', f.rel, 'installer script', r.text, r.truncated, name === 'setup.py' ? 'always' : 'if_flagged');
  }

  // 3. git hooks and git config entries that can run commands
  for (const name of (await listRel(root, '.git', 'hooks')).slice(0, 50)) {
    if (name.endsWith('.sample')) continue;
    const r = await readRel(root, '.git', 'hooks', name);
    if (!r) continue;
    const rel = `.git/hooks/${name}`;
    add('install_script', rel, 'git hook', r.text, r.truncated, 'always', [flag('local.git_hook_present', 'A git hook is installed and will run on git operations', 'medium', rel)]);
  }
  for (const f of w.files.filter((x) => x.rel === '.husky' || x.rel.startsWith('.husky/'))) {
    if (f.rel.startsWith('.husky/_') || f.rel.endsWith('.gitignore')) continue;
    const r = await read(f);
    if (r) add('install_script', f.rel, 'husky hook', r.text, r.truncated, 'always');
  }
  const gc = await readRel(root, '.git', 'config');
  if (gc) {
    const risky: string[] = [];
    const local: LocalFinding[] = [];
    let section = '';
    gc.text.split('\n').forEach((raw, i) => {
      const sec = /^\s*\[([^\]]+)\]/.exec(raw);
      if (sec) {
        section = sec[1]!.trim().toLowerCase();
        return;
      }
      const kv = /^\s*([\w.-]+)\s*=\s*(.*)$/.exec(raw);
      if (!kv) return;
      const key = kv[1]!.toLowerCase();
      const val = kv[2]!.trim();
      let sev: Severity | null = null;
      if (section === 'core' && key === 'sshcommand') sev = 'high';
      else if (section === 'core' && key === 'fsmonitor' && !/^(true|false)$/i.test(val)) sev = 'medium';
      else if (section === 'core' && key === 'hookspath') sev = 'medium';
      else if (section.startsWith('alias') && val.startsWith('!')) sev = 'high';
      else if (section.startsWith('credential') && key === 'helper' && val.startsWith('!')) sev = 'high';
      else if (section.startsWith('filter') && ['clean', 'smudge', 'process'].includes(key) && !/^git-lfs\b/.test(val)) sev = 'high'; // git-lfs is the common legitimate case
      if (sev) {
        risky.push(raw.trim());
        local.push(flag('local.git_config_exec', `git config can run commands (${section} ${key})`, sev, '.git/config', i + 1));
      }
    });
    if (risky.length) {
      add('source_file', '.git/config', 'git config entries that can run commands', risky.join('\n'), false, 'always', local);
    }
  }

  // 4. editor and container auto-run
  for (const f of w.files) {
    if (matchesPath(f.rel, '.vscode/tasks.json')) {
      const r = await read(f);
      if (!r) continue;
      let auto = /"runOn"\s*:\s*"folderOpen"/.test(r.text);
      try {
        const tasks = (parseJsonc(r.text) as { tasks?: { runOptions?: { runOn?: string } }[] }).tasks ?? [];
        auto = tasks.some((t) => t?.runOptions?.runOn === 'folderOpen');
      } catch {
        /* keep the regex answer */
      }
      if (auto) {
        const line = lineOf(r.text, r.text.search(/"runOn"\s*:\s*"folderOpen"/));
        add('repo_manifest', f.rel, 'auto-run editor task', r.text, r.truncated, 'always', [
          flag('local.workspace_autorun', 'An editor task is set to run when the folder is opened', 'high', f.rel, line, 'It runs once you trust the workspace.'),
        ]);
      }
    } else if (/(^|\/)(\.devcontainer\/(.+\/)?devcontainer\.json|\.devcontainer\.json)$/.test(f.rel)) {
      const r = await read(f);
      if (!r) continue;
      let cfg: Record<string, unknown>;
      try {
        cfg = parseJsonc(r.text) as Record<string, unknown>;
      } catch {
        continue;
      }
      const local: LocalFinding[] = [];
      if (cfg.initializeCommand) local.push(flag('local.devcontainer_host_command', 'A dev container setting runs a command on your own machine', 'high', f.rel, undefined, 'initializeCommand'));
      for (const k of ['onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand']) {
        if (cfg[k]) local.push(flag('local.devcontainer_command', `A dev container runs a command on setup (${k})`, 'medium', f.rel, undefined, k));
      }
      if (local.length) add('repo_manifest', f.rel, 'dev container commands', r.text, r.truncated, 'always', local);
    }
  }

  // 5. AI tool configuration and instruction files
  for (const f of w.files) {
    if (AI_JSON.some((p) => matchesPath(f.rel, p))) {
      const r = await read(f);
      if (!r) continue;
      const local: LocalFinding[] = [];
      try {
        const cfg = parseJsonc(r.text) as { hooks?: unknown };
        if (/\.claude\/settings/.test(f.rel) && cfg?.hooks && typeof cfg.hooks === 'object' && Object.keys(cfg.hooks).length > 0) {
          local.push(flag('local.ai_tool_hooks', 'An AI tool setting defines hooks that can run commands automatically', 'medium', f.rel));
        }
      } catch {
        /* unparseable: still reviewed */
      }
      add('ai_tool_config', f.rel, 'AI tool configuration', r.text, r.truncated, 'always', local);
    } else if (AI_MD.some((p) => matchesPath(f.rel, p))) {
      const r = await read(f);
      if (!r) continue;
      const hit = OVERRIDE.map((re) => re.exec(r.text)).find(Boolean);
      const local = hit ? [flag('local.agent_instruction_override', 'Instructions for an AI assistant try to override its rules or hide actions from you', 'medium', f.rel, lineOf(r.text, hit.index))] : [];
      add('source_file', f.rel, 'AI assistant instructions', r.text, r.truncated, 'if_flagged', local);
    }
  }

  // 6. secrets in the repo (reported by type and count only; never sent, never printed)
  for (const f of w.files) {
    const name = path.posix.basename(f.rel);
    if (!SECRET_FILE.test(name) || EXAMPLE_FILE.test(name)) continue;
    const r = await readTextSafe(f.abs, 64_000);
    if (!r) continue;
    const { redactions } = redact(r.text);
    const count = redactions.reduce((n, x) => n + x.count, 0);
    if (count > 0) {
      secrets.push({ rel: f.rel, types: redactions.map((x) => x.type), count });
    }
  }

  // 7. symlinks that leave the repository (never followed)
  for (const s of w.symlinks.filter((x) => x.escapes)) {
    findings.push(flag('local.symlink_escape', 'A symlink points outside the repository', 'high', s.rel, undefined, s.target));
  }

  return { candidates: [...candidates.values()], findings, secrets };
}
