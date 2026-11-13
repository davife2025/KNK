import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { CliError } from './errors.js';

export const Config = z.object({
  apiUrl: z.string().min(1),
  apiKey: z.string().min(20),
  subject: z.string().trim().min(1).max(120),
});
export type Config = z.infer<typeof Config>;

export function defaultSubject(): string {
  try {
    return `${os.userInfo().username}@${os.hostname()}`;
  } catch {
    return 'unknown@unknown';
  }
}

export function configPath(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform, home = os.homedir()): string {
  if (env.KNK_CONFIG) return env.KNK_CONFIG;
  if (platform === 'win32') return path.join(env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), 'knk', 'config.json');
  return path.join(env.XDG_CONFIG_HOME ?? path.join(home, '.config'), 'knk', 'config.json');
}

/** The key is sent as a bearer token, so plain http is refused except for a machine talking to itself. */
export function assertSafeApiUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CliError(`Invalid API URL: ${raw.slice(0, 100)}`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new CliError('The API URL must use https (http is allowed only for localhost), so your key is never sent in the clear.');
  }
  if (url.username || url.password) throw new CliError('The API URL must not contain credentials.');
  return url;
}

export interface LoadedConfig {
  config: Config | null;
  path: string;
  warnings: string[];
}

/** Environment variables override the file: KNK_API_URL, KNK_API_KEY, KNK_SUBJECT. */
export async function loadConfig(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): Promise<LoadedConfig> {
  const file = configPath(env, platform);
  const warnings: string[] = [];
  let stored: Partial<Config> = {};
  try {
    const text = await readFile(file, 'utf8');
    stored = JSON.parse(text) as Partial<Config>;
    if (platform !== 'win32' && ((await stat(file)).mode & 0o077) !== 0) {
      warnings.push(`${file} is readable by other users and holds your API key. Run: chmod 600 ${file}`);
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') warnings.push(`Could not read ${file}: ${e instanceof Error ? e.message : 'error'}`);
  }
  const merged = {
    apiUrl: env.KNK_API_URL ?? stored.apiUrl,
    apiKey: env.KNK_API_KEY ?? stored.apiKey,
    subject: env.KNK_SUBJECT ?? stored.subject ?? defaultSubject(),
  };
  if (!merged.apiUrl || !merged.apiKey) return { config: null, path: file, warnings };
  const parsed = Config.safeParse(merged);
  if (!parsed.success) {
    warnings.push('The saved configuration is invalid. Run: knk init');
    return { config: null, path: file, warnings };
  }
  assertSafeApiUrl(parsed.data.apiUrl);
  return { config: parsed.data, path: file, warnings };
}

export async function saveConfig(file: string, config: Config, platform: NodeJS.Platform = process.platform): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  if (platform !== 'win32') await chmod(file, 0o600); // writeFile's mode is ignored if the file already existed
}
