import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { assertSafeApiUrl, configPath, loadConfig, saveConfig } from '../src/config.js';
import { tmp } from './helpers.js';

const KEY = `knk_aaaaaaaa_${'b'.repeat(43)}`;
const cfg = { apiUrl: 'https://api.example.com', apiKey: KEY, subject: 'alice@laptop' };
const posix = process.platform !== 'win32';

describe('configPath', () => {
  it('follows platform conventions and KNK_CONFIG', () => {
    expect(configPath({ KNK_CONFIG: '/x/c.json' }, 'linux', '/home/a')).toBe('/x/c.json');
    expect(configPath({}, 'linux', '/home/a')).toBe('/home/a/.config/knk/config.json');
    expect(configPath({ XDG_CONFIG_HOME: '/xdg' }, 'linux', '/home/a')).toBe('/xdg/knk/config.json');
    expect(configPath({ APPDATA: 'C:\\A' }, 'win32', 'C:\\Users\\a')).toContain('knk');
  });
});

describe('assertSafeApiUrl', () => {
  it('requires https, except for a machine talking to itself, and never allows embedded credentials', () => {
    for (const ok of ['https://api.example.com', 'http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787']) expect(() => assertSafeApiUrl(ok), ok).not.toThrow();
    for (const bad of ['http://api.example.com', 'http://192.168.1.5', 'ftp://x.test', 'javascript:alert(1)', 'nonsense', 'https://u:p@api.example.com']) expect(() => assertSafeApiUrl(bad), bad).toThrow();
  });
});

describe('save and load', () => {
  it('round-trips and stores the key owner-only', async () => {
    const file = path.join(await tmp(), 'sub', 'config.json');
    await saveConfig(file, cfg);
    expect(JSON.parse(await readFile(file, 'utf8'))).toEqual(cfg);
    const loaded = await loadConfig({ KNK_CONFIG: file });
    expect(loaded.config).toEqual(cfg);
    expect(loaded.warnings).toEqual([]);
    if (posix) {
      expect((await stat(file)).mode & 0o777).toBe(0o600);
      expect((await stat(path.dirname(file))).mode & 0o777).toBe(0o700);
    }
  });

  it('tightens permissions when overwriting a file that was world-readable', async () => {
    if (!posix) return;
    const file = path.join(await tmp(), 'config.json');
    await writeFile(file, '{}', { mode: 0o644 });
    await saveConfig(file, cfg);
    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it('warns when the file holding the key is readable by others', async () => {
    if (!posix) return;
    const file = path.join(await tmp(), 'config.json');
    await saveConfig(file, cfg);
    await chmod(file, 0o644);
    expect((await loadConfig({ KNK_CONFIG: file })).warnings.join(' ')).toMatch(/readable by other users/);
  });

  it('environment overrides the file, and missing or invalid config yields null, not a crash', async () => {
    const file = path.join(await tmp(), 'config.json');
    expect((await loadConfig({ KNK_CONFIG: file })).config).toBeNull(); // no file
    await saveConfig(file, cfg);
    const o = await loadConfig({ KNK_CONFIG: file, KNK_SUBJECT: 'bob@box', KNK_API_URL: 'https://other.example.com' });
    expect(o.config).toMatchObject({ subject: 'bob@box', apiUrl: 'https://other.example.com', apiKey: KEY });
    await writeFile(file, '{ not json');
    const bad = await loadConfig({ KNK_CONFIG: file });
    expect(bad.config).toBeNull();
    expect(bad.warnings.join(' ')).toMatch(/Could not read/);
    expect((await loadConfig({ KNK_CONFIG: file, KNK_API_URL: 'https://a.example.com', KNK_API_KEY: 'short' })).warnings.join(' ')).toMatch(/invalid/);
  });

  it('refuses to use a plain-http API URL from the environment', async () => {
    await expect(loadConfig({ KNK_CONFIG: '/nonexistent/c.json', KNK_API_URL: 'http://api.example.com', KNK_API_KEY: KEY })).rejects.toThrow(/https/);
  });
});
