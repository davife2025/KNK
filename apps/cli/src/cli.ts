import path from 'node:path';
import { parseArgs } from 'node:util';
import type { GateTx } from '@knk/shared';
import { ApiFailure, createClient, type KnkClient } from './client.js';
import { assertSafeApiUrl, configPath, defaultSubject, loadConfig, saveConfig, type Config } from './config.js';
import { CliError } from './errors.js';
import { renderGate, renderScan, renderStatus } from './report.js';
import { safe } from './sanitize.js';
import { runScan } from './scan.js';

export const VERSION = '0.0.0';

export interface Io {
  out(s: string): void;
  err(s: string): void;
  readStdin(): Promise<string>;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  home: string;
  cwd: string;
  isTTY: boolean;
  fetchImpl?: typeof fetch;
}

const HELP = `knk ${VERSION}: developer-side defence for teams that hold signing power

Usage
  knk init [--api-url URL] [--subject NAME] [--key-stdin]   Link this machine to your workspace
  knk scan [path] [--untrusted] [--offline] [--machine]     Scan a repository (read-only, nothing is executed)
           [--report-tokens] [--max-send N] [--json]
  knk gate check <wallet> (--raw HEX | --delegate ADDR [--chain-id N] [--nonce N]
                          | --transfer TO --amount N --asset SYM) [--subject NAME] [--json]
  knk status                                                Show your workspace and trust state

Your API key is read from KNK_API_KEY or --key-stdin, never from a flag, so it stays out of shell history.

Exit codes
  scan   0 no suspicious signals   2 suspicious   3 malicious
  gate   0 allow                   4 hold         5 block
  any    1 error
`;

async function need(io: Io, offlineOk = false): Promise<{ config: Config; client: KnkClient }> {
  const loaded = await loadConfig(io.env, io.platform);
  loaded.warnings.forEach((w) => io.err(`note: ${safe(w, 300)}`));
  if (!loaded.config) {
    if (offlineOk) throw new CliError('not configured');
    throw new CliError('Not configured. Run: knk init');
  }
  return { config: loaded.config, client: createClient({ baseUrl: loaded.config.apiUrl, key: loaded.config.apiKey, fetchImpl: io.fetchImpl }) };
}

const failure = (e: unknown): CliError =>
  e instanceof CliError
    ? e
    : e instanceof ApiFailure
      ? new CliError(e.status === 401 || e.status === 403 ? `KNK rejected the request (${e.code}). Check your key and its scopes.` : `${safe(e.message)} (${e.code})`)
      : new CliError(e instanceof Error ? safe(e.message) : 'Unexpected error');

function parse<T extends Record<string, { type: 'string' | 'boolean' }>>(args: string[], options: T) {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (e) {
    throw new CliError(e instanceof Error ? safe(e.message.split('\n')[0] ?? 'Invalid arguments') : 'Invalid arguments');
  }
}

async function init(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, { 'api-url': { type: 'string' }, subject: { type: 'string' }, 'key-stdin': { type: 'boolean' } });
  const existing = (await loadConfig(io.env, io.platform)).config;
  const key = io.env.KNK_API_KEY ?? (values['key-stdin'] ? (await io.readStdin()).trim() : undefined);
  if (!key) {
    throw new CliError('Provide your API key with KNK_API_KEY or --key-stdin. A --key flag is not supported on purpose: command-line arguments end up in shell history and process lists.');
  }
  const apiUrl = values['api-url'] ?? io.env.KNK_API_URL ?? existing?.apiUrl;
  if (!apiUrl) throw new CliError('Provide the API URL with --api-url or KNK_API_URL.');
  assertSafeApiUrl(apiUrl);
  const subject = values.subject ?? io.env.KNK_SUBJECT ?? existing?.subject ?? defaultSubject();

  const me = await createClient({ baseUrl: apiUrl, key, fetchImpl: io.fetchImpl }).me();
  await saveConfig(configPath(io.env, io.platform, io.home), { apiUrl, apiKey: key, subject }, io.platform);

  io.out(`[ok] linked workspace “${safe(me.workspace.name)}”`);
  io.out('[ok] sensors: installs, repos, AI tool configs');
  io.out(`    subject  ${safe(subject)}`);
  const missing = ['analyze', 'events:write', 'gate:check'].filter((s) => !me.scopes.includes(s as never) && !me.scopes.includes('admin'));
  if (missing.length) io.out(`[!] this key lacks scope(s): ${missing.join(', ')}. Some commands will not work.`);
  io.out(`    config saved to ${safe(configPath(io.env, io.platform, io.home))} (owner-only)`);
  return 0;
}

async function scan(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(args, {
    untrusted: { type: 'boolean' },
    offline: { type: 'boolean' },
    machine: { type: 'boolean' },
    'report-tokens': { type: 'boolean' },
    'max-send': { type: 'string' },
    json: { type: 'boolean' },
  });
  if (positionals.length > 1) throw new CliError('scan takes one path.');
  const maxSend = values['max-send'] === undefined ? undefined : Number(values['max-send']);
  if (maxSend !== undefined && (!Number.isInteger(maxSend) || maxSend < 0 || maxSend > 100)) throw new CliError('--max-send must be an integer from 0 to 100.');
  if (values['report-tokens'] && !values.machine) throw new CliError('--report-tokens needs --machine.');

  let client: KnkClient | null = null;
  let subject = defaultSubject();
  if (!values.offline) {
    const loaded = await loadConfig(io.env, io.platform);
    loaded.warnings.forEach((w) => io.err(`note: ${safe(w, 300)}`));
    if (loaded.config) {
      subject = loaded.config.subject;
      client = createClient({ baseUrl: loaded.config.apiUrl, key: loaded.config.apiKey, fetchImpl: io.fetchImpl });
    } else {
      io.err('note: not configured, so this is a local-only scan. Run knk init for signed verdicts and team trust.');
    }
  }

  const result = await runScan(
    { path: path.resolve(io.cwd, positionals[0] ?? '.'), untrusted: Boolean(values.untrusted), offline: Boolean(values.offline), machine: Boolean(values.machine), reportTokens: Boolean(values['report-tokens']), maxSend },
    { client, subject, home: io.home, platform: io.platform },
  );
  io.out(values.json ? JSON.stringify(result, null, 2) : renderScan(result, io.isTTY && !io.env.NO_COLOR));
  return result.label === 'malicious' ? 3 : result.label === 'suspicious' ? 2 : 0;
}

async function gate(args: string[], io: Io): Promise<number> {
  if (args[0] !== 'check') throw new CliError('Usage: knk gate check <wallet> ...');
  const { values, positionals } = parse(args.slice(1), {
    subject: { type: 'string' },
    raw: { type: 'string' },
    delegate: { type: 'string' },
    'chain-id': { type: 'string' },
    nonce: { type: 'string' },
    transfer: { type: 'string' },
    amount: { type: 'string' },
    asset: { type: 'string' },
    json: { type: 'boolean' },
  });
  const wallet = positionals[0];
  if (!wallet || positionals.length > 1) throw new CliError('Usage: knk gate check <wallet> (--raw HEX | --delegate ADDR | --transfer TO --amount N --asset SYM)');
  const modes = [values.raw, values.delegate, values.transfer].filter((v) => v !== undefined).length;
  if (modes !== 1) throw new CliError('Give exactly one of --raw, --delegate or --transfer.');
  const int = (v: string | undefined, name: string, d: number) => {
    const n = v === undefined ? d : Number(v);
    if (!Number.isInteger(n) || n < 0) throw new CliError(`--${name} must be a non-negative integer.`);
    return n;
  };
  let tx: GateTx;
  if (values.raw !== undefined) tx = { format: 'evm_raw', raw: values.raw };
  else if (values.delegate !== undefined) tx = { format: 'evm_authorization', chainId: int(values['chain-id'], 'chain-id', 1), delegate: values.delegate, nonce: int(values.nonce, 'nonce', 0) };
  else {
    if (!values.amount || !values.asset) throw new CliError('--transfer needs --amount and --asset.');
    tx = { format: 'transfer', to: values.transfer!, amount: values.amount, asset: values.asset };
  }

  const { config, client } = await need(io);
  const view = await client.gateCheck({ subject: values.subject ?? config.subject, wallet, tx });
  io.out(values.json ? JSON.stringify(view, null, 2) : renderGate(view, io.isTTY && !io.env.NO_COLOR));
  return view.payload.decision === 'allow' ? 0 : view.payload.decision === 'hold' ? 4 : 5;
}

async function status(args: string[], io: Io): Promise<number> {
  parse(args, {});
  const { config, client } = await need(io);
  const [me, trust] = await Promise.all([client.me(), client.trust(config.subject)]);
  io.out(renderStatus({ workspace: me.workspace.name, subject: config.subject, scopes: me.scopes, trust }, io.isTTY && !io.env.NO_COLOR));
  return 0;
}

/** Returns the process exit code. Never throws: every failure becomes one clean line on stderr. */
export async function main(argv: string[], io: Io): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
      io.out(HELP);
      return cmd ? 0 : 1;
    }
    if (cmd === '--version' || cmd === '-v') {
      io.out(`knk ${VERSION}`);
      return 0;
    }
    if (cmd === 'init') return await init(rest, io);
    if (cmd === 'scan') return await scan(rest, io);
    if (cmd === 'gate') return await gate(rest, io);
    if (cmd === 'status') return await status(rest, io);
    throw new CliError(`Unknown command "${safe(cmd, 40)}". Run: knk help`);
  } catch (e) {
    io.err(`knk: ${failure(e).message}`);
    return 1;
  }
}
