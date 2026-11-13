#!/usr/bin/env node
import os from 'node:os';
import { main } from './cli.js';

const code = await main(process.argv.slice(2), {
  out: (s) => void process.stdout.write(`${s}\n`),
  err: (s) => void process.stderr.write(`${s}\n`),
  readStdin: async () => {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8');
  },
  env: process.env,
  platform: process.platform,
  home: os.homedir(),
  cwd: process.cwd(),
  isTTY: Boolean(process.stdout.isTTY),
});
process.exitCode = code;
