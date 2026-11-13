// C0/C1 controls (includes ESC, so ANSI sequences die), bidi overrides and zero-width characters.
// A malicious repo can name a file or write a string to spoof or hide terminal output; nothing untrusted is printed raw.
const UNSAFE = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2066-\u2069\uFEFF]/g;

/** Single-line, terminal-safe rendering of untrusted text. */
export function safe(input: unknown, max = 200): string {
  const s = String(input).replace(UNSAFE, '?');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
