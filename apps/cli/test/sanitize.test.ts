import { describe, expect, it } from 'vitest';
import { safe } from '../src/sanitize.js';

describe('safe', () => {
  it('neutralises ANSI escapes so a hostile name cannot rewrite the terminal', () => {
    const out = safe('readme\u001b[2J\u001b[31mFAKE\u001b[0m.txt');
    expect(out).not.toContain('\u001b');
    expect(out).toBe('readme?[2J?[31mFAKE?[0m.txt');
  });

  it('removes line breaks, tabs, NUL, C1 controls (8-bit CSI), bidi overrides, zero-width characters and BOM', () => {
    for (const bad of ['\n', '\r', '\t', '\u0000', '\u0007', '\u009b', '\u202e', '\u2066', '\u200b', '\u200f', '\u2028', '\ufeff', '\u007f']) {
      expect(safe(`a${bad}b`), JSON.stringify(bad)).toBe('a?b');
    }
  });

  it('keeps ordinary text, including non-ASCII', () => {
    expect(safe('café 漢字 – ok')).toBe('café 漢字 – ok');
  });

  it('truncates long input and coerces non-strings', () => {
    expect(safe('x'.repeat(500), 10)).toBe('xxxxxxxxx…');
    expect(safe(12345)).toBe('12345');
    expect(safe(null)).toBe('null');
  });
});
