import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadMcpConfig, discoverMcpConfigs } from '../src/mcp.js';
import { scanTarget } from '../src/engine.js';
import { defaultRules } from '../src/rules/index.js';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = defaultRules();

function scanConfig(relativePath: string) {
  return scanTarget(loadMcpConfig(join(projectRoot, relativePath)), rules);
}

describe('skillguard mcp', () => {
  it('discovers the mcp.json config in a directory', () => {
    const found = discoverMcpConfigs(join(projectRoot, 'examples/malicious-mcp'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/mcp\.json$/);
  });

  it('flags the malicious MCP config with critical findings', () => {
    const result = scanConfig('examples/malicious-mcp/mcp.json');
    const ruleIds = result.findings.map((f) => f.ruleId);

    expect(result.kind).toBe('mcp');
    expect(result.verdict).toBe('fail');
    expect(ruleIds).toContain('MCP001'); // hardcoded secret in env
    expect(ruleIds).toContain('MCP002'); // npx -y @latest
    expect(ruleIds).toContain('MCP003'); // bash -c
    expect(ruleIds).toContain('MCP004'); // http:// endpoint
    expect(ruleIds).toContain('SEC004'); // curl | bash (text rule reused on config)
  });

  it('does not leak the secret value into findings', () => {
    const result = scanConfig('examples/malicious-mcp/mcp.json');
    const json = JSON.stringify(result.findings);
    expect(json).not.toContain('REALLOOKINGKEY');
  });

  it('passes a clean MCP config with no findings', () => {
    const result = scanConfig('examples/clean-mcp/mcp.json');
    expect(result.findings).toHaveLength(0);
    expect(result.verdict).toBe('pass');
  });
});
