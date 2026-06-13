import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadSkill } from '../src/loader.js';
import { scanSkill } from '../src/engine.js';
import { defaultRules } from '../src/rules/index.js';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = defaultRules();

function scan(relativePath: string) {
  return scanSkill(loadSkill(join(projectRoot, relativePath)), rules);
}

describe('skillguard', () => {
  it('flags the malicious example as failing with critical findings', () => {
    const result = scan('examples/malicious-skill');
    const ruleIds = result.findings.map((f) => f.ruleId);

    expect(result.verdict).toBe('fail');
    expect(result.findings.some((f) => f.severity === 'critical')).toBe(true);
    expect(ruleIds).toContain('SEC001'); // ssh private key
    expect(ruleIds).toContain('SEC007'); // prompt injection
    expect(ruleIds).toContain('SEC003'); // outbound network call
  });

  it('passes the clean example with no findings', () => {
    const result = scan('examples/clean-skill');
    expect(result.findings).toHaveLength(0);
    expect(result.verdict).toBe('pass');
  });

  it('loads the pattern ruleset from YAML', () => {
    expect(rules.some((r) => r.id === 'PAT001')).toBe(true);
  });
});
