import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadToolManifest } from '../src/tools.js';
import { buildLock, diffAgainstLock, fingerprintTool } from '../src/pin.js';
import type { ToolSet } from '../src/types.js';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function cleanSet(): ToolSet {
  return loadToolManifest(join(projectRoot, 'examples/clean-tools/tools.json'));
}

describe('tool pinning', () => {
  it('builds a lock with a fingerprint per tool', () => {
    const lock = buildLock([cleanSet()]);
    expect(Object.keys(lock.tools).sort()).toEqual(['format_json', 'slugify']);
  });

  it('reports no drift when nothing changed', () => {
    const set = cleanSet();
    const lock = buildLock([set]);
    expect(diffAgainstLock(set, lock)).toHaveLength(0);
  });

  it('flags a changed tool definition as a possible rug-pull (PIN001)', () => {
    const set = cleanSet();
    const lock = buildLock([set]);
    set.tools.find((t) => t.name === 'slugify')!.description = 'Now does something else entirely.';
    const findings = diffAgainstLock(set, lock);
    expect(findings.map((f) => f.ruleId)).toContain('PIN001');
    expect(findings.find((f) => f.ruleId === 'PIN001')!.severity).toBe('high');
  });

  it('flags added (PIN002) and removed (PIN003) tools', () => {
    const set = cleanSet();
    const lock = buildLock([set]);
    set.tools.pop(); // remove slugify
    set.tools.push({ name: 'new_tool', description: 'A new tool.', parameters: [], raw: {} });
    const ids = diffAgainstLock(set, lock).map((f) => f.ruleId);
    expect(ids).toContain('PIN002'); // new_tool added
    expect(ids).toContain('PIN003'); // slugify removed
  });

  it('fingerprint is stable for identical definitions and changes with content', () => {
    const a = cleanSet().tools[0];
    const b = cleanSet().tools[0];
    expect(fingerprintTool(a)).toBe(fingerprintTool(b));
    b.description += ' changed';
    expect(fingerprintTool(a)).not.toBe(fingerprintTool(b));
  });
});
