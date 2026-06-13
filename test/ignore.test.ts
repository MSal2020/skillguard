import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeIgnoreMatcher, applyIgnore, loadIgnoreEntries } from '../src/ignore.js';
import { fingerprintFinding } from '../src/util.js';
import type { Finding, ScanResult } from '../src/types.js';

function f(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'SEC004', title: 'Pipe-to-shell', category: 'security',
    severity: 'critical', message: 'm', file: 'scripts/install.sh', ...over,
  };
}

describe('ignore / allowlist', () => {
  it('fingerprint is stable and content-derived', () => {
    expect(fingerprintFinding(f())).toBe(fingerprintFinding(f()));
    expect(fingerprintFinding(f())).not.toBe(fingerprintFinding(f({ ruleId: 'SEC001' })));
  });

  it('matches by rule, path glob, and fingerprint', () => {
    expect(makeIgnoreMatcher([{ rule: 'SEC004' }])(f())).toBe(true);
    expect(makeIgnoreMatcher([{ rule: 'sec004' }])(f())).toBe(true); // case-insensitive
    expect(makeIgnoreMatcher([{ rule: 'SEC001' }])(f())).toBe(false);
    expect(makeIgnoreMatcher([{ path: '**/install.sh' }])(f())).toBe(true);
    expect(makeIgnoreMatcher([{ path: '*.sh' }])(f())).toBe(true); // basename glob
    expect(makeIgnoreMatcher([{ path: '**/other.sh' }])(f())).toBe(false);
    expect(makeIgnoreMatcher([{ fingerprint: fingerprintFinding(f()) }])(f())).toBe(true);
  });

  it('requires all specified fields to match (AND), and ignores empty entries', () => {
    expect(makeIgnoreMatcher([{ rule: 'SEC004', path: '**/other.sh' }])(f())).toBe(false);
    expect(makeIgnoreMatcher([{ rule: 'SEC004', path: '**/install.sh' }])(f())).toBe(true);
    expect(makeIgnoreMatcher([{}])(f())).toBe(false);
  });

  it('removes suppressed findings and recomputes the verdict', () => {
    const result: ScanResult = { kind: 'tools', name: 't', root: '', findings: [f()], score: 40, verdict: 'fail' };
    const { result: out, ignored } = applyIgnore(result, makeIgnoreMatcher([{ rule: 'SEC004' }]));
    expect(ignored).toBe(1);
    expect(out.findings).toHaveLength(0);
    expect(out.verdict).toBe('pass');
  });

  it('loads entries from a .skillguardignore file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-'));
    writeFileSync(join(dir, '.skillguardignore'), JSON.stringify({ ignore: [{ rule: 'SEC004' }] }));
    expect(loadIgnoreEntries([dir])).toEqual([{ rule: 'SEC004' }]);
  });
});
