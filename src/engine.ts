import type { ScanTarget, Finding, Rule, ScanResult } from './types.js';
import { scoreFindings, verdictFor } from './score.js';

export function runRules(target: ScanTarget, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.check(target));
    } catch (err) {
      // A buggy rule should never crash the whole scan.
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: 'info',
        message: `rule errored: ${(err as Error).message}`,
      });
    }
  }
  return findings;
}

export function scanTarget(target: ScanTarget, rules: Rule[]): ScanResult {
  const findings = runRules(target, rules);
  const score = scoreFindings(findings);
  return {
    kind: target.kind,
    name: target.name,
    root: target.root,
    findings,
    score,
    verdict: verdictFor(findings, score),
  };
}

/** Back-compat alias — skills are just one kind of scan target. */
export const scanSkill = scanTarget;

/**
 * Add findings produced outside the rule engine (e.g. pinning / rug-pull
 * checks) and recompute the score and verdict.
 */
export function appendFindings(result: ScanResult, extra: Finding[]): ScanResult {
  if (extra.length === 0) return result;
  const findings = [...result.findings, ...extra];
  const score = scoreFindings(findings);
  return { ...result, findings, score, verdict: verdictFor(findings, score) };
}
