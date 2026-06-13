import type { LoadedSkill, Finding, Rule, ScanResult } from './types.js';
import { scoreFindings, verdictFor } from './score.js';

export function runRules(skill: LoadedSkill, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.check(skill));
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

export function scanSkill(skill: LoadedSkill, rules: Rule[]): ScanResult {
  const findings = runRules(skill, rules);
  const score = scoreFindings(findings);
  return {
    skill: skill.name,
    root: skill.root,
    findings,
    score,
    verdict: verdictFor(findings, score),
  };
}
