import type { Finding, Severity, Verdict } from './types.js';

const WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

/** Aggregate findings into a 0–100 risk score (higher = riskier). */
export function scoreFindings(findings: Finding[]): number {
  const raw = findings.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  return Math.min(100, raw);
}

export function verdictFor(findings: Finding[], score: number): Verdict {
  if (findings.some((f) => f.severity === 'critical') || score >= 50) return 'fail';
  if (score >= 15) return 'warn';
  return 'pass';
}
