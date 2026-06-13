import type { Rule } from '../types.js';
import { securityRules } from './security.js';
import { qualityRules } from './quality.js';
import { loadPatternRules } from './patterns.js';

/** All built-in rules: hand-written security + quality checks, plus the YAML ruleset. */
export function defaultRules(): Rule[] {
  return [...securityRules, ...qualityRules, ...loadPatternRules()];
}

export { securityRules, qualityRules, loadPatternRules };
