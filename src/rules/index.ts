import type { Rule } from '../types.js';
import { securityRules } from './security.js';
import { qualityRules } from './quality.js';
import { mcpRules } from './mcp.js';
import { loadPatternRules } from './patterns.js';

/**
 * All built-in rules. Security and YAML pattern rules run over any target's
 * files (skills and MCP configs alike); quality rules apply to skills and MCP
 * rules to configs — each guards on `target.kind`.
 */
export function defaultRules(): Rule[] {
  return [...securityRules, ...qualityRules, ...mcpRules, ...loadPatternRules()];
}

export { securityRules, qualityRules, mcpRules, loadPatternRules };
