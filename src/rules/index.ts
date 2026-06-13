import type { Rule } from '../types.js';
import { securityRules } from './security.js';
import { qualityRules } from './quality.js';
import { mcpRules } from './mcp.js';
import { poisoningRules } from './poisoning.js';
import { loadPatternRules } from './patterns.js';

/**
 * All built-in rules. Security and YAML pattern rules run over any target's
 * files (skills and MCP configs alike); quality rules apply to skills, MCP
 * rules to configs, and poisoning rules to tool definitions — each guards on
 * `target.kind` (or simply finds no tools to analyse).
 */
export function defaultRules(): Rule[] {
  return [...securityRules, ...qualityRules, ...mcpRules, ...poisoningRules, ...loadPatternRules()];
}

export { securityRules, qualityRules, mcpRules, poisoningRules, loadPatternRules };
