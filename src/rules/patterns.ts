import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Rule, Finding, LoadedSkill, Severity, Category } from '../types.js';
import { matchInSkill } from '../util.js';

interface PatternSpec {
  id: string;
  title: string;
  category?: Category;
  severity?: Severity;
  pattern: string;
  flags?: string;
  message: string;
  remediation?: string;
}

/**
 * Load data-driven detection rules from a YAML ruleset. Contributors can add a
 * rule by appending one entry — no TypeScript required.
 */
export function loadPatternRules(rulesetPath?: string): Rule[] {
  const path = rulesetPath ?? defaultRulesetPath();
  if (!existsSync(path)) return [];
  const parsed = parseYaml(readFileSync(path, 'utf8')) as { rules?: PatternSpec[] } | null;
  const specs = parsed?.rules ?? [];
  return specs.map(specToRule);
}

function specToRule(spec: PatternSpec): Rule {
  const severity = spec.severity ?? 'medium';
  const category = spec.category ?? 'security';
  const regex = new RegExp(spec.pattern, spec.flags ?? 'i');
  return {
    id: spec.id,
    title: spec.title,
    category,
    severity,
    check(skill: LoadedSkill): Finding[] {
      return matchInSkill(skill, regex).map((m) => ({
        ruleId: spec.id,
        title: spec.title,
        category,
        severity,
        message: spec.message,
        remediation: spec.remediation,
        file: m.file,
        line: m.line,
        snippet: m.snippet,
      }));
    },
  };
}

function defaultRulesetPath(): string {
  // Works from both src/rules (dev/tests via tsx) and dist/rules (built).
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, '..', '..', 'rulesets', 'patterns.yaml'),
    join(here, '..', 'rulesets', 'patterns.yaml'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return candidates[0];
}
