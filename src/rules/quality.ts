import { basename } from 'node:path';
import type { ScanTarget, LoadedSkill, Finding, Rule } from '../types.js';

function manifestFile(skill: LoadedSkill): string {
  return basename(skill.manifestPath);
}

/** Quality rules only apply to skills; MCP configs have no description/body. */
function skillRule(
  id: string,
  title: string,
  fn: (skill: LoadedSkill) => Finding[],
): Pick<Rule, 'check'> {
  return {
    check(target: ScanTarget): Finding[] {
      if (target.kind !== 'skill') return [];
      return fn(target);
    },
  };
}

export const qualityRules: Rule[] = [
  {
    id: 'QUA001',
    title: 'Missing or weak description',
    category: 'quality',
    severity: 'medium',
    ...skillRule('QUA001', 'Missing or weak description', (skill) => {
      const d = skill.description.trim();
      if (!d) {
        return [{
          ruleId: 'QUA001',
          title: 'Missing description',
          category: 'quality',
          severity: 'high',
          message: 'No `description` in frontmatter. Agents use it to decide when to trigger a skill — without one the skill is effectively invisible.',
          remediation: 'Add a description that states what the skill does and when to use it.',
          file: manifestFile(skill),
        }];
      }
      if (d.length < 25) {
        return [{
          ruleId: 'QUA001',
          title: 'Weak description',
          category: 'quality',
          severity: 'medium',
          message: `Description is very short (${d.length} chars). Triggering accuracy suffers when it lacks "use when…" context.`,
          remediation: 'Expand it with concrete trigger conditions and keywords.',
          file: manifestFile(skill),
          snippet: d,
        }];
      }
      return [];
    }),
  },
  {
    id: 'QUA002',
    title: 'Description lacks trigger cues',
    category: 'quality',
    severity: 'low',
    ...skillRule('QUA002', 'Description lacks trigger cues', (skill) => {
      const d = skill.description.toLowerCase();
      if (!d) return [];
      if (!/(use (?:this )?when|trigger|for (?:when|tasks)|whenever)/.test(d)) {
        return [{
          ruleId: 'QUA002',
          title: 'Description lacks trigger cues',
          category: 'quality',
          severity: 'low',
          message: 'Description does not say *when* to use the skill (e.g. "Use when…"). This is the single biggest factor in reliable triggering.',
          remediation: 'Add an explicit "Use when…" clause describing the trigger conditions.',
          file: manifestFile(skill),
        }];
      }
      return [];
    }),
  },
];
