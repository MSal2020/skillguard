import type { LoadedSkill } from './types.js';

export interface Match {
  file: string;
  line: number;
  snippet: string;
}

const MAX_SNIPPET = 160;

/**
 * Scan every file in a skill line-by-line for a pattern and return the
 * locations that match. The pattern should be non-global; we reset lastIndex
 * defensively so a stray `g` flag can't cause skipped lines.
 */
export function matchInSkill(skill: LoadedSkill, pattern: RegExp): Match[] {
  const matches: Match[] = [];
  for (const file of skill.files) {
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      pattern.lastIndex = 0;
      if (pattern.test(lines[i])) {
        matches.push({
          file: file.path,
          line: i + 1,
          snippet: lines[i].trim().slice(0, MAX_SNIPPET),
        });
      }
    }
  }
  return matches;
}
