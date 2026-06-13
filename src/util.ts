import type { SkillFile } from './types.js';

export interface Match {
  file: string;
  line: number;
  snippet: string;
}

const MAX_SNIPPET = 160;

/**
 * Scan every file in a target line-by-line for a pattern and return the
 * locations that match. The pattern should be non-global; we reset lastIndex
 * defensively so a stray `g` flag can't cause skipped lines.
 */
export function matchInTarget(target: { files: SkillFile[] }, pattern: RegExp): Match[] {
  const matches: Match[] = [];
  for (const file of target.files) {
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

/** Find the 1-based line a substring first appears on, or undefined. */
export function findLine(target: { files: SkillFile[] }, needle: string): number | undefined {
  if (!needle) return undefined;
  for (const file of target.files) {
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(needle)) return i + 1;
    }
  }
  return undefined;
}
