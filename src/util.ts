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

// Zero-width and bidirectional control characters, by code point. Listed
// explicitly (rather than as a regex literal) so the source stays ASCII-clean.
export const INVISIBLE_CODE_POINTS = new Set<number>([
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // zero-width space/joiners + LRM/RLM
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidirectional embedding/override
  0x2060, 0xfeff,                         // word joiner + BOM/zero-width no-break
]);

export function hasInvisibleChar(text: string): boolean {
  for (const ch of text) {
    if (INVISIBLE_CODE_POINTS.has(ch.codePointAt(0) ?? 0)) return true;
  }
  return false;
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
