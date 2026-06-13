import { extname } from 'node:path';
import { createHash } from 'node:crypto';
import type { SkillFile, Finding } from './types.js';

/**
 * A short, stable id for a finding — by rule + file + matched content (not line,
 * which shifts on edits). Shown in output so a user can suppress one finding via
 * a `.skillguardignore` entry.
 */
export function fingerprintFinding(f: Finding): string {
  return createHash('sha256')
    .update(`${f.ruleId}|${f.file ?? ''}|${f.snippet ?? f.title}`)
    .digest('hex')
    .slice(0, 8);
}

export interface Match {
  file: string;
  line: number;
  snippet: string;
}

export interface MatchOptions {
  /**
   * Only test "code" lines — every line of a script or data file, and the
   * fenced code blocks of a markdown doc, but NOT documentation prose. Keeps
   * execution rules (network, pipe-to-shell, obfuscation) from firing on a
   * sentence that merely mentions `curl`.
   */
  codeOnly?: boolean;
}

const MAX_SNIPPET = 160;

const SCRIPT_EXT = new Set([
  '.sh', '.bash', '.zsh', '.dash', '.js', '.mjs', '.cjs', '.ts', '.tsx',
  '.py', '.rb', '.ps1', '.php', '.pl', '.go', '.rs', '.java',
]);
const DATA_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.env', '.ndjson', '.ini', '.cfg']);

const DOC_EXT = new Set(['.md', '.markdown', '.mdx', '.rst', '.txt']);

/** True for documentation files (where a risky command is usually shown, not run). */
export function isDocFile(path: string): boolean {
  return DOC_EXT.has(extname(path).toLowerCase());
}

/** Per-line flags: is this line "code" (vs documentation prose)? */
export function codeLineFlags(path: string, lines: string[]): boolean[] {
  const ext = extname(path).toLowerCase();
  if (SCRIPT_EXT.has(ext) || DATA_EXT.has(ext) || ext === '') {
    return lines.map(() => true);
  }
  if (ext === '.md' || ext === '.markdown' || ext === '.mdx' || ext === '.rst') {
    let inFence = false;
    return lines.map((l) => {
      if (/^\s{0,3}(```|~~~)/.test(l)) {
        inFence = !inFence;
        return false; // the fence delimiter itself is not code
      }
      return inFence;
    });
  }
  return lines.map(() => false); // .txt and unknown → treat as prose
}

/**
 * Scan every file in a target line-by-line for a pattern and return the
 * locations that match. The pattern should be non-global; we reset lastIndex
 * defensively so a stray `g` flag can't cause skipped lines.
 */
export function matchInTarget(
  target: { files: SkillFile[] },
  pattern: RegExp,
  opts: MatchOptions = {},
): Match[] {
  const matches: Match[] = [];
  for (const file of target.files) {
    const lines = file.content.split(/\r?\n/);
    const flags = opts.codeOnly ? codeLineFlags(file.path, lines) : null;
    for (let i = 0; i < lines.length; i++) {
      if (flags && !flags[i]) continue;
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
