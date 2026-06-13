import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { LoadedSkill, SkillFile } from './types.js';

const MANIFEST_NAMES = ['SKILL.md', 'skill.md', 'Skill.md'];

const TEXT_EXT = new Set([
  '.md', '.markdown', '.sh', '.bash', '.zsh', '.js', '.mjs', '.cjs',
  '.ts', '.py', '.rb', '.json', '.yaml', '.yml', '.txt', '.toml', '.env', '.ps1',
]);

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.venv', '__pycache__']);
const MAX_FILE_BYTES = 512 * 1024;

export function findManifest(dir: string): string | null {
  for (const name of MANIFEST_NAMES) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Resolve which skills to scan from a target path:
 * - if the path itself contains a manifest, it's a single skill;
 * - otherwise, treat it as a directory of skills (one per immediate subdir).
 */
export function discoverSkills(target: string): string[] {
  if (findManifest(target)) return [target];
  const dirs: string[] = [];
  for (const entry of readdirSync(target)) {
    const full = join(target, entry);
    try {
      if (statSync(full).isDirectory() && findManifest(full)) dirs.push(full);
    } catch {
      // unreadable entry — skip
    }
  }
  return dirs.sort();
}

function walk(dir: string, root: string, out: SkillFile[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, root, out);
    } else if (st.isFile()) {
      if (st.size > MAX_FILE_BYTES) continue;
      const ext = extname(entry).toLowerCase();
      if (!TEXT_EXT.has(ext) && !MANIFEST_NAMES.includes(entry)) continue;
      try {
        out.push({ path: relative(root, full), content: readFileSync(full, 'utf8') });
      } catch {
        // binary or unreadable — skip
      }
    }
  }
}

function splitFrontmatter(raw: string): { frontmatter: Record<string, unknown>; body: string } {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!m) return { frontmatter: {}, body: raw };
  let frontmatter: Record<string, unknown> = {};
  try {
    frontmatter = (parseYaml(m[1]) as Record<string, unknown>) ?? {};
  } catch {
    frontmatter = {};
  }
  return { frontmatter, body: m[2] ?? '' };
}

export function loadSkill(dir: string): LoadedSkill {
  const manifestPath = findManifest(dir);
  if (!manifestPath) {
    throw new Error(`No SKILL.md found in ${dir}`);
  }
  const { frontmatter, body } = splitFrontmatter(readFileSync(manifestPath, 'utf8'));
  const files: SkillFile[] = [];
  walk(dir, dir, files);
  const name =
    (typeof frontmatter.name === 'string' && frontmatter.name.trim()) || basename(dir);
  const description = typeof frontmatter.description === 'string' ? frontmatter.description : '';
  return { name, root: dir, manifestPath, frontmatter, description, body, files };
}
