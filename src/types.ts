export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'quality';
export type Verdict = 'pass' | 'warn' | 'fail';

export interface SkillFile {
  /** Path relative to the skill root. */
  path: string;
  content: string;
}

export interface LoadedSkill {
  name: string;
  /** Absolute path to the skill directory. */
  root: string;
  /** Absolute path to the manifest (SKILL.md). */
  manifestPath: string;
  frontmatter: Record<string, unknown>;
  description: string;
  /** Manifest body with frontmatter stripped. */
  body: string;
  /** Every scannable text file in the skill, including the manifest. */
  files: SkillFile[];
}

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  snippet?: string;
  remediation?: string;
}

export interface Rule {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  check(skill: LoadedSkill): Finding[];
}

export interface ScanResult {
  skill: string;
  root: string;
  findings: Finding[];
  /** 0–100, higher means riskier. */
  score: number;
  verdict: Verdict;
}
