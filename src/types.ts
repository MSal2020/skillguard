export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'quality' | 'poisoning' | 'integrity';
export type Verdict = 'pass' | 'warn' | 'fail';
export type TargetKind = 'skill' | 'mcp' | 'tools';

export interface SkillFile {
  /** Path relative to the target root. */
  path: string;
  content: string;
}

export interface LoadedSkill {
  kind: 'skill';
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

export interface McpServerConfig {
  name: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  type?: string;
  headers: Record<string, string>;
  /** The raw server definition as written in the config. */
  raw: Record<string, unknown>;
}

export interface McpToolParam {
  name: string;
  description: string;
  required: boolean;
}

export interface McpTool {
  name: string;
  description: string;
  parameters: McpToolParam[];
  /** Server this tool belongs to, when known (e.g. from introspection). */
  serverName?: string;
  /** The raw tool definition as published by the server. */
  raw: Record<string, unknown>;
}

export interface McpConfig {
  kind: 'mcp';
  name: string;
  /** Absolute path to the directory containing the config. */
  root: string;
  /** Absolute path to the config file (mcp.json, .mcp.json, …). */
  configPath: string;
  servers: McpServerConfig[];
  /** Tool definitions, populated by introspection or a sibling manifest. */
  tools: McpTool[];
  /** The config file as a single scannable file, so text rules apply too. */
  files: SkillFile[];
}

/** A set of MCP tool definitions (a manifest file or introspected server). */
export interface ToolSet {
  kind: 'tools';
  name: string;
  root: string;
  /** Where the tools came from: a manifest path, or e.g. "introspect:<server>". */
  source: string;
  tools: McpTool[];
  files: SkillFile[];
}

/** Anything skillguard can scan. The text rules only need `.files`. */
export type ScanTarget = LoadedSkill | McpConfig | ToolSet;

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
  check(target: ScanTarget): Finding[];
}

export interface ScanResult {
  kind: TargetKind;
  name: string;
  root: string;
  findings: Finding[];
  /** 0–100, higher means riskier. */
  score: number;
  verdict: Verdict;
}
