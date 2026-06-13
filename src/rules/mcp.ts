import { basename } from 'node:path';
import type { ScanTarget, McpConfig, McpServerConfig, Finding, Rule, Severity } from '../types.js';
import { findLine } from '../util.js';

function mcpRule(
  id: string,
  title: string,
  severity: Severity,
  fn: (config: McpConfig) => Finding[],
): Rule {
  return {
    id,
    title,
    category: 'security',
    severity,
    check(target: ScanTarget): Finding[] {
      if (target.kind !== 'mcp') return [];
      return fn(target);
    },
  };
}

function configFile(config: McpConfig): string {
  return basename(config.configPath);
}

// --- MCP001: hardcoded secrets in env / headers ------------------------------

const SECRET_PREFIX = /^(sk-|rk_|ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-|AKIA|ASIA|AIza|glpat-|hf_|Bearer\s+\S)/;
const SECRETISH_KEY = /(token|secret|key|password|passwd|api[_-]?key|auth|credential)/i;
const PLACEHOLDER = /(\$\{|\$[A-Za-z]|<[^>]+>|your[_-]?|change[_-]?me|example|x{4,}|placeholder|\.\.\.|^$)/i;

function redact(value: string): string {
  return value.length <= 6 ? '***' : `${value.slice(0, 4)}…(redacted)`;
}

const mcp001 = mcpRule('MCP001', 'Hardcoded secret in MCP config', 'critical', (config) => {
  const findings: Finding[] = [];
  for (const server of config.servers) {
    const pairs: Array<['env' | 'header', string, string]> = [
      ...Object.entries(server.env).map(([k, v]) => ['env', k, v] as ['env', string, string]),
      ...Object.entries(server.headers).map(([k, v]) => ['header', k, v] as ['header', string, string]),
    ];
    for (const [where, key, value] of pairs) {
      if (!value || PLACEHOLDER.test(value)) continue;
      const looksSecret =
        SECRET_PREFIX.test(value) || (SECRETISH_KEY.test(key) && value.length >= 20 && !/\s/.test(value));
      if (!looksSecret) continue;
      findings.push({
        ruleId: 'MCP001',
        title: 'Hardcoded secret in MCP config',
        category: 'security',
        severity: 'critical',
        message: `Server "${server.name}" has a live-looking credential hardcoded in its ${where} (${key}).`,
        remediation: 'Reference a secret via ${ENV_VAR} interpolation or a secrets manager — never commit credentials.',
        file: configFile(config),
        line: findLine(config, key),
        snippet: `${key} = ${redact(value)}`,
      });
    }
  }
  return findings;
});

// --- MCP002: unpinned package runner (supply-chain) --------------------------

const RUNNERS = new Set(['npx', 'npm', 'pnpm', 'bunx', 'uvx', 'pipx', 'yarn', 'dlx']);

function baseCommand(command?: string): string {
  if (!command) return '';
  return command.split(/[\\/]/).pop() ?? command;
}

const mcp002 = mcpRule('MCP002', 'Unpinned package execution', 'medium', (config) => {
  const findings: Finding[] = [];
  for (const server of config.servers) {
    const base = baseCommand(server.command);
    if (!RUNNERS.has(base)) continue;
    const joined = server.args.join(' ');
    const autoYes = /(^|\s)(-y|--yes)(\s|$)/.test(joined);
    const latest = /@latest\b/.test(joined);
    const pkg = server.args.find((a) => !a.startsWith('-') && a !== 'dlx' && a !== 'exec');
    const pinned = pkg ? /@\d/.test(pkg) : true;
    if (!autoYes && !latest && pinned) continue;
    findings.push({
      ruleId: 'MCP002',
      title: 'Unpinned package execution',
      category: 'security',
      severity: 'medium',
      message: `Server "${server.name}" launches a package via ${base} without a pinned version${autoYes ? ' and auto-confirms install (-y)' : ''}. A rug-pull or typosquat would run with your privileges.`,
      remediation: 'Pin an exact version (e.g. pkg@1.2.3) and drop -y so installs are explicit.',
      file: configFile(config),
      line: findLine(config, pkg ?? base),
      snippet: `${server.command} ${joined}`.trim().slice(0, 160),
    });
  }
  return findings;
});

// --- MCP003: inline interpreter / shell execution from config ----------------

const INTERPRETERS = new Set(['bash', 'sh', 'zsh', 'dash', 'node', 'deno', 'bun', 'python', 'python3', 'ruby', 'perl', 'php']);
const INLINE_FLAG = /^(-c|-e|--eval|-r)$/;

const mcp003 = mcpRule('MCP003', 'Inline shell/interpreter command in config', 'high', (config) => {
  const findings: Finding[] = [];
  for (const server of config.servers) {
    const base = baseCommand(server.command);
    if (!INTERPRETERS.has(base)) continue;
    if (!server.args.some((a) => INLINE_FLAG.test(a))) continue;
    findings.push({
      ruleId: 'MCP003',
      title: 'Inline shell/interpreter command in config',
      category: 'security',
      severity: 'high',
      message: `Server "${server.name}" runs an inline ${base} script from the config instead of a vetted, reviewable executable.`,
      remediation: 'Move the logic into a checked-in, reviewable script or a published package; do not inline code in config.',
      file: configFile(config),
      line: findLine(config, server.command ?? base),
      snippet: `${server.command} ${server.args.join(' ')}`.trim().slice(0, 160),
    });
  }
  return findings;
});

// --- MCP004: insecure remote endpoint ----------------------------------------

const RAW_IP = /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}\b/;

function isLocalhost(url: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(url);
}

const mcp004 = mcpRule('MCP004', 'Insecure remote MCP endpoint', 'high', (config) => {
  const findings: Finding[] = [];
  for (const server of config.servers) {
    if (!server.url) continue;
    const url = server.url;
    if (url.startsWith('http://') && !isLocalhost(url)) {
      findings.push({
        ruleId: 'MCP004',
        title: 'Insecure remote MCP endpoint',
        category: 'security',
        severity: 'high',
        message: `Server "${server.name}" connects over plaintext http:// — traffic (and any auth headers) can be intercepted.`,
        remediation: 'Use https:// for remote MCP servers.',
        file: configFile(config),
        line: findLine(config, url),
        snippet: url.slice(0, 160),
      });
    } else if (RAW_IP.test(url) && !isLocalhost(url)) {
      findings.push({
        ruleId: 'MCP004',
        title: 'Insecure remote MCP endpoint',
        category: 'security',
        severity: 'medium',
        message: `Server "${server.name}" connects to a raw IP address rather than a named, auditable host.`,
        remediation: 'Use a named host you can verify and that supports TLS.',
        file: configFile(config),
        line: findLine(config, url),
        snippet: url.slice(0, 160),
      });
    }
  }
  return findings;
});

export const mcpRules: Rule[] = [mcp001, mcp002, mcp003, mcp004];
