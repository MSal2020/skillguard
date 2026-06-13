#!/usr/bin/env node
import { resolve } from 'node:path';
import { loadSkill, discoverSkills } from './loader.js';
import { loadMcpConfig, discoverMcpConfigs } from './mcp.js';
import { scanTarget } from './engine.js';
import { defaultRules } from './rules/index.js';
import { formatResult, SEVERITY_ORDER } from './report.js';
import type { Severity, ScanResult } from './types.js';

type KindFilter = 'auto' | 'skill' | 'mcp';

interface Options {
  path: string;
  json: boolean;
  ci: boolean;
  kind: KindFilter;
  minSeverity: Severity;
  color: boolean;
}

const HELP = `skillguard — audit agent skills & MCP servers for safety and quality

Usage:
  skillguard <path>            Scan skills and/or MCP configs found at <path>
  skillguard mcp <path>        Scan only MCP server configs
  skillguard skill <path>      Scan only skills
  skillguard ci <path>         Scan and exit non-zero if anything fails (for CI)

Options:
  --json                       Output machine-readable JSON
  --min-severity <level>       Hide findings below this level
                               (critical|high|medium|low|info, default: info)
  --no-color                   Disable ANSI colors
  -h, --help                   Show this help

Examples:
  skillguard examples/malicious-skill
  skillguard mcp examples/malicious-mcp
  skillguard ci ./skills --min-severity high
`;

function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as string[]).includes(value);
}

function parseArgs(argv: string[]): Options {
  const args = [...argv];
  let ci = false;
  let kind: KindFilter = 'auto';

  if (args[0] === 'ci') {
    ci = true;
    args.shift();
  }
  if (args[0] === 'mcp' || args[0] === 'skill') {
    kind = args[0];
    args.shift();
  }

  const opts: Options = {
    path: '.',
    json: false,
    ci,
    kind,
    minSeverity: 'info',
    color: Boolean(process.stdout.isTTY),
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') opts.json = true;
    else if (a === '--no-color') opts.color = false;
    else if (a === '--color') opts.color = true;
    else if (a === '--min-severity') {
      const level = args[++i];
      if (!level || !isSeverity(level)) {
        process.stderr.write(`Invalid --min-severity: ${level ?? '(missing)'}\n`);
        process.exit(2);
      }
      opts.minSeverity = level;
    } else if (a === '-h' || a === '--help') {
      process.stdout.write(HELP);
      process.exit(0);
    } else if (!a.startsWith('-')) {
      opts.path = a;
    } else {
      process.stderr.write(`Unknown option: ${a}\n`);
      process.exit(2);
    }
  }
  return opts;
}

function filterBySeverity(result: ScanResult, min: Severity): ScanResult {
  const maxIdx = SEVERITY_ORDER.indexOf(min);
  return {
    ...result,
    findings: result.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= maxIdx),
  };
}

function discover(target: string, kind: KindFilter): Array<{ kind: 'skill' | 'mcp'; path: string }> {
  const out: Array<{ kind: 'skill' | 'mcp'; path: string }> = [];
  if (kind !== 'mcp') {
    for (const dir of discoverSkills(target)) out.push({ kind: 'skill', path: dir });
  }
  if (kind !== 'skill') {
    for (const cfg of discoverMcpConfigs(target)) out.push({ kind: 'mcp', path: cfg });
  }
  return out;
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const target = resolve(opts.path);

  const found = discover(target, opts.kind);
  if (found.length === 0) {
    process.stderr.write(
      `No ${opts.kind === 'auto' ? 'skills or MCP configs' : opts.kind + 's'} found at ${target}.\n` +
        `(looked for SKILL.md and mcp.json / .mcp.json / claude_desktop_config.json)\n`,
    );
    process.exit(2);
  }

  const rules = defaultRules();
  const results = found.map(({ kind, path }) => {
    const loaded = kind === 'skill' ? loadSkill(path) : loadMcpConfig(path);
    return filterBySeverity(scanTarget(loaded, rules), opts.minSeverity);
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) process.stdout.write(formatResult(r, opts.color));
  }

  // Non-zero exit on any failure is useful everywhere, not just in CI mode.
  if (results.some((r) => r.verdict === 'fail')) process.exit(1);
}

main();
