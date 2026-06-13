#!/usr/bin/env node
import { resolve } from 'node:path';
import { loadSkill, discoverSkills } from './loader.js';
import { scanSkill } from './engine.js';
import { defaultRules } from './rules/index.js';
import { formatResult, SEVERITY_ORDER } from './report.js';
import type { Severity, ScanResult } from './types.js';

interface Options {
  path: string;
  json: boolean;
  ci: boolean;
  minSeverity: Severity;
  color: boolean;
}

const HELP = `skillguard — audit agent skills & MCP servers for safety and quality

Usage:
  skillguard <path>            Scan a skill directory (or a directory of skills)
  skillguard ci <path>         Scan and exit non-zero if anything fails (for CI)

Options:
  --json                       Output machine-readable JSON
  --min-severity <level>       Hide findings below this level
                               (critical|high|medium|low|info, default: info)
  --no-color                   Disable ANSI colors
  -h, --help                   Show this help

Examples:
  skillguard ./my-skill
  skillguard examples/malicious-skill
  skillguard ci ./skills --min-severity high
`;

function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as string[]).includes(value);
}

function parseArgs(argv: string[]): Options {
  const args = [...argv];
  let ci = false;
  if (args[0] === 'ci') {
    ci = true;
    args.shift();
  }

  const opts: Options = {
    path: '.',
    json: false,
    ci,
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

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const target = resolve(opts.path);

  let skillDirs: string[];
  try {
    skillDirs = discoverSkills(target);
  } catch (err) {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exit(2);
  }

  if (skillDirs.length === 0) {
    process.stderr.write(`No skills found at ${target} (looked for SKILL.md).\n`);
    process.exit(2);
  }

  const rules = defaultRules();
  const results = skillDirs.map((dir) =>
    filterBySeverity(scanSkill(loadSkill(dir), rules), opts.minSeverity),
  );

  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) process.stdout.write(formatResult(r, opts.color));
  }

  // Non-zero exit on any failure is useful everywhere, not just in CI mode.
  if (results.some((r) => r.verdict === 'fail')) process.exit(1);
}

main();
