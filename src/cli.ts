#!/usr/bin/env node
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { loadSkill, discoverSkills } from './loader.js';
import { loadMcpConfig, discoverMcpConfigs, isLikelyUnsafeToLaunch } from './mcp.js';
import { loadToolManifest, discoverToolManifests } from './tools.js';
import { introspectServer } from './introspect.js';
import { scanTarget, appendFindings } from './engine.js';
import { defaultRules } from './rules/index.js';
import { formatResult, SEVERITY_ORDER } from './report.js';
import { buildLock, readLock, writeLock, diffAgainstLock, DEFAULT_LOCK_PATH } from './pin.js';
import { knownLocations } from './locations.js';
import { loadIgnoreEntries, makeIgnoreMatcher, applyIgnore } from './ignore.js';
import type { Severity, ScanTarget, McpConfig, ScanResult } from './types.js';

type KindFilter = 'auto' | 'skill' | 'mcp' | 'tools';
type Command = 'scan' | 'pin' | 'audit';
type Entry = { kind: 'skill' | 'mcp' | 'tools'; path: string; label?: string };

interface Options {
  command: Command;
  path: string;
  json: boolean;
  ci: boolean;
  kind: KindFilter;
  minSeverity: Severity;
  color: boolean;
  introspect: boolean;
  introspectUnsafe: boolean;
  timeoutMs: number;
  lockPath: string;
}

const HELP = `skillguard — audit agent skills & MCP servers for safety and quality

Usage:
  skillguard <path>            Scan skills and/or MCP configs found at <path>
  skillguard audit             Scan every MCP config & skill installed on this machine
  skillguard mcp <path>        Scan only MCP server configs
  skillguard skill <path>      Scan only skills
  skillguard tools <path>      Scan MCP tool manifests for tool poisoning
  skillguard pin <path>        Pin current tool definitions to a lockfile
  skillguard ci <path>         Scan and exit non-zero if anything fails (for CI)

Options:
  --introspect                 Launch/contact MCP servers and analyse their live tools
  --introspect-unsafe          Also introspect servers that launch inline code
  --timeout <ms>               Introspection timeout (default: 10000)
  --lock <path>                Lockfile path (default: ${DEFAULT_LOCK_PATH})
  --json                       Output machine-readable JSON
  --min-severity <level>       Hide findings below this level (default: info)
  --no-color                   Disable ANSI colors
  -h, --help                   Show this help

Findings are suppressible via a .skillguardignore file
({"ignore":[{"rule":"SEC004","path":"**/install.sh"}]}); each finding prints a
fingerprint you can target directly.

Examples:
  skillguard audit
  skillguard mcp ./config --introspect
  skillguard ci ./skills --min-severity high`;

function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as string[]).includes(value);
}

function parseArgs(argv: string[]): Options {
  const args = [...argv];
  const opts: Options = {
    command: 'scan', path: '.', json: false, ci: false, kind: 'auto',
    minSeverity: 'info', color: Boolean(process.stdout.isTTY),
    introspect: false, introspectUnsafe: false, timeoutMs: 10_000, lockPath: DEFAULT_LOCK_PATH,
  };

  if (args[0] === 'audit') {
    opts.command = 'audit';
    args.shift();
  } else if (args[0] === 'pin') {
    opts.command = 'pin';
    args.shift();
  } else if (args[0] === 'ci') {
    opts.ci = true;
    args.shift();
  }
  if (args[0] === 'mcp' || args[0] === 'skill' || args[0] === 'tools') {
    opts.kind = args[0];
    args.shift();
  }

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') opts.json = true;
    else if (a === '--no-color') opts.color = false;
    else if (a === '--color') opts.color = true;
    else if (a === '--introspect') opts.introspect = true;
    else if (a === '--introspect-unsafe') { opts.introspect = true; opts.introspectUnsafe = true; }
    else if (a === '--timeout') opts.timeoutMs = Number(args[++i]) || opts.timeoutMs;
    else if (a === '--lock') opts.lockPath = args[++i] ?? opts.lockPath;
    else if (a === '--min-severity') {
      const level = args[++i];
      if (!level || !isSeverity(level)) {
        process.stderr.write(`Invalid --min-severity: ${level ?? '(missing)'}\n`);
        process.exit(2);
      }
      opts.minSeverity = level;
    } else if (a === '-h' || a === '--help') {
      process.stdout.write(HELP + '\n');
      process.exit(0);
    } else if (!a.startsWith('-')) opts.path = a;
    else {
      process.stderr.write(`Unknown option: ${a}\n`);
      process.exit(2);
    }
  }
  return opts;
}

function discover(target: string, kind: KindFilter): Entry[] {
  const out: Entry[] = [];
  if (kind === 'skill' || kind === 'auto') for (const p of discoverSkills(target)) out.push({ kind: 'skill', path: p });
  if (kind === 'mcp' || kind === 'auto') for (const p of discoverMcpConfigs(target)) out.push({ kind: 'mcp', path: p });
  if (kind === 'tools' || kind === 'auto') for (const p of discoverToolManifests(target)) out.push({ kind: 'tools', path: p });
  return out;
}

/** Every MCP config & skill installed on this machine, plus the current project. */
function auditEntries(): Entry[] {
  const out: Entry[] = [];
  const seen = new Set<string>();
  const add = (kind: Entry['kind'], path: string, label: string): void => {
    const key = resolve(path);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, path, label });
  };
  for (const loc of knownLocations()) {
    if (!existsSync(loc.path)) continue;
    if (loc.kind === 'mcp') add('mcp', loc.path, loc.client);
    else for (const d of discoverSkills(loc.path)) add('skill', d, loc.client);
  }
  return out;
}

async function introspectInto(config: McpConfig, opts: Options): Promise<void> {
  for (const server of config.servers) {
    if (!server.command && !server.url) continue;
    if (server.command && isLikelyUnsafeToLaunch(server) && !opts.introspectUnsafe) {
      process.stderr.write(
        `! skillguard: refusing to introspect "${server.name}" — it launches inline code. ` +
          `Re-run with --introspect-unsafe to override (this executes it).\n`,
      );
      continue;
    }
    try {
      config.tools.push(...(await introspectServer(server, { timeoutMs: opts.timeoutMs })));
    } catch (err) {
      process.stderr.write(`! skillguard: could not introspect "${server.name}": ${(err as Error).message}\n`);
    }
  }
}

async function load(entry: Entry, opts: Options): Promise<ScanTarget> {
  if (entry.kind === 'skill') return loadSkill(entry.path);
  if (entry.kind === 'tools') return loadToolManifest(entry.path);
  const config = loadMcpConfig(entry.path);
  if (opts.introspect) await introspectInto(config, opts);
  return config;
}

function runEntries(opts: Options, entries: Entry[]): Promise<void> {
  return (async () => {
    const rules = defaultRules();
    const lock = readLock(opts.lockPath);
    const ignore = makeIgnoreMatcher(loadIgnoreEntries([process.cwd()]));
    const maxIdx = SEVERITY_ORDER.indexOf(opts.minSeverity);

    let totalIgnored = 0;
    const scanned: Array<{ result: ScanResult; label?: string }> = [];
    for (const entry of entries) {
      let target: ScanTarget;
      try {
        target = await load(entry, opts);
      } catch (err) {
        // One unreadable/malformed target must never abort the whole run.
        process.stderr.write(`! skillguard: skipped ${entry.path}: ${(err as Error).message}\n`);
        continue;
      }
      let result = scanTarget(target, rules);
      if (lock) result = appendFindings(result, diffAgainstLock(target, lock));
      const applied = applyIgnore(result, ignore);
      totalIgnored += applied.ignored;
      result = {
        ...applied.result,
        findings: applied.result.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= maxIdx),
      };
      scanned.push({ result, label: entry.label });
    }

    if (opts.json) {
      process.stdout.write(JSON.stringify(scanned.map((s) => ({ source: s.label, ...s.result })), null, 2) + '\n');
    } else {
      for (const { result, label } of scanned) {
        if (label) process.stdout.write(`\n${opts.color ? '\x1b[2m' : ''}── ${label} ──${opts.color ? '\x1b[0m' : ''}`);
        process.stdout.write(formatResult(result, opts.color));
      }
      const fails = scanned.filter((s) => s.result.verdict === 'fail').length;
      const warns = scanned.filter((s) => s.result.verdict === 'warn').length;
      if (opts.command === 'audit' || scanned.length > 1) {
        process.stdout.write(
          `\nScanned ${scanned.length} target(s): ${fails} fail, ${warns} warn` +
            (totalIgnored ? `, ${totalIgnored} finding(s) ignored` : '') + '.\n',
        );
      }
    }

    if (scanned.some((s) => s.result.verdict === 'fail')) process.exit(1);
  })();
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.introspect && !opts.json) {
    process.stderr.write('⚠ introspection launches (stdio) or contacts (http) MCP servers — only run it on servers you trust.\n');
  }

  if (opts.command === 'audit') {
    const entries = auditEntries();
    if (entries.length === 0) {
      process.stdout.write('skillguard audit: no installed MCP configs or skills found on this machine.\n');
      return;
    }
    if (!opts.json) {
      process.stderr.write(`skillguard audit — scanning ${entries.length} installed target(s)…\n`);
    }
    return runEntries(opts, entries);
  }

  if (opts.command === 'pin') {
    const found = discover(resolve(opts.path), opts.kind);
    const targets: ScanTarget[] = [];
    for (const e of found) targets.push(await load(e, opts));
    const withTools = targets.filter((t) => t.kind === 'tools' || t.kind === 'mcp');
    const lock = buildLock(withTools);
    const count = Object.keys(lock.tools).length;
    if (count === 0) {
      process.stderr.write('Nothing to pin: no tool definitions found. Provide a tool manifest, or use --introspect.\n');
      process.exit(2);
    }
    writeLock(opts.lockPath, lock);
    process.stdout.write(`Pinned ${count} tool definition(s) to ${opts.lockPath}\n`);
    return;
  }

  const target = resolve(opts.path);
  const entries = discover(target, opts.kind);
  if (entries.length === 0) {
    process.stderr.write(`No targets found at ${target}.\n`);
    process.exit(2);
  }
  return runEntries(opts, entries);
}

main().catch((err) => {
  process.stderr.write(`Error: ${(err as Error).message}\n`);
  process.exit(2);
});
