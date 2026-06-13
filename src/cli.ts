#!/usr/bin/env node
import { resolve } from 'node:path';
import { loadSkill, discoverSkills } from './loader.js';
import { loadMcpConfig, discoverMcpConfigs, isLikelyUnsafeToLaunch } from './mcp.js';
import { loadToolManifest, discoverToolManifests } from './tools.js';
import { introspectServer } from './introspect.js';
import { scanTarget, appendFindings } from './engine.js';
import { defaultRules } from './rules/index.js';
import { formatResult, SEVERITY_ORDER } from './report.js';
import { buildLock, readLock, writeLock, diffAgainstLock, DEFAULT_LOCK_PATH } from './pin.js';
import type { Severity, ScanTarget, McpConfig } from './types.js';

type KindFilter = 'auto' | 'skill' | 'mcp' | 'tools';
type Command = 'scan' | 'pin';

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
  skillguard mcp <path>        Scan only MCP server configs
  skillguard skill <path>      Scan only skills
  skillguard tools <path>      Scan MCP tool manifests for tool poisoning
  skillguard pin <path>        Pin current tool definitions to a lockfile
  skillguard ci <path>         Scan and exit non-zero if anything fails (for CI)

Options:
  --introspect                 Launch stdio MCP servers and analyse their live
                               tools (executes the server — opt-in)
  --introspect-unsafe          Also introspect servers that launch inline code
  --timeout <ms>               Introspection timeout (default: 10000)
  --lock <path>                Lockfile path (default: ${DEFAULT_LOCK_PATH})
  --json                       Output machine-readable JSON
  --min-severity <level>       Hide findings below this level (default: info)
  --no-color                   Disable ANSI colors
  -h, --help                   Show this help

Examples:
  skillguard examples/poisoned-tools
  skillguard mcp ./config --introspect
  skillguard pin ./config --introspect && skillguard mcp ./config --introspect
`;

function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as string[]).includes(value);
}

function parseArgs(argv: string[]): Options {
  const args = [...argv];
  const opts: Options = {
    command: 'scan',
    path: '.',
    json: false,
    ci: false,
    kind: 'auto',
    minSeverity: 'info',
    color: Boolean(process.stdout.isTTY),
    introspect: false,
    introspectUnsafe: false,
    timeoutMs: 10_000,
    lockPath: DEFAULT_LOCK_PATH,
  };

  if (args[0] === 'pin') {
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
    else if (a === '--introspect-unsafe') {
      opts.introspect = true;
      opts.introspectUnsafe = true;
    } else if (a === '--timeout') {
      opts.timeoutMs = Number(args[++i]) || opts.timeoutMs;
    } else if (a === '--lock') {
      opts.lockPath = args[++i] ?? opts.lockPath;
    } else if (a === '--min-severity') {
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

function discover(target: string, kind: KindFilter): Array<{ kind: 'skill' | 'mcp' | 'tools'; path: string }> {
  const out: Array<{ kind: 'skill' | 'mcp' | 'tools'; path: string }> = [];
  if (kind === 'skill' || kind === 'auto') {
    for (const dir of discoverSkills(target)) out.push({ kind: 'skill', path: dir });
  }
  if (kind === 'mcp' || kind === 'auto') {
    for (const cfg of discoverMcpConfigs(target)) out.push({ kind: 'mcp', path: cfg });
  }
  if (kind === 'tools' || kind === 'auto') {
    for (const man of discoverToolManifests(target)) out.push({ kind: 'tools', path: man });
  }
  return out;
}

async function introspectInto(config: McpConfig, opts: Options): Promise<void> {
  for (const server of config.servers) {
    if (!server.command) continue; // remote/HTTP not yet supported
    if (isLikelyUnsafeToLaunch(server) && !opts.introspectUnsafe) {
      process.stderr.write(
        `! skillguard: refusing to introspect "${server.name}" — it launches inline code. ` +
          `Re-run with --introspect-unsafe to override (this executes it).\n`,
      );
      continue;
    }
    try {
      const tools = await introspectServer(server, { timeoutMs: opts.timeoutMs });
      config.tools.push(...tools);
    } catch (err) {
      process.stderr.write(`! skillguard: could not introspect "${server.name}": ${(err as Error).message}\n`);
    }
  }
}

async function load(entry: { kind: 'skill' | 'mcp' | 'tools'; path: string }, opts: Options): Promise<ScanTarget> {
  if (entry.kind === 'skill') return loadSkill(entry.path);
  if (entry.kind === 'tools') return loadToolManifest(entry.path);
  const config = loadMcpConfig(entry.path);
  if (opts.introspect) await introspectInto(config, opts);
  return config;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const target = resolve(opts.path);

  if (opts.introspect && !opts.json) {
    process.stderr.write('⚠ introspection launches MCP servers — only run it on servers you trust.\n');
  }

  const found = discover(target, opts.kind);
  if (found.length === 0) {
    process.stderr.write(`No targets found at ${target}.\n`);
    process.exit(2);
  }

  const targets: ScanTarget[] = [];
  for (const entry of found) targets.push(await load(entry, opts));

  if (opts.command === 'pin') {
    const withTools = targets.filter((t) => (t.kind === 'tools' || t.kind === 'mcp'));
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

  const rules = defaultRules();
  const lock = readLock(opts.lockPath);
  const maxIdx = SEVERITY_ORDER.indexOf(opts.minSeverity);

  const results = targets.map((t) => {
    let result = scanTarget(t, rules);
    if (lock) result = appendFindings(result, diffAgainstLock(t, lock));
    return {
      ...result,
      findings: result.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= maxIdx),
    };
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) process.stdout.write(formatResult(r, opts.color));
  }

  if (results.some((r) => r.verdict === 'fail')) process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`Error: ${(err as Error).message}\n`);
  process.exit(2);
});
