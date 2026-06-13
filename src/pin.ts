import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import type { McpTool, ScanTarget, Finding } from './types.js';
import { getTools } from './tools.js';

export interface Lockfile {
  version: 1;
  /** "<server>/<tool>" (or "<tool>") → schema fingerprint. */
  tools: Record<string, string>;
}

export const DEFAULT_LOCK_PATH = 'skillguard.lock.json';

/**
 * Fingerprint the security-relevant surface of a tool: its name, description,
 * and parameters (descriptions + required-ness). A silent change to any of
 * these — the rug-pull attack — flips the hash.
 */
export function fingerprintTool(tool: McpTool): string {
  const normalized = {
    name: tool.name,
    description: tool.description,
    parameters: [...tool.parameters]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((p) => ({ name: p.name, description: p.description, required: p.required })),
  };
  return createHash('sha256').update(JSON.stringify(normalized)).digest('hex').slice(0, 16);
}

function keyFor(tool: McpTool): string {
  return tool.serverName ? `${tool.serverName}/${tool.name}` : tool.name;
}

export function buildLock(targets: ScanTarget[]): Lockfile {
  const tools: Record<string, string> = {};
  for (const target of targets) {
    for (const tool of getTools(target)) tools[keyFor(tool)] = fingerprintTool(tool);
  }
  return { version: 1, tools };
}

export function readLock(path: string): Lockfile | null {
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Lockfile;
    if (parsed && parsed.version === 1 && parsed.tools) return parsed;
  } catch {
    /* fall through */
  }
  return null;
}

export function writeLock(path: string, lock: Lockfile): void {
  writeFileSync(path, JSON.stringify(lock, null, 2) + '\n');
}

/**
 * Compare a target's current tools against a previously pinned lock and report
 * drift. A changed fingerprint is the rug-pull signature: the tool you approved
 * is not the tool you're now running.
 */
export function diffAgainstLock(target: ScanTarget, lock: Lockfile): Finding[] {
  const findings: Finding[] = [];
  const current = new Map(getTools(target).map((t) => [keyFor(t), fingerprintTool(t)]));

  for (const [key, fp] of current) {
    const prev = lock.tools[key];
    if (prev === undefined) {
      findings.push({
        ruleId: 'PIN002',
        title: 'New tool since pinning',
        category: 'integrity',
        severity: 'info',
        message: `Tool "${key}" was not present when this set was pinned. Review it, then re-pin.`,
        remediation: 'Run `skillguard pin` again once you have reviewed the new tool.',
      });
    } else if (prev !== fp) {
      findings.push({
        ruleId: 'PIN001',
        title: 'Tool definition changed since pinning',
        category: 'integrity',
        severity: 'high',
        message: `Tool "${key}" no longer matches its pinned definition (possible rug-pull). It was approved with a different description/parameters than it now advertises.`,
        remediation: 'Re-review the tool. If the change is legitimate, re-pin with `skillguard pin`; otherwise stop using this server.',
      });
    }
  }

  for (const key of Object.keys(lock.tools)) {
    if (!current.has(key)) {
      findings.push({
        ruleId: 'PIN003',
        title: 'Pinned tool no longer present',
        category: 'integrity',
        severity: 'info',
        message: `Tool "${key}" was pinned but is no longer advertised by the server.`,
        remediation: 'If intentional, re-pin to clear this notice.',
      });
    }
  }

  return findings;
}
