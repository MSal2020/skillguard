import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import type { McpConfig, McpServerConfig } from './types.js';

/** Config filenames used by Claude Code, Claude Desktop, Cursor, VS Code, etc. */
const KNOWN_NAMES = ['mcp.json', '.mcp.json', 'claude_desktop_config.json', 'mcp_settings.json'];
const KNOWN_RELATIVE = [
  ...KNOWN_NAMES,
  join('.cursor', 'mcp.json'),
  join('.vscode', 'mcp.json'),
];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.venv', '__pycache__']);

function parseJson(path: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** True if a file is (or very likely is) an MCP config. */
export function looksLikeMcpConfig(path: string): boolean {
  if (KNOWN_NAMES.includes(basename(path))) return true;
  if (extname(path) !== '.json') return false;
  const json = parseJson(path);
  return Boolean(json && (json.mcpServers || json.servers));
}

function configsInDir(dir: string): string[] {
  const found: string[] = [];
  for (const rel of KNOWN_RELATIVE) {
    const p = join(dir, rel);
    if (existsSync(p) && looksLikeMcpConfig(p)) found.push(p);
  }
  return found;
}

/**
 * Resolve MCP config files from a target path:
 * - a config file → itself;
 * - a directory → known configs in it, plus known configs one level down.
 */
export function discoverMcpConfigs(target: string): string[] {
  let st;
  try {
    st = statSync(target);
  } catch {
    return [];
  }
  if (st.isFile()) return looksLikeMcpConfig(target) ? [target] : [];

  const found = [...configsInDir(target)];
  for (const entry of readdirSync(target)) {
    if (SKIP_DIRS.has(entry)) continue;
    const sub = join(target, entry);
    try {
      if (statSync(sub).isDirectory()) found.push(...configsInDir(sub));
    } catch {
      // unreadable — skip
    }
  }
  return [...new Set(found)].sort();
}

function asStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = typeof v === 'string' ? v : JSON.stringify(v);
  }
  return out;
}

function normalizeServer(name: string, def: unknown): McpServerConfig {
  const raw = (def && typeof def === 'object' ? def : {}) as Record<string, unknown>;
  return {
    name,
    command: typeof raw.command === 'string' ? raw.command : undefined,
    args: Array.isArray(raw.args) ? raw.args.map((a) => String(a)) : [],
    env: asStringRecord(raw.env),
    url: typeof raw.url === 'string' ? raw.url : undefined,
    type: typeof raw.type === 'string' ? raw.type : undefined,
    headers: asStringRecord(raw.headers),
    raw,
  };
}

export function loadMcpConfig(configPath: string): McpConfig {
  const content = readFileSync(configPath, 'utf8');
  const json = parseJson(configPath);
  if (!json) {
    throw new Error(`Could not parse MCP config: ${configPath}`);
  }

  // Claude/Cursor use `mcpServers`; VS Code uses `servers`.
  const serverMap = {
    ...(json.mcpServers && typeof json.mcpServers === 'object' ? (json.mcpServers as Record<string, unknown>) : {}),
    ...(json.servers && typeof json.servers === 'object' ? (json.servers as Record<string, unknown>) : {}),
  };
  const servers = Object.entries(serverMap).map(([name, def]) => normalizeServer(name, def));

  const root = dirname(configPath);
  return {
    kind: 'mcp',
    name: basename(configPath),
    root,
    configPath,
    servers,
    files: [{ path: basename(configPath), content }],
  };
}
