import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import type { McpConfig, McpServerConfig } from './types.js';

const INLINE_INTERPRETERS = new Set([
  'bash', 'sh', 'zsh', 'dash', 'node', 'deno', 'bun', 'python', 'python3', 'ruby', 'perl', 'php',
]);

/**
 * Heuristic: would launching this server (which introspection requires) run an
 * inline payload rather than a normal executable? Used to refuse to introspect
 * obviously-dangerous servers unless explicitly forced.
 */
export function isLikelyUnsafeToLaunch(server: McpServerConfig): boolean {
  const base = (server.command ?? '').split(/[\\/]/).pop() ?? '';
  if (INLINE_INTERPRETERS.has(base) && server.args.some((a) => /^(-c|-e|--eval|-r)$/.test(a))) {
    return true;
  }
  return server.args.some((a) => /\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/.test(a));
}

/** Config filenames used by Claude Code, Claude Desktop, Cursor, VS Code, etc. */
const KNOWN_NAMES = ['mcp.json', '.mcp.json', 'claude_desktop_config.json', 'mcp_settings.json'];
const KNOWN_RELATIVE = [
  ...KNOWN_NAMES,
  join('.cursor', 'mcp.json'),
  join('.vscode', 'mcp.json'),
];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.venv', '__pycache__']);

/** Parse JSON, tolerating JSONC (comments + trailing commas) — VS Code configs use it. */
function looseParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    /* fall through to comment-stripping */
  }
  let out = '';
  let inStr = false;
  let strCh = '';
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (inLine) {
      if (c === '\n') {
        inLine = false;
        out += c;
      }
      continue;
    }
    if (inBlock) {
      if (c === '*' && n === '/') {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inStr) {
      out += c;
      if (c === '\\') out += text[++i] ?? '';
      else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
      out += c;
    } else if (c === '/' && n === '/') {
      inLine = true;
      i++;
    } else if (c === '/' && n === '*') {
      inBlock = true;
      i++;
    } else {
      out += c;
    }
  }
  try {
    return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
  } catch {
    return null;
  }
}

function parseJson(path: string): Record<string, unknown> | null {
  const value = looseParse(readFileSync(path, 'utf8'));
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
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
export function discoverMcpConfigs(target: string, maxDepth = 8): string[] {
  let st;
  try {
    st = statSync(target);
  } catch {
    return [];
  }
  if (st.isFile()) return looksLikeMcpConfig(target) ? [target] : [];

  const found: string[] = [];
  function walk(dir: string, depth: number): void {
    found.push(...configsInDir(dir));
    if (depth >= maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue;
      const sub = join(dir, entry);
      try {
        if (statSync(sub).isDirectory()) walk(sub, depth + 1);
      } catch {
        // unreadable — skip
      }
    }
  }
  walk(target, 0);
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
  const serverMap: Record<string, unknown> = {
    ...(json.mcpServers && typeof json.mcpServers === 'object' ? (json.mcpServers as Record<string, unknown>) : {}),
    ...(json.servers && typeof json.servers === 'object' ? (json.servers as Record<string, unknown>) : {}),
  };
  // Claude Code's ~/.claude.json nests per-project servers under `projects`.
  if (json.projects && typeof json.projects === 'object' && !Array.isArray(json.projects)) {
    for (const [projPath, projVal] of Object.entries(json.projects as Record<string, unknown>)) {
      const pv = projVal as Record<string, unknown>;
      if (pv && typeof pv.mcpServers === 'object' && pv.mcpServers) {
        for (const [name, def] of Object.entries(pv.mcpServers as Record<string, unknown>)) {
          serverMap[`${basename(projPath)}:${name}`] = def;
        }
      }
    }
  }
  const servers = Object.entries(serverMap).map(([name, def]) => normalizeServer(name, def));

  const root = dirname(configPath);
  return {
    kind: 'mcp',
    name: basename(configPath),
    root,
    configPath,
    servers,
    tools: [],
    files: [{ path: basename(configPath), content }],
  };
}
