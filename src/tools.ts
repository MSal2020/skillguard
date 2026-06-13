import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { dirname, basename, extname, join } from 'node:path';
import type { McpTool, McpToolParam, ToolSet, ScanTarget } from './types.js';

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function extractParams(schema: Record<string, unknown>): McpToolParam[] {
  const properties = asRecord(schema.properties);
  const required = Array.isArray(schema.required) ? schema.required.map(String) : [];
  return Object.entries(properties).map(([name, def]) => {
    const d = asRecord(def);
    return {
      name,
      description: typeof d.description === 'string' ? d.description : '',
      required: required.includes(name),
    };
  });
}

function normalizeOneTool(raw: unknown): McpTool | null {
  const t = asRecord(raw);
  if (typeof t.name !== 'string') return null;
  // Tolerate the various ways a tool's input schema is spelled.
  const schema = asRecord(t.inputSchema ?? t.input_schema ?? t.parameters ?? t.schema);
  return {
    name: t.name,
    description: typeof t.description === 'string' ? t.description : '',
    parameters: extractParams(schema),
    serverName: typeof t.serverName === 'string' ? t.serverName : undefined,
    raw: t,
  };
}

/**
 * Accept any of the shapes tool definitions arrive in:
 * a bare array, `{ tools: [...] }` (MCP ListToolsResult / our manifest),
 * or a raw JSON-RPC response `{ result: { tools: [...] } }`.
 */
export function normalizeTools(json: unknown): McpTool[] {
  let list: unknown[] = [];
  if (Array.isArray(json)) list = json;
  else {
    const obj = asRecord(json);
    const result = asRecord(obj.result);
    const candidate = obj.tools ?? result.tools;
    if (Array.isArray(candidate)) list = candidate;
  }
  return list.map(normalizeOneTool).filter((t): t is McpTool => t !== null);
}

export function loadToolManifest(path: string): ToolSet {
  const content = readFileSync(path, 'utf8');
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    throw new Error(`Could not parse tool manifest: ${path}`);
  }
  return {
    kind: 'tools',
    name: basename(path),
    root: dirname(path),
    source: path,
    tools: normalizeTools(json),
    files: [{ path: basename(path), content }],
  };
}

/** The tool definitions associated with any target (empty for skills). */
export function getTools(target: ScanTarget): McpTool[] {
  if (target.kind === 'tools') return target.tools;
  if (target.kind === 'mcp') return target.tools;
  return [];
}

/** True if a .json file looks like a tool manifest (a `tools` array, or an array of tools). */
export function looksLikeToolManifest(path: string): boolean {
  if (extname(path).toLowerCase() !== '.json') return false;
  try {
    const json = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (Array.isArray(json)) {
      return json.length > 0 && json.every((x) => x && typeof x === 'object' && typeof (x as Record<string, unknown>).name === 'string');
    }
    return Boolean(json && typeof json === 'object' && Array.isArray((json as Record<string, unknown>).tools));
  } catch {
    return false;
  }
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.venv', '__pycache__']);

/** Resolve tool manifests from a path: the file itself, or `tools.json` in a dir / its subdirs. */
export function discoverToolManifests(target: string): string[] {
  let st;
  try {
    st = statSync(target);
  } catch {
    return [];
  }
  if (st.isFile()) return looksLikeToolManifest(target) ? [target] : [];

  const found: string[] = [];
  const direct = join(target, 'tools.json');
  if (existsSync(direct) && looksLikeToolManifest(direct)) found.push(direct);
  for (const entry of readdirSync(target)) {
    if (SKIP_DIRS.has(entry)) continue;
    const sub = join(target, entry, 'tools.json');
    try {
      if (existsSync(sub) && looksLikeToolManifest(sub)) found.push(sub);
    } catch {
      /* skip */
    }
  }
  return [...new Set(found)].sort();
}
