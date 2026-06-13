import { spawn } from 'node:child_process';
import type { McpServerConfig, McpTool } from './types.js';
import { normalizeTools } from './tools.js';

export interface IntrospectOptions {
  timeoutMs?: number;
}

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

const INIT_PARAMS = {
  protocolVersion: '2025-06-18',
  capabilities: {},
  clientInfo: { name: 'skillguard', version: '0.1' },
};

/**
 * Launch a stdio MCP server (or connect to an HTTP one), perform the initialize
 * handshake, call `tools/list`, and return the advertised tool definitions.
 *
 * For stdio this EXECUTES the server — only call it on servers you intend to
 * run. We never call `tools/call`; we only read tool schemas, with a timeout.
 */
export function introspectServer(server: McpServerConfig, opts: IntrospectOptions = {}): Promise<McpTool[]> {
  if (server.command) return introspectStdio(server, opts);
  if (server.url) return introspectHttp(server, opts);
  return Promise.reject(new Error(`Server "${server.name}" has neither a stdio command nor a url.`));
}

// --- stdio transport ---------------------------------------------------------

function introspectStdio(server: McpServerConfig, opts: IntrospectOptions): Promise<McpTool[]> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const command = server.command as string;

  return new Promise<McpTool[]>((resolve, reject) => {
    const child = spawn(command, server.args, {
      env: { ...process.env, ...server.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let settled = false;
    let stdoutBuf = '';
    let stderrBuf = '';
    const timer = setTimeout(
      () => finish(new Error(`introspection of "${server.name}" timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );

    function cleanup(): void {
      clearTimeout(timer);
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    }
    function finish(err: Error | null, value?: McpTool[]): void {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) reject(err);
      else resolve(value ?? []);
    }
    function send(msg: JsonRpcMessage): void {
      try {
        child.stdin.write(JSON.stringify(msg) + '\n');
      } catch (e) {
        finish(e as Error);
      }
    }
    function handle(msg: JsonRpcMessage): void {
      if (msg.id === 1) {
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
      } else if (msg.id === 2) {
        if (msg.error) return finish(new Error(`tools/list error: ${JSON.stringify(msg.error)}`));
        finish(null, normalizeTools(msg.result).map((t) => ({ ...t, serverName: server.name })));
      }
    }

    child.on('error', (e) => finish(new Error(`failed to launch "${command}": ${e.message}`)));
    child.stderr.on('data', (d: Buffer) => {
      stderrBuf = (stderrBuf + d.toString()).slice(-64_000);
    });
    child.stdout.on('data', (d: Buffer) => {
      stdoutBuf += d.toString();
      let nl: number;
      while ((nl = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line) continue;
        try {
          handle(JSON.parse(line) as JsonRpcMessage);
        } catch {
          /* ignore non-JSON log lines */
        }
      }
    });
    child.on('close', () => {
      if (!settled) {
        const detail = stderrBuf.trim() ? ` (stderr: ${stderrBuf.trim().slice(0, 200)})` : '';
        finish(new Error(`server "${server.name}" exited before returning tools${detail}`));
      }
    });

    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: INIT_PARAMS });
  });
}

// --- Streamable HTTP transport ----------------------------------------------

/** Parse an SSE response body into the JSON-RPC messages carried by its `data:` lines. */
export function parseSseEvents(text: string): JsonRpcMessage[] {
  const out: JsonRpcMessage[] = [];
  for (const event of text.split(/\r?\n\r?\n/)) {
    const data = event
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).trim())
      .join('\n');
    if (!data) continue;
    try {
      out.push(JSON.parse(data) as JsonRpcMessage);
    } catch {
      /* ignore keep-alives / comments */
    }
  }
  return out;
}

async function introspectHttp(server: McpServerConfig, opts: IntrospectOptions): Promise<McpTool[]> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const url = server.url as string;
  const baseHeaders: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...server.headers,
  };
  let sessionId: string | undefined;

  async function rpc(message: JsonRpcMessage, expectResponse: boolean): Promise<JsonRpcMessage | null> {
    const headers = { ...baseHeaders };
    if (sessionId) headers['mcp-session-id'] = sessionId;

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(message),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new Error(`request to ${url} failed: ${(e as Error).message}`);
    }

    const sid = res.headers.get('mcp-session-id');
    if (sid) sessionId = sid;

    if (!expectResponse) return null; // notification → 202 Accepted, no body
    if (!res.ok) {
      throw new Error(`server returned HTTP ${res.status} for ${message.method}: ${(await res.text()).slice(0, 200)}`);
    }

    const contentType = res.headers.get('content-type') ?? '';
    const body = await res.text();
    const messages = contentType.includes('text/event-stream')
      ? parseSseEvents(body)
      : [JSON.parse(body) as JsonRpcMessage];
    return messages.find((m) => m.id === message.id) ?? messages.find((m) => m.result || m.error) ?? null;
  }

  const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: INIT_PARAMS }, true);
  if (init?.error) throw new Error(`initialize error: ${JSON.stringify(init.error)}`);

  await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' }, false);

  const list = await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, true);
  if (!list) throw new Error(`server "${server.name}" returned no tools/list response`);
  if (list.error) throw new Error(`tools/list error: ${JSON.stringify(list.error)}`);

  return normalizeTools(list.result).map((t) => ({ ...t, serverName: server.name }));
}
