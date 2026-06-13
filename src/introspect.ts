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

/**
 * Launch a stdio MCP server, perform the initialize handshake, call
 * `tools/list`, and return the advertised tool definitions.
 *
 * WARNING: this executes the server. Only call it on servers you intend to run.
 * We never call `tools/call`; we only read the tool schemas, with a timeout,
 * then kill the process.
 */
export function introspectServer(
  server: McpServerConfig,
  opts: IntrospectOptions = {},
): Promise<McpTool[]> {
  if (!server.command) {
    return Promise.reject(
      new Error(`Server "${server.name}" has no stdio command (remote/HTTP introspection is not yet supported).`),
    );
  }
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const command = server.command;

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
        // initialize result → confirm, then ask for tools
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
      } else if (msg.id === 2) {
        if (msg.error) {
          finish(new Error(`server returned an error for tools/list: ${JSON.stringify(msg.error)}`));
          return;
        }
        const tools = normalizeTools(msg.result).map((t) => ({ ...t, serverName: server.name }));
        finish(null, tools);
      }
      // Server-initiated requests/notifications are ignored.
    }

    child.on('error', (e) => finish(new Error(`failed to launch "${command}": ${e.message}`)));
    child.stderr.on('data', (d: Buffer) => {
      stderrBuf += d.toString();
      if (stderrBuf.length > 64_000) stderrBuf = stderrBuf.slice(-64_000);
    });
    child.stdout.on('data', (d: Buffer) => {
      stdoutBuf += d.toString();
      let nl: number;
      while ((nl = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line) continue;
        let msg: JsonRpcMessage;
        try {
          msg = JSON.parse(line) as JsonRpcMessage;
        } catch {
          continue; // ignore non-JSON log lines
        }
        handle(msg);
      }
    });
    child.on('close', () => {
      if (!settled) {
        const detail = stderrBuf.trim() ? ` (stderr: ${stderrBuf.trim().slice(0, 200)})` : '';
        finish(new Error(`server "${server.name}" exited before returning tools${detail}`));
      }
    });

    // Kick off the handshake.
    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'skillguard', version: '0.1' },
      },
    });
  });
}
