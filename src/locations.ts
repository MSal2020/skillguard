import { homedir, platform } from 'node:os';
import { join } from 'node:path';

export interface LocationEnv {
  home: string;
  platform: NodeJS.Platform;
  appData?: string;
}

export function currentEnv(): LocationEnv {
  return { home: homedir(), platform: platform(), appData: process.env.APPDATA };
}

export interface KnownLocation {
  client: string;
  kind: 'mcp' | 'skills';
  path: string;
}

/**
 * Where the common AI clients keep their MCP server configs and installed
 * skills, per platform. `skillguard audit` scans whichever of these exist.
 */
export function knownLocations(env: LocationEnv = currentEnv()): KnownLocation[] {
  const { home } = env;
  const mac = env.platform === 'darwin';
  const win = env.platform === 'win32';
  const appData = env.appData || join(home, 'AppData', 'Roaming');
  const macSupport = join(home, 'Library', 'Application Support');
  const config = join(home, '.config');

  const claudeDesktop = mac
    ? join(macSupport, 'Claude', 'claude_desktop_config.json')
    : win
      ? join(appData, 'Claude', 'claude_desktop_config.json')
      : join(config, 'Claude', 'claude_desktop_config.json');

  const vscode = mac
    ? join(macSupport, 'Code', 'User', 'mcp.json')
    : win
      ? join(appData, 'Code', 'User', 'mcp.json')
      : join(config, 'Code', 'User', 'mcp.json');

  return [
    { client: 'Claude Desktop', kind: 'mcp', path: claudeDesktop },
    { client: 'Claude Code', kind: 'mcp', path: join(home, '.claude.json') },
    { client: 'Cursor', kind: 'mcp', path: join(home, '.cursor', 'mcp.json') },
    { client: 'Windsurf', kind: 'mcp', path: join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { client: 'VS Code', kind: 'mcp', path: vscode },
    { client: 'Claude Code skills', kind: 'skills', path: join(home, '.claude', 'skills') },
    { client: 'Claude plugins', kind: 'skills', path: join(home, '.claude', 'plugins') },
  ];
}
