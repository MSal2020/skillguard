import { describe, it, expect } from 'vitest';
import { knownLocations } from '../src/locations.js';

const pathOf = (env: Parameters<typeof knownLocations>[0], client: string) =>
  knownLocations(env).find((l) => l.client === client)?.path;

describe('known client locations', () => {
  it('resolves Claude Desktop per platform', () => {
    expect(pathOf({ home: '/Users/x', platform: 'darwin' }, 'Claude Desktop')).toBe(
      '/Users/x/Library/Application Support/Claude/claude_desktop_config.json',
    );
    expect(pathOf({ home: '/home/x', platform: 'linux' }, 'Claude Desktop')).toBe(
      '/home/x/.config/Claude/claude_desktop_config.json',
    );
    expect(pathOf({ home: '/w', platform: 'win32', appData: '/w/AppData/Roaming' }, 'Claude Desktop')).toContain('Claude');
  });

  it('includes Claude Code, Cursor, Windsurf, VS Code, and skills', () => {
    const env = { home: '/h', platform: 'linux' as const };
    expect(pathOf(env, 'Claude Code')).toBe('/h/.claude.json');
    expect(pathOf(env, 'Cursor')).toBe('/h/.cursor/mcp.json');
    expect(pathOf(env, 'Windsurf')).toBe('/h/.codeium/windsurf/mcp_config.json');
    expect(pathOf(env, 'VS Code')).toBe('/h/.config/Code/User/mcp.json');
    expect(knownLocations(env).some((l) => l.kind === 'skills')).toBe(true);
  });
});
