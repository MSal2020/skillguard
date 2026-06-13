import type { ScanResult, Severity, Verdict } from './types.js';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: C.magenta,
  high: C.red,
  medium: C.yellow,
  low: C.cyan,
  info: C.gray,
};

const SEV_LABEL: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED ',
  low: 'LOW ',
  info: 'INFO',
};

/** Most-severe first. Also used by the CLI for `--min-severity` filtering. */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function paint(on: boolean, codes: string, s: string): string {
  return on ? `${codes}${s}${C.reset}` : s;
}

function verdictBadge(v: Verdict, useColor: boolean): string {
  if (v === 'fail') return paint(useColor, C.red + C.bold, '✗ FAIL');
  if (v === 'warn') return paint(useColor, C.yellow + C.bold, '! WARN');
  return paint(useColor, C.green + C.bold, '✓ PASS');
}

export function formatResult(result: ScanResult, useColor = true): string {
  const lines: string[] = [];
  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  lines.push('');
  lines.push(
    paint(useColor, C.bold, `skillguard › ${result.name}`) +
      paint(useColor, C.cyan, `  [${result.kind}]`) +
      paint(useColor, C.gray, `  (${result.root})`),
  );

  if (sorted.length === 0) {
    lines.push(paint(useColor, C.green, '  ✓ no issues found'));
  }

  for (const f of sorted) {
    const sev = paint(useColor, SEV_COLOR[f.severity] + C.bold, SEV_LABEL[f.severity]);
    lines.push(`  ${sev} ${paint(useColor, C.bold, f.title)} ${paint(useColor, C.gray, f.ruleId)}`);
    lines.push(`       ${f.message}`);
    if (f.file) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      lines.push(
        paint(useColor, C.gray, `       ↳ ${loc}`) +
          (f.snippet ? paint(useColor, C.dim, `  ${f.snippet}`) : ''),
      );
    }
    if (f.remediation) lines.push(paint(useColor, C.gray, `       fix: ${f.remediation}`));
  }

  lines.push('');
  lines.push(
    '  ' +
      verdictBadge(result.verdict, useColor) +
      '  ' +
      paint(useColor, C.gray, `risk score ${result.score}/100 · ${result.findings.length} finding(s) shown`),
  );
  lines.push('');
  return lines.join('\n') + '\n';
}
