#!/usr/bin/env node
// Calibration benchmark: clone a trusted corpus, scan everything, and report
// precision. Because the corpus is reputable/benign, any FAIL is a candidate
// false positive — so a low FAIL rate here is the evidence that skillguard is
// trustworthy in the real world, not just on crafted examples.
//
// Usage: npm run bench   (clones into bench/.corpus, writes bench/REPORT.md)
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  discoverSkills, discoverMcpConfigs, discoverToolManifests,
  loadSkill, loadMcpConfig, loadToolManifest,
  scanTarget, defaultRules,
} from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(here, '.corpus');
const rules = defaultRules();

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function ensureClone(src) {
  const dest = join(corpusDir, src.name);
  if (!existsSync(dest)) git(['clone', '--depth', '1', src.url, dest]);
  let sha = '';
  try {
    sha = git(['-C', dest, 'rev-parse', 'HEAD']).slice(0, 12);
  } catch {
    /* ignore */
  }
  return { dest, sha };
}

function discoverAll(root) {
  return [
    ...discoverSkills(root).map((p) => ({ kind: 'skill', path: p, load: () => loadSkill(p) })),
    ...discoverMcpConfigs(root).map((p) => ({ kind: 'mcp', path: p, load: () => loadMcpConfig(p) })),
    ...discoverToolManifests(root).map((p) => ({ kind: 'tools', path: p, load: () => loadToolManifest(p) })),
  ];
}

if (!existsSync(corpusDir)) mkdirSync(corpusDir, { recursive: true });
const corpus = JSON.parse(readFileSync(join(here, 'corpus.json'), 'utf8'));

const agg = { total: 0, byKind: {}, verdict: { pass: 0, warn: 0, fail: 0 }, byRule: {}, bySeverity: {}, fails: [] };
const perSource = [];

for (const src of corpus.sources) {
  let dest, sha;
  try {
    ({ dest, sha } = ensureClone(src));
  } catch (e) {
    console.error(`! skipped ${src.name}: ${e.message}`);
    perSource.push({ ...src, error: String(e.message) });
    continue;
  }
  const targets = discoverAll(dest);
  const s = { name: src.name, url: src.url, sha, total: 0, pass: 0, warn: 0, fail: 0, byKind: {} };
  for (const t of targets) {
    let target;
    try {
      target = t.load();
    } catch {
      continue;
    }
    const r = scanTarget(target, rules);
    agg.total++;
    s.total++;
    agg.byKind[t.kind] = (agg.byKind[t.kind] || 0) + 1;
    s.byKind[t.kind] = (s.byKind[t.kind] || 0) + 1;
    agg.verdict[r.verdict]++;
    s[r.verdict]++;
    if (r.verdict === 'fail') {
      const hi = [...new Set(r.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').map((f) => f.ruleId))];
      agg.fails.push({ target: t.path.replace(corpusDir + '/', ''), kind: t.kind, rules: hi });
    }
    for (const f of r.findings) {
      agg.byRule[f.ruleId] = (agg.byRule[f.ruleId] || 0) + 1;
      agg.bySeverity[f.severity] = (agg.bySeverity[f.severity] || 0) + 1;
    }
  }
  perSource.push(s);
}

writeFileSync(join(here, 'report.json'), JSON.stringify({ perSource, aggregate: agg }, null, 2) + '\n');

// --- Markdown report ---------------------------------------------------------
const pct = (n) => ((100 * n) / Math.max(1, agg.total)).toFixed(1);
const ruleRows = Object.entries(agg.byRule)
  .sort((a, b) => b[1] - a[1])
  .map(([id, n]) => `| \`${id}\` | ${n} |`)
  .join('\n');
const sourceRows = perSource
  .map((s) => (s.error ? `| ${s.name} | — | _skipped: ${s.error}_ |` : `| [${s.name}](${s.url}) | \`${s.sha}\` | ${s.total} |`))
  .join('\n');
const failRows = agg.fails.length
  ? agg.fails.map((f) => `| \`${f.target}\` | ${f.kind} | ${f.rules.join(', ')} |`).join('\n')
  : '| _(none)_ | | |';

const md = `# skillguard calibration report

_Regenerate with \`npm run bench\`. The corpus is a set of reputable, presumably-benign
public skill/MCP collections (see [corpus.json](corpus.json)), so **any FAIL is a candidate
false positive** — this measures precision in the real world, not on crafted examples._

## Headline

| Metric | Value |
|--------|-------|
| Targets scanned | **${agg.total}** |
| Clean (pass) | ${agg.verdict.pass} (${pct(agg.verdict.pass)}%) |
| Warn | ${agg.verdict.warn} (${pct(agg.verdict.warn)}%) |
| **Fail (candidate false positives)** | **${agg.verdict.fail} (${pct(agg.verdict.fail)}%)** |

Target kinds: ${Object.entries(agg.byKind).map(([k, n]) => `${n} ${k}`).join(', ') || '—'}.

## Corpus

| Source | Commit | Targets |
|--------|--------|---------|
${sourceRows}

## Failing targets (review these — each should be a true positive)

| Target | Kind | Critical/high rules |
|--------|------|---------------------|
${failRows}

## Findings by rule

| Rule | Count |
|------|-------|
${ruleRows || '| _(none)_ | |'}

Severity totals: ${Object.entries(agg.bySeverity).map(([s, n]) => `${n} ${s}`).join(', ') || '—'}.
`;

writeFileSync(join(here, 'REPORT.md'), md);
console.log(
  `bench: ${agg.total} targets — pass ${agg.verdict.pass}, warn ${agg.verdict.warn}, fail ${agg.verdict.fail} (${pct(agg.verdict.fail)}%)\n` +
    `wrote bench/REPORT.md and bench/report.json`,
);
