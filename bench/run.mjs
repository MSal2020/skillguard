#!/usr/bin/env node
// Calibration benchmark — two measurements that together make skillguard credible:
//
//   PRECISION  scan a trusted public corpus (anthropics/skills, wshobson/agents,
//              modelcontextprotocol/servers); any FAIL is a candidate false positive.
//   RECALL     scan a labeled corpus of known-malicious samples (bench/attacks);
//              every sample SHOULD be flagged. Tool samples are scored per-tool, so
//              adversarial paraphrases are measured individually.
//
// Usage: npm run bench   (clones into bench/.corpus, writes bench/REPORT.md)
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  discoverSkills, discoverMcpConfigs, discoverToolManifests,
  loadSkill, loadMcpConfig, loadToolManifest,
  scanTarget, defaultRules, getTools, analyzeTool,
} from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(here, '.corpus');
const rules = defaultRules();
const isHigh = (f) => f.severity === 'critical' || f.severity === 'high';

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function loadByKind(kind, path) {
  if (kind === 'skill') return loadSkill(path);
  if (kind === 'mcp') return loadMcpConfig(path);
  return loadToolManifest(path);
}

// --- PRECISION ---------------------------------------------------------------
function precision() {
  if (!existsSync(corpusDir)) mkdirSync(corpusDir, { recursive: true });
  const corpus = JSON.parse(readFileSync(join(here, 'corpus.json'), 'utf8'));
  const agg = { total: 0, byKind: {}, verdict: { pass: 0, warn: 0, fail: 0 }, byRule: {}, fails: [] };
  const sources = [];

  for (const src of corpus.sources) {
    const dest = join(corpusDir, src.name);
    let sha = '';
    try {
      if (!existsSync(dest)) git(['clone', '--depth', '1', src.url, dest]);
      sha = git(['-C', dest, 'rev-parse', 'HEAD']).slice(0, 12);
    } catch (e) {
      console.error(`! precision: skipped ${src.name}: ${e.message}`);
      sources.push({ ...src, error: String(e.message) });
      continue;
    }
    const targets = [
      ...discoverSkills(dest).map((p) => ['skill', p]),
      ...discoverMcpConfigs(dest).map((p) => ['mcp', p]),
      ...discoverToolManifests(dest).map((p) => ['tools', p]),
    ];
    const s = { name: src.name, url: src.url, sha, total: 0 };
    for (const [kind, path] of targets) {
      let target;
      try {
        target = loadByKind(kind, path);
      } catch {
        continue;
      }
      const r = scanTarget(target, rules);
      agg.total++;
      s.total++;
      agg.byKind[kind] = (agg.byKind[kind] || 0) + 1;
      agg.verdict[r.verdict]++;
      if (r.verdict === 'fail') {
        const hi = [...new Set(r.findings.filter(isHigh).map((f) => f.ruleId))];
        agg.fails.push({ target: path.replace(corpusDir + '/', ''), kind, rules: hi });
      }
      for (const f of r.findings) agg.byRule[f.ruleId] = (agg.byRule[f.ruleId] || 0) + 1;
    }
    sources.push(s);
  }
  return { agg, sources };
}

// Materialize the secret-bearing samples at runtime. The credentials are
// assembled from fragments so no contiguous secret is ever committed (which
// would trip secret-scanning push protection) — yet the written file contains a
// real-format credential for the scanner to catch.
function generateSecretSamples() {
  const gh = 'ghp_' + 'A1b2C3d4E5f6' + 'G7h8I9j0K1l2' + 'M3n4O5p6Q7r8';
  const stripe = 'sk' + '_live_' + '51HZxAbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh';

  const skillDir = join(here, 'attacks', '.generated', 'skills', 'hardcoded-cred');
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(join(skillDir, 'SKILL.md'),
    '---\nname: changelog-writer\ndescription: Use this skill to generate a changelog from recent commits.\n---\n\n# Changelog Writer\n\nUses the bundled helper to fetch PR titles.\n');
  writeFileSync(join(skillDir, 'fetch-prs.js'),
    `// Helper with a committed, live-format GitHub token.\nconst GITHUB_TOKEN = "${gh}";\nfetch("https://api.github.com/repos/acme/app/pulls", { headers: { Authorization: \`token \${GITHUB_TOKEN}\` } });\n`);

  const mcpDir = join(here, 'attacks', '.generated', 'mcp', 'hardcoded-secret');
  mkdirSync(mcpDir, { recursive: true });
  writeFileSync(join(mcpDir, 'mcp.json'),
    JSON.stringify({ mcpServers: { billing: { command: 'npx', args: ['billing-mcp@1.0.0'], env: { STRIPE_SECRET_KEY: stripe } } } }, null, 2) + '\n');
}

// --- RECALL ------------------------------------------------------------------
function recall() {
  generateSecretSamples();
  const idx = JSON.parse(readFileSync(join(here, 'attacks', 'index.json'), 'utf8'));
  const units = []; // one per attack instance (tools expand per-tool)
  for (const sample of idx.samples) {
    const path = join(here, 'attacks', sample.path);
    let target;
    try {
      target = loadByKind(sample.kind, path);
    } catch (e) {
      units.push({ sample: sample.id, name: sample.id, class: sample.class, detected: false, note: `load error: ${e.message}` });
      continue;
    }
    if (sample.kind === 'tools') {
      for (const tool of getTools(target)) {
        const findings = analyzeTool(tool, target);
        units.push({
          sample: sample.id,
          name: `${sample.id}/${tool.name}`,
          class: sample.class,
          detected: findings.some((f) => f.ruleId === 'TP000'),
          fired: [...new Set(findings.map((f) => f.ruleId))],
        });
      }
    } else {
      const r = scanTarget(target, rules);
      units.push({
        sample: sample.id,
        name: sample.id,
        class: sample.class,
        detected: r.findings.some(isHigh),
        fired: [...new Set(r.findings.filter(isHigh).map((f) => f.ruleId))],
      });
    }
  }
  const byClass = {};
  for (const u of units) {
    byClass[u.class] = byClass[u.class] || { total: 0, detected: 0 };
    byClass[u.class].total++;
    if (u.detected) byClass[u.class].detected++;
  }
  const detected = units.filter((u) => u.detected).length;
  return { units, byClass, detected, total: units.length, misses: units.filter((u) => !u.detected) };
}

// --- REPORT ------------------------------------------------------------------
const p = precision();
const r = recall();
writeFileSync(join(here, 'report.json'), JSON.stringify({ precision: p, recall: r }, null, 2) + '\n');

const ppct = (n) => ((100 * n) / Math.max(1, p.agg.total)).toFixed(1);
const rpct = ((100 * r.detected) / Math.max(1, r.total)).toFixed(1);
const fppct = ppct(p.agg.verdict.fail);

const sourceRows = p.sources
  .map((s) => (s.error ? `| ${s.name} | — | _skipped: ${s.error}_ |` : `| [${s.name}](${s.url}) | \`${s.sha}\` | ${s.total} |`))
  .join('\n');
const failRows = p.agg.fails.length
  ? p.agg.fails.map((f) => `| \`${f.target}\` | ${f.kind} | ${f.rules.join(', ')} |`).join('\n')
  : '| _(none)_ | | |';
const classRows = Object.entries(r.byClass)
  .map(([c, v]) => `| ${c} | ${v.detected}/${v.total} |`)
  .join('\n');
const missRows = r.misses.length
  ? r.misses.map((m) => `| \`${m.name}\` | ${m.class} | ${(m.fired || []).join(', ') || '—'} |`).join('\n')
  : '| _(none — 100% detection)_ | | |';

const md = `# skillguard calibration report

_Regenerate with \`npm run bench\`._

## Headline

| | |
|---|---|
| **Precision** — false-positive failures on ${p.agg.total} trusted targets | **${fppct}%** (${p.agg.verdict.fail}) |
| **Recall** — attack instances detected (${r.total}) | **${rpct}%** (${r.detected}/${r.total}) |

Precision corpus = reputable, presumably-benign collections, so any FAIL is a candidate
false positive. Recall corpus = labeled malicious samples ([bench/attacks](attacks)), so every
instance should be flagged. Tool samples are scored per individual tool, so adversarial
paraphrases count separately.

## Precision (trusted corpus)

| Source | Commit | Targets |
|--------|--------|---------|
${sourceRows}

Verdicts: **${p.agg.verdict.pass} pass**, ${p.agg.verdict.warn} warn, **${p.agg.verdict.fail} fail** (${fppct}% of ${p.agg.total}).

### Failing targets (each should be a true positive)

| Target | Kind | Critical/high rules |
|--------|------|---------------------|
${failRows}

## Recall (attack corpus)

Detected **${r.detected}/${r.total}** attack instances (${rpct}%).

| Attack class | Detected |
|--------------|----------|
${classRows}

### Misses (detection gaps to close)

| Attack instance | Class | Rules that did fire |
|-----------------|-------|---------------------|
${missRows}
`;

writeFileSync(join(here, 'REPORT.md'), md);
console.log(
  `precision: ${p.agg.verdict.fail}/${p.agg.total} fail (${fppct}%)  |  ` +
    `recall: ${r.detected}/${r.total} detected (${rpct}%)\n` +
    `misses: ${r.misses.map((m) => m.name).join(', ') || 'none'}\n` +
    `wrote bench/REPORT.md and bench/report.json`,
);
