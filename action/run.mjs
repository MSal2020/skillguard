#!/usr/bin/env node
// Entry point for the skillguard GitHub Action. Scans the repo, emits inline
// annotations (::error/::warning/::notice) on the offending file:line, writes a
// job summary, honors .skillguardignore, and exits per the `fail-on` input.
import { resolve, relative, join, isAbsolute } from 'node:path';
import { appendFileSync } from 'node:fs';
import {
  discoverSkills, discoverMcpConfigs, discoverToolManifests,
  loadSkill, loadMcpConfig, loadToolManifest,
  scanTarget, defaultRules, fingerprintFinding,
  loadIgnoreEntries, makeIgnoreMatcher, applyIgnore, SEVERITY_ORDER,
} from '../dist/index.js';

const env = process.env;
const workspace = env.SG_WORKSPACE || process.cwd();
const rawPath = env.SG_PATH || '.';
const target = isAbsolute(rawPath) ? rawPath : resolve(workspace, rawPath);
const command = (env.SG_COMMAND || 'ci').toLowerCase();
const minSeverity = (env.SG_MIN_SEVERITY || 'high').toLowerCase();
const failOn = (env.SG_FAIL_ON || 'fail').toLowerCase();

const kind = ['mcp', 'skill', 'tools'].includes(command) ? command : 'auto';
const minIdx = SEVERITY_ORDER.indexOf(minSeverity);
const maxIdx = minIdx >= 0 ? minIdx : SEVERITY_ORDER.indexOf('info');

const escData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
const levelFor = (sev) => (sev === 'critical' || sev === 'high' ? 'error' : sev === 'medium' ? 'warning' : 'notice');

function discover() {
  const out = [];
  if (kind === 'skill' || kind === 'auto') for (const p of discoverSkills(target)) out.push(['skill', p]);
  if (kind === 'mcp' || kind === 'auto') for (const p of discoverMcpConfigs(target)) out.push(['mcp', p]);
  if (kind === 'tools' || kind === 'auto') for (const p of discoverToolManifests(target)) out.push(['tools', p]);
  return out;
}
function load(k, p) {
  return k === 'skill' ? loadSkill(p) : k === 'tools' ? loadToolManifest(p) : loadMcpConfig(p);
}

const rules = defaultRules();
const ignore = makeIgnoreMatcher(loadIgnoreEntries([workspace]));
const entries = discover();

if (entries.length === 0) {
  console.log(`::notice::skillguard found no skills or MCP configs under ${rawPath}`);
  process.exit(0);
}

let fails = 0;
let warns = 0;
let ignored = 0;
const rows = [];

for (const [k, p] of entries) {
  let tgt;
  try {
    tgt = load(k, p);
  } catch (e) {
    console.log(`::warning::skillguard skipped ${p}: ${escData(e.message)}`);
    continue;
  }
  const applied = applyIgnore(scanTarget(tgt, rules), ignore);
  const res = applied.result;
  ignored += applied.ignored;
  if (res.verdict === 'fail') fails++;
  else if (res.verdict === 'warn') warns++;

  for (const f of res.findings) {
    if (SEVERITY_ORDER.indexOf(f.severity) > maxIdx) continue;
    const abs = f.file ? join(res.root, f.file) : res.root;
    const rel = relative(workspace, abs) || f.file || res.name;
    const msg = `${f.message}${f.remediation ? ' — ' + f.remediation : ''} [${fingerprintFinding(f)}]`;
    const title = `skillguard: ${f.title} (${f.ruleId})`;
    console.log(`::${levelFor(f.severity)} file=${escProp(rel)},line=${f.line || 1},title=${escProp(title)}::${escData(msg)}`);
  }
  rows.push(`| \`${relative(workspace, res.root) || res.name}\` | ${k} | ${res.verdict.toUpperCase()} | ${res.score} |`);
}

const summary =
  `## skillguard\n\n**${fails} fail · ${warns} warn** across ${entries.length} target(s)` +
  `${ignored ? ` · ${ignored} ignored` : ''}\n\n` +
  `| Target | Kind | Verdict | Risk |\n|---|---|---|---|\n${rows.join('\n')}\n`;
if (env.GITHUB_STEP_SUMMARY) {
  try {
    appendFileSync(env.GITHUB_STEP_SUMMARY, summary);
  } catch {
    /* not on a runner */
  }
}
console.log(`skillguard: ${fails} fail, ${warns} warn across ${entries.length} target(s)`);

const shouldFail = failOn === 'never' ? false : failOn === 'warn' ? fails > 0 || warns > 0 : fails > 0;
process.exit(shouldFail ? 1 : 0);
