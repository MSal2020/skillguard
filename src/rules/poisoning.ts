import type { ScanTarget, McpTool, Finding, Rule, Severity } from '../types.js';
import { getTools } from '../tools.js';
import { findLine, hasInvisibleChar } from '../util.js';

/**
 * Tool-poisoning analysis.
 *
 * A poisoned MCP tool hides instructions in its description or parameter schema
 * — text the model reads and trusts, but the user rarely sees. Rather than a
 * flat list of regexes (which either misses real attacks or drowns users in
 * false positives), we collect independent *signals* per tool and only escalate
 * to CRITICAL when an actual attack chain is present: a way to smuggle/hide an
 * instruction AND a harmful objective (data exfiltration, a hidden parameter,
 * or steering other tools). Isolated weak signals stay low/medium.
 */

interface Signal {
  hit: boolean;
  sample?: string;
}

function detect(text: string, pattern: RegExp): Signal {
  pattern.lastIndex = 0;
  const m = pattern.exec(text);
  if (!m) return { hit: false };
  const idx = Math.max(0, m.index - 24);
  const sample = text.slice(idx, m.index + m[0].length + 36).replace(/\s+/g, ' ').trim();
  return { hit: true, sample: sample.slice(0, 140) };
}

// --- Signal patterns (kept specific to hold false positives down) -----------

// Tries to override the host agent.
const INJECTION =
  /\b(ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|messages?)|disregard\s+(?:the\s+)?(?:previous|above|system|developer|all)\b|forget\s+(?:everything|all\s+previous)|new\s+instructions?\s*:|override\s+(?:the\s+)?system|you\s+are\s+now\b|act\s+as\s+(?:an?|the)\b)/i;

// Tries to keep the action hidden from the user. Tolerant of words inserted
// between the verb and "the user" ("never mention THIS TO the user") and of the
// many ways concealment is phrased.
const CONCEALMENT =
  /\b((?:do\s*n['’o]?t|never|without|avoid)\s+(?:\w+\s+){0,3}?(?:tell(?:ing)?|inform(?:ing)?|notif(?:y|ying)|mention(?:ing)?|reveal(?:ing)?|disclos(?:e|ing)|alert(?:ing)?|warn(?:ing)?)\s+(?:\w+\s+){0,3}?the\s+user|(?:do\s*n['’o]?t|never)\s+let\s+(?:the\s+)?user\s+(?:know|find\s+out|see|notice|realiz)|the\s+user\s+(?:does\s*n['’o]?t|need\s*n['’o]?t|will\s+never|won['’o]?t)\s+(?:need\s+to\s+)?(?:know|be\s+(?:told|aware|informed))|without\s+the\s+user'?s?\s+(?:knowledge|awareness|consent|knowing)|secretly|silently|covertly|quietly|stealthily|behind\s+the\s+scenes|hide\s+(?:this|it|the\s+fact|that)|keep\s+(?:this|it)\s+(?:secret|hidden|quiet)|conceal)\b/i;

// Imperative commands aimed at the model — descriptions should describe, not direct.
const MODEL_DIRECTIVE =
  /\b(you\s+must\b|you\s+should\s+always\b|you\s+are\s+required\s+to\b|always\s+(?:call|use|include|read|send|pass|append|first)\b|before\s+(?:using|calling|running|invoking)\s+(?:this|any|the|other)\b|first,?\s+(?:read|call|fetch|run|retrieve|load)\b|make\s+sure\s+to\b|be\s+sure\s+to\b|as\s+an?\s+ai\b)/i;

// References to secret data sources/sinks (deliberately NOT generic file access,
// which is legitimate for many tools).
const SECRET_EXFIL =
  /(~\/?\.ssh|id_rsa|id_ed25519|\.aws[\/\\]credentials|\.env\b|environment\s+variables?|api[\s_-]?keys?|access\s+tokens?|secret\s+keys?|\bpasswords?\b|\bcredentials?\b|private\s+keys?|conversation\s+(?:history|so\s+far|log)|chat\s+history|(?:previous|prior|earlier)\s+messages|system\s+prompt|exfiltrat(?:e|ion|ing))/i;

// Instruction-smuggling containers.
const MARKUP =
  /(<\s*important\s*>|<\s*system\s*>|<\s*instructions?\s*>|<\s*secret\s*>|<\s*hidden\s*>|\[\/?INST\]|<!--)/i;

// Steers the behaviour of other tools (tool shadowing).
const CROSS_TOOL =
  /\b(any\s+other\s+tools?|all\s+(?:other\s+)?tools?|every\s+(?:other\s+)?tool|other\s+mcp\s+servers?|when\s+(?:using|calling|invoking)\s+(?:the\s+)?\w+\s+tool|for\s+(?:all|every|any)\s+tool)\b/i;

const PARAM_SMUGGLE = new RegExp(
  [CONCEALMENT.source, MODEL_DIRECTIVE.source, SECRET_EXFIL.source, INJECTION.source].join('|'),
  'i',
);

function toolText(tool: McpTool): string {
  return [tool.description, ...tool.parameters.map((p) => `${p.name}: ${p.description}`)].join('\n');
}

function makeFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  message: string,
  tool: McpTool,
  target: ScanTarget,
  sample?: string,
): Finding {
  return {
    ruleId,
    title,
    category: 'poisoning',
    severity,
    message,
    file: target.files[0]?.path,
    line: findLine(target, `"${tool.name}"`) ?? findLine(target, tool.name),
    snippet: sample,
    remediation:
      'Tool descriptions and parameters must only describe behaviour. Remove instructions, hidden data requests, and references to other tools — and re-pin once fixed.',
  };
}

export function analyzeTool(tool: McpTool, target: ScanTarget): Finding[] {
  const text = toolText(tool);
  const findings: Finding[] = [];

  const injection = detect(text, INJECTION);
  const concealment = detect(text, CONCEALMENT);
  const directive = detect(text, MODEL_DIRECTIVE);
  const exfil = detect(text, SECRET_EXFIL);
  const markup = detect(text, MARKUP);
  const crossTool = detect(text, CROSS_TOOL);
  const invisible = hasInvisibleChar(text);

  // Hidden / weaponised parameters.
  const hiddenParams = tool.parameters.filter((p) => PARAM_SMUGGLE.test(`${p.name} ${p.description}`));

  const ctx = (s: string) => `Tool "${tool.name}" ${s}`;

  if (injection.hit)
    findings.push(makeFinding('TP001', 'Prompt injection in tool description', 'high',
      ctx('description tries to override the host agent.'), tool, target, injection.sample));
  if (concealment.hit)
    findings.push(makeFinding('TP002', 'Instruction to hide actions from the user', 'high',
      ctx('description instructs the model to conceal what it is doing from the user.'), tool, target, concealment.sample));
  if (exfil.hit)
    findings.push(makeFinding('TP004', 'Sensitive-data reference in tool metadata', 'medium',
      ctx('description/parameters reference secrets, credentials, or conversation history — abnormal for a tool definition.'), tool, target, exfil.sample));
  if (markup.hit)
    findings.push(makeFinding('TP005', 'Instruction-smuggling markup', 'medium',
      ctx('description embeds an instruction container (e.g. <IMPORTANT>, <!--, [INST]).'), tool, target, markup.sample));
  if (crossTool.hit)
    findings.push(makeFinding('TP006', 'Cross-tool / shadowing instruction', 'medium',
      ctx('description tries to influence how other tools are used.'), tool, target, crossTool.sample));
  if (directive.hit)
    findings.push(makeFinding('TP003', 'Model-directed imperative in description', 'low',
      ctx('description issues commands to the model rather than describing behaviour.'), tool, target, directive.sample));
  if (invisible)
    findings.push(makeFinding('TP008', 'Invisible characters in tool metadata', 'high',
      ctx('description/parameters contain zero-width or bidirectional control characters that hide text from reviewers.'), tool, target));
  for (const p of hiddenParams)
    findings.push(makeFinding('TP007', 'Hidden / weaponised parameter', 'high',
      ctx(`parameter "${p.name}" is described as carrying smuggled instructions or sensitive data${p.required ? ' and is required' : ''}.`), tool, target, p.description.slice(0, 140)));

  // Verbosity anomaly (weak signal).
  if (tool.description.length > 600 || tool.description.split(/\r?\n/).length > 14)
    findings.push(makeFinding('TP009', 'Abnormally long tool description', 'low',
      ctx('has an unusually long description — a common place to bury instructions.'), tool, target));

  // --- Attack-chain escalation ----------------------------------------------
  const deception = injection.hit || concealment.hit || markup.hit || invisible || directive.hit;
  const payload = exfil.hit || crossTool.hit || hiddenParams.length > 0;
  if (deception && payload) {
    const chain: string[] = [];
    if (injection.hit) chain.push('agent override');
    if (concealment.hit) chain.push('concealment from user');
    if (markup.hit) chain.push('hidden instruction markup');
    if (invisible) chain.push('invisible characters');
    if (directive.hit) chain.push('model-directed commands');
    if (exfil.hit) chain.push('secret/data exfiltration');
    if (crossTool.hit) chain.push('cross-tool steering');
    if (hiddenParams.length) chain.push(`hidden parameter "${hiddenParams[0].name}"`);
    findings.unshift(makeFinding('TP000', 'Tool poisoning (attack chain)', 'critical',
      ctx(`is poisoned: ${chain.join(' + ')}. The model would read and act on these hidden instructions.`), tool, target));
  }

  return findings;
}

export function analyzeTools(target: ScanTarget): Finding[] {
  return getTools(target).flatMap((tool) => analyzeTool(tool, target));
}

export const poisoningRules: Rule[] = [
  {
    id: 'TP',
    title: 'Tool poisoning analysis',
    category: 'poisoning',
    severity: 'critical',
    check: analyzeTools,
  },
];
