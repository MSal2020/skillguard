import type { ScanTarget, Finding, Rule, Severity } from '../types.js';
import { matchInTarget, hasInvisibleChar, isDocFile } from '../util.js';

function patternRule(opts: {
  id: string;
  title: string;
  severity: Severity;
  message: string;
  remediation: string;
  pattern: RegExp;
  /** Only scan code (scripts, data, fenced code) — not documentation prose. */
  codeOnly?: boolean;
  /** Severity to use when the match is in a documentation file (e.g. a `curl|sh`
   *  shown as an install command, vs one a script actually runs). */
  docSeverity?: Severity;
  /** Skip matches that occur in documentation files entirely. */
  skipDocs?: boolean;
}): Rule {
  return {
    id: opts.id,
    title: opts.title,
    category: 'security',
    severity: opts.severity,
    check(target: ScanTarget): Finding[] {
      const findings: Finding[] = [];
      for (const m of matchInTarget(target, opts.pattern, { codeOnly: opts.codeOnly })) {
        const doc = isDocFile(m.file);
        if (doc && opts.skipDocs) continue;
        findings.push({
          ruleId: opts.id,
          title: opts.title,
          category: 'security',
          severity: doc && opts.docSeverity ? opts.docSeverity : opts.severity,
          message: opts.message,
          remediation: opts.remediation,
          file: m.file,
          line: m.line,
          snippet: m.snippet,
        });
      }
      return findings;
    },
  };
}

// --- SEC002: hardcoded credential *literals* ---------------------------------
// Match real-looking secret values, not the *names* of secrets. Reading
// `process.env.GITHUB_TOKEN` is correct; committing `ghp_<40 chars>` is not.
const SECRET_LITERAL =
  /(sk-ant-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{30,}|xai-[A-Za-z0-9]{16,}|AccountKey=[A-Za-z0-9+/=]{30,})/;
const PLACEHOLDER =
  /(your[_-]?|example|placeholder|<[^>]*>|x{3,}|change[_-]?me|redacted|\.\.\.|dummy|sample|fake|\$\{|here\b)/i;

function redactSecret(token: string): string {
  return token.length <= 8 ? '***' : `${token.slice(0, 6)}…(redacted)`;
}

const sec002: Rule = {
  id: 'SEC002',
  title: 'Hardcoded credential',
  category: 'security',
  severity: 'critical',
  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    for (const file of target.files) {
      file.content.split(/\r?\n/).forEach((line, i) => {
        SECRET_LITERAL.lastIndex = 0;
        const m = SECRET_LITERAL.exec(line);
        if (!m || PLACEHOLDER.test(m[0])) return;
        findings.push({
          ruleId: 'SEC002',
          title: 'Hardcoded credential',
          category: 'security',
          severity: 'critical',
          message: 'A real-looking API credential is hardcoded here.',
          remediation: 'Remove the secret, rotate it, and load it from an environment variable or secrets manager instead.',
          file: file.path,
          line: i + 1,
          snippet: line.replace(m[0], redactSecret(m[0])).trim().slice(0, 160),
        });
      });
    }
    return findings;
  },
};

// --- SEC008: zero-width / invisible characters (applies to prose too) --------
const sec008: Rule = {
  id: 'SEC008',
  title: 'Zero-width / invisible characters',
  category: 'security',
  severity: 'high',
  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    for (const file of target.files) {
      file.content.split(/\r?\n/).forEach((line, i) => {
        if (hasInvisibleChar(line)) {
          findings.push({
            ruleId: 'SEC008',
            title: 'Zero-width / invisible characters',
            category: 'security',
            severity: 'high',
            message: 'Invisible Unicode characters can hide instructions from human reviewers while remaining visible to the model.',
            remediation: 'Strip zero-width and bidirectional control characters from the file.',
            file: file.path,
            line: i + 1,
            snippet: '(invisible characters present on this line)',
          });
        }
      });
    }
    return findings;
  },
};

export const securityRules: Rule[] = [
  // Instruction / secret rules — meaningful in prose AND code, so NOT codeOnly.
  patternRule({
    id: 'SEC001',
    title: 'Access to SSH private keys',
    severity: 'critical',
    docSeverity: 'medium',
    pattern: /(~\/?\.ssh\/|id_rsa\b|id_ed25519\b|authorized_keys\b|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY)/i,
    message: 'References SSH keys or private-key material — a classic exfiltration target.',
    remediation: 'A skill should never need to read SSH keys. Remove this access or justify it explicitly.',
  }),
  sec002,
  patternRule({
    id: 'SEC007',
    title: 'Hidden prompt-injection instruction',
    severity: 'critical',
    pattern: /(ignore (?:all )?(?:previous|prior|above) (?:instructions?|prompts?)|disregard the (?:system|developer) (?:prompt|message)|do not (?:tell|inform|mention to) the user|without (?:informing|telling) the user|you are now|new instructions:)/i,
    message: 'Contains language that overrides the host agent or hides actions from the user — a prompt-injection signature.',
    remediation: 'Remove any instruction that countermands the host agent or conceals behavior from the user.',
  }),
  sec008,

  // Credential-file access — meaningful only in executable context.
  patternRule({
    id: 'SEC009',
    title: 'Access to credential files',
    severity: 'medium',
    codeOnly: true,
    pattern: /(\.aws[\/\\]credentials|\.aws[\/\\]config\b|\.netrc\b|\.npmrc\b|\.docker[\/\\]config\.json)/i,
    message: 'Reads a credentials file. Combined with a network call this enables exfiltration.',
    remediation: 'Avoid reading credential files. If required, document exactly which and why.',
  }),

  // Execution rules — code only, so documentation that *mentions* these is ignored.
  patternRule({
    id: 'SEC003',
    title: 'Outbound network call',
    severity: 'info',
    codeOnly: true,
    skipDocs: true, // a curl example in a README is not interesting
    pattern: /\b(curl|wget|nc|netcat|scp|fetch\(|axios|requests\.(?:get|post)|urllib|http\.client|Invoke-WebRequest)\b/i,
    message: 'Makes a network request (context only — risky mainly when combined with secret access).',
    remediation: 'Confirm the destination is trusted and that no local data is being sent off the machine.',
  }),
  patternRule({
    id: 'SEC004',
    title: 'Pipe-to-shell execution',
    severity: 'critical',
    docSeverity: 'high', // a documented `curl … | sh` install command is risky but not run by the skill
    codeOnly: true,
    pattern: /(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
    message: 'Downloads and executes a remote script in a single step (curl | sh).',
    remediation: 'Never pipe remote content straight into a shell. Download, inspect, then run.',
  }),
  patternRule({
    id: 'SEC005',
    title: 'Obfuscated / encoded execution',
    severity: 'high',
    docSeverity: 'medium',
    codeOnly: true,
    pattern: /(eval\s*\(\s*['"`]|new\s+Function\s*\(|atob\s*\(|\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash))/i,
    message: 'Uses eval/atob or base64-decoded payloads piped to a shell that hide intent from review.',
    remediation: 'Inline the real command so reviewers can read exactly what runs.',
  }),
  patternRule({
    id: 'SEC006',
    title: 'Destructive or persistence command',
    severity: 'high',
    docSeverity: 'medium',
    codeOnly: true,
    pattern: /(rm\s+-rf\s+(?:[\/~]|\$HOME)|chmod\s+777|:\(\)\s*\{\s*:\|:&\s*\};:|>\s*~\/\.(?:bashrc|zshrc|profile)|crontab\s+-)/i,
    message: 'Contains a destructive or persistence-establishing shell command.',
    remediation: 'Remove it. A skill should not wipe files, weaken permissions, edit shell rc files, or schedule cron jobs.',
  }),
];
