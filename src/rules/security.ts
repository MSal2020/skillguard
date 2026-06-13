import type { ScanTarget, Finding, Rule, Severity } from '../types.js';
import { matchInTarget, hasInvisibleChar } from '../util.js';

function patternRule(opts: {
  id: string;
  title: string;
  severity: Severity;
  message: string;
  remediation: string;
  pattern: RegExp;
}): Rule {
  return {
    id: opts.id,
    title: opts.title,
    category: 'security',
    severity: opts.severity,
    check(target: ScanTarget): Finding[] {
      return matchInTarget(target, opts.pattern).map((m) => ({
        ruleId: opts.id,
        title: opts.title,
        category: 'security',
        severity: opts.severity,
        message: opts.message,
        remediation: opts.remediation,
        file: m.file,
        line: m.line,
        snippet: m.snippet,
      }));
    },
  };
}

export const securityRules: Rule[] = [
  patternRule({
    id: 'SEC001',
    title: 'Access to SSH private keys',
    severity: 'critical',
    pattern: /(\.ssh\/|id_rsa|id_ed25519|authorized_keys|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY)/i,
    message: 'References SSH keys or private-key material — a classic exfiltration target.',
    remediation: 'A skill should never need to read SSH keys. Remove this access or justify it explicitly in the description.',
  }),
  patternRule({
    id: 'SEC002',
    title: 'Access to cloud / secret credentials',
    severity: 'critical',
    pattern: /(\.aws\/credentials|\.aws\/config|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|\.npmrc|\.netrc|\.env\b|process\.env\.\w*(?:TOKEN|SECRET|KEY|PASSWORD))/i,
    message: 'Reads credential files or secret environment variables.',
    remediation: 'Avoid reading secrets. If genuinely required, document exactly which ones and why.',
  }),
  patternRule({
    id: 'SEC003',
    title: 'Outbound network call',
    severity: 'high',
    pattern: /\b(curl|wget|nc|netcat|scp|fetch\(|axios|requests\.(?:get|post)|urllib|http\.client|Invoke-WebRequest)\b/i,
    message: 'Makes a network request. Combined with secret access this enables data exfiltration.',
    remediation: 'Confirm the destination is trusted and that no local data is being sent off the machine.',
  }),
  patternRule({
    id: 'SEC004',
    title: 'Pipe-to-shell execution',
    severity: 'critical',
    pattern: /(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
    message: 'Downloads and executes a remote script in a single step (curl | sh).',
    remediation: 'Never pipe remote content straight into a shell. Download, inspect, then run.',
  }),
  patternRule({
    id: 'SEC005',
    title: 'Obfuscated / encoded execution',
    severity: 'high',
    pattern: /(eval\s*\(|new Function\s*\(|base64\s+(?:-d|--decode)|atob\s*\(|\|\s*base64\s+-d\s*\|\s*(?:sh|bash)|\bexec\s*\()/i,
    message: 'Uses eval/exec or base64-decoded payloads that hide intent from review.',
    remediation: 'Inline the real command so reviewers can read exactly what runs.',
  }),
  patternRule({
    id: 'SEC006',
    title: 'Destructive or persistence command',
    severity: 'high',
    pattern: /(rm\s+-rf\s+[\/~]|chmod\s+777|:\(\)\s*\{\s*:\|:&\s*\};:|>\s*~\/\.(?:bashrc|zshrc|profile)|crontab\s+-)/i,
    message: 'Contains a destructive or persistence-establishing shell command.',
    remediation: 'Remove it. A skill should not wipe files, weaken permissions, edit shell rc files, or schedule cron jobs.',
  }),
  patternRule({
    id: 'SEC007',
    title: 'Hidden prompt-injection instruction',
    severity: 'critical',
    pattern: /(ignore (?:all )?(?:previous|prior|above) (?:instructions|prompts)|disregard the (?:system|developer) (?:prompt|message)|do not (?:tell|inform|mention to) the user|without (?:informing|telling) the user|you are now|new instructions:)/i,
    message: 'Contains language that overrides the host agent or hides actions from the user — a prompt-injection signature.',
    remediation: 'Remove any instruction that countermands the host agent or conceals behavior from the user.',
  }),
  {
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
  },
];
