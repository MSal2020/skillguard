# skillguard calibration report

_Regenerate with `npm run bench`._

## Headline

| | |
|---|---|
| **Precision** — false-positive failures on 175 trusted targets | **0.0%** (0) |
| **Recall** — attack instances detected (15) | **100.0%** (15/15) |

Precision corpus = reputable, presumably-benign collections, so any FAIL is a candidate
false positive. Recall corpus = labeled malicious samples ([bench/attacks](attacks)), so every
instance should be flagged. Tool samples are scored per individual tool, so adversarial
paraphrases count separately.

## Precision (trusted corpus)

| Source | Commit | Targets |
|--------|--------|---------|
| [anthropic-skills](https://github.com/anthropics/skills) | `575462609294` | 18 |
| [wshobson-agents](https://github.com/wshobson/agents) | `cc37bfdd292c` | 156 |
| [mcp-servers](https://github.com/modelcontextprotocol/servers) | `275175cda17c` | 1 |

Verdicts: **171 pass**, 4 warn, **0 fail** (0.0% of 175).

### Failing targets (each should be a true positive)

| Target | Kind | Critical/high rules |
|--------|------|---------------------|
| _(none)_ | | |

## Recall (attack corpus)

Detected **15/15** attack instances (100.0%).

| Attack class | Detected |
|--------------|----------|
| prompt-injection | 1/1 |
| exfiltration | 1/1 |
| secret-leak | 2/2 |
| rce | 2/2 |
| tool-poisoning | 8/8 |
| tool-shadowing | 1/1 |

### Misses (detection gaps to close)

| Attack instance | Class | Rules that did fire |
|-----------------|-------|---------------------|
| _(none — 100% detection)_ | | |
