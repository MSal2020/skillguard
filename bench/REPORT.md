# skillguard calibration report

_Regenerate with `npm run bench`. The corpus is a set of reputable, presumably-benign
public skill/MCP collections (see [corpus.json](corpus.json)), so **any FAIL is a candidate
false positive** — this measures precision in the real world, not on crafted examples._

## Headline

| Metric | Value |
|--------|-------|
| Targets scanned | **175** |
| Clean (pass) | 171 (97.7%) |
| Warn | 4 (2.3%) |
| **Fail (candidate false positives)** | **0 (0.0%)** |

Target kinds: 174 skill, 1 mcp.

## Corpus

| Source | Commit | Targets |
|--------|--------|---------|
| [anthropic-skills](https://github.com/anthropics/skills) | `575462609294` | 18 |
| [wshobson-agents](https://github.com/wshobson/agents) | `cc37bfdd292c` | 156 |
| [mcp-servers](https://github.com/modelcontextprotocol/servers) | `275175cda17c` | 1 |

## Failing targets (review these — each should be a true positive)

| Target | Kind | Critical/high rules |
|--------|------|---------------------|
| _(none)_ | | |

## Findings by rule

| Rule | Count |
|------|-------|
| `QUA002` | 30 |
| `SEC003` | 6 |
| `SEC004` | 3 |
| `SEC009` | 1 |
| `SEC001` | 1 |
| `PAT002` | 1 |
| `SEC006` | 1 |

Severity totals: 30 low, 3 high, 4 medium, 6 info.
