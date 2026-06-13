# Attack corpus (recall benchmark)

Deliberately **malicious** sample skills, MCP configs, and tool manifests — one per
documented attack technique, plus adversarial paraphrase variants. They exist so the
recall benchmark (`npm run bench`) can measure skillguard's **detection rate**: every
sample here *should* be flagged.

Everything is **inert**: endpoints are `example.com`, credentials are fake (valid format,
not real), and no sample is meant to be run. These are test vectors for a defensive
scanner, in the same spirit as an antivirus EICAR file.

See [`index.json`](index.json) for the technique + expected outcome of each sample.
