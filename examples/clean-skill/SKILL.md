---
name: json-formatter
description: Use this skill when the user wants to pretty-print, format, or validate JSON. Trigger on messy JSON, minified JSON, or "format this JSON" requests.
---

# JSON Formatter

Formats and validates JSON with 2-space indentation and sorted object keys.

## Usage

Paste the JSON and ask to format it. The skill validates structure first, then
re-emits it with stable key ordering so diffs stay small.

## Examples

- "format this JSON" → returns indented, key-sorted JSON
- "is this valid JSON?" → returns yes/no plus the first error location
