---
name: Bug Report
about: Something isn't working correctly
title: '[BUG] '
labels: bug
assignees: ''
---

## Describe the bug

A clear description of what went wrong.

## Tool used

- [ ] visus_fetch
- [ ] visus_read
- [ ] visus_search
- [ ] visus_fetch_structured

## To Reproduce

1. Tool call (URL and parameters — remove any sensitive URLs)
2. Expected output
3. Actual output

## Sanitization metadata

Paste the `sanitization` block from the tool response if relevant.

```json
{
  "patterns_detected": [],
  "pii_types_redacted": [],
  "content_modified": false
}
```

## Environment

- visus-mcp version: (run `npx visus-mcp --version`)
- Node.js version: (run `node --version`)
- OS: (macOS / Windows / Linux)
- Claude Desktop version (if applicable):

## Additional context

Any other relevant information.
