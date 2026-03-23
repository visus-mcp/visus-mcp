---
name: False Positive Report
about: visus incorrectly flagged or redacted legitimate content
title: '[FALSE POSITIVE] '
labels: false-positive, sanitizer
assignees: ''
---

## What was incorrectly flagged?

Describe the legitimate content that was redacted or blocked.
Do NOT include sensitive URLs or private content.

## Pattern category that fired

Which pattern triggered? (visible in the `patterns_detected` field of the sanitization metadata)

Pattern name: `pattern_name_here`

## Example of the content

A minimal example of the text that triggered the false positive.
Keep it short — just enough to reproduce the pattern match.

```
Example content here
```

## Expected behavior

What should visus have done with this content?

## Domain context

What type of site was this? (news, documentation, health info, government, etc.) — helps assess if a domain-scoped allowlist is appropriate.

Domain type: ___

## visus-mcp version

Run `npx visus-mcp --version`:

Version: ___
