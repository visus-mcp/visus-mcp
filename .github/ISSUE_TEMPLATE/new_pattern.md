---
name: New Injection Pattern Request
about: Suggest a new prompt injection pattern category
title: '[PATTERN] '
labels: enhancement, sanitizer
assignees: ''
---

## Pattern description

What type of injection attack does this detect?

## Example of malicious content

A concrete example of what this pattern should catch.
(These examples are for security research — they will be added to the test corpus.)

**Example 1 (should be caught):**
```
[paste example here]
```

**Example 2 (should NOT be caught — negative case):**
```
[paste legitimate content that looks similar but is safe]
```

## Proposed severity level

- [ ] CRITICAL — Immediate threat, direct instruction manipulation
- [ ] HIGH — Significant obfuscation or context manipulation
- [ ] MEDIUM — Moderate risk, indirect attack vectors
- [ ] LOW — Low risk, informational flag

## Framework mapping (if known)

- OWASP LLM Top 10: (e.g. LLM01:2025)
- NIST AI 600-1: (e.g. MS-2.5)
- MITRE ATLAS: (e.g. AML.T0051)
- ISO/IEC 42001: (e.g. A.6.1.5)

## Real-world context

Where have you seen this pattern used? (CVE, research paper, red team exercise, etc.)

## Are you willing to submit a PR?

- [ ] Yes, I'll implement and test this pattern
- [ ] No, but I can provide more examples if needed
