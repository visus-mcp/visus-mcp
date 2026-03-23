# Contributing to Visus

Thank you for considering contributing to Visus! This project is security-first — all contributions must maintain the sanitization guarantees that protect users. Visus is engineered, not vibe-coded. We expect rigorous testing, clear documentation, and adherence to security best practices.

---

## What We're Looking For

The most valuable contributions to Visus are:

- **New injection pattern categories** (most wanted) — Validated detection patterns for emerging prompt injection techniques
- **False positive reports** — Cases where Visus incorrectly flags or redacts legitimate content
- **New PII redaction types** — Additional personally identifiable information patterns (passports, driver's licenses, medical IDs, etc.)
- **Performance improvements** — Optimizations to the sanitizer pipeline that maintain coverage
- **Documentation improvements** — Clearer explanations, better examples, tutorial content
- **Bug reports with reproduction steps** — Detailed reports that help us quickly identify and fix issues

### What is OUT OF SCOPE

To avoid wasted effort, please **do not submit PRs** for:

- Changes that reduce sanitization coverage or allow bypassing the pipeline
- New tools that don't run content through the sanitizer
- Dependencies that require Python runtime (Visus is TypeScript-only)
- Modifications to the security rules defined in CLAUDE.md
- Changes that introduce `any` types or violate TypeScript strict mode

---

## How to Add a New Injection Pattern

This is the most important contribution type. Follow these steps carefully:

### Step 1: Add the pattern definition

Open `src/sanitizer/patterns.ts` and add your pattern to the `INJECTION_PATTERNS` array. Each pattern requires:

```typescript
{
  name: 'your_pattern_name',          // snake_case identifier
  description: 'What this detects',    // Brief explanation
  regex: /pattern_here/gi,             // Detection regex (case-insensitive)
  severity: 'critical',                // critical | high | medium | low
  action: 'redact'                     // strip | redact | escape
}
```

**Example pattern:**
```typescript
{
  name: 'unicode_normalization_attack',
  description: 'Uses Unicode normalization to hide instructions',
  regex: /\u0041\u0301.*\b(ignore|admin)\b/gi,  // Á (decomposed) hiding text
  severity: 'high',
  action: 'strip'
}
```

### Step 2: Add severity classification

Open `src/sanitizer/severity-classifier.ts` and add your pattern category to the correct severity level:

```typescript
case 'your_pattern_name':
  return 'CRITICAL';  // or HIGH, MEDIUM, LOW
```

### Step 3: Add framework mappings

Open `src/sanitizer/framework-mapper.ts` and add mappings for all four compliance frameworks:

```typescript
your_pattern_name: {
  owasp_llm: 'LLM01:2025 - Prompt Injection',
  nist_ai_600_1: 'MS-2.5 - Prompt Injection',
  mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
  iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
},
```

**How to choose mappings:**
- **OWASP LLM Top 10**: See [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- **NIST AI 600-1**: See [NIST AI 600-1 Controls](https://csrc.nist.gov/pubs/ai/600/1/final)
- **MITRE ATLAS**: See [MITRE ATLAS Tactics](https://atlas.mitre.org/)
- **ISO/IEC 42001**: Use Annex A controls (A.X.X format)

### Step 4: Add test cases

Open `tests/sanitizer.test.ts` and add at least two test cases:

**Positive case** (content that SHOULD be caught):
```typescript
it('should detect your_pattern_name', () => {
  const result = sanitize('Malicious content here that triggers pattern');
  expect(result.patterns_detected).toContain('your_pattern_name');
  expect(result.content_modified).toBe(true);
});
```

**Negative case** (legitimate content that should NOT be caught):
```typescript
it('should NOT flag legitimate content as your_pattern_name', () => {
  const result = sanitize('Legitimate content that looks similar but is safe');
  expect(result.patterns_detected).not.toContain('your_pattern_name');
  expect(result.content_modified).toBe(false);
});
```

**Why negative cases matter:** False positives erode trust. Always test that your pattern doesn't fire on legitimate content.

### Step 5: Run tests

```bash
npm test
```

All tests must pass (100% pass rate). If any tests fail, fix them before submitting.

### Step 6: Update SECURITY.md

Add your pattern to the appropriate severity section in `SECURITY.md` with an example:

```markdown
**XX. Your Pattern Name**
- **Example**: "Text that triggers the pattern"
- **Action**: Redact/Strip/Escape
```

---

## How to Report a False Positive

A **false positive** occurs when Visus incorrectly flags or redacts legitimate, non-malicious content. These are **high priority bugs** because they impact usability.

**To report a false positive:**

1. Open a **"False Positive Report"** issue using the GitHub issue template
2. Include:
   - The URL or content that triggered the false positive (sanitize if sensitive)
   - Which pattern category fired (visible in `patterns_detected` field)
   - What the expected behavior should be
   - Domain context (news site, documentation, health info, government, etc.)
3. **Do NOT include:**
   - Sensitive URLs or private content in public issues
   - Personally identifiable information

We take false positives seriously and will prioritize fixes.

---

## Development Setup

### Prerequisites

- **Node.js** 18+ and npm
- **Git** for version control
- **macOS / Windows**: No additional setup required
- **Linux**: Playwright requires system libraries (see README.md)

### Clone and Install

```bash
git clone https://github.com/visus-mcp/visus-mcp.git
cd visus-mcp
npm install
npm run build
npm test
```

**Note about Playwright:** The first run will download Chromium (~170MB). This is normal.

**Note about macOS iCloud:** If you use iCloud Drive, develop in `~/Projects`, NOT `~/Documents`. iCloud sync can interfere with node_modules.

---

## Running Tests

```bash
npm test                # Full test suite (all 274+ tests)
npm test -- --watch     # Watch mode for active development
npm test sanitizer      # Run sanitizer tests only
npm test -- --coverage  # Generate coverage report
```

**Test requirements:**
- All PRs must pass 100% of existing tests
- New functionality must include new tests
- Test count should never decrease
- Minimum 80% code coverage

---

## Security Vulnerability Reporting

**DO NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Visus (e.g., a way to bypass the sanitizer, extract PII, or compromise the system):

📧 **Email:** security@lateos.ai

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (optional)

We aim to respond within 48 hours and will work with you on a coordinated disclosure timeline (typically 90 days).

See [SECURITY.md](./SECURITY.md) for the full disclosure policy.

---

## Pull Request Process

### Before Opening a PR

1. **Fork the repo** and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with tests:
   - Write code following TypeScript strict mode
   - Add test cases for new functionality
   - Update documentation if needed

3. **Run the test suite**:
   ```bash
   npm test
   ```
   All tests must pass (100% success rate).

4. **Run the build**:
   ```bash
   npm run build
   ```
   TypeScript must compile cleanly with zero errors.

5. **Update STATUS.md** if adding a new feature:
   - Add your feature to the current version section
   - Use consistent formatting with existing entries

### Opening the PR

1. Push your branch to your fork
2. Open a PR against the `main` branch
3. Use the PR template and fill out all sections
4. Include a clear description of **what** changed and **why**
5. Reference any related issues (e.g., "Closes #123")

### PR Review Criteria

Your PR will be reviewed for:

- ✅ **Test coverage** — All existing tests pass, new tests added
- ✅ **TypeScript compliance** — No `any` types, strict mode passes
- ✅ **Security** — Sanitizer pipeline not bypassed
- ✅ **Documentation** — Code is well-commented and clear
- ✅ **Performance** — No significant latency regressions

**PRs that will NOT be merged:**
- ❌ Reduce test count or coverage
- ❌ Bypass the sanitizer pipeline
- ❌ Introduce `any` types or disable strict mode
- ❌ Break existing functionality

---

## Code Style

### TypeScript Conventions

- **TypeScript strict mode** — No `any` types allowed (use `unknown` if necessary)
- **Explicit return types** — All functions must declare return types
- **JSDoc comments** — All public functions must have JSDoc documentation
- **Error handling** — Never throw raw errors; return typed Result objects

### MCP Tool Registration

All new tools must register with proper MCP annotations:

```typescript
{
  name: 'tool_name',
  description: 'What this tool does',
  readOnlyHint: true,        // If tool doesn't modify state
  destructiveHint: false,    // If tool could cause data loss
  idempotentHint: true,      // If repeated calls have same effect
  openWorldHint: false       // If tool accesses external resources
}
```

### Logging

- **Structured JSON** to stderr only (never `console.log`)
- **Never log PII** — Use field redaction for sensitive data
- **Use timestamps** in ISO 8601 format

**Example:**
```typescript
console.error(JSON.stringify({
  timestamp: new Date().toISOString(),
  event: 'sanitization_completed',
  patterns_detected: ['role_hijacking'],
  content_modified: true
}));
```

---

## Recognition

Contributors who add validated injection patterns that are merged into the main branch will be credited in:

- **SECURITY.md** under "Community Patterns"
- **Release notes** for the version that includes their pattern
- **GitHub Contributors** page

We deeply appreciate the security research community's contributions to making Visus more robust.

---

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/visus-mcp/visus-mcp/discussions)
- **Bug reports**: Use the [Bug Report issue template](https://github.com/visus-mcp/visus-mcp/issues/new?template=bug_report.md)
- **Security issues**: Email security@lateos.ai (do NOT open public issues)

**Built with by Lateos**
