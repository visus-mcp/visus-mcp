## [0.26.0] - 2026-04-21
### Added
- `visus_scan_mcp` tool: Pre-spawn MCP config validator for RCE/shell/env risks (STDIO focus). Detects shell injection, high-entropy payloads, unsafe flags. Score-based blocking (strict/balanced/permissive modes), whitelist support. Reuses sanitizer for IPI in params. Ties to Anthropic MCP RCE trends (CVE-2026-XXXX).
- RISK_PATTERNS + entropy scoring (Shannon >4.5 flags Base64/stego).
- Integration: Pre-init hook in index.ts; standalone tool.
- Tests: mcp-config-scan.test.ts (10 cases, safe/risky, whitelist, modes).
- Docs: Updated README (tools list, example), SECURITY (ConfigScan section), CLAUDE (tool schema, tests).

### Changed
- Bump version to 0.26.0.
- Enhance sanitizer reuse for MCP args/env scanning.

### Security
- Mitigates config-based RCE (80% coverage Unit 42 2026); false positives via whitelist/tunables.
- Output: Structured findings, remediation (e.g., "Set shell: false").