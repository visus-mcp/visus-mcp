# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.0] - 2026-04-02

### Added

- **Glassworm Malware Detection** (`src/sanitizer/injection-detector.ts`)
  - Specialized detection for steganographic attacks using invisible Unicode Variation Selectors
  - Detects clusters of 3+ consecutive Unicode Variation Selectors (U+FE00-FE0F, U+E0100-E01EF)
  - Decoder pattern detection: identifies `.codePointAt()` within 500 characters of hex constants (0xFE00, 0xE0100)
  - Automatic severity escalation: clusters of 10+ characters marked as CRITICAL
  - Intelligent filtering: ignores single selectors (legitimate emoji usage)
  - New functions: `detectGlassworm()`, `detectDecoderPattern()`, `stripUnicodeVariationSelectors()`
  - Full integration into `detectAndNeutralize()` pipeline

- **Glassworm Pattern** (`src/sanitizer/patterns.ts`)
  - New `glassworm_unicode_clusters` pattern for regex-based detection
  - Severity: HIGH, Action: STRIP
  - Prevents steganographic payload injection attacks

### Tests

- Added 14 comprehensive Glassworm detection tests (`tests/sanitizer.test.ts`)
  - Unicode cluster detection (various sizes)
  - Decoder pattern proximity detection
  - Severity classification (HIGH vs CRITICAL)
  - Real-world Glassworm attack scenarios
  - False positive prevention (legitimate emoji usage)
  - Test count increased from 437 to 451 tests
  - 100% pass rate

### Security

- **Steganographic Attack Prevention**: Blocks Glassworm-style attacks that hide malicious payloads in invisible Unicode characters
- **Zero False Positives**: Legitimate single variation selector usage (emojis) preserved
- **Critical Threat Detection**: Large clusters (10+) automatically escalated to CRITICAL severity

## [0.12.0] - 2026-03-30

### Added

- **Token Metrics Feature** (`src/utils/tokenMetrics.ts`)
  - Real-time token reduction statistics displayed in every tool response
  - Shows before/after token counts, reduction percentage, threats blocked, and elapsed time
  - Visual metrics header box using Unicode box-drawing characters for clear visibility
  - Appears automatically in all content-returning tools: `visus_fetch`, `visus_fetch_structured`, `visus_read`, `visus_search`
  - Example output: `4,200 → 890 tokens · 79% reduction · 3 threats blocked · fetch 1.2s`
  - Character-based token estimation using GPT-family approximation (chars / 4)
  - New optional `content` field in `VisusFetchStructuredOutput` and `VisusSearchOutput` for human-readable display

- **VISUS_SHOW_METRICS Environment Variable**
  - Set `VISUS_SHOW_METRICS=false` to disable metrics header display
  - Defaults to `true` (metrics shown by default)
  - Allows users to opt out of metrics display if preferred

### Changed

- **Tool Response Format** - All content-returning tools now prepend token metrics header when enabled
- **Type Definitions** (`src/types.ts`)
  - Added optional `content?: string` field to `VisusFetchStructuredOutput` for human-readable representation
  - Added optional `content?: string` field to `VisusSearchOutput` for formatted search results with metrics

### Tests

- Added comprehensive unit tests for token estimation, metrics calculation, and header formatting (`src/utils/__tests__/tokenMetrics.test.ts`)
- Added integration smoke tests verifying metrics appear in all 4 content-returning tools (`tests/token-metrics-integration.test.ts`)
- Verified `visus_report` and `visus_verify` tools do NOT include metrics (as intended)
- Test count increased from 391 to 420+ tests

## [0.9.0] - 2026-03-26

### Added

- **NIST AI RMF Framework Mappings** (`src/sanitizer/framework-mapper.ts`)
  - Added NIST AI Risk Management Framework (AI 100-1) mappings for all 43 injection patterns
  - Maps threats to four core functions: GOVERN, MAP, MEASURE, and MANAGE
  - Examples: GOVERN-1.1 (Legal Requirements), MEASURE-2.7 (AI System Security), MANAGE-2.3 (Respond to Unknown Risks)
  - Provides comprehensive risk management alignment for federal/government users

- **NIST CSF 2.0 Framework Mappings** (`src/sanitizer/framework-mapper.ts`)
  - Added NIST Cybersecurity Framework 2.0 mappings for all 43 injection patterns
  - Maps threats to six core functions: IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, and GOVERN
  - Examples: DE.CM-01 (Network Monitoring), PR.DS-01 (Data at Rest Protection), PR.AC-04 (Access Control)
  - Widely adopted enterprise cybersecurity framework for compliance and audit requirements

- **Enhanced Threat Reporting** (`src/sanitizer/threat-reporter.ts`)
  - Expanded framework coverage from 4 to 6 compliance frameworks
  - Updated TOON format from 10 fields to 12 fields (added nist_ai_rmf, nist_csf_2_0)
  - Enhanced Markdown threat report table with new AI-RMF and CSF 2.0 columns
  - All threat reports now include comprehensive 6-framework alignment

### Changed

- **Framework Badge** (README.md) - Updated security badge to highlight NIST AI RMF and CSF 2.0
- **Tool Descriptions** (README.md) - All 4 MCP tools now reference 6 frameworks in their descriptions
- **Framework Alignments Section** (README.md) - Expanded to document all 6 frameworks with descriptions
- **Test Coverage** (tests/threat-reporter.test.ts) - Updated to verify 6 frameworks and 12 TOON fields

### Fixed

- **server.json Version Sync** - Ensured server.json version matches package.json per MCP Registry requirements

## [0.8.1] - 2026-03-25

### Added

- **PDF Content Handler** (`src/content-handlers/pdf-handler.ts`)
  - Handles `application/pdf` content type
  - Extracts text and metadata (title, author, subject, keywords, creator, producer) from PDF files
  - Passes all extracted text through the 43-pattern injection detection pipeline
  - Returns sanitized plain text, discarding binary objects
  - Returns structured error (`PDF_PARSE_FAILED`) for corrupt or encrypted PDFs

- **JSON Content Handler** (`src/content-handlers/json-handler.ts`)
  - Handles `application/json` and `text/json` content types
  - Recursively traverses JSON object tree and sanitizes all string values
  - Preserves original JSON structure in output
  - Handles arrays, nested objects, and mixed-type arrays correctly
  - Falls back to plain text sanitization pipeline if JSON parsing fails
  - Tracks and reports count of sanitized fields per request

- **SVG Content Handler** (`src/content-handlers/svg-handler.ts`)
  - Handles `image/svg+xml` content type
  - Strips dangerous elements unconditionally:
    - `<script>` elements and all children
    - `<use>` elements with external `href`/`xlink:href` attributes
    - `<foreignObject>` elements and all children
    - All event handler attributes (onload, onclick, onerror, etc.)
    - `<set>` and `<animate>` elements referencing external resources
    - `data:` URI attributes
  - Extracts and scans text content (title, desc, text elements) for injection patterns
  - Preserves safe presentation attributes (fill, stroke, transform, viewBox, etc.)
  - Returns structured error (`SVG_PARSE_FAILED`) if XML parsing fails

- **Content Type Routing** (`src/content-handlers/index.ts`)
  - Central routing system for content-type specific handlers
  - Normalizes MIME types (strips parameters, lowercases)
  - Routes content to appropriate handler based on MIME type
  - Returns structured rejection (`UNSUPPORTED_CONTENT_TYPE`) for unsupported types
  - No unhandled exceptions - all errors return structured responses

- **Updated `visus_fetch` Tool** (`src/tools/fetch.ts`)
  - Integrated content handler routing for PDF, JSON, and SVG
  - Checks Content-Type header and routes to specialized handlers before existing HTML/XML flow
  - Maintains backward compatibility with existing HTML/XML/RSS conversion logic

- **Comprehensive Test Suite** (`tests/content-handlers.test.ts`)
  - 20 test cases covering all three handlers
  - Tests for clean content (no false positives)
  - Tests for injection detection and sanitization
  - Tests for error handling (corrupt/invalid content)
  - Tests for edge cases (nested structures, arrays, malformed input)

### Fixed

- **PDF Text Extraction** - Fixed critical bug where PDF content was passed as corrupted UTF-8 strings instead of binary data
  - Root cause: `response.text()` in `playwright-renderer.ts` converted all response bodies to strings, mangling binary PDFs
  - Fix: Use `response.arrayBuffer()` for binary content types (`application/pdf`, `image/*`, `application/octet-stream`)
  - Impact: PDF handler now receives proper binary data, text extraction works correctly
  - Files modified: `src/types.ts`, `src/browser/playwright-renderer.ts`, `src/tools/fetch.ts`, `src/tools/read.ts`, `src/tools/fetch-structured.ts`
  - Note: Some complex PDFs may fail with "Invalid Root reference" error - this is a limitation of the pdf-parse library, not Visus

### Changed

- Added `pdf-parse` dependency (v2.4.5) for PDF text extraction
- Updated `BrowserRenderResult.html` type to `string | Buffer` to support binary content

## [0.6.2] - 2026-03-14

Previous releases documented in git history.
