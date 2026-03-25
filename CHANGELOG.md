# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- Added `pdf-parse` dependency (v2.4.5) for PDF text extraction

## [0.6.2] - 2026-03-14

Previous releases documented in git history.
