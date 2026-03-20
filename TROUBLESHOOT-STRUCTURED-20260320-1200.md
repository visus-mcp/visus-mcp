# Visus MCP visus_fetch_structured Null Extraction Bug - Troubleshooting Log

Started: 2026-03-20 12:00
Goal: Fix null extraction issue in visus_fetch_structured tool

---

## [12:00:00] Step 1 - Document Symptom

**Goal:** Capture observed behavior from smoke test
**Reasoning:** Need baseline before debugging
**Action:** Review Test 4 results from Claude Desktop
**Result:**
```json
{
  "data": {
    "page_title": null,
    "main_paragraph": null,
    "link_url": null
  },
  "sanitization": {
    "patterns_detected": [],
    "content_modified": false
  },
  "metadata": {
    "content_length_original": 139,
    "content_length_sanitized": 0
  }
}
```
**Observations:**
- All schema fields returned null
- content_length_original: 139 bytes (vs 528 for visus_fetch on same URL)
- content_length_sanitized: 0
- metadata.title: "Example Domain" (proves page was fetched)
**Status:** ✅ Success - Symptom documented

---

## [12:01:00] Step 2 - Analyze Implementation

**Goal:** Understand data flow from fetch to extraction
**Reasoning:** Need to trace where content gets lost
**Action:** Read src/tools/fetch-structured.ts
**Result:**

**Key code sections:**
```typescript
// Line 90: Uses text format
format: 'text'

// Line 97-98: Extracts text field
const { title, text } = renderResult.value;
const rawContent = text || '';  // rawContent = 139 bytes of plain text

// Line 101: Calls extractor
const extractedData = extractStructuredData(rawContent, schema);
```

**Status:** ✅ Success - Data flow mapped

---

## [12:02:00] Step 3 - Check Text Extraction Process

**Goal:** Determine what "text" format produces
**Reasoning:** Need to understand why content is only 139 bytes vs 528 bytes
**Action:** Review playwright-renderer.ts extractText() function
**Result:**
```typescript
function extractText(html: string): string {
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove scripts
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '') // Remove styles
    .replace(/<[^>]+>/g, '') // Remove all HTML tags
    .replace(/\s+/g, ' ') // Collapse whitespace
    .trim();
}
```

**For example.com HTML (528 bytes):**
```html
<!doctype html><html><head><title>Example Domain</title>...
<h1>Example Domain</h1>
<p>This domain is for use in documentation...</p>
<a href="https://iana.org/domains/example">Learn more</a>
```

**After extractText() (139 bytes):**
```
Example Domain This domain is for use in documentation examples without needing permission. Avoid use in operations. Learn more
```

**Key finding:** ALL HTML structure removed, including:
- `<h1>` tags (needed to identify headings)
- `<p>` tags (needed to identify paragraphs)
- `<a href>` attributes (needed to extract link URLs)

**Status:** ✅ Success - Text stripping identified

---

## [12:03:00] Step 4 - Analyze extractStructuredData() Function

**Goal:** Understand extraction logic and why it fails
**Reasoning:** Need to see what patterns the extractor looks for
**Action:** Review fetch-structured.ts lines 22-64
**Result:**

**Extraction logic:**
1. Regex search for `(fieldName|description)\s*[:=]?\s*([^\n]+)`
2. Falls back to line-by-line search for field name
3. Looks for key-value pairs split by `:` or `=`

**Example patterns it WOULD match:**
```
page_title: Example Domain
main_paragraph = This domain is for use...
link_url: https://example.com
```

**What it receives from example.com:**
```
Example Domain This domain is for use in documentation examples without needing permission. Avoid use in operations. Learn more
```

**Result:** No key-value structure → no regex matches → all fields return null

**Status:** ✅ Success - Extraction failure explained

---

## [12:04:00] Step 5 - Identify Root Causes

**Goal:** Summarize why extraction fails
**Reasoning:** Need to document fundamental issues before proposing fix
**Action:** Analyze Phase 1 design constraints
**Result:**

**Root Cause 1: Format Mismatch**
- Structured extraction uses `format: 'text'`
- Text format strips ALL HTML tags and attributes
- Cannot extract link URLs (href stripped)
- Cannot identify structure (h1, p tags stripped)

**Root Cause 2: Naive Extraction Algorithm**
- extractStructuredData() only looks for key-value patterns
- Cannot understand semantic meaning ("main heading", "first paragraph")
- Cannot parse HTML structure
- Works for: JSON-like text, YAML, INI files
- Fails for: Web pages, prose content, any unstructured text

**Root Cause 3: Phase 1 Known Limitation**
Per fetch-structured.ts:18-20:
```
* Phase 1: Basic pattern matching
* Phase 2+: LLM-powered extraction with Bedrock
```

**Status:** ✅ Success - Root causes documented

---

## [12:05:00] Step 6 - Evaluate Fix Options

**Goal:** Determine best approach for Phase 1
**Reasoning:** Need to balance functionality vs scope creep
**Action:** Consider alternatives

**Option A: Do Nothing**
- Mark as known Phase 1 limitation
- Document in STATUS.md
- Wait for Phase 2 LLM-powered extraction
- ❌ Leaves tool completely non-functional

**Option B: Add HTML Parser**
- Use cheerio or jsdom
- Parse HTML structure
- Extract headings, paragraphs, links properly
- ✅ Would work for basic HTML extraction
- ⚠️ Adds dependency, increases scope

**Option C: Hybrid Approach**
- Keep current text-based extraction for key-value content
- Add basic HTML parsing for common patterns (h1, p, a[href])
- Fall back to simple heuristics (first line = title, etc.)
- ✅ Improves functionality without full rewrite
- ⚠️ Still limited compared to LLM extraction

**Option D: Add Note to Tool Description**
- Keep current implementation
- Update tool description to clarify limitations
- Add example of what kind of data it works with
- ✅ Honest about capabilities
- ❌ Doesn't fix the issue

**Recommendation:** Option B (Add HTML Parser)
- Cheerio is lightweight (~500KB)
- Industry standard for HTML parsing
- Enables proper semantic extraction
- Still simpler than full Playwright + LLM

**Status:** ✅ Success - Fix options evaluated

---

## [12:06:00] Step 7 - Implement Fix with cheerio

**Goal:** Add HTML parsing capability to structured extraction
**Reasoning:** Option B provides best balance of functionality and complexity
**Action:** Install cheerio and update extractStructuredData()
**Result:** (to be implemented)
**Status:** ⏸️ Pending decision

---

# ROOT CAUSE SUMMARY

**Issue:** visus_fetch_structured returns null for all schema fields

**Root Causes:**
1. **Text extraction strips HTML structure** - format='text' removes all tags/attributes needed for semantic extraction
2. **Naive pattern matching** - extractStructuredData() only finds key-value pairs, cannot understand "extract the main heading"
3. **Phase 1 design limitation** - Documented as needing LLM-powered extraction in Phase 2

**Impact:**
- Tool is non-functional for extracting data from typical web pages
- Only works for structured text formats (JSON-like, key-value)
- Cannot extract link URLs, headings, or semantic content

**Recommendation:**
Add cheerio HTML parser to enable basic semantic extraction:
- Parse HTML structure
- Extract headings (<h1>, <h2>)
- Extract paragraphs (<p>)
- Extract links (<a href>)
- Apply sanitization to extracted values
- Maintain security-first design

**Alternative:**
Document as Phase 1 limitation and wait for Phase 2 LLM extraction

---

**Status:** 🔍 Analysis complete, awaiting fix decision
**Total Time:** 6 minutes
