/**
 * Format Converter - Content-Type based format detection and conversion
 *
 * Handles format-appropriate conversion based on detected Content-Type.
 * Supports HTML, JSON, XML, and RSS/Atom feeds.
 */

import { XMLParser } from 'fast-xml-parser';

/**
 * Detected format type
 */
export type FormatType = 'html' | 'json' | 'xml' | 'rss';

/**
 * Detect format from Content-Type header
 *
 * @param contentType - Content-Type header value (e.g., "application/json", "text/html; charset=utf-8")
 * @returns Detected format type
 */
export function detectFormat(contentType: string): FormatType {
  // Normalize: lowercase and extract MIME type (before semicolon)
  const mimeType = contentType.toLowerCase().split(';')[0].trim();

  // HTML formats
  if (mimeType === 'text/html' || mimeType === 'application/xhtml+xml') {
    return 'html';
  }

  // JSON formats
  if (mimeType === 'application/json' || mimeType === 'text/json') {
    return 'json';
  }

  // RSS/Atom feed formats
  if (mimeType === 'application/rss+xml' ||
      mimeType === 'application/atom+xml' ||
      mimeType === 'application/feed+json') {
    return 'rss';
  }

  // XML formats (must come after RSS check)
  if (mimeType === 'application/xml' || mimeType === 'text/xml') {
    return 'xml';
  }

  // Default to HTML for unknown types
  return 'html';
}

/**
 * Convert JSON content to formatted string
 *
 * @param raw - Raw JSON string
 * @returns Formatted JSON string with prefix, or raw string if parse fails
 */
export function convertJson(raw: string): string {
  try {
    // Parse and re-stringify with 2-space indent for readability
    const parsed = JSON.parse(raw);
    const formatted = JSON.stringify(parsed, null, 2);
    return `JSON Response:\n\n${formatted}`;
  } catch (error) {
    // Parse failed, return raw string unchanged
    return raw;
  }
}

/**
 * Convert XML content to clean text representation
 *
 * @param raw - Raw XML string
 * @returns Formatted XML representation with prefix, or tag-stripped fallback if parse fails
 */
export function convertXml(raw: string): string {
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      ignoreDeclaration: true,
      ignorePiTags: true,
      removeNSPrefix: true,
    });

    const parsed = parser.parse(raw);
    const formatted = JSON.stringify(parsed, null, 2);

    return `XML Response:\n\n${formatted}`;
  } catch (error) {
    // Parse failed, strip XML tags using regex and return
    const stripped = raw.replace(/<[^>]+>/g, '').trim();
    return `XML Response:\n\n${stripped}`;
  }
}

/**
 * Convert RSS/Atom feed content to clean Markdown
 *
 * @param raw - Raw RSS/Atom XML string
 * @returns Formatted Markdown representation, or falls back to convertXml if parse fails
 */
export function convertRss(raw: string): string {
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      removeNSPrefix: true,
    });

    const parsed = parser.parse(raw);

    // Handle RSS 2.0 format
    if (parsed.rss && parsed.rss.channel) {
      return formatRss2(parsed.rss.channel);
    }

    // Handle Atom format
    if (parsed.feed) {
      return formatAtom(parsed.feed);
    }

    // Handle RSS 1.0 (RDF) format
    if (parsed.rdf && parsed.rdf.channel) {
      return formatRss2(parsed.rdf.channel);
    }

    // Unknown feed format, fall back to XML
    return convertXml(raw);

  } catch (error) {
    // Parse failed, fall back to XML converter
    return convertXml(raw);
  }
}

/**
 * Format RSS 2.0 feed data as Markdown
 */
function formatRss2(channel: any): string {
  const title = channel.title || 'Untitled Feed';
  const description = channel.description || '';
  const items = Array.isArray(channel.item) ? channel.item : (channel.item ? [channel.item] : []);

  let markdown = `RSS Feed:\n\n# ${title}\n`;

  if (description) {
    markdown += `${description}\n`;
  }

  markdown += '\n## Items\n\n';

  // Extract up to 10 items
  const itemsToShow = items.slice(0, 10);

  for (const item of itemsToShow) {
    const itemTitle = item.title || 'Untitled';
    const itemLink = item.link || '';
    const itemDescription = item.description || '';
    const itemPubDate = item.pubDate || '';

    // Truncate description to 200 chars
    const truncatedDesc = itemDescription.length > 200
      ? itemDescription.substring(0, 200) + '...'
      : itemDescription;

    markdown += `### ${itemTitle}\n\n`;

    if (truncatedDesc) {
      markdown += `${truncatedDesc}\n\n`;
    }

    if (itemLink) {
      markdown += `Link: ${itemLink}\n`;
    }

    if (itemPubDate) {
      markdown += `Published: ${itemPubDate}\n`;
    }

    markdown += '\n---\n\n';
  }

  return markdown;
}

/**
 * Format Atom feed data as Markdown
 */
function formatAtom(feed: any): string {
  const title = feed.title || 'Untitled Feed';
  const subtitle = feed.subtitle || '';
  const entries = Array.isArray(feed.entry) ? feed.entry : (feed.entry ? [feed.entry] : []);

  let markdown = `RSS Feed:\n\n# ${title}\n`;

  if (subtitle) {
    markdown += `${subtitle}\n`;
  }

  markdown += '\n## Items\n\n';

  // Extract up to 10 entries
  const entriesToShow = entries.slice(0, 10);

  for (const entry of entriesToShow) {
    const entryTitle = entry.title || 'Untitled';
    const entryLink = entry.link ? (entry.link['@_href'] || entry.link) : '';
    const entrySummary = entry.summary || entry.content || '';
    const entryPublished = entry.published || entry.updated || '';

    // Truncate summary to 200 chars
    const truncatedSummary = entrySummary.length > 200
      ? entrySummary.substring(0, 200) + '...'
      : entrySummary;

    markdown += `### ${entryTitle}\n\n`;

    if (truncatedSummary) {
      markdown += `${truncatedSummary}\n\n`;
    }

    if (entryLink) {
      markdown += `Link: ${entryLink}\n`;
    }

    if (entryPublished) {
      markdown += `Published: ${entryPublished}\n`;
    }

    markdown += '\n---\n\n';
  }

  return markdown;
}
