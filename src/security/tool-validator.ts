/**
 * Tool Validator - Detects tool poisoning attacks in MCP descriptors and schemas
 *
 * Scans for anomalous names, IPI in descriptions, schema poisoning, and provides pinning.
 */

import { INJECTION_PATTERNS } from '../sanitizer/patterns.js';
import { detectAndNeutralize, type DetectionResult as SanitizeResult } from '../sanitizer/injection-detector.js';
import crypto from 'crypto';

export interface ToolRisk {
  pattern: string;
  location: string; // 'name', 'description', 'schema.properties', etc.
  snippet: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ValidationResult {
  isValid: boolean;
  risks: ToolRisk[];
  sanitized: any; // Sanitized tool definition
  pinnedHash?: string; // Expected hash if pinned
  hashMismatch?: boolean;
}

const TOOL_PINNED_HASHES: Record<string, string> = {
  // Load from package.json or registry (MVP: hardcode known tools)
  'visus_fetch': 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // Example hash
  'visus_fetch_structured': 'sha256:d41d8cd98f00b204e9800998ecf8427e', // Example
  // Add more from known tools
};

const ANOMALOUS_NAME_REGEX = /[^a-zA-Z0-9_-]|^(ignore|actas|override|bypass)/i;
const INSTRUCTION_IN_DESC_REGEX = /\b(ignore|act\s+as|override|system\s+prompt)\b/i;

export function computeSchemaHash(toolDef: any): string {
  const schemaStr = JSON.stringify(toolDef, Object.keys(toolDef).sort());
  return crypto.createHash('sha256').update(schemaStr).digest('hex');
}

export function validateToolDescriptor(descriptor: any, name?: string): ValidationResult {
  const risks: ToolRisk[] = [];
  let sanitized = { ...descriptor };
  let hashMismatch = false;

  // 1. Anomalous name check
  if (name && ANOMALOUS_NAME_REGEX.test(name)) {
    risks.push({
      pattern: 'anomalous_tool_name',
      location: 'name',
      snippet: name,
      severity: 'high'
    });
  }

  // 2. Pinning check if known tool
  if (name && TOOL_PINNED_HASHES[name]) {
    const currentHash = computeSchemaHash(descriptor);
    if (currentHash !== TOOL_PINNED_HASHES[name]) {
      hashMismatch = true;
      risks.push({
        pattern: 'schema_hash_mismatch',
        location: 'pinned',
        snippet: `Expected: ${TOOL_PINNED_HASHES[name].substring(0, 16)}... Got: ${currentHash.substring(0, 16)}...`,
        severity: 'critical'
      });
    }
  }

  // 3. Description scan for IPI
  if (sanitized.description) {
    const descResult: SanitizeResult = detectAndNeutralize(sanitized.description);
    if (descResult.patterns_detected.length > 0 || INSTRUCTION_IN_DESC_REGEX.test(sanitized.description)) {
      risks.push({
        pattern: 'instruction_in_description',
        location: 'description',
        snippet: sanitized.description.substring(0, 100) + '...',
        severity: 'high'
      });
      sanitized.description = '[REDACTED: potential poisoning]';
    }
  }

  // 4. Schema poisoning: scan properties for long defaults, comments (JSON no comments, but check values)
  if (sanitized.inputSchema?.properties) {
    Object.entries(sanitized.inputSchema.properties).forEach(([prop, schema]) => {
      if (typeof schema === 'object' && schema.default && typeof schema.default === 'string' && schema.default.length > 256) {
        risks.push({
          pattern: 'long_default_value',
          location: `schema.properties.${prop}.default`,
          snippet: schema.default.substring(0, 100) + '...',
          severity: 'medium'
        });
        // Sanitize default
        (schema as any).default = '[REDACTED: long default]';
      }
      // Scan default for IPI
      if (schema.default && typeof schema.default === 'string') {
        const defaultResult: SanitizeResult = detectAndNeutralize(schema.default);
        if (defaultResult.patterns_detected.length > 0) {
          risks.push({
            pattern: 'ipi_in_default',
            location: `schema.properties.${prop}.default`,
            snippet: schema.default.substring(0, 50) + '...',
            severity: 'high'
          });
          (schema as any).default = '[REDACTED: IPI detected]';
        }
      }
    });
  }

  // 5. Additional tool poisoning patterns (e.g., anomalous types, hidden params)
  if (sanitized.inputSchema?.properties) {
    const propNames = Object.keys(sanitized.inputSchema.properties);
    if (propNames.some(p => p.includes('__') || p.startsWith('_'))) {
      risks.push({
        pattern: 'hidden_param_names',
        location: 'schema.properties',
        snippet: propNames.join(', '),
        severity: 'medium'
      });
    }
  }

  const isValid = risks.length === 0 && !hashMismatch;
  const pinnedHash = name ? TOOL_PINNED_HASHES[name] : undefined;

  return { isValid, risks, sanitized, pinnedHash, ...(pinnedHash && { hashMismatch }) };
}

// Load pins from external source (MVP function)
export function loadPinnedHashes(): Record<string, string> {
  // In prod: fetch from secure registry or package.json
  return TOOL_PINNED_HASHES;
}

// Graceful degradation: stub if invalid
export function createStubTool(name: string): any {
  return {
    name: `${name}_stub`,
    description: 'Tool blocked due to poisoning risks. Use safe alternative.',
    inputSchema: { type: 'object', properties: {} }
  };
}
