/**
 * ImmutableLedger - Tamper-Evident Session Logging for EU AI Act Compliance
 *
 * Extends VSIL with persistent Merkle tree-based audit trail.
 * Each event is hashed and added to a Merkle tree per session.
 * Supports inclusion proofs for audit verification.
 *
 * EU AI Act Art. 12 (Traceability) & Art. 19 (Transparency obligations)
 */

import { createHash } from 'crypto';
import { MerkleTree } from 'merkletreejs';
import { randomUUID } from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { SessionLedger, type HashedEntity, type SessionRiskSummary, type ThreatAnnotation } from '../security/session-ledger.js'; // Adjust path if needed

export interface LedgerEvent {
  request_id: string;
  session_id: string;
  timestamp: string; // ISO with ms
  url?: string;
  original_hash: string; // SHA-256 of raw input
  sanitization_steps: string[];
  threats_detected: { pattern_id: string; severity: string; snippet_hash: string }[];
  pii_redacted_count: number;
  pii_types: string[];
  cleaned_hash: string; // SHA-256 of final output
  visus_proof: string; // Existing HMAC
  human_review_flag: boolean;
  human_reviewer_id?: string;
  model_output_hash?: string;
  tool_name?: string;
  // VSIL integration
  entities?: HashedEntity[];
  risk_summary?: SessionRiskSummary;
  new_threats?: ThreatAnnotation[];
}

export interface InclusionProof {
  leaf: string;
  siblings: string[];
  path: number[]; // 0 left, 1 right
  root: string;
}

interface SessionTree {
  session_id: string;
  events: LedgerEvent[];
  merkle_root: string;
  tree: MerkleTree;
  last_updated: number;
  file_path: string;
}

export class ImmutableLedger extends SessionLedger {
  private trees: Map<string, SessionTree> = new Map();
  private ledger_path: string;
  private enabled: boolean;
  private merkle_algo: 'sha256' | 'keccak256' = 'sha256';
  private retention_months: number = 12; // GDPR default

  constructor() {
    super();
    this.enabled = process.env.VISUS_LEDGER_ENABLED !== 'false';
    this.ledger_path = process.env.VISUS_LEDGER_PATH || path.join(process.cwd(), 'audit');
    this.merkle_algo = (process.env.VISUS_MERKLE_ALGO as any) || 'sha256';
    // Ensure directory
    // fs.mkdir(this.ledger_path, { recursive: true }); // Async, call on init if needed
  }

  private sha256(data: string | Buffer): string {
    return createHash('sha256').update(data).digest('hex');
  }

  private async getOrCreateTree(sessionId: string): Promise<SessionTree> {
    let treeData = this.trees.get(sessionId);
    if (!treeData) {
      const dateStr = new Date().toISOString().split('T')[0];
      const filePath = path.join(this.ledger_path, `ledger-${dateStr}.jsonl`);
      // Load existing events from file if exists
      const events: LedgerEvent[] = [];
      try {
        const content = await fs.readFile(filePath, 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        for (const line of lines) {
          const event = JSON.parse(line);
          if (event.session_id === sessionId) {
            events.push(event);
          }
        }
      } catch (err) {
        // File not exist, start new
      }
      const leafHashes = events.map(e => this.sha256(JSON.stringify(e)));
      const tree = new MerkleTree(leafHashes, this.sha256, { sortPairs: true });
      treeData = {
        session_id: sessionId,
        events,
        merkle_root: tree.getRoot()?.toString('hex') || '',
        tree,
        last_updated: Date.now(),
        file_path: filePath,
      };
      this.trees.set(sessionId, treeData);
    }
    return treeData;
  }

  async addEvent(sessionId: string, event: Omit<LedgerEvent, 'request_id' | 'timestamp'> & { url?: string; tool_name?: string; }): Promise<{ merkle_root: string; proof: InclusionProof }> {
    if (!this.enabled) {
      return { merkle_root: '', proof: { leaf: '', siblings: [], path: [], root: '' } };
    }

    const fullEvent: LedgerEvent = {
      request_id: randomUUID(),
      session_id,
      timestamp: new Date().toISOString(),
      ...event,
      human_review_flag: false,
    };

    const treeData = await this.getOrCreateTree(sessionId);
    const eventHash = this.sha256(JSON.stringify(fullEvent));
    treeData.tree.addLeaf(eventHash);
    treeData.events.push(fullEvent);
    treeData.merkle_root = treeData.tree.getRoot()?.toString('hex') || '';
    treeData.last_updated = Date.now();

    // Append to JSONL file
    const line = JSON.stringify(fullEvent) + '\n';
    await fs.appendFile(treeData.file_path, line);

    // Save Merkle index? For now, tree is in memory, persist tree separately if needed

    // Generate proof for this leaf
    const index = treeData.events.length - 1;
    const proof = treeData.tree.getProof(eventHash, index);
    const path = []; // Simplified, compute path if needed
    const inclusionProof: InclusionProof = {
      leaf: eventHash,
      siblings: proof.map(p => p.toString('hex')),
      path, // Implement path calculation using tree internals if needed
      root: treeData.merkle_root,
    };

    this.trees.set(sessionId, treeData);

    // Integrate with VSIL update
    const hashes = event.entities?.map(e => e.hash) || [];
    this.update(sessionId, hashes, event.tool_name || 'unknown', event.new_threats || []);

    return { merkle_root: treeData.merkle_root, proof: inclusionProof };
  }

  async getProof(requestId: string): Promise<LedgerEvent & { proof: InclusionProof }> {
    if (!this.enabled) return null as any;

    // Scan all trees/files for request_id - inefficient for prod, use index/DB in future
    for (const [sid, treeData] of this.trees) {
      const event = treeData.events.find(e => e.request_id === requestId);
      if (event) {
        const index = treeData.events.indexOf(event);
        const eventHash = this.sha256(JSON.stringify(event));
        const proof = treeData.tree.getProof(eventHash, index);
        event.proof = {
          leaf: eventHash,
          siblings: proof.map(p => p.toString('hex')),
          path: [], // TODO: compute
          root: treeData.merkle_root,
        };
        return event as any;
      }
    }
    // Scan files if not in memory
    const dateStr = new Date().toDateString().split(' ').slice(1).join('-'); // Approx
    // Implement file scan...
    return null as any;
  }

  async verifyProof(proof: InclusionProof, eventData: LedgerEvent): Promise<boolean> {
    const leaf = this.sha256(JSON.stringify(eventData));
    if (leaf !== proof.leaf) return false;

    // Reconstruct root from proof (MerkleTree has verify method)
    const leaves = [Buffer.from(leaf, 'hex')]; // Dummy leaves
    const tree = new MerkleTree(leaves, this.sha256);
    return tree.verify(proof.siblings.map(s => Buffer.from(s, 'hex')), Buffer.from(leaf, 'hex'), Buffer.from(proof.root, 'hex'), /* path */ 0);
  }

  // Retention policy: purge old files
  async purgeOldLedgers(): Promise<void> {
    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - this.retention_months);
    const cutoffStr = cutoff.toISOString().split('T')[0];
    const files = await fs.readdir(this.ledger_path);
    for (const file of files) {
      if (file.startsWith('ledger-') && file.endsWith('.jsonl')) {
        const dateMatch = file.match(/ledger-(\d{4}-\d{2}-\d{2})/);
        if (dateMatch && dateMatch[1] < cutoffStr) {
          await fs.unlink(path.join(this.ledger_path, file));
        }
      }
    }
  }

  // Call periodically
  startRetentionSweep(intervalMs: number = 24 * 60 * 60 * 1000): void { // Daily
    setInterval(() => this.purgeOldLedgers(), intervalMs);
  }
}

export default ImmutableLedger;

/**
 * Export Ledger Events for Compliance/Audit
 * @param sessionId - Session to export
 * @param outputPath - File path for JSONL export
 * @returns Promise with exported file path and stats
 */
export async function exportLedger(sessionId: string, outputPath: string = path.join(process.env.VISUS_LEDGER_PATH || './audit', `export-${sessionId}-${Date.now()}.jsonl`)): Promise<{ file: string; eventCount: number; merkleRoots: string[]; }> {
  const ledger = new ImmutableLedger();
  if (!ledger.enabled) throw new Error('Ledger disabled');
  
  const treeData = await getOrCreateTree.call(ledger, sessionId); // Internal access (adjust visibility if needed)
  if (!treeData || treeData.events.length === 0) throw new Error('No events for session');
  
  const exportEvents = treeData.events.map(event => ({
    ...event,
    proof: await ledger.getProof(event.request_id) // Attach full proof
  }));
  
  const content = exportEvents.map(e => JSON.stringify(e)).join('\n') + '\n';
  await fs.writeFile(outputPath, content, 'utf8');
  
  // Stats
  const merkleRoots = treeData.tree.getMerkleRoots ? treeData.tree.getMerkleRoots() : [treeData.merkle_root]; // If MMR
  
  return {
    file: outputPath,
    eventCount: exportEvents.length,
    merkleRoots: merkleRoots.map(r => r.toString('hex'))
  };
}
