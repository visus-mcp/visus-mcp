export interface SequenceEvent {
  tool: string;
  args: unknown;
  timestamp: number;
  risk: number;
}

export class SequenceRiskLedger {
  private sequences: SequenceEvent[] = [];

  addEvent(event: SequenceEvent) {
    this.sequences.push(event);
  }

  getRiskScore() {
    // Stub: Basic LMG detection
    let score = 0;
    for (let i = 0; i < this.sequences.length - 1; i++) {
      if (this.sequences[i].tool === 'visus_fetch' && this.sequences[i+1].tool === 'visus_fetch_structured') {
        score += 0.3; // OAuth pivot pattern
      }
    }
    return score;
  }

  export() {
    return this.sequences;
  }
}

export const lmg = new SequenceRiskLedger();
