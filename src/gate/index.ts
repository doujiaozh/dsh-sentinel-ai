/**
 * sentinel_gate - System 1 (Jev-style instant router).
 *
 * Contract: never blocks, never calls a big model. Local heuristics always
 * run (microseconds). A Jev API verdict, when configured, is merged in with a
 * "danger wins" policy. Output is the strongly typed GateVerdict.
 */

import type { GateVerdict, RuleHit } from '../types';
import { parseUnifiedDiff } from '../util/diff';
import { decide, gateConfidence, heuristicScan } from './heuristics';
import { JevClient, type JevOptions } from './jev-client';

export type { JevOptions } from './jev-client';

export interface GateOptions {
  jev?: JevOptions;
}

export class SentinelGate {
  private readonly jev: JevClient;

  constructor(opts: GateOptions = {}) {
    this.jev = new JevClient(opts.jev);
  }

  /** True when a live Jev endpoint is configured. */
  get jevEnabled(): boolean {
    return this.jev.enabled;
  }

  /**
   * Classify a whole unified diff. Runs in milliseconds.
   */
  async verdict(diff: string): Promise<GateVerdict> {
    const t0 = Date.now();
    const files = parseUnifiedDiff(diff);
    const h = heuristicScan(files);

    let hits: RuleHit[] = h.hits;
    let engine: GateVerdict['engine'] = 'heuristic';
    let score = h.score;
    const reasons = [...h.noul.reasons];

    let choice = decide(h);

    if (this.jev.enabled) {
      try {
        const j = await this.jev.classify(diff);
        engine = 'jev+heuristic';
        // Danger wins: either engine saying "risk" routes to a human.
        if (j.choice === 'security_risk' || h.noul.hardcodedSecrets || h.noul.maliciousObfuscation) {
          choice = 'security_risk';
        } else if (j.choice === 'full_review' || choice !== 'trivial') {
          choice = j.choice === 'trivial' && choice === 'trivial' ? 'trivial' : 'full_review';
        }
        score = Math.max(score, j.score);
        reasons.push(...j.noul.reasons);
        hits = [
          ...hits,
          ...j.noul.reasons.map((r) => ({ ruleId: 'jev-flag', message: `Jev: ${r}`, weight: 30 })),
        ];
      } catch (err) {
        // System 1 degrades silently to heuristics; a slow router must never
        // become the pipeline's bottleneck.
        engine = 'heuristic';
        hits = [
          ...hits,
          {
            ruleId: 'jev-unavailable',
            message: `Jev unavailable, heuristics only: ${err instanceof Error ? err.message : String(err)}`,
            weight: 0,
          },
        ];
      }
    }

    const elapsedMs = Date.now() - t0;
    return {
      choice,
      score: { risk: score, confidence: gateConfidence(h) },
      noul: {
        maliciousObfuscation: h.noul.maliciousObfuscation,
        hardcodedSecrets: h.noul.hardcodedSecrets,
        reasons,
      },
      hits,
      files: h.files,
      addedLines: h.addedLines,
      removedLines: h.removedLines,
      elapsedMs,
      engine,
    };
  }
}
