/**
 * Jev System-1 client.
 *
 * Jev is the fast-twitch router: given a diff it returns a strongly typed
 * { choice, score, noul } verdict. If no Jev endpoint is configured (the
 * default), the gate runs on local heuristics alone - this client only ever
 * fires when SENTINEL_JEV_URL is set. Any network/protocol failure falls back
 * to heuristics, never blocks the pipeline.
 */

import type { Choice, Noul } from '../types';

export interface JevOptions {
  /** Base URL of the Jev service, e.g. http://jev.internal:7070 */
  url?: string;
  apiKey?: string;
  /** Per-request budget. System 1 must stay in milliseconds territory. */
  timeoutMs?: number;
}

export interface JevVerdict {
  choice: Choice;
  score: number;
  noul: Noul;
}

const CHOICES: ReadonlySet<string> = new Set(['trivial', 'security_risk', 'full_review']);

export class JevClient {
  readonly url: string | undefined;
  private readonly apiKey: string | undefined;
  readonly timeoutMs: number;

  constructor(opts: JevOptions = {}) {
    this.url = opts.url ?? process.env.SENTINEL_JEV_URL;
    this.apiKey = opts.apiKey ?? process.env.SENTINEL_JEV_API_KEY;
    this.timeoutMs = opts.timeoutMs ?? 2000;
  }

  get enabled(): boolean {
    return typeof this.url === 'string' && this.url.length > 0;
  }

  async classify(diff: string): Promise<JevVerdict> {
    if (!this.enabled) throw new Error('Jev client is not enabled');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.url}/v1/jev/classify`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
        },
        body: JSON.stringify({ diff, schema: 'Choice|Score|Noul' }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`Jev HTTP ${res.status}`);
      }
      const body = (await res.json()) as Partial<JevVerdict>;
      if (!body || !CHOICES.has(String(body.choice))) {
        throw new Error('Jev returned an invalid choice');
      }
      const noul = body.noul ?? { maliciousObfuscation: false, hardcodedSecrets: false, reasons: [] };
      return {
        choice: body.choice as Choice,
        score: typeof body.score === 'number' ? Math.max(0, Math.min(100, body.score)) : 0,
        noul: {
          maliciousObfuscation: !!noul.maliciousObfuscation,
          hardcodedSecrets: !!noul.hardcodedSecrets,
          reasons: Array.isArray(noul.reasons) ? noul.reasons : [],
        },
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
