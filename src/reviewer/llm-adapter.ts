/**
 * sentinel_reviewer / llm-adapter - pluggable LLM backends for System 2.
 *
 * Two implementations ship:
 *  - MockLLMAdapter: a deterministic, offline fake that behaves like an
 *    opinionated reviewer AND deliberately emits hallucinated positions, so
 *    the anti-hallucination layer is exercised on every run.
 *  - OpenAICompatibleAdapter: any /chat/completions endpoint, configured via
 *    SENTINEL_LLM_* env vars. Supports abort (so the state machine can kill
 *    a hung review on timeout).
 *
 * Both respect AbortSignal: the state machine's TTL watchdog aborts an
 * in-flight review instead of letting it leak memory.
 */

import type { DiffFile } from '../util/diff';
import type { Finding, Severity } from '../types';

export interface LLMReviewInput {
  files: Array<{
    path: string;
    added: Array<{ lineNo: number; text: string }>;
  }>;
  abortSignal?: AbortSignal;
}

export interface RawFinding {
  ruleId?: string;
  message?: string;
  severity?: Severity;
  file?: string;
  line?: number | null;
  column?: number | null;
}

export interface LLMAdapter {
  readonly name: string;
  review(input: LLMReviewInput): Promise<RawFinding[]>;
}

const SYSTEM_PROMPT = `You are Sentinel-Reviewer, a deterministic-minded code reviewer.
Rules:
- Only report findings about CHANGED lines listed in the prompt. Never invent positions.
- Never report an issue on an empty line or a comment line.
- Return STRICT JSON: an array of objects with keys
  ruleId, message, severity ("info"|"warning"|"critical"), file, line, column.
- If you find nothing, return []. No prose, no markdown.`;

/* ---------------------------------------------------------------- *
 * Mock adapter (offline, deterministic, by design)                  *
 * ---------------------------------------------------------------- */

export type SimulationMode = 'none' | 'llm-error' | 'llm-slow';

export interface MockLLMOptions {
  simulate?: SimulationMode;
  /** Artificial latency in ms (used by llm-slow simulation). */
  latencyMs?: number;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (signal?.aborted) return reject(new DOMException('aborted', 'AbortError'));
      if (Date.now() - start >= ms) return resolve();
      setTimeout(tick, 25);
    };
    tick();
  });

export class MockLLMAdapter implements LLMAdapter {
  readonly name = 'mock-llm';
  constructor(private opts: MockLLMOptions = {}) {}

  async review(input: LLMReviewInput): Promise<RawFinding[]> {
    const simulate = this.opts.simulate ?? 'none';
    const latency = this.opts.latencyMs ?? 12_000;

    if (simulate === 'llm-error') {
      await sleep(25, input.abortSignal);
      throw new Error('LLM simulated failure: upstream 503 (API 抽风)');
    }
    if (simulate === 'llm-slow') {
      await sleep(latency, input.abortSignal); // abort lands here on timeout
    }

    const findings: RawFinding[] = [];

    for (const f of input.files) {
      const codeLines = f.added.filter((l) => l.text.trim().length > 0);
      if (codeLines.length === 0) continue;

      for (const l of codeLines) {
        const t = l.text;
        if (/console\.(log|debug|info)\s*\(/.test(t)) {
          findings.push({ ruleId: 'llm-leftover-log', message: 'Leftover debug logging ships secrets to stdout in production', severity: 'warning', file: f.path, line: l.lineNo, column: 0 });
        }
        if (/(?:^|[^\=!<>])==[^=]/.test(t) && !/=>/.test(t)) {
          findings.push({ ruleId: 'llm-loose-equality', message: 'Loose equality (==) - use strict equality (===)', severity: 'info', file: f.path, line: l.lineNo, column: 0 });
        }
        if (/\bdebugger\s*;/.test(t)) {
          findings.push({ ruleId: 'llm-debugger', message: 'debugger statement left in the diff', severity: 'warning', file: f.path, line: l.lineNo, column: 0 });
        }
      }

      // Induced hallucinations, on purpose:
      // (a) a scary finding pinned to a COMMENT line -> must be dropped
      const commentLine = f.added.find((l) => /^\s*(\/\/|\/\*|\*)/.test(l.text));
      if (commentLine) {
        findings.push({
          ruleId: 'llm-data-exfiltration',
          message: 'This line tunnels credentials out via DNS resolution',
          severity: 'critical',
          file: f.path,
          line: commentLine.lineNo,
          column: 0,
        });
      }
      // (b) a finding with a line number that does not exist at all
      const maxLine = Math.max(...f.added.map((l) => l.lineNo), 0);
      findings.push({
        ruleId: 'llm-rce-backdoor',
        message: 'Reverse shell spawned on this line',
        severity: 'critical',
        file: f.path,
        line: maxLine + 9001,
        column: 0,
      });
    }

    return findings;
  }
}

/* ---------------------------------------------------------------- *
 * OpenAI-compatible adapter (real LLM, optional)                    *
 * ---------------------------------------------------------------- */

export interface OpenAICompatibleOptions {
  baseUrl?: string;
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
}

export class OpenAICompatibleAdapter implements LLMAdapter {
  readonly name = 'openai-compat';
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeoutMs: number;

  constructor(opts: OpenAICompatibleOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env.SENTINEL_LLM_BASE_URL ?? '').replace(/\/+$/, '');
    this.apiKey = opts.apiKey ?? process.env.SENTINEL_LLM_API_KEY ?? '';
    this.model = opts.model ?? process.env.SENTINEL_LLM_MODEL ?? 'gpt-4o-mini';
    this.timeoutMs = opts.timeoutMs ?? 120_000;
    if (!this.baseUrl) throw new Error('SENTINEL_LLM_BASE_URL is required');
  }

  async review(input: LLMReviewInput): Promise<RawFinding[]> {
    const userContent = renderchangedLinesPrompt(input.files);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const onAbort = () => controller.abort();
    input.abortSignal?.addEventListener('abort', onAbort, { once: true });
    try {
      const res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
        },
        body: JSON.stringify({
          model: this.model,
          temperature: 0,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: userContent },
          ],
        }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`LLM HTTP ${res.status}`);
      const body = (await res.json()) as any;
      const content: string = body?.choices?.[0]?.message?.content ?? '';
      return extractJsonFindings(content);
    } finally {
      clearTimeout(timer);
      input.abortSignal?.removeEventListener('abort', onAbort);
    }
  }
}

function renderchangedLinesPrompt(
  files: Array<{ path: string; added: Array<{ lineNo: number; text: string }> }>
): string {
  const parts: string[] = ['CHANGED LINES (file:line => source). Findings must reference these lines only:'];
  for (const f of files) {
    for (const l of f.added) {
      parts.push(`${f.path}:${l.lineNo} => ${l.text}`);
    }
  }
  return parts.join('\n');
}

function extractJsonFindings(content: string): RawFinding[] {
  const text = content.trim();
  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start < 0 || end < 0) return [];
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x) => x && typeof x === 'object') as RawFinding[];
  } catch {
    return [];
  }
}

/* ---------------------------------------------------------------- *
 * Factory                                                            *
 * ---------------------------------------------------------------- */

export function createLLMAdapter(env: NodeJS.ProcessEnv = process.env): LLMAdapter {
  const simulate = (env.SENTINEL_LLM_SIMULATE ?? 'none') as SimulationMode;
  if ((env.SENTINEL_LLM_BASE_URL ?? '') !== '') {
    return new OpenAICompatibleAdapter({
      baseUrl: env.SENTINEL_LLM_BASE_URL,
      apiKey: env.SENTINEL_LLM_API_KEY,
      model: env.SENTINEL_LLM_MODEL,
    });
  }
  return new MockLLMAdapter({ simulate });
}
