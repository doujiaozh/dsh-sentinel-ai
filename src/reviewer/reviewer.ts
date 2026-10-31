/**
 * sentinel_reviewer - System 2 deep review orchestration.
 *
 * Determinism first: AST checks always run and their line numbers are real by
 * construction. The LLM is an amplifier, never the source of truth: its raw
 * findings pass the anti-hallucination projection before they are allowed to
 * influence the verdict. A failed/aborted LLM call degrades the review to
 * AST-only instead of guessing ("zero hallucination" contract).
 */

import type { Finding, ReviewResult } from '../types';
import { parseUnifiedDiff } from '../util/diff';
import { runAstChecksOnDiff } from './ast-checks';
import { buildLineTable, filterHallucinatedFindings } from './hallucination';
import {
  createLLMAdapter,
  type LLMAdapter,
  type LLMReviewInput,
  type RawFinding,
} from './llm-adapter';

export interface ReviewerOptions {
  llm?: LLMAdapter;
  /** Skip the LLM pass entirely (AST-only deep review). Default: false. */
  astOnly?: boolean;
}

const SEVERITY_WEIGHT: Record<string, { points: number; cap: number }> = {
  critical: { points: 30, cap: 90 },
  warning: { points: 8, cap: 30 },
  info: { points: 2, cap: 10 },
};

export interface ReviewRunOptions {
  abortSignal?: AbortSignal;
}

export class Reviewer {
  private readonly llm: LLMAdapter;
  private readonly astOnly: boolean;

  constructor(opts: ReviewerOptions = {}) {
    this.llm = opts.llm ?? createLLMAdapter();
    this.astOnly = opts.astOnly ?? false;
  }

  async review(diff: string, runOpts: ReviewRunOptions = {}): Promise<ReviewResult> {
    const t0 = Date.now();
    const files = parseUnifiedDiff(diff);

    // Pass 1 - deterministic AST checks (line numbers are real).
    const ast = runAstChecksOnDiff(files);

    // Pass 2 - LLM review, projected against reality.
    let raw: RawFinding[] = [];
    let degraded = false;
    let llmError: string | null = null;
    if (!this.astOnly) {
      const input: LLMReviewInput = {
        files: files
          .filter((f) => f.added.length > 0)
          .map((f) => ({ path: f.path, added: f.added })),
        abortSignal: runOpts.abortSignal,
      };
      try {
        raw = await this.llm.review(input);
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          throw err; // timeout path handles this upstream
        }
        llmError = err instanceof Error ? err.message : String(err);
        degraded = true;
      }
    }

    const table = buildLineTable(files);
    const llmFindings: Finding[] = raw.map((r) => ({
      ruleId: r.ruleId ?? 'llm-unspecified',
      message: r.message ?? '(no message)',
      severity: (r.severity as Finding['severity']) ?? 'info',
      file: r.file ?? (files[0]?.path ?? ''),
      line: typeof r.line === 'number' ? r.line : null,
      column: typeof r.column === 'number' ? r.column : null,
      source: 'llm',
    }));

    // Pass 3 - anti-hallucination projection of everything non-AST.
    const { kept: keptLlm, dropped: droppedLlm } = filterHallucinatedFindings(llmFindings, table);
    // AST findings are geometry-verified already, but run them through the
    // same projection anyway so comments/blank lines can never produce a hit.
    const { kept: keptAst } = filterHallucinatedFindings(ast.findings, table);

    // Merge + dedupe on (file, ruleId, line).
    const merged: Finding[] = [];
    const seen = new Set<string>();
    for (const f of [...keptAst, ...keptLlm]) {
      const key = `${f.file}|${f.ruleId}|${f.line ?? 'null'}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(f);
    }
    merged.sort((a, b) => {
      const order = { critical: 0, warning: 1, info: 2 } as const;
      if (order[a.severity] !== order[b.severity]) return order[a.severity] - order[b.severity];
      return (a.file + String(a.line)).localeCompare(b.file + String(b.line));
    });

    // Scoring: severity-weighted, capped per band.
    const score = computeScore(merged);

    if (llmError) {
      merged.push({
        ruleId: 'llm-degraded',
        message: `LLM pass failed, AST-only review ran instead: ${llmError}`,
        severity: 'info',
        file: files[0]?.path ?? '',
        line: null,
        column: null,
        source: 'llm',
      });
    }

    const critical = merged.filter((f) => f.severity === 'critical');
    const warnings = merged.filter((f) => f.severity === 'warning');

    let decision: ReviewResult['decision'];
    if (critical.some((f) => f.ruleId.startsWith('secret-') || f.ruleId.startsWith('obf-') || f.ruleId.startsWith('ast-eval'))) {
      decision = 'escalate_human';
    } else if (critical.length > 0 || warnings.length >= 3) {
      decision = 'request_changes';
    } else {
      decision = 'approve';
    }

    return {
      decision,
      score,
      findings: merged,
      hallucinatedDropped: droppedLlm.length,
      astCheckedFiles: ast.checked,
      degraded,
      elapsedMs: Date.now() - t0,
    };
  }
}

function computeScore(findings: Finding[]): number {
  let score = 0;
  for (const sev of ['critical', 'warn', 'info'] as const) {
    const key = sev === 'warn' ? 'warning' : sev;
    const band = SEVERITY_WEIGHT[key];
    if (!band) continue;
    const count = findings.filter((f) => f.severity === key).length;
    score += Math.min(count * band.points, band.cap);
  }
  return Math.min(100, score);
}
