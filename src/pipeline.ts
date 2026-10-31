/**
 * Sentinel-AI end-to-end pipeline: the full async review sprint.
 *
 *   webhook(diff) -> System 1 gate (ms) -> [trivial: skip]
 *                                        -> [security_risk: escalate to human]
 *                                        -> [full_review: async deep review]
 *        -> state machine (submit now / TTL watchdog / idempotent lock)
 *        -> System 2 (AST always, LLM projected, anti-hallucination)
 *        -> terminal state + report
 *
 * The pipeline never blocks the caller longer than the LLM timeout: the moment
 * the state machine's watchdog fires, an AbortController kills the in-flight
 * LLM call and the task lands in `timeout` with its payload released.
 */

import { SentinelGate } from './gate';
import { Reviewer } from './reviewer/reviewer';
import { SentinelStateMachine } from './state';
import type {
  ReviewDecision,
  ReviewResult,
  SentinelReport,
  TaskSnapshot,
} from './types';
import { parseUnifiedDiff } from './util/diff';
import { isTerminal } from './state';

export interface PipelineInput {
  /** Unified diff of the push/PR. */
  diff: string;
  /** Idempotency key - usually `repo@commitSha`. */
  key: string;
  /** Webhook-ish metadata for the report. */
  webhook?: {
    repo?: string;
    ref?: string;
    commit?: string;
    message?: string;
  };
}

export interface PipelineOptions {
  ttlMs?: number;
  gate?: SentinelGate;
  reviewer?: Reviewer;
  machine?: SentinelStateMachine;
}

export interface PipelineResult {
  report: SentinelReport;
  gateChoice: string;
  decision: ReviewDecision | 'skip' | 'timeout';
  task: TaskSnapshot | null;
  review: ReviewResult | null;
}

export class Pipeline {
  private readonly gate: SentinelGate;
  private readonly reviewer: Reviewer;
  private readonly machine: SentinelStateMachine;
  private readonly ttlMs: number;

  constructor(opts: PipelineOptions = {}) {
    this.gate = opts.gate ?? new SentinelGate();
    this.reviewer = opts.reviewer ?? new Reviewer();
    this.machine = opts.machine ?? new SentinelStateMachine();
    this.ttlMs = opts.ttlMs ?? 30 * 60 * 1000;
  }

  get stateMachine(): SentinelStateMachine {
    return this.machine;
  }

  async run(input: PipelineInput): Promise<PipelineResult> {
    const t0 = Date.now();
    await this.machine.start();

    /* ---------- System 1: milliseconds triage ---------- */
    const verdict = await this.gate.verdict(input.diff);
    const wh = input.webhook ?? {};

    /* ---------- Idempotent submission (returns immediately) ---------- */
    const handle = await this.machine.submit(input.key, {
      diff: input.diff,
      webhook: wh,
      gate: { choice: verdict.choice, risk: verdict.score.risk },
    }, { ttlMs: this.ttlMs });

    const skipState = async (reason: string) => {
      await this.machine.transition(handle.id, 'skipped', reason).catch(() => undefined);
      const snap = await handle.snapshot();
      return this.finish(input, verdict, snap, null, t0);
    };

    // trivial: System 1 is confident nothing needs System 2.
    if (verdict.choice === 'trivial') {
      return skipState('System 1: trivial change, deep review skipped');
    }

    // security_risk: never let the LLM anywhere near it - force a human.
    if (verdict.choice === 'security_risk') {
      const snap = await this.machine
        .transition(handle.id, 'skipped', 'System 1: security_risk, escalated to human')
        .catch(() => undefined);
      const finalSnap = (await handle.snapshot()) ?? snap ?? null;
      return this.finish(input, verdict, finalSnap, null, t0, 'escalate_human',
        'security_risk: hardcoded secret / malicious obfuscation - human required');
    }

    /* ---------- full_review: async deep sprint ---------- */
    await this.machine.startWork(handle.id);

    const abort = new AbortController();
    const onTimeout = (evt: { id?: string }) => {
      if (evt?.id === handle.id) abort.abort();
    };
    this.machine.on('timeout', onTimeout);

    const reviewPromise = this.reviewer.review(input.diff, { abortSignal: abort.signal });

    let review: ReviewResult | null = null;
    try {
      review = await reviewPromise;
      const record = await this.machine
        .transition(handle.id, 'succeeded', 'System 2 deep review completed')
        .catch(() => null);
      const snap = (await handle.snapshot()) ?? (record ? this.snapshot(record) : null);
      return this.finishWith(input, verdict, snap, review, t0);
    } catch (err) {
      const aborted = err instanceof Error && (err.name === 'AbortError' || /aborted/i.test(err.message));
      if (aborted) {
        // The watchdog (or a manual abort) pulled the plug. Give the machine a
        // moment to land in its terminal `timeout` state before we read it.
        const settled = await handle.wait(2000);
        const snap = settled ?? (await handle.snapshot());
        if (snap && (snap.status === 'timeout' || isTerminal(snap.status))) {
          return this.finish(input, verdict, snap, null, t0, 'timeout',
            snap.status === 'timeout'
              ? 'LLM timed out: task marked timeout, payload released'
              : `task aborted, terminal status ${snap.status}`);
        }
      }
      const msg = err instanceof Error ? err.message : String(err);
      const failed = await this.machine
        .transition(handle.id, 'failed', `review error: ${msg}`)
        .catch(() => null);
      const snap2 = (await handle.snapshot()) ?? failed ?? null;
      return this.finish(input, verdict, snap2, null, t0, 'skip', `review failed: ${msg}`);
    } finally {
      this.machine.off('timeout', onTimeout);
    }
  }

  private snapshot(record: any): TaskSnapshot {
    const { payload, ...rest } = record;
    return rest as TaskSnapshot;
  }

  private finish(
    input: PipelineInput,
    verdict: ReturnType<SentinelGate['verdict']> extends Promise<infer V> ? V : never,
    task: TaskSnapshot | null,
    review: ReviewResult | null,
    t0: number,
    decision?: ReviewDecision | 'skip' | 'timeout',
    reason?: string
  ): PipelineResult {
    const report = this.buildReport(input, verdict, task, review, t0, decision, reason);
    return { report, gateChoice: verdict.choice, decision: report.final.decision, task, review };
  }

  private finishWith(
    input: PipelineInput,
    verdict: any,
    task: TaskSnapshot | null,
    review: ReviewResult,
    t0: number
  ): PipelineResult {
    let decision: ReviewDecision | 'skip' = 'approve';
    if (review.decision === 'escalate_human') decision = 'escalate_human';
    else if (review.decision === 'request_changes') decision = 'request_changes';
    return this.finish(input, verdict, task, review, t0, decision, undefined);
  }

  private buildReport(
    input: PipelineInput,
    verdict: any,
    task: TaskSnapshot | null,
    review: ReviewResult | null,
    t0: number,
    decisionOverride?: ReviewDecision | 'skip' | 'timeout',
    reasonOverride?: string
  ): SentinelReport {
    let decision: ReviewDecision | 'skip' | 'timeout' = review ? review.decision : 'skip';
    if (decisionOverride) decision = decisionOverride;
    if (verdict.choice === 'security_risk') decision = 'escalate_human';

    const reason = reasonOverride ??
      (review
        ? `${review.decision}: score ${review.score}, ${review.findings.length} finding(s), ${review.hallucinatedDropped} hallucinated finding(s) dropped`
        : verdict.choice === 'security_risk'
          ? 'security_risk: forced human review'
          : 'trivial: skipped deep review');

    return {
      meta: {
        name: 'dsh-sentinel-ai',
        version: '1.0.0',
        generatedAt: new Date().toISOString(),
        simulate: process.env.SENTINEL_LLM_SIMULATE ?? 'none',
      },
      webhook: {
        repo: input.webhook?.repo ?? 'unknown-repo',
        ref: input.webhook?.ref ?? 'refs/heads/main',
        commit: input.webhook?.commit ?? input.key,
        message: input.webhook?.message ?? '',
      },
      gate: verdict,
      state: task
        ? {
            taskId: task.id,
            key: task.key,
            status: task.status,
            purged: task.purged,
            timeoutAt: task.timeoutAt,
            transitions: task.transitions,
          }
        : {
            taskId: '',
            key: input.key,
            status: 'failed',
            purged: false,
            timeoutAt: '',
            transitions: [],
          },
      review: review ?? undefined,
      final: { decision, reason },
      timing: {
        totalMs: Date.now() - t0,
        gateMs: verdict.elapsedMs,
        reviewMs: review?.elapsedMs ?? 0,
      },
    };
  }
}

/**
 * Functional entry point used by tests and the CLI.
 */
export async function runPipeline(
  input: PipelineInput,
  opts: PipelineOptions = {}
): Promise<PipelineResult> {
  const pipeline = new Pipeline(opts);
  return pipeline.run(input);
}

/** Count hunks/lines for CLI logging. */
export function quickStats(diff: string) {
  const files = parseUnifiedDiff(diff);
  return {
    files: files.length,
    added: files.reduce((s, f) => s + f.addedCount, 0),
    removed: files.reduce((s, f) => s + f.removedCount, 0),
  };
}
