/**
 * sentinel_state - async timeout state machine (Redis TTL + setTimeout).
 *
 * Anti-blocking contract:
 *   submit() returns a TaskID IMMEDIATELY - the diff is queued, a TTL watchdog
 *   is armed, and the caller may walk away. Nothing waits on an LLM.
 *
 * OOM contract:
 *   every task carries a TTL (30min default). When the LLM does not answer in
 *   time the watchdog force-transitions the task to `timeout`, RELEASES the
 *   payload (the diff) from memory, and emits `timeout` so the in-flight LLM
 *   call is aborted. No leaked diffs, no unbounded growth.
 *
 * Idempotency contract (Redis distributed lock semantics):
 *   the commit key `repo@sha` takes a SET-NX lock. A duplicate webhook for the
 *   same commit resolves to the SAME task - it is never reviewed twice. Once
 *   terminal, the lock becomes a tombstone for `tombstoneTtlMs` so replays
 *   still get the cached verdict instead of a fresh review.
 */

import { EventEmitter } from 'events';
import type {
  ReviewResult,
  TaskRecord,
  TaskSnapshot,
  TaskStatus,
  TaskTransition,
} from '../types';
import { createStore, type KVStore, type StoreOptions } from './store';

export interface StateMachineEvents {
  submitted: { id: string; key: string };
  transition: { id: string; from: TaskStatus | 'init'; to: TaskStatus; reason?: string };
  timeout: { id: string; key: string };
  completed: { id: string; key: string; status: TaskStatus };
}

export interface StateMachineOptions {
  /** Inject a store (tests); otherwise built from storeOpts/env. */
  store?: KVStore;
  storeOpts?: StoreOptions;
  /** Default watchdog budget: 30 minutes - "API 抽风" room. */
  defaultTtlMs?: number;
  /** How long a terminal task stays answerable before its tombstone expires. */
  tombstoneTtlMs?: number;
}

const LOCK_PREFIX = 'lock:';
const TASK_PREFIX = 'task:';

const ALLOWED: Record<TaskStatus, TaskStatus[]> = {
  queued: ['in_progress', 'skipped', 'succeeded', 'failed', 'timeout'],
  in_progress: ['succeeded', 'failed', 'timeout'],
  skipped: [],
  succeeded: [],
  timeout: [],
  failed: [],
};

export function isTerminal(status: TaskStatus): boolean {
  return status === 'succeeded' || status === 'timeout' || status === 'failed' || status === 'skipped';
}

function nowIso(): string {
  return new Date().toISOString();
}

function randomId(): string {
  return 'tsk_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
}

/**
 * The async timeout state machine. Emits: submitted / transition / timeout /
 * completed (see StateMachineEvents). Uses the untyped EventEmitter surface so
 * listeners stay ergonomic across host Node type versions.
 */
export class SentinelStateMachine extends EventEmitter {
  readonly defaultTtlMs: number;
  private readonly tombstoneTtlMs: number;
  private store: KVStore | null = null;
  private storePromise: Promise<KVStore> | null = null;
  /** taskId -> watchdog timer. */
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private stopped = false;

  constructor(opts: StateMachineOptions = {}) {
    super();
    this.defaultTtlMs = opts.defaultTtlMs ?? 30 * 60 * 1000;
    this.tombstoneTtlMs = opts.tombstoneTtlMs ?? 60 * 60 * 1000;
    if (opts.store) this.store = opts.store;
    else this.storePromise = createStore(opts.storeOpts ?? {});
  }

  /** Resolve the store (Redis connect / no-op in memory mode). */
  async start(): Promise<KVStore> {
    if (!this.store && this.storePromise) {
      this.store = await this.storePromise;
      this.storePromise = null;
    }
    if (!this.store) throw new Error('sentinel state machine: no store');
    return this.store;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const [, t] of this.timers) clearTimeout(t);
    this.timers.clear();
    const s = this.store;
    this.store = null;
    await s?.quit().catch(() => undefined);
  }

  /* -------------------------------------------------------------- *
   * Submission - non-blocking, idempotent                           *
   * -------------------------------------------------------------- */

  /**
   * Register a review task. Resolves as soon as the task is durable - NOT when
   * the review finishes. Duplicate `key` (same commit) resolves to the
   * existing task so the commit is never reviewed twice.
   */
  async submit(
    key: string,
    payload: unknown,
    opts: { ttlMs?: number; id?: string } = {}
  ): Promise<TaskHandle> {
    const store = await this.start();
    const ttlMs = opts.ttlMs ?? this.defaultTtlMs;

    const lockKey = LOCK_PREFIX + key;
    const holder = await store.get(lockKey);
    if (holder) {
      const prior = await this.load(holder);
      if (prior) {
        // Live or tombstoned: hand back the same task, never re-review.
        return new TaskHandle(this, prior);
      }
      // Stale lock whose record evaporated: steal it.
    }

    const id = opts.id ?? randomId();
    const now = Date.now();
    const record: TaskRecord = {
      id,
      key,
      status: 'queued',
      createdAt: nowIso(),
      updatedAt: nowIso(),
      ttlMs,
      timeoutAt: new Date(now + ttlMs).toISOString(),
      purged: false,
      payload,
      result: null,
      error: null,
      transitions: [{ from: 'init', to: 'queued', at: nowIso() }],
    };

    const won = await store.setNx(lockKey, id, ttlMs + this.tombstoneTtlMs);
    if (!won) {
      // Lost a submit race: adopt the winner.
      const winnerId = await store.get(lockKey);
      const winner = winnerId ? await this.load(winnerId) : null;
      if (winner) return new TaskHandle(this, winner);
    }

    await store.set(TASK_PREFIX + id, JSON.stringify(record), ttlMs + this.tombstoneTtlMs);
    this.armWatchdog(id, ttlMs);
    this.emit('submitted', { id, key });
    return new TaskHandle(this, record);
  }

  /* -------------------------------------------------------------- *
   * Transitions                                                     *
   * -------------------------------------------------------------- */

  async transition(id: string, to: TaskStatus, reason?: string): Promise<TaskRecord> {
    const store = await this.start();
    const record = await this.load(id);
    if (!record) throw new Error(`sentinel: unknown task ${id}`);
    if (record.status === to) return record;
    const allowed = ALLOWED[record.status];
    if (!allowed.includes(to)) {
      throw new Error(`sentinel: illegal transition ${record.status} -> ${to} (${id})`);
    }

    const from = record.status;
    record.transitions.push({ from, to, at: nowIso(), reason });
    record.status = to;
    record.updatedAt = nowIso();

    if (to === 'timeout') {
      // OOM protection: drop the diff, keep the verdict-shaped tombstone.
      record.purged = true;
      record.payload = undefined;
    }
    if (to === 'succeeded' || to === 'failed') {
      // The result/error is the durable part; the diff is no longer needed.
      record.payload = undefined;
    }

    if (isTerminal(to)) {
      this.clearWatchdog(id);
      // Tombstone the commit lock: replays read the cached verdict instead of
      // re-reviewing the same commit. Expires after tombstoneTtlMs.
      await store.set(LOCK_PREFIX + record.key, id, this.tombstoneTtlMs).catch(() => undefined);
      if (to === 'timeout') this.emit('timeout', { id, key: record.key });
      this.emit('completed', { id, key: record.key, status: to });
    }

    await store.set(
      TASK_PREFIX + id,
      JSON.stringify(record),
      this.tombstoneTtlMs
    );
    this.emit('transition', { id, from, to, reason });
    return record;
  }

  /** queued -> in_progress. */
  startWork(id: string): Promise<TaskRecord> {
    return this.transition(id, 'in_progress', 'System 2 deep review started');
  }

  async get(id: string): Promise<TaskSnapshot | null> {
    const record = await this.load(id);
    return record ? this.snapshot(record) : null;
  }

  async list(): Promise<TaskSnapshot[]> {
    const store = await this.start();
    const keys = await store.keys(TASK_PREFIX);
    const out: TaskSnapshot[] = [];
    for (const k of keys) {
      const raw = await store.get(k);
      if (!raw) continue;
      try {
        out.push(this.snapshot(JSON.parse(raw)));
      } catch {
        /* corrupted entry - skip */
      }
    }
    return out.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  /* -------------------------------------------------------------- *
   * Internals                                                       *
   * -------------------------------------------------------------- */

  private async load(id: string): Promise<TaskRecord | null> {
    const store = await this.start();
    const raw = await store.get(TASK_PREFIX + id);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as TaskRecord;
    } catch {
      return null;
    }
  }

  private armWatchdog(id: string, ttlMs: number): void {
    if (this.stopped) return;
    const timer = setTimeout(() => {
      this.timers.delete(id);
      // Only fires if the task is still live; terminal tasks cleared theirs.
      this.transition(id, 'timeout', `TTL ${ttlMs}ms expired - LLM did not answer`)
        .catch(() => undefined);
    }, ttlMs);
    if (typeof (timer as any)?.unref === 'function') (timer as any).unref();
    this.timers.set(id, timer);
  }

  private clearWatchdog(id: string): void {
    const t = this.timers.get(id);
    if (t) {
      clearTimeout(t);
      this.timers.delete(id);
    }
  }

  private snapshot(record: TaskRecord): TaskSnapshot {
    const { payload, ...rest } = record;
    return rest;
  }
}

export interface TaskHandleOptions {
  pollIntervalMs?: number;
}

/** Live handle for a submitted task; pollable without blocking the machine. */
export class TaskHandle {
  readonly id: string;
  readonly key: string;
  private readonly machine: SentinelStateMachine;

  constructor(machine: SentinelStateMachine, record: TaskRecord) {
    this.machine = machine;
    this.id = record.id;
    this.key = record.key;
  }

  get status(): Promise<TaskStatus | null> {
    return this.machine.get(this.id).then((s) => s?.status ?? null);
  }

  snapshot(): Promise<TaskSnapshot | null> {
    return this.machine.get(this.id);
  }

  /**
   * Resolve when the task reaches a terminal status, or when `deadlineMs`
   * elapses (returns the last snapshot either way - the machine keeps running).
   */
  async wait(deadlineMs: number, opts: TaskHandleOptions = {}): Promise<TaskSnapshot | null> {
    const poll = opts.pollIntervalMs ?? 50;
    const deadline = Date.now() + deadlineMs;
    for (;;) {
      const snap = await this.machine.get(this.id);
      if (snap && isTerminal(snap.status)) return snap;
      if (Date.now() >= deadline) return snap ?? null;
      await new Promise((r) => setTimeout(r, poll));
    }
  }
}

export type { ReviewResult };
