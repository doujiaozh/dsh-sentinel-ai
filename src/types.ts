/**
 * Sentinel-AI shared strong types.
 *
 * Modeled on the Jev System-1 output contract: Choice / Score / Noul.
 * Everything the pipeline produces flows through these types so that heuristic
 * gate, LLM deep review and state machine all speak one language.
 */

/* ---------------------------------------------------------------- *
 * System 1 - Jev-style strongly typed output contract              *
 * ---------------------------------------------------------------- */

/** System-1 triage decision for an incoming change. */
export type Choice = 'trivial' | 'security_risk' | 'full_review';

/**
 * Score - Jev-style strongly typed risk score.
 * `risk` is 0-100, `confidence` is 0-1 (how sure the router is).
 */
export interface Score {
  risk: number;
  confidence: number;
}

/**
 * Noul - "is it malicious?" verdict.
 * maliciousObfuscation: code is deliberately obfuscated (eval(atob(...)),
 *   long base64/hex blobs, Function constructor payloads, ...).
 * hardcodedSecrets: credentials/keys/tokens appear as literals.
 */
export interface Noul {
  maliciousObfuscation: boolean;
  hardcodedSecrets: boolean;
  reasons: string[];
}

/** A single fired heuristic rule. */
export interface RuleHit {
  ruleId: string;
  message: string;
  weight: number;
}

/** The verdict System 1 returns in milliseconds. */
export interface GateVerdict {
  choice: Choice;
  score: Score;
  noul: Noul;
  hits: RuleHit[];
  /** Number of files / added lines seen by the gate. */
  files: number;
  addedLines: number;
  removedLines: number;
  elapsedMs: number;
  engine: 'heuristic' | 'jev' | 'jev+heuristic';
}

/* ---------------------------------------------------------------- *
 * System 2 - deep review findings                                  *
 * ---------------------------------------------------------------- */

export type Severity = 'info' | 'warning' | 'critical';
export type FindingSource = 'gate' | 'ast' | 'llm';

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  file: string;
  /** 1-based line in the NEW file, or null when the finding is file-level. */
  line: number | null;
  column: number | null;
  source: FindingSource;
}

export type ReviewDecision = 'approve' | 'request_changes' | 'escalate_human';

export interface ReviewResult {
  decision: ReviewDecision;
  /** 0-100 review risk score (severity weighted). */
  score: number;
  findings: Finding[];
  /** Findings discarded by the anti-hallucination filter (empty/comment lines). */
  hallucinatedDropped: number;
  astCheckedFiles: string[];
  /** True when an aborted/timed-out review had to fall back to AST-only. */
  degraded: boolean;
  elapsedMs: number;
}

/* ---------------------------------------------------------------- *
 * sentinel_state - async timeout state machine                     *
 * ---------------------------------------------------------------- */

export type TaskStatus =
  | 'queued'
  | 'in_progress'
  | 'skipped'
  | 'succeeded'
  | 'timeout'
  | 'failed';

export interface TaskTransition {
  from: TaskStatus | 'init';
  to: TaskStatus;
  /** ISO timestamp. */
  at: string;
  reason?: string;
}

/**
 * Task record. `payload` (the diff under review) is RELEASED from memory once
 * the task times out - that is the OOM protection contract.
 */
export interface TaskRecord {
  id: string;
  key: string;
  status: TaskStatus;
  createdAt: string;
  updatedAt: string;
  ttlMs: number;
  /** ISO timestamp when the TTL watchdog fires. */
  timeoutAt: string;
  purged: boolean;
  payload?: unknown;
  result?: ReviewResult | null;
  error?: string | null;
  transitions: TaskTransition[];
}

/** Public view of a task: same as the record minus the (possibly purged) payload. */
export type TaskSnapshot = Omit<TaskRecord, 'payload'>;

/** Final sentinel report emitted by the CLI / pipeline. */
export interface SentinelReport {
  meta: {
    name: string;
    version: string;
    generatedAt: string;
    simulate: string;
  };
  webhook: {
    repo: string;
    ref: string;
    commit: string;
    message: string;
  };
  gate: GateVerdict;
  state: {
    taskId: string;
    key: string;
    status: TaskStatus;
    purged: boolean;
    timeoutAt: string;
    transitions: TaskTransition[];
  };
  review?: ReviewResult;
  final: {
    decision: ReviewDecision | 'skip' | 'timeout';
    reason: string;
  };
  timing: {
    totalMs: number;
    gateMs: number;
    reviewMs: number;
  };
}
