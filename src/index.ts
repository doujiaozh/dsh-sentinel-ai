import type { SentinelReport } from './types';
import type { GateVerdict, ReviewResult, TaskSnapshot } from './types';

export * from './types';

export { SentinelGate } from './gate';
export type { GateOptions } from './gate';
export { heuristicScan, decide } from './gate/heuristics';
export { JevClient } from './gate/jev-client';
export type { JevOptions, JevVerdict } from './gate/jev-client';

export { Reviewer } from './reviewer/reviewer';
export type { ReviewerOptions, ReviewRunOptions } from './reviewer/reviewer';
export { runAstChecks, runAstChecksOnDiff } from './reviewer/ast-checks';
export {
  buildLineTable,
  filterHallucinatedFindings,
  isBlankLine,
  isCommentLine,
} from './reviewer/hallucination';
export {
  MockLLMAdapter,
  OpenAICompatibleAdapter,
  createLLMAdapter,
} from './reviewer/llm-adapter';
export type {
  LLMAdapter,
  LLMReviewInput,
  MockLLMOptions,
  OpenAICompatibleOptions,
  RawFinding,
  SimulationMode,
} from './reviewer/llm-adapter';

export {
  SentinelStateMachine,
  TaskHandle,
  isTerminal,
  MemoryKVStore,
  RedisKVStore,
  createStore,
} from './state';
export type { StateMachineOptions, KVStore, StoreOptions } from './state';

export {
  parseUnifiedDiff,
  diffStats,
  mapSnippetLine,
  isCosmeticOnly,
  isCodeFile,
} from './util/diff';
export type { DiffFile, DiffLine } from './util/diff';
export { shannonEntropy, isHighEntropy } from './util/entropy';

export { runPipeline, type PipelineInput, type PipelineOptions } from './pipeline';
export type { SentinelReport, GateVerdict, ReviewResult, TaskSnapshot } from './types';
