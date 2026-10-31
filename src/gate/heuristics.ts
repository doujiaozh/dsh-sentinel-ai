/**
 * sentinel_gate / heuristics - System 1 rule engine.
 *
 * Deliberately model-free: pure regex + path + size rules that run in
 * microseconds. The gate's job is NOT to understand the diff, only to decide
 * in milliseconds WHO should understand it.
 */

import type { Choice, Noul, RuleHit } from '../types';
import type { DiffFile } from '../util/diff';
import { diffStats, isCodeFile, isCosmeticOnly } from '../util/diff';
import { isHighEntropy } from '../util/entropy';

/* ------------------------------------------------------------------ *
 * Hardcoded credential signatures                                     *
 * ------------------------------------------------------------------ */
const SECRET_PATTERNS: Array<{ id: string; re: RegExp; weight: number; message: string }> = [
  { id: 'secret-password-assign', re: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"][^'"\s]{4,}['"]/i, weight: 45, message: 'Hardcoded password literal' },
  { id: 'secret-api-key', re: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i, weight: 45, message: 'Hardcoded API key / secret literal' },
  { id: 'secret-aws-access-key-id', re: /\bAKIA[0-9A-Z]{16}\b/, weight: 50, message: 'AWS access key id exposed' },
  { id: 'secret-github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, weight: 50, message: 'GitHub personal access token exposed' },
  { id: 'secret-private-key-block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, weight: 55, message: 'Embedded private key block' },
  { id: 'secret-jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, weight: 35, message: 'Hardcoded JWT' },
  { id: 'secret-connection-string', re: /(?:mongodb|mongodb\+srv|postgres(?:ql)?|mysql|redis):\/\/[^\s/'"@]+:[^\s/'"@]+@/i, weight: 45, message: 'Connection string with inline credentials' },
  { id: 'secret-slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, weight: 45, message: 'Slack token exposed' },
];

/* ------------------------------------------------------------------ *
 * Malicious obfuscation signatures (Noul)                             *
 * ------------------------------------------------------------------ */
const OBFUSCATION_PATTERNS: Array<{ id: string; re: RegExp; weight: number; message: string }> = [
  { id: 'obf-eval-atob', re: /eval\(\s*atob\s*\(/, weight: 55, message: 'eval(atob(...)) - classic payload dropper' },
  { id: 'obf-eval-base64', re: /eval\(\s*(?:window|globalThis)?\s*(?:Buffer\.from|atob)\s*\(/, weight: 55, message: 'eval() decoding base64 payload' },
  { id: 'obf-new-function', re: /\bnew\s+Function\s*\(/, weight: 40, message: 'Function constructor used as eval' },
  { id: 'obf-function-constructor-return', re: /Function\s*\(\s*['"]return\s/, weight: 45, message: 'Function("return ...") escape hatch' },
  { id: 'obf-fromcharcode-chain', re: /String\.fromCharCode\([^)]*\)\s*\+/, weight: 30, message: 'String.fromCharCode character assembly' },
  { id: 'obf-hex-escape-blob', re: /(?:\\x[0-9a-fA-F]{2}){16,}/, weight: 35, message: 'Long hex-escape blob' },
  { id: 'obf-base64-blob', re: /['"][A-Za-z0-9+/]{80,}={0,2}['"]/, weight: 25, message: 'Long base64 blob (payload candidate)' },
  { id: 'obf-unescape', re: /\bunescape\s*\(/, weight: 20, message: 'unescape() string decoding' },
  { id: 'obf-document-write-decoded', re: /document\.write\(\s*(?:unescape|atob|decodeURI)/, weight: 45, message: 'document.write of decoded payload' },
];

/* ------------------------------------------------------------------ *
 * Supply-chain / CI sensitive paths                                   *
 * ------------------------------------------------------------------ */
const SENSITIVE_PATHS: Array<{ id: string; re: RegExp; weight: number; message: string }> = [
  { id: 'ci-github-workflow', re: /^\.github\/(workflows|actions)\//, weight: 25, message: 'Change to GitHub Actions workflow' },
  { id: 'ci-dockerfile', re: /(^|\/)Dockerfile(?:\.\w+)?$/, weight: 20, message: 'Change to Dockerfile' },
  { id: 'ci-env-file', re: /(^|\/)\.env/, weight: 30, message: 'Change to environment file' },
  { id: 'ci-package-json', re: /(^|\/)package\.json$/, weight: 15, message: 'Change to package.json (dependency surface)' },
  { id: 'ci-jenkinsfile', re: /(^|\/)Jenkinsfile/, weight: 25, message: 'Change to Jenkinsfile' },
  { id: 'ci-shell-script', re: /\.sh$|\.bash$/, weight: 15, message: 'Change to shell script' },
  { id: 'ci-terraform', re: /\.tf$|\.tfvars$/, weight: 25, message: 'Change to Terraform infrastructure' },
  { id: 'ci-compose', re: /(^|\/)docker-compose/, weight: 20, message: 'Change to docker-compose file' },
];

const TEST_FILE_RE = /(^|[\/\\])(?:__tests__|test|tests|spec)[\/\\].+|\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs)$|(?:test|spec)\.(?:js|ts)$/i;
const DOC_EXTS = ['.md', '.markdown', '.mdx', '.txt', '.rst', '.licen', '.changelog'];
const CONFIG_EXTS = ['.json', '.yml', '.yaml', '.toml', '.ini', '.conf'];

export const LARGE_DIFF_LINES = 200;
export const FULL_REVIEW_SCORE = 35;

export interface HeuristicResult {
  score: number;
  noul: Noul;
  hits: RuleHit[];
  addedLines: number;
  removedLines: number;
  files: number;
  docsOnly: boolean;
  cosmeticOnly: boolean;
  /** True when at least one code file receives added lines. */
  codePresent: boolean;
}

/**
 * Run the whole System-1 rule battery over a parsed diff.
 */
export function heuristicScan(files: DiffFile[]): HeuristicResult {
  const hits: RuleHit[] = [];
  const noulReasons: string[] = [];
  let secretFound = false;
  let obfFound = false;

  for (const f of files) {
    const addedText = f.added.map((l) => l.text).join('\n');
    const haystack = addedText + '\n' + f.path;

    for (const p of SECRET_PATTERNS) {
      if (p.re.test(addedText)) {
        secretFound = true;
        noulReasons.push(`${p.id} in ${f.path}`);
        hits.push({ ruleId: p.id, message: `${p.message} (${f.path})`, weight: p.weight });
      }
    }
    for (const p of OBFUSCATION_PATTERNS) {
      if (p.re.test(addedText)) {
        obfFound = true;
        noulReasons.push(`${p.id} in ${f.path}`);
        hits.push({ ruleId: p.id, message: `${p.message} (${f.path})`, weight: p.weight });
      }
    }
    for (const p of SENSITIVE_PATHS) {
      if (p.re.test(f.path)) {
        hits.push({ ruleId: p.id, message: `${p.message}`, weight: p.weight });
      }
    }
    // Entropy sweep on string literals (cheap secret fallback).
    const literalRe = /(?:['"`])([^'"`\n]{24,})(?:['"`])/g;
    let m: RegExpExecArray | null;
    while ((m = literalRe.exec(addedText)) !== null) {
      const lit = m[1]!;
      // Report high-entropy literals that are not plain kebab-case words
      // (which are benign config keys / css names).
      if (isHighEntropy(lit) && !/^[a-z]+(?:-[a-z]+)*$/.test(lit)) {
        hits.push({
          ruleId: 'secret-high-entropy-literal',
          message: `High-entropy literal in ${f.path} (possible secret/obfuscation)`,
          weight: 20,
        });
      }
    }
    // Test deletions are a review smell.
    if ((f.isDeleted || f.removedCount > f.addedCount) && TEST_FILE_RE.test(f.path)) {
      hits.push({
        ruleId: 'test-deletion',
        message: `Test material removed: ${f.path} (-${f.removedCount}/+${f.addedCount})`,
        weight: 15,
      });
    }
  }

  const stats = diffStats(files);
  if (stats.addedLines >= LARGE_DIFF_LINES) {
    hits.push({
      ruleId: 'large-diff',
      message: `Diff adds ${stats.addedLines} lines (>= ${LARGE_DIFF_LINES})`,
      weight: 20,
    });
  }

  let score = 0;
  for (const h of hits) score += h.weight;
  score = Math.min(100, score);

  const docsOnly =
    files.length > 0 &&
    files.every((f) => DOC_EXTS.some((e) => f.path.toLowerCase().endsWith(e)));
  const configOnly =
    files.length > 0 &&
    files.every((f) => [...DOC_EXTS, ...CONFIG_EXTS].some((e) => f.path.toLowerCase().endsWith(e)));

  const cosmetic = isCosmeticOnly(files);
  const codePresent = hasCode(files);

  return {
    score,
    noul: {
      maliciousObfuscation: obfFound,
      hardcodedSecrets: secretFound,
      reasons: noulReasons,
    },
    hits,
    addedLines: stats.addedLines,
    removedLines: stats.removedLines,
    files: stats.files,
    docsOnly,
    cosmeticOnly: cosmetic || docsOnly || (configOnly && score === 0),
    codePresent,
  };
}

/**
 * The router decision itself.Runs in O(1) after the scan.
 */
export function decide(h: HeuristicResult): Choice {
  // Noul first: malicious content NEVER reaches the deep reviewer - it goes
  // straight to a human.
  if (h.noul.maliciousObfuscation || h.noul.hardcodedSecrets) {
    return 'security_risk';
  }
  if (h.score >= FULL_REVIEW_SCORE) return 'full_review';
  if (h.addedLines >= LARGE_DIFF_LINES) return 'full_review';
  if (h.hits.some((x) => x.ruleId === 'test-deletion')) return 'full_review';
  if (h.hits.some((x) => x.ruleId.startsWith('ci-'))) {
    // CI/supply-chain changes are only trivial when the diff touched nothing else.
    if (!h.docsOnly && !h.cosmeticOnly) return 'full_review';
  }
  if (h.docsOnly || h.cosmeticOnly) return 'trivial';
  if (h.addedLines === 0) return 'trivial';
  // Any diff still carrying real code deserves a System 2 pass: the text-level
  // patterns above only catch what they know - absence of hits is not safety.
  return h.codePresent ? 'full_review' : 'trivial';
}

export function gateConfidence(h: HeuristicResult): number {
  if (h.noul.maliciousObfuscation || h.noul.hardcodedSecrets) return 0.95;
  if (h.score === 0) return 0.9;
  if (Math.abs(h.score - FULL_REVIEW_SCORE) > 15) return 0.8;
  return 0.6; // borderline score: least confident routing
}

/**
 * Does this diff contain any code at all? (used by the skip path)
 */
export function hasCode(files: DiffFile[]): boolean {
  return files.some((f) => isCodeFile(f.path) && f.addedCount > 0);
}
