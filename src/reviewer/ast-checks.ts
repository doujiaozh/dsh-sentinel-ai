/**
 * sentinel_reviewer / ast-checks - the deterministic spine of System 2.
 *
 * Parses each changed JS/TS snippet with @babel/parser (pure JS, no native
 * modules) and walks the tree with a tiny generic visitor - no
 * @babel/traverse dependency needed. Findings carry REAL line numbers in the
 * new file, so they survive the anti-hallucination filter by construction.
 */

import { parse } from '@babel/parser';
import type { DiffFile, DiffLine } from '../util/diff';
import { isCodeFile, mapSnippetLine } from '../util/diff';
import { isHighEntropy } from '../util/entropy';
import type { Finding, Severity } from '../types';

// babel's PluginConfig union is version-sensitive; keep it loosely typed.
const EXT_PLUGINS: Record<string, any[]> = {
  '.js': ['jsx'],
  '.jsx': ['jsx'],
  '.mjs': ['jsx'],
  '.cjs': ['jsx'],
  '.ts': ['typescript'],
  '.tsx': ['typescript', 'jsx'],
};

const CHILD_PROCESS_CALLS = new Set(['exec', 'execSync', 'spawn', 'spawnSync']);
const SCHEDULER_STRINGS = new Set(['setTimeout', 'setInterval', 'setImmediate']);
const SQL_KEYWORDS = /\b(?:select|insert|update|delete|drop|union|truncate)\b/i;

export interface AstContext {
  file: DiffFile;
  snippet: string;
  lines: DiffLine[];
  childProcessImported: boolean;
}

/**
 * Parse the added lines of a diff file. Returns null when the file is not
 * parseable JS/TS or contains no added lines.
 */
function buildContext(file: DiffFile): AstContext | null {
  if (!isCodeFile(file.path) || file.added.length === 0) return null;
  const ext = file.path.slice(file.path.lastIndexOf('.')).toLowerCase();
  const snippet = file.added.map((l) => l.text).join('\n');
  return { file, snippet, lines: file.added, childProcessImported: false };
}

function tryParse(ctx: AstContext): import('@babel/types').File | null {
  const plugins = EXT_PLUGINS[ctx.file.path.slice(ctx.file.path.lastIndexOf('.')).toLowerCase()] ?? ['jsx'];  try {
    return parse(ctx.snippet, {
      sourceType: 'unambiguous',
      plugins,
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
  } catch {
    return null; // a snippet that is not standalone-parseable is skipped, never fatal
  }
}

/** Naive recursive AST walker - visits every node with a `type`. */
function walk(node: unknown, visit: (n: any) => void): void {
  if (!node || typeof node !== 'object' || typeof (node as any).type !== 'string') return;
  visit(node as any);
  for (const key of Object.keys(node as object)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' ||
        key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') {
      continue;
    }
    const value = (node as any)[key];
    if (Array.isArray(value)) {
      for (const item of value) walk(item, visit);
    } else if (value && typeof value === 'object' && typeof value.type === 'string') {
      walk(value, visit);
    }
  }
}

function locLine(node: any): number | null {
  const loc = node?.loc;
  if (!loc || typeof loc.start?.line !== 'number') return null;
  return loc.start.line;
}

/** true when the snippet imports/requires child_process */
function detectChildProcess(ast: any): boolean {
  let found = false;
  walk(ast, (n) => {
    if (n.type === 'CallExpression') {
      const callee = n.callee;
      if (callee?.type === 'Identifier' && callee.name === 'require' &&
        n.arguments?.[0]?.type === 'StringLiteral' && n.arguments[0].value === 'child_process') {
        found = true;
      }
    }
    if (n.type === 'ImportDeclaration' && n.source?.value === 'child_process') found = true;
  });
  return found;
}

export function runAstChecks(file: DiffFile): Finding[] {
  const ctx = buildContext(file);
  if (!ctx) return [];
  const ast = tryParse(ctx);
  if (!ast) return [];

  const childProcessImported = detectChildProcess(ast);
  const findings: Array<{ ruleId: string; message: string; severity: Severity; snippetLine: number | null }> = [];

  walk(ast, (n) => {
    const type: string = n.type;

    if (type === 'CallExpression') {
      const callee = n.callee;
      const first = n.arguments?.[0];
      const calleeName = callee?.type === 'Identifier' ? callee.name : callee?.property?.name;

      // eval(...) - never acceptable
      if (calleeName === 'eval') {
        findings.push({ ruleId: 'ast-eval', message: 'eval() executes attacker-controlled strings', severity: 'critical', snippetLine: locLine(n) });
      }
      // setTimeout("code", ...) - eval in disguise
      if (SCHEDULER_STRINGS.has(calleeName) && first?.type === 'StringLiteral') {
        findings.push({ ruleId: 'ast-scheduler-string', message: `${calleeName}() called with a string argument (implicit eval)`, severity: 'warning', snippetLine: locLine(n) });
      }
      // child_process execution with dynamic argument
      if (CHILD_PROCESS_CALLS.has(calleeName) && first && first.type !== 'StringLiteral') {
        findings.push({
          ruleId: 'ast-dynamic-exec',
          message: `child_process.${calleeName}() with non-literal command (command injection surface)`,
          severity: childProcessImported ? 'critical' : 'warning',
          snippetLine: locLine(n),
        });
      }
    }

    if (type === 'NewExpression' && n.callee?.type === 'Identifier' && n.callee.name === 'Function') {
      findings.push({ ruleId: 'ast-function-constructor', message: 'new Function(...) is eval with a lambda suit', severity: 'critical', snippetLine: locLine(n) });
    }

    if (type === 'AssignmentExpression') {
      const left = n.left;
      // process.env.TOKEN = "<literal>" style secret pinning
      if (left?.type === 'MemberExpression' &&
        left.object?.type === 'MemberExpression' &&
        left.object.object?.name === 'process' &&
        left.object.property?.name === 'env' &&
        n.right?.type === 'StringLiteral' && isHighEntropy(n.right.value)) {
        findings.push({ ruleId: 'ast-env-secret-pin', message: 'High-entropy value pinned into process.env', severity: 'warning', snippetLine: locLine(n) });
      }
    }

    if (type === 'BinaryExpression' && n.operator === '+') {
      // SQL string concatenation: 'SELECT ... ' + <dynamic>
      const sqlSide = [n.left, n.right].find((s) => s?.type === 'StringLiteral' && SQL_KEYWORDS.test(s.value));
      if (sqlSide && (n.left?.type !== 'StringLiteral' || n.right?.type !== 'StringLiteral')) {
        findings.push({ ruleId: 'ast-sql-concat', message: 'SQL statement built by string concatenation (injection surface)', severity: 'critical', snippetLine: locLine(n) });
      }
    }

    if (type === 'StringLiteral') {
      if (isHighEntropy(n.value) && !/^[a-z]+(?:-[a-z]+)*$/.test(n.value)) {
        findings.push({ ruleId: 'ast-high-entropy-literal', message: `High-entropy literal ("${n.value.slice(0, 12)}…") - likely secret or obfuscated payload`, severity: 'warning', snippetLine: locLine(n) });
      }
    }

    if (type === 'Identifier' && /^_0x[0-9a-f]{2,}$/i.test(n.name)) {
      findings.push({ ruleId: 'ast-obfuscated-identifier', message: `Obfuscated identifier name ${n.name}`, severity: 'warning', snippetLine: locLine(n) });
    }

    if (type === 'JSXAttribute' && n.name?.name === 'dangerouslySetInnerHTML' &&
      n.value?.type === 'JSXExpressionContainer' && n.value.expression?.type !== 'StringLiteral') {
      findings.push({ ruleId: 'ast-dangerous-innerhtml', message: 'dangerouslySetInnerHTML bound to a dynamic value (XSS surface)', severity: 'warning', snippetLine: locLine(n) });
    }
  });

  // Deduplicate per (rule, line) then translate snippet lines to real lines.
  const seen = new Set<string>();
  const mapped: Finding[] = [];
  for (const f of findings) {
    const line = f.snippetLine == null ? null : mapSnippetLine(file, f.snippetLine);
    const key = `${f.ruleId}:${file.path}:${line ?? 'null'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    mapped.push({
      ruleId: f.ruleId,
      message: f.message,
      severity: f.severity,
      file: file.path,
      line,
      column: null,
      source: 'ast',
    });
  }
  return mapped;
}

/**
 * Run AST checks across every code file in a diff.
 */
export function runAstChecksOnDiff(files: DiffFile[]): { findings: Finding[]; checked: string[] } {
  const findings: Finding[] = [];
  const checked: string[] = [];
  for (const f of files) {
    if (!isCodeFile(f.path) || f.added.length === 0) continue;
    checked.push(f.path);
    findings.push(...runAstChecks(f));
  }
  return { findings, checked };
}
