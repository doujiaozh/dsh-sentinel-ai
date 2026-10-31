/**
 * sentinel_reviewer / hallucination - anti-hallucination ("position drift")
 * filter.
 *
 * The #1 failure mode of LLM code review is confidently citing a line that is
 * empty or a comment. Sentinel-AI refuses to trust positions: every LLM
 * finding is re-projected onto the actual changed lines of the NEW file, and
 * anything that lands on whitespace or a comment line is DISCARDED, never
 * shown to the human.
 */

import type { DiffFile } from '../util/diff';
import type { Finding } from '../types';

export type LineTable = Map<string, Map<number, string>>;

/**
 * Build { file => { lineNo => sourceText } } from the ADDED lines of a diff.
 * LLM findings may only ever reference lines present here.
 */
export function buildLineTable(files: DiffFile[]): LineTable {
  const table: LineTable = new Map();
  for (const f of files) {
    const inner = new Map<number, string>();
    for (const l of f.added) inner.set(l.lineNo, l.text);
    table.set(f.path, inner);
  }
  return table;
}

/** Is this line a comment in the given file's language? */
export function isCommentLine(text: string, filePath: string): boolean {
  const ext = filePath.slice(filePath.lastIndexOf('.') + 1).toLowerCase();
  const COMMENT_MARKERS: Record<string, string | string[]> = {
    js: '//', jsx: '//', mjs: '//', cjs: '//', ts: '//', tsx: '//',
    py: '#', sh: '#', yml: '#', yaml: '#', toml: '#', dockerfile: '#',
    html: '<!--', md: ['<!--', '<!---'],
  };
  const commentMarkers = COMMENT_MARKERS[ext] ?? ['#', '//'];

  const markers: string[] = Array.isArray(commentMarkers) ? commentMarkers : [commentMarkers];
  const trimmed = text.trimStart();
  return markers.some((m) => trimmed.startsWith(m)) || trimmed.startsWith('*');
}

/** Is this line empty or whitespace-only? */
export function isBlankLine(text: string): boolean {
  return text == null || text.trim().length === 0;
}

export interface FilterOutcome {
  kept: Finding[];
  dropped: Finding[];
}

/**
 * Validate an array of (possibly LLM-fabricated) findings against reality.
 */
export function filterHallucinatedFindings(
  findings: Finding[],
  table: LineTable
): FilterOutcome {
  const kept: Finding[] = [];
  const dropped: Finding[] = [];

  for (const f of findings) {
    // 1) unknown file -> drop
    const fileLines = table.get(f.file);
    if (!fileLines) {
      dropped.push({ ...f, message: `[dropped: file not in diff] ${f.message}` });
      continue;
    }
    // 2) file-level finding (no line) -> keep, nothing to verify
    if (f.line == null) {
      kept.push(f);
      continue;
    }
    // 3) line number out of the changed range -> drop (position drift)
    const text = fileLines.get(f.line);
    if (text === undefined) {
      dropped.push({ ...f, message: `[dropped: line ${f.line} not in changed range] ${f.message}` });
      continue;
    }
    // 4) lands on an empty line -> drop
    if (isBlankLine(text)) {
      dropped.push({ ...f, message: `[dropped: line ${f.line} is blank] ${f.message}` });
      continue;
    }
    // 5) lands on a comment line -> drop
    if (isCommentLine(text, f.file)) {
      dropped.push({ ...f, message: `[dropped: line ${f.line} is a comment] ${f.message}` });
      continue;
    }
    kept.push(f);
  }

  return { kept, dropped };
}
