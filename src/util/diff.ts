/**
 * Unified-diff parser.
 *
 * Zero-dependency, tolerant of `diff --git` headers as well as bare
 * `--- a/... +++ b/...` hunks. Produces per-file added/removed lines with
 * 1-based line numbers from the NEW file - which is exactly what the
 * anti-hallucination layer needs to verify LLM-claimed positions.
 */

export interface DiffLine {
  /** 1-based line number in the new file. */
  lineNo: number;
  text: string;
}

export interface DiffFile {
  path: string;
  oldPath: string | null;
  isNew: boolean;
  isDeleted: boolean;
  added: DiffLine[];
  removed: DiffLine[];
  addedCount: number;
  removedCount: number;
}

const CODE_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
]);

export function isCodeFile(path: string): boolean {
  const i = path.lastIndexOf('.');
  if (i < 0) return false;
  return CODE_EXTS.has(path.slice(i).toLowerCase());
}

function cleanPath(header: string): string {
  let p = header.trim();
  if (p.startsWith('"') && p.endsWith('"')) p = p.slice(1, -1);
  if (p.startsWith('a/') || p.startsWith('b/')) p = p.slice(2);
  return p === '/dev/null' ? '' : p;
}

function newFile(path: string): DiffFile {
  return {
    path,
    oldPath: null,
    isNew: false,
    isDeleted: false,
    added: [],
    removed: [],
    addedCount: 0,
    removedCount: 0,
  };
}

export function parseUnifiedDiff(diff: string): DiffFile[] {
  const files: DiffFile[] = [];
  let current: DiffFile | null = null;
  let oldLine = 0;
  let newLine = 0;

  const lines = diff.split(/\r?\n/);
  for (const raw of lines) {
    if (raw.startsWith('diff --git')) {
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
      current = newFile(m ? m[2] : 'unknown');
      files.push(current);
    } else if (raw.startsWith('new file mode')) {
      if (current) current.isNew = true;
    } else if (raw.startsWith('deleted file mode')) {
      if (current) current.isDeleted = true;
    } else if (raw.startsWith('--- ')) {
      if (!current) {
        current = newFile('');
        files.push(current);
      }
      const oldP = cleanPath(raw.slice(4));
      current.oldPath = oldP || null;
      if (!current.path) current.path = oldP;
    } else if (raw.startsWith('+++ ')) {
      if (!current) {
        current = newFile('');
        files.push(current);
      }
      const newP = cleanPath(raw.slice(4));
      if (newP) current.path = newP;
    } else if (raw.startsWith('@@')) {
      const m = /@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      if (m) {
        oldLine = parseInt(m[1], 10);
        newLine = parseInt(m[2], 10);
      }
    } else if (current) {
      if (raw.startsWith('+++') || raw.startsWith('---')) continue;
      if (raw.startsWith('+')) {
        current.added.push({ lineNo: newLine, text: raw.slice(1) });
        current.addedCount++;
        newLine++;
      } else if (raw.startsWith('-')) {
        current.removed.push({ lineNo: oldLine, text: raw.slice(1) });
        current.removedCount++;
        oldLine++;
      } else if (raw.startsWith('\\')) {
        // "\ No newline at end of file"
      } else {
        oldLine++;
        newLine++;
      }
    }
  }

  return files.filter((f) => f.path);
}

/**
 * Total added/removed counters across a diff.
 */
export function diffStats(files: DiffFile[]): {
  files: number;
  addedLines: number;
  removedLines: number;
} {
  let addedLines = 0;
  let removedLines = 0;
  for (const f of files) {
    addedLines += f.addedCount;
    removedLines += f.removedCount;
  }
  return { files: files.length, addedLines, removedLines };
}

/**
 * Map a line number inside a snippet (added lines joined together) back to the
 * real 1-based line number in the new file. Returns null when the snippet line
 * does not correspond to an added line.
 */
export function mapSnippetLine(
  file: DiffFile,
  snippetLine: number
): number | null {
  const idx = snippetLine - 1;
  if (idx < 0 || idx >= file.added.length) return null;
  return file.added[idx]?.lineNo ?? null;
}

/**
 * Detect whether a diff hunk is ONLY whitespace / comment noise.
 */
export function isCosmeticOnly(files: DiffFile[]): boolean {
  if (files.length === 0) return true;
  for (const f of files) {
    for (const l of [...f.added, ...f.removed]) {
      const t = l.text;
      if (t.trim().length === 0) continue;
      if (isCommentOnly(t)) continue;
      return false;
    }
  }
  return true;
}

function isCommentOnly(text: string): boolean {
  return /^\s*(\/\/|\/\*|\*|;|<!--)/.test(text);
}
