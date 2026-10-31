/**
 * Shannon entropy helpers - used to catch hardcoded secrets and obfuscated
 * blobs without any model call. Pure arithmetic, zero dependencies.
 */

const LOG2 = Math.log(2);

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  const len = s.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= (p * Math.log(p)) / LOG2;
  }
  return entropy;
}

const FALSE_POSITIVE_PREFIXES = [
  'http://',
  'https://',
  'data:image/',
  'data:text/',
  'UTF-8',
  'utf-8',
];

/**
 * True when a string literal is long AND high-entropy: the fingerprint of a
 * hardcoded secret or an obfuscated payload (generic base64/hex blobs).
 */
export function isHighEntropy(
  s: string,
  opts: { threshold?: number; minLen?: number } = {}
): boolean {
  const threshold = opts.threshold ?? 4.5;
  const minLen = opts.minLen ?? 24;
  if (!s || s.length < minLen) return false;
  for (const prefix of FALSE_POSITIVE_PREFIXES) {
    if (s.startsWith(prefix)) return false;
  }
  // Plain english sentences have low entropy; keys/ptokens usually > 4.5.
  return shannonEntropy(s) >= threshold;
}
