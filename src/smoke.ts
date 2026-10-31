/**
 * smoke.ts - offline verification of the whole Sentinel-AI contract.
 *   run: npm test
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { SentinelGate } from './gate';
import { Reviewer } from './reviewer/reviewer';
import { MockLLMAdapter } from './reviewer/llm-adapter';
import { SentinelStateMachine } from './state';
import { Pipeline } from './pipeline';
import { isTerminal } from './state';

const examples = path.resolve(__dirname, '..', 'examples');
const read = (n: string) => fs.readFileSync(path.join(examples, n), 'utf8');

let passed = 0;
let failed = 0;

async function check(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}\n        ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function main(): Promise<void> {
  console.log('\nSentinel-AI smoke tests\n');

  await check('S1 gate: trivial diff -> choice=trivial, no review', async () => {
    const gate = new SentinelGate();
    const v = await gate.verdict(read('diff-trivial.patch'));
    assert.strictEqual(v.choice, 'trivial');
    assert.ok(v.elapsedMs < 2000, `gate too slow: ${v.elapsedMs}ms`);
  });

  await check('S1 gate: security diff -> choice=security_risk + Noul flags', async () => {
    const gate = new SentinelGate();
    const v = await gate.verdict(read('diff-security.patch'));
    assert.strictEqual(v.choice, 'security_risk');
    assert.strictEqual(v.noul.hardcodedSecrets, true, 'must detect hardcoded secrets');
    assert.strictEqual(v.noul.maliciousObfuscation, true, 'must detect obfuscation');
    assert.ok(v.noul.reasons.length >= 2);
  });

  await check('S1 gate: big feature diff -> choice=full_review', async () => {
    const gate = new SentinelGate();
    const v = await gate.verdict(read('diff-full-review.patch'));
    assert.strictEqual(v.choice, 'full_review');
  });

  await check('S2: AST-only findings land on real code lines', async () => {
    const reviewer = new Reviewer({ astOnly: true });
    const res = await reviewer.review(read('diff-full-review.patch'));
    assert.ok(res.findings.length > 0, 'expected AST findings');
    const sql = res.findings.find((f) => f.ruleId === 'ast-sql-concat');
    assert.ok(sql, 'expected ast-sql-concat finding');
    assert.strictEqual(typeof sql.line, 'number');
    assert.ok(sql.line! > 0);
  });

  await check('S2: anti-hallucination drops comment/phantom LLM positions', async () => {
    const reviewer = new Reviewer({ llm: new MockLLMAdapter() });
    const res = await reviewer.review(read('diff-full-review.patch'));
    // The mock LLM fabricates: (a) a finding on a comment line, (b) a bogus
    // line beyond EOF. Both must be dropped, never reported.
    assert.ok(res.hallucinatedDropped >= 2, `expected >=2 hallucinated drops, got ${res.hallucinatedDropped}`);
    for (const f of res.findings) {
      if (f.source === 'llm') assert.notStrictEqual(f.ruleId, 'llm-data-exfiltration');
      assert.notStrictEqual(f.ruleId, 'llm-rce-backdoor');
    }
    const kept = res.findings.find((f) => f.ruleId === 'llm-leftover-log');
    assert.ok(kept, 'a genuinely-on-code-line LLM finding must survive');
  });

  await check('S3: async submit returns immediately + idempotency', async () => {
    const machine = new SentinelStateMachine({ defaultTtlMs: 60_000 });
    const t0 = Date.now();
    const h1 = await machine.submit('repo@sha-idem', { some: 'payload' });
    const h2 = await machine.submit('repo@sha-idem', { some: 'payload' });
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 2000, `submit should be instant, took ${elapsed}ms`);
    assert.strictEqual(h1.id, h2.id, 'duplicate key must resolve to same task');
    await machine.transition(h1.id, 'succeeded', 'test');
    await machine.stop();
  });

  await check('S3: illegal transitions are rejected', async () => {
    const machine = new SentinelStateMachine({ defaultTtlMs: 60_000 });
    const h = await machine.submit('repo@sha-illegal', {});
    await machine.transition(h.id, 'succeeded');
    await assert.rejects(() => machine.transition(h.id, 'in_progress'));
    await machine.stop();
  });

  await check('S3: TTL watchdog -> timeout + payload released (no OOM)', async () => {
    const machine = new SentinelStateMachine({ defaultTtlMs: 200 });
    const h = await machine.submit('repo@sha-timeout', { big: 'x'.repeat(1000) });
    await machine.startWork(h.id);
    const snap = await h.wait(1500);
    assert.ok(snap, 'no snapshot');
    assert.strictEqual(snap!.status, 'timeout');
    assert.strictEqual(snap!.purged, true, 'payload must be released on timeout');
    await machine.stop();
  });

  await check('S3 + S2 pipeline: timeout path aborts the hung LLM', async () => {
    const pipeline = new Pipeline({
      ttlMs: 300,
      gate: new SentinelGate(),
      reviewer: new Reviewer({ llm: new MockLLMAdapter({ simulate: 'llm-slow', latencyMs: 9000 }) }),
      machine: new SentinelStateMachine({ defaultTtlMs: 300 }),
    });
    const res = await pipeline.run({
      diff: read('diff-full-review.patch'),
      key: 'repo@sha-slow-llm',
    });
    assert.strictEqual(res.report.state.status, 'timeout');
    assert.ok(isTerminal(res.report.state.status));
    assert.ok(res.report.timing.totalMs < 5000, `pipeline should not block on the hung LLM (took ${res.report.timing.totalMs}ms)`);
  });

  await check('S3 + S2 pipeline: LLM error -> degraded AST-only review still succeeds', async () => {
    const pipeline = new Pipeline({
      ttlMs: 30_000,
      gate: new SentinelGate(),
      reviewer: new Reviewer({ llm: new MockLLMAdapter({ simulate: 'llm-error' }) }),
      machine: new SentinelStateMachine({ defaultTtlMs: 30_000 }),
    });
    const res = await pipeline.run({
      diff: read('diff-full-review.patch'),
      key: 'repo@sha-llm-error',
    });
    // The reviewer degrades to AST-only instead of failing the whole task: the
    // deterministic pass still returns a verdict, with the LLM outage recorded.
    assert.strictEqual(res.report.state.status, 'succeeded');
    assert.ok(res.review, 'AST-only review result must still be returned');
    assert.ok(res.review.degraded, 'review must be flagged degraded');
    assert.ok(
      res.review.findings.some((f) => f.ruleId === 'llm-degraded'),
      'an llm-degraded notice finding must be attached'
    );
  });

  await check('end-to-end demo scenarios via Pipeline (memory store)', async () => {
    for (const [name, file, expected] of [
      ['trivial', 'diff-trivial.patch', 'trivial'],
      ['security', 'diff-security.patch', 'security_risk'],
      ['full', 'diff-full-review.patch', 'full_review'],
    ] as const) {
      const machine = new SentinelStateMachine({ defaultTtlMs: 60_000 });
      const pipeline = new Pipeline({ machine, ttlMs: 60_000 });
      const res = await pipeline.run({ diff: read(file), key: `smoke@${name}` });
      assert.strictEqual(res.gateChoice, expected, `scenario ${name}`);
      assert.ok(isTerminal(res.report.state.status), `${name}: task must terminate`);
      await machine.stop();
    }
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
