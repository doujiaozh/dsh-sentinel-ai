#!/usr/bin/env node
/**
 * sentinel_cli - end-to-end demo of the Sentinel-AI pipeline.
 *
 * Simulates receiving a GitHub Webhook push (examples/webhook-push.json is a
 * ready-made fake payload), runs System 1 triage, then either skips, escalates
 * or drives System 2 deep review through the async timeout state machine, and
 * prints the final report as JSON.
 *
 * Usage:
 *   node dist/cli.js demo                       # run all 3 built-in scenarios
 *   node dist/cli.js demo --simulate llm-slow   # force the timeout path
 *   node dist/cli.js demo --simulate llm-error  # force review failure path
 *   node dist/cli.js review --diff path/to.diff --key repo@sha
 *   node dist/cli.js gate --diff path/to.diff   # System 1 verdict only
 *
 * Env:
 *   SENTINEL_LLM_BASE_URL / SENTINEL_LLM_API_KEY / SENTINEL_LLM_MODEL
 *   SENTINEL_LLM_SIMULATE=none|llm-error|llm-slow
 *   SENTINEL_JEV_URL / SENTINEL_JEV_API_KEY
 *   SENTINEL_REDIS_URL (optional; memory store by default)
 *   SENTINEL_TTL_MS (default 1800000 = 30 min)
 */

import * as fs from 'fs';
import * as path from 'path';
import { SentinelGate } from './gate';
import { Reviewer } from './reviewer/reviewer';
import { SentinelStateMachine } from './state';
import { MockLLMAdapter } from './reviewer/llm-adapter';
import { Pipeline } from './pipeline';
import type { SentinelReport } from './types';

interface CliArgs {
  command: string;
  diff?: string;
  key?: string;
  simulate?: 'none' | 'llm-slow' | 'llm-error';
  ttlMs?: number;
  out?: string;
  help?: boolean;
  webhook?: string;
}

const log = (s: string) => process.stderr.write(s + '\n');

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { command: argv[0] ?? 'demo' };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--diff') args.diff = argv[++i];
    else if (a === '--key') args.key = argv[++i];
    else if (a === '--simulate') args.simulate = argv[++i] as CliArgs['simulate'];
    else if (a === '--ttl') args.ttlMs = parseInt(argv[++i] ?? '', 10);
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--webhook') args.webhook = argv[++i];
    else if (a === '-h' || a === '--help') args.help = true;
  }
  return args;
}

const USAGE = `
Sentinel-AI CLI  (System 1 gate + System 2 deep review + async state machine)

  demo                        run the 3 built-in webhook scenarios
    --simulate llm-slow       simulate an LLM that exceeds the TTL (timeout path)
    --simulate llm-error      simulate an LLM failure (failed path)
    --ttl <ms>                override the state machine TTL
    --out <file>              write the last report JSON to a file
  review --diff <file>        review a real diff file
    --key <repo@sha>          idempotency key (required)
  gate --diff <file>          System 1 verdict only, no review

Env: SENTINEL_JEV_URL, SENTINEL_LLM_BASE_URL, SENTINEL_LLM_API_KEY,
     SENTINEL_LLM_MODEL, SENTINEL_REDIS_URL, SENTINEL_TTL_MS
`.trim();

function examplesDir(): string {
  return path.resolve(__dirname, '..', 'examples');
}

function readExample(name: string): string {
  return fs.readFileSync(path.join(examplesDir(), name), 'utf8');
}

interface Scenario {
  name: string;
  webhookFile: string;
  commitSha: string;
  commitMessage: string;
  diffFile: string;
}

const SCENARIOS: Scenario[] = [
  {
    name: 'docs-typo',
    webhookFile: 'webhook-push.json',
    commitSha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    commitMessage: 'docs: fix typo in README',
    diffFile: 'diff-trivial.patch',
  },
  {
    name: 'legacy-auth-rewrite',
    webhookFile: 'webhook-push.json',
    commitSha: 'b2c3d4e5f60718293a4b5c6d7e8f9012345678a',
    commitMessage: 'feat(auth): re-add legacy sign-in (quick win)',
    diffFile: 'diff-security.patch',
  },
  {
    name: 'user-service-refactor',
    webhookFile: 'webhook-push.json',
    commitSha: 'c3d4e5f60718293a4b5c6d7e8f9012345678ab',
    commitMessage: 'feat(user): inline user lookup + report export',
    diffFile: 'diff-full-review.patch',
  },
];

async function runScenario(
  scenario: Scenario,
  args: CliArgs
): Promise<SentinelReport> {
  const diff = readExample(scenario.diffFile);
  let webhook: any = {};
  try {
    webhook = JSON.parse(readExample(scenario.webhookFile));
  } catch {
    webhook = {};
  }

  const repo = webhook?.repository?.full_name ?? 'acme/payments-core';
  const ref = webhook?.ref ?? 'refs/heads/main';

  const simulate = args.simulate ?? 'none';
  const defaultTtl = args.ttlMs ?? Number(process.env.SENTINEL_TTL_MS ?? 1800000);
  // llm-slow demo: compress the TTL so the watchdog visibly fires.
  const ttlMs = simulate === 'llm-slow' ? (args.ttlMs ?? 3000) : defaultTtl;

  const machine = new SentinelStateMachine({ defaultTtlMs: ttlMs });
  const reviewer = new Reviewer({
    llm: process.env.SENTINEL_LLM_BASE_URL
      ? undefined // real adapter via factory
      : new MockLLMAdapter({ simulate, ...(simulate === 'llm-slow' ? { latencyMs: 9000 } : {}) }),
  });
  const gate = new SentinelGate();

  const pipeline = new Pipeline({ gate, reviewer, machine, ttlMs });

  log('');
  log('╔══════════════════════════════════════════════════════════════╗');
  log(`║  WEBHOOK simulated: ${scenario.name.padEnd(45)}║`);
  log('╚══════════════════════════════════════════════════════════════╝');
  log(`  repo   : ${repo}`);
  log(`  ref    : ${ref}`);
  log(`  commit : ${scenario.commitSha.slice(0, 10)} ${scenario.commitMessage}`);
  log(`  ttl    : ${ttlMs}ms  simulate=${simulate}`);

  machine.on('transition', (evt: any) => {
    log(`  [state] ${evt.from} -> ${evt.to}${evt.reason ? ` (${evt.reason})` : ''}`);
  });

  const result = await pipeline.run({
    diff,
    key: `${repo}@${scenario.commitSha}`,
    webhook: { repo, ref, commit: scenario.commitSha, message: scenario.commitMessage },
  });

  const r = result.report;
  log('');
  log(`  GATE  : choice=${r.gate.choice} risk=${r.gate.score.risk}/100 ` +
    `engine=${r.gate.engine} elapsed=${r.gate.elapsedMs}ms`);
  if (r.gate.noul.maliciousObfuscation || r.gate.noul.hardcodedSecrets) {
    log(`  NOUL  : obfuscation=${r.gate.noul.maliciousObfuscation} secrets=${r.gate.noul.hardcodedSecrets}`);
  }
  log(`  STATE : task=${r.state.taskId} status=${r.state.status} purged=${r.state.purged}`);
  if (r.review) {
    log(`  REVIEW: decision=${r.review.decision} score=${r.review.score} ` +
      `findings=${r.review.findings.length} hallucinated-dropped=${r.review.hallucinatedDropped}`);
    for (const f of r.review.findings) {
      log(`    [${f.severity.padEnd(8)}] ${f.ruleId} ${f.file}${f.line ? `:${f.line}` : ''} - ${f.message}`);
    }
  }
  log(`  FINAL : decision=${r.final.decision} | ${r.final.reason}`);
  log(`  TOTAL : ${r.timing.totalMs}ms`);
  await machine.stop().catch(() => undefined);
  return r;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.command) {
    console.log(USAGE);
    return 0;
  }

  if (args.command === 'demo') {
    const reports: SentinelReport[] = [];
    for (const s of SCENARIOS) {
      reports.push(await runScenario(s, args));
    }
    const summary = reports.map((r) => ({
      commit: r.webhook.commit.slice(0, 10),
      gate: r.gate.choice,
      status: r.state.status,
      decision: r.final.decision,
      totalMs: r.timing.totalMs,
    }));
    console.log(JSON.stringify({ pipeline: 'dsh-sentinel-ai', scenarios: summary, lastReport: reports[reports.length - 1] }, null, 2));
    if (args.out) {
      fs.writeFileSync(args.out, JSON.stringify(reports[reports.length - 1], null, 2), 'utf8');
      log(`\nreport written to ${args.out}`);
    }
    return 0;
  }

  if (args.command === 'gate' || args.command === 'review') {
    if (!args.diff) {
      console.error('--diff <file> is required');
      return 2;
    }
    const diff = fs.readFileSync(args.diff, 'utf8');
    const gate = new SentinelGate();
    const verdict = await gate.verdict(diff);
    if (args.command === 'gate') {
      console.log(JSON.stringify(verdict, null, 2));
      return 0;
    }
    const key = args.key ?? `cli@${require('crypto').createHash('sha1').update(diff).digest('hex')}`;
    const ttlMs = args.ttlMs ?? Number(process.env.SENTINEL_TTL_MS ?? 1800000);
    const machine = new SentinelStateMachine({ defaultTtlMs: ttlMs });
    machine.on('transition', (evt: any) => {
      log(`  [state] ${evt.from} -> ${evt.to}${evt.reason ? ` (${evt.reason})` : ''}`);
    });
    const pipeline = new Pipeline({ gate, machine, ttlMs });
    const result = await pipeline.run({ diff, key });
    console.log(JSON.stringify(result.report, null, 2));
    await machine.stop().catch(() => undefined);
    return 0;
  }

  console.error(`unknown command: ${args.command}\n\n${USAGE}`);
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('sentinel-cli fatal:', err);
    process.exit(1);
  });
