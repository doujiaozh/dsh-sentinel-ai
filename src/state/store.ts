/**
 * sentinel_state / store - dual-mode KV store.
 *
 * Pure-JS contract: ioredis (itself pure JS, ZERO native modules) when a Redis
 * URL is configured and reachable; an in-memory Map with per-key TTL timers
 * otherwise. Callers never see the difference - this is the "graceful
 * degradation" requirement of the Win7 no-native-module policy.
 */

export interface KVStore {
  readonly kind: 'memory' | 'redis';
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  setNx(key: string, value: string, ttlMs: number): Promise<boolean>;
  del(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
  quit(): Promise<void>;
}

export interface StoreOptions {
  redisUrl?: string;
  keyPrefix?: string;
  connectTimeoutMs?: number;
}

/* ---------------------------------------------------------------- *
 * Memory store                                                       *
 * ---------------------------------------------------------------- */

interface MemEntry {
  value: string;
  timer?: ReturnType<typeof setTimeout>;
  expiresAt: number;
}

export class MemoryKVStore implements KVStore {
  readonly kind = 'memory' as const;
  private readonly map = new Map<string, MemEntry>();
  /** OOM guard: hard cap, oldest entries evicted first. */
  constructor(private readonly maxKeys = 5000) {}

  async get(key: string): Promise<string | null> {
    const e = this.map.get(key);
    if (!e) return null;
    if (Date.now() >= e.expiresAt) {
      this.deleteEntry(key);
      return null;
    }
    return e.value;
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    this.evictIfNeeded();
    this.deleteEntry(key);
    const entry: MemEntry = { value, expiresAt: Date.now() + (ttlMs ?? Infinity) };
    if (ttlMs != null && Number.isFinite(ttlMs)) {
      entry.timer = setTimeout(() => this.deleteEntry(key), ttlMs);
      if (typeof (entry.timer as any)?.unref === 'function') (entry.timer as any).unref();
    }
    this.map.set(key, entry);
  }

  async setNx(key: string, value: string, ttlMs: number): Promise<boolean> {
    const existing = await this.get(key);
    if (existing !== null) return false;
    await this.set(key, value, ttlMs);
    return true;
  }

  async del(key: string): Promise<void> {
    this.deleteEntry(key);
  }

  async keys(prefix: string): Promise<string[]> {
    const out: string[] = [];
    for (const [k, e] of this.map) {
      if (Date.now() < e.expiresAt && k.startsWith(prefix)) out.push(k);
    }
    return out;
  }

  async quit(): Promise<void> {
    for (const [k] of this.map) this.deleteEntry(k);
  }

  private deleteEntry(key: string) {
    const e = this.map.get(key);
    if (e?.timer) clearTimeout(e.timer);
    this.map.delete(key);
  }

  private evictIfNeeded() {
    if (this.map.size < this.maxKeys) return;
    const oldest = [...this.map.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    while (this.map.size >= this.maxKeys && oldest.length > 0) {
      const [k] = oldest.shift()!;
      this.deleteEntry(k);
    }
  }
}

/* ---------------------------------------------------------------- *
 * Redis store (ioredis, lazily loaded, optional)                     *
 * ---------------------------------------------------------------- */

export class RedisKVStore implements KVStore {
  readonly kind = 'redis' as const;
  private readonly client: any;
  private readonly prefix: string;

  constructor(client: any, keyPrefix = 'sentinel:') {
    this.client = client;
    this.prefix = keyPrefix;
  }

  private k(key: string): string {
    return this.prefix + key;
  }

  async get(key: string): Promise<string | null> {
    const v = await this.client.get(this.k(key));
    return v ?? null;
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    if (ttlMs == null || !Number.isFinite(ttlMs)) {
      await this.client.set(this.k(key), value);
    } else {
      await this.client.set(this.k(key), value, 'PX', Math.ceil(ttlMs));
    }
  }

  async setNx(key: string, value: string, ttlMs: number): Promise<boolean> {
    const res = await this.client.set(this.k(key), value, 'PX', Math.ceil(ttlMs), 'NX');
    return res === 'OK';
  }

  async del(key: string): Promise<void> {
    await this.client.del(this.k(key));
  }

  async keys(prefix: string): Promise<string[]> {
    return (await this.client.keys(this.k(prefix) + '*')) as string[];
  }

  async quit(): Promise<void> {
    await this.client.quit().catch(() => undefined);
  }
}

/**
 * Build a store: Redis when configured AND reachable, memory otherwise.
 * A dead Redis never kills the pipeline - it degrades loudly but safely.
 */
export async function createStore(opts: StoreOptions = {}): Promise<KVStore> {
  const url = opts.redisUrl ?? process.env.SENTINEL_REDIS_URL;
  if (url) {
    let IORedis: any = null;
    try {
      // optionalDependencies: may legitimately be absent.
      IORedis = require('ioredis');
    } catch {
      console.warn('[sentinel-state] ioredis not installed -> memory mode');
    }
    if (IORedis) {
      const client = new IORedis(url, {
        connectTimeout: opts.connectTimeoutMs ?? 1500,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
      });
      try {
        await pendingWithTimeout(client.connect(), 1500, 'redis connect');
        console.warn(`[sentinel-state] Redis connected: ${redactUrl(url)}`);
        return new RedisKVStore(client, opts.keyPrefix);
      } catch (err) {
        console.warn(`[sentinel-state] Redis unreachable (${err instanceof Error ? err.message : err}) -> memory mode`);
        client.disconnect().catch(() => undefined);
      }
    }
  }
  return new MemoryKVStore();
}

function pendingWithTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

function redactUrl(url: string): string {
  return url.replace(/:\/\/[^@]+@/, '://***:***@');
}
