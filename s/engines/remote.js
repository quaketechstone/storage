/**
 * 远端 Provider 客户端：通过真实 HTTP 访问 `remote-server.mjs`。
 *
 * 与 SQLite 引擎同契约、同语义。区别只在「数据放哪」——放远端服务，而非本进程。
 * 客户端负责用 `computeNextRecord` 算 rev/hash（单一事实来源），服务端只做
 * 持久化 + 并发冲突判定 + 原子提交。
 */
import { STORAGE_OPS, STORAGE_ERROR_CODES } from '../contract.js';
import { scopeId } from '../canonical.js';
import { storageErrorOf } from '../errors.js';
import { computeNextRecord } from './record.js';
function isKnownCode(c) {
    return STORAGE_ERROR_CODES.includes(c);
}
export async function createRemoteEngine(deps) {
    const endpoint = deps.endpoint.replace(/\/+$/, '');
    const doFetch = deps.fetchImpl ?? globalThis.fetch;
    const now = deps.now ?? (() => Date.now());
    async function rpc(op, payload) {
        let res;
        try {
            res = await doFetch(`${endpoint}/rpc`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ op, ...payload }),
            });
        }
        catch {
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        }
        if (!res.ok)
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        let body;
        try {
            body = (await res.json());
        }
        catch {
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        }
        if (!body.ok) {
            throw storageErrorOf(isKnownCode(body.code) ? body.code : 'STORAGE_UNAVAILABLE');
        }
        return body.value;
    }
    function rowToRecord(raw) {
        if (raw === null || raw === undefined)
            return null;
        const r = raw;
        return Object.freeze({
            value: r.value,
            rev: r.rev,
            bytes: r.bytes,
            hash: r.hash,
            ts: r.ts,
            deleted: r.deleted === true,
        });
    }
    const engine = {
        kind: 'remote',
        endpoint,
        capabilities() {
            return { ops: [...STORAGE_OPS], transactions: true, ttl: false, orderedList: true };
        },
        async get(scope, key) {
            const raw = await rpc('get', { scopeId: scopeId(scope), key });
            const rec = rowToRecord(raw);
            if (rec === null || rec.deleted)
                return null;
            return rec;
        },
        async put(scope, key, value, opts = {}) {
            const sid = scopeId(scope);
            const rawPrev = await rpc('get', { scopeId: sid, key });
            const prev = rowToRecord(rawPrev);
            const next = await computeNextRecord(scope, key, value, prev, opts, now);
            const stored = await rpc('put', {
                scopeId: sid,
                key,
                record: next,
                baseRev: prev === null ? 0 : prev.rev,
            });
            return rowToRecord(stored) ?? next;
        },
        async del(scope, key, expectedRev) {
            const v = (await rpc('del', {
                scopeId: scopeId(scope),
                key,
                ...(expectedRev === undefined ? {} : { expectedRev }),
            }));
            return { removed: v.removed, bytes: v.bytes };
        },
        async list(scope, prefix = '') {
            const v = (await rpc('list', { scopeId: scopeId(scope), prefix }));
            return [...v];
        },
        async scan(scope, prefix = '', limit = 1000) {
            const v = (await rpc('scan', { scopeId: scopeId(scope), prefix, limit }));
            return v.map((x) => ({ key: x.key, rec: rowToRecord(x.rec) }));
        },
        async purge(scope) {
            return (await rpc('purge', { scopeId: scopeId(scope) }));
        },
        async usage(scope) {
            return (await rpc('usage', { scopeId: scopeId(scope) }));
        },
        async commit(mutations) {
            if (mutations.length === 0)
                return Object.freeze([]);
            // 读一次每个键的服务端当前值（用于算 rev 与 baseRev）。
            const prevByKey = new Map();
            const baseRev = new Map();
            for (const m of mutations) {
                const sid = scopeId(m.scope);
                const k = `${sid}\u0000${m.key}`;
                if (!prevByKey.has(k)) {
                    const raw = await rpc('get', { scopeId: sid, key: m.key });
                    const rec = rowToRecord(raw);
                    prevByKey.set(k, rec);
                    baseRev.set(k, rec === null ? 0 : rec.rev);
                }
            }
            // 本地暂存模拟，保证同键多次变更的 rev 递增正确。
            const staged = new Map(prevByKey);
            const payload = [];
            for (const m of mutations) {
                const sid = scopeId(m.scope);
                const k = `${sid}\u0000${m.key}`;
                const base = staged.get(k) ?? null;
                if (m.op === 'put') {
                    const next = await computeNextRecord(m.scope, m.key, m.value, base, m.opts ?? {}, now);
                    staged.set(k, next);
                    payload.push({ op: 'put', scopeId: sid, key: m.key, record: next, baseRev: baseRev.get(k) ?? 0 });
                }
                else {
                    if (base !== null) {
                        const expected = m.opts?.expectedRev;
                        if (expected !== undefined && expected !== 0 && base.rev !== expected) {
                            throw storageErrorOf('STORAGE_CONFLICT');
                        }
                        staged.set(k, null);
                        payload.push({
                            op: 'del',
                            scopeId: sid,
                            key: m.key,
                            ...(expected === undefined ? {} : { expectedRev: expected }),
                        });
                    }
                }
            }
            const results = (await rpc('commit', { mutations: payload }));
            return results.map((r) => rowToRecord(r));
        },
    };
    return engine;
}
