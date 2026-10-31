/**
 * IndexedDB 引擎：生产引擎。语义与 `memory.ts` **逐条对齐**（见该文件顶部表格）。
 *
 * # 与内存引擎的唯一实质差异：写路径是两阶段
 *
 * 记录 hash 含 `rev`，而 `rev` 只有读到旧记录才知道；摘要计算又必须 `await`
 * `crypto.subtle`，它会把 IDB 事务提前提交（见 `idb-db.ts` 顶部说明）。因此写入
 * 拆成两步：
 *
 * ```
 *   ① 只读事务读 prev  →  事务外算 rev/bytes/hash
 *   ② 读写事务读 prev  →  与 ① 的 rev 比对（CAS）→ 不一致则 CONFLICT → 写入
 * ```
 *
 * 第 ② 步的比对不是冗余：两个标签页可能同时写同一个键，①读到的 prev 可能已经过期。
 * 少了这一步，后写者会用错误的 rev 覆盖前者且**不会报冲突**——这正是"丢失更新"。
 *
 * # 为什么不把 hash 改成"只对 value 算"
 *
 * 那样可以一步写完（先算 hash 再开事务）。但 hash 不含 `rev` 时，攻击者可以把旧版本
 * 记录整条搬回来（rev 回退）而校验依旧通过。`rev` 进摘要让"回退"可检出。
 *
 * # 已知未实现
 *
 * - TTL 过期：`capabilities().ttl = false`。如实声明，不假装支持。
 * - 跨 store 事务：只有一个 store，天然不需要。
 * - 读时完整性校验：不在引擎内做（引擎不知道策略），由 `integrity.ts` 在网关层做。
 */
import { physicalKey } from '../contract.js';
import { recordBytes, recordHash } from '../canonical.js';
import { isStorageError, storageErrorOf, storageErrorWithRev } from '../errors.js';
import { STORE_RECORDS, closeStorageDb, idbErrorCode, idbRun, openStorageDb, req, } from './idb-db.js';
const ALL_OPS = Object.freeze([
    'read',
    'list',
    'scan',
    'write',
    'delete',
    'purge',
    'tx',
    'migrate',
    'backup',
    'restore',
    'keyAccess',
]);
function toRecord(row) {
    return Object.freeze({
        value: row.value,
        rev: row.rev,
        bytes: row.bytes,
        hash: row.hash,
        ts: row.ts,
        deleted: row.deleted,
    });
}
function scopeText(scope) {
    return `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`;
}
/**
 * 创建 IDB 引擎。
 *
 * 异步工厂：打开库本身是异步的。调用方（装配层）必须 await 它，**不能**先拿到
 * 一个"还没连上库"的引擎——那样第一次 `get` 会拿到 `undefined` 而不是 `null`，
 * 把"不存在"和"没准备好"混成一种。
 */
export async function createIdbEngine(deps = {}) {
    const now = deps.now ?? (() => Date.now());
    const db = await openStorageDb(deps);
    function fail(e) {
        // 本层自己抛的结构化错误（例如 CAS 复核的 `STORAGE_CONFLICT`）必须原样透出。
        // 曾经这里无条件走 `idbErrorCode`，而它只认 DOMException 的 `name`，于是
        // `{code:'STORAGE_CONFLICT'}` 被归一成 `STORAGE_UNAVAILABLE`——症状是
        // "两个标签页同时撤销 → 报存储不可用"，把可重试的冲突说成了故障。
        if (isStorageError(e))
            throw e;
        const code = idbErrorCode(e);
        if (code === 'STORAGE_QUOTA_EXCEEDED')
            throw storageErrorOf('STORAGE_QUOTA_EXCEEDED');
        if (code === 'STORAGE_VERSION_MISMATCH')
            throw storageErrorOf('STORAGE_VERSION_MISMATCH');
        if (code === 'STORAGE_TX_ABORTED')
            throw storageErrorOf('STORAGE_TX_ABORTED');
        if (code === 'STORAGE_CORRUPT')
            throw storageErrorOf('STORAGE_CORRUPT');
        throw storageErrorOf('STORAGE_UNAVAILABLE');
    }
    function scopePrefix(scope) {
        return physicalKey(scope, 'k').slice(0, -1);
    }
    /** 事务外计算下一条记录。与 `memory.ts` 的 `computeRecord` 同构。 */
    async function computeNext(scope, key, value, prev, opts) {
        const expected = opts.expectedRev;
        if (expected !== undefined) {
            if (expected === 0) {
                if (prev !== null)
                    throw storageErrorWithRev('STORAGE_CONFLICT', prev.rev);
            }
            else if (prev === null) {
                throw storageErrorOf('STORAGE_CONFLICT');
            }
            else if (prev.rev !== expected) {
                throw storageErrorWithRev('STORAGE_CONFLICT', prev.rev);
            }
        }
        const rev = prev === null ? 1 : prev.rev + 1;
        const bytes = recordBytes(value);
        const hash = await recordHash(scope, key, rev, value);
        return Object.freeze({
            value,
            rev,
            bytes,
            hash,
            ts: opts.ts ?? now(),
            deleted: opts.softDelete === true,
        });
    }
    function rowOf(scope, key, rec) {
        return {
            pk: physicalKey(scope, key),
            scope: scopeText(scope),
            key,
            value: rec.value,
            rev: rec.rev,
            bytes: rec.bytes,
            hash: rec.hash,
            ts: rec.ts,
            deleted: rec.deleted,
        };
    }
    /** 只读事务取一条原始行（含软删）。 */
    async function readRow(scope, key) {
        try {
            return await idbRun(db, STORE_RECORDS, 'readonly', async (tx) => {
                const got = (await req(tx.objectStore(STORE_RECORDS).get(physicalKey(scope, key))));
                return got ?? null;
            });
        }
        catch (e) {
            fail(e);
        }
    }
    const engine = {
        kind: 'idb',
        db,
        capabilities() {
            return {
                ops: ALL_OPS,
                transactions: true,
                // 如实置 false：本引擎不做过期清理。声明 true 而实际不清理，
                // 会让上层以为 `cache` 的 TTL 已经生效。
                ttl: false,
                orderedList: true,
            };
        },
        async get(scope, key) {
            const row = await readRow(scope, key);
            if (row === null)
                return null;
            return row.deleted ? null : toRecord(row);
        },
        async put(scope, key, value, opts = {}) {
            // ① 读 prev 并计算（事务外，因为要 await crypto）。
            const prevRow = await readRow(scope, key);
            const prev = prevRow === null ? null : toRecord(prevRow);
            const next = await computeNext(scope, key, value, prev, opts);
            const prevRev = prev === null ? 0 : prev.rev;
            // ② CAS 复核后写入。
            try {
                return await idbRun(db, STORE_RECORDS, 'readwrite', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    const cur = (await req(store.get(physicalKey(scope, key))));
                    const curRev = cur === undefined ? 0 : cur.rev;
                    if (curRev !== prevRev) {
                        // ① 与 ② 之间有人写过。报冲突而不是覆盖：覆盖会静默丢掉对方的写。
                        throw storageErrorWithRev('STORAGE_CONFLICT', curRev);
                    }
                    await req(store.put(rowOf(scope, key, next)));
                    return next;
                });
            }
            catch (e) {
                fail(e);
            }
        },
        async del(scope, key, expectedRev) {
            try {
                return await idbRun(db, STORE_RECORDS, 'readwrite', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    const cur = (await req(store.get(physicalKey(scope, key))));
                    if (cur === undefined)
                        return { removed: false, bytes: 0 };
                    if (expectedRev !== undefined && cur.rev !== expectedRev) {
                        throw storageErrorWithRev('STORAGE_CONFLICT', cur.rev);
                    }
                    await req(store.delete(cur.pk));
                    return { removed: true, bytes: cur.bytes };
                });
            }
            catch (e) {
                fail(e);
            }
        },
        async list(scope, prefix = '') {
            const sp = scopePrefix(scope);
            try {
                return await idbRun(db, STORE_RECORDS, 'readonly', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    const out = [];
                    // 用 lowerBound + 前缀判定终止，而不是 `bound(sp, sp + '\uffff')`：
                    // 后者对含星面字符（> U+FFFF）的键会漏。前缀判定没有这个盲区。
                    const cur = store.openCursor(IDBKeyRange.lowerBound(sp));
                    await new Promise((resolve, reject) => {
                        cur.onerror = () => reject(cur.error ?? new Error('cursor'));
                        cur.onsuccess = () => {
                            const c = cur.result;
                            if (c === null) {
                                resolve();
                                return;
                            }
                            const pk = String(c.key);
                            if (!pk.startsWith(sp)) {
                                resolve();
                                return;
                            }
                            const row = c.value;
                            if (!row.deleted) {
                                const logical = pk.slice(sp.length);
                                if (prefix === '' || logical.startsWith(prefix))
                                    out.push(logical);
                            }
                            c.continue();
                        };
                    });
                    return out;
                });
            }
            catch (e) {
                fail(e);
            }
        },
        async scan(scope, prefix = '', limit = 1000) {
            const sp = scopePrefix(scope);
            try {
                return await idbRun(db, STORE_RECORDS, 'readonly', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    const out = [];
                    const cur = store.openCursor(IDBKeyRange.lowerBound(sp));
                    await new Promise((resolve, reject) => {
                        cur.onerror = () => reject(cur.error ?? new Error('cursor'));
                        cur.onsuccess = () => {
                            const c = cur.result;
                            if (c === null || out.length >= limit) {
                                resolve();
                                return;
                            }
                            const pk = String(c.key);
                            if (!pk.startsWith(sp)) {
                                resolve();
                                return;
                            }
                            const row = c.value;
                            if (!row.deleted) {
                                const logical = pk.slice(sp.length);
                                if (prefix === '' || logical.startsWith(prefix)) {
                                    out.push(Object.freeze({ key: logical, rec: toRecord(row) }));
                                }
                            }
                            c.continue();
                        };
                    });
                    return out;
                });
            }
            catch (e) {
                fail(e);
            }
        },
        async purge(scope) {
            const sp = scopePrefix(scope);
            try {
                return await idbRun(db, STORE_RECORDS, 'readwrite', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    let n = 0;
                    const cur = store.openCursor(IDBKeyRange.lowerBound(sp));
                    await new Promise((resolve, reject) => {
                        cur.onerror = () => reject(cur.error ?? new Error('cursor'));
                        cur.onsuccess = () => {
                            const c = cur.result;
                            if (c === null) {
                                resolve();
                                return;
                            }
                            const pk = String(c.key);
                            if (!pk.startsWith(sp)) {
                                resolve();
                                return;
                            }
                            c.delete();
                            n++;
                            c.continue();
                        };
                    });
                    return n;
                });
            }
            catch (e) {
                fail(e);
            }
        },
        async usage(scope) {
            const sp = scopePrefix(scope);
            try {
                return await idbRun(db, STORE_RECORDS, 'readonly', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    let total = 0;
                    const cur = store.openCursor(IDBKeyRange.lowerBound(sp));
                    await new Promise((resolve, reject) => {
                        cur.onerror = () => reject(cur.error ?? new Error('cursor'));
                        cur.onsuccess = () => {
                            const c = cur.result;
                            if (c === null) {
                                resolve();
                                return;
                            }
                            const pk = String(c.key);
                            if (!pk.startsWith(sp)) {
                                resolve();
                                return;
                            }
                            total += c.value.bytes;
                            c.continue();
                        };
                    });
                    return total;
                });
            }
            catch (e) {
                fail(e);
            }
        },
        /**
         * 原子批量。
         *
         * 阶段与 `put` 相同，但**所有** CAS 在同一个事务内完成：任一键的 rev 与预读不符，
         * 整个事务 abort，一条都不写。IDB 的原生事务给了"全有或全无"，不需要内存引擎
         * 那样的快照回滚。
         */
        async commit(mutations) {
            if (mutations.length === 0)
                return Object.freeze([]);
            // ① 一次性预读全部 prev（同一只读事务，避免 N 次开事务）。
            const prevs = new Map();
            try {
                await idbRun(db, STORE_RECORDS, 'readonly', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    for (const m of mutations) {
                        const pk = physicalKey(m.scope, m.key);
                        if (prevs.has(pk))
                            continue;
                        const row = (await req(store.get(pk)));
                        prevs.set(pk, row === undefined ? null : toRecord(row));
                    }
                });
            }
            catch (e) {
                fail(e);
            }
            // ② 事务外计算终值。同一键多次出现时后一次以前一次为基。
            const staged = new Map();
            const results = [];
            for (const m of mutations) {
                const pk = physicalKey(m.scope, m.key);
                const base = staged.has(pk) ? (staged.get(pk) ?? null) : (prevs.get(pk) ?? null);
                if (m.op === 'put') {
                    const next = await computeNext(m.scope, m.key, m.value, base, m.opts ?? {});
                    staged.set(pk, next);
                    results.push(next);
                }
                else {
                    if (base !== null) {
                        const expected = m.opts?.expectedRev;
                        if (expected !== undefined && expected !== 0 && base.rev !== expected) {
                            throw storageErrorWithRev('STORAGE_CONFLICT', base.rev);
                        }
                        staged.set(pk, null);
                    }
                }
            }
            // ③ 单事务写入 + 全量 CAS。
            try {
                await idbRun(db, STORE_RECORDS, 'readwrite', async (tx) => {
                    const store = tx.objectStore(STORE_RECORDS);
                    for (const [pk, next] of staged) {
                        const cur = (await req(store.get(pk)));
                        const curRev = cur === undefined ? 0 : cur.rev;
                        const base = prevs.get(pk) ?? null;
                        const baseRev = base === null ? 0 : base.rev;
                        if (curRev !== baseRev)
                            throw storageErrorWithRev('STORAGE_CONFLICT', curRev);
                        if (next === null) {
                            if (cur !== undefined)
                                await req(store.delete(pk));
                        }
                        else {
                            const m = mutations.find((x) => physicalKey(x.scope, x.key) === pk);
                            if (m === undefined)
                                continue;
                            await req(store.put(rowOf(m.scope, m.key, next)));
                        }
                    }
                });
            }
            catch (e) {
                fail(e);
            }
            return Object.freeze(results);
        },
        async close() {
            db.close();
            await closeStorageDb(deps.name);
        },
    };
    return engine;
}
