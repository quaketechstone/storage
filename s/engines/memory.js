/**
 * 内存引擎：T1.2 的参考实现与测试基座。
 *
 * # 定位
 *
 * 它**不是**生产引擎。生产是 IndexedDB（`engines/idb.ts`，T1.2 不实现——那需要
 * 触碰 `api/idb.ts` 的 `DB_VERSION`，属未批准变更）。内存引擎的作用是：
 *
 * 1. 把引擎接口的**语义**固定下来（rev 递增、原子 commit、软删、字节计量），
 *    让未来的 IDB 引擎有可对照的行为基线；
 * 2. 让网关的门禁、配额、并发、审计逻辑可以在**无浏览器**环境下被穷举测试；
 * 3. 提供故障注入点，用于验证"引擎失败时网关不会误报成功"。
 *
 * # 语义承诺（IDB 引擎必须逐条对齐）
 *
 * | 场景 | 行为 |
 * |---|---|
 * | 新键 `put` | `rev = 1` |
 * | 覆盖 `put` | `rev = 旧 + 1`，`hash` 重算 |
 * | `expectedRev: 0` 且键存在 | `STORAGE_CONFLICT`，**不写入** |
 * | `expectedRev: n` 且 `rev !== n` | `STORAGE_CONFLICT`，**不写入** |
 * | 软删后 `get` | `null` |
 * | 软删后 `put` | `rev` 从软删记录的 rev 继续 +1（不重置） |
 * | 硬删后 `put` | `rev` 从 1 重新开始 |
 * | `commit` 中任一条失败 | 全部不生效，`STORAGE_*` 原样抛出 |
 * | `commit` 空数组 | 成功，返回空数组 |
 */
import { physicalKey } from '../contract.js';
import { canonicalJson, recordBytes, recordHash } from '../canonical.js';
import { storageErrorOf, storageErrorWithRev } from '../errors.js';
// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------
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
/**
 * 创建内存引擎。
 *
 * 存储结构是扁平的 `Map<physicalKey, EngineRecord>`，**不**按 scope 分桶。
 * 理由：scope 隔离若靠"分桶"实现，`purge(scope)` 就变成"删掉一个桶"，而桶名
 * 由 scope 拼出——拼错一次就是清空别人的数据。扁平结构下 `purge` 必须显式
 * 比较每条记录的 scope 前缀，比较逻辑可被单独测试。
 */
export function createMemoryEngine(deps = {}) {
    const now = deps.now ?? (() => Date.now());
    const data = new Map();
    const faults = deps.faults ?? createFaultInjector();
    const faultMap = faults.map;
    function trip(point) {
        const f = faultMap.get(point);
        if (f === undefined)
            return;
        if (f.remaining <= 0) {
            faultMap.delete(point);
            return;
        }
        f.remaining--;
        if (f.remaining === 0)
            faultMap.delete(point);
        throw storageErrorOf(f.code);
    }
    /** 该 scope 下的物理键前缀。**带尾部斜杠**，防止 `chat` 匹配到 `chat2`。 */
    function scopePrefix(scope) {
        return `${physicalKey(scope, 'k').slice(0, -1)}`;
    }
    function inScope(pk, prefix) {
        return pk.startsWith(prefix);
    }
    async function computeRecord(scope, key, value, prev, opts) {
        const expected = opts.expectedRev;
        if (expected !== undefined) {
            if (expected === 0) {
                // 仅新建。软删的记录算"已存在"——否则软删键可被 expectedRev:0 覆盖，
                // 而调用方以为自己在建新记录。
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
        // 先算字节与 hash 再返回：任何一步失败都不留下半条记录。
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
    const engine = {
        kind: 'memory',
        capabilities() {
            return {
                ops: ALL_OPS,
                transactions: true,
                ttl: true,
                orderedList: true,
            };
        },
        async get(scope, key) {
            trip('get');
            const rec = data.get(physicalKey(scope, key));
            if (rec === undefined)
                return null;
            // 软删对调用方不可见。恢复走 put（rev 继续递增），不走"取消删除"，
            // 避免出现"rev 相同、内容不同"的两个版本。
            return rec.deleted ? null : rec;
        },
        async put(scope, key, value, opts = {}) {
            trip('put');
            const pk = physicalKey(scope, key);
            const prev = data.get(pk) ?? null;
            const next = await computeRecord(scope, key, value, prev, opts);
            data.set(pk, next);
            return next;
        },
        async del(scope, key, expectedRev) {
            trip('del');
            const pk = physicalKey(scope, key);
            const prev = data.get(pk);
            if (prev === undefined)
                return { removed: false, bytes: 0 };
            if (expectedRev !== undefined && prev.rev !== expectedRev) {
                throw storageErrorWithRev('STORAGE_CONFLICT', prev.rev);
            }
            data.delete(pk);
            return { removed: true, bytes: prev.bytes };
        },
        async list(scope, prefix = '') {
            trip('list');
            const sp = scopePrefix(scope);
            const out = [];
            for (const [pk, rec] of data) {
                if (!inScope(pk, sp) || rec.deleted)
                    continue;
                const logical = pk.slice(sp.length);
                if (prefix !== '' && !logical.startsWith(prefix))
                    continue;
                out.push(logical);
            }
            // 字典序由引擎保证（`orderedList: true`）。用码元序而非 locale 序：
            // locale 序在不同浏览器/系统语言下不一致，会让分页结果漂移。
            out.sort();
            return out;
        },
        async scan(scope, prefix = '', limit = 1000) {
            trip('scan');
            const sp = scopePrefix(scope);
            const out = [];
            for (const [pk, rec] of data) {
                if (!inScope(pk, sp) || rec.deleted)
                    continue;
                const logical = pk.slice(sp.length);
                if (prefix !== '' && !logical.startsWith(prefix))
                    continue;
                out.push({ key: logical, rec });
                if (out.length >= limit)
                    break;
            }
            out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
            return out;
        },
        async purge(scope) {
            trip('purge');
            const sp = scopePrefix(scope);
            let n = 0;
            for (const pk of [...data.keys()]) {
                if (!inScope(pk, sp))
                    continue;
                data.delete(pk);
                n++;
            }
            return n;
        },
        async usage(scope) {
            trip('usage');
            const sp = scopePrefix(scope);
            let total = 0;
            for (const [pk, rec] of data) {
                if (inScope(pk, sp))
                    total += rec.bytes;
            }
            return total;
        },
        /**
         * 原子批量。
         *
         * 两阶段：**试算**（只在临时层叠加，不碰 `data`）→ **应用**。
         * 任何一条试算失败都直接抛出，`data` 保持原样。这是"原子"的全部含义：
         * 不存在"写了一半"的中间态，因为写入只发生在所有校验通过之后。
         *
         * 代价是内存占用翻倍（临时层 + 原表），但事务上限是 200 条（API 契约 §3.5），
         * 且临时层只存变更键。IDB 引擎用原生事务，不受此限。
         */
        async commit(mutations) {
            trip('commit');
            if (mutations.length === 0)
                return Object.freeze([]);
            const staged = new Map();
            const results = [];
            for (const m of mutations) {
                const pk = physicalKey(m.scope, m.key);
                const base = staged.has(pk) ? (staged.get(pk) ?? null) : (data.get(pk) ?? null);
                if (m.op === 'put') {
                    const next = await computeRecord(m.scope, m.key, m.value, base, m.opts ?? {});
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
                    // 删除不存在或已删除的键：幂等成功，不产生结果记录。
                }
            }
            // 应用阶段。到这里不可能再失败（纯 Map 操作），因此不需要回滚逻辑。
            for (const [pk, rec] of staged) {
                if (rec === null)
                    data.delete(pk);
                else
                    data.set(pk, rec);
            }
            return Object.freeze(results);
        },
        size() {
            return data.size;
        },
        peek(scope, key) {
            return data.get(physicalKey(scope, key)) ?? null;
        },
        faults,
    };
    return engine;
}
/**
 * 故障注入器。
 *
 * `map` 故意挂成公开字段（类型上用交叉断言取出），是为了让引擎内部能在不增加
 * 接口方法的前提下读到它。生产代码不传 `faults`，因此 `map` 永远为空。
 */
export function createFaultInjector() {
    const map = new Map();
    const injector = {
        arm(point, times = 1, code = 'STORAGE_UNAVAILABLE') {
            map.set(point, { remaining: times, code });
        },
        clear() {
            map.clear();
        },
    };
    injector.map = map;
    return injector;
}
/** 诊断：把记录内容摊平成可比较的字符串（测试用，避免直接比对对象引用）。 */
export function dumpRecord(rec) {
    if (rec === null)
        return 'null';
    return `${rec.rev}|${rec.hash.slice(0, 8)}|${rec.deleted ? 'D' : 'A'}|${canonicalJson(rec.value)}`;
}
