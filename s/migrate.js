/**
 * 迁移：把母体旧库里的数据搬进 `s1/` 布局。
 *
 * # 先说结论：默认不搬
 *
 * 旧库（`gw_convos`）里没有任何字段记录"这条数据属于哪个模块"。`ctx.kv` 的 `__ns`
 * 只是 store 名（`cache`/`sec`/`skills`），两个模块用同一个 ns 时键会互相覆盖——
 * 这正是本次改造要解决的问题，但也意味着**历史数据无法自动归属**。
 *
 * 因此本模块的默认动作是 `inspect`（只统计、只报告），迁移必须由运维给出**显式映射**
 * （哪条前缀搬到哪个 scope）。自动猜归属会把 A 模块的数据搬进 B 模块的 scope，
 * 那是数据泄露，不是迁移。
 *
 * # 三条硬约束
 *
 * 1. **源库只读**：`LegacyReader` 只有 `get`/`keys`/`count`，没有写方法。类型层面
 *    就写不出"顺手改一下源库"。
 * 2. **可重入**：每条写完立即记检查点；重跑跳过已完成项；目标已存在同内容视为成功。
 * 3. **先验后切**：`runMigration` 每条写完立刻读回比对；不一致立即中止并保留检查点。
 *    切换读路径是**另一步**，不在本模块内。
 *
 * # 回滚
 *
 * 源库一字未改，所以回滚 = 丢弃目标 scope（`rollbackScopes`）或直接删库
 * （`deleteStorageDb`）。没有"反向迁移"——反向迁移会把新数据写回旧库，
 * 那才是不可逆的。
 */
import { canonicalJson, recordBytes } from './canonical.js';
import { createScope, validateKey } from './contract.js';
import { storageErrorOf } from './errors.js';
import { STORE_META, idbRun, openStorageDb, req } from './engines/idb-db.js';
import { LEGACY_DB_NAME, prefixOf, } from './migrate-legacy.js';
// 旧库读取器已独立成 `migrate-legacy.ts`（边界自检要求例外收敛到单文件）。
// 这里再导出一次，保持既有调用方与测试的 import 路径不变。
export { LEGACY_DB_NAME, createLegacyReader, splitComposite, prefixOf } from './migrate-legacy.js';
// ---------------------------------------------------------------------------
// 盘点
// ---------------------------------------------------------------------------
/** 快速摘要（FNV-1a 32 位）。用于跨环境核对"键集合是否一致"，不用于安全判定。 */
function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
}
/** 盘点旧库。只读、无副作用。 */
export async function inspectLegacy(reader, dbName = LEGACY_DB_NAME) {
    const stores = await reader.stores();
    const stats = [];
    let total = 0;
    for (const store of stores) {
        const keys = await reader.keys(store);
        total += keys.length;
        const counts = new Map();
        for (const k of keys) {
            const p = prefixOf(k);
            counts.set(p, (counts.get(p) ?? 0) + 1);
        }
        const prefixes = [...counts.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([prefix, count]) => Object.freeze({ prefix, count }));
        stats.push(Object.freeze({
            store,
            count: keys.length,
            prefixes: Object.freeze(prefixes),
            sampleDigest: fnv1a(keys.slice().sort().join('\n')),
        }));
    }
    return Object.freeze({
        dbName,
        stores: Object.freeze(stats),
        totalRecords: total,
        absent: stores.length === 0,
    });
}
/**
 * 校验规则表。**不读库、不写库**。
 *
 * 为什么单独一步：规则写错（比如 `stripPrefix` 不在 `keyPrefix` 之下）会让迁移
 * "成功"地搬出一批键名被截断的数据，而报告里全是 `written`——没有任何迹象表明
 * 出了事。结构错误必须在读第一条数据之前就被拒绝。
 */
export function validateRules(rules) {
    const problems = [];
    const seen = new Set();
    for (let i = 0; i < rules.length; i++) {
        const r = rules[i];
        if (typeof r.from !== 'string' || r.from.length === 0) {
            problems.push(Object.freeze({ index: i, reason: 'empty-from' }));
        }
        try {
            createScope(r.to.tenant, r.to.ks, r.to.app, r.to.domain);
        }
        catch {
            problems.push(Object.freeze({ index: i, reason: 'bad-scope' }));
        }
        if (r.decode !== undefined && r.decode !== 'json' && r.decode !== 'raw') {
            problems.push(Object.freeze({ index: i, reason: 'bad-decode' }));
        }
        if (r.stripPrefix !== undefined &&
            r.keyPrefix !== undefined &&
            !r.stripPrefix.startsWith(r.keyPrefix)) {
            problems.push(Object.freeze({ index: i, reason: 'strip-outside-prefix' }));
        }
        const sig = `${r.from}|${r.keyPrefix ?? ''}|${r.stripPrefix ?? ''}|${r.to.tenant}/${r.to.ks}/${r.to.app}/${r.to.domain}`;
        if (seen.has(sig))
            problems.push(Object.freeze({ index: i, reason: 'duplicate-rule' }));
        seen.add(sig);
    }
    return Object.freeze({ ok: problems.length === 0, problems: Object.freeze(problems) });
}
/**
 * 生成计划。**不写任何东西**。
 *
 * 拒绝项不会被静默丢弃：调用方必须看到 `rejected` 才能判断"这次迁移是否完整"。
 */
export async function planMigration(reader, rules, opts = {}) {
    // 结构错误直接拒绝：让"规则写错"表现为一次明确的失败，而不是一份看起来
    // 成功的报告（键名被截断的数据也能算出 written=n）。
    if (!validateRules(rules).ok)
        throw storageErrorOf('STORAGE_DENIED');
    const items = [];
    const rejected = [];
    const seen = new Set();
    let bytes = 0;
    let truncated = false;
    const maxBytes = opts.maxBytes ?? 512 * 1024 * 1024;
    let index = 0;
    for (const rule of rules) {
        const keys = await reader.keys(rule.from);
        const prefix = rule.keyPrefix ?? '';
        for (const k of keys) {
            index++;
            if (!k.startsWith(prefix))
                continue;
            if (rule.stripPrefix !== undefined && !k.startsWith(rule.stripPrefix)) {
                rejected.push(Object.freeze({ store: rule.from, reason: 'strip-mismatch', index }));
                continue;
            }
            const stripped = rule.stripPrefix === undefined ? k : k.slice(rule.stripPrefix.length);
            if (stripped.length === 0) {
                rejected.push(Object.freeze({ store: rule.from, reason: 'empty-after-strip', index }));
                continue;
            }
            try {
                validateKey(stripped);
            }
            catch {
                rejected.push(Object.freeze({
                    store: rule.from,
                    reason: stripped.length > 512 ? 'key-too-long' : 'invalid-key',
                    index,
                }));
                continue;
            }
            const target = `${rule.to.tenant}/${rule.to.ks}/${rule.to.app}/${rule.to.domain}/${stripped}`;
            if (seen.has(target)) {
                rejected.push(Object.freeze({ store: rule.from, reason: 'duplicate-target', index }));
                continue;
            }
            seen.add(target);
            items.push(Object.freeze({
                store: rule.from,
                sourceKey: k,
                targetKey: stripped,
                scope: rule.to,
                decode: rule.decode ?? 'json',
            }));
            if (bytes > maxBytes) {
                // 超预算不抛错：让调用方看到"计划被截断"这个事实，再决定是否分批。
                truncated = true;
                break;
            }
            bytes += 64;
        }
    }
    return Object.freeze({
        id: opts.id ?? `mg-${items.length}-${fnv1a(items.map((i) => i.targetKey).join('|'))}`,
        items: Object.freeze(items),
        rejected: Object.freeze(rejected),
        bytesEstimate: bytes,
        truncated,
    });
}
/** 内存实现。 */
export function createMemoryCheckpoints() {
    const map = new Map();
    return {
        async load(id) {
            return map.get(id) ?? null;
        },
        async save(cp) {
            map.set(cp.id, cp);
        },
        async clear(id) {
            map.delete(id);
        },
    };
}
/** 复用存储库 `meta` 表。 */
export function createIdbCheckpoints(opts = {}) {
    const slot = (id) => `migrate.${id}`;
    return {
        async load(id) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            const row = await idbRun(db, STORE_META, 'readonly', async (tx) => {
                const got = (await req(tx.objectStore(STORE_META).get(slot(id))));
                return got ?? null;
            });
            if (row === null)
                return null;
            const cp = row.v;
            if (typeof cp.id !== 'string' || !Array.isArray(cp.done))
                return null;
            return {
                id: cp.id,
                done: cp.done.filter((x) => typeof x === 'string'),
                updatedAt: typeof cp.updatedAt === 'number' ? cp.updatedAt : 0,
            };
        },
        async save(cp) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            await idbRun(db, STORE_META, 'readwrite', async (tx) => {
                await req(tx.objectStore(STORE_META).put({ k: slot(cp.id), v: cp }));
            });
        },
        async clear(id) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            await idbRun(db, STORE_META, 'readwrite', async (tx) => {
                await req(tx.objectStore(STORE_META).delete(slot(id)));
            });
        },
    };
}
/**
 * 执行迁移。
 *
 * 每条的流程是「读源 → 解码 → 写入（`expectedRev: 0`）→ 读回比对」。
 * `expectedRev: 0` 让"目标已存在"表现为 `CONFLICT`，从而被计为 `skipped`——
 * 这就是幂等：重跑不会覆盖已经迁过的数据，也不会重复计数。
 */
export async function runMigration(opts) {
    const { plan, reader, engine } = opts;
    const dryRun = opts.dryRun === true;
    const every = Math.max(1, opts.checkpointEvery ?? 50);
    const now = opts.now ?? (() => Date.now());
    // 空计划必须报错，不能空转返回 0。
    //
    // 空转的后果不是"没搬"，而是"运维以为搬完了"：报告里 written=0、aborted=false，
    // 看起来和"全部已完成"一模一样。没有显式映射就不该产生一份看起来成功的报告。
    if (plan.items.length === 0)
        throw storageErrorOf('STORAGE_DENIED');
    const cp = opts.checkpoints === undefined ? null : await opts.checkpoints.load(plan.id);
    const done = new Set(cp?.done ?? []);
    let written = 0;
    let skipped = 0;
    let verified = 0;
    let diverged = 0;
    let failed = 0;
    let failedAt = 0;
    let bytesWritten = 0;
    let sinceSave = 0;
    const dirty = [];
    for (let i = 0; i < plan.items.length; i++) {
        const item = plan.items[i];
        const cpKey = `${item.store}::${item.targetKey}`;
        if (done.has(cpKey)) {
            skipped++;
            continue;
        }
        let value;
        try {
            const raw = await reader.get(item.store, item.sourceKey);
            if (raw === null) {
                skipped++;
                continue;
            }
            if (item.decode === 'raw') {
                value = raw;
            }
            else {
                // 旧库多数 store 存的是 JSON 字符串；`msgs` 存的是对象。
                value = typeof raw === 'string' ? JSON.parse(raw) : raw;
            }
        }
        catch {
            failed++;
            failedAt = i + 1;
            break;
        }
        if (dryRun) {
            bytesWritten += recordBytes(value);
            written++;
            continue;
        }
        try {
            const rec = await engine.put(item.scope, item.targetKey, value, { expectedRev: 0 });
            written++;
            bytesWritten += rec.bytes;
        }
        catch (e) {
            if (e.code === 'STORAGE_CONFLICT') {
                // 目标已存在：可能是上次跑过（检查点丢了），也可能被人工改过。
                // 不能一律算"跳过"——那样"目标数据与源不一致"会被静默接受。
                // 读回来比：相同才算已迁移，不同就是数据分歧，必须中止并报出来。
                let same = false;
                try {
                    const back = await engine.get(item.scope, item.targetKey);
                    same = back !== null && canonicalJson(back.value) === canonicalJson(value);
                }
                catch {
                    same = false;
                }
                if (same) {
                    skipped++;
                    done.add(cpKey);
                    dirty.push(cpKey);
                    continue;
                }
                diverged++;
                failedAt = i + 1;
                break;
            }
            failed++;
            failedAt = i + 1;
            break;
        }
        // 读回比对。**必须**做：`put` 成功不等于"读出来一样"（编码器可能改了形态）。
        try {
            const back = await engine.get(item.scope, item.targetKey);
            if (back === null || canonicalJson(back.value) !== canonicalJson(value)) {
                failed++;
                failedAt = i + 1;
                break;
            }
            verified++;
        }
        catch {
            failed++;
            failedAt = i + 1;
            break;
        }
        done.add(cpKey);
        dirty.push(cpKey);
        sinceSave++;
        if (opts.checkpoints !== undefined && sinceSave >= every) {
            await opts.checkpoints?.save({ id: plan.id, done: [...done], updatedAt: now() });
            sinceSave = 0;
            dirty.length = 0;
        }
    }
    if (!dryRun && opts.checkpoints !== undefined && dirty.length > 0) {
        await opts.checkpoints?.save({ id: plan.id, done: [...done], updatedAt: now() });
    }
    return Object.freeze({
        id: plan.id,
        planned: plan.items.length,
        written,
        skipped,
        verified,
        diverged,
        failed,
        failedAt,
        aborted: failed > 0 || diverged > 0,
        dryRun,
        bytesWritten,
    });
}
/** 回滚：清空目标 scope。源库不受影响。 */
export async function rollbackScopes(engine, scopes) {
    let cleared = 0;
    for (const s of scopes)
        cleared += await engine.purge(s);
    return Object.freeze({ cleared });
}
