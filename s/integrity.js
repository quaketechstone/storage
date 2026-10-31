/**
 * 读时完整性校验：引擎装饰器。
 *
 * # 为什么放在引擎层而不是网关层
 *
 * 网关看到的是"业务值"。若在网关层校验，就必须知道 hash 是对**哪种表示**算的：
 * 明文还是密文。一旦接了加密装饰器，两者不同，网关要么算错、要么得知道加密细节。
 * 放在引擎层后，规则变成一句可检查的话：
 *
 * > `rec.hash` 恒等于 `sha256(scopeId|key|rev|canonical(rec.value))`，
 * > 而 `rec.value` 是**该层实际存下来的表示**。
 *
 * 于是 `verify(inner)` 直接坐在最内层，加密装饰器坐在它外面。校验对象是密文，
 * 明文的真实性由 AES-GCM 的 tag 保证——两层各管一段，不重叠也不留缝。
 *
 * # 校验成本
 *
 * 每次读多一次 SHA-256。1 KiB 值约 3–5 µs，`scan` 1000 条约 3–5 ms。
 * 这个代价换来的是"落盘内容被改过就报错"，而不是"读到垃圾值继续用"。
 * 若某场景确实承担不起，可以 `mode: 'never'` 显式关掉——**显式**是关键：
 * 默认开启，关掉要在构造参数里写出来，能被 code review 看见。
 *
 * # 校验失败之后
 *
 * 抛 `STORAGE_INTEGRITY`，**不返回**该记录。返回"可疑值 + 一个警告标记"是更糟的
 * 设计：调用方几乎总是只看值、不看标记，于是篡改被静默接受。
 *
 * # 四类输入，四种处置（不能合并）
 *
 * | 输入 | 判定 | 处置 |
 * |---|---|---|
 * | 正常记录 | 摘要相符 | 返回 |
 * | 值被改（摘要不符） | `tampered` | 抛 `STORAGE_INTEGRITY`，计数，不返回 |
 * | 记录结构坏（缺 `hash`、`hash` 非 64 位十六进制、`rev` 非正整数、值不可规范化） | `malformed` | 抛 `STORAGE_CORRUPT`，计数，不返回 |
 * | 记录不存在 | —— | 返回 `null`（**不是错误**：缺失与损坏是两件事） |
 *
 * "旧格式记录"落在 `malformed`：`s1/` 库里出现无摘要记录，只可能是迁移写错或跨版本
 * 降级。若把它当 `tampered`，运维会去查"谁改了数据"，而真正该做的是查版本。
 */
import { recordBytes, recordDigestInput, sha256Hex } from './canonical.js';
import { storageErrorOf } from './errors.js';
/**
 * 默认校验模式。
 *
 * 导出成常量而不是散在 `?? 'always'` 里，是为了让"默认开着"成为可被测试断言的事实：
 * 任何地方把默认改成 `never`，`integrity.test.mjs` 的默认配置用例立刻红。
 */
export const DEFAULT_INTEGRITY_MODE = 'always';
/** 64 位小写十六进制（`sha256Hex` 的输出形态）。 */
const HEX64 = /^[0-9a-f]{64}$/;
/**
 * 记录结构是否可校验。
 *
 * 注意这里**不**检查 `value` 的类型：任何可 JSON 化的值都合法。只检查那些会让
 * "比较"本身失去意义的东西——没有摘要、摘要形态不对、版本号不是整数。
 */
function isWellFormed(rec) {
    if (typeof rec !== 'object' || rec === null)
        return false;
    if (typeof rec.hash !== 'string' || !HEX64.test(rec.hash))
        return false;
    if (!Number.isSafeInteger(rec.rev) || rec.rev < 1)
        return false;
    if (rec.value === undefined)
        return false;
    return true;
}
/** 计算记录应有的摘要。导出供测试与 scrub 复用。 */
export async function expectedHash(scope, key, rev, value) {
    return sha256Hex(recordDigestInput(scope, key, rev, value));
}
/** 单条校验。结构不合法抛 `STORAGE_CORRUPT`，摘要不符抛 `STORAGE_INTEGRITY`。 */
export async function verifyRecord(scope, key, rec) {
    // 结构先判：`rec.hash` 缺失时下面那行会拿 `undefined` 去比，结果是 `INTEGRITY`，
    // 把"旧格式记录"误报成"被篡改"。旧格式与篡改的处置完全不同，不能混。
    if (!isWellFormed(rec))
        throw storageErrorOf('STORAGE_CORRUPT');
    let actual;
    try {
        actual = await expectedHash(scope, key, rec.rev, rec.value);
    }
    catch {
        // 值不可规范化（循环引用、bigint、超深嵌套）——数据问题，不是篡改。
        throw storageErrorOf('STORAGE_CORRUPT');
    }
    if (actual !== rec.hash)
        throw storageErrorOf('STORAGE_INTEGRITY');
}
/**
 * 包装引擎，读时校验。
 *
 * 写路径不校验：写入时的 hash 由内层引擎自己算，不存在"外部传进来的 hash"，
 * 因此没有可校验的对象。校验只对**读到的**数据有意义——那才是可能被第三方改过的数据。
 */
export function createVerifyingEngine(inner, opts = {}) {
    const mode = opts.mode ?? DEFAULT_INTEGRITY_MODE;
    let checked = 0;
    let failures = 0;
    let lastFailure = null;
    async function check(scope, key, rec) {
        if (mode === 'never')
            return;
        checked++;
        // 比较逻辑**只有一处**（`verifyRecord`）。这里不再抄一遍 `actual === rec.hash`：
        // 抄两遍的后果是变异测试只能杀掉其中一份——实测 M24 在旧写法下存活，
        // 因为读路径走的是本函数、而变异打在 `verifyRecord` 上。
        try {
            await verifyRecord(scope, key, rec);
        }
        catch (e) {
            const code = e.code;
            if (code !== 'STORAGE_INTEGRITY' && code !== 'STORAGE_CORRUPT')
                throw e;
            failures++;
            // 摘要只在失败路径重算：失败是罕见的，多算一次比让正常读多算一次划算。
            // `malformed` 时可能根本算不出摘要（值不可规范化），此时 actual 记 `'-'`。
            let actual = '-';
            try {
                actual = await expectedHash(scope, key, rec.rev, rec.value);
            }
            catch {
                /* 保留 '-' */
            }
            const f = Object.freeze({
                scope: `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`,
                key,
                rev: typeof rec.rev === 'number' ? rec.rev : 0,
                expected: typeof rec.hash === 'string' ? rec.hash : '-',
                actual,
                reason: code === 'STORAGE_INTEGRITY' ? 'tampered' : 'malformed',
            });
            lastFailure = f;
            opts.onFailure?.(f);
            throw e;
        }
    }
    const engine = {
        kind: inner.kind,
        get checked() {
            return checked;
        },
        get failures() {
            return failures;
        },
        get lastFailure() {
            return lastFailure;
        },
        capabilities: () => inner.capabilities(),
        async get(scope, key) {
            const rec = await inner.get(scope, key);
            if (rec === null)
                return null;
            await check(scope, key, rec);
            return rec;
        },
        async put(scope, key, value, putOpts) {
            return inner.put(scope, key, value, putOpts);
        },
        async del(scope, key, expectedRev) {
            return inner.del(scope, key, expectedRev);
        },
        list: (scope, prefix) => inner.list(scope, prefix),
        async scan(scope, prefix = '', limit) {
            const rows = await inner.scan(scope, prefix, limit);
            // 串行校验：并行会让 1000 条同时进 SHA-256，抢占主线程反而更慢。
            for (const r of rows)
                await check(scope, r.key, r.rec);
            return rows;
        },
        purge: (scope) => inner.purge(scope),
        usage: (scope) => inner.usage(scope),
        commit: (mutations) => inner.commit(mutations),
        ...(inner.close === undefined ? {} : { close: () => inner.close?.() }),
    };
    return engine;
}
/**
 * 全量校验某 scope。
 *
 * 用途：定期巡检、迁移后验收、以及"怀疑被改过"时的取证。不参与读路径。
 *
 * 与 `scan` 的区别：`scan` 受 `limit` 限制且遇错即抛；scrub 走完所有记录，
 * 把失败收集起来——巡检的价值在于"知道有多少坏"，而不是"碰到第一个坏就停"。
 */
export async function scrubScope(inner, scope, opts = {}) {
    const limit = opts.limit ?? 100_000;
    const rows = await inner.scan(scope, '', limit);
    const failures = [];
    let bytes = 0;
    for (const r of rows) {
        try {
            bytes += recordBytes(r.rec.value);
        }
        catch {
            /* 值不可规范化：字节数无从计算，跳过累加（该条下面会计为 malformed） */
        }
        // 与读路径共用同一个判定函数。抄一份 `actual !== hash` 会让"旧格式"在巡检里
        // 被误报成"篡改"——实测过：删掉 hash 字段时 expectedHash 仍能算出来，
        // 于是 actual !== undefined 成立，reason 就错成了 tampered。
        let reason = null;
        try {
            await verifyRecord(scope, r.key, r.rec);
        }
        catch (e) {
            const code = e.code;
            if (code === 'STORAGE_INTEGRITY')
                reason = 'tampered';
            else if (code === 'STORAGE_CORRUPT')
                reason = 'malformed';
            else
                throw e;
        }
        if (reason === null)
            continue;
        let actual = '-';
        try {
            actual = await expectedHash(scope, r.key, r.rec.rev, r.rec.value);
        }
        catch {
            actual = '-';
        }
        failures.push(Object.freeze({
            scope: `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`,
            key: r.key,
            rev: typeof r.rec.rev === 'number' ? r.rec.rev : 0,
            expected: typeof r.rec.hash === 'string' ? r.rec.hash : '-',
            actual,
            reason,
        }));
    }
    return Object.freeze({
        scope: `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`,
        checked: rows.length,
        failed: failures.length,
        failures: Object.freeze(failures),
        bytes,
    });
}
