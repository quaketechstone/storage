/**
 * 加密装饰器：把"值"换成"信封"再交给下层引擎。
 *
 * # 位置
 *
 * ```
 *   gateway → [encrypt] → [verify] → idb
 * ```
 *
 * `verify` 在里层，因此它校验的是**密文**的摘要；明文的真实性由 GCM tag 保证。
 * 顺序反过来的话，`verify` 会拿密文去比明文的 hash，每次读都报 `INTEGRITY`。
 *
 * # 序列化
 *
 * 明文用 `canonicalJson` 序列化（键序确定、`undefined` 丢弃、`Date` 转 ISO）。
 * 代价是"存进去的对象取回来是 JSON 归一化后的形态"：`undefined` 属性消失、
 * `Date` 变字符串、`Map`/`Set` 变 `{}`。这与"跨进程存储"的既有语义一致
 * （母体的 `store.rs` 也是 JSON 过桥），但它**不是**"原样往返"。
 * 因此加密模式默认关闭；打开后 A4（原样往返）降级为 A4'（JSON 往返），
 * 见 `STORAGE-COMPATIBILITY.md`。
 *
 * # 密钥不可得时
 *
 * 抛 `STORAGE_KEY_UNAVAILABLE`，**不**降级成明文写入。降级写入是这条路径上最危险的
 * 失败模式：一次密钥未就绪，此后库里就混进了明文，而调用方以为全都加密了。
 */
import { canonicalJson, scopeId } from '../canonical.js';
import { storageErrorOf } from '../errors.js';
import { aadFor, isEnvelope, openText, rewrapDek, sealText } from './envelope.js';
/**
 * 包装引擎，读写自动加解密。
 *
 * `keyring` 按需取 KEK：`device` 模式首次读会从槽里加载，`passphrase` 模式未解锁时
 * 直接抛 `STORAGE_KEY_UNAVAILABLE`——不会静默跳过加密。
 */
export function createEncryptingEngine(inner, keyring) {
    let sealed = 0;
    let opened = 0;
    let openedWithPrev = 0;
    let rewrapped = 0;
    async function seal(scope, key, value) {
        const kek = await keyring.kek();
        const env = await sealText(kek, canonicalJson(value), aadFor(scopeId(scope), key));
        sealed++;
        return env;
    }
    async function open(scope, key, stored) {
        // 非信封值：可能是加密开启前写入的明文。**报错而不是放行**——放行会让
        // "明文混入"变成静默可读，从而长期存在。
        if (!isEnvelope(stored))
            throw storageErrorOf('STORAGE_CORRUPT');
        const aad = aadFor(scopeId(scope), key);
        const kek = await keyring.kek();
        let text;
        try {
            text = await openText(kek, stored, aad);
            opened++;
        }
        catch (e) {
            if (e.code !== 'STORAGE_KEY_UNAVAILABLE')
                throw e;
            // 轮换进行中：这条还没重包，是被旧 KEK 包的。用旧 KEK 打开，**不**顺手重包
            // （读路径不做写，否则一次读会被并发写放大成一条冲突链）。
            // 重包由 `rewrapScope()` 显式完成，完成后再 `finalizeRotation()`。
            const old = await keyring.previousKek();
            if (old === null)
                throw e;
            text = await openText(old, stored, aad);
            openedWithPrev++;
        }
        try {
            return JSON.parse(text);
        }
        catch {
            throw storageErrorOf('STORAGE_CORRUPT');
        }
    }
    async function decryptRecord(scope, key, rec) {
        const value = await open(scope, key, rec.value);
        return Object.freeze({
            value,
            rev: rec.rev,
            bytes: rec.bytes,
            hash: rec.hash,
            ts: rec.ts,
            deleted: rec.deleted,
        });
    }
    const engine = {
        kind: inner.kind,
        get stats() {
            return { sealed, opened, openedWithPrev, rewrapped };
        },
        capabilities: () => inner.capabilities(),
        async get(scope, key) {
            const rec = await inner.get(scope, key);
            if (rec === null)
                return null;
            return decryptRecord(scope, key, rec);
        },
        async put(scope, key, value, opts) {
            const env = await seal(scope, key, value);
            const rec = await inner.put(scope, key, env, opts);
            // 返回给上层的记录带明文值：调用方看到的是自己写进去的东西。
            return Object.freeze({ ...rec, value });
        },
        async del(scope, key, expectedRev) {
            return inner.del(scope, key, expectedRev);
        },
        list: (scope, prefix) => inner.list(scope, prefix),
        async scan(scope, prefix = '', limit) {
            const rows = await inner.scan(scope, prefix, limit);
            const out = [];
            for (const r of rows) {
                out.push(Object.freeze({ key: r.key, rec: await decryptRecord(scope, r.key, r.rec) }));
            }
            return out;
        },
        purge: (scope) => inner.purge(scope),
        usage: (scope) => inner.usage(scope),
        async commit(mutations) {
            const sealedMutations = [];
            // 结果记录与 put 的顺序一一对应，所以明文按同样顺序留一份。
            const plain = [];
            for (const m of mutations) {
                if (m.op === 'put') {
                    plain.push(m.value);
                    sealedMutations.push(Object.freeze({ ...m, value: await seal(m.scope, m.key, m.value) }));
                }
                else {
                    sealedMutations.push(m);
                }
            }
            const recs = await inner.commit(sealedMutations);
            const out = [];
            for (let i = 0; i < recs.length; i++) {
                out.push(Object.freeze({ ...recs[i], value: plain[i] }));
            }
            return Object.freeze(out);
        },
        ...(inner.close === undefined ? {} : { close: () => inner.close?.() }),
    };
    return engine;
}
/**
 * 用新 KEK 重包某 scope 的全部信封。
 *
 * 幂等：已经用新 KEK 包裹的记录无法用旧 KEK 打开，会被计为 `skipped` 而不是失败。
 * 这让"轮换中途崩溃 → 重跑"是安全的。
 *
 * 跨进程也可重入：`previousKek()` 从 `kek.prev` 槽读回旧 KEK（`device` 模式）或
 * 由口令重算（`passphrase` 模式），因此"重开浏览器继续重包"不需要任何额外状态。
 * 在 `finalizeRotation()` 之前，未重包的记录靠 `createEncryptingEngine` 的读路径
 * 回退到旧 KEK 仍然可读——**轮换期间不会出现"读不了"的窗口**。
 */
export async function rewrapScope(engine, keyring, scope, opts = {}) {
    const next = await keyring.kek();
    const prev = await keyring.previousKek();
    if (prev === null)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    const rows = await engine.scan(scope, '', opts.limit ?? 100_000);
    let done = 0;
    let skipped = 0;
    let failed = 0;
    const aadOf = (key) => aadFor(scopeId(scope), key);
    for (const r of rows) {
        if (!isEnvelope(r.rec.value)) {
            // 不是信封 = 这条不是本密钥环的密文。放在"轮换中的库"里，这是**数据形态错误**：
            // 常见成因是调用方把加密引擎（读出来是明文）传给了 `rewrapScope`。
            // 旧实现记为 skipped，于是"一条都没重包"的报告长得和"全部已重包"一样，
            // 调用方据此 finalize → 旧 KEK 被删 → 明文记录与密文记录混在一起无法收拾。
            failed++;
            continue;
        }
        try {
            const env = await rewrapDek(prev, next, r.rec.value);
            await engine.put(scope, r.key, env, { expectedRev: r.rec.rev });
            done++;
        }
        catch (e) {
            const code = e.code;
            if (code !== 'STORAGE_KEY_UNAVAILABLE') {
                failed++;
                continue;
            }
            // 旧 KEK 打不开有两种截然不同的含义，旧实现一律算 skipped：
            //  · 已经用新 KEK 包过了（上一轮跑到这里就崩了，重跑时命中）——可跳过；
            //  · 这条是用**更早的** KEK 包的（上上轮漏重包），prev 已经是再下一代的 KEK
            //    ——这条其实救不回来了，必须报 failed，否则调用方看到 failed=0 就去
            //    finalize，把最后一点救回来的可能也删掉。
            // 区分办法：拿新 KEK 试开一次。能开 = 已重包；开不了 = 真的丢了。
            let alreadyNew = false;
            try {
                await openText(next, r.rec.value, aadOf(r.key));
                alreadyNew = true;
            }
            catch {
                alreadyNew = false;
            }
            if (alreadyNew)
                skipped++;
            else
                failed++;
        }
    }
    return Object.freeze({
        scope: `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`,
        total: rows.length,
        rewrapped: done,
        skipped,
        failed,
    });
}
