/**
 * 加密回滚：把密文记录解密回明文。
 *
 * # 为什么这是启用加密的**前置条件**
 *
 * 加密装饰器是"读路径的假设"：它假设库里每条值都是信封。一旦打开，回滚就只剩两条路：
 *
 * 1. 保留加密装饰器、但让每条记录变回明文 → 装饰器读到明文会抛 `STORAGE_CORRUPT`，
 *    所以必须**同时**摘掉装饰器。也就是说回滚是一次"代码 + 数据"的协同动作。
 * 2. 直接删库重来 → 用户数据全丢。
 *
 * 没有本文件时，第 1 条路的数据侧根本不存在：`rewrapScope()` 只换 KEK 包裹，
 * `ct` 一字不动，把它当回滚工具会得到"以为关了加密、实际还是密文"的结果。
 *
 * # 三条安全约束
 *
 * 1. **先预检，后动手**。`preflightDecrypt` 先确认"每条都能用当前 KEK 打开"。
 *    有打不开的就整批拒绝——否则会得到"一半明文一半密文"，而两种状态在同一套
 *    代码下都读不了（加密引擎读明文报 CORRUPT，明文引擎读信封报 CORRUPT）。
 * 2. **逐条写、逐条读回比对**。`put` 成功不等于"读出来一样"。
 * 3. **幂等**。已解密的记录再跑一次会被识别为明文并跳过；中断后重跑只补剩下的。
 *    这让"跑到 80% 崩溃"不等于"数据毁了"。
 *
 * # 中断之后是什么状态
 *
 * 已处理的记录是明文，未处理的是信封。此时**两种引擎都读不全**，这是回滚的中间态，
 * 不是终态。处置方式只有两种：
 * - 重跑 `decryptToPlain` 直到 `remaining === 0`（推荐）；
 * - 放弃回滚，重新启用加密装饰器（未处理的记录仍可读，已处理的会报 CORRUPT）——
 *   **不推荐**，等于把中间态固化。
 *
 * 因此运维流程必须写成："解密 → 校验 remaining=0 → 再切代码"。反过来（先切代码）
 * 会让中间态暴露给用户。
 */
import { canonicalJson } from '../canonical.js';
import { storageErrorOf } from '../errors.js';
import { isEnvelope, openText, aadFor } from './envelope.js';
import { scopeId } from '../canonical.js';
async function openRecord(keyring, scope, key, value) {
    try {
        const kek = await keyring.kek();
        const text = await openText(kek, value, aadFor(scopeId(scope), key));
        try {
            return { ok: true, value: JSON.parse(text) };
        }
        catch {
            return { ok: false, code: 'STORAGE_CORRUPT' };
        }
    }
    catch (e) {
        const code = e.code;
        return { ok: false, code: typeof code === 'string' ? code : 'STORAGE_CORRUPT' };
    }
}
/**
 * 预检：只读，不改任何东西。
 *
 * 用途：启用加密前评估"回滚是否可行"、回滚前确认"每条都能打开"。
 */
export async function preflightDecrypt(engine, keyring, scope, opts = {}) {
    const rows = await engine.scan(scope, '', opts.limit ?? 100_000);
    let plaintext = 0;
    let openable = 0;
    let corrupt = 0;
    let keyUnavailable = 0;
    for (const r of rows) {
        if (!isEnvelope(r.rec.value)) {
            plaintext++;
            continue;
        }
        const res = await openRecord(keyring, scope, r.key, r.rec.value);
        if (res.ok)
            openable++;
        else if (res.code === 'STORAGE_KEY_UNAVAILABLE')
            keyUnavailable++;
        else
            corrupt++;
    }
    return Object.freeze({
        scope: scopeId(scope),
        total: rows.length,
        plaintext,
        openable,
        corrupt,
        keyUnavailable,
    });
}
/**
 * 解密整段 scope。
 *
 * 预检不通过（有打不开的记录）时抛错，除非 `allowPartial`。
 */
export async function decryptToPlain(engine, keyring, scope, opts = {}) {
    const limit = opts.limit ?? 100_000;
    const dryRun = opts.dryRun === true;
    const rows = await engine.scan(scope, '', limit);
    const pre = await preflightDecrypt(engine, keyring, scope, { limit });
    const blocked = pre.corrupt + pre.keyUnavailable;
    if (blocked > 0 && opts.allowPartial !== true) {
        // 密钥问题优先报：它更可能是"口令输错/轮换没完成"，处置是修密钥而不是修数据。
        throw storageErrorOf(pre.keyUnavailable > 0 ? 'STORAGE_KEY_UNAVAILABLE' : 'STORAGE_CORRUPT');
    }
    let decrypted = 0;
    let skipped = 0;
    let verified = 0;
    let remaining = 0;
    let failed = 0;
    let failedAt = 0;
    for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        if (!isEnvelope(r.rec.value)) {
            skipped++;
            continue;
        }
        const opened = await openRecord(keyring, scope, r.key, r.rec.value);
        if (!opened.ok) {
            failed++;
            failedAt = i + 1;
            remaining = rows.length - i;
            break;
        }
        if (dryRun) {
            decrypted++;
            continue;
        }
        try {
            await engine.put(scope, r.key, opened.value, { expectedRev: r.rec.rev });
            decrypted++;
        }
        catch {
            failed++;
            failedAt = i + 1;
            remaining = rows.length - i;
            break;
        }
        // 读回比对：解密后的值必须能原样读出来，否则"解密成功"只是写进去了。
        try {
            const back = await engine.get(scope, r.key);
            if (back === null || canonicalJson(back.value) !== canonicalJson(opened.value)) {
                failed++;
                failedAt = i + 1;
                remaining = rows.length - i;
                break;
            }
            verified++;
        }
        catch {
            failed++;
            failedAt = i + 1;
            remaining = rows.length - i;
            break;
        }
    }
    if (!dryRun && failed === 0) {
        // 全量复核：确认没有漏掉的信封（scan 期间被并发写入的记录也要算进来）。
        const post = await preflightDecrypt(engine, keyring, scope, { limit });
        remaining = post.total - post.plaintext;
    }
    return Object.freeze({
        scope: scopeId(scope),
        total: rows.length,
        decrypted,
        skipped,
        verified,
        remaining,
        failed,
        failedAt,
        aborted: failed > 0,
        dryRun,
    });
}
/**
 * 回滚后的验收：确认该 scope 全部是明文且摘要相符。
 *
 * 用 `scrubScope` 的同一套摘要规则，但**额外**要求"没有信封"——否则一份
 * "全部能读"的报告可能来自"一条都没解密"。
 */
export async function verifyPlainScope(engine, scope, opts = {}) {
    const rows = await engine.scan(scope, '', opts.limit ?? 100_000);
    const reasons = [];
    let failed = 0;
    for (const r of rows) {
        if (isEnvelope(r.rec.value)) {
            failed++;
            reasons.push('envelope-remains');
        }
    }
    return Object.freeze({
        scope: scopeId(scope),
        checked: rows.length,
        failed,
        reasons: Object.freeze(reasons),
    });
}
