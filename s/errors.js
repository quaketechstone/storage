/**
 * S1 错误归一化：把「抛出」收敛成「返回」，并让错误消息**结构上**不可能泄漏数据。
 *
 * # 为什么消息要来自常量表
 *
 * `STORAGE_API.md` A2/A3 要求错误形状固定为 `{ code, message }`，且宪法第 31 条禁止
 * 错误消息携带键值、密钥或业务数据。若靠「写代码时注意别拼 key」来保证，第一次
 * `fail(Denied, \`denied: ${key}\`)` 就破了。
 *
 * 本文件把 message 收窄成**查表**：`messageFor(code)` 的入参只有错误码，没有别的
 * 可变信息，因此"消息里出现键名"在类型层面无法表达。少数确实需要携带数值的场景
 * （如 `CONFLICT` 报实际 rev）走 `numericHint`，只接受 `number`，且渲染成固定句式。
 *
 * # 为什么需要 Result 包装
 *
 * 驱动侧（未来的 `ctx.kv`）不能吞异常也不能把 `StorageError` 抛到 wasm 边界外——
 * `host/mod.rs:8` 的既有约束是"跨边界只传结构化错误"。网关内部仍用 throw 表达拒绝
 * （便于提前返回、便于 `finally` 清理），只在**门面边界**转成 Result。
 */
import { STORAGE_ERROR_CODES, isRetryable, } from './contract.js';
/** 构造成功。 */
export function ok(value) {
    return Object.freeze({ ok: true, value });
}
/** 构造失败。 */
export function err(error) {
    return Object.freeze({ ok: false, error });
}
/** 错误码 → 失败 Result。 */
export function errCode(code) {
    return err(storageErrorOf(code));
}
// ---------------------------------------------------------------------------
// 固定消息表
// ---------------------------------------------------------------------------
/**
 * 每个错误码的唯一文案。
 *
 * 约束：
 * 1. **不含**占位符。任何插值都会引入泄漏面。
 * 2. 面向调用方（驱动作者），不是面向终端用户；因此写"为什么被拒"，不写"怎么修"。
 * 3. 与 `STORAGE_API.md` §4 的语义列一致，改文案要同步该表。
 */
export const ERROR_MESSAGES = Object.freeze({
    STORAGE_DENIED: '操作未被授予',
    STORAGE_SCOPE_VIOLATION: '作用域不在票据授权范围内',
    STORAGE_TICKET_INVALID: '票据无效',
    STORAGE_TICKET_EXPIRED: '票据已失效',
    STORAGE_NOT_FOUND: '目标不存在',
    STORAGE_CONFLICT: '版本冲突',
    STORAGE_QUOTA_EXCEEDED: '超出配额',
    STORAGE_INTEGRITY: '记录完整性校验失败',
    STORAGE_KEY_UNAVAILABLE: '密钥不可得',
    STORAGE_UNSUPPORTED: '引擎不支持该操作',
    STORAGE_UNAVAILABLE: '存储引擎不可用',
    STORAGE_VERSION_MISMATCH: '本地库版本高于当前代码',
    STORAGE_TX_ABORTED: '事务被中止',
    STORAGE_BLOCKED: '本地库被其他标签页占用',
    STORAGE_MIGRATION_FAILED: '迁移步骤失败',
    STORAGE_RESTORE_REJECTED: '备份包校验未通过',
    STORAGE_CORRUPT: '记录无法解析',
});
/**
 * 由码构造错误。**唯一**合法的构造入口（`contract.storageError` 仅供契约层自用）。
 *
 * 返回值冻结，防止调用方改写 `code` 绕过下游判断。
 */
export function storageErrorOf(code) {
    return Object.freeze({ code, message: ERROR_MESSAGES[code] });
}
/**
 * 带数值提示的错误。
 *
 * 只接受 `number` 是刻意的：数值无法承载键名、密钥或业务内容。渲染格式固定，
 * 调用方不需要（也不能）拼接任意字符串。
 *
 * 目前仅 `CONFLICT` 使用（报实际 rev），其余码一律走 `storageErrorOf`。
 */
export function storageErrorWithRev(code, rev) {
    if (!Number.isSafeInteger(rev) || rev < 0)
        return storageErrorOf(code);
    return Object.freeze({ code, message: `${ERROR_MESSAGES[code]}（当前 rev=${rev}）` });
}
// ---------------------------------------------------------------------------
// 边界转换
// ---------------------------------------------------------------------------
/** 是否为本模块的结构化错误。用于区分"我们的拒绝"与"引擎/环境的意外异常"。 */
export function isStorageError(x) {
    if (typeof x !== 'object' || x === null)
        return false;
    const c = x.code;
    return typeof c === 'string' && STORAGE_ERROR_CODES.includes(c);
}
/**
 * 把任意异常归一成 `StorageError`。
 *
 * 未知异常一律 `STORAGE_UNAVAILABLE`——**不**把原始 `Error.message` 透传出去，
 * 因为引擎异常里常带物理键（`idb.ts` 的 `QuotaExceededError` 就带 store 名）。
 */
export function normalizeError(e) {
    if (isStorageError(e))
        return e;
    return storageErrorOf('STORAGE_UNAVAILABLE');
}
/** 同步执行并捕获。 */
export function attempt(fn) {
    try {
        return ok(fn());
    }
    catch (e) {
        return err(normalizeError(e));
    }
}
/** 异步执行并捕获。 */
export async function attemptAsync(fn) {
    try {
        return ok(await fn());
    }
    catch (e) {
        return err(normalizeError(e));
    }
}
/** 把 Result 还原成抛出，供需要提前返回的内部函数使用。 */
export function unwrap(r) {
    if (r.ok)
        return r.value;
    throw r.error;
}
// ---------------------------------------------------------------------------
// 重试
// ---------------------------------------------------------------------------
/** 是否值得重试。委托契约层推导，避免两处判定漂移。 */
export function retryable(e) {
    return isRetryable(e.code);
}
/**
 * 有界重试。
 *
 * 只对 `retryable(code) === true` 的错误重试；不可重试的错误立即返回，避免
 * 「用重试掩盖确定性失败」——那会让真正的 bug 表现成偶发超时。
 *
 * `baseDelayMs` 为 0 时不等待（测试用）。
 */
export async function withRetry(fn, opts = {}) {
    const attempts = Math.max(1, opts.attempts ?? 3);
    const base = opts.baseDelayMs ?? 20;
    let last = null;
    for (let i = 0; i < attempts; i++) {
        const r = await attemptAsync(fn);
        if (r.ok)
            return r;
        last = r.error;
        if (!retryable(r.error))
            return r;
        if (i < attempts - 1 && base > 0)
            await sleep(base * 2 ** i);
    }
    return err(last ?? storageErrorOf('STORAGE_UNAVAILABLE'));
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
