/**
 * S1 配额：按主体分档计量，**写入前**拒绝而不是写入后报错。
 *
 * # 为什么必须在写入前判
 *
 * 浏览器配额耗尽时抛的是 `QuotaExceededError`，它发生在**任意**一次写入点，
 * 不区分业务，也不保证事务可回滚。等到那一刻才发现，用户看到的是"保存失败"，
 * 而实际状态可能已经写了一半。网关的可控分支（`STORAGE_QUOTA_EXCEEDED`）能把
 * 失败限定在单次调用，且可以给出"还差多少"。
 *
 * # 分档依据（RV-03）
 *
 * 单一 10 MiB 配额会直接打断现有功能：内核要写附件，单条上限 24 MiB
 * （`api.rs:377` `MAX_CHARS = 24 * 1024 * 1024`）。若内核也按 10 MiB 计量，
 * 改造后**存不进大附件**，而现状可以——这是功能倒退，不是安全加固。
 *
 * | 主体 | 总量 | 单条 | 依据 |
 * |---|---|---|---|
 * | `module:*` | 10 MiB | 4 MiB | `INT-RLSD/spec/policy-default.json:185`；驱动无写附件的业务理由 |
 * | `system:kernel` | 256 MiB | 32 MiB | 容纳 24 MiB 附件（data URL 字符数）并留封装余量 |
 *
 * # 计量的是**落盘**字节
 *
 * `recordBytes` 用 `canonicalJson` 的 UTF-8 长度。三层放大已计入：
 * 记录封装（JSON 引号/转义）、base64（附件 ×1.37）、索引键。因此 256 MiB 配额
 * 对应的原始数据约 170 MiB——**这条换算要写进 UI 的容量提示**，否则用户看到的
 * "已用 80%"与实际可存量对不上。
 */
import { storageErrorOf } from './errors.js';
/** 1 MiB。用 `1024 * 1024` 而不是 `1e6`：与 `api.rs:377` 同尺。 */
export const MIB = 1024 * 1024;
/** 驱动档。 */
export const QUOTA_DRIVER = Object.freeze({
    maxTotalBytes: 10 * MIB,
    maxRecordBytes: 4 * MIB,
});
/** 内核档。 */
export const QUOTA_KERNEL = Object.freeze({
    maxTotalBytes: 256 * MIB,
    maxRecordBytes: 32 * MIB,
});
/**
 * 按主体取档。
 *
 * 未知主体（不符合 `system:kernel` 也不符合 `module:*`）落到**驱动档**：
 * 更严格的一侧。反过来会让一个拼错的主体标识拿到 25 倍配额。
 */
export function policyFor(subject) {
    return subject === 'system:kernel' ? QUOTA_KERNEL : QUOTA_DRIVER;
}
/**
 * 创建配额账本。
 *
 * 账本本身是内存态。持久化（`sys/quota/<subject>`）由网关在接线阶段负责——
 * T1.2 不接 IDB，因此这里只暴露 `snapshot()` / `initial` 两个口子，
 * 不假装"已经持久化了"。
 *
 * 为什么持久化是必要的：内存账本在刷新后归零，若不以引擎实际占用校正，
 * 刷新一次就等于"配额重置"。`reconcile` 是这条路径的唯一入口。
 */
export function createQuotaLedger(deps = {}) {
    const used = new Map();
    for (const [subject, bytes] of Object.entries(deps.initial ?? {})) {
        if (Number.isSafeInteger(bytes) && bytes >= 0)
            used.set(subject, bytes);
    }
    function get(subject) {
        return used.get(subject) ?? 0;
    }
    return {
        reserve(subject, deltaBytes, recordBytes) {
            if (!Number.isSafeInteger(deltaBytes) || deltaBytes < 0) {
                throw storageErrorOf('STORAGE_DENIED');
            }
            const policy = policyFor(subject);
            // 单条上限先判：一条 5 MiB 的记录写进 10 MiB 总额的驱动，即使总量没超，
            // 也应该报单条超限——否则错误信息会指向"总量不够"，误导调用方去清理数据。
            if (recordBytes > policy.maxRecordBytes)
                throw storageErrorOf('STORAGE_QUOTA_EXCEEDED');
            if (get(subject) + deltaBytes > policy.maxTotalBytes) {
                throw storageErrorOf('STORAGE_QUOTA_EXCEEDED');
            }
            used.set(subject, get(subject) + deltaBytes);
        },
        commit(subject, _deltaBytes) {
            // 预占时已计入。此方法保留为将来"两阶段账本"（预占 + 确认）的锚点，
            // 现在不改变状态，避免重复计数。
            void subject;
            void _deltaBytes;
        },
        release(subject, deltaBytes) {
            const next = get(subject) - deltaBytes;
            if (next <= 0)
                used.delete(subject);
            else
                used.set(subject, next);
        },
        used: get,
        reconcile(subject, actualBytes) {
            if (!Number.isSafeInteger(actualBytes) || actualBytes < 0)
                return 0;
            const before = get(subject);
            used.set(subject, actualBytes);
            return actualBytes - before;
        },
        snapshot() {
            return Object.freeze(Object.fromEntries(used));
        },
        policy: policyFor,
    };
}
/**
 * 一次覆盖写的净增量（**可负**）。
 *
 * 覆盖写不是"加 value 的字节"，而是"加 (新 - 旧)"。若按新值累加，反复覆盖同一个键
 * 会把账本越算越大，最终明明只有 1 MiB 数据却报超配额——这类"账本漂移"比超配额本身
 * 更难排查，因为它只在大批量重写后出现。
 *
 * 调用约定：
 * - `delta >= 0`：先 `reserve(subject, delta, nextBytes)`，写入失败则 `release(subject, delta)`。
 * - `delta < 0`：先 `reserve(subject, 0, nextBytes)`（只做单条上限检查），
 *   写入**成功后**再 `release(subject, -delta)`。缩减不预占，因为它不会导致超额。
 */
export function byteDelta(prevBytes, nextBytes) {
    return nextBytes - prevBytes;
}
