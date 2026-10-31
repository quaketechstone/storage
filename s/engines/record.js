/**
 * 引擎共用的「下一版本记录」构造。
 *
 * 提取自 `memory.ts` 的 `computeRecord`，供新引擎（sqlite / remote）复用，
 * 避免每加一个后端就复制一份 rev/冲突/字节/hash 逻辑——复制出来的迟早漂移。
 *
 * 语义与 memory 引擎逐条一致：
 * - `expectedRev === 0` 仅新建；`prev !== null` 即 CONFLICT（软删也算存在）。
 * - `expectedRev === n>0` 必须 `prev.rev === n`。
 * - `expectedRev === undefined` 无条件覆盖，rev = prev+1 或 1。
 */
import { storageErrorOf, storageErrorWithRev } from '../errors.js';
import { recordBytes, recordHash } from '../canonical.js';
export async function computeNextRecord(scope, key, value, prev, opts, now) {
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
