/**
 * 跨设备恢复：把"能重建 KEK 的最小材料"导出成一个可携带的包。
 *
 * # 为什么只有 `passphrase` 模式能恢复
 *
 * | 模式 | KEK 来源 | 换设备后 |
 * |---|---|---|
 * | `device` | 浏览器生成的随机 256 位，存在 `kek` 槽 | **无法恢复**。槽不随数据走，导出也导不出（`extractable:false`） |
 * | `passphrase` | PBKDF2(口令, salt, 310k) | 材料（salt/迭代数/校验块）+ 口令 → 同一个 KEK |
 *
 * 所以本模块对 `device` 模式**明确抛错**，而不是导出一份"看起来能恢复"的包。
 * 这一点必须写进用户文档：`device` 模式丢的是设备，也就是数据。
 *
 * # 材料为什么可以外传
 *
 * 材料里没有密钥，只有 KDF 参数与一个被 KEK 包裹的探针。拿到材料但没有口令，
 * 既不能解开探针，也不能解开任何记录。因此它可以放在配置仓库、运维笔记里，
 * **但记录本身仍然要按密文对待**——两者合起来才是完整的数据。
 *
 * # 与备份的关系
 *
 * 恢复数据需要两样东西：**密文备份包**（`createBackup(raw, scope)`，用未装饰的
 * 引擎导出，所以是信封而不是明文）+ **恢复材料**。缺一不可：
 * - 只有备份：换设备后解不开；
 * - 只有材料：没有数据可解。
 *
 * 这条约束在 `__tests__/recovery.test.mjs` 里有端到端用例（A 设备加密 → 导出
 * 材料与备份 → B 设备导入 → 读出原文）。
 */
import { MIN_RESTORE_ITERATIONS, createKeyring } from './keyring.js';
/** 包版本。字段变更必须升版本。 */
export const RECOVERY_KIT_VERSION = 1;
/** 包类型标记。防止把别的 JSON 当恢复材料喂进来。 */
export const RECOVERY_KIT_KIND = 'quake.storage.keyring';
/** 导出。`device` 模式抛 `STORAGE_DENIED`。 */
export async function exportRecoveryKit(ring, opts = {}) {
    const material = await ring.recoveryMaterial();
    return Object.freeze({
        v: RECOVERY_KIT_VERSION,
        kind: RECOVERY_KIT_KIND,
        material,
        exportedAt: (opts.now ?? (() => Date.now()))(),
    });
}
/**
 * 形状校验（**不需要口令**）。
 *
 * 用途：导入前先判断"这是不是一个恢复材料包"，避免把口令错报成"包坏了"。
 * 它不证明材料正确——那只由 `restoreKeyring` 的探针校验负责。
 */
export function verifyRecoveryKit(kit) {
    if (typeof kit !== 'object' || kit === null)
        return { ok: false, reason: 'bad-shape' };
    const k = kit;
    if (k.kind !== RECOVERY_KIT_KIND)
        return { ok: false, reason: 'bad-kind' };
    if (k.v !== RECOVERY_KIT_VERSION)
        return { ok: false, reason: 'bad-version' };
    const m = k.material;
    if (typeof m !== 'object' ||
        m === null ||
        m.mode !== 'passphrase' ||
        typeof m.salt !== 'string' ||
        typeof m.check !== 'string' ||
        // 迭代数下限在这里就查，而不是留给 `restoreFrom`：预检说"这是个好包"、
        // 导入时却因迭代数被拒，两个口径不一致会让调用方先报"包坏了"再报"口令错"，
        // 排障方向被带偏。`NaN` / 0 / 负数 / 小数同理——它们能过 `typeof === 'number'`。
        !Number.isSafeInteger(m.iterations) ||
        m.iterations < MIN_RESTORE_ITERATIONS) {
        return { ok: false, reason: 'bad-shape' };
    }
    return { ok: true, reason: 'ok' };
}
/**
 * 在空密钥环上重建。
 *
 * 失败分三类，**不合并**：包坏了（形状/版本/类型）、口令错、目标已有密钥。
 * 合并成"恢复失败"会让用户无从判断该换包还是该换口令。
 */
export async function restoreKeyring(store, kit, passphrase) {
    const shape = verifyRecoveryKit(kit);
    if (!shape.ok)
        return Object.freeze({ ok: false, reason: shape.reason, keyring: null });
    const ring = createKeyring({ store });
    try {
        const okPass = await ring.restoreFrom(kit.material, passphrase);
        if (!okPass)
            return Object.freeze({ ok: false, reason: 'bad-passphrase', keyring: null });
        return Object.freeze({ ok: true, reason: 'ok', keyring: ring });
    }
    catch (e) {
        const code = e.code;
        if (code === 'STORAGE_DENIED') {
            return Object.freeze({ ok: false, reason: 'already-present', keyring: null });
        }
        if (code === 'STORAGE_CORRUPT') {
            return Object.freeze({ ok: false, reason: 'bad-shape', keyring: null });
        }
        // 原样抛出。旧实现把一切未知错误改写成 `STORAGE_DENIED`，于是"WebCrypto 不可用"
        // （`STORAGE_KEY_UNAVAILABLE`）会被读成"这里已经有密钥环了"——两个完全不同的
        // 处置动作（换浏览器 vs 换库），合并成一句会让排障走错方向。
        throw e;
    }
}
