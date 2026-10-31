/**
 * 备份包签名。
 *
 * # 补的是哪个洞
 *
 * 没有签名时，攻击者改 `value`、重算 `hash`、重算 `digest`，就能造出一份**自洽**
 * 的包（`backup.test.mjs` 里有一条用例专门断言"这种包会被接受"，把边界钉住）。
 * 摘要只能发现"改坏了"，发现不了"改对了"。
 *
 * 签名把"这份包是谁产的"变成可验证的事实：MAC 覆盖 `v|keyId|scope|count|digest`，
 * 攻击者改任何一个字段都必须重算 MAC，而他没有密钥。
 *
 * # 三种密钥来源，安全属性不同
 *
 * | 工厂 | 密钥在哪 | 能跨设备验签 | 适用 |
 * |---|---|---|---|
 * | `createBackupSigner(store)` | 设备本地 `backup.hmac` 槽（不可导出） | 否 | 同设备导出→导入 |
 * | `deriveBackupSigner(口令, salt, iters)` | 由口令派生，不落盘 | 是 | 跨设备/跨浏览器恢复 |
 * | `createHmacSigner(key, id)` | 调用方自己管 | 取决于调用方 | 测试与外部 KMS |
 *
 * # 它挡不住什么
 *
 * 同源脚本可以调 `sign()`（密钥就在本源），所以**签名不防"已控制同源环境的攻击者"**，
 * 只防"只拿到备份文件的人"——云盘同步、邮件附件、U 盘、误传的工单附件。
 * 这个边界必须写进威胁模型，不能因为"有签名了"就说备份安全了。
 */
import { bytesToB64, b64ToBytes } from './crypto/envelope.js';
import { storageErrorOf } from './errors.js';
/** 算法标识。换算法要升 `BACKUP_VERSION`。 */
export const BACKUP_SIG_ALG = 'HMAC-SHA256';
/**
 * 口令派生签名器的迭代数下限。
 *
 * 签名密钥由口令派生，迭代数就是"离线爆破的成本"。不设下限时，构造一份
 * iterations=1 的材料就能在毫秒级试完常用口令表——这与 `keyring` 的
 * `MIN_RESTORE_ITERATIONS` 是同一条规则，只是落在本模块（避免为取一个常量
 * 引入对 `crypto/keyring` 的运行时依赖）。
 */
export const MIN_SIGN_ITERATIONS = 100_000;
const encoder = new TextEncoder();
/**
 * 签名口径。**唯一**一处。
 *
 * `keyId` 参与签名：否则攻击者可以把 A 密钥的签名搬到"声称由 B 签发"的包上，
 * 让验签方去试错的密钥。
 */
export function backupSignaturePayload(t, keyId) {
    return `${t.v}|${BACKUP_SIG_ALG}|${keyId}|${t.scope}|${t.count}|${t.digest}`;
}
function subtle() {
    const s = globalThis.crypto?.subtle;
    if (s === undefined)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    return s;
}
/** 用既有 HMAC 密钥构造签名器。 */
export function createHmacSigner(key, keyId) {
    return Object.freeze({
        keyId,
        async sign(payload) {
            const mac = await subtle().sign('HMAC', key, encoder.encode(payload));
            return bytesToB64(new Uint8Array(mac));
        },
        async verify(payload, mac) {
            const bytes = b64ToBytes(mac);
            if (bytes === null)
                return false;
            try {
                // `subtle.verify` 内部是定时安全的比较，不要自己写 `===`。
                return await subtle().verify('HMAC', key, bytes, encoder.encode(payload));
            }
            catch {
                return false;
            }
        },
    });
}
/** 由口令派生签名器（跨设备可验）。 */
export async function deriveBackupSigner(passphrase, saltB64, iterations, keyId = 'passphrase') {
    if (passphrase.length < 8)
        throw storageErrorOf('STORAGE_DENIED');
    if (!Number.isSafeInteger(iterations) || iterations < MIN_SIGN_ITERATIONS) {
        throw storageErrorOf('STORAGE_DENIED');
    }
    const salt = b64ToBytes(saltB64);
    if (salt === null)
        throw storageErrorOf('STORAGE_DENIED');
    const s = subtle();
    const base = await s.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const key = await s.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
    return createHmacSigner(key, keyId);
}
const SLOT_KEY = 'backup.hmac';
const SLOT_ID = 'backup.hmac.id';
/**
 * 设备本地签名器。首次调用生成不可导出的 HMAC 密钥并落进 `meta` 表。
 *
 * 为什么用 `extractable: false`：导出一次就意味着"密钥可以离开本设备"，而备份
 * 签名的全部意义是"只有本设备能产"。代价是**换设备后无法验签**——需要跨设备时
 * 用 `deriveBackupSigner`。
 */
export async function createBackupSigner(store, opts = {}) {
    const existing = await store.get(SLOT_KEY);
    if (typeof existing === 'object' && existing !== null && existing.type === 'secret') {
        const id = await store.get(SLOT_ID);
        return createHmacSigner(existing, typeof id === 'string' ? id : 'device');
    }
    const key = await subtle().generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, false, [
        'sign',
        'verify',
    ]);
    const keyId = opts.keyId ?? 'device';
    await store.put(SLOT_KEY, key);
    await store.put(SLOT_ID, keyId);
    return createHmacSigner(key, keyId);
}
