/**
 * 加密信封：每条记录一个随机 DEK，用不可导出的 KEK 包裹。
 *
 * # 为什么是"每条记录一个 DEK"而不是"直接用 KEK 加密"
 *
 * | 方案 | 换 KEK 的代价 | 单条泄露的影响 |
 * |---|---|---|
 * | KEK 直接加密全部记录 | **全量重加密**（附件 24 MiB × N 条） | 一条 IV 复用就可能波及全局 |
 * | 每记录 DEK，KEK 只包裹 DEK | **只重包 32 字节 DEK**，payload 不动 | 只影响那一条 |
 *
 * 换密钥是必然会发生的运维动作（口令轮换、设备迁移）。把它的代价压到"只重包 32 字节"，
 * 才可能真的去轮换；否则"设计上支持轮换、实际从没轮换过"就是事实上的永不轮换。
 *
 * # 绑定位置
 *
 * AAD（附加认证数据）= `v1|<scopeId>|<key>`。GCM 会把 AAD 纳入 tag 校验，于是：
 *
 * - 把 A 的记录搬到 B 的键下 → tag 校验失败（`key` 变了）；
 * - 把模块 X 的记录搬到模块 Y 的 scope 下 → 失败（`scopeId` 变了）。
 *
 * 这挡的是"有库写权限但没有 KEK 的攻击者"把密文挪到低权限位置再诱导读取。
 * 它**不挡**整条记录的替换（把旧记录连同其密文一起写回）——那需要外部单调计数器，
 * 见 `STORAGE-CRYPTO.md` 的 L-3。
 *
 * # 不含 rev
 *
 * AAD 里刻意不放 `rev`：`rev` 每次写都变，放进去会让"重包 DEK"（不改变 payload）
 * 也必须改 AAD，从而必须重算 tag——那就退化成全量重加密了。位置绑定已经足够，
 * 版本回退是另一类问题。
 */
import { storageErrorOf } from '../errors.js';
/** 信封版本。字段或算法变更必须升版本。 */
export const ENVELOPE_VERSION = 1;
/** 算法标识。写进信封，便于未来并存多算法。 */
export const ENVELOPE_ALG = 'A256GCM+KW256';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/** 字节 → base64。不依赖 `btoa`（Node 无此全局）。 */
export function bytesToB64(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const b0 = bytes[i];
        const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
        const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
        out += B64[b0 >> 2];
        out += B64[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += i + 1 < bytes.length ? B64[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
        out += i + 2 < bytes.length ? B64[b2 & 0x3f] : '=';
    }
    return out;
}
/** base64 → 字节。非法输入返回 `null`（不抛：调用方要能把它当作"数据坏了"处理）。 */
export function b64ToBytes(s) {
    if (s.length % 4 !== 0)
        return null;
    const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
    const out = new Uint8Array((s.length / 4) * 3 - pad);
    let o = 0;
    for (let i = 0; i < s.length; i += 4) {
        const c0 = B64.indexOf(s[i]);
        const c1 = B64.indexOf(s[i + 1]);
        const c2 = s[i + 2] === '=' ? 0 : B64.indexOf(s[i + 2]);
        const c3 = s[i + 3] === '=' ? 0 : B64.indexOf(s[i + 3]);
        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0)
            return null;
        const n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
        if (o < out.length)
            out[o++] = (n >> 16) & 0xff;
        if (o < out.length)
            out[o++] = (n >> 8) & 0xff;
        if (o < out.length)
            out[o++] = n & 0xff;
    }
    return out;
}
/** 判定一个值是否为信封。逐字段校验——落盘内容不可信。 */
export function isEnvelope(v) {
    if (typeof v !== 'object' || v === null)
        return false;
    const e = v;
    return (e.v === ENVELOPE_VERSION &&
        e.alg === ENVELOPE_ALG &&
        typeof e.iv === 'string' &&
        typeof e.ct === 'string' &&
        typeof e.dek === 'string');
}
/** 附加认证数据。位置绑定。 */
export function aadFor(scopeId, key) {
    return `${ENVELOPE_VERSION}|${scopeId}|${key}`;
}
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function subtle() {
    const s = globalThis.crypto?.subtle;
    if (s === undefined)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    return s;
}
/** 随机字节。`getRandomValues` 缺失时不退化成 `Math.random`——那等于没有密钥。 */
function randomBytes(n) {
    const c = globalThis.crypto;
    if (c?.getRandomValues === undefined)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    const buf = new Uint8Array(n);
    c.getRandomValues(buf);
    return buf;
}
/** 加密一个字符串。 */
export async function sealText(kek, plaintext, aad) {
    const s = subtle();
    // DEK 必须 extractable=true 才能被 wrapKey 包裹；包裹完成后立即丢弃这个句柄，
    // 之后只用 unwrap 出来的不可导出句柄。
    const dek = await s.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = randomBytes(12);
    const ct = await s.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, dek, encoder.encode(plaintext));
    const wrapped = await s.wrapKey('raw', dek, kek, { name: 'AES-KW' });
    return Object.freeze({
        v: ENVELOPE_VERSION,
        alg: ENVELOPE_ALG,
        iv: bytesToB64(iv),
        ct: bytesToB64(new Uint8Array(ct)),
        dek: bytesToB64(new Uint8Array(wrapped)),
    });
}
/**
 * 解密。
 *
 * 三类失败**分别**映射，不合并成"解密失败"：
 * - 信封结构坏了 → `STORAGE_CORRUPT`（数据问题）
 * - KEK 打不开 DEK → `STORAGE_KEY_UNAVAILABLE`（密钥问题，可能换了口令）
 * - GCM tag 不匹配 → `STORAGE_INTEGRITY`（被改过，或 AAD 位置不符）
 *
 * 合并会让运维无法判断"该换口令还是该查篡改"。
 */
export async function openText(kek, env, aad) {
    if (!isEnvelope(env))
        throw storageErrorOf('STORAGE_CORRUPT');
    const s = subtle();
    const iv = b64ToBytes(env.iv);
    const ct = b64ToBytes(env.ct);
    const wrapped = b64ToBytes(env.dek);
    if (iv === null || ct === null || wrapped === null)
        throw storageErrorOf('STORAGE_CORRUPT');
    let dek;
    try {
        dek = await s.unwrapKey('raw', wrapped, kek, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    }
    catch {
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    }
    try {
        const pt = await s.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, dek, ct);
        return decoder.decode(pt);
    }
    catch {
        throw storageErrorOf('STORAGE_INTEGRITY');
    }
}
/**
 * 只重包 DEK：payload 与 IV 不动，tag 也不动。
 *
 * 因为 AAD 不含 KEK，换 KEK 不影响 GCM tag。这是"轮换只花 32 字节"的实现基础。
 */
export async function rewrapDek(oldKek, newKek, env) {
    const s = subtle();
    const wrapped = b64ToBytes(env.dek);
    if (wrapped === null)
        throw storageErrorOf('STORAGE_CORRUPT');
    let dek;
    try {
        dek = await s.unwrapKey('raw', wrapped, oldKek, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }
    catch {
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    }
    const next = await s.wrapKey('raw', dek, newKek, { name: 'AES-KW' });
    return Object.freeze({ ...env, dek: bytesToB64(new Uint8Array(next)) });
}
