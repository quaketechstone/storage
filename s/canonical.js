/**
 * 规范化序列化与摘要。
 *
 * # 为什么不能直接 `JSON.stringify`
 *
 * 两个内容相同、键序不同的对象会得到不同字符串：
 * `{a:1,b:2}` vs `{b:2,a:1}`。若拿它算 hash，"值没变"会被判成"完整性失败"，
 * 而这类误报会让真正的篡改淹没在噪声里。因此按**键字典序**重建。
 *
 * # 为什么 hash 要包含 scope 与 key
 *
 * 只对 value 算 hash 的话，把 A 的记录整条搬到 B 的键下仍然"校验通过"——
 * 记录迁移（S-14 的级联清理、迁移工具）会成为绕过完整性的通道。
 *
 * # 字节计数口径
 *
 * 配额按 `canonicalJson(value)` 的 **UTF-8 字节数** 计。用规范化后的长度而不是
 * 原始 `JSON.stringify` 长度，是为了让"同样内容、不同键序"占用同样配额——
 * 否则调用方可以通过重排键把配额算小。
 */
import { storageErrorOf } from './errors.js';
/** UTF-8 编码器。模块级复用，`TextEncoder` 无状态。 */
const encoder = new TextEncoder();
/** UTF-8 字节数。 */
export function utf8Bytes(s) {
    return encoder.encode(s).length;
}
/** 作用域标识：`tenant/ks/app/domain`。用于 hash 前缀与审计。 */
export function scopeId(scope) {
    return `${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}`;
}
/**
 * 确定性 JSON。
 *
 * 规则（与 `JSON.stringify` 的差异都写在这里，避免"看起来一样其实不一样"）：
 * 1. 对象键按 UTF-16 码元序排序（`Array.prototype.sort` 默认序，稳定且跨引擎一致）。
 * 2. 值为 `undefined` 的对象属性被**丢弃**（同 JSON）；数组中的 `undefined` 变 `null`。
 * 3. `NaN` / `Infinity` 变 `null`（同 JSON）。
 * 4. 循环引用抛 `STORAGE_CORRUPT`——不是 `STORAGE_DENIED`：这是数据问题，不是授权问题。
 * 5. 顶层 `undefined` 返回 `'null'`。
 */
export function canonicalJson(value) {
    const seen = new Set();
    return write(value, seen, 0);
}
const MAX_DEPTH = 64;
function write(v, seen, depth) {
    if (depth > MAX_DEPTH)
        throw storageErrorOf('STORAGE_CORRUPT');
    if (v === null)
        return 'null';
    switch (typeof v) {
        case 'undefined':
            return 'null';
        case 'boolean':
            return v ? 'true' : 'false';
        case 'number':
            return Number.isFinite(v) ? JSON.stringify(v) : 'null';
        case 'string':
            return JSON.stringify(v);
        case 'bigint':
            // JSON 无 bigint。静默转字符串会让"存 1 取 '1'"，破坏原样往返（A4）。
            throw storageErrorOf('STORAGE_CORRUPT');
        case 'function':
        case 'symbol':
            return 'null';
        default:
            break;
    }
    const obj = v;
    if (seen.has(obj))
        throw storageErrorOf('STORAGE_CORRUPT');
    seen.add(obj);
    try {
        if (Array.isArray(obj)) {
            const parts = [];
            for (const item of obj)
                parts.push(write(item, seen, depth + 1));
            return `[${parts.join(',')}]`;
        }
        if (obj instanceof Date)
            return JSON.stringify(obj.toISOString());
        if (obj instanceof Uint8Array) {
            // 二进制按十六进制编码。直接 JSON.stringify(Uint8Array) 会得到 {"0":1,...}，
            // 体积膨胀十倍且顺序依赖索引，不可用于摘要。
            let hex = '';
            for (const b of obj)
                hex += b.toString(16).padStart(2, '0');
            return `{"$bin":"${hex}"}`;
        }
        const rec = obj;
        const keys = Object.keys(rec).sort();
        const parts = [];
        for (const k of keys) {
            const val = rec[k];
            if (val === undefined)
                continue;
            parts.push(`${JSON.stringify(k)}:${write(val, seen, depth + 1)}`);
        }
        return `{${parts.join(',')}}`;
    }
    finally {
        seen.delete(obj);
    }
}
/**
 * sha256 → 64 位小写十六进制。
 *
 * 依赖 `crypto.subtle`，它在**非安全上下文**（`http://` 且非 localhost）下不存在。
 * 此时抛 `STORAGE_UNAVAILABLE` 而不是退化成弱摘要：静默降级会让完整性校验变成
 * 摆设，而调用方看不出区别。
 */
export async function sha256Hex(input) {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined)
        throw storageErrorOf('STORAGE_UNAVAILABLE');
    const buf = await subtle.digest('SHA-256', encoder.encode(input));
    const bytes = new Uint8Array(buf);
    let out = '';
    for (const b of bytes)
        out += b.toString(16).padStart(2, '0');
    return out;
}
/** 记录摘要输入：`scopeId|key|rev|canonical(value)`。 */
export function recordDigestInput(scope, key, rev, value) {
    return `${scopeId(scope)}|${key}|${rev}|${canonicalJson(value)}`;
}
/** 计算记录 hash。 */
export async function recordHash(scope, key, rev, value) {
    return sha256Hex(recordDigestInput(scope, key, rev, value));
}
/** 记录落盘字节数。 */
export function recordBytes(value) {
    return utf8Bytes(canonicalJson(value));
}
