/**
 * S0 安全原语：存储契约的**纯类型与纯函数**（TS 镜像）。
 *
 * 与 `crates/core/src/storage_contract.rs` 逐项镜像，对应施工计划 T1.1。
 *
 * # 硬约束
 *
 * - **零 IO**：不 import `api/host`、`api/idb`、`loader/*`，不碰 `window`/`indexedDB`/`fetch`。
 * - **零全局状态**：模块级只有 `const` 冻结数据，没有可变单例。
 * - **零调用方**：T1.1 阶段没有任何代码 import 本文件，打包产物不变。
 *
 * # 为什么单独成文件而不是塞进 gateway
 *
 * 边界必须在纯函数上才可穷举测试。一旦混进 IO，"默认拒绝"就只能靠集成测试碰运气。
 *
 * # 已知差异（有意为之，不是遗漏）
 *
 * - 键长度按 **UTF-8 字节** 计（`utf8Len`），不是 `String.length` 的 UTF-16 码元。
 *   用 `.length` 会让 512 个中文字符通过 TS 校验、却在 Rust 侧被拒 —— 两侧必须同尺。
 * - JS 可表达孤立代理项（lone surrogate），Rust `String` 不能。本文件**拒绝**这类键，
 *   避免"字节长度"与"落盘形态"（`TextEncoder` 会替换成 U+FFFD）不一致。
 */
// ---------------------------------------------------------------------------
// 布局常量
// ---------------------------------------------------------------------------
/** 物理键布局版本。布局变更必须升版本。 */
export const LAYOUT_VERSION = 1;
/** 布局根段。裸键（无前缀）属 legacy 区，不归网关管辖。 */
export const LAYOUT_ROOT = 's1';
/** 逻辑键最大长度（**字节**）。 */
export const MAX_KEY_LEN = 512;
/** 单个路径段的最大长度。 */
export const MAX_SEGMENT_LEN = 64;
/** 内核主体标识。 */
export const SUBJECT_KERNEL = 'system:kernel';
/** 驱动主体前缀。 */
export const SUBJECT_MODULE_PREFIX = 'module:';
/** 网关账本的保留 app 名。 */
export const APP_SYS = 'sys';
/** 母体自身数据的 app 名。 */
export const APP_HOST = 'host';
/** 全部键空间，顺序与 Rust `KeySpace::ALL` 一致。 */
export const KEY_SPACES = ['user', 'sys'];
/** 解析键空间段。未知值返回 `null`（不做大小写折叠、不做别名）。 */
export function parseKeySpace(s) {
    return s === 'user' || s === 'sys' ? s : null;
}
/** 全部操作，顺序与 `STORAGE_API.md` §2.2 一致。 */
export const STORAGE_OPS = [
    'read',
    'list',
    'scan',
    'write',
    'delete',
    'purge',
    'tx',
    'migrate',
    'backup',
    'restore',
    'keyAccess',
];
/** 敏感操作：执行段必须同步过 `judge`，不能仅凭 grant 放行。 */
export const SENSITIVE_OPS = ['purge', 'migrate', 'backup', 'restore', 'keyAccess'];
/** 是否敏感操作。 */
export function isSensitiveOp(op) {
    return SENSITIVE_OPS.includes(op);
}
/** 全部错误码，顺序与 `STORAGE_API.md` §4 表格一致。 */
export const STORAGE_ERROR_CODES = [
    'STORAGE_DENIED',
    'STORAGE_SCOPE_VIOLATION',
    'STORAGE_TICKET_INVALID',
    'STORAGE_TICKET_EXPIRED',
    'STORAGE_NOT_FOUND',
    'STORAGE_CONFLICT',
    'STORAGE_QUOTA_EXCEEDED',
    'STORAGE_INTEGRITY',
    'STORAGE_KEY_UNAVAILABLE',
    'STORAGE_UNSUPPORTED',
    'STORAGE_UNAVAILABLE',
    'STORAGE_VERSION_MISMATCH',
    'STORAGE_TX_ABORTED',
    'STORAGE_BLOCKED',
    'STORAGE_MIGRATION_FAILED',
    'STORAGE_RESTORE_REJECTED',
    'STORAGE_CORRUPT',
];
/** 重试**可能**改变结果的错误码。其余重试无意义，调用方不得重试（宪法第 28 条）。 */
export const RETRYABLE_CODES = [
    'STORAGE_CONFLICT',
    'STORAGE_KEY_UNAVAILABLE',
    'STORAGE_UNAVAILABLE',
    'STORAGE_TX_ABORTED',
    'STORAGE_BLOCKED',
    'STORAGE_MIGRATION_FAILED',
];
/** 重试建议。由码推导，**不存字段** —— 存下来的布尔量会与码漂移。 */
export function isRetryable(code) {
    return RETRYABLE_CODES.includes(code);
}
/** 构造错误。 */
export function storageError(code, message) {
    return Object.freeze({ code, message });
}
/** 抛出错误。S0 层用抛出表达拒绝，网关在 T1.2 统一捕获转成返回值。 */
export function fail(code, message) {
    throw storageError(code, message);
}
/** 母体自身在 user 空间的作用域。 */
export function hostScope(domain) {
    return createScope('local', 'user', APP_HOST, domain);
}
/** 网关账本作用域（sys）。 */
export function sysScope(domain) {
    return createScope('local', 'sys', APP_SYS, domain);
}
/**
 * 构造并校验作用域。
 *
 * 不变量：
 * 1. `ks === 'sys'` ⟺ `app === 'sys'`。`sys` 键空间不对任何模块开放。
 * 2. `app` 只能是 `host` / `sys` / `module:<反向域名 id>`。
 */
export function createScope(tenant, ks, app, domain) {
    validateSegment('tenant', tenant);
    validateDomain(domain);
    validateApp(ks, app);
    return Object.freeze({ tenant, ks, app, domain });
}
// ---------------------------------------------------------------------------
// 校验（纯函数）
// ---------------------------------------------------------------------------
/** UTF-8 字节长度。**必须**用它而不是 `.length` 做长度判定。 */
export function utf8Len(s) {
    return new TextEncoder().encode(s).length;
}
function hasLoneSurrogate(s) {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return true;
            i++;
        }
        else if (c >= 0xdc00 && c <= 0xdfff) {
            return true;
        }
    }
    return false;
}
function validateSegment(what, v) {
    if (v.length === 0 || utf8Len(v) > MAX_SEGMENT_LEN)
        fail('STORAGE_DENIED', `${what} 长度非法`);
    if (!/^[a-z0-9]/.test(v))
        fail('STORAGE_DENIED', `${what} 首字符非法`);
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(v))
        fail('STORAGE_DENIED', `${what} 含非法字符`);
}
function validateDomain(domain) {
    if (domain.length === 0 || utf8Len(domain) > MAX_SEGMENT_LEN) {
        fail('STORAGE_DENIED', 'domain 长度非法');
    }
    for (const seg of domain.split('.'))
        validateSegment('domain', seg);
}
function validateApp(ks, app) {
    if (ks === 'sys') {
        if (app !== APP_SYS)
            fail('STORAGE_DENIED', 'sys 键空间只允许 app=sys');
        return;
    }
    if (app === APP_SYS)
        fail('STORAGE_DENIED', 'app=sys 属 sys 键空间，不得用于 user');
    if (app === APP_HOST)
        return;
    if (app.startsWith(SUBJECT_MODULE_PREFIX)) {
        if (isReverseDomainId(app.slice(SUBJECT_MODULE_PREFIX.length)))
            return;
        fail('STORAGE_DENIED', '模块 id 必须是反向域名风格');
    }
    fail('STORAGE_DENIED', 'app 必须是 host / sys / module:<id>');
}
/**
 * 反向域名 id。等价于 `web/src/loader/contract.ts:34` 的 `ID_RE`
 * （`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`）—— 该校验是既有权威，此处镜像而非另立。
 */
export function isReverseDomainId(id) {
    const segs = id.split('.');
    if (segs.length < 2)
        return false;
    return segs.every((s) => /^[a-z][a-z0-9-]*$/.test(s));
}
/**
 * 逻辑键合法性（`STORAGE_API.md` §2.1）。
 *
 * `/` 被禁 ⇒ 键无法跨段，路径穿越在结构上不可能；`..` 检查是纵深防御。
 */
export function validateKey(key) {
    if (key.length === 0 || utf8Len(key) > MAX_KEY_LEN)
        fail('STORAGE_DENIED', '键长度非法');
    if (key.includes('/'))
        fail('STORAGE_DENIED', "键不得含 '/'");
    if (hasLoneSurrogate(key))
        fail('STORAGE_DENIED', '键含孤立代理项');
    for (const ch of key) {
        const cp = ch.codePointAt(0) ?? 0;
        if (cp < 0x20 || cp === 0x7f)
            fail('STORAGE_DENIED', '键不得含控制字符');
    }
    if (key.split('/').some((seg) => seg === '..' || seg === '.')) {
        fail('STORAGE_DENIED', "键不得含 '.' / '..' 段");
    }
}
/** 主体标识：`system:kernel` 或 `module:<反向域名 id>`。 */
export function validateSubject(subject) {
    if (subject === SUBJECT_KERNEL)
        return;
    if (subject.startsWith(SUBJECT_MODULE_PREFIX)) {
        if (isReverseDomainId(subject.slice(SUBJECT_MODULE_PREFIX.length)))
            return;
    }
    fail('STORAGE_DENIED', '主体标识非法');
}
// ---------------------------------------------------------------------------
// 匹配与授权（纯函数）
// ---------------------------------------------------------------------------
/**
 * 作用域是否**完全**相等（逐字段）。
 *
 * 不支持通配：`app`/`domain` 不做前缀或 `*` 匹配。`policy-default.json` 的
 * `cross_ns_forbidden: true` 已把「同 ns 内跨域」判为越界，通配会把它放回来。
 */
export function scopeMatches(granted, requested) {
    return (granted.tenant === requested.tenant &&
        granted.ks === requested.ks &&
        granted.app === requested.app &&
        granted.domain === requested.domain);
}
/**
 * 操作是否被授予。
 *
 * 语义是**交集**，不是覆盖：`op` 必须同时在 `grantOps` 与 `scopeOps`（若给出）中。
 * 若按「scopeOps 覆盖 grantOps」实现，一条写错的 scope 就能把 grant 里没有的
 * `purge` 放出来 —— 那是提权，不是细化。
 */
export function opAllowed(grantOps, scopeOps, op) {
    if (!grantOps.includes(op))
        return false;
    if (scopeOps === undefined)
        return true;
    return scopeOps.includes(op);
}
// ---------------------------------------------------------------------------
// 物理键
// ---------------------------------------------------------------------------
/** 组装物理键：`s1/<tenant>/<ks>/<app>/<domain>/<logicalKey>`。 */
export function physicalKey(scope, key) {
    validateKey(key);
    return `${LAYOUT_ROOT}/${scope.tenant}/${scope.ks}/${scope.app}/${scope.domain}/${key}`;
}
/** 解析物理键。非 `s1/` 前缀或段数不符返回 `null`（legacy 裸键不在此处理）。 */
export function parsePhysicalKey(raw) {
    if (!raw.startsWith(`${LAYOUT_ROOT}/`))
        return null;
    const parts = raw.slice(LAYOUT_ROOT.length + 1).split('/');
    if (parts.length !== 5)
        return null;
    const ks = parseKeySpace(parts[1]);
    if (ks === null)
        return null;
    try {
        const scope = createScope(parts[0], ks, parts[2], parts[3]);
        validateKey(parts[4]);
        return { scope, key: parts[4] };
    }
    catch {
        return null;
    }
}
/** 是否为网关管辖的物理键（`s1/` 前缀）。 */
export function isManagedKey(raw) {
    return raw === LAYOUT_ROOT || raw.startsWith(`${LAYOUT_ROOT}/`);
}
