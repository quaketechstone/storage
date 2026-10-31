/**
 * S1 门面：驱动看到的 `ctx.kv` 形状。票据在**闭包**里，不在对象上。
 *
 * # 逐项对齐现状（U-1 零契约变更）
 *
 * 形状取自 `web/src/loader/types.ts:118-127` 的 `ModuleCtx.kv`：
 *
 * ```ts
 * kv?: {
 *   __ns: string
 *   get:  (key: string) => Promise<unknown>
 *   put:  (key: string, value: unknown) => Promise<void>
 *   del:  (key: string) => Promise<void>
 *   list: (prefix: string) => Promise<string[]>
 * }
 * ```
 *
 * 三处容易写错、写错就破坏兼容的地方：
 *
 * 1. **方法名是 `del` 不是 `delete`**。写成 `delete` 后，现有驱动调 `ctx.kv.del(...)`
 *    会得到 `undefined is not a function`。
 * 2. **字段名是 `__ns` 不是 `scope`**。`__ns` 被模块用于"kv:sec 双态判定"
 *    （`types.ts:120` 的注释），语义是**原始命名空间名**，不是本模块内部的
 *    `tenant/ks/app/domain` 标识。两者不能互换。
 * 3. **失败是抛错，不是返回 Result**。现状 `bridgeKvGet` 在未授权时 `throw`；
 *    若改成返回 `{ok:false}`，所有 `try/catch` 的驱动会静默拿到一个对象当值用。
 *
 * 抛出的对象与 `StorageError` 同构（`{code, message}`，冻结），**不是** `Error` 实例。
 * 理由：`Error` 的 `stack` 会带内部路径，`message` 可被下游改写；而结构化错误是
 * `host/mod.rs:8` 的既有约束（跨边界只传结构化错误）。驱动侧判 `e.code` 即可。
 *
 * # 为什么不用 `ctx.ticket`
 *
 * `ctx` 是驱动可以自由枚举、`JSON.stringify`、传给任意 npm 依赖的对象
 * （`loader.ts` 的 `makeCtx` 就是这么交出去的）。把票据挂上去，等于把它交给
 * 每一个能碰到 `ctx` 的库。闭包是唯一"不需要额外机制就不可枚举"的容器。
 *
 * # 这是 RV-06 的落实，不是声明
 *
 * `facade.test.mjs` 逐项断言：`'ticket' in facade === false`、`Reflect.ownKeys(facade)`
 * 等于白名单、`JSON.stringify` 不含票据、原型链上也取不到。文档里说"没挂"不算数。
 */
import { scopeId } from './canonical.js';
import { unwrap } from './errors.js';
/** 门面允许出现的自有键。`inspectFacade` 据此判定是否有字段被偷加。 */
export const FACADE_KEYS = Object.freeze(['__ns', 'get', 'put', 'del', 'list']);
/**
 * 创建门面。
 *
 * `scope` 必须与 `ticket` 的作用域相同；不同则每次调用都抛
 * `STORAGE_SCOPE_VIOLATION`（网关 GATE-4）。**不在这里提前报错**，因为提前报错
 * 会让"构造门面失败"成为一个可探测的信号，而逐次拒绝更接近真实使用路径。
 *
 * `ns` 是 `manifest.kvNs[0]` 的原始字符串，仅用于 `__ns` 字段，**不参与授权判定**
 * ——授权只看 ticket 里的 `DataScope`。把 ns 当授权依据会让"改 manifest 就能换
 * 权限"，而 manifest 是模块自己写的。
 *
 * 门面不提供 `purge`/`tx`/`migrate`/`backup`/`restore`：
 * - 驱动没有清空整个 scope 的业务理由；
 * - `tx` 需要跨键编排，属内核职责；
 * - 迁移/备份/恢复是运维操作，只能由启动器发起。
 */
export function createKvFacade(gw, ticket, scope, ns) {
    const facade = {
        __ns: ns,
        async get(key) {
            const r = await gw.get(ticket, scope, key);
            const rec = unwrap(r);
            // 现状语义：不存在返回 `null`（`bridgeKvGet` 的 `if (raw === null) return null`）。
            return rec === null ? null : rec.value;
        },
        async put(key, value) {
            unwrap(await gw.put(ticket, scope, key, value));
        },
        async del(key) {
            unwrap(await gw.del(ticket, scope, key));
        },
        async list(prefix) {
            const keys = unwrap(await gw.list(ticket, scope, prefix));
            return [...keys];
        },
    };
    // 冻结：防止驱动往门面上挂 `__ticket` 之类的字段再转手（挂上去也没用，
    // 但冻结让"这个对象是只读的"成为可断言的事实）。
    return Object.freeze(facade);
}
/**
 * 校验门面是否满足 RV-06（供测试与启动期自检调用）。
 *
 * 返回违规项列表；空数组表示通过。之所以做成运行时检查而不是只在测试里写死：
 * 未来若有人给门面加了 `ticket` 字段，这个函数能在启动自检里立刻报出来，
 * 而不用等某个测试用例恰好覆盖到。
 */
export function inspectFacade(f) {
    const problems = [];
    const anyF = f;
    if ('ticket' in anyF)
        problems.push('facade has own "ticket" property');
    if ('__ticket' in anyF)
        problems.push('facade has own "__ticket" property');
    for (const sym of Object.getOwnPropertySymbols(f)) {
        const v = f[sym];
        if (typeof v === 'object' && v !== null)
            problems.push(`facade has object-valued symbol ${String(sym)}`);
    }
    const allowed = new Set(FACADE_KEYS);
    for (const k of Reflect.ownKeys(f).map(String)) {
        if (!allowed.has(k))
            problems.push(`unexpected key ${k}`);
    }
    // 原型链上也不应有票据。门面是字面量，原型是 Object.prototype，正常情况为空。
    let proto = Object.getPrototypeOf(f);
    let depth = 0;
    while (proto !== null && depth < 8) {
        for (const k of Reflect.ownKeys(proto)) {
            const name = String(k);
            if (name === 'ticket' || name === '__ticket')
                problems.push(`prototype has ${name}`);
        }
        proto = Object.getPrototypeOf(proto);
        depth++;
    }
    return problems;
}
/** 诊断：门面绑定的作用域标识（不含票据）。 */
export function facadeScopeId(scope) {
    return scopeId(scope);
}
