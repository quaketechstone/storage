/**
 * S1 票据：**不可枚举、不可构造、不可复制出有效副本**的授权句柄。
 *
 * # 结构
 *
 * ```
 *   调用方拿到的          模块私有的
 *   ┌──────────┐          ┌────────────────────────────┐
 *   │  handle  │ ──────►  │ WeakMap<handle, TicketState>│
 *   │ (冻结空  │          │  subject / scope / ops /    │
 *   │  对象)   │          │  epoch / expiresAt          │
 *   └──────────┘          └────────────────────────────┘
 * ```
 *
 * handle 是 `Object.freeze(Object.create(null))`：
 * - **无原型** ⇒ 没有 `toString` / `constructor` / `__proto__` 可被原型污染利用；
 * - **冻结** ⇒ 无法往 handle 上挂字段把它"升级"成别的票据；
 * - **空** ⇒ `Object.keys` / `Reflect.ownKeys` / `JSON.stringify` 只能看到空。
 *
 * # 本设计**不**声称的事
 *
 * 不声称"防复制引用"。`const t2 = t` 必然成立，这是 JS 的对象语义。安全性来自
 * 「内部态不可枚举 + 撤销使全部引用一并失效」，而不是"复制不了"。
 * `STORAGE_API.md` §2.3 的「残余」段已写明这一点，测试也按此断言（复制引用应**仍然可用**，
 * 撤销后应**一并失效**），不写成"复制即拒绝"——那会让测试通过、结论虚假。
 *
 * # 为什么是工厂而不是模块级单例
 *
 * 模块级可变状态会让测试互相污染（前一个用例 bump 了 epoch，后一个用例莫名失效），
 * 也无法注入时钟去测过期。工厂返回独立实例，网关持有一个。
 */
// ---------------------------------------------------------------------------
// 时钟
// ---------------------------------------------------------------------------
/**
 * 单调时钟。
 *
 * 用 `performance.now()` 而不是 `Date.now()`：后者可被系统时间回拨/用户改表影响，
 * 回拨一次就能让"已过期"的票据复活。`performance.now()` 只增不减。
 *
 * 跨刷新会归零——但票据本身也不跨刷新（内存对象），所以不存在"归零后旧票据复活"。
 */
export function monoNow() {
    const p = globalThis.performance;
    if (p && typeof p.now === 'function')
        return p.now();
    return Date.now();
}
// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------
/** 每个 handle 都是新的、冻结的、无原型的空对象。 */
function newHandle() {
    return Object.freeze(Object.create(null));
}
/**
 * 创建票据存储。
 *
 * 代际语义：
 * - 代际按 **subject** 分账，不按 scope。一个模块被销毁，它的所有 domain 一起失效。
 * - 代际只增。`bumpEpoch` 与 `refreshEpoch` 都不会让它变小。
 * - 新建票据取**当前**代际，因此"先撤销、后签发"得到的新票据是有效的——
 *   这是正确的：撤销针对的是旧票据，不是禁止该主体再获得授权。
 */
export function createTicketStore(deps = {}) {
    const clock = deps.clock ?? monoNow;
    const epochSource = deps.epochSource;
    const tickets = new WeakMap();
    const epochs = new Map();
    /** 签发过票据的主体集合。`revokeAll` 需要它——WeakMap 无法枚举。 */
    const subjects = new Set();
    let minted = 0;
    let seq = 0;
    function currentEpoch(subject) {
        return epochs.get(subject) ?? 0;
    }
    function bumpEpoch(subject) {
        const next = currentEpoch(subject) + 1;
        epochs.set(subject, next);
        return next;
    }
    function read(t) {
        if (typeof t !== 'object' || t === null)
            return undefined;
        return tickets.get(t);
    }
    function verify(t) {
        const s = read(t);
        if (s === undefined)
            return { ok: false, code: 'STORAGE_TICKET_INVALID' };
        // 顺序：先查代际（撤销是确定性的、不依赖时钟），再查过期。
        // 反过来会让"已撤销且已过期"报成 EXPIRED 的普通过期，掩盖撤销事实。
        if (s.epoch !== currentEpoch(s.subject))
            return { ok: false, code: 'STORAGE_TICKET_EXPIRED' };
        if (clock() >= s.expiresAt)
            return { ok: false, code: 'STORAGE_TICKET_EXPIRED' };
        return { ok: true };
    }
    return {
        mint(spec) {
            if (spec.ops.length === 0) {
                // 空票据永远无法通过 op 授权。与其发出去让人调试半天，不如在签发点拒绝。
                // 这里抛错而不是返回 Result：签发是内部 API，调用方是网关/装载器，不是驱动。
                throw new Error('ticket: empty ops');
            }
            const handle = newHandle();
            const issuedAt = clock();
            const ttl = spec.ttlMs ?? 0;
            const state = Object.freeze({
                ticketId: `tk-${++seq}`,
                subject: spec.subject,
                scope: spec.scope,
                ops: Object.freeze([...spec.ops]),
                issuedAt,
                expiresAt: ttl > 0 ? issuedAt + ttl : Infinity,
                epoch: currentEpoch(spec.subject),
            });
            tickets.set(handle, state);
            subjects.add(spec.subject);
            minted++;
            return handle;
        },
        read,
        verify,
        currentEpoch,
        bumpEpoch,
        raiseEpoch(subject, epoch) {
            if (!Number.isSafeInteger(epoch) || epoch < 0)
                return currentEpoch(subject);
            if (epoch <= currentEpoch(subject))
                return currentEpoch(subject);
            epochs.set(subject, epoch);
            return epoch;
        },
        async refreshEpoch(subject) {
            if (epochSource === undefined)
                return currentEpoch(subject);
            const remote = await epochSource.read(subject);
            if (!Number.isSafeInteger(remote) || remote < 0) {
                // 外部源给了垃圾值：不采信，保持内存值。采信会让"读到 0"把撤销抹掉。
                return currentEpoch(subject);
            }
            const local = currentEpoch(subject);
            if (remote > local)
                epochs.set(subject, remote);
            return currentEpoch(subject);
        },
        revokeAll() {
            for (const subject of subjects)
                bumpEpoch(subject);
        },
        stats() {
            return { minted, subjects: subjects.size };
        },
    };
}
