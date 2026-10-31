/**
 * S1 授权：grant 的签发、解析与**降维**成票据。
 *
 * # grant 与 ticket 的分工
 *
 * | | grant | ticket |
 * |---|---|---|
 * | 生命周期 | 与模块/页面同寿（装载期签发一次） | 与一次挂载或一次敏感操作同寿 |
 * | 作用域 | **集合**（一个模块可声明多个 domain） | **单个** scope |
 * | 可变性 | 签发后不可变 | 不可变，但可被撤销代际整体作废 |
 * | 持有者 | 装载器（`loader.ts` 的 authorize 阶段） | 网关 + 门面闭包 |
 *
 * 之所以要两层：`ctx.kv` 是"一次调用一个 domain"的形状，若直接把 grant 交给门面，
 * 门面就得在每次调用时判断"这个 key 属于哪个 scope"，而 key 本身不含 scope 信息
 * （A5：键是逻辑键，不含前缀）。降维成单 scope 票据后，门面**在结构上**只能访问
 * 那一个 scope——越权不再是"检查漏了"，而是"没有可用的参数"。
 *
 * # 不可构造
 *
 * grant 与 ticket 同构：句柄是冻结空对象，内部态在模块私有 WeakMap。
 * `{ subject: 'system:kernel', ops: [...全部] }` 这种字面量不是 grant，
 * `readGrant` 返回 `undefined`，网关直接 `STORAGE_TICKET_INVALID`。
 *
 * 仅靠 `instanceof` 或 `Symbol` 标记不够——`Object.getOwnPropertySymbols` 能列出
 * 符号键，`Object.create(GrantProto)` 能伪造原型链。WeakMap 没有这两个缺口。
 */
import { APP_SYS, createScope, opAllowed, scopeMatches, validateSubject, } from './contract.js';
// ---------------------------------------------------------------------------
// 写类操作
// ---------------------------------------------------------------------------
/**
 * 会改变落盘状态的操作。`readOnly` 的 scope 会把这些滤掉。
 *
 * `backup` 不在其中：导出不改数据，只读语义下应当允许（但仍属敏感 op，需 judge）。
 */
export const WRITE_OPS = Object.freeze([
    'write',
    'delete',
    'purge',
    'tx',
    'migrate',
    'restore',
    'keyAccess',
]);
// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------
function newHandle() {
    return Object.freeze(Object.create(null));
}
/**
 * 创建 grant 存储。
 *
 * 校验在签发点完成（fail fast）：非法主体、非法 scope、空 op 集合、`sys` 键空间
 * 授予模块——这些一旦签出去，后续每次调用都要重复检查，且检查漏一处就是越权。
 */
export function createGrantStore() {
    const grants = new WeakMap();
    let issued = 0;
    let seq = 0;
    function read(g) {
        if (typeof g !== 'object' || g === null)
            return undefined;
        return grants.get(g);
    }
    return {
        issue(spec, now) {
            // 1. 主体合法。非法主体（如 `admin`、空串）会让审计归因失真。
            validateSubject(spec.subject);
            // 2. 至少一个 scope、至少一个 op。
            if (spec.scopes.length === 0)
                throw new Error('grant: empty scopes');
            if (spec.ops.length === 0)
                throw new Error('grant: empty ops');
            // 3. `sys` 键空间不对模块开放（RV-02）。内核可以用 sys，模块不行。
            //    这条在签发点拦，而不是在每次调用时拦——否则漏一处就是账本可读。
            for (const s of spec.scopes) {
                if (s.scope.ks === 'sys' && spec.subject !== 'system:kernel') {
                    throw new Error('grant: sys keyspace is kernel-only');
                }
                if (s.scope.app === APP_SYS && spec.subject !== 'system:kernel') {
                    throw new Error('grant: app=sys is kernel-only');
                }
                // 4. 主体只能拿自己 app 的授权。`module:a.b` 不得拿到 `module:c.d` 的 scope。
                //    这条挡的是"装载器配错"与"manifest 声明他人 id"两类问题。
                if (spec.subject.startsWith('module:') && s.scope.app !== spec.subject) {
                    throw new Error('grant: scope app must equal subject');
                }
            }
            // 5. 重复 scope 是配置错误，不是"合并"。静默合并会让"后写的覆盖先写的"
            //    成为隐式语义，而覆盖正是提权的常见来源。
            for (let i = 0; i < spec.scopes.length; i++) {
                for (let j = i + 1; j < spec.scopes.length; j++) {
                    const a = spec.scopes[i];
                    const b = spec.scopes[j];
                    if (a !== undefined && b !== undefined && scopeMatches(a.scope, b.scope)) {
                        throw new Error('grant: duplicate scope');
                    }
                }
            }
            const handle = newHandle();
            grants.set(handle, Object.freeze({
                grantId: `gr-${++seq}`,
                subject: spec.subject,
                scopes: Object.freeze(spec.scopes.map((s) => Object.freeze({ ...s }))),
                ops: Object.freeze([...spec.ops]),
                source: spec.source,
                issuedAt: now,
            }));
            issued++;
            return handle;
        },
        read,
        resolveOps(g, scope) {
            const state = read(g);
            if (state === undefined)
                return null;
            const entry = state.scopes.find((s) => scopeMatches(s.scope, scope));
            if (entry === undefined)
                return null;
            const readOnly = entry.readOnly === true;
            const out = [];
            for (const op of state.ops) {
                // 交集语义：grant 级 ops ∩ scope 级 ops（若给出）。
                if (!opAllowed(state.ops, entry.ops, op))
                    continue;
                if (readOnly && WRITE_OPS.includes(op))
                    continue;
                out.push(op);
            }
            return Object.freeze(out);
        },
        stats() {
            return { issued };
        },
    };
}
/**
 * 便捷构造：从「主体 + domain 列表」生成 grant 规格。
 *
 * 这是给装载器用的糖，不参与判定。之所以放在这里而不是 `loader.ts`：T1.2 不得
 * 修改母体源码，而装载器未来接线时需要这个形状；先在本模块内提供并测试。
 */
export function buildModuleGrantSpec(subject, domains, ops, source = 'manifest') {
    return {
        subject,
        scopes: domains.map((domain) => ({
            scope: createScope('local', 'user', subject, domain),
        })),
        ops,
        source,
    };
}
