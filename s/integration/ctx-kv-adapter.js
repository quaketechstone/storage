/**
 * 母体融合适配器：把 Storage 栈包装成 `ModuleCtx.kv` 形状，供驱动使用。
 *
 * # 边界
 *
 * 本文件**不**修改 `web/src/loader/*`，也**不**被任何生产代码 import。它是「接线前
 * 的最后一段」：契约、授权、可用性、生命周期、错误形状全部就绪，只等 A-2 审批后
 * 由装载器把 `ctx.kv` 指过来。当前状态：**ISOLATED_INTEGRATION**。
 *
 * # 与 `facade.ts` 的关系
 *
 * `facade.ts` 只解决「形状 + 票据在闭包」。本适配器补上母体真正需要的三件事：
 * 1. **可用性检测**（`available()`）：存储不可用时能提前降级，而不是每次调用才炸。
 * 2. **生命周期**（`close()`）：释放引擎资源（SQLite 关库 / IDB 关连接）。
 * 3. **装配授权**（`mountCtxKv`）：按 subject + scopes + ops 签 grant 与 ticket。
 *
 * # 错误
 *
 * 一律抛 `{ code, message }` 结构化对象（非 `Error` 实例），与 `host/mod.rs:8`
 * 「跨边界只传结构化错误」一致；`message` 来自固定文案表，不含键名/密钥。
 */
import { createKvFacade, inspectFacade } from '../facade.js';
import { normalizeError } from '../errors.js';
/** 可用性探测用的只读 scope（不写库）。 */
const PROBE_SCOPE = Object.freeze({
    tenant: 'sys',
    ks: 'sys',
    app: 'probe',
    domain: 'probe',
});
/**
 * 装配 `ctx.kv`。
 *
 * 票据签发失败（例如 scope 不在 grant 内）会直接抛结构化错误——这属于装配期
 * 错误，应当在启动时暴露，而不是等第一次 `kv.get` 才发现。
 */
export function mountCtxKv(deps) {
    const gw = deps.stack.gateway;
    const grant = gw.mintGrant({
        subject: deps.subject,
        scopes: deps.scopes,
        ops: deps.ops,
        source: deps.source ?? 'manifest',
    });
    const ticketRes = gw.mintTicket(grant, deps.scope);
    if (!ticketRes.ok)
        throw ticketRes.error;
    const kv = createKvFacade(gw, ticketRes.value, deps.scope, deps.ns);
    const mount = {
        kv,
        ticket: ticketRes.value,
        scope: deps.scope,
        async available() {
            try {
                await deps.stack.engine.get(PROBE_SCOPE, '__probe__');
                return true;
            }
            catch {
                return false;
            }
        },
        async close() {
            const engine = deps.stack.engine;
            if (typeof engine.close === 'function')
                await engine.close();
        },
        inspect() {
            return inspectFacade(kv);
        },
    };
    return Object.freeze(mount);
}
/** 把任意异常归一为结构化存储错误（供调用方在边界处使用）。 */
export function ctxKvError(e) {
    return normalizeError(e);
}
