/**
 * 装配：把 S0 契约、S1 网关、S2 引擎按**唯一正确的方式**接起来。
 *
 * # 为什么需要这个文件
 *
 * 五个组件（ticket / grant / quota / audit / engine）互相有引用关系，其中两条是
 * 容易接错的：
 *
 * 1. `gateway` 与 `ticketStore` 必须是**同一个** `ticketStore` 实例。若各建一个，
 *    网关签发的票据在自己的 store 里有效，在别处无效——症状是"刚发的票立刻失效"，
 *    排查成本极高。
 * 2. `quota` 必须与 `engine` 的生命周期一致。若重建 quota 而不 reconcile，
 *    账本归零，配额检查形同虚设。
 *
 * 把装配收进一个函数，让"接错"变成不可能，而不是靠调用方记得。
 *
 * # 引擎装饰顺序（顺序错了就是安全漏洞）
 *
 * ```
 *   raw（idb / memory）
 *     → verifying（读时校验，校验对象=落盘表示）
 *       → encrypting（加解密，把值换成信封）
 *         → gateway
 * ```
 *
 * `verifying` 必须在 `encrypting` **里面**：它校验的是"存下来的东西有没有被改"，
 * 也就是密文。反过来会让它拿密文去比明文的 hash，每次读都报 `INTEGRITY`。
 *
 * # 零调用方
 *
 * 本文件仍无生产代码 import。装配完成后由 `__tests__` 使用，未来由装载器接线时使用。
 */
import { nullSink } from './audit.js';
import { createEncryptingEngine } from './crypto/engine.js';
import { createIdbEngine } from './engines/idb.js';
import { createMemoryEngine } from './engines/memory.js';
import { createBroadcastBus, createEngineEpochStore, createRevocationCoordinator, } from './epoch.js';
import { createGateway, denyAllJudge } from './gateway.js';
import { createGrantStore } from './grant.js';
import { createVerifyingEngine, DEFAULT_INTEGRITY_MODE, } from './integrity.js';
import { createQuotaLedger } from './quota.js';
import { createTicketStore, monoNow } from './ticket.js';
/**
 * 装配整套存储栈。
 *
 * 返回值里 `tickets` / `grants` / `quota` 都暴露出来，是为了让测试能直接断言
 * "撤销代际变了"、"账本扣减了"这类内部事实；生产接线时只应把 `gateway` 与
 * 由它派生的 facade 交出去。
 */
export function createStorageStack(deps = {}) {
    const raw = deps.engine ?? createMemoryEngine();
    const audit = deps.audit ?? nullSink;
    const verifyMode = deps.verify ?? DEFAULT_INTEGRITY_MODE;
    const verifying = createVerifyingEngine(raw, { mode: verifyMode });
    const engine = deps.keyring === undefined ? verifying : createEncryptingEngine(verifying, deps.keyring);
    const tickets = createTicketStore({ clock: deps.clock ?? monoNow });
    const grants = createGrantStore();
    const quota = createQuotaLedger(deps.initialQuota === undefined ? {} : { initial: deps.initialQuota });
    let revocation = null;
    let revocationBus = null;
    if (deps.revocation !== false) {
        const cfg = deps.revocation ?? {};
        const bus = cfg.bus === undefined ? null : cfg.bus;
        revocation = createRevocationCoordinator({
            tickets,
            store: cfg.store ?? createEngineEpochStore(engine),
            bus,
            ...(cfg.maxStalenessMs === undefined ? {} : { maxStalenessMs: cfg.maxStalenessMs }),
            ...(deps.now === undefined ? {} : { now: deps.now }),
        });
        revocationBus = bus === null ? 'none' : 'broadcast';
    }
    const gateway = createGateway({
        engine,
        tickets,
        grants,
        quota,
        audit,
        judge: deps.judge ?? denyAllJudge,
        ...(revocation === null ? {} : { revocation }),
        ...(deps.now === undefined ? {} : { now: deps.now }),
    });
    return Object.freeze({
        engine,
        raw,
        tickets,
        grants,
        quota,
        audit,
        gateway,
        verifying,
        revocation,
        keyring: deps.keyring ?? null,
        verifyMode,
        revocationBus,
    });
}
/**
 * 打开真实 IndexedDB 并按**生产默认值**装配。
 *
 * 这是"接入时到底生效了什么"的唯一答案，也是验收要断言的对象：
 *
 * | 能力 | 默认 | 依据 |
 * |---|---|---|
 * | 读时完整性校验 | **开**（`always`） | B-2 批准启用 |
 * | 跨标签页撤销 | **开**（持久代际 + BroadcastChannel） | B-3 批准启用 |
 * | 加密 | **关**（需显式传 `keyring`） | B-1 暂不启用 |
 *
 * 广播通道在环境不支持时降级为"仅持久轮询"（`createBroadcastBus` 返回 `null`），
 * 不抛错——广播是优化，`maxStalenessMs` 才是最终一致性的保证。
 */
export async function createPersistentStack(deps = {}) {
    const engine = await createIdbEngine(deps.dbName === undefined ? {} : { name: deps.dbName });
    const bus = deps.noBus === true ? null : createBroadcastBus(deps.busName);
    return createStorageStack({
        ...deps,
        engine,
        revocation: deps.noRevocation === true
            ? false
            : {
                bus,
                ...(deps.maxStalenessMs === undefined ? {} : { maxStalenessMs: deps.maxStalenessMs }),
            },
    });
}
