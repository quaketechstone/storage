/**
 * 跨标签页撤销一致性。
 *
 * # 问题
 *
 * 票据是内存对象，撤销代际（`ticket.ts` 的 `epochs`）也是内存态。两个标签页各有一份，
 * 于是：
 *
 * ```
 *   Tab A：用户点了"注销" → revoke('module:x') → A 的 epoch = 1
 *   Tab B：仍持有一张 epoch=0 的票据 → 它不知道 A 撤销过 → 继续读写
 * ```
 *
 * 这在单页应用里是真实存在的越权：注销后另一个标签页还能读写被注销模块的数据。
 *
 * # 三个动作，缺一不可
 *
 * | 动作 | 作用 | 失败后果 |
 * |---|---|---|
 * | 持久化 | 刷新/新标签页能读到当前代际 | 新标签页从 0 起算，撤销被"遗忘" |
 * | 广播 | 其他**活跃**标签页立即失效 | 最长滞后一个 `maxStalenessMs` |
 * | 读取校验 | 广播丢失时（后台标签页被冻结）兜底 | 见下 |
 *
 * 只做广播是不够的：`BroadcastChannel` 在标签页被浏览器冻结（bfcache、后台节流）
 * 时不投递，而冻结的标签页恢复后仍持有旧票据。因此**每次操作前**还要按
 * `maxStalenessMs` 主动读一次持久代际。广播负责"快"，持久读取负责"最终一致"。
 *
 * # 边界（必须写明，不能用"已实现跨标签页撤销"一句盖过）
 *
 * 1. 撤销的**传播**有上界 `maxStalenessMs`（默认 2000 ms）。在此窗口内，另一个
 *    标签页仍可操作。要 0 窗口，只能把 `maxStalenessMs` 设为 0——代价是每次操作
 *    多一次 IDB 读（约 0.1–0.3 ms）。
 * 2. 本机制**不防**"同源代码直接改持久代际"。持久代际存在本模块的库里，同源脚本
 *    可以写它。它能防的是"忘记撤销/撤销不传播"，不能防"恶意撤销"或"恶意不撤销"。
 * 3. 代际只增。写入方取 `max(本地, 持久, 广播)`，任何一方的回退都不会让已撤销的
 *    票据复活。
 * 4. 持久代际**读不到**时 fail-closed：本次操作被拒（`STORAGE_UNAVAILABLE`），
 *    而不是按本地代际放行。放行会把"存储抖动"变成"撤销失效窗口"。
 * 5. 撤销的**写入**失败时，本地代际已经推进（本标签页立即生效），但错误会抛给调用方：
 *    必须让运维知道"其他标签页可能没收到"。
 */
import { sysScope } from './contract.js';
import { storageErrorOf } from './errors.js';
/** 内存实现。测试与无持久层场景。 */
export function createMemoryEpochStore(initial = {}) {
    const map = new Map(Object.entries(initial));
    return {
        async read(subject) {
            const v = map.get(subject);
            return v === undefined ? null : v;
        },
        async write(subject, epoch) {
            const cur = map.get(subject) ?? 0;
            if (Number.isSafeInteger(epoch) && epoch > cur)
                map.set(subject, epoch);
        },
    };
}
/** 账本所在作用域。`sys` 键空间，模块即使拿到同 domain 的 grant 也匹配不到。 */
export const EPOCH_DOMAIN = 'epoch';
/** 物理键前缀。 */
const EPOCH_KEY_PREFIX = 'ep.';
/** 短暂等待。仅用于并发写冲突的退避，单位毫秒。 */
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * 引擎实现：直接读写 `sys` 作用域的引擎，**不经过网关**。
 *
 * 为什么可以绕过网关：这是存储模块自己的账本，不是任何主体的业务数据。若它也要
 * 走票据，就得有人给存储模块自己发一张 `sys` 票据——那把"谁能读账本"变成了
 * 一个需要授权的循环问题。网关的 `sys` 作用域对模块不可达（`grant.ts` 在签发点
 * 拒绝），因此这里绕过的不是授权，而是"没有主体"的场景。
 *
 * # 为什么写要重试
 *
 * 引擎的写入是 CAS（读到的 rev 与写前复核不一致就报冲突）。同一标签页里连续点两次
 * "注销"、或两个标签页同时撤销，都会撞上这个冲突。账本的语义是"只升不降"，
 * 冲突不是失败而是"别人先写了"：重读一次，若对方已经写到不小于本次的值就完成，
 * 否则退避后重试。**不重试的后果**是用户并发注销时看到 `STORAGE_CONFLICT`，
 * 而实际上撤销已经生效（本地代际推进了），只是持久层没跟上。
 */
export function createEngineEpochStore(engine, domain = EPOCH_DOMAIN) {
    const scope = sysScope(domain);
    const keyOf = (subject) => `${EPOCH_KEY_PREFIX}${subject}`;
    async function read(subject) {
        const rec = await engine.get(scope, keyOf(subject));
        if (rec === null)
            return null;
        const v = rec.value;
        return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null;
    }
    return {
        read,
        async write(subject, epoch) {
            if (!Number.isSafeInteger(epoch) || epoch < 0)
                return;
            const attempts = 3;
            for (let i = 0; i < attempts; i++) {
                const cur = await read(subject);
                if (cur !== null && epoch <= cur)
                    return;
                try {
                    await engine.put(scope, keyOf(subject), epoch);
                    return;
                }
                catch (e) {
                    if (e.code !== 'STORAGE_CONFLICT')
                        throw e;
                    // 最后一次仍冲突：重读确认对方是否已写到不小于本次。
                    if (i === attempts - 1) {
                        const again = await read(subject);
                        if (again !== null && again >= epoch)
                            return;
                        throw e;
                    }
                    await sleep(5 * (i + 1));
                }
            }
        },
    };
}
/** 空实现：环境不支持广播时使用。 */
export function createNullBus() {
    return Object.freeze({
        publish() {
            /* 无广播 */
        },
        subscribe() {
            return () => {
                /* 无订阅 */
            };
        },
        close() {
            /* 无资源 */
        },
    });
}
/**
 * `BroadcastChannel` 实现。
 *
 * 环境不支持（Safari 旧版、Worker 之外的某些上下文）时返回 `null`，调用方退化为
 * 空广播 + 轮询式持久读取。**不抛错**：广播是优化，不是正确性前提。
 */
export function createBroadcastBus(name = 'quake.s1.revoke') {
    const Ctor = globalThis.BroadcastChannel;
    if (Ctor === undefined)
        return null;
    let ch;
    try {
        ch = new Ctor(name);
    }
    catch {
        return null;
    }
    const handlers = new Set();
    ch.onmessage = (ev) => {
        const m = ev.data;
        // 通道内容来自同源的其他标签页，同样不可信：逐字段校验，不合规直接丢弃。
        if (m === null || typeof m !== 'object')
            return;
        if (m.t !== 'revoke')
            return;
        if (typeof m.s !== 'string' || m.s.length === 0 || m.s.length > 256)
            return;
        if (typeof m.e !== 'number' || !Number.isSafeInteger(m.e) || m.e < 0)
            return;
        for (const h of handlers) {
            try {
                h(m.s, m.e);
            }
            catch {
                /* 单个订阅者异常不影响其余 */
            }
        }
    };
    return {
        publish(subject, epoch) {
            try {
                ch.postMessage({ t: 'revoke', s: subject, e: epoch });
            }
            catch {
                /* 通道已关闭或不可用：广播是优化，失败不影响本地撤销 */
            }
        },
        subscribe(fn) {
            handlers.add(fn);
            return () => handlers.delete(fn);
        },
        close() {
            handlers.clear();
            try {
                ch.close();
            }
            catch {
                /* 已关闭 */
            }
        },
    };
}
/** 创建协调器。 */
export function createRevocationCoordinator(deps) {
    const { tickets, store } = deps;
    const bus = deps.bus ?? null;
    const now = deps.now ?? (() => Date.now());
    const maxStaleness = deps.maxStalenessMs ?? 2000;
    const lastSync = new Map();
    let published = 0;
    let received = 0;
    let syncs = 0;
    /** 合并一个来自外部的绝对代际。只升不降。 */
    function merge(subject, epoch) {
        // 主体标识先校验：空串/超长串会让 `epochs` 表被无界污染，而且空主体的票据
        // 本来就不可能签出来（`validateSubject` 拒绝）。
        if (typeof subject !== 'string' || subject.length === 0 || subject.length > 256)
            return;
        if (!Number.isSafeInteger(epoch) || epoch < 0)
            return;
        const before = tickets.currentEpoch(subject);
        const after = tickets.raiseEpoch(subject, epoch);
        if (after > before)
            lastSync.set(subject, now());
    }
    const unsubscribe = bus === null
        ? () => {
            /* 无订阅 */
        }
        : bus.subscribe((subject, epoch) => {
            received++;
            merge(subject, epoch);
        });
    async function pull(subject) {
        syncs++;
        let remote;
        try {
            remote = await store.read(subject);
        }
        catch {
            // **fail-closed**：读不到持久代际时，无法证明"没有被撤销过"。
            // 此时放行等于把"存储暂时不可用"变成"撤销暂时失效"——那正是攻击者想要的窗口。
            // 因此抛错，让网关把本次操作拒掉（调用方看到 STORAGE_UNAVAILABLE 可重试）。
            // 不更新 `lastSync`：否则失败会被当成"刚同步过"，在 `maxStalenessMs` 内继续放行。
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        }
        const local = tickets.currentEpoch(subject);
        if (remote !== null && remote > local) {
            merge(subject, remote);
        }
        else if (local > 0 && (remote === null || local > remote)) {
            // 本地更"新"：把本地值补写回持久层。否则刷新后撤销会丢失。
            await store.write(subject, local);
        }
        lastSync.set(subject, now());
        return tickets.currentEpoch(subject);
    }
    return {
        async revoke(subject) {
            const next = tickets.bumpEpoch(subject);
            await store.write(subject, next);
            published++;
            bus?.publish(subject, next);
            lastSync.set(subject, now());
            return next;
        },
        async ensureFresh(subject) {
            const at = lastSync.get(subject);
            if (at !== undefined && now() - at < maxStaleness)
                return tickets.currentEpoch(subject);
            return pull(subject);
        },
        forceSync(subject) {
            return pull(subject);
        },
        lastSyncedAt(subject) {
            return lastSync.get(subject) ?? 0;
        },
        close() {
            unsubscribe();
            bus?.close();
        },
        stats() {
            return { published, received, syncs };
        },
    };
}
