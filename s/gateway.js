/**
 * S1 网关：**唯一**的存储访问入口，所有门禁在此集中。
 *
 * # 门禁顺序（顺序本身是安全属性）
 *
 * ```
 *   GATE-1  句柄有效性      未知对象 → TICKET_INVALID
 *   GATE-2  撤销代际        与当前代际不符 → TICKET_EXPIRED
 *   GATE-3  时效            已过期 → TICKET_EXPIRED
 *   GATE-4  作用域精确匹配  不等 → SCOPE_VIOLATION
 *   GATE-5  操作授权        op ∉ ops → DENIED
 *   GATE-6  引擎能力        op ∉ capabilities → UNSUPPORTED
 *   GATE-7  参数合法性      键/值非法 → DENIED
 *   GATE-8  配额           超限 → QUOTA_EXCEEDED
 *   GATE-9  敏感操作咨询    judge 拒绝 → DENIED
 * ```
 *
 * 为什么 GATE-4 在 GATE-5 之前：先判 scope 后判 op，越权者只能学到"这个 scope 不归你"，
 * 学不到"这个 scope 里 purge 是敏感操作"。反过来会泄漏一张权限地图。
 *
 * 为什么 GATE-2 在 GATE-3 之前：撤销是确定性事实，过期是时间流逝。已撤销且已过期的
 * 票据报 EXPIRED 是巧合正确，但把"被撤销"藏进"过期"里，审计就少一条线索。
 *
 * # 主体绑定在哪里
 *
 * **在签发时**，不在每次调用时。`mintTicket` 把 `grant.subject` 写进票据内部态，
 * 之后不可改；审计事件从内部态取主体，因此归因不会因调用方传参而失真。
 *
 * 本模块**不**声称"验证了调用者身份"。JS 没有调用者身份原语：任何持有 facade 引用
 * 的代码都能以该 facade 的主体身份操作。防御边界是「票据不可由数据构造 + 撤销可
 * 全局失效」，不是「每次调用都重新认证」——后者在纯前端无法实现，写成"已验证"就是
 * 用文档代替控制（U-2）。
 */
import { isSensitiveOp, physicalKey, scopeMatches, validateKey, } from './contract.js';
import { recordBytes, scopeId } from './canonical.js';
import { attemptAsync, errCode, isStorageError, ok, storageErrorOf } from './errors.js';
import { nullSink, safeEmit } from './audit.js';
import { createKeyedMutex, createLimiter } from './concurrency.js';
import { byteDelta } from './quota.js';
/**
 * 默认咨询器：**一律拒绝**。
 *
 * 这是安全的默认值。未接线时敏感操作全部不可用，比"未接线时全部放行"好：
 * 前者暴露为功能缺失，后者暴露为静默越权。
 */
export const denyAllJudge = Object.freeze({
    async check() {
        return false;
    },
});
/** 一律放行。**仅测试**——生产注入它等于关掉 GATE-9。 */
export function createAllowAllJudge() {
    return Object.freeze({
        async check() {
            return true;
        },
    });
}
// ---------------------------------------------------------------------------
// 拒绝类别（用于审计归类）
// ---------------------------------------------------------------------------
const DENIAL_CODES = Object.freeze([
    'STORAGE_DENIED',
    'STORAGE_SCOPE_VIOLATION',
    'STORAGE_TICKET_INVALID',
    'STORAGE_TICKET_EXPIRED',
]);
function auditKindFor(code) {
    if (code === 'STORAGE_QUOTA_EXCEEDED')
        return 'quota';
    if (DENIAL_CODES.includes(code))
        return 'denied';
    return 'op';
}
// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------
/** 创建网关。 */
export function createGateway(deps) {
    const { engine, tickets, grants, quota } = deps;
    const audit = deps.audit ?? nullSink;
    const judge = deps.judge ?? denyAllJudge;
    const revocation = deps.revocation ?? null;
    const now = deps.now ?? (() => Date.now());
    const maxScan = deps.maxScan ?? 10_000;
    const maxTxOps = deps.maxTxOps ?? 200;
    /** 同键互斥：保证 `get → 配额预检 → put` 之间没有插入。 */
    const mutex = createKeyedMutex();
    /** 事务串行：两个 tx 交错会让"原子"变成"看起来原子"。 */
    const txMutex = createKeyedMutex();
    /** 读并发上限：防止一次 scan 打出上千个并发事务。 */
    const limiter = createLimiter(8);
    function emit(e) {
        safeEmit(audit, Object.freeze({ ...e, at: now(), engine: engine.kind }));
    }
    /**
     * 门禁 GATE-1..6。返回票据内部态，失败抛 `StorageError`。
     *
     * 不返回 Result：门禁在 9 个方法里各调一次，若每处都写 `if (!r.ok) return r`
     * 会淹没真正的业务逻辑，而漏写一次就是越权。
     */
    async function gate(t, scope, op) {
        const state = tickets.read(t);
        if (state === undefined)
            throw storageErrorOf('STORAGE_TICKET_INVALID');
        // 撤销代际可能已被其他标签页推进。先按 `maxStalenessMs` 拉一次（新鲜时零 IO），
        // 再判有效性——否则"别的标签页注销了，这个标签页还在写"。
        if (revocation !== null)
            await revocation.ensureFresh(state.subject);
        const verdict = tickets.verify(t);
        if (!verdict.ok)
            throw storageErrorOf(verdict.code);
        if (!scopeMatches(state.scope, scope))
            throw storageErrorOf('STORAGE_SCOPE_VIOLATION');
        if (!state.ops.includes(op))
            throw storageErrorOf('STORAGE_DENIED');
        if (!engine.capabilities().ops.includes(op))
            throw storageErrorOf('STORAGE_UNSUPPORTED');
        return state;
    }
    /** GATE-9：敏感操作咨询。 */
    async function consult(state, scope, op) {
        if (!isSensitiveOp(op))
            return;
        let allowed = false;
        try {
            allowed = await judge.check({
                subject: state.subject,
                op,
                scope: scopeId(scope),
                ticketId: state.ticketId,
            });
        }
        catch {
            // judge 自身异常按拒绝处理：咨询器崩了不等于放行。
            allowed = false;
        }
        if (!allowed)
            throw storageErrorOf('STORAGE_DENIED');
    }
    /** 统一失败审计。`state` 未知时主体记为 `unknown`——这本身就是线索。 */
    function emitFailure(state, scope, op, e) {
        const code = isStorageError(e) ? e.code : 'STORAGE_UNAVAILABLE';
        emit({
            kind: auditKindFor(code),
            subject: state?.subject ?? 'unknown',
            op,
            scope: scope === undefined ? '-' : scopeId(scope),
            ticketId: state?.ticketId ?? 'none',
            code,
        });
    }
    /** 本地撤销（不传播）。 */
    function localRevoke(subject) {
        const next = tickets.bumpEpoch(subject);
        emit({ kind: 'revoke', subject, scope: '-', ticketId: '-' });
        return next;
    }
    function toView(rec) {
        return Object.freeze({ value: rec.value, rev: rec.rev, hash: rec.hash, ts: rec.ts });
    }
    /** 一次写入的配额处理：预占 → 执行 → 失败释放 / 缩减确认。 */
    async function writeWithQuota(subject, scope, key, value, opts) {
        const prev = await engine.get(scope, key);
        const nextBytes = recordBytes(value);
        const delta = byteDelta(prev?.bytes ?? 0, nextBytes);
        if (delta >= 0)
            quota.reserve(subject, delta, nextBytes);
        else
            quota.reserve(subject, 0, nextBytes);
        try {
            const rec = await engine.put(scope, key, value, opts);
            if (delta < 0)
                quota.release(subject, -delta);
            return Object.freeze({ rev: rec.rev, hash: rec.hash });
        }
        catch (e) {
            if (delta > 0)
                quota.release(subject, delta);
            throw e;
        }
    }
    /**
     * 事务实现。
     *
     * 配额在这里比单条写复杂：一条 tx 可能覆盖同一个键两次，净增量必须按**最终态**
     * 算，而不是按每条 op 累加。做法是在锁内模拟每个键的起止字节。
     */
    async function runTx(state, ops) {
        if (ops.length > maxTxOps)
            throw storageErrorOf('STORAGE_DENIED');
        if (ops.length === 0) {
            return Object.freeze({ committed: true, results: [], deleted: 0 });
        }
        for (const o of ops) {
            if (!scopeMatches(state.scope, o.scope))
                throw storageErrorOf('STORAGE_SCOPE_VIOLATION');
            validateKey(o.key);
        }
        return txMutex.run('__tx__', async () => {
            // 1. 模拟每个键的起始字节与终值字节。
            const before = new Map();
            const after = new Map();
            let peakRecord = 0;
            for (const o of ops) {
                const pk = physicalKey(o.scope, o.key);
                if (!before.has(pk)) {
                    const prev = await engine.get(o.scope, o.key);
                    const b = prev?.bytes ?? 0;
                    before.set(pk, b);
                    after.set(pk, b);
                }
                if (o.op === 'put') {
                    const nb = recordBytes(o.value);
                    if (nb > peakRecord)
                        peakRecord = nb;
                    after.set(pk, nb);
                }
                else {
                    after.set(pk, 0);
                }
            }
            // 2. 净增量按终值算。同一键被覆盖多次时只有最后一次计入。
            let delta = 0;
            for (const [pk, a] of after)
                delta += a - (before.get(pk) ?? 0);
            // 3. 预占。单条上限用本次 tx 内最大的 put 值判定。
            if (delta > 0)
                quota.reserve(state.subject, delta, peakRecord);
            else
                quota.reserve(state.subject, 0, peakRecord);
            // 4. 提交。引擎保证全有或全无；失败时把预占退回去。
            const mutations = ops.map((o) => ({
                op: o.op,
                scope: o.scope,
                key: o.key,
                ...(o.op === 'put' ? { value: o.value } : {}),
                ...(o.opts === undefined ? {} : { opts: o.opts }),
            }));
            let records;
            try {
                records = await engine.commit(mutations);
            }
            catch (e) {
                if (delta > 0)
                    quota.release(state.subject, delta);
                throw e;
            }
            if (delta < 0)
                quota.release(state.subject, -delta);
            // 实际删除数：只数"原本有记录"的键，且同一键只数一次。
            const delKeys = new Set();
            for (const o of ops) {
                if (o.op !== 'del')
                    continue;
                const pk = physicalKey(o.scope, o.key);
                if ((before.get(pk) ?? 0) > 0)
                    delKeys.add(pk);
            }
            return Object.freeze({
                committed: true,
                results: Object.freeze(records.map((r) => Object.freeze({ rev: r.rev, hash: r.hash }))),
                deleted: delKeys.size,
            });
        });
    }
    return {
        mintGrant(spec) {
            return grants.issue(spec, now());
        },
        mintTicket(grant, scope, ops, ttlMs) {
            const state = grants.read(grant);
            if (state === undefined)
                return errCode('STORAGE_TICKET_INVALID');
            const allowed = grants.resolveOps(grant, scope);
            if (allowed === null)
                return errCode('STORAGE_SCOPE_VIOLATION');
            // 收窄而非扩张：`ops` 给定时只保留交集。
            const finalOps = ops === undefined ? allowed : allowed.filter((o) => ops.includes(o));
            if (finalOps.length === 0)
                return errCode('STORAGE_DENIED');
            try {
                return ok(tickets.mint({ subject: state.subject, scope, ops: finalOps, ttlMs }));
            }
            catch {
                return errCode('STORAGE_DENIED');
            }
        },
        async get(t, scope, key) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    state = await gate(t, scope, 'read');
                    validateKey(key);
                    const rec = await limiter.run(() => engine.get(scope, key));
                    emit({
                        kind: 'op',
                        subject: state.subject,
                        op: 'read',
                        scope: scopeId(scope),
                        ticketId: state.ticketId,
                    });
                    return rec === null ? null : toView(rec);
                }
                catch (e) {
                    emitFailure(state, scope, 'read', e);
                    throw e;
                }
            });
        },
        async list(t, scope, prefix = '') {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    state = await gate(t, scope, 'list');
                    const keys = await limiter.run(() => engine.list(scope, prefix));
                    emit({
                        kind: 'op',
                        subject: state.subject,
                        op: 'list',
                        scope: scopeId(scope),
                        ticketId: state.ticketId,
                    });
                    return Object.freeze(keys);
                }
                catch (e) {
                    emitFailure(state, scope, 'list', e);
                    throw e;
                }
            });
        },
        async scan(t, scope, q = {}) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    state = await gate(t, scope, 'scan');
                    const limit = Math.min(Math.max(1, q.limit ?? 1000), maxScan);
                    const order = q.order ?? 'key';
                    // `ts` 排序必须先取全量再截断，否则拿到的是"键序前 N 条按 ts 排"，
                    // 不是"ts 最小的 N 条"。用 maxScan 兜底防止无界读。
                    const fetchLimit = order === 'ts' ? maxScan : limit;
                    const rows = await limiter.run(() => engine.scan(scope, q.prefix ?? '', fetchLimit));
                    let views = rows.map((r) => toView(r.rec));
                    if (order === 'ts')
                        views = [...views].sort((a, b) => a.ts - b.ts).slice(0, limit);
                    emit({
                        kind: 'op',
                        subject: state.subject,
                        op: 'scan',
                        scope: scopeId(scope),
                        ticketId: state.ticketId,
                    });
                    return Object.freeze(views);
                }
                catch (e) {
                    emitFailure(state, scope, 'scan', e);
                    throw e;
                }
            });
        },
        async stat(t, scope, key) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    state = await gate(t, scope, 'read');
                    validateKey(key);
                    const rec = await limiter.run(() => engine.get(scope, key));
                    emit({
                        kind: 'op',
                        subject: state.subject,
                        op: 'read',
                        scope: scopeId(scope),
                        ticketId: state.ticketId,
                    });
                    return rec === null ? null : Object.freeze({ rev: rec.rev, hash: rec.hash, ts: rec.ts });
                }
                catch (e) {
                    emitFailure(state, scope, 'read', e);
                    throw e;
                }
            });
        },
        async usage(t, scope) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    state = await gate(t, scope, 'read');
                    const n = await limiter.run(() => engine.usage(scope));
                    emit({
                        kind: 'op',
                        subject: state.subject,
                        op: 'read',
                        scope: scopeId(scope),
                        ticketId: state.ticketId,
                    });
                    return n;
                }
                catch (e) {
                    emitFailure(state, scope, 'read', e);
                    throw e;
                }
            });
        },
        async put(t, scope, key, value, opts = {}) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    const s = await gate(t, scope, 'write');
                    state = s;
                    validateKey(key);
                    const pk = physicalKey(scope, key);
                    // 锁在配额预检之前：否则两个并发写都读到旧字节，都通过预检。
                    const res = await mutex.run(pk, () => writeWithQuota(s.subject, scope, key, value, opts));
                    emit({
                        kind: 'op',
                        subject: s.subject,
                        op: 'write',
                        scope: scopeId(scope),
                        ticketId: s.ticketId,
                        rev: res.rev,
                    });
                    return res;
                }
                catch (e) {
                    emitFailure(state, scope, 'write', e);
                    throw e;
                }
            });
        },
        async del(t, scope, key, expectedRev) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    const s = await gate(t, scope, 'delete');
                    state = s;
                    validateKey(key);
                    const pk = physicalKey(scope, key);
                    await mutex.run(pk, async () => {
                        const r = await engine.del(scope, key, expectedRev);
                        // 引擎在删除的同一原子步报出释放字节，避免"另读一次旧记录"的竞态。
                        if (r.removed && r.bytes > 0)
                            quota.release(s.subject, r.bytes);
                    });
                    emit({
                        kind: 'op',
                        subject: s.subject,
                        op: 'delete',
                        scope: scopeId(scope),
                        ticketId: s.ticketId,
                    });
                    return undefined;
                }
                catch (e) {
                    emitFailure(state, scope, 'delete', e);
                    throw e;
                }
            });
        },
        async purge(t, scope) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    const s = await gate(t, scope, 'purge');
                    state = s;
                    await consult(s, scope, 'purge');
                    // 先取用量：purge 之后 engine.usage 归零，就不知道要释放多少。
                    const before = await engine.usage(scope);
                    const deleted = await engine.purge(scope);
                    if (before > 0)
                        quota.release(s.subject, before);
                    emit({
                        kind: 'op',
                        subject: s.subject,
                        op: 'purge',
                        scope: scopeId(scope),
                        ticketId: s.ticketId,
                    });
                    return Object.freeze({ deleted });
                }
                catch (e) {
                    emitFailure(state, scope, 'purge', e);
                    throw e;
                }
            });
        },
        async tx(t, ops) {
            return attemptAsync(async () => {
                // 先取内部态用于审计归因：gate 抛错时 state 还没被赋值，若这里不预取，
                // 一个「票据有效但越权」的拒绝会被记成 subject=unknown，审计无法定位主体。
                let state = tickets.read(t);
                try {
                    // 空事务也要过门禁：它仍然是一次"以该主体身份调用 tx"的尝试，
                    // 审计需要记录。scope 取票据自身的——空 ops 没有别的 scope 可用。
                    const peek = tickets.read(t);
                    if (peek === undefined)
                        throw storageErrorOf('STORAGE_TICKET_INVALID');
                    const scope = ops.length > 0 ? ops[0].scope : peek.scope;
                    const s = await gate(t, scope, 'tx');
                    state = s;
                    const r = await runTx(s, ops);
                    emit({
                        kind: 'tx',
                        subject: s.subject,
                        op: 'tx',
                        scope: scopeId(s.scope),
                        ticketId: s.ticketId,
                    });
                    return r;
                }
                catch (e) {
                    emitFailure(state, undefined, 'tx', e);
                    throw e;
                }
            });
        },
        revoke: localRevoke,
        async revokeGlobal(subject) {
            const fn = revocation?.revoke;
            if (fn === undefined)
                return localRevoke(subject);
            const next = await fn.call(revocation, subject);
            emit({ kind: 'revoke', subject, scope: '-', ticketId: '-' });
            return next;
        },
        async refreshEpoch(subject) {
            return tickets.refreshEpoch(subject);
        },
        info() {
            return { engine: engine.kind, minted: tickets.stats().minted, grants: grants.stats().issued };
        },
    };
}
