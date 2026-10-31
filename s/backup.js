/**
 * 备份与恢复。
 *
 * # 这份实现能防什么、不能防什么
 *
 * 能防：意外损坏、传输截断、版本不兼容、把 A 模块的包恢复到 B 模块的 scope
 * （包内记录了 scope，恢复时逐字段比对）、"包里的值与摘要不符"。
 *
 * **伪造要靠签名**（`backup-sign.ts`）。不带 `signer` 时本模块**只做摘要校验**，
 * 而摘要校验挡不住"改值 + 重算 hash + 重算 digest"的自洽伪造——`backup.test.mjs`
 * 有一条用例故意断言这种包会被接受，把边界钉在测试里而不是文档里。
 *
 * 因此调用方的选择只有两个：
 * 1. 带 `signer`（推荐）：签名不符 → `STORAGE_RESTORE_REJECTED`；
 * 2. 不带 `signer`：必须自己保证包来源（同源下载、HTTPS、人工核对），
 *    且**不得**对外宣称"备份已校验完整性"。
 *
 * 签名也不防"已控制同源环境的攻击者"——密钥就在本源（见 `backup-sign.ts` 文件头）。
 *
 * # 为什么恢复默认拒绝覆盖
 *
 * 恢复的典型事故不是"包坏了"，而是"把三天前的包恢复到了今天的库上"，覆盖掉
 * 这三天的新数据。默认 `onExisting: 'reject'` 让这类误操作变成一次明确的失败，
 * 而不是一次静默的数据丢失。要覆盖必须显式写 `'overwrite'`。
 *
 * # 为什么先全量校验再写
 *
 * 边校验边写的话，第 500 条发现包坏了，前 499 条已经落库。恢复没有事务
 * （跨多条记录），因此"要么全写要么不写"只能靠"先校验完再写"来近似。
 * 写入阶段仍可能中途失败（配额、磁盘），所以报告里有 `aborted` 与 `written`。
 */
import { BACKUP_SIG_ALG, backupSignaturePayload } from './backup-sign.js';
import { canonicalJson, recordBytes, recordHash, scopeId, sha256Hex } from './canonical.js';
import { validateKey } from './contract.js';
import { storageErrorOf } from './errors.js';
/** 包版本。字段或摘要口径变更必须升版本。v2 起支持 `sig`。 */
export const BACKUP_VERSION = 2;
/**
 * 兼容读取的旧版本。v1 的包**没有** `sig` 字段，只做摘要校验。
 *
 * 为什么保留而不是一律拒绝：拒绝会让升级前的导出包直接变成废纸，而它可能正是
 * 用户唯一的备份。旧包按"未签名"处理，配置了 `signer` 时会被 `unsigned` 拒掉——
 * 处置是"重新导出"，而不是"数据没了"。
 */
export const LEGACY_BACKUP_VERSION = 1;
export const DEFAULT_BACKUP_LIMITS = Object.freeze({
    maxRecords: 100_000,
    maxBytes: 64 * 1024 * 1024,
    maxRecordBytes: 8 * 1024 * 1024,
});
/**
 * 摘要口径。**唯一**一处，导出供测试断言"改口径会红"。
 *
 * 版本参与摘要：v1 与 v2 对同一批记录算出不同摘要，这样"把 v1 包改成 v2 头"
 * 会立刻被摘要校验挡住，而不是被当成合法的新包。
 */
export function backupDigest(scope, records, version = BACKUP_VERSION) {
    const body = records.map((r) => `${r.key}\u0000${r.rev}\u0000${r.hash}\u0000${canonicalJson(r.value)}`);
    return sha256Hex(`${version}|${scope}|${body.join('\u0001')}`);
}
/** 导出。 */
export async function createBackup(engine, scope, opts = {}) {
    const limits = { ...DEFAULT_BACKUP_LIMITS, ...(opts.limits ?? {}) };
    const rows = await engine.scan(scope, '', Math.min(opts.limit ?? limits.maxRecords, limits.maxRecords));
    const records = [];
    let bytes = 0;
    for (const r of rows) {
        const size = recordBytes(r.rec.value);
        if (size > limits.maxRecordBytes)
            throw storageErrorOf('STORAGE_QUOTA_EXCEEDED');
        bytes += size;
        if (bytes > limits.maxBytes)
            throw storageErrorOf('STORAGE_QUOTA_EXCEEDED');
        records.push(Object.freeze({
            key: r.key,
            rev: r.rec.rev,
            hash: r.rec.hash,
            ts: r.rec.ts,
            value: r.rec.value,
        }));
    }
    const sid = scopeId(scope);
    const digest = await backupDigest(sid, records);
    let sig = null;
    if (opts.signer !== undefined) {
        const mac = await opts.signer.sign(backupSignaturePayload({ v: BACKUP_VERSION, scope: sid, count: records.length, digest }, opts.signer.keyId));
        sig = Object.freeze({ alg: BACKUP_SIG_ALG, keyId: opts.signer.keyId, mac });
    }
    return Object.freeze({
        v: BACKUP_VERSION,
        id: opts.id ?? `bk-${records.length}-${digest.slice(0, 12)}`,
        createdAt: (opts.now ?? (() => Date.now()))(),
        scope: sid,
        count: records.length,
        bytes,
        digest,
        sig,
        records: Object.freeze(records),
    });
}
/**
 * 校验包。**只读**。
 *
 * 逐层检查：形状 → scope → 数量/体积 → 每条 key/value/hash → 摘要。
 * 任何一层不过都返回 `ok:false`，不抛错——调用方需要拿到"为什么不过"。
 */
export async function verifyBackup(pkg, opts = {}) {
    const limits = { ...DEFAULT_BACKUP_LIMITS, ...(opts.limits ?? {}) };
    const bad = (reason, at = 0, signature = 'not-checked') => Object.freeze({ ok: false, reason, at, signature });
    if (typeof pkg !== 'object' || pkg === null)
        return bad('bad-shape');
    const p = pkg;
    if (p.v !== BACKUP_VERSION && p.v !== LEGACY_BACKUP_VERSION)
        return bad('bad-version');
    if (typeof p.scope !== 'string' || typeof p.digest !== 'string')
        return bad('bad-shape');
    if (!Array.isArray(p.records))
        return bad('bad-shape');
    if (typeof p.count !== 'number' || p.count !== p.records.length)
        return bad('bad-shape');
    if (p.v === LEGACY_BACKUP_VERSION && p.sig !== undefined && p.sig !== null) {
        // v1 没有签名字段。带着签名来的 v1 包要么是被改过版本号，要么是伪造尝试。
        return bad('bad-shape');
    }
    // 签名先验：伪造包不该有机会消耗 O(n) 的摘要计算。代价是签名不符时看不到
    // 更细的内容错误——这是刻意的取舍，`reason` 已经足够指向"包不可信"。
    let signature = 'not-checked';
    if (opts.signer !== undefined) {
        const sig = p.sig;
        if (sig === null || sig === undefined) {
            if ((opts.onUnsigned ?? 'reject') === 'reject')
                return bad('unsigned');
            signature = 'unsigned';
        }
        else {
            if (typeof sig !== 'object' ||
                sig.alg !== BACKUP_SIG_ALG ||
                typeof sig.keyId !== 'string' ||
                typeof sig.mac !== 'string') {
                return bad('bad-shape');
            }
            if (sig.keyId !== opts.signer.keyId)
                return bad('unknown-key');
            const payload = backupSignaturePayload({ v: p.v, scope: p.scope, count: p.count, digest: p.digest }, sig.keyId);
            if (!(await opts.signer.verify(payload, sig.mac)))
                return bad('bad-signature');
            signature = 'verified';
        }
    }
    if (opts.scope !== undefined && p.scope !== scopeId(opts.scope))
        return bad('bad-scope');
    if (p.records.length > limits.maxRecords)
        return bad('too-many');
    let bytes = 0;
    for (let i = 0; i < p.records.length; i++) {
        const r = p.records[i];
        if (typeof r !== 'object' || r === null)
            return bad('bad-record', i + 1);
        if (typeof r.key !== 'string')
            return bad('bad-record', i + 1);
        try {
            validateKey(r.key);
        }
        catch {
            return bad('bad-record', i + 1);
        }
        if (typeof r.hash !== 'string' || !/^[0-9a-f]{64}$/.test(r.hash))
            return bad('bad-record', i + 1);
        if (typeof r.rev !== 'number' || !Number.isSafeInteger(r.rev) || r.rev < 1) {
            return bad('bad-record', i + 1);
        }
        if (typeof r.ts !== 'number' || !Number.isFinite(r.ts))
            return bad('bad-record', i + 1);
        let size;
        try {
            size = recordBytes(r.value);
        }
        catch {
            return bad('bad-record', i + 1);
        }
        if (size > limits.maxRecordBytes)
            return bad('too-large', i + 1);
        bytes += size;
        if (bytes > limits.maxBytes)
            return bad('too-large', i + 1);
    }
    const digest = await backupDigest(p.scope, p.records, p.v);
    if (digest !== p.digest)
        return bad('digest-mismatch');
    // 摘要对上了还要逐条重算 hash：攻击者改 value 后可以连 digest 一起重算，
    // 但**改不了**"value 与写入时 hash 的对应关系"——除非他连 hash 一起改。
    // 这一步挡的是"只改了 value 忘了改 hash"的损坏，以及跨版本口径漂移。
    const scope = parseScopeText(p.scope);
    if (scope === null)
        return bad('bad-scope');
    for (let i = 0; i < p.records.length; i++) {
        const r = p.records[i];
        const actual = await recordHash(scope, r.key, r.rev, r.value);
        if (actual !== r.hash)
            return bad('hash-mismatch', i + 1);
    }
    return Object.freeze({ ok: true, reason: 'none', at: 0, signature });
}
/** `tenant/ks/app/domain` → scope。非法返回 `null`。 */
function parseScopeText(s) {
    const parts = s.split('/');
    if (parts.length !== 4)
        return null;
    const [tenant, ks, app, domain] = parts;
    if (ks !== 'user' && ks !== 'sys')
        return null;
    return Object.freeze({ tenant, ks, app, domain });
}
/**
 * 恢复。
 *
 * 顺序：校验包 → 预检冲突（`reject` 模式下发现任一冲突即整包拒绝）→ 逐条写 → 逐条读回。
 */
export async function restoreBackup(engine, pkg, opts = {}) {
    const onExisting = opts.onExisting ?? 'reject';
    const dryRun = opts.dryRun === true;
    const v = await verifyBackup(pkg, {
        ...(opts.scope === undefined ? {} : { scope: opts.scope }),
        ...(opts.limits === undefined ? {} : { limits: opts.limits }),
        ...(opts.signer === undefined ? {} : { signer: opts.signer }),
        ...(opts.onUnsigned === undefined ? {} : { onUnsigned: opts.onUnsigned }),
    });
    if (!v.ok)
        throw storageErrorOf('STORAGE_RESTORE_REJECTED');
    const p = pkg;
    const scope = opts.scope ?? parseScopeText(p.scope);
    if (scope === null)
        throw storageErrorOf('STORAGE_RESTORE_REJECTED');
    // 预检：`reject` 模式下，任一目标已存在且内容不同就整包拒绝。
    // 内容相同视为"上次恢复过"，允许跳过（幂等）。
    const planned = [];
    for (const rec of p.records) {
        const cur = await engine.get(scope, rec.key);
        if (cur === null) {
            planned.push({ rec, skip: false, rev: null });
            continue;
        }
        if (canonicalJson(cur.value) === canonicalJson(rec.value)) {
            planned.push({ rec, skip: true, rev: cur.rev });
            continue;
        }
        if (onExisting === 'reject')
            throw storageErrorOf('STORAGE_RESTORE_REJECTED');
        if (onExisting === 'skip')
            planned.push({ rec, skip: true, rev: cur.rev });
        else
            planned.push({ rec, skip: false, rev: cur.rev });
    }
    let written = 0;
    let skipped = 0;
    let verified = 0;
    let failed = 0;
    let failedAt = 0;
    for (let i = 0; i < planned.length; i++) {
        const item = planned[i];
        if (item.skip) {
            skipped++;
            continue;
        }
        if (dryRun) {
            written++;
            continue;
        }
        try {
            // `expectedRev` 用读到的当前 rev 做 CAS：预检与写入之间若被别人改过，
            // 宁可失败也不覆盖——恢复不是"最后写入者赢"的场景。
            const putOpts = item.rev === null ? { expectedRev: 0 } : { expectedRev: item.rev };
            await engine.put(scope, item.rec.key, item.rec.value, putOpts);
            written++;
        }
        catch {
            failed++;
            failedAt = i + 1;
            break;
        }
        try {
            const back = await engine.get(scope, item.rec.key);
            if (back === null || canonicalJson(back.value) !== canonicalJson(item.rec.value)) {
                failed++;
                failedAt = i + 1;
                break;
            }
            verified++;
        }
        catch {
            failed++;
            failedAt = i + 1;
            break;
        }
    }
    return Object.freeze({
        ok: failed === 0,
        total: planned.length,
        written,
        skipped,
        verified,
        failed,
        failedAt,
        aborted: failed > 0,
        dryRun,
    });
}
