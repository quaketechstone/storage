/**
 * IndexedDB 连接层：**独立数据库**，不复用母体的 `gw_convos`。
 *
 * # 为什么不复用母体库
 *
 * 三条路都试过，只有第三条成立：
 *
 * | 方案 | 问题 |
 * |---|---|
 * | 在 `gw_convos` 里加 store | 必须升 `DB_VERSION`（`api/idb.ts:14`），属未批准变更；且升级不可逆 |
 * | 复用 `config`/`sec` 等既有 store 存 `s1/` 前缀键 | 与母体数据混住：`idbList('config')` 会列出我们的键，母体的 `store.rs` 也可能遍历到；污染面不可控 |
 * | **独立库 `quake_s1`** | 母体库与 `DB_VERSION` 一字不改；回滚 = `deleteDatabase('quake_s1')`，母体数据零影响 |
 *
 * 独立库的代价是「数据不在同一个库里，无法跨库事务」。本层接受这个代价：
 * 存储模块的事务语义限定在自身库内，与母体的写入从不要求原子（两者是不同 owner
 * 的数据，不存在"要么都成功"的业务含义）。
 *
 * # 事务与 `await`
 *
 * IDB 事务在**没有 pending 请求**时自动提交。`await` 一个 IDB 请求的 Promise 是安全的
 * （微任务在同一 task 内继续），但 `await` 一个**非 IDB** 的 Promise（例如
 * `crypto.subtle.digest`）会把控制权交回事件循环，事务当场提交。
 *
 * 因此本层的铁律是：**事务内只 await IDB 请求**。摘要计算一律在事务外完成，
 * 写入用「读 prev → 算 hash → 写前 CAS 复核」两步，见 `idb.ts` 的 `prepare`。
 */
/** 独立库名。与母体 `gw_convos` 无任何关系。 */
import { storageErrorOf } from '../errors.js';
export const STORAGE_DB_NAME = 'quake_s1';
/** 本库版本。与母体 `api/idb.ts:14` 的 `DB_VERSION` **不是**同一个东西。 */
export const STORAGE_DB_VERSION = 1;
/** 记录表。`keyPath = 'pk'`（物理键）。 */
export const STORE_RECORDS = 'records';
/** 元数据表。`keyPath = 'k'`。存 KEK 句柄、撤销代际、迁移检查点。 */
export const STORE_META = 'meta';
const cache = new Map();
/** 把 IDB 异常映射成存储错误码。**不透传** `DOMException.message`（含 store 名）。 */
export function idbErrorCode(e) {
    const name = e?.name ?? '';
    switch (name) {
        case 'QuotaExceededError':
            return 'STORAGE_QUOTA_EXCEEDED';
        case 'VersionError':
            return 'STORAGE_VERSION_MISMATCH';
        case 'InvalidStateError':
            return 'STORAGE_UNAVAILABLE';
        case 'AbortError':
        case 'TransactionInactiveError':
            return 'STORAGE_TX_ABORTED';
        case 'DataCloneError':
            return 'STORAGE_CORRUPT';
        case 'UnknownError':
            return 'STORAGE_UNAVAILABLE';
        default:
            return 'STORAGE_UNAVAILABLE';
    }
}
/** 打开（或复用）存储库。同一 `name` 只打开一次。 */
export function openStorageDb(opts = {}) {
    const name = opts.name ?? STORAGE_DB_NAME;
    const version = opts.version ?? STORAGE_DB_VERSION;
    const key = `${name}@${version}`;
    const hit = cache.get(key);
    if (hit !== undefined)
        return hit;
    const factory = opts.factory ?? globalThis.indexedDB;
    if (factory === undefined) {
        return Promise.reject(storageErrorOf('STORAGE_UNAVAILABLE'));
    }
    const p = new Promise((resolve, reject) => {
        let req;
        try {
            req = factory.open(name, version);
        }
        catch (e) {
            reject(e);
            return;
        }
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE_RECORDS)) {
                // 只用一个 store：物理键自带 scope 前缀，`purge(scope)` 靠键区间而不是
                // "按 scope 分桶"。分桶方案里桶名由 scope 拼出，拼错一次就是清空别人的数据。
                db.createObjectStore(STORE_RECORDS, { keyPath: 'pk' });
            }
            if (!db.objectStoreNames.contains(STORE_META)) {
                db.createObjectStore(STORE_META, { keyPath: 'k' });
            }
        };
        req.onsuccess = () => {
            const db = req.result;
            db.onversionchange = () => {
                // 别的标签页要升级：立刻关掉本连接，否则对方会一直 blocked。
                db.close();
                cache.delete(key);
                opts.onVersionChange?.();
            };
            resolve(db);
        };
        req.onerror = () => {
            const err = req.error ?? new Error('IndexedDB 打开失败');
            // 版本不匹配是确定性的：缓存一个失败的 Promise 会让本会话永久不可用，
            // 所以只在非版本错误时清缓存。
            if (err.name !== 'VersionError')
                cache.delete(key);
            reject(err);
        };
        req.onblocked = () => {
            cache.delete(key);
            reject(storageErrorOf('STORAGE_BLOCKED'));
        };
    });
    cache.set(key, p);
    // 失败的 Promise 不留在缓存里（`onerror` 里已删，这里兜住同步抛出的分支）。
    void p.catch(() => cache.delete(key));
    return p;
}
/** 关闭并移出缓存（测试与回滚用）。 */
export async function closeStorageDb(name = STORAGE_DB_NAME) {
    for (const [key, p] of [...cache]) {
        if (!key.startsWith(`${name}@`))
            continue;
        cache.delete(key);
        try {
            ;
            (await p).close();
        }
        catch {
            /* 打开就失败的连接无需关闭 */
        }
    }
}
/** 删除整个库。**回滚**的唯一动作；母体库不受影响。 */
export function deleteStorageDb(name = STORAGE_DB_NAME) {
    const factory = globalThis.indexedDB;
    if (factory === undefined)
        return Promise.resolve();
    cache.delete(`${name}@${STORAGE_DB_VERSION}`);
    return new Promise((resolve, reject) => {
        const req = factory.deleteDatabase(name);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error ?? new Error('deleteDatabase 失败'));
        req.onblocked = () => reject(new Error('STORAGE_BLOCKED: 删除被占用'));
    });
}
/**
 * 单事务执行。
 *
 * `fn` 内**只能** await IDB 请求。任何非 IDB 的 await 都会让事务提前提交，
 * 后续请求抛 `TransactionInactiveError`——本层把它映射成 `STORAGE_TX_ABORTED`，
 * 不伪装成成功。
 */
export async function idbRun(db, stores, mode, fn) {
    const names = typeof stores === 'string' ? [stores] : [...stores];
    let tx;
    try {
        tx = db.transaction(names, mode);
    }
    catch (e) {
        throw e;
    }
    return await new Promise((resolve, reject) => {
        let out;
        let settled = false;
        const fail = (e) => {
            if (settled)
                return;
            settled = true;
            reject(e);
        };
        tx.onabort = () => fail(tx.error ?? new Error('STORAGE_TX_ABORTED'));
        tx.onerror = () => fail(tx.error ?? new Error('STORAGE_UNAVAILABLE'));
        tx.oncomplete = () => {
            if (settled)
                return;
            settled = true;
            resolve(out);
        };
        Promise.resolve()
            .then(() => fn(tx))
            .then((v) => {
            out = v;
        })
            .catch((e) => {
            try {
                tx.abort();
            }
            catch {
                /* 事务可能已结束 */
            }
            fail(e);
        });
    });
}
/** 请求包装。 */
export function req(r) {
    return new Promise((resolve, reject) => {
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error ?? new Error('IDB 请求失败'));
    });
}
/**
 * 请求"持久化存储"。
 *
 * 不请求的后果是真实的：浏览器在磁盘压力下会清掉"best-effort"来源的 IndexedDB，
 * 而用户看到的是"数据莫名消失"。请求了也不保证获批（Firefox 会弹窗，Safari 按
 * 使用习惯自动决定），因此返回值必须如实反映结果，**不能**默认当成成功。
 *
 * 这是"尽力而为"的加固，不是数据安全的保证——真正的保证是备份。
 */
export async function requestPersistence() {
    const s = globalThis.navigator?.storage;
    if (s === undefined || typeof s.persist !== 'function')
        return 'unsupported';
    try {
        return (await s.persist()) ? 'granted' : 'denied';
    }
    catch {
        return 'error';
    }
}
/** 已持久化？（不触发请求） */
export async function isPersisted() {
    const s = globalThis.navigator?.storage;
    if (s === undefined || typeof s.persisted !== 'function')
        return null;
    try {
        return await s.persisted();
    }
    catch {
        return null;
    }
}
/** 用量估算。环境不支持返回 `null`。 */
export async function storageEstimate() {
    const s = globalThis.navigator?.storage;
    if (s === undefined || typeof s.estimate !== 'function')
        return null;
    try {
        const e = await s.estimate();
        return { usage: e.usage ?? 0, quota: e.quota ?? 0 };
    }
    catch {
        return null;
    }
}
