/**
 * 旧库只读读取器（独立文件，便于边界自检精确放行）。
 *
 * # 为什么单独一个文件
 *
 * 边界自检（`__tests__/boundary.mjs`）禁止存储层直接碰 `indexedDB`——持久化必须
 * 经 S2 引擎。迁移是唯一的例外：旧库（`gw_convos`）的 schema 不属于本模块的引擎
 * 接口，只能按原始 IDB 读。
 *
 * 把这份例外**收进一个文件**，白名单才能写得精确：
 * "`migrate-legacy.ts` 可以用 indexedDB，但它不许开 `readwrite` 事务、不许写"。
 * 若留在 `migrate.ts` 里，同文件还要写自己的检查点库，那条"不许写"就无法成立。
 *
 * # 只读是怎么保证的
 *
 * 1. 类型层：`LegacyReader` 只有 `stores`/`keys`/`get`/`close`，没有写方法；
 * 2. 事务层：本文件所有 `db.transaction(...)` 的模式参数都是 `'readonly'`；
 * 3. 脚本层：`boundary.mjs` 对该文件断言不含 `'readwrite'` 与写调用。
 */
import { storageErrorOf } from './errors.js';
import { req } from './engines/idb-db.js';
// ---------------------------------------------------------------------------
// 源库读取
// ---------------------------------------------------------------------------
/** 旧库名（母体 `api/idb.ts:12`）。 */
export const LEGACY_DB_NAME = 'gw_convos';
function keyToString(k) {
    return Array.isArray(k) ? `${k[0]}#${k[1]}` : String(k);
}
export function prefixOf(key) {
    const i = key.indexOf('#');
    if (i > 0)
        return key.slice(0, i);
    const j = key.indexOf(':');
    if (j > 0)
        return key.slice(0, j);
    return key.length > 12 ? `${key.slice(0, 12)}…` : key;
}
/**
 * 打开旧库，**只读**。
 *
 * 两个陷阱：
 * 1. `indexedDB.open(name)` 不带版本会以当前版本打开；若库不存在，浏览器会**新建**
 *    一个空库。因此先查 `databases()`；不支持时用"打开后 store 数为 0 ⇒ 刚建的"
 *    判定，并把它删掉，避免给用户凭空造一个空库。
 * 2. 打开时不能触发升级：不传版本就不会有 `upgradeneeded`。
 */
export async function createLegacyReader(opts = {}) {
    const name = opts.dbName ?? LEGACY_DB_NAME;
    const factory = opts.factory ?? globalThis.indexedDB;
    if (factory === undefined)
        throw storageErrorOf('STORAGE_UNAVAILABLE');
    const lister = factory.databases;
    if (typeof lister === 'function') {
        const list = await lister.call(factory);
        if (!list.some((d) => d.name === name)) {
            return {
                async stores() {
                    return [];
                },
                async keys() {
                    return [];
                },
                async get() {
                    return null;
                },
                close() {
                    /* 未打开 */
                },
            };
        }
    }
    const db = await new Promise((resolve, reject) => {
        const r = factory.open(name);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error ?? new Error('open legacy failed'));
        r.onblocked = () => reject(new Error('STORAGE_BLOCKED'));
    });
    // 兜底：`databases()` 不可用时，空库说明是刚才新建的。
    if (db.objectStoreNames.length === 0) {
        db.close();
        await new Promise((resolve) => {
            const r = factory.deleteDatabase(name);
            r.onsuccess = () => resolve();
            r.onerror = () => resolve();
            r.onblocked = () => resolve();
        });
        return {
            async stores() {
                return [];
            },
            async keys() {
                return [];
            },
            async get() {
                return null;
            },
            close() {
                /* 已删除 */
            },
        };
    }
    async function keysOf(store) {
        if (!db.objectStoreNames.contains(store))
            return [];
        const tx = db.transaction([store], 'readonly');
        const all = await req(tx.objectStore(store).getAllKeys());
        return all.map(keyToString);
    }
    return {
        async stores() {
            return [...db.objectStoreNames];
        },
        keys: keysOf,
        async get(store, key) {
            if (!db.objectStoreNames.contains(store))
                return null;
            const tx = db.transaction([store], 'readonly');
            const os = tx.objectStore(store);
            // `msgs` 是复合主键：必须拆回 `[convoId, idx]`，否则查不到。
            const q = store === 'msgs' ? splitComposite(key) : key;
            const rec = await req(os.get(q));
            if (rec === undefined)
                return null;
            return rec;
        },
        close() {
            db.close();
        },
    };
}
/** `convoId#idx` → `[convoId, idx]`（从右侧切分，id 里允许出现 `#`）。 */
export function splitComposite(key) {
    const i = key.lastIndexOf('#');
    if (i < 0)
        return [key, 0];
    return [key.slice(0, i), Number(key.slice(i + 1)) || 0];
}
