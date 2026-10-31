/**
 * SQLite Provider（服务端/原生侧真实持久化）。
 *
 * 用 Node 内置 `node:sqlite`（真实 SQLite，非 mock）。定位是「本地持久化适配器」：
 * 浏览器里用 IndexedDB，Node/Worker/桌面原生侧用 SQLite，两者遵循**同一个**
 * `StorageEngine` 契约（8 方法 + 能力声明），上层网关零改动即可切换。
 *
 * # 为什么不在浏览器里用
 *
 * `node:sqlite` 是 Node 内建模块，浏览器没有。浏览器侧走 `engines/idb.ts`。
 * 强行把 SQLite 编译进浏览器（sql.js/wasm）会引入第二套持久化实现，违背
 * 「不擅自引入第二套存储引擎」。故本适配器明确标注 `environment: 'node'`。
 *
 * # 语义与 memory 引擎逐条对齐
 *
 * rev 递增、expectedRev 冲突、软删不可见、purge 计数、usage 含软删、commit 原子，
 * 全部复用 `computeNextRecord` 与相同规则，避免「memory 这么做、sqlite 那么做」。
 */
import { STORAGE_OPS } from '../contract.js';
import { scopeId } from '../canonical.js';
import { storageErrorOf, storageErrorWithRev } from '../errors.js';
import { computeNextRecord } from './record.js';
function rowToRecord(r) {
    return Object.freeze({
        value: JSON.parse(r.value),
        rev: r.rev,
        bytes: r.bytes,
        hash: r.hash,
        ts: r.ts,
        deleted: r.deleted !== 0,
    });
}
/**
 * 打开 SQLite 引擎。真实建表 + WAL。失败抛 `STORAGE_UNAVAILABLE`。
 */
export async function createSqliteEngine(deps = {}) {
    const path = deps.path ?? ':memory:';
    const now = deps.now ?? (() => Date.now());
    // 动态、变量化 specifier：既避开 tsc 对 node:sqlite 的静态解析，也保证浏览器
    // 打包时不会把它当作可解析模块（本引擎只在 node 侧被 open）。
    const spec = 'node:sqlite';
    let DatabaseSync;
    try {
        const mod = (await import(spec));
        DatabaseSync = mod.DatabaseSync;
    }
    catch {
        throw storageErrorOf('STORAGE_UNAVAILABLE');
    }
    let db;
    try {
        db = new DatabaseSync(path);
        db.exec(`
      CREATE TABLE IF NOT EXISTS records (
        scope_id TEXT NOT NULL,
        key      TEXT NOT NULL,
        value    TEXT NOT NULL,
        rev      INTEGER NOT NULL,
        bytes    INTEGER NOT NULL,
        hash     TEXT NOT NULL,
        ts       INTEGER NOT NULL,
        deleted  INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (scope_id, key)
      );
    `);
        db.exec('CREATE INDEX IF NOT EXISTS idx_scope ON records(scope_id, deleted, key);');
        if (path !== ':memory:') {
            try {
                db.exec('PRAGMA journal_mode=WAL;');
                db.exec('PRAGMA synchronous=NORMAL;');
            }
            catch {
                // 某些文件系统不支持 WAL，退回默认日志模式即可，不阻断打开。
            }
        }
    }
    catch {
        throw storageErrorOf('STORAGE_UNAVAILABLE');
    }
    const selOne = db.prepare('SELECT * FROM records WHERE scope_id=? AND key=?');
    const delOne = db.prepare('DELETE FROM records WHERE scope_id=? AND key=?');
    const upsert = db.prepare(`
    INSERT INTO records (scope_id,key,value,rev,bytes,hash,ts,deleted)
    VALUES (?,?,?,?,?,?,?,?)
    ON CONFLICT(scope_id,key) DO UPDATE SET
      value=excluded.value, rev=excluded.rev, bytes=excluded.bytes,
      hash=excluded.hash, ts=excluded.ts, deleted=excluded.deleted
  `);
    const selScope = db.prepare('SELECT * FROM records WHERE scope_id=? AND deleted=0 ORDER BY key');
    const countScope = db.prepare('SELECT COUNT(*) AS n FROM records WHERE scope_id=?');
    const sumBytes = db.prepare('SELECT COALESCE(SUM(bytes),0) AS s FROM records WHERE scope_id=?');
    function getRaw(sid, key) {
        const r = selOne.get(sid, key);
        return r ?? null;
    }
    function writeRow(sid, key, rec) {
        upsert.run(sid, key, JSON.stringify(rec.value), rec.rev, rec.bytes, rec.hash, rec.ts, rec.deleted ? 1 : 0);
    }
    const engine = {
        kind: 'sqlite',
        path,
        capabilities() {
            return { ops: [...STORAGE_OPS], transactions: true, ttl: false, orderedList: true };
        },
        async get(scope, key) {
            const row = getRaw(scopeId(scope), key);
            if (row === null || row.deleted !== 0)
                return null;
            return rowToRecord(row);
        },
        async put(scope, key, value, opts = {}) {
            const sid = scopeId(scope);
            const row = getRaw(sid, key);
            const prev = row === null ? null : rowToRecord(row);
            const next = await computeNextRecord(scope, key, value, prev, opts, now);
            writeRow(sid, key, next);
            return next;
        },
        async del(scope, key, expectedRev) {
            const sid = scopeId(scope);
            const row = getRaw(sid, key);
            if (row === null)
                return { removed: false, bytes: 0 };
            if (expectedRev !== undefined && row.rev !== expectedRev) {
                throw storageErrorWithRev('STORAGE_CONFLICT', row.rev);
            }
            delOne.run(sid, key);
            return { removed: true, bytes: row.bytes };
        },
        async list(scope, prefix = '') {
            const rows = selScope.all(scopeId(scope));
            const out = rows
                .map((r) => r.key)
                .filter((k) => prefix === '' || k.startsWith(prefix));
            out.sort();
            return out;
        },
        async scan(scope, prefix = '', limit = 1000) {
            const rows = selScope.all(scopeId(scope));
            const out = [];
            for (const r of rows) {
                if (prefix !== '' && !r.key.startsWith(prefix))
                    continue;
                out.push({ key: r.key, rec: rowToRecord(r) });
                if (out.length >= limit)
                    break;
            }
            out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
            return out;
        },
        async purge(scope) {
            const sid = scopeId(scope);
            const n = Number(countScope.get(sid).n);
            db.prepare('DELETE FROM records WHERE scope_id=?').run(sid);
            return n;
        },
        async usage(scope) {
            const s = Number(sumBytes.get(scopeId(scope)).s);
            return s;
        },
        async commit(mutations) {
            if (mutations.length === 0)
                return Object.freeze([]);
            const results = [];
            // 原生事务：任一步失败 ROLLBACK，库保持原样。
            db.exec('BEGIN');
            try {
                for (const m of mutations) {
                    const sid = scopeId(m.scope);
                    const row = getRaw(sid, m.key);
                    const base = row === null ? null : rowToRecord(row);
                    if (m.op === 'put') {
                        const next = await computeNextRecord(m.scope, m.key, m.value, base, m.opts ?? {}, now);
                        writeRow(sid, m.key, next);
                        results.push(next);
                    }
                    else {
                        if (base !== null) {
                            const expected = m.opts?.expectedRev;
                            if (expected !== undefined && expected !== 0 && base.rev !== expected) {
                                throw storageErrorWithRev('STORAGE_CONFLICT', base.rev);
                            }
                            delOne.run(sid, m.key);
                        }
                    }
                }
                db.exec('COMMIT');
                return Object.freeze(results);
            }
            catch (e) {
                db.exec('ROLLBACK');
                throw e;
            }
        },
        async close() {
            db.close();
        },
    };
    return engine;
}
