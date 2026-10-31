/**
 * 内置 Provider 工厂。
 *
 * 每个 `open` 都是**动态 import**：注册时不加载引擎，只有真正 `open(kind)` 时才
 * 载入对应实现。这样浏览器端不会因为注册表里列了 sqlite 就把 `node:sqlite` 打进包，
 * 反之亦然。
 */
/** 内存引擎（任何环境）。 */
export function memoryProvider() {
    return {
        kind: 'memory',
        label: 'In-Memory',
        environment: 'any',
        open: async () => (await import('../engines/memory.js')).createMemoryEngine(),
    };
}
/** IndexedDB 引擎（浏览器）。 */
export function idbProvider(opts = {}) {
    return {
        kind: 'idb',
        label: 'IndexedDB',
        environment: 'browser',
        open: async () => (await import('../engines/idb.js')).createIdbEngine(opts),
    };
}
/** SQLite 引擎（Node / 原生，`node:sqlite`）。 */
export function sqliteProvider(opts = {}) {
    return {
        kind: 'sqlite',
        label: 'SQLite (node:sqlite)',
        environment: 'node',
        open: async () => (await import('../engines/sqlite.js')).createSqliteEngine(opts),
    };
}
/** 远端 HTTP 引擎。 */
export function remoteProvider(opts) {
    return {
        kind: 'remote',
        label: 'Remote HTTP',
        environment: 'any',
        open: async () => (await import('../engines/remote.js')).createRemoteEngine(opts),
    };
}
