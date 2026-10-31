/**
 * 通用故障注入装饰器：包住**任意**引擎，在方法执行前按规则抛错。
 *
 * 与 `engines/memory.ts` 内建的 `FaultInjector` 不同，本装饰器不依赖具体引擎实现，
 * 因此 memory / idb / sqlite / remote 都能用同一套注入规则做「失败行为」验证
 * （例如：put 抛 UNAVAILABLE 时，网关是否零写入、是否不越权）。
 *
 * 生产代码不装配本装饰器；它只用于测试与工作台的「故障注入」面板。
 */
import { storageErrorOf } from '../errors.js';
const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
/** 创建故障控制器。 */
export function createFaultController() {
    const rules = new Map();
    const ctl = {
        arm(method, times = 1, code = 'STORAGE_UNAVAILABLE', delayMs = 0) {
            rules.set(method, { remaining: Math.max(0, times), code, delayMs });
        },
        clear() {
            rules.clear();
        },
        remaining(method) {
            return rules.get(method)?.remaining ?? 0;
        },
        snapshot() {
            return [...rules.entries()].map(([method, r]) => ({
                method,
                remaining: r.remaining,
                code: r.code,
            }));
        },
        async trip(method) {
            const r = rules.get(method);
            if (r === undefined || r.remaining <= 0)
                return;
            r.remaining--;
            if (r.remaining === 0)
                rules.delete(method);
            if (r.delayMs > 0)
                await sleep(r.delayMs);
            throw storageErrorOf(r.code);
        },
    };
    return ctl;
}
/** 包装引擎。`ctl` 缺省新建一个（可通过 `engine.faults` 访问）。 */
export function withFaults(engine, ctl = createFaultController()) {
    const internal = ctl;
    const wrapped = {
        kind: engine.kind,
        faults: ctl,
        capabilities() {
            return engine.capabilities();
        },
        async get(scope, key) {
            await internal.trip('get');
            return engine.get(scope, key);
        },
        async put(scope, key, value, opts) {
            await internal.trip('put');
            return engine.put(scope, key, value, opts);
        },
        async del(scope, key, expectedRev) {
            await internal.trip('del');
            return engine.del(scope, key, expectedRev);
        },
        async list(scope, prefix) {
            await internal.trip('list');
            return engine.list(scope, prefix);
        },
        async scan(scope, prefix, limit) {
            await internal.trip('scan');
            return engine.scan(scope, prefix, limit);
        },
        async purge(scope) {
            await internal.trip('purge');
            return engine.purge(scope);
        },
        async usage(scope) {
            await internal.trip('usage');
            return engine.usage(scope);
        },
        async commit(mutations) {
            await internal.trip('commit');
            return engine.commit(mutations);
        },
        async close() {
            if (engine.close)
                await engine.close();
        },
    };
    return wrapped;
}
