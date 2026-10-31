/**
 * Provider 注册表：统一「能力声明 + 健康检查 + 生命周期 + 故障切换」。
 *
 * 之前 `stack.ts` 直接 `new` 一个引擎，换后端要改装配代码，且没有健康探测、
 * 没有故障切换、没有统一的能力前置拒绝。本文件把「选哪个后端、它能不能用、
 * 挂了换谁」收进一处，让装配代码只依赖接口。
 *
 * 不改变任何既有引擎实现；只是在其上加一层治理。生产接线仍需审批（A-2）。
 */
import { isStorageError, normalizeError, storageErrorOf } from '../errors.js';
import { missingCapabilities, satisfies } from './capabilities.js';
/** 健康探测用的只读 scope（不会写库）。 */
const PROBE_SCOPE = Object.freeze({
    tenant: 'sys',
    ks: 'sys',
    app: 'probe',
    domain: 'probe',
});
/** 创建注册表。可传入初始描述列表。 */
export function createProviderRegistry(initial = []) {
    const descriptors = new Map();
    const engines = new Map();
    const healthMap = new Map();
    for (const d of initial)
        descriptors.set(d.kind, d);
    function requireDescriptor(kind) {
        const d = descriptors.get(kind);
        if (d === undefined)
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        return d;
    }
    async function probe(kind, engine) {
        const t0 = nowMs();
        try {
            // 只读探测：健康引擎对不存在的键返回 null，不会写库。
            await engine.get(PROBE_SCOPE, '__health__');
            const h = { ok: true, kind, latencyMs: Math.max(0, nowMs() - t0) };
            healthMap.set(kind, h);
            return h;
        }
        catch (e) {
            const h = {
                ok: false,
                kind,
                latencyMs: Math.max(0, nowMs() - t0),
                error: isStorageError(e) ? e : normalizeError(e),
            };
            healthMap.set(kind, h);
            return h;
        }
    }
    const registry = {
        register(d) {
            descriptors.set(d.kind, d);
        },
        kinds() {
            return [...descriptors.keys()];
        },
        info() {
            return [...descriptors.values()].map((d) => {
                const engine = engines.get(d.kind);
                return {
                    kind: d.kind,
                    label: d.label,
                    environment: d.environment,
                    capabilities: engine ? engine.capabilities() : null,
                    opened: engine !== undefined,
                    lastHealth: healthMap.get(d.kind) ?? null,
                };
            });
        },
        async open(kind) {
            const d = requireDescriptor(kind);
            let engine = engines.get(kind);
            if (engine === undefined) {
                engine = await d.open();
                engines.set(kind, engine);
            }
            const health = await probe(kind, engine);
            return { descriptor: d, engine, health };
        },
        async health(kind) {
            const d = requireDescriptor(kind);
            let engine = engines.get(kind);
            if (engine === undefined) {
                engine = await d.open();
                engines.set(kind, engine);
            }
            return probe(kind, engine);
        },
        async select(req, preferred = []) {
            const order = [...preferred.filter((k) => descriptors.has(k)), ...descriptors.keys()];
            const seen = new Set();
            const reasons = [];
            for (const kind of order) {
                if (seen.has(kind))
                    continue;
                seen.add(kind);
                let opened;
                try {
                    opened = await registry.open(kind);
                }
                catch (e) {
                    reasons.push(`${kind}:open-failed`);
                    continue;
                }
                if (!opened.health.ok) {
                    reasons.push(`${kind}:unhealthy`);
                    continue;
                }
                const caps = opened.engine.capabilities();
                if (!satisfies(caps, req)) {
                    reasons.push(`${kind}:missing(${missingCapabilities(caps, req).join('|')})`);
                    continue;
                }
                return opened;
            }
            // 所有候选都不满足：归一为 UNAVAILABLE（不暴露内部 kind 细节给调用方）。
            void reasons;
            throw storageErrorOf('STORAGE_UNAVAILABLE');
        },
        async closeAll() {
            for (const engine of engines.values()) {
                try {
                    if (engine.close)
                        await engine.close();
                }
                catch {
                    // 关闭失败不阻断其它引擎关闭；资源释放是尽力而为。
                }
            }
            engines.clear();
            healthMap.clear();
        },
    };
    return registry;
}
function nowMs() {
    return typeof performance !== 'undefined' && typeof performance.now === 'function'
        ? performance.now()
        : Date.now();
}
