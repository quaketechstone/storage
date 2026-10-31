/**
 * 密钥生命周期：创建 / 解锁 / 轮换 / 销毁。
 *
 * # 两种模式，安全属性完全不同
 *
 * | | `device` | `passphrase` |
 * |---|---|---|
 * | KEK 从哪来 | 浏览器生成的随机 256 位 | PBKDF2(口令, salt, 310k) |
 * | 存在哪 | IndexedDB（`CryptoKey` 对象） | **不存**，只存 salt 与校验块 |
 * | 设备丢失/磁盘被拷 | 数据可解（KEK 与密文同库） | 数据不可解（除非口令弱） |
 * | 刷新后是否需要输入 | 否 | 是（`locked`） |
 * | 能防同源 XSS | **不能** | **不能**（口令在页面内存里） |
 *
 * 结论必须说清：`device` 模式**不是**"设备丢失防护"，它只是把明文从库里挪走，
 * 让"只拿到数据文件、没拿到密钥槽"的场景失效。真正的设备丢失防护只有
 * `passphrase` 模式，且强度完全取决于口令强度与 KDF 参数。
 *
 * # 不可导出（`extractable: false`）到底挡什么
 *
 * 挡的是"把密钥读出来带走"：`crypto.subtle.exportKey` 会失败，所以一段注入脚本
 * 无法把 KEK 原样回传。它**不挡**"用这个 KEK 就地解密再回传明文"——同源脚本能
 * 调 `decrypt`。因此不可导出是**降低泄露面**，不是"防住已控制同源环境的攻击者"。
 * 这句话必须写在文档里，否则就是拿文档声明代替安全控制（U-2）。
 *
 * # 轮换的代价
 *
 * 只重包 DEK，不动 payload（见 `envelope.ts`）。因此 `rotate()` 本身是 O(1)，
 * 重包全部记录是 `rewrapScope()` 的 O(n)，且可分批、可中断、可重入（幂等：
 * 已用新 KEK 包裹的记录再次重包会失败并跳过，见实现）。
 */
import { storageErrorOf } from '../errors.js';
import { STORE_META, idbRun, openStorageDb, req } from '../engines/idb-db.js';
import { b64ToBytes, bytesToB64 } from './envelope.js';
/** 内存实现。测试用；进程结束即丢失，**不是**持久化方案。 */
export function createMemoryKeyStore() {
    const map = new Map();
    return {
        async get(name) {
            return map.has(name) ? map.get(name) : null;
        },
        async put(name, value) {
            map.set(name, value);
        },
        async del(name) {
            map.delete(name);
        },
    };
}
/**
 * IndexedDB 实现：复用存储库的 `meta` 表。
 *
 * `CryptoKey` 是结构化克隆对象，浏览器允许直接存进 IDB 且保持不可导出属性——
 * 存进去的不是原始字节，而是"只有这个源能用的句柄"。这是本方案能成立的前提。
 */
export function createIdbKeyStore(opts = {}) {
    return {
        async get(name) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            const row = await idbRun(db, STORE_META, 'readonly', async (tx) => {
                const got = (await req(tx.objectStore(STORE_META).get(name)));
                return got ?? null;
            });
            return row === null ? null : row.v;
        },
        async put(name, value) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            await idbRun(db, STORE_META, 'readwrite', async (tx) => {
                await req(tx.objectStore(STORE_META).put({ k: name, v: value }));
            });
        },
        async del(name) {
            const db = await openStorageDb(opts.name === undefined ? {} : { name: opts.name });
            await idbRun(db, STORE_META, 'readwrite', async (tx) => {
                await req(tx.objectStore(STORE_META).delete(name));
            });
        },
    };
}
const SLOT_KEK = 'kek';
const SLOT_META = 'kek.meta';
const SLOT_PROBE = 'kek.probe';
/** 轮换中的旧 KEK（`device` 模式）。 */
const SLOT_PREV = 'kek.prev';
/** 轮换中的新 KEK（`device` 模式）。`finalizeRotation()` 才把它提升为 `kek`。 */
const SLOT_NEXT = 'kek.next';
/** 默认 PBKDF2 迭代数（OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限）。 */
export const DEFAULT_ITERATIONS = 310_000;
/**
 * 导入恢复材料时允许的最低迭代数。
 *
 * 材料是外部输入：把它改成 `iterations: 1` 会让后续口令校验在毫秒内可爆破。
 * 下限挡的就是这个降级，而不是"用户想用低参数"——那种需求不该由恢复路径满足。
 */
export const MIN_RESTORE_ITERATIONS = 100_000;
function subtle() {
    const s = globalThis.crypto?.subtle;
    if (s === undefined)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    return s;
}
function randomBytes(n) {
    const c = globalThis.crypto;
    if (c?.getRandomValues === undefined)
        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
    const buf = new Uint8Array(n);
    c.getRandomValues(buf);
    return buf;
}
const encoder = new TextEncoder();
/** PBKDF2 → AES-KW 密钥。 */
async function deriveKek(passphrase, salt, iterations) {
    const s = subtle();
    const base = await s.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return s.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
/** 新随机 KEK。不可导出。 */
function newDeviceKek() {
    return subtle().generateKey({ name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
/** 包裹一个随机探针，作为口令正确性的校验块。 */
async function makeCheck(kek) {
    const probe = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, [
        'encrypt',
        'decrypt',
    ]);
    const wrapped = await subtle().wrapKey('raw', probe, kek, { name: 'AES-KW' });
    return bytesToB64(new Uint8Array(wrapped));
}
/** 校验块能否被该 KEK 打开。 */
async function checkOk(kek, check) {
    const bytes = b64ToBytes(check);
    if (bytes === null)
        return false;
    try {
        await subtle().unwrapKey('raw', bytes, kek, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        return true;
    }
    catch {
        return false;
    }
}
/** 创建密钥环。 */
export function createKeyring(deps) {
    const { store } = deps;
    const now = deps.now ?? (() => Date.now());
    const iterations = deps.iterations ?? DEFAULT_ITERATIONS;
    let held = null;
    let prev = null;
    let meta = null;
    /**
     * 读 meta。`force = true` 时**丢弃内存缓存**重新读槽。
     *
     * 为什么要有 force：同一 origin 下多个标签页各持一个 Keyring 实例，内存缓存会
     * 让"别的标签页已经轮换"这件事在本实例里不可见。`rotate()` 的 pending 检查
     * （478 行）因此形同虚设，第二个标签页会覆写 `kek.prev`/`kek.next` 槽，把第一个
     * 标签页正在用的新 KEK 顶掉——已重包的记录随之永久不可读。
     * 轮换与收尾是**状态迁移**，必须先看到最新状态；读路径可以用缓存（省一次 IDB 读）。
     */
    async function loadMeta(force = false) {
        if (meta !== null && !force)
            return meta;
        meta = null;
        const raw = await store.get(SLOT_META);
        if (raw === null || typeof raw !== 'object')
            return null;
        const m = raw;
        if (m.mode !== 'device' && m.mode !== 'passphrase')
            return null;
        if (typeof m.version !== 'number')
            return null;
        const p = m.pending;
        const pending = typeof p === 'object' &&
            p !== null &&
            typeof p.from === 'number' &&
            typeof p.to === 'number' &&
            typeof p.startedAt === 'number'
            ? Object.freeze({
                from: p.from,
                to: p.to,
                startedAt: p.startedAt,
                prevSalt: typeof p.prevSalt === 'string' ? p.prevSalt : null,
                prevCheck: typeof p.prevCheck === 'string' ? p.prevCheck : null,
            })
            : null;
        meta = Object.freeze({
            mode: m.mode,
            version: m.version,
            createdAt: typeof m.createdAt === 'number' ? m.createdAt : 0,
            rotatedAt: typeof m.rotatedAt === 'number' ? m.rotatedAt : null,
            salt: typeof m.salt === 'string' ? m.salt : null,
            check: typeof m.check === 'string' ? m.check : null,
            iterations: typeof m.iterations === 'number' ? m.iterations : iterations,
            pending,
        });
        return meta;
    }
    const ring = {
        async status() {
            const m = await loadMeta();
            if (m === null) {
                return {
                    state: 'absent',
                    mode: 'device',
                    version: 0,
                    createdAt: null,
                    rotatedAt: null,
                    rotationPending: false,
                };
            }
            const base = {
                mode: m.mode,
                version: m.version,
                createdAt: m.createdAt,
                rotatedAt: m.rotatedAt,
                rotationPending: m.pending !== null,
            };
            if (held !== null)
                return { state: 'ready', ...base };
            // `device` 模式的 KEK 存在槽里，能直接取出来，因此"未持有"不等于"锁着"。
            if (m.mode === 'device')
                return { state: 'ready', ...base };
            return { state: 'locked', ...base };
        },
        async create(opts = {}) {
            const existing = await loadMeta();
            if (existing !== null)
                throw storageErrorOf('STORAGE_DENIED');
            const passphrase = opts.passphrase;
            if (passphrase !== undefined) {
                if (passphrase.length < 8)
                    throw storageErrorOf('STORAGE_DENIED');
                const salt = randomBytes(16);
                const kek = await deriveKek(passphrase, salt, iterations);
                const check = await makeCheck(kek);
                const next = Object.freeze({
                    mode: 'passphrase',
                    version: 1,
                    createdAt: now(),
                    rotatedAt: null,
                    salt: bytesToB64(salt),
                    check,
                    iterations,
                    pending: null,
                });
                await store.put(SLOT_META, next);
                meta = next;
                held = kek;
                return;
            }
            const kek = await newDeviceKek();
            await store.put(SLOT_KEK, kek);
            const next = Object.freeze({
                mode: 'device',
                version: 1,
                createdAt: now(),
                rotatedAt: null,
                salt: null,
                check: null,
                iterations,
                pending: null,
            });
            await store.put(SLOT_META, next);
            meta = next;
            held = kek;
        },
        async unlock(passphrase) {
            const m = await loadMeta();
            if (m === null || m.mode !== 'passphrase' || m.salt === null || m.check === null)
                return false;
            const salt = b64ToBytes(m.salt);
            if (salt === null)
                return false;
            const kek = await deriveKek(passphrase, salt, m.iterations);
            if (!(await checkOk(kek, m.check)))
                return false;
            held = kek;
            // 有未完成轮换时顺手把旧 KEK 重算出来：口令相同（`rotate` 强制校验），
            // 只是 salt 不同。不重算的话，"轮换中断 → 重开 → 解锁"之后旧记录读不出来。
            if (m.pending !== null && m.pending.prevSalt !== null) {
                const prevSalt = b64ToBytes(m.pending.prevSalt);
                if (prevSalt !== null)
                    prev = await deriveKek(passphrase, prevSalt, m.iterations);
            }
            return true;
        },
        lock() {
            held = null;
            prev = null;
        },
        async kek() {
            if (held !== null)
                return held;
            const m = await loadMeta();
            if (m === null)
                throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
            if (m.mode !== 'device')
                throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
            // 轮换进行中，新 KEK 在 `kek.next`：此时**写入必须用新 KEK**，
            // 否则轮换永远收敛不了（边重包边用旧 KEK 写新数据）。
            const k = await store.get(m.pending === null ? SLOT_KEK : SLOT_NEXT);
            // 槽里必须是 CryptoKey 且能用于 wrap/unwrap。类型检查挡的是"槽被换成字符串"。
            if (typeof k !== 'object' || k === null || k.type !== 'secret') {
                throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
            }
            held = k;
            return held;
        },
        async previousKek() {
            if (prev !== null)
                return prev;
            const m = await loadMeta();
            if (m === null || m.pending === null)
                return null;
            // `passphrase` 模式的旧 KEK 只能由口令重算，`unlock()` 时已填好；
            // 未解锁就是"拿不到"，如实返回 null 而不是猜。
            if (m.mode !== 'device')
                return null;
            const k = await store.get(SLOT_PREV);
            if (typeof k !== 'object' || k === null || k.type !== 'secret')
                return null;
            prev = k;
            return prev;
        },
        async rotate(opts = {}) {
            // 同上：轮换是状态迁移，必须用槽里的最新 meta 做 pending 检查。
            const m = await loadMeta(true);
            if (m === null)
                throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
            // 上一轮没完成就再轮换，会出现三个 KEK 同时有效，重包失去单一真相。
            if (m.pending !== null)
                throw storageErrorOf('STORAGE_DENIED');
            const current = await ring.kek();
            const passphrase = opts.passphrase;
            let nextKek;
            let salt = m.salt;
            let check = m.check;
            let prevSalt = null;
            let prevCheck = null;
            if (m.mode === 'passphrase') {
                if (passphrase === undefined)
                    throw storageErrorOf('STORAGE_DENIED');
                if (passphrase.length < 8)
                    throw storageErrorOf('STORAGE_DENIED');
                // 只换 salt，不换口令。改口令意味着"用旧 KEK 解、用新 KEK 重加密全部记录"，
                // 那是另一个功能；这里用旧 check 明确拒绝，避免"以为改了口令其实没改"。
                const oldSalt = m.salt === null ? null : b64ToBytes(m.salt);
                if (oldSalt === null || m.check === null)
                    throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
                if (!(await checkOk(await deriveKek(passphrase, oldSalt, m.iterations), m.check))) {
                    throw storageErrorOf('STORAGE_DENIED');
                }
                const s = randomBytes(16);
                nextKek = await deriveKek(passphrase, s, m.iterations);
                prevSalt = m.salt;
                prevCheck = m.check;
                salt = bytesToB64(s);
                check = await makeCheck(nextKek);
                // 派生密钥**不落盘**：落盘就把 `passphrase` 模式降级成 `device` 模式。
            }
            else {
                nextKek = await newDeviceKek();
                // 先落旧、再落新、最后落 meta：任一步崩溃都停在"两个密钥都在"，
                // 而不是"新的生效了、旧的没了"。
                await store.put(SLOT_PREV, current);
                await store.put(SLOT_NEXT, nextKek);
            }
            const next = Object.freeze({
                mode: m.mode,
                version: m.version + 1,
                createdAt: m.createdAt,
                rotatedAt: now(),
                salt,
                check,
                iterations: m.iterations,
                pending: Object.freeze({
                    from: m.version,
                    to: m.version + 1,
                    startedAt: now(),
                    prevSalt,
                    prevCheck,
                }),
            });
            await store.put(SLOT_META, next);
            meta = next;
            prev = current;
            held = nextKek;
            return { from: m.version, to: next.version };
        },
        async finalizeRotation() {
            // 状态迁移：必须读最新 meta，不能用内存缓存（多标签页，见 loadMeta 注释）。
            const m = await loadMeta(true);
            if (m !== null && m.pending !== null) {
                if (m.mode === 'device') {
                    const next = await store.get(SLOT_NEXT);
                    if (typeof next !== 'object' || next === null || next.type !== 'secret') {
                        // **fail-closed**。`kek.next` 槽里没有可用的新 KEK，说明"待重包的新 KEK"
                        // 已经不可得。此时若照旧清掉 pending 并删掉 `kek.prev`，那些**已经用新
                        // KEK 重包过**的记录会永久不可读（旧 KEK 被删、新 KEK 只在 next 槽）。
                        // 保持 pending 让下一轮还能重试，代价只是"轮换未完成"。
                        throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
                    }
                    await store.put(SLOT_KEK, next);
                    // 写序即提交顺序：**先清 pending，再删旧槽**。
                    // pending 是"这一轮是否已提交"的唯一真相；`kek.next`/`kek.prev` 只是残留。
                    // 反过来的旧写法（先 del next、再写 meta）在两步之间崩溃时，重开会看到
                    // pending 仍在 → `kek()` 去读已被删除的 `kek.next` → 全库 STORAGE_KEY_UNAVAILABLE，
                    // 而此时 `kek` 槽其实已经是新 KEK，数据本可读。清理动作放在提交点之后，
                    // 即使清理失败也只留下无用槽，不影响正确性。
                    const done = Object.freeze({ ...m, pending: null });
                    await store.put(SLOT_META, done);
                    await store.del(SLOT_NEXT);
                    await store.del(SLOT_PREV);
                    meta = done;
                    prev = null;
                    return;
                }
                const done = Object.freeze({ ...m, pending: null });
                await store.put(SLOT_META, done);
                meta = done;
            }
            prev = null;
        },
        async recoveryMaterial() {
            const m = await loadMeta();
            if (m === null)
                throw storageErrorOf('STORAGE_KEY_UNAVAILABLE');
            if (m.mode !== 'passphrase' || m.salt === null || m.check === null) {
                // `device` 模式没有可携带的材料。返回一个"空材料"会让人以为能恢复。
                throw storageErrorOf('STORAGE_DENIED');
            }
            return Object.freeze({
                mode: 'passphrase',
                salt: m.salt,
                check: m.check,
                iterations: m.iterations,
                version: m.version,
                createdAt: m.createdAt,
            });
        },
        async restoreFrom(material, passphrase) {
            const existing = await loadMeta();
            if (existing !== null)
                throw storageErrorOf('STORAGE_DENIED');
            // 材料是外部输入：逐字段校验，不信任形状。迭代数下限挡的是"材料被改成
            // iterations: 1"——那会让后续口令校验在毫秒内被爆破。
            //
            // 材料非法用 `STORAGE_CORRUPT`（数据问题），已存在用 `STORAGE_DENIED`
            // （状态问题）。两者合并会让调用方把"包坏了"读成"这里已经有密钥了"。
            const badMaterial = () => storageErrorOf('STORAGE_CORRUPT');
            if (typeof material !== 'object' || material === null)
                throw badMaterial();
            const mat = material;
            if (mat.mode !== 'passphrase')
                throw badMaterial();
            if (typeof mat.salt !== 'string' || typeof mat.check !== 'string')
                throw badMaterial();
            if (typeof mat.iterations !== 'number' ||
                !Number.isSafeInteger(mat.iterations) ||
                mat.iterations < MIN_RESTORE_ITERATIONS) {
                throw badMaterial();
            }
            if (typeof mat.version !== 'number' || mat.version < 1)
                throw badMaterial();
            const salt = b64ToBytes(mat.salt);
            if (salt === null)
                throw badMaterial();
            const kek = await deriveKek(passphrase, salt, mat.iterations);
            if (!(await checkOk(kek, mat.check)))
                return false;
            const next = Object.freeze({
                mode: 'passphrase',
                version: mat.version,
                createdAt: typeof mat.createdAt === 'number' ? mat.createdAt : now(),
                rotatedAt: null,
                salt: mat.salt,
                check: mat.check,
                iterations: mat.iterations,
                pending: null,
            });
            await store.put(SLOT_META, next);
            meta = next;
            held = kek;
            return true;
        },
        async destroy() {
            held = null;
            prev = null;
            meta = null;
            await store.del(SLOT_KEK);
            await store.del(SLOT_NEXT);
            await store.del(SLOT_PREV);
            await store.del(SLOT_META);
            await store.del(SLOT_PROBE);
        },
    };
    return ring;
}
