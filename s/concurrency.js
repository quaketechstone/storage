/**
 * S1 并发控制：把"同一键的读改写"串起来，把"同一资源的重复请求"合并。
 *
 * # 为什么需要
 *
 * IndexedDB 的事务是原子的，但**跨事务**的读改写不是。`get → 改 → put` 中间只要
 * 有 `await`，另一个调用就能插进来写同一个键，结果是"后写的赢"——而两个调用都以为
 * 自己成功。这类丢失更新在单用户场景下也会发生：两个驱动同时写 `config.theme`，
 * 一个的修改会静默消失。
 *
 * 解法有两层，缺一不可：
 * 1. **乐观并发**（`expectedRev`）：发现冲突就报 `STORAGE_CONFLICT`，让调用方决定重试。
 * 2. **同键串行**（本文件的 `KeyedMutex`）：把并发降成顺序，让"读改写"在逻辑上原子。
 *
 * 只有 1 没有 2，会让正常的并发读改写频繁失败；只有 2 没有 1，跨标签页（不同 JS
 * 上下文，锁不共享）依然会丢更新。两者互补。
 *
 * # 为什么锁要按 key 而不是全局
 *
 * 全局串行会让一次慢写阻塞所有无关读写。按 key 分锁后，`chat.a` 与 `chat.b` 互不影响。
 * 代价是锁表需要清理——`tails.delete` 的条件判断见实现。
 */
/**
 * 创建同键互斥。
 *
 * 实现是「尾链」：每个 key 维护一个"最后一个排队者完成"的 Promise，新来的先 `await`
 * 它，再执行自己的 `fn`，最后释放自己的 gate 让下一位继续。
 *
 * 不用"计数 + 条件变量"是因为 JS 没有阻塞原语，用 Promise 链更直观且不会死锁。
 */
export function createKeyedMutex() {
    /** key → 队尾 Promise。队尾完成即表示轮到下一位。 */
    const tails = new Map();
    return {
        async run(key, fn) {
            const prev = tails.get(key) ?? Promise.resolve();
            let release;
            const gate = new Promise((resolve) => {
                release = resolve;
            });
            // 队尾 = 前一位完成后再等本位的 gate。`prev.then` 不传播 prev 的拒绝：
            // 前一位失败不应该让后一位直接失败，否则一个坏调用会连坐整条链。
            const tail = prev.then(() => gate);
            tails.set(key, tail);
            try {
                await prev;
                return await fn();
            }
            finally {
                release();
                // 只有当自己仍是队尾时才清理。否则会删掉后来者的队尾，导致新来的调用
                // 拿 `Promise.resolve()` 直接跳过排队——锁形同虚设。
                if (tails.get(key) === tail)
                    tails.delete(key);
            }
        },
        size() {
            return tails.size;
        },
    };
}
/** 创建单飞。 */
export function createSingleFlight() {
    const inflight = new Map();
    return {
        do(key, fn) {
            const existing = inflight.get(key);
            if (existing !== undefined)
                return existing;
            const p = (async () => fn())();
            inflight.set(key, p);
            // 用 `then` 的双参数而非 `finally`：`finally` 返回的新 Promise 会继承拒绝态，
            // 若不接住就产生 unhandledRejection——测试进程会因此打印 "Error: boom" 并在
            // 严格模式下退出码非 0，把一个正常的失败路径变成噪声。
            const clear = () => {
                if (inflight.get(key) === p)
                    inflight.delete(key);
            };
            p.then(clear, clear);
            return p;
        },
        size() {
            return inflight.size;
        },
    };
}
/**
 * 创建并发上限。
 *
 * 用途：`scan` 大范围时逐条读会打出成百上千个并发事务，反而拖慢（IDB 事务在
 * 同一 store 上是串行的，排队开销比串行更大）。限制在 4~8 是常见取值。
 *
 * `max <= 0` 视为 1：不限制等于放弃保护，而 0 会让所有任务永远排队（死锁）。
 */
export function createLimiter(max) {
    const limit = Math.max(1, Math.floor(max));
    let active = 0;
    const waiters = [];
    function acquire() {
        if (active < limit) {
            active++;
            return Promise.resolve();
        }
        return new Promise((resolve) => {
            waiters.push(() => {
                active++;
                resolve();
            });
        });
    }
    function release() {
        active--;
        const next = waiters.shift();
        if (next !== undefined)
            next();
    }
    return {
        async run(fn) {
            await acquire();
            try {
                return await fn();
            }
            finally {
                release();
            }
        },
        get active() {
            return active;
        },
        get pending() {
            return waiters.length;
        },
    };
}
