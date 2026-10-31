/**
 * S1 审计出口：网关**产生事件**，母体**记录审计**。两者不是同一件事。
 *
 * # 为什么必须分开（C3）
 *
 * 「模块自称可信审计」是一个具体的错误：本模块运行在与被审计代码**相同的 JS 上下文**
 * 里，同一份代码既能产生事件，也能选择不产生。因此本模块产出的任何记录都**不是**
 * 不可否认凭证，只是"模块自己说它做了什么"。
 *
 * 真正的审计记录必须由母体的审计单点（宪法第 12 条，`web/src/api/audit.ts`）落盘，
 * 且落盘动作不经过被审计模块。所以本文件的定位是：
 *
 * ```
 *   网关 ──emit──► AuditSink（接口） ──► 母体审计单点（接线阶段注入）
 *                    │
 *                    └── 默认实现：nullSink（丢弃）
 * ```
 *
 * T1.2 **不提供**任何写日志的实现。`createMemorySink` 只用于测试断言"事件确实产生了"，
 * 它的注释与命名都避免"audit log"字样。
 *
 * # 事件里**没有**什么
 *
 * 没有键名、没有值、没有密钥、没有 hash 原文。类型定义里就没有这些字段——不是
 * "约定不填"，而是"填不进去"。`scope` 是 `tenant/ks/app/domain` 的拼接，domain 是
 * 固定词表（`chat`/`config`/`sec`/`cache`/`plugin.<id>`），不承载业务内容。
 *
 * # 失败不影响业务
 *
 * `emit` 抛错被吞掉。沿用 `audit.ts:12-13` 的既有原则：审计失败不回滚业务。
 * 反过来（审计失败即业务失败）会让一个写满的审计库变成全局写阻断。
 */
// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------
/** 丢弃一切事件。默认出口——未接线时事件不该落地到任何地方。 */
export const nullSink = Object.freeze({
    emit() {
        /* 有意为空 */
    },
});
/**
 * 创建测试用出口。
 *
 * `capacity` 上限防止长时间测试把内存吃满。超出后**丢弃最旧的**——保留最近的
 * 事件对断言更有用（失败通常发生在用例末尾）。
 */
export function createMemorySink(capacity = 2048) {
    const buf = [];
    return {
        emit(e) {
            buf.push(Object.freeze({ ...e }));
            if (buf.length > capacity)
                buf.splice(0, buf.length - capacity);
        },
        get events() {
            return buf;
        },
        clear() {
            buf.length = 0;
        },
        of(kind) {
            return buf.filter((e) => e.kind === kind);
        },
    };
}
/**
 * 组合出口：扇出到多个 sink，单个失败不影响其余。
 *
 * 用途：接线阶段同时送母体审计单点与开发期控制台。顺序按参数顺序，不保证异步完成。
 */
export function createFanoutSink(...sinks) {
    return Object.freeze({
        emit(e) {
            for (const s of sinks) {
                try {
                    s.emit(e);
                }
                catch {
                    // 单个 sink 失败不影响其余。这里**不能**再抛：网关会在 emit 外层
                    // 再捕一次，两层捕获会让"审计失败不阻断业务"变成"审计失败被吞两次"，
                    // 掩盖真实问题。
                }
            }
        },
    });
}
/** 安全发射：吞掉 sink 的异常。网关统一走这里。 */
export function safeEmit(sink, e) {
    try {
        sink.emit(e);
    }
    catch {
        /* 审计失败不阻断业务（`audit.ts:12-13`） */
    }
}
