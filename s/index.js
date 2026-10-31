/**
 * 存储基础设施公开入口。
 *
 * # 当前状态（T1.3 候选版本）
 *
 * **零调用方**：本文件没有被任何生产代码 import，`ctx.kv` 仍走
 * `loader.ts` 的 `bridgeKv*`。这是刻意的——「可以写库，不能接线」。
 *
 * 因此本文件的导出集合**不是**稳定 API。接线时若发现某个导出不需要，应当删除
 * 而不是"留着以后用"：暴露面越大，越难证明"模块只能访问自己的 scope"。
 *
 * # 分层
 *
 * ```
 *   S0  contract.ts        纯类型与纯函数（无 IO、无状态）
 *   S1  ticket / grant     授权对象（不可伪造、不可枚举）
 *       gateway            门禁与分发
 *       facade             ctx.kv 形状（票据在闭包）
 *       epoch              跨标签页撤销
 *       quota / concurrency / audit  横切能力
 *   S2  engines/*          数据引擎（唯一接触持久层的地方）
 *       integrity          读时完整性校验（装饰器）
 *       crypto/*           信封加密与密钥生命周期（装饰器）
 *       migrate            旧库 → s1 布局的迁移
 * ```
 *
 * 依赖方向严格单向：S2 不 import S1，S1 不 import 母体的 `api/*`、`loader/*`。
 * 反向依赖由 `__tests__/boundary.mjs` 检查。
 */
export * from './contract.js';
export * from './errors.js';
export * from './ticket.js';
export * from './grant.js';
export * from './canonical.js';
export * from './quota.js';
export * from './concurrency.js';
export * from './audit.js';
export * from './epoch.js';
export * from './integrity.js';
export * from './engines/types.js';
export * from './engines/memory.js';
export * from './engines/idb-db.js';
export * from './engines/idb.js';
export * from './crypto/envelope.js';
export * from './crypto/keyring.js';
export * from './crypto/engine.js';
export * from './crypto/rollback.js';
export * from './crypto/recovery.js';
export * from './backup.js';
export * from './backup-sign.js';
export * from './migrate.js';
export * from './gateway.js';
export * from './facade.js';
export * from './stack.js';
