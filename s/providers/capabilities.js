/**
 * Provider 能力声明与匹配。
 *
 * 网关/注册表据此在**调用前**拒绝不满足的后端，而不是等引擎在深处抛
 * `STORAGE_UNSUPPORTED`——后者会让"后端不支持"和"实现有 bug"混为一谈。
 */
/** 返回不满足的能力项（空数组表示满足）。 */
export function missingCapabilities(caps, req) {
    const miss = [];
    for (const op of req.ops ?? []) {
        if (!caps.ops.includes(op))
            miss.push(`op:${op}`);
    }
    if (req.transactions === true && !caps.transactions)
        miss.push('transactions');
    if (req.ttl === true && !caps.ttl)
        miss.push('ttl');
    if (req.orderedList === true && !caps.orderedList)
        miss.push('orderedList');
    return miss;
}
/** 是否满足要求。 */
export function satisfies(caps, req) {
    return missingCapabilities(caps, req).length === 0;
}
/** 一行式能力描述（诊断/工作台展示用）。 */
export function describeCapabilities(caps) {
    return [
        `ops=${caps.ops.join(',')}`,
        `tx=${caps.transactions ? 'yes' : 'no'}`,
        `ttl=${caps.ttl ? 'yes' : 'no'}`,
        `orderedList=${caps.orderedList ? 'yes' : 'no'}`,
    ].join('; ');
}
