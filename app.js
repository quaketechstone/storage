/**
 * 受控测试预览 · 人机测试工作台逻辑。
 *
 * 三层职责，刻意分开：
 * 1. **服务端**（Rust）判定权限、发确认令牌、写审计——唯一权威；
 * 2. **WASM**（同一份 Rust 权限内核）只用于"按钮该不该亮"，属于减少误操作的门禁；
 * 3. **本文件**只做展示与调用，**不复制任何权限规则**：能做什么一律问 `guard.can()`，
 *    它内部调 `preview-guard.wasm` 的 `guard_can`；WASM 不可用时退回服务端下发的
 *    `allowed` 标记（同样是 Rust 算的）。
 */
import * as S from '/storage/s/index.js'
import { mountCtxKv } from '/storage/s/integration/ctx-kv-adapter.js'
import { createProviderRegistry } from '/storage/s/providers/registry.js'
import { memoryProvider, idbProvider } from '/storage/s/providers/builtins.js'
import { withFaults } from '/storage/s/providers/faulty.js'

const ALL_OPS = ['read', 'list', 'scan', 'write', 'delete', 'purge', 'tx', 'migrate', 'backup', 'restore', 'keyAccess']
const NS = 'demo-ns'

const state = {
  // 存储侧
  stack: null,
  gw: null,
  ticket: null,
  scope: null,
  kv: null,
  mount: null,
  keyring: null,
  signer: null,
  backup: null,
  registry: null,
  fault: null,
  evidence: null,
  // 预览侧
  me: null,
  role: null,
  roleCode: 0,
  caps: 0,
  ops: new Map(),
  roles: [],
  wasm: null,
  mustChange: false,
  mn: null,
}

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel)
const logEl = () => $('#log')

function log(msg, cls = 'info') {
  const el = logEl()
  if (!el) return
  const line = document.createElement('div')
  line.className = cls
  const t = new Date().toISOString().slice(11, 19)
  line.textContent = `[${t}] ${msg}`
  el.appendChild(line)
  el.scrollTop = el.scrollHeight
}

function setStatus(text, cls = '') {
  const el = $('#status')
  if (!el) return
  el.textContent = text
  el.className = 'status ' + cls
}

function out(id, value) {
  const el = $(id)
  if (!el) return
  el.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}

async function run(label, fn, outId) {
  try {
    const r = await fn()
    log(`✓ ${label}` + (r === undefined ? '' : ` → ${JSON.stringify(r).slice(0, 300)}`), 'ok')
    if (outId) out(outId, r === undefined ? 'ok' : r)
    return r
  } catch (e) {
    const code = e && e.code ? e.code : ''
    const msg = e && e.message ? e.message : String(e)
    log(`✗ ${label} ${code ? '[' + code + '] ' : ''}${msg}`, 'err')
    if (outId) out(outId, { error: code || msg, message: msg })
    throw e
  }
}

// ---------------------------------------------------------------------------
// 服务端 API
// ---------------------------------------------------------------------------
class ApiError extends Error {
  constructor(code, message, status) {
    super(message)
    this.code = code
    this.status = status
  }
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {}
  if (method !== 'GET') {
    headers['content-type'] = 'application/json'
    // CSRF 第二道：写请求必须带自定义头（跨站表单无法伪造）
    headers['x-preview-csrf'] = '1'
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let data = null
  try {
    data = await res.json()
  } catch {
    data = null
  }
  if (!res.ok) {
    const code = (data && data.code) || `HTTP_${res.status}`
    // `res.statusText` 在 HTTP/2 下常常是空串（协议没有 reason phrase），
    // 静态托管又可能回 HTML 让 `res.json()` 失败。两者叠加就会出现
    // `message === ''`，最终渲染成 "初始化失败：Error"——把人吓一跳还查不出原因。
    // 所以这里兜底到 code，保证 message 永不为空。
    const msg = (data && data.message) || res.statusText || code
    if (res.status === 401 && !/\/api\/auth\/login$/.test(path)) {
      showLogin('会话已失效，请重新登录')
    }
    throw new ApiError(code, msg, res.status)
  }
  return data
}

// ---------------------------------------------------------------------------
// 权限门禁（WASM，与服务端同一份 Rust 源码）
// ---------------------------------------------------------------------------
const guard = {
  async loadWasm() {
    try {
      const res = await fetch('/storage/wasm/preview-guard.wasm')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const buf = await res.arrayBuffer()
      const { instance } = await WebAssembly.instantiate(buf, {})
      const e = instance.exports
      if (typeof e.guard_can !== 'function' || e.guard_op_count() !== state.ops.size) {
        throw new Error('wasm 导出与 /api/caps 不一致')
      }
      state.wasm = e
      log(`权限内核已加载：WASM v${e.guard_version()}，${e.guard_op_count()} 个操作`, 'ok')
    } catch (e) {
      state.wasm = null
      log(`WASM 门禁不可用（${e.message}），回退服务端 allowed 标记`, 'warn')
    }
  },

  can(opName) {
    const op = state.ops.get(opName)
    if (!op) return false
    if (state.mustChange) return false
    if (state.wasm && typeof state.wasm.guard_can === 'function') {
      return state.wasm.guard_can(state.roleCode, op.code) === 1
    }
    return op.allowed === true
  },

  minRole(opName) {
    const op = state.ops.get(opName)
    if (!op) return '?'
    for (const r of state.roles) {
      if ((r.caps >> op.code) & 1) return r.label
    }
    return '?'
  },
}

/** 按权限刷新所有按钮的可用性；不可用的显式标注需要什么角色。 */
function applyGating() {
  document.querySelectorAll('[data-op]').forEach((el) => {
    const op = el.dataset.op
    const ok = guard.can(op)
    el.disabled = !ok
    el.classList.toggle('locked', !ok)
    el.title = ok ? '' : `需要「${guard.minRole(op)}」权限`
  })
  $('#pwd-banner').hidden = !state.mustChange
}

// ---------------------------------------------------------------------------
// 登录 / 会话 / 改密
// ---------------------------------------------------------------------------
function showLogin(msg = '') {
  state.me = null
  $('#app').hidden = true
  $('#login').hidden = false
  $('#login-err').textContent = msg
  const u = $('#login-user')
  if (u) u.focus()
}

function showApp() {
  $('#login').hidden = true
  $('#app').hidden = false
}

async function doLogin(username, password) {
  const r = await api('/api/auth/login', { method: 'POST', body: { username, password } })
  state.me = r.user
  state.role = r.role
  state.mustChange = r.mustChange
  await afterAuth()
  return r
}

async function afterAuth() {
  const me = await api('/api/auth/me')
  state.me = me.user
  state.role = me.role
  state.mustChange = me.mustChange
  state.caps = me.caps
  const caps = await api('/api/caps')
  state.roles = caps.roles
  state.ops = new Map(caps.ops.map((o) => [o.name, o]))
  state.roleCode = (caps.roles.find((r) => r.name === me.role) || { code: 0 }).code
  if (!state.wasm) await guard.loadWasm()

  $('#who-name').textContent = me.user.username
  $('#who-role').textContent = `${me.roleLabel} · ${me.role}`
  $('#who-role').className = 'pill ' + (me.role === 'operator' ? 'warn' : 'ok')
  showApp()
  applyGating()
  renderCaps()
  await refreshStatus().catch(() => {})
  setStatus(`就绪 · ${me.role}${state.mustChange ? ' · 需改密' : ''}`, state.mustChange ? 'warn' : 'ok')
}

async function doLogout() {
  try {
    await api('/api/auth/logout', { method: 'POST', body: {} })
  } catch {
    /* 忽略 */
  }
  state.me = null
  showLogin('已退出')
}

async function changePassword() {
  const oldP = prompt('当前口令')
  if (!oldP) return
  const newP = prompt('新口令（≥12 位，至少含大小写/数字/符号中的两类）')
  if (!newP) return
  const r = await run('修改口令', () =>
    api('/api/auth/password', { method: 'POST', body: { old: oldP, new: newP } }),
  )
  if (r && r.ok) {
    state.mustChange = false
    applyGating()
    setStatus('口令已更新', 'ok')
    log('口令已更新；其它设备上的会话已作废', 'ok')
  }
}

// ---------------------------------------------------------------------------
// 危险操作确认（短语 + 理由 → 服务端一次性令牌）
// ---------------------------------------------------------------------------
function askConfirm(opName, target) {
  const dlg = $('#confirm-dlg')
  const op = state.ops.get(opName)
  const phrase = (op && op.phrase) || 'CONFIRM'
  $('#dlg-title').textContent = `确认危险操作：${opName}`
  $('#dlg-desc').textContent = `目标：${target || '—'} · 该操作会写审计并留下操作者身份`
  $('#dlg-phrase').textContent = phrase
  $('#dlg-input').value = ''
  $('#dlg-reason').value = ''
  dlg.returnValue = ''
  return new Promise((resolve) => {
    const form = dlg.querySelector('form')
    const onSubmit = (e) => {
      const typed = $('#dlg-input').value.trim()
      const reason = $('#dlg-reason').value.trim()
      if (typed !== phrase) {
        e.preventDefault()
        $('#dlg-input').focus()
        $('#dlg-desc').textContent = `短语不匹配：请输入 ${phrase}`
        return
      }
      if (reason.length < 4) {
        e.preventDefault()
        $('#dlg-reason').focus()
        $('#dlg-desc').textContent = '请填写至少 4 个字符的操作理由（会写进审计）'
        return
      }
      dlg.returnValue = 'ok'
    }
    form.addEventListener('submit', onSubmit, { once: false })
    dlg.addEventListener(
      'close',
      () => {
        form.removeEventListener('submit', onSubmit)
        resolve(dlg.returnValue === 'ok' ? $('#dlg-reason').value.trim() : null)
      },
      { once: true },
    )
    dlg.showModal()
    $('#dlg-input').focus()
  })
}

/** 危险操作统一入口：确认 → 取令牌 → 执行。令牌一次性、120 秒、绑定 op+target。 */
async function dangerous(opName, target, fn) {
  if (!guard.can(opName)) throw new ApiError('PREVIEW_FORBIDDEN', `当前角色无权执行 ${opName}`, 403)
  const reason = await askConfirm(opName, target)
  if (!reason) {
    log(`已取消 ${opName}`, 'warn')
    return null
  }
  const c = await api('/api/confirm', { method: 'POST', body: { op: opName, target, reason } })
  log(`确认令牌已签发（${opName}，${c.ttlSecs}s 内有效）`, 'info')
  return fn(c.token)
}

// ---------------------------------------------------------------------------
// 存储侧装配
// ---------------------------------------------------------------------------
async function initStack(kind = 'memory') {
  const engine = kind === 'idb' ? await S.createIdbEngine({ name: 'quake_wb' }) : S.createMemoryEngine()
  state.stack = S.createStorageStack({ engine, now: () => Date.now() })
  state.gw = state.stack.gateway
  state.scope = S.createScope('local', 'user', 'module:demo.app', 'chat')
  const grant = state.gw.mintGrant({
    subject: 'module:demo.app',
    scopes: [{ scope: state.scope }],
    ops: ALL_OPS,
    source: 'manifest',
  })
  const t = state.gw.mintTicket(grant, state.scope)
  if (!t.ok) throw t.error
  state.ticket = t.value
  state.kv = S.createKvFacade(state.gw, state.ticket, state.scope, NS)
  state.kind = kind
  log(`装配完成：${kind} 后端，scope=${state.scope.app}/${state.scope.domain}`, 'ok')
}

function registry() {
  if (!state.registry) state.registry = createProviderRegistry([memoryProvider(), idbProvider()])
  return state.registry
}

async function refreshProviders() {
  const body = $('#providers')
  body.innerHTML = ''
  for (const kind of registry().kinds()) {
    const tr = document.createElement('tr')
    const d = registry().info().find((x) => x.kind === kind)
    let health = '—'
    let healthCls = 'warn'
    let caps = '未打开'
    try {
      const p = await registry().open(kind)
      const c = p.engine.capabilities()
      caps = `${c.ops.length} ops · tx=${c.transactions} · ttl=${c.ttl}`
      health = p.health.ok ? `ok ${p.health.latencyMs}ms` : 'down'
      healthCls = p.health.ok ? 'ok' : 'err'
    } catch (e) {
      health = e && e.code ? e.code : 'open failed'
      healthCls = 'err'
    }
    tr.innerHTML = `<td>${kind}</td><td>${d ? d.environment : '—'}</td><td>${caps}</td><td><span class="pill ${healthCls}">${health}</span></td>`
    body.appendChild(tr)
  }
  log('Provider 已刷新', 'info')
}

// ---------------------------------------------------------------------------
// 状态 / 权限 / 审计
// ---------------------------------------------------------------------------
async function refreshStatus() {
  const st = await api('/api/status')
  const five = await api('/api/state')
  out('#status-out', { service: st.service, counts: st.counts, audit: st.audit, states: five.states })
  return st
}

function renderCaps() {
  const body = $('#caps-tbl tbody')
  body.innerHTML = ''
  for (const op of state.ops.values()) {
    const tr = document.createElement('tr')
    const allowed = guard.can(op.name)
    tr.innerHTML =
      `<td><code>${op.name}</code></td>` +
      `<td>${op.dangerous ? '<span class="pill warn">危险</span>' : '—'}</td>` +
      `<td><span class="pill ${allowed ? 'ok' : 'muted'}">${allowed ? '可执行' : '需「' + guard.minRole(op.name) + '」'}</span></td>`
    body.appendChild(tr)
  }
}

async function showAudit() {
  const r = await api('/api/audit?limit=30')
  out('#status-out', r)
}

async function verifyAudit() {
  const r = await dangerous('audit.verify', 'audit', (token) =>
    api('/api/audit/verify', { method: 'POST', body: { confirm: token } }),
  )
  if (r) out('#status-out', r)
}

// ---------------------------------------------------------------------------
// 面板动作
// ---------------------------------------------------------------------------
const actions = {
  // 会话
  logout: () => doLogout(),
  'change-password': () => changePassword(),

  // 状态
  'refresh-status': () => run('刷新状态', refreshStatus, '#status-out'),
  'refresh-caps': () => run('刷新权限', async () => {
    const caps = await api('/api/caps')
    state.roles = caps.roles
    state.ops = new Map(caps.ops.map((o) => [o.name, o]))
    applyGating()
    renderCaps()
    return { role: caps.role, ops: caps.ops.length, guardVersion: caps.guardVersion }
  }, '#status-out'),
  'show-audit': () => run('查看审计', showAudit),
  'verify-audit': () => run('校验审计链', verifyAudit),

  // Provider
  'refresh-providers': () => refreshProviders(),
  'open-memory': async () => {
    await initStack('memory')
    await refreshProviders()
    out('#data-out', 'memory 已装配，可直接读写')
  },
  'open-idb': async () => {
    await initStack('idb')
    await refreshProviders()
    out('#data-out', 'IndexedDB 已装配（真实库 quake_wb）')
  },

  // 数据
  put: async () => {
    const k = $('#data-key').value
    const v = JSON.parse($('#data-val').value)
    await run(`put ${k}`, () => state.kv.put(k, v), '#data-out')
  },
  get: async () => {
    const k = $('#data-key').value
    await run(`get ${k}`, () => state.kv.get(k), '#data-out')
  },
  del: async () => {
    const k = $('#data-key').value
    await run(
      `del ${k}`,
      () => dangerous('data.delete', k, (token) => state.kv.del(k).then((r) => ({ deleted: true, k, token: token.slice(0, 8) }))),
      '#data-out',
    )
  },
  list: async () => {
    await run('list', () => state.kv.list(''), '#data-out')
  },
  tx: async () => {
    const k = $('#data-key').value
    const v = JSON.parse($('#data-val').value)
    await run(
      'tx（两条原子写）',
      async () => {
        const r = await state.gw.tx(state.ticket, [
          { op: 'put', scope: state.scope, key: `${k}.a`, value: v },
          { op: 'put', scope: state.scope, key: `${k}.b`, value: v },
        ])
        if (!r.ok) throw r.error
        return r.value
      },
      '#data-out',
    )
  },

  // 授权
  mount: async () => {
    await run(
      '挂载 ctx.kv',
      async () => {
        state.mount = mountCtxKv({
          stack: state.stack,
          subject: 'module:demo.app',
          scopes: [{ scope: state.scope }],
          ops: ALL_OPS,
          ns: NS,
          scope: state.scope,
        })
        return { inspect: state.mount.inspect(), available: await state.mount.available() }
      },
      '#auth-out',
    )
  },
  'auth-rw': async () => {
    await run(
      '适配器写读',
      async () => {
        if (!state.mount) throw new Error('请先挂载 ctx.kv')
        await state.mount.kv.put('auth.k', { via: 'adapter' })
        return await state.mount.kv.get('auth.k')
      },
      '#auth-out',
    )
  },
  'cross-scope': async () => {
    await run(
      '跨 scope 测试（应被拒）',
      async () => {
        const other = S.createScope('local', 'user', 'module:other.app', 'chat')
        const r = await state.gw.get(state.ticket, other, 'x')
        return { ok: r.ok, code: r.ok ? null : r.error.code }
      },
      '#auth-out',
    )
  },
  availability: async () => {
    await run(
      '可用性检测',
      async () => ({ available: state.mount ? await state.mount.available() : false }),
      '#auth-out',
    )
  },

  // 加密
  keyring: async () => {
    await run(
      '创建密钥环（隔离）',
      async () => {
        const store = S.createMemoryKeyStore()
        state.keyring = S.createKeyring({ store })
        await state.keyring.create({ passphrase: 'demo-passphrase' })
        return await state.keyring.status()
      },
      '#crypto-out',
    )
  },
  seal: async () => {
    await run(
      '信封加密 / 解密',
      async () => {
        if (!state.keyring) throw new Error('请先创建密钥环')
        const kek = await state.keyring.kek()
        const env = await S.sealText(kek, 'hello-secret', 'aad-demo')
        const txt = await S.openText(kek, env, 'aad-demo')
        return { alg: env.alg || env.v, roundtrip: txt === 'hello-secret' }
      },
      '#crypto-out',
    )
  },
  rotate: async () => {
    await run(
      '轮换 KEK',
      () =>
        dangerous('crypto.rotate', 'demo-kek', async () => {
          if (!state.keyring) throw new Error('请先创建密钥环')
          // 轮换只换 salt，不换口令；passphrase 必须与创建时相同（证明持有旧 KEK）
          const r = await state.keyring.rotate({ passphrase: 'demo-passphrase' })
          return { rotate: r, status: await state.keyring.status() }
        }),
      '#crypto-out',
    )
  },

  // 备份
  backup: async () => {
    await run(
      '导出签名备份',
      async () => {
        if (!state.signer) state.signer = await S.createBackupSigner(S.createMemoryKeyStore(), { keyId: 'demo' })
        state.backup = await S.createBackup(state.stack.raw, state.scope, { signer: state.signer })
        return { count: state.backup.count, digest: state.backup.digest.slice(0, 16), signed: state.backup.sig !== null }
      },
      '#backup-out',
    )
  },
  verify: async () => {
    await run(
      '验签',
      async () => {
        if (!state.backup) throw new Error('请先导出备份')
        const v = await S.verifyBackup(state.backup, { signer: state.signer })
        return { ok: v.ok, code: v.ok ? null : v.code }
      },
      '#backup-out',
    )
  },
  tamper: async () => {
    await run(
      '篡改后验签（应被拒）',
      async () => {
        if (!state.backup) throw new Error('请先导出备份')
        const bad = JSON.parse(JSON.stringify(state.backup))
        if (bad.records.length === 0) return { note: '无记录可篡改' }
        bad.records[0].value = { tampered: true }
        const v = await S.verifyBackup(bad, { signer: state.signer })
        return { ok: v.ok, code: v.ok ? null : v.code }
      },
      '#backup-out',
    )
  },
  restore: async () => {
    await run(
      '恢复到新库',
      () =>
        dangerous('backup.restore', 'browser-restore', async () => {
          if (!state.backup) throw new Error('请先导出备份')
          const fresh = S.createMemoryEngine()
          const rep = await S.restoreBackup(fresh, state.backup, { scope: state.scope, signer: state.signer })
          const keys = await fresh.list(state.scope, '')
          return { report: rep, keys }
        }),
      '#backup-out',
    )
  },

  // 故障注入
  'fault-arm': async () => {
    await run(
      '装配故障引擎并注入 put',
      () =>
        dangerous('fault.inject', 'put', async () => {
          const mem = S.createMemoryEngine()
          const faulty = withFaults(mem)
          const stack = S.createStorageStack({ engine: faulty, now: () => Date.now() })
          const grant = stack.gateway.mintGrant({
            subject: 'module:demo.app',
            scopes: [{ scope: state.scope }],
            ops: ALL_OPS,
            source: 'manifest',
          })
          const t = stack.gateway.mintTicket(grant, state.scope)
          if (!t.ok) throw t.error
          const kv = S.createKvFacade(stack.gateway, t.value, state.scope, NS)
          faulty.faults.arm('put', 1, 'STORAGE_UNAVAILABLE')
          state.fault = { mem, faulty, kv }
          return { armed: faulty.faults.snapshot() }
        }),
      '#fault-out',
    )
  },
  'fault-trigger': async () => {
    await run(
      '触发 put（应失败）',
      async () => {
        if (!state.fault) throw new Error('请先注入故障')
        try {
          await state.fault.kv.put('fault.k', 1)
          return { unexpected: 'put 竟然成功' }
        } catch (e) {
          return { rejected: e.code || e.message }
        }
      },
      '#fault-out',
    )
  },
  'fault-check': async () => {
    await run(
      '检查库内无脏写',
      async () => {
        if (!state.fault) throw new Error('请先注入故障')
        const keys = await state.fault.mem.list(state.scope, '')
        return { keys, dirty: keys.includes('fault.k') }
      },
      '#fault-out',
    )
  },

  // 证据
  evidence: async () => {
    await run(
      '采集证据',
      async () => {
        const mem = S.createMemoryEngine()
        const stack = S.createStorageStack({ engine: mem, now: () => 1_700_000_000_000 })
        const scope = S.createScope('local', 'user', 'module:evidence.app', 'chat')
        const grant = stack.gateway.mintGrant({
          subject: 'module:evidence.app',
          scopes: [{ scope }],
          ops: ALL_OPS,
          source: 'manifest',
        })
        const t = stack.gateway.mintTicket(grant, scope)
        if (!t.ok) throw t.error
        const kv = S.createKvFacade(stack.gateway, t.value, scope, 'ev')
        const results = []
        await kv.put('ev.1', { n: 1 })
        results.push({ step: 'put', ok: (await kv.get('ev.1'))?.n === 1 })
        results.push({ step: 'list', ok: (await kv.list('ev.')).includes('ev.1') })
        const other = S.createScope('local', 'user', 'module:other.app', 'chat')
        const x = await stack.gateway.get(t.value, other, 'x')
        results.push({ step: 'cross-scope', ok: x.ok === false && x.error.code === 'STORAGE_SCOPE_VIOLATION' })
        const payload = {
          at: new Date().toISOString(),
          results,
          pass: results.every((r) => r.ok),
          operator: state.me ? state.me.username : '-',
          role: state.role,
          userAgent: navigator.userAgent,
        }
        payload.sha256 = await S.sha256Hex(JSON.stringify(payload))
        state.evidence = payload
        return payload
      },
      '#evidence-out',
    )
  },
  'upload-evidence': async () => {
    await run(
      '上传证据到服务端',
      async () => {
        if (!state.evidence) throw new Error('请先采集证据')
        const r = await api('/api/evidence', {
          method: 'POST',
          body: { payload: state.evidence, note: `workbench ${state.kind || 'memory'} 冒烟` },
        })
        await refreshEvidence()
        return r
      },
      '#evidence-out',
    )
  },
  'refresh-evidence': () => run('刷新服务端证据', refreshEvidence),
  'download-evidence': async () => {
    if (!state.evidence) return out('#evidence-out', '请先采集证据')
    download('storage-evidence.json', state.evidence)
  },

  // 运维
  'refresh-backups': () => run('刷新备份', refreshBackups, '#admin-out'),
  'server-backup': () =>
    run('创建服务端备份', async () => {
      const r = await api('/api/admin/backup', { method: 'POST', body: {} })
      await refreshBackups()
      return { id: r.manifest.id, files: r.manifest.files.length, bytes: r.manifest.total_bytes }
    }, '#admin-out'),
  'server-restore': () =>
    run('恢复服务端备份', async () => {
      const id = $('#restore-id').value.trim()
      if (!id) throw new Error('请填写备份 id（bk-…）')
      return dangerous('backup.restore', id, (token) =>
        api('/api/admin/restore', { method: 'POST', body: { id, confirm: token } }),
      )
    }, '#admin-out'),
  'server-reset': () =>
    run('重置测试数据', async () => {
      const scope = $('#reset-scope').value
      return dangerous('service.reset', scope, (token) =>
        api('/api/admin/reset', { method: 'POST', body: { scope, confirm: token } }),
      )
    }, '#admin-out'),
  'server-stop': () =>
    run(
      '停止服务',
      () =>
        dangerous('service.control', 'service', (token) =>
          api('/api/admin/service', { method: 'POST', body: { action: 'stop', confirm: token } }),
        ),
      '#admin-out',
    ),
  'refresh-users': () => run('刷新账号', refreshUsers, '#admin-out'),
  'user-create': () =>
    run('新建账号', async () => {
      const username = $('#new-user').value.trim()
      const role = $('#new-role').value
      const note = $('#new-note').value.trim()
      if (!username) throw new Error('请填写用户名')
      const r = await dangerous('account.admin', username, (token) =>
        api('/api/admin/users', { method: 'POST', body: { username, role, note, confirm: token } }),
      )
      if (r) {
        await refreshUsers()
        out('#admin-out', {
          新建账号: r.account.username,
          角色: r.account.role,
          临时口令: r.tempPassword,
          提示: r.hint,
        })
      }
      return r
    }),

  // 真人验收
  'refresh-mn': () => run('刷新验收记录', refreshMn, '#mn-out'),
  'load-mn01': () => run('载入 MN-01 清单', () => loadMn('MN-01'), '#mn-out'),
  'load-mn02': () => run('载入 MN-02 清单', () => loadMn('MN-02'), '#mn-out'),
  'mn-submit': () =>
    run('提交验收记录', async () => {
      if (!state.mn) throw new Error('请先载入 MN-01 或 MN-02 清单')
      const name = $('#mn-name').value.trim()
      if (name.length < 2) throw new Error('请填写验收人姓名（Agent 不代签）')
      const checked = [...document.querySelectorAll('#mn-checklist input[type=checkbox]')]
      const checklist = checked.map((c) => ({ item: c.dataset.item, ok: c.checked }))
      const passed = checklist.filter((c) => c.ok).length
      const r = await api('/api/signoff', {
        method: 'POST',
        body: {
          mn: state.mn,
          name,
          decision: $('#mn-decision').value,
          note: $('#mn-note').value,
          evidence_ids: state.evidenceIds || [],
          checklist,
        },
      })
      await refreshMn()
      return { ...r, checked: `${passed}/${checklist.length}`, 提示: '提交后状态为 SUBMITTED_PENDING_REVIEW，不会自动变 PASS' }
    }, '#mn-out'),

  'clear-log': () => {
    logEl().innerHTML = ''
  },
}

// ---------------------------------------------------------------------------
// 运维 / 证据 / 验收的渲染
// ---------------------------------------------------------------------------
async function refreshBackups() {
  const r = await api('/api/admin/backups')
  if (r.items.length === 0) {
    out('#admin-out', { backups: [], 提示: '还没有备份，点「创建服务端备份」' })
    return r
  }
  out('#admin-out', { backups: r.items })
  const first = r.items[0]
  const el = $('#restore-id')
  if (el && !el.value) el.value = first.id
  return r
}

async function refreshUsers() {
  const r = await api('/api/admin/users')
  const body = $('#users-tbl tbody')
  body.innerHTML = ''
  for (const u of r.items) {
    const tr = document.createElement('tr')
    const td = (html) => {
      const c = document.createElement('td')
      c.innerHTML = html
      return c
    }
    tr.appendChild(td(`<code>${u.username}</code>`))
    tr.appendChild(td(`${u.role_label} <span class="muted">(${u.role})</span>`))
    tr.appendChild(
      td(
        u.disabled
          ? '<span class="pill err">禁用</span>'
          : u.must_change
            ? '<span class="pill warn">待改密</span>'
            : '<span class="pill ok">正常</span>',
      ),
    )
    tr.appendChild(td(u.last_login_at || '—'))
    const ops = document.createElement('td')
    const b1 = document.createElement('button')
    b1.className = 'ghost'
    b1.textContent = '重置口令'
    b1.dataset.op = 'account.admin'
    b1.onclick = () =>
      run('重置口令', async () => {
        const res = await dangerous('account.admin', u.username, (token) =>
          api('/api/admin/users/password', { method: 'POST', body: { username: u.username, confirm: token } }),
        )
        if (res) {
          await refreshUsers()
          out('#admin-out', { 账号: u.username, 临时口令: res.tempPassword, 提示: '该账号全部会话已作废' })
        }
        return res
      })
    const b2 = document.createElement('button')
    b2.className = 'ghost'
    b2.textContent = u.disabled ? '启用' : '禁用'
    b2.dataset.op = 'account.admin'
    b2.onclick = () =>
      run(u.disabled ? '启用账号' : '禁用账号', async () => {
        const res = await dangerous('account.admin', u.username, (token) =>
          api('/api/admin/users/disable', {
            method: 'POST',
            body: { username: u.username, disabled: !u.disabled, confirm: token },
          }),
        )
        if (res) await refreshUsers()
        return res
      })
    ops.appendChild(b1)
    ops.appendChild(b2)
    tr.appendChild(ops)
    body.appendChild(tr)
  }
  applyGating()
  return r
}

async function refreshEvidence() {
  const r = await api('/api/evidence')
  const body = $('#evidence-tbl tbody')
  body.innerHTML = ''
  state.evidenceIds = []
  if (r.items.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="muted">服务端还没有证据</td></tr>'
    return r
  }
  for (const it of r.items) {
    state.evidenceIds.push(it.id)
    const tr = document.createElement('tr')
    tr.innerHTML = `<td><code>${it.id}</code></td><td>${it.at || '—'}</td><td>${it.actor || '—'}</td><td class="mono">${(it.sha256 || '').slice(0, 16)}…</td>`
    body.appendChild(tr)
  }
  return r
}

const MN = {
  'MN-01': [
    '登录后看到角色徽章与服务状态（含 release=CONTROLLED_PREVIEW_RELEASED）',
    '打开 memory 与 IndexedDB，Provider 表显示健康状态',
    'put / get / list 返回与写入一致',
    '事务两条写原子生效',
    '挂载 ctx.kv 适配器并读写成功',
    '跨 scope 访问被拒（STORAGE_SCOPE_VIOLATION）',
    '创建密钥环并完成一次加解密往返',
    '轮换 KEK（需输入确认短语与理由）',
    '导出备份 → 验签通过 → 篡改后被拒',
    '注入 put 故障后库内无脏写',
  ],
  'MN-02': [
    '匿名访问 /api/status 返回 401（不开放匿名）',
    '未登录时看不到工作台，仅见登录页',
    'viewer 账号：写/删除/轮换等按钮为禁用，且直接调接口返回 403',
    '危险操作必须输入确认短语 + 理由，令牌一次性（重复使用被拒）',
    '跨 scope 越权被网关拒绝',
    '审计链校验通过（audit verify）',
    '上传证据后 sha256 可与本地采集结果核对',
    '恢复/重置前自动生成 pre-restore 快照',
    '手机端（≤560px）可完成上述关键步骤',
  ],
}

async function loadMn(mn) {
  state.mn = mn
  const wrap = $('#mn-checklist')
  wrap.innerHTML = ''
  const h = document.createElement('h3')
  h.textContent = `${mn} 检查清单（逐项勾选后提交）`
  wrap.appendChild(h)
  MN[mn].forEach((text, i) => {
    const id = `${mn}-${i + 1}`
    const label = document.createElement('label')
    label.className = 'check'
    const cb = document.createElement('input')
    cb.type = 'checkbox'
    cb.id = id
    cb.dataset.item = text
    const span = document.createElement('span')
    span.textContent = `${i + 1}. ${text}`
    label.appendChild(cb)
    label.appendChild(span)
    wrap.appendChild(label)
  })
  applyGating()
  return { mn, items: MN[mn].length }
}

async function refreshMn() {
  const [stateRes, signoffs] = await Promise.all([api('/api/state'), api('/api/signoffs')])
  out('#mn-out', {
    states: stateRes.states,
    已提交记录: signoffs.items.map((s) => ({
      mn: s.mn,
      验收人: s.name,
      结论: s.decision,
      提交时间: s.submittedAt,
      状态: s.reviewState,
      由账号: s.submittedBy,
    })),
    note: stateRes.note,
  })
  return stateRes
}

function download(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}

// ---------------------------------------------------------------------------
// 事件绑定
// ---------------------------------------------------------------------------
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]')
  if (!btn) return
  const act = btn.dataset.act
  const fn = actions[act]
  if (!fn) return
  if (btn.disabled) return
  btn.disabled = true
  try {
    await fn()
  } catch (err) {
    if (err && err.code) log(`✗ ${act} [${err.code}] ${err.message}`, 'err')
    else log(`✗ ${act} ${err && err.message ? err.message : err}`, 'err')
  } finally {
    btn.disabled = false
    applyGating()
  }
})

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const btn = e.target.querySelector('button[type=submit]')
  btn.disabled = true
  $('#login-err').textContent = ''
  try {
    await doLogin($('#login-user').value.trim(), $('#login-pass').value)
    $('#login-pass').value = ''
    log('登录成功', 'ok')
  } catch (err) {
    $('#login-err').textContent = `${err.code || ''} ${err.message || err}`.trim()
    log(`登录失败：${err.message || err}`, 'err')
  } finally {
    btn.disabled = false
  }
})

// ---------------------------------------------------------------------------
// 启动
// ---------------------------------------------------------------------------
;(async () => {
  // 先问服务端"我是谁"：401 就停在登录页，不装配任何存储能力
  try {
    await afterAuth()
    await initStack('memory')
    await refreshProviders()
    await refreshEvidence().catch(() => {})
    await refreshBackups().catch(() => {})
    log('工作台就绪', 'ok')
  } catch (e) {
    if (e && e.status === 401) {
      showLogin()
    } else if (e && e.status === 404) {
      // 404 基本只有一个原因：这一份是**静态构建**，同源没有控制面。
      // 说清楚比抛 "Error" 有用——否则测试人员会以为是工作台坏了。
      showLogin('未检测到控制面：这是静态构建产物，不含认证服务。请访问 preview-server 启动的实例。')
    } else {
      showLogin(`初始化失败：${(e && e.message) || e}`)
    }
  }
})()

// 供 Playwright 冒烟与外部检查
window.__WB__ = { state, actions, api, guard, log, applyGating, doLogin, doLogout, loadMn }
