/**
 * upstream-radar 可视化控制面板（host 侧 HTTP 路由）。
 *
 * 把已部署的 upstream-radar 能力聚合为 HTTP 路由，供 Web 设置面板消费：
 *   GET  /@dsh-external/upstream-radar/api/status     → 实时状态（state+config+任务）
 *   GET  /@dsh-external/upstream-radar/api/events     → 活跃事件明细（漏洞/兼容性/源健康）
 *   GET  /@dsh-external/upstream-radar/api/tasks      → 待办分析任务队列
 *   GET  /@dsh-external/upstream-radar/api/results    → 已回的分析结论
 *   GET  /@dsh-external/upstream-radar/api/result-failures → 到达但未被接受的答复（校验失败，诊断用）
 *   GET  /@dsh-external/upstream-radar/api/inventory  → 当前监控清单（插件×版本×图规模）
 *   GET  /@dsh-external/upstream-radar/api/releases   → 上游新版本（良性通知 + 兼容风险）
 *   POST /@dsh-external/upstream-radar/api/upgrade-request → 手动升级/评估（转发消息给接收会话，host 不安装）
 *   GET  /@dsh-external/upstream-radar/api/jobs       → 后台 job 列表
 *   GET  /@dsh-external/upstream-radar/api/job?id=    → 单个 job 进度/结果
 *   POST /@dsh-external/upstream-radar/api/refresh    → 主动触发一轮全链（poll+保存+投递）
 *   POST /@dsh-external/upstream-radar/api/inspect    → 装前静态审查（inspect --deep）
 *   POST /@dsh-external/upstream-radar/api/review     → 装前加载矩阵（review dsh-plugin）
 *
 * 设计边界（对齐 upstream-radar 的 AGENTS.md 不变量）：
 *   - 全部路由只读 radar 的 state/config 文件 + 受控子进程（CLI），不 import 插件业务代码
 *   - inspect/review 走 CLI 相同代码路径（lifecycle scripts 禁用，不执行插件代码）
 *   - 长任务（inspect/review）为后台 job，前端轮询取结果，不阻塞 HTTP；并发上限可配
 *   - job 原子落盘（jobsDir/），输出截断保界（64KB）
 *   - 本模块刻意只依赖 node 内置 + 本地结构类型，不引入 cordis/schemastery/typert
 *     编译依赖（upstream-radar 的构建环境极简，靠注入方提供 webServer 结构）。
 */
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { readAnalysisResultFailures } from './analysis-result-failures.js'
import { compareSemver, parseSemver } from './semver.js'

/** 与 host `webServer` 能力匹配的最小结构（避免 cordis 编译依赖）。 */
export interface WebServerLike {
  register(route: {
    kind: 'prefix' | 'exact'
    path: string
    handler: (req: RequestLike, res: ResponseLike) => void | Promise<void>
  }): () => void
}

/** 极简 Node HTTP 请求/响应结构（`webServer` 回调的实参）。 */
export interface RequestLike {
  method?: string
  url?: string
  on(event: 'data' | 'end', listener: (chunk?: Buffer) => void): void
}
export interface ResponseLike {
  writeHead(code: number, headers?: Record<string, string>): void
  end(body?: string): void
}

export interface RadarPanelOptions {
  /** radar 安装目录（CLI 工作目录）。 */
  radarDir: string
  configFile: string
  stateFile: string
  /** 被复用的 CLI 入口（`dist/src/cli.js`）。 */
  cliPath: string
  /** background job 落盘目录。 */
  jobsDir: string
  /** 并发 job 上限。 */
  maxJobs: number
  /** review 默认的 dsh 版本矩阵。 */
  reviewDshVersions: string
  /** 触发一轮新周期（由 upstream-radar apply 注入，调用内建 poll 全链）。 */
  refresh(): void | Promise<void>
  /**
   * 用户经面板手动触发的升级/评估请求（由 upstream-radar apply 注入）。
   * host 侧**不执行任何安装**，只把消息发给接收会话（agent 执行）：
   *   kind='upgrade' 请 agent 直接升级；kind='assess' 请 agent 先评估（用于有兼容风险的候选）。
   * 未注入时该路由返回 503。
   */
  requestUpgrade?(request: {
    plugin: string
    fromVersion: string | null
    toVersion: string
    kind: 'upgrade' | 'assess'
  }): Promise<{ delivered: boolean; note?: string }>
}

export type JobKind = 'inspect' | 'review' | 'refresh'
export type JobStatus = 'running' | 'done' | 'failed'

export interface RadarPanelJob {
  id: string
  kind: JobKind
  status: JobStatus
  startedAt: string
  finishedAt?: string | undefined
  target?: string | undefined
  output: string
  exitCode?: number
}

/** 进程内 job 登记表（跨挂载共享；落盘仍有 jobsDir 兜底）。 */
const jobs = new Map<string, RadarPanelJob>()

/* ------------------------------------------------------------------ 状态读取 */

async function readJson(path: string): Promise<Record<string, unknown> | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
  } catch {
    return undefined
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function json(res: ResponseLike, code: number, body: unknown): void {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}

async function readBody(req: RequestLike): Promise<Record<string, unknown> | undefined> {
  return await new Promise((resolve) => {
    let data = ''
    req.on('data', (chunk?: Buffer) => { if (chunk !== undefined) data += chunk.toString('utf8') })
    req.on('end', () => {
      try { resolve(data.length > 0 ? JSON.parse(data) : {}) } catch { resolve(undefined) }
    })
  })
}

/** radar state 摘要（面板首屏）。 */
async function statusSummary(opts: RadarPanelOptions): Promise<unknown> {
  const [state, config, resultFailures] = await Promise.all([
    readJson(opts.stateFile),
    readJson(opts.configFile),
    readAnalysisResultFailures(opts.stateFile),
  ])
  if (state === undefined) {
    return { radarRunning: false, hint: 'radar state 不存在（插件未运行或首轮未完成）' }
  }
  const mtime = await stat(opts.stateFile).catch(() => undefined)
  const projects = Array.isArray(config?.projects) ? config.projects : []
  const firstProject = (projects[0] ?? {}) as { project?: unknown; plugins?: unknown }
  const plugins = Array.isArray(firstProject.plugins) ? firstProject.plugins : []
  return {
    radarRunning: true,
    stateMtime: mtime?.mtime?.toISOString() ?? null,
    radarCycleAgeSec: mtime?.mtime ? Math.round((Date.now() - mtime.mtime.getTime()) / 1000) : null,
    project: (firstProject.project as { name?: string } | undefined)?.name ?? null,
    pluginsMonitored: plugins.length,
    activeVulnerabilities: Object.keys(state.activeVulnerabilities ?? {}).length,
    activeCompatibility: Object.keys(state.activeCompatibility ?? {}).length,
    pendingTasks: Array.isArray(state.pendingAnalysisTasks) ? state.pendingAnalysisTasks.length : 0,
    deliveries: Object.keys(state.analysisDeliveries ?? {}).length,
    results: Object.keys(state.analysisResults ?? {}).length,
    resultFailures: resultFailures.length,
    sourceHealth: Object.keys(state.sourceHealth ?? {}).length,
  } as Record<string, unknown>
}

/**
 * 到达但未被接受的答复（verdict 校验失败）。
 *
 * 没有这个出口，被丢弃的结论在面板上完全不可见：投递只是"一直挂着"，
 * 看不出是 agent 没回、还是回了但没通过校验。
 */
async function resultFailureList(opts: RadarPanelOptions): Promise<unknown[]> {
  const failures = await readAnalysisResultFailures(opts.stateFile)
  return failures
    .slice()
    .sort((left, right) => right.detectedAt.localeCompare(left.detectedAt))
    .map(failure => ({
      sessionId: failure.sessionId,
      assistantSeq: failure.assistantSeq,
      incidentIds: failure.incidentIds,
      detectedAt: failure.detectedAt,
      outcome: failure.outcome,
      detail: failure.detail ?? null,
      attempt: failure.attempt,
      unrecoverable: failure.unrecoverable === true,
    }))
}

/** 一条"已被评估的候选版本"（不含事件头条 candidate 自身）。 */
export interface RadarEvaluatedVersion {
  version: string
  status: 'blocked' | 'unblocked'
  /** 是否比事件头条候选（npm `latest`）还新——这正是"只在 next/预发布通道"的那类。 */
  newerThanCandidate: boolean
  /** 阻断理由（首个 signal 的 code），仅 blocked 有。 */
  reason?: string
}

/**
 * 把 upgradePath 里"除头条候选之外"的已评估版本摊平出来。
 *
 * 起因（2026-09-12）：`candidate` 取的是 npm `dist-tags.latest`，所以挂在
 * `next`（或别的通道）上的更新版本——例如 DSH 0.1.5-rc.2（latest=0.1.5-rc.1）——
 * 虽然**已被完整评估**（evaluated 计数含它、blocked 数组含它、agent 结论也覆盖
 * 它），却不出现在面板任何位置，只能去读 state JSON 才发现。这里把它带出来。
 *
 * 注意 `upgradePath.blocked` 只存**前 8 个**被阻断的候选，所以 evaluated 大于
 * 已列条数时差额用 unlistedEvaluated 如实报出，不假装列全了。
 */
function evaluatedVersions(event: Record<string, unknown>): {
  evaluated: number
  blockedCount: number
  unlistedEvaluated: number
  versions: RadarEvaluatedVersion[]
} | undefined {
  const upgradePath = asRecord(event.upgradePath)
  if (upgradePath === undefined) return undefined
  const headline = ((event.candidate ?? {}) as { version?: string }).version ?? null
  const evaluated = typeof upgradePath.evaluated === 'number' ? upgradePath.evaluated : 0
  const blockedCount = typeof upgradePath.blockedCount === 'number' ? upgradePath.blockedCount : 0
  const isNewer = (version: string): boolean => (
    headline === null ? true : (compareReleaseVersions(version, headline) ?? 0) > 0
  )
  const versions: RadarEvaluatedVersion[] = []
  const seen = new Set<string>()
  const push = (version: unknown, status: RadarEvaluatedVersion['status'], reason?: unknown): void => {
    if (typeof version !== 'string' || version === '' || version === headline || seen.has(version)) return
    seen.add(version)
    const code = (asRecord(reason)?.code ?? undefined)
    versions.push({
      version,
      status,
      newerThanCandidate: isNewer(version),
      ...(typeof code === 'string' ? { reason: code } : {}),
    })
  }
  const blocked = Array.isArray(upgradePath.blocked) ? upgradePath.blocked : []
  for (const entry of blocked) {
    const assessed = asRecord(entry)
    const candidate = asRecord(assessed?.candidate)
    const signals = Array.isArray(assessed?.signals) ? assessed.signals : []
    push(candidate?.version, 'blocked', signals[0])
  }
  const first = asRecord(asRecord(upgradePath.firstCandidate)?.candidate ?? undefined)
  if (first?.version !== undefined) push(first.version, 'unblocked')
  // 候选比"已列出的"多，就是 blocked 只存前 8 个造成的；如实报差额。
  const unlistedEvaluated = Math.max(0, evaluated - versions.length - (headline === null ? 0 : 1))
  return { evaluated, blockedCount, unlistedEvaluated, versions }
}

/** 活跃事件明细。 */
async function eventList(opts: RadarPanelOptions): Promise<unknown[]> {
  const state = await readJson(opts.stateFile)
  if (state === undefined) return []
  const out: unknown[] = []
  const vulns = (state.activeVulnerabilities ?? {}) as Record<string, { event?: Record<string, unknown> }>
  for (const [id, entry] of Object.entries(vulns)) {
    const event = entry?.event ?? {}
    const installed = (event.installed ?? {}) as { name?: string; version?: string }
    const advisory = (event.advisory ?? {}) as { summary?: string; fixed_versions?: unknown }
    out.push({
      incidentId: id,
      kind: 'vulnerability',
      detectedAt: event.detectedAt ?? null,
      package: `${installed.name ?? '?'}@${installed.version ?? '?'}`,
      severity: event.severity ?? null,
      summary: String(advisory.summary ?? event.summary ?? event.title ?? '').slice(0, 200),
      fixedVersions: advisory.fixed_versions ?? null,
    })
  }
  const compat = (state.activeCompatibility ?? {}) as Record<string, { event?: Record<string, unknown> }>
  for (const [id, entry] of Object.entries(compat)) {
    const event = entry?.event ?? {}
    const installed = (event.installed ?? {}) as { name?: string; version?: string }
    const candidate = (event.candidate ?? {}) as { version?: string }
    const signals = Array.isArray(event.signals) ? event.signals : []
    const sorted = signals as Array<{ code?: string; summary?: string }>
    const upgrade = evaluatedVersions(event)
    out.push({
      incidentId: id,
      kind: 'compatibility',
      detectedAt: event.detectedAt ?? null,
      package: `${installed.name ?? '?'}@${installed.version ?? '?'}`,
      candidate: candidate.version ?? null,
      signals: sorted.slice(0, 4).map((signal) => signal.code),
      summary: String(sorted[0]?.summary ?? '').slice(0, 200),
      ...(upgrade === undefined ? {} : {
        upgradeEvaluated: upgrade.evaluated,
        upgradeBlockedCount: upgrade.blockedCount,
        upgradeUnlisted: upgrade.unlistedEvaluated,
        upgradeVersions: upgrade.versions.slice(0, 12),
      }),
    })
  }
  return out
}

/** 一条"上游新版本"信息。risk=compat 表示该候选触发兼容信号（活跃事件，待分析）；
 * risk=benign 表示良性候选（信息级通知，已投递 agent）。 */
export interface RadarRelease {
  plugin: string
  installedVersion: string | null
  candidateVersion: string | null
  notifiedAt: string | null
  risk: 'compat' | 'benign'
  /** 已评估但不等于 candidate 的版本（例如挂在 next 上的 0.1.5-rc.2）。 */
  upgradeVersions?: RadarEvaluatedVersion[]
  upgradeEvaluated?: number
  upgradeBlockedCount?: number
  upgradeUnlisted?: number
}

/**
 * 当前已装版本（来自监控清单）。
 *
 * 返回 undefined 表示清单读不出来——此时**不做过滤**，宁可多显示也不要把整个
 * 区块静默清空。清单可读时，不在清单里的插件视为已不在监控范围。
 */
async function installedVersions(opts: RadarPanelOptions): Promise<Map<string, string> | undefined> {
  const config = await readJson(opts.configFile)
  if (config === undefined) return undefined
  const projects = Array.isArray(config.projects) ? config.projects : []
  const installed = new Map<string, string>()
  for (const project of projects) {
    const plugins = (project as { plugins?: unknown }).plugins
    if (!Array.isArray(plugins)) continue
    for (const plugin of plugins) {
      const pkg = (plugin as { package?: { name?: unknown; version?: unknown } }).package
      if (typeof pkg?.name === 'string' && pkg.name !== '' && typeof pkg?.version === 'string' && pkg.version !== '') {
        installed.set(pkg.name, pkg.version)
      }
    }
  }
  return installed
}

/**
 * 比较两个上游/已装版本，容忍 `1.2` 这类两段写法。
 *
 * `compareSemverValues` 对部分版本返回 undefined，面板里若直接用它会把
 * 「1.1 vs 1.2」判成不可比较，从而把陈旧行留下。
 */
function compareReleaseVersions(candidate: string, current: string): number | undefined {
  const left = parseSemver(candidate, true)
  const right = parseSemver(current, true)
  if (left === undefined || right === undefined) return undefined
  return compareSemver(left, right)
}

/**
 * 这一行是否还值得行动：候选必须**严格新于当前已装版本**。
 *
 * 良性通知的 sidecar 是只增不减的台账，升级完成后旧行会永久滞留（实际出现过
 * 「web-all 0.3.18→0.3.19」这种本机早已是 0.3.19 的历史行堆在面板上）。
 * 面板是"当前状态"视图，历史留在 sidecar 文件里即可。
 */
function stillActionable(
  candidate: string,
  plugin: string,
  installed: Map<string, string> | undefined,
): { keep: boolean; current: string | undefined } {
  if (installed === undefined) return { keep: true, current: undefined }
  const current = installed.get(plugin)
  if (current === undefined) return { keep: false, current: undefined }
  // 已装到同一个版本：无论能否解析，都必然不再需要行动。
  if (candidate === current) return { keep: false, current }
  const comparison = compareReleaseVersions(candidate, current)
  // 真正解析不了（如 latest/next 之类）时不猜，保留以免漏掉真实升级。
  return { keep: comparison === undefined ? true : comparison > 0, current }
}

/** 上游新版本清单：合并良性候选（release-notices sidecar）与有兼容风险的候选（activeCompatibility）。 */
async function releaseList(opts: RadarPanelOptions): Promise<RadarRelease[]> {
  const [state, installed] = await Promise.all([readJson(opts.stateFile), installedVersions(opts)])
  const byKey = new Map<string, RadarRelease>()
  // 良性候选来自 sidecar（informational 通知，去重标记 key 编码 project|plugin|pv|installed|iv|candidate|cv）。
  const sidecar = await readJson(`${opts.stateFile}.release-notices.json`)
  if (sidecar !== undefined) {
    for (const [key, meta] of Object.entries(sidecar)) {
      const parts = key.split('|')
      if (parts.length < 7) continue
      const plugin = parts[3] ?? ''
      const candidate = parts[6] ?? ''
      if (plugin === '' || candidate === '') continue
      const verdict = stillActionable(candidate, plugin, installed)
      if (!verdict.keep) continue
      const marker = (meta as { notifiedAt?: unknown } | undefined) ?? {}
      const rec: RadarRelease = {
        plugin,
        // 显示"当前已装"而非通知当时的版本，否则跨度会与现状不符。
        installedVersion: verdict.current ?? null,
        candidateVersion: candidate,
        notifiedAt: typeof marker.notifiedAt === 'string' ? marker.notifiedAt : null,
        risk: 'benign',
      }
      const key2 = `${plugin}|${candidate}`
      const existing = byKey.get(key2)
      // 若该候选已作为兼容事件存在，则标记为 compat（风险优先）。
      byKey.set(key2, existing === undefined ? rec : existing.risk === 'compat' ? existing : { ...rec, risk: existing.risk })
    }
  }
  // 有兼容风险的候选来自 activeCompatibility。
  const compat = (state?.activeCompatibility ?? {}) as Record<string, { event?: Record<string, unknown> }>
  for (const [, entry] of Object.entries(compat)) {
    const event = entry?.event ?? {}
    const eventInstalled = (event.installed ?? {}) as { name?: string; version?: string }
    const candidate = (event.candidate ?? {}) as { version?: string }
    const plugin = eventInstalled.name ?? ''
    const candidateVersion = candidate.version ?? ''
    if (plugin === '' || candidateVersion === '') continue
    const verdict = stillActionable(candidateVersion, plugin, installed)
    if (!verdict.keep) continue
    const upgrade = evaluatedVersions(event)
    byKey.set(`${plugin}|${candidateVersion}`, {
      plugin,
      installedVersion: verdict.current ?? eventInstalled.version ?? null,
      candidateVersion,
      notifiedAt: typeof event.detectedAt === 'string' ? event.detectedAt : null,
      risk: 'compat',
      ...(upgrade === undefined ? {} : {
        upgradeVersions: upgrade.versions.slice(0, 12),
        upgradeEvaluated: upgrade.evaluated,
        upgradeBlockedCount: upgrade.blockedCount,
        upgradeUnlisted: upgrade.unlistedEvaluated,
      }),
    })
  }
  return [...byKey.values()].sort((a, b) => String(b.notifiedAt ?? '').localeCompare(String(a.notifiedAt ?? '')))
}

/** 装前审查/触发 的共享 job 执行器：内存 + 原子落盘，输出截断保界。 */
function startJob(
  opts: RadarPanelOptions,
  kind: JobKind,
  target: string | undefined,
  args: string[],
): RadarPanelJob | { error: string } {
  const running = Array.from(jobs.values()).filter(job => job.status === 'running').length
  if (running >= opts.maxJobs) return { error: `并发 job 已达上限（${opts.maxJobs}），请等待完成` }
  const id = createHash('sha256').update(`${kind}\0${target ?? ''}\0${Date.now()}\0${Math.random()}`).digest('hex').slice(0, 12)
  const job: RadarPanelJob = {
    id,
    kind,
    status: 'running',
    startedAt: new Date().toISOString(),
    target,
    output: '',
  }
  jobs.set(id, job)
  const persist = async (): Promise<void> => {
    try {
      await mkdir(opts.jobsDir, { recursive: true })
      const tmp = join(opts.jobsDir, `${id}.json.tmp`)
      await writeFile(tmp, JSON.stringify(job))
      await rename(tmp, join(opts.jobsDir, `${id}.json`))
    } catch { /* 磁盘写失败不影响内存 job */ }
  }
  void persist()
  const child = spawn(process.execPath, args, { cwd: opts.radarDir, stdio: ['ignore', 'pipe', 'pipe'] })
  const push = (chunk: Buffer): void => { job.output = (job.output + chunk.toString('utf8')).slice(-64 * 1024) }
  child.stdout?.on('data', push)
  child.stderr?.on('data', push)
  const timer = setTimeout(() => { try { child.kill('SIGKILL') } catch { /* ignore */ } }, 15 * 60_000)
  child.on('close', (code) => {
    clearTimeout(timer)
    job.status = code === 0 ? 'done' : 'failed'
    job.exitCode = code ?? -1
    job.finishedAt = new Date().toISOString()
    void persist()
  })
  return job
}

/* ------------------------------------------------------------------ 路由注册 */

export function registerRadarPanelApi(webServer: WebServerLike, opts: RadarPanelOptions): () => void {
  const BASE = '/@dsh-external/upstream-radar'
  const routes: Array<{ kind: 'prefix' | 'exact'; path: string; handler: (req: RequestLike, res: ResponseLike) => void | Promise<void> }> = []

  const handle = (method: 'GET' | 'POST', sub: string, fn: (req: RequestLike, res: ResponseLike) => unknown | Promise<unknown>): void => {
    routes.push({
      kind: 'prefix',
      path: `${BASE}${sub}`,
      handler: async (req, res) => {
        const reqMethod = (req.method ?? 'GET').toUpperCase()
        if (reqMethod !== method && !(method === 'GET' && reqMethod === 'HEAD')) {
          json(res, 405, { error: 'method not allowed' })
          return
        }
        try {
          await fn(req, res)
        } catch (error: unknown) {
          json(res, 500, { error: error instanceof Error ? error.message : String(error) })
        }
      },
    })
  }

  handle('GET', '/api/status', async (_req, res) => { json(res, 200, await statusSummary(opts)) })
  handle('GET', '/api/events', async (_req, res) => { json(res, 200, { events: await eventList(opts) }) })
  handle('GET', '/api/tasks', async (_req, res) => {
    const state = await readJson(opts.stateFile)
    const tasks = Array.isArray(state?.pendingAnalysisTasks) ? state.pendingAnalysisTasks : []
    json(res, 200, {
      tasks: tasks.map((task: Record<string, unknown>) => {
        const event = (task.event ?? {}) as { kind?: string; installed?: { name?: string; version?: string }; project?: { workspace?: string } }
        const installed = event.installed ?? {}
        return {
          id: task.id,
          kind: event.kind ?? null,
          package: `${installed.name ?? '?'}@${installed.version ?? '?'}`,
          createdAt: task.createdAt ?? null,
          workspace: event.project?.workspace ?? null,
        }
      }),
    })
  })
  handle('GET', '/api/results', async (_req, res) => {
    const state = await readJson(opts.stateFile)
    const results = (state?.analysisResults ?? {}) as Record<string, Record<string, unknown>>
    json(res, 200, {
      results: Object.values(results).map((result) => ({
        incidentId: result.incidentId ?? null,
        receivedAt: result.receivedAt ?? null,
        exposure: result.project_exposure ?? null,
        confidence: result.confidence ?? null,
        urgency: result.urgency ?? null,
        action: String(result.recommended_action ?? '').slice(0, 300),
      })),
    })
  })
  handle('GET', '/api/result-failures', async (_req, res) => {
    json(res, 200, { failures: await resultFailureList(opts) })
  })
  handle('GET', '/api/inventory', async (_req, res) => {
    const config = await readJson(opts.configFile)
    const projects = Array.isArray(config?.projects) ? config.projects : []
    const first = (projects[0] ?? {}) as { plugins?: unknown }
    const plugins = Array.isArray(first.plugins) ? first.plugins : []
    json(res, 200, {
      plugins: plugins.map((plugin: Record<string, unknown>) => {
        const pkg = (plugin.package ?? {}) as { name?: string; version?: string }
        const graph = (plugin.graph ?? {}) as { nodes?: unknown[]; edges?: unknown[] }
        return {
          name: pkg.name ?? null,
          version: pkg.version ?? null,
          graphNodes: Array.isArray(graph.nodes) ? graph.nodes.length : 0,
          graphEdges: Array.isArray(graph.edges) ? graph.edges.length : 0,
        }
      }),
    })
  })
  handle('GET', '/api/releases', async (_req, res) => {
    json(res, 200, { releases: await releaseList(opts) })
  })

  // 用户手动触发：把"升级/评估 <plugin> 到 <ver>"作为消息发给接收会话（agent 执行）。
  // host 不执行安装；仅接受当前真实候选（plugin+candidateVersion 必须出现在 /api/releases）。
  handle('POST', '/api/upgrade-request', async (req, res) => {
    const body = await readBody(req)
    if (body === undefined) { json(res, 400, { error: 'invalid JSON body' }); return }
    const plugin = String(body.plugin ?? '').trim()
    const toVersion = String(body.toVersion ?? '').trim()
    const kind = body.kind === 'assess' ? 'assess' : 'upgrade'
    if (plugin === '' || toVersion === '') { json(res, 400, { error: 'plugin 与 toVersion 必填' }); return }
    // 只允许对"当前真实候选"发起（防止任意输入被当作升级指令转发给 agent）。
    const releases = await releaseList(opts)
    const match = releases.find(r => r.plugin === plugin && r.candidateVersion === toVersion)
    if (match === undefined) { json(res, 404, { error: `未找到候选：${plugin} → ${toVersion}（不在当前上游新版本列表内）` }); return }
    if (opts.requestUpgrade === undefined) { json(res, 503, { error: '升级请求通道未启用（host 未注入 requestUpgrade）' }); return }
    try {
      const outcome = await opts.requestUpgrade({
        plugin,
        fromVersion: match.installedVersion,
        toVersion,
        kind,
      })
      json(res, outcome.delivered ? 200 : 502, {
        delivered: outcome.delivered,
        kind,
        plugin,
        toVersion,
        fromVersion: match.installedVersion,
        risk: match.risk,
        note: outcome.note ?? (outcome.delivered
          ? (kind === 'assess' ? '已把"先评估"请求发给接收会话' : '已把升级请求发给接收会话')
          : '未能送达接收会话'),
      })
    } catch (error: unknown) {
      json(res, 500, { error: error instanceof Error ? error.message : String(error) })
    }
  })
  handle('GET', '/api/jobs', async (_req, res) => {
    json(res, 200, {
      jobs: Array.from(jobs.values()).map(job => ({
        id: job.id, kind: job.kind, status: job.status, target: job.target ?? null,
        startedAt: job.startedAt, finishedAt: job.finishedAt ?? null,
      })),
    })
  })
  handle('GET', '/api/job', async (req, res) => {
    const id = new URL(req.url ?? '', 'http://dsh.invalid').searchParams.get('id')
    const job = jobs.get(id ?? '')
    if (job === undefined) { json(res, 404, { error: 'job not found' }); return }
    json(res, 200, job)
  })

  // 主动触发①：跑一轮完整全链（poll + 保存 + 投递），不重建 loader 入口。
  handle('POST', '/api/refresh', async (_req, res) => {
    try {
      await opts.refresh()
      json(res, 200, { note: '新周期已触发，约 30-90s 后 state 更新' })
    } catch (error: unknown) {
      json(res, 500, { error: error instanceof Error ? error.message : String(error) })
    }
  })

  // 主动触发②：装前静态审查（inspect --deep；lifecycle scripts 禁用，不执行插件代码）。
  handle('POST', '/api/inspect', async (req, res) => {
    const body = await readBody(req)
    if (body === undefined) { json(res, 400, { error: 'invalid JSON body' }); return }
    const target = String(body.target ?? '').trim()
    if (!/^(npm:)?(@[\w.-]+\/)?[\w.-]+@[^\s@]+$/.test(target)) {
      json(res, 400, { error: 'target 必须是 包名@精确版本（npm: 前缀可选）' })
      return
    }
    const job = startJob(opts, 'inspect', target, [opts.cliPath, 'inspect', target, '--deep', '--fail-on', 'never'])
    if ('error' in job) { json(res, 429, job); return }
    json(res, 200, { job })
  })

  // 主动触发③：装前加载矩阵（review dsh-plugin；临时 profile 真实加载，不碰 live profile）。
  handle('POST', '/api/review', async (req, res) => {
    const body = await readBody(req)
    if (body === undefined) { json(res, 400, { error: 'invalid JSON body' }); return }
    const target = String(body.target ?? '').trim()
    if (!/^(npm:)?(@[\w.-]+\/)?[\w.-]+@[^\s@]+$/.test(target)) {
      json(res, 400, { error: 'target 必须是 包名@精确版本（npm: 前缀可选）' })
      return
    }
    const versions = String(body.dshVersions ?? opts.reviewDshVersions).trim()
    const job = startJob(opts, 'review', target, [opts.cliPath, 'review', 'dsh-plugin', target, '--dsh-version', versions])
    if ('error' in job) { json(res, 429, job); return }
    json(res, 200, { job })
  })

  const disposers = routes.map(route => webServer.register(route))
  return () => { for (const dispose of disposers) dispose() }
}
