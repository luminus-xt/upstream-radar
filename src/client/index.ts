/**
 * upstream-radar 可视化面板（client 侧，Web GUI 设置 → 插件 分页）。
 *
 * 注册进 `settings.plugins.tab`（list 型，id `upstream-radar`），通过同源
 * `/@dsh-external/upstream-radar/api` HTTP 路由拉取状态/事件/任务/结论/清单，
 * 三个手动动作（刷新新周期 / inspect / review），长任务后台 job 轮询取结果。
 *
 * 组件协议：React 函数组件（react/jsx-runtime 经 tsdown neverBundle 外部化，
 * 运行时由框架 require 注入）——这是 slots 的真实契约。
 */
/// <reference types="react" />

interface SlotRegistration {
  name: string
  id: string
  order?: number
  label?: () => string
  locale?: string
  inject?: () => unknown
}

interface SlotsLike {
  inject(slot: string, factory: () => () => void): () => void
  register(registration: SlotRegistration, component: (props: Record<string, unknown>) => unknown): () => void
}

type ClientContext = {
  slots: SlotsLike
  effect(setup: () => void | (() => void), label?: string): void
  logger?: { info(message: string): void; warn(message: string): void }
}

export const inject = ['slots']

// tsdown neverBundle 的 react 外部：require('react') / require('react/jsx-runtime')
// 由 ModuleLoader factory 注入的 require 提供（与 agent-teams client 相同通道）。
// eslint-disable-next-line @typescript-eslint/no-var-requires
const React = require('react') as typeof import('react')
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jsxRuntime = require('react/jsx-runtime') as typeof import('react/jsx-runtime')
const { jsx, jsxs } = jsxRuntime

const API = '/@dsh-external/upstream-radar/api'

interface StatusData {
  radarRunning?: boolean
  radarCycleAgeSec?: number | null
  pluginsMonitored?: number
  activeVulnerabilities?: number
  activeCompatibility?: number
  pendingTasks?: number
  deliveries?: number
  results?: number
  resultFailures?: number
  sourceHealth?: number
  hint?: string
}
interface EvaluatedVersion { version: string; status: string; newerThanCandidate: boolean; reason?: string }
interface EventRow {
  incidentId: string; kind: string; package: string; candidate?: string | null; severity?: string | null
  signals?: string[]; summary?: string
  upgradeEvaluated?: number; upgradeBlockedCount?: number; upgradeUnlisted?: number; upgradeVersions?: EvaluatedVersion[]
}
interface TaskRow { id: string; kind: string; package: string; createdAt?: string }
interface ResultRow { incidentId: string; receivedAt?: string; exposure: string; confidence: string; urgency: string; action: string }
interface InventoryRow { name: string; version?: string; graphNodes?: number; graphEdges?: number }
interface ReleaseRow {
  plugin: string; installedVersion?: string | null; candidateVersion?: string | null; notifiedAt?: string | null; risk?: 'compat' | 'benign'
  upgradeEvaluated?: number; upgradeBlockedCount?: number; upgradeUnlisted?: number; upgradeVersions?: EvaluatedVersion[]
}
interface JobState { id: string; kind: string; status: string; target?: string | null; output?: string; exitCode?: number }
interface FailureRow { sessionId: string; assistantSeq: number; incidentIds: string[]; detectedAt: string; outcome: string; detail?: string | null; attempt?: number; unrecoverable?: boolean; recoveredAt?: string | null }

/** 校验失败原因的可读标签（取值由 host 侧 outcome 枚举决定）。 */
const FAILURE_LABEL: Record<string, string> = {
  'oversized-text': '文本超长',
  'json-syntax-error': 'JSON 语法错误',
  'contract-mismatch': '不符合字段契约',
  'ambiguous-candidates': '候选不唯一',
}

async function api<T = unknown>(path: string, init?: RequestInit): Promise<T | undefined> {
  try {
    const response = await fetch(API + path, { headers: { 'content-type': 'application/json' }, ...init })
    if (!response.ok) return undefined
    return (await response.json()) as T
  } catch {
    return undefined
  }
}

const useInterval = (fn: () => void, ms: number, active: boolean): void => {
  React.useEffect(() => {
    if (!active) return
    const timer = window.setInterval(fn, ms)
    return () => window.clearInterval(timer)
  }, [fn, ms, active])
}

/** 状态 + 数据刷新 hook。 */
function useRadarData(): {
  status: StatusData | undefined
  events: EventRow[]
  tasks: TaskRow[]
  results: ResultRow[]
  inventory: InventoryRow[]
  releases: ReleaseRow[]
  failures: FailureRow[]
  refresh: () => Promise<void>
} {
  const [status, setStatus] = React.useState<StatusData | undefined>(undefined)
  const [events, setEvents] = React.useState<EventRow[]>([])
  const [tasks, setTasks] = React.useState<TaskRow[]>([])
  const [results, setResults] = React.useState<ResultRow[]>([])
  const [inventory, setInventory] = React.useState<InventoryRow[]>([])
  const [releases, setReleases] = React.useState<ReleaseRow[]>([])
  const [failures, setFailures] = React.useState<FailureRow[]>([])
  const refresh = React.useCallback(async () => {
    const [s, e, t, r, i, rel, f] = await Promise.all([
      api<StatusData>('/status'),
      api<{ events: EventRow[] }>('/events'),
      api<{ tasks: TaskRow[] }>('/tasks'),
      api<{ results: ResultRow[] }>('/results'),
      api<{ plugins?: InventoryRow[] }>('/inventory'),
      api<{ releases?: ReleaseRow[] }>('/releases'),
      api<{ failures?: FailureRow[] }>('/result-failures'),
    ])
    if (s !== undefined) setStatus(s)
    if (e !== undefined) setEvents(e.events ?? [])
    if (t !== undefined) setTasks(t.tasks ?? [])
    if (r !== undefined) setResults(r.results ?? [])
    if (i !== undefined) setInventory(i.plugins ?? [])
    if (rel !== undefined) setReleases(rel.releases ?? [])
    if (f !== undefined) setFailures(f.failures ?? [])
  }, [])
  React.useEffect(() => { void refresh() }, [refresh])
  useInterval(() => { void refresh() }, 15000, true)
  return { status, events, tasks, results, inventory, releases, failures, refresh }
}

const KIND_COLOR: Record<string, string> = { vulnerability: '#ef4444', compatibility: '#f59e0b' }

const styles = {
  root: { padding: '20px 24px', fontSize: '13px', lineHeight: 1.6, overflow: 'auto', height: '100%' } as React.CSSProperties,
  head: { display: 'flex', alignItems: 'baseline', gap: '12px', marginBottom: '14px', flexWrap: 'wrap' } as React.CSSProperties,
  h1: { fontSize: '18px', fontWeight: 700, margin: 0 } as React.CSSProperties,
  sub: { opacity: 0.7 } as React.CSSProperties,
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: '8px', margin: '10px 0 18px' } as React.CSSProperties,
  stat: { border: '1px solid rgba(128,128,128,.35)', borderRadius: '10px', padding: '8px 12px' } as React.CSSProperties,
  statNum: { fontSize: '22px', fontWeight: 700, display: 'block' } as React.CSSProperties,
  statLabel: { fontSize: '11px', opacity: 0.7 } as React.CSSProperties,
  section: { margin: '18px 0 8px', fontWeight: 600, opacity: 0.8 } as React.CSSProperties,
  card: { border: '1px solid rgba(128,128,128,.3)', borderRadius: '10px', padding: '9px 12px', marginBottom: '6px' } as React.CSSProperties,
  pkg: { fontWeight: 600 } as React.CSSProperties,
  meta: { fontSize: '11.5px', opacity: 0.75 } as React.CSSProperties,
  tag: (kind: string): React.CSSProperties => ({ display: 'inline-block', fontSize: '10px', padding: '1px 7px', borderRadius: '999px', border: `1px solid ${KIND_COLOR[kind] ?? '#888'}`, color: KIND_COLOR[kind] ?? '#888', marginRight: '6px' }),
  row: { display: 'flex', gap: '8px', flexWrap: 'wrap', margin: '8px 0' } as React.CSSProperties,
  btn: { fontSize: '13px', padding: '6px 14px', borderRadius: '9px', border: '1px solid rgba(128,128,128,.45)', background: 'rgba(128,128,128,.1)', cursor: 'pointer' } as React.CSSProperties,
  input: { fontSize: '13px', padding: '6px 10px', borderRadius: '9px', border: '1px solid rgba(128,128,128,.45)', background: 'transparent', color: 'inherit', minWidth: '300px' } as React.CSSProperties,
  pre: { whiteSpace: 'pre-wrap', fontFamily: 'ui-monospace, monospace', fontSize: '11px', maxHeight: '300px', overflow: 'auto', border: '1px solid rgba(128,128,128,.25)', borderRadius: '9px', padding: '10px', marginTop: '8px' } as React.CSSProperties,
  muted: { opacity: 0.55 } as React.CSSProperties,
  /** 「比候选更新的已评估版本」这类需要被看见的信息（如 next 通道的 0.1.5-rc.2）。 */
  warnMeta: { fontSize: '11.5px', color: '#f59e0b', marginTop: '2px' } as React.CSSProperties,
  invGrid: { display: 'flex', flexWrap: 'wrap', gap: '6px' } as React.CSSProperties,
  invChip: (active: boolean): React.CSSProperties => ({
    display: 'inline-flex', flexDirection: 'column', fontSize: '11.5px', lineHeight: 1.35,
    border: `1px solid ${active ? 'rgba(245,158,11,.65)' : 'rgba(128,128,128,.3)'}`, borderRadius: '8px',
    padding: '5px 9px', background: active ? 'rgba(245,158,11,.08)' : 'transparent',
  }),
  invName: { fontWeight: 600, opacity: 0.92 } as React.CSSProperties,
  invMeta: { fontSize: '10px', opacity: 0.62 } as React.CSSProperties,
  riskBadge: (risk: 'compat' | 'benign'): React.CSSProperties => ({
    display: 'inline-block', fontSize: '10px', padding: '1px 7px', borderRadius: '999px', marginRight: '8px',
    border: `1px solid ${risk === 'compat' ? '#f59e0b' : '#22c55e'}`,
    color: risk === 'compat' ? '#f59e0b' : '#22c55e',
  }),
}

/**
 * 「已评估候选」小字（事件卡与上游新版本行共用）。
 *
 * 存在理由：事件头条 `candidate` 取的是 npm `dist-tags.latest`，因此挂在 `next`
 * 等通道上的更新版本（如 DSH 0.1.5-rc.2，latest 是 0.1.5-rc.1）虽然已被 radar
 * 完整评估、agent 也出过结论，却在面板上完全不可见。这里把它摊出来。
 */
const EvaluatedLine = (row: {
  upgradeEvaluated?: number
  upgradeBlockedCount?: number
  upgradeUnlisted?: number
  upgradeVersions?: EvaluatedVersion[]
}) => {
  const versions = row.upgradeVersions ?? []
  const newer = versions.filter(v => v.newerThanCandidate)
  const children: React.ReactNode[] = []
  if (row.upgradeEvaluated !== undefined) {
    children.push(jsx('div', { style: styles.meta, children: `候选已评估 ${row.upgradeEvaluated} 个 · 阻断 ${row.upgradeBlockedCount ?? 0} 个${row.upgradeUnlisted ? ` · 另有 ${row.upgradeUnlisted} 个未列出` : ''}` }))
  }
  if (newer.length > 0) {
    children.push(jsx('div', { style: styles.warnMeta, children: `⚠ 比候选更新且已评估：${newer.map(v => `${v.version}（${v.status === 'blocked' ? '阻断' : '未阻断'}）`).join('、')}` }))
  } else if (versions.length > 0) {
    children.push(jsx('div', { style: styles.meta, children: `同时评估：${versions.map(v => v.version).join('、')}` }))
  }
  return children.length === 0 ? null : jsx('div', { children })
}

const Stat = ({ n, label }: { n: React.ReactNode; label: string }) => jsx('div', { style: styles.stat, children: jsxs('div', { children: [jsx('span', { style: styles.statNum, children: n }), jsx('span', { style: styles.statLabel, children: label })] }) })

const EventCard = (e: EventRow) => jsxs('div', { style: styles.card, children: [
  jsx('span', { style: styles.tag(e.kind), children: e.kind }),
  jsx('span', { style: styles.pkg, children: `${e.package}${e.candidate ? ` → ${e.candidate}` : ''}` }),
  e.severity !== undefined && e.severity !== null ? jsx('div', { style: styles.meta, children: `severity: ${e.severity}` }) : null,
  e.signals?.length ? jsx('div', { style: styles.meta, children: `信号: ${e.signals.join(', ')}` }) : null,
  e.summary ? jsx('div', { style: styles.meta, children: e.summary }) : null,
  jsx(EvaluatedLine, { ...e }),
] })

/**
 * 监控插件清单中的一个 chip（有活跃事件的插件高亮）。
 *
 * 必须以**单个 props 对象**接收：React 只按 `(props, legacyContext)` 调用函数组件，
 * 写成 `(row, hasEvent)` 时第二个参数恒为 legacy context（`{}`，恒真），
 * 会让每个 chip 都带 ⚠ 并全部走高亮样式。判定用 `=== true` 兜底非布尔入参。
 */
const InvChip = (props: InventoryRow & { hasEvent: boolean }) => {
  const { hasEvent, ...row } = props
  const active = hasEvent === true
  return jsxs('span', { style: styles.invChip(active), children: [
    jsx('span', { style: styles.invName, children: row.name }),
    jsx('span', { style: styles.invMeta, children: `${row.version ?? '?'} · ${row.graphNodes ?? 0}n/${row.graphEdges ?? 0}e${active ? ' · ⚠' : ''}` }),
  ] })
}

/** 上游新版本行：插件、版本跨度、风险徽标，以及手动 [升级]/[让 agent 评估] 按钮。 */
const ReleaseLine = (props: ReleaseRow & { onRequest?: (row: ReleaseRow, kind: 'upgrade' | 'assess') => void }) => {
  const isCompat = props.risk === 'compat'
  const onRequest = props.onRequest
  return jsxs('div', { style: styles.card, children: [
    jsxs('div', { style: styles.meta, children: [
      jsx('span', { style: styles.riskBadge(isCompat ? 'compat' : 'benign'), children: isCompat ? '兼容风险' : '良性' }),
      jsx('span', { style: styles.pkg, children: props.plugin }),
      jsx('span', { children: ` ${props.installedVersion ?? '?'} → ${props.candidateVersion ?? '?'}` }),
      props.notifiedAt ? jsx('span', { style: styles.muted, children: ` · ${String(props.notifiedAt).slice(0, 19)}` }) : null,
    ] }),
    jsx(EvaluatedLine, { ...props }),
    onRequest !== undefined && props.candidateVersion
      ? jsx('div', { style: styles.row, children: jsx('button', {
          style: styles.btn,
          onClick: () => onRequest(props, isCompat ? 'assess' : 'upgrade'),
          children: isCompat ? '🧭 让 agent 评估' : `⬆ 升级到 ${props.candidateVersion}`,
        }) })
      : null,
  ] })
}

/** 装前审查区块：输入 + inspect/review 按钮 + job 轮询输出。 */
function PreInstallSection() {
  const [target, setTarget] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [output, setOutput] = React.useState<string | undefined>(undefined)
  const [jobInfo, setJobInfo] = React.useState<JobState | undefined>(undefined)

  React.useEffect(() => {
    if (jobInfo?.status !== 'running') return
    const timer = window.setInterval(async () => {
      const job = await api<JobState>('/job?id=' + jobInfo.id)
      if (job !== undefined) {
        setJobInfo(job)
        setOutput(`【${job.kind}】${job.status}${job.exitCode !== undefined ? ` (exit ${job.exitCode})` : ''}\n目标: ${job.target ?? ''}\n\n${(job.output ?? '').split('\n').slice(-40).join('\n')}`)
        if (job.status !== 'running') setBusy(false)
      }
    }, 3000)
    return () => window.clearInterval(timer)
  }, [jobInfo])

  const run = async (endpoint: 'inspect' | 'review') => {
    if (!target.trim() || busy) return
    setBusy(true); setOutput(`提交中：${target} …`); setJobInfo(undefined)
    const started = await api<{ job?: JobState }>('/' + endpoint, { method: 'POST', body: JSON.stringify({ target: target.trim() }) })
    if (started?.job === undefined) { setOutput('提交失败（路由不可达）'); setBusy(false); return }
    setJobInfo(started.job)
    setOutput(`job ${started.job.id} 运行中…（inspect ~1min / review ~3-5min）`)
  }

  return jsxs('div', { children: [
    jsx('div', { style: styles.row, children: [
      jsx('input', { style: styles.input, placeholder: '包名@精确版本，如 @linxin666/dsh-web-all@0.3.14', value: target, onChange: (e: { target: { value: string } }) => setTarget(e.target.value), disabled: busy }),
      jsx('button', { style: styles.btn, disabled: busy, onClick: () => { void run('inspect') }, children: '🔍 inspect（静态审查）' }),
      jsx('button', { style: styles.btn, disabled: busy, onClick: () => { void run('review') }, children: '🧪 review（加载矩阵）' }),
    ] }),
    output !== undefined ? jsx('pre', { style: styles.pre, children: output }) : jsx('div', { style: styles.muted, children: '审查不执行插件代码（lifecycle scripts 禁用）；review 在一次性临时 profile 真实加载，不碰 live 环境。' }),
  ] })
}

/** 主面板（settings.plugins.tab slot 组件根）。 */
function RadarPanel() {
  const { status, events, tasks, results, inventory, releases, failures, refresh } = useRadarData()
  const [refreshing, setRefreshing] = React.useState(false)

  // 一次成功的纠错会让"已回收"的失败记录永久留在待办清单上，除非按 recoveredAt
  // 把它们区分开（host 侧在该投递被接受时写入该字段）。
  const unrecoveredFailures = failures.filter(f => f.recoveredAt == null)
  const recoveredFailures = failures.filter(f => f.recoveredAt != null)

  const doRefresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    await api('/refresh', { method: 'POST', body: '{}' })
    setTimeout(() => { void refresh() }, 2500); setTimeout(() => { void refresh() }, 45000); setTimeout(() => { void refresh() }, 95000)
    setTimeout(() => setRefreshing(false), 3000)
  }

  // 有活跃事件的监控插件集合（用于清单高亮）。
  const activePackages = React.useMemo(() => {
    const set = new Set<string>()
    for (const e of events) {
      if (!e.package) continue
      // 只剥**尾部**版本号：scoped 名（@scope/name@1.2.3）用 split('@')[0] 会得到空串，
      // 导致 scoped 包永远点不亮（2026-09-18 修复）。
      const at = e.package.lastIndexOf('@')
      set.add(at > 0 ? e.package.slice(0, at) : e.package)
    }
    return set
  }, [events])

  // 手动升级/评估请求：弹确认 → 把请求转发给接收会话（host 不执行安装）。
  const [requestMsg, setRequestMsg] = React.useState<string | undefined>(undefined)
  const requestUpgrade = async (row: ReleaseRow, kind: 'upgrade' | 'assess') => {
    const to = row.candidateVersion ?? ''
    const what = kind === 'assess' ? '请 agent 先评估' : '升级'
    if (!window.confirm(`确认${what}：${row.plugin} ${row.installedVersion ?? '?'} → ${to}？\n（仅把请求发给接收会话，由 agent 执行升级）`)) return
    setRequestMsg(`提交中：${row.plugin} → ${to} …`)
    const r = await api<{ delivered?: boolean; note?: string; error?: string }>('/upgrade-request', {
      method: 'POST',
      body: JSON.stringify({ plugin: row.plugin, toVersion: to, kind }),
    })
    if (r === undefined) { setRequestMsg('提交失败（路由不可达）'); return }
    setRequestMsg(r.error !== undefined ? `失败：${r.error}` : `${r.delivered === true ? '✅ ' : '⚠️ '}${r.note ?? '已处理'}`)
  }

  const stats: Array<[React.ReactNode, string]> = [
    [status?.pluginsMonitored ?? '–', '监控插件'],
    [status?.activeVulnerabilities ?? 0, '漏洞事件'],
    [status?.activeCompatibility ?? 0, '兼容事件'],
    [status?.pendingTasks ?? 0, '待分析'],
    [status?.results ?? 0, '结论'],
    [status?.radarCycleAgeSec !== null && status?.radarCycleAgeSec !== undefined ? (status.radarCycleAgeSec < 2400 ? `${status.radarCycleAgeSec}s 前` : 'stale') : '–', '上周期'],
  ]

  return jsxs('div', { style: styles.root, children: [
    jsxs('div', { style: styles.head, children: [
      jsx('h1', { style: styles.h1, children: '📡 Upstream Radar' }),
      jsx('span', { style: styles.sub, children: status?.radarRunning === true ? `运行中 · 每 30 分钟一周期 · 距今 ${status?.radarCycleAgeSec ?? '–'}s` : (status?.hint ?? '未运行') }),
      jsx('button', { style: styles.btn, disabled: refreshing, onClick: () => { void doRefresh() }, children: refreshing ? '刷新中…' : '🔄 刷新监控（新周期）' }),
    ] }),
    jsx('div', { style: styles.grid, children: stats.map(([n, label], i) => jsx(Stat, { n, label }, String(i))) }),
    jsx('div', { style: styles.muted, children: '数据每 30 分钟刷新一周期；此处状态反映最近一次周期，点“刷新监控”可立即触发新周期。' }),

    jsx('div', { style: styles.section, children: `监控插件清单（${inventory.length || (status?.pluginsMonitored ?? 0)}）` }),
    inventory.length === 0 ? jsx('div', { style: styles.muted, children: '（无清单数据，确认 radar 首轮已跑）' }) : jsxs('div', { style: styles.invGrid, children: inventory.map((row) => jsx(InvChip, { ...row, hasEvent: activePackages.has(row.name) }, row.name)) }),

    jsx('div', { style: styles.section, children: `上游新版本（${releases.length}）` }),
    releases.length === 0 ? jsx('div', { style: styles.muted, children: '（无已探测到的上游新版本）' }) : jsxs('div', { children: releases.map((row) => jsx(ReleaseLine, { ...row, onRequest: requestUpgrade }, `${row.plugin}|${row.candidateVersion ?? ''}`)) }),
    requestMsg !== undefined ? jsx('div', { style: styles.meta, children: requestMsg }) : null,

    jsx('div', { style: styles.section, children: '活跃事件' }),
    events.length === 0 ? jsx('div', { style: styles.muted, children: '（无）' }) : jsxs('div', { children: events.map((e) => jsx(EventCard, { ...e }, e.incidentId)) }),

    jsx('div', { style: styles.section, children: '待办分析任务（投递到 workspace 匹配的会话）' }),
    tasks.length === 0 ? jsx('div', { style: styles.muted, children: '（无）' }) : jsxs('div', { children: tasks.map((t) => jsxs('div', { style: styles.card, children: [
      jsx('span', { style: styles.pkg, children: t.package }),
      jsx('div', { style: styles.meta, children: `${t.kind ?? ''} · ${t.id.slice(0, 20)} · ${(t.createdAt ?? '').slice(0, 19)}` }),
    ], }, t.id)) }),

    jsx('div', { style: styles.section, children: '已回收的分析结论' }),
    results.length === 0 ? jsx('div', { style: styles.muted, children: '（无）' }) : jsxs('div', { children: results.map((r) => jsxs('div', { style: styles.card, children: [
      jsx('div', { style: styles.pkg, children: `${r.exposure ?? ''} · ${r.confidence ?? ''} · ${r.urgency ?? ''} · ${(r.receivedAt ?? '').slice(0, 19)}` }),
      jsx('div', { style: styles.meta, children: r.action }),
    ], }, r.incidentId)) }),

    // 到达但未被接受的答复：没有这个区块，被丢弃的结论在面板上完全不可见。
    // host 侧已对前两次失败自动补发纠错请求（attempt 1/2）；到第 3 次标 unrecoverable。
    // 已被纠错回收的条目不再计入"未回收"，只在尾部留一行弱化说明。
    jsx('div', { style: styles.section, children: `未回收的答复（校验失败 ${unrecoveredFailures.length}）` }),
    unrecoveredFailures.length === 0
      ? jsx('div', { style: styles.muted, children: '（无：所有投递要么已回收，要么仍在等待 agent 回复）' })
      : jsxs('div', { children: unrecoveredFailures.map((f) => jsxs('div', { style: styles.card, children: [
          jsx('div', { style: styles.pkg, children: `⚠ ${FAILURE_LABEL[f.outcome] ?? f.outcome}${f.unrecoverable === true ? ' · 已放弃（纠错预算用尽）' : ` · 第 ${f.attempt ?? 1} 次`}` }),
          jsx('div', { style: styles.meta, children: `${(f.detectedAt ?? '').slice(0, 19)} · ${f.sessionId.slice(0, 28)} · seq=${f.assistantSeq}` }),
          jsx('div', { style: styles.meta, children: `incident: ${f.incidentIds.join(', ')}${f.detail ? ` · ${f.detail}` : ''}` }),
        ], }, `${f.sessionId}|${f.assistantSeq}`)) }),
    recoveredFailures.length > 0
      ? jsx('div', { style: styles.muted, children: `另有 ${recoveredFailures.length} 条已由纠正重试回收：${recoveredFailures.map(f => `${FAILURE_LABEL[f.outcome] ?? f.outcome}（第 ${f.attempt ?? 1} 次）`).join('、')}` })
      : null,

    jsx('div', { style: styles.section, children: '装前审查（未安装的插件）' }),
    jsx(PreInstallSection, {}),
  ] })
}

export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
    name: 'settings.plugins.tab',
    id: 'upstream-radar',
    order: 30,
    label: () => 'Radar 监控',
  }, RadarPanel)), 'upstream-radar: settings tab')
}
