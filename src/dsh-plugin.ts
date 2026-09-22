import { randomUUID } from 'node:crypto'
import { readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { renderAgentAnalysisGroupPrompt, renderAgentAnalysisPrompt } from './dsh-analysis.js'
import {
  discoverDshRuntimeHostNodeModulesDirectory,
  discoverDshRuntimePackage,
  discoverDshRuntimePackageDirectory,
} from './dsh-runtime.js'
import { GitHubReleaseClient } from './github-release.js'
import { GitHubAdvisoryClient } from './github-advisory.js'
import { parseRadarConfig } from './inventory.js'
import { refreshRadarConfigFromDshProfile } from './init.js'
import { OsvClient } from './osv.js'
import { NpmCandidateGraphClient } from './npm-candidate.js'
import { NpmReleaseClient } from './npm-release.js'
import { CisaKevClient, EpssClient } from './threat-intel.js'
import {
  createNotificationPolicyMap,
  decideProjectRadarNotification,
  filterNotifiableRadarEvents,
  isRadarIncidentMuted,
} from './notification-policy.js'
import { pollRadar } from './radar.js'
import { loadRadarState, saveRadarState } from './radar-state.js'
import {
  eventsForRadarWebhookTarget,
  markRadarWebhookEventsDelivered,
  markRadarWebhookEventsDeliveredForRoute,
  normalizeRadarWebhookUrl,
  queueRadarWebhookEvents,
  queueRadarWebhookEventsForRoute,
  resolveRadarWebhookTargets,
  sendRadarWebhook,
  undeliveredRadarWebhookEvents,
  undeliveredRadarWebhookEventsForRoute,
} from './webhook.js'
import {
  ANALYSIS_DELIVERY_SCHEMA,
  type AnalysisDelivery,
  type AnalysisTask,
  type ProjectReference,
  type RadarEvent,
  type RadarNotificationPolicy,
  type RadarState,
  type StoredAnalysisResult,
} from './radar-types.js'
import {
  extractAnalysisTaskIds,
  inspectAgentAnalysisResult,
  renderAnalysisTaskMarker,
  type AgentAnalysisResultInspection,
} from './dsh-analysis-result.js'
import { ANALYSIS_EXPECTED_OUTPUT } from './dsh-analysis.js'
import {
  readAnalysisResultFailures,
  recordAnalysisResultFailure,
  type AnalysisResultFailure,
  type DroppedAnalysisAnswerOutcome,
} from './analysis-result-failures.js'
import { registerRadarPanelApi, type RadarPanelOptions, type UpgradeTargetReport } from './radar-panel.js'

export const name = 'upstream-radar'
export const inject = ['agents']

export interface Config {
  configFile?: string
  stateFile?: string
  /** DSH profile name written by `init --dsh-patch`; enables safe graph refresh. */
  profile?: string
  /** Set false to keep a generated inventory as a static snapshot. */
  refreshProfile?: boolean
  intervalSeconds?: number
  osvBaseUrl?: string
  registry?: string
  /** Set false to skip bounded transitive candidate graph checks. */
  deepCandidates?: boolean
  /** Candidate dependency graph check timeout (ms). Default 60000; deep DSH
   * graphs can need ~110s on slow networks, and a timeout flip makes every
   * event re-emit (stale deliveries). Bump to 120000 when unstable. */
  candidateTimeoutMs?: number
  /** OSV advisory query timeout (ms). Default 20000. One OSV failure marks
   * every candidate's dependencyStatus unavailable for that cycle, so slow
   * proxied networks may want 60000. Retries once before failing. */
  osvTimeoutMs?: number
  /** Set false to skip the independent GitHub Advisory Database check. */
  githubAdvisories?: boolean
  /** Set false to skip CISA KEV and FIRST EPSS prioritization signals. */
  threatIntel?: boolean
  /** Optional HTTPS endpoint for changed-event notifications; the URL is never persisted. */
  webhookUrl?: string
  runOnStart?: boolean
  /** Max concurrent panel background jobs (inspect/review). Default 3. */
  panelMaxJobs?: number
  /** Default DSH version matrix for the panel's review action. */
  panelReviewDshVersions?: string
  /**
   * 面板 [升级]/[评估] 按钮的**投递目标会话 workspace**（专用升级会话）。
   * 设置后：升级请求只发给 cwd 等于该 workspace 的会话；找不到就返回未送达，
   * **绝不回退**到雷达接收会话（那是只读会话）。不设置时保持旧行为（发给项目会话）。
   */
  upgradeWorkspace?: string
}

export interface DshRadarMessage {
  id: string
  role: 'user'
  content: Array<{ type: 'text'; text: string }>
  source: {
    kind: 'plugin'
    plugin: 'upstream-radar'
    form: 'notice'
    summary: string
  }
}

export interface DshSessionEventLike {
  type: string
  seq?: number
  time?: number
  data?: unknown
}

export interface DshSessionLike {
  id?: string
  header?: {
    cwd?: string | null
  }
  /** Live DSH Session objects expose snapshotEvents(), not an events array. */
  events?: readonly DshSessionEventLike[]
  snapshotEvents?: () => readonly DshSessionEventLike[]
}

export interface DshAgentLike {
  id?: string
  followup(message: DshRadarMessage): void
  session?: DshSessionLike
}

export interface DshRadarContext {
  agents: {
    roots(): DshAgentLike[]
  }
  logger: {
    info(message: string): void
    warn(message: string): void
  }
  effect(setup: () => void | (() => void | Promise<void>), label?: string): void
  on(event: 'agent/created', listener: () => void): () => void
  on(event: 'session/event', listener: (session: DshSessionLike, event: DshSessionEventLike) => void): () => void
}

function safeMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error)
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?').slice(0, 2_048)
}

function taskSummary(task: AnalysisTask): string {
  const project = task.event.project.name.slice(0, 60)
  if (task.event.kind === 'compatibility') {
    const packageName = task.event.installed.name
    if (packageName === '@deepseek-ai/cordis' || packageName.startsWith('@deepseek-ai/dsh-')) {
      return `DSH runtime compatibility change for ${project}`
    }
    return `Compatibility change for ${project}`
  }
  if (task.event.kind === 'source-health') return `Monitoring source degraded for ${project}`
  return `${task.event.kind === 'malware' ? 'Malicious package' : 'Vulnerability'} for ${project}`
}

function isDshRuntimePackage(name: string): boolean {
  return name === '@deepseek-ai/dsh'
    || name === '@deepseek-ai/cordis'
    || name.startsWith('@deepseek-ai/dsh-')
}

/** Informational release notices (benign newer candidates). Kept fully
 * outside the radar state machine: dedupe markers live in a plugin-owned
 * sidecar file, and delivery is a plain one-shot notice to the project
 * agent — never an analysis task. [PATCH-20260907-RELEASE-NOTICE] */

const MAX_RELEASE_NOTICE_MARKERS = 4_096

interface ReleaseNoticeMarker {
  eventId: string
  notifiedAt: string
}

function releaseNoticeKey(event: RadarEvent): string {
  if (event.kind !== 'compatibility') return ''
  return [
    event.project.id,
    event.plugin.name,
    event.plugin.version,
    event.installed.name,
    event.installed.version,
    event.candidate.name,
    event.candidate.version,
  ].join('|')
}

async function loadReleaseNoticeMarkers(path: string): Promise<Map<string, ReleaseNoticeMarker>> {
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as unknown
    const record = raw as Record<string, unknown>
    const markers = new Map<string, ReleaseNoticeMarker>()
    for (const [key, value] of Object.entries(record)) {
      const item = value as { eventId?: unknown; notifiedAt?: unknown }
      if (typeof item?.eventId === 'string' && typeof item?.notifiedAt === 'string'
        && Number.isFinite(Date.parse(item.notifiedAt))) {
        markers.set(key, { eventId: item.eventId, notifiedAt: item.notifiedAt })
      }
    }
    return markers
  } catch {
    return new Map()
  }
}

async function saveReleaseNoticeMarkers(path: string, markers: Map<string, ReleaseNoticeMarker>): Promise<void> {
  while (markers.size > MAX_RELEASE_NOTICE_MARKERS) {
    let oldest: string | undefined
    for (const [key, marker] of markers) {
      if (oldest === undefined || marker.notifiedAt < markers.get(oldest)!.notifiedAt) oldest = key
    }
    if (oldest === undefined) break
    markers.delete(oldest)
  }
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
  try {
    await writeFile(temporary, `${JSON.stringify(Object.fromEntries(markers), null, 2)}\n`, { flag: 'wx', mode: 0o600 })
    await rename(temporary, path)
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined)
  }
}

function releaseNoticeMessage(event: RadarEvent, now: Date): DshRadarMessage {
  const text = event.kind === 'compatibility' && event.informational === true
    ? `[upstream-radar 信息] 上游新版本可用：${event.installed.name} ${event.installed.version} → ${event.candidate.version}（本机插件 ${event.plugin.name}@${event.plugin.version}）。依赖图与漏洞检查均无异常，无需分析。\n【重要】本条仅为信息上报，请勿执行任何升级/安装/变更操作。你的职责：① 核对并确认该版本已正确记录到监控清单（入库）；② 给出结论（是否建议升级、理由、风险），作为回复返回。`
      + (event.releaseNotesUrl === undefined ? '' : `\n发布说明：${event.releaseNotesUrl}`)
    : '[upstream-radar 信息] 上游有新版本可用（详情见状态文件）。'
  return {
    id: `notice-${randomUUID()}`,
    role: 'user',
    content: [{ type: 'text', text }],
    source: {
      kind: 'plugin',
      plugin: 'upstream-radar',
      form: 'notice',
      summary: event.kind === 'compatibility'
        ? `new version available: ${event.installed.name} ${event.installed.version} -> ${event.candidate.version}`
        : 'new upstream version available',
    },
  }
}

/**
 * 用户经 Radar 面板手动触发的升级/评估请求消息（form='upgrade-request'，
 * 与信息级通知区分：那条是"勿升级"，这条是明确的用户授权动作）。 */
function upgradeRequestMessage(request: {
  plugin: string
  fromVersion: string | null
  toVersion: string
  kind: 'upgrade' | 'assess'
}): DshRadarMessage {
  const span = request.fromVersion === null ? request.toVersion : `${request.fromVersion} → ${request.toVersion}`
  const text = request.kind === 'assess'
    ? `[upstream-radar 升级请求 · 先评估] 用户通过 Radar 面板手动触发：候选 ${request.plugin} ${span} 触发过兼容信号。请先评估（依赖/兼容/风险、是否建议升级），给出结论；确认可行后再执行升级，并报告版本/磁盘/热重载/是否需要重启。`
    : `[upstream-radar 升级请求] 用户通过 Radar 面板手动触发：请把 ${request.plugin} 从 ${span} 升级。这是用户明确授权的升级动作（非自动）。请执行升级（含必要的备份），完成后报告：版本、磁盘/热重载状态、是否需要重启。`
  return {
    id: `upgrade-${randomUUID()}`,
    role: 'user',
    content: [{ type: 'text', text }],
    source: {
      kind: 'plugin',
      plugin: 'upstream-radar',
      form: 'notice',
      summary: `${request.kind === 'assess' ? 'assess' : 'upgrade'} requested (panel): ${request.plugin} ${span}`,
    },
  }
}

async function deliverReleaseNotices(
  stateFile: string,
  notices: readonly RadarEvent[],
  agents: readonly DshAgentLike[],
  state: RadarState,
  now: Date,
): Promise<number> {  if (notices.length === 0 || agents.length === 0) return 0
  const markersPath = `${stateFile}.release-notices.json`
  const markers = await loadReleaseNoticeMarkers(markersPath)
  const pending = notices.filter(event => {
    if (isRadarIncidentMuted(state, event, now)) return false
    const key = releaseNoticeKey(event)
    return key.length > 0 && !markers.has(key)
  })
  let delivered = 0
  for (const event of pending) {
    const agent = selectDshAgentForProject(event.project, agents)
    if (agent === undefined) continue
    try {
      agent.followup(releaseNoticeMessage(event, now))
    } catch {
      continue
    }
    markers.set(releaseNoticeKey(event), { eventId: event.id, notifiedAt: now.toISOString() })
    delivered += 1
  }
  if (delivered > 0) await saveReleaseNoticeMarkers(markersPath, markers)
  return delivered
}

/** Keep independent state incidents, but combine one project's DSH runtime updates into one Agent notice. */
export function groupPendingAnalysisTasks(tasks: readonly AnalysisTask[]): AnalysisTask[][] {
  const groups: AnalysisTask[][] = []
  const byProject = new Map<string, AnalysisTask[]>()
  for (const task of tasks) {
    const event = task.event
    if (event.kind !== 'compatibility' || !isDshRuntimePackage(event.installed.name)) {
      groups.push([task])
      continue
    }
    const key = `${event.project.id}\0dsh-runtime\0${event.detectedAt}`
    const existing = byProject.get(key)
    if (existing !== undefined) {
      existing.push(task)
      continue
    }
    const group = [task]
    byProject.set(key, group)
    groups.push(group)
  }
  return groups
}

export function createDshRadarMessage(task: AnalysisTask): DshRadarMessage {
  return Object.freeze({
    id: randomUUID(),
    role: 'user' as const,
    content: [{ type: 'text' as const, text: renderAgentAnalysisPrompt(task) }],
    source: {
      kind: 'plugin' as const,
      plugin: 'upstream-radar' as const,
      form: 'notice' as const,
      summary: taskSummary(task),
    },
  })
}

export function createDshRadarFamilyMessage(tasks: readonly AnalysisTask[]): DshRadarMessage {
  const first = tasks[0]
  if (first === undefined) throw new Error('cannot create a DSH family message without tasks')
  return Object.freeze({
    id: randomUUID(),
    role: 'user' as const,
    content: [{ type: 'text' as const, text: renderAgentAnalysisGroupPrompt(tasks) }],
    source: {
      kind: 'plugin' as const,
      plugin: 'upstream-radar' as const,
      form: 'notice' as const,
      summary: `DSH runtime compatibility changes (${tasks.length}) for ${first.event.project.name.slice(0, 60)}`,
    },
  })
}

/**
 * Correction budget for one delivered task group.
 *
 * A model that emits structurally invalid JSON almost always fixes it once the
 * exact failure is named, so two correction rounds recover the common case
 * without letting a confused session burn turns forever.
 */
export const MAX_ANALYSIS_RESULT_RETRIES = 2

/** What to do about one dropped answer. */
export type CorrectionDecision =
  | { action: 'ignore-replay' }
  | { action: 'retry'; attempt: number }
  | { action: 'give-up'; attempt: number }

/**
 * Decide how to react to one dropped answer.
 *
 * Kept pure so the retry budget, the replay guard and the give-up boundary can
 * be tested without a live DSH session. `attempt` counts answers for the same
 * delivery: 1 is the original, 2 is the first correction, and so on.
 */
export function decideAnalysisResultCorrection(
  recorded: readonly AnalysisResultFailure[],
  drop: Pick<DroppedAnalysisAnswer, 'sessionId' | 'assistantSeq' | 'deliveryId'>,
): CorrectionDecision {
  // A replayed session event must never trigger a second correction.
  if (recorded.some(entry => entry.sessionId === drop.sessionId && entry.assistantSeq === drop.assistantSeq)) {
    return { action: 'ignore-replay' }
  }
  const attempt = recorded.filter(entry => entry.deliveryId === drop.deliveryId).length + 1
  return attempt <= MAX_ANALYSIS_RESULT_RETRIES
    ? { action: 'retry', attempt }
    : { action: 'give-up', attempt }
}

/**
 * Correction prompt sent when a bound answer failed verdict validation.
 *
 * Every byte is plugin-generated: the task marker, the structural failure
 * reason and the fixed contract. No task content, no advisory text and no model
 * text is echoed back, so a retry cannot widen the untrusted surface.
 */
export function renderAnalysisResultRetryPrompt(
  taskIds: readonly string[],
  outcome: DroppedAnalysisAnswerOutcome,
  detail: string | undefined,
  attempt: number,
): string {
  const reason = detail === undefined ? outcome : `${outcome} (${detail})`
  return `${renderAnalysisTaskMarker(taskIds)}

你的上一条回复已到达 Radar，但没有通过 verdict 校验，已被丢弃：${reason}
这是第 ${attempt}/${MAX_ANALYSIS_RESULT_RETRIES} 次纠正请求，只做一件事：把同一份结论重新输出一次。

要求：
1. 只输出一个 JSON 代码块，块内只能有这一个对象；字段严格为 project_exposure、confidence、evidence、recommended_action、urgency、reasoning_summary。
2. 必须是严格合法的 JSON：不得有尾逗号，不得在对象闭合后再写多余的 } 或 ]。
3. 代码块之后可以照常写结论摘要（尾部会被忽略）。
4. 不要重新分析、不要重新读取上游材料：直接按已完成的结论重新输出。
5. 若原始任务内容已不在上下文中，如实输出 project_exposure=unknown、confidence=low，并在 reasoning_summary 说明上下文丢失，不要猜测。

expected_output:
${JSON.stringify(ANALYSIS_EXPECTED_OUTPUT, null, 2)}
`
}

/**
 * Build the correction notice for one outstanding delivery.
 *
 * The message reuses the delivery's own message id on purpose: the retry is the
 * SAME durable delivery re-sent, which is what lets the corrected answer bind
 * back to it instead of opening a second, untracked task.
 */
export function createDshRadarRetryMessage(
  delivery: Pick<AnalysisDelivery, 'messageId'>,
  taskIds: readonly string[],
  outcome: DroppedAnalysisAnswerOutcome,
  detail: string | undefined,
  attempt: number,
): DshRadarMessage {
  return Object.freeze({
    id: delivery.messageId,
    role: 'user' as const,
    content: [{ type: 'text' as const, text: renderAnalysisResultRetryPrompt(taskIds, outcome, detail, attempt) }],
    source: {
      kind: 'plugin' as const,
      plugin: 'upstream-radar' as const,
      form: 'notice' as const,
      summary: `verdict retry ${attempt}/${MAX_ANALYSIS_RESULT_RETRIES} (${outcome})`,
    },
  })
}

function createAnalysisDelivery(
  message: DshRadarMessage,
  tasks: readonly AnalysisTask[],
  agent: DshAgentLike,
  deliveredAt: string,
): AnalysisDelivery {
  const first = tasks[0]
  if (first === undefined) throw new Error('analysis delivery cannot be empty')
  return {
    schema: ANALYSIS_DELIVERY_SCHEMA,
    id: message.id,
    messageId: message.id,
    taskRefs: tasks.map(task => ({
      taskId: task.id,
      incidentId: task.event.incidentId,
      eventId: task.event.id,
      questionKey: questionKeyForEvent(task.event),
    })),
    projectId: first.event.project.id,
    deliveredAt,
    ...(agent.id === undefined ? {} : { agentId: agent.id }),
    ...(agent.session?.id === undefined ? {} : { sessionId: agent.session.id }),
  }
}

function messageRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function messageText(value: unknown): string | undefined {
  const message = messageRecord(value)
  if (message === undefined || !Array.isArray(message.content)) return undefined
  const text = message.content.flatMap(block => {
    const record = messageRecord(block)
    return record?.type === 'text' && typeof record.text === 'string' ? [record.text] : []
  }).join('')
  return text.length === 0 ? undefined : text
}

function messageId(value: unknown): string | undefined {
  const message = messageRecord(value)
  return typeof message?.id === 'string' && message.id.length > 0 ? message.id : undefined
}

function isRadarNotice(value: unknown): boolean {
  const message = messageRecord(value)
  const source = messageRecord(message?.source)
  return message?.role === 'user'
    && source?.kind === 'plugin'
    && source.plugin === 'upstream-radar'
    && source.form === 'notice'
}

function isModelAssistant(value: unknown): boolean {
  const message = messageRecord(value)
  const source = messageRecord(message?.source)
  return message?.role === 'assistant' && source?.kind === 'model'
}

function sessionId(session: DshSessionLike): string | undefined {
  return typeof session.id === 'string' && session.id.length > 0 ? session.id : undefined
}

function eventSequence(event: DshSessionEventLike): number | undefined {
  return typeof event.seq === 'number' && Number.isSafeInteger(event.seq) && event.seq >= 0
    ? event.seq
    : undefined
}

function sessionEventsOf(session: DshSessionLike): readonly DshSessionEventLike[] {
  // Live DSH sessions materialize their event log through snapshotEvents();
  // an `events` array exists only on the fabricated sessions used in tests.
  // Without this fallback the assistant-message reclamation path silently
  // matched nothing and every model analysis result was dropped.
  if (session.events !== undefined) return session.events
  if (typeof session.snapshotEvents === 'function') return session.snapshotEvents()
  return []
}

function sessionUserEvents(session: DshSessionLike): Array<{ event: DshSessionEventLike; message: Record<string, unknown>; text: string }> {
  return sessionEventsOf(session).flatMap(event => {
    if (event.type !== 'user/message') return []
    const message = messageRecord(event.data)
    const text = messageText(event.data)
    if (message === undefined || text === undefined || !isRadarNotice(event.data)) return []
    return [{ event, message, text }]
  })
}

function activeEventForIncident(state: RadarState, incidentId: string): RadarEvent | undefined {
  const vulnerability = Object.values(state.activeVulnerabilities).find(item => item.event.incidentId === incidentId)
  if (vulnerability !== undefined) return vulnerability.event
  const compatibility = state.activeCompatibility[incidentId]
    ?? Object.values(state.activeCompatibility).find(item => item.event.incidentId === incidentId)
  if (compatibility !== undefined) return compatibility.event
  const sourceHealth = Object.values(state.activeSourceHealth ?? {}).find(item => item.event.incidentId === incidentId)
  return sourceHealth?.event
}

/**
 * Identity of the question one analysis task asks.
 *
 * A compatibility or vulnerability event asks a new question every time it
 * changes, so its event id IS the question. A source-health incident is the
 * exception: `sourceHealthEventChanged` compares only project, route, source,
 * status and error, so an ongoing degradation keeps asking the same question
 * while `activeSourceHealth` hands out a fresh event id every cycle. Keying
 * such a reference on the event id discarded a correct answer that arrived one
 * cycle late; keying it on the question keeps the answer while still
 * invalidating it as soon as the status or the error text changes.
 */
function questionKeyForEvent(event: RadarEvent): string {
  if (event.kind === 'source-health') {
    return JSON.stringify([event.kind, event.project.id, event.source, event.status, event.error ?? ''])
  }
  return JSON.stringify([event.kind, event.incidentId, event.id])
}

function deliveryTaskIds(delivery: AnalysisDelivery): string[] {
  return delivery.taskRefs.map(reference => reference.taskId)
}

function sameTaskIds(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((taskId, index) => taskId === right[index])
}

function deliveryForUserMessage(
  state: RadarState,
  knownDeliveries: ReadonlyMap<string, AnalysisDelivery>,
  message: Record<string, unknown>,
  text: string,
): AnalysisDelivery | undefined {
  const id = messageId(message)
  if (id === undefined) return undefined
  const taskIds = extractAnalysisTaskIds(text)
  if (taskIds === undefined) return undefined
  const fromState = state.analysisDeliveries?.[id]
  const delivery = fromState ?? knownDeliveries.get(id)
  if (delivery === undefined || !sameTaskIds(deliveryTaskIds(delivery), taskIds)) return undefined
  return delivery
}

/**
 * Keep only the references whose question is still the one being asked.
 *
 * References written before `questionKey` existed fall back to exact event-id
 * identity, which is the previous behaviour.
 */
function resultEventRefsAreCurrent(state: RadarState, delivery: AnalysisDelivery): AnalysisDelivery['taskRefs'] {
  return delivery.taskRefs.filter(reference => {
    const active = activeEventForIncident(state, reference.incidentId)
    if (active === undefined) return false
    return reference.questionKey === undefined
      ? active.id === reference.eventId
      : questionKeyForEvent(active) === reference.questionKey
  })
}

function deliveryForAssistantMessage(
  state: RadarState,
  session: DshSessionLike,
  event: DshSessionEventLike,
  knownDeliveries: ReadonlyMap<string, AnalysisDelivery>,
): { delivery: AnalysisDelivery; userMessageId: string; userMessageSeq: number } | undefined {
  const assistantSeq = eventSequence(event)
  const currentSessionId = sessionId(session)
  if (assistantSeq === undefined || currentSessionId === undefined) return undefined
  const userEvents = sessionUserEvents(session)
  const candidates: Array<{ delivery: AnalysisDelivery; userMessageId: string; userMessageSeq: number }> = []
  const allDeliveries = new Map<string, AnalysisDelivery>([
    ...Object.entries(state.analysisDeliveries ?? {}),
    ...knownDeliveries,
  ])
  for (const delivery of allDeliveries.values()) {
    if (delivery.sessionId !== undefined && delivery.sessionId !== currentSessionId) continue
    if (delivery.userMessageId !== undefined) {
      const known = userEvents.find(item => messageId(item.message) === delivery.userMessageId)
      if (known === undefined) continue
    }
    const user = userEvents
      .filter(item => messageId(item.message) === delivery.messageId || messageId(item.message) === delivery.userMessageId)
      .map(item => {
        const sequence = eventSequence(item.event)
        const id = messageId(item.message)
        return sequence === undefined || id === undefined ? undefined : { sequence, id }
      })
      .filter((item): item is { sequence: number; id: string } => item !== undefined && item.sequence < assistantSeq)
      .at(-1)
    if (user === undefined) continue
    candidates.push({ delivery, userMessageId: user.id, userMessageSeq: user.sequence })
  }
  candidates.sort((left, right) => right.userMessageSeq - left.userMessageSeq)
  return candidates[0]
}

/** One answer that looked like a verdict but was not accepted as one. */
export interface DroppedAnalysisAnswer {
  deliveryId: string
  /** The delivery's own message id, reused when the correction is re-sent. */
  messageId: string
  taskIds: string[]
  incidentIds: string[]
  sessionId: string
  assistantSeq: number
  assistantMessageId?: string
  outcome: DroppedAnalysisAnswerOutcome
  detail?: string
}

export interface DshAnalysisEventOutcome {
  state: RadarState
  accepted: StoredAnalysisResult[]
  consumedDeliveryIds: string[]
  /** Answers that arrived but were rejected, so the caller can surface them. */
  dropped: DroppedAnalysisAnswer[]
}

function droppedOutcome(inspection: AgentAnalysisResultInspection): DroppedAnalysisAnswerOutcome | undefined {
  switch (inspection.outcome) {
    case 'oversized-text':
    case 'json-syntax-error':
    case 'contract-mismatch':
    case 'ambiguous-candidates':
      return inspection.outcome
    default:
      return undefined
  }
}

/**
 * Consume one DSH session event without trusting arbitrary transcript text.
 * Only a plugin-originated message admitted as a durable delivery can bind a
 * later model response to a Radar incident.
 */
export function applyDshAnalysisSessionEvent(
  state: RadarState,
  session: DshSessionLike,
  event: DshSessionEventLike,
  knownDeliveries: ReadonlyMap<string, AnalysisDelivery> = new Map(),
  now = new Date(),
): DshAnalysisEventOutcome {
  if (!Number.isFinite(now.getTime())) throw new Error('analysis result time is invalid')
  if (event.type === 'user/message') {
    if (!isRadarNotice(event.data)) return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
    const message = messageRecord(event.data)
    const text = messageText(event.data)
    const currentSessionId = sessionId(session)
    const sequence = eventSequence(event)
    const currentMessageId = messageId(message)
    if (message === undefined || text === undefined || currentSessionId === undefined
      || sequence === undefined || currentMessageId === undefined) {
      return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
    }
    const delivery = deliveryForUserMessage(state, knownDeliveries, message, text)
    if (delivery === undefined) return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
    const updatedDelivery: AnalysisDelivery = {
      ...delivery,
      sessionId: currentSessionId,
      userMessageId: currentMessageId,
      userMessageSeq: sequence,
    }
    const deliveries = { ...(state.analysisDeliveries ?? {}), [updatedDelivery.id]: updatedDelivery }
    return {
      state: { ...state, analysisDeliveries: deliveries },
      accepted: [],
      consumedDeliveryIds: [],
      dropped: [],
    }
  }
  if (event.type !== 'assistant/message') return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
  const data = messageRecord(event.data)
  const assistant = messageRecord(data?.message)
  if (assistant === undefined || !isModelAssistant(assistant)) {
    return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
  }
  const inspection = inspectAgentAnalysisResult(assistant)
  const dropReason = droppedOutcome(inspection)
  if (inspection.result === undefined) {
    // Name the drop instead of swallowing it. Only an answer that really binds
    // to an outstanding delivery is reported, so unrelated chat in a session
    // that merely discusses verdicts cannot pollute the log.
    const dropSessionId = sessionId(session)
    const dropSeq = eventSequence(event)
    const dropMessageId = messageId(assistant)
    const droppedDelivery = dropReason === undefined || dropSessionId === undefined || dropSeq === undefined
      ? undefined
      : deliveryForAssistantMessage(state, session, event, knownDeliveries)
    if (dropReason !== undefined && droppedDelivery !== undefined
      && dropSessionId !== undefined && dropSeq !== undefined) {
      return {
        state,
        accepted: [],
        consumedDeliveryIds: [],
        dropped: [{
          deliveryId: droppedDelivery.delivery.id,
          messageId: droppedDelivery.delivery.messageId,
          taskIds: droppedDelivery.delivery.taskRefs.map(reference => reference.taskId),
          incidentIds: droppedDelivery.delivery.taskRefs.map(reference => reference.incidentId),
          sessionId: dropSessionId,
          assistantSeq: dropSeq,
          ...(dropMessageId === undefined ? {} : { assistantMessageId: dropMessageId }),
          outcome: dropReason,
          ...(inspection.detail === undefined ? {} : { detail: inspection.detail }),
        }],
      }
    }
    return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
  }
  const parsed = inspection.result
  const matched = deliveryForAssistantMessage(state, session, event, knownDeliveries)
  if (matched === undefined) return { state, accepted: [], consumedDeliveryIds: [], dropped: [] }
  const currentRefs = resultEventRefsAreCurrent(state, matched.delivery)
  const assistantMessageId = messageId(assistant)
  const currentSessionId = sessionId(session)
  if (currentRefs.length === 0 || assistantMessageId === undefined || currentSessionId === undefined) {
    const deliveries = { ...(state.analysisDeliveries ?? {}) }
    delete deliveries[matched.delivery.id]
    return {
      state: { ...state, analysisDeliveries: deliveries },
      accepted: [],
      consumedDeliveryIds: [matched.delivery.id],
      dropped: [],
    }
  }
  const receivedAt = new Date(typeof event.time === 'number' && Number.isFinite(event.time) ? event.time : now.getTime()).toISOString()
  const results = { ...(state.analysisResults ?? {}) }
  const accepted: StoredAnalysisResult[] = []
  for (const reference of currentRefs) {
    const stored: StoredAnalysisResult = {
      schema: 'upstream-radar.analysis-result/v1alpha1',
      taskId: reference.taskId,
      incidentId: reference.incidentId,
      eventId: reference.eventId,
      deliveryId: matched.delivery.id,
      receivedAt,
      sessionId: currentSessionId,
      userMessageId: matched.userMessageId,
      assistantMessageId,
      ...parsed,
    }
    results[reference.incidentId] = stored
    accepted.push(stored)
  }
  const deliveries = { ...(state.analysisDeliveries ?? {}) }
  delete deliveries[matched.delivery.id]
  return {
    state: { ...state, analysisDeliveries: deliveries, analysisResults: results },
    accepted,
    consumedDeliveryIds: [matched.delivery.id],
    dropped: [],
  }
}

function normalizedWorkspace(workspace: string | undefined): string | undefined {
  if (workspace === undefined || workspace.trim() === '') return undefined
  return resolve(workspace)
}

/**
 * Match one project to a DSH root by the session's working directory.
 *
 * Without a configured workspace a single root remains the
 * backwards-compatible default. With a configured workspace the exact-match
 * rule always applies, even when only one root exists: a boot-time restore
 * race can leave an unrelated captain session as the only live root for a
 * few seconds, and the single-root fallback would then misdeliver every
 * analysis task into it. Refusing to deliver keeps tasks durable until the
 * matching root comes online in a later cycle.
 */
export function selectDshAgentForProject(
  project: ProjectReference,
  agents: readonly DshAgentLike[],
): DshAgentLike | undefined {
  const workspace = normalizedWorkspace(project.workspace)
  if (workspace === undefined) {
    if (agents.length === 1) return agents[0]
    return undefined
  }
  const matches = agents.filter((agent) => {
    const cwd = agent.session?.header?.cwd
    return typeof cwd === 'string' && normalizedWorkspace(cwd) === workspace
  })
  return matches.length === 1 ? matches[0] : undefined
}

/** DSH 的 blank 规则：一次 turn/start 之后就不再是“新建会话”草稿。 */
function sessionHasTurn(session: DshSessionLike | undefined): boolean {
  if (session === undefined) return false
  return sessionEventsOf(session).some(event => event.type === 'turn/start')
}

/** 会话日志里最后一个事件的时间（空白草稿之间的确定性排序用）。 */
function sessionLastEventTime(session: DshSessionLike | undefined): number {
  if (session === undefined) return 0
  return sessionEventsOf(session).reduce((latest, event) => {
    const time = typeof event.time === 'number' && Number.isFinite(event.time) ? event.time : 0
    return time > latest ? time : latest
  }, 0)
}

export interface UpgradeTargetSelection {
  agent?: DshAgentLike | undefined
  /** cwd 归一化后精确命中该 workspace 的活跃根会话数。 */
  matches: number
  /** 命中里已经跑过至少一个 turn 的数量（DSH 语义的非空白会话）。 */
  engaged: number
}

/**
 * 选择面板 [升级]/[评估] 的投递会话。
 *
 * 与分析任务投递刻意分开：分析投递是无人值守的持久任务，误投比延迟更糟
 * （见 selectDshAgentForProject 的说明）；而面板点击是用户在场、结果可见的手动
 * 动作，不应因为同一 workspace 里多了一张**侧栏不可见的空白草稿**（Web 客户端
 * 为每个工作区保留的“新建会话”行，登录后重建/复用）而永久失效。
 *
 *   - cwd 归一化后必须精确相等；
 *   - 恰好一个命中 → 就是它；
 *   - 多个命中里恰好一个“跑过 turn” → 选它，忽略空白草稿；
 *   - 多个命中都“跑过 turn” → 不猜，返回 undefined；
 *   - 全部是空白草稿 → 取最近有事件的那个（草稿没有别的工作在做）。
 */
export function selectUpgradeAgentForWorkspace(
  workspace: string | undefined,
  agents: readonly DshAgentLike[],
): UpgradeTargetSelection {
  const normalized = normalizedWorkspace(workspace)
  if (normalized === undefined) {
    // 未配置 workspace 时保持旧行为：只有单根会话才可路由。
    const engaged = agents.filter(agent => sessionHasTurn(agent.session)).length
    if (agents.length === 1) return { agent: agents[0], matches: 1, engaged }
    return { matches: agents.length, engaged }
  }
  const matches = agents.filter((agent) => {
    const cwd = agent.session?.header?.cwd
    return typeof cwd === 'string' && normalizedWorkspace(cwd) === normalized
  })
  if (matches.length === 0) return { matches: 0, engaged: 0 }
  const engaged = matches.filter(agent => sessionHasTurn(agent.session))
  if (engaged.length === 1) return { agent: engaged[0], matches: matches.length, engaged: 1 }
  if (engaged.length > 1) return { matches: matches.length, engaged: engaged.length }
  const ranked = [...matches].sort((left, right) =>
    sessionLastEventTime(right.session) - sessionLastEventTime(left.session)
    || String(left.id ?? left.session?.id ?? '').localeCompare(String(right.id ?? right.session?.id ?? '')))
  return { agent: ranked[0], matches: matches.length, engaged: 0 }
}

/** 选中目标的人可读说明（按钮回执与诊断路由共用）。 */
export function upgradeSelectionNote(selection: UpgradeTargetSelection): string {
  const session = selection.agent?.id ?? selection.agent?.session?.id ?? '(unknown session)'
  return selection.engaged > 0
    ? `已选中升级会话 ${session}（该 workspace 有 ${selection.matches} 个活跃会话，其中 ${selection.engaged} 个已使用过）`
    : `已选中该 workspace 的空白会话 ${session}（暂无已使用过的会话，请确认这是你要的会话）`
}

/** 未能唯一确定目标时的说明（按钮回执与诊断路由共用）。 */
export function upgradeRefusalNote(selection: UpgradeTargetSelection, workspace: string | undefined): string {
  const label = workspace ?? '(未配置)'
  if (selection.matches === 0) return `升级会话不在线：workspace ${label} 下没有活跃会话`
  if (selection.engaged >= 2) {
    return `workspace ${label} 下有 ${selection.engaged} 个已使用过的活跃会话（共 ${selection.matches} 个），无法唯一确定升级目标：请关掉多余的会话后重试`
  }
  return `workspace ${label} 下有 ${selection.matches} 个活跃会话，无法唯一确定升级目标`
}

type DeliveryObserver = (delivery: AnalysisDelivery, phase: 'before' | 'accepted' | 'rejected') => void

/** Deliver grouped tasks to the matching DSH root; unroutable tasks stay queued. */
export function deliverPendingAnalysisTasksToAgents(
  state: RadarState,
  agents: readonly DshAgentLike[],
  now = new Date(),
  observeDelivery?: DeliveryObserver,
  notificationPolicies: ReadonlyMap<string, RadarNotificationPolicy> = new Map(),
): RadarState {
  if (!Number.isFinite(now.getTime())) throw new Error('analysis delivery time is invalid')
  const deliveredIds = new Set<string>()
  const deliveries = { ...(state.analysisDeliveries ?? {}) }
  for (const group of groupPendingAnalysisTasks(state.pendingAnalysisTasks)) {
    const deliverableGroup = group.filter(task => !isRadarIncidentMuted(state, task.event, now))
    const first = deliverableGroup[0]
    if (first === undefined) continue
    if (deliverableGroup.some(task => !decideProjectRadarNotification(task.event, notificationPolicies, now).deliver)) continue
    const agent = selectDshAgentForProject(first.event.project, agents)
    if (agent === undefined) continue
    const message = deliverableGroup.length === 1
      ? createDshRadarMessage(deliverableGroup[0]!)
      : createDshRadarFamilyMessage(deliverableGroup)
    const delivery = createAnalysisDelivery(message, deliverableGroup, agent, now.toISOString())
    observeDelivery?.(delivery, 'before')
    try {
      agent.followup(message)
      observeDelivery?.(delivery, 'accepted')
      deliveries[delivery.id] = delivery
      for (const task of deliverableGroup) deliveredIds.add(task.id)
    } catch {
      observeDelivery?.(delivery, 'rejected')
      // Admission failed for this project only; unrelated project tasks may
      // still be delivered, while this group remains durable for retry.
      continue
    }
  }
  if (deliveredIds.size === 0) return state
  return {
    ...state,
    pendingAnalysisTasks: state.pendingAnalysisTasks.filter(task => !deliveredIds.has(task.id)),
    analysisDeliveries: deliveries,
  }
}

/** Synchronous follow-up admission is the acknowledgement boundary; failures stay queued. */
export function deliverPendingAnalysisTasks(
  state: RadarState,
  agent: DshAgentLike,
  notificationPolicies?: ReadonlyMap<string, RadarNotificationPolicy>,
): RadarState {
  return deliverPendingAnalysisTasksToAgents(state, [agent], new Date(), undefined, notificationPolicies)
}

async function readConfig(path: string): Promise<ReturnType<typeof parseRadarConfig>> {
  const contents = await readFile(path, 'utf8')
  if (Buffer.byteLength(contents) > 256 * 1024 * 1024) throw new Error('radar config exceeds the file size limit')
  try {
    return parseRadarConfig(JSON.parse(contents) as unknown)
  } catch (error: unknown) {
    if (error instanceof SyntaxError) throw new Error('radar config is not valid JSON')
    throw error
  }
}

/** Cordis function-plugin entrypoint. The polling loop stays deterministic; DSH receives only matched tasks. */
export function apply(ctx: DshRadarContext, config: Config = {}): void {
  if (config.configFile === undefined || config.configFile.trim() === '') {
    ctx.logger.warn('upstream-radar: UPSTREAM_RADAR_CONFIG is not set; monitoring is dormant')
    return
  }
  const configFile = resolve(config.configFile)
  const stateFile = resolve(config.stateFile ?? `${configFile}.state.json`)
  const intervalSeconds = config.intervalSeconds ?? 1_800
  if (!Number.isSafeInteger(intervalSeconds) || intervalSeconds < 300 || intervalSeconds > 86_400) {
    throw new Error('upstream-radar intervalSeconds must be between 300 and 86400')
  }
  // 可视化面板（host 侧 HTTP 路由）所需路径。CLI 工作目录 = radar 安装目录。
  const radarDir = dirname(configFile)
  const cliPath = join(radarDir, 'dist', 'src', 'cli.js')
  const panelJobsDir = join(radarDir, 'panel-jobs')
  // 手动"刷新新周期"钩子：apply 的 ctx.effect 内定义 run(true) 后回填。
  const refreshHook: { run: () => void } = { run: () => undefined }
  const source = new OsvClient({
    ...(config.osvBaseUrl === undefined ? {} : { baseUrl: config.osvBaseUrl }),
    ...(config.osvTimeoutMs === undefined ? {} : { timeoutMs: config.osvTimeoutMs }),
  })
  const releases = new NpmReleaseClient({ ...(config.registry === undefined ? {} : { registry: config.registry }) })
  const candidateGraphs = config.deepCandidates === false
    ? undefined
    : new NpmCandidateGraphClient({
        ...(config.registry === undefined ? {} : { registry: config.registry }),
        ...(config.candidateTimeoutMs === undefined ? {} : { timeoutMs: config.candidateTimeoutMs }),
      })
  const releaseNotes = new GitHubReleaseClient()
  const githubAdvisories = config.githubAdvisories === false
    ? undefined
    : new GitHubAdvisoryClient({ ...(process.env.GITHUB_TOKEN === undefined ? {} : { token: process.env.GITHUB_TOKEN }) })
  const threatIntelSources = config.threatIntel === false
    ? []
    : [
        { name: 'cisa-kev' as const, source: new CisaKevClient() },
        { name: 'epss' as const, source: new EpssClient() },
      ]
  const configuredWebhookUrl = config.webhookUrl ?? process.env.UPSTREAM_RADAR_WEBHOOK_URL
  const webhookUrl = configuredWebhookUrl === undefined || configuredWebhookUrl.trim() === ''
    ? undefined
    : normalizeRadarWebhookUrl(configuredWebhookUrl)
  const feishuSecret = process.env.UPSTREAM_RADAR_FEISHU_SECRET?.trim() || undefined
  const dshHostNodeModulesDirectory = config.profile === undefined || config.refreshProfile === false
    ? undefined
    // A package-local node_modules directory is enough for a flat npm
    // installation, but pnpm's actual dependency links may resolve through
    // the enclosing .pnpm virtual store. The host-plane variant deliberately
    // includes that controlled outer directory.
    : discoverDshRuntimeHostNodeModulesDirectory()
  const dshHostRuntimePackage = config.profile === undefined || config.refreshProfile === false
    ? undefined
    : discoverDshRuntimePackage()
  const dshHostRuntimePackageDirectory = config.profile === undefined || config.refreshProfile === false
    ? undefined
    : discoverDshRuntimePackageDirectory()
  if (dshHostNodeModulesDirectory !== undefined) {
    ctx.logger.info('upstream-radar: DSH runtime dependency plane discovered for exact graph refresh')
  }

  ctx.effect(() => {
    let stopped = false
    let serial = Promise.resolve()
    const inFlightDeliveries = new Map<string, AnalysisDelivery>()
    let activeNotificationPolicies: ReadonlyMap<string, RadarNotificationPolicy> = new Map()
    let notificationPoliciesLoaded = false
    let pollNotices: readonly RadarEvent[] = []
    const onSessionEvent = (session: DshSessionLike, event: DshSessionEventLike): void => {
      serial = serial.then(async () => {
        const state = await loadRadarState(stateFile)
        const outcome = applyDshAnalysisSessionEvent(state, session, event, inFlightDeliveries)
        if (outcome.state !== state) await saveRadarState(stateFile, outcome.state)
        for (const deliveryId of outcome.consumedDeliveryIds) inFlightDeliveries.delete(deliveryId)
        if (outcome.accepted.length > 0) {
          ctx.logger.info(`upstream-radar: accepted ${outcome.accepted.length} verified DSH analysis result(s)`)
        }
        for (const drop of outcome.dropped) {
          const detail = drop.detail === undefined ? '' : ` (${drop.detail})`
          ctx.logger.warn(
            `upstream-radar: dropped analysis answer from ${drop.sessionId} seq=${drop.assistantSeq}`
            + ` outcome=${drop.outcome}${detail} for ${drop.incidentIds.join(', ')}`,
          )
          try {
            const recorded = await readAnalysisResultFailures(stateFile)
            const decision = decideAnalysisResultCorrection(recorded, drop)
            if (decision.action === 'ignore-replay') continue
            const canRetry = decision.action === 'retry'
            await recordAnalysisResultFailure(stateFile, {
              sessionId: drop.sessionId,
              assistantSeq: drop.assistantSeq,
              ...(drop.assistantMessageId === undefined ? {} : { assistantMessageId: drop.assistantMessageId }),
              deliveryId: drop.deliveryId,
              incidentIds: drop.incidentIds,
              detectedAt: new Date().toISOString(),
              outcome: drop.outcome,
              ...(drop.detail === undefined ? {} : { detail: drop.detail }),
              attempt: decision.attempt,
              ...(canRetry ? {} : { unrecoverable: true }),
            })
            if (!canRetry) {
              ctx.logger.warn(
                `upstream-radar: correction budget exhausted for ${drop.incidentIds.join(', ')}`
                + ` after ${decision.attempt - 1} correction(s); giving up`,
              )
              continue
            }
            const target = ctx.agents.roots().find(agent => agent.session?.id === drop.sessionId)
            if (target === undefined) {
              ctx.logger.warn(
                `upstream-radar: cannot retry dropped answer for ${drop.incidentIds.join(', ')}:`
                + ` session ${drop.sessionId} is no longer active`,
              )
              continue
            }
            try {
              target.followup(createDshRadarRetryMessage(drop, drop.taskIds, drop.outcome, drop.detail, decision.attempt))
            } catch (error: unknown) {
              ctx.logger.warn(
                `upstream-radar: could not send correction ${decision.attempt}`
                + ` for ${drop.incidentIds.join(', ')}: ${safeMessage(error)}`,
              )
              continue
            }
            ctx.logger.info(
              `upstream-radar: requested correction ${decision.attempt}/${MAX_ANALYSIS_RESULT_RETRIES}`
              + ` for ${drop.incidentIds.join(', ')}`,
            )
          } catch (error: unknown) {
            ctx.logger.warn(`upstream-radar: could not record dropped analysis answer: ${safeMessage(error)}`)
          }
        }
      }).catch((error: unknown) => {
        ctx.logger.warn(`upstream-radar: session event handling failed: ${safeMessage(error)}`)
      })
    }
    const run = (poll: boolean): void => {
      serial = serial.then(async () => {
        if (stopped) return
        let state = await loadRadarState(stateFile)
        let notificationPolicies = activeNotificationPolicies
        if (poll) {
          const configured = await readConfig(configFile)
          const radarConfig = config.profile === undefined || config.refreshProfile === false
            ? configured
            : await refreshRadarConfigFromDshProfile(
              configured,
              config.profile,
              undefined,
              dshHostNodeModulesDirectory === undefined ? {} : {
                hostNodeModulesDirectory: dshHostNodeModulesDirectory,
                hostRuntimeSource: 'dsh-process',
                ...(dshHostRuntimePackage === undefined ? {} : { hostRuntimePackage: dshHostRuntimePackage }),
                ...(dshHostRuntimePackageDirectory === undefined ? {} : { hostRuntimePackageDirectory: dshHostRuntimePackageDirectory }),
              },
            )
          if (radarConfig !== configured && JSON.stringify(radarConfig.projects) !== JSON.stringify(configured.projects)) {
            ctx.logger.info(`upstream-radar: refreshed installed DSH profile ${config.profile}`)
          }
          notificationPolicies = createNotificationPolicyMap(radarConfig.projects)
          activeNotificationPolicies = notificationPolicies
          notificationPoliciesLoaded = true
          const result = await pollRadar(
            radarConfig.projects,
            state,
            source,
            new Date(),
            releases,
            releaseNotes,
            candidateGraphs,
            githubAdvisories === undefined ? [] : [{ name: 'github-advisories' as const, source: githubAdvisories }],
            threatIntelSources,
          )
          state = result.state
          pollNotices = result.notices
          // Persist before model delivery. A crash may duplicate a task, but cannot silently lose it.
          await saveRadarState(stateFile, state)
          const webhookTargets = resolveRadarWebhookTargets(radarConfig.projects, {
            ...(webhookUrl === undefined ? {} : { globalUrl: webhookUrl }),
            ...(feishuSecret === undefined ? {} : { globalFeishuSecret: feishuSecret }),
          })
          for (const target of webhookTargets) {
            const targetEvents = eventsForRadarWebhookTarget(result.events, target)
            const isLegacyGlobal = webhookUrl !== undefined && target.projectIds === undefined
            const queuedState = isLegacyGlobal
              ? queueRadarWebhookEvents(state, target.endpointHash, targetEvents)
              : queueRadarWebhookEventsForRoute(state, target.endpointHash, targetEvents)
            state = queuedState
            await saveRadarState(stateFile, state)
            const pendingWebhookEvents = filterNotifiableRadarEvents(
              isLegacyGlobal
                ? undeliveredRadarWebhookEvents(state, target.endpointHash, targetEvents)
                : undeliveredRadarWebhookEventsForRoute(state, target.endpointHash, targetEvents),
              notificationPolicies,
              new Date(),
              state,
            )
            if (pendingWebhookEvents.length === 0) continue
            try {
              const payload = await sendRadarWebhook(target.url, pendingWebhookEvents, target.feishuSecret === undefined ? {} : { feishuSecret: target.feishuSecret })
              const deliveredIds = new Set(payload.events.map(event => event.id))
              const deliveredEvents = pendingWebhookEvents.filter(event => deliveredIds.has(event.id))
              state = isLegacyGlobal
                ? markRadarWebhookEventsDelivered(state, target.endpointHash, deliveredEvents)
                : markRadarWebhookEventsDeliveredForRoute(state, target.endpointHash, deliveredEvents)
              await saveRadarState(stateFile, state)
              ctx.logger.info(`upstream-radar: delivered ${deliveredEvents.length} changed event(s) to the configured webhook route`)
            } catch (error: unknown) {
              ctx.logger.warn(`upstream-radar: webhook delivery failed; will retry: ${safeMessage(error)}`)
            }
          }
          if (result.events.length > 0) {
            ctx.logger.info(`upstream-radar: ${result.events.length} change(s), ${result.analysisTasks.length} analysis task(s)`)
          }
          for (const error of result.sourceErrors) {
            ctx.logger.warn(`upstream-radar: ${error.source}: ${safeMessage(error.message)}`)
          }
        } else if (!notificationPoliciesLoaded) {
          const configured = await readConfig(configFile)
          activeNotificationPolicies = createNotificationPolicyMap(configured.projects)
          notificationPolicies = activeNotificationPolicies
          notificationPoliciesLoaded = true
        }
        const agents = ctx.agents.roots()
        // Informational release notices are delivered once per candidate as
        // plain one-shot radar notices — independent of the analysis-task
        // queue, its guards, and its early returns.
        if (pollNotices.length > 0 && agents.length > 0) {
          try {
            const deliveredNotices = await deliverReleaseNotices(stateFile, pollNotices, agents, state, new Date())
            if (deliveredNotices > 0) ctx.logger.info(`upstream-radar: delivered ${deliveredNotices} release notice(s)`)
          } catch (error: unknown) {
            ctx.logger.warn(`upstream-radar: release notice delivery failed: ${safeMessage(error)}`)
          }
          pollNotices = []
        }
        if (agents.length === 0 || state.pendingAnalysisTasks.length === 0) return
        const next = deliverPendingAnalysisTasksToAgents(
          state,
          agents,
          new Date(),
          (delivery, phase) => {
            if (phase === 'rejected') inFlightDeliveries.delete(delivery.id)
            else inFlightDeliveries.set(delivery.id, delivery)
          },
          notificationPolicies,
        )
        if (next !== state) await saveRadarState(stateFile, next)
        const unrouted = groupPendingAnalysisTasks(next.pendingAnalysisTasks).find((group) => {
          const first = group[0]
          return first !== undefined && selectDshAgentForProject(first.event.project, agents) === undefined
        })
        if (unrouted !== undefined) {
          const first = unrouted[0]
          if (first !== undefined) {
            ctx.logger.warn(`upstream-radar: kept ${unrouted.length} analysis task(s) queued; no DSH root matches project ${first.event.project.name} workspace ${first.event.project.workspace ?? '(not configured)'}`)
          }
        }
      }).catch((error: unknown) => {
        ctx.logger.warn(`upstream-radar: cycle failed: ${safeMessage(error)}`)
      })
    }

    const stopCreated = ctx.on('agent/created', () => { run(false) })
    const stopSessionEvents = ctx.on('session/event', onSessionEvent)
    if (config.runOnStart !== false) run(true)
    const timer = setInterval(() => { run(true) }, intervalSeconds * 1_000)
    // 面板"刷新新周期"触发内建全链（poll + 保存 + 投递），而非重启 loader 入口。
    refreshHook.run = () => { run(true) }
    return async () => {
      stopped = true
      clearInterval(timer)
      stopCreated()
      stopSessionEvents()
      await serial
    }
  }, 'upstream-radar.lifecycle()')

  // 可视化面板：可选注册 HTTP 路由（webServer 能力存在时）。挂 ctx.effect，
  // 热重载/卸载自动注销；webServer 缺失时静默降级（监控照常运行）。
  // 投递目标：优先「专用升级会话」（upgradeWorkspace）；未配置时才回退到项目会话。
  // 配置了但找不到 → 明确失败，绝不回退到雷达接收会话（那应是只读会话）。
  const upgradeWorkspaceRef = async (): Promise<{ workspace: string | undefined } | { failure: string }> => {
    const configuredWorkspace = config.upgradeWorkspace?.trim()
    if (configuredWorkspace !== undefined && configuredWorkspace !== '') return { workspace: configuredWorkspace }
    try {
      const configured = await readConfig(configFile)
      const project: ProjectReference | undefined = configured.projects[0]?.project
      if (project === undefined) return { failure: 'radar 配置无项目引用，且未配置 upgradeWorkspace，无法路由升级请求' }
      return { workspace: project.workspace }
    } catch (error: unknown) {
      return { failure: `读取 radar 配置失败：${safeMessage(error)}` }
    }
  }

  // 只读诊断通道：报告选靶结果，不投递任何消息（GET /api/upgrade-target）。
  const inspectUpgradeTarget = async (): Promise<UpgradeTargetReport> => {
    const reference = await upgradeWorkspaceRef()
    if ('failure' in reference) {
      return { workspace: null, matches: 0, engaged: 0, sessionId: null, reason: reference.failure }
    }
    const selection = selectUpgradeAgentForWorkspace(reference.workspace, ctx.agents.roots())
    const agent = selection.agent
    return {
      workspace: reference.workspace ?? null,
      matches: selection.matches,
      engaged: selection.engaged,
      sessionId: agent === undefined ? null : (agent.id ?? agent.session?.id ?? null),
      reason: agent === undefined
        ? upgradeRefusalNote(selection, reference.workspace)
        : upgradeSelectionNote(selection),
    }
  }

  // 用户经面板手动触发的升级/评估请求：只把消息发给接收会话，host 不执行安装。
  const requestUpgrade = async (request: {
    plugin: string
    fromVersion: string | null
    toVersion: string
    kind: 'upgrade' | 'assess'
  }): Promise<{ delivered: boolean; note?: string }> => {
    const reference = await upgradeWorkspaceRef()
    if ('failure' in reference) return { delivered: false, note: reference.failure }
    const selection = selectUpgradeAgentForWorkspace(reference.workspace, ctx.agents.roots())
    const agent = selection.agent
    if (agent === undefined) return { delivered: false, note: upgradeRefusalNote(selection, reference.workspace) }
    try {
      agent.followup(upgradeRequestMessage(request))
    } catch (error: unknown) {
      return { delivered: false, note: `投递失败：${safeMessage(error)}` }
    }
    const note = upgradeSelectionNote(selection)
    ctx.logger.info(`upstream-radar: panel ${request.kind} request delivered to ${reference.workspace ?? 'project session'} (${request.plugin} -> ${request.toVersion}); ${note}`)
    return { delivered: true, note }
  }

  const panelOptions: RadarPanelOptions = {
    radarDir,
    configFile,
    stateFile,
    cliPath,
    jobsDir: panelJobsDir,
    maxJobs: config.panelMaxJobs ?? 3,
    reviewDshVersions: config.panelReviewDshVersions ?? '0.1.1-rc.2,0.1.2-alpha.5',
    refresh: () => refreshHook.run(),
    requestUpgrade,
    upgradeTarget: inspectUpgradeTarget,
  }
  const panelContext = ctx as unknown as {
    inject?: (deps: string[], fn: (scope: {
      webServer: Parameters<typeof registerRadarPanelApi>[0]
      effect(setup: () => void | (() => void), label?: string): void
    }) => void) => void
  }
  panelContext.inject?.call(ctx, ['webServer'], (scope) => {
    scope.effect(() => registerRadarPanelApi(scope.webServer, panelOptions), 'upstream-radar: panel api')
  })
}
