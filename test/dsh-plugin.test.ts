import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { createAnalysisTask } from '../src/dsh-analysis.js'
import {
  createDshRadarMessage,
  deliverPendingAnalysisTasks,
  deliverPendingAnalysisTasksToAgents,
  groupPendingAnalysisTasks,
  selectDshAgentForProject,
  selectUpgradeAgentForWorkspace,
  upgradeRefusalNote,
  upgradeSelectionNote,
} from '../src/dsh-plugin.js'
import { emptyRadarState } from '../src/radar.js'
import type { CompatibilityEvent, SourceHealthEvent } from '../src/radar-types.js'

const event: CompatibilityEvent = {
  schema: 'upstream-radar.event/v1alpha1',
  id: 'event-compat',
  incidentId: 'incident-compat',
  kind: 'compatibility',
  change: 'new',
  detectedAt: '2026-08-14T04:00:00.000Z',
  project: { id: 'project-a', name: 'Project A', workspace: '/workspace/project-a' },
  route: { owner: 'platform', channels: ['stdout'] },
  plugin: { ecosystem: 'npm', name: 'plugin', version: '1.0.0' },
  installed: { ecosystem: 'npm', name: 'plugin', version: '1.0.0' },
  candidate: { ecosystem: 'npm', name: 'plugin', version: '2.0.0' },
  signals: [{ code: 'breaking-version-boundary', confidence: 'strong', summary: 'Major update.' }],
}

const sourceHealthEvent: SourceHealthEvent = {
  schema: 'upstream-radar.event/v1alpha1',
  id: 'event-source-health',
  incidentId: 'project-a\u0000osv',
  kind: 'source-health',
  change: 'new',
  detectedAt: '2026-08-14T04:00:00.000Z',
  project: { id: 'project-a', name: 'Project A', workspace: '/workspace/project-a' },
  route: { owner: 'platform', channels: ['stdout'] },
  source: 'osv',
  status: 'degraded',
  failureCount: 3,
  lastAttemptedAt: '2026-08-14T04:00:00.000Z',
  error: 'OSV timeout',
}

describe('DSH radar plugin adapter', () => {
  it('delivers durable pending tasks as identified DSH follow-up messages', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(task)
    const messages: unknown[] = []
    const remaining = deliverPendingAnalysisTasks(state, { session: { header: { cwd: '/workspace/project-a' } }, followup: message => messages.push(message) })

    assert.equal(remaining.pendingAnalysisTasks.length, 0)
    assert.equal(messages.length, 1)
    assert.match(JSON.stringify(messages[0]), /UPSTREAM RADAR ANALYSIS TASK/)
    assert.match(JSON.stringify(messages[0]), /sourceMaterialIsUntrusted|不可信数据/)
  })

  it('creates a bounded plugin notice rather than a user-authored instruction', () => {
    const message = createDshRadarMessage(createAnalysisTask(event))
    assert.equal(message.role, 'user')
    assert.deepEqual(message.source, {
      kind: 'plugin',
      plugin: 'upstream-radar',
      form: 'notice',
      summary: 'Compatibility change for Project A',
    })
  })

  it('routes a source-health incident as a useful DSH notice', () => {
    const message = createDshRadarMessage(createAnalysisTask(sourceHealthEvent))
    assert.equal(message.source.summary, 'Monitoring source degraded for Project A')
    assert.match(message.content[0]?.text ?? '', /监控源当前不可用/)
  })

  it('groups one project\'s DSH runtime updates without merging unrelated incidents', () => {
    const dshAgent = createAnalysisTask({
      ...event,
      id: 'event-dsh-agent',
      incidentId: 'incident-dsh-agent',
      installed: { ecosystem: 'npm', name: '@deepseek-ai/dsh-agent', version: '0.1.0-rc.6' },
      candidate: { ecosystem: 'npm', name: '@deepseek-ai/dsh-agent', version: '0.2.0' },
    })
    const dshSession = createAnalysisTask({
      ...event,
      id: 'event-dsh-session',
      incidentId: 'incident-dsh-session',
      installed: { ecosystem: 'npm', name: '@deepseek-ai/dsh-session', version: '0.1.0-rc.6' },
      candidate: { ecosystem: 'npm', name: '@deepseek-ai/dsh-session', version: '0.2.0' },
    })
    const unrelated = createAnalysisTask(sourceHealthEvent)
    const groups = groupPendingAnalysisTasks([dshAgent, unrelated, dshSession])
    assert.deepEqual(groups.map(group => group.length), [2, 1])

    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(dshAgent, unrelated, dshSession)
    const messages: Array<{ content: Array<{ text: string }>; source: { summary: string } }> = []
    const remaining = deliverPendingAnalysisTasks(state, { session: { header: { cwd: '/workspace/project-a' } }, followup: message => messages.push(message) })
    assert.equal(remaining.pendingAnalysisTasks.length, 0)
    assert.equal(messages.length, 2)
    assert.match(messages[0]?.content[0]?.text ?? '', /@deepseek-ai\/dsh-agent/)
    assert.match(messages[0]?.content[0]?.text ?? '', /@deepseek-ai\/dsh-session/)
    assert.match(messages[0]?.source.summary ?? '', /DSH runtime compatibility changes \(2\)/)
  })

  it('routes multiple projects by exact DSH session workspace', () => {
    const secondEvent: CompatibilityEvent = {
      ...event,
      id: 'event-compat-second',
      incidentId: 'incident-compat-second',
      project: { id: 'project-b', name: 'Project B', workspace: '/workspace/project-b' },
    }
    const firstTask = createAnalysisTask(event)
    const secondTask = createAnalysisTask(secondEvent)
    const firstMessages: unknown[] = []
    const secondMessages: unknown[] = []
    const firstAgent = {
      session: { header: { cwd: '/workspace/project-a' } },
      followup: (message: unknown) => firstMessages.push(message),
    }
    const secondAgent = {
      session: { header: { cwd: '/workspace/project-b' } },
      followup: (message: unknown) => secondMessages.push(message),
    }

    assert.equal(selectDshAgentForProject(event.project, [firstAgent, secondAgent]), firstAgent)
    assert.equal(selectDshAgentForProject(secondEvent.project, [firstAgent, secondAgent]), secondAgent)
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(firstTask, secondTask)
    const remaining = deliverPendingAnalysisTasksToAgents(state, [firstAgent, secondAgent])

    assert.equal(remaining.pendingAnalysisTasks.length, 0)
    assert.equal(firstMessages.length, 1)
    assert.equal(secondMessages.length, 1)
    assert.match(JSON.stringify(firstMessages[0]), /Project A/)
    assert.match(JSON.stringify(secondMessages[0]), /Project B/)
  })

  it('keeps a policy-held task durable and delivers it after quiet hours', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(task)
    const agent = { session: { header: { cwd: '/workspace/project-a' } }, followup: () => undefined }
    const policy = new Map([['project-a', {
      quietHours: { timezone: 'Asia/Shanghai', start: '22:00', end: '08:00' },
    }]])
    const held = deliverPendingAnalysisTasksToAgents(
      state,
      [agent],
      new Date('2026-08-16T15:30:00.000Z'),
      undefined,
      policy,
    )
    assert.equal(held.pendingAnalysisTasks.length, 1)
    const delivered = deliverPendingAnalysisTasksToAgents(
      held,
      [agent],
      new Date('2026-08-16T02:00:00.000Z'),
      undefined,
      policy,
    )
    assert.equal(delivered.pendingAnalysisTasks.length, 0)
  })

  it('keeps a muted task queued until the exact mute expires', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(task)
    state.incidentMutes = {
      [event.incidentId]: { eventId: event.id, mutedUntil: '2026-08-17T00:00:00.000Z' },
    }
    const messages: unknown[] = []
    const agent = { session: { header: { cwd: '/workspace/project-a' } }, followup: (message: unknown) => messages.push(message) }
    const held = deliverPendingAnalysisTasksToAgents(
      state,
      [agent],
      new Date('2026-08-16T02:00:00.000Z'),
    )
    assert.equal(held.pendingAnalysisTasks.length, 1)
    assert.equal(messages.length, 0)
    const delivered = deliverPendingAnalysisTasksToAgents(
      held,
      [agent],
      new Date('2026-08-17T00:00:00.000Z'),
    )
    assert.equal(delivered.pendingAnalysisTasks.length, 0)
    assert.equal(messages.length, 1)
  })

  it('keeps a multi-project task queued when no workspace match is trustworthy', () => {
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(createAnalysisTask(event))
    const messages: unknown[] = []
    const otherAgent = {
      session: { header: { cwd: '/workspace/other' } },
      followup: (message: unknown) => messages.push(message),
    }

    const remaining = deliverPendingAnalysisTasksToAgents(state, [otherAgent, {
      session: { header: { cwd: '/workspace/another' } },
      followup: (message: unknown) => messages.push(message),
    }])

    assert.equal(remaining.pendingAnalysisTasks.length, 1)
    assert.equal(messages.length, 0)
  })

  it('does not guess when two roots advertise the same workspace', () => {
    const matches = [
      { session: { header: { cwd: '/workspace/project-a' } }, followup: () => undefined },
      { session: { header: { cwd: '/workspace/project-a' } }, followup: () => undefined },
    ]
    assert.equal(selectDshAgentForProject(event.project, matches), undefined)
  })

  it('preserves single-root compatibility for a project without a configured workspace', () => {
    // Legacy branch: no workspace in the project config, so the single root
    // stays the backwards-compatible default regardless of its cwd.
    const legacyEvent: CompatibilityEvent = {
      ...event,
      project: { id: 'project-a', name: 'Project A' },
    }
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(createAnalysisTask(legacyEvent))
    const messages: unknown[] = []
    const remaining = deliverPendingAnalysisTasksToAgents(state, [{ followup: (message: unknown) => messages.push(message) }])

    assert.equal(remaining.pendingAnalysisTasks.length, 0)
    assert.equal(messages.length, 1)
  })

  it('refuses the single-root fallback when the project configures a workspace', () => {
    // A boot-restore race can leave an unrelated session as the only live
    // root; with a configured workspace the exact-match rule must hold even
    // then, or every analysis task is misdelivered into that session.
    const state = emptyRadarState()
    state.pendingAnalysisTasks.push(createAnalysisTask(event))
    const messages: unknown[] = []
    const captain = { session: { header: { cwd: '/workspace/unrelated' } }, followup: (message: unknown) => messages.push(message) }

    // Single root, wrong workspace: refuse (task stays durable).
    assert.equal(selectDshAgentForProject(event.project, [captain]), undefined)
    const remaining = deliverPendingAnalysisTasksToAgents(state, [captain])
    assert.equal(remaining.pendingAnalysisTasks.length, 1)
    assert.equal(messages.length, 0)

    // Single root, matching workspace: still delivered.
    const receiver = { session: { header: { cwd: '/workspace/project-a' } }, followup: (message: unknown) => messages.push(message) }
    assert.equal(selectDshAgentForProject(event.project, [receiver]), receiver)
    const delivered = deliverPendingAnalysisTasksToAgents(state, [receiver])
    assert.equal(delivered.pendingAnalysisTasks.length, 0)
    assert.equal(messages.length, 1)
  })
})

/** 面板升级选靶用的假 agent（events 走 DshSessionLike.events 分支）。 */
function upgradeAgent(id: string, cwd: string, events: Array<{ type: string; time?: number }>): {
  id: string
  messages: unknown[]
  session: { id: string; header: { cwd: string }; events: Array<{ type: string; time?: number }> }
  followup: (message: unknown) => void
} {
  const messages: unknown[] = []
  return {
    id,
    messages,
    session: { id, header: { cwd }, events },
    followup: (message: unknown) => { messages.push(message) },
  }
}

describe('radar panel upgrade target selection', () => {
  it('ignores an invisible blank draft when exactly one match has run a turn', () => {
    // 回归：Web 客户端为每个 workspace 保留一张侧栏不可见的“新建会话”草稿
    // （DSH blank 规则 = 尚未出现 turn/start）。旧的严格唯一匹配会被它永久挡住。
    const upgrade = upgradeAgent('session-upgrade', '/workspace/upgrade', [
      { type: 'turn/start', time: 100 },
      { type: 'turn/end', time: 200 },
    ])
    const draft = upgradeAgent('session-draft', '/workspace/upgrade', [
      { type: 'sandbox/mode', time: 10 },
      { type: 'agent-preset/selected', time: 300 },
    ])

    const selection = selectUpgradeAgentForWorkspace('/workspace/upgrade', [draft, upgrade])
    assert.equal(selection.agent, upgrade)
    assert.equal(selection.matches, 2)
    assert.equal(selection.engaged, 1)
    assert.match(upgradeSelectionNote(selection), /session-upgrade/)
  })

  it('refuses to guess between two workspaces sessions that both ran a turn', () => {
    const first = upgradeAgent('session-first', '/workspace/upgrade', [{ type: 'turn/start', time: 100 }])
    const second = upgradeAgent('session-second', '/workspace/upgrade', [{ type: 'turn/start', time: 900 }])

    const selection = selectUpgradeAgentForWorkspace('/workspace/upgrade', [first, second])
    assert.equal(selection.agent, undefined)
    assert.equal(selection.matches, 2)
    assert.equal(selection.engaged, 2)
    assert.match(upgradeRefusalNote(selection, '/workspace/upgrade'), /2 个已使用过的活跃会话/)
  })

  it('routes the only match even when it is still a blank draft', () => {
    const only = upgradeAgent('session-only-draft', '/workspace/upgrade', [{ type: 'sandbox/mode', time: 10 }])
    const selection = selectUpgradeAgentForWorkspace('/workspace/upgrade', [only])
    assert.equal(selection.agent, only)
    assert.equal(selection.matches, 1)
    assert.equal(selection.engaged, 0)
  })

  it('picks the most recent draft deterministically when every match is blank', () => {
    const older = upgradeAgent('session-old-draft', '/workspace/upgrade', [{ type: 'sandbox/mode', time: 10 }])
    const newer = upgradeAgent('session-new-draft', '/workspace/upgrade', [{ type: 'sandbox/mode', time: 500 }])

    assert.equal(selectUpgradeAgentForWorkspace('/workspace/upgrade', [older, newer]).agent, newer)
    assert.equal(selectUpgradeAgentForWorkspace('/workspace/upgrade', [newer, older]).agent, newer)
    // 时间相同 → 以会话 id 兜底，保证两次点击不会给出不同答案。
    const twinA = upgradeAgent('session-a', '/workspace/upgrade', [{ type: 'sandbox/mode', time: 7 }])
    const twinB = upgradeAgent('session-b', '/workspace/upgrade', [{ type: 'sandbox/mode', time: 7 }])
    assert.equal(selectUpgradeAgentForWorkspace('/workspace/upgrade', [twinB, twinA]).agent, twinA)
  })

  it('normalizes the configured workspace and reports a missing target', () => {
    const upgrade = upgradeAgent('session-upgrade', '/workspace/upgrade', [{ type: 'turn/start', time: 100 }])
    assert.equal(selectUpgradeAgentForWorkspace('/workspace/upgrade/', [upgrade]).agent, upgrade)

    const elsewhere = upgradeAgent('session-elsewhere', '/workspace/other', [{ type: 'turn/start', time: 100 }])
    const missing = selectUpgradeAgentForWorkspace('/workspace/upgrade', [elsewhere])
    assert.equal(missing.agent, undefined)
    assert.equal(missing.matches, 0)
    assert.match(upgradeRefusalNote(missing, '/workspace/upgrade'), /没有活跃会话/)
  })

  it('keeps the single-root legacy branch when no workspace is configured', () => {
    const sole = upgradeAgent('session-sole', '/workspace/upgrade', [{ type: 'turn/start', time: 100 }])
    assert.equal(selectUpgradeAgentForWorkspace(undefined, [sole]).agent, sole)

    const second = upgradeAgent('session-second', '/workspace/other', [{ type: 'turn/start', time: 100 }])
    const ambiguous = selectUpgradeAgentForWorkspace(undefined, [sole, second])
    assert.equal(ambiguous.agent, undefined)
    assert.equal(ambiguous.matches, 2)
  })
})
