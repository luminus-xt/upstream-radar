import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { createAnalysisTask } from '../src/dsh-analysis.js'
import {
  applyDshAnalysisSessionEvent,
  createDshRadarMessage,
  createDshRadarRetryMessage,
  decideAnalysisResultCorrection,
  deliverPendingAnalysisTasks,
  MAX_ANALYSIS_RESULT_RETRIES,
  renderAnalysisResultRetryPrompt,
  type DshSessionEventLike,
} from '../src/dsh-plugin.js'
import { extractAnalysisTaskIds, inspectAgentAnalysisResult, parseAgentAnalysisResult } from '../src/dsh-analysis-result.js'
import { emptyRadarState } from '../src/radar.js'
import type { CompatibilityEvent, SourceHealthEvent } from '../src/radar-types.js'

const event: CompatibilityEvent = {
  schema: 'upstream-radar.event/v1alpha1',
  id: 'event-analysis-result',
  incidentId: 'incident-analysis-result',
  kind: 'compatibility',
  change: 'new',
  detectedAt: '2026-08-16T04:00:00.000Z',
  project: { id: 'project-analysis', name: 'Analysis project', workspace: '/workspace/analysis' },
  route: { channels: ['stdout'] },
  plugin: { ecosystem: 'npm', name: 'plugin', version: '1.0.0' },
  installed: { ecosystem: 'npm', name: 'plugin', version: '1.0.0' },
  candidate: { ecosystem: 'npm', name: 'plugin', version: '2.0.0' },
  signals: [{ code: 'breaking-version-boundary', confidence: 'strong', summary: 'Major update.' }],
}

const answer = {
  project_exposure: 'likely_exposed',
  confidence: 'medium',
  evidence: ['src/index.ts:12', 'package.json'],
  recommended_action: 'Review the candidate in a disposable branch and run the project tests.',
  urgency: 'planned',
  reasoning_summary: 'The release crosses a major version boundary, but the repository evidence is incomplete.',
} as const

function assistantEvent(seq: number): DshSessionEventLike {
  return {
    type: 'assistant/message',
    seq,
    time: Date.parse('2026-08-16T04:01:00.000Z'),
    data: {
      turn: 1,
      step: 1,
      message: {
        id: 'assistant-message-1',
        role: 'assistant',
        source: { kind: 'model', provider: 'local', model: 'deterministic' },
        content: [{ type: 'text', text: JSON.stringify(answer) }],
      },
    },
  }
}

function assistantText(text: string, seq: number, id = 'assistant-message-1'): DshSessionEventLike {
  return {
    type: 'assistant/message',
    seq,
    time: Date.parse('2026-08-16T04:01:00.000Z'),
    data: { turn: 1, step: 1, message: { id, role: 'assistant', source: { kind: 'model' }, content: [{ type: 'text', text }] } },
  }
}

function modelMessage(text: string): Record<string, unknown> {
  return { role: 'assistant', source: { kind: 'model' }, content: [{ type: 'text', text }] }
}

/**
 * Reproduce the exact malformation observed in production: the last field gains
 * a trailing comma and the object is closed twice.
 */
function malformedFence(payload: object): string {
  const body = JSON.stringify(payload, null, 2)
  return `\`\`\`json\n${body.replace(/\n\}$/, ',\n  }\n}')}\n\`\`\`\n\n结论摘要：一句话。`
}

describe('DSH analysis result protocol', () => {
  it('uses an exact task marker and accepts only the six-field JSON contract', () => {
    const task = createAnalysisTask(event)
    const message = createDshRadarMessage(task)
    const text = message.content[0]?.text ?? ''
    assert.deepEqual(extractAnalysisTaskIds(text), [task.id])
    assert.deepEqual(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: JSON.stringify(answer) }],
    }), answer)
    assert.equal(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: `Here is the result:\n${JSON.stringify(answer)}` }],
    }), undefined)
    assert.equal(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'user' },
      content: [{ type: 'text', text: JSON.stringify(answer) }],
    }), undefined)
  })

  it('accepts a pure JSON fence and rejects prose before the fence', () => {
    const fenced = `\`\`\`json\n${JSON.stringify(answer)}\n\`\`\``
    assert.deepEqual(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: fenced }],
    }), answer)
    assert.equal(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: `结论：暂缓。\n${fenced}` }],
    }), undefined)
  })

  it('accepts a JSON fence followed by a conclusion summary (two-step protocol)', () => {
    const fenced = `\`\`\`json\n${JSON.stringify(answer)}\n\`\`\``
    const twoStep = `${fenced}\n结论：推荐升级（一句话理由），展开见上。`
    assert.deepEqual(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: twoStep }],
    }), answer)
    // The tail is not parsed as JSON when it sits outside the fence.
    assert.deepEqual(parseAgentAnalysisResult({
      role: 'assistant',
      source: { kind: 'model' },
      content: [{ type: 'text', text: `${fenced}\nnot json` }],
    }), answer)
  })

  it('binds a model response to the admitted message and writes one verified result', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.activeCompatibility = { [event.incidentId]: { key: event.incidentId, event } }
    state.pendingAnalysisTasks = [task]
    let delivered: Record<string, unknown> | undefined
    const deliveredState = deliverPendingAnalysisTasks(state, {
      session: { header: { cwd: '/workspace/analysis' } },
      followup: message => { delivered = message as unknown as Record<string, unknown> },
    })
    assert.ok(delivered)
    const userEvent: DshSessionEventLike = { type: 'user/message', seq: 1, time: Date.now(), data: delivered }
    const session = { id: 'session-analysis', events: [userEvent] }
    const afterUser = applyDshAnalysisSessionEvent(deliveredState, session, userEvent)
    assert.equal(afterUser.accepted.length, 0)
    assert.equal(Object.keys(afterUser.state.analysisDeliveries ?? {}).length, 1)

    const modelEvent = assistantEvent(4)
    const afterAssistant = applyDshAnalysisSessionEvent(
      afterUser.state,
      { ...session, events: [userEvent, modelEvent] },
      modelEvent,
      new Map(),
      new Date('2026-08-16T04:01:00.000Z'),
    )
    assert.equal(afterAssistant.accepted.length, 1)
    assert.equal(afterAssistant.accepted[0]?.incidentId, event.incidentId)
    assert.equal(afterAssistant.state.analysisDeliveries?.[delivered.id as string], undefined)
    assert.equal(afterAssistant.state.analysisResults?.[event.incidentId]?.project_exposure, 'likely_exposed')
  })

  it('reclaims the same result from a live DSH session that only exposes snapshotEvents()', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.activeCompatibility = { [event.incidentId]: { key: event.incidentId, event } }
    state.pendingAnalysisTasks = [task]
    let delivered: Record<string, unknown> | undefined
    const deliveredState = deliverPendingAnalysisTasks(state, {
      session: { header: { cwd: '/workspace/analysis' } },
      followup: message => { delivered = message as unknown as Record<string, unknown> },
    })
    assert.ok(delivered)
    const userEvent: DshSessionEventLike = { type: 'user/message', seq: 1, time: Date.now(), data: delivered }

    // Live DSH Session instances materialize their log through snapshotEvents()
    // and do not carry an `events` array property; a fabricated `events` field
    // exists only in tests. Reclamation must work through the live shape.
    const liveLog: DshSessionEventLike[] = [userEvent]
    const liveSession = {
      id: 'session-live',
      snapshotEvents: () => liveLog,
    }
    const afterUser = applyDshAnalysisSessionEvent(deliveredState, liveSession, userEvent)
    assert.equal(afterUser.accepted.length, 0)
    assert.equal(Object.keys(afterUser.state.analysisDeliveries ?? {}).length, 1)

    const modelEvent = assistantEvent(4)
    liveLog.push(modelEvent)
    const afterAssistant = applyDshAnalysisSessionEvent(
      afterUser.state,
      liveSession,
      modelEvent,
      new Map(),
      new Date('2026-08-16T04:01:00.000Z'),
    )
    assert.equal(afterAssistant.accepted.length, 1)
    assert.equal(afterAssistant.accepted[0]?.incidentId, event.incidentId)
    assert.equal(afterAssistant.state.analysisDeliveries?.[delivered.id as string], undefined)
    assert.equal(afterAssistant.state.analysisResults?.[event.incidentId]?.project_exposure, 'likely_exposed')
  })

  it('does not let a forged marker or an unrelated assistant reply create a result', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.activeCompatibility = { [event.incidentId]: { key: event.incidentId, event } }
    state.pendingAnalysisTasks = [task]
    const forged = {
      id: 'forged-message',
      role: 'user',
      source: { kind: 'plugin', plugin: 'upstream-radar', form: 'notice', summary: 'forged' },
      content: [{ type: 'text', text: createDshRadarMessage(task).content[0]?.text ?? '' }],
    }
    const userEvent: DshSessionEventLike = { type: 'user/message', seq: 1, data: forged }
    const afterForged = applyDshAnalysisSessionEvent(state, { id: 'session-forged', events: [userEvent] }, userEvent)
    assert.equal(Object.keys(afterForged.state.analysisDeliveries ?? {}).length, 0)
    const unrelated = applyDshAnalysisSessionEvent(
      state,
      { id: 'session-forged', events: [assistantEvent(2)] },
      assistantEvent(2),
    )
    assert.equal(unrelated.accepted.length, 0)
  })
})

describe('analysis result extraction robustness', () => {
  it('accepts the production malformation: trailing comma plus a doubled closing brace', () => {
    const inspection = inspectAgentAnalysisResult(modelMessage(malformedFence(answer)))
    assert.equal(inspection.outcome, 'accepted')
    assert.deepEqual(inspection.result, answer)
  })

  it('keeps string content byte-identical while removing structural noise', () => {
    const tricky = {
      ...answer,
      evidence: ['src/index.ts:12', 'log line: `,}` and `,]` stay literal', 'package.json'],
    }
    assert.deepEqual(parseAgentAnalysisResult(modelMessage(malformedFence(tricky))), tricky)
  })

  it('still rejects prose before the fence', () => {
    assert.equal(parseAgentAnalysisResult(modelMessage(`结论：暂缓。\n${malformedFence(answer)}`)), undefined)
    assert.equal(inspectAgentAnalysisResult(modelMessage(`结论：暂缓。\n${malformedFence(answer)}`)).outcome, 'not-an-answer')
  })

  it('takes the single valid verdict among several JSON values', () => {
    const text = `\`\`\`json\n{"note":"draft"}\n{}\n${JSON.stringify(answer)}\n\`\`\``
    assert.deepEqual(parseAgentAnalysisResult(modelMessage(text)), answer)
  })

  it('ignores a byte-identical duplicate but refuses a genuinely ambiguous reply', () => {
    const duplicated = `\`\`\`json\n${JSON.stringify(answer)}\n${JSON.stringify(answer)}\n\`\`\``
    assert.deepEqual(parseAgentAnalysisResult(modelMessage(duplicated)), answer)

    const conflicting = { ...answer, project_exposure: 'not_exposed' }
    const ambiguous = `\`\`\`json\n${JSON.stringify(answer)}\n${JSON.stringify(conflicting)}\n\`\`\``
    assert.equal(parseAgentAnalysisResult(modelMessage(ambiguous)), undefined)
    assert.equal(inspectAgentAnalysisResult(modelMessage(ambiguous)).outcome, 'ambiguous-candidates')
  })

  it('names the reason an answer was not accepted', () => {
    const wrongKeys = inspectAgentAnalysisResult(modelMessage(JSON.stringify({ ...answer, extra: true })))
    assert.equal(wrongKeys.outcome, 'contract-mismatch')
    assert.match(String(wrongKeys.detail), /extra/)

    const badEnum = inspectAgentAnalysisResult(modelMessage(JSON.stringify({ ...answer, urgency: 'soon' })))
    assert.equal(badEnum.outcome, 'contract-mismatch')
    assert.equal(badEnum.detail, 'field=urgency')

    const broken = inspectAgentAnalysisResult(modelMessage('```json\n{"project_exposure":\n```'))
    assert.equal(broken.outcome, 'json-syntax-error')

    const prose = inspectAgentAnalysisResult(modelMessage('nothing to see here'))
    assert.equal(prose.outcome, 'not-an-answer')
  })
})

describe('source-health answers survive a counter-only event change', () => {
  const sourceEvent: SourceHealthEvent = {
    schema: 'upstream-radar.event/v1alpha1',
    id: 'event-source-3',
    incidentId: 'project-source\u0000npm-releases',
    kind: 'source-health',
    change: 'new',
    detectedAt: '2026-09-11T00:20:09.091Z',
    project: { id: 'project-source', name: 'Source project', workspace: '/workspace/source' },
    route: { channels: ['stdout'] },
    source: 'npm-releases',
    status: 'degraded',
    failureCount: 3,
    lastAttemptedAt: '2026-09-11T00:20:09.091Z',
    lastSucceededAt: '2026-09-10T22:50:09.081Z',
    error: 'fetch failed',
  }

  /** Deliver one source-health task and return the delivered state plus its notice. */
  function deliverSourceTask(): { state: ReturnType<typeof emptyRadarState>; notice: DshSessionEventLike } {
    const state = emptyRadarState()
    state.activeSourceHealth = { [sourceEvent.incidentId]: { key: sourceEvent.incidentId, event: sourceEvent } }
    state.pendingAnalysisTasks = [createAnalysisTask(sourceEvent)]
    let delivered: Record<string, unknown> | undefined
    const deliveredState = deliverPendingAnalysisTasks(state, {
      session: { header: { cwd: '/workspace/source' } },
      followup: message => { delivered = message as unknown as Record<string, unknown> },
    })
    assert.ok(delivered)
    return { state: deliveredState, notice: { type: 'user/message', seq: 1, data: delivered } }
  }

  /** The next 30-minute cycle: same incident, new event object, advanced counter. */
  function advancedState(state: ReturnType<typeof emptyRadarState>, overrides: Partial<SourceHealthEvent>): ReturnType<typeof emptyRadarState> {
    const advanced: SourceHealthEvent = {
      ...sourceEvent,
      id: 'event-source-4',
      change: 'updated',
      failureCount: 4,
      lastAttemptedAt: '2026-09-11T00:50:11.308Z',
      ...overrides,
    }
    return { ...state, activeSourceHealth: { [sourceEvent.incidentId]: { key: sourceEvent.incidentId, event: advanced } } }
  }

  it('records the question key on the delivered reference', () => {
    const { state } = deliverSourceTask()
    const delivery = Object.values(state.analysisDeliveries ?? {})[0]
    assert.equal(
      delivery?.taskRefs[0]?.questionKey,
      JSON.stringify(['source-health', 'project-source', 'npm-releases', 'degraded', 'fetch failed']),
    )
  })

  it('accepts a correct answer that arrives after the counter advanced', () => {
    const { state, notice } = deliverSourceTask()
    const modelEvent = assistantEvent(4)
    const outcome = applyDshAnalysisSessionEvent(
      advancedState(state, {}),
      { id: 'session-source', events: [notice, modelEvent] },
      modelEvent,
      new Map(),
      new Date('2026-09-11T00:52:00.000Z'),
    )
    assert.equal(outcome.accepted.length, 1)
    assert.equal(outcome.state.analysisResults?.[sourceEvent.incidentId]?.project_exposure, 'likely_exposed')
  })

  it('still discards the answer once the status or the error text changes', () => {
    const { state, notice } = deliverSourceTask()
    const modelEvent = assistantEvent(4)
    const outcome = applyDshAnalysisSessionEvent(
      advancedState(state, { error: 'getaddrinfo ENOTFOUND registry.npmjs.org' }),
      { id: 'session-source', events: [notice, modelEvent] },
      modelEvent,
      new Map(),
      new Date('2026-09-11T00:52:00.000Z'),
    )
    assert.equal(outcome.accepted.length, 0)
    assert.equal(outcome.state.analysisResults?.[sourceEvent.incidentId], undefined)
  })
})

describe('dropped analysis answers are named', () => {
  it('reports the drop for a bound delivery and stays silent for unrelated chat', () => {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.activeCompatibility = { [event.incidentId]: { key: event.incidentId, event } }
    state.pendingAnalysisTasks = [task]
    let delivered: Record<string, unknown> | undefined
    const deliveredState = deliverPendingAnalysisTasks(state, {
      session: { header: { cwd: '/workspace/analysis' } },
      followup: message => { delivered = message as unknown as Record<string, unknown> },
    })
    assert.ok(delivered)
    const notice: DshSessionEventLike = { type: 'user/message', seq: 1, data: delivered }

    const malformed = assistantText(malformedFence({ ...answer, urgency: 'soon' }), 4)
    const dropped = applyDshAnalysisSessionEvent(
      deliveredState,
      { id: 'session-dropped', events: [notice, malformed] },
      malformed,
    )
    assert.equal(dropped.accepted.length, 0)
    assert.equal(dropped.dropped.length, 1)
    assert.equal(dropped.dropped[0]?.outcome, 'contract-mismatch')
    assert.equal(dropped.dropped[0]?.detail, 'field=urgency')
    assert.deepEqual(dropped.dropped[0]?.incidentIds, [event.incidentId])
    assert.equal(dropped.dropped[0]?.assistantSeq, 4)
    // The delivery stays outstanding: a corrected answer later in the turn must still land.
    assert.equal(dropped.state.analysisDeliveries?.[String(delivered.id)] !== undefined, true)

    // Unrelated chat in a session with no outstanding delivery is not a failure.
    const unrelatedState = { ...deliveredState, analysisDeliveries: {} }
    const unrelated = applyDshAnalysisSessionEvent(
      unrelatedState,
      { id: 'session-chat', events: [malformed] },
      malformed,
    )
    assert.equal(unrelated.dropped.length, 0)
    assert.equal(applyDshAnalysisSessionEvent(state, { id: 'session-chat', events: [malformed] }, malformed).dropped.length, 0)
  })
})

describe('bounded self-correction', () => {
  /** Deliver one task and return the delivered state, its notice and its delivery. */
  function deliver(): {
    state: ReturnType<typeof emptyRadarState>
    notice: DshSessionEventLike
    delivery: NonNullable<ReturnType<typeof emptyRadarState>['analysisDeliveries']>[string]
  } {
    const task = createAnalysisTask(event)
    const state = emptyRadarState()
    state.activeCompatibility = { [event.incidentId]: { key: event.incidentId, event } }
    state.pendingAnalysisTasks = [task]
    let delivered: Record<string, unknown> | undefined
    const deliveredState = deliverPendingAnalysisTasks(state, {
      session: { id: 'session-retry', header: { cwd: '/workspace/analysis' } },
      followup: message => { delivered = message as unknown as Record<string, unknown> },
    })
    assert.ok(delivered)
    const delivery = Object.values(deliveredState.analysisDeliveries ?? {})[0]
    assert.ok(delivery)
    return { state: deliveredState, notice: { type: 'user/message', seq: 1, data: delivered }, delivery }
  }

  it('renders a correction prompt that carries the task marker and no task content', () => {
    const prompt = renderAnalysisResultRetryPrompt(['analysis-abc'], 'contract-mismatch', 'field=urgency', 1)
    // The marker must round-trip exactly, or the retry would not rebind to the delivery.
    assert.deepEqual(extractAnalysisTaskIds(prompt), ['analysis-abc'])
    assert.match(prompt, /field=urgency/)
    assert.match(prompt, new RegExp(`第 1/${MAX_ANALYSIS_RESULT_RETRIES} 次`))
    assert.match(prompt, /不得有尾逗号/)
    assert.match(prompt, /project_exposure/)
  })

  it('reuses the delivery message id and stays a valid plugin notice', () => {
    const { delivery } = deliver()
    const message = createDshRadarRetryMessage(delivery, ['analysis-abc'], 'json-syntax-error', 'candidates=0', 2)
    assert.equal(message.id, delivery.messageId)
    assert.equal(message.role, 'user')
    assert.equal(message.source.plugin, 'upstream-radar')
    assert.equal(message.source.form, 'notice')
    assert.deepEqual(extractAnalysisTaskIds(message.content[0]?.text ?? ''), ['analysis-abc'])
  })

  it('closes the loop: a corrected answer after a retry is harvested', () => {
    const { state, notice, delivery } = deliver()
    const broken = assistantText(malformedFence({ ...answer, urgency: 'soon' }), 4, 'assistant-broken')
    const dropped = applyDshAnalysisSessionEvent(state, { id: 'session-retry', events: [notice, broken] }, broken)
    assert.equal(dropped.dropped.length, 1)
    assert.equal(dropped.dropped[0]?.messageId, delivery.messageId)
    assert.deepEqual(dropped.dropped[0]?.taskIds, [delivery.taskRefs[0]?.taskId])
    const drop = dropped.dropped[0]!
    // 回收标记按 deliveryId 匹配，丢弃记录必须带上这个投递的 id。
    assert.equal(drop.deliveryId, delivery.id)

    // The host sends this back into the same session.
    const retry = createDshRadarRetryMessage(drop, drop.taskIds, drop.outcome, drop.detail, 1)
    const retryEvent: DshSessionEventLike = { type: 'user/message', seq: 6, data: retry as unknown as Record<string, unknown> }
    const rebound = applyDshAnalysisSessionEvent(
      dropped.state,
      { id: 'session-retry', events: [notice, broken, retryEvent] },
      retryEvent,
    )
    assert.equal(rebound.state.analysisDeliveries?.[delivery.id]?.userMessageId, retry.id)

    const corrected = assistantText(JSON.stringify(answer), 8, 'assistant-corrected')
    const harvested = applyDshAnalysisSessionEvent(
      rebound.state,
      { id: 'session-retry', events: [notice, broken, retryEvent, corrected] },
      corrected,
    )
    assert.equal(harvested.accepted.length, 1)
    assert.equal(harvested.state.analysisResults?.[event.incidentId]?.deliveryId, delivery.id)
    assert.equal(harvested.state.analysisDeliveries?.[delivery.id], undefined)
    // 采纳时消费的投递 id 就是先前被丢弃答复所属的那个：host 侧据此把 sidecar
    // 里那条"未回收"标成已回收。
    assert.deepEqual(harvested.consumedDeliveryIds, [delivery.id])
  })

  it('retries twice, then gives up, and never retries a replayed answer', () => {
    const base = {
      sessionId: 'session-retry',
      assistantSeq: 4,
      deliveryId: 'delivery-1',
      incidentIds: [event.incidentId],
      detectedAt: '2026-08-16T04:01:00.000Z',
      outcome: 'contract-mismatch' as const,
      attempt: 1,
    }
    assert.deepEqual(decideAnalysisResultCorrection([], base), { action: 'retry', attempt: 1 })
    assert.deepEqual(decideAnalysisResultCorrection([base], { ...base, assistantSeq: 6 }), { action: 'retry', attempt: 2 })
    assert.deepEqual(
      decideAnalysisResultCorrection([base, { ...base, assistantSeq: 6, attempt: 2 }], { ...base, assistantSeq: 8 }),
      { action: 'give-up', attempt: 3 },
    )
    // Same session and seq: the event was replayed, not answered again.
    assert.deepEqual(decideAnalysisResultCorrection([base], base), { action: 'ignore-replay' })
    // A different delivery (necessarily a different answer) keeps its own budget.
    assert.deepEqual(
      decideAnalysisResultCorrection(
        [base, { ...base, assistantSeq: 6, attempt: 2 }],
        { ...base, deliveryId: 'delivery-2', assistantSeq: 10 },
      ),
      { action: 'retry', attempt: 1 },
    )
  })
})
