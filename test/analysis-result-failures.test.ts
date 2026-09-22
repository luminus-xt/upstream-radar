import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  MAX_ANALYSIS_RESULT_FAILURES,
  analysisResultFailureLogPath,
  markAnalysisResultFailuresRecovered,
  readAnalysisResultFailures,
  recordAnalysisResultFailure,
  type AnalysisResultFailure,
} from '../src/analysis-result-failures.js'
import { decideAnalysisResultCorrection } from '../src/dsh-plugin.js'

function failure(overrides: Partial<AnalysisResultFailure> = {}): AnalysisResultFailure {
  return {
    sessionId: 'session-receptor',
    assistantSeq: 4,
    incidentIds: ['project\u0000npm-releases'],
    detectedAt: '2026-09-11T00:22:44.000Z',
    outcome: 'contract-mismatch',
    detail: 'field=urgency',
    attempt: 1,
    ...overrides,
  }
}

describe('analysis result failure log', () => {
  it('records and reads back a dropped answer', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      await recordAnalysisResultFailure(stateFile, failure({ deliveryId: 'delivery-1', assistantMessageId: 'message-1' }))
      const failures = await readAnalysisResultFailures(stateFile)
      assert.equal(failures.length, 1)
      assert.equal(failures[0]?.deliveryId, 'delivery-1')
      assert.equal(failures[0]?.assistantMessageId, 'message-1')
      assert.equal(failures[0]?.detail, 'field=urgency')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('replaces the same answer instead of duplicating a replayed event', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      await recordAnalysisResultFailure(stateFile, failure({ detectedAt: '2026-09-11T00:22:44.000Z' }))
      await recordAnalysisResultFailure(stateFile, failure({
        detectedAt: '2026-09-11T00:22:45.000Z',
        outcome: 'json-syntax-error',
        detail: 'candidates=0',
      }))
      const failures = await readAnalysisResultFailures(stateFile)
      assert.equal(failures.length, 1)
      assert.equal(failures[0]?.outcome, 'json-syntax-error')
      assert.equal(failures[0]?.detail, 'candidates=0')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('keeps the newest entries and stays bounded', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      const total = MAX_ANALYSIS_RESULT_FAILURES + 5
      for (let index = 0; index < total; index += 1) {
        await recordAnalysisResultFailure(stateFile, failure({
          assistantSeq: index,
          detectedAt: new Date(Date.UTC(2026, 8, 11, 0, 0, index)).toISOString(),
        }))
      }
      const failures = await readAnalysisResultFailures(stateFile)
      assert.equal(failures.length, MAX_ANALYSIS_RESULT_FAILURES)
      assert.equal(failures.at(-1)?.assistantSeq, total - 1)
      assert.equal(failures[0]?.assistantSeq, total - MAX_ANALYSIS_RESULT_FAILURES)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('treats a missing or damaged log as empty instead of failing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      assert.deepEqual(await readAnalysisResultFailures(stateFile), [])
      await writeFile(analysisResultFailureLogPath(stateFile), '{ not json')
      assert.deepEqual(await readAnalysisResultFailures(stateFile), [])
      await writeFile(analysisResultFailureLogPath(stateFile), JSON.stringify({
        schema: 'upstream-radar.analysis-result-failures/v1alpha1',
        failures: [{ sessionId: 's', assistantSeq: 1, detectedAt: 'now', outcome: 'not-a-real-outcome', incidentIds: [] }],
      }))
      assert.deepEqual(await readAnalysisResultFailures(stateFile), [])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe('analysis result failure recovery marking', () => {
  it('survives a later read-modify-write of the same log', async () => {
    // 回归：这个日志每次记录都是"读 → 改 → 写"。任何没有在 parseFailure 里被
    // 重建的字段都会在下一次写入时被静默抹掉，回收标记也不例外。
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      await recordAnalysisResultFailure(stateFile, failure({ deliveryId: 'delivery-1' }))
      assert.equal(
        await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-1']), '2026-09-13T12:53:57.856Z'),
        1,
      )
      await recordAnalysisResultFailure(stateFile, failure({
        sessionId: 'session-other',
        assistantSeq: 9,
        deliveryId: 'delivery-2',
        detectedAt: '2026-09-13T13:00:00.000Z',
      }))
      const failures = await readAnalysisResultFailures(stateFile)
      assert.equal(failures.length, 2)
      assert.equal(failures.find(entry => entry.deliveryId === 'delivery-1')?.recoveredAt, '2026-09-13T12:53:57.856Z')
      assert.equal(failures.find(entry => entry.deliveryId === 'delivery-2')?.recoveredAt, undefined)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('marks only the given deliveries and is idempotent', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      await recordAnalysisResultFailure(stateFile, failure({ assistantSeq: 4, deliveryId: 'delivery-1' }))
      await recordAnalysisResultFailure(stateFile, failure({
        assistantSeq: 5,
        deliveryId: 'delivery-2',
        detectedAt: '2026-09-11T00:23:00.000Z',
      }))
      assert.equal(
        await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-1']), '2026-09-13T12:53:57.856Z'),
        1,
      )
      // 第二次标记同一投递不再计入，也不覆盖首次写入的时间。
      assert.equal(
        await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-1']), '2026-09-14T00:00:00.000Z'),
        0,
      )
      const failures = await readAnalysisResultFailures(stateFile)
      assert.equal(failures.find(entry => entry.deliveryId === 'delivery-1')?.recoveredAt, '2026-09-13T12:53:57.856Z')
      assert.equal(failures.find(entry => entry.deliveryId === 'delivery-2')?.recoveredAt, undefined)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('keeps a recovered entry usable as the replay guard', async () => {
    // 回收标记只能改变面板读数，不能把记录本身删掉：这条日志同时是防重复纠错的
    // 守卫，记录消失会让重放的事件再触发一次纠错。
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      await recordAnalysisResultFailure(stateFile, failure({ deliveryId: 'delivery-1' }))
      await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-1']), '2026-09-13T12:53:57.856Z')
      assert.deepEqual(
        decideAnalysisResultCorrection(await readAnalysisResultFailures(stateFile), {
          sessionId: 'session-receptor',
          assistantSeq: 4,
          deliveryId: 'delivery-1',
        }),
        { action: 'ignore-replay' },
      )
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('writes nothing when no recorded answer belongs to the delivery', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      // 没有任何记录时不得凭空创建这个诊断文件。
      assert.equal(await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-x']), 'at'), 0)
      assert.equal(existsSync(analysisResultFailureLogPath(stateFile)), false)
      await recordAnalysisResultFailure(stateFile, failure({ deliveryId: 'delivery-1' }))
      assert.equal(await markAnalysisResultFailuresRecovered(stateFile, new Set(['delivery-x']), 'at'), 0)
      assert.equal(await markAnalysisResultFailuresRecovered(stateFile, new Set(), 'at'), 0)
      assert.equal((await readAnalysisResultFailures(stateFile))[0]?.recoveredAt, undefined)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
