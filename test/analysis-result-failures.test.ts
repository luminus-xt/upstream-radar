import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  MAX_ANALYSIS_RESULT_FAILURES,
  analysisResultFailureLogPath,
  readAnalysisResultFailures,
  recordAnalysisResultFailure,
  type AnalysisResultFailure,
} from '../src/analysis-result-failures.js'

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
