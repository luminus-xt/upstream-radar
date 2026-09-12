import { readFile, rename, writeFile } from 'node:fs/promises'

/**
 * Sidecar log for analysis answers that reached a receiving session but were
 * never accepted as a verdict.
 *
 * The main Radar state is rebuilt from scratch on every poll, so anything that
 * is not part of that rebuild is kept beside it in its own file, exactly like
 * the benign release notices. Without this log a dropped verdict is invisible:
 * the delivery simply stays outstanding and the panel shows nothing.
 */
export const ANALYSIS_RESULT_FAILURES_SCHEMA = 'upstream-radar.analysis-result-failures/v1alpha1'

export const MAX_ANALYSIS_RESULT_FAILURES = 100

/** Why an answer that looked like a verdict was not accepted as one. */
export type DroppedAnalysisAnswerOutcome =
  | 'oversized-text'
  | 'json-syntax-error'
  | 'contract-mismatch'
  | 'ambiguous-candidates'

export interface AnalysisResultFailure {
  sessionId: string
  assistantSeq: number
  assistantMessageId?: string
  deliveryId?: string
  incidentIds: string[]
  detectedAt: string
  outcome: DroppedAnalysisAnswerOutcome
  /** Bounded, structural explanation (key or field names), never raw model text. */
  detail?: string
  /** 1-based correction round; 1 is the original answer. */
  attempt: number
  /** Set when the correction budget is exhausted and no retry was sent. */
  unrecoverable?: boolean
}

export function analysisResultFailureLogPath(stateFile: string): string {
  return `${stateFile}.analysis-result-failures.json`
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function boundedText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
}

const OUTCOMES: readonly DroppedAnalysisAnswerOutcome[] = [
  'oversized-text',
  'json-syntax-error',
  'contract-mismatch',
  'ambiguous-candidates',
]

function parseFailure(value: unknown): AnalysisResultFailure | undefined {
  const failure = asRecord(value)
  if (failure === undefined) return undefined
  const outcome = failure.outcome
  if (typeof outcome !== 'string' || !OUTCOMES.includes(outcome as DroppedAnalysisAnswerOutcome)) return undefined
  const incidentIds = failure.incidentIds
  if (!Array.isArray(incidentIds) || incidentIds.length > 64
    || !incidentIds.every(item => boundedText(item, 512))) return undefined
  const assistantSeq = failure.assistantSeq
  if (!boundedText(failure.sessionId, 512) || typeof assistantSeq !== 'number'
    || !Number.isSafeInteger(assistantSeq) || assistantSeq < 0
    || !boundedText(failure.detectedAt, 256)) return undefined
  if (failure.assistantMessageId !== undefined && !boundedText(failure.assistantMessageId, 512)) return undefined
  if (failure.deliveryId !== undefined && !boundedText(failure.deliveryId, 512)) return undefined
  if (failure.detail !== undefined && !boundedText(failure.detail, 1_024)) return undefined
  const attempt = failure.attempt
  if (typeof attempt !== 'number' || !Number.isSafeInteger(attempt) || attempt < 1 || attempt > 1_000) return undefined
  if (failure.unrecoverable !== undefined && typeof failure.unrecoverable !== 'boolean') return undefined
  return {
    sessionId: failure.sessionId,
    assistantSeq,
    ...(failure.assistantMessageId === undefined ? {} : { assistantMessageId: failure.assistantMessageId }),
    ...(failure.deliveryId === undefined ? {} : { deliveryId: failure.deliveryId }),
    incidentIds: [...incidentIds],
    detectedAt: failure.detectedAt,
    outcome: outcome as DroppedAnalysisAnswerOutcome,
    ...(failure.detail === undefined ? {} : { detail: failure.detail }),
    attempt,
    ...(failure.unrecoverable === undefined ? {} : { unrecoverable: failure.unrecoverable }),
  }
}

/**
 * Read the failure log. A missing or damaged file reads as "no failures": this
 * log is diagnostic, and it must never be able to stop the plugin from loading
 * the state it actually needs.
 */
export async function readAnalysisResultFailures(stateFile: string): Promise<AnalysisResultFailure[]> {
  try {
    const root = asRecord(JSON.parse(await readFile(analysisResultFailureLogPath(stateFile), 'utf8')))
    if (root?.schema !== ANALYSIS_RESULT_FAILURES_SCHEMA || !Array.isArray(root.failures)) return []
    return root.failures.flatMap(entry => {
      const failure = parseFailure(entry)
      return failure === undefined ? [] : [failure]
    })
  } catch {
    return []
  }
}

function failureKey(failure: AnalysisResultFailure): string {
  return `${failure.sessionId}\u0000${failure.assistantSeq}`
}

/** Record (or refresh) one dropped answer, keeping the newest entries. */
export async function recordAnalysisResultFailure(
  stateFile: string,
  failure: AnalysisResultFailure,
): Promise<void> {
  const existing = await readAnalysisResultFailures(stateFile)
  const key = failureKey(failure)
  const merged = [...existing.filter(entry => failureKey(entry) !== key), failure]
    .sort((left, right) => left.detectedAt.localeCompare(right.detectedAt))
  const failures = merged.slice(Math.max(0, merged.length - MAX_ANALYSIS_RESULT_FAILURES))
  const path = analysisResultFailureLogPath(stateFile)
  const temporary = `${path}.tmp`
  await writeFile(temporary, `${JSON.stringify({ schema: ANALYSIS_RESULT_FAILURES_SCHEMA, failures }, null, 2)}\n`, 'utf8')
  await rename(temporary, path)
}
