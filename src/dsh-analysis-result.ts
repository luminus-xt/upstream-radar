import {
  ANALYSIS_TASK_SCHEMA,
  type AgentAnalysisResult,
} from './radar-types.js'

const TASK_ID = '[A-Za-z0-9][A-Za-z0-9._:-]{0,127}'
const MARKER_PATTERN = new RegExp(
  `^\\[UPSTREAM RADAR ANALYSIS TASK (?:id|ids)=(${TASK_ID}(?:,${TASK_ID})*) schema=${ANALYSIS_TASK_SCHEMA.replaceAll('.', '\\.') }\\]\\s*`,
)

const RESULT_KEYS = [
  'project_exposure',
  'confidence',
  'evidence',
  'recommended_action',
  'urgency',
  'reasoning_summary',
] as const

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}
function boundedText(value: unknown, maxLength: number, allowEmpty = false): value is string {
  return typeof value === 'string'
    && value.length <= maxLength
    && (allowEmpty || value.trim().length > 0)
}

/** Render a stable, machine-readable prefix that identifies the Radar task(s). */
export function renderAnalysisTaskMarker(taskIds: readonly string[]): string {
  if (taskIds.length === 0 || taskIds.length > 64) throw new Error('analysis task marker requires 1 to 64 task ids')
  const unique = new Set(taskIds)
  if (unique.size !== taskIds.length || taskIds.some(taskId => !new RegExp(`^${TASK_ID}$`).test(taskId))) {
    throw new Error('analysis task marker contains an invalid or duplicate task id')
  }
  const field = taskIds.length === 1 ? `id=${taskIds[0]}` : `ids=${taskIds.join(',')}`
  return `[UPSTREAM RADAR ANALYSIS TASK ${field} schema=${ANALYSIS_TASK_SCHEMA}]`
}

/** Read task ids only from the prefix emitted by this plugin. */
export function extractAnalysisTaskIds(text: string): string[] | undefined {
  const match = MARKER_PATTERN.exec(text)
  if (match === null) return undefined
  const raw = match[1]
  if (raw === undefined) return undefined
  const ids = raw.split(',')
  if (ids.length === 0 || ids.length > 64 || new Set(ids).size !== ids.length) return undefined
  return ids
}

function textFromMessage(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  const message = asRecord(value)
  const content = message?.content
  if (!Array.isArray(content)) return undefined
  const textBlocks = content.flatMap(block => {
    const record = asRecord(block)
    return record?.type === 'text' && typeof record.text === 'string' ? [record.text] : []
  })
  return textBlocks.length === 0 ? undefined : textBlocks.join('')
}

const MAX_CANDIDATES = 64

/**
 * A few model adapters preserve a JSON code fence. Accept only a response that
 * OPENS with the fence; anything after its closing fence (e.g. a follow-up
 * conclusion summary, per the two-step reply protocol) is ignored. Never search
 * arbitrary prose for JSON: prose before the fence still rejects.
 */
const FENCED_OPEN = /^```(?:json)?\s*\r?\n([\s\S]*?)\r?\n```(?:[\s\S]*)$/

function isJsonWhitespace(character: string): boolean {
  return character === ' ' || character === '\t' || character === '\n' || character === '\r'
}

/**
 * Drop commas that sit at a structural position, i.e. a comma followed only by
 * whitespace and then a closing brace or bracket.
 *
 * This is a lexical scan, never a regular-expression replacement: `evidence`
 * entries are free text and may themselves contain `,}`. Normalization only
 * removes syntax noise; it never rewrites, adds or removes a value.
 */
function stripStructuralTrailingCommas(text: string): string {
  const out: string[] = []
  let inString = false
  let escaped = false
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index] as string
    if (inString) {
      out.push(character)
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (character === '"') {
      inString = true
      out.push(character)
      continue
    }
    if (character === ',') {
      let cursor = index + 1
      while (cursor < text.length && isJsonWhitespace(text[cursor] as string)) cursor += 1
      const next = text[cursor]
      if (next === '}' || next === ']') continue
    }
    out.push(character)
  }
  return out.join('')
}

/**
 * Collect every complete top-level JSON value in `body`.
 *
 * A model that closes the object twice (`}` on its own line after the real
 * closer) leaves trailing junk behind. Scanning for balanced values instead of
 * requiring the whole body to be exactly one value keeps that reply usable,
 * without ever reading JSON out of surrounding prose.
 */
function balancedJsonValues(body: string): string[] {
  const values: string[] = []
  let depth = 0
  let start = -1
  let inString = false
  let escaped = false
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index] as string
    if (inString) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (character === '"') {
      inString = true
      continue
    }
    if (character === '{' || character === '[') {
      if (depth === 0) start = index
      depth += 1
      continue
    }
    if (character === '}' || character === ']') {
      if (depth === 0) continue
      depth -= 1
      if (depth === 0 && start >= 0) {
        values.push(body.slice(start, index + 1))
        start = -1
        if (values.length >= MAX_CANDIDATES) return values
      }
    }
  }
  return values
}

function parseJsonValue(text: string): unknown {
  try {
    return JSON.parse(text) as unknown
  } catch {
    try {
      return JSON.parse(stripStructuralTrailingCommas(text)) as unknown
    } catch {
      return undefined
    }
  }
}

/**
 * Extract every JSON value a reply is allowed to contain.
 *
 * Returns `undefined` when the reply is not an answer at all (no fence and not
 * bare JSON), which is deliberately different from returning an empty list: an
 * unattempted reply is not a failure and must not be reported as one.
 */
function jsonCandidates(text: string): unknown[] | undefined {
  const trimmed = text.trim()
  if (trimmed === '') return undefined
  const bare = parseJsonValue(trimmed)
  if (bare !== undefined) return [bare]
  const fenced = FENCED_OPEN.exec(trimmed)
  if (fenced?.[1] === undefined) return undefined
  const body = fenced[1]
  const direct = parseJsonValue(body)
  if (direct !== undefined) return [direct]
  return balancedJsonValues(body).flatMap(value => {
    const parsed = parseJsonValue(value)
    return parsed === undefined ? [] : [parsed]
  })
}

type ContractCheck = { ok: true; result: AgentAnalysisResult } | { ok: false; detail: string }

/**
 * Validate the exact six-field JSON contract.
 *
 * This is the contract itself and stays deliberately strict: exact key set,
 * bounded lengths, enumerated values. Normalization happens entirely in
 * `jsonCandidates` and can never add, drop or rename a field.
 */
function checkAnalysisResult(parsed: Record<string, unknown>): ContractCheck {
  const keys = Object.keys(parsed).sort()
  const expectedKeys = [...RESULT_KEYS].sort()
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    return { ok: false, detail: `keys=${keys.join(',').slice(0, 200)}` }
  }
  if (parsed.project_exposure !== 'exposed'
    && parsed.project_exposure !== 'likely_exposed'
    && parsed.project_exposure !== 'not_exposed'
    && parsed.project_exposure !== 'unknown') return { ok: false, detail: 'field=project_exposure' }
  if (parsed.confidence !== 'high' && parsed.confidence !== 'medium' && parsed.confidence !== 'low') {
    return { ok: false, detail: 'field=confidence' }
  }
  if (parsed.urgency !== 'immediate'
    && parsed.urgency !== 'within_24_hours'
    && parsed.urgency !== 'planned'
    && parsed.urgency !== 'monitor') return { ok: false, detail: 'field=urgency' }
  if (!Array.isArray(parsed.evidence) || parsed.evidence.length > 64
    || !parsed.evidence.every(item => boundedText(item, 4_096))) return { ok: false, detail: 'field=evidence' }
  if (!boundedText(parsed.recommended_action, 8_192)
    || !boundedText(parsed.reasoning_summary, 16_384)) return { ok: false, detail: 'field=text-length' }
  return {
    ok: true,
    result: {
      project_exposure: parsed.project_exposure,
      confidence: parsed.confidence,
      evidence: [...parsed.evidence],
      recommended_action: parsed.recommended_action,
      urgency: parsed.urgency,
      reasoning_summary: parsed.reasoning_summary,
    },
  }
}

/** Why a reply that looked like an answer was not accepted as one. */
export type AgentAnalysisResultOutcome =
  | 'accepted'
  | 'not-an-answer'
  | 'oversized-text'
  | 'json-syntax-error'
  | 'contract-mismatch'
  | 'ambiguous-candidates'

export interface AgentAnalysisResultInspection {
  outcome: AgentAnalysisResultOutcome
  result?: AgentAnalysisResult
  /** Bounded, structural explanation (key names or field names), never raw model text. */
  detail?: string
}

/**
 * Inspect one assistant message against the analysis-result contract.
 *
 * Callers that only need the value use `parseAgentAnalysisResult`; callers that
 * must make a dropped verdict visible use the outcome and detail as well.
 */
export function inspectAgentAnalysisResult(value: unknown): AgentAnalysisResultInspection {
  const message = asRecord(value)
  if (message !== undefined) {
    if (message.role !== 'assistant') return { outcome: 'not-an-answer' }
    const source = asRecord(message.source)
    if (source?.kind !== 'model') return { outcome: 'not-an-answer' }
  }
  const text = textFromMessage(value)
  if (text === undefined) return { outcome: 'not-an-answer' }
  if (text.length > 64 * 1024) return { outcome: 'oversized-text', detail: `length=${text.length}` }
  const candidates = jsonCandidates(text)
  if (candidates === undefined) return { outcome: 'not-an-answer' }
  if (candidates.length === 0) return { outcome: 'json-syntax-error', detail: 'candidates=0' }
  const accepted: AgentAnalysisResult[] = []
  const details: string[] = []
  const seen = new Set<string>()
  for (const candidate of candidates) {
    const parsed = asRecord(candidate)
    if (parsed === undefined) {
      details.push('candidate=not-an-object')
      continue
    }
    const checked = checkAnalysisResult(parsed)
    if (!checked.ok) {
      details.push(checked.detail)
      continue
    }
    const canonical = JSON.stringify(checked.result)
    if (seen.has(canonical)) continue
    seen.add(canonical)
    accepted.push(checked.result)
  }
  const only = accepted[0]
  if (accepted.length === 1 && only !== undefined) return { outcome: 'accepted', result: only }
  if (accepted.length > 1) {
    return { outcome: 'ambiguous-candidates', detail: `valid=${accepted.length}` }
  }
  return { outcome: 'contract-mismatch', detail: [...new Set(details)].join(';').slice(0, 240) }
}

/**
 * Parse the exact JSON contract emitted by the DSH model.
 *
 * This function deliberately rejects prose, extra fields, and oversized text.
 * The result is advisory data only; callers still attach it to the exact Radar
 * event and must not treat it as proof that a project is safe.
 */
export function parseAgentAnalysisResult(value: unknown): AgentAnalysisResult | undefined {
  return inspectAgentAnalysisResult(value).result
}
