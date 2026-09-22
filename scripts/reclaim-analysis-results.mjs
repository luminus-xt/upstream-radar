#!/usr/bin/env node
// Operator repair tool: reclaim analysis results from a DSH session transcript.
//
// The live plugin only sees what it is handed at delivery time. When a reply
// could not be observed (for example because the session object exposed a
// snapshot accessor instead of an event list, so the assistant-message branch
// matched nothing), the results of already-delivered tasks stay unclaimed. This
// tool replays the receiving session's real transcript through the plugin's own
// analysis-session handler and persists the resulting state — exactly what the
// live handler would have done.
//
// Usage:
//   pnpm run build
//   node scripts/reclaim-analysis-results.mjs --session-file <session.jsonl.zstd> [options]
//
// Guards:
//  - refuses to run while a poll cycle may still be writing the state file
//    (state mtime younger than --min-age, default 120s; --force skips);
//  - replays each reply with only the history that preceded it;
//  - writes the state file only when the replay actually changed it.
import { stat } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { basename, dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zstdDecompressSync } from 'node:zlib'
import { loadRadarState, saveRadarState } from '../dist/src/radar-state.js'
import { applyDshAnalysisSessionEvent } from '../dist/src/dsh-plugin.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_MIN_AGE_MS = 120_000
const ZSTD_MAGIC = 4247762216

const HELP = `usage: node scripts/reclaim-analysis-results.mjs --session-file <file> [options]

Replay a DSH session transcript through the plugin's analysis-session handler and
persist the reclaimed results, so deliveries the live handler could not observe
are settled.

options:
  --session-file <file>  multi-frame zstd session transcript (required)
  --session-id <id>      session id recorded in the replayed events
                         (default: parent directory name of --session-file)
  --since <when>         only replay assistant messages after this point:
                         an ISO timestamp or epoch milliseconds (default: all)
  --state <file>         radar state file (default: $UPSTREAM_RADAR_STATE_FILE,
                         else <repo>/upstream-radar.state.json)
  --min-age <secs>       freshness guard: refuse to run when the state file was
                         written more recently than this (default 120s)
  --force                skip the freshness guard
  --dry-run              report the intended change without writing the state file
  -h, --help             print this help
`

function pathFromRoot(value) {
  return isAbsolute(value) ? value : resolve(ROOT, value)
}

function parseSince(value) {
  if (value === undefined || value === '') return 0
  if (/^[0-9]+$/.test(value)) return Number(value)
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) throw new Error(`--since expects an ISO timestamp or epoch milliseconds: ${value}`)
  return parsed
}

function parseArgs(argv) {
  const options = {
    state: pathFromRoot(process.env.UPSTREAM_RADAR_STATE_FILE ?? 'upstream-radar.state.json'),
    sessionFile: '',
    sessionId: '',
    since: 0,
    minAgeMs: DEFAULT_MIN_AGE_MS,
    force: false,
    dryRun: false,
    help: false,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '-h' || arg === '--help') options.help = true
    else if (arg === '--force') options.force = true
    else if (arg === '--dry-run') options.dryRun = true
    else if (arg === '--session-file') options.sessionFile = pathFromRoot(argv[++index] ?? '')
    else if (arg === '--session-id') options.sessionId = argv[++index] ?? ''
    else if (arg === '--since') options.since = parseSince(argv[++index])
    else if (arg === '--state') options.state = pathFromRoot(argv[++index] ?? '')
    else if (arg === '--min-age') options.minAgeMs = Number(argv[++index] ?? '') * 1000
    else throw new Error(`unknown argument: ${arg}`)
  }
  return options
}

// Decode a multi-frame zstd session log into its JSONL events.
function decodeSession(file) {
  const buffer = readFileSync(file)
  let offset = 0
  const parts = []
  while (offset < buffer.length) {
    const start = offset
    if (buffer.length - offset < 4) break
    if (buffer.readUInt32LE(offset) !== ZSTD_MAGIC) break
    offset += 4
    const descriptor = buffer.readUInt8(offset)
    offset += 1
    const contentSizeFlag = descriptor >>> 6
    const singleSegment = (descriptor & 32) !== 0
    const checksum = (descriptor & 4) !== 0
    const dictionaryFlag = descriptor & 3
    const dictionaryBytes = dictionaryFlag === 3 ? 4 : dictionaryFlag
    const contentSizeBytes = contentSizeFlag === 0 ? (singleSegment ? 1 : 0) : (1 << contentSizeFlag)
    offset += (singleSegment ? 0 : 1) + dictionaryBytes + contentSizeBytes
    for (;;) {
      if (buffer.length - offset < 3) return { parts }
      const blockHeader = buffer.readUIntLE(offset, 3)
      offset += 3
      const last = (blockHeader & 1) !== 0
      const type = (blockHeader >>> 1) & 3
      const size = blockHeader >>> 3
      offset += type === 1 ? 1 : size
      if (last) break
    }
    if (checksum) offset += 4
    parts.push(zstdDecompressSync(buffer.subarray(start, offset)))
  }
  const text = Buffer.concat(parts).toString('utf8')
  return text
    .trim()
    .split('\n')
    .map(line => {
      try {
        return JSON.parse(line)
      } catch {
        return null
      }
    })
    .filter(Boolean)
}

let options
try {
  options = parseArgs(process.argv.slice(2))
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n\n${HELP}`)
  process.exit(1)
}
if (options.help) {
  process.stdout.write(HELP)
  process.exit(0)
}
if (!options.sessionFile) {
  process.stderr.write(`--session-file <file> is required\n\n${HELP}`)
  process.exit(1)
}
if (!Number.isFinite(options.minAgeMs) || options.minAgeMs < 0) {
  process.stderr.write('--min-age expects a non-negative number of seconds\n')
  process.exit(1)
}
if (!options.sessionId) options.sessionId = basename(dirname(options.sessionFile))

const stats = await stat(options.state)
const ageMs = Date.now() - stats.mtimeMs
if (!options.force && ageMs < options.minAgeMs) {
  console.error(`${options.state} was written ${Math.round(ageMs / 1000)}s ago — a poll cycle may still be running; retry later or pass --force`)
  process.exit(1)
}

const events = decodeSession(options.sessionFile)
const state = await loadRadarState(options.state)
const resultsBefore = Object.keys(state.analysisResults ?? {}).length

// Replay every assistant message after --since; each is processed with the
// session history that preceded it, exactly as the live handler would see it.
const now = Date.now()
const replies = events.filter(event => event.type === 'assistant/message' && (event.time ?? 0) > options.since && (event.time ?? 0) < now)
console.log(`replaying ${replies.length} assistant reply(ies) of session ${options.sessionId} against ${Object.keys(state.analysisDeliveries ?? {}).length} live delivery record(s)`)

let working = state
let accepted = 0
for (const message of replies) {
  const history = events.filter(event => (event.seq ?? 0) < (message.seq ?? 0))
  const session = { id: options.sessionId, events: history }
  const outcome = applyDshAnalysisSessionEvent(working, session, message, new Map(), new Date(message.time))
  working = outcome.state
  accepted += outcome.accepted.length
}

if (working === state) {
  console.log('no state change — nothing to persist')
  process.exit(0)
}
if (options.dryRun) {
  console.log(`[dry-run] would accept ${accepted} result(s) and write ${options.state} (results: ${resultsBefore} -> ${Object.keys(working.analysisResults ?? {}).length})`)
  process.exit(0)
}

await saveRadarState(options.state, working)

const verify = await loadRadarState(options.state)
console.log(`accepted ${accepted} result(s); results: ${resultsBefore} -> ${Object.keys(verify.analysisResults ?? {}).length}; deliveries: ${Object.keys(verify.analysisDeliveries ?? {}).length}`)
for (const [incidentId, result] of Object.entries(verify.analysisResults ?? {})) {
  console.log(`  ${incidentId}  ${result.project_exposure}/${result.confidence}/${result.urgency}  received=${result.receivedAt}`)
}
