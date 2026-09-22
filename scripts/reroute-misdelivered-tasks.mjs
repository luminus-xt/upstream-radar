#!/usr/bin/env node
// Operator repair tool: reroute analysis deliveries that were bound to the
// wrong DSH session through the single-root fallback.
//
// Delivery selection must match the session that hosts the project workspace.
// When a poll cycle runs while only one root is live — for example during a
// boot-restore race — the single-root fallback can bind a delivery to a session
// that does not host that workspace. This tool drops the affected delivery
// records and re-pends the same incidents, so the next cycle delivers them to
// the workspace-matching session.
//
// Usage:
//   pnpm run build
//   node scripts/reroute-misdelivered-tasks.mjs --session <sessionId> [options]
//
// Guards: the state file is re-read and verified after writing; an incident
// that already reclaimed a result is never re-pended.
import { stat } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadRadarState, saveRadarState } from '../dist/src/radar-state.js'
import { createAnalysisTask } from '../dist/src/dsh-analysis.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_MIN_AGE_MS = 120_000

const HELP = `usage: node scripts/reroute-misdelivered-tasks.mjs --session <sessionId> [options]

Reroute analysis deliveries bound to the wrong session by the single-root
fallback: drop those delivery records and re-pend the same incidents so the next
poll cycle delivers them to the workspace-matching session.

options:
  --session <id>    session the deliveries were wrongly bound to (required)
  --state <file>    radar state file (default: $UPSTREAM_RADAR_STATE_FILE, else
                    <repo>/upstream-radar.state.json)
  --min-age <secs>  freshness guard: refuse to run when the state file was
                    written more recently than this (default 120s)
  --force           skip the freshness guard
  --dry-run         report the intended change without writing the state file
  -h, --help        print this help
`

function pathFromRoot(value) {
  return isAbsolute(value) ? value : resolve(ROOT, value)
}

function parseArgs(argv) {
  const options = {
    state: pathFromRoot(process.env.UPSTREAM_RADAR_STATE_FILE ?? 'upstream-radar.state.json'),
    session: '',
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
    else if (arg === '--session') options.session = argv[++index] ?? ''
    else if (arg === '--state') options.state = pathFromRoot(argv[++index] ?? '')
    else if (arg === '--min-age') options.minAgeMs = Number(argv[++index] ?? '') * 1000
    else throw new Error(`unknown argument: ${arg}`)
  }
  return options
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
if (!options.session) {
  process.stderr.write(`--session <sessionId> is required\n\n${HELP}`)
  process.exit(1)
}
if (!Number.isFinite(options.minAgeMs) || options.minAgeMs < 0) {
  process.stderr.write('--min-age expects a non-negative number of seconds\n')
  process.exit(1)
}

const stats = await stat(options.state)
const ageMs = Date.now() - stats.mtimeMs
if (!options.force && ageMs < options.minAgeMs) {
  console.error(`${options.state} was written ${Math.round(ageMs / 1000)}s ago — a poll cycle may still be running; retry later or pass --force`)
  process.exit(1)
}

const state = await loadRadarState(options.state)
const deliveries = { ...(state.analysisDeliveries ?? {}) }
const rerouted = []
for (const [id, delivery] of Object.entries(deliveries)) {
  if (delivery.sessionId !== options.session) continue
  for (const ref of delivery.taskRefs ?? []) rerouted.push(ref.incidentId)
  delete deliveries[id]
}

if (rerouted.length === 0) {
  console.log(`no deliveries bound to ${options.session}; nothing to do`)
  process.exit(0)
}

const pending = [...(state.pendingAnalysisTasks ?? [])]
const pendingIncidents = new Set(pending.map(task => task.event.incidentId))
let added = 0
for (const incidentId of rerouted) {
  if (pendingIncidents.has(incidentId)) continue
  const stored = state.activeCompatibility?.[incidentId]
  if (stored === undefined) continue
  // An incident that already reclaimed a result must not be re-analyzed.
  if ((state.analysisResults ?? {})[incidentId] !== undefined) continue
  pending.push(createAnalysisTask(stored.event))
  pendingIncidents.add(incidentId)
  added += 1
}

if (options.dryRun) {
  console.log(`[dry-run] would drop ${rerouted.length} delivery record(s) and re-pend ${added} task(s) in ${options.state}`)
  process.exit(0)
}

const next = { ...state, pendingAnalysisTasks: pending, analysisDeliveries: deliveries }
await saveRadarState(options.state, next)
const verify = await loadRadarState(options.state)
console.log(`dropped ${rerouted.length} misdelivered record(s); re-pended ${added} task(s)`)
for (const task of verify.pendingAnalysisTasks) {
  console.log(`  ${task.id}  ${task.event.plugin.name} ${task.event.installed.version} -> ${task.event.candidate.version}`)
}
console.log(`pending: ${verify.pendingAnalysisTasks.length}; deliveries: ${Object.keys(verify.analysisDeliveries ?? {}).length}; results: ${Object.keys(verify.analysisResults ?? {}).length}`)
