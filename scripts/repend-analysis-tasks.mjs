#!/usr/bin/env node
// Operator repair tool: re-pend the currently active compatibility incidents as
// analysis tasks so the next radar cycle re-delivers them to the receiving
// session.
//
// Use it when results for active incidents were never reclaimed — for example
// after a delivery was routed to a session that could not answer it, or after a
// fix to delivery selection landed and the tasks should be handed out again.
//
// Usage:
//   pnpm run build
//   node scripts/repend-analysis-tasks.mjs [options]
//
// Guards:
//  - refuses to run while a poll cycle may still be writing the state file
//    (state mtime younger than --min-age, default 120s; --force skips);
//  - re-reads and verifies the patch after writing;
//  - drops only the stale delivery records whose incident is being re-pended.
import { stat } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadRadarState, saveRadarState } from '../dist/src/radar-state.js'
import { createAnalysisTask } from '../dist/src/dsh-analysis.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_MIN_AGE_MS = 120_000

const HELP = `usage: node scripts/repend-analysis-tasks.mjs [options]

Re-pend every active compatibility incident as an analysis task, and drop the
stale delivery records for those incidents, so the next poll cycle delivers them
to the unique workspace-matching session.

options:
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
if (!Number.isFinite(options.minAgeMs) || options.minAgeMs < 0) {
  process.stderr.write('--min-age expects a non-negative number of seconds\n')
  process.exit(1)
}

const stats = await stat(options.state)
const ageMs = Date.now() - stats.mtimeMs
if (!options.force && ageMs < options.minAgeMs) {
  console.error(`${options.state} was written ${Math.round(ageMs / 1000)}s ago — a cycle may still be running; retry later or pass --force`)
  process.exit(1)
}

const state = await loadRadarState(options.state)
const incidents = new Map()
for (const [, item] of Object.entries(state.activeCompatibility ?? {})) {
  incidents.set(item.event.incidentId, item.event)
}
if (incidents.size === 0) {
  console.error('no active compatibility events found — nothing to repend')
  process.exit(1)
}

const pending = [...(state.pendingAnalysisTasks ?? [])]
const pendingIncidents = new Set(pending.map(task => task.event.incidentId))
let added = 0
for (const event of incidents.values()) {
  if (pendingIncidents.has(event.incidentId)) continue
  pending.push(createAnalysisTask(event))
  pendingIncidents.add(event.incidentId)
  added += 1
}

const deliveries = { ...(state.analysisDeliveries ?? {}) }
let dropped = 0
for (const [id, delivery] of Object.entries(deliveries)) {
  const stale = (delivery.taskRefs ?? []).some(ref => incidents.has(ref.incidentId))
  if (stale) {
    delete deliveries[id]
    dropped += 1
  }
}

if (options.dryRun) {
  console.log(`[dry-run] would re-pend ${added} task(s) for ${incidents.size} active incident(s) and drop ${dropped} stale delivery record(s) in ${options.state}`)
  process.exit(0)
}

const next = { ...state, pendingAnalysisTasks: pending, analysisDeliveries: deliveries }
await saveRadarState(options.state, next)

const verify = await loadRadarState(options.state)
console.log(`re-pended ${added} task(s) for ${incidents.size} active incident(s); dropped ${dropped} stale delivery record(s)`)
console.log(`pending now: ${verify.pendingAnalysisTasks.length}; deliveries now: ${Object.keys(verify.analysisDeliveries ?? {}).length}`)
for (const task of verify.pendingAnalysisTasks) {
  console.log(`  ${task.id}  ${task.event.plugin.name} ${task.event.installed.version} -> ${task.event.candidate.version}  eventId=${task.event.id}`)
}
console.log('the next poll cycle will deliver these to the unique workspace-matching session')
