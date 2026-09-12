import { parsePackageManifestSnapshot } from './inventory.js'
import { packageKey } from './osv.js'
import type { PackageCoordinate, PackageManifestSnapshot } from './radar-types.js'
import { compareSemverValues } from './semver.js'
import { TOOL_VERSION } from './version.js'

const DEFAULT_REGISTRY = 'https://registry.npmjs.org/'
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024
const MAX_PACKAGES = 10_000

/** Connection-level error codes that are worth one bounded retry. */
const TRANSIENT_CAUSE_CODES = new Set([
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_ABORTED',
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'ENETUNREACH',
  'EHOSTUNREACH',
])

function delay(ms: number): Promise<void> {
  return new Promise(resolve => { setTimeout(resolve, ms) })
}

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>

export interface NpmReleaseClientOptions {
  registry?: string
  fetch?: FetchLike
  timeoutMs?: number
  /** Bounded retries for transient failures only (default 1). */
  retries?: number
  /** Backoff before each retry, multiplied by the attempt number (default 250ms). */
  retryBackoffMs?: number
}

/** One package whose packument could not be observed this cycle. */
export interface NpmReleaseQueryFailure {
  name: string
  message: string
}

/**
 * One release query plus its coverage.
 *
 * A registry query is not all-or-nothing any more: a single flaky connection
 * used to discard every observation for the cycle. Callers must decide what to
 * do with `failures` instead of silently treating a partial result as complete.
 */
export interface NpmReleaseQueryResult {
  releases: Map<string, NpmReleaseObservation>
  failures: NpmReleaseQueryFailure[]
  /** Distinct package names attempted in this cycle. */
  attempted: number
}

export type NpmReleaseCandidateStatus = 'newer' | 'same' | 'older' | 'uncomparable'

export interface NpmReleaseObservation {
  installed: PackageCoordinate
  latestVersion: string
  previous: PackageManifestSnapshot
  candidate: PackageManifestSnapshot
  /** Exact npm manifests newer than the installed version, sorted ascending. */
  upgradeCandidates?: PackageManifestSnapshot[]
  /** Whether npm's latest tag is newer than the installed exact version. */
  candidateStatus?: NpmReleaseCandidateStatus
  publishedAt?: string
  repository?: string
}

function candidateStatus(candidate: string, installed: string): NpmReleaseCandidateStatus {
  const comparison = compareSemverValues(candidate, installed)
  if (comparison === undefined) return 'uncomparable'
  if (comparison > 0) return 'newer'
  if (comparison < 0) return 'older'
  return 'same'
}

function upgradeCandidates(
  name: string,
  versions: Record<string, unknown>,
  installed: string,
): PackageManifestSnapshot[] {
  return Object.entries(versions)
    .flatMap(([version, raw]) => {
      const comparison = compareSemverValues(version, installed)
      return comparison === undefined || comparison <= 0 ? [] : [[version, raw] as const]
    })
    .sort(([left], [right]) => (compareSemverValues(left, right) ?? 0))
    .flatMap(([version, raw]) => {
      try {
        const parsed = parsePackageManifestSnapshot(raw)
        return parsed.name === name && parsed.version === version ? [parsed] : []
      } catch {
        return []
      }
    })
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function repositoryReference(value: unknown): string | undefined {
  const raw = typeof value === 'string' ? value : asRecord(value)?.url
  if (typeof raw !== 'string') return undefined
  const trimmed = raw.trim()
  return trimmed.length === 0 || trimmed.length > 4_096 ? undefined : trimmed
}

function normalizeRegistry(input: string): string {
  const url = new URL(input)
  if (url.protocol !== 'https:') throw new Error('npm release registry must use HTTPS')
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new Error('npm release registry must not contain credentials, a query string or a fragment')
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/'
  return url.toString()
}

async function boundedJson(response: Response): Promise<unknown> {
  if (!response.ok) throw new Error(`npm registry returned HTTP ${response.status}`)
  const declared = response.headers.get('content-length')
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) throw new Error('npm packument exceeds the byte limit')
  if (response.body === null) throw new Error('npm registry returned an empty packument')
  const reader = response.body.getReader()
  const chunks: Buffer[] = []
  let total = 0
  while (true) {
    const next = await reader.read()
    if (next.done) break
    const chunk = Buffer.from(next.value)
    total += chunk.length
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel('npm packument exceeded byte limit')
      throw new Error('npm packument exceeds the byte limit')
    }
    chunks.push(chunk)
  }
  try {
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8')) as unknown
  } catch {
    throw new Error('npm registry returned invalid JSON')
  }
}

/**
 * Classify one registry failure as transient.
 *
 * Retrying is only useful for failures that carry no information: a connection
 * that never came up, a reset socket, a timeout, or a 429/5xx. A 404 is a
 * definitive "not published" and a malformed packument will not parse on the
 * second try, so neither is retried.
 */
export function isTransientNpmReleaseFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  if (error.name === 'TimeoutError' || error.name === 'AbortError') return true
  // undici wraps every connection-level failure in `TypeError: fetch failed`.
  if (error.message === 'fetch failed') return true
  const cause = (error as { cause?: { code?: unknown } }).cause
  if (typeof cause?.code === 'string' && TRANSIENT_CAUSE_CODES.has(cause.code)) return true
  const status = /^npm registry returned HTTP (\d{3})$/.exec(error.message)
  if (status?.[1] !== undefined) {
    const code = Number(status[1])
    return code === 429 || code >= 500
  }
  return false
}

function boundedFailureMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error)
  return raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?').slice(0, 512)
}

export class NpmReleaseClient {
  private readonly registry: string
  private readonly fetcher: FetchLike
  private readonly timeoutMs: number
  private readonly retries: number
  private readonly retryBackoffMs: number

  constructor(options: NpmReleaseClientOptions = {}) {
    this.registry = normalizeRegistry(options.registry ?? DEFAULT_REGISTRY)
    this.fetcher = options.fetch ?? fetch
    this.timeoutMs = options.timeoutMs ?? 20_000
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1_000 || this.timeoutMs > 120_000) {
      throw new Error('npm release timeout must be between 1000 and 120000 milliseconds')
    }
    this.retries = options.retries ?? 1
    if (!Number.isSafeInteger(this.retries) || this.retries < 0 || this.retries > 5) {
      throw new Error('npm release retries must be between 0 and 5')
    }
    this.retryBackoffMs = options.retryBackoffMs ?? 250
    if (!Number.isSafeInteger(this.retryBackoffMs) || this.retryBackoffMs < 0 || this.retryBackoffMs > 10_000) {
      throw new Error('npm release retry backoff must be between 0 and 10000 milliseconds')
    }
  }

  private async fetchPackument(name: string): Promise<unknown | undefined> {
    const url = new URL(encodeURIComponent(name), this.registry)
    const response = await this.fetcher(url, {
      headers: {
        accept: 'application/vnd.npm.install-v1+json, application/json',
        'user-agent': `upstream-radar/${TOOL_VERSION}`,
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(this.timeoutMs),
    })
    // A DSH plugin may be private, GitHub-only, or still unpublished. That is
    // not a registry outage: skip its release comparison while continuing to
    // monitor the exact lockfile graph and any published host packages.
    if (response.status === 404) return undefined
    return boundedJson(response)
  }

  /** Fetch one packument, retrying only failures that carry no information. */
  private async fetchPackumentWithRetry(name: string): Promise<unknown | undefined> {
    let last: unknown
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      try {
        return await this.fetchPackument(name)
      } catch (error: unknown) {
        last = error
        if (attempt === this.retries || !isTransientNpmReleaseFailure(error)) throw error
        if (this.retryBackoffMs > 0) await delay(this.retryBackoffMs * (attempt + 1))
      }
    }
    throw last
  }

  /**
   * Query the registry, isolating every package from every other package.
   *
   * One unreachable packument now costs exactly one missing observation instead
   * of the whole cycle, and the caller is told how many were missing. The query
   * still throws when *every* attempted package failed, because that is a real
   * registry outage rather than partial coverage.
   */
  async queryWithCoverage(input: readonly PackageCoordinate[]): Promise<NpmReleaseQueryResult> {
    const unique = [...new Map(input.map(item => [packageKey(item), item])).values()]
    if (unique.length > MAX_PACKAGES) throw new Error(`npm release query exceeds the ${MAX_PACKAGES} package limit`)
    const byName = new Map<string, PackageCoordinate[]>()
    for (const item of unique) {
      if (item.ecosystem !== 'npm' || item.name.length === 0 || item.version.length === 0) {
        throw new Error('npm release queries require exact package names and versions')
      }
      const list = byName.get(item.name) ?? []
      list.push(item)
      byName.set(item.name, list)
    }

    const packuments = new Map<string, unknown>()
    const failures: NpmReleaseQueryFailure[] = []
    const queue = [...byName.keys()]
    const workers = Array.from({ length: Math.min(8, queue.length) }, async () => {
      while (queue.length > 0) {
        const name = queue.shift()
        if (name === undefined) return
        try {
          const packument = await this.fetchPackumentWithRetry(name)
          if (packument !== undefined) packuments.set(name, packument)
        } catch (error: unknown) {
          failures.push({ name, message: boundedFailureMessage(error) })
        }
      }
    })
    await Promise.all(workers)

    const attempted = byName.size
    if (attempted > 0 && failures.length === attempted) {
      const first = failures.slice(0, 3).map(failure => `${failure.name}: ${failure.message}`).join('; ')
      throw new Error(`npm registry query failed for all ${attempted} package(s) (${first})`)
    }

    const result = new Map<string, NpmReleaseObservation>()
    for (const [name, coordinates] of byName) {
      const packument = packuments.get(name)
      if (packument === undefined) continue
      try {
        const packumentRecord = asRecord(packument)
        const tags = asRecord(packumentRecord?.['dist-tags'])
        const versions = asRecord(packumentRecord?.versions)
        const times = asRecord(packumentRecord?.time)
        const latestVersion = typeof tags?.latest === 'string' ? tags.latest : undefined
        if (latestVersion === undefined || versions === undefined) throw new Error(`npm packument has no latest release for ${name}`)
        const rawCandidate = versions[latestVersion]
        const candidate = parsePackageManifestSnapshot(rawCandidate)
        if (candidate.name !== name || candidate.version !== latestVersion) throw new Error(`npm latest manifest identity mismatch for ${name}`)
        const repository = repositoryReference(asRecord(rawCandidate)?.repository)
        // Build every observation for this package before committing any of
        // them, so a failure halfway through cannot leave a partial commit.
        const observations: Array<[string, NpmReleaseObservation]> = []
        for (const installed of coordinates) {
          const previous = parsePackageManifestSnapshot(versions[installed.version])
          if (previous.name !== name || previous.version !== installed.version) {
            throw new Error(`npm installed manifest identity mismatch for ${name}@${installed.version}`)
          }
          const publishedAt = typeof times?.[latestVersion] === 'string' ? times[latestVersion] : undefined
          const status = candidateStatus(latestVersion, installed.version)
          observations.push([packageKey(installed), {
            installed: { ...installed },
            latestVersion,
            previous,
            candidate,
            ...(status === 'newer'
              ? { upgradeCandidates: upgradeCandidates(name, versions, installed.version) }
              : {}),
            candidateStatus: status,
            ...(publishedAt === undefined ? {} : { publishedAt }),
            ...(repository === undefined ? {} : { repository }),
          }])
        }
        for (const [key, observation] of observations) result.set(key, observation)
      } catch (error: unknown) {
        failures.push({ name, message: boundedFailureMessage(error) })
      }
    }

    // Deterministic order regardless of which worker finished first.
    failures.sort((left, right) => left.name.localeCompare(right.name))
    return { releases: result, failures, attempted }
  }

  /**
   * Strict form of {@link queryWithCoverage}: any package that could not be
   * observed fails the whole query. Kept unchanged for existing callers; new
   * callers should use `queryWithCoverage` so incomplete coverage stays visible.
   */
  async query(input: readonly PackageCoordinate[]): Promise<Map<string, NpmReleaseObservation>> {
    const outcome = await this.queryWithCoverage(input)
    if (outcome.failures.length > 0) {
      const first = outcome.failures.slice(0, 3).map(failure => `${failure.name}: ${failure.message}`).join('; ')
      throw new Error(`npm registry query missed ${outcome.failures.length}/${outcome.attempted} package(s) (${first})`)
    }
    return outcome.releases
  }
}
