import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { NpmReleaseClient, isTransientNpmReleaseFailure } from '../src/npm-release.js'

/** A packument for one package, enough for a successful observation. */
function packument(name: string): Response {
  return Response.json({
    'dist-tags': { latest: '2.0.0' },
    versions: {
      '1.0.0': { name, version: '1.0.0' },
      '2.0.0': { name, version: '2.0.0' },
    },
  })
}

function connectionFailure(): Error {
  const error = new TypeError('fetch failed')
  ;(error as Error & { cause?: unknown }).cause = Object.assign(new Error('Connect Timeout Error'), {
    code: 'UND_ERR_CONNECT_TIMEOUT',
  })
  return error
}

describe('npm release source', () => {
  it('returns the current and latest manifests without installing either release', async () => {
    const fetcher = async (): Promise<Response> => Response.json({
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '1.0.0': { name: 'plugin', version: '1.0.0', main: './old.js', engines: { node: '>=22' } },
        '2.0.0': {
          name: 'plugin',
          version: '2.0.0',
          main: './new.js',
          engines: { node: '>=24' },
          repository: { type: 'git', url: 'git+https://github.com/acme/plugin.git' },
        },
      },
      time: { '2.0.0': '2026-08-14T02:00:00.000Z' },
    })
    const client = new NpmReleaseClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: 'plugin', version: '1.0.0' }])
    const change = result.get('npm:plugin@1.0.0')
    assert.equal(change?.previous.main, './old.js')
    assert.equal(change?.candidate.version, '2.0.0')
    assert.equal(change?.publishedAt, '2026-08-14T02:00:00.000Z')
    assert.equal(change?.repository, 'git+https://github.com/acme/plugin.git')
    assert.equal(change?.candidateStatus, 'newer')
    assert.deepEqual(change?.upgradeCandidates?.map(item => item.version), ['2.0.0'])
  })

  it('returns newer exact manifests in ascending order without installing them', async () => {
    const fetcher = async (): Promise<Response> => Response.json({
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '1.0.0': { name: 'plugin', version: '1.0.0' },
        '1.2.0': { name: 'plugin', version: '1.2.0' },
        '1.1.0': { name: 'plugin', version: '1.1.0' },
        '2.0.0': { name: 'plugin', version: '2.0.0' },
      },
    })
    const client = new NpmReleaseClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: 'plugin', version: '1.0.0' }])
    assert.deepEqual(result.get('npm:plugin@1.0.0')?.upgradeCandidates?.map(item => item.version), [
      '1.1.0',
      '1.2.0',
      '2.0.0',
    ])
  })

  it('marks a regressed npm latest tag as older instead of an upgrade', async () => {
    const fetcher = async (): Promise<Response> => Response.json({
      'dist-tags': { latest: '0.0.1-rc.1' },
      versions: {
        '0.0.1-rc.1': { name: '@deepseek-ai/dsh-agent', version: '0.0.1-rc.1' },
        '0.1.0-rc.6': { name: '@deepseek-ai/dsh-agent', version: '0.1.0-rc.6' },
      },
    })
    const client = new NpmReleaseClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: '@deepseek-ai/dsh-agent', version: '0.1.0-rc.6' }])
    assert.equal(result.get('npm:@deepseek-ai/dsh-agent@0.1.0-rc.6')?.candidateStatus, 'older')
  })

  it('skips an unpublished plugin without hiding other published release streams', async () => {
    const fetcher = async (input: string | URL): Promise<Response> => {
      const name = decodeURIComponent(new URL(String(input)).pathname.slice(1))
      if (name === 'local-plugin') return new Response('not found', { status: 404 })
      return Response.json({
        'dist-tags': { latest: '2.0.0' },
        versions: {
          '1.0.0': { name, version: '1.0.0' },
          '2.0.0': { name, version: '2.0.0' },
        },
      })
    }
    const client = new NpmReleaseClient({ fetch: fetcher })
    const result = await client.query([
      { ecosystem: 'npm', name: 'local-plugin', version: '1.0.0' },
      { ecosystem: 'npm', name: 'published-host', version: '1.0.0' },
    ])
    assert.equal(result.has('npm:local-plugin@1.0.0'), false)
    assert.equal(result.get('npm:published-host@1.0.0')?.candidateStatus, 'newer')
  })
})

describe('npm release coverage isolation', () => {
  const coordinates = [
    { ecosystem: 'npm' as const, name: 'flaky', version: '1.0.0' },
    { ecosystem: 'npm' as const, name: 'healthy', version: '1.0.0' },
  ]

  it('keeps the packages that answered and reports the one that did not', async () => {
    let flakyCalls = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      const name = decodeURIComponent(new URL(String(input)).pathname.slice(1))
      if (name === 'flaky') {
        flakyCalls += 1
        throw connectionFailure()
      }
      return packument(name)
    }
    const client = new NpmReleaseClient({ fetch: fetcher, retryBackoffMs: 0 })
    const outcome = await client.queryWithCoverage(coordinates)

    // A single unreachable packument no longer discards the whole cycle.
    assert.deepEqual([...outcome.releases.keys()], ['npm:healthy@1.0.0'])
    assert.equal(outcome.attempted, 2)
    assert.equal(outcome.failures.length, 1)
    assert.equal(outcome.failures[0]?.name, 'flaky')
    assert.match(String(outcome.failures[0]?.message), /fetch failed/)
    // The transient failure was retried exactly once before being reported.
    assert.equal(flakyCalls, 2)
  })

  it('retries a transient failure and keeps the package when the retry succeeds', async () => {
    let calls = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      calls += 1
      if (calls === 1) throw connectionFailure()
      return packument(decodeURIComponent(new URL(String(input)).pathname.slice(1)))
    }
    const client = new NpmReleaseClient({ fetch: fetcher, retryBackoffMs: 0 })
    const outcome = await client.queryWithCoverage([{ ecosystem: 'npm', name: 'flaky', version: '1.0.0' }])
    assert.equal(calls, 2)
    assert.equal(outcome.failures.length, 0)
    assert.equal(outcome.releases.get('npm:flaky@1.0.0')?.candidateStatus, 'newer')
  })

  it('does not retry definitive answers and does not count a 404 as a gap', async () => {
    const seen: string[] = []
    const fetcher = async (input: string | URL): Promise<Response> => {
      const name = decodeURIComponent(new URL(String(input)).pathname.slice(1))
      seen.push(name)
      if (name === 'unpublished') return new Response('not found', { status: 404 })
      if (name === 'forbidden') return new Response('no', { status: 403 })
      if (name === 'broken') return new Response('{ nope', { status: 200 })
      return packument(name)
    }
    const client = new NpmReleaseClient({ fetch: fetcher, retryBackoffMs: 0 })
    const outcome = await client.queryWithCoverage([
      { ecosystem: 'npm', name: 'unpublished', version: '1.0.0' },
      { ecosystem: 'npm', name: 'forbidden', version: '1.0.0' },
      { ecosystem: 'npm', name: 'broken', version: '1.0.0' },
      { ecosystem: 'npm', name: 'healthy', version: '1.0.0' },
    ])
    // 404 means "not published", which is not a coverage gap.
    assert.deepEqual(outcome.failures.map(f => f.name), ['broken', 'forbidden'])
    assert.equal(outcome.releases.has('npm:healthy@1.0.0'), true)
    // Each definitive failure was attempted exactly once.
    assert.deepEqual(seen.sort(), ['broken', 'forbidden', 'healthy', 'unpublished'])
  })

  it('retries HTTP 500 but not HTTP 403', async () => {
    let serverErrors = 0
    let redirects = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      const name = decodeURIComponent(new URL(String(input)).pathname.slice(1))
      if (name === 'server-error') {
        serverErrors += 1
        return new Response('boom', { status: 500 })
      }
      if (name === 'forbidden') {
        redirects += 1
        return new Response('no', { status: 403 })
      }
      return packument(name)
    }
    const client = new NpmReleaseClient({ fetch: fetcher, retryBackoffMs: 0 })
    const outcome = await client.queryWithCoverage([
      { ecosystem: 'npm', name: 'server-error', version: '1.0.0' },
      { ecosystem: 'npm', name: 'forbidden', version: '1.0.0' },
      { ecosystem: 'npm', name: 'healthy', version: '1.0.0' },
    ])
    assert.equal(serverErrors, 2)
    assert.equal(redirects, 1)
    assert.deepEqual(outcome.failures.map(f => f.name), ['forbidden', 'server-error'])
    assert.equal(outcome.releases.has('npm:healthy@1.0.0'), true)
  })

  it('still fails loudly when every attempted package failed', async () => {
    const client = new NpmReleaseClient({ fetch: async () => { throw connectionFailure() }, retryBackoffMs: 0 })
    await assert.rejects(
      () => client.queryWithCoverage(coordinates),
      /failed for all 2 package\(s\)/,
    )
  })

  it('keeps the strict query all-or-nothing for existing callers', async () => {
    const fetcher = async (input: string | URL): Promise<Response> => {
      const name = decodeURIComponent(new URL(String(input)).pathname.slice(1))
      if (name === 'flaky') throw connectionFailure()
      return packument(name)
    }
    const client = new NpmReleaseClient({ fetch: fetcher, retryBackoffMs: 0 })
    await assert.rejects(() => client.query(coordinates), /missed 1\/2 package\(s\)/)
  })

  it('classifies transient failures and leaves definitive ones alone', () => {
    assert.equal(isTransientNpmReleaseFailure(connectionFailure()), true)
    assert.equal(isTransientNpmReleaseFailure(new DOMException('timed out', 'TimeoutError')), true)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm registry returned HTTP 500')), true)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm registry returned HTTP 429')), true)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm registry returned HTTP 404')), false)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm registry returned HTTP 403')), false)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm registry returned invalid JSON')), false)
    assert.equal(isTransientNpmReleaseFailure(new Error('npm packument exceeds the byte limit')), false)
  })
})
