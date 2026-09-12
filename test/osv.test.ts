import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { OsvClient } from '../src/osv.js'

describe('OSV client', () => {
  it('queries exact npm versions in a batch and fetches changed advisory details', async () => {
    const requests: string[] = []
    const fetcher = async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input)
      requests.push(url)
      if (url.endsWith('/v1/querybatch')) {
        assert.equal(init?.method, 'POST')
        assert.deepEqual(JSON.parse(String(init?.body)), {
          queries: [{ package: { ecosystem: 'npm', name: 'parser' }, version: '2.9.0' }],
        })
        return Response.json({ results: [{ vulns: [{ id: 'GHSA-demo', modified: '2026-08-14T01:00:00Z' }] }] })
      }
      if (url.endsWith('/v1/vulns/GHSA-demo')) {
        return Response.json({
          id: 'GHSA-demo',
          modified: '2026-08-14T01:00:00Z',
          published: '2026-08-14T00:00:00Z',
          summary: 'Parser accepts an unsafe archive header',
          aliases: ['CVE-2026-1234'],
          affected: [{
            package: { ecosystem: 'npm', name: 'parser' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.0.0' }] }],
          }],
          database_specific: { severity: 'HIGH' },
          references: [{ type: 'ADVISORY', url: 'https://example.test/advisory' }],
        })
      }
      return new Response('not found', { status: 404 })
    }

    const client = new OsvClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: 'parser', version: '2.9.0' }])
    const hit = result.get('npm:parser@2.9.0')
    assert.equal(hit?.length, 1)
    assert.equal(hit?.[0]?.advisory.id, 'GHSA-demo')
    assert.deepEqual(hit?.[0]?.advisory.fixedVersions, ['3.0.0'])
    assert.equal(hit?.[0]?.advisory.severity, 'high')
    assert.deepEqual(hit?.[0]?.advisory.sources, ['osv'])
    assert.equal(requests.length, 2)
  })

  it('retries one transient batch failure and still returns the advisory', async () => {
    let attempts = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      const url = String(input)
      if (url.endsWith('/v1/querybatch')) {
        attempts += 1
        if (attempts === 1) throw new Error('temporary network blip')
        return Response.json({ results: [{ vulns: [] }] })
      }
      return new Response('not found', { status: 404 })
    }

    const client = new OsvClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: 'parser', version: '2.9.0' }])
    assert.equal(result.get('npm:parser@2.9.0')?.length, 0)
    assert.equal(attempts, 2)
  })

  it('retries one advisory-detail failure once before succeeding', async () => {
    let detailAttempts = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      const url = String(input)
      if (url.endsWith('/v1/querybatch')) {
        return Response.json({ results: [{ vulns: [{ id: 'GHSA-demo', modified: '2026-08-14T01:00:00Z' }] }] })
      }
      if (url.endsWith('/v1/vulns/GHSA-demo')) {
        detailAttempts += 1
        if (detailAttempts === 1) return new Response('server error', { status: 503 })
        return Response.json({
          id: 'GHSA-demo',
          modified: '2026-08-14T01:00:00Z',
          published: '2026-08-14T00:00:00Z',
          summary: 'Parser accepts an unsafe archive header',
          affected: [{
            package: { ecosystem: 'npm', name: 'parser' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.0.0' }] }],
          }],
          database_specific: { severity: 'HIGH' },
          references: [],
        })
      }
      return new Response('not found', { status: 404 })
    }

    const client = new OsvClient({ fetch: fetcher })
    const result = await client.query([{ ecosystem: 'npm', name: 'parser', version: '2.9.0' }])
    assert.equal(result.get('npm:parser@2.9.0')?.[0]?.advisory.id, 'GHSA-demo')
    assert.equal(detailAttempts, 2)
  })

  it('still fails the query after one failed retry', async () => {
    let attempts = 0
    const fetcher = async (input: string | URL): Promise<Response> => {
      const url = String(input)
      if (url.endsWith('/v1/querybatch')) {
        attempts += 1
        return new Response('unavailable', { status: 503 })
      }
      return new Response('not found', { status: 404 })
    }

    const client = new OsvClient({ fetch: fetcher })
    await assert.rejects(() => client.query([{ ecosystem: 'npm', name: 'parser', version: '2.9.0' }]), /HTTP 503/)
    assert.equal(attempts, 2)
  })
})
