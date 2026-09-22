import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  registerRadarPanelApi,
  type RadarPanelJob,
  type RequestLike,
  type ResponseLike,
  type WebServerLike,
} from '../src/radar-panel.js'

/** 捕获注册的路由。 */
function fakeServer(): { routes: Array<{ kind: string; path: string; handler: (req: RequestLike, res: ResponseLike) => unknown | Promise<unknown> }>; webServer: WebServerLike } {
  const routes: Array<{ kind: string; path: string; handler: (req: RequestLike, res: ResponseLike) => unknown | Promise<unknown> }> = []
  const webServer: WebServerLike = {
    register(route) {
      routes.push(route as never)
      return () => { /* noop */ }
    },
  }
  return { routes, webServer }
}

interface MockResponse extends ResponseLike {
  result(): { code: number; headers: Record<string, string>; body: unknown }
}

/** 可检查结果的响应 mock。 */
function jsonResponse(): MockResponse {
  let code = 0
  let headers: Record<string, string> = {}
  let body: unknown
  return {
    writeHead(c: number, h?: Record<string, string>) { code = c; headers = h ?? {} },
    end(text?: string) { body = text === undefined ? undefined : JSON.parse(text) },
    result() { return { code, headers, body } },
  }
}

interface StateLike {
  activeVulnerabilities?: Record<string, unknown>
  activeCompatibility?: Record<string, unknown>
  pendingAnalysisTasks?: unknown[]
  analysisDeliveries?: Record<string, unknown>
  analysisResults?: Record<string, unknown>
  sourceHealth?: Record<string, unknown>
}

function panel(
  webServer: WebServerLike,
  overrides: Partial<{
    radarDir: string
    configFile: string
    stateFile: string
    cliPath: string
    jobsDir: string
    maxJobs: number
    reviewDshVersions: string
    refresh: () => void
    requestUpgrade: (request: { plugin: string; fromVersion: string | null; toVersion: string; kind: 'upgrade' | 'assess' }) => Promise<{ delivered: boolean; note?: string }>
    upgradeTarget: () => Promise<{ workspace: string | null; matches: number; engaged: number; sessionId: string | null; reason: string }>
  }>,
): void {
  registerRadarPanelApi(webServer, {
    radarDir: '/tmp',
    configFile: '/tmp/c.json',
    stateFile: '/tmp/s.json',
    cliPath: '/tmp/cli.js',
    jobsDir: '/tmp/jobs',
    maxJobs: 3,
    reviewDshVersions: 'x,y',
    refresh() {},
    ...overrides,
  })
}

/** 请求 mock：立即触发 end（readBody 依赖它落定），data 不产生内容。 */
function req(method: string): RequestLike {
  return {
    method,
    on(event, cb) { if (event === 'end') cb() },
  }
}

/** 带 JSON body 的请求 mock：先发 data 再发 end。 */
function reqJson(method: string, body: unknown): RequestLike {
  return {
    method,
    on(event, cb) {
      if (event === 'data') cb(Buffer.from(JSON.stringify(body), 'utf8'))
      else if (event === 'end') cb()
    },
  }
}

describe('radar-panel api', () => {
  it('registers the expected route set', () => {
    const { routes, webServer } = fakeServer()
    panel(webServer, {})
    assert.equal(routes.length, 14)
    const paths = routes.map(r => r.path)
    for (const suffix of ['/api/status', '/api/events', '/api/tasks', '/api/results', '/api/result-failures', '/api/inventory', '/api/releases', '/api/upgrade-request', '/api/upgrade-target', '/api/jobs', '/api/job', '/api/refresh', '/api/inspect', '/api/review']) {
      assert.ok(paths.some(p => p.endsWith(suffix)), `missing route ${suffix}`)
    }
  })

  it('status reflects the parsed state and config', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      const state: StateLike = {
        activeVulnerabilities: { v1: {} },
        activeCompatibility: { c1: {} },
        pendingAnalysisTasks: [{ id: 't1' }, { id: 't2' }],
        analysisDeliveries: { d1: {} },
        analysisResults: { r1: {} },
        sourceHealth: { s1: {} },
      }
      const config = { projects: [{ project: { name: 'p1' }, plugins: [{}, {}, {}] }] }
      await writeFile(stateFile, JSON.stringify(state))
      await writeFile(configFile, JSON.stringify(config))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const statusRoute = routes.find(r => r.path.endsWith('/api/status'))!
      const res = jsonResponse()
      await statusRoute.handler(req('GET'), res)
      const out = res.result()
      assert.equal(out.code, 200)
      const body = out.body as Record<string, unknown>
      assert.equal(body.radarRunning, true)
      assert.equal(body.pluginsMonitored, 3)
      assert.equal(body.activeVulnerabilities, 1)
      assert.equal(body.activeCompatibility, 1)
      assert.equal(body.pendingTasks, 2)
      assert.equal(body.deliveries, 1)
      assert.equal(body.results, 1)
      assert.equal(body.sourceHealth, 1)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('surfaces dropped analysis answers from the failure sidecar', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-failures-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(stateFile, JSON.stringify({ activeVulnerabilities: {}, activeCompatibility: {}, analysisDeliveries: {}, analysisResults: {} }))
      await writeFile(configFile, JSON.stringify({ projects: [] }))
      await writeFile(`${stateFile}.analysis-result-failures.json`, JSON.stringify({
        schema: 'upstream-radar.analysis-result-failures/v1alpha1',
        failures: [{
          sessionId: 'session-receptor',
          assistantSeq: 42,
          deliveryId: 'delivery-1',
          incidentIds: ['project\u0000npm-releases'],
          detectedAt: '2026-09-11T00:22:44.000Z',
          outcome: 'contract-mismatch',
          detail: 'field=project_exposure',
          attempt: 2,
        }],
      }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })

      const statusRes = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/status'))!.handler(req('GET'), statusRes)
      assert.equal((statusRes.result().body as Record<string, unknown>).resultFailures, 1)

      const failuresRes = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/result-failures'))!.handler(req('GET'), failuresRes)
      const failures = (failuresRes.result().body as { failures: Array<Record<string, unknown>> }).failures
      assert.equal(failures.length, 1)
      assert.equal(failures[0]?.outcome, 'contract-mismatch')
      assert.equal(failures[0]?.assistantSeq, 42)
      assert.deepEqual(failures[0]?.incidentIds, ['project\u0000npm-releases'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('status reports not running when the state file is absent', async () => {
    const { routes, webServer } = fakeServer()
    panel(webServer, { radarDir: '/tmp', configFile: '/tmp/nope.json', stateFile: '/tmp/nope-state.json' })
    const statusRoute = routes.find(r => r.path.endsWith('/api/status'))!
    const res = jsonResponse()
    await statusRoute.handler(req('GET'), res)
    assert.equal(res.result().code, 200)
    assert.equal((res.result().body as Record<string, unknown>).radarRunning, false)
  })

  it('refresh invokes the injected hook', async () => {
    let called = false
    const { routes, webServer } = fakeServer()
    panel(webServer, { refresh() { called = true } })
    const refreshRoute = routes.find(r => r.path.endsWith('/api/refresh'))!
    const res = jsonResponse()
    await refreshRoute.handler(req('POST'), res)
    assert.equal(called, true)
    assert.equal(res.result().code, 200)
  })

  it('rejects malformed inspect/review targets with 400', async () => {
    const { routes, webServer } = fakeServer()
    panel(webServer, {})
    for (const suffix of ['/api/inspect', '/api/review']) {
      const route = routes.find(r => r.path.endsWith(suffix))!
      const res = jsonResponse()
      await route.handler(req('POST'), res)
      assert.equal(res.result().code, 400, `${suffix} should reject empty/malformed target`)
    }
  })

  it('methods other than the route verb are rejected with 405', async () => {
    const { routes, webServer } = fakeServer()
    panel(webServer, {})
    const statusRoute = routes.find(r => r.path.endsWith('/api/status'))!
    const res = jsonResponse()
    await statusRoute.handler(req('POST'), res)
    assert.equal(res.result().code, 405)
  })

  it('releases merges benign sidecar notices with compat-risk candidates', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-rel-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      // state: 一个兼容事件（compat 风险），candidate 2.0
      const state = {
        activeCompatibility: {
          'incident-1': { event: { installed: { name: 'pkg-a', version: '1.0' }, candidate: { version: '2.0' }, detectedAt: '2026-09-08T01:00:00.000Z' } },
        },
      }
      await writeFile(stateFile, JSON.stringify(state))
      // sidecar: 一个良性新版本（key 编码 project|plugin|pv|installed|iv|candidate|cv）
      const sidecarKey = 'proj|pkg-b|1.0|pkg-b|1.0|pkg-b|1.1'
      await writeFile(`${stateFile}.release-notices.json`, JSON.stringify({ [sidecarKey]: { eventId: 'e1', notifiedAt: '2026-09-08T02:00:00.000Z' } }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const route = routes.find(r => r.path.endsWith('/api/releases'))!
      const res = jsonResponse()
      await route.handler(req('GET'), res)
      assert.equal(res.result().code, 200)
      const body = res.result().body as { releases: Array<{ plugin: string; candidateVersion: string; risk: string; notifiedAt: string | null }> }
      assert.equal(body.releases.length, 2)
      const byPlugin = Object.fromEntries(body.releases.map(r => [r.plugin, r])) as Record<string, { plugin: string; candidateVersion: string; risk: string; notifiedAt: string | null }>
      assert.equal(byPlugin['pkg-a']!.risk, 'compat')
      assert.equal(byPlugin['pkg-a']!.candidateVersion, '2.0')
      assert.equal(byPlugin['pkg-b']!.risk, 'benign')
      assert.equal(byPlugin['pkg-b']!.candidateVersion, '1.1')
      assert.equal(byPlugin['pkg-b']!.notifiedAt, '2026-09-08T02:00:00.000Z')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('drops stale release rows and shows the version actually installed now', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-stale-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(stateFile, JSON.stringify({ activeCompatibility: {} }))
      // 当前装配的是 1.2
      await writeFile(configFile, JSON.stringify({
        projects: [{ project: { name: 'p' }, plugins: [{ package: { name: 'pkg-b', version: '1.2' } }] }],
      }))
      const notices = {
        'proj|pkg-b|1.0|pkg-b|1.0|pkg-b|1.1': { eventId: 'e1', notifiedAt: '2026-09-07T00:00:00.000Z' },
        'proj|pkg-b|1.1|pkg-b|1.1|pkg-b|1.2': { eventId: 'e2', notifiedAt: '2026-09-08T00:00:00.000Z' },
        'proj|pkg-b|1.2|pkg-b|1.2|pkg-b|1.3': { eventId: 'e3', notifiedAt: '2026-09-09T00:00:00.000Z' },
      }
      await writeFile(`${stateFile}.release-notices.json`, JSON.stringify(notices))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const res = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/releases'))!.handler(req('GET'), res)
      const body = res.result().body as { releases: Array<{ plugin: string; installedVersion: string; candidateVersion: string }> }
      // 只有 1.3 还新于当前已装；另外两行（1.1、1.2 候选）是历史，不该出现。
      assert.equal(body.releases.length, 1)
      assert.equal(body.releases[0]?.candidateVersion, '1.3')
      // 显示当前已装 1.2，而不是通知当时的 1.2/1.1/1.0。
      assert.equal(body.releases[0]?.installedVersion, '1.2')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('drops compat rows that are no longer newer than the installed version', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-compat-stale-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(configFile, JSON.stringify({
        projects: [{
          project: { name: 'p' },
          plugins: [
            { package: { name: 'pkg-a', version: '2.0' } },
            { package: { name: 'pkg-c', version: '1.0' } },
          ],
        }],
      }))
      await writeFile(stateFile, JSON.stringify({
        activeCompatibility: {
          'incident-stale': { event: { installed: { name: 'pkg-a', version: '2.0' }, candidate: { version: '2.0' }, detectedAt: '2026-09-08T01:00:00.000Z' } },
          'incident-live': { event: { installed: { name: 'pkg-c', version: '1.0' }, candidate: { version: '3.0' }, detectedAt: '2026-09-09T01:00:00.000Z' } },
        },
      }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const res = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/releases'))!.handler(req('GET'), res)
      const body = res.result().body as { releases: Array<{ plugin: string; candidateVersion: string }> }
      assert.deepEqual(body.releases.map(r => `${r.plugin}@${r.candidateVersion}`), ['pkg-c@3.0'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('drops notices for plugins that are no longer monitored', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-gone-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(stateFile, JSON.stringify({ activeCompatibility: {} }))
      await writeFile(configFile, JSON.stringify({
        projects: [{ project: { name: 'p' }, plugins: [{ package: { name: 'pkg-b', version: '1.0' } }] }],
      }))
      await writeFile(`${stateFile}.release-notices.json`, JSON.stringify({
        'proj|pkg-gone|0.9|pkg-gone|0.9|pkg-gone|1.0': { eventId: 'e1', notifiedAt: '2026-09-08T00:00:00.000Z' },
        'proj|pkg-b|1.0|pkg-b|1.0|pkg-b|1.1': { eventId: 'e2', notifiedAt: '2026-09-09T00:00:00.000Z' },
      }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const res = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/releases'))!.handler(req('GET'), res)
      const body = res.result().body as { releases: Array<{ plugin: string }> }
      assert.deepEqual(body.releases.map(r => r.plugin), ['pkg-b'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('surfaces evaluated versions that are not the headline candidate', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-evaluated-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(configFile, JSON.stringify({
        projects: [{ project: { name: 'p' }, plugins: [{ package: { name: 'pkg-a', version: '1.0' } }] }],
      }))
      // 头条 candidate = 2.0（相当于 npm 的 dist-tags.latest）；2.5 是"挂在别的通道上的更新版本"。
      await writeFile(stateFile, JSON.stringify({
        activeCompatibility: {
          'incident-eval': {
            event: {
              installed: { name: 'pkg-a', version: '1.0' },
              candidate: { name: 'pkg-a', version: '2.0' },
              detectedAt: '2026-09-12T02:00:00.000Z',
              signals: [{ code: 'breaking-version-boundary', summary: 'Major update.' }],
              upgradePath: {
                evaluated: 3,
                blockedCount: 2,
                vulnerabilityStatus: 'checked',
                dependencyStatus: 'not-requested',
                uncheckedCount: 0,
                blocked: [
                  { candidate: { version: '1.5' }, signals: [{ code: 'sig-low', summary: 'low' }] },
                  { candidate: { version: '2.5' }, signals: [{ code: 'sig-high', summary: 'high' }] },
                ],
                firstCandidate: { candidate: { version: '1.8' } },
              },
            },
          },
        },
      }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })

      const eventsRes = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/events'))!.handler(req('GET'), eventsRes)
      const events = (eventsRes.result().body as { events: Array<Record<string, unknown>> }).events
      const row = events.find(e => e.incidentId === 'incident-eval')
      assert.ok(row !== undefined)
      assert.equal(row.upgradeEvaluated, 3)
      assert.equal(row.upgradeBlockedCount, 2)
      // 3 个已评估 = 2 个 blocked + 1 个 firstCandidate，全部列出，无遗漏。
      assert.equal(row.upgradeUnlisted, 0)
      const versions = row.upgradeVersions as Array<{ version: string; status: string; newerThanCandidate: boolean; reason?: string }>
      // 头条候选 2.0 本身不出现在列表里。
      assert.deepEqual(versions.map(v => v.version), ['1.5', '2.5', '1.8'])
      assert.deepEqual(versions.map(v => v.status), ['blocked', 'blocked', 'unblocked'])
      // 2.5 比头条候选新 → 这正是面板原先看不到的那一类。
      assert.deepEqual(versions.map(v => v.newerThanCandidate), [false, true, false])
      assert.equal(versions[1]?.reason, 'sig-high')

      // 「上游新版本」行同样带上这些信息（同一份数据，两处可见）。
      const releasesRes = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/releases'))!.handler(req('GET'), releasesRes)
      const releases = (releasesRes.result().body as { releases: Array<Record<string, unknown>> }).releases
      assert.equal(releases.length, 1)
      assert.equal(releases[0]?.upgradeEvaluated, 3)
      assert.equal((releases[0]?.upgradeVersions as unknown[]).length, 3)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('reports the evaluated versions that upgradePath did not list by name', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-unlisted-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(configFile, JSON.stringify({
        projects: [{ project: { name: 'p' }, plugins: [{ package: { name: 'pkg-a', version: '1.0' } }] }],
      }))
      // blocked 只存前 8 个：evaluated=12、列出 8 个 → 还有 3 个只能如实报数量。
      const blocked = Array.from({ length: 8 }, (_, index) => (
        { candidate: { version: `1.${index + 1}` }, signals: [{ code: 'sig' }] }
      ))
      await writeFile(stateFile, JSON.stringify({
        activeCompatibility: {
          'incident-many': {
            event: {
              installed: { name: 'pkg-a', version: '1.0' },
              candidate: { name: 'pkg-a', version: '2.0' },
              detectedAt: '2026-09-12T02:00:00.000Z',
              upgradePath: {
                evaluated: 12,
                blockedCount: 12,
                vulnerabilityStatus: 'checked',
                dependencyStatus: 'not-requested',
                uncheckedCount: 0,
                blocked,
              },
            },
          },
        },
      }))

      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const res = jsonResponse()
      await routes.find(r => r.path.endsWith('/api/events'))!.handler(req('GET'), res)
      const row = (res.result().body as { events: Array<Record<string, unknown>> }).events[0]
      assert.equal(row?.upgradeEvaluated, 12)
      assert.equal(row?.upgradeUnlisted, 3)
      assert.equal((row?.upgradeVersions as unknown[]).length, 8)
      assert.equal(row?.upgradeBlockedCount, 12)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('upgrade-request forwards only known candidates through the injected channel', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-up-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      const state = {
        activeCompatibility: {
          'incident-x': { event: { installed: { name: 'pkg-a', version: '1.0' }, candidate: { version: '2.0' }, detectedAt: '2026-09-10T01:00:00.000Z' } },
        },
      }
      await writeFile(stateFile, JSON.stringify(state))
      const calls: Array<{ plugin: string; toVersion: string; kind: string; fromVersion: string | null }> = []
      const { routes, webServer } = fakeServer()
      panel(webServer, {
        radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs'),
        requestUpgrade: async (r) => {
          calls.push({ plugin: r.plugin, toVersion: r.toVersion, kind: r.kind, fromVersion: r.fromVersion })
          return { delivered: true }
        },
      })
      const route = routes.find(r => r.path.endsWith('/api/upgrade-request'))!

      // 未知候选 → 404，且绝不把请求转发出去
      const miss = jsonResponse()
      await route.handler(reqJson('POST', { plugin: 'pkg-a', toVersion: '9.9' }), miss)
      assert.equal(miss.result().code, 404)
      assert.equal(calls.length, 0)

      // 已知候选 → 200 delivered，回调收到正确参数
      const hit = jsonResponse()
      await route.handler(reqJson('POST', { plugin: 'pkg-a', toVersion: '2.0', kind: 'upgrade' }), hit)
      assert.equal(hit.result().code, 200)
      const body = hit.result().body as Record<string, unknown>
      assert.equal(body.delivered, true)
      assert.equal(body.fromVersion, '1.0')
      assert.equal(calls.length, 1)
      assert.deepEqual(calls[0], { plugin: 'pkg-a', toVersion: '2.0', kind: 'upgrade', fromVersion: '1.0' })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('upgrade-request returns 503 when the channel is not injected', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-up2-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      await writeFile(stateFile, JSON.stringify({
        activeCompatibility: { i: { event: { installed: { name: 'p', version: '1' }, candidate: { version: '2' } } } },
      }))
      const { routes, webServer } = fakeServer()
      panel(webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const route = routes.find(r => r.path.endsWith('/api/upgrade-request'))!
      const res = jsonResponse()
      await route.handler(reqJson('POST', { plugin: 'p', toVersion: '2' }), res)
      assert.equal(res.result().code, 503)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('upgrade-target reports the selection read-only and returns 503 when not injected', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'radar-panel-target-'))
    try {
      const stateFile = join(dir, 'state.json')
      const configFile = join(dir, 'config.json')
      const report = {
        workspace: '/workspace/upgrade',
        matches: 2,
        engaged: 1,
        sessionId: 'session-upgrade',
        reason: 'selected session-upgrade',
      }
      const { routes, webServer } = fakeServer()
      panel(webServer, {
        radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs'),
        upgradeTarget: async () => report,
      })
      const route = routes.find(r => r.path.endsWith('/api/upgrade-target'))!
      const res = jsonResponse()
      await route.handler({ method: 'GET' } as never, res)
      assert.equal(res.result().code, 200)
      assert.deepEqual(res.result().body, report)

      // 只读路由不接受写方法（沿用统一的 method 校验）。
      const wrong = jsonResponse()
      await route.handler({ method: 'POST' } as never, wrong)
      assert.equal(wrong.result().code, 405)

      const second = fakeServer()
      panel(second.webServer, { radarDir: dir, configFile, stateFile, cliPath: join(dir, 'cli.js'), jobsDir: join(dir, 'jobs') })
      const route2 = second.routes.find(r => r.path.endsWith('/api/upgrade-target'))!
      const missing = jsonResponse()
      await route2.handler({ method: 'GET' } as never, missing)
      assert.equal(missing.result().code, 503)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('ensures RadarPanelJob typing is sound', () => {
    const job: RadarPanelJob = { id: 'x', kind: 'inspect', status: 'running', startedAt: 'now', output: '' }
    assert.equal(job.kind, 'inspect')
    assert.equal(job.status, 'running')
  })
})
