import test, { mock, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'dgram'
import * as sparoid from '../src/sparoid.js'

type Response = { status: number, body?: string } | 'timeout'

// Stubs fetch, a URL missing from responses fails like a network error
function mockFetch(responses: Record<string, Response>): string[] {
  const calls: string[] = []
  mock.method(globalThis, 'fetch', async (url: string, init?: RequestInit) => {
    calls.push(url)
    assert.ok(init?.signal instanceof AbortSignal, 'every lookup must have a timeout')
    const r = responses[url]
    if (r === undefined) throw new TypeError('fetch failed')
    if (r === 'timeout') throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    return new Response(r.body ?? '', { status: r.status })
  })
  return calls
}

// No global IPv6 source address from the OS, so the HTTP lookup is used
function mockNoOsIPv6(): void {
  mock.method(dgram, 'createSocket', (() => {
    let onError: (err: Error) => void = () => {}
    return {
      on: (event: string, cb: (err: Error) => void) => { if (event === 'error') onError = cb },
      connect: () => onError(new Error('ENETUNREACH')),
      close: () => {},
    }
  }) as unknown as typeof dgram.createSocket)
}

afterEach(() => mock.restoreAll())

test("IPv4 falls back in order until a provider answers", async () => {
  const calls = mockFetch({
    "https://ipv4.icanhazip.com": { status: 500 },
    "https://checkip.amazonaws.com": 'timeout',
    "https://api.ipify.org": { status: 200, body: "198.51.100.4\n" },
  })
  assert.deepEqual(await sparoid.publicIPv4(), Buffer.from([198, 51, 100, 4]))
  assert.deepEqual(calls, ["https://ipv4.icanhazip.com", "https://checkip.amazonaws.com", "https://api.ipify.org"])
})

test("IPv4 stops at the first valid answer and skips invalid ones", async () => {
  const calls = mockFetch({
    "https://ipv4.icanhazip.com": { status: 200, body: "<html>oops</html>" },
    "https://checkip.amazonaws.com": { status: 200, body: "203.0.113.9\n" },
    "https://api.ipify.org": { status: 200, body: "198.51.100.4" },
  })
  assert.deepEqual(await sparoid.publicIPv4(), Buffer.from([203, 0, 113, 9]))
  assert.deepEqual(calls, ["https://ipv4.icanhazip.com", "https://checkip.amazonaws.com"])
})

test("IPv4 rejects with every provider's error when all fail", async () => {
  mockFetch({ "https://api.ipify.org": { status: 503 } })
  await assert.rejects(() => sparoid.publicIPv4(),
    { message: /ipv4\.icanhazip\.com.*checkip\.amazonaws\.com.*api\.ipify\.org: returned 503/ })
})

test("IPv6 falls back and rejects non-global addresses", async () => {
  mockNoOsIPv6()
  const calls = mockFetch({
    "https://ipv6.icanhazip.com": { status: 200, body: "fe80::1" },
    "https://api6.ipify.org": { status: 200, body: "2606:4700:4700::1111\n" },
  })
  const ip = await sparoid.publicIPv6()
  assert.equal(ip.toString('hex'), "26064700470000000000000000001111")
  assert.deepEqual(calls, ["https://ipv6.icanhazip.com", "https://api6.ipify.org"])
})

test("IPv6 rejects an IPv4 answer", async () => {
  mockNoOsIPv6()
  mockFetch({ "https://ipv6.icanhazip.com": { status: 200, body: "203.0.113.9" } })
  await assert.rejects(() => sparoid.publicIPv6(), { message: /invalid response/ })
})
