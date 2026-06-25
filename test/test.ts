import test, { mock } from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'dgram'
import * as sparoid from '../src/sparoid.js'

const key = "0000000000000000000000000000000000000000000000000000000000000000"
const loopback = Buffer.from([127, 0, 0, 1])

type SendCb = (err?: Error | null) => void

// Replace dgram sockets with a fake whose send() outcome we control, so the
// "all knocks fail" / "partial success" paths don't depend on the host's
// network (IPv6 routing, reachability) — which is what made these tests flaky.
function mockSend(send: (cb: SendCb) => void): void {
  mock.method(dgram, 'createSocket', (() => ({
    send: (_msg: Buffer, _port: number, _host: string, cb: SendCb) => send(cb),
    close: () => {},
  })) as unknown as typeof dgram.createSocket)
}

test("it can auth", async () => {
  const server = dgram.createSocket('udp4')
  await new Promise<void>((resolve, reject) => {
    server.on('message', (msg) => {
      assert.equal(msg.length, 96)
      server.close()
      resolve()
    })

    server.on('listening', async () => {
      try {
        await sparoid.auth("127.0.0.1", 8484, key, key, [loopback])
      } catch (err) {
        server.close()
        reject(err)
      }
    })

    server.on('error', (err) => {
      server.close()
      reject(err)
    })

    server.bind(8484, "127.0.0.1")
  })
})

test("raises on error on DNS error", async () => {
  await assert.rejects(() => sparoid.auth("none.arpa", 8485, key, key),
    { message: /ENOTFOUND/ })
})

test("throws AggregateError when all knocks fail", async () => {
  // Every send fails -> auth() must reject with an aggregated error.
  mockSend(cb => cb(new Error('ENETUNREACH')))
  try {
    await assert.rejects(
      () => sparoid.auth("100::1", 8486, key, key, [loopback]),
      (err: unknown) =>
        err instanceof AggregateError && /all knocks failed/.test(err.message),
    )
  } finally {
    mock.restoreAll()
  }
})

test("succeeds when at least one knock succeeds", async () => {
  // First knock fails to send, the second succeeds: auth() must still resolve
  // (mirrors a dual-stack host where one address family is unreachable).
  let calls = 0
  mockSend(cb => cb(calls++ === 0 ? new Error('ENETUNREACH') : null))
  try {
    await assert.doesNotReject(
      () => sparoid.auth("127.0.0.1", 8487, key, key, [loopback, loopback]),
    )
  } finally {
    mock.restoreAll()
  }
})
