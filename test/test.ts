import test from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'dgram'
import * as sparoid from '../src/sparoid.js'

const key = "0000000000000000000000000000000000000000000000000000000000000000"
const loopback = Buffer.from([127, 0, 0, 1])

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

test("throws AggregateError when all knocks fail", async t => {
  // 100::1 is a non-routable IPv6 address that should give ENETUNREACH
  const err = await t.throwsAsync(() => sparoid.auth("100::1", 8486, key, key, [loopback]))
  t.true(err instanceof AggregateError)
  t.regex((err as AggregateError).message, /all knocks failed/)
})

test("succeeds when at least one knock works (dual-stack via localhost)", async t => {
  // localhost resolves to both ::1 and 127.0.0.1
  // Server only listens on IPv4 — both sends succeed on loopback
  // but this validates that Promise.allSettled handles multiple knocks correctly
  const server = dgram.createSocket('udp4')
  await new Promise<void>((resolve, reject) => {
    server.on('message', (msg) => {
      t.is(msg.length, 96)
      server.close()
      resolve()
    })

    server.on('listening', async () => {
      try {
        await sparoid.auth("localhost", 8487, key, key, [loopback])
      } catch (err) {
        server.close()
        reject(err)
      }
    })

    server.on('error', (err) => {
      server.close()
      reject(err)
    })

    server.bind(8487, "127.0.0.1")
  })
  t.pass()
})
