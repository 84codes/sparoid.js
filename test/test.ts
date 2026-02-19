import test from 'ava'
import dgram from 'dgram'
import * as sparoid from '../src/sparoid.js'

const key = "0000000000000000000000000000000000000000000000000000000000000000"
const loopback = Buffer.from([127, 0, 0, 1])

test("it can auth", async t => {
  const server = dgram.createSocket('udp4')
  await new Promise<void>((resolve, reject) => {
    server.on('message', (msg) => {
      t.is(msg.length, 96)
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

test("raises on error on DNS error", async t => {
  await t.throwsAsync(() => sparoid.auth("none.arpa", 8485, key, key),
    { message: /ENOTFOUND/ })
})
