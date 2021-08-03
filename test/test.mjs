import test from 'ava'
import dgram from 'dgram'
import * as sparoid from '../src/sparoid.mjs'

test.cb("it can auth", t => {
  const key = "0000000000000000000000000000000000000000000000000000000000000000"
  const server = dgram.createSocket('udp4')
  server.on('message', (msg) => {
    t.is(msg.length, 96)
    t.end()
  })

  server.on('listening', async () => {
    try {
      await sparoid.auth("127.0.0.1", 8484, key, key)
    } catch (err) {
      t.end(err)
    }
  })

  server.on('error', (err) => {
    t.end(err)
    server.close()
  })

  server.bind(8484, "127.0.0.1")
})
