import test from 'ava';
import Sparoid from '../src/sparoid.mjs';
import dgram from 'dgram'

test.cb("it can auth", t => {
  const key = "0000000000000000000000000000000000000000000000000000000000000000"
  const server = dgram.createSocket('udp4');
  server.on('message', (msg) => {
    t.is(msg.length, 96)
    t.end()
  });

  server.on('listening', async () => {
    try {
      const s = new Sparoid("127.0.0.1", 8484, key, key)
      await s.auth()
    } catch (err) {
      t.end(err)
    }
  })

  server.on('error', (err) => {
    t.end(err)
    server.close()
  })

  server.bind(8484, "127.0.0.1");
})
