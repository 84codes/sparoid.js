import test from 'ava'
import { ipv6ToBuffer } from '../src/ipv6.js'

// --- Full addresses (no ::) ---

test("full address", t => {
  const buf = ipv6ToBuffer("2001:0db8:0000:0000:0000:0000:0000:0001")
  t.deepEqual(buf, Buffer.from([
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]))
})

test("full address without leading zeros", t => {
  const buf = ipv6ToBuffer("2001:db8:0:0:0:0:0:1")
  t.deepEqual(buf, Buffer.from([
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]))
})

test("all ones", t => {
  const buf = ipv6ToBuffer("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
  t.deepEqual(buf, Buffer.alloc(16, 0xff))
})

// --- :: expansion ---

test(":: expands to all zeros", t => {
  const buf = ipv6ToBuffer("::")
  t.deepEqual(buf, Buffer.alloc(16, 0))
})

test("::1 (loopback)", t => {
  const buf = ipv6ToBuffer("::1")
  const expected = Buffer.alloc(16, 0)
  expected.writeUInt16BE(1, 14)
  t.deepEqual(buf, expected)
})

test("prefix::suffix expansion", t => {
  const buf = ipv6ToBuffer("2001:db8::1")
  t.deepEqual(buf, Buffer.from([
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]))
})

test(":: at the end", t => {
  const buf = ipv6ToBuffer("fe80::")
  const expected = Buffer.alloc(16, 0)
  expected.writeUInt16BE(0xfe80, 0)
  t.deepEqual(buf, expected)
})

test("multiple groups on both sides of ::", t => {
  const buf = ipv6ToBuffer("2001:db8::ff00:42:8329")
  t.deepEqual(buf, Buffer.from([
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0x00, 0x00, 0x42, 0x83, 0x29,
  ]))
})

// --- Buffer is always 16 bytes ---

test("result is always 16 bytes", t => {
  t.is(ipv6ToBuffer("::").length, 16)
  t.is(ipv6ToBuffer("::1").length, 16)
  t.is(ipv6ToBuffer("2001:db8::1").length, 16)
  t.is(ipv6ToBuffer("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").length, 16)
})

// --- Embedded IPv4 tail ---

test("IPv4-mapped address ::ffff:192.0.2.128", t => {
  const buf = ipv6ToBuffer("::ffff:192.0.2.128")
  t.deepEqual(buf, Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x80,
  ]))
})

test("IPv4-mapped address ::ffff:10.0.0.1", t => {
  const buf = ipv6ToBuffer("::ffff:10.0.0.1")
  t.deepEqual(buf, Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
  ]))
})

test("IPv4-compatible address ::192.168.1.1", t => {
  const buf = ipv6ToBuffer("::192.168.1.1")
  t.deepEqual(buf, Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
  ]))
})

// --- Invalid inputs ---

test("rejects empty string", t => {
  t.throws(() => ipv6ToBuffer(""), { message: /Invalid IPv6/ })
})

test("rejects IPv4 address", t => {
  t.throws(() => ipv6ToBuffer("192.168.1.1"), { message: /Invalid IPv6/ })
})

test("rejects garbage", t => {
  t.throws(() => ipv6ToBuffer("not-an-ip"), { message: /Invalid IPv6/ })
})
