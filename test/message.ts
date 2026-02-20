import test from 'ava'
import crypto from 'crypto'
import { MessageV2 } from '../src/message.js'

const ipv4 = Buffer.from([192, 168, 1, 1])
const ipv6 = Buffer.from([
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]) // 2001:db8::1

// --- MessageV2 format ---

test("MessageV2 buffer length is 46 bytes", t => {
  const msg = new MessageV2(ipv4, 32)
  t.is(msg.toBuffer().length, 46)
})

test("MessageV2 with IPv6 buffer length is 46 bytes", t => {
  const msg = new MessageV2(ipv6, 64)
  t.is(msg.toBuffer().length, 46)
})

test("MessageV2 version field is 2", t => {
  const msg = new MessageV2(ipv4, 24)
  const buf = msg.toBuffer()
  t.is(buf.readInt32BE(0), 2)
})

test("MessageV2 contains timestamp", t => {
  const before = Date.now()
  const msg = new MessageV2(ipv4, 24)
  const after = Date.now()
  const buf = msg.toBuffer()
  const ts = Number(buf.readBigInt64BE(4))
  t.true(ts >= before && ts <= after)
})

test("MessageV2 contains 16-byte nonce at offset 12", t => {
  const msg = new MessageV2(ipv4, 24)
  const buf = msg.toBuffer()
  const nonce = buf.subarray(12, 28)
  // nonce should not be all zeros (random)
  t.false(nonce.every(b => b === 0))
})

test("MessageV2 IPv4 family byte is 4", t => {
  const msg = new MessageV2(ipv4, 24)
  const buf = msg.toBuffer()
  t.is(buf.readUint8(28), 4)
})

test("MessageV2 IPv6 family byte is 6", t => {
  const msg = new MessageV2(ipv6, 64)
  const buf = msg.toBuffer()
  t.is(buf.readUint8(28), 6)
})

test("MessageV2 IPv4 address at offset 29", t => {
  const msg = new MessageV2(ipv4, 24)
  const buf = msg.toBuffer()
  t.deepEqual(buf.subarray(29, 33), ipv4)
})

test("MessageV2 IPv6 address at offset 29", t => {
  const msg = new MessageV2(ipv6, 64)
  const buf = msg.toBuffer()
  t.deepEqual(buf.subarray(29, 45), ipv6)
})

test("MessageV2 range byte after IPv4", t => {
  const msg = new MessageV2(ipv4, 24)
  const buf = msg.toBuffer()
  t.is(buf.readUint8(33), 24)
})

test("MessageV2 range byte after IPv6", t => {
  const msg = new MessageV2(ipv6, 64)
  const buf = msg.toBuffer()
  t.is(buf.readUint8(45), 64)
})

test("MessageV2 rejects invalid IP length", t => {
  t.throws(() => new MessageV2(Buffer.alloc(8), 24), { message: /Invalid IP length/ })
})

test("MessageV2 rejects range > 128", t => {
  t.throws(() => new MessageV2(ipv4, 129), { message: /Invalid range/ })
})

test("MessageV2 rejects negative range", t => {
  t.throws(() => new MessageV2(ipv4, -1), { message: /Invalid range/ })
})

// --- Round-trip encrypt/decrypt ---

function encrypt(plain: Buffer, key: Buffer): { iv: Buffer; ciphertext: Buffer } {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
  const u = cipher.update(plain)
  const f = cipher.final()
  return { iv, ciphertext: Buffer.concat([u, f]) }
}

function decrypt(iv: Buffer, ciphertext: Buffer, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv)
  const u = decipher.update(ciphertext)
  const f = decipher.final()
  return Buffer.concat([u, f])
}

const aesKey = Buffer.alloc(32) // 256-bit zero key

test("MessageV2 IPv4 round-trip encrypt/decrypt", t => {
  const msg = new MessageV2(ipv4, 24)
  const plain = msg.toBuffer()
  const { iv, ciphertext } = encrypt(plain, aesKey)
  const decrypted = decrypt(iv, ciphertext, aesKey)
  t.deepEqual(decrypted, plain)
})

test("MessageV2 IPv6 round-trip encrypt/decrypt", t => {
  const msg = new MessageV2(ipv6, 64)
  const plain = msg.toBuffer()
  const { iv, ciphertext } = encrypt(plain, aesKey)
  const decrypted = decrypt(iv, ciphertext, aesKey)
  t.deepEqual(decrypted, plain)
})
