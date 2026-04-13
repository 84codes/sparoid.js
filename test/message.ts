import test from 'ava'
import crypto from 'crypto'
import { Message } from '../src/message.js'

const ipv4 = Buffer.from([192, 168, 1, 1])
const ipv6 = Buffer.from([
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]) // 2001:db8::1

test("Message with IPv4 buffer length is 32 bytes", t => {
  const msg = new Message(ipv4)
  t.is(msg.toBuffer().length, 32)
})

test("Message with IPv6 buffer length is 44 bytes", t => {
  const msg = new Message(ipv6)
  t.is(msg.toBuffer().length, 44)
})

test("Message version field is 1", t => {
  const msg = new Message(ipv4)
  const buf = msg.toBuffer()
  t.is(buf.readInt32BE(0), 1)
})

test("Message contains timestamp", t => {
  const before = Date.now()
  const msg = new Message(ipv4)
  const after = Date.now()
  const buf = msg.toBuffer()
  const ts = Number(buf.readBigInt64BE(4))
  t.true(ts >= before && ts <= after)
})

test("Message contains 16-byte nonce at offset 12", t => {
  const msg = new Message(ipv4)
  const buf = msg.toBuffer()
  const nonce = buf.subarray(12, 28)
  t.false(nonce.every(b => b === 0))
})

test("Message IPv4 address at offset 28", t => {
  const msg = new Message(ipv4)
  const buf = msg.toBuffer()
  t.deepEqual(buf.subarray(28, 32), ipv4)
})

test("Message IPv6 address at offset 28", t => {
  const msg = new Message(ipv6)
  const buf = msg.toBuffer()
  t.deepEqual(buf.subarray(28, 44), ipv6)
})

test("Message rejects invalid IP length", t => {
  t.throws(() => new Message(Buffer.alloc(8)), { message: /IP must be 4 .* or 16/ })
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

test("Message IPv4 round-trip encrypt/decrypt", t => {
  const msg = new Message(ipv4)
  const plain = msg.toBuffer()
  const { iv, ciphertext } = encrypt(plain, aesKey)
  const decrypted = decrypt(iv, ciphertext, aesKey)
  t.deepEqual(decrypted, plain)
})

test("Message IPv6 round-trip encrypt/decrypt", t => {
  const msg = new Message(ipv6)
  const plain = msg.toBuffer()
  const { iv, ciphertext } = encrypt(plain, aesKey)
  const decrypted = decrypt(iv, ciphertext, aesKey)
  t.deepEqual(decrypted, plain)
})
