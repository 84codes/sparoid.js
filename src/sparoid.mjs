import dgram from 'dgram'
import crypto from 'crypto'
import { Buffer } from 'buffer'
import process from 'process'
import dns from 'dns'
import net from 'net'

export async function auth(host, port, key, hmac_key, public_ip) {
    key = Buffer.from(key || process.env.SPAROID_KEY, 'hex')
    hmac_key = Buffer.from(hmac_key || process.env.SPAROID_HMAC_KEY, 'hex')
    public_ip = public_ip || await publicIp()
    const msg = await plainMsg(public_ip)
    const encrypted = encrypt(msg, key)
    const hmaced = prefixHmac(encrypted, hmac_key)
    udpSend(hmaced, host, port)
    await sleep(200) // let the server process the packet
}

function sleep(s) {
    return new Promise((resolv) => setTimeout(resolv, s))
}

function encrypt(msg, key) {
    const buf = Buffer.alloc(64)
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
    const u = cipher.update(msg)
    const f = cipher.final()
    iv.copy(buf)
    u.copy(buf, 16)
    f.copy(buf, 48)
    return buf
}

function prefixHmac(encrypted, hmac_key) {
    const hmac = crypto.createHmac('sha256', hmac_key)
    hmac.update(encrypted)
    const buf = Buffer.alloc(96)
    const digest = hmac.digest()
    digest.copy(buf)
    encrypted.copy(buf, 32)
    return buf
}

function plainMsg(ip) {
    const version = 1
    const ts = new Date().getTime()
    const nounce = crypto.randomBytes(16)

    const msg = Buffer.alloc(4 + 8 + 16 + 4)
    msg.writeInt32BE(version, 0)
    msg.writeBigInt64BE(BigInt(ts), 4)
    nounce.copy(msg, 12)
    ip.copy(msg, 28)
    return msg
}

export function publicIp() {
    return new Promise((resolv, reject) => {
        const resolver = new dns.Resolver()
        resolver.setServers(["208.67.222.222", "208.67.220.220"])
        resolver.resolve4('myip.opendns.com', (err, addresses) => {
            if (err) return reject(err)

            const buf = Buffer.alloc(4)
            addresses[0].split(".").forEach((part, idx) => buf.writeUint8(part, idx))
            resolv(buf)
        })
    })
}

function resolvHost(host) {
    return new Promise((resolv, reject) => {
        if (net.isIPv4(host)) resolv([host])
        const resolver = new dns.Resolver()
        resolver.resolve4(host, (err, addresses) => {
            if (err) return reject(err)

            resolv(addresses)
        })
    })
}

async function udpSend(message, host, port) {
    const ips = await resolvHost(host)
    const client = dgram.createSocket('udp4')
    await Promise.all(ips.map((ip) => {
        return new Promise((resolv, reject) => {
            client.send(message, port, ip, (err) => {
                if (err) return reject(err)
                resolv()
            })
        })
    }))
    client.close()
}
