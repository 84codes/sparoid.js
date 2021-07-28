import dgram from 'dgram'
import crypto from 'crypto'
import { Buffer } from 'buffer'
import process from 'process'
import dns from 'dns'
import net from 'net'

export default class Sparoid {
    constructor(host, port, key, hmac_key) {
        this.host = host
        this.port = port
        this.key = Buffer.from(key || process.env.SPAROID_KEY, 'hex')
        this.hmac_key = Buffer.from(hmac_key || process.env.SPAROID_HMAC_KEY, 'hex')
    }

    async auth() {
        const self = this
        const msg = await this.plainMsg()
        const encrypted = this.encrypt(msg)
        const hmaced = this.prefixHmac(encrypted)
        const addresses = await this.resolvHost(self.host)
        await Promise.all(addresses.map((address) => {
            this.udpSend(hmaced, address)
        }));
        await this.sleep(200) // let the server process the packet
    }

    sleep(s) {
        return new Promise((resolv) => setTimeout(resolv, s))
    }

    encrypt(msg) {
        const buf = Buffer.alloc(64)
        const iv = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv("aes-256-cbc", this.key, iv)
        const u = cipher.update(msg)
        const f = cipher.final()
        iv.copy(buf)
        u.copy(buf, 16)
        f.copy(buf, 48)
        return buf
    }

    prefixHmac(encrypted) {
        const hmac = crypto.createHmac('sha256', this.hmac_key)
        hmac.update(encrypted)
        const buf = Buffer.alloc(96)
        const digest = hmac.digest()
        digest.copy(buf)
        encrypted.copy(buf, 32)
        return buf
    }

    async plainMsg() {
        const version = 1
        const ts = new Date().getTime() 
        const nounce = crypto.randomBytes(16)
        const ip = await this.myip()

        const msg = Buffer.alloc(4 + 8 + 16 + 4)
        msg.writeInt32BE(version, 0)
        msg.writeBigInt64BE(BigInt(ts), 4)
        nounce.copy(msg, 12)
        ip.copy(msg, 28)
        return msg
    }

    myip() {
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

    resolvHost(host) {
        return new Promise((resolv, reject) => {
            if (net.isIPv4(host)) resolv([host])
            const resolver = new dns.Resolver()
            resolver.resolve4(host, (err, addresses) => {
                if (err) return reject(err)

                resolv(addresses)
            })
        })
    }

    udpSend(message, address) {
        const self = this
        return new Promise((resolv, reject) => {
            const client = dgram.createSocket('udp4')
            client.send(message, self.port, address, (err) => {
                if (err) return reject(err)

                client.close()
                resolv()
            })
        })
    }
}
