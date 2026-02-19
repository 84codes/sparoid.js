import dgram from 'dgram'
import crypto from 'crypto'
import { Buffer } from 'buffer'
import process from 'process'
import dns from 'dns'
import { lookup } from 'dns/promises'
import net from 'net'
import { Message, MessageV1, MessageV2 } from './message.js'
import { ipv6ToBuffer, getGlobalIPv6 } from './ipv6.js'

export async function auth(host: string, port: number, key?: string, hmac_key?: string): Promise<void> {
    const keyBuf = Buffer.from(key || process.env.SPAROID_KEY!, 'hex')
    const hmacKeyBuf = Buffer.from(hmac_key || process.env.SPAROID_HMAC_KEY!, 'hex')
    const hostAddresses = await resolvHost(host);
    const ips = await publicIp()
    const globalIps = getGlobalIPv6();

    for (const addr of hostAddresses) {
        let ipv6Added = false;

        const messages: Message[] = [];
        for (const ipv6 of globalIps) {
            messages.push(new MessageV2(ipv6.address, ipv6.range))
            ipv6Added = true;
        }

        for (const ip of ips) {
            switch (ip.length) {
                case 4:
                    messages.push(new MessageV1(ip))
                    messages.push(new MessageV2(ip, 32))
                    break;
                case 16:
                    if (!ipv6Added)
                        messages.push(new MessageV2(ip, 128))
                    break;
            }
        }

        messages.sort((a, b) => a.toBuffer().length - b.toBuffer().length) // send shorter messages first

        for (const msg of messages) {
            const encrypted = encrypt(msg, keyBuf)
            const hmaced = prefixHmac(encrypted, hmacKeyBuf)
            udpSend(hmaced, addr, port)
        }
    }
    await sleep(200) // let the server process the packet
}

function sleep(s: number): Promise<void> {
    return new Promise((resolv) => setTimeout(resolv, s))
}

function encrypt(msg: Message, key: Buffer): Buffer {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
    const u = cipher.update(msg.toBuffer())
    const f = cipher.final()
    return Buffer.concat([iv, u, f])
}

function prefixHmac(encrypted: Buffer, hmac_key: Buffer): Buffer {
    const hmac = crypto.createHmac('sha256', hmac_key)
    hmac.update(encrypted)
    const digest = hmac.digest()
    return Buffer.concat([digest, encrypted])
}

async function publicIp(): Promise<Buffer[]> {
    const settled = await Promise.allSettled(["http://ipv4.icanhazip.com", "http://ipv6.icanhazip.com"].map(async (url) => {
        const ip = await (await fetch(url).then((res) => res.text())).trim()
        if (net.isIPv4(ip)) return Buffer.from(ip.split(".").map((part) => parseInt(part)))
        else if (net.isIPv6(ip)) {
            return ipv6ToBuffer(ip);
        }
    }))
    const ips = settled.filter((r): r is PromiseFulfilledResult<Buffer> => r.status === "fulfilled").map((r) => r.value)
    if (ips.length === 0) throw new Error("Failed to determine public IP")
    return ips
}

async function resolvHost(host: string): Promise<dns.LookupAddress[]> {
    const family = net.isIP(host)
    if (family !== 0) {
        return [{ address: host, family }]
    }
    return lookup(host, {
        all: true
    });
}

async function udpSend(message: Buffer, host: dns.LookupAddress, port: number): Promise<void> {
    const client = dgram.createSocket(host.family === 4 ? 'udp4' : 'udp6')
    const promise = new Promise<void>((resolve, reject) => {
        client.send(message, port, host.address, (err) => {
            if (err) reject(err)
            else resolve()
        })
    })
    await promise
    client.close()
    return;
}
