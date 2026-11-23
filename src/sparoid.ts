import dgram from 'dgram'
import crypto from 'crypto'
import { Buffer } from 'buffer'
import process from 'process'
import { LookupAddress } from 'dns'
import { lookup } from 'dns/promises'
import net from 'net'
import { Message } from './message.js'
import { ipv6ToBuffer, getPublicIPv6 } from './ipv6.js'

function getHexKeyBuffer(envVarName: string, argValue: string | undefined, keyDescription: string): Buffer {
    const value = argValue || process.env[envVarName];

    if (!value) {
        throw new Error(
            `Missing ${keyDescription}: provide it as an argument or set the ${envVarName} environment variable.`,
        );
    }

    if (value.length % 2 !== 0) {
        throw new Error(
            `The ${keyDescription} (from ${envVarName}) must be a hex string with an even number of characters.`,
        );
    }

    if (!/^[0-9a-fA-F]+$/.test(value)) {
        throw new Error(
            `The ${keyDescription} (from ${envVarName}) must contain only hexadecimal characters (0-9, a-f).`,
        );
    }

    return Buffer.from(value, 'hex');
}

export async function auth(host: string, port: number, key?: string, hmac_key?: string, public_ips?: Buffer[]): Promise<void> {
    const keyBuf = getHexKeyBuffer('SPAROID_KEY', key, 'encryption key');
    const hmacKeyBuf = getHexKeyBuffer('SPAROID_HMAC_KEY', hmac_key, 'HMAC key');
    const hostAddresses = await resolveHost(host);
    const ips = public_ips || await publicIps()

    const promises: Promise<void>[] = [];
    for (const addr of hostAddresses) {
        for (const ip of ips) {
            const msg = new Message(ip)
            const encrypted = encrypt(msg, keyBuf)
            const hmaced = prefixHmac(encrypted, hmacKeyBuf)
            promises.push(udpSend(hmaced, addr, port));
        }
    }
    const results = await Promise.allSettled(promises)
    if (results.length === 0 || results.every(r => r.status === 'rejected')) {
        throw new AggregateError(
            results.map(r => (r as PromiseRejectedResult).reason),
            'sparoid auth failed: all knocks failed',
        )
    }
    await sleep(200) // let the server process the packet
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolv) => setTimeout(resolv, ms))
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

async function publicIps(): Promise<Buffer[]> {
    const [ipv4, ipv6] = await Promise.allSettled([
        publicIPv4(),
        publicIPv6(),
    ])
    const ips: Buffer[] = []
    if (ipv4.status === "fulfilled" && ipv4.value) ips.push(ipv4.value)
    if (ipv6.status === "fulfilled" && ipv6.value) ips.push(ipv6.value)
    if (ips.length === 0) {
        const errors = [ipv4, ipv6]
            .filter((r): r is PromiseRejectedResult => r.status === "rejected")
            .map(r => r.reason)
        throw new Error("Failed to determine public IP: " + errors.join("; "))
    }
    return ips
}

const IPV4_URLS = [
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
]

const IPV6_URLS = [
    "https://ipv6.icanhazip.com",
    "https://api6.ipify.org",
]

export async function publicIPv4(): Promise<Buffer> {
    return firstValid(IPV4_URLS, parseIPv4)
}

export async function publicIPv6(): Promise<Buffer> {
    const ip = await getPublicIPv6()
    if (ip) return ip
    return firstValid(IPV6_URLS, parseIPv6)
}

// Tries the URLs one at a time, the next only if the previous failed
async function firstValid(urls: string[], parse: (ip: string) => Buffer | null): Promise<Buffer> {
    const errors: string[] = []
    for (const url of urls) {
        try {
            const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
            if (!res.ok) throw new Error(`returned ${res.status}`)
            const body = (await res.text()).trim()
            const ip = parse(body)
            if (ip) return ip
            errors.push(`${url}: invalid response`)
        } catch (err) {
            errors.push(`${url}: ${err instanceof Error ? err.message : err}`)
        }
    }
    throw new Error(`No public IP: ${errors.join(", ")}`)
}

function parseIPv4(ip: string): Buffer | null {
    if (!net.isIPv4(ip)) return null
    return Buffer.from(ip.split(".").map((part) => parseInt(part, 10)))
}

function parseIPv6(ip: string): Buffer | null {
    if (!net.isIPv6(ip)) return null
    const buf = ipv6ToBuffer(ip)
    // Ensure it's a global unicast address (2000::/3)
    if ((buf[0] & 0xe0) !== 0x20) return null
    return buf
}

async function resolveHost(host: string): Promise<LookupAddress[]> {
    const family = net.isIP(host)
    if (family !== 0) {
        return [{ address: host, family }]
    }
    return lookup(host, {
        all: true
    });
}

async function udpSend(message: Buffer, host: LookupAddress, port: number): Promise<void> {
    const client = dgram.createSocket(host.family === 4 ? 'udp4' : 'udp6')
    try {
        await new Promise<void>((resolve, reject) => {
            client.send(message, port, host.address, (err) => {
                if (err) reject(err)
                else resolve()
            })
        })
    } finally {
        client.close()
    }
}
