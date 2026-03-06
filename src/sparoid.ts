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

    if (value.length === 0) {
        throw new Error(
            `The ${keyDescription} (from ${envVarName}) must not be empty.`,
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
    await Promise.all(promises)
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

async function publicIps(): Promise<Buffer[]> {
    const [ipv4, ipv6] = await Promise.allSettled([
        publicIPv4(),
        publicIPv6(),
    ])
    const ips: Buffer[] = []
    if (ipv4.status === "fulfilled" && ipv4.value) ips.push(ipv4.value)
    if (ipv6.status === "fulfilled" && ipv6.value) ips.push(ipv6.value)
    if (ips.length === 0) throw new Error("Failed to determine public IP")
    return ips
}

async function publicIPv4(): Promise<Buffer> {
    const text = await fetch("http://ipv4.icanhazip.com").then((res) => res.text())
    const ip = text.trim()
    if (!net.isIPv4(ip)) throw new Error(`Invalid IPv4 response: ${ip}`)
    return Buffer.from(ip.split(".").map((part) => parseInt(part)))
}

async function publicIPv6(): Promise<Buffer | null> {
    const ip = await getPublicIPv6()
    if (ip) return ip
    // Fallback to icanhazip.com
    const text = await fetch("http://ipv6.icanhazip.com").then((res) => res.text())
    const addr = text.trim()
    if (!net.isIPv6(addr)) return null
    return ipv6ToBuffer(addr)
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
