import crypto from 'crypto'

export class Message {
    version: number;
    ts: number;
    nonce: Buffer;
    ip: Buffer;

    constructor(ip: Buffer) {
        if (ip.length !== 4 && ip.length !== 16) {
            throw new Error("IP must be 4 (IPv4) or 16 (IPv6) bytes")
        }
        this.version = 1
        this.ts = Date.now()
        this.nonce = crypto.randomBytes(16)
        this.ip = ip
    }

    toBuffer(): Buffer {
        const msg = Buffer.alloc(4 + 8 + 16 + this.ip.length)
        msg.writeInt32BE(this.version, 0)
        msg.writeBigInt64BE(BigInt(this.ts), 4)
        this.nonce.copy(msg, 12)
        this.ip.copy(msg, 28)
        return msg
    }
}
