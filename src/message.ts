import crypto from 'crypto'
interface BaseMessage {
    ts: number;
    nonce: Buffer;
    ip: Buffer;
}

export abstract class Message {
    abstract toBuffer(): Buffer;
}


export class MessageV1 extends Message implements BaseMessage {
    version: number;
    ts: number;
    nonce: Buffer;
    ip: Buffer;

    constructor(ip: Buffer) {
        super()
        this.version = 1
        this.ts = Date.now()
        this.nonce = crypto.randomBytes(16)
        this.ip = ip
    }

    toBuffer(): Buffer {
        const msg = Buffer.alloc(4 + 8 + 16 + 4)
        msg.writeInt32BE(this.version, 0)
        msg.writeBigInt64BE(BigInt(this.ts), 4)
        this.nonce.copy(msg, 12)
        this.ip.copy(msg, 28)
        return msg
    }
}

export class MessageV2 extends Message implements BaseMessage {
    version: number
    ts: number;
    nonce: Buffer
    ip: Buffer;
    range: number;

    constructor(ip: Buffer, range: number) {
        if (ip.length !== 4 && ip.length !== 16) {
            throw new Error("Invalid IP length")
        }
        if (range < 0 || range > 128) {
            throw new Error("Invalid range")
        }
        super()
        this.version = 2
        this.ts = Date.now()
        this.nonce = crypto.randomBytes(16)
        this.ip = ip
        this.range = range
    }

    toBuffer(): Buffer {
        const msg = Buffer.alloc(4 + 8 + 16 + 1 + 16 + 1)
        msg.writeInt32BE(this.version, 0)
        msg.writeBigInt64BE(BigInt(this.ts), 4)
        this.nonce.copy(msg, 12)
        switch (this.ip.length) {
            case 4:
                msg.writeUint8(4, 28)
                break;
            case 16:
                msg.writeUint8(6, 28)
                break;
            default:
                throw new Error("Invalid IP length")
        }
        this.ip.copy(msg, 29, 0, this.ip.length)
        msg.writeUint8(this.range, 29 + this.ip.length)
        return msg
    }
}
