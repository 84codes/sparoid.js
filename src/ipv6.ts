import dgram from "dgram";
import net from "net";

export function ipv6ToBuffer(ip: string): Buffer {
    if (!net.isIPv6(ip)) {
        throw new Error('Invalid IPv6 address');
    }

    // Check for embedded IPv4 tail (e.g. ::ffff:192.0.2.128)
    // The IPv4 part occupies the last 2 of the 8 groups
    const hasIPv4 = ip.includes('.');
    const targetGroups = hasIPv4 ? 7 : 8;

    let fullParts: string[] = [];

    // 1. Handle "::" expansion
    const doubleColonIndex = ip.indexOf('::');

    if (doubleColonIndex > -1) {
        const split = ip.split('::');
        const left = split[0] ? split[0].split(':') : [];
        const right = split[1] ? split[1].split(':') : [];

        const missing = targetGroups - (left.length + right.length);

        if (missing < 0) throw new Error('Invalid IPv6: Too many groups');

        fullParts = [...left, ...Array(missing).fill('0'), ...right];
    } else {
        fullParts = ip.split(':');
    }

    // 2. Expand embedded IPv4 tail into two hex groups
    if (hasIPv4) {
        const lastPart = fullParts[fullParts.length - 1];
        const octets = lastPart.split('.').map(Number);
        if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
            throw new Error(`Invalid embedded IPv4 in IPv6: ${lastPart}`);
        }
        fullParts.splice(-1, 1,
            ((octets[0] << 8) | octets[1]).toString(16),
            ((octets[2] << 8) | octets[3]).toString(16),
        );
    }

    if (fullParts.length !== 8) {
        throw new Error('Invalid IPv6: Incorrect number of groups');
    }

    // 3. Write to buffer
    const buffer = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
        const hex = fullParts[i];

        if (hex === '') throw new Error('Invalid IPv6: Empty group');

        const val = parseInt(hex, 16);

        if (isNaN(val) || val > 0xFFFF) {
            throw new Error(`Invalid IPv6 group: ${hex}`);
        }

        buffer.writeUInt16BE(val, i * 2);
    }

    return buffer;
}

// Get public IPv6 address by connecting a UDP socket to Google Public DNS
export function getPublicIPv6(): Promise<Buffer | null> {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp6');
        const timeout = setTimeout(() => {
            socket.close();
            resolve(null);
        }, 3000);
        socket.on('error', () => {
            clearTimeout(timeout);
            socket.close();
            resolve(null);
        });
        socket.connect(53, '2001:4860:4860::8888', () => {
            clearTimeout(timeout);
            try {
                const addr = socket.address() as { address: string };
                socket.close();
                const buf = ipv6ToBuffer(addr.address);
                // Ensure it's a global unicast address (2000::/3)
                if ((buf[0] & 0xe0) !== 0x20) {
                    resolve(null);
                    return;
                }
                resolve(buf);
            } catch {
                socket.close();
                resolve(null);
            }
        });
    });
}
