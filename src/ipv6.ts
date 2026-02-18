import net from "net";
import os from "os";

export function ipv6ToBuffer(ip: string): Buffer {
    if (!net.isIPv6(ip)) {
        throw new Error('Invalid IPv6 address');
    }

    const parts = ip.split(':');
    let fullParts = [];

    // 1. Handle "::" expansion
    const doubleColonIndex = ip.indexOf('::');

    if (doubleColonIndex > -1) {
        const split = ip.split('::');
        const left = split[0] ? split[0].split(':') : [];
        const right = split[1] ? split[1].split(':') : [];

        // Calculate how many blocks of "0000" we need to fill the gap
        // Total groups must be 8
        const missing = 8 - (left.length + right.length);

        if (missing < 0) throw new Error('Invalid IPv6: Too many groups');

        // Reconstruct the full array
        fullParts = [...left, ...Array(missing).fill('0'), ...right];
    } else {
        fullParts = parts;
    }

    if (fullParts.length !== 8) {
        throw new Error('Invalid IPv6: Incorrect number of groups');
    }

    // 2. Write to buffer
    const buffer = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
        const hex = fullParts[i];

        // If a part is empty string (e.g. malformed input), this will fail cleanly
        if (hex === '') throw new Error('Invalid IPv6: Empty group');

        // Parse hex string to integer
        const val = parseInt(hex, 16);

        if (isNaN(val) || val > 0xFFFF) {
            throw new Error(`Invalid IPv6 group: ${hex}`);
        }

        buffer.writeUInt16BE(val, i * 2);
    }

    return buffer;
}

export function getGlobalIPv6() {
    const interfaces = os.networkInterfaces();
    const globalAddresses = [];

    for (const interfaceName in interfaces) {
        const networks = interfaces[interfaceName];
        if (!networks) continue;

        for (const net of networks) {
            // 1. Check if it's IPv6
            if (net.family === 'IPv6') {

                // 2. Filter out internal (Loopback like ::1)
                if (net.internal) continue;

                // 3. Filter out Link-Local addresses (start with fe80)
                // These are only valid on the local physical link
                if (net.address.toLowerCase().startsWith('fe80')) continue;

                // 4. Filter out Unique Local Addresses (start with fc or fd)
                // These are "private" addresses (similar to 192.168.x.x in IPv4)
                if (net.address.toLowerCase().startsWith('fc') ||
                    net.address.toLowerCase().startsWith('fd')) continue;

                // 5. (Optional strict check) Verify it starts with 2 or 3 (Global Unicast 2000::/3)
                const firstChar = net.address[0];
                if (firstChar === '2' || firstChar === '3') {
                    const range = net.cidr ? parseInt(net.cidr.split('/')[1]) : 128;
                    globalAddresses.push({
                        address: ipv6ToBuffer(net.address),
                        range,
                    });
                }
            }
        }
    }

    return globalAddresses;
}
