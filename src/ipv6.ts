import net from "net";
import os from "os";

export function ipv6ToBuffer(ip: string): Buffer {
    if (!net.isIPv6(ip)) {
        throw new Error('Invalid IPv6 address');
    }

    // Check for embedded IPv4 tail (e.g. ::ffff:192.0.2.128)
    // The IPv4 part occupies the last 2 of the 8 groups
    const hasIPv4 = ip.includes('.');
    const targetGroups = hasIPv4 ? 7 : 8;

    const parts = ip.split(':');
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
        fullParts = parts;
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
