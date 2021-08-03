'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var dgram = require('dgram');
var crypto = require('crypto');
var buffer = require('buffer');
var process = require('process');
var dns = require('dns');
var net = require('net');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var dgram__default = /*#__PURE__*/_interopDefaultLegacy(dgram);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var process__default = /*#__PURE__*/_interopDefaultLegacy(process);
var dns__default = /*#__PURE__*/_interopDefaultLegacy(dns);
var net__default = /*#__PURE__*/_interopDefaultLegacy(net);

async function auth(host, port, key, hmac_key, public_ip) {
    key = buffer.Buffer.from(key || process__default['default'].env.SPAROID_KEY, 'hex');
    hmac_key = buffer.Buffer.from(hmac_key || process__default['default'].env.SPAROID_HMAC_KEY, 'hex');
    public_ip = public_ip || await publicIp();
    const msg = await plainMsg(public_ip);
    const encrypted = encrypt(msg, key);
    const hmaced = prefixHmac(encrypted, hmac_key);
    udpSend(hmaced, host, port);
    await sleep(200); // let the server process the packet
}

function sleep(s) {
    return new Promise((resolv) => setTimeout(resolv, s))
}

function encrypt(msg, key) {
    const buf = buffer.Buffer.alloc(64);
    const iv = crypto__default['default'].randomBytes(16);
    const cipher = crypto__default['default'].createCipheriv("aes-256-cbc", key, iv);
    const u = cipher.update(msg);
    const f = cipher.final();
    iv.copy(buf);
    u.copy(buf, 16);
    f.copy(buf, 48);
    return buf
}

function prefixHmac(encrypted, hmac_key) {
    const hmac = crypto__default['default'].createHmac('sha256', hmac_key);
    hmac.update(encrypted);
    const buf = buffer.Buffer.alloc(96);
    const digest = hmac.digest();
    digest.copy(buf);
    encrypted.copy(buf, 32);
    return buf
}

function plainMsg(ip) {
    const version = 1;
    const ts = new Date().getTime();
    const nounce = crypto__default['default'].randomBytes(16);

    const msg = buffer.Buffer.alloc(4 + 8 + 16 + 4);
    msg.writeInt32BE(version, 0);
    msg.writeBigInt64BE(BigInt(ts), 4);
    nounce.copy(msg, 12);
    ip.copy(msg, 28);
    return msg
}

function publicIp() {
    return new Promise((resolv, reject) => {
        const resolver = new dns__default['default'].Resolver();
        resolver.setServers(["208.67.222.222", "208.67.220.220"]);
        resolver.resolve4('myip.opendns.com', (err, addresses) => {
            if (err) return reject(err)

            const buf = buffer.Buffer.alloc(4);
            addresses[0].split(".").forEach((part, idx) => buf.writeUint8(part, idx));
            resolv(buf);
        });
    })
}

function resolvHost(host) {
    return new Promise((resolv, reject) => {
        if (net__default['default'].isIPv4(host)) resolv([host]);
        const resolver = new dns__default['default'].Resolver();
        resolver.resolve4(host, (err, addresses) => {
            if (err) return reject(err)

            resolv(addresses);
        });
    })
}

async function udpSend(message, host, port) {
    const ips = await resolvHost(host);
    const client = dgram__default['default'].createSocket('udp4');
    await Promise.all(ips.map((ip) => {
        return new Promise((resolv, reject) => {
            client.send(message, port, ip, (err) => {
                if (err) return reject(err)
                resolv();
            });
        })
    }));
    client.close();
}

exports.auth = auth;
exports.publicIp = publicIp;
