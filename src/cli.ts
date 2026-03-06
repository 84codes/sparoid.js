#!/usr/bin/env node
import fs from "fs"
import { auth } from "./sparoid.js"

const [iniFile, host, portArg] = process.argv.slice(2)

if (!iniFile || !host) {
  console.error("Usage: sparoid <ini-file> <host> [port]")
  process.exit(1)
}

const port = portArg ? Number(portArg) : 8484
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error(
    `Invalid port "${portArg ?? port}". Port must be an integer between 1 and 65535.`
  )
  process.exit(1)
}

const ini = fs.readFileSync(iniFile, "utf-8")
const config: Record<string, string> = {}
for (const line of ini.split("\n")) {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue
  const idx = trimmed.indexOf("=")
  if (idx === -1) continue
  config[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim()
}

const key = config["key"]
const hmacKey = config["hmac-key"]
if (!key || !hmacKey) {
  console.error("INI file must contain 'key' and 'hmac-key'")
  process.exit(1)
}

auth(host, port, key, hmacKey).catch((err: Error) => {
  console.error(err.message)
  process.exit(1)
})
