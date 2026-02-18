import fs from "fs"
import { auth } from "./sparoid.js"

const [iniFile, host, portArg] = process.argv.slice(2)

if (!iniFile || !host) {
  console.error("Usage: npx tsx src/cli.ts <ini-file> <host> [port]")
  process.exit(1)
}

const port = portArg ? parseInt(portArg, 10) : 8484

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
