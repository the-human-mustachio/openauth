import { Glob } from "bun"
import { watch } from "node:fs"
import { spawn } from "node:child_process"

async function buildAll() {
  const files = new Glob("./src/**/*.{ts,tsx}").scan()
  for await (const file of files) {
    const result = await Bun.build({
      format: "esm",
      outdir: "dist/esm",
      external: ["*"],
      root: "src",
      entrypoints: [file],
    })
    if (!result.success) {
      for (const log of result.logs) console.error(log)
    }
  }
}

console.log("[build:watch] initial JS build…")
await buildAll()
console.log("[build:watch] starting tsc --watch for .d.ts…")

const tsc = spawn(
  "bunx",
  [
    "tsc",
    "--watch",
    "--preserveWatchOutput",
    "--outDir",
    "dist/types",
    "--declaration",
    "--emitDeclarationOnly",
    "--declarationMap",
  ],
  { stdio: "inherit" },
)

const stop = () => {
  tsc.kill()
  process.exit(0)
}
process.on("SIGINT", stop)
process.on("SIGTERM", stop)

let inFlight: Promise<void> | null = null
let dirty = false

function schedule() {
  if (inFlight) {
    dirty = true
    return
  }
  inFlight = (async () => {
    do {
      dirty = false
      try {
        await buildAll()
      } catch (e) {
        console.error(e)
      }
    } while (dirty)
    inFlight = null
  })()
}

console.log("[build:watch] watching src/")
watch("src", { recursive: true }, (_event, filename) => {
  if (!filename || !/\.(ts|tsx)$/.test(filename)) return
  console.log(`[build:watch] change: ${filename}`)
  schedule()
})
