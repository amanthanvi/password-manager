import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const cargoBinary = resolveCargoBinary()

const build = spawnSync(cargoBinary, ['build', '-p', 'npw-addon'], {
  cwd: rootDir,
  stdio: 'inherit',
  shell: process.platform === 'win32'
})
if (build.status !== 0) {
  process.exit(build.status ?? 1)
}

const sourceLibrary = resolveAddonLibraryPath(rootDir)
const destinationDir = path.resolve(rootDir, 'apps/desktop/native')
const destinationNode = path.join(destinationDir, 'npw-addon.node')
fs.mkdirSync(destinationDir, { recursive: true })
fs.copyFileSync(sourceLibrary, destinationNode)
console.log(`Native addon ready at ${destinationNode}`)

function resolveCargoBinary() {
  if (process.env.CARGO) {
    return process.env.CARGO
  }

  if (process.env.HOME) {
    const homeCargo = path.join(process.env.HOME, '.cargo', 'bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo')
    if (fs.existsSync(homeCargo)) {
      return homeCargo
    }
  }

  return process.platform === 'win32' ? 'cargo.exe' : 'cargo'
}

function resolveAddonLibraryPath(root) {
  const targetDir = path.join(root, 'target', 'debug')
  switch (process.platform) {
    case 'win32':
      return path.join(targetDir, 'npw_addon.dll')
    case 'darwin':
      return path.join(targetDir, 'libnpw_addon.dylib')
    default:
      return path.join(targetDir, 'libnpw_addon.so')
  }
}
