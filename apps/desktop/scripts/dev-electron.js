import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const cwd = path.resolve(here, '..')
const pnpmCmd = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'

const DEV_PORT = Number(process.env.NPW_DEV_PORT ?? 5173)
const devServerUrl = `http://localhost:${DEV_PORT}`

const run = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: 'inherit',
      shell: process.platform === 'win32',
      env: options.env ?? process.env
    })
    child.on('error', reject)
    child.on('exit', (code) => {
      if (code === 0) {
        resolve()
        return
      }
      reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`))
    })
  })

const spawnLongRunning = (command, args, options = {}) => {
  const child = spawn(command, args, {
    cwd,
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: options.env ?? process.env
  })
  return child
}

const waitForFile = async (filePath, timeoutMs = 20_000) => {
  const startedAt = Date.now()
  while (Date.now() - startedAt < timeoutMs) {
    if (fs.existsSync(filePath)) {
      return
    }
    await delay(150)
  }
  throw new Error(`Timed out waiting for ${filePath}`)
}

const waitForHttpOk = async (url, timeoutMs = 30_000) => {
  const startedAt = Date.now()
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url, { method: 'GET' })
      if (response.ok) {
        return
      }
    } catch {
      // ignore while waiting for the dev server to come up
    }
    await delay(250)
  }
  throw new Error(`Timed out waiting for ${url}`)
}

const terminate = (child) => {
  if (!child || child.killed) {
    return
  }
  try {
    child.kill('SIGTERM')
  } catch {
    // ignore
  }
}

const main = async () => {
  await run(pnpmCmd, ['run', 'build:addon'])
  await run(pnpmCmd, ['exec', 'tsc', '-p', 'tsconfig.electron.json'])

  const vite = spawnLongRunning(pnpmCmd, ['exec', 'vite', '--port', String(DEV_PORT), '--strictPort'])
  const mainJs = path.join(cwd, 'dist-electron', 'main.js')
  await waitForFile(mainJs)
  await waitForHttpOk(devServerUrl)

  const electron = spawnLongRunning(pnpmCmd, ['exec', 'electron', '.', '--disable-gpu'], {
    env: {
      ...process.env,
      VITE_DEV_SERVER_URL: devServerUrl
    }
  })

  const cleanup = () => {
    terminate(electron)
    terminate(vite)
  }

  process.on('SIGINT', () => {
    cleanup()
    process.exit(130)
  })
  process.on('SIGTERM', () => {
    cleanup()
    process.exit(143)
  })

  electron.on('exit', (code) => {
    terminate(vite)
    process.exit(code ?? 0)
  })
  vite.on('exit', (code) => {
    terminate(electron)
    if (typeof code === 'number' && code !== 0) {
      process.exit(code)
    }
  })
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})

