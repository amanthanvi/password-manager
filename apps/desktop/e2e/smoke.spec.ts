import { randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import { _electron as electron } from 'playwright'
import { expect, test } from 'playwright/test'

test('smoke: create + unlock + add login + search + import/copy TOTP', async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'npw-e2e-'))
  const vaultPath = path.join(tempDir, `${randomUUID()}.npw`)
  const masterPassword = 'npw-e2e correct horse battery staple 2026!'
  const here = path.dirname(fileURLToPath(import.meta.url))

  const app = await electron.launch({
    args: ['.', '--npw-e2e', '--no-sandbox', '--disable-gpu'],
    cwd: path.resolve(here, '..'),
    env: {
      ...process.env,
      NPW_E2E: '1'
    }
  })
  const page = await app.firstWindow()

  await page.getByLabel('Vault path').fill(vaultPath)
  await page.getByLabel('Vault label').fill('E2E')
  await page.getByLabel('Master password').fill(masterPassword)

  await page.getByRole('button', { name: 'Create Vault' }).click()
  await expect(page.locator('pre.result')).toContainText('Created vault at')

  // Unlock clears the master password field on success, so re-fill before clicking.
  await page.getByLabel('Master password').fill(masterPassword)
  await page.getByRole('button', { name: 'Unlock Vault' }).click()
  await expect(page.locator('section.add-login')).toBeVisible()

  const addLogin = page.locator('section.add-login')
  await addLogin.getByLabel('Title').fill('Example Login')
  await addLogin.getByLabel('Username').fill('user@example.com')
  await addLogin.getByLabel('Password').fill('password123!')
  await addLogin.getByRole('button', { name: 'Save Login' }).click()
  await expect(page.locator('pre.result')).toContainText('Created login')

  await page.getByLabel('Search').fill('Example')
  await expect(page.locator('section.items')).toContainText('Example Login')

  // Add-login selects the created item, but keep this explicit to avoid state flakes.
  await page
    .locator('section.items')
    .getByRole('button', { name: /Example Login/ })
    .click()

  await page.getByRole('button', { name: 'Import QR / Paste' }).click()
  await expect(page.getByRole('heading', { name: 'Import TOTP' })).toBeVisible()
  await page
    .getByLabel('otpauth:// URI or base32 secret')
    .fill('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=npw&algorithm=SHA1&digits=6&period=30')
  await page.getByRole('button', { name: 'Import TOTP' }).click()
  await expect(page.getByText('Imported TOTP')).toBeVisible()

  await expect(page.locator('span.totp')).toBeVisible()
  const totpField = page.locator('section.detail .field').filter({ hasText: 'TOTP' })
  await totpField.getByRole('button', { name: 'Copy' }).click()
  await expect(page.locator('pre.result')).toContainText('Copied TOTP to clipboard')

  await app.close()
})
