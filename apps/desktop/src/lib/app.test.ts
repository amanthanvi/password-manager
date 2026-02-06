import { describe, expect, it } from 'vitest'
import { APP_TITLE, formatStatus } from './app'

describe('app helpers', () => {
  it('formats status using app title prefix', () => {
    expect(formatStatus('ready')).toBe(`${APP_TITLE}: ready`)
  })
})
