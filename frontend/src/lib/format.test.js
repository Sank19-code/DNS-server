import { describe, expect, it } from 'vitest'
import { compact, full, ms, pct, uptime } from './format.js'

describe('format', () => {
  it('compact shortens big numbers', () => {
    expect(compact(999)).toBe('999')
    expect(compact(1284)).toBe('1.3K')
    expect(compact(12_900)).toBe('13K')
    expect(compact(1_200_000)).toBe('1.2M')
    expect(compact(null)).toBe('–')
  })

  it('ms picks a precision that fits the size', () => {
    expect(ms(0.0523)).toBe('0.052 ms')
    expect(ms(1.236)).toBe('1.24 ms')
    expect(ms(18.4)).toBe('18 ms')
    expect(ms(undefined)).toBe('–')
  })

  it('pct handles zero totals', () => {
    expect(pct(0, 0)).toBe('0%')
    expect(pct(1, 3)).toBe('33%')
    expect(pct(1, 40)).toBe('2.5%')
  })

  it('uptime uses the two largest units', () => {
    expect(uptime(42)).toBe('42s')
    expect(uptime(125)).toBe('2m')
    expect(uptime(3 * 3600 + 5 * 60)).toBe('3h 5m')
    expect(uptime(2 * 86400 + 3600)).toBe('2d 1h')
  })

  it('full adds thousands separators', () => {
    expect(full(null)).toBe('–')
    expect(full(0)).toBe('0')
  })
})
