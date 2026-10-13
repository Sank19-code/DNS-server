import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// The client touches window (events), localStorage and fetch. Node has none of those, so give it
// small stand-ins: enough to check the token header and the 401 -> "ask for the token" signal.
function memoryStorage() {
  const m = new Map()
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  }
}

function reply(status, body) {
  return Promise.resolve({ ok: status < 400, status, statusText: '', json: () => Promise.resolve(body) })
}

describe('api client', () => {
  let client

  beforeEach(async () => {
    vi.stubGlobal('window', new EventTarget())
    vi.stubGlobal('localStorage', memoryStorage())
    vi.resetModules()
    client = await import('./client.js')
  })

  afterEach(() => vi.unstubAllGlobals())

  it('sends the saved token as a Bearer header', async () => {
    const fetch = vi.fn(() => reply(200, { status: 'ok' }))
    vi.stubGlobal('fetch', fetch)
    client.setToken('my-long-admin-token-123')
    await client.api.stats()
    expect(fetch).toHaveBeenCalledWith('/api/stats', expect.objectContaining({
      headers: expect.objectContaining({ Authorization: 'Bearer my-long-admin-token-123' }),
    }))
  })

  it('sends no Authorization header without a token', async () => {
    const fetch = vi.fn(() => reply(200, {}))
    vi.stubGlobal('fetch', fetch)
    await client.api.health()
    expect(fetch.mock.calls[0][1].headers.Authorization).toBeUndefined()
  })

  it('a 401 throws with the status and asks the app for the token', async () => {
    vi.stubGlobal('fetch', vi.fn(() => reply(401, { error: 'admin token required' })))
    const asked = vi.fn()
    window.addEventListener(client.AUTH_EVENT, asked)
    await expect(client.api.queries()).rejects.toMatchObject({ status: 401, message: 'admin token required' })
    expect(asked).toHaveBeenCalledTimes(1)
  })

  it('other errors do not ask for the token', async () => {
    vi.stubGlobal('fetch', vi.fn(() => reply(429, { error: 'too many lookups, slow down' })))
    const asked = vi.fn()
    window.addEventListener(client.AUTH_EVENT, asked)
    await expect(client.api.resolve('example.com')).rejects.toMatchObject({ status: 429 })
    expect(asked).not.toHaveBeenCalled()
  })

  it('encodes user input in query strings', async () => {
    const fetch = vi.fn(() => reply(200, {}))
    vi.stubGlobal('fetch', fetch)
    await client.api.check('a&b=c.com')
    expect(fetch.mock.calls[0][0]).toBe('/api/blocklist?domain=a%26b%3Dc.com')
  })
})
