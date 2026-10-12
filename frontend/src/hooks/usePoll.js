import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Calls `fn` now and every `ms` milliseconds; pauses while the tab is hidden.
 * Returns { data, error, refresh }. Keeps the last good data when a poll fails.
 */
export function usePoll(fn, ms, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const fnRef = useRef(fn)
  fnRef.current = fn

  const refresh = useCallback(async () => {
    try {
      setData(await fnRef.current())
      setError(null)
    } catch (e) {
      setError(e)
    }
  }, [])

  useEffect(() => {
    let timer
    const tick = async () => {
      if (!document.hidden) await refresh()
      timer = setTimeout(tick, ms)
    }
    tick()
    const onVisible = () => { if (!document.hidden) refresh() }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, refresh, ...deps])

  return { data, error, refresh }
}
