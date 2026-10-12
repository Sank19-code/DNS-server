import { useEffect, useState } from 'react'

/**
 * Resolves CSS custom properties to real colors for SVG charts, and re-resolves when the
 * OS switches between light and dark mode.
 */
export function useCssVars(names) {
  const read = () => {
    const s = getComputedStyle(document.documentElement)
    return Object.fromEntries(names.map((n) => [n, s.getPropertyValue(n).trim()]))
  }
  const [vars, setVars] = useState(read)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setVars(read())
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return vars
}
