import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: /api calls are proxied to the Java backend so the browser sees one origin.
// Prod: `npm run build` -> dist/, which the Java server itself serves at "/" (api.staticDir).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8081' },
  },
  build: {
    // Third-party code (React + Recharts, ~150 KB gzipped) goes in its own chunk, which the
    // browser caches across deploys of the app code.
    rollupOptions: {
      output: { manualChunks: { vendor: ['react', 'react-dom', 'recharts'] } },
    },
    chunkSizeWarningLimit: 600,
  },
})
