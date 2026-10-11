import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// /api calls are proxied to the Java backend so the browser sees one origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8080' },
  },
})
