import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import type { ClientRequest } from 'node:http'

/**
 * The dev proxy may carry the operator's API token, so the dashboard keeps working
 * once the API is closed.
 *
 * D25/D30 make the API require a credential as soon as one is configured, but the
 * dashboard sends no headers of its own — which meant "turn auth on" quietly broke
 * the documented `npm run dev` workflow. This injects `HATCHERY_DASHBOARD_TOKEN`
 * into proxied API and WebSocket requests. It is a **development** convenience: the
 * token lives in the operator's environment, never in this file and never in the
 * bundle, and the proxy is a loopback dev server. A production deployment has to
 * handle its own token — the dashboard does not ship an auth flow.
 */
const token = process.env.HATCHERY_DASHBOARD_TOKEN ?? ''
const authorization = token ? `Bearer ${token}` : ''

function withAuth(proxy: any) {
  if (!authorization) return
  proxy.on('proxyReq', (request: ClientRequest) => {
    request.setHeader('authorization', authorization)
  })
  proxy.on('proxyReqWs', (request: ClientRequest) => {
    request.setHeader('authorization', authorization)
  })
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // README and the API startup banner document 5173.
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:3002',
        configure: withAuth,
      },
      '/ws': {
        target: 'ws://localhost:3002',
        ws: true,
        configure: withAuth,
      },
    },
  },
})
