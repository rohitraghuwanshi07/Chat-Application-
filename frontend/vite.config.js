import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In dev, `npm run dev` serves the app on :5173 but the WebSocket lives
// on the Python backend at :3210. This proxy forwards /ws traffic there
// so the frontend code can always just connect to its own origin --
// no backend URL hardcoded anywhere in React code.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/ws': {
        target: 'ws://localhost:3210',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
})
