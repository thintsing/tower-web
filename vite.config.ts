import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // 用 IPv4 直连：Windows 上 localhost 可能先解析到 ::1，而服务端只监听 0.0.0.0。
        target: 'http://127.0.0.1:8787',
        changeOrigin: true,
      },
    },
  },
})
