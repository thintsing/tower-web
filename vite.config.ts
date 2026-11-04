import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // 把体积大且更新不频繁的部分单独切块：主 chunk 立减，规则/数据
        // 变更时也不会让浏览器重新下载整个应用。
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (/node_modules[\\/](react|react-dom|scheduler|zustand)[\\/]/.test(id)) return 'react'
            if (id.includes('node_modules/yaml/')) return 'yaml'
            if (/node_modules[\\/](jsqr|react-simple-maps|d3-[^\\/]+|topojson-client|world-atlas)[\\/]/.test(id)) {
              return 'graphics'
            }
          }
          if (id.includes('chinaCIDRs')) return 'rules-cidrs'
          if (id.includes('/src/rules/') || id.includes('/src/parser/')) return 'rules'
        },
      },
    },
  },
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
