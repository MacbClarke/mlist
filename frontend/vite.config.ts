import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vite'
import type { Plugin } from 'vite'
import react from '@vitejs/plugin-react'

function spaFallbackForPathRoutes(): Plugin {
  return {
    name: "spa-fallback-for-path-routes",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const method = req.method ?? "GET"
        if (method !== "GET" && method !== "HEAD") {
          next()
          return
        }

        const url = req.url ?? "/"
        const isApiRequest = url === "/api" || url.startsWith("/api/")
        const isDirectFileRequest = url === "/d" || url.startsWith("/d/")
        if (
          isApiRequest ||
          isDirectFileRequest ||
          url.startsWith("/@") ||
          url.startsWith("/src/") ||
          url.startsWith("/node_modules/") ||
          url.startsWith("/assets/")
        ) {
          next()
          return
        }

        req.url = "/"
        next()
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: [['babel-plugin-react-compiler']],
      },
    }),
    tailwindcss(),
    spaFallbackForPathRoutes(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '^/api(?:/|$)': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      '^/d(?:/|$)': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
    },
  },
})
