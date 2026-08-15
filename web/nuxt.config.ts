import { defineNuxtConfig } from 'nuxt/config'

// Certio embeds this dashboard in the Go binary, so it is built as a fully
// static SPA: no Nitro server, no Node runtime in production. `nuxt generate`
// writes to .output/public, which cmd/certio embeds with //go:embed.
export default defineNuxtConfig({
  compatibilityDate: '2025-01-01',

  ssr: false,

  devtools: { enabled: false },

  modules: ['@pinia/nuxt'],

  css: [
    '@mdi/font/css/materialdesignicons.css',
    '~/assets/css/tokens.css',
    '~/assets/css/base.css',
    '~/assets/css/components.css',
  ],

  app: {
    // Client-side routing owns every path; the Go server's WebFS falls back to
    // index.html for anything that is not an API route or a real asset.
    baseURL: '/',
    head: {
      title: 'Certio',
      htmlAttrs: { lang: 'en' },
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'robots', content: 'noindex,nofollow' },
        { name: 'theme-color', content: '#9333ea' },
        {
          name: 'description',
          content: 'Certio — self-signed PKI and TLS certificate management.',
        },
      ],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
      script: [
        {
          // Apply the stored theme before the first paint. Without this the
          // page flashes light before Vue hydrates and sets data-theme.
          innerHTML: `(function(){try{var m=localStorage.getItem('certio_theme')||'system';
var d=m==='dark'||(m==='system'&&window.matchMedia('(prefers-color-scheme: dark)').matches);
document.documentElement.setAttribute('data-theme',d?'dark':'light');}catch(e){}})();`,
          type: 'text/javascript',
          tagPosition: 'head',
        },
      ],
    },
  },

  nitro: {
    preset: 'static',
  },

  experimental: {
    payloadExtraction: false,
  },

  runtimeConfig: {
    public: {
      // Same-origin by default: the Go binary serves both the API and this app.
      apiBase: '/api/v1',
    },
  },

  vite: {
    server: {
      proxy: {
        // In development the dashboard runs on 3000 and the Go server on 8080.
        '/api': { target: 'http://localhost:8080', changeOrigin: true },
        '/ca': { target: 'http://localhost:8080', changeOrigin: true },
        '/health': { target: 'http://localhost:8080', changeOrigin: true },
      },
    },
    build: {
      // CodeMirror is only needed on the PEM viewer and inspect pages; keeping
      // it out of the entry chunk keeps the login screen small.
      rollupOptions: {
        output: {
          manualChunks(id: string) {
            if (id.includes('node_modules/@codemirror') || id.includes('node_modules/codemirror')) {
              return 'codemirror'
            }
          },
        },
      },
    },
  },
})
