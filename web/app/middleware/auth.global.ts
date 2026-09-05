import { useAuthStore } from '~/stores/auth'

/**
 * Routes reachable without a session. /oauth/callback is where the identity
 * provider lands the browser back, which is by definition before there is one.
 */
const PUBLIC_ROUTES = new Set(['/login', '/oauth/callback'])

export default defineNuxtRouteMiddleware(async (to) => {
  // This is a client-rendered SPA; there is no server pass to guard.
  if (import.meta.server) return

  const auth = useAuthStore()

  // The very first navigation happens before app.vue's onMounted, so the
  // session has to be resolved here or every reload would bounce to /login.
  if (!auth.ready) {
    await auth.restore()
  }

  if (PUBLIC_ROUTES.has(to.path)) {
    // An authenticated user has no business on the login page — but the OAuth
    // callback signs them in as it runs, and bouncing it would abort the
    // exchange it is in the middle of.
    if (auth.isAuthenticated && to.path !== '/oauth/callback') return navigateTo('/')
    return
  }

  if (!auth.isAuthenticated) {
    // Remember where they were headed so the login can return them there.
    const redirect = to.fullPath !== '/' ? `?redirect=${encodeURIComponent(to.fullPath)}` : ''
    return navigateTo(`/login${redirect}`)
  }
})
