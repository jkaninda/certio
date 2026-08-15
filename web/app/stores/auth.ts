import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type { LoginResponse, TokenResponse, User } from '~/types/api'

const REFRESH_KEY = 'certio_refresh_token'

/**
 * TwoFactorChallenge is what login() returns when the password was accepted
 * but a code is still owed. The token is short-lived and carries no authority
 * of its own — it can only be exchanged at /auth/2fa/verify.
 */
export interface TwoFactorChallenge {
  token: string
  expiresIn: number
}

export const useAuthStore = defineStore('auth', () => {
  // The access token lives in memory only. The server also sets it as an
  // HttpOnly cookie, so a reload recovers the session without ever putting a
  // long-lived credential where a script can read it.
  const accessToken = ref<string | null>(null)
  const user = ref<User | null>(null)
  const ready = ref(false)

  const isAuthenticated = computed(() => user.value !== null)
  const isAdmin = computed(() => user.value?.role === 'admin')
  const canWrite = computed(() => user.value?.role === 'admin' || user.value?.role === 'operator')

  function setSession(payload: TokenResponse | LoginResponse) {
    accessToken.value = payload.access_token ?? null
    user.value = payload.user ?? null
    if (import.meta.client && payload.refresh_token) {
      localStorage.setItem(REFRESH_KEY, payload.refresh_token)
    }
  }

  function clearSession() {
    accessToken.value = null
    user.value = null
    if (import.meta.client) {
      localStorage.removeItem(REFRESH_KEY)
    }
  }

  /**
   * login exchanges credentials for a session, or for a two-factor challenge
   * when the account has a second factor. A challenge is returned rather than
   * thrown: it is a step in the flow, not a failure.
   */
  async function login(email: string, password: string): Promise<TwoFactorChallenge | null> {
    const api = useApi()
    const payload = await api.post<LoginResponse>('/auth/login', { email, password })

    if (payload.two_factor_required) {
      return {
        token: payload.challenge_token ?? '',
        expiresIn: payload.challenge_expires_in ?? 0,
      }
    }
    setSession(payload)
    return null
  }

  /** verifyTwoFactor exchanges a challenge and a code for a session. */
  async function verifyTwoFactor(challengeToken: string, code: string) {
    const api = useApi()
    const payload = await api.post<LoginResponse>('/auth/2fa/verify', {
      challenge_token: challengeToken,
      code,
    })
    setSession(payload)
    return payload
  }

  async function logout() {
    const api = useApi()
    try {
      await api.post('/auth/logout')
    } catch {
      // Signing out locally matters more than the server acknowledging it.
    }
    clearSession()
    await navigateTo('/login')
  }

  /**
   * restore re-establishes the session on a page load. It tries the cookie
   * first, then the stored refresh token, and gives up quietly — an
   * unauthenticated visitor simply lands on the login page.
   */
  async function restore() {
    if (ready.value) return
    const api = useApi()

    try {
      user.value = await api.get<User>('/auth/me')
      ready.value = true
      return
    } catch {
      // No valid cookie; fall through to the refresh token.
    }

    const refreshToken = import.meta.client ? localStorage.getItem(REFRESH_KEY) : null
    if (refreshToken) {
      try {
        const payload = await api.post<TokenResponse>('/auth/refresh', { refresh_token: refreshToken })
        setSession(payload)
        ready.value = true
        return
      } catch {
        clearSession()
      }
    }

    ready.value = true
  }

  return {
    accessToken, user, ready,
    isAuthenticated, isAdmin, canWrite,
    setSession, clearSession, login, verifyTwoFactor, logout, restore,
  }
})
