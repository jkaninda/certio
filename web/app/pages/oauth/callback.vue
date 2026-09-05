<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuthStore } from '~/stores/auth'

/**
 * Where the identity provider sends the browser back.
 *
 * This page holds no logic of its own beyond the exchange: it posts the code
 * and state to the API, and either lands on the dashboard or hands a
 * two-factor challenge back to the sign-in page, which already knows how to
 * ask for a code. Duplicating that form here would be a second place for the
 * second factor to go wrong.
 */
definePageMeta({ layout: 'auth' })
useHead({ title: 'Signing in · Certio' })

const auth = useAuthStore()
const route = useRoute()

const error = ref('')

onMounted(async () => {
  const code = route.query.code as string | undefined
  const state = route.query.state as string | undefined

  // The provider reports a refusal in the URL rather than by failing the
  // redirect, so this is the only place that error is ever visible.
  const denied = route.query.error as string | undefined
  if (denied) {
    error.value = (route.query.error_description as string) || `The provider refused the sign-in (${denied}).`
    return
  }
  if (!code || !state) {
    error.value = 'That sign-in link is incomplete. Please start again.'
    return
  }

  try {
    const challenge = await auth.completeOAuth(code, state)
    if (challenge) {
      // The sign-in page picks this up and shows the code step. sessionStorage
      // rather than a query parameter: a challenge token in a URL ends up in
      // history and in whatever logs the browser's address bar feeds.
      sessionStorage.setItem('certio_oauth_challenge', challenge.token)
      await navigateTo('/login')
      return
    }
    await navigateTo(redirectTarget())
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Single sign-on failed.'
  }
})

/**
 * Where to land afterwards. The provider round-trip loses whatever page the
 * user was headed for, so it is parked before leaving and read back here.
 */
function redirectTarget(): string {
  const stored = sessionStorage.getItem('certio_oauth_redirect')
  sessionStorage.removeItem('certio_oauth_redirect')
  return stored && stored.startsWith('/') ? stored : '/'
}
</script>

<template>
  <div class="oauth-callback">
    <template v-if="error">
      <h1 class="callback-title">Sign-in failed</h1>
      <div class="app-banner app-banner--danger mb-4">
        <span class="app-banner-icon mdi mdi-alert-circle-outline" />
        <div class="app-banner-content">
          <p class="app-banner-text">{{ error }}</p>
        </div>
      </div>
      <button class="btn btn-primary auth-btn" @click="navigateTo('/login')">
        Back to sign in
      </button>
    </template>

    <template v-else>
      <span class="spinner spinner-lg" />
      <p class="callback-text">Completing sign-in…</p>
    </template>
  </div>
</template>

<style scoped>
.oauth-callback {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 16px;
}
.callback-title {
  font-size: 22px;
  font-weight: 600;
  letter-spacing: -0.2px;
  margin: 0;
}
.callback-text {
  font-size: 14px;
  color: var(--text-muted);
  margin: 0;
}
.auth-btn {
  width: 100%;
  padding: 11px 18px;
  font-size: 15px;
}
/* The banner is a block element inside a centred column. */
.oauth-callback .app-banner { width: 100%; text-align: left; }
</style>
