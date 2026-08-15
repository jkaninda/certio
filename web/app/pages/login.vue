<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { useAuthStore } from '~/stores/auth'
import { ApiRequestError } from '~/composables/useApi'

definePageMeta({ layout: 'auth' })
useHead({ title: 'Sign in · Certio' })

const auth = useAuthStore()
const route = useRoute()

const email = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

// The second step is only reached once the password is accepted, so the two
// forms never contend for the same submit handler.
const challengeToken = ref('')
const code = ref('')
const useRecoveryCode = ref(false)
const codeInput = ref<HTMLInputElement | null>(null)

async function submitCredentials() {
  error.value = ''
  busy.value = true
  try {
    const challenge = await auth.login(email.value, password.value)
    if (challenge) {
      challengeToken.value = challenge.token
      await nextTick()
      codeInput.value?.focus()
      return
    }
    await finish()
  } catch (err) {
    error.value = describe(err, 'Sign-in failed')
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  error.value = ''
  busy.value = true
  try {
    const result = await auth.verifyTwoFactor(challengeToken.value, code.value)
    if (result.used_recovery_code) {
      // Not a toast: the layout has not mounted yet, and this is worth landing
      // on rather than fading away.
      sessionStorage.setItem(
        'certio_recovery_notice',
        String(result.recovery_codes_remaining ?? 0),
      )
    }
    await finish()
  } catch (err) {
    code.value = ''
    error.value = describe(err, 'That code was not accepted')
    // An expired challenge cannot be retried; send the user back to the start.
    if (err instanceof ApiRequestError && err.code === 'unauthorized') {
      challengeToken.value = ''
      password.value = ''
      error.value = 'That sign-in attempt expired. Please enter your password again.'
    }
  } finally {
    busy.value = false
  }
}

async function finish() {
  const redirect = route.query.redirect as string | undefined
  await navigateTo(redirect && redirect.startsWith('/') ? redirect : '/')
}

function restart() {
  challengeToken.value = ''
  code.value = ''
  error.value = ''
  useRecoveryCode.value = false
}

function describe(err: unknown, fallback: string): string {
  if (err instanceof ApiRequestError && err.status === 429) {
    return 'Too many attempts. Wait a moment before trying again.'
  }
  return err instanceof Error ? err.message : fallback
}
</script>

<template>
  <form class="login-form" @submit.prevent="challengeToken ? submitCode() : submitCredentials()">
    <template v-if="!challengeToken">
      <h1 class="login-title">Sign in</h1>
      <p class="login-subtitle">Manage your private certificate authority.</p>
    </template>
    <template v-else>
      <h1 class="login-title">Two-factor authentication</h1>
      <p class="login-subtitle">
        {{ useRecoveryCode
          ? 'Enter one of the recovery codes you saved when you set this up.'
          : `Enter the six-digit code from your authenticator app for ${email}.` }}
      </p>
    </template>

    <div v-if="error" class="app-banner app-banner--danger mb-4">
      <span class="app-banner-icon mdi mdi-alert-circle-outline" />
      <div class="app-banner-content">
        <p class="app-banner-text">{{ error }}</p>
      </div>
    </div>

    <!-- Step 1: credentials -->
    <template v-if="!challengeToken">
      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input
          id="email"
          v-model="email"
          type="email"
          class="form-input"
          autocomplete="username"
          required
          autofocus
          placeholder="admin@example.com"
        >
      </div>

      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input
          id="password"
          v-model="password"
          type="password"
          class="form-input"
          autocomplete="current-password"
          required
        >
      </div>

      <button class="btn btn-primary auth-btn" type="submit" :disabled="busy || !email || !password">
        <span v-if="busy" class="spinner" />
        {{ busy ? 'Signing in…' : 'Sign in' }}
      </button>

      <p class="login-hint">
        First run? The initial administrator is created from
        <code>CERTIO_ADMIN_EMAIL</code> and <code>CERTIO_ADMIN_PASSWORD</code>,
        or with <code>certio user create</code>.
      </p>
    </template>

    <!-- Step 2: the second factor -->
    <template v-else>
      <div class="form-group">
        <label class="form-label" for="code">
          {{ useRecoveryCode ? 'Recovery code' : 'Authentication code' }}
        </label>
        <input
          id="code"
          ref="codeInput"
          v-model="code"
          class="form-input"
          :class="{ 'code-input': !useRecoveryCode }"
          :inputmode="useRecoveryCode ? 'text' : 'numeric'"
          :autocomplete="useRecoveryCode ? 'off' : 'one-time-code'"
          :placeholder="useRecoveryCode ? 'xxxxxx-xxxxxx' : '000000'"
          :maxlength="useRecoveryCode ? 20 : 7"
          spellcheck="false"
          required
        >
      </div>

      <button class="btn btn-primary auth-btn" type="submit" :disabled="busy || !code">
        <span v-if="busy" class="spinner" />
        {{ busy ? 'Verifying…' : 'Verify' }}
      </button>

      <div class="login-links">
        <button type="button" class="link-button" @click="useRecoveryCode = !useRecoveryCode; code = ''">
          {{ useRecoveryCode ? 'Use my authenticator app' : 'Use a recovery code' }}
        </button>
        <button type="button" class="link-button" @click="restart">Back</button>
      </div>

      <p class="login-hint">
        Lost your device and your recovery codes? An administrator can reset the
        second factor for you, or run <code>certio user reset-2fa</code> on the server.
      </p>
    </template>
  </form>
</template>

<style scoped>
/* The heading sits under the wordmark the layout draws, so it is centred with
   it rather than aligned to the fields below. */
.login-title {
  font-size: 22px;
  font-weight: 600;
  letter-spacing: -0.2px;
  text-align: center;
  margin: 0 0 8px;
}
.login-subtitle {
  font-size: 14px;
  color: var(--text-muted);
  text-align: center;
  margin: 0 0 24px;
}
.login-hint {
  margin-top: 20px;
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.6;
  text-align: center;
}
.login-hint code {
  background: var(--bg-tertiary);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11px;
}

/* A one-time code is read digit by digit off a phone; the extra tracking makes
   it far easier to check against what was typed. */
.code-input {
  font-family: var(--font-mono);
  font-size: 22px;
  letter-spacing: 0.35em;
  text-align: center;
  padding-left: 0.35em;
}

.auth-btn {
  width: 100%;
  padding: 11px 18px;
  font-size: 15px;
  margin-top: 4px;
}

.login-links {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-top: 14px;
}
.link-button {
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  font-size: 12.5px;
  color: var(--primary-600);
  cursor: pointer;
}
.link-button:hover { text-decoration: underline; }
[data-theme="dark"] .link-button { color: var(--primary-400); }
</style>
