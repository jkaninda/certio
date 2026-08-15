<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import { useAuthStore } from '~/stores/auth'
import type { RecoveryCodes, TwoFactorSetup, TwoFactorStatus, User } from '~/types/api'

useHead({ title: 'Security · Certio' })

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { dateTime } = useFormat()

const status = ref<TwoFactorStatus | null>(null)
const loading = ref(true)
const busy = ref(false)

// The enrolment wizard: null until "Set up" is pressed, then two steps —
// scan the code, then prove the app holds it.
const setup = ref<TwoFactorSetup | null>(null)
const enrolCode = ref('')
const showSecret = ref(false)
const enrolInput = ref<HTMLInputElement | null>(null)

// Recovery codes are shown exactly once, in a dialog the user has to dismiss.
const issuedCodes = ref<string[]>([])
const codesWarning = ref('')

const disableOpen = ref(false)
const regenerateOpen = ref(false)
const disableForm = reactive({ password: '', code: '' })
const regenerateCode = ref('')

const lowOnRecoveryCodes = computed(
  () => !!status.value?.enabled && status.value.recovery_codes_remaining <= 2,
)

async function load() {
  try {
    status.value = await api.get<TwoFactorStatus>('/auth/2fa')
  } catch (err) {
    toast.error(message(err, 'could not load your security settings'))
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function startEnrolment() {
  busy.value = true
  try {
    setup.value = await api.post<TwoFactorSetup>('/auth/2fa/setup')
    enrolCode.value = ''
    showSecret.value = false
    await nextTick()
    enrolInput.value?.focus()
  } catch (err) {
    toast.error(message(err, 'could not start the enrolment'))
  } finally {
    busy.value = false
  }
}

async function confirmEnrolment() {
  busy.value = true
  try {
    const result = await api.post<RecoveryCodes>('/auth/2fa/enable', { code: enrolCode.value })
    reveal(result)
    setup.value = null
    enrolCode.value = ''
    await load()
    await refreshSession()
    toast.success('Two-factor authentication is on')
  } catch (err) {
    enrolCode.value = ''
    toast.error(message(err, 'that code was not accepted'))
  } finally {
    busy.value = false
  }
}

async function disable() {
  busy.value = true
  try {
    await api.post('/auth/2fa/disable', { password: disableForm.password, code: disableForm.code })
    disableOpen.value = false
    disableForm.password = ''
    disableForm.code = ''
    await load()
    await refreshSession()
    toast.success('Two-factor authentication is off')
  } catch (err) {
    toast.error(message(err, 'could not disable two-factor authentication'))
  } finally {
    busy.value = false
  }
}

async function regenerate() {
  busy.value = true
  try {
    const result = await api.post<RecoveryCodes>('/auth/2fa/recovery-codes', { code: regenerateCode.value })
    reveal(result)
    regenerateOpen.value = false
    regenerateCode.value = ''
    await load()
  } catch (err) {
    toast.error(message(err, 'could not issue new recovery codes'))
  } finally {
    busy.value = false
  }
}

function reveal(result: RecoveryCodes) {
  issuedCodes.value = result.recovery_codes
  codesWarning.value = result.warning
}

/** downloadCodes saves the codes as a text file, since that is what people
 *  actually do with them. */
function downloadCodes() {
  const body = [
    'Certio recovery codes',
    `Account: ${auth.user?.email ?? ''}`,
    `Issued:  ${new Date().toISOString()}`,
    '',
    'Each code works exactly once. Keep them somewhere other than the device',
    'holding your authenticator app.',
    '',
    ...issuedCodes.value,
    '',
  ].join('\n')

  const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'certio-recovery-codes.txt'
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** refreshSession re-reads the account so the 2FA badge elsewhere in the UI
 *  matches what just changed. */
async function refreshSession() {
  try {
    auth.user = await api.get<User>('/auth/me')
  } catch {
    // The page already reflects the change; a stale badge is not worth an error.
  }
}

function message(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Security</h1>
        <p class="page-subtitle">Two-factor authentication for your own account.</p>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else>
      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Authenticator app</h2>
            <span class="card-subtitle">A time-based one-time code, on top of your password</span>
          </div>
          <span class="badge badge-dot" :class="status?.enabled ? 'badge-success' : 'badge-neutral'">
            {{ status?.enabled ? 'enabled' : 'disabled' }}
          </span>
        </div>

        <div class="card-body">
          <!-- Enabled -->
          <template v-if="status?.enabled">
            <div class="detail-grid">
              <span class="detail-label">Enabled</span>
              <span class="detail-value">{{ status.enabled_at ? dateTime(status.enabled_at) : '—' }}</span>

              <span class="detail-label">Recovery codes</span>
              <span class="detail-value">
                <span class="badge" :class="lowOnRecoveryCodes ? 'badge-warning' : 'badge-neutral'">
                  {{ status.recovery_codes_remaining }} left
                </span>
                <p v-if="lowOnRecoveryCodes" class="form-hint">
                  You are nearly out. Issue a new set before you need one.
                </p>
              </span>
            </div>

            <div class="action-row">
              <button class="btn btn-secondary" @click="regenerateOpen = true">
                <span class="mdi mdi-refresh" />
                New recovery codes
              </button>
              <button class="btn btn-secondary" @click="disableOpen = true">
                <span class="mdi mdi-shield-off-outline" />
                Turn off
              </button>
            </div>
          </template>

          <!-- Enrolment wizard -->
          <template v-else-if="setup">
            <p class="step-label">Step 1 — scan this with your authenticator app</p>
            <div class="enrol">
              <img class="qr" :src="setup.qr_code" :alt="`QR code enrolling ${setup.account}`" width="200" height="200">
              <div class="enrol-side">
                <p class="form-hint">
                  Google Authenticator, 1Password, Aegis, Bitwarden — anything that speaks TOTP.
                  It will appear as <strong>{{ setup.issuer }}</strong>.
                </p>
                <button type="button" class="link-button" @click="showSecret = !showSecret">
                  {{ showSecret ? 'Hide the setup key' : 'Cannot scan? Enter a key instead' }}
                </button>
                <div v-if="showSecret" class="secret-box">
                  <code class="secret-value">{{ setup.secret }}</code>
                  <UiCopyButton :value="setup.secret.replace(/ /g, '')" label="Copy key" />
                </div>
              </div>
            </div>

            <p class="step-label mt-4">Step 2 — enter the code it shows</p>
            <form class="enrol-confirm" @submit.prevent="confirmEnrolment">
              <input
                ref="enrolInput"
                v-model="enrolCode"
                class="form-input code-input"
                inputmode="numeric"
                autocomplete="one-time-code"
                placeholder="000000"
                maxlength="7"
                spellcheck="false"
              >
              <button class="btn btn-primary" type="submit" :disabled="busy || !enrolCode">
                <span v-if="busy" class="spinner" />
                Turn on
              </button>
              <button class="btn btn-secondary" type="button" :disabled="busy" @click="setup = null">
                Cancel
              </button>
            </form>
          </template>

          <!-- Not enrolled -->
          <template v-else>
            <p class="prose">
              With two-factor authentication on, signing in needs your password
              <em>and</em> a code from your phone. A stolen password is not enough on its own.
            </p>
            <div class="app-banner app-banner--info mt-4 mb-4">
              <span class="app-banner-icon mdi mdi-information-outline" />
              <div class="app-banner-content">
                <p class="app-banner-text">
                  API tokens are not covered by this. They are separate credentials with their own
                  lifecycle — revoke them from
                  <NuxtLink to="/settings/tokens">API tokens</NuxtLink> if one is compromised.
                </p>
              </div>
            </div>
            <button class="btn btn-primary" :disabled="busy" @click="startEnrolment">
              <span v-if="busy" class="spinner" />
              <span v-else class="mdi mdi-shield-key-outline" />
              Set up two-factor authentication
            </button>
          </template>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h2>If you lose your device</h2></div>
        <div class="card-body">
          <p class="prose">
            Sign in with one of your recovery codes — each works once. If those are gone too, an
            administrator can reset the second factor for your account, or run
            <code>certio user reset-2fa &lt;email&gt;</code> on the server. Both are recorded in the
            audit log.
          </p>
        </div>
      </div>
    </template>

    <!-- Recovery codes, shown exactly once -->
    <UiBaseModal v-if="issuedCodes.length" title="Save your recovery codes" @close="issuedCodes = []">
      <div class="app-banner app-banner--warning mb-4">
        <span class="app-banner-icon mdi mdi-alert-outline" />
        <div class="app-banner-content">
          <p class="app-banner-text">{{ codesWarning }}</p>
        </div>
      </div>

      <ul class="codes">
        <li v-for="c in issuedCodes" :key="c" class="code">{{ c }}</li>
      </ul>

      <template #footer>
        <UiCopyButton :value="issuedCodes.join('\n')" label="Copy all" />
        <button class="btn btn-secondary" @click="downloadCodes">
          <span class="mdi mdi-download-outline" />
          Download
        </button>
        <button class="btn btn-primary" @click="issuedCodes = []">I have saved them</button>
      </template>
    </UiBaseModal>

    <!-- Turn off -->
    <UiBaseModal v-if="disableOpen" title="Turn off two-factor authentication" :busy="busy" @close="disableOpen = false">
      <p class="prose mb-4">
        Your password alone will be enough to sign in again. Your recovery codes are destroyed.
      </p>
      <div class="form-group">
        <label class="form-label">Password <span class="required">*</span></label>
        <input v-model="disableForm.password" type="password" class="form-input" autocomplete="current-password">
      </div>
      <div class="form-group">
        <label class="form-label">Current code <span class="required">*</span></label>
        <input
          v-model="disableForm.code"
          class="form-input"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="000000"
        >
        <p class="form-hint">A code from your authenticator app, or an unused recovery code.</p>
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="disableOpen = false">Cancel</button>
        <button
          class="btn btn-danger"
          :disabled="busy || !disableForm.password || !disableForm.code"
          @click="disable"
        >
          <span v-if="busy" class="spinner" />
          Turn off
        </button>
      </template>
    </UiBaseModal>

    <!-- New recovery codes -->
    <UiBaseModal v-if="regenerateOpen" title="Issue new recovery codes" :busy="busy" @close="regenerateOpen = false">
      <p class="prose mb-4">
        Every code you were given before will stop working. Confirm with a current code.
      </p>
      <div class="form-group">
        <label class="form-label">Current code <span class="required">*</span></label>
        <input
          v-model="regenerateCode"
          class="form-input"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="000000"
        >
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="regenerateOpen = false">Cancel</button>
        <button class="btn btn-primary" :disabled="busy || !regenerateCode" @click="regenerate">
          <span v-if="busy" class="spinner" />
          Issue new codes
        </button>
      </template>
    </UiBaseModal>
  </div>
</template>

<style scoped>
.settings-page { max-width: 860px; }
.prose { font-size: 13.5px; color: var(--text-secondary); line-height: 1.65; }
.prose code {
  background: var(--bg-tertiary);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 12px;
}

.action-row { display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }

.step-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
  margin-bottom: 10px;
}

.enrol { display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap; }
.qr {
  width: 200px;
  height: 200px;
  border-radius: var(--radius);
  /* The PNG has no quiet zone of its own and scanners need one. */
  padding: 10px;
  background: #fff;
  border: 1px solid var(--border-primary);
  flex-shrink: 0;
}
.enrol-side { flex: 1; min-width: 240px; display: flex; flex-direction: column; gap: 10px; }

.secret-box {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
}
.secret-value {
  flex: 1;
  font-family: var(--font-mono);
  font-size: 12.5px;
  word-break: break-all;
  user-select: all;
  color: var(--text-primary);
}

.enrol-confirm { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.code-input {
  max-width: 190px;
  font-family: var(--font-mono);
  font-size: 20px;
  letter-spacing: 0.3em;
  text-align: center;
  padding-left: 0.3em;
}

.codes {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  list-style: none;
  padding: 14px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
}
.code {
  font-family: var(--font-mono);
  font-size: 13px;
  letter-spacing: 0.04em;
  user-select: all;
  color: var(--text-primary);
}

.link-button {
  align-self: flex-start;
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

@media (max-width: 560px) {
  .codes { grid-template-columns: 1fr; }
}
</style>
