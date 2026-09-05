<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '~/composables/useToast'
import { ApiRequestError } from '~/composables/useApi'
import type { OAuthProvider, Role } from '~/types/api'

useHead({ title: 'Single sign-on · Certio' })

const api = useApi()
const toast = useToast()

const provider = ref<OAuthProvider | null>(null)
const loading = ref(true)
const busy = ref(false)
const removing = ref(false)
const copied = ref(false)

const form = reactive({
  name: '',
  display_name: '',
  client_id: '',
  client_secret: '',
  auth_url: '',
  token_url: '',
  user_info_url: '',
  scopes: 'openid email profile',
  subject_field: 'sub',
  email_field: 'email',
  name_field: 'name',
  allowed_domains: '',
  allow_signup: true,
  allow_unverified_email: false,
  default_role: 'viewer' as Role,
  enabled: true,
})

/**
 * The endpoints of the providers people actually deploy. Picking one fills the
 * three URLs and the field names, which is where every mis-set-up SSO starts —
 * `{issuer}` is the only thing left to replace.
 */
const presets: Record<string, Partial<typeof form> & { hint?: string }> = {
  'OpenID Connect': {
    auth_url: 'https://idp.example.com/authorize',
    token_url: 'https://idp.example.com/oauth/token',
    user_info_url: 'https://idp.example.com/userinfo',
    scopes: 'openid email profile',
    subject_field: 'sub',
    email_field: 'email',
    name_field: 'name',
    hint: 'Any standards-compliant provider. Its discovery document (/.well-known/openid-configuration) names all three URLs.',
  },
  Keycloak: {
    name: 'keycloak',
    display_name: 'Keycloak',
    auth_url: 'https://keycloak.example.com/realms/REALM/protocol/openid-connect/auth',
    token_url: 'https://keycloak.example.com/realms/REALM/protocol/openid-connect/token',
    user_info_url: 'https://keycloak.example.com/realms/REALM/protocol/openid-connect/userinfo',
    scopes: 'openid email profile',
    subject_field: 'sub',
    email_field: 'email',
    name_field: 'name',
    hint: 'Replace REALM with your realm name.',
  },
  Google: {
    name: 'google',
    display_name: 'Google',
    auth_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token',
    user_info_url: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: 'openid email profile',
    subject_field: 'sub',
    email_field: 'email',
    name_field: 'name',
    hint: 'Set an allowed domain below — otherwise any Google account can sign in.',
  },
  GitHub: {
    name: 'github',
    display_name: 'GitHub',
    auth_url: 'https://github.com/login/oauth/authorize',
    token_url: 'https://github.com/login/oauth/access_token',
    user_info_url: 'https://api.github.com/user',
    scopes: 'read:user user:email',
    subject_field: 'id',
    email_field: 'email',
    name_field: 'name',
    hint: 'GitHub returns an email only when the account has a public one; otherwise sign-in is refused.',
  },
  Gitea: {
    name: 'gitea',
    display_name: 'Gitea',
    auth_url: 'https://gitea.example.com/login/oauth/authorize',
    token_url: 'https://gitea.example.com/login/oauth/access_token',
    user_info_url: 'https://gitea.example.com/login/oauth/userinfo',
    scopes: 'openid email profile',
    subject_field: 'sub',
    email_field: 'email',
    name_field: 'name',
  },
}

const presetNames = Object.keys(presets)
const activePreset = ref('')
const presetHint = computed(() => (activePreset.value ? presets[activePreset.value]?.hint : ''))

function applyPreset(preset: string) {
  activePreset.value = preset
  const { hint: _hint, ...values } = presets[preset] ?? {}
  Object.assign(form, values)
}

onMounted(load)

async function load() {
  loading.value = true
  try {
    provider.value = await api.get<OAuthProvider>('/oauth-provider')
    Object.assign(form, {
      name: provider.value.name,
      display_name: provider.value.display_name ?? '',
      client_id: provider.value.client_id,
      // Never prefilled: the API does not return it, and a placeholder that
      // looked like a secret would be sent back as one.
      client_secret: '',
      auth_url: provider.value.auth_url,
      token_url: provider.value.token_url,
      user_info_url: provider.value.user_info_url,
      scopes: provider.value.scopes.join(' '),
      subject_field: provider.value.subject_field,
      email_field: provider.value.email_field,
      name_field: provider.value.name_field,
      allowed_domains: provider.value.allowed_domains.join(', '),
      allow_signup: provider.value.allow_signup,
      allow_unverified_email: provider.value.allow_unverified_email,
      default_role: provider.value.default_role,
      enabled: provider.value.enabled,
    })
  } catch (err) {
    // A 404 is the normal state of an instance that has not federated, not a
    // failure worth a toast.
    if (!(err instanceof ApiRequestError && err.status === 404)) {
      toast.error(err instanceof Error ? err.message : 'could not load the single sign-on configuration')
    }
    provider.value = null
  } finally {
    loading.value = false
  }
}

/** The redirect URI is derived from the base URL; before a first save there is
 *  no server value to show, so it is built the same way here. */
const redirectURI = computed(() =>
  provider.value?.redirect_uri ?? `${window.location.origin}/oauth/callback`,
)

async function copyRedirect() {
  try {
    await navigator.clipboard.writeText(redirectURI.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1600)
  } catch {
    toast.error('could not copy to the clipboard')
  }
}

const canSave = computed(() =>
  Boolean(
    form.name && form.client_id && form.auth_url && form.token_url && form.user_info_url
    // A secret is required the first time and optional thereafter.
    && (form.client_secret || provider.value?.client_secret_set),
  ),
)

function splitList(raw: string): string[] {
  return raw.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean)
}

async function save() {
  busy.value = true
  try {
    provider.value = await api.put<OAuthProvider>('/oauth-provider', {
      name: form.name,
      display_name: form.display_name,
      client_id: form.client_id,
      client_secret: form.client_secret,
      auth_url: form.auth_url,
      token_url: form.token_url,
      user_info_url: form.user_info_url,
      scopes: splitList(form.scopes),
      subject_field: form.subject_field,
      email_field: form.email_field,
      name_field: form.name_field,
      allowed_domains: splitList(form.allowed_domains),
      allow_signup: form.allow_signup,
      allow_unverified_email: form.allow_unverified_email,
      default_role: form.default_role,
      enabled: form.enabled,
    })
    form.client_secret = ''
    toast.success('Single sign-on saved')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not save the configuration')
  } finally {
    busy.value = false
  }
}

async function remove() {
  busy.value = true
  try {
    await api.del('/oauth-provider')
    removing.value = false
    toast.success('Single sign-on removed')
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not remove the configuration')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Single sign-on</h1>
        <p class="page-subtitle">
          Delegate sign-in to your identity provider. One provider per instance — the client
          secret is encrypted at rest with the master key.
        </p>
      </div>
      <div v-if="provider" class="page-header-actions">
        <button class="btn btn-ghost" @click="removing = true">
          <span class="mdi mdi-link-variant-off" />
          Remove
        </button>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else>
      <div v-if="provider" class="app-banner mb-6" :class="provider.enabled ? 'app-banner--success' : 'app-banner--warning'">
        <span class="app-banner-icon mdi" :class="provider.enabled ? 'mdi-check-circle-outline' : 'mdi-pause-circle-outline'" />
        <div class="app-banner-content">
          <p class="app-banner-text">
            {{ provider.enabled
              ? `Sign-in through ${provider.display_name || provider.name} is live on the login page.`
              : 'Configured but switched off. The login page shows no single sign-on button.' }}
          </p>
        </div>
      </div>

      <!-- The redirect URI first: it is the one value that has to be copied
           into the provider, and getting it wrong is the usual failure. -->
      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Redirect URI</h2>
            <span class="card-subtitle">Register this at your provider before saving</span>
          </div>
        </div>
        <div class="card-body">
          <div class="redirect-row">
            <code class="redirect-uri">{{ redirectURI }}</code>
            <button class="btn btn-secondary btn-sm" @click="copyRedirect">
              <span class="mdi" :class="copied ? 'mdi-check' : 'mdi-content-copy'" />
              {{ copied ? 'Copied' : 'Copy' }}
            </button>
          </div>
          <p class="form-hint">
            Derived from the instance base URL, so the two cannot disagree. If this is not the
            address people reach Certio at, set <code>CERTIO_BASE_URL</code> first.
          </p>
        </div>
      </div>

      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Provider</h2>
            <span class="card-subtitle">Start from a preset, then fill in your own host</span>
          </div>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Preset</label>
            <div class="preset-choice">
              <button
                v-for="preset in presetNames"
                :key="preset"
                type="button"
                class="preset-option"
                :class="{ selected: activePreset === preset }"
                @click="applyPreset(preset)"
              >
                {{ preset }}
              </button>
            </div>
            <p v-if="presetHint" class="form-hint">{{ presetHint }}</p>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Name <span class="required">*</span></label>
              <input v-model="form.name" class="form-input" placeholder="keycloak" autocomplete="off">
              <p class="form-hint">Identifies the provider in the audit log. Lowercase, no spaces.</p>
            </div>
            <div class="form-group">
              <label class="form-label">Button label</label>
              <input v-model="form.display_name" class="form-input" placeholder="Company SSO">
              <p class="form-hint">What the sign-in page writes on the button.</p>
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Client ID <span class="required">*</span></label>
              <input v-model="form.client_id" class="form-input" autocomplete="off">
            </div>
            <div class="form-group">
              <label class="form-label">
                Client secret
                <span v-if="!provider?.client_secret_set" class="required">*</span>
              </label>
              <input
                v-model="form.client_secret"
                type="password"
                class="form-input"
                autocomplete="new-password"
                :placeholder="provider?.client_secret_set ? '••••••••  (unchanged)' : ''"
              >
              <p v-if="provider?.client_secret_set" class="form-hint">
                A secret is stored. Leave this blank to keep it.
              </p>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Authorization URL <span class="required">*</span></label>
            <input v-model="form.auth_url" class="form-input mono" autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Token URL <span class="required">*</span></label>
            <input v-model="form.token_url" class="form-input mono" autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Userinfo URL <span class="required">*</span></label>
            <input v-model="form.user_info_url" class="form-input mono" autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Scopes</label>
            <input v-model="form.scopes" class="form-input mono" placeholder="openid email profile">
            <p class="form-hint">Space- or comma-separated.</p>
          </div>
        </div>
      </div>

      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Who may sign in</h2>
            <span class="card-subtitle">What the provider proving an identity is allowed to grant</span>
          </div>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Allowed email domains</label>
            <input v-model="form.allowed_domains" class="form-input" placeholder="example.com, jkaninda.dev">
            <p class="form-hint">
              Empty allows any address the provider vouches for — right for a private IdP,
              and wrong for a public one, where it means anyone with an account there.
            </p>
          </div>

          <div class="form-group">
            <label class="checkbox-label">
              <input v-model="form.allow_signup" type="checkbox">
              Create an account the first time someone signs in
            </label>
            <p class="form-hint">
              With this off, an administrator has to add the account first and the provider
              only proves who they are.
            </p>
          </div>

          <div class="form-group" :class="{ 'is-disabled': !form.allow_signup }">
            <label class="form-label">Role for new accounts</label>
            <select v-model="form.default_role" class="form-select" :disabled="!form.allow_signup">
              <option value="viewer">Viewer — read-only</option>
              <option value="operator">Operator — may issue and revoke</option>
              <option value="admin">Admin — full control</option>
            </select>
            <p class="form-hint">
              Viewer is the default on purpose: an identity provider says who somebody is,
              not what they may sign.
            </p>
          </div>

          <div class="form-group">
            <label class="checkbox-label">
              <input v-model="form.allow_unverified_email" type="checkbox">
              Accept addresses the provider has not verified
            </label>
            <p class="form-hint">
              Leave this off for a public provider: an unverified address is a claim, and
              accepting one lets anybody who types it at the provider take over the matching
              account. Turn it on for a directory that simply never sends
              <code>email_verified</code>.
            </p>
          </div>

          <div class="form-group">
            <label class="checkbox-label">
              <input v-model="form.enabled" type="checkbox">
              Enabled
            </label>
            <p class="form-hint">
              Turning this off hides the button without discarding the configuration.
            </p>
          </div>
        </div>
      </div>

      <details class="card mb-6 mapping">
        <summary>
          <span class="mdi mdi-code-json" />
          Userinfo field mapping
          <span class="text-muted text-sm">— only needed for a provider that does not speak OIDC</span>
        </summary>
        <div class="card-body">
          <p class="form-hint mb-4">
            Where to read each value out of the provider's userinfo document. A dotted path
            descends into nested objects, e.g. <code>data.email</code>.
          </p>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Subject field</label>
              <input v-model="form.subject_field" class="form-input mono" placeholder="sub">
              <p class="form-hint">The provider's permanent ID for the person.</p>
            </div>
            <div class="form-group">
              <label class="form-label">Email field</label>
              <input v-model="form.email_field" class="form-input mono" placeholder="email">
            </div>
            <div class="form-group">
              <label class="form-label">Name field</label>
              <input v-model="form.name_field" class="form-input mono" placeholder="name">
            </div>
          </div>
        </div>
      </details>

      <div class="flex justify-end">
        <button class="btn btn-primary" :disabled="busy || !canSave" @click="save">
          <span v-if="busy" class="spinner" />
          {{ provider ? 'Save changes' : 'Enable single sign-on' }}
        </button>
      </div>
    </template>

    <UiConfirmDialog
      v-if="removing"
      title="Remove single sign-on?"
      message="The button disappears from the login page and the client secret is deleted.
               Accounts the provider created are kept — they own certificates — but anyone
               without a password will have no way in until you set a provider up again."
      confirm-label="Remove"
      danger
      :busy="busy"
      @cancel="removing = false"
      @confirm="remove"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 900px; }

.redirect-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.redirect-uri {
  flex: 1;
  min-width: 0;
  overflow-x: auto;
  white-space: nowrap;
  padding: 9px 12px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-tertiary);
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-primary);
}

.preset-choice { display: flex; gap: 8px; flex-wrap: wrap; }
.preset-option {
  padding: 8px 14px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-primary);
  cursor: pointer;
  font-family: inherit;
  font-size: 13.5px;
  color: var(--text-secondary);
  transition: all var(--transition);
}
.preset-option:hover { border-color: var(--primary-400); }
.preset-option.selected {
  border-color: var(--primary-600);
  background: var(--primary-50);
  color: var(--primary-700);
  font-weight: 500;
}
[data-theme="dark"] .preset-option.selected { color: var(--primary-300); }

.mono { font-family: var(--font-mono); font-size: 13px; }

.is-disabled { opacity: 0.55; }

.mapping > summary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px 20px;
  cursor: pointer;
  font-weight: 600;
  color: var(--text-primary);
  user-select: none;
}
.mapping > summary::-webkit-details-marker { display: none; }
.mapping[open] > summary { border-bottom: 1px solid var(--border-primary); }
</style>
