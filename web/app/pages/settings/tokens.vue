<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { ApiToken, TokenScope } from '~/types/api'

useHead({ title: 'API tokens · Certio' })

const api = useApi()
const toast = useToast()
const { date, relative } = useFormat()

const items = ref<ApiToken[]>([])
const loading = ref(true)
const busy = ref(false)

const createOpen = ref(false)
const revoking = ref<ApiToken | null>(null)
const issued = ref<{ token: ApiToken; plaintext: string } | null>(null)

const form = reactive({ name: '', expires_in: '', scopes: [] as string[] })

/** The scope catalog comes from the backend that enforces it, so the two
 *  cannot drift apart. */
const scopes = ref<TokenScope[]>([])
const fullAccess = computed(() => form.scopes.includes('*'))

function toggleScope(name: string) {
  if (name === '*') {
    form.scopes = fullAccess.value ? [] : ['*']
    return
  }
  const rest = form.scopes.filter((s) => s !== '*')
  form.scopes = rest.includes(name) ? rest.filter((s) => s !== name) : [...rest, name]
}

/** A write scope covers its read counterpart, so showing the read box ticked
 *  matches what the server will actually allow. */
function scopeChecked(name: string) {
  if (fullAccess.value) return true
  if (form.scopes.includes(name)) return true
  const [resource, action] = name.split(':')
  return action === 'read' && form.scopes.includes(`${resource}:write`)
}

const expiryOptions = [
  { value: '', label: 'Never expires' },
  { value: '720h', label: '30 days' },
  { value: '2160h', label: '90 days' },
  { value: '8760h', label: '1 year' },
]

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: ApiToken[] }>('/api-tokens')
    items.value = payload.items ?? []
    if (!scopes.value.length) {
      const meta = await api.get<{ token_scopes: TokenScope[] }>('/meta')
      scopes.value = meta.token_scopes ?? []
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load API tokens')
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function create() {
  busy.value = true
  try {
    const result = await api.post<{ token: ApiToken; plaintext_token: string }>('/api-tokens', {
      name: form.name,
      expires_in: form.expires_in || undefined,
      scopes: form.scopes.length ? form.scopes : undefined,
    })
    issued.value = { token: result.token, plaintext: result.plaintext_token }
    createOpen.value = false
    form.name = ''
    form.expires_in = ''
    form.scopes = []
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not create the token')
  } finally {
    busy.value = false
  }
}

async function revoke() {
  if (!revoking.value) return
  busy.value = true
  try {
    await api.del(`/api-tokens/${revoking.value.id}`)
    toast.success('Token revoked')
    revoking.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not revoke the token')
  } finally {
    busy.value = false
  }
}

function state(token: ApiToken): { label: string; klass: string } {
  if (token.revoked_at) return { label: 'revoked', klass: 'badge-danger' }
  if (token.expires_at && new Date(token.expires_at) < new Date()) {
    return { label: 'expired', klass: 'badge-neutral' }
  }
  return { label: 'active', klass: 'badge-success' }
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>API tokens</h1>
        <p class="page-subtitle">
          Long-lived credentials for automation. A token inherits the role of the account that owns it.
        </p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-primary" @click="createOpen = true">
          <span class="mdi mdi-key-plus" />
          New token
        </button>
      </div>
    </div>

    <SettingsNav />

    <div class="card">
      <div v-if="loading" class="loading-page">
        <span class="spinner spinner-lg" />
      </div>

      <UiEmptyState
        v-else-if="!items.length"
        icon="key-outline"
        title="No API tokens yet"
        message="Create one to issue certificates from CI, or to renew them from a deployment script."
      >
        <button class="btn btn-primary" @click="createOpen = true">Create a token</button>
      </UiEmptyState>

      <div v-else class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Token</th>
              <th>Scopes</th>
              <th>Last used</th>
              <th>Expires</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <tr v-for="token in items" :key="token.id">
              <td class="cell-title">{{ token.name }}</td>
              <td class="cell-mono">{{ token.prefix }}…</td>
              <td class="text-sm">
                <span v-if="!token.scopes?.length || token.scopes.includes('*')" class="badge badge-neutral">
                  full access
                </span>
                <span v-else class="scope-chips">
                  <code v-for="scope in token.scopes" :key="scope">{{ scope }}</code>
                </span>
              </td>
              <td class="text-sm">{{ token.last_used_at ? relative(token.last_used_at) : 'never' }}</td>
              <td class="text-sm">{{ token.expires_at ? date(token.expires_at) : 'never' }}</td>
              <td><span class="badge badge-dot" :class="state(token).klass">{{ state(token).label }}</span></td>
              <td class="table-actions">
                <button
                  class="btn btn-icon btn-icon-danger"
                  title="Revoke"
                  :disabled="!!token.revoked_at"
                  @click="revoking = token"
                >
                  <span class="mdi mdi-cancel" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="usage-card card">
      <div class="card-header"><h2>Using a token</h2></div>
      <div class="card-body">
        <pre class="code-block">curl -H "Authorization: Bearer certio_…" \
  {{ 'https://certio.example.com' }}/api/v1/certificates</pre>
        <p class="form-hint mt-2">
          The full OpenAPI description is at <a href="/docs" target="_blank">/docs</a>.
        </p>
      </div>
    </div>

    <!-- Create -->
    <UiBaseModal v-if="createOpen" title="New API token" :busy="busy" @close="createOpen = false">
      <div class="form-group">
        <label class="form-label">Name <span class="required">*</span></label>
        <input v-model="form.name" class="form-input" placeholder="ci-pipeline">
        <p class="form-hint">So you can recognise it later — and know what breaks if you revoke it.</p>
      </div>
      <div class="form-group">
        <label class="form-label">Expires</label>
        <select v-model="form.expires_in" class="form-select">
          <option v-for="option in expiryOptions" :key="option.value" :value="option.value">
            {{ option.label }}
          </option>
        </select>
      </div>

      <div class="form-group">
        <label class="form-label">Scopes</label>
        <p class="form-hint mb-2">
          What this token may do, below whatever its owner's role already allows. Leave everything
          unticked and the token is unrestricted within that role.
        </p>
        <div class="scope-grid">
          <label v-for="scope in scopes" :key="scope.name" class="scope-option" :class="{ selected: scopeChecked(scope.name) }">
            <input
              type="checkbox"
              :checked="scopeChecked(scope.name)"
              :disabled="fullAccess && scope.name !== '*'"
              @change="toggleScope(scope.name)"
            >
            <span>
              <code>{{ scope.name }}</code>
              <em>{{ scope.description }}</em>
            </span>
          </label>
        </div>
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="createOpen = false">Cancel</button>
        <button class="btn btn-primary" :disabled="busy || !form.name" @click="create">
          <span v-if="busy" class="spinner" />
          Create token
        </button>
      </template>
    </UiBaseModal>

    <!-- Shown exactly once -->
    <UiBaseModal v-if="issued" title="Copy your token now" @close="issued = null">
      <div class="app-banner app-banner--warning mb-4">
        <span class="app-banner-icon mdi mdi-alert-outline" />
        <div class="app-banner-content">
          <p class="app-banner-text">
            This is the only time the token is shown. Certio stores only its SHA-256 digest, so it
            cannot be recovered — you would have to create a new one.
          </p>
        </div>
      </div>

      <div class="token-reveal">
        <code class="token-value">{{ issued.plaintext }}</code>
        <UiCopyButton :value="issued.plaintext" label="Copy token" />
      </div>

      <template #footer>
        <button class="btn btn-primary" @click="issued = null">I have saved it</button>
      </template>
    </UiBaseModal>

    <UiConfirmDialog
      v-if="revoking"
      title="Revoke this token?"
      :message="`Anything using ${revoking.name} stops working immediately. This cannot be undone — create a new token instead.`"
      confirm-label="Revoke token"
      danger
      :busy="busy"
      @cancel="revoking = null"
      @confirm="revoke"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 900px; }
.usage-card { margin-top: 18px; }

.token-reveal {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  background: var(--bg-code);
  border-radius: var(--radius);
  border: 1px solid var(--border-primary);
}
.token-value {
  flex: 1;
  font-family: var(--font-mono);
  font-size: 12.5px;
  color: #d4d4f8;
  word-break: break-all;
  user-select: all;
}

.scope-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 6px;
  max-height: 320px;
  overflow-y: auto;
  padding: 4px;
}
.scope-option {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  cursor: pointer;
  font-size: 13px;
  transition: all var(--transition);
}
.scope-option:hover { border-color: var(--primary-400); }
.scope-option.selected { border-color: var(--primary-600); background: var(--primary-50); }
[data-theme="dark"] .scope-option.selected { background: color-mix(in srgb, var(--primary-600) 12%, transparent); }
.scope-option code {
  display: block;
  font-size: 12.5px;
  color: var(--text-primary);
  font-weight: 600;
}
.scope-option em {
  display: block;
  font-style: normal;
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 2px;
}
.scope-chips { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.scope-chips code {
  font-size: 11.5px;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--bg-tertiary, var(--bg-secondary));
  color: var(--text-secondary);
}
</style>
