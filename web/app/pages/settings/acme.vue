<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { AcmeAccount, ExternalAccount } from '~/types/api'

useHead({ title: 'ACME · Certio' })

const api = useApi()
const toast = useToast()
const { date, relative } = useFormat()

const bindings = ref<ExternalAccount[]>([])
const accounts = ref<AcmeAccount[]>([])
const loading = ref(true)
const busy = ref(false)

const createOpen = ref(false)
const deleting = ref<ExternalAccount | null>(null)
const issued = ref<{ kid: string; hmac: string; directory: string } | null>(null)

const form = reactive({ description: '', domains: '', expiresInDays: '' })

async function load() {
  loading.value = true
  try {
    const [bindingPayload, accountPayload] = await Promise.all([
      api.get<{ items: ExternalAccount[] }>('/acme/external-accounts'),
      api.get<{ items: AcmeAccount[] }>('/acme/accounts'),
    ])
    bindings.value = bindingPayload.items ?? []
    accounts.value = accountPayload.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the ACME configuration')
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function create() {
  busy.value = true
  try {
    const domains = form.domains
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean)

    const result = await api.post<{
      external_account: ExternalAccount
      hmac_key: string
      directory_url: string
    }>('/acme/external-accounts', {
      description: form.description || undefined,
      allowed_domains: domains.length ? domains : undefined,
      expires_in_days: form.expiresInDays ? Number(form.expiresInDays) : undefined,
    })

    issued.value = {
      kid: result.external_account.kid,
      hmac: result.hmac_key,
      directory: result.directory_url,
    }
    createOpen.value = false
    Object.assign(form, { description: '', domains: '', expiresInDays: '' })
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not issue the credential')
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (!deleting.value) return
  busy.value = true
  try {
    await api.del(`/acme/external-accounts/${deleting.value.id}`)
    toast.success('Credential revoked')
    deleting.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not revoke the credential')
  } finally {
    busy.value = false
  }
}

function certbotCommand(issuedValue: { kid: string; hmac: string; directory: string }): string {
  return `certbot certonly \\
  --server ${issuedValue.directory} \\
  --eab-kid ${issuedValue.kid} \\
  --eab-hmac-key ${issuedValue.hmac} \\
  -d api.example.com`
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success('Copied')
  } catch {
    toast.error('could not copy to the clipboard')
  }
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>ACME</h1>
        <p class="page-subtitle">
          Point cert-manager, Traefik, Caddy or certbot at this instance and internal certificates
          renew themselves, with nobody in the loop.
        </p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-primary" @click="createOpen = true">
          <span class="mdi mdi-key-chain" />
          Issue credential
        </button>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else>
      <div class="card mb-4">
        <div class="card-header"><h2>Credentials</h2></div>
        <div class="card-body">
          <p class="form-hint mb-3">
            A client has to present one of these to register at all. Without them, anything that can
            reach the directory could obtain a certificate for any name this CA will sign — which on
            an internal network is most of them.
          </p>

          <UiEmptyState
            v-if="!bindings.length"
            icon="key-chain"
            title="No credentials issued"
            message="Issue one per team or per cluster, so a leaked credential can be revoked without affecting anyone else."
          >
            <button class="btn btn-primary" @click="createOpen = true">Issue a credential</button>
          </UiEmptyState>

          <div v-else class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Key ID</th>
                  <th>Description</th>
                  <th>Limited to</th>
                  <th>Last used</th>
                  <th>Expires</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                <tr v-for="binding in bindings" :key="binding.id">
                  <td class="cell-mono">{{ binding.kid }}</td>
                  <td class="cell-title">{{ binding.description || '—' }}</td>
                  <td class="text-sm">
                    <span v-if="!binding.allowed_domains?.length" class="badge badge-neutral">
                      whatever the CA allows
                    </span>
                    <span v-else class="scope-chips">
                      <code v-for="domain in binding.allowed_domains" :key="domain">{{ domain }}</code>
                    </span>
                  </td>
                  <td class="text-sm">{{ binding.last_used_at ? relative(binding.last_used_at) : 'never' }}</td>
                  <td class="text-sm">{{ binding.expires_at ? date(binding.expires_at) : 'never' }}</td>
                  <td class="table-actions">
                    <button class="btn btn-icon btn-icon-danger" title="Revoke" @click="deleting = binding">
                      <span class="mdi mdi-cancel" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h2>Registered clients</h2></div>
        <div class="card-body">
          <UiEmptyState
            v-if="!accounts.length"
            icon="account-network-outline"
            title="No clients have registered yet"
            message="An ACME client registers the first time it asks for a certificate."
          />

          <div v-else class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Contact</th>
                  <th>Key thumbprint</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="account in accounts" :key="account.id">
                  <td class="cell-title">{{ account.contact?.join(', ') || '—' }}</td>
                  <td class="cell-mono">{{ account.key_thumbprint.slice(0, 16) }}…</td>
                  <td>
                    <span
                      class="badge badge-dot"
                      :class="account.status === 'valid' ? 'badge-success' : 'badge-neutral'"
                    >{{ account.status }}</span>
                  </td>
                  <td class="text-sm">{{ account.last_used_at ? relative(account.last_used_at) : 'never' }}</td>
                  <td class="text-sm">{{ date(account.created_at) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </template>

    <!-- Issue -->
    <UiBaseModal v-if="createOpen" title="Issue an ACME credential" :busy="busy" @close="createOpen = false">
      <div class="form-group">
        <label class="form-label">Description</label>
        <input v-model="form.description" class="form-input" placeholder="payments cluster">
        <p class="form-hint">So you know what breaks if you revoke it.</p>
      </div>
      <div class="form-group">
        <label class="form-label">Limit to domains</label>
        <input v-model="form.domains" class="form-input" placeholder="corp.example.com, lab.example.com">
        <p class="form-hint">
          Comma-separated, subdomains included. Leave empty to allow whatever the issuing CA's own
          name constraints already permit.
        </p>
      </div>
      <div class="form-group">
        <label class="form-label">Expires in (days)</label>
        <input v-model="form.expiresInDays" class="form-input" type="number" placeholder="never">
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="createOpen = false">Cancel</button>
        <button class="btn btn-primary" :disabled="busy" @click="create">
          <span v-if="busy" class="spinner" />
          Issue credential
        </button>
      </template>
    </UiBaseModal>

    <!-- Shown exactly once -->
    <UiBaseModal v-if="issued" title="Copy this now" wide @close="issued = null">
      <div class="app-banner app-banner--warning mb-4">
        <span class="app-banner-icon mdi mdi-alert-outline" />
        <div class="app-banner-content">
          <p class="app-banner-text">
            This is the only time the HMAC key is shown. Certio stores only its sealed form, so it
            cannot be recovered — you would have to issue a new credential.
          </p>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Directory URL</label>
        <code class="code-block">{{ issued.directory }}</code>
      </div>
      <div class="form-group">
        <label class="form-label">Key ID</label>
        <code class="code-block">{{ issued.kid }}</code>
      </div>
      <div class="form-group">
        <label class="form-label">HMAC key</label>
        <code class="code-block">{{ issued.hmac }}</code>
      </div>

      <div class="form-group">
        <label class="form-label">certbot</label>
        <pre class="code-block">{{ certbotCommand(issued) }}</pre>
      </div>

      <template #footer>
        <button class="btn btn-secondary" @click="copy(certbotCommand(issued!))">
          <span class="mdi mdi-content-copy" />
          Copy command
        </button>
        <button class="btn btn-primary" @click="issued = null">Done</button>
      </template>
    </UiBaseModal>

    <UiConfirmDialog
      v-if="deleting"
      title="Revoke this credential?"
      :message="`No new client can register with ${deleting.kid}. Clients already registered with it keep working.`"
      confirm-label="Revoke"
      danger
      :busy="busy"
      @cancel="deleting = null"
      @confirm="remove"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 1000px; }
.mb-3 { margin-bottom: 12px; }
.mb-4 { margin-bottom: 16px; }
.scope-chips { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.scope-chips code {
  font-size: 11.5px;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--bg-tertiary, var(--bg-secondary));
  color: var(--text-secondary);
}
.code-block { display: block; word-break: break-all; }
</style>
