<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { DeployResult, DeploymentTarget } from '~/types/api'

useHead({ title: 'Deployments · Certio' })

const api = useApi()
const toast = useToast()
const { relative } = useFormat()

const items = ref<DeploymentTarget[]>([])
const loading = ref(true)
const busy = ref(false)
const testing = ref<string | null>(null)

const createOpen = ref(false)
const deleting = ref<DeploymentTarget | null>(null)

const form = reactive({
  name: '',
  kind: 'kubernetes' as DeploymentTarget['kind'],
  enabled: true,
  commonName: '',
  selector: '',
  config: {} as Record<string, string>,
})

/** Each kind declares the fields it needs, so the form is data-driven and the
 *  backend stays the only place that knows what a target really requires. */
const kindFields: Record<
  string,
  { key: string; label: string; type?: string; hint?: string; placeholder?: string }[]
> = {
  kubernetes: [
    { key: 'api_url', label: 'API server', placeholder: 'https://kubernetes.default.svc' },
    { key: 'token', label: 'ServiceAccount token', type: 'password', hint: 'Needs get, create and update on secrets in the one namespace — nothing more.' },
    { key: 'namespace', label: 'Namespace', placeholder: 'default' },
    { key: 'secret_name', label: 'Secret name', placeholder: 'api-tls' },
    { key: 'ca_bundle', label: 'API server CA bundle', hint: 'PEM. In-cluster this is the ServiceAccount ca.crt.' },
    { key: 'annotations', label: 'Annotations', hint: 'key=value, comma-separated. This is how a reloader is told to restart the pods.', placeholder: 'reloader.stakater.com/match=true' },
  ],
  ssh: [
    { key: 'host', label: 'Host', placeholder: 'lb-01.internal' },
    { key: 'port', label: 'Port', placeholder: '22' },
    { key: 'user', label: 'User', placeholder: 'deploy' },
    { key: 'private_key', label: 'Private key', type: 'password', hint: 'OpenSSH or PEM. Or use a password below.' },
    { key: 'password', label: 'Password', type: 'password' },
    { key: 'host_key', label: 'Host key', hint: 'The line ssh-keyscan prints. Without it, the private key goes to whoever answers the address.', placeholder: 'ssh-ed25519 AAAAC3Nz…' },
    { key: 'fullchain_path', label: 'Fullchain path', placeholder: '/etc/ssl/certs/api.pem' },
    { key: 'key_path', label: 'Key path', placeholder: '/etc/ssl/private/api.key' },
    { key: 'cert_path', label: 'Certificate path' },
    { key: 'chain_path', label: 'Chain path' },
    { key: 'reload_command', label: 'Reload command', placeholder: 'systemctl reload nginx' },
  ],
  webhook: [
    { key: 'url', label: 'URL', placeholder: 'https://deploy.example.com/hooks/certio' },
    { key: 'secret', label: 'Signing secret', type: 'password', hint: 'The body is signed HMAC-SHA256 as X-Certio-Signature. Required when the key is sent.' },
    { key: 'include_key', label: 'Send the private key', hint: 'true or false. Leave false for a receiver that only needs to know a renewal happened.', placeholder: 'true' },
    { key: 'headers', label: 'Extra headers', hint: 'key=value, comma-separated.' },
  ],
}

const kindIcon: Record<string, string> = {
  kubernetes: 'kubernetes',
  ssh: 'console',
  webhook: 'webhook',
}

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: DeploymentTarget[] }>('/deployments')
    items.value = payload.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load deployment targets')
  } finally {
    loading.value = false
  }
}

onMounted(load)

function resetForm() {
  Object.assign(form, {
    name: '', kind: 'kubernetes', enabled: true, commonName: '', selector: '', config: {},
  })
}

/** The selector is typed as `env=prod, team=payments` and stored as a map. */
const parsedSelector = computed(() => {
  const out: Record<string, string> = {}
  for (const entry of form.selector.split(',')) {
    const [key, ...rest] = entry.split('=')
    if (!key?.trim() || !rest.length) continue
    out[key.trim()] = rest.join('=').trim()
  }
  return out
})

const canSubmit = computed(
  () => !!form.name && (!!form.commonName || Object.keys(parsedSelector.value).length > 0),
)

async function create() {
  busy.value = true
  try {
    await api.post('/deployments', {
      name: form.name,
      kind: form.kind,
      config: form.config,
      selector: parsedSelector.value,
      common_name: form.commonName || undefined,
      enabled: form.enabled,
    })
    toast.success('Target added')
    createOpen.value = false
    resetForm()
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not add the target')
  } finally {
    busy.value = false
  }
}

async function toggleEnabled(target: DeploymentTarget) {
  try {
    await api.patch(`/deployments/${target.id}`, { enabled: !target.enabled })
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not update the target')
  }
}

async function test(target: DeploymentTarget) {
  testing.value = target.id
  try {
    const payload = await api.post<{ results: DeployResult[] }>(`/deployments/${target.id}/test`)
    const result = payload.results?.[0]
    if (result?.error) {
      toast.error(result.error)
    } else {
      toast.success(`Deployed to ${result?.destination || target.name}`)
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the test failed')
  } finally {
    testing.value = null
    await load()
  }
}

async function remove() {
  if (!deleting.value) return
  busy.value = true
  try {
    await api.del(`/deployments/${deleting.value.id}`)
    toast.success('Target deleted')
    deleting.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not delete the target')
  } finally {
    busy.value = false
  }
}

function describeSelector(target: DeploymentTarget): string {
  const parts = Object.entries(target.selector ?? {}).map(([k, v]) => `${k}=${v}`)
  if (target.common_name) parts.unshift(`cn=${target.common_name}`)
  return parts.join(' · ') || 'nothing'
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Deployments</h1>
        <p class="page-subtitle">
          Where renewed certificates are written. Without one, auto-renewal produces a new
          certificate and leaves somebody to copy it onto a server by hand.
        </p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-primary" @click="createOpen = true">
          <span class="mdi mdi-rocket-launch-outline" />
          Add target
        </button>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <div v-else-if="!items.length" class="card">
      <UiEmptyState
        icon="rocket-launch-outline"
        title="No deployment targets"
        message="A target selects certificates by label and pushes them where they are used — a
                 Kubernetes Secret, a load balancer over SSH, or a webhook. Labels survive renewal,
                 so the target keeps pointing at whatever is currently the certificate for that thing."
      >
        <button class="btn btn-primary" @click="createOpen = true">Add a target</button>
      </UiEmptyState>
    </div>

    <div v-else class="channel-list">
      <div v-for="target in items" :key="target.id" class="card channel-card">
        <div class="channel-head">
          <span class="channel-icon mdi" :class="`mdi-${kindIcon[target.kind] ?? 'server'}`" />
          <div class="flex-1 min-w-0">
            <div class="channel-name">
              {{ target.name }}
              <span class="badge badge-secondary">{{ target.kind }}</span>
              <span class="badge" :class="target.enabled ? 'badge-success' : 'badge-neutral'">
                {{ target.enabled ? 'enabled' : 'disabled' }}
              </span>
            </div>
            <div class="channel-meta">
              matches {{ describeSelector(target) }}
              <template v-if="target.last_success_at"> · last deployed {{ relative(target.last_success_at) }}</template>
            </div>
          </div>

          <div class="channel-actions">
            <button class="btn btn-ghost btn-sm" :disabled="testing === target.id" @click="test(target)">
              <span v-if="testing === target.id" class="spinner" />
              <span v-else class="mdi mdi-send-outline" />
              Deploy now
            </button>
            <button class="btn btn-icon btn-icon-muted" :title="target.enabled ? 'Disable' : 'Enable'" @click="toggleEnabled(target)">
              <span class="mdi" :class="target.enabled ? 'mdi-pause' : 'mdi-play'" />
            </button>
            <button class="btn btn-icon btn-icon-danger" title="Delete" @click="deleting = target">
              <span class="mdi mdi-delete-outline" />
            </button>
          </div>
        </div>

        <p v-if="target.last_error" class="channel-error">
          <span class="mdi mdi-alert-circle-outline" />
          Last deployment failed: {{ target.last_error }}
        </p>
      </div>
    </div>

    <!-- Create -->
    <UiBaseModal v-if="createOpen" title="Add a deployment target" wide :busy="busy" @close="createOpen = false">
      <div class="form-group">
        <label class="form-label">Name <span class="required">*</span></label>
        <input v-model="form.name" class="form-input" placeholder="prod ingress">
      </div>

      <div class="form-group">
        <label class="form-label">Kind</label>
        <div class="channel-choice">
          <button
            v-for="option in (['kubernetes', 'ssh', 'webhook'] as const)"
            :key="option"
            class="channel-option"
            :class="{ selected: form.kind === option }"
            @click="form.kind = option; form.config = {}"
          >
            <span class="mdi" :class="`mdi-${kindIcon[option]}`" />
            {{ option }}
          </button>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Which certificates <span class="required">*</span></label>
        <input v-model="form.selector" class="form-input" placeholder="env=prod, app=api">
        <p class="form-hint">
          Label selector. Labels survive renewal, so this keeps pointing at the current certificate.
          Give a common name below instead if there is only one.
        </p>
        <input v-model="form.commonName" class="form-input mt-2" placeholder="api.example.com">
      </div>

      <div v-for="field in kindFields[form.kind]" :key="field.key" class="form-group">
        <label class="form-label">{{ field.label }}</label>
        <input
          v-model="form.config[field.key]"
          :type="field.type ?? 'text'"
          class="form-input"
          :placeholder="field.placeholder"
          autocomplete="off"
        >
        <p v-if="field.hint" class="form-hint">{{ field.hint }}</p>
      </div>

      <div class="form-group">
        <label class="checkbox-label">
          <input v-model="form.enabled" type="checkbox">
          Enabled
        </label>
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="createOpen = false">Cancel</button>
        <button class="btn btn-primary" :disabled="busy || !canSubmit" @click="create">
          <span v-if="busy" class="spinner" />
          Add target
        </button>
      </template>
    </UiBaseModal>

    <UiConfirmDialog
      v-if="deleting"
      title="Delete this target?"
      :message="`${deleting.name} will stop receiving renewed certificates. Nothing already deployed is removed.`"
      confirm-label="Delete"
      danger
      :busy="busy"
      @cancel="deleting = null"
      @confirm="remove"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 900px; }
.channel-list { display: flex; flex-direction: column; gap: 12px; }
.channel-card { padding: 16px 20px; }
.channel-head { display: flex; align-items: center; gap: 14px; }
.channel-icon { font-size: 24px; color: var(--primary-600); flex-shrink: 0; }
.channel-name {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  color: var(--text-primary);
  flex-wrap: wrap;
}
.channel-meta { font-size: 12.5px; color: var(--text-muted); margin-top: 2px; }
.channel-actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
.channel-error {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px dashed var(--border-primary);
  font-size: 12.5px;
  color: var(--danger-600);
}
.channel-choice { display: flex; gap: 8px; flex-wrap: wrap; }
.channel-option {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 16px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-primary);
  cursor: pointer;
  font-family: inherit;
  font-size: 13.5px;
  color: var(--text-secondary);
  text-transform: capitalize;
  transition: all var(--transition);
}
.channel-option:hover { border-color: var(--primary-400); }
.channel-option.selected {
  border-color: var(--primary-600);
  background: var(--primary-50);
  color: var(--primary-700);
  font-weight: 500;
}
[data-theme="dark"] .channel-option.selected { color: var(--primary-300); }
.flex-1 { flex: 1; }
.min-w-0 { min-width: 0; }
.mt-2 { margin-top: 8px; }
</style>
