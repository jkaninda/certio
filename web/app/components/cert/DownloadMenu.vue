<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useToast } from '~/composables/useToast'
import { ApiRequestError } from '~/composables/useApi'
import type { Certificate } from '~/types/api'

const props = defineProps<{ certificate: Certificate }>()

const api = useApi()
const toast = useToast()

const open = ref(false)
const busy = ref(false)
const passwordPrompt = ref<{ format: string; label: string } | null>(null)
const password = ref('')

interface Format {
  format: string
  label: string
  hint: string
  icon: string
  /** Contains private key material, so it needs the download policy check. */
  key?: boolean
  /** Requires a password before it can be produced. */
  password?: boolean
}

const groups: { title: string; formats: Format[] }[] = [
  {
    title: 'Certificate',
    formats: [
      { format: 'pem', label: 'Certificate', hint: '.crt — the leaf alone', icon: 'file-certificate-outline' },
      { format: 'fullchain', label: 'Full chain', hint: '.pem — leaf + issuers, what nginx wants', icon: 'file-tree' },
      { format: 'chain', label: 'Chain only', hint: '.pem — the issuers without the leaf', icon: 'link-variant' },
      { format: 'root', label: 'Root CA', hint: '.crt — the trust anchor for clients', icon: 'shield-crown-outline' },
    ],
  },
  {
    title: 'Private key',
    formats: [
      { format: 'key', label: 'Private key', hint: '.key — PKCS#8 PEM', icon: 'key-outline', key: true },
      { format: 'p12', label: 'PKCS#12', hint: '.p12 — for Java, Windows, appliances', icon: 'package-variant-closed', key: true, password: true },
      { format: 'zip', label: 'Everything', hint: '.zip — every file plus a README', icon: 'folder-zip-outline', key: true },
    ],
  },
  {
    title: 'Deployment',
    formats: [
      { format: 'k8s', label: 'Kubernetes Secret', hint: 'kubernetes.io/tls YAML', icon: 'kubernetes', key: true },
      { format: 'nginx', label: 'nginx snippet', hint: 'a server block wired to these files', icon: 'server' },
      { format: 'traefik', label: 'Traefik config', hint: 'dynamic TLS configuration', icon: 'router-network' },
      { format: 'haproxy', label: 'HAProxy config', hint: 'frontend with the combined PEM', icon: 'lan-connect' },
      { format: 'goma', label: 'Goma Gateway', hint: 'global gateway.tls block', icon: 'gate' },
      { format: 'goma-route', label: 'Goma route', hint: 'route with its own certificate', icon: 'sign-direction' },
      { format: 'compose', label: 'docker compose', hint: 'volume layout for the bundle', icon: 'docker' },
    ],
  },
]

async function run(entry: Format) {
  if (entry.password && !password.value) {
    passwordPrompt.value = { format: entry.format, label: entry.label }
    open.value = false
    return
  }

  busy.value = true
  try {
    const query = new URLSearchParams({ format: entry.format })
    if (password.value) query.set('password', password.value)

    await api.download(`/certificates/${props.certificate.id}/download?${query.toString()}`)
    toast.success(`${entry.label} downloaded`)
    open.value = false
    passwordPrompt.value = null
    password.value = ''
  } catch (err) {
    if (err instanceof ApiRequestError && err.isForbidden) {
      // The download policy, not a permission problem — say which.
      toast.error(err.message)
    } else {
      toast.error(err instanceof Error ? err.message : 'the download failed')
    }
  } finally {
    busy.value = false
  }
}

function confirmPassword() {
  const entry = groups.flatMap((g) => g.formats).find((f) => f.format === passwordPrompt.value?.format)
  if (entry) run(entry)
}

function close(event: MouseEvent) {
  if (!(event.target as Element)?.closest?.('.download-menu')) open.value = false
}

onMounted(() => document.addEventListener('click', close))
onBeforeUnmount(() => document.removeEventListener('click', close))
</script>

<template>
  <div class="dropdown download-menu">
    <button class="btn btn-secondary" :disabled="busy" @click.stop="open = !open">
      <span v-if="busy" class="spinner" />
      <span v-else class="mdi mdi-download" />
      Download
      <span class="mdi mdi-chevron-down" />
    </button>

    <div v-if="open" class="dropdown-menu" @click.stop>
      <template v-for="group in groups" :key="group.title">
        <div class="dropdown-label">{{ group.title }}</div>
        <button
          v-for="entry in group.formats"
          :key="entry.format"
          class="dropdown-item"
          :disabled="entry.key && !certificate.has_private_key"
          :title="entry.key && !certificate.has_private_key
            ? 'Certio does not hold the private key for this certificate — it was signed from an external CSR'
            : entry.hint"
          @click="run(entry)"
        >
          <span class="mdi" :class="`mdi-${entry.icon}`" />
          <span class="download-item-text">
            <span class="download-item-label">{{ entry.label }}</span>
            <span class="download-item-hint">{{ entry.hint }}</span>
          </span>
        </button>
      </template>

      <template v-if="certificate.csr_pem">
        <div class="dropdown-divider" />
        <button class="dropdown-item" @click="run({ format: 'csr', label: 'CSR', hint: '', icon: 'file-document-outline' })">
          <span class="mdi mdi-file-document-outline" />
          <span class="download-item-text">
            <span class="download-item-label">Original CSR</span>
            <span class="download-item-hint">.csr — as submitted</span>
          </span>
        </button>
      </template>
    </div>

    <UiBaseModal
      v-if="passwordPrompt"
      :title="`Password for ${passwordPrompt.label}`"
      :busy="busy"
      @close="passwordPrompt = null; password = ''"
    >
      <p class="text-secondary mb-4">
        PKCS#12 files are always encrypted. Choose a password — you will need it when importing
        the file into a keystore.
      </p>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input
          v-model="password"
          type="password"
          class="form-input"
          autocomplete="new-password"
          @keydown.enter="confirmPassword"
        >
      </div>
      <template #footer>
        <button class="btn btn-secondary" @click="passwordPrompt = null; password = ''">Cancel</button>
        <button class="btn btn-primary" :disabled="!password || busy" @click="confirmPassword">
          <span v-if="busy" class="spinner" />
          Download
        </button>
      </template>
    </UiBaseModal>
  </div>
</template>

<style scoped>
.dropdown-menu { min-width: 300px; }
.download-item-text { display: flex; flex-direction: column; line-height: 1.3; min-width: 0; }
.download-item-label { font-weight: 500; }
.download-item-hint { font-size: 11.5px; color: var(--text-muted); }
.dropdown-item:disabled { opacity: 0.45; cursor: not-allowed; }
.dropdown-item:disabled:hover { background: transparent; }
</style>
