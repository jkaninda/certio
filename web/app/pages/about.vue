<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { About } from '~/types/api'

useHead({ title: 'About · Certio' })

const api = useApi()
const toast = useToast()
const { dateTime } = useFormat()

const about = ref<About | null>(null)
const loading = ref(true)

onMounted(async () => {
  try {
    about.value = await api.get<About>('/about')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the instance details')
  } finally {
    loading.value = false
  }
})

/** The version line as you would quote it in a bug report. */
const buildLine = computed(() => {
  if (!about.value) return ''
  const parts = [`certio ${about.value.version}`]
  if (about.value.commit && about.value.commit !== 'none') parts.push(`commit ${about.value.commit}`)
  parts.push(about.value.go_version, about.value.platform)
  return parts.join(' · ')
})

const capabilities = [
  {
    icon: 'certificate-outline',
    title: 'Certificate authorities',
    text: 'Create roots and intermediates, or import the CA you already have — certificate and key — without re-issuing anything.',
  },
  {
    icon: 'file-certificate-outline',
    title: 'Issuance with real SAN support',
    text: 'DNS, IP (v4 and v6), email, URI and wildcards, with the validation browsers actually apply. Managed keys or BYO-CSR.',
  },
  {
    icon: 'autorenew',
    title: 'Renewal and revocation',
    text: 'Renew by hand, in bulk or automatically on a threshold. Revoke with an RFC 5280 reason and publish a CRL clients can fetch.',
  },
  {
    icon: 'export-variant',
    title: 'Export in every shape',
    text: 'PEM, chain, fullchain, PKCS#12, ZIP, Kubernetes TLS Secret, and nginx / Traefik / HAProxy / Goma Gateway / compose snippets.',
  },
  {
    icon: 'shield-lock-outline',
    title: 'Keys sealed at rest',
    text: 'Private keys are AES-256-GCM encrypted with a master key, and a CA key can be bound to a passphrase that is never stored.',
  },
  {
    icon: 'text-box-search-outline',
    title: 'An audit log that only grows',
    text: 'Every mutation is appended. The API exposes no update or delete for it — that is a property of the schema, not a convention.',
  },
]

const policyText: Record<string, string> = {
  always: 'downloadable as often as needed',
  once: 'downloadable exactly once each',
  never: 'never downloadable',
}
</script>

<template>
  <div class="about-page">
    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else-if="about">
      <!-- Masthead -->
      <section class="masthead">
        <AppLogo class="masthead-logo" :size="52" />
        <div class="masthead-text">
          <h1 class="masthead-title">
            {{ about.name }}<span class="masthead-dot">.</span>
            <span class="badge badge-info masthead-version">{{ about.version }}</span>
          </h1>
          <p class="masthead-tagline">{{ about.tagline }}</p>
        </div>
      </section>

      <p class="lede">{{ about.description }}</p>

      <!-- What it does -->
      <div class="capabilities">
        <div v-for="item in capabilities" :key="item.title" class="capability">
          <span class="capability-icon mdi" :class="`mdi-${item.icon}`" aria-hidden="true" />
          <div>
            <h3 class="capability-title">{{ item.title }}</h3>
            <p class="capability-text">{{ item.text }}</p>
          </div>
        </div>
      </div>

      <!-- Build -->
      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Build</h2>
            <span class="card-subtitle">Quote this line when you report a bug</span>
          </div>
          <UiCopyButton :value="buildLine" label="Copy" />
        </div>
        <div class="card-body">
          <div class="detail-grid">
            <span class="detail-label">Version</span>
            <span class="detail-value mono-value">{{ about.version }}</span>

            <span class="detail-label">Commit</span>
            <span class="detail-value mono-value">{{ about.commit || '—' }}</span>

            <span class="detail-label">Built</span>
            <span class="detail-value">{{ about.build_date || '—' }}</span>

            <span class="detail-label">Runtime</span>
            <span class="detail-value mono-value">{{ about.go_version }} · {{ about.platform }}</span>

            <span class="detail-label">Started</span>
            <span class="detail-value">
              {{ dateTime(about.started_at) }}
              <span class="text-muted text-sm">— up {{ about.uptime }}</span>
            </span>
          </div>
        </div>
      </div>

      <!-- This instance -->
      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>This instance</h2>
            <span class="card-subtitle">How this deployment is configured</span>
          </div>
        </div>
        <div class="card-body">
          <div class="detail-grid">
            <span class="detail-label">Base URL</span>
            <span class="detail-value">
              <span class="mono-value">{{ about.instance.base_url || 'not set' }}</span>
              <p class="form-hint">Baked into the CRL distribution point of every certificate issued.</p>
            </span>

            <span class="detail-label">Database</span>
            <span class="detail-value mono-value">{{ about.instance.database_driver }}</span>

            <span class="detail-label">Transport</span>
            <span class="detail-value">
              <span class="badge" :class="about.instance.tls ? 'badge-success' : 'badge-neutral'">
                {{ about.instance.tls ? 'HTTPS, terminated here' : 'HTTP' }}
              </span>
              <p v-if="!about.instance.tls" class="form-hint">
                Fine behind a TLS-terminating proxy; not fine on an open network.
              </p>
            </span>

            <span class="detail-label">Private keys</span>
            <span class="detail-value">
              <span class="badge badge-info">{{ about.instance.key_download_policy }}</span>
              <span class="text-muted text-sm">
                — {{ policyText[about.instance.key_download_policy] ?? '' }}
              </span>
            </span>

            <span class="detail-label">Scheduler</span>
            <span class="detail-value">
              <span class="badge badge-dot" :class="about.instance.scheduler_enabled ? 'badge-success' : 'badge-neutral'">
                {{ about.instance.scheduler_enabled ? 'running' : 'disabled' }}
              </span>
              <span class="text-muted text-sm">
                — warns {{ about.instance.expiry_warn_days }} days before expiry
              </span>
            </span>

            <span class="detail-label">Sessions</span>
            <span class="detail-value">
              <span class="mono-value">{{ about.instance.access_token_ttl }}</span> access,
              <span class="mono-value">{{ about.instance.refresh_token_ttl }}</span> refresh
            </span>

            <span class="detail-label">API description</span>
            <span class="detail-value">
              <a v-if="about.instance.docs_enabled" href="/docs" target="_blank" rel="noopener noreferrer">
                /docs <span class="mdi mdi-open-in-new" />
              </a>
              <span v-else class="text-muted">disabled on this instance</span>
            </span>
          </div>
        </div>
      </div>

      <!-- Project -->
      <div class="card">
        <div class="card-header">
          <div>
            <h2>Project</h2>
            <span class="card-subtitle">Released under the {{ about.license }} licence</span>
          </div>
        </div>
        <div class="card-body">
          <div class="links">
            <a class="link-card" :href="about.repository" target="_blank" rel="noopener noreferrer">
              <span class="mdi mdi-github" />
              <span>
                <strong>Source</strong>
                <em>Read the code, or send a patch</em>
              </span>
            </a>
            <a class="link-card" :href="about.documentation" target="_blank" rel="noopener noreferrer">
              <span class="mdi mdi-book-open-variant" />
              <span>
                <strong>Documentation</strong>
                <em>Deployment, configuration and the CLI</em>
              </span>
            </a>
            <a class="link-card" :href="about.issues_url" target="_blank" rel="noopener noreferrer">
              <span class="mdi mdi-bug-outline" />
              <span>
                <strong>Report a problem</strong>
                <em>Include the build line above</em>
              </span>
            </a>
            <a class="link-card" :href="about.license_url" target="_blank" rel="noopener noreferrer">
              <span class="mdi mdi-scale-balance" />
              <span>
                <strong>{{ about.license }} licence</strong>
                <em>What you may do with it</em>
              </span>
            </a>
          </div>
          <p class="copyright">
            Copyright © 2026
            <a href="https://jkaninda.dev" target="_blank" rel="noopener noreferrer">Jonas Kaninda</a>
          </p>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.about-page { max-width: 880px; }

.masthead { display: flex; align-items: center; gap: 16px; margin-bottom: 18px; }
.masthead-logo {
  flex-shrink: 0;
}
.masthead-title {
  font-size: 26px;
  font-weight: 700;
  line-height: 1.2;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.masthead-dot { color: var(--primary-500); }
.masthead-version { font-size: 11px; }
.masthead-tagline { font-size: 14px; color: var(--text-muted); margin-top: 2px; }

.lede {
  font-size: 14px;
  line-height: 1.7;
  color: var(--text-secondary);
  margin-bottom: 24px;
  max-width: 66ch;
}

.capabilities {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 14px;
  margin-bottom: 26px;
}
.capability {
  display: flex;
  gap: 12px;
  padding: 14px 16px;
  background: var(--bg-primary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
}
.capability-icon {
  font-size: 20px;
  color: var(--primary-600);
  flex-shrink: 0;
  line-height: 1.3;
}
[data-theme="dark"] .capability-icon { color: var(--primary-400); }
.capability-title { font-size: 13.5px; font-weight: 600; margin-bottom: 3px; }
.capability-text { font-size: 12.5px; color: var(--text-muted); line-height: 1.6; }

.links {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 10px;
}
.link-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 14px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  color: var(--text-secondary);
  transition: border-color var(--transition), background var(--transition);
}
.link-card:hover { border-color: var(--primary-400); background: var(--bg-hover); }
.link-card .mdi { font-size: 20px; color: var(--text-tertiary); flex-shrink: 0; }
.link-card span span, .link-card > span:last-child {
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.link-card strong { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.link-card em { font-size: 12px; font-style: normal; color: var(--text-muted); }

.copyright {
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--border-primary);
  font-size: 12.5px;
  color: var(--text-muted);
  text-align: center;
}
.copyright a { color: inherit; }
.copyright a:hover { color: var(--text-secondary); }
</style>
