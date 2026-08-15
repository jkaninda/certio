<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useAuthStore } from '~/stores/auth'
import { useToast } from '~/composables/useToast'
import type { Authority } from '~/types/api'

useHead({ title: 'Authorities · Certio' })

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { date, days, statusClass } = useFormat()

const items = ref<Authority[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const payload = await api.get<{ items: Authority[] }>('/authorities', { limit: 200 })
    items.value = payload.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load authorities')
  } finally {
    loading.value = false
  }
})

/** Roots first, each followed by the intermediates that chain to it. */
const tree = computed(() => {
  const roots = items.value.filter((ca) => !ca.parent_id)
  const orphans = items.value.filter(
    (ca) => ca.parent_id && !items.value.some((r) => r.id === ca.parent_id),
  )
  const out: { ca: Authority; depth: number }[] = []

  function walk(parent: Authority, depth: number) {
    out.push({ ca: parent, depth })
    for (const child of items.value.filter((c) => c.parent_id === parent.id)) {
      walk(child, depth + 1)
    }
  }

  for (const root of roots) walk(root, 0)
  // An intermediate whose parent is not managed here still has to be visible.
  for (const orphan of orphans) out.push({ ca: orphan, depth: 0 })
  return out
})
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Certificate authorities</h1>
        <p class="page-subtitle">The roots and intermediates that sign everything you issue.</p>
      </div>
      <div v-if="auth.canWrite" class="page-header-actions">
        <NuxtLink to="/authorities/new?mode=import" class="btn btn-secondary">
          <span class="mdi mdi-import" />
          Import
        </NuxtLink>
        <NuxtLink to="/authorities/new" class="btn btn-primary">
          <span class="mdi mdi-plus" />
          New authority
        </NuxtLink>
      </div>
    </div>

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <div v-else-if="!items.length" class="card">
      <UiEmptyState
        icon="shield-plus-outline"
        title="No certificate authority yet"
        message="A CA is the trust anchor for everything Certio issues. Create a root, or import the one
                 you already manage with openssl — certificate and key, adopted as they are."
      >
        <div class="flex gap-2 justify-center">
          <NuxtLink to="/authorities/new" class="btn btn-primary">Create a root CA</NuxtLink>
          <NuxtLink to="/authorities/new?mode=import" class="btn btn-secondary">Import existing</NuxtLink>
        </div>
      </UiEmptyState>
    </div>

    <div v-else class="ca-grid">
      <NuxtLink
        v-for="node in tree"
        :key="node.ca.id"
        :to="`/authorities/${node.ca.id}`"
        class="ca-card"
        :class="{ 'ca-card-child': node.depth > 0 }"
        :style="{ marginLeft: `${node.depth * 28}px` }"
      >
        <div class="ca-card-head">
          <span
            class="ca-card-icon mdi"
            :class="node.ca.type === 'root' ? 'mdi-shield-crown-outline' : 'mdi-shield-link-variant-outline'"
          />
          <div class="min-w-0 flex-1">
            <div class="ca-card-title">
              {{ node.ca.name }}
              <span v-if="node.ca.passphrase_protected" class="mdi mdi-lock-outline ca-lock" title="Passphrase-protected" />
            </div>
            <div class="ca-card-sub">{{ node.ca.subject_dn }}</div>
          </div>
          <span class="badge badge-dot" :class="statusClass(node.ca.status)">{{ node.ca.status }}</span>
        </div>

        <div class="ca-card-meta">
          <span><span class="mdi mdi-shape-outline" /> {{ node.ca.type }}</span>
          <span><span class="mdi mdi-key-outline" /> {{ node.ca.key_algorithm }}</span>
          <span><span class="mdi mdi-file-certificate-outline" /> {{ node.ca.certificate_count }} issued</span>
          <span :class="node.ca.days_remaining < 90 ? 'ca-expiring' : ''">
            <span class="mdi mdi-calendar-clock" />
            expires {{ date(node.ca.not_after) }} ({{ days(node.ca.days_remaining) }})
          </span>
        </div>
      </NuxtLink>
    </div>
  </div>
</template>

<style scoped>
.ca-grid { display: flex; flex-direction: column; gap: 12px; }

.ca-card {
  display: block;
  padding: 16px 20px;
  background: var(--bg-primary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  color: inherit;
  transition: border-color var(--transition), transform var(--transition), box-shadow var(--transition);
}
.ca-card:hover {
  color: inherit;
  border-color: var(--primary-400);
  transform: translateY(-1px);
  box-shadow: var(--shadow);
}
/* An intermediate is drawn indented with a connector to its parent above. */
.ca-card-child { position: relative; }
.ca-card-child::before {
  content: '';
  position: absolute;
  left: -16px;
  top: -13px;
  bottom: 50%;
  width: 2px;
  background: var(--border-primary);
}
.ca-card-child::after {
  content: '';
  position: absolute;
  left: -16px;
  top: 50%;
  width: 14px;
  height: 2px;
  background: var(--border-primary);
}

.ca-card-head { display: flex; align-items: flex-start; gap: 14px; }
.ca-card-icon {
  font-size: 24px;
  color: var(--primary-600);
  flex-shrink: 0;
  margin-top: 2px;
}
.ca-card-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
}
.ca-lock { font-size: 14px; color: var(--warning-600); }
.ca-card-sub {
  font-size: 12.5px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ca-card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 20px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--border-secondary);
  font-size: 12.5px;
  color: var(--text-muted);
}
.ca-card-meta .mdi { font-size: 14px; margin-right: 3px; }
.ca-expiring { color: var(--warning-600); }

.min-w-0 { min-width: 0; }
</style>
