<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useCatalogStore } from '~/stores/catalog'
import { useAuthStore } from '~/stores/auth'
import { useToast } from '~/composables/useToast'
import type { BulkResponse, Certificate, PageMeta } from '~/types/api'

useHead({ title: 'Certificates · Certio' })

const api = useApi()
const route = useRoute()
const router = useRouter()
const catalog = useCatalogStore()
const auth = useAuthStore()
const toast = useToast()
const { date, days, statusClass, initials } = useFormat()

const items = ref<Certificate[]>([])
const meta = ref<PageMeta>({ total: 0, page: 1, limit: 25, total_pages: 0 })
const loading = ref(true)

const search = ref((route.query.q as string) ?? '')
const caFilter = ref((route.query.ca as string) ?? '')
const statusFilter = ref((route.query.status as string) ?? '')
const expiringFilter = ref((route.query.expiring_in as string) ?? '')
const sort = ref((route.query.sort as string) ?? 'not_after')
const page = ref(Number(route.query.page ?? 1))

const selected = ref<Set<string>>(new Set())
const bulkBusy = ref(false)

let searchTimer: ReturnType<typeof setTimeout> | undefined

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: Certificate[] } & PageMeta>('/certificates', {
      q: search.value,
      ca: caFilter.value,
      status: statusFilter.value,
      expiring_in: expiringFilter.value,
      sort: sort.value,
      order: sort.value === 'not_after' ? 'asc' : 'desc',
      page: page.value,
      limit: 25,
    })
    items.value = payload.items ?? []
    meta.value = {
      total: payload.total, page: payload.page,
      limit: payload.limit, total_pages: payload.total_pages,
    }
    // Drop selections that are no longer on screen.
    selected.value = new Set([...selected.value].filter((id) => items.value.some((c) => c.id === id)))
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load certificates')
  } finally {
    loading.value = false
  }
}

/** syncQuery keeps the URL shareable and the back button meaningful. */
function syncQuery() {
  router.replace({
    query: {
      ...(search.value ? { q: search.value } : {}),
      ...(caFilter.value ? { ca: caFilter.value } : {}),
      ...(statusFilter.value ? { status: statusFilter.value } : {}),
      ...(expiringFilter.value ? { expiring_in: expiringFilter.value } : {}),
      ...(sort.value !== 'not_after' ? { sort: sort.value } : {}),
      ...(page.value > 1 ? { page: String(page.value) } : {}),
    },
  })
}

watch(search, () => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    page.value = 1
    syncQuery()
    load()
  }, 300)
})

watch([caFilter, statusFilter, expiringFilter, sort], () => {
  page.value = 1
  syncQuery()
  load()
})

watch(page, () => {
  syncQuery()
  load()
})

onMounted(async () => {
  await catalog.load()
  // The sidebar's active CA scopes this list unless the URL says otherwise.
  if (!caFilter.value && catalog.activeAuthorityId) {
    caFilter.value = catalog.activeAuthorityId
  }
  await load()
})

const allSelected = computed(
  () => items.value.length > 0 && items.value.every((c) => selected.value.has(c.id)),
)

function toggleAll() {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(items.value.map((c) => c.id))
  }
}

function toggleOne(id: string) {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

async function bulkRenew() {
  bulkBusy.value = true
  try {
    const result = await api.post<BulkResponse>('/certificates/bulk/renew', {
      ids: [...selected.value],
    })
    if (result.failed === 0) {
      toast.success(`Renewed ${result.succeeded} certificate(s)`)
    } else {
      // Naming the first failure is more useful than a bare count.
      const firstError = result.results.find((r) => !r.success)?.error
      toast.warning(`Renewed ${result.succeeded}, failed ${result.failed}${firstError ? `: ${firstError}` : ''}`)
    }
    selected.value = new Set()
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the bulk renewal failed')
  } finally {
    bulkBusy.value = false
  }
}

function clearFilters() {
  search.value = ''
  caFilter.value = ''
  statusFilter.value = ''
  expiringFilter.value = ''
}

const hasFilters = computed(
  () => !!(search.value || caFilter.value || statusFilter.value || expiringFilter.value),
)
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Certificates</h1>
        <p class="page-subtitle">{{ meta.total }} certificate{{ meta.total === 1 ? '' : 's' }} managed</p>
      </div>
      <div class="page-header-actions">
        <NuxtLink v-if="auth.canWrite" to="/certificates/new" class="btn btn-primary">
          <span class="mdi mdi-plus" />
          Issue certificate
        </NuxtLink>
      </div>
    </div>

    <div class="toolbar">
      <input
        v-model="search"
        class="form-input search-input"
        type="search"
        placeholder="Search common name, SAN, serial or fingerprint…"
      >
      <select v-model="caFilter" class="form-select" aria-label="Filter by authority">
        <option value="">All authorities</option>
        <option v-for="ca in catalog.authorities" :key="ca.id" :value="ca.id">{{ ca.name }}</option>
      </select>
      <select v-model="statusFilter" class="form-select" aria-label="Filter by status">
        <option value="">Any status</option>
        <option value="active">Active</option>
        <option value="expiring">Expiring</option>
        <option value="expired">Expired</option>
        <option value="revoked">Revoked</option>
      </select>
      <select v-model="expiringFilter" class="form-select" aria-label="Filter by expiry window">
        <option value="">Any expiry</option>
        <option value="7">Within 7 days</option>
        <option value="30">Within 30 days</option>
        <option value="90">Within 90 days</option>
      </select>
      <button v-if="hasFilters" class="btn btn-ghost btn-sm" @click="clearFilters">
        <span class="mdi mdi-filter-remove-outline" />
        Clear
      </button>
    </div>

    <div v-if="selected.size" class="bulk-bar">
      <span class="bulk-count">{{ selected.size }} selected</span>
      <button class="btn btn-secondary btn-sm" :disabled="bulkBusy" @click="bulkRenew">
        <span v-if="bulkBusy" class="spinner" />
        <span v-else class="mdi mdi-autorenew" />
        Renew selected
      </button>
      <button class="btn btn-ghost btn-sm" @click="selected = new Set()">Clear selection</button>
    </div>

    <div class="card">
      <div v-if="loading" class="loading-page">
        <span class="spinner spinner-lg" />
      </div>

      <UiEmptyState
        v-else-if="!items.length"
        icon="file-certificate-outline"
        :title="hasFilters ? 'No certificates match those filters' : 'No certificates yet'"
        :message="hasFilters
          ? 'Try widening the search, or clear the filters.'
          : 'Issue your first certificate — Certio generates the key, signs it and hands you every format your server wants.'"
      >
        <button v-if="hasFilters" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
        <NuxtLink v-else-if="auth.canWrite" to="/certificates/new" class="btn btn-primary">
          Issue a certificate
        </NuxtLink>
      </UiEmptyState>

      <template v-else>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th v-if="auth.canWrite" class="checkbox-col">
                  <input type="checkbox" :checked="allSelected" aria-label="Select all" @change="toggleAll">
                </th>
                <th>Common name</th>
                <th>Authority</th>
                <th>Profile</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="cert in items"
                :key="cert.id"
                class="row-clickable"
                @click="navigateTo(`/certificates/${cert.id}`)"
              >
                <td v-if="auth.canWrite" class="checkbox-col" @click.stop>
                  <input
                    type="checkbox"
                    :checked="selected.has(cert.id)"
                    :aria-label="`Select ${cert.common_name}`"
                    @change="toggleOne(cert.id)"
                  >
                </td>
                <td>
                  <div class="cell-id">
                    <span class="avatar avatar-sm avatar-square">{{ initials(cert.common_name) }}</span>
                    <span class="cell-text">
                      <span class="cell-title">{{ cert.common_name }}</span>
                      <span class="cell-sub">
                        {{ cert.sans.length }} SAN{{ cert.sans.length === 1 ? '' : 's' }} ·
                        {{ cert.key_algorithm }}
                      </span>
                    </span>
                  </div>
                </td>
                <td class="text-sm">{{ cert.ca_name || catalog.authorityName(cert.ca_id) }}</td>
                <td>
                  <span class="badge badge-secondary">{{ cert.profile }}</span>
                </td>
                <td>
                  <div class="expiry-cell">
                    <span class="expiry-cell-date">{{ date(cert.not_after) }}</span>
                    <span class="expiry-cell-days" :class="cert.severity">{{ days(cert.days_remaining) }}</span>
                  </div>
                </td>
                <td>
                  <span class="badge badge-dot" :class="statusClass(cert.status)">{{ cert.status }}</span>
                  <span
                    v-if="cert.auto_renew"
                    class="mdi mdi-autorenew auto-renew-icon"
                    title="Auto-renew is on"
                  />
                </td>
                <td class="table-actions" @click.stop>
                  <NuxtLink
                    :to="`/certificates/${cert.id}`"
                    class="btn btn-icon btn-icon-muted"
                    title="Open"
                  >
                    <span class="mdi mdi-chevron-right" />
                  </NuxtLink>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <UiPagination
          :page="meta.page"
          :limit="meta.limit"
          :total="meta.total"
          :total-pages="meta.total_pages"
          @update:page="page = $event"
        />
      </template>
    </div>
  </div>
</template>

<style scoped>
.checkbox-col { width: 40px; }
.bulk-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  margin-bottom: 14px;
  background: var(--primary-50);
  border: 1px solid color-mix(in srgb, var(--primary-500) 25%, transparent);
  border-radius: var(--radius);
}
.bulk-count { font-size: 13px; font-weight: 600; color: var(--primary-700); }
[data-theme="dark"] .bulk-count { color: var(--primary-300); }

.expiry-cell { display: flex; flex-direction: column; line-height: 1.3; }
.expiry-cell-date { font-size: 13.5px; color: var(--text-primary); }
.expiry-cell-days { font-size: 12px; font-variant-numeric: tabular-nums; }
.expiry-cell-days.ok { color: var(--success-600); }
.expiry-cell-days.warning { color: var(--warning-600); }
.expiry-cell-days.critical { color: var(--danger-600); }
.expiry-cell-days.expired { color: var(--text-muted); }

.auto-renew-icon { font-size: 14px; color: var(--success-600); margin-left: 6px; vertical-align: middle; }
</style>
