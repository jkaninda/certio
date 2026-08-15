<script setup lang="ts">
import { ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import type { ChainLink } from '~/types/api'

const props = defineProps<{ links: ChainLink[]; valid: boolean }>()

const { date, days } = useFormat()
const expanded = ref<Set<number>>(new Set())

function toggle(index: number) {
  const next = new Set(expanded.value)
  if (next.has(index)) next.delete(index)
  else next.add(index)
  expanded.value = next
}

/** roleFor names each position in the path the way a person reads it. */
function roleFor(index: number, link: ChainLink): string {
  if (index === 0) return link.is_ca ? 'Certificate authority' : 'Leaf certificate'
  if (link.self_signed) return 'Root CA'
  return 'Intermediate CA'
}

function iconFor(index: number, link: ChainLink): string {
  if (index === 0 && !link.is_ca) return 'file-certificate-outline'
  if (link.self_signed) return 'shield-crown-outline'
  return 'shield-link-variant-outline'
}
</script>

<template>
  <div>
    <div
      class="app-banner mb-4"
      :class="valid ? 'app-banner--success' : 'app-banner--danger'"
    >
      <span class="app-banner-icon mdi" :class="valid ? 'mdi-check-decagram' : 'mdi-alert-decagram'" />
      <div class="app-banner-content">
        <p class="app-banner-title">
          {{ valid ? 'The chain verifies' : 'The chain does not verify' }}
        </p>
        <p class="app-banner-text">
          {{ valid
            ? 'Every link is within its validity window and signed by the one above it.'
            : 'A client would reject this certificate. The failing link is highlighted below.' }}
        </p>
      </div>
    </div>

    <div class="chain-list">
      <div
        v-for="(link, index) in links"
        :key="link.serial_number"
        class="chain-link"
        :class="{ 'chain-link-invalid': !link.valid }"
      >
        <div class="chain-head">
          <span class="chain-icon mdi" :class="`mdi-${iconFor(index, link)}`" />
          <div class="flex-1">
            <div class="chain-role">{{ roleFor(index, link) }}</div>
            <div class="chain-subject">{{ link.subject || '(no common name)' }}</div>
            <div class="chain-meta">
              issued by {{ link.issuer || '—' }} ·
              expires {{ date(link.not_after) }} ({{ days(link.days_remaining) }})
            </div>
          </div>
          <span class="badge" :class="link.valid ? 'badge-success' : 'badge-danger'">
            {{ link.valid ? 'valid' : 'invalid' }}
          </span>
          <button class="btn btn-icon btn-icon-muted" :title="expanded.has(index) ? 'Hide PEM' : 'Show PEM'" @click="toggle(index)">
            <span class="mdi" :class="expanded.has(index) ? 'mdi-chevron-up' : 'mdi-chevron-down'" />
          </button>
        </div>

        <p v-if="link.problem" class="chain-problem">
          <span class="mdi mdi-alert-circle-outline" /> {{ link.problem }}
        </p>

        <div v-if="expanded.has(index)" class="chain-detail">
          <div class="detail-grid">
            <span class="detail-label">Serial</span>
            <span class="detail-value font-mono text-sm">{{ link.serial_number }}</span>
            <span class="detail-label">Valid from</span>
            <span class="detail-value">{{ date(link.not_before) }}</span>
            <span class="detail-label">Valid until</span>
            <span class="detail-value">{{ date(link.not_after) }}</span>
          </div>
          <CertPemViewer :pem="link.pem" :label="link.subject || 'certificate'" :collapsed="false" class="mt-4" />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.chain-detail {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px dashed var(--border-primary);
}
</style>
