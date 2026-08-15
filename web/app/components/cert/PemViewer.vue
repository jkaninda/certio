<script setup lang="ts">
import { computed, ref } from 'vue'

const props = withDefaults(defineProps<{
  pem: string
  label?: string
  /** Starts collapsed; a full chain is a lot of base64 to drop on a page. */
  collapsed?: boolean
  filename?: string
}>(), { label: 'PEM', collapsed: true })

const open = ref(!props.collapsed)

const lineCount = computed(() => props.pem.trim().split('\n').length)

/** The block types present, so the header can say what this actually is. */
const blockTypes = computed(() => {
  const matches = [...props.pem.matchAll(/-----BEGIN ([A-Z0-9 #]+)-----/g)]
  const types = matches.map((m) => m[1]!.toLowerCase())
  return [...new Set(types)]
})

function downloadPem() {
  const blob = new Blob([props.pem], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = props.filename ?? 'certificate.pem'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<template>
  <div class="pem-viewer">
    <div class="pem-header">
      <button class="pem-toggle" type="button" @click="open = !open">
        <span class="mdi" :class="open ? 'mdi-chevron-down' : 'mdi-chevron-right'" />
        <span class="pem-label">{{ label }}</span>
        <span class="pem-meta">
          {{ blockTypes.join(', ') || 'pem' }} · {{ lineCount }} lines
        </span>
      </button>
      <div class="pem-actions">
        <UiCopyButton :value="pem" icon label="Copy PEM" />
        <button class="btn btn-icon btn-icon-muted" title="Download" @click="downloadPem">
          <span class="mdi mdi-download" />
        </button>
      </div>
    </div>
    <pre v-if="open" class="code-block code-block-sm">{{ pem.trim() }}</pre>
  </div>
</template>

<style scoped>
.pem-viewer {
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  overflow: hidden;
  background: var(--bg-primary);
}
.pem-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 10px 8px 6px;
  background: var(--bg-tertiary);
}
.pem-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  border: none;
  background: transparent;
  cursor: pointer;
  font-family: inherit;
  color: var(--text-primary);
  font-size: 13px;
  min-width: 0;
  padding: 2px 4px;
}
.pem-toggle .mdi { color: var(--text-muted); font-size: 16px; }
.pem-label { font-weight: 600; }
.pem-meta { color: var(--text-muted); font-size: 12px; }
.pem-actions { display: flex; gap: 2px; flex-shrink: 0; }
.code-block { border: none; border-radius: 0; max-height: 340px; overflow-y: auto; }
</style>
