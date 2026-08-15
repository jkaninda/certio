<script setup lang="ts">
import { computed, ref } from 'vue'
import type { SAN, SANType } from '~/types/api'

const props = withDefaults(defineProps<{
  modelValue: SAN[]
  /** Folded into the DNS names automatically, mirroring what the backend does. */
  commonName?: string
}>(), { commonName: '' })

const emit = defineEmits<{ 'update:modelValue': [value: SAN[]] }>()

const draft = ref('')
const error = ref('')
const bulkOpen = ref(false)
const bulkText = ref('')

/**
 * detectType mirrors pki.DetectSANType so a chip shows the same type the
 * server will assign. Getting this wrong would mean the preview lies.
 */
function detectType(value: string): SANType {
  if (isIP(value)) return 'ip'
  if (value.includes('://')) return 'uri'
  if (value.includes('@')) return 'email'
  return 'dns'
}

function isIP(value: string): boolean {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255)
  }
  // IPv6: loose but sufficient to distinguish it from a hostname.
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(':')
}

/** parseEntry accepts an explicit "type:value" prefix or infers the type. */
function parseEntry(raw: string): SAN | null {
  const trimmed = raw.trim()
  if (!trimmed) return null

  const separator = trimmed.indexOf(':')
  if (separator > 0) {
    const prefix = trimmed.slice(0, separator).toLowerCase()
    if (['dns', 'ip', 'email', 'uri'].includes(prefix)) {
      return { type: prefix as SANType, value: trimmed.slice(separator + 1).trim() }
    }
  }
  return { type: detectType(trimmed), value: trimmed }
}

/**
 * validate mirrors the server's rules so a bad entry is caught before the
 * request, not after. The wildcard rule is the one people get wrong.
 */
function validate(san: SAN): string {
  if (!san.value) return 'the value is empty'

  switch (san.type) {
    case 'ip':
      return isIP(san.value) ? '' : `${san.value} is not a valid IP address`
    case 'email':
      return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(san.value) ? '' : `${san.value} is not a valid email address`
    case 'uri':
      return san.value.includes('://') ? '' : 'a URI SAN must be absolute, e.g. spiffe://cluster/ns/default'
    case 'dns': {
      const labels = san.value.split('.')
      if (san.value.length > 253) return 'the DNS name is longer than 253 characters'
      for (const [index, label] of labels.entries()) {
        if (!label) return 'the DNS name has an empty label'
        if (label.length > 63) return 'a DNS label is longer than 63 characters'
        if (label.includes('*')) {
          if (index !== 0) return 'a wildcard must be the leftmost label'
          if (label !== '*') return 'a wildcard label must be exactly "*" — browsers reject partial wildcards'
          if (labels.length < 3) return 'a wildcard must cover a subdomain, e.g. *.example.com'
          continue
        }
        if (!/^[A-Za-z0-9_-]+$/.test(label)) return `${san.value} contains an invalid character`
        if (label.startsWith('-') || label.endsWith('-')) return 'a DNS label may not start or end with "-"'
      }
      return ''
    }
    default:
      return ''
  }
}

function exists(san: SAN): boolean {
  return props.modelValue.some(
    (entry) => entry.type === san.type && entry.value.toLowerCase() === san.value.toLowerCase(),
  )
}

function add(raw: string): boolean {
  const san = parseEntry(raw)
  if (!san) return false

  const problem = validate(san)
  if (problem) {
    error.value = problem
    return false
  }
  if (exists(san)) {
    error.value = `${san.value} is already in the list`
    return false
  }

  emit('update:modelValue', [...props.modelValue, san])
  error.value = ''
  return true
}

function commitDraft() {
  if (add(draft.value)) draft.value = ''
}

function remove(index: number) {
  const next = [...props.modelValue]
  next.splice(index, 1)
  emit('update:modelValue', next)
  error.value = ''
}

function onBackspace() {
  // Backspace on an empty input removes the previous chip, the way every tag
  // input people already know behaves.
  if (draft.value === '' && props.modelValue.length > 0) {
    remove(props.modelValue.length - 1)
  }
}

function onPaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData('text') ?? ''
  if (!/[\n,;\s]/.test(text.trim())) return

  event.preventDefault()
  for (const part of text.split(/[\n,;\s]+/)) {
    if (part.trim()) add(part)
  }
}

function applyBulk() {
  let added = 0
  for (const part of bulkText.value.split(/[\n,;\s]+/)) {
    if (part.trim() && add(part)) added++
  }
  bulkText.value = ''
  bulkOpen.value = false
  if (added === 0) error.value = error.value || 'nothing new was added'
}

/** The CN is added to the DNS names by the backend; showing it makes that visible. */
const impliedCommonName = computed(() => {
  const cn = props.commonName.trim()
  if (!cn) return null
  if (validate({ type: 'dns', value: cn })) return null
  if (exists({ type: 'dns', value: cn })) return null
  return cn
})

function acceptImplied() {
  if (impliedCommonName.value) add(`dns:${impliedCommonName.value}`)
}
</script>

<template>
  <div class="san-input">
    <div class="chip-input" @click="($refs.field as HTMLInputElement)?.focus()">
      <span v-for="(san, index) in modelValue" :key="`${san.type}-${san.value}`" class="chip">
        <span class="chip-type">{{ san.type }}</span>
        <span class="chip-value">{{ san.value }}</span>
        <button class="chip-remove" type="button" :aria-label="`Remove ${san.value}`" @click.stop="remove(index)">
          <span class="mdi mdi-close" />
        </button>
      </span>

      <input
        ref="field"
        v-model="draft"
        type="text"
        :placeholder="modelValue.length ? 'Add another…' : 'api.example.com, *.example.com, 10.0.0.1, ops@example.com'"
        autocomplete="off"
        spellcheck="false"
        @keydown.enter.prevent="commitDraft"
        @keydown.tab="draft && (commitDraft(), $event.preventDefault())"
        @keydown.,.prevent="commitDraft"
        @keydown.delete="onBackspace"
        @paste="onPaste"
        @blur="commitDraft"
      >
    </div>

    <p v-if="error" class="form-error">{{ error }}</p>
    <p v-else class="form-hint">
      Press Enter or comma to add. The type is detected automatically —
      prefix with <code>dns:</code>, <code>ip:</code>, <code>email:</code> or <code>uri:</code> to force it.
    </p>

    <div class="san-actions">
      <button type="button" class="btn btn-ghost btn-xs" @click="bulkOpen = !bulkOpen">
        <span class="mdi mdi-format-list-bulleted" />
        Paste a list
      </button>
      <button
        v-if="impliedCommonName"
        type="button"
        class="btn btn-ghost btn-xs"
        @click="acceptImplied"
      >
        <span class="mdi mdi-plus" />
        Add {{ impliedCommonName }}
      </button>
    </div>

    <div v-if="bulkOpen" class="bulk-box">
      <textarea
        v-model="bulkText"
        class="form-textarea"
        rows="4"
        placeholder="One per line, or comma-separated:&#10;example.com&#10;*.example.com&#10;ip:10.0.0.1"
      />
      <div class="flex gap-2 justify-end mt-2">
        <button type="button" class="btn btn-secondary btn-sm" @click="bulkOpen = false">Cancel</button>
        <button type="button" class="btn btn-primary btn-sm" @click="applyBulk">Add all</button>
      </div>
    </div>

    <p v-if="!modelValue.length" class="san-warning">
      <span class="mdi mdi-alert-outline" />
      At least one SAN is required — modern clients ignore the Common Name entirely.
    </p>
  </div>
</template>

<style scoped>
.san-actions { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.bulk-box { margin-top: 10px; }
.san-warning {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 10px;
  font-size: 12.5px;
  color: var(--warning-600);
}
.form-hint code {
  background: var(--bg-tertiary);
  padding: 0 4px;
  border-radius: 3px;
  font-size: 11.5px;
}
</style>
