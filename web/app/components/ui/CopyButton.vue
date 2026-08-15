<script setup lang="ts">
import { ref } from 'vue'

const props = withDefaults(defineProps<{
  value: string
  label?: string
  /** Renders as a bare icon rather than a labelled button. */
  icon?: boolean
}>(), { label: 'Copy', icon: false })

const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
  } catch {
    // navigator.clipboard needs a secure context. On plain HTTP — which a
    // private PKI dashboard often runs on before its own certificate is
    // installed — fall back to the legacy path rather than silently failing.
    const area = document.createElement('textarea')
    area.value = props.value
    area.style.position = 'fixed'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    document.execCommand('copy')
    area.remove()
  }
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <button
    class="btn btn-ghost"
    :class="icon ? 'btn-icon btn-icon-muted' : 'btn-xs'"
    :title="copied ? 'Copied' : label"
    :aria-label="label"
    @click.stop="copy"
  >
    <span class="mdi" :class="copied ? 'mdi-check' : 'mdi-content-copy'" />
    <span v-if="!icon">{{ copied ? 'Copied' : label }}</span>
  </button>
</template>
