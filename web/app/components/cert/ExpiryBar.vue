<script setup lang="ts">
import { computed } from 'vue'
import type { Severity } from '~/types/api'

const props = defineProps<{
  notBefore: string
  notAfter: string
  daysRemaining: number
  severity: Severity
  /** Pre-computed by the API; recomputed here when absent. */
  percentElapsed?: number
}>()

const percent = computed(() => {
  if (props.percentElapsed !== undefined) return props.percentElapsed
  const start = new Date(props.notBefore).getTime()
  const end = new Date(props.notAfter).getTime()
  if (end <= start) return 100
  const elapsed = Date.now() - start
  return Math.min(100, Math.max(0, Math.round((elapsed / (end - start)) * 100)))
})
</script>

<template>
  <div class="expiry-bar" :class="`expiry-${severity}`" :title="`${percent}% of its lifetime elapsed`">
    <div class="expiry-bar-fill" :style="{ width: `${percent}%` }" />
  </div>
</template>
