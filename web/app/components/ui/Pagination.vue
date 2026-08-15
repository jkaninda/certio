<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  page: number
  limit: number
  total: number
  totalPages: number
}>()

const emit = defineEmits<{ 'update:page': [value: number] }>()

const from = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.limit + 1))
const to = computed(() => Math.min(props.page * props.limit, props.total))
</script>

<template>
  <div v-if="total > 0" class="pagination">
    <span class="pagination-info">
      Showing {{ from }}–{{ to }} of {{ total }}
    </span>
    <div class="pagination-buttons">
      <button
        class="btn btn-secondary btn-sm"
        :disabled="page <= 1"
        @click="emit('update:page', page - 1)"
      >
        <span class="mdi mdi-chevron-left" />
        Previous
      </button>
      <button
        class="btn btn-secondary btn-sm"
        :disabled="page >= totalPages"
        @click="emit('update:page', page + 1)"
      >
        Next
        <span class="mdi mdi-chevron-right" />
      </button>
    </div>
  </div>
</template>
