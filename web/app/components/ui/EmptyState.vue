<script setup lang="ts">
withDefaults(defineProps<{
  icon?: string
  title: string
  message?: string
}>(), { icon: 'inbox-outline' })
</script>

<template>
  <div class="empty-state">
    <div class="empty-icon mdi" :class="`mdi-${icon}`" />
    <h3>{{ title }}</h3>
    <p v-if="message">{{ message }}</p>
    <slot />
  </div>
</template>
