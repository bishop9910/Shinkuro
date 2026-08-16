<script setup lang="ts">
import { onMounted, ref } from 'vue'
import VaultHome from './components/VaultHome.vue'
import VaultBrowser from './components/VaultBrowser.vue'
import { isOpen } from './scripts/ipc/vault'
import { GetConfigSafe } from './scripts/ipc/config'
import { applyTheme } from './scripts/theme'

const vaultOpen = ref(false)
const vaultPath = ref('')

onMounted(async () => {
  // 恢复上次保存的主题
  try {
    const config = await GetConfigSafe()
    applyTheme(config?.theme === 'dark' ? 'dark' : 'light')
  } catch {
    applyTheme('light')
  }

  // 恢复保险柜打开状态
  try {
    const state = await isOpen()
    vaultOpen.value = state.open
  } catch {
    vaultOpen.value = false
  }
})

function onOpened(path: string) {
  vaultPath.value = path
  vaultOpen.value = true
}

function onLocked() {
  vaultPath.value = ''
  vaultOpen.value = false
}
</script>

<template>
  <div class="min-h-screen bg-gray-100 text-gray-800 dark:bg-gray-950 dark:text-gray-200">
    <VaultHome v-if="!vaultOpen" @opened="onOpened" />
    <VaultBrowser v-else :path="vaultPath" @locked="onLocked" />
  </div>
</template>
