<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  ElButton,
  ElDialog,
  ElIcon,
  ElRadioButton,
  ElRadioGroup,
  ElSwitch,
} from 'element-plus'
import { Moon, Setting, Sunny } from '@element-plus/icons-vue'
import type { Config } from '../../type'
import { EditConfig, GetConfigSafe } from '../scripts/ipc/config'
import { applyTheme } from '../scripts/theme'

const visible = ref(false)
const theme = ref<'light' | 'dark'>('light')
const autoUpdate = ref(false)

async function loadConfig() {
  try {
    const c = await GetConfigSafe()
    if (c) {
      theme.value = c.theme === 'dark' ? 'dark' : 'light'
      autoUpdate.value = !!c.autoUpdate
      applyTheme(theme.value)
    }
  } catch {
    /* ignore */
  }
}

function save() {
  const config: Config = { theme: theme.value, autoUpdate: autoUpdate.value }
  EditConfig(config)
  applyTheme(theme.value)
}

function onThemeChange(val: string | number | boolean | undefined) {
  theme.value = val === 'dark' ? 'dark' : 'light'
  save()
}

function onAutoChange(val: string | number | boolean | undefined) {
  autoUpdate.value = !!val
  save()
}

onMounted(loadConfig)
</script>

<template>
  <el-button :icon="Setting" circle title="设置" aria-label="设置" @click="visible = true" />

  <el-dialog v-model="visible" title="设置" width="420px" append-to-body>
    <div class="space-y-6 py-1">
      <div>
        <div class="mb-3 text-sm font-medium text-gray-700 dark:text-gray-300">外观主题</div>
        <el-radio-group :model-value="theme" @change="onThemeChange">
          <el-radio-button value="light">
            <el-icon class="mr-1"><Sunny /></el-icon>亮色
          </el-radio-button>
          <el-radio-button value="dark">
            <el-icon class="mr-1"><Moon /></el-icon>暗色
          </el-radio-button>
        </el-radio-group>
      </div>

      <div class="flex items-center justify-between">
        <div>
          <div class="text-sm font-medium text-gray-700 dark:text-gray-300">自动更新</div>
          <div class="mt-0.5 text-xs text-gray-400 dark:text-gray-500">发布新版本时自动下载更新</div>
        </div>
        <el-switch :model-value="autoUpdate" @change="onAutoChange" />
      </div>
    </div>

    <template #footer>
      <el-button @click="visible = false">关闭</el-button>
    </template>
  </el-dialog>
</template>
