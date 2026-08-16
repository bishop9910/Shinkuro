<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElButton, ElDialog, ElIcon, ElRadioButton, ElRadioGroup } from 'element-plus'
import { Moon, Setting, Sunny } from '@element-plus/icons-vue'
import type { Config } from '../../type'
import { EditConfig, GetConfigSafe } from '../scripts/ipc/config'
import { applyTheme } from '../scripts/theme'

const visible = ref(false)
const theme = ref<'light' | 'dark'>('light')

async function loadConfig() {
  try {
    const c = await GetConfigSafe()
    if (c) {
      theme.value = c.theme === 'dark' ? 'dark' : 'light'
      applyTheme(theme.value)
    }
  } catch {
    /* ignore */
  }
}

function save() {
  const config: Config = { theme: theme.value }
  EditConfig(config)
  applyTheme(theme.value)
}

function onThemeChange(val: string | number | boolean | undefined) {
  theme.value = val === 'dark' ? 'dark' : 'light'
  save()
}

onMounted(loadConfig)
</script>

<template>
  <el-button :icon="Setting" circle title="设置" aria-label="设置" @click="visible = true" />

  <el-dialog v-model="visible" title="设置" width="420px" append-to-body>
    <div class="py-1">
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

    <template #footer>
      <el-button @click="visible = false">关闭</el-button>
    </template>
  </el-dialog>
</template>
