<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  ElButton,
  ElIcon,
  ElMessage,
  ElMessageBox,
  ElTable,
  ElTableColumn,
  ElTooltip,
} from 'element-plus'
import { Delete, Document, FolderAdd, Lock } from '@element-plus/icons-vue'
import type { VaultEntry } from '../../type'
import { addFiles, deleteFile, listFiles, lockVault, openFile } from '../scripts/ipc/vault'
import SettingsDialog from './SettingsDialog.vue'

const props = defineProps<{ path: string }>()
const emit = defineEmits<{ locked: [] }>()

const files = ref<VaultEntry[]>([])

const vaultName = computed(() => {
  const p = props.path.replace(/\\/g, '/')
  return p.substring(p.lastIndexOf('/') + 1)
})

const totalSize = computed(() => files.value.reduce((sum, f) => sum + f.size, 0))

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = bytes
  let u = -1
  do {
    v /= 1024
    u++
  } while (v >= 1024 && u < units.length - 1)
  return `${v.toFixed(1)} ${units[u]}`
}

function formatTime(sec: number): string {
  if (!sec) return '-'
  return new Date(sec * 1000).toLocaleString('zh-CN')
}

async function load() {
  try {
    const list = await listFiles()
    files.value = list.files
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '读取文件列表失败')
  }
}

async function onAdd() {
  try {
    const r = await addFiles()
    if (r.errors.length) ElMessage.warning(`部分文件未添加：${r.errors.join('；')}`)
    if (r.added.length) ElMessage.success(`已添加 ${r.added.length} 个文件`)
    if (r.added.length || r.errors.length) await load()
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '添加失败')
  }
}

async function onOpen(name: string) {
  try {
    const r = await openFile(name)
    if (!r.opened && r.openError) {
      ElMessage.warning(`已解密，但系统未能自动打开：${r.openError}`)
    }
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '打开失败')
  }
}

function onRowDblClick(row: VaultEntry) {
  onOpen(row.name)
}

async function onDelete(name: string) {
  try {
    await ElMessageBox.confirm(
      `确定从保险柜中删除「${name}」吗？此操作不可撤销。`,
      '删除文件',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }
    )
  } catch {
    return
  }
  try {
    await deleteFile(name)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '删除失败')
  }
}

async function onLock() {
  try {
    await lockVault()
  } catch {
    /* ignore */
  }
  files.value = []
  emit('locked')
}

onMounted(load)
</script>

<template>
  <div class="mx-auto flex min-h-screen max-w-5xl flex-col gap-4 p-6">
    <!-- 顶部栏 -->
    <header
      class="flex items-center justify-between gap-3 rounded-2xl border border-gray-200 bg-white px-5 py-4 shadow-sm dark:border-gray-700 dark:bg-gray-900"
    >
      <div class="flex min-w-0 items-center gap-3">
        <div
          class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-linear-to-br from-pink-300 to-indigo-400 text-white"
        >
          <el-icon :size="22"><Lock /></el-icon>
        </div>
        <div class="min-w-0">
          <div class="truncate text-base font-semibold leading-tight">{{ vaultName }}</div>
          <el-tooltip :content="path" placement="bottom">
            <span class="block truncate text-xs text-gray-400 dark:text-gray-500">{{ path }}</span>
          </el-tooltip>
        </div>
      </div>
      <div class="flex shrink-0 items-center gap-2">
        <el-button type="primary" :icon="FolderAdd" @click="onAdd">添加文件</el-button>
        <el-button :icon="Lock" @click="onLock">锁定</el-button>
        <SettingsDialog />
      </div>
    </header>

    <!-- 统计 -->
    <div class="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
      <span>共 {{ files.length }} 个文件</span>
      <span>占用 {{ formatSize(totalSize) }}</span>
    </div>

    <!-- 文件表 -->
    <div
      class="flex-1 overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-900"
    >
      <el-table
        :data="files"
        empty-text="保险柜是空的，点击右上角「添加文件」"
        row-key="name"
        @row-dblclick="onRowDblClick"
      >
        <el-table-column label="文件名" min-width="240">
          <template #default="{ row }">
            <div class="flex items-center gap-2">
              <el-icon class="text-gray-400"><Document /></el-icon>
              <span class="truncate">{{ row.name }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="120" align="right">
          <template #default="{ row }">{{ formatSize(row.size) }}</template>
        </el-table-column>
        <el-table-column label="修改时间" width="180">
          <template #default="{ row }">{{ formatTime(row.mtime) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="140" align="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="onOpen(row.name)">打开</el-button>
            <el-button link type="danger" size="small" :icon="Delete" @click="onDelete(row.name)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <p class="text-center text-xs text-gray-400 dark:text-gray-500">
      双击文件即可解密并用系统默认程序打开，锁定后临时明文会被彻底清除
    </p>
  </div>
</template>
