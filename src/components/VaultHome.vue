<script setup lang="ts">
import { ref } from 'vue'
import { ElButton, ElDialog, ElForm, ElFormItem, ElInput, ElMessage } from 'element-plus'
import { FolderAdd, FolderOpened, Lock } from '@element-plus/icons-vue'
import { createVault, openVault, pickOpen, pickSave } from '../scripts/ipc/vault'
import SettingsDialog from './SettingsDialog.vue'

const emit = defineEmits<{ opened: [path: string] }>()

const busy = ref(false)

// create dialog
const createVisible = ref(false)
const createPath = ref('')
const createPassword = ref('')
const createConfirm = ref('')

// open dialog
const openVisible = ref(false)
const openPath = ref('')
const openPassword = ref('')

async function onNewVault() {
  const p = await pickSave()
  if (!p) return
  createPath.value = p
  createPassword.value = ''
  createConfirm.value = ''
  createVisible.value = true
}

async function onOpenVault() {
  const p = await pickOpen()
  if (!p) return
  openPath.value = p
  openPassword.value = ''
  openVisible.value = true
}

async function submitCreate() {
  if (!createPassword.value) {
    ElMessage.warning('请输入密码')
    return
  }
  if (createPassword.value !== createConfirm.value) {
    ElMessage.warning('两次输入的密码不一致')
    return
  }
  busy.value = true
  try {
    const r = await createVault(createPath.value, createPassword.value)
    createVisible.value = false
    ElMessage.success('保险柜创建成功')
    emit('opened', r.path)
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '创建失败')
  } finally {
    busy.value = false
    createPassword.value = ''
    createConfirm.value = ''
  }
}

async function submitOpen() {
  if (!openPassword.value) {
    ElMessage.warning('请输入密码')
    return
  }
  busy.value = true
  try {
    const r = await openVault(openPath.value, openPassword.value)
    openVisible.value = false
    ElMessage.success('保险柜已打开')
    emit('opened', r.path)
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '打开失败')
  } finally {
    busy.value = false
    openPassword.value = ''
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center p-6">
    <div class="fixed right-5 top-5 z-10">
      <SettingsDialog />
    </div>
    <div class="w-full max-w-md">
      <div class="mb-8 text-center">
        <div
          class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-linear-to-br from-pink-300 to-indigo-400 text-white shadow-lg"
        >
          <el-icon :size="34"><Lock /></el-icon>
        </div>
        <h1 class="text-2xl font-bold">Shinkuro 保险柜</h1>
      </div>

      <div class="space-y-3 rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-900">
        <el-button
          type="primary"
          size="large"
          class="w-full"
          :icon="FolderAdd"
          @click="onNewVault"
        >
          创建保险柜
        </el-button>
        <br>
        <el-button
          size="large"
          class="w-full"
          :icon="FolderOpened"
          @click="onOpenVault"
        >
          打开保险柜
        </el-button>
      </div>

      <p class="mt-6 text-center text-xs text-gray-400 dark:text-gray-500">
        保险柜由 <span class="font-mono">.vault</span> 与 <span class="font-mono">.vault.idx</span> 两个强绑定文件组成，缺少任意一个都无法使用
      </p>
    </div>

    <!-- 创建对话框 -->
    <el-dialog v-model="createVisible" title="创建保险柜" width="440px" append-to-body>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="保存位置">
          <el-input :model-value="createPath" readonly />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="createPassword"
            type="password"
            show-password
            placeholder="设置保险柜密码"
            @keyup.enter="submitCreate"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="createConfirm"
            type="password"
            show-password
            placeholder="再次输入密码"
            @keyup.enter="submitCreate"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 打开对话框 -->
    <el-dialog v-model="openVisible" title="打开保险柜" width="440px" append-to-body>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="保险柜文件">
          <el-input :model-value="openPath" readonly />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="openPassword"
            type="password"
            show-password
            placeholder="输入保险柜密码"
            @keyup.enter="submitOpen"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="openVisible = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="submitOpen">打开</el-button>
      </template>
    </el-dialog>
  </div>
</template>
