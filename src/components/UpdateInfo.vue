<!-- UpdateInfo.vue -->
<template>
  <div v-if="visible" class="update-info-container" :class="statusClass">
    <div class="update-content">
      <!-- 状态图标 -->
      <div class="status-icon">
        <template v-if="status === 'checking'">
          <el-icon class="icon-loading">
            <Loading />
          </el-icon>
        </template>
        <template v-else-if="status === 'downloading'">
          <el-icon class="icon-downloading">
            <Download />
          </el-icon>
        </template>
        <template v-else-if="status === 'downloaded'">
          <el-icon class="icon-success">
            <CircleCheck />
          </el-icon>
        </template>
        <template v-else-if="status === 'error'">
          <el-icon class="icon-error">
            <CircleClose />
          </el-icon>
        </template>
      </div>

      <!-- 消息和进度 -->
      <div class="update-details">
        <div class="update-message">{{ message }}</div>
        
        <div v-if="status === 'downloading'" class="progress-section">
          <el-progress 
            :percentage="progress" 
            :stroke-width="6"
            :color="progressColor"
            :show-text="false"
          />
          <span class="progress-text">{{ progress }}%</span>
        </div>
        
        <div v-if="status === 'downloaded'" class="action-buttons">
          <el-button 
            type="primary" 
            size="small" 
            @click="handleInstall"
            class="install-btn"
          >
            立即重启安装
          </el-button>
          <el-button 
            type="info" 
            size="small" 
            @click="handleLater"
            class="later-btn"
          >
            稍后
          </el-button>
        </div>
      </div>

      <!-- 关闭按钮 -->
      <el-button 
        v-if="showClose" 
        type="text" 
        class="close-btn"
        @click="handleClose"
      >
        <el-icon><Close /></el-icon>
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { 
  Loading, 
  Download, 
  CircleCheck, 
  CircleClose,
  Close 
} from '@element-plus/icons-vue'
import { ElMessage, ElIcon, ElProgress, ElButton } from 'element-plus'

// 组件属性
interface Props {
  autoCloseDelay?: number // 自动关闭延迟（毫秒）
}

const props = withDefaults(defineProps<Props>(), {
  autoCloseDelay: 3000
})

// 组件事件
const emit = defineEmits<{
  install: []
  close: []
}>()

// 响应式状态
const visible = ref(false)
const status = ref<'checking' | 'downloading' | 'downloaded' | 'error'>('checking')
const message = ref('')
const progress = ref(0)
const showClose = ref(false)

// 计算属性
const progressColor = computed(() => {
  if (progress.value < 30) return '#e6a23c'
  if (progress.value < 70) return '#409eff'
  return '#67c23a'
})

const statusClass = computed(() => {
  return `status-${status.value}`
})

// 自动关闭定时器
let autoCloseTimer: NodeJS.Timeout | null = null

// 方法
const setStatus = (
  newStatus: 'checking' | 'downloading' | 'downloaded' | 'error',
  newMessage: string,
  newProgress?: number
) => {
  visible.value = true
  status.value = newStatus
  message.value = newMessage
  
  if (newProgress !== undefined) {
    progress.value = newProgress
  }
  
  // 根据状态设置是否显示关闭按钮
  showClose.value = newStatus === 'error' || newStatus === 'downloaded'
  
  // 设置自动关闭
  setupAutoClose(newStatus)
}

const setupAutoClose = (currentStatus: string) => {
  if (autoCloseTimer) {
    clearTimeout(autoCloseTimer)
    autoCloseTimer = null
  }
  
  // 某些状态不需要自动关闭
  if (currentStatus === 'error' || currentStatus === 'downloaded') {
    return
  }
  
  // 检查更新和没有更新的情况自动关闭
  autoCloseTimer = setTimeout(() => {
    visible.value = false
  }, props.autoCloseDelay)
}

const handleInstall = () => {
  emit('install')
  visible.value = false
}

const handleLater = () => {
  visible.value = false
}

const handleClose = () => {
  visible.value = false
  emit('close')
}

// IPC事件监听
onMounted(() => {
  // 检查更新中
  window.ipcRenderer.on('update-checking', () => {
    setStatus('checking', '正在检查更新...')
  })

  // 更新可用
  window.ipcRenderer.on('update-available', () => {
    setStatus('downloading', '发现新版本，正在下载...', 0)
  })

  // 没有更新
  window.ipcRenderer.on('update-not-available', () => {
    setStatus('checking', '当前已是最新版本')
  })

  // 下载进度
  window.ipcRenderer.on('update-download-progress', (_event, data) => {
    const percent = Math.round(data.percent)
    setStatus('downloading', `正在下载更新 ${percent}%`, percent)
  })

  // 下载完成
  window.ipcRenderer.on('update-downloaded', () => {
    setStatus('downloaded', '更新下载完成，准备安装')
  })

  // 更新错误
  window.ipcRenderer.on('update-error', (_event, error) => {
    setStatus('error', `更新失败: ${error}`)
    ElMessage({
      message: `更新失败: ${error}`,
      type: 'error',
      duration: 5000
    })
  })
})

onUnmounted(() => {
  // 清理监听器
  const events = [
    'update-checking',
    'update-available',
    'update-not-available',
    'update-download-progress',
    'update-downloaded',
    'update-error'
  ]
  
  events.forEach(event => {
    window.ipcRenderer?.removeAllListeners(event)
  })
  
  // 清理定时器
  if (autoCloseTimer) {
    clearTimeout(autoCloseTimer)
  }
})
</script>

<style scoped>
.update-info-container {
  position: fixed;
  top: 20px;
  right: 20px;
  width: 320px;
  background-color: var(--el-bg-color);
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  z-index: 9999;
  overflow: hidden;
  border: 1px solid var(--el-border-color);
  animation: slideIn 0.3s ease;
}

@keyframes slideIn {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

.update-content {
  display: flex;
  align-items: center;
  padding: 16px;
  gap: 12px;
}

.status-icon {
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-loading {
  color: var(--el-color-warning);
  animation: rotate 2s linear infinite;
}

.icon-downloading {
  color: var(--el-color-info);
}

.icon-success {
  color: var(--el-color-success);
}

.icon-error {
  color: var(--el-color-danger);
}

@keyframes rotate {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.update-details {
  flex: 1;
  min-width: 0;
}

.update-message {
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 8px;
  line-height: 1.4;
  color: var(--el-text-color-primary);
}

.progress-section {
  display: flex;
  align-items: center;
  gap: 12px;
}

.progress-section .el-progress {
  flex: 1;
  margin: 4px 0;
}

.progress-text {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  min-width: 36px;
  text-align: right;
}

.action-buttons {
  display: flex;
  gap: 8px;
  margin-top: 8px;
}

.install-btn {
  background: linear-gradient(135deg, var(--el-color-primary), var(--el-color-primary-light-3));
  border: none;
  color: var(--el-color-white);
}

.install-btn:hover {
  background: linear-gradient(135deg, var(--el-color-primary-light-3), var(--el-color-primary));
}

.later-btn {
  border-color: var(--el-border-color);
  color: var(--el-text-color-regular);
}

.later-btn:hover {
  border-color: var(--el-color-primary);
  color: var(--el-color-primary);
}

.close-btn {
  margin-left: auto;
  padding: 0;
  width: 24px;
  height: 24px;
  color: var(--el-text-color-secondary);
  background: transparent;
  border: none;
}

.close-btn:hover {
  color: var(--el-text-color-primary);
}

/* 状态边框样式 */
.status-checking {
  border-left: 4px solid var(--el-color-warning);
}

.status-downloading {
  border-left: 4px solid var(--el-color-info);
}

.status-downloaded {
  border-left: 4px solid var(--el-color-success);
}

.status-error {
  border-left: 4px solid var(--el-color-danger);
}
</style>