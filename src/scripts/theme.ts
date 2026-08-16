export type Theme = 'light' | 'dark'

// 切换 <html> 上的 .dark 类，驱动 Tailwind 与 Element Plus 的暗色主题
export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark')
}
