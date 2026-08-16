# Shinkuro 保险柜

一个本地加密保险柜软件：文件以 **AES-256-GCM** 加密存储，前端负责交互，底层加解密与压缩全部由 **C++17** 完成，主打效率与安全。

## 特性

- **创建 / 打开保险柜**：每个保险柜由 `.vault`（加密容器）和 `.vault.idx`（加密索引）两个强绑定文件组成。
- **浏览文件**：文件列表、大小、修改时间一目了然。
- **双击调用系统程序打开**：双击任意文件，后台解密到系统临时目录后交给系统默认程序打开。
- **提取文件**：可把任意文件解密提取到指定位置。
- **修改密码**：可修改保险柜密码（逐块重新加密，无需重新导入文件）。
- **防误删**：保险柜打开期间锁定 `.vault` / `.idx`，用户删除不掉。
- **增容 / 缩水**：添加文件会追加加密块使保险柜变大；删除文件会重写容器、紧排剩余数据使其真正变小。
- **关闭即清除**：锁定、关窗或退出时，密钥 / 索引 / 临时明文全部在内存与磁盘上被清除。
- **亮暗主题**：外观主题持久化到 `config.json`。

## 技术栈

| 层 | 技术 |
|----|------|
| 界面 | Vue 3 + Element Plus + Tailwind CSS v4 |
| 桌面壳 | Electron + vite-plugin-electron |
| 加密引擎 | C++17 + OpenSSL（AES-256-GCM / PBKDF2 / HKDF） |

## 目录结构

```
├─┬ electron
│ ├─┬ main                 Electron 主进程
│ │ ├── index.ts           入口（窗口 / IPC / 生命周期）
│ │ ├── vault.ts           保险柜后端进程管理与 JSON-RPC 客户端
│ │ ├── config.ts          配置读写
│ │ ├── theme.ts           亮暗主题
│ │ └── ...                其余主进程脚本
│ └─┬ preload
│   └── index.ts           预加载脚本（暴露 window.ipcRenderer）
├─┬ src
│ ├─┬ components
│ │ ├── VaultHome.vue      保险柜创建 / 打开页
│ │ ├── VaultBrowser.vue   保险柜文件浏览页
│ │ └── SettingsDialog.vue 设置（主题）
│ ├─┬ scripts
│ │ ├── ipc/               IPC 封装（vault / config ...）
│ │ └── theme.ts           渲染层主题切换
│ ├── App.vue              根组件
│ └── main.ts              渲染进程入口
├─┬ cpp_backend            C++ 加密后端（详见其 README）
│ ├── src/                 main.cpp / vault.cpp / crypto.cpp / json.hpp ...
│ ├── build.bat            编译脚本（MinGW-w64）
│ └── build.sh
├── electron-builder.json5  打包配置
└── package.json
```

## 环境要求

- **Node.js**（推荐 18+）
- **g++（MinGW-w64）** + **OpenSSL（libcrypto）**

  ```sh
  # MSYS2
  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
  ```

  > 后端只需 OpenSSL 一个第三方库，JSON 解析器已自研内置。更多细节见 [cpp_backend/README.md](cpp_backend/README.md)。

## 快速开始

```sh
# 1. 克隆
git clone https://github.com/bishop9910/Shinkuro.git
cd Shinkuro

# 2. 编译 C++ 加密后端（产出 cpp_backend/build/vault_backend.exe，静态编译无 DLL 依赖）
npm run build:backend

# 3. 安装依赖
npm install

# 4. 开发运行
npm run dev
```

> `npm run build:backend` 可从任意目录调用，脚本内部会自动切换到自身目录。

## 打包发布

```sh
# 编译后端
npm run build:backend

# 类型检查 + 构建前端 + electron-builder 打包
npm run build
```

产物位于 `release/<version>/`，例如 `Shinkuro-Windows-<version>-Setup.exe`。

## 安全说明

- 内容加密采用 **AES-256-GCM**（认证加密，防篡改），每个文件独立随机 nonce。
- 密钥派生：`PBKDF2-HMAC-SHA256(600000 轮)` → `HKDF-SHA256` 分离索引密钥与内容密钥。
- `.vault` 与 `.vault.idx` 通过随机 `pair_token` 强绑定，替换任一文件都会导致校验失败。
- 锁定 / 退出时用 `OPENSSL_cleanse` 清零内存中的密钥，并覆写删除临时明文文件。

完整的文件格式与 RPC 协议见 [cpp_backend/README.md](cpp_backend/README.md)。

## License

[MIT](LICENSE)
