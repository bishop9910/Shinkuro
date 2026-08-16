# Shinkuro 保险柜

一个本地加密保险柜：文件以 **AES-256-GCM** 加密存储，界面负责交互，底层加解密、压缩与密钥管理全部由 **C++17** 完成，主打效率与安全。

> 每个保险柜 = 一个 `.vault` 加密容器 + 一个 `.vault.idx` 加密索引，两者强绑定，缺一不可。

## ✨ 特性

- **创建 / 打开保险柜**：`.vault`（加密容器）与 `.vault.idx`（加密索引）成对生成、强绑定。
- **浏览文件**：文件名、大小、修改时间一目了然。
- **双击打开**：双击任意文件，后台解密到系统临时目录后用系统默认程序打开。
- **提取文件**：把任意文件解密导出到你指定的位置（另存为）。
- **修改密码**：逐块重新加密，改密后旧密码立即失效，无需重新导入文件。
- **防误删**：保险柜打开期间锁定 `.vault` / `.idx`，用户删不掉正在使用的保险柜。
- **增容 / 缩水**：添加文件追加加密块使容器变大；删除文件重写容器、紧排剩余数据使其真正变小。
- **关闭即清除**：锁定、关窗或退出时，密钥 / 索引 / 临时明文全部在内存与磁盘上被清除。
- **亮暗主题**：外观主题持久化到 `config.json`。
- **中文路径 / 文件名**：完整支持中文目录与中文文件名。

## 🧰 技术栈

| 层 | 技术 |
|----|------|
| 界面 | Vue 3 + Element Plus + Tailwind CSS v4 |
| 桌面壳 | Electron + vite-plugin-electron |
| 加密引擎 | C++17 + OpenSSL（AES-256-GCM / PBKDF2-HMAC-SHA256 / HKDF） |

## 📁 目录结构

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
│ ├─┬ src/
│ │ ├── main.cpp           JSON-RPC 入口（stdin/stdout）
│ │ ├── vault.cpp / vault.hpp
│ │ │                      保险柜引擎（加解密、压缩、改密、删除锁）
│ │ ├── crypto.cpp / crypto.hpp
│ │ │                      OpenSSL 封装（AES-256-GCM / PBKDF2 / HKDF）
│ │ ├── json.hpp           自研 JSON 解析器
│ │ └── util.hpp           工具（hex / UTF-8 路径 / 常量时间比较）
│ ├── build.bat            编译脚本（MinGW-w64）
│ ├── build.sh             编译脚本（MSYS2 bash）
│ └── README.md            后端文件格式 / RPC 协议文档
├── electron-builder.json5  打包配置
└── package.json
```

## 🧱 环境要求

- **Node.js**（推荐 18+）
- **g++（MinGW-w64）** + **OpenSSL（libcrypto，需静态库）**

  ```sh
  # MSYS2
  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
  ```

  > 后端只用 OpenSSL 一个第三方库，JSON 解析器已自研内置（`cpp_backend/src/json.hpp`）。更多细节见 [cpp_backend/README.md](cpp_backend/README.md)。

## 🚀 快速开始

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

## 🖱️ 使用说明

1. **创建保险柜**：首页点「创建保险柜」→ 选择保存位置 → 设置密码。
2. **打开保险柜**：首页点「打开保险柜」→ 选择 `.vault` 文件 → 输入密码。
3. **添加文件**：打开后点「添加文件」，可多选。程序会自动拦截把保险柜自身（`.vault` / `.vault.idx`）添加进去。
4. **打开 / 提取文件**：双击文件名用系统程序打开；或点「提取」另存到指定位置。
5. **修改密码**：点「修改密码」，输入当前密码和新密码。
6. **锁定**：点「锁定」或直接关窗，敏感信息即刻清除。

## 📦 打包发布

```sh
# 编译后端
npm run build:backend

# 类型检查 + 构建前端 + electron-builder 打包
npm run build
```

产物位于 `release/<version>/`，例如 `Shinkuro-Windows-<version>-Setup.exe`。

> 后端用 `-static` 静态编译，`libstdc++` / `libgcc` / `winpthread` / `libcrypto` 全部打进 exe。

## 🔐 安全设计

- **内容加密**：AES-256-GCM 认证加密（防篡改），每个文件块独立随机 nonce。
- **密钥派生**：`PBKDF2-HMAC-SHA256(600000 轮)` 派生主密钥，再经 `HKDF-SHA256` 分离出「索引密钥」与「内容密钥」。
- **强绑定**：`.vault` 与 `.vault.idx` 通过随机 `pair_token` 互相校验，替换任一文件都会导致校验失败。
- **关闭即清除**：锁定/退出时用 `OPENSSL_cleanse` 清零内存密钥，并覆写删除临时明文文件。
- **防误删**：打开期间持有文件句柄且不共享删除权限，防止删除正在使用的保险柜文件。

完整的文件格式与 RPC 协议见 [cpp_backend/README.md](cpp_backend/README.md)。

## 📄 License

[MIT](LICENSE)
