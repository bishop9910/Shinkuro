# Shinkuro Vault Backend (C++17)

独立进程实现的加密保险柜引擎。Electron 主进程通过 **换行分隔的 JSON-RPC**（stdin/stdout）
与它通信，文件内容在 C++ 层完成 AES-256-GCM 加解密与压缩/扩容，前端不直接接触明文。

## 依赖（唯一需要安装的第三方库）

| 依赖 | 用途 | 安装方式（MinGW-w64 / MSYS2） |
|------|------|------------------------------|
| **OpenSSL (libcrypto)** | AES-256-GCM、PBKDF2-HMAC-SHA256、HKDF、安全随机数 | `pacman -S mingw-w64-x86_64-openssl` |
| g++ (MinGW-w64) | 编译 | `pacman -S mingw-w64-x86_64-gcc` |

> JSON 解析器已自研内置（`src/json.hpp`），无其他第三方依赖。

## 编译

```bat
cd cpp_backend
build.bat            REM 发布版 ( -O2 )
build.bat debug      REM 调试版 ( -O0 -g )
```

产出：`cpp_backend/build/vault_backend.exe`。使用 `-static` 静态编译，libstdc++ /
libgcc / winpthread / libcrypto 全部链接进 exe，**无需任何额外的运行时 DLL**，
拷贝到任意机器都能直接启动（不会再出现 `0xC0000135 DLL 缺失`）。

- 需要 OpenSSL 的**静态库**（标准 `mingw-w64-*-openssl` 包已包含 `libcrypto.a`）。
- 若链接报 `std::filesystem` 符号缺失（g++ < 9），在命令行末尾追加 `-lstdc++fs`。

## 文件格式

每个保险柜由 **两个强绑定的文件** 组成，创建时自动生成在 `.vault` 旁边：

```
我的保险柜.vault       加密内容容器
我的保险柜.vault.idx   加密索引文件
```

### 强绑定机制

- 创建时生成 32 字节随机 **pair_token**，同时写入 `.vault` 头部与 `.idx` 头部。
- 索引加密密钥与内容加密密钥都由 `pair_token` 经 HKDF 派生，因此：
  - 用其它保险柜的索引替换本索引 → 密钥不匹配，无法解密；
  - 用其它保险柜的 `.vault` 替换本文件 → `pair_token` 不一致，直接拒绝。
- 打开时会校验两侧 `pair_token`，不一致立即报「保险柜与索引文件不匹配」。

### 密钥派生

```
master_key = PBKDF2-HMAC-SHA256(password, salt(16B), 600000, 32B)
idx_key    = HKDF-SHA256(master_key, "SKidxv1",  pair_token, 32B)
chunk_key  = HKDF-SHA256(master_key, "SKchnkv1", pair_token, 32B)
```

### `.vault` 布局

```
[0..95]  头部：magic(8) | version(4) | iterations(4) | salt(16) | pair_token(32) | reserved(32)
[96..]   数据块序列，每块一个文件：
         nonce(12) | data_len(8) | ciphertext(data_len) | tag(16)
```

- 每个文件块用独立的随机 nonce，AES-256-GCM 认证加密，AAD = file_id(16) + data_len(8)。
- GCM 不填充，`ciphertext 长度 == 明文长度`。
- **添加文件**：优先复用索引里记录的空闲洞（best-fit），没有再向 `.vault` 末尾追加一个块。
- **删除文件**：O(1) 惰性删除——只把该块标记为空闲并重写小索引，不再整文件重写；
  若删除的是文件末尾的块，则立即截断文件实现「删除即缩水」。中间留下的洞会被后续添加复用，
  避免大保险柜删除一个文件也要 O(整个文件) 拷贝、还额外占用等量临时空间的问题。
- 空闲洞（含跨文件合并）随索引持久化，`compact` 操作用 mmap 原地搬移把洞消除、真正缩水。

### `.idx` 布局

```
magic(8) | version(4) | pair_token(32) | nonce(12) | cipher_len(8) | ciphertext | tag(16)
```

解密后为 JSON：

```json
{ "version": 1, "pair_token": "<hex>",
  "files": [ { "name": "a.pdf", "size": 1234, "offset": 96, "mtime": 1700000000, "id": "<hex>" } ],
  "free": [ { "offset": 1340, "size": 5678 } ] }
```

> `free` 为可复用的空闲区间（字节偏移 + 长度），旧版索引没有该字段时按空处理，向前兼容。

## RPC 协议

每行一个 JSON 请求，响应一行 JSON。长耗时操作（`add` / `compact` / `change_password`）期间，
后端会额外输出与请求相同 `id` 的进度通知行（无 `ok`/`result`），供 Electron 主进程转发给前端进度条：

```json
{"id":2,"progress":{"phase":"encrypt","done":1048576,"total":4194304}}
```

`phase` 取值：`encrypt`（添加加密）、`compact`（整理）、`reencrypt`（改密重加密）。

```json
{"id":1,"method":"create","params":{"path":"D:/a.vault","password":"pw"}}
{"id":1,"method":"open","params":{"path":"D:/a.vault","password":"pw"}}
{"id":1,"method":"lock"}
{"id":1,"method":"list"}
{"id":1,"method":"add","params":{"src":"C:/file.pdf"}}
{"id":1,"method":"extract","params":{"name":"file.pdf"}}
{"id":1,"method":"extract_to","params":{"name":"file.pdf","dest":"D:/out/file.pdf"}}
{"id":1,"method":"change_password","params":{"old_password":"old","new_password":"new"}}
{"id":1,"method":"delete","params":{"name":"file.pdf"}}
{"id":1,"method":"compact"}
{"id":1,"method":"shutdown"}
```

错误码：`NOT_OPEN` / `ALREADY_EXISTS` / `WRONG_PASSWORD` / `CORRUPT` / `MISMATCHED_PAIR` /
`NOT_FOUND` / `EXISTS` / `INVALID` / `IO_ERROR` / `CRYPTO_ERROR` / `INTERNAL`。

## 安全要点

- 密钥、`pair_token`、文件表、临时明文在锁定（`lock`/`shutdown`）或析构时用
  `OPENSSL_cleanse` 清零后再释放。
- 双击「打开文件」会把解密后的临时文件写到系统临时目录下的随机子目录，
  锁定/退出时对该目录逐文件覆写归零并删除。
- 密码字符串在用完 `derive_keys` 后立即清零。
- 保险柜打开期间，后端会持有 `.vault` / `.idx` 的文件句柄且不共享删除权限（Windows），
  从而阻止用户误删正在使用的保险柜文件；锁定/退出后自动释放。

> 注意：若某临时文件正被外部程序（如 PDF 阅读器）占用，Windows 下删除可能失败，
> 该文件会残留于 `%TEMP%\shinkuro-vault\`，可手动清理。
