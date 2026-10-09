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
- **删除文件**：O(1) 惰性删除——先原子提交索引（把该块标记为空闲），再截断文件尾部实现
  「删除即缩水」。中间留下的洞会被后续添加复用，避免大保险柜删除一个文件也要 O(整个文件) 拷贝。
- 空闲洞（含跨文件合并）随索引持久化，`compact` 用「临时文件 + 原子替换」把洞消除、真正缩水。

### `.idx` 布局（version 2，加密 B+ 树）

索引文件是**定长页**的序列，每个树节点一页、独立 AES-256-GCM 加密，页 id 即物理槽位：

```
[0..63]    固定头（明文）：
            magic(8)="SKIDX002" | version(4)=2 | pair_token(32)
            page_size(4)=4096 | generation(8) | reserved(8)
[64..255]  两个 superblock 槽（各 96B）：
            nonce(12) | GCM(superblock 64B) | tag(16) | pad
[256..]    页槽位区：槽 1..N，每槽 = nonce(12) | GCM(页 4096B) | tag(16)
```

- 文件按文件名（UTF-8 字节字典序）组织成 B+ 树，值 = `{size,offset,mtime,file_id,seq}`；
  空闲区间（`free`）按 offset 组织成第二棵 B+ 树。
- **superblock** 携带单调递增的 `seq`、两棵树的根页 id、`next_page` 高水位、文件/空洞计数和
  `generation`；双槽取 `seq` 较大者为活动槽。页 AAD 绑定 `magic+version+pair_token+page_id`，
  防止页被整体搬移/替换。
- **原子提交（copy-on-write）**：一次增删只改写「根→叶」路径上的 O(log N) 个页，新页写入新槽位
  （绝不原地覆盖），最后把新 superblock 写入非活动槽并 `fsync`。任何时刻崩溃，磁盘上都有一个
  完整可用的索引版本（旧 superblock 或新 superblock）。页空间为 append-only，`compact` /
  `change_password` / 自动 reindex 会整树紧排重建以回收泄漏页。
- 旧版（version 1）JSON 索引在打开时**自动迁移**为 B+ 树，向前兼容。

## 原子性与崩溃恢复

- 索引的每次变更（增/删文件、变更空洞表）都是**原子**的：copy-on-write + 双槽 superblock +
  `fsync`，崩溃只会落在「旧状态」或「新状态」，绝不会出现半写坏的索引。
- `add` 先写内容块、后提交索引：崩溃只会留下一个孤儿块（下次 `open` 时按引用范围自动截掉尾部），
  不会破坏数据。
- `delete` 先在索引里把尾部空洞一并移出并提交，**然后**才截断 `.vault`：索引绝不描述 EOF 之后的
  字节，截断是幂等的，崩溃后 `open` 自愈。反过来的顺序（先截断、后提交）会让索引留下指向 EOF 之外的
  空洞，而 `open` 的完整性校验会把它当成 `CORRUPT`——「文件全删光、锁上再打开」报「保险箱损坏」正是
  这个顺序造成的。
- `open` 对这类「空洞指向 EOF 之后」的索引是容错的：丢弃/钳制越界空洞并重建索引，因此旧版本留下的
  空保险柜（或截断后残留尾部空洞的保险柜）会按它真实的内容打开，不会被判为损坏。
- `compact` / `change_password` 会同时替换 `.vault` 与 `.idx` 两个文件：采用
  「写 `*.tmp` → `fsync` → 备份 `*.old` → 重命名替换 → 删除 `*.old`」，并在两个文件头各写入一个
  单调递增的 **`generation`**。`open()` 时若发现残留 `*.old`/`*.tmp`，比较两侧明文 `generation`：
  - 一致 → 视为已完整提交，清理残留；
  - 不一致 → 回滚到 `*.old` 备份对（`change_password` 撕裂时需用旧密码重试）。
- 因此任何时刻进程崩溃，下次打开都能恢复到一致状态（要么新态、要么经备份回滚的旧态），
  RPC 协议与错误码保持不变。

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
