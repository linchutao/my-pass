# MyPass

MyPass 是一个用 Rust 编写的本地优先密码管理器。它把账号凭据保存在本地加密密码库文件中，并提供一个适合日常使用的小型命令行界面。

这个项目刻意保持简单：没有云同步，没有浏览器扩展，没有远程账号系统，也没有后台保持解锁的会话。一个密码库就是一个本地加密文件。

## 功能

- 初始化本地加密密码库。
- 添加账号凭据。
- 按条目名称获取凭据。
- 更新已有条目。
- 删除条目，并要求显式确认。
- 列出已保存条目，但不显示密码。
- 修改主密码，并且不需要逐条重新加密账号数据。
- 使用默认密码库路径，或通过 `--vault <path>` 指定密码库文件。
- 使用 `mypass tui` 进入命令式交互模式。

## 安全模型

MyPass 不保存主密码。它使用分层密钥模型：

1. 你记住一个主密码。
2. MyPass 生成一个随机的数据加密密钥，即 DEK。
3. MyPass 使用 Argon2id、每个密码库独立的随机盐，以及主密码派生密钥加密密钥，即 KEK。
4. KEK 加密 DEK。
5. DEK 加密密码库数据。

密码库文件会保存元数据、KDF 参数、盐、nonce、加密后的 DEK，以及加密后的密码库数据。它不会保存主密码、明文 KEK、明文 DEK 或明文条目。

解锁流程：

```text
master password + salt
-> Argon2id
-> KEK
-> decrypt encrypted DEK
-> DEK
-> decrypt vault data
-> entries
```

修改主密码不会逐条重新加密账号条目。MyPass 会先用旧主密码解锁 DEK，再用新主密码派生新的 KEK，然后用新的 KEK 重新加密同一个 DEK。

## 密码学

当前使用的基础组件：

- 密钥派生：Argon2id
- 认证加密：ChaCha20-Poly1305
- 随机数：操作系统 CSPRNG
- 密码库文件中的二进制字段：base64 编码

初始 Argon2id 参数：

```text
memory_kib = 65536
iterations = 3
parallelism = 1
```

加密密码库是一个带有 base64 字段的 JSON 文件。账号数据本身会先序列化为 JSON，再作为一个整体认证加密为密文。

## 威胁模型

MyPass 主要防护的是离线攻击：攻击者拿到了密码库文件，但仍然需要主密码才能派生正确的 KEK 并解密 DEK。

它不能完整防护已经被攻陷的本机环境。如果恶意软件可以记录键盘输入、读取进程内存、检查剪贴板或控制你的终端，秘密仍然可能泄露。

## 构建

先安装 Rust。这个项目使用以下版本构建过：

```text
rustc 1.87.0
cargo 1.87.0
```

开发构建：

```bash
cargo build
```

发布构建：

```bash
cargo build --release
```

如果想把可运行二进制放到项目根目录：

```bash
cp target/release/mypass ./mypass
```

验证：

```bash
./mypass --version
```

## 测试与检查

运行测试：

```bash
cargo test
```

检查格式：

```bash
cargo fmt --check
```

运行 clippy：

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## 使用

使用默认密码库位置：

```bash
mypass init
```

默认密码库文件是 `~/personal.mypass`。

或指定一个密码库文件：

```bash
mypass --vault ./personal.mypass init
```

`--vault` 表示密码库文件路径，不是目录。如果你不想使用默认密码库，后续命令也需要使用相同的 `--vault` 值。

### 交互模式

启动命令式交互会话：

```bash
mypass tui
```

或打开指定密码库：

```bash
mypass --vault ./personal.mypass tui
```

如果省略 `--vault`，MyPass 会提示输入密码库文件路径。直接回车会使用默认密码库路径。之后输入一次主密码来解锁本次会话。

交互模式可用命令：

```text
/list
/view <entry> [-u <username>]
/copy <entry> [-u <username>]
/add <entry>
/update <entry> [-u <username>]
/delete <entry> [-u <username>]
/change-master
/help
/exit
```

`/exit` 会离开会话，并释放已解锁的密码库状态和内存中的主密码。

### 初始化

```bash
mypass --vault ./personal.mypass init
```

提示：

```text
Create master password:
Confirm master password:
```

### 添加条目

```bash
mypass --vault ./personal.mypass add github
```

提示：

```text
Master password:
Username:
Password:
Confirm password:
```

条目名称通常是服务名称。用户名会保存在该服务名下，所以同一个服务可以保存多个用户名：

```bash
mypass --vault ./personal.mypass add github
# Username: alice@example.com

mypass --vault ./personal.mypass add github
# Username: bob@example.com
```

### 获取条目

默认行为会把密码复制到剪贴板：

```bash
mypass --vault ./personal.mypass get github
```

MyPass 会立即打印复制成功消息，等待 30 秒，然后仅在剪贴板内容仍然是刚复制的密码时清空剪贴板。

如果要明确打印密码：

```bash
mypass --vault ./personal.mypass get github --show
```

如果同一个服务下有多个用户名，需要指定用户名：

```bash
mypass --vault ./personal.mypass get github --username alice@example.com --show
```

### 更新条目

```bash
mypass --vault ./personal.mypass update github
```

提示：

```text
Master password:
Username [current username]:
New password:
Confirm new password:
```

在用户名提示处直接回车会保留当前用户名。

如果同一个服务下有多个用户名，需要指定要更新哪一个：

```bash
mypass --vault ./personal.mypass update github --username alice@example.com
```

### 删除条目

```bash
mypass --vault ./personal.mypass delete github
```

提示：

```text
Master password:
Delete entry "github"? Type the entry name to confirm:
```

只有当确认输入与条目名称完全一致时，条目才会被删除。

如果同一个服务下有多个用户名，需要指定要删除哪一个：

```bash
mypass --vault ./personal.mypass delete github --username alice@example.com
```

### 列出条目

```bash
mypass --vault ./personal.mypass list
```

只显示服务名称和用户名，不显示密码。

### 修改主密码

```bash
mypass --vault ./personal.mypass change-master
```

提示：

```text
Current master password:
New master password:
Confirm new master password:
```

修改成功后，旧主密码会停止工作。

## 示例

```bash
./mypass --vault ./demo.mypass init
./mypass --vault ./demo.mypass add github
./mypass --vault ./demo.mypass get github --show
./mypass --vault ./demo.mypass update github
./mypass --vault ./demo.mypass list
./mypass --vault ./demo.mypass change-master
./mypass --vault ./demo.mypass delete github
```

## 注意事项

- 不要把密码作为命令行参数传入。
- 如果数据重要，请保留密码库备份。
- 使用足够长、熵足够高的主密码。
- 项目根目录下的 `mypass` 二进制文件是本地构建产物。源码变更后，请用 `cargo build --release` 重新构建。
