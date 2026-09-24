# married sh

让没有公网、没有 SSH 服务的 Unix 设备主动连接另一台机器，再从那台机器执行它的命令。

Alice 主动连 Bob，Bob 本地的 `console` 通过 Unix socket 控制 Alice。只需要一个可执行文件，
不需要 SSH 客户端、SSH 服务、系统 OpenSSL 或 root。支持 Linux 和 macOS；Linux 优先用 musl 静态构建。

## 快速开始

```sh
# Bob：启动后台服务，使用非特权端口
marriedsh daemon -n bob -p '同一个配对密码' 0.0.0.0:1234

# Alice：后台运行，掉线后一直重试
marriedsh join -n alice -p '同一个配对密码' bob.example:1234

# Bob：可以先 ssh 登录 Bob，再执行这些本地命令
marriedsh list
marriedsh console
marriedsh console -n alice -- uname -a
marriedsh console -n alice -- sh -c 'cd /tmp && ls -l'
cat input.bin | marriedsh console -n alice -- cat > output.bin
```

`-n` 可以省略。只有一个连接时自动选中；多个连接时必须指定名称或 `--id`。
`list` 显示内部连接 ID、显示名称、认证凭据 ID，以及对端是否允许执行命令。
连接 ID 在 join 的整个进程生命周期内不变，包括重连；进程重启后重新生成，不用写入设备文件系统。
名称和认证 ID 均使用 1–64 个 ASCII 字母、数字、点、下划线或连字符。

命令参数逐个传递，不经过隐式 `sh -c`。管道、变量展开等 shell 语法需要显式运行 `sh -c`。
不带命令时使用执行用户在 passwd 中的 shell，以 `-bash` / `-sh` 等 argv[0] 启动 login shell。
明确指定的命令继承 join 的工作目录和环境；后台模式的工作目录为 `/`，login shell 会尽量进入 HOME。

### 密码

`-p` 适合临时测试，但会出现在命令行及 shell 历史中。长期使用推荐配置文件或 `--psk-file`：

```sh
umask 077
marriedsh keygen > pair.psk
# 将同一份文件安全地交给另一端；不要分别生成两个不同密码。
marriedsh daemon --psk-file pair.psk 0.0.0.0:1234
marriedsh join --psk-file pair.psk bob.example:1234
```

未配置密码时，交互终端会隐藏输入并询问密码；非交互启动则报错。没有默认密码或匿名认证模式。
`daemon` / `join` 先在当前终端读完密码，再进入后台，不需要加 `&` 或 `nohup`。
认证采用 OPAQUE（RFC 9807），数据使用 ChaCha20-Poly1305 加密和认证。
支持普通口令，推荐使用 `keygen` 的 256 位随机秘密。详见 [安全设计](SECURITY.md)。

## 权限边界

**Alice 默认允许 Bob 执行命令，Bob 默认拒绝。第一版强制禁止 Bob 上的反向执行。**

如果给 Alice 一个与 Bob daemon 同用户的任意 shell，它就能读取 Bob 的配置和控制 socket，
从而控制 Clark。协议规则无法阻止这种操作。未来反向执行需要独立执行用户或沙箱支持；
第一版在 daemon 配置 `allow_remote_exec = true` 时直接报错。

每条连接只控制直接相连的对端，网络协议不提供跨设备路由。Alice 的本地 `list` 只显示 Bob，
而 Bob 不接受命令，因此 Alice 无法通过 marriedsh 控制 Clark。

命令以 join 的启动用户身份执行，拥有该用户的全部权限，**不是沙箱**。
需要更低权限时，以普通用户启动 join。连接 Bob 的本地控制 socket 等同于获得所有已配对设备的 shell 权限。
不要把 socket、配置文件或 daemon 用户账号共享给不受信任的人。

### 一对多

每台设备必须有独立 PSK 和凭据 ID。同一凭据只允许一条在线连接，不支持用全局密码把所有设备当成独立身份。
单密码命令对应默认凭据 `pair`，适合一对一。

Bob 的配置：

```toml
name = "bob"
allow_remote_exec = false

[[peers]]
id = "alice-key"
name = "alice"
psk = "只与Alice共享的密码"

[[peers]]
id = "clark-key"
name = "clark"
psk = "只与Clark共享的另一个密码"
```

```sh
marriedsh daemon 0.0.0.0:1234
# Alice
marriedsh join --credential alice-key -p '只与Alice共享的密码' bob.example:1234
# Clark
marriedsh join --credential clark-key -p '只与Clark共享的另一个密码' bob.example:1234
# Bob
marriedsh console -n clark -- uname -a
marriedsh console --id <list中的完整ID> -- uname -a
```

多凭据模式的名称由 Bob 的配置指定；省略 `peers.name` 则采用 `peers.id`。
设备自报名称不能覆盖其他凭据的名称。重复 PSK、凭据 ID 和配置名称会被拒绝。

## 终端与退出

- `--pty=auto`（默认）：本地 stdin/stdout 都是终端时使用 PTY；PTY 分配失败则回退到管道。
- `--pty=always`：强制 PTY，不可用就报错。PTY 合并 stdout/stderr，并可能转换换行或回显输入。
- `--pty=never`：保留二进制输入输出和独立 stderr，适合脚本和管道。
- 支持终端窗口缩放、Ctrl-C、Ctrl-D 和全屏程序。终端退出时恢复本机终端模式和文件状态标志。
- PTY 交互模式下，在行首输入 `~.` 可本地断开；`~~` 输入一个字面 `~`。
- 非 PTY 输入结束会关闭远端 stdin，但继续读取输出。PTY 无真正的输入半关闭；规范模式下模拟 VEOF。
- 正常返回远端退出码；被信号终止返回 `128 + signal`；本地错误或连接中断返回 255。

关闭 console 或失去连接会终止对应远端进程组；正常命令退出后也清理该组剩余子进程。
故意调用 `setsid()` 脱离进程组的程序不受这种清理机制约束。
第一版不支持 detach/重新挂接、持久终端、文件传输协议或 TCP 端口转发。

## 保活和重连

join 在 DNS 失败、连接失败、Bob 重启、认证失败后继续存活，不重启本地服务进程。
默认重试间隔 5 秒，带 ±20% 随机抖动；Alice 每 60 秒发起 ping，默认 180 秒无 pong 就重连。
Bob 回复 ping，并清理超时连接。定时器使用单调时钟；失败日志限频。

只恢复连接，**不自动重放命令**。断线时命令可能已经产生副作用，结果未知；恢复后手动判断是否重试。
旧的半开连接可能占用其凭据，最长到保活超时后释放；新连接不会直接顶掉仍在线的设备。

一个连接最多 8 个会话。每会话每方向 64 KiB 信用窗口，数据块最多 8 KiB，
小数据块按至少 1 KiB 计费，限制队列条目数量。慢会话不会无限积压内存。
所有会话共用一个 TCP 连接，所以底层 TCP 丢包仍可能暂时影响全部会话。

## 配置

默认读取 `$XDG_CONFIG_HOME/marriedsh/config.toml`，否则 `~/.config/marriedsh/config.toml`。
可用 `--config /path/config.toml` 指定。文件不存在时使用默认值；显式指定的文件不存在、
格式错误、未知字段或权限不安全时会报错。配置和密码文件必须由当前用户拥有，权限 `0600`，不能是符号链接。

```toml
# Alice 的可选配置；所有字段均可省略
name = "alice"
credential = "pair"
psk = "替换为真实配对密码"
allow_remote_exec = true
# 自定义 socket 的父目录必须属于当前用户，且权限为 0700
# socket = "/home/me/.marriedsh/run/control.sock"
reconnect_secs = 5
heartbeat_secs = 60
heartbeat_timeout_secs = 180
connect_timeout_secs = 15
max_peers = 32 # daemon 接受的最大在线设备数，范围 1–256
```

命令行选项覆盖配置，配置覆盖默认值。`--reconnect-secs` 和 `--heartbeat-secs` 可直接用于 daemon/join。
两端应配置兼容的 heartbeat 和 timeout；配置不会动态热重载。

默认控制 socket 为 `$XDG_RUNTIME_DIR/marriedsh/control.sock`，否则 `~/.marriedsh/run/control.sock`。
支持 `--socket /path/control.sock`。在同一用户下同时启动多个 daemon/join 时，为它们指定不同 socket。
socket 权限为 `0600`，父目录为 `0700`，并校验连接对端 UID。锁文件防止多进程抢占，重启可清理遗留 socket。

### 后台运行与停止

Unix 下 `daemon` 和 `join` 默认采用双重 fork、`setsid()` 脱离终端，关闭继承的文件描述符，
将工作目录切到 `/`，并设置 `umask 077`。命令返回后可以退出当前 shell 或 SSH 连接，服务继续运行。
配置文件、密码文件和相对 socket 路径在脱离终端前解析。

启动成功后打印最终 PID、控制 socket、日志和 PID 文件路径。父进程等待本地初始化完成才返回成功；
端口占用、socket 冲突等错误会返回到当前终端。join 的启动成功表示本地服务已就绪，
不代表已经连上 Bob；Bob 离线时 join 仍会在后台重连，用 `list` 查看连接状态。

stdin 指向 `/dev/null`，stdout/stderr 追加写入 socket 同目录下的日志文件。
日志和 PID 路径将 socket 文件的扩展名替换为 `.log` / `.pid`，权限均为 `0600`。
例如未设置 `XDG_RUNTIME_DIR`、未自定义 socket 时：

```sh
tail -f ~/.marriedsh/run/control.log
kill -TERM "$(cat ~/.marriedsh/run/control.pid)"
```

实际路径以启动输出为准。正常停止会清理 socket 和 PID 文件，保留日志及锁文件；日志不自动轮转。
也可以直接 `kill -TERM <启动时打印的PID>`。

调试或交给 systemd、OpenRC、procd 等监护程序时，使用 `-f` / `--foreground` 保持前台运行：

```sh
marriedsh daemon --foreground 0.0.0.0:1234
marriedsh join --foreground bob.example:1234
```

前台模式不创建后台日志和 PID 文件，日志写到 stderr。网络重连由 join 自己处理；
进程被杀或机器重启后的重新启动交给系统服务管理器。

### 在 .profile 中重复启动

默认已经按控制 socket 加锁：同一用户使用同一 socket 时，第二个实例会报错退出，
但仍会先读取配置和询问密码。使用不同 socket 时可以运行多个实例。

`daemon` / `join` 可加 `--lock PATH`，在读取配置和密码前尝试非阻塞 `flock`。
该锁已被占用时，不提示密码、不打印信息，直接以退出码 0 返回；
打开文件失败、权限不安全等真正的错误仍会报告并返回非零。
锁由最终服务进程持有，正常退出或被 SIGKILL 后由内核释放，后台启动的父进程退出不会释放它。

例如把下面命令放入 `.profile`，使用可执行文件的绝对路径，省略 `-f`：

```sh
"$HOME/.local/bin/marriedsh" join \
  --lock /tmp/marriedsh.lock \
  --credential clark -n clark \
  --psk-file "$HOME/.config/marriedsh/clark.psk" \
  bob.example:1234
```

预先将 Clark 的密码写入上述密码文件并设置权限 `0600`，也可使用配置文件中的 `psk`。
`-f` 会让首次启动占住登录 shell，因此不适用于这个例子。
首次启用时先停止旧实例，再使用带 `--lock` 的命令启动；后续调用统一使用同一个锁路径。

锁文件的父目录必须已存在，文件由程序以 `0600` 创建，也可放在自己的私有目录。
使用独立的锁文件，不要与控制 socket、内置 socket 锁、日志或 PID 文件共用。
**不要删除锁文件**：文件存在不代表服务正在运行，程序只判断内核锁状态；
运行期间删除文件可能使后来启动的实例锁住另一个 inode，破坏互斥。

## 构建和测试

```sh
make
make check
make test
make release
make install                   # 默认 ~/.local/bin

rustup target add x86_64-unknown-linux-musl
make musl
# target/x86_64-unknown-linux-musl/release/marriedsh

# 其他有 Rust std 支持的 Linux musl 架构，例如 ARM64：
rustup target add aarch64-unknown-linux-musl
make musl MUSL_TARGET=aarch64-unknown-linux-musl
```

构建需要 Rust/Cargo；进程集成测试需要 Python 3。目标设备只需要可执行文件和 Unix 系统能力。
PTY 需要可用的 `/dev/ptmx` / devpts（macOS 为系统 PTY）；不可用时可使用管道模式。
设备必须有可靠的系统随机数来源，以及进程、socket、信号等基本能力。不支持裸机或无 MMU 环境。

`tests/integration.py` 会在本机启动 Bob、Alice、Clark，测试密码拒绝、参数、二进制流、终端、
隔离、并发、背压、断线清理、重连和模拟网络黑洞。可以传入其他构建的可执行文件路径。
`tests/background.py` 验证真实终端密码输入、后台启动、退出原 shell 后存活、离线重连、
继承文件描述符关闭、启动错误回传及 PID/socket 清理。`make test` 包含这两组测试。
测试结果与真实部署验证见 [TESTING.md](TESTING.md)。
