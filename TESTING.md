# 验证记录

日期：2026-09-24。构建工具链：Rust / Cargo 1.97.0。

## 本机验证

macOS ARM64：

```sh
make check
make test
make musl
make release
```

- rustfmt、Clippy（所有 target，warnings 作为错误）通过。
- 6 项 Rust 测试通过：OPAQUE 双向认证、错误密码/伪造服务端/未知凭据拒绝，
  AEAD 篡改/重放/错误方向拒绝，直接网络执行请求被 Bob 拒绝，帧边界和 socket 保护。
- 真实进程集成测试通过：参数原样传输，1 MiB 二进制管道，输入半关闭，远端提前结束 stdin，
  独立 stderr、退出码、exec 失败、PTY、login shell、名称/ID 选择和多设备隔离。
- 并发、慢输出背压、窗口缩放、Ctrl-C、终端恢复、断线进程回收、
  stdin 完全阻塞时的取消、Bob 重启和重连、超大帧拒绝、socket 抢占保护通过。
- TCP 保持打开但丢弃双向数据的网络黑洞测试通过；随后恢复网络能自动重连。
- 连续 40 个会话的创建、退出和连接存活测试通过。
- Unix 后台模式测试通过：真实 PTY 中隐藏输入密码、双重 fork、脱离原会话和控制终端，
  原 shell 收到 SIGHUP 并退出后仍可运行远端命令；离线启动后自动连上恢复的 Bob。
- 已验证相对配置/密码/socket 路径、标准输入输出与继承 FD 的脱离、私有日志/PID 权限、
  启动失败回传、重复实例拒绝、日志符号链接拒绝、SIGTERM 清理和重启。

这些是功能、故障恢复和有限压力测试，不等同于数周运行的 soak test 或独立安全审计。

## Linux 部署环境

验证了 Linux x86_64 musl 静态构建，可直接执行，不依赖目标系统的动态链接器或额外运行库。
Bob 以普通用户运行测试，Alice 为用户提供的 root 测试账号。
最终构建产物在 Bob 和 Alice 上分别运行上述完整进程集成测试及 Unix 后台生命周期测试，均通过。

远端本机测试可重跑：

```sh
python3 tests/remote_smoke.py \
  --bob <Bob的SSH目标> \
  --alice <Alice的SSH目标> --alice-port <SSH端口> \
  --bob-address <Alice可达的Bob地址> --local-only
```

脚本将构建和测试脚本放进两端各自的私有临时目录，分别运行完整进程测试，最后清理。
不安装系统服务，不修改防火墙，不保留密码或后台 daemon。

初次跨机器直连测试曾尝试域名和 Bob 的已确认 IPv4 地址：

- Alice 的域名解析失败，join 在错误后持续重试。
- 使用数字 IPv4 后，两个不同的临时监听端口均持续超时。
- Alice 对同一 Bob IPv4 的 SSH 端口 TCP 连接成功。
- 尚不能确定限制位于哪一层；没有修改任一机器的网络或防火墙配置。

随后用户已反馈开放防火墙后手动直连测试通过。上述网络失败保留为初次测试记录。
本次后台模式改动在独立临时目录中验证，不替换用户正在运行的实例。
去掉 `--local-only` 可运行跨机器命令、二进制往返、PTY、隔离、退出码、资源和重连测试；
这套自动化跨机器流程尚未在防火墙调整后重新执行。

## 构建产物

| 平台 | 文件 | 大小 |
| --- | --- | --- |
| macOS ARM64 | `target/release/marriedsh` | 约 1.3 MiB |
| Linux x86_64 musl | `target/x86_64-unknown-linux-musl/release/marriedsh` | 约 1.8 MiB，static PIE |

SHA-256：

```text
macOS: 187a1487a9239be44186db66ae60980de9d630da7c948ed6372433af7897a4fb
Linux: 06368fcfa354ac6532ca3f2683c087e6d6a1dc44cb922f0d924293195d3cd461
```

## 依赖检查

通过 OSV 的 crates.io 查询接口检查 Cargo.lock 中的 104 个注册表包，检查时无匹配公告。
锁文件 SHA-256：`9003defa0adce4d8a7c42ade2cdee26a690b89c48de60cc9d156189674ab7f15`。
原先的 bincode 因维护状态公告已移除，最终使用 postcard。
来源：[RustSec 维护状态公告](https://rustsec.org/advisories/RUSTSEC-2025-0141.html)、
[OSV API](https://google.github.io/osv.dev/api/)。

“未匹配公告”只反映检查时数据库中已知的信息，不代表应用经过密码学审计。
