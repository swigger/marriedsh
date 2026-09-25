#!/bin/sh
# Self-contained installer. Embedded file contents are copied verbatim.
# Installation only: none of the embedded scripts are executed.
# Define the whole installer before running it, including when read from stdin.
install_home_init() (
    set -eu
    case "${1-}" in
        -h|--help)
            printf '%s\n' 'Usage: sh install.sh' '       DESTDIR=/absolute/staging/path sh install.sh' 'Default destination: /home/hatch (requires root).'
            exit 0
            ;;
    esac
    if [ "$#" -ne 0 ]; then
        printf '%s\n' 'Error: unexpected arguments; use --help.' >&2
        exit 1
    fi

    root=${DESTDIR:-/}
    case "$root" in
        /*) ;;
        *) printf '%s\n' 'Error: DESTDIR must be an absolute path.' >&2; exit 1 ;;
    esac
    # Resolve an existing root so that /, // and /tmp/.. get the same check.
    if [ -d "$root" ]; then
        root=$(cd "$root" && pwd -P)
    fi
    uid=$(id -u)
    if [ "$root" = / ] && [ "$uid" -ne 0 ]; then
        printf '%s\n' 'Error: run as root to install into /home/hatch.' >&2
        exit 1
    fi
    target=${root%/}/home/hatch

    for command in cat chmod mkdir mktemp mv rm; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'Error: required command not found: %s\n' "$command" >&2
            exit 1
        fi
    done
    if [ "$uid" -eq 0 ] && ! command -v chown >/dev/null 2>&1; then
        printf '%s\n' 'Error: required command not found: chown' >&2
        exit 1
    fi
    for relative in hooks/definitions/home-init.json hooks/scripts/home-init.sh init.sh; do
        destination=$target/$relative
        if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
            printf 'Error: destination must be a regular file, not a link: %s\n' "$destination" >&2
            exit 1
        fi
    done

    umask 022
    mkdir -p "$target/hooks/definitions" "$target/hooks/scripts"
    stage=$(mktemp -d "$target/.home-init.XXXXXX")
    trap 'rm -rf "$stage"' 0
    trap 'exit 1' HUP INT TERM
    umask 077

    cat > "$stage/0" <<'HOME_INIT_PAYLOAD_2570d23323a1c8835739e81ebcdd8f8bffdc1147c6e42faf83c9abaa69f0b887'
{
  "version": 1,
  "id": "home-init",
  "enabled": true,
  "script_path": "/home/hatch/hooks/scripts/home-init.sh",
  "prompt": "Managed Home initialization hook. Its script always returns silent.",
  "poll_interval_secs": 60,
  "script_timeout_secs": 600,
  "delivery": {"surface": "main"},
  "created_at_ms": 0,
  "updated_at_ms": 0
}
HOME_INIT_PAYLOAD_2570d23323a1c8835739e81ebcdd8f8bffdc1147c6e42faf83c9abaa69f0b887
    chmod 0600 "$stage/0"

    cat > "$stage/1" <<'HOME_INIT_PAYLOAD_35cbfc82368ae5de4864dd7138fe5c14798914ea258b2c9faafde3b51fdb3c16'
#!/bin/bash
set -e
umask 077
source "${HATCH_HOOK_RUNTIME:?}"
[[ "${HATCH_HOOK_DRY_RUN:-0}" == 1 ]] && silent "dry-run"
[[ -x /home/hatch/init.sh ]] || silent "waiting for init.sh"
mkdir -p /run/hatch-home-init
exec 9>/run/hatch-home-init/lock
flock -n 9 || silent "running"
[[ ! -e /run/hatch-home-init/started ]] || silent "already run"
cd /home/hatch
{
    touch /run/hatch-home-init/started  # 每次启动只尝试一次，失败也不重跑。
    printf '\n[%s] init started\n' "$(date -Is)"
    /bin/bash ./init.sh 9>&- </dev/null && rc=0 || rc=$?
    printf '[%s] init exited: %s\n' "$(date -Is)" "$rc"
} >>/tmp/home-init.log 2>&1
silent "already run"
HOME_INIT_PAYLOAD_35cbfc82368ae5de4864dd7138fe5c14798914ea258b2c9faafde3b51fdb3c16
    chmod 0700 "$stage/1"

    cat > "$stage/2" <<'HOME_INIT_PAYLOAD_bff82bfb7cb3952052c2d976091c5b39a4e55d4dfb44c703df879ed1ceca1795'
#!/bin/bash
set -euo pipefail

# 在下面写初始化命令。运行身份为 root，工作目录为 /home/hatch。
# 写好后执行 chmod 700 /home/hatch/init.sh 启用。

HOME_INIT_PAYLOAD_bff82bfb7cb3952052c2d976091c5b39a4e55d4dfb44c703df879ed1ceca1795
    chmod 0600 "$stage/2"

    if [ "$uid" -eq 0 ]; then
        chown 0:0 "$stage"/*
    fi
    mv -f "$stage/0" "$target/hooks/definitions/home-init.json"
    mv -f "$stage/1" "$target/hooks/scripts/home-init.sh"
    mv -f "$stage/2" "$target/init.sh"
    chmod +x "$target/hooks/scripts/home-init.sh"
    chmod +x "$target/init.sh"
    printf 'Installed 3 files into %s\n' "$target"
)

install_home_init "$@"
