#!/usr/bin/env python3
"""Opt-in deployment smoke test. Stages into private temporary dirs and cleans up."""
import argparse
import hashlib
import pathlib
import re
import secrets
import shlex
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bob", required=True)
    parser.add_argument("--alice", required=True)
    parser.add_argument("--alice-port", default="22")
    parser.add_argument("--bob-address", required=True, help="Bob's address reachable from Alice")
    parser.add_argument("--binary", default="target/x86_64-unknown-linux-musl/release/marriedsh")
    parser.add_argument("--local-only", action="store_true", help="Run integration separately on both hosts, without opening a public listener")
    args = parser.parse_args()
    token = secrets.token_hex(5)
    directory = f"/tmp/marriedsh-smoke-{token}"
    binary = directory + "/marriedsh"
    hosts = {"bob": (args.bob, "22"), "alice": (args.alice, args.alice_port)}
    options = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2"]

    def ssh(who, command, data=None, timeout=45, check=True):
        host, port = hosts[who]
        result = subprocess.run(["ssh", *options, "-p", port, host, command], input=data if data is not None else b"", capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{who}: {result.returncode}: {result.stderr.decode(errors='replace')}")
        return result

    def copy(who, source, name):
        host, port = hosts[who]
        for attempt in range(3):
            result = subprocess.run(["scp", *options, "-P", port, str(source), f"{host}:{directory}/{name}"], capture_output=True, timeout=90)
            if result.returncode == 0:
                return
            if attempt == 2:
                raise RuntimeError(result.stderr.decode(errors="replace"))
            time.sleep(1)

    def invoke(who, *cmd, **kwargs):
        return ssh(who, shlex.join([binary, "--config", directory + "/config.toml", "--socket", directory + "/run/control.sock", *cmd]), **kwargs)

    def wait(fn, seconds=45):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            value = fn()
            if value:
                return value
            time.sleep(1)
        raise RuntimeError("remote readiness timed out")

    def launch(who, *cmd):
        cmd = (cmd[0], "--foreground", *cmd[1:])
        command = shlex.join([binary, "--config", directory + "/config.toml", "--socket", directory + "/run/control.sock", *cmd])
        ssh(who, f"nohup {command} > {directory}/log 2>&1 < /dev/null & echo $! > {directory}/pid")

    def stop(who):
        # Verify the executable path before acting on a PID file.
        ssh(who, f"if test -f {directory}/pid; then p=$(cat {directory}/pid); if test -r /proc/$p/cmdline && tr '\\0' '\\n' < /proc/$p/cmdline | head -n 1 | grep -Fxq {binary}; then kill -TERM $p; fi; fi", check=False)

    staged = []
    try:
        with tempfile.TemporaryDirectory(prefix="marriedsh-deploy-") as temp:
            password = secrets.token_hex(32)
            for who in ("bob", "alice"):
                ssh(who, f"umask 077; mkdir {directory}")
                staged.append(who)
                copy(who, args.binary, "marriedsh")
                config = pathlib.Path(temp) / (who + ".toml")
                config.write_text(f'name="{who}"\npsk="{password}"\nreconnect_secs=2\nheartbeat_secs=3\nheartbeat_timeout_secs=12\n')
                config.chmod(0o600)
                copy(who, config, "config.toml")
                ssh(who, f"chmod 700 {binary}; chmod 600 {directory}/config.toml")
                print(who, invoke(who, "--version").stdout.decode().strip(), flush=True)
            for who in (("bob", "alice") if args.local_only else ("bob",)):
                for test in ("integration.py", "background.py"):
                    copy(who, pathlib.Path(__file__).with_name(test), test)
                    result = ssh(who, shlex.join(["python3", directory + "/" + test, binary]), timeout=120)
                    print(who + " Linux musl " + test + ":\n" + result.stdout.decode(), flush=True)
            if args.local_only:
                return

            launch("bob", "daemon", "0.0.0.0:0")
            def port_ready():
                r = ssh("bob", f"cat {directory}/log", check=False)
                m = re.search(rb"listening on 0\.0\.0\.0:(\d+)", r.stdout)
                return m.group(1).decode() if m else None
            port = wait(port_ready)
            launch("alice", "join", args.bob_address + ":" + port)
            wait(lambda: b"alice" in invoke("bob", "list", check=False).stdout)
            result = invoke("bob", "console", "--", "uname", "-sm")
            print("Cross-host command:", result.stdout.decode().strip(), flush=True)
            payload = bytes(range(256)) * 1024
            result = invoke("bob", "console", "--", "cat", data=payload, timeout=60)
            assert result.stdout == payload
            print("Cross-host binary round-trip SHA256:", hashlib.sha256(payload).hexdigest(), flush=True)
            result = invoke("bob", "console", "--pty=always", "--", "sh", "-c", "test -t 0 && test -t 1 && printf pty-ok")
            assert b"pty-ok" in result.stdout
            result = invoke("bob", "console", "--", "sh", "-c", "printf stdout; printf stderr >&2; exit 23", check=False)
            assert result.returncode == 23 and result.stdout == b"stdout" and b"stderr" in result.stderr
            result = invoke("alice", "console", "--", "true", check=False)
            assert result.returncode == 255 and b"does not allow" in result.stderr
            print("Cross-host PTY, stdout/stderr, exit code, Bob execution denial: PASS", flush=True)

            def resources():
                return ssh("alice", f"p=$(cat {directory}/pid); printf 'fds='; ls /proc/$p/fd | wc -l; awk '/VmRSS|Threads/ {{print}}' /proc/$p/status").stdout.decode().strip()
            before = resources()
            for _ in range(30):
                invoke("bob", "console", "--", "true")
            after = resources()
            assert before.splitlines()[0] == after.splitlines()[0], (before, after)
            print("Alice resources before / after 30 sessions:\n" + before + "\n" + after, flush=True)
            stop("bob")
            wait(lambda: len(invoke("alice", "list", check=False).stdout.splitlines()) == 1)
            launch("bob", "daemon", "0.0.0.0:" + port)
            wait(lambda: b"alice" in invoke("bob", "list", check=False).stdout)
            assert invoke("bob", "console", "--", "printf", "reconnected").stdout == b"reconnected"
            print("Cross-host Bob restart / Alice reconnect: PASS", flush=True)
    except BaseException:
        for who in staged:
            try:
                print(who, ssh(who, f"cat {directory}/log", check=False).stdout.decode(errors="replace"), flush=True)
            except Exception:
                pass
        raise
    finally:
        for who in reversed(staged):
            try:
                stop(who)
                time.sleep(0.3)
                ssh(who, f"rm -rf -- {directory}")
            except Exception as exc:
                print(f"Cleanup incomplete on {who}: {directory}: {exc}", flush=True)


if __name__ == "__main__":
    main()
