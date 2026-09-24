#!/usr/bin/env python3
"""Exercise real Unix daemonization, including password entry and terminal loss."""
import os
import pathlib
import pty
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import time


def wait_for(fn, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("condition timed out")


def run(binary):
    with tempfile.TemporaryDirectory(prefix="mrsh-bg-", dir="/tmp") as temp:
        root = pathlib.Path(temp)
        env = dict(os.environ, HOME=temp, XDG_CONFIG_HOME=temp + "/config")
        env.pop("XDG_RUNTIME_DIR", None)
        sockets = []
        shells = []
        password = "background-test-password"

        def path(name):
            sock = root / name / "control.sock"
            sockets.append(sock)
            return sock

        def call(sock, *args, **kwargs):
            return subprocess.run([binary, "--socket", str(sock), *args], env=env,
                                  capture_output=True, timeout=15, **kwargs)

        def success(result):
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            return result

        def pid(sock):
            return int(sock.with_suffix(".pid").read_text())

        def stop(sock):
            if sock.with_suffix(".pid").exists():
                os.kill(pid(sock), signal.SIGTERM)
                wait_for(lambda: not sock.exists() and not sock.with_suffix(".pid").exists())

        def terminal_start(sock, role, address):
            command = shlex.join([binary, "--socket", str(sock), role, "-n", role, address])
            # The shell remains alive after marriedsh returns, then exits on request.
            child, master = pty.fork()
            if child == 0:
                os.execve("/bin/sh", ["sh", "-c", command + "; result=$?; printf 'RETURNED:%s\\n' \"$result\"; read reply; exit"], env)
            shells.append((child, master))
            output = bytearray()

            def read_until(marker):
                def read():
                    if select.select([master], [], [], 0.1)[0]:
                        output.extend(os.read(master, 65536))
                    return marker in output
                wait_for(read)

            read_until(b"Pairing password: ")
            # rpassword prints the prompt before disabling echo. Synchronize on
            # the terminal mode so synthetic input cannot race that transition.
            wait_for(lambda: not termios.tcgetattr(master)[3] & termios.ECHO)
            assert not sock.exists(), "detached before reading password"
            os.write(master, (password + "\n").encode())
            read_until(b"RETURNED:0")
            assert password.encode() not in output, "password was echoed"
            background = pid(sock)
            assert f"PID {background}".encode() in output
            assert os.getsid(background) != child
            assert os.getsid(background) != background, "daemon is a session leader"
            assert os.getpgid(background) != child
            tty = subprocess.check_output(["ps", "-o", "tty=", "-p", str(background)]).strip()
            assert tty in (b"?", b"??", b"-"), tty
            # Simulate logout/HUP of the originating terminal session.
            os.killpg(child, signal.SIGHUP)
            os.waitpid(child, 0)
            os.close(master)
            shells.remove((child, master))
            time.sleep(0.15)
            success(call(sock, "list"))
            for suffix in (".pid", ".log"):
                assert sock.with_suffix(suffix).stat().st_mode & 0o777 == 0o600

        try:
            bob, alice = path("bob"), path("alice")
            terminal_start(bob, "daemon", "127.0.0.1:0")
            import re
            address = re.search(r"listening on (127\.0\.0\.1:\d+)", bob.with_suffix(".log").read_text())[1]
            terminal_start(alice, "join", address)
            wait_for(lambda: b"join" in success(call(bob, "list")).stdout)
            result = success(call(bob, "console", "--", "sh", "-c", "printf '%s:' test; pwd"))
            assert result.stdout == b"test:/\n", result.stdout
            print("PASS password prompt, double fork, terminal logout survival, command channel, private PID/log", flush=True)

            # A captured launch must return without waiting for service exit; extra
            # inherited descriptors must not keep the launcher's pipes open either.
            offline = path("offline")
            config = root / "settings.toml"
            config.write_text('reconnect_secs=1\n')
            config.chmod(0o600)
            secret = root / "pair.psk"
            secret.write_text(password)
            secret.chmod(0o600)
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                destination = "127.0.0.1:" + str(reserved.getsockname()[1])
            read_fd, write_fd = os.pipe()
            try:
                success(call(offline.relative_to(root), "--config", "settings.toml", "join", "--psk-file", "pair.psk", "-n", "offline", destination,
                             cwd=root, pass_fds=(write_fd,), stdin=subprocess.DEVNULL))
                os.close(write_fd)
                write_fd = None
                assert select.select([read_fd], [], [], 2)[0], "daemon retained inherited FD"
                assert os.read(read_fd, 1) == b""
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)
            success(call(offline, "list"))
            assert b"offline" not in success(call(offline, "list")).stdout
            later = path("later")
            success(call(later, "daemon", "-p", password, destination))
            wait_for(lambda: b"offline" in success(call(later, "list")).stdout)
            assert success(call(later, "console", "--", "printf", "reconnected")).stdout == b"reconnected"
            print("PASS offline startup/reconnect, relative config/password/socket paths, stdio and inherited FD closure", flush=True)

            original_pid = pid(bob)
            duplicate = call(bob, "daemon", "-p", password, "127.0.0.1:0")
            assert duplicate.returncode != 0 and b"started (PID" not in duplicate.stderr, duplicate
            assert pid(bob) == original_pid
            success(call(bob, "list"))
            busy = path("busy")
            result = call(busy, "daemon", "-p", password, address)
            assert result.returncode != 0 and b"listening on" in result.stderr, result
            assert not busy.with_suffix(".pid").exists()
            unsafe = path("unsafe")
            unsafe.parent.mkdir(mode=0o700)
            unsafe.with_suffix(".log").symlink_to(root / "should-not-create")
            assert call(unsafe, "join", "-p", password, address).returncode != 0
            assert not (root / "should-not-create").exists()
            print("PASS startup error propagation, duplicate instance protection, unsafe log rejection", flush=True)

            stop(alice)
            stop(bob)
            success(call(bob, "daemon", "-p", password, address))
            stop(bob)
            print("PASS SIGTERM cleanup and restart", flush=True)
        except BaseException:
            for log in root.glob("*/*.log"):
                if not log.is_symlink():
                    print(log, log.read_text(errors="replace"), file=sys.stderr)
            raise
        finally:
            for child, master in shells:
                try:
                    os.killpg(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                except ProcessLookupError:
                    pass
                os.close(master)
            for sock in reversed(sockets):
                stop(sock)


if __name__ == "__main__":
    run(str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/marriedsh").resolve()))
