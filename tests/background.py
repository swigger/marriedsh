#!/usr/bin/env python3
"""Exercise real Unix daemonization, including password entry and terminal loss."""
import os
import concurrent.futures
import fcntl
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
        foregrounds = []
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

        def lock_free(gate):
            with gate.open("r+") as file:
                try:
                    fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except BlockingIOError:
                    return False

        def terminal_start(sock, role, address):
            instance_lock = sock.parent.parent / (role + ".instance-lock")
            command = shlex.join([binary, "--socket", str(sock), role, "--lock", str(instance_lock), "-n", role, address])
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
            # Lock must remain held by the grandchild after its launcher exits.
            duplicate = call(sock, role, "--lock", str(instance_lock), address, stdin=subprocess.DEVNULL)
            assert duplicate.returncode == 0 and not duplicate.stdout and not duplicate.stderr, duplicate
            assert pid(sock) == background
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
            # Executed user commands must not inherit the service instance lock.
            script = """import os, sys
expected = os.stat(sys.argv[1])
for fd in range(3, 256):
    try:
        actual = os.fstat(fd)
    except OSError:
        continue
    assert (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino), fd
print('no-lock-fd')
"""
            assert success(call(bob, "console", "--", "python3", "-c", script, str(root / "join.instance-lock"))).stdout == b"no-lock-fd\n"
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
            repeated_join = call(alice, "join", "-f", "-p", password, address, stdin=subprocess.DEVNULL)
            assert repeated_join.returncode == 255 and b"another marriedsh instance" in repeated_join.stderr
            missing_password = call(alice, "join", "-f", address, stdin=subprocess.DEVNULL)
            assert missing_password.returncode == 255 and b"no PSK configured" in missing_password.stderr
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

            # Concurrent launches using one lock but distinct sockets must start
            # exactly one service. Losers succeed silently, without reading PSKs.
            gate = root / "concurrent.lock"
            candidates = [path("race" + str(i)) for i in range(8)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda sock: call(sock, "join", "--lock", str(gate), "-p", password, destination), candidates))
            for result in results:
                success(result)
            winners = [sock for sock in candidates if sock.exists()]
            assert len(winners) == 1, winners
            assert sum(bool(result.stderr) for result in results) == 1
            winner = winners[0]
            original = pid(winner)
            for mode in ([], ["-f"]):
                skipped = call(winner, "--config", str(root / "missing.toml"), "join", *mode, "--lock", str(gate), destination, stdin=subprocess.DEVNULL)
                assert skipped.returncode == 0 and not skipped.stdout and not skipped.stderr, skipped
            assert pid(winner) == original
            inode = gate.stat().st_ino
            stop(winner)
            # PID/socket cleanup precedes final runtime teardown and lock close.
            wait_for(lambda: lock_free(gate))
            assert gate.stat().st_ino == inode, "lock file must not be unlinked"
            success(call(winner, "join", "--lock", str(gate), "-p", password, destination))
            assert pid(winner) != original
            killed = pid(winner)
            os.kill(killed, signal.SIGKILL)
            wait_for(lambda: lock_free(gate))
            success(call(winner, "join", "--lock", str(gate), "-p", password, destination))
            stop(winner)
            print("PASS concurrent single-instance startup, silent skip before config/password, lock release after exit/SIGKILL", flush=True)

            front = path("foreground")
            with (root / "foreground.log").open("wb") as log:
                process = subprocess.Popen([binary, "--socket", str(front), "join", "-f", "--lock", "foreground.lock", "-p", password, destination], cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            foregrounds.append(process)
            wait_for(front.exists)
            skipped = call(front, "join", "--lock", str(root / "foreground.lock"), destination, stdin=subprocess.DEVNULL)
            assert skipped.returncode == 0 and not skipped.stdout and not skipped.stderr, skipped
            assert process.poll() is None
            process.terminate()
            assert process.wait(timeout=5) == 0
            success(call(front, "join", "--lock", str(root / "foreground.lock"), "-p", password, destination))
            stop(front)
            bad_lock = root / "bad.lock"
            bad_lock.symlink_to(root / "do-not-create")
            for lock in (bad_lock, root / "nonexistent-parent" / "lock", root):
                failed = call(front, "join", "--lock", str(lock), "-p", password, destination)
                assert failed.returncode != 0 and failed.stderr, failed
            assert not (root / "do-not-create").exists()
            alias_socket = path("alias")
            alias_socket.parent.mkdir(mode=0o700)
            alias = alias_socket.with_suffix(".pid")
            collision = call(alias_socket, "join", "--lock", str(alias), "-p", password, destination)
            assert collision.returncode != 0 and b"separate file" in collision.stderr, collision
            alias.unlink()  # Empty lock file, not a service PID file.
            print("PASS foreground/relative locks and actionable errors for invalid lock paths", flush=True)

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
            for process in foregrounds:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
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
