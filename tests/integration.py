#!/usr/bin/env python3
"""Real-process tests; Python is a test dependency only. No external hosts needed."""
import argparse
import concurrent.futures
import contextlib
import fcntl
import os
import pathlib
import pty
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
import threading


class BlackholeProxy:
    """Keep TCP sockets open while discarding traffic in either direction."""
    def __init__(self, destination):
        self.destination = destination
        self.blackhole = threading.Event()
        self.stopping = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self.relay, args=(client,), daemon=True).start()

    def relay(self, client):
        with client:
            try:
                with socket.create_connection(("127.0.0.1", self.destination), timeout=3) as server:
                    while not self.stopping.is_set():
                        ready, _, _ = select.select([client, server], [], [], 0.2)
                        for src in ready:
                            data = src.recv(65536)
                            if not data:
                                return
                            if not self.blackhole.is_set():
                                (server if src is client else client).sendall(data)
            except OSError:
                pass

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)


def wait_for(fn, timeout=20):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            last = fn()
            if last:
                return last
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.1)
    raise AssertionError(f"condition timed out; last={last!r}")


def run(binary):
    with tempfile.TemporaryDirectory(prefix="mrsh-", dir="/tmp") as temp:
        root = pathlib.Path(temp)
        env = dict(os.environ, HOME=temp, XDG_CONFIG_HOME=str(root / "config"))
        processes, logs, proxies = [], [], []
        def config(name, text):
            path = root / (name + ".toml")
            path.write_text(text)
            path.chmod(0o600)
            return str(path)
        def start(*args):
            args = list(args)
            for command in ("daemon", "join"):
                if command in args:
                    args.insert(args.index(command) + 1, "--foreground")
                    break
            log = root / f"log{len(logs)}"
            logs.append(log)
            with log.open("wb") as output:
                p = subprocess.Popen([binary, *map(str, args)], stdin=subprocess.DEVNULL, stdout=output, stderr=output, env=env)
            processes.append(p)
            return p
        def call(sock, *args, data=None, timeout=20):
            return subprocess.run([binary, "--socket", str(sock), *map(str,args)], input=data, capture_output=True, env=env, timeout=timeout)
        def stop(p):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
        def success(result, expected=None):
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            if expected is not None:
                assert result.stdout == expected, (result.stdout[:1000], expected[:1000], result.stderr)
        bob = root / "b" / "sock"
        alice = root / "a" / "sock"
        clark = root / "c" / "sock"
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        address = f"127.0.0.1:{port}"
        common = 'heartbeat_secs=1\nheartbeat_timeout_secs=4\nreconnect_secs=1\n'
        bob_cfg = config("bob", common + '''
[[peers]]
id="alice-key"
name="alice"
psk="alice-test-password"
[[peers]]
id="clark-key"
name="clark"
psk="clark-test-password"
''')
        alice_cfg = config("alice", common + 'credential="alice-key"\npsk="alice-test-password"\n')
        clark_cfg = config("clark", common + 'credential="clark-key"\npsk="clark-test-password"\n')
        try:
            daemon = start("--config", bob_cfg, "--socket", bob, "daemon", address)
            wait_for(lambda: bob.exists())
            wrong = start("--socket", root / "w" / "sock", "join", "--credential", "alice-key", "-p", "wrong", "--reconnect-secs", "1", address)
            wait_for(lambda: "authentication failed" in logs[-1].read_text())
            assert len(call(bob, "list").stdout.splitlines()) == 1
            assert wrong.poll() is None
            stop(wrong)
            a = start("--config", alice_cfg, "--socket", alice, "join", "-n", "alice", address)
            wait_for(lambda: b"alice-key" in call(bob, "list").stdout)
            print("PASS authentication, wrong password, persistent join", flush=True)

            success(call(bob, "console", "--", "printf", "%s|%s", "a b", "$(touch nope);*"), b"a b|$(touch nope);*")
            data = bytes(range(256)) * 4096
            success(call(bob, "console", "--", "cat", data=data), data)
            success(call(bob, "console", "--", "head", "-c", "1", data=data), data[:1])
            r = call(bob, "console", "--", "sh", "-c", "printf out; printf err >&2; exit 17")
            assert (r.returncode, r.stdout, r.stderr) == (17, b"out", b"err"), r
            success(call(bob, "console", "--", "sh", "-c", "head -c 1048576 /dev/zero"), bytes(1048576))
            r = call(bob, "console", "--", "/does-not-exist")
            assert r.returncode == 255 and b"exec" in r.stderr
            print("PASS argv, binary stdin/stdout, EOF, stderr, exit status, exec failure", flush=True)

            r = call(bob, "console", "--pty=always", "--", "sh", "-c", "test -t 0 && test -t 1 && printf pty-ok")
            success(r)
            assert r.stdout.endswith(b"pty-ok"), r.stdout  # macOS may echo synthesized terminal EOF.
            success(call(bob, "console", "--pty=never", "--", "sh", "-c", "test ! -t 0 && printf pipe-ok"), b"pipe-ok")
            r = call(bob, "console", "--pty=never", data=b'printf "login:%s\\n" "$0"\nexit\n')
            success(r)
            assert b"login:-" in r.stdout, r.stdout
            print("PASS PTY, pipe mode, default login shell", flush=True)

            c = start("--config", clark_cfg, "--socket", clark, "join", "-n", "alice", address)
            wait_for(lambda: b"clark-key" in call(bob, "list").stdout)
            r = call(bob, "console", "--", "true")
            assert r.returncode == 255 and b"ambiguous" in r.stderr
            for name in ("alice", "clark"):
                success(call(bob, "console", "-n", name, "--", "printf", name), name.encode())
            # Clark's self-reported name cannot override Bob's configured alias.
            assert b"clark" in call(bob, "list").stdout
            r = call(alice, "console", "--", "true")
            assert r.returncode == 255 and b"does not allow" in r.stderr
            r = call(alice, "console", "-n", "clark", "--", "true")
            assert r.returncode == 255 and b"no matching" in r.stderr
            peers = call(bob, "list").stdout.splitlines()[1:]
            device_id = peers[0].split()[0].decode()
            success(call(bob, "console", "--id", device_id, "--", "printf", "by-id"), b"by-id")
            print("PASS multiple peers, authoritative names, ambiguity, ID selection, isolation", flush=True)

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                results = list(pool.map(lambda i: call(bob, "console", "-n", "alice", "--", "sh", "-c", f"sleep 0.1; printf {i}"), range(5)))
            for i, result in enumerate(results):
                success(result, str(i).encode())
            # An unread output pipe must not block heartbeats or other sessions.
            slow = subprocess.Popen([binary, "--socket", str(bob), "console", "-n", "alice", "--", "sh", "-c", "yes"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            processes.append(slow)
            time.sleep(5)
            success(call(bob, "console", "-n", "alice", "--", "printf", "responsive"), b"responsive")
            stop(slow)
            print("PASS concurrent commands, slow-reader backpressure, heartbeat", flush=True)

            # A real local terminal verifies resize forwarding and raw-mode restoration.
            master, slave = pty.openpty()
            import termios
            original = termios.tcgetattr(slave)
            original_flags = fcntl.fcntl(slave, fcntl.F_GETFL)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 31, 97, 0, 0))
            terminal = subprocess.Popen([binary, "--socket", str(bob), "console", "-n", "alice", "--", "sh", "-c", "stty size; read x; stty size; sleep 30"], stdin=slave, stdout=slave, stderr=slave, env=env)
            processes.append(terminal)
            captured = bytearray()
            def see(needle):
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    captured.extend(os.read(master, 8192))
                return needle in captured
            wait_for(lambda: see(b"31 97"))
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 111, 0, 0))
            terminal.send_signal(signal.SIGWINCH)
            time.sleep(0.2); os.write(master, b"\n")
            wait_for(lambda: see(b"42 111"))
            os.write(master, b"\x03")
            terminal.wait(timeout=5)
            assert terminal.returncode == 130, (terminal.returncode, captured)
            assert termios.tcgetattr(slave) == original
            # macOS adds a non-settable internal "was written" bit after any write.
            flag_mask = os.O_NONBLOCK | os.O_APPEND | os.O_ASYNC
            assert fcntl.fcntl(slave, fcntl.F_GETFL) & flag_mask == original_flags & flag_mask
            os.close(master); os.close(slave)
            print("PASS window resize, Ctrl-C, terminal restoration", flush=True)

            marker = root / "child-pid"
            session = subprocess.Popen([binary, "--socket", str(bob), "console", "-n", "alice", "--", "sh", "-c", f"echo $$ > {marker}; exec sleep 90"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            processes.append(session)
            wait_for(marker.exists)
            child_pid = int(marker.read_text())
            stop(session)
            def gone():
                try:
                    os.kill(child_pid, 0); return False
                except ProcessLookupError:
                    return True
            wait_for(gone)
            print("PASS disconnected console terminates and reaps remote command", flush=True)

            # Cancellation must still work when the remote process never reads stdin.
            for sig in (signal.SIGINT, signal.SIGTERM):
                marker.unlink()
                with (root / "large-input").open("wb") as f:
                    f.write(bytes(2 * 1024 * 1024))
                with (root / "large-input").open("rb") as f:
                    blocked = subprocess.Popen([binary, "--socket", str(bob), "console", "-n", "alice", "--", "sh", "-c", f"echo $$ > {marker}; exec sleep 90"], stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                processes.append(blocked)
                wait_for(marker.exists)
                child_pid = int(marker.read_text())
                time.sleep(0.3)
                blocked.send_signal(sig)
                blocked.wait(timeout=5)
                wait_for(gone, timeout=5)
            print("PASS cancellation with fully backpressured stdin", flush=True)

            stop(daemon)
            assert a.poll() is None and c.poll() is None
            wait_for(lambda: len(call(alice, "list").stdout.splitlines()) == 1)
            daemon = start("--config", bob_cfg, "--socket", bob, "daemon", address)
            wait_for(lambda: len(call(bob, "list").stdout.splitlines()) == 3, timeout=30)
            success(call(bob, "console", "-n", "alice", "--", "printf", "reconnected"), b"reconnected")
            print("PASS Bob restart and automatic reconnect", flush=True)

            # Bad frames and stalled unauthenticated peers cannot stop the listener.
            with socket.create_connection(("127.0.0.1", port)) as s:
                s.sendall(struct.pack("!I", 0xFFFFFFFF))
            success(call(bob, "console", "-n", "alice", "--", "true"))
            duplicate = start("--config", bob_cfg, "--socket", bob, "daemon", "127.0.0.1:0")
            duplicate.wait(timeout=10)
            assert duplicate.returncode != 0
            success(call(bob, "console", "-n", "alice", "--", "true"))
            print("PASS oversized unauthenticated frame, duplicate daemon socket protection", flush=True)

            stop(a)
            wait_for(lambda: b"alice-key" not in call(bob, "list").stdout)
            proxy = BlackholeProxy(port)
            proxies.append(proxy)
            a = start("--config", alice_cfg, "--socket", alice, "join", f"127.0.0.1:{proxy.port}")
            wait_for(lambda: b"alice-key" in call(bob, "list").stdout)
            proxy.blackhole.set()
            wait_for(lambda: len(call(alice, "list").stdout.splitlines()) == 1, timeout=10)
            assert a.poll() is None
            proxy.blackhole.clear()
            wait_for(lambda: b"alice-key" in call(bob, "list").stdout, timeout=30)
            success(call(bob, "console", "-n", "alice", "--", "printf", "after-blackhole"), b"after-blackhole")
            print("PASS silent network blackhole detection and reconnect", flush=True)

            baseline = call(bob, "list").stdout
            for _ in range(40):
                success(call(bob, "console", "-n", "alice", "--", "true"))
            assert call(bob, "list").stdout == baseline
            print("PASS repeated session lifecycle", flush=True)
        except BaseException:
            for log in logs:
                print(f"--- {log.name} ---\n{log.read_text()}", flush=True)
            raise
        finally:
            for p in reversed(processes):
                stop(p)
            for proxy in proxies:
                proxy.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="target/debug/marriedsh")
    args = parser.parse_args()
    run(str(pathlib.Path(args.binary).resolve()))
