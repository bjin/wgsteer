"""Namespace plumbing for the integration suite (adapted from phantun's harness).

`setup_userns()` maps the invoking user to root in a fresh user + network
namespace, so the suite needs no host privileges. Every node of the topology is
a `NetNS`: a sleeping child process that owns a network namespace (and
optionally a private mount namespace). Commands run inside a node by entering
its namespaces between fork and exec.

`ManagedProcess` wraps a long-running command inside a node and collects its
combined stdout/stderr lines into a thread-safe buffer for `wait_for_log`.
"""

import ctypes
import os
import re
import signal
import subprocess
import sys
import threading
import time

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

_PR_SET_PDEATHSIG = 1
_MS_REC = 0x4000
_MS_PRIVATE = 1 << 18
_MS_BIND = 0x1000


def setup_userns():
    """
    Creates a new user and network namespace, mapping the current unprivileged
    user to 'root' (UID/GID 0) inside the namespace.

    Call it once at the very start of the test program, before any threads
    exist. Requirements: unprivileged user namespaces enabled on the host and
    `/dev/net/tun` accessible (for the wireguard-go variant).

    Writing "deny" to /proc/self/setgroups is required by the kernel before
    writing /proc/self/gid_map.
    """
    try:
        uid = os.getuid()
        gid = os.getgid()
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"0 {uid} 1\n")
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"0 {gid} 1\n")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    except PermissionError:
        print("PermissionError: unprivileged user namespaces might be restricted.", file=sys.stderr)
        sys.exit(1)


def _die_with_parent():
    # Children of the test process die with it, even on SIGKILL of the runner.
    _libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)


def _mount(source, target, fstype, flags, data=None):
    enc = lambda s: s.encode() if s is not None else None
    if _libc.mount(enc(source), enc(target), enc(fstype), flags, enc(data)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {target}: {os.strerror(err)}")


def enter_ns(pid, mount=False):
    """Moves the calling (single-threaded) process into the namespaces of pid."""
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        os.setns(fd, os.CLONE_NEWNET)
    finally:
        os.close(fd)
    if mount:
        # setns(CLONE_NEWNS) resets root and cwd to the namespace root; the
        # mount namespace is a copy of ours, so the same path resolves again.
        cwd = os.getcwd()
        fd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
        try:
            os.setns(fd, os.CLONE_NEWNS)
        finally:
            os.close(fd)
        os.chdir(cwd)


class CommandError(RuntimeError):
    pass


class NetNS:
    """
    An isolated network namespace held open by a sleeping child process.

    private_run=True gives the node a tmpfs on /run (with /run/wireguard
    created in it). /run/wireguard does not exist on the host and /run is not
    writable from the user namespace, so the whole of /run is replaced.
    wireguard-go's UAPI sockets and wgctrl's userspace lookup
    (/var/run/wireguard -> /run/wireguard) then meet there, invisible to the
    host.

    binds: {target: source} directories bind-mounted over existing targets.

    Either option creates a private mount namespace for the node; every
    command run in the node enters it.
    """

    def __init__(self, name, private_run=False, binds=None):
        self.name = name
        self.private_mnt = bool(private_run or binds)
        r1, w1 = os.pipe()  # child -> parent: namespace ready (or error text)
        r2, w2 = os.pipe()  # parent -> child: exit (EOF when the parent dies)
        pid = os.fork()
        if pid == 0:
            try:
                keep = {0, 1, 2, w1, r2}
                for fd in os.listdir("/proc/self/fd"):
                    if int(fd) not in keep:
                        try:
                            os.close(int(fd))
                        except OSError:
                            pass
                _die_with_parent()
                flags = os.CLONE_NEWNET
                if self.private_mnt:
                    flags |= os.CLONE_NEWNS
                os.unshare(flags)
                if self.private_mnt:
                    _mount(None, "/", None, _MS_REC | _MS_PRIVATE)
                for target, source in (binds or {}).items():
                    _mount(source, target, None, _MS_BIND)
                if private_run:
                    _mount("tmpfs", "/run", "tmpfs", 0, "mode=0755")
                    os.mkdir("/run/wireguard", 0o700)
                os.write(w1, b"1")
            except BaseException as e:  # report to the parent, never return into the test runner
                os.write(w1, b"E" + str(e).encode()[:500])
                os._exit(1)
            os.read(r2, 1)
            os._exit(0)

        os.close(w1)
        os.close(r2)
        msg = os.read(r1, 1024)
        os.close(r1)
        self.pid = pid
        self.kill_pipe = w2
        if msg != b"1":
            self.cleanup()
            raise RuntimeError(f"namespace {name}: {msg[1:].decode(errors='replace') or 'child died'}")

    def cleanup(self):
        if self.kill_pipe is None:
            return
        try:
            os.write(self.kill_pipe, b"1")
        except OSError:
            pass
        os.waitpid(self.pid, 0)
        os.close(self.kill_pipe)
        self.kill_pipe = None

    def _preexec(self):
        _die_with_parent()
        enter_ns(self.pid, mount=self.private_mnt)

    def popen(self, cmd, **kwargs):
        """subprocess.Popen inside the namespace. Call from the main thread (PDEATHSIG follows the forking thread)."""
        return subprocess.Popen(cmd, preexec_fn=self._preexec, **kwargs)

    def run(self, cmd, **kwargs):
        """subprocess.run inside the namespace."""
        return subprocess.run(cmd, preexec_fn=self._preexec, **kwargs)

    def check(self, cmd, input=None, env=None, timeout=60):
        """Runs cmd, returns stdout (text); raises CommandError with stderr on failure."""
        p = self.run(cmd, input=input, env=env, timeout=timeout, capture_output=True, text=True)
        if p.returncode != 0:
            raise CommandError(f"[{self.name}] {' '.join(map(str, cmd))}: exit {p.returncode}: {p.stderr.strip()}")
        return p.stdout

    def __repr__(self):
        return f"NetNS({self.name}, pid={self.pid})"


class ManagedProcess:
    """
    A long-running command inside a NetNS with its combined stdout+stderr
    collected line by line (thread-safe). Indices returned by mark() can be
    passed as `since` to only look at lines logged after that point.
    """

    def __init__(self, ns, cmd, name=None, env=None, stdin=None, cwd=None):
        self.ns = ns
        self.cmd = [str(c) for c in cmd]
        self.name = name or os.path.basename(self.cmd[0])
        self._lines = []
        self._times = []
        self._cond = threading.Condition()
        self._eof = False
        self.proc = ns.popen(
            self.cmd,
            stdin=subprocess.PIPE if stdin is True else subprocess.DEVNULL if stdin is None else stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=cwd,
        )
        self._reader = threading.Thread(target=self._read, name=f"log-{self.name}", daemon=True)
        self._reader.start()

    def _read(self):
        for raw in self.proc.stdout:
            line = raw.decode(errors="replace").rstrip("\n")
            with self._cond:
                self._lines.append(line)
                self._times.append(time.monotonic())
                self._cond.notify_all()
        self.proc.stdout.close()
        with self._cond:
            self._eof = True
            self._cond.notify_all()

    @property
    def pid(self):
        return self.proc.pid

    @property
    def returncode(self):
        return self.proc.poll()

    def running(self):
        return self.proc.poll() is None

    def lines(self, since=0):
        with self._cond:
            return list(self._lines[since:])

    def line_times(self, since=0):
        """Monotonic receive time of each line (same indices as lines())."""
        with self._cond:
            return list(self._times[since:])

    def output(self):
        return "\n".join(self.lines())

    def mark(self):
        """Current line count; pass as `since` to ignore older lines."""
        with self._cond:
            return len(self._lines)

    def find_logs(self, regex, since=0):
        rx = re.compile(regex)
        return [m for m in (rx.search(l) for l in self.lines(since)) if m]

    def wait_for_log(self, regex, timeout=10.0, since=0):
        """
        Waits for a line matching regex (re.search) at index >= since and
        returns the re.Match (its .string is the line). Raises TimeoutError,
        including the log tail, on timeout or if the process exits first.
        """
        rx = re.compile(regex)
        return self.wait_for_line(rx.search, timeout, since, desc=f"line matching {regex!r}")[1]

    def wait_for_line(self, fn, timeout=10.0, since=0, desc="matching line"):
        """
        Waits for the first line at index >= since for which fn(line) is
        truthy and returns (index, fn(line)). Raises TimeoutError like
        wait_for_log.
        """
        deadline = time.monotonic() + timeout
        i = since
        with self._cond:
            while True:
                while i < len(self._lines):
                    v = fn(self._lines[i])
                    if v:
                        return i, v
                    i += 1
                if self._eof:
                    reason = f"process exited (rc={self.proc.poll()})"
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    reason = f"timeout after {timeout}s"
                    break
                self._cond.wait(left)
        tail = "\n".join(self.lines()[-30:])
        raise TimeoutError(f"{self.name}: no {desc} ({reason}); last lines:\n{tail}")

    def write_stdin(self, data):
        self.proc.stdin.write(data.encode() if isinstance(data, str) else data)
        self.proc.stdin.flush()

    def signal(self, sig):
        if self.proc.poll() is None:
            self.proc.send_signal(sig)

    def wait(self, timeout=None):
        rc = self.proc.wait(timeout)
        self._reader.join(timeout=5)
        return rc

    def stop(self, sig=None, timeout=5.0):
        """Sends sig (default SIGTERM), waits up to timeout, then SIGKILLs. Returns the exit code."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM if sig is None else sig)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self._reader.join(timeout=5)
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        return self.proc.returncode

    def kill(self):
        return self.stop(signal.SIGKILL)
