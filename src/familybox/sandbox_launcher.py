"""Runs INSIDE the throwaway Linux namespaces made by familybox.sandbox. Standard library only.

Started as:  unshare --user --map-root-user --mount --net --pid --ipc --uts --fork --kill-child \
                 /usr/bin/python3 -I -S sandbox_launcher.py <stage> <status_fd>

It is process 1 of a fresh PID namespace, root only inside its own user namespace, with no network
devices except a downed loopback. It then:

  1. builds a new root on tmpfs with an allowlist: /usr (and the /bin, /lib... symlinks) bound
     read-only, a tiny /etc, a few /dev nodes, read-only /data (copies of the asker's files) and
     /code, writable tmpfs /work and /tmp that vanish afterwards;
  2. pivots into it and detaches the old root, so the box home, runtime, other people's folders,
     /home, /run (sockets) and /proc of the host are not reachable at all (not just covered);
  3. drops every capability (bounding set, ambient, securebits locked, no_new_privs);
  4. forks the analysis script under rlimits (memory, CPU, threads, file size, open files), a
     seccomp filter and a wall clock, waits for it, and writes one JSON status line to status_fd.

The seccomp filter lets the script start threads but no new processes (so the memory limit
covers the whole script: one address space), and refuses the system calls a sandbox escape or a
kernel exploit usually starts from: namespaces, mounts, ptrace, keyrings, bpf, io_uring and others.

When this process exits, the kernel kills everything else left in the PID namespace.
The analysis script never gets status_fd, so it cannot forge the status line.
"""

import ctypes
import json
import os
import platform
import resource
import shutil
import signal
import socket
import sys
import time

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_RELATIME = 1 << 21
MNT_DETACH = 2

PR_SET_DUMPABLE = 4
PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
# noroot, noroot_locked, no_setuid_fixup, no_setuid_fixup_locked, keep_caps_locked, no_cap_ambient_raise(+locked)
SECUREBITS = 0x01 | 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80

PIVOT_ROOT_NR = {"x86_64": 155, "aarch64": 41, "arm64": 41, "riscv64": 41, "armv7l": 218, "armv6l": 218,
                 "i686": 217, "i386": 217}

SYSTEM_DIRS = ("usr", "bin", "sbin", "lib", "lib64", "lib32", "libx32")
DEV_NODES = ("null", "zero", "full", "random", "urandom")

libc = ctypes.CDLL(None, use_errno=True)

# ---- seccomp ----------------------------------------------------------------------------------
# Syscall numbers. aarch64 uses the generic table (checked against asm-generic/unistd.h on the Pi).
DENY = {
    "aarch64": {"unshare": 97, "setns": 268, "mount": 40, "umount2": 39, "pivot_root": 41, "chroot": 51,
                "ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271, "keyctl": 219,
                "add_key": 217, "request_key": 218, "bpf": 280, "perf_event_open": 241, "userfaultfd": 282,
                "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "kexec_load": 104,
                "kexec_file_load": 294, "init_module": 105, "finit_module": 273, "delete_module": 106,
                "reboot": 142, "swapon": 224, "swapoff": 225, "open_by_handle_at": 265,
                "name_to_handle_at": 264, "mount_setattr": 442, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
                "fspick": 433, "move_mount": 429, "open_tree": 428, "acct": 89, "quotactl": 60, "syslog": 116,
                "fanotify_init": 262, "lookup_dcookie": 18, "personality": 92},
    "x86_64": {"unshare": 272, "setns": 308, "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
               "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "keyctl": 250,
               "add_key": 248, "request_key": 249, "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
               "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "kexec_load": 246,
               "kexec_file_load": 320, "init_module": 175, "finit_module": 313, "delete_module": 176,
               "reboot": 169, "swapon": 167, "swapoff": 168, "open_by_handle_at": 304,
               "name_to_handle_at": 303, "mount_setattr": 442, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
               "fspick": 433, "move_mount": 429, "open_tree": 428, "acct": 163, "quotactl": 179, "syslog": 103,
               "fanotify_init": 300, "lookup_dcookie": 212, "personality": 135},
}
NEW_PROCESS = {"aarch64": {}, "x86_64": {"fork": 57, "vfork": 58}}
CLONE = {"aarch64": 220, "x86_64": 56}
CLONE3 = 435
AUDIT_ARCH = {"aarch64": 0xC00000B7, "x86_64": 0xC000003E}
CLONE_THREAD = 0x00010000
EPERM, EAGAIN, ENOSYS = 1, 11, 38
RET_KILL_PROCESS, RET_ALLOW, RET_ERRNO = 0x80000000, 0x7FFF0000, 0x00050000
LD_ABS, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def seccomp_program(arch):
    """BPF: wrong arch -> kill; denied calls -> EPERM; new processes -> EAGAIN; clone3 -> ENOSYS
    (so threads fall back to clone, where CLONE_THREAD is checked); everything else allowed."""
    prog = [(LD_ABS, None, None, 4), (JEQ, "load_nr", "kill", AUDIT_ARCH[arch]),
            ("label", "load_nr"), (LD_ABS, None, None, 0)]
    if arch == "x86_64":
        prog.append((JGE, "eperm", None, 0x40000000))   # the x32 ABI
    for nr in sorted(DENY[arch].values()):
        prog.append((JEQ, "eperm", None, nr))
    for nr in NEW_PROCESS[arch].values():
        prog.append((JEQ, "eagain", None, nr))
    prog += [(JEQ, "enosys", None, CLONE3), (JEQ, "clone", None, CLONE[arch]), (RET, None, None, RET_ALLOW),
             ("label", "clone"), (LD_ABS, None, None, 16),   # args[0] (clone flags), low 32 bits
             (JSET, "allow", "eagain", CLONE_THREAD),
             ("label", "allow"), (RET, None, None, RET_ALLOW),
             ("label", "eagain"), (RET, None, None, RET_ERRNO | EAGAIN),
             ("label", "eperm"), (RET, None, None, RET_ERRNO | EPERM),
             ("label", "enosys"), (RET, None, None, RET_ERRNO | ENOSYS),
             ("label", "kill"), (RET, None, None, RET_KILL_PROCESS)]
    labels, out = {}, []
    for ins in prog:
        if ins[0] == "label":
            labels[ins[1]] = len(out)
        else:
            out.append(ins)
    resolved = []
    for i, (code, jt, jf, k) in enumerate(out):
        rel = [0 if lab is None else labels[lab] - (i + 1) for lab in (jt, jf)]
        if not all(0 <= r < 256 for r in rel):
            raise ValueError("seccomp jump out of range")
        resolved.append((code, rel[0], rel[1], k))
    return resolved


def install_seccomp():
    arch = {"arm64": "aarch64"}.get(platform.machine(), platform.machine())
    if arch not in DENY:
        raise OSError(0, f"no seccomp filter for {arch}")
    prog = seccomp_program(arch)
    arr = (SockFilter * len(prog))(*[SockFilter(*ins) for ins in prog])
    fprog = SockFprog(len(prog), arr)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    _check(libc.prctl(22, 2, ctypes.cast(ctypes.byref(fprog), ctypes.c_void_p), 0, 0),
           "seccomp")  # PR_SET_SECCOMP, SECCOMP_MODE_FILTER


def _b(s):
    return None if s is None else os.fsencode(s)


def _check(rc, what):
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{what}: {os.strerror(e)}")


def mount(src, target, fstype, flags, data=None):
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    _check(libc.mount(_b(src), _b(target), _b(fstype), flags, _b(data)), f"mount {target}")


def kept_flags(path):
    """Mount flags the kernel locks for us in a user namespace: carry them into any remount."""
    f = os.statvfs(path).f_flag
    out = 0
    for st, ms in ((os.ST_NOEXEC, MS_NOEXEC), (os.ST_NOATIME, MS_NOATIME), (os.ST_NODIRATIME, MS_NODIRATIME),
                   (getattr(os, "ST_RELATIME", 4096), MS_RELATIME)):
        if f & st:
            out |= ms
    return out


def bind_ro(src, target):
    try:
        mount(src, target, None, MS_BIND)
    except OSError:
        mount(src, target, None, MS_BIND | MS_REC)  # source has locked submounts
    mount(None, target, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | kept_flags(src))


def tmpfs(target, size, mode, inodes=2048, extra=0):
    mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV | extra, f"size={size},nr_inodes={inodes},mode={mode}")


def build_root(stage, spec):
    root = os.path.join(stage, "root")
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    tmpfs(root, "4m", "0755")
    for d in SYSTEM_DIRS:
        src = "/" + d
        dst = os.path.join(root, d)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.mkdir(dst)
            bind_ro(src, dst)

    etc = os.path.join(root, "etc")
    os.mkdir(etc)
    for name in ("ld.so.cache", "ld.so.conf", "localtime"):
        if os.path.isfile("/etc/" + name):
            shutil.copyfile("/etc/" + name, os.path.join(etc, name))
    if os.path.isdir("/etc/ld.so.conf.d"):
        shutil.copytree("/etc/ld.so.conf.d", os.path.join(etc, "ld.so.conf.d"), symlinks=False,
                        ignore_dangling_symlinks=True)
    with open(os.path.join(etc, "passwd"), "w") as f:
        f.write("sandbox:x:0:0:sandbox:/work:/bin/false\n")
    with open(os.path.join(etc, "group"), "w") as f:
        f.write("sandbox:x:0:\n")
    with open(os.path.join(etc, "hosts"), "w") as f:
        f.write("127.0.0.1 localhost\n")

    dev = os.path.join(root, "dev")
    os.mkdir(dev)
    for name in DEV_NODES:
        node = os.path.join(dev, name)
        open(node, "w").close()
        mount("/dev/" + name, node, None, MS_BIND)
    os.symlink("/proc/self/fd", os.path.join(dev, "fd"))

    for d in ("work", "tmp", "data", "code", "proc"):
        os.mkdir(os.path.join(root, d))
    tmpfs(os.path.join(root, "work"), spec["work_bytes"], "0755")
    tmpfs(os.path.join(root, "tmp"), spec["tmp_bytes"], "1777")
    data = os.path.join(root, "data")
    tmpfs(data, spec["data_bytes"], "0755", inodes=spec["data_inodes"])
    shutil.copytree(spec["data_src"], data, dirs_exist_ok=True, symlinks=True)  # links copied as links
    mount(None, data, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
    shutil.copyfile(os.path.join(stage, "main.py"), os.path.join(root, "code", "main.py"))
    # /proc stays an empty directory: no process list, no /proc/<pid>/environ, nothing of the host.

    os.chdir(root)
    nr = PIVOT_ROOT_NR.get(platform.machine())
    if nr is None:
        raise OSError(0, f"pivot_root: unknown machine {platform.machine()}")
    _check(libc.syscall(nr, b".", b"."), "pivot_root")
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _check(libc.umount2(b".", MNT_DETACH), "umount old root")
    os.chdir("/")
    # The new root itself becomes read-only too; only /work and /tmp take writes.
    mount(None, "/", None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    try:
        socket.sethostname("sandbox")
    except OSError:
        pass


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def drop_privileges():
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    _check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs")
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    for cap in range(64):
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            break  # EINVAL: past the last capability this kernel knows
    _check(libc.prctl(PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0), "securebits")
    hdr = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    _check(libc.capset(ctypes.byref(hdr), data), "capset")
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)


def limit_child(spec):
    mem = spec["memory_bytes"]
    for res, soft, hard in (
        (resource.RLIMIT_AS, mem, mem),
        (resource.RLIMIT_DATA, mem, mem),
        (resource.RLIMIT_CPU, spec["cpu_s"], spec["cpu_s"] + 1),
        (resource.RLIMIT_NPROC, spec["max_procs"], spec["max_procs"]),
        (resource.RLIMIT_FSIZE, spec["file_bytes"], spec["file_bytes"]),
        (resource.RLIMIT_NOFILE, 64, 64),
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_MEMLOCK, 0, 0),
    ):
        resource.setrlimit(res, (soft, hard))


def main():
    stage, status_fd = sys.argv[1], int(sys.argv[2])
    status = {"ok": False, "stage": "setup"}

    def report(**kw):
        status.update(kw)
        os.write(status_fd, (json.dumps(status) + "\n").encode())

    try:
        with open(os.path.join(stage, "spec.json")) as f:
            spec = json.load(f)
        build_root(stage, spec)
        drop_privileges()
    except Exception as e:  # noqa: BLE001 - report and stop; nothing of the script ran
        report(error=f"{type(e).__name__}: {e}")
        os._exit(125)

    started = time.monotonic()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(status_fd)
            os.chdir("/work")
            limit_child(spec)
            install_seccomp()
            env = {"PATH": "/usr/bin:/bin", "HOME": "/work", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
                   "PYTHONIOENCODING": "utf-8"}
            os.execve(spec["python"], [spec["python"], "-I", "/code/main.py"], env)
        except BaseException as e:  # noqa: BLE001
            os.write(2, f"sandbox could not start python: {e}\n".encode())
        os._exit(126)

    timed_out = False

    def on_alarm(signum, frame):
        nonlocal timed_out
        timed_out = True
        try:
            os.kill(-1, signal.SIGKILL)  # every other process in this PID namespace
        except OSError:
            pass

    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(int(spec["wall_s"]))
    code = sig = None
    while True:
        try:
            got, st = os.wait()  # also reaps orphans the script left behind
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        if got == pid:
            if os.WIFSIGNALED(st):
                sig = os.WTERMSIG(st)
            else:
                code = os.WEXITSTATUS(st)
            break
    signal.alarm(0)
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    report(ok=True, stage="done", exit_code=code, signal=sig, timed_out=timed_out,
           seconds=round(time.monotonic() - started, 3), cpu_s=round(ru.ru_utime + ru.ru_stime, 3),
           max_rss_kb=ru.ru_maxrss)
    os._exit(0)


if __name__ == "__main__":
    main()
