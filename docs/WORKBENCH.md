# Confidential analysis workbench

Some questions need math across several files: "What were our combined wages?", "How many days until each
passport expires?", "Add up this year's medical bills." For these, the private model can write a short Python
script. The box runs it in a sealed sandbox on the box itself, and the model reads the result.

- **What the script can see:** read-only copies of only the asking person's files: their own folders, the
  family's shared files, and any folders the owner granted them. Health folders stay owner only.
- **What it cannot do:** reach the internet or the home network, see anyone else's files, see the box's own
  folders (settings, search index, logs, keys), start other programs, or keep anything it writes.
- **Where the output goes:** back to the model only. Whatever the model then says goes through the same
  answer gate as every other answer.
- **What gets logged:** every script, what it printed, and any limit it hit. They go in the question's event
  log, its audit entry, and the person's own workbench log. Private numbers are replaced with
  `[protected]`. Each person can see their own scripts on the box's web page, under Analysis.

## Switching it on

Off by default. The box owner adds this to `family.toml`:

```toml
[workbench]
enabled = true
people = ["dana", "maya"]   # optional: only these people get it (default: everyone)
```

`FAMILYBOX_WORKBENCH=on` or `off` overrides the file. Check it with `familybox workbench status --as maya`.
Try a script by hand with `familybox workbench run --as maya script.py`, and list past scripts with
`familybox workbench log --as maya`.

The tool is only offered to the model when the sandbox actually works on the computer. On a Mac, or on a
Linux computer that does not allow unprivileged user namespaces, it is not offered and `status` says why.

## How the sandbox is built

No root, no sudo, and no extra packages: only `unshare` (util-linux) and the system Python. These are the
same tools a stock Raspberry Pi OS has. Code: `src/familybox/sandbox.py` (host side) and
`src/familybox/sandbox_launcher.py` (runs inside the namespaces).

1. **Staging.** The box copies the person's readable files into a private temporary folder (mode 0700):
   `files/<path>` (the original), `text/<path>.txt` (plain text, FHIR flattened, PDFs through pdftotext),
   and `index.json`. Links are skipped, so a link in someone's folder can never pull in another person's file.
2. **New namespaces.** `unshare --user --map-root-user --mount --net --pid --ipc --uts --fork --kill-child`
   starts the launcher as process 1 of a new PID namespace with an empty network namespace.
3. **New root from an allowlist.** The launcher builds a fresh tmpfs root with `/usr` (and the `/bin`, `/lib`
   links) bound read-only, a tiny `/etc`, five `/dev` nodes, read-only `/data` and `/code`, and small
   writable `/work` and `/tmp`. It then calls `pivot_root` and detaches the old root. The host's `/home`,
   the box folder, `/run` (sockets), `/proc` and `/sys` are not hidden behind something: they are not in
   the sandbox at all. `/proc` is empty, so the script cannot read other processes or their environments.
4. **No privileges.** All capabilities are dropped (bounding set, ambient set, securebits locked,
   `no_new_privs`). The script cannot mount, unmount or remount anything.
5. **Limits.** Per script: 512 MB of memory, 20 s of CPU, 30 s of wall time, 16 threads, 16 MB per file it
   writes, 64 open files, 32 MB in `/work` and 16 MB in `/tmp`. The output the model sees is capped at
   16 KB, and a script that prints more than 4 MB in total is stopped. At most one script runs at a time,
   and three per question.
6. **Seccomp filter.** Threads are allowed but new processes are refused, so the memory limit covers the
   whole script. The filter also refuses the calls sandbox escapes usually start from: namespaces, mounts,
   ptrace, keyrings, bpf, io_uring, kernel modules and others. The filter exists for aarch64 (checked on the
   Pi) and x86_64.
7. **Clean up.** When the script ends, the launcher exits and the kernel ends every process left in the
   namespace. The tmpfs folders disappear with it, and the host staging copy is deleted.

The script gets a clean environment (`PATH`, `HOME=/work`, `TMPDIR`, `LANG`), so API keys in the box's
environment never reach it. The status line the box reads comes on a private pipe the script does not have,
so a script cannot fake its own exit status.

## Tests

`tests/test_workbench.py`. The first part runs anywhere with a fake sandbox: the switch, the
people list, the staging scope (including links to other people's files), logging and scrubbing, the gate
still holding a protected value from script output, the per-question cap, the CLI, the web page, the
`fleet_exec.py` folder check, and the seccomp program's decisions (through a small BPF interpreter).

The second part runs real scripts and is skipped unless the sandbox works on that computer. It checks:
no network (TCP, UDP, DNS; only `lo` exists), no reading outside the workspace (another person's file,
the runtime folder, the box home, `/home/offlinebase/familybox`, `.env`, `/proc/1/environ`, `/run`),
reading your own files, writes refused or thrown away, no privileges, refused escape calls, memory bomb,
endless loop (CPU limit) and sleeping forever (wall clock), fork bomb, threads, output cap and output
flood, a script that tries to fake its status, and a full question through the box.

On the Pi: `FAMILYBOX_PI_DIR=~/familybox-wb uv run --env-file .env python scripts/fleet_exec.py test tests/test_workbench.py`

## Limits of this design

- **It is not a VM.** The script shares the kernel with the box. A kernel bug reachable from the allowed
  system calls could break out. The seccomp filter removes the usual starting points, but it is a deny list.
- **No cgroups.** Memory is limited per process (address space). Because the script cannot start other
  processes, that covers the whole script, but tmpfs space and threads are counted separately.
- **The model writes the code.** A model tricked by a planted instruction could compute something sneaky from
  the person's own files, for example a protected number written backwards. The gate checks the final answer
  for the protected values in many forms, but it cannot know every transformation. The script only ever sees
  that one person's files, so the worst case is that person's own data, not anyone else's.
- **Blocking call.** The tool runs synchronously inside the question, for up to about 30 s.
