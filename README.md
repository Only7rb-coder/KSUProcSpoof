# ProcSpoof

A Zygisk module (KernelSU / Magisk / ZygiskNext / ReZygisk) with a WebUI that makes
selected apps see a **stock process state**:

| Detector signal | What the module reports |
| --- | --- |
| `getppid() > 5000` (parent is not the early-boot zygote) | a configurable low parent PID (default 750) |
| `Seccomp: 0` in `/proc/self/status` | `Seccomp: 2` (content rewritten on the fly) |
| `prctl(PR_GET_SECCOMP)` returning 0 | 2 (`SECCOMP_MODE_FILTER`) |
| `TracerPid: N` (ptrace residue) | `TracerPid: 0` (optional) |
| Root daemons visible via `/proc` / cgroup scans ("Abnormal process") | names you list are filtered out (optional, experimental) |

Hooking is **PLT/GOT only** (via [LSPlt](https://github.com/LSPosed/LSPlt)). No code
page of any library is patched, so executable-segment CRC / inline-hook checks
("Malicious Hook", "Critical libc inline hook") are not triggered.

Works with any Zygisk provider: ZygiskNext, ReZygisk, NeoZygisk, Magisk built-in Zygisk.
The WebUI opens from KernelSU manager (or MMRL) — it is a plain `webroot/index.html`.

## Why your ppid is > 5000 in the first place

With LKM-mode KernelSU and ptrace-based Zygisk providers, zygote is (re)started late
and gets a high PID. Every app forked afterwards inherits that high parent PID, which
is exactly what the `getppid() > 5000` criterion flags. The module reports a plausible
early-boot PID to the apps you select; the rest of the system is untouched.

## Build

### Easiest: GitHub Actions (no local toolchain needed)

1. Make sure `.github/workflows/build.yml` exists (see note below if it is missing).
2. Actions → **Build** → Run workflow (or just push).
3. Download the `procspoof-zip` artifact → flash in KernelSU manager.
4. Tag a release (`git tag v1.0.0 && git push --tags`) to get the zip attached to a Release.

### Local build

Requires Android NDK r25+ and CMake:

```sh
cmake -S native -B build \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
cmake --build build
cp build/libprocspoof.so module/zygisk/arm64-v8a.so
# repeat per ABI, then:
cd module && zip -r9 ../procspoof.zip . -x '*/.gitkeep'
```

## Configure

Everything is configured from the WebUI (KernelSU manager → module → WebUI).
Files live in `/data/adb/ksu_proc_spoof/` and survive module updates:

- `config.conf` — `enabled`, `fake_ppid`, `spoof_seccomp`, `spoof_tracerpid`, `hide_procs`
- `targets.txt` — package names to spoof (`*` = every app, not recommended)
- `hideprocs.txt` — process names hidden from the target's `/proc` and cgroup views

Config is read **per app start** by a root companion process, so changes take effect
after force-stopping the target app — no reboot needed.

## Notes & limitations

- **"Found KSU / no-unlock device"**: this item can also appear right after a
  *hot reboot* — do a full reboot once before judging the module.
- **"Abnormal process"**: expand the item in the detector to get the pid list, run
  `su -c "ps -ef | grep <pid>"` to identify the daemon (commonly the Zygisk provider's
  monitor or a keybox daemon), then put its process name in `hideprocs.txt` and enable
  "Hide processes". Hiding is best-effort: it covers `/proc` listing/access and
  `cgroup.procs` content, but not kernel vulnerabilities the detector may abuse.
- If a detector calls `getppid` via a **fully inlined raw syscall** (its own `svc`
  stub, no libc at all), no userspace hook can see it — that needs a kernel-level
  approach (e.g. SuSFS). The common cases (libc wrappers, `syscall()`,
  `android.system.Os`) are all covered.
- The fake parent PID is a number, not a real process. A detector that also reads
  `/proc/<ppid>/cmdline` and cross-checks it is "zygote64" would notice; pick a PID
  accordingly (the WebUI shows your real zygote pid for reference).
- Spoofed files are served from `memfd`; an extremely paranoid reader could
  `readlink("/proc/self/fd/N")` and see `/memfd:... (deleted)`. Not observed in the
  criteria this module targets.

## Safety

- Hooks only activate inside the apps listed in `targets.txt`; everything else is
  untouched, and the module unloads itself elsewhere.
- Boot-loop recovery: reboot into safe mode (hold volume-down during boot) or
  `adb wait-for-device shell rm -rf /data/adb/modules/procspoof`.

## Credits / licenses

- Zygisk API header: [topjohnwu/zygisk-module-sample](https://github.com/topjohnwu/zygisk-module-sample) (0BSD)
- PLT hooking: [LSPosed/LSPlt](https://github.com/LSPosed/LSPlt) (LGPL-3.0, statically linked; source at the linked repo)

For technical study and interoperability testing on your own device only.
