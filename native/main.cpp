// ProcSpoof — Zygisk module (Magisk / ZygiskNext / ReZygisk compatible)
//
// Presents stock-looking process state to selected apps:
//   * getppid()           -> configurable low PID (detectors flag ppid > 5000,
//                            typical side effect of ptrace-based Zygisk injection
//                            restarting zygote late in boot)
//   * /proc/self/status   -> "Seccomp: 0" rewritten to "Seccomp: 2",
//                            optional "TracerPid" rewrite to 0 (memfd, on the fly)
//   * prctl(PR_GET_SECCOMP) / syscall(SYS_prctl, PR_GET_SECCOMP) -> 0 becomes 2
//   * syscall(SYS_getppid) -> fake ppid
//   * optional: hide configured processes from /proc listings, /proc/<pid>/*
//               access and cgroup.procs / cgroup.threads contents
//
// Hooking is done with LSPlt (PLT/GOT rewrite) — libc .text is never touched,
// so inline-hook / CRC-versus-disk checks are not triggered.
//
// Config (read as root via the companion, per app start):
//   /data/adb/ksu_proc_spoof/config.conf   key=value, see WebUI
//   /data/adb/ksu_proc_spoof/targets.txt   package/process names, one per line, "*" = all
//   /data/adb/ksu_proc_spoof/hideprocs.txt process names to hide (hide_procs=1)

#include <android/log.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <unordered_set>

#include "zygisk.hpp"
#include "lsplt.hpp"

#define LOG_TAG "ProcSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static constexpr const char *kCfgFile    = "/data/adb/ksu_proc_spoof/config.conf";
static constexpr const char *kTargetFile = "/data/adb/ksu_proc_spoof/targets.txt";
static constexpr const char *kHideFile   = "/data/adb/ksu_proc_spoof/hideprocs.txt";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

struct Config {
    bool enabled        = true;
    long fake_ppid      = 750;   // <= 0 disables ppid spoofing
    bool spoof_seccomp  = true;  // report Seccomp: 2 / PR_GET_SECCOMP = 2
    bool spoof_tracer   = true;  // rewrite TracerPid to 0 in /proc/self/status
    bool hide_procs     = false; // experimental /proc + cgroup hiding
    std::unordered_set<std::string> targets;
    std::unordered_set<std::string> hide_names;
};

static Config g_cfg;
static bool   g_active  = false;   // hooks wanted in this process
static bool   g_hide_on = false;   // proc hiding active (hide_procs && names resolved)
static std::unordered_set<pid_t> g_hidden_pids;

// ---------------------------------------------------------------------------
// Raw syscall helpers (never routed through our own PLT hooks)
// ---------------------------------------------------------------------------

static int sys_open(const char *path, int flags) {
    return (int)::syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}
static std::string read_file_raw(const char *path) {
    int fd = sys_open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::string out;
    char buf[2048];
    ssize_t n;
    while ((n = ::syscall(SYS_read, fd, buf, sizeof(buf))) > 0)
        out.append(buf, (size_t)n);
    ::syscall(SYS_close, fd);
    return out;
}
static int memfd_write(const char *name, const std::string &data) {
    int mfd = (int)::syscall(SYS_memfd_create, name, (unsigned)MFD_CLOEXEC);
    if (mfd < 0) return -1;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t w = ::syscall(SYS_write, mfd, data.data() + off, data.size() - off);
        if (w <= 0) { ::syscall(SYS_close, mfd); return -1; }
        off += (size_t)w;
    }
    ::syscall(SYS_lseek, mfd, 0, SEEK_SET);
    return mfd;
}

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------

static std::string trim(const std::string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static void str_replace(std::string &s, const char *from, const char *to) {
    size_t pos = 0, flen = strlen(from);
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, flen, to);
        pos += strlen(to);
    }
}

static bool ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

// If path is "/proc/<digits>" or "/proc/<digits>/...", returns the pid, else -1.
static long proc_pid_of(const char *path) {
    if (strncmp(path, "/proc/", 6) != 0) return -1;
    const char *p = path + 6;
    if (!isdigit((unsigned char)*p)) return -1;
    long pid = 0;
    while (isdigit((unsigned char)*p)) { pid = pid * 10 + (*p - '0'); p++; }
    if (*p != '\0' && *p != '/') return -1;
    return pid;
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

static void for_each_line(const std::string &text, void (*cb)(const std::string &, void *), void *arg) {
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = (nl == std::string::npos) ? text.substr(pos)
                                                     : text.substr(pos, nl - pos);
        cb(trim(line), arg);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
}

static void cfg_line_cb(const std::string &line, void *) {
    if (line.empty() || line[0] == '#') return;
    size_t eq = line.find('=');
    if (eq == std::string::npos) return;
    std::string key = trim(line.substr(0, eq));
    std::string val = trim(line.substr(eq + 1));
    long v = strtol(val.c_str(), nullptr, 10);
    if      (key == "enabled")         g_cfg.enabled       = (v != 0);
    else if (key == "fake_ppid")       g_cfg.fake_ppid     = v;
    else if (key == "spoof_seccomp")   g_cfg.spoof_seccomp = (v != 0);
    else if (key == "spoof_tracerpid") g_cfg.spoof_tracer  = (v != 0);
    else if (key == "hide_procs")      g_cfg.hide_procs    = (v != 0);
}

static void targets_line_cb(const std::string &line, void *) {
    if (line.empty() || line[0] == '#') return;
    g_cfg.targets.insert(line);
}

static void hide_line_cb(const std::string &line, void *) {
    if (line.empty() || line[0] == '#') return;
    g_cfg.hide_names.insert(line);
}

static void parse_config(const std::string &cfg, const std::string &targets,
                         const std::string &hide) {
    g_cfg = Config{};
    for_each_line(cfg, cfg_line_cb, nullptr);
    for_each_line(targets, targets_line_cb, nullptr);
    for_each_line(hide, hide_line_cb, nullptr);
}

// ---------------------------------------------------------------------------
// Companion IPC (root side reads config; app side parses it)
// ---------------------------------------------------------------------------

static bool write_exact(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) return false;
        p += w; len -= (size_t)w;
    }
    return true;
}
static bool read_exact(int fd, void *buf, size_t len) {
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t r = read(fd, p, len);
        if (r <= 0) return false;
        p += r; len -= (size_t)r;
    }
    return true;
}
static void send_blob(int fd, const std::string &data) {
    uint32_t len = (uint32_t)data.size();
    write_exact(fd, &len, sizeof(len));
    if (len) write_exact(fd, data.data(), len);
}
static bool recv_blob(int fd, std::string &out) {
    uint32_t len = 0;
    if (!read_exact(fd, &len, sizeof(len)) || len > (1u << 20)) return false;
    out.assign(len, '\0');
    return len == 0 || read_exact(fd, out.data(), len);
}

static void companion_handler(int fd) {
    send_blob(fd, read_file_raw(kCfgFile));
    send_blob(fd, read_file_raw(kTargetFile));
    send_blob(fd, read_file_raw(kHideFile));
    close(fd);
}
REGISTER_ZYGISK_COMPANION(companion_handler)

// ---------------------------------------------------------------------------
// /proc scan (used in preAppSpecialize, still root — hidepid does not apply)
// ---------------------------------------------------------------------------

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static const char *base_name(const std::string &s) {
    size_t slash = s.rfind('/');
    return slash == std::string::npos ? s.c_str() : s.c_str() + slash + 1;
}

static bool name_matches_hide_list(const std::string &cmdline) {
    // cmdline may be "tricky_store", "/system/bin/tricky_store", "zygiskd64" ...
    std::string full = cmdline.c_str(); // cut at first NUL
    if (g_cfg.hide_names.count(full)) return true;
    return g_cfg.hide_names.count(base_name(full)) > 0;
}

static void resolve_hidden_pids() {
    g_hidden_pids.clear();
    if (g_cfg.hide_names.empty()) return;
    int fd = sys_open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    alignas(8) char buf[8192];
    for (;;) {
        long nread = ::syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread <= 0) break;
        for (long bpos = 0; bpos < nread;) {
            auto *d = (linux_dirent64 *)(buf + bpos);
            if (isdigit((unsigned char)d->d_name[0])) {
                long pid = strtol(d->d_name, nullptr, 10);
                char p[64];
                snprintf(p, sizeof(p), "/proc/%ld/cmdline", pid);
                std::string cmd = read_file_raw(p);
                if (!cmd.empty() && name_matches_hide_list(cmd)) {
                    g_hidden_pids.insert((pid_t)pid);
                    LOGI("hiding pid %ld (%s) from target", pid, base_name(cmd));
                }
            }
            bpos += d->d_reclen;
        }
    }
    ::syscall(SYS_close, fd);
}

// ---------------------------------------------------------------------------
// Spoofed content builders
// ---------------------------------------------------------------------------

static int spoof_status() {
    std::string data = read_file_raw("/proc/self/status");
    if (data.empty()) return -1;
    if (g_cfg.spoof_seccomp) {
        str_replace(data, "Seccomp:\t0\n", "Seccomp:\t2\n");
        str_replace(data, "Seccomp_filters:\t0\n", "Seccomp_filters:\t1\n");
    }
    if (g_cfg.spoof_tracer) {
        size_t p = data.find("TracerPid:\t");
        if (p != std::string::npos) {
            size_t v = p + strlen("TracerPid:\t");
            size_t e = data.find('\n', v);
            if (e != std::string::npos) data.replace(v, e - v, "0");
        }
    }
    return memfd_write("status", data);
}

static int spoof_pid_list(const char *path) {
    std::string data = read_file_raw(path);
    if (data.empty()) return -1;
    std::string out;
    size_t pos = 0;
    while (pos < data.size()) {
        size_t nl = data.find('\n', pos);
        std::string line = (nl == std::string::npos) ? data.substr(pos)
                                                     : data.substr(pos, nl - pos);
        char *end = nullptr;
        long pid = strtol(line.c_str(), &end, 10);
        bool keep = !(end && *end == '\0' && end != line.c_str() &&
                      g_hidden_pids.count((pid_t)pid));
        if (keep) { out += line; out += '\n'; }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return memfd_write("cgroup", out);
}

// ---------------------------------------------------------------------------
// Path interception policy
// ---------------------------------------------------------------------------

enum : int { INTERCEPT_PASS = -2 };

// Returns >= 0: use this fd. -1: fail with errno set. INTERCEPT_PASS: untouched.
static int intercept_open(const char *path) {
    if (!path || path[0] != '/') return INTERCEPT_PASS;
    if (strncmp(path, "/proc/", 6) == 0) {
        if (g_hide_on) {
            long pid = proc_pid_of(path);
            if (pid > 0 && g_hidden_pids.count((pid_t)pid)) {
                errno = ENOENT;
                return -1;
            }
        }
        if (strcmp(path, "/proc/self/status") == 0 ||
            strcmp(path, "/proc/thread-self/status") == 0) {
            int fd = spoof_status();
            if (fd >= 0) return fd; // fall through to real file on failure
        }
        return INTERCEPT_PASS;
    }
    if (g_hide_on &&
        (ends_with(path, "/cgroup.procs") || ends_with(path, "/cgroup.threads"))) {
        int fd = spoof_pid_list(path);
        if (fd >= 0) return fd;
    }
    return INTERCEPT_PASS;
}

// True when this path must be reported as nonexistent.
static bool deny_path(const char *path) {
    if (!g_hide_on || !path || path[0] != '/') return false;
    long pid = proc_pid_of(path);
    return pid > 0 && g_hidden_pids.count((pid_t)pid);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

static pid_t (*orig_getppid)(void) = nullptr;
static pid_t my_getppid(void) {
    return (pid_t)g_cfg.fake_ppid; // only hooked when fake_ppid > 0
}

static int (*orig_prctl)(int, unsigned long, unsigned long, unsigned long,
                         unsigned long) = nullptr;
static int my_prctl(int option, unsigned long a2, unsigned long a3,
                    unsigned long a4, unsigned long a5) {
    int ret = orig_prctl(option, a2, a3, a4, a5);
    if (option == PR_GET_SECCOMP && ret == 0 && g_cfg.spoof_seccomp)
        ret = 2; // SECCOMP_MODE_FILTER
    return ret;
}

static long (*orig_syscall)(long, ...) = nullptr;
static int  (*orig_getdents64)(int, void *, size_t) = nullptr;

// getdents64 with /proc filtering; `raw` performs the unfiltered syscall.
template <typename RawFn>
static long filtered_getdents64(int fd, void *dirp, size_t count, RawFn raw) {
    for (int attempt = 0; attempt < 5; attempt++) {
        long ret = raw(fd, dirp, count);
        if (ret <= 0) return ret;

        // Is this fd a directory handle on /proc?
        char linkpath[64], target[256];
        snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
        long n = ::syscall(SYS_readlinkat, AT_FDCWD, linkpath, target,
                           sizeof(target) - 1);
        if (n <= 0) return ret;
        target[n] = '\0';
        if (strcmp(target, "/proc") != 0) return ret;

        char *buf = (char *)dirp;
        long bpos = 0, newlen = 0;
        while (bpos < ret) {
            auto *d = (linux_dirent64 *)(buf + bpos);
            bool hide = false;
            if (isdigit((unsigned char)d->d_name[0])) {
                long pid = strtol(d->d_name, nullptr, 10);
                hide = g_hidden_pids.count((pid_t)pid) > 0;
            }
            if (!hide) {
                if (newlen != bpos) memmove(buf + newlen, d, d->d_reclen);
                newlen += d->d_reclen;
            }
            bpos += d->d_reclen;
        }
        if (newlen > 0 || ret <= 0) return newlen;
        // everything in this batch was hidden: fetch the next batch instead of
        // reporting a bogus EOF
    }
    return 0;
}

static int my_getdents64(int fd, void *dirp, size_t count) {
    if (!g_hide_on)
        return orig_getdents64 ? orig_getdents64(fd, dirp, count)
                               : (int)::syscall(SYS_getdents64, fd, dirp, count);
    return (int)filtered_getdents64(fd, dirp, count, [](int f, void *d, size_t c) {
        return orig_getdents64 ? (long)orig_getdents64(f, d, c)
                               : ::syscall(SYS_getdents64, f, d, c);
    });
}

static long my_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (number == SYS_getppid && g_cfg.fake_ppid > 0)
        return g_cfg.fake_ppid;

    if (number == SYS_prctl) {
        long ret = orig_syscall(number, a1, a2, a3, a4, a5, a6);
        if (a1 == PR_GET_SECCOMP && ret == 0 && g_cfg.spoof_seccomp)
            ret = 2;
        return ret;
    }

    if (number == SYS_getdents64 && g_hide_on) {
        return filtered_getdents64((int)a1, (void *)a2, (size_t)a3,
                                   [&](int f, void *d, size_t c) {
            return orig_syscall(SYS_getdents64, f, d, c, 0, 0, 0);
        });
    }

    return orig_syscall(number, a1, a2, a3, a4, a5, a6);
}

// --- open family (variadic, mode only present with O_CREAT) -----------------

#define DEF_OPENAT_HOOK(SYM)                                                   \
static int (*orig_##SYM)(int, const char *, int, ...) = nullptr;               \
static int my_##SYM(int dirfd, const char *path, int flags, ...) {             \
    mode_t mode = 0;                                                           \
    if (flags & O_CREAT) {                                                     \
        va_list ap; va_start(ap, flags);                                       \
        mode = (mode_t)va_arg(ap, int); va_end(ap);                            \
    }                                                                          \
    int r = intercept_open(path);                                              \
    if (r != INTERCEPT_PASS) return r;                                         \
    return orig_##SYM(dirfd, path, flags, mode);                               \
}

#define DEF_OPEN_HOOK(SYM)                                                     \
static int (*orig_##SYM)(const char *, int, ...) = nullptr;                    \
static int my_##SYM(const char *path, int flags, ...) {                        \
    mode_t mode = 0;                                                           \
    if (flags & O_CREAT) {                                                     \
        va_list ap; va_start(ap, flags);                                       \
        mode = (mode_t)va_arg(ap, int); va_end(ap);                            \
    }                                                                          \
    int r = intercept_open(path);                                              \
    if (r != INTERCEPT_PASS) return r;                                         \
    return orig_##SYM(path, flags, mode);                                      \
}

DEF_OPENAT_HOOK(__openat)
DEF_OPENAT_HOOK(__openat_2)
DEF_OPENAT_HOOK(__openat64)
DEF_OPENAT_HOOK(openat)
DEF_OPENAT_HOOK(openat64)
DEF_OPEN_HOOK(open)
DEF_OPEN_HOOK(open64)

// --- stat / access family: deny hidden /proc/<pid> paths --------------------

#define DEF_PATH_HOOK(SYM)                                                     \
static int (*orig_##SYM)(const char *, void *) = nullptr;                      \
static int my_##SYM(const char *path, void *buf) {                             \
    if (deny_path(path)) { errno = ENOENT; return -1; }                        \
    return orig_##SYM(path, buf);                                              \
}

DEF_PATH_HOOK(stat)
DEF_PATH_HOOK(stat64)
DEF_PATH_HOOK(lstat)
DEF_PATH_HOOK(lstat64)

#define DEF_DIRFD_STAT_HOOK(SYM)                                               \
static int (*orig_##SYM)(int, const char *, void *, int) = nullptr;            \
static int my_##SYM(int dirfd, const char *path, void *buf, int flags) {       \
    if (deny_path(path)) { errno = ENOENT; return -1; }                        \
    return orig_##SYM(dirfd, path, buf, flags);                                \
}

DEF_DIRFD_STAT_HOOK(fstatat)
DEF_DIRFD_STAT_HOOK(fstatat64)
DEF_DIRFD_STAT_HOOK(__fstatat64)

static int (*orig_statx)(int, const char *, int, unsigned, void *) = nullptr;
static int my_statx(int dirfd, const char *path, int flags, unsigned mask,
                    void *buf) {
    if (deny_path(path)) { errno = ENOENT; return -1; }
    return orig_statx(dirfd, path, flags, mask, buf);
}

static int (*orig_faccessat)(int, const char *, int) = nullptr;
static int my_faccessat(int dirfd, const char *path, int mode) {
    if (deny_path(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode);
}

static int (*orig_faccessat2)(int, const char *, int, int) = nullptr;
static int my_faccessat2(int dirfd, const char *path, int mode, int flags) {
    if (deny_path(path)) { errno = ENOENT; return -1; }
    return orig_faccessat2(dirfd, path, mode, flags);
}

// ---------------------------------------------------------------------------
// Hook installation: patch the PLT/GOT of every loaded ELF (LSPlt)
// ---------------------------------------------------------------------------

struct HookDef {
    const char *symbol;
    void *replacement;
    void **backup;
};

static size_t file_size(const char *path) {
    int fd = sys_open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    off_t sz = ::syscall(SYS_lseek, fd, 0, SEEK_END);
    ::syscall(SYS_close, fd);
    return sz > 0 ? (size_t)sz : 0;
}

static void register_all(const HookDef *defs, size_t n) {
    for (const auto &map : lsplt::MapInfo::Scan()) {
        if (!map.is_private || !(map.perms & PROT_READ)) continue;
        const bool from_apk =
            ends_with(map.path.c_str(), ".apk") || ends_with(map.path.c_str(), ".zip");
        if (map.offset == 0) {
            if (from_apk) continue; // whole-archive map, not a library
            for (size_t i = 0; i < n; i++)
                lsplt::RegisterHook(map.dev, map.inode, defs[i].symbol,
                                    defs[i].replacement, defs[i].backup);
        } else if (from_apk) {
            // Library loaded directly from inside an APK (extractNativeLibs=false):
            // the ELF starts at map.offset within the archive. Non-header segments
            // fail to register and are harmless no-ops.
            size_t fsz = file_size(map.path.c_str());
            if (fsz == 0 || (size_t)map.offset >= fsz) continue;
            for (size_t i = 0; i < n; i++)
                lsplt::RegisterHook(map.dev, map.inode, (uintptr_t)map.offset,
                                    fsz - (size_t)map.offset, defs[i].symbol,
                                    defs[i].replacement, defs[i].backup);
        }
    }
}

static void install_hooks() {
    static const HookDef proc_hooks[] = {
        { "__openat",    (void *)my___openat,    (void **)&orig___openat },
        { "__openat_2",  (void *)my___openat_2,  (void **)&orig___openat_2 },
        { "__openat64",  (void *)my___openat64,  (void **)&orig___openat64 },
        { "openat",      (void *)my_openat,      (void **)&orig_openat },
        { "openat64",    (void *)my_openat64,    (void **)&orig_openat64 },
        { "open",        (void *)my_open,        (void **)&orig_open },
        { "open64",      (void *)my_open64,      (void **)&orig_open64 },
        { "syscall",     (void *)my_syscall,     (void **)&orig_syscall },
    };
    register_all(proc_hooks, sizeof(proc_hooks) / sizeof(proc_hooks[0]));

    if (g_cfg.fake_ppid > 0) {
        static const HookDef ppid_hook[] = {
            { "getppid", (void *)my_getppid, (void **)&orig_getppid },
        };
        register_all(ppid_hook, 1);
    }
    if (g_cfg.spoof_seccomp) {
        static const HookDef prctl_hook[] = {
            { "prctl", (void *)my_prctl, (void **)&orig_prctl },
        };
        register_all(prctl_hook, 1);
    }
    if (g_hide_on) {
        static const HookDef hide_hooks[] = {
            { "stat",        (void *)my_stat,        (void **)&orig_stat },
            { "stat64",      (void *)my_stat64,      (void **)&orig_stat64 },
            { "lstat",       (void *)my_lstat,       (void **)&orig_lstat },
            { "lstat64",     (void *)my_lstat64,     (void **)&orig_lstat64 },
            { "fstatat",     (void *)my_fstatat,     (void **)&orig_fstatat },
            { "fstatat64",   (void *)my_fstatat64,   (void **)&orig_fstatat64 },
            { "__fstatat64", (void *)my___fstatat64, (void **)&orig___fstatat64 },
            { "statx",       (void *)my_statx,       (void **)&orig_statx },
            { "faccessat",   (void *)my_faccessat,   (void **)&orig_faccessat },
            { "faccessat2",  (void *)my_faccessat2,  (void **)&orig_faccessat2 },
            { "getdents64",  (void *)my_getdents64,  (void **)&orig_getdents64 },
        };
        register_all(hide_hooks, sizeof(hide_hooks) / sizeof(hide_hooks[0]));
    }

    bool ok = lsplt::CommitHook();
    LOGI("hooks committed: %s (fake_ppid=%ld seccomp=%d tracer=%d hide=%d)",
         ok ? "ok" : "partial", g_cfg.fake_ppid, (int)g_cfg.spoof_seccomp,
         (int)g_cfg.spoof_tracer, (int)g_hide_on);
}

// ---------------------------------------------------------------------------
// Zygisk module entry points
// ---------------------------------------------------------------------------

class ProcSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *raw =
            args->nice_name ? env->GetStringUTFChars(args->nice_name, nullptr)
                            : nullptr;
        std::string proc = raw ? raw : "";
        if (raw) env->ReleaseStringUTFChars(args->nice_name, raw);

        // Read config through the root companion (zygote context cannot
        // reliably open /data/adb on every setup due to SELinux).
        std::string cfg, targets, hide;
        int s = api->connectCompanion();
        if (s >= 0) {
            recv_blob(s, cfg);
            recv_blob(s, targets);
            recv_blob(s, hide);
            close(s);
        } else {
            LOGE("companion unavailable, module inactive");
        }
        parse_config(cfg, targets, hide);

        g_active = g_cfg.enabled && matches_target(proc);
        if (!g_active) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (g_cfg.hide_procs && !g_cfg.hide_names.empty()) {
            resolve_hidden_pids();
            g_hide_on = !g_hidden_pids.empty();
        }
        LOGI("active in [%s]: fake_ppid=%ld spoof_seccomp=%d hide=%d(%zu pids)",
             proc.c_str(), g_cfg.fake_ppid, (int)g_cfg.spoof_seccomp,
             (int)g_hide_on, g_hidden_pids.size());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!g_active) return;
        install_hooks();
    }

private:
    bool matches_target(const std::string &proc) const {
        if (g_cfg.targets.empty()) return false;
        if (g_cfg.targets.count("*")) return true;
        if (g_cfg.targets.count(proc)) return true;
        // also match "com.example.app" against "com.example.app:remote"
        size_t colon = proc.find(':');
        if (colon != std::string::npos &&
            g_cfg.targets.count(proc.substr(0, colon)))
            return true;
        return false;
    }

    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(ProcSpoofModule)
