#!/system/bin/sh
# ProcSpoof installer script (Magisk/KernelSU module installer environment)

ui_print "********************************"
ui_print " ProcSpoof - process state fixer"
ui_print "********************************"

case "$ARCH" in
  arm64|arm|x64|x86) ;;
  *) abort "! Unsupported architecture: $ARCH" ;;
esac
ui_print "- Device ABI: $ARCH"

CFG=/data/adb/ksu_proc_spoof
mkdir -p "$CFG"

if [ ! -f "$CFG/config.conf" ]; then
  cat > "$CFG/config.conf" <<'EOF'
enabled=1
fake_ppid=750
spoof_seccomp=1
spoof_tracerpid=1
hide_procs=0
EOF
fi

if [ ! -f "$CFG/targets.txt" ]; then
  cat > "$CFG/targets.txt" <<'EOF'
# Apps to spoof, one package name per line ('#' = comment).
# Sub-processes (pkg:remote) are covered by the base package name.
# Use * to apply to every app (not recommended).
# com.example.detector
EOF
fi

if [ ! -f "$CFG/hideprocs.txt" ]; then
  cat > "$CFG/hideprocs.txt" <<'EOF'
# Process names hidden from target apps' /proc and cgroup views
# (only used when hide_procs=1). One name per line, e.g.:
# tricky_store
# zygiskd64
EOF
fi

chmod 755 "$CFG"
chmod 644 "$CFG"/* 2>/dev/null

ui_print "- Config: $CFG (survives module updates)"
ui_print "- Open the WebUI in your root manager to configure"
ui_print "- Force-stop target apps after changing the config"
