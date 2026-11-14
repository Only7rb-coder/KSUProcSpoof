#!/system/bin/sh
# ProcSpoof quick status (module action button)
MODDIR=${0%/*}
CFG=/data/adb/ksu_proc_spoof

echo "== ProcSpoof status =="
echo "-- config.conf:"
cat "$CFG/config.conf" 2>/dev/null || echo "(missing)"
echo "-- targets.txt:"
grep -v '^\s*#' "$CFG/targets.txt" 2>/dev/null | grep -v '^\s*$' || echo "(none)"
echo "-- hideprocs.txt:"
grep -v '^\s*#' "$CFG/hideprocs.txt" 2>/dev/null | grep -v '^\s*$' || echo "(none)"
echo "-- zygote pids (a high value explains getppid>5000 detections):"
ps -A 2>/dev/null | grep -i zygote | grep -v grep
echo "-- zygisk libs:"
ls -l "$MODDIR/zygisk" 2>/dev/null
