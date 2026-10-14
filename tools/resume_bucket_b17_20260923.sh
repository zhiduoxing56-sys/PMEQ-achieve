#!/usr/bin/env bash
set -uo pipefail

root="/home/tenggn/projects/clean_pmeq"
base="$root/results/bucket-count-candidate-final-20260923"
previous="$base/formal-b15-v2"
next="$base/formal-b17"

while true; do
    if [[ -f "$previous/summary.csv" ]]; then
        break
    fi
    if [[ -f "$previous/run.log" ]] && grep -q '^FAIL$' "$previous/run.log"; then
        break
    fi
    if [[ -f "$previous/checkpoint.log" ]] && grep -q 'Traceback' "$previous/checkpoint.log"; then
        break
    fi
    sleep 15
done

cd "$root/internal/discovery" || exit 1
mkdir "$next" || exit 1
PMEQ_BUCKET_FINAL_OUTPUT="$next" PMEQ_BUCKET_FINAL_BITS=17 \
    /tmp/pmeq-bucket-final.test -test.run '^TestBucketCountFinal$' -test.v > "$next/run.log" 2>&1
status=$?
printf '%s\n' "$status" > "$next/exit-status.txt"
if [[ "$status" -eq 0 ]]; then
    python3 "$root/tools/check_bucket_count_stage_20260923.py" 17 formal-b17 > "$next/checkpoint.log" 2>&1
    printf '%s\n' "$?" > "$next/checkpoint-exit-status.txt"
fi

cd "$root" || exit 1
python3 tools/finalize_bucket_count_20260923.py > "$base/finalize.log" 2>&1
final_status=$?
printf '%s\n' "$final_status" > "$base/finalize-exit-status.txt"
exit "$final_status"
