#!/bin/bash

v2_timing_output=${VPNCTL_V2_TIMING_OUTPUT:-}
v2_timing_parts=
v2_timing_last=0

v2_timing_now_ms() {
  perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e 'printf "%.0f\n", clock_gettime(CLOCK_MONOTONIC) * 1000'
}

v2_timing_begin() {
  [ -n "$v2_timing_output" ] || return 0
  case "$v2_timing_output" in /*/child-timing.json) ;; *) echo "invalid private stage timing output" >&2; return 3 ;; esac
  [ ! -e "$v2_timing_output" ] && [ ! -L "$v2_timing_output" ] || { echo "stage timing output already exists" >&2; return 3; }
  v2_timing_parts="$v2_timing_output.parts"
  [ ! -e "$v2_timing_parts" ] && [ ! -L "$v2_timing_parts" ] || { echo "stage timing scratch already exists" >&2; return 3; }
  : > "$v2_timing_parts"
  chmod 0600 "$v2_timing_parts"
  v2_timing_last=$(v2_timing_now_ms)
}

v2_timing_mark() {
  local name=$1 now duration
  [ -n "$v2_timing_output" ] || return 0
  [[ "$name" =~ ^[a-z][a-z0-9_]{0,63}$ ]] || { echo "invalid stage timing phase" >&2; return 3; }
  ! cut -f 1 "$v2_timing_parts" | grep -Fxq "$name" || { echo "duplicate stage timing phase" >&2; return 3; }
  now=$(v2_timing_now_ms)
  if [ "$now" -ge "$v2_timing_last" ]; then duration=$((now - v2_timing_last)); else duration=0; fi
  printf '%s\t%s\n' "$name" "$duration" >> "$v2_timing_parts"
  v2_timing_last=$now
}

v2_timing_finish() {
  local final_phase=$1 temporary
  [ -n "$v2_timing_output" ] || return 0
  v2_timing_mark "$final_phase"
  temporary="$v2_timing_output.tmp"
  jq -Rn --arg producer "${VPNCTL_V2_TIMING_PRODUCER:-child-harness}" '
    [inputs | split("\t") | {(.[0]): (.[1] | tonumber)}] | add as $phases |
    {schema_version:1,producer:$producer,phases:$phases}
  ' < "$v2_timing_parts" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$v2_timing_output"
  rm -f -- "$v2_timing_parts"
  v2_timing_parts=
}
