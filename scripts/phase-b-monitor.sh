#!/bin/bash
# Phase B 실행 모니터링 스크립트
# Davinci assess 실행 중 컨텍스트 압축, 유실, 진행 상황 추적

ENGAGEMENT_DIR=""
LOG_FILE="/tmp/nunchi-phase-b-monitor.log"
POLL_INTERVAL=30

echo "=== Phase B Monitor Started: $(date) ===" | tee "$LOG_FILE"

wait_for_engagement() {
  local reports_dir="/Users/philip/workdir/pentest/davinci/reports"
  while true; do
    local latest=$(ls -td "$reports_dir"/davinci_* 2>/dev/null | head -1)
    if [ -n "$latest" ] && [ "$latest" != "$ENGAGEMENT_DIR" ]; then
      ENGAGEMENT_DIR="$latest"
      echo "[$(date +%H:%M:%S)] New engagement detected: $ENGAGEMENT_DIR" | tee -a "$LOG_FILE"
      return 0
    fi
    sleep 5
  done
}

monitor_loop() {
  local compaction_count=0
  local last_event_count=0

  while true; do
    if [ ! -d "$ENGAGEMENT_DIR" ]; then
      sleep "$POLL_INTERVAL"
      continue
    fi

    # 1. Run state
    local run_status="unknown"
    if [ -f "$ENGAGEMENT_DIR/run-state.json" ]; then
      run_status=$(python3 -c "import json; f=open('$ENGAGEMENT_DIR/run-state.json'); print(json.load(f).get('status','?'))" 2>/dev/null)
    fi

    # 2. Event count
    local event_count=0
    if [ -f "$ENGAGEMENT_DIR/run-events.jsonl" ]; then
      event_count=$(wc -l < "$ENGAGEMENT_DIR/run-events.jsonl" | tr -d ' ')
    fi

    # 3. Context compaction tracking (from host-ledger)
    local new_compactions=0
    if [ -f "$ENGAGEMENT_DIR/host-ledger.jsonl" ]; then
      new_compactions=$(grep -c "context-compacted\|SDKCompactBoundary\|compaction" "$ENGAGEMENT_DIR/host-ledger.jsonl" 2>/dev/null || echo 0)
    fi

    # 4. Work unit progress
    local unit_done=0
    local unit_total=0
    if [ -d "$ENGAGEMENT_DIR/work-units" ]; then
      unit_total=$(ls "$ENGAGEMENT_DIR/work-units/" 2>/dev/null | wc -l | tr -d ' ')
      unit_done=$(find "$ENGAGEMENT_DIR/work-units" -name "02_verify_result-1st.md" -o -name "02a_verify_autonomous-1st.md" 2>/dev/null | wc -l | tr -d ' ')
    fi

    # 5. Root VA presence
    local root_va="not_started"
    if [ -f "$ENGAGEMENT_DIR/run-events.jsonl" ]; then
      if grep -q '"va:1st"' "$ENGAGEMENT_DIR/run-events.jsonl" 2>/dev/null; then
        root_va="started"
      fi
    fi

    # 6. Failures
    local failures=0
    if [ -f "$ENGAGEMENT_DIR/run-events.jsonl" ]; then
      failures=$(grep -c "phase.failed\|run.blocked" "$ENGAGEMENT_DIR/run-events.jsonl" 2>/dev/null || echo 0)
    fi

    # Report
    local delta=$((event_count - last_event_count))
    local ts=$(date +%H:%M:%S)

    echo "[$ts] status=$run_status units=$unit_done/$unit_total rootVA=$root_va events=$event_count(+$delta) compactions=$new_compactions failures=$failures" | tee -a "$LOG_FILE"

    # Alert on compactions
    if [ "$new_compactions" -gt "$compaction_count" ]; then
      echo "  !! COMPACTION: $((new_compactions - compaction_count)) new" | tee -a "$LOG_FILE"
      compaction_count=$new_compactions
    fi
    if [ "$failures" -gt "0" ]; then
      echo "  !! FAILURES: $failures" | tee -a "$LOG_FILE"
    fi

    # Completion check
    if [ "$run_status" = "completed" ] || [ "$run_status" = "blocked" ]; then
      echo "[$ts] DONE: $run_status" | tee -a "$LOG_FILE"
      echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
      echo "Units: $unit_done/$unit_total | RootVA: $root_va | Compactions: $new_compactions | Failures: $failures" | tee -a "$LOG_FILE"
      return 0
    fi

    last_event_count=$event_count
    sleep "$POLL_INTERVAL"
  done
}

echo "Waiting for new engagement..." | tee -a "$LOG_FILE"
wait_for_engagement
monitor_loop
echo "=== Monitor Complete: $(date) ===" | tee -a "$LOG_FILE"
