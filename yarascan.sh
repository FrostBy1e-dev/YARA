#!/bin/bash
# Author: SRE-JD (Modified for disconnection resistance)

# Check if YARA rules file and target directory are provided, with optional threads
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <rules_file> <target_directory> [threads]"
    echo "       $0 --resume <state_file>"
    exit 1
fi

# Handle resume functionality
if [ "$1" = "--resume" ] && [ -n "$2" ]; then
    STATE_FILE="$2"
    if [ ! -f "$STATE_FILE" ]; then
        echo "Error: State file $STATE_FILE does not exist"
        exit 1
    fi
    # Source the state file to restore variables
    source "$STATE_FILE"
    echo "Resuming scan from state file: $STATE_FILE"
    RESUME_MODE=true
else
    RULES_FILE="$1"
    TARGET_DIR="$2"
    RESUME_MODE=false
fi

# Set threads: use provided value or default to number of processors
if [ $# -eq 3 ] && [ "$RESUME_MODE" = false ]; then
    if ! [[ $3 =~ ^[0-9]+$ ]] || [ $3 -lt 1 ]; then
        echo "Error: Threads must be a positive integer >=1"
        exit 1
    fi
    THREADS=$3
elif [ "$RESUME_MODE" = false ]; then
    THREADS=$(nproc)
fi

# Convert relative paths to absolute (only in new scan mode)
if [ "$RESUME_MODE" = false ]; then
    RULES_FILE=$(realpath "$RULES_FILE" 2>/dev/null)
    TARGET_DIR=$(realpath "$TARGET_DIR" 2>/dev/null)

    # Validate inputs
    if [ ! -f "$RULES_FILE" ]; then
        echo "Error: Rules file $RULES_FILE does not exist"
        exit 1
    fi

    if [ ! -d "$TARGET_DIR" ]; then
        echo "Error: Target directory $TARGET_DIR does not exist"
        exit 1
    fi
fi

# Create unique session ID for this scan
if [ "$RESUME_MODE" = false ]; then
    SESSION_ID="yara_$(date '+%Y%m%d_%H%M%S')_$$"
    SCAN_DIR="/tmp/yara_scan_$SESSION_ID"
    mkdir -p "$SCAN_DIR" || {
        echo "Error: Could not create scan directory $SCAN_DIR"
        exit 1
    }
else
    # Use existing scan directory from state file
    if [ ! -d "$SCAN_DIR" ]; then
        echo "Error: Scan directory $SCAN_DIR from state file does not exist"
        exit 1
    fi
fi

# Define file paths
STATE_FILE="$SCAN_DIR/scan_state.sh"
PID_FILE="$SCAN_DIR/yara.pid"
LOG_FILE_TEMP="$SCAN_DIR/scan_progress.log"
TIME_LOG="$SCAN_DIR/timing.log"
TEMP_INFECTED_LOG="$SCAN_DIR/infected.log"
MEMORY_LOG="$SCAN_DIR/memory.log"
FINAL_LOG_FILE="$SCAN_DIR/final_results.log"

# Set up final log file name
if [ "$RESUME_MODE" = false ]; then
    if [ "$TARGET_DIR" = "/" ]; then
        TARGET_BASE="rootfs"
    else
        TARGET_BASE=$(basename "$TARGET_DIR")
    fi
    FINAL_OUTPUT_LOG="YARA_scan_log_${TARGET_BASE}_Y$(date '+%Y')_M$(date '+%m')_D$(date '+%d')_$(date '+%H-%M-%S').log"
fi

# Save state function
save_state() {
    cat > "$STATE_FILE" << EOF
# YARA Scan State File - Generated at $(date)
RULES_FILE="$RULES_FILE"
TARGET_DIR="$TARGET_DIR"
THREADS=$THREADS
SESSION_ID="$SESSION_ID"
SCAN_DIR="$SCAN_DIR"
START_TIME="$START_TIME"
START_EPOCH=$START_EPOCH
TARGET_BASE="$TARGET_BASE"
FINAL_OUTPUT_LOG="$FINAL_OUTPUT_LOG"
SCAN_STATUS="$SCAN_STATUS"
SKIP_SECOND_SCAN=$SKIP_SECOND_SCAN
EOF
}

# Cleanup function
cleanup_and_exit() {
    local exit_code=${1:-0}

    # Kill YARA process if running
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null
            fi
        fi
        rm -f "$PID_FILE"
    fi

    # Generate final report if we have partial results
    if [ -f "$TEMP_INFECTED_LOG" ] && [ "$exit_code" -ne 0 ]; then
        generate_final_report "interrupted"
    fi

    save_state
    echo "Scan session can be resumed with: $0 --resume $STATE_FILE"
    exit "$exit_code"
}

# Signal handlers for disconnection resistance
trap 'nohup bash -c "exec $0 --resume $STATE_FILE" > /dev/null 2>&1 & disown' HUP
trap 'cleanup_and_exit 130' INT
trap 'cleanup_and_exit 143' TERM
trap 'cleanup_and_exit 1' ERR

# Detach from terminal to survive disconnections
if [ "$RESUME_MODE" = false ]; then
    # Simplified start message
    if [ "$TARGET_DIR" = "/" ]; then
        echo "Starting YARA scan (excluding virtual filesystems)..."
    else
        echo "Starting YARA scan..."
    fi

    # Capture start time
    START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    START_EPOCH=$(date +%s)
    SCAN_STATUS="running"

    echo "Starting YARA scan at: $START_TIME"
    echo

    # Determine scan type
    if [ "$TARGET_DIR" = "/" ]; then
        SKIP_SECOND_SCAN=true
    else
        SKIP_SECOND_SCAN=false
    fi

    save_state
fi

# Function to monitor memory usage
monitor_memory() {
    local pid=$1
    local max_rss=0
    local max_vss=0

    while kill -0 "$pid" 2>/dev/null; do
        if [ -f "/proc/$pid/status" ]; then
            local current_rss=$(grep '^VmRSS:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || echo "0")
            local current_vss=$(grep '^VmSize:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || echo "0")

            [ "$current_rss" -gt "$max_rss" ] && max_rss=$current_rss
            [ "$current_vss" -gt "$max_vss" ] && max_vss=$current_vss

            # Log current memory usage
            echo "$(date '+%H:%M:%S') RSS: ${current_rss}KB VSS: ${current_vss}KB" >> "$MEMORY_LOG"
        fi
        sleep 1
    done

    echo "$max_rss $max_vss"
}

# Function to generate final report
generate_final_report() {
    local final_status="$1"

    # Capture end time
    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    END_EPOCH=$(date +%s)

    # Parse memory stats
    if [ -f "$MEMORY_LOG" ]; then
        MAX_RSS_KB=$(awk '{print $3}' "$MEMORY_LOG" | sed 's/KB//' | sort -n | tail -1)
        MAX_VSS_KB=$(awk '{print $5}' "$MEMORY_LOG" | sed 's/KB//' | sort -n | tail -1)
    else
        MAX_RSS_KB=0
        MAX_VSS_KB=0
    fi

    # Convert to MB
    MAX_RSS_MB=$(echo "scale=2; ${MAX_RSS_KB:-0} / 1024" | bc 2>/dev/null || echo "0.00")
    MAX_VSS_MB=$(echo "scale=2; ${MAX_VSS_KB:-0} / 1024" | bc 2>/dev/null || echo "0.00")

    # Get current swap usage
    SWAP_INFO=$(cat /proc/meminfo)
    SWAP_USED_CURRENT=$(echo "$SWAP_INFO" | grep SwapFree | awk '{print $2}' || echo "0")
    TOTAL_SWAP=$(echo "$SWAP_INFO" | grep SwapTotal | awk '{print $2}' || echo "0")
    SWAP_USED=$((TOTAL_SWAP - SWAP_USED_CURRENT))
    [ $SWAP_USED -lt 0 ] && SWAP_USED=0
    SWAP_USED_MB=$(echo "scale=2; $SWAP_USED / 1024" | bc 2>/dev/null || echo "0.00")

    # Parse timing information
    if [ -f "$TIME_LOG" ]; then
        USER_TIME=$(grep 'User time' "$TIME_LOG" | awk '{print $NF}' || echo "0.00s")
        SYS_TIME=$(grep 'System time' "$TIME_LOG" | awk '{print $NF}' || echo "0.00s")
        REAL_TIME_RAW=$(grep 'Elapsed.*wall' "$TIME_LOG" | awk '{print $NF}' || echo "0:00.00")
        if [[ $REAL_TIME_RAW == *:* ]]; then
            REAL_TIME="$REAL_TIME_RAW"
        else
            REAL_TIME="0:$REAL_TIME_RAW"
        fi
    else
        USER_TIME="N/A"
        SYS_TIME="N/A"
        REAL_TIME="N/A"
    fi

    # Calculate elapsed time
    ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))
    ELAPSED_SECONDS=$((ELAPSED_SECONDS < 1 ? 1 : ELAPSED_SECONDS))

    # Calculate CPU usage percentage
    if [[ "$USER_TIME" != "N/A" ]] && [[ "$SYS_TIME" != "N/A" ]]; then
        # Extract numeric values from time strings
        USER_TIME_NUM=$(echo "$USER_TIME" | sed 's/s$//')
        SYS_TIME_NUM=$(echo "$SYS_TIME" | sed 's/s$//')
        TOTAL_CPU=$(echo "$USER_TIME_NUM + $SYS_TIME_NUM" | bc 2>/dev/null || echo "0.00")
        CPU_PERCENT=$(echo "scale=2; ($TOTAL_CPU / $ELAPSED_SECONDS) * 100" | bc 2>/dev/null || echo "0.00")
    else
        CPU_PERCENT="N/A"
    fi

    # Format infected files list
    INFECTED_FILES="None"
    TOTAL_RULE_MATCHES=0
    if [ -f "$TEMP_INFECTED_LOG" ] && [ -s "$TEMP_INFECTED_LOG" ]; then
        INFECTED_FILES=$(grep -E '^[[:alnum:]_]+[[:space:]]+/' "$TEMP_INFECTED_LOG" | grep -v -i 'skipping\|error\|warning' | sed 's/^/  - /')
        TOTAL_RULE_MATCHES=$(grep -E '^[[:alnum:]_]+[[:space:]]+/' "$TEMP_INFECTED_LOG" | grep -v -i 'skipping\|error\|warning' | wc -l)
    fi

    # Count skipped files - fix the integer comparison error
    SKIPPED_FILES_COUNT=0
    if [ -f "$TEMP_INFECTED_LOG" ]; then
        SKIPPED_FILES_COUNT=$(grep -c '^warning: skipping' "$TEMP_INFECTED_LOG" 2>/dev/null || echo "0")
    fi

    # Calculate total files
    if [ "$TARGET_DIR" = "/" ]; then
        TOTAL_FILES="N/A (multi-directory scan)"
    else
        TOTAL_FILES=$(find "$TARGET_DIR" -type f 2>/dev/null | wc -l)
    fi

    # Set command used
    if [ "$SKIP_SECOND_SCAN" = true ]; then
        COMMAND="Multi-directory scan of: /bin /boot /etc /home /lib /lib64 /opt /root /sbin /srv /usr /var"
    else
        COMMAND="yara -f -p $THREADS -C -r \"$RULES_FILE\" \"$TARGET_DIR\""
    fi

    # Generate report
    FINAL_REPORT=$(cat << EOF
==================================================
YARA SCAN REPORT
==================================================
Scan Started at: $START_TIME
Scan Status: $final_status
Scan Completed at: $END_TIME
Command Used: $COMMAND

RESULTS:
Infected Files:
$INFECTED_FILES

PERFORMANCE METRICS:
User Time: $USER_TIME
System Time: $SYS_TIME
Elapsed Time: $REAL_TIME
Percent of CPU for this Job: $CPU_PERCENT%
Peak Memory Used (RSS): $MAX_RSS_MB MB
Peak Virtual Memory (VSS): $MAX_VSS_MB MB
Current System Swap Used: $SWAP_USED_MB MB

SCAN DETAILS:
- YARA Rule File: $RULES_FILE
- Directory Scanned: $TARGET_DIR
- Total Scanned Files: $TOTAL_FILES
- Threads Used: $THREADS
- Total Detected Rule Matches: $TOTAL_RULE_MATCHES
- Skipped Files: $SKIPPED_FILES_COUNT

Scan finished!
==================================================
EOF
)

    # Save final report
    echo "$FINAL_REPORT" > "$FINAL_LOG_FILE"
    if [ -n "$FINAL_OUTPUT_LOG" ]; then
        cp "$FINAL_LOG_FILE" "$FINAL_OUTPUT_LOG"
    fi

    echo "$FINAL_REPORT"
}

# Handle different scan types
if [ "$TARGET_DIR" = "/" ]; then
    # Create wrapper script for root scan
    ROOT_SCAN_SCRIPT="$SCAN_DIR/root_scan.sh"
    cat > "$ROOT_SCAN_SCRIPT" << EOF
#!/bin/bash
for dir in /bin /boot /etc /home /lib /lib64 /opt /root /sbin /srv /usr /var; do
    if [ -d "\$dir" ]; then
        /usr/bin/time -v yara -f -p $THREADS -C -r "$RULES_FILE" "\$dir" 2>/dev/null
    fi
done
EOF
    chmod +x "$ROOT_SCAN_SCRIPT"

    # Execute root scan
    nohup bash -c "/usr/bin/time -v \"$ROOT_SCAN_SCRIPT\" > \"$TEMP_INFECTED_LOG\" 2> \"$TIME_LOG\"" > /dev/null 2>&1 &
    YARA_PID=$!
else
    # Regular directory scan
    nohup bash -c "/usr/bin/time -v yara -f -p $THREADS -C -r \"$RULES_FILE\" \"$TARGET_DIR\" > \"$TEMP_INFECTED_LOG\" 2> \"$TIME_LOG\"" > /dev/null 2>&1 &
    YARA_PID=$!
fi

# Save PID for monitoring and cleanup
echo "$YARA_PID" > "$PID_FILE"

# Monitor memory usage in background
monitor_memory "$YARA_PID" > /dev/null 2>&1 &
MONITOR_PID=$!

# Wait for scan completion
wait "$YARA_PID"
EXIT_STATUS=$?

# Clean up monitoring
kill "$MONITOR_PID" 2>/dev/null
rm -f "$PID_FILE"

# Generate final report
if [ $EXIT_STATUS -eq 0 ]; then
    generate_final_report "completed successfully"
    SCAN_STATUS="completed"
else
    generate_final_report "completed with errors"
    SCAN_STATUS="completed_with_errors"
fi

save_state

# Auto-remove temporary files
rm -rf "$SCAN_DIR" 2>/dev/null