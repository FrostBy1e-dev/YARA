#!/bin/bash
# Author: SRE-JD

# Check if YARA rules file and target directory are provided, with optional threads
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <rules_file> <target_directory> [threads]"
    exit 1
fi

RULES_FILE="$1"
TARGET_DIR="$2"

# Set threads: use provided value or default to number of processors
if [ $# -eq 3 ]; then
    if ! [[ $3 =~ ^[0-9]+$ ]] || [ $3 -lt 1 ]; then
        echo "Error: Threads must be a positive integer >=1"
        exit 1
    fi
    THREADS=$3
else
    THREADS=$(nproc)
fi

# Convert relative paths to absolute
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

# Capture start time
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
START_EPOCH=$(date +%s)

# Capture initial memory usage (in KB)
MEM_INFO_START=$(cat /proc/meminfo)
MEM_USED_START=$(echo "$MEM_INFO_START" | grep MemAvailable | awk '{print $2}' || echo "0")
SWAP_USED_START=$(echo "$MEM_INFO_START" | grep SwapFree | awk '{print $2}' || echo "0")
TOTAL_SWAP=$(echo "$MEM_INFO_START" | grep SwapTotal | awk '{print $2}' || echo "0")

# Output file for scan report with target directory basename
TARGET_BASE=$(basename "$TARGET_DIR")
LOG_FILE="YARA_scan_log_${TARGET_BASE}_Y$(date '+%Y')_M$(date '+%m')_D$(date '+%d')_$(date '+%H-%M-%S').log"
touch "$LOG_FILE"

# Temporary file for timing
TIME_LOG="yara_time_$(date '+%Y%m%d_%H%M%S').log"

# Run YARA scan and capture output
COMMAND="yara -f -p $THREADS -z 10485760 -C -r \"$RULES_FILE\" \"$TARGET_DIR\""
echo "Executing: $COMMAND"

# Execute YARA with sudo, capture all output to a temporary file, and verbose time output to TIME_LOG
TEMP_INFECTED_LOG="temp_infected_$(date '+%Y%m%d_%H%M%S').log"
sudo bash -c "$COMMAND &> \"$TEMP_INFECTED_LOG\"; /usr/bin/time -v $COMMAND &> \"$TIME_LOG\""

EXIT_STATUS=$?

# Capture end time
END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
END_EPOCH=$(date +%s)

# Capture final memory usage (in KB)
MEM_INFO_END=$(cat /proc/meminfo)
MEM_USED_END=$(echo "$MEM_INFO_END" | grep MemAvailable | awk '{print $2}' || echo "0")
SWAP_USED_END=$(echo "$MEM_INFO_END" | grep SwapFree | awk '{print $2}' || echo "0")

# Calculate memory and swap usage
MEM_USED=$((MEM_USED_START - MEM_USED_END))
SWAP_USED=$((TOTAL_SWAP - SWAP_USED_END))
[ $MEM_USED -lt 0 ] && MEM_USED=0
[ $SWAP_USED -lt 0 ] && SWAP_USED=0

# Convert to MB for readability
MEM_USED_MB=$(echo "scale=2; $MEM_USED / 1024" | bc 2>/dev/null || echo "0.00")
SWAP_USED_MB=$(echo "scale=2; $SWAP_USED / 1024" | bc 2>/dev/null || echo "0.00")

# Parse time output, handle empty or malformed output
USER_TIME=$(grep 'User time' "$TIME_LOG" | awk '{print $NF}' || echo "0.00")
SYS_TIME=$(grep 'System time' "$TIME_LOG" | awk '{print $NF}' || echo "0.00")
REAL_TIME=$(grep 'Elapsed.*wall' "$TIME_LOG" | awk '{print $NF}' | sed 's/.*://' | awk -F'.' '{print "0m"$1"."$2"s"}' || echo "0m0.00s")

# Add seconds unit to USER_TIME and SYS_TIME
USER_TIME="${USER_TIME}s"
SYS_TIME="${SYS_TIME}s"

# Extract peak RSS (in KB)
PEAK_RSS=$(grep 'Maximum resident set size' "$TIME_LOG" | awk '{print $NF}' || echo "0")
PEAK_RSS_MB=$(echo "scale=2; $PEAK_RSS / 1024" | bc 2>/dev/null || echo "0.00")

# Calculate elapsed time in seconds
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))
ELAPSED_SECONDS=$((ELAPSED_SECONDS < 1 ? 1 : ELAPSED_SECONDS)) # Avoid division by zero

# Calculate CPU usage percentage
TOTAL_CPU=$(echo "${USER_TIME%s} + ${SYS_TIME%s}" | bc 2>/dev/null || echo "0.00")
CPU_PERCENT=$(echo "scale=2; ($TOTAL_CPU / $ELAPSED_SECONDS) * 100" | bc 2>/dev/null || echo "0.00")

# Determine scan status
SCAN_STATUS="completed"
if [ $EXIT_STATUS -ne 0 ]; then
    SCAN_STATUS="failed"
fi

# Format infected files list, filter out errors/warnings/skipping messages
INFECTED_FILES="None"
if [ -s "$TEMP_INFECTED_LOG" ]; then
    INFECTED_FILES=$(grep -E '^[[:alnum:]_]+[[:space:]]+/' "$TEMP_INFECTED_LOG" | grep -v -i 'skipping\|error\|warning' | sed 's/^/  - /')
fi

# Count total detected rule matches, filter out errors/warnings/skipping messages
TOTAL_RULE_MATCHES=$(grep -E '^[[:alnum:]_]+[[:space:]]+/' "$TEMP_INFECTED_LOG" | grep -v -i 'skipping\|error\|warning' | wc -l)

# Extract skipped files count and list
SKIPPED_FILES_COUNT=$(grep -c '^warning: skipping' "$TEMP_INFECTED_LOG")
SKIPPED_FILES_LIST=$(grep '^warning: skipping' "$TEMP_INFECTED_LOG" | sed -e 's/^warning: skipping //' -e 's/ (\(.*\))$//' -e 's/^/  - /')

# Generate common report for terminal and log
COMMON_REPORT=$(cat << EOF
Scan Started at: $START_TIME
Infected Files:
$INFECTED_FILES
The Scan $SCAN_STATUS at: $END_TIME
Command Used: $COMMAND
User Time: $USER_TIME
System Time: $SYS_TIME
Elapsed Time: $REAL_TIME
Percent of CPU for this Job: $CPU_PERCENT%
Additional Info:
  - Directory to Recursively Scan: $2
  - Used Thread/s: $3
  - Log File: $LOG_FILE
  - Total Scanned Files: $(find "$TARGET_DIR" -type f 2>/dev/null | wc -l)
  - Skipped Files: $SKIPPED_FILES_COUNT
  - Total Detected Rule Matches: $TOTAL_RULE_MATCHES
  - Memory Used: $MEM_USED_MB MB
  - Swap Used: $SWAP_USED_MB MB
  - Peak Resident Set Size: $PEAK_RSS_MB MB
EOF
)

# Output common report to terminal
echo "$COMMON_REPORT"

# Save full report to log file, including skipped files list
{
    echo "$COMMON_REPORT"
    echo "Skipped Files List:"
    if [ $SKIPPED_FILES_COUNT -gt 0 ]; then
        echo "$SKIPPED_FILES_LIST"
    else
        echo "  None"
    fi
} > "$LOG_FILE"

# Clean up temporary files
rm -f "$TIME_LOG" "$TEMP_INFECTED_LOG"