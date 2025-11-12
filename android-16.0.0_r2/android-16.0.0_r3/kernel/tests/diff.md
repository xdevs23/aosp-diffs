```diff
diff --git a/tools/OWNERS b/tools/OWNERS
index b3332dc..9308712 100644
--- a/tools/OWNERS
+++ b/tools/OWNERS
@@ -1,11 +1,10 @@
 bettyzhou@google.com
-edliaw@google.com
+chihsheng@google.com
 elsk@google.com
 hsinyichen@google.com
 joneslee@google.com
 jstultz@google.com
 locc@google.com
 maennich@google.com
-vmartensson@google.com
+ttritton@google.com
 willmcvicker@google.com
-
diff --git a/tools/common_lib.sh b/tools/common_lib.sh
new file mode 100755
index 0000000..162542b
--- /dev/null
+++ b/tools/common_lib.sh
@@ -0,0 +1,543 @@
+#!/usr/bin/env bash
+# SPDX-License-Identifier: GPL-2.0
+
+# Common Script Library for kernel test tools
+
+# --- Include Guard ---
+# Prevents the library from being sourced multiple times.
+if [[ -n "$__COMMON_LIB_SOURCED__" ]]; then
+    return 0
+fi
+readonly __COMMON_LIB_SOURCED__=1
+
+# --- Constants ---
+readonly FETCH_SCRIPT_PATH_IN_REPO="kernel/tests/tools/fetch_artifact.sh"
+readonly KERNEL_JDK_PATH="prebuilts/jdk/jdk11/linux-x86"
+readonly LOCAL_JDK_PATH="/usr/local/buildtools/java/jdk11"
+readonly PLATFORM_JDK_PATH="prebuilts/jdk/jdk21/linux-x86"
+
+# --- BinFS ---
+readonly COMMON_LIB_CL_FLASH_CLI="/google/bin/releases/android/flashstation/cl_flashstation"
+readonly COMMON_LIB_LOCAL_FLASH_CLI="/google/bin/releases/android/flashstation/local_flashstation"
+
+
+# --- Internal State Flags ---
+__COMMON_LIB_NO_TPUT__="" # Flag set if tput is unavailable
+
+# --- Dependency Checks ---
+if ! command -v tput &> /dev/null; then
+    echo "[WARN] common_lib.sh: Command 'tput' not found. Colored output disabled." >&2
+    __COMMON_LIB_NO_TPUT__=1
+fi
+
+if ! command -v repo &> /dev/null; then
+    echo "[ERROR] common_lib.sh: Required command 'repo' not found. This library needs 'repo'." >&2
+    return 1
+fi
+
+if ! command -v date &> /dev/null; then
+    echo "[ERROR] common_lib.sh: Required command 'date' not found. Timestamping will fail." >&2
+    return 1
+fi
+
+# --- Color Constants ---
+# Initialize empty, setup if tput exists and stdout is a terminal.
+BLUE=""
+BOLD=""
+END=""
+GREEN=""
+ORANGE=""
+RED=""
+YELLOW=""
+if [[ -z "$__COMMON_LIB_NO_TPUT__" && -t 1 ]]; then
+    BLUE=$(tput setaf 4 2>/dev/null)
+    BOLD=$(tput bold 2>/dev/null)
+    END=$(tput sgr0 2>/dev/null)
+    GREEN=$(tput setaf 2 2>/dev/null)
+    ORANGE=$(tput setaf 208 2>/dev/null || tput setaf 3 2>/dev/null) # Fallback orange
+    RED=$(tput setaf 198 2>/dev/null || tput setaf 1 2>/dev/null)    # Fallback red
+    YELLOW=$(tput setaf 3 2>/dev/null)
+
+    # Basic check if tput commands worked (might fail on minimal terminals)
+    if [[ -z "$BLUE" || -z "$BOLD" || -z "$END" ]]; then
+        echo "[WARN] common_lib.sh: tput commands failed to set colors properly. Disabling colors." >&2
+        BLUE="" BOLD="" END="" GREEN="" ORANGE="" RED="" YELLOW=""
+    fi
+fi
+# Make color variables readonly after setting
+readonly BLUE BOLD END GREEN ORANGE RED YELLOW
+
+# --- Internal Helper ---
+
+function _timestamp() {
+    local ts=""
+    # Try ISO 8601 format with nanoseconds if supported
+    if ts=$(date --iso-8601=ns 2>/dev/null); then
+        printf "%s" "$ts"
+        return 0
+    # Fallback to seconds
+    elif ts=$(date --iso-8601=seconds 2>/dev/null); then
+        printf "%s" "$ts"
+        return 0
+    # Fallback to high-precision format if ISO fails but N supported
+    elif ts=$(date '+%Y-%m-%d %H:%M:%S.%N' 2>/dev/null); then
+        printf "%s" "$ts"
+        return 0
+    elif ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null); then
+        printf "%s" "$ts"
+        return 0
+    else
+        # If date command fails entirely
+        printf "TIMESTAMP_ERR" >&2 # Avoid calling log_error to prevent recursion
+        return 1
+    fi
+}
+
+function _print_log() {
+    local log_level="$1"
+    local color_code="$2"
+    local message="$3"
+    local exit_code="${4:-}" # Optional exit code for context
+    local external_frame_hint="${5:-}"
+    local timestamp
+    timestamp=$(_timestamp) || timestamp="TIMESTAMP_ERR"
+
+    local frame_to_report # This will hold the final frame number for 'caller'
+    if [[ -n "$external_frame_hint" && "$external_frame_hint" =~ ^[0-9]+$ ]]; then
+        # If an explicit frame hint is provided and is a number, use it directly.
+        frame_to_report="$external_frame_hint"
+    else
+        frame_to_report=1
+        if [[ -n "$external_frame_hint" && ! "$external_frame_hint" =~ ^[0-9]+$ ]]; then
+            echo "[WARN] common_lib.sh: Invalid external_frame_hint '$external_frame_hint' provided to _print_log. Using default frame 1." >&2
+        fi
+    fi
+
+    # Get caller info (line, function, script) - 'caller 1' gets info about the caller of log_info/warn/error
+    local caller_info
+    caller_info=$(caller "$frame_to_report" 2>/dev/null) || caller_info="? <unknown> <unknown>"
+
+    # Simple parsing of caller output (e.g., "123 my_func ./script.sh")
+    local caller_line="" caller_function="" caller_path="" caller_file="" context_info=""
+    if read -r caller_line caller_function caller_path <<< "$caller_info"; then
+        caller_file=$(basename "$caller_path")
+        context_info="[$caller_file:$caller_line ($caller_function)]"
+    else
+        context_info="[${caller_info}]" # Fallback if parsing fails
+    fi
+
+    # Format: TIMESTAMP LEVEL [script:line (function)]: Message
+    local log_prefix="${timestamp} ${log_level}"
+    local full_message_prefix="${log_prefix} ${context_info}: "
+    local full_message_suffix=""
+
+    # Append exit code context for errors if provided and non-zero
+    if [[ "$log_level" == "ERROR" && -n "$exit_code" && "$exit_code" -ne 0 ]]; then
+        # Append color codes carefully around the exit code part
+        full_message_suffix=" (${BOLD}Exit Code ${exit_code}${END}${color_code})${END}"
+    fi
+
+    # Determine output stream (stderr for WARN/ERROR)
+    local output_stream="/dev/stderr"
+    if [[ "$log_level" == "INFO" ]]; then
+        output_stream="/dev/stdout"
+    fi
+
+    # Print using printf with %s for the message to handle special characters safely
+    # Structure: ColorStart Prefix Message Suffix ColorEnd Newline
+    printf "%s%s%s%s%s\n" "${color_code}" "${full_message_prefix}" "$message" "${full_message_suffix}" "${END}" > "$output_stream"
+}
+
+# --- Public API Functions ---
+
+function log_info() {
+    _print_log "INFO" "${GREEN}" "$1"
+}
+
+# Accepts an optional second argument for context (e.g., an exit code).
+# Returns 0 (warnings don't indicate function failure).
+function log_warn() {
+    local message="$1"
+    local exit_code="${2:-}" # Optional context code
+    _print_log "WARN" "${YELLOW}" "$message" "$exit_code"
+    return 0
+}
+
+
+# Does NOT exit the script.
+# The caller should check the return status of functions using log_error.
+function log_error() {
+    local message="$1"
+    local exit_code="${2:-1}" # defaults to 1
+    local caller_frame_offset="${3:-}" # Default to empty, _print_log handles the default logic
+    _print_log "ERROR" "${RED}" "$message" "$exit_code" "$caller_frame_offset"
+    # Indicate that an error occurred via return status, but don't exit.
+    if [[ "$exit_code" =~ ^[0-9]+$ ]]; then
+        return "$exit_code"
+    else
+        return 1 # Default failure code if provided one was non-numeric
+    fi
+}
+
+function check_command() {
+    local cmd="$1"
+    if [[ -z "$cmd" ]]; then
+        log_error "Usage: check_command <cmd>"
+        return 1
+    fi
+
+    if command -v "$cmd" &> /dev/null; then
+        return 0
+    else
+        return 1
+    fi
+}
+
+# Usage: check_commands_available "cmd1" "cmd2" ...
+function check_commands_available() {
+    local -a commands_to_check=("$@")
+    if [[ ${#commands_to_check[@]} -eq 0 ]]; then
+        log_warn "No commands provided to check_commands_available."
+        return 0 # Nothing to check
+    fi
+
+    local all_available=true
+    local -a unavailable_commands=()
+    local cmd
+
+    for cmd in "${commands_to_check[@]}"; do
+        if ! check_command "$cmd"; then
+            all_available=false
+            unavailable_commands+=("'$cmd'")
+        fi
+    done
+
+    if "$all_available"; then
+        return 0
+    else
+        local unavailable_list
+        unavailable_list=$(printf "%s, " "${unavailable_commands[@]}")
+        unavailable_list=${unavailable_list%, } # Remove trailing comma and space
+        log_error "The following required commands are not available: ${unavailable_list}" 1
+        return 1
+    fi
+}
+
+function find_repo_root() {
+    local start_dir="${1:-$PWD}"
+    local current_dir
+
+    # Resolve potential ~ and relative paths to absolute, physical path (-P)
+    # Use '--' to handle start_dir potentially starting with '-'
+    if ! current_dir=$(cd -- "$start_dir" &>/dev/null && pwd -P); then
+        log_error "Invalid or inaccessible starting directory: '$start_dir'" 1
+        return 1
+    fi
+
+    # Search upwards for .repo directory, stopping at root '/'
+    while [[ "$current_dir" != "/" && ! -d "${current_dir}/.repo" ]]; do
+        current_dir=$(dirname -- "$current_dir")
+    done
+
+    # Check if found (must have .repo and not be the filesystem root itself)
+    if [[ -d "${current_dir}/.repo" && "$current_dir" != "/" ]]; then
+        printf "%s\n" "$current_dir" # Print the found path to stdout
+        return 0
+    fi
+
+    log_warn "No .repo directory found in or above: '$start_dir'" 1
+    return 1
+}
+
+function go_to_repo_root() {
+    local start_dir="${1:-$PWD}"
+    local repo_root
+    local cd_status
+
+    log_info "Attempting to find repo root starting from: '${start_dir}'"
+
+    # Call find_repo_root, capture its output (the path) and exit status
+    # Use process substitution or command substitution carefully
+    if ! repo_root=$(find_repo_root "$start_dir"); then
+        log_error "Failed to find repo root directory. Cannot change directory." 1
+        return 1
+    fi
+
+    if [[ -z "$repo_root" ]]; then
+        # Should not happen if find_repo_root returns 0, but good safety check
+        log_error "find_repo_root succeeded but returned an empty path. Cannot change directory." 1
+        return 1
+    fi
+
+    log_info "Repo root found: '${repo_root}'. Changing directory..."
+
+    cd -- "$repo_root" &>/dev/null
+    cd_status=$?
+    if (( cd_status != 0 )); then
+        log_error "Failed to change directory to: '${repo_root}'" "$cd_status"
+        return "$cd_status"
+    fi
+
+    log_info "Successfully changed directory to repo root: $PWD"
+    return 0
+}
+
+function is_in_repo_workspace() {
+    local check_path="${1:-$PWD}"
+    local resolved_path
+
+    if ! resolved_path=$(cd -- "$check_path" &>/dev/null && pwd -P); then
+        log_error "Invalid or inaccessible directory for repo check: '$check_path'" 1
+        return 1
+    fi
+
+    # Run 'repo list' in a subshell to avoid affecting the main script's directory
+    # and to capture stderr in case of repo tool issues. Redirect stdout to /dev/null.
+    local repo_output repo_status
+    repo_output=$( (cd -- "$resolved_path" && repo list) 2>&1 >/dev/null )
+    repo_status=$?
+
+    if (( repo_status != 0 )); then
+        # Log detailed warning including repo command output for debugging
+        log_warn "'repo list' command failed (exit code $repo_status) in '$resolved_path'. Not a repo workspace or repo tool issue? Output: ${repo_output}" "$repo_status"
+    fi
+    return $repo_status
+}
+
+function is_repo_root_dir() {
+    local root_path="$1"
+    local resolved_path
+
+    if [[ -z "$root_path" ]]; then
+        log_error "Usage: is_repo_root_dir <path>" 1
+        return 1
+    fi
+
+    # Resolve path robustly first
+    if ! resolved_path=$(cd -- "$root_path" &>/dev/null && pwd -P); then
+        # Log as warning because non-existence isn't strictly an error in logic, just a state.
+        log_warn "Directory does not exist or is inaccessible: '$root_path'" 1
+        return 1
+    fi
+
+    if [[ ! -d "${resolved_path}/.repo" ]]; then
+        log_warn "Directory exists but is missing '.repo' subdirectory: '${resolved_path}'" 1
+        return 1
+    fi
+
+    if is_in_repo_workspace "$resolved_path"; then
+        # Both .repo exists and 'repo list' works
+        log_info "Confirmed valid repo root directory: '$resolved_path'"
+        return 0
+    else
+        log_error "Directory '${resolved_path}' contains '.repo' but 'repo list' failed. May be an incomplete or corrupted checkout." 1
+        return 1
+    fi
+}
+
+function is_platform_repo() {
+    local repo_path="$1"
+    local resolved_path
+
+    if [[ -z "$repo_path" ]]; then
+        log_error "Usage: is_platform_repo <path>" 1
+        return 1
+    fi
+
+    if ! is_repo_root_dir "$repo_path"; then
+        log_error "'$repo_path' is not a valid repo root directory." 1
+        return 1
+    fi
+
+    resolved_path=$(cd -- "$repo_path" &>/dev/null && pwd -P) # Should succeed if is_repo_root_dir passed
+    local output repo_status
+    # Run in a subshell to cd safely and capture output/errors
+    output=$( (cd -- "$resolved_path" && repo list -p) 2>&1 )
+    repo_status=$?
+
+    if (( repo_status != 0 )); then
+        log_error "'repo list -p' failed in '${resolved_path}' (Exit Code $repo_status):$(printf '\n%s' "$output")" "$repo_status"
+        return 1
+    fi
+
+    # --- Heuristic Check ---
+    # This check assumes common Android platform structure.
+    # It might need adjustment if the platform layout changes significantly.
+    log_info "Applying heuristic check based on 'repo list -p' output..."
+    if [[ "$output" != *"build/make"* && "$output" != *"build/soong"* ]]; then
+        log_warn "Directory '${resolved_path}' may not be an Android Platform repository (heuristic check failed: missing 'build/make' or 'build/soong' in 'repo list -p' output)." 1
+        return 1
+    fi
+    # --- End Heuristic Check ---
+
+    log_info "Confirmed Android Platform repository (based on heuristic): ${resolved_path}"
+    return 0
+}
+
+function set_platform_repo() {
+    local product="$1"
+    local device_variant="$2" # e.g., "userdebug"
+    local platform_root="$3"
+    local resolved_root
+    local lunch_target
+    local envsetup_script
+
+    # Validate arguments
+    if [[ -z "$product" || -z "$device_variant" || -z "$platform_root" ]]; then
+        log_error "Usage: set_platform_repo <product> <variant> <platform_root>" 1
+        return 1
+    fi
+
+    # Validate platform_root is a usable platform repo directory
+    # This also resolves the path internally via is_repo_root_dir
+    if ! is_platform_repo "$platform_root"; then
+        # is_platform_repo already logs details
+        log_error "Validation failed for platform root: '$platform_root'" 1
+        return 1
+    fi
+
+    # Get the resolved absolute path (already validated)
+    resolved_root=$(cd -- "$platform_root" && pwd -P)
+
+    # Check for envsetup.sh existence robustly
+    envsetup_script="${resolved_root}/build/envsetup.sh"
+    if [[ ! -f "$envsetup_script" ]]; then
+        log_error "Cannot find build/envsetup.sh in specified platform root: '${resolved_root}'" 1
+        return 1
+    fi
+
+    if [[ -f "${resolved_root}/build/release/release_configs/trunk_staging.textproto" ]]; then
+        lunch_target="${product}-trunk_staging-${device_variant}"
+    else
+        lunch_target="${product}-${device_variant}"
+    fi
+    log_info "Determined lunch target: ${BOLD}${lunch_target}${END}"
+
+    # Temporarily change to the repo root to run the commands
+    # Use pushd/popd to manage directory changes reliably
+    log_info "Changing directory to '${resolved_root}' for setup..."
+
+    pushd "$resolved_root" &> /dev/null || { log_error "Failed to pushd into platform root: '${resolved_root}'"; return 1; }
+
+    log_info "Changed directory to '${resolved_root}' successfully."
+
+    # Source the setup script. This executes it in the CURRENT shell.
+    env_cmd=("." "${envsetup_script}")
+    log_info "Sourcing Script: ${env_cmd[*]}..."
+    run_command "${env_cmd[@]}"
+    local source_status=$?
+    if (( source_status != 0 )); then
+        log_error "Sourcing ${envsetup_script} failed." "$source_status"
+        popd > /dev/null || { log_error "'popd' failed after sourcing."; return 1; }
+        return "$source_status"
+    fi
+
+    log_info "Sourced envsetup.sh successfully."
+
+    # Run the lunch command (should be defined after sourcing envsetup.sh).
+    if ! check_command "lunch"; then
+        log_error "'lunch' command not found after sourcing envsetup.sh. Setup failed." 1
+        popd > /dev/null || { log_error "'popd' failed after checking command."; return 1; }
+        return 1
+    fi
+
+    log_info "Running: ${BOLD}lunch ${lunch_target}${END}"
+
+    local lunch_output
+    local temp_file
+    temp_file=$(mktemp)
+    lunch "${lunch_target}" 1>"$temp_file" 2>&1
+    local lunch_status=$?
+    lunch_output=$(cat "$temp_file")
+    # Clean up the temporary file
+    rm "$temp_file"
+
+    if [[ "$lunch_output" != *"error:"* ]]; then
+        log_info "Build environment successfully set for ${lunch_target}."
+    else
+        log_error "'lunch ${lunch_target}' failed. Output:$(printf '\n%s' "$lunch_output")" "$lunch_status"
+        popd > /dev/null || { log_error "'popd' failed after lunching target."; return 1; }
+        return "$lunch_status"
+    fi
+
+    popd > /dev/null || log_warn "'popd' failed after successful setup. Current directory: $PWD"
+
+    log_info "Setup complete. Returned to original directory via popd."
+    return 0
+}
+
+function parse_ab_url() {
+    local url="$1"
+    local branch_var="$2"
+    local target_var="$3"
+    local id_var="$4"
+
+    if [[ "$url" != ab://* ]]; then
+        log_error "Invalid ab URL format: $url" 1
+        return 1
+    fi
+
+    local path_part="${url#ab://}"
+    local -a parts=()
+    local IFS='/'
+    read -r -a parts <<< "$path_part"
+
+    if [[ ${#parts[@]} -lt 2 ]]; then # Must have at least branch and target
+        log_error "Malformed ab URL (not enough parts): $url" 1
+        return 1
+    fi
+
+    if [[ -z "${parts[0]}" ]]; then
+        log_error "branch variable has no value, check url format: $url" 1
+        return 1
+    fi
+
+    if [[ -z "${parts[1]}" ]]; then
+        log_error "target variable has no value, check url format: $url" 1
+        return 1
+    fi
+    printf -v "$branch_var" "%s" "${parts[0]}"
+    printf -v "$target_var" "%s" "${parts[1]}"
+
+    if [[ ${#parts[@]} -ge 3 && -n "${parts[2]}" ]]; then
+        printf -v "$id_var" "%s" "${parts[2]}"
+    else
+        log_warn "id variable is empty, use 'latest' as default id"
+        printf -v "$id_var" "%s" "latest"
+    fi
+    return 0
+}
+
+function run_command() {
+    local -a command_to_run=("$@")
+    local status_code
+
+    # log_info "Running: '${command_to_run[*]}'"
+
+    "${command_to_run[@]}"
+    status_code=$?
+    if (( status_code == 0 )); then
+        log_info "Succeeded."
+    else
+        log_error "Failed." "$status_code"
+    fi
+
+    return $status_code
+}
+
+function set_env_var() {
+    local var_name="$1"
+    local var_value="$2"
+
+    # Validate variable name (POSIX-compliant)
+    if ! [[ "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
+        log_error "Invalid environment variable name '$var_name'"
+        return 1
+    fi
+
+    export "$var_name=$var_value"
+    log_info "Exported environment variable: ${var_name}='${var_value}'"
+    return 0
+}
+
+log_info "common_lib.sh sourced successfully."
diff --git a/tools/common_lib_test.sh b/tools/common_lib_test.sh
new file mode 100755
index 0000000..b86c1fa
--- /dev/null
+++ b/tools/common_lib_test.sh
@@ -0,0 +1,488 @@
+#!/usr/bin/env bash
+
+# --- Test Configuration ---
+readonly SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
+readonly COMMON_LIB_PATH="${SCRIPT_DIR}/common_lib.sh"
+readonly SHUNIT2_PATH="${SCRIPT_DIR}/../../../external/shflags/lib/shunit2"
+
+# --- Global Test Variables ---
+TEST_TEMP_DIR=""
+MOCK_REPO_DIR=""
+MOCK_PLATFORM_DIR=""
+ORIGINAL_PATH="" # To store original PATH for restoration
+
+# --- Test Suite Setup ---
+oneTimeSetUp() {
+    # Save original PATH
+    ORIGINAL_PATH="$PATH"
+
+    # Ensure common_lib.sh is found and source it
+    if [[ ! -f "${COMMON_LIB_PATH}" ]]; then
+        echo "FATAL ERROR: Cannot find required library '$COMMON_LIB_PATH'" >&2
+        exit 1
+    fi
+
+    if ! . "${COMMON_LIB_PATH}" >/dev/null; then
+        echo "FATAL ERROR: Failed to source library '$COMMON_LIB_PATH'. Check common_lib.sh dependencies." >&2
+        exit 1
+    fi
+
+    # Create a temporary directory for test artifacts
+    TEST_TEMP_DIR=$(mktemp -d -t common_lib_test_XXXXXX)
+
+    # Setup common mock directories and files
+    MOCK_REPO_DIR="${TEST_TEMP_DIR}/mock_repo_root"
+    mkdir -p "${MOCK_REPO_DIR}/.repo"
+
+    MOCK_PLATFORM_DIR="${TEST_TEMP_DIR}/mock_platform_repo"
+    mkdir -p "${MOCK_PLATFORM_DIR}/.repo/manifests"
+    mkdir -p "${MOCK_PLATFORM_DIR}/build/make"
+    mkdir -p "${MOCK_PLATFORM_DIR}/build/soong" # For platform check
+    mkdir -p "${MOCK_PLATFORM_DIR}/build/release/release_configs"
+    # Create a mock envsetup.sh
+    cat <<-'EOF' > "${MOCK_PLATFORM_DIR}/build/envsetup.sh"
+#!/bin/sh
+lunch() {
+    echo "Mock lunch executing for target: $1"
+    if echo "$1" | grep -q "error"; then
+        echo "error: Mock lunch encountered an error for $1" >&2
+        return 1
+    elif echo "$1" | grep -q "no_lunch_cmd"; then
+        # This case should not happen if sourced correctly, but for testing check_command
+        echo "Error: lunch command was expected to be defined." >&2
+        return 127 # command not found
+    else
+        # Simulate setting some environment variables
+        export TARGET_PRODUCT=$(echo "$1" | cut -d- -f1)
+        export TARGET_BUILD_VARIANT=$(echo "$1" | cut -d- -f3)
+        echo "Mock TARGET_PRODUCT=${TARGET_PRODUCT}"
+        echo "Mock TARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT}"
+        return 0
+    fi
+}
+EOF
+    chmod +x "${MOCK_PLATFORM_DIR}/build/envsetup.sh"
+}
+
+oneTimeTearDown() {
+    # Clean up temporary directory
+    if [ -n "${TEST_TEMP_DIR}" ] && [ -d "${TEST_TEMP_DIR}" ]; then
+        rm -rf "${TEST_TEMP_DIR}"
+    fi
+    # Restore original PATH
+    PATH="$ORIGINAL_PATH"
+    # Unset any global variables
+    unset TEST_TEMP_DIR MOCK_REPO_DIR MOCK_PLATFORM_DIR ORIGINAL_PATH
+}
+
+setUp() {
+    cd "${TEST_TEMP_DIR}" || exit 1
+    # Restore PATH to original before each test, specific mocks will modify it per test
+    PATH="$ORIGINAL_PATH"
+    # Clear any environment variables that might be set by functions under test
+    unset MY_TEST_VAR MY_EMPTY_VAR TARGET_PRODUCT TARGET_BUILD_VARIANT
+}
+
+tearDown() {
+    # Runs after each test function
+    # Clean up any files created by a specific test if not in TEST_TEMP_DIR root
+    # Ensure PATH is restored if a test modified it and didn't clean up (though individual tests should)
+    PATH="$ORIGINAL_PATH"
+}
+
+# --- Empty suite() function ---
+# This will prevent the "command not found" error, and shunit2 will then
+# proceed to its auto-detection logic for "test_..." functions.
+suite() {
+    :
+}
+
+# --- Helper function to mock commands ---
+# Usage: _mock_command "cmd_name" "exit_code" "stdout_message" "stderr_message"
+_mock_command() {
+    local cmd_name="$1"
+    local exit_code="${2:-0}"
+    local stdout_msg="${3:-}"
+    local stderr_msg="${4:-}"
+
+    mkdir -p "${TEST_TEMP_DIR}/bin"
+    cat > "${TEST_TEMP_DIR}/bin/${cmd_name}" <<-EOF
+#!/bin/sh
+# Mock for ${cmd_name}
+if [ -n "${stderr_msg}" ]; then echo "${stderr_msg}" >&2; fi
+if [ -n "${stdout_msg}" ]; then echo "${stdout_msg}"; fi
+exit ${exit_code}
+EOF
+    chmod +x "${TEST_TEMP_DIR}/bin/${cmd_name}"
+    PATH="${TEST_TEMP_DIR}/bin:${PATH}"
+}
+
+# --- Test Cases ---
+
+# Test _timestamp
+test__timestamp_format() {
+    local ts
+    ts=$(_timestamp)
+    local status=$?
+    assertEquals "_timestamp should succeed" 0 "${status}"
+    assertTrue "_timestamp should return a non-empty string" "[ -n \"${ts}\" ]"
+    # Basic check for ISO-like format (YYYY-MM-DD)
+    assertContains "_timestamp output should contain YYYY-MM-DD" "${ts}" "$(date +%Y-%m-%d)"
+}
+
+test__timestamp_date_fails() {
+    _mock_command "date" 1 "" "mock date failure" # Mock date to fail
+
+    local stdout_val stderr_val
+    # Capture stdout and _timestamp's direct stderr separately
+    # Subshell to capture stdout correctly
+    stdout_val=$( ( _timestamp ) 2> "${TEST_TEMP_DIR}/stderr.txt" )
+    local status=$?
+    stderr_val=$(cat "${TEST_TEMP_DIR}/stderr.txt")
+    rm "${TEST_TEMP_DIR}/stderr.txt"
+
+    assertEquals "_timestamp should return 1 if all date attempts fail" 1 "${status}"
+    assertTrue "_timestamp stdout should be empty if all date attempts fail" "[ -z \"${stdout_val}\" ]"
+    assertContains "Stderr from _timestamp should contain TIMESTAMP_ERR" "${stderr_val}" "TIMESTAMP_ERR"
+}
+
+# Test log_info, log_warn, log_error
+test_log_info_runs() {
+    local stdout_val stderr_val
+    stdout_val=$(log_info "Test info message" 2> "${TEST_TEMP_DIR}/stderr.txt")
+    stderr_val=$(cat "${TEST_TEMP_DIR}/stderr.txt")
+    rm "${TEST_TEMP_DIR}/stderr.txt"
+
+    assertTrue "log_info should not fail (return 0)" $? # log_info itself has no return, relies on _print_log
+    assertContains "log_info stdout should contain INFO and message" "${stdout_val}" "INFO"
+    assertContains "log_info stdout should contain the message" "${stdout_val}" "Test info message"
+    assertTrue "log_info stderr should be empty" "[ -z \"${stderr_val}\" ]"
+}
+
+test_log_warn_runs_and_returns_zero() {
+    local stderr_val stdout_val
+    stderr_val=$(log_warn "Test warn message" 2>&1 1>"${TEST_TEMP_DIR}/stdout.txt") # Capture combined, then filter
+    local status=$?
+    stdout_val=$(cat "${TEST_TEMP_DIR}/stdout.txt")
+    rm "${TEST_TEMP_DIR}/stdout.txt"
+
+    assertEquals "log_warn should return 0" 0 "${status}"
+    assertContains "log_warn stderr should contain WARN and message" "${stderr_val}" "WARN"
+    assertContains "log_warn stderr should contain the message" "${stderr_val}" "Test warn message"
+    assertTrue "log_warn stdout should be empty" "[ -z \"${stdout_val}\" ]"
+}
+
+test_log_warn_with_exit_code_context() {
+    local stderr_val
+    stderr_val=$(log_warn "Test warn message with context" 123 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "log_warn with context should return 0" 0 "${status}"
+}
+
+test_log_error_runs_and_returns_code() {
+    local stderr_val
+    stderr_val=$(log_error "Test error message" 5 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "log_error should return the specified exit code" 5 "${status}"
+    assertContains "log_error stderr should contain ERROR and message" "${stderr_val}" "ERROR"
+    assertContains "log_error stderr should contain the message" "${stderr_val}" "Test error message"
+    assertContains "log_error output should contain exit code" "${stderr_val}" "Exit Code 5"
+}
+
+test_log_error_default_exit_code() {
+    log_error "Test error message default" >/dev/null 2>&1
+    local status=$?
+    assertEquals "log_error should return 1 by default" 1 "${status}"
+}
+
+test_log_error_non_numeric_exit_code() {
+    log_error "Test error with non-numeric code" "invalid" >/dev/null 2>&1
+    local status=$?
+    assertEquals "log_error should return 1 for non-numeric code" 1 "${status}"
+}
+
+# Test check_command
+test_check_command_exists() {
+    assertTrue "check_command for 'echo' should return true (0)" "check_command echo"
+}
+
+test_check_command_not_exists() {
+    assertFalse "check_command for 'non_existent_command_xyz' should return false (1)" "check_command non_existent_command_xyz"
+}
+
+test_check_command_empty_arg() {
+    # Behavior of `command -v ""` can vary. Bash returns 0, others might return 1.
+    # common_lib.sh uses #!/usr/bin/env bash, so test bash behavior.
+    local stderr_val
+    stderr_val=$(check_command "" 2>&1)
+    local status=$?
+    # In Bash, `command -v ""` is true, set up guard clause.
+    assertEquals "check_command with empty string should return 1 in bash" 1 "${status}"
+    assertContains "Error message should contain 'Usage: check_command <cmd>'" "${stderr_val}" "Usage: check_command <cmd>"
+}
+
+# Test check_commands_available
+test_check_commands_available_all_exist() {
+    check_commands_available echo true cat
+    local status=$?
+    assertEquals "check_commands_available for 'echo', 'true', 'cat' should succeed (0)" 0 "${status}"
+}
+
+test_check_commands_available_one_missing() {
+    local stderr_val
+    stderr_val=$(check_commands_available echo non_existent_cmd_789 true 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "check_commands_available with one missing should return 1" 1 "${status}"
+    assertContains "Error message should contain 'non_existent_cmd_789'" "${stderr_val}" "'non_existent_cmd_789'"
+}
+
+test_check_commands_available_no_args() {
+    local warn_output
+    warn_output=$(check_commands_available 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "check_commands_available with no args should return 0" 0 "${status}"
+    assertContains "Warning message should indicate no commands provided" "${warn_output}" "No commands provided"
+}
+
+# Test find_repo_root
+test_find_repo_root_is_current_dir() {
+    mkdir -p "${TEST_TEMP_DIR}/current_is_root/.repo"
+    cd "${TEST_TEMP_DIR}/current_is_root" || exit 1
+    local found_root
+    found_root=$(find_repo_root "$PWD") # Use PWD directly for clarity
+    local status=$?
+    assertEquals "find_repo_root status should be 0" 0 "${status}"
+    assertEquals "find_repo_root should find current dir" "$PWD" "${found_root}"
+}
+
+test_find_repo_root_is_parent_dir() {
+    mkdir -p "${MOCK_REPO_DIR}/subdir1/subdir2" # MOCK_REPO_DIR has .repo
+    cd "${MOCK_REPO_DIR}/subdir1/subdir2" || exit 1
+    local found_root
+    found_root=$(find_repo_root ".")
+    local status=$?
+    assertEquals "find_repo_root status should be 0" 0 "${status}"
+    assertEquals "find_repo_root should find MOCK_REPO_DIR" "${MOCK_REPO_DIR}" "${found_root}"
+}
+
+test_find_repo_root_not_found() {
+    mkdir -p "${TEST_TEMP_DIR}/no_repo_here"
+    cd "${TEST_TEMP_DIR}/no_repo_here" || exit 1
+    local found_root stderr_log
+    found_root=$(find_repo_root . 2> "${TEST_TEMP_DIR}/stderr.txt")
+    local status=$?
+    stderr_log=$(cat "${TEST_TEMP_DIR}/stderr.txt")
+    rm "${TEST_TEMP_DIR}/stderr.txt"
+    assertEquals "find_repo_root status should be 1 when not found" 1 "${status}"
+    assertTrue "find_repo_root stdout should be empty when not found" "[ -z \"${found_root}\" ]"
+    assertContains "Error message should indicate no .repo directory" "${stderr_log}" "No .repo directory found"
+}
+
+# Test go_to_repo_root
+test_go_to_repo_root_success() {
+    local start_path="${MOCK_REPO_DIR}/some_subdir_for_go_to" # MOCK_REPO_DIR has .repo
+    mkdir -p "${start_path}"
+    cd "${start_path}" || exit 1
+
+    local original_pwd="$PWD"
+    local info_log
+    go_to_repo_root "."    1>"${TEST_TEMP_DIR}/stdout.txt"
+    local status=$?
+    info_log=$(cat "${TEST_TEMP_DIR}/stdout.txt")
+    rm "${TEST_TEMP_DIR}/stdout.txt"
+    assertEquals "go_to_repo_root should succeed" 0 "${status}"
+    assertEquals "Should change directory to MOCK_REPO_DIR" "${MOCK_REPO_DIR}" "$PWD"
+    assertContains "Log should indicate success" "${info_log}" "Successfully changed directory to repo root"
+    cd "${original_pwd}" # Go back
+}
+
+# Test is_in_repo_workspace
+test_is_in_repo_workspace_true() {
+    _mock_command "repo" 0 "mock repo list output" "" # Mock 'repo list' to succeed
+    is_in_repo_workspace "${TEST_TEMP_DIR}"
+    local status=$?
+    assertEquals "is_in_repo_workspace should return 0 when 'repo list' succeeds" 0 "${status}"
+}
+
+test_is_in_repo_workspace_false() {
+    _mock_command "repo" 1 "" "mock repo list error" # Mock 'repo list' to fail
+    local warn_log
+    warn_log=$(is_in_repo_workspace "${TEST_TEMP_DIR}" 2>&1 >/dev/null)
+    local status=$?
+    # Modified
+    assertEquals "is_in_repo_workspace should return 1 when 'repo list' fails" 1 "${status}"
+    assertContains "Warning log should contain 'repo list command failed'" "${warn_log}" "'repo list' command failed"
+}
+
+# Test is_repo_root_dir
+test_is_repo_root_dir_true() {
+    _mock_command "repo" 0 # Mock 'repo list' to succeed
+    local info_log
+    info_log=$(is_repo_root_dir "${MOCK_REPO_DIR}" 2>/dev/null) # MOCK_REPO_DIR has .repo
+    local status=$?
+    assertEquals "is_repo_root_dir should return 0 for valid repo root" 0 "${status}"
+    assertContains "Info log should confirm valid repo root" "${info_log}" "Confirmed valid repo root directory"
+}
+
+# Test is_platform_repo
+test_is_platform_repo_true() {
+    # MOCK_PLATFORM_DIR has .repo and build/make
+    # Mock 'repo list' and 'repo list -p'
+    mkdir -p "${TEST_TEMP_DIR}/bin"
+    cat > "${TEST_TEMP_DIR}/bin/repo" <<-EOF
+#!/bin/sh
+if [ "\$1" = "list" ] && [ "\$2" = "-p" ]; then echo "kernel/common build/make some/other"; exit 0; fi
+if [ "\$1" = "list" ]; then exit 0; fi
+exit 1
+EOF
+    chmod +x "${TEST_TEMP_DIR}/bin/repo"
+    PATH="${TEST_TEMP_DIR}/bin:${PATH}"
+
+    local info_log
+    info_log=$(is_platform_repo "${MOCK_PLATFORM_DIR}" 2>/dev/null)
+    local status=$?
+    assertEquals "is_platform_repo should return 0 for valid platform repo" 0 "${status}"
+    assertContains "Info log should confirm platform repo" "${info_log}" "Confirmed Android Platform repository"
+}
+
+test_is_platform_repo_not_platform_heuristic_fails() {
+    mkdir -p "${TEST_TEMP_DIR}/bin"
+    cat > "${TEST_TEMP_DIR}/bin/repo" <<-EOF
+#!/bin/sh
+if [ "\$1" = "list" ] && [ "\$2" = "-p" ]; then echo "some/other/project"; exit 0; fi
+if [ "\$1" = "list" ]; then exit 0; fi
+exit 1
+EOF
+    chmod +x "${TEST_TEMP_DIR}/bin/repo"
+    PATH="${TEST_TEMP_DIR}/bin:${PATH}"
+
+    local warn_log
+    warn_log=$(is_platform_repo "${MOCK_REPO_DIR}" 2>&1 >/dev/null) # MOCK_REPO_DIR has .repo but -p output won't match
+    local status=$?
+    assertEquals "is_platform_repo should return 1 if heuristic fails" 1 "${status}"
+    assertContains "Warn log should indicate heuristic check failed" "${warn_log}" "may not be an Android Platform repository"
+}
+
+# Test set_platform_repo
+test_set_platform_repo_success() {
+    # MOCK_PLATFORM_DIR has mock envsetup.sh & .repo, build/make
+    # Mock 'repo list' and 'repo list -p' for is_platform_repo to pass
+    mkdir -p "${TEST_TEMP_DIR}/bin"
+    cat > "${TEST_TEMP_DIR}/bin/repo" <<-EOF
+#!/bin/sh
+if [ "\$1" = "list" ] && [ "\$2" = "-p" ]; then echo "kernel/common build/make"; exit 0; fi
+if [ "\$1" = "list" ]; then exit 0; fi
+exit 1
+EOF
+    chmod +x "${TEST_TEMP_DIR}/bin/repo"
+    PATH="${TEST_TEMP_DIR}/bin:${PATH}"
+
+    local output_log
+    output_log=$(set_platform_repo "myproduct" "userdebug" "${MOCK_PLATFORM_DIR}" 2>&1)
+    local status=$?
+
+    assertEquals "set_platform_repo should return 0 on success" 0 "${status}"
+    assertContains "Log should indicate successful setup" "${output_log}" "Build environment successfully set for myproduct-userdebug"
+    assertContains "Log should show lunch target" "${output_log}" "myproduct-userdebug"
+    # Check if vars set by mock lunch are present
+    # Need to run this in a subshell to check env vars set by sourcing.
+    local subshell_output
+    subshell_output=$( (set_platform_repo "aproduct" "eng" "${MOCK_PLATFORM_DIR}" >/dev/null 2>&1 && echo "TARGET_PRODUCT=${TARGET_PRODUCT:-unset}") )
+    assertContains "TARGET_PRODUCT should be set by mock lunch" "${subshell_output}" "TARGET_PRODUCT=aproduct"
+}
+
+test_set_platform_repo_lunch_fails() {
+    mkdir -p "${TEST_TEMP_DIR}/bin" # For repo mock
+    cat > "${TEST_TEMP_DIR}/bin/repo" <<-EOF
+#!/bin/sh
+if [ "\$1" = "list" ] && [ "\$2" = "-p" ]; then echo "build/make"; exit 0; fi
+if [ "\$1" = "list" ]; then exit 0; fi
+exit 1
+EOF
+    chmod +x "${TEST_TEMP_DIR}/bin/repo"
+    PATH="${TEST_TEMP_DIR}/bin:${PATH}"
+
+    local err_log
+    # Mock lunch in MOCK_PLATFORM_DIR/build/envsetup.sh will fail if target contains "error"
+    err_log=$(set_platform_repo "product_error" "userdebug" "${MOCK_PLATFORM_DIR}" 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "set_platform_repo should fail if lunch fails" 1 "${status}"
+    assertContains "Log should indicate lunch failed" "${err_log}" "'lunch product_error-userdebug' failed"
+}
+
+# Test parse_ab_url
+test_parse_ab_url_full_url() {
+    local branch target id
+    parse_ab_url "ab://my-branch/my-target/12345" branch target id
+    local status=$?
+    assertEquals "parse_ab_url for full URL should succeed" 0 "${status}"
+    assertEquals "Branch not parsed correctly" "my-branch" "${branch}"
+    assertEquals "Target not parsed correctly" "my-target" "${target}"
+    assertEquals "ID not parsed correctly" "12345" "${id}"
+}
+
+test_parse_ab_url_no_id() {
+    local branch target id
+    local warn_output
+    parse_ab_url "ab://another-branch/another-target" branch target id 2>/dev/null
+    local status=$?
+    assertEquals "parse_ab_url with no ID should succeed" 0 "${status}"
+    assertEquals "ID should default to 'latest' when missing" "latest" "${id}"
+}
+
+test_parse_ab_url_invalid_prefix() {
+    local branch="" target="" id="" # Initialize to check they are not set
+    local err_log
+    err_log=$(parse_ab_url "http://my-branch/my-target/123" branch target id 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "parse_ab_url with invalid prefix should fail" 1 "${status}"
+    assertContains "Error log for invalid prefix" "${err_log}" "Invalid ab URL format"
+    assertEquals "Branch should remain empty on failure" "" "${branch}"
+}
+
+# Test run_command
+test_run_command_success() {
+    local output_log
+    output_log=$(run_command true 2>&1)
+    local status=$?
+    assertEquals "run_command with 'true' should return 0" 0 "${status}"
+    assertContains "Log for successful run_command" "${output_log}" "Succeeded."
+}
+
+test_run_command_failure() {
+    local output_log
+    output_log=$(run_command false 2>&1)
+    local status=$?
+    assertEquals "run_command with 'false' should return 1" 1 "${status}"
+    assertContains "Log for failed run_command" "${output_log}" "Failed."
+    assertContains "Log for failed run_command should show exit code" "${output_log}" "Exit Code 1"
+}
+
+# Test set_env_var
+test_set_env_var_success() {
+    set_env_var "MY_TEST_VAR" "my_value" >/dev/null
+    local status=$?
+    assertEquals "set_env_var should return 0 on success" 0 "${status}"
+    assertEquals "Environment variable MY_TEST_VAR set correctly" "my_value" "${MY_TEST_VAR:-}"
+}
+
+test_set_env_var_invalid_name() {
+    local err_log
+    err_log=$(set_env_var "1INVALID_VAR" "value" 2>&1 >/dev/null)
+    local status=$?
+    assertEquals "set_env_var with invalid name should return 1" 1 "${status}"
+    assertContains "Error log for invalid name" "${err_log}" "Invalid environment variable name"
+    # Check that the invalid variable was not actually set
+    assertFalse "Invalid variable 1INVALID_VAR should not be set" "printenv | grep -q '^1INVALID_VAR='"
+}
+
+# --- Load shunit2 ---
+if [[ ! -f "${SHUNIT2_PATH}" ]]; then
+    echo "FATAL ERROR: Cannot find required library '$SHUNIT2_PATH'" >&2
+    exit 1
+fi
+
+if ! . "${SHUNIT2_PATH}"; then
+    echo "FATAL ERROR: Failed to source library '$SHUNIT2_PATH'. Check common_lib.sh dependencies." >&2
+    exit 1
+fi
diff --git a/tools/flash_device.sh b/tools/flash_device.sh
index f7f75e0..ef7153f 100755
--- a/tools/flash_device.sh
+++ b/tools/flash_device.sh
@@ -4,12 +4,8 @@
 # A handy tool to flash device with local build or remote build.
 
 # Constants
-FETCH_SCRIPT="fetch_artifact.sh"
 # Please see go/cl_flashstation
-CL_FLASH_CLI=/google/bin/releases/android/flashstation/cl_flashstation
-LOCAL_FLASH_CLI=/google/bin/releases/android/flashstation/local_flashstation
 MIX_SCRIPT_NAME="build_mixed_kernels_ramdisk"
-FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
 DOWNLOAD_PATH="/tmp/downloaded_images"
 KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
 PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
@@ -19,30 +15,23 @@ LOCAL_JDK_PATH=/usr/local/buildtools/java/jdk11
 LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
 MIN_FASTBOOT_VERSION="35.0.2-12583183"
 VENDOR_KERNEL_IMGS=("boot.img" "initramfs.img" "dtb.img" "dtbo.img" "vendor_dlkm.img")
-# Color constants
-BOLD="$(tput bold)"
-END="$(tput sgr0)"
-GREEN="$(tput setaf 2)"
-RED="$(tput setaf 198)"
-YELLOW="$(tput setaf 3)"
-ORANGE="$(tput setaf 208)"
-BLUE=$(tput setaf 4)
-
+SKIP_UPDATE_BOOTLOADER=false
 SKIP_BUILD=false
 GCOV=false
 DEBUG=false
 KASAN=false
 EXTRA_OPTIONS=()
-LOCAL_REPO=
 DEVICE_VARIANT="userdebug"
 
-BOARD=
 ABI=
 PRODUCT=
 BUILD_TYPE=
 DEVICE_KERNEL_STRING=
 DEVICE_KERNEL_VERSION=
+LOCAL_FLASH_CLI=
+CL_FLASH_CLI=
 SYSTEM_DLKM_INFO=
+readonly REQUIRED_COMMANDS=("adb" "dirname" "fastboot")
 
 function print_help() {
     echo "Usage: $0 [OPTIONS]"
@@ -53,6 +42,8 @@ function print_help() {
     echo "  -s <serial_number>, --serial=<serial_number>"
     echo "                        [Mandatory] The serial number for device to be flashed with."
     echo "  --skip-build          [Optional] Skip the image build step. Will build by default if in repo."
+    echo "  --skip-update-bootloader"
+    echo "                        [Optional] Skip update bootloader for Anti-Rollback device."
     echo "  --gcov                [Optional] Build gcov enabled kernel"
     echo "  --debug               [Optional] Build debug enabled kernel"
     echo "  --kasan               [Optional] Build kasan enabled kernel"
@@ -192,6 +183,10 @@ function parse_arg() {
                 DEVICE_VARIANT=$(echo $1 | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
+            --skip-update-bootloader)
+                SKIP_UPDATE_BOOTLOADER=true
+                shift
+                ;;
             --gcov)
                 GCOV=true
                 shift
@@ -206,29 +201,14 @@ function parse_arg() {
                 ;;
             *)
                 print_error "Unsupported flag: $1" >&2
-                shift
                 ;;
         esac
     done
 }
 
-function adb_checker() {
-    if ! which adb &> /dev/null; then
-        print_error "adb not found!"
-    fi
-}
-
-function go_to_repo_root() {
-    current_dir="$1"
-    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
-        current_dir=$(dirname "$current_dir")  # Go up one directory
-        cd "$current_dir"
-    done
-}
-
 function print_info() {
     local log_prompt=$MY_NAME
-    if [ ! -z "$2" ]; then
+    if [ -n "$2" ]; then
         log_prompt+=" line $2"
     fi
     echo "[$log_prompt]: ${GREEN}$1${END}"
@@ -236,7 +216,7 @@ function print_info() {
 
 function print_warn() {
     local log_prompt=$MY_NAME
-    if [ ! -z "$2" ]; then
+    if [ -n "$2" ]; then
         log_prompt+=" line $2"
     fi
     echo "[$log_prompt]: ${ORANGE}$1${END}"
@@ -244,7 +224,7 @@ function print_warn() {
 
 function print_error() {
     local log_prompt=$MY_NAME
-    if [ ! -z "$2" ]; then
+    if [ -n "$2" ]; then
         log_prompt+=" line $2"
     fi
     echo -e "[$log_prompt]: ${RED}$1${END}"
@@ -252,7 +232,7 @@ function print_error() {
     exit 1
 }
 
-function set_platform_repo () {
+function set_platform_repo() {
     print_warn "Build environment target product '${TARGET_PRODUCT}' does not match expected $1. \
     Reset build environment" "$LINENO"
     local lunch_cli="source build/envsetup.sh && lunch $1"
@@ -271,7 +251,7 @@ function set_platform_repo () {
     fi
 }
 
-function find_repo () {
+function find_repo() {
     manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "kernel/private/devices/google/common" \
      -e "private/google-modules/soc/gs" -e "kernel/common" -e "common-modules/virtual-device" \
      .repo/manifests/default.xml)
@@ -310,7 +290,7 @@ function find_repo () {
     esac
 }
 
-function build_platform () {
+function build_platform() {
     if [[ "$SKIP_BUILD" = true ]]; then
         print_warn "--skip-build is set. Do not rebuild platform build" "$LINENO"
         return
@@ -331,7 +311,7 @@ function build_platform () {
     fi
 }
 
-function build_ack () {
+function build_ack() {
     if [[ "$SKIP_BUILD" = true ]]; then
         print_warn "--skip-build is set. Do not rebuild kernel" "$LINENO"
         return
@@ -360,7 +340,7 @@ function build_ack () {
 function format_ab_platform_build_string() {
     if [[ "$PLATFORM_BUILD" != ab://* ]]; then
         print_error "Please provide the platform build in the form of ab:// with flag -pb" "$LINENO"
-        return 1
+        return 1 # Keep return for consistency, though print_error exits
     fi
     IFS='/' read -ra array <<< "$PLATFORM_BUILD"
     local _branch="${array[2]}"
@@ -371,7 +351,7 @@ function format_ab_platform_build_string() {
         _branch="git_main"
     fi
     if [ -z "$_build_target" ]; then
-        if [ ! -z "$PRODUCT" ]; then
+        if [ -n "$PRODUCT" ]; then
             _build_target="$PRODUCT-userdebug"
         else
             print_error "Can not find platform build target through device info. Please \
@@ -380,7 +360,8 @@ function format_ab_platform_build_string() {
         fi
     fi
     if [[ "$_branch" == aosp-main* ]] || [[ "$_branch" == git_main* ]]; then
-        if [[ "$_build_target" != *-trunk_staging-* ]] || [[ "$_build_target" != *-next-* ]]  || [[ "$_build_target" != *-trunk_food-* ]]; then
+        if [[ "$_build_target" != *-trunk_staging-* ]] && [[ "$_build_target" != *-next-* ]] \
+        && [[ "$_build_target" != *-trunk_food-* ]]; then
             _build_target="${_build_target/-user/-trunk_staging-user}"
         fi
     fi
@@ -391,6 +372,35 @@ function format_ab_platform_build_string() {
     print_info "Platform build to be used is $PLATFORM_BUILD" "$LINENO"
 }
 
+function format_ab_system_build_string() {
+    if [[ "$SYSTEM_BUILD" != ab://* ]]; then
+        print_error "Please provide the system build in the form of ab:// with flag -sb" "$LINENO"
+        return 1
+    fi
+    IFS='/' read -ra array <<< "$SYSTEM_BUILD"
+    local _branch="${array[2]}"
+    local _build_target="${array[3]}"
+    local _build_id="${array[4]}"
+    if [ -z "$_branch" ]; then
+        print_info "Branch is not specified in system build as ab://<branch>. Using git_main branch" "$LINENO"
+        _branch="git_main"
+    fi
+    if [ -z "$_build_target" ]; then
+        _build_target="gsi_arm64-userdebug"
+    fi
+    if [[ "$_branch" == aosp-main* ]] || [[ "$_branch" == git_main* ]]; then
+        if [[ "$_build_target" != *-trunk_staging-* ]] && [[ "$_build_target" != *-next-* ]]  && \
+        [[ "$_build_target" != *-trunk_food-* ]]; then
+            _build_target="${_build_target/-user/-trunk_staging-user}"
+        fi
+    fi
+    if [ -z "$_build_id" ]; then
+        _build_id="latest"
+    fi
+    SYSTEM_BUILD="ab://$_branch/$_build_target/$_build_id"
+    print_info "System build to be used is $SYSTEM_BUILD" "$LINENO"
+}
+
 function format_ab_kernel_build_string() {
     if [[ "$KERNEL_BUILD" != ab://* ]]; then
         print_error "Please provide the kernel build in the form of ab:// with flag -kb" "$LINENO"
@@ -401,12 +411,25 @@ function format_ab_kernel_build_string() {
     local _build_target="${array[3]}"
     local _build_id="${array[4]}"
     if [ -z "$_branch" ]; then
+        print_info "$KERNEL_BUILD provided in -kb doesn't have branch info. Will use the kernel version from device" "$LINENO"
         if [ -z "$DEVICE_KERNEL_VERSION" ]; then
-            print_error "Branch is not provided in kernel build $KERNEL_BUILD. \
-            The kernel version can not be retrieved from device to decide GKI kernel build" "$LINENO"
+            print_error "The kernel version can not be retrieved from device to decide GKI kernel build" "$LINENO"
         fi
-        print_info "Branch is not specified in kernel build as ab://<branch>. Using $DEVICE_KERNEL_VERSION kernel branch." "$LINENO"
+        print_info "Branch is not specified in kernel build as ab://<branch>. Using device's existing kernel version $DEVICE_KERNEL_VERSION." "$LINENO"
         _branch="$DEVICE_KERNEL_VERSION"
+        KERNEL_VERSION="$DEVICE_KERNEL_VERSION"
+    else
+        if [[ "$_branch" == *mainline* ]]; then
+            KERNEL_VERSION="android-mainline"
+        else
+            local _android_version=$(echo "$_branch" | grep -oE 'android[0-9]+')
+            local _kernel_version=$(echo "$_branch" | grep -oE '[0-9]+\.[0-9]+')
+            if [ -z "$_android_version" ] || [ -z "$_kernel_version" ]; then
+                print_warn "Unable to get kernel version from $KERNEL_BUILD" "$LINENO"
+            else
+                KERNEL_VERSION="$_android_version-$_kernel_version"
+            fi
+        fi
     fi
     if [[ "$_branch" == "android"* ]]; then
         _branch="aosp_kernel-common-$_branch"
@@ -545,13 +568,19 @@ function format_ab_vendor_kernel_build_string() {
 function download_platform_build() {
     print_info "Downloading $PLATFORM_BUILD to $PWD" "$LINENO"
     local _build_info="$PLATFORM_BUILD"
-    local _file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "misc_info.txt" "otatools.zip")
-    if [[ "$1" == *git_sc* ]]; then
-        _file_patterns+=("ramdisk.img")
-    elif [[ "$1" == *user/* ]]; then
-        _file_patterns+=("vendor_ramdisk-debug.img")
-    else
-        _file_patterns+=("vendor_ramdisk.img")
+    local _file_patterns=("*$PRODUCT-img-*.zip" "radio.img")
+    if [ "$SKIP_UPDATE_BOOTLOADER" = false ]; then
+        _file_patterns+=("bootloader.img")
+    fi
+    if [ -n "$VENDOR_KERNEL_BUILD" ]; then
+        _file_patterns+=("misc_info.txt" "otatools.zip")
+        if [[ "$1" == *git_sc* ]]; then
+            _file_patterns+=("ramdisk.img")
+        elif [[ "$1" == *user/* ]]; then
+            _file_patterns+=("vendor_ramdisk-debug.img")
+        else
+            _file_patterns+=("vendor_ramdisk.img")
+        fi
     fi
 
     for _pattern in "${_file_patterns[@]}"; do
@@ -570,18 +599,58 @@ function download_platform_build() {
     echo ""
 }
 
-function download_gki_build() {
-    print_info "Downloading $1 to $PWD" "$LINENO"
-    local _build_info="$1"
-    local _file_patterns=( "boot-lz4.img"  )
-
-    if [[ "$PRODUCT" == "oriole" ]] || [[ "$PRODUCT" == "raven" ]]; then
-        if [[ "$_build_info" != *android13* ]]; then
-            _file_patterns+=("system_dlkm_staging_archive.tar.gz" "kernel_aarch64_Module.symvers")
+function download_system_build() {
+    print_info "Downloading $SYSTEM_BUILD to $PWD" "$LINENO"
+    local _build_info="$SYSTEM_BUILD"
+    local _file_patterns=("*_arm64-img-*.zip")
+    for _pattern in "${_file_patterns[@]}"; do
+        print_info "Downloading $_build_info/$_pattern" "$LINENO"
+        eval "$FETCH_SCRIPT $_build_info/$_pattern"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Downloading $_build_info/$_pattern succeeded" "$LINENO"
+        else
+            print_error "Downloading $_build_info/$_pattern failed" "$LINENO"
         fi
-    else
-        _file_patterns+=("system_dlkm.img")
+    done
+    echo ""
+}
+
+function download_gki_build() {
+    print_info "Download GKI kernel build $KERNEL_BUILD" "$LINENO"
+    if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
+        rm -rf "$DOWNLOAD_PATH/gki_dir"
     fi
+    local _gki_dir="$DOWNLOAD_PATH/gki_dir"
+    mkdir -p "$_gki_dir"
+    cd "$_gki_dir" || print_error "Fail to go to $_gki_dir" "$LINENO"
+    print_info "Downloading $KERNEL_BUILD to $PWD" "$LINENO"
+
+    local _build_info="$KERNEL_BUILD"
+    local _file_patterns
+    case "$PRODUCT" in
+        oriole | raven | bluejay)
+            _file_patterns=( "boot-lz4.img" )
+            if [ -n "$VENDOR_KERNEL_BUILD" ]; then
+                _file_patterns+=( "system_dlkm_staging_archive.tar.gz" "kernel_aarch64_Module.symvers" )
+            fi
+            ;;
+        kirkwood)
+            _file_patterns=( "boot.img" "system_dlkm.flatten.erofs.img" )
+            ;;
+        eos | aurora | betty | harriet)
+            _file_patterns=( "boot.img" "system_dlkm.flatten.ext4.img" )
+            ;;
+        slsi | qcom )
+            _file_patterns=( "boot-gz.img" "system_dlkm.img"  )
+            ;;
+        mtk )
+            _file_patterns=( "boot.img" "system_dlkm.img"  )
+            ;;
+        *)
+            _file_patterns=( "boot-lz4.img" "system_dlkm.img" )
+            ;;
+    esac
     for _pattern in "${_file_patterns[@]}"; do
         print_info "Downloading $_build_info/$_pattern" "$LINENO"
         eval "$FETCH_SCRIPT $_build_info/$_pattern"
@@ -596,6 +665,7 @@ function download_gki_build() {
         fi
     done
     echo ""
+    KERNEL_BUILD="$_gki_dir"
 }
 
 function download_vendor_kernel_build() {
@@ -603,7 +673,7 @@ function download_vendor_kernel_build() {
     local _build_info="$1"
     local _file_patterns=("Image.lz4" "dtbo.img" "initramfs.img")
 
-    if [[ "$VENDOR_KERNEL_VERSION" == *6.6 ]]; then
+    if [[ "$VENDOR_KERNEL_VERSION" == *6.6 ]] || [[ "$VENDOR_KERNEL_VERSION" == *6.12 ]]; then
         _file_patterns+=("*vendor_dev_nodes_fragment.img")
     fi
 
@@ -675,34 +745,53 @@ function download_vendor_kernel_for_direct_flash() {
 
 }
 
-function flash_gki_build() {
-    local _flash_cmd
-    if [[ "$KERNEL_BUILD" == ab://* ]]; then
-        IFS='/' read -ra array <<< "$KERNEL_BUILD"
-        KERNEL_VERSION=$(echo "${array[2]}" | sed "s/aosp_kernel-common-//g")
-        _flash_cmd="$CL_FLASH_CLI --nointeractive -w -s $DEVICE_SERIAL_NUMBER "
-        _flash_cmd+=" -t ${array[3]}"
-        if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
-            _flash_cmd+=" --bid ${array[4]}"
-        else
-            _flash_cmd+=" -l ${array[2]}"
+function reboot_device_into_bootloader() {
+    if [ -n "$ADB_SERIAL_NUMBER" ] && (( $(adb devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
+        print_info "Reboot $ADB_SERIAL_NUMBER into bootloader" "$LINENO"
+        adb -s "$ADB_SERIAL_NUMBER" reboot bootloader
+        sleep 10
+        if [ -z "$FASTBOOT_SERIAL_NUMBER" ]; then
+            find_fastboot_serial_number
         fi
-    elif [ -d "$KERNEL_BUILD" ]; then
-        _flash_cmd="$LOCAL_FLASH_CLI --nointeractive -w --kernel_dist_dir=$KERNEL_BUILD -s $DEVICE_SERIAL_NUMBER"
-    else
-        print_error "Can not flash GKI kernel from $KERNEL_BUILD" "$LINENO"
+    elif [ -n "$FASTBOOT_SERIAL_NUMBER" ] && (( $(fastboot devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
+        print_info "Reboot $FASTBOOT_SERIAL_NUMBER into bootloader" "$LINENO"
+        fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot bootloader
+        sleep 2
     fi
+}
 
-    IFS='-' read -ra array <<< "$KERNEL_VERSION"
-    KERNEL_VERSION="${array[0]}-${array[1]}"
-    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION" "$LINENO"
-    if [ ! -z "$DEVICE_KERNEL_VERSION" ] && [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
-        print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING $DEVICE_KERNEL_VERSION kernel. \
-        Can't flash $KERNEL_VERSION GKI directly. Please use a platform build with the $KERNEL_VERSION kernel \
-        or use a vendor kernel build by flag -vkb, for example -vkb -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+function flash_gki_build() {
+    print_info "The boot image in $KERNEL_BUILD has kernel verson: $KERNEL_VERSION" "$LINENO"
+    if [ -n "$DEVICE_KERNEL_VERSION" ] && [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
+        print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_VERSION kernel. \
+Can't flash $KERNEL_VERSION GKI directly. Please use a platform build with the $KERNEL_VERSION kernel \
+or use a vendor kernel build by flag -vkb, such as ab://kernel-android*-gs-pixel-*.*" "$LINENO"
         print_error "Cannot flash $KERNEL_VERSION GKI to device $SERIAL_NUMBER directly." "$LINENO"
     fi
 
+    reboot_device_into_bootloader
+    print_info "Flash GKI kernel from $KERNEL_BUILD" "$LINENO"
+    print_info "Wiping the device" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" -w
+    print_info "Disabling oem verification" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" oem disable-verification
+    local _flash_cmd
+    if [ -f "$KERNEL_BUILD/boot-lz4.img" ]; then
+        _flash_cmd="fastboot -s $FASTBOOT_SERIAL_NUMBER flash boot $KERNEL_BUILD/boot-lz4.img"
+    elif [ -f "$KERNEL_BUILD/boot-gz.img" ]; then
+        _flash_cmd="fastboot -s $FASTBOOT_SERIAL_NUMBER flash boot $KERNEL_BUILD/boot-gz.img"
+    elif [ -f "$KERNEL_BUILD/boot.img" ]; then
+        _flash_cmd="fastboot -s $FASTBOOT_SERIAL_NUMBER flash boot $KERNEL_BUILD/boot.img"
+    fi
+    if [ -f "$KERNEL_BUILD/system_dlkm.img" ]; then
+        _flash_cmd+=" && fastboot -s $FASTBOOT_SERIAL_NUMBER reboot fastboot && fastboot -s $FASTBOOT_SERIAL_NUMBER flash system_dlkm $KERNEL_BUILD/system_dlkm.img"
+    elif [ -f "$KERNEL_BUILD/system_dlkm.flatten.ext4.img" ]; then
+        _flash_cmd+=" && fastboot -s $FASTBOOT_SERIAL_NUMBER reboot fastboot && fastboot -s $FASTBOOT_SERIAL_NUMBER flash system_dlkm $KERNEL_BUILD/system_dlkm.flatten.ext4.img"
+    elif [ -f "$KERNEL_BUILD/system_dlkm.flatten.erofs.img" ]; then
+        _flash_cmd+=" && fastboot -s $FASTBOOT_SERIAL_NUMBER reboot fastboot && fastboot -s $FASTBOOT_SERIAL_NUMBER flash system_dlkm $KERNEL_BUILD/system_dlkm.flatten.erofs.img"
+    fi
+    _flash_cmd+=" && fastboot -s $FASTBOOT_SERIAL_NUMBER reboot"
+
     print_info "Flashing GKI kernel with: $_flash_cmd" "$LINENO"
     eval "$_flash_cmd"
     exit_code=$?
@@ -724,8 +813,8 @@ function check_fastboot_version() {
         print_info "The existing fastboot version $_fastboot_version doesn't meet minimum requirement $MIN_FASTBOOT_VERSION. Download the latest fastboot" "$LINENO"
 
         local _download_file_name="ab://aosp-sdk-release/sdk/latest/fastboot"
-        mkdir -p "/tmp/fastboot" || $(print_error "Fail to mkdir /tmp/fastboot" "$LINENO")
-        cd /tmp/fastboot || $(print_error "Fail to go to /tmp/fastboot" "$LINENO")
+        mkdir -p "/tmp/fastboot" || print_error "Fail to mkdir /tmp/fastboot" "$LINENO"
+        cd /tmp/fastboot || print_error "Fail to go to /tmp/fastboot" "$LINENO"
 
         # Use $FETCH_SCRIPT and $_download_file_name correctly
         eval "$FETCH_SCRIPT $_download_file_name"
@@ -755,20 +844,8 @@ function flash_vendor_kernel_build() {
 
     cd $VENDOR_KERNEL_BUILD
 
-    # Switch to flashstatoin after b/390489174
     print_info "Flash vendor kernel from $VENDOR_KERNEL_BUILD" "$LINENO"
-    if [ ! -z "$ADB_SERIAL_NUMBER" ] && (( $(adb devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
-        print_info "Reboot $ADB_SERIAL_NUMBER into bootloader" "$LINENO"
-        adb -s "$ADB_SERIAL_NUMBER" reboot bootloader
-        sleep 10
-        if [ -z "$FASTBOOT_SERIAL_NUMBER" ]; then
-            find_fastboot_serial_number
-        fi
-    elif [ ! -z "$FASTBOOT_SERIAL_NUMBER" ] && (( $(fastboot devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
-        print_info "Reboot $FASTBOOT_SERIAL_NUMBER into bootloader" "$LINENO"
-        fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot bootloader
-        sleep 2
-    fi
+    reboot_device_into_bootloader
     print_info "Wiping the device" "$LINENO"
     fastboot -s "$FASTBOOT_SERIAL_NUMBER" -w
     print_info "Disabling oem verification" "$LINENO"
@@ -790,15 +867,18 @@ function flash_vendor_kernel_build() {
 }
 
 # Function to check and wait for an ADB device
+# shellcheck disable=SC2120
 function wait_for_device_in_adb() {
-    local timeout_seconds="${2:-300}"  # Timeout in seconds (default 5 minutes)
-
-    local start_time=$(date +%s)
-    local end_time=$((start_time + timeout_seconds))
+    local timeout_seconds="${1:-300}"  # Timeout in seconds (default 5 minutes)
 
+    local start_time
+    local end_time
+    start_time=$(date +%s)
+    end_time=$((start_time + timeout_seconds))
     while (( $(date +%s) < end_time )); do
         if [ -z "$ADB_SERIAL_NUMBER" ] && [ -x pontis ]; then
-            local _pontis_device=$(pontis devices | grep "$DEVICE_SERIAL_NUMBER")
+            local _pontis_device
+            _pontis_device=$(pontis devices | grep "$DEVICE_SERIAL_NUMBER")
             if [[ "$_pontis_device" == *ADB* ]]; then
                 print_info "Device $DEVICE_SERIAL_NUMBER is connected through pontis in adb" "$LINENO"
                 find_adb_serial_number
@@ -823,56 +903,84 @@ function wait_for_device_in_adb() {
 }
 
 function find_flashstation_binary() {
-    if [ -x "${ANDROID_HOST_OUT}/bin/local_flashstation" ]; then
-        $LOCAL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/local_flashstation"
-    elif [ ! -x "$LOCAL_FLASH_CLI" ]; then
-        if ! which local_flashstation &> /dev/null; then
-            print_error "Can not find local_flashstation binary. \
-            Please see go/web-flashstation-command-line to download it" "$LINENO"
+    # Prefer local build in ANDROID_HOST_OUT if available
+    if [[ -n "${ANDROID_HOST_OUT}" && -x "${ANDROID_HOST_OUT}/bin/local_flashstation" ]]; then
+        LOCAL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/local_flashstation"
+    elif ! check_command "local_flashstation"; then
+        if check_command "$COMMON_LIB_LOCAL_FLASH_CLI"; then
+             LOCAL_FLASH_CLI="$COMMON_LIB_LOCAL_FLASH_CLI"
         else
-            LOCAL_FLASH_CLI="local_flashstation"
+            print_warn "Cannot find 'local_flashstation' in PATH. Will use fastboot to flash device.. \
+            Please see go/web-flashstation-command-line to download flashstation cli" "$LINENO"
+            LOCAL_FLASH_CLI=""
         fi
+    else
+        LOCAL_FLASH_CLI="local_flashstation"
     fi
-    if [ -x "${ANDROID_HOST_OUT}/bin/cl_flashstation" ]; then
-        $CL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/cl_flashstation"
-    elif [ ! -x "$CL_FLASH_CLI" ]; then
-        if ! which cl_flashstation &> /dev/null; then
-            print_error "Can not find cl_flashstation binary. \
-            Please see go/web-flashstation-command-line to download it" "$LINENO"
+
+    if [[ -n "${ANDROID_HOST_OUT}" && -x "${ANDROID_HOST_OUT}/bin/cl_flashstation" ]]; then
+        CL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/cl_flashstation"
+    elif ! check_command "cl_flashstation"; then
+        if check_command "$COMMON_LIB_CL_FLASH_CLI"; then
+             CL_FLASH_CLI="$COMMON_LIB_CL_FLASH_CLI"
         else
-            CL_FLASH_CLI="cl_flashstation"
+            print_warn "Cannot find 'cl_flashstation' in PATH. Will use fastboot to flash device.. \
+            Please see go/web-flashstation-command-line to download flashstation cli" "$LINENO"
+            CL_FLASH_CLI=""
         fi
+    else
+        CL_FLASH_CLI="cl_flashstation"
     fi
+
+    print_info "Using LOCAL_FLASH_CLI: ${LOCAL_FLASH_CLI:-Not Found}" "$LINENO"
+    print_info "Using CL_FLASH_CLI: ${CL_FLASH_CLI:-Not Found}" "$LINENO"
 }
 
 function flash_platform_build() {
+    if [ "$SKIP_UPDATE_BOOTLOADER" = true ] && [[ "$PLATFORM_BUILD" == ab://* ]] || [ -z "$CL_FLASH_CLI" ]; then
+        if [ -d "$DOWNLOAD_PATH/device_dir" ]; then
+            rm -rf "$DOWNLOAD_PATH/device_dir"
+        fi
+        PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
+        mkdir -p "$PLATFORM_DIR"
+        cd "$PLATFORM_DIR" || print_error "Fail to go to $PLATFORM_DIR" "$LINENO"
+        download_platform_build
+        PLATFORM_BUILD="$PLATFORM_DIR"
+    fi
+
     local _flash_cmd
     if [[ "$PLATFORM_BUILD" == ab://* ]]; then
         _flash_cmd="$CL_FLASH_CLI --nointeractive --force_flash_partitions --disable_verity -w -s $DEVICE_SERIAL_NUMBER "
-        IFS='/' read -ra array <<< "$PLATFORM_BUILD"
-        if [ ! -z "${array[3]}" ]; then
-            local _build_type="${array[3]#*-}"
-            if [[ "${array[2]}" == git_main* ]] && [[ "$_build_type" == user* ]]; then
+
+        local _branch
+        local _build_target
+        local _build_id
+        if ! parse_ab_url "$PLATFORM_BUILD" _branch _build_target _build_id &> /dev/null; then
+            print_error "Invalid Android Build url string. PLATFORM_BUILD=${PLATFORM_BUILD}"  "$LINENO"
+        fi
+
+        if [ -n "${_build_target}" ]; then
+            local _build_type="${_build_target#*-}"
+            if [[ "${_branch}" == git_main* ]] && [[ "$_build_type" == user* ]]; then
                 print_info "Build variant is not provided, using trunk_staging build" "$LINENO"
                 _build_type="trunk_staging-$_build_type"
             fi
             _flash_cmd+=" -t $_build_type"
-            if [[ "$_build_type" == *user ]] && [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
+            if [[ "$_build_type" == *user ]] && [ -n "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
                 print_info "Need to flash GKI after flashing platform build, hence enabling --force_debuggable in user build flashing" "$LINENO"
                 _flash_cmd+=" --force_debuggable"
             fi
         fi
-        if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
-            echo "Flash $SERIAL_NUMBER with platform build from branch $PLATFORM_BUILD..."
-            _flash_cmd+=" --bid ${array[4]}"
+        print_info "Flash $SERIAL_NUMBER by flash station with platform build $PLATFORM_BUILD..." "$LINENO"
+        if [ -n "${_build_id}" ] && [[ "${_build_id}" != latest* ]]; then
+            _flash_cmd+=" --bid ${_build_id}"
         else
-            echo "Flash $SERIAL_NUMBER with platform build $PLATFORM_BUILD..."
-            _flash_cmd+=" -l ${array[2]}"
+            _flash_cmd+=" -l ${_branch}"
         fi
-    elif [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT" ]] && \
+    elif [ -n "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT" ]] && \
     [ -x "$PLATFORM_REPO_ROOT/vendor/google/tools/flashall" ]; then
-        cd "$PLATFORM_REPO_ROOT"
-        print_info "Flashing device with vendor/google/tools/flashall" "$LINENO"
+        cd "$PLATFORM_REPO_ROOT" || print_error "Fail to go to $PLATFORM_REPO_ROOT" "$LINENO"
+        print_info "Flashing device by vendor/google/tools/flashall with platform build from $$PLATFORM_BUILD" "$LINENO"
         if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
             if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
                 set_platform_repo "aosp_$PRODUCT"
@@ -882,42 +990,124 @@ function flash_platform_build() {
         fi
         _flash_cmd="vendor/google/tools/flashall  --nointeractive -w -s $DEVICE_SERIAL_NUMBER"
     else
-        if [ -z "${TARGET_PRODUCT}" ]; then
-            export TARGET_PRODUCT="$PRODUCT"
-        fi
-        if [ -z "${TARGET_BUILD_VARIANT}" ]; then
-            export TARGET_BUILD_VARIANT="$DEVICE_VARIANT"
-        fi
-        if [ -z "${ANDROID_PRODUCT_OUT}" ] || [[ "${ANDROID_PRODUCT_OUT}" != "$PLATFORM_BUILD" ]] ; then
-            export ANDROID_PRODUCT_OUT="$PLATFORM_BUILD"
-        fi
-        if [ -z "${ANDROID_HOST_OUT}" ]; then
-            export ANDROID_HOST_OUT="$PLATFORM_BUILD"
+        print_info "Flashing device by local flash station with platform build from $$PLATFORM_BUILD" "$LINENO"
+        prepare_to_flash_platform_build_from_local_directory
+
+        _flash_cmd="$LOCAL_FLASH_CLI --nointeractive --force_flash_partitions --disable_verity --disable_verification  -w -s $DEVICE_SERIAL_NUMBER"
+    fi
+
+    print_info "Flashing device with: $_flash_cmd" "$LINENO"
+    eval "$_flash_cmd"
+    exit_code=$?
+    if (( exit_code == 0 )); then
+        echo "Flash platform succeeded"
+        wait_for_device_in_adb
+        return 0
+    else
+        print_error "Flash platform build failed with exit code $exit_code" "$LINENO"
+        return 1
+    fi
+}
+
+function flash_system_build() {
+    if [[ "$SYSTEM_BUILD" == ab://* ]]; then
+        if [ -d "$DOWNLOAD_PATH/system_dir" ]; then
+            rm -rf "$DOWNLOAD_PATH/system_dir"
         fi
-        if [ ! -f "$PLATFORM_BUILD/system.img" ]; then
-            local device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img*.zip)
-            unzip -j "$device_image" -d "$PLATFORM_BUILD"
+        SYSTEM_DIR="$DOWNLOAD_PATH/system_dir"
+        mkdir -p "$SYSTEM_DIR"
+        cd "$SYSTEM_DIR" || print_error "Fail to go to $SYSTEM_DIR" "$LINENO"
+        download_system_build
+        SYSTEM_BUILD="$SYSTEM_DIR"
+    fi
+    if [ ! -f "$SYSTEM_BUILD/system.img" ]; then
+        local _device_image=$(find "$SYSTEM_BUILD" -maxdepth 1 -type f -name *-img*.zip)
+        if [ -f "$_device_image" ]; then
+            unzip -j "$_device_image" -d "$SYSTEM_BUILD"
+            if [ ! -f "$SYSTEM_BUILD/system.img" ]; then
+                print_error "There is no system.img in $_device_image" "$LINENO"
+            fi
+        else
+            print_error "$SYSTEM_BUILD doesn't have valid system image or device image to be flashed with" "$LINENO"
         fi
+    fi
 
-        awk '! /baseband/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
-        awk '! /bootloader/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
+    local _flash_cmd
 
-        _flash_cmd="$LOCAL_FLASH_CLI --nointeractive --force_flash_partitions --disable_verity --disable_verification  -w -s $DEVICE_SERIAL_NUMBER"
+    print_info "Flash GSI from $SYSTEM_BUILD" "$LINENO"
+    reboot_device_into_bootloader
+    local _output=$(fastboot -s "$FASTBOOT_SERIAL_NUMBER" getvar current-slot 2>&1)
+    local _current_slot=$(echo "$_output" | grep "^current-slot:" | awk '{print $2}')
+    print_info "Wiping the device" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" -w
+    print_info "Reboot device into fastbootd" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot-fastboot
+    print_info "Delete logical partition product_$_current_slot" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" delete-logical-partition product_"$_current_slot"
+    print_info "Erase logical partition system_$_current_slot" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" erase system_"$_current_slot"
+
+    local _flash_cmd
+    if [ -f "$SYSTEM_BUILD/system.img" ]; then
+        _flash_cmd="fastboot -s $FASTBOOT_SERIAL_NUMBER flash system $SYSTEM_BUILD/system.img"
     fi
-    print_info "Flashing device with: $_flash_cmd" "$LINENO"
+    if [ -f "$KERNEL_BUILD/pvmfw.img" ]; then
+        _flash_cmd=" && fastboot -s $FASTBOOT_SERIAL_NUMBER flash pvmfw $SYSTEM_BUILD/pvmfw.img"
+    fi
+    _flash_cmd+=" && fastboot -s $FASTBOOT_SERIAL_NUMBER reboot"
+
+    print_info "Flashing GSI with: $_flash_cmd" "$LINENO"
     eval "$_flash_cmd"
     exit_code=$?
     if [ $exit_code -eq 0 ]; then
-        echo "Flash platform succeeded"
+        echo "Flash GSI succeeded"
         wait_for_device_in_adb
         return
     else
-        echo "Flash platform build failed with exit code $exit_code"
+        echo "Flash GSI failed with exit code $exit_code"
         exit 1
     fi
 
 }
 
+function prepare_to_flash_platform_build_from_local_directory () {
+    print_info "Setting up local environment to flash platform build from $$PLATFORM_BUILD" "$LINENO"
+    if [ ! -f "$PLATFORM_BUILD/android-info.txt" ] || [ ! -f "$PLATFORM_BUILD/boot.img" ]; then
+        local device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img*.zip)
+        if [ -f "$device_image" ]; then
+            unzip -j "$device_image" -d "$PLATFORM_BUILD"
+            if [ ! -f "$PLATFORM_BUILD/android-info.txt" ] || [ ! -f "$PLATFORM_BUILD/boot.img" ]; then
+                print_error "There is no android-info.txt in $device_image" "$LINENO"
+            fi
+        else
+            print_error "$PLATFORM_BUILD doesn't have valid device image to be flashed with" "$LINENO"
+        fi
+    fi
+    if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "$PRODUCT" ]]; then
+        print_info "Set env var TARGET_PRODUCT to $PRODUCT"  "$LINENO"
+        export TARGET_PRODUCT="$PRODUCT"
+    fi
+    if [ -z "${TARGET_BUILD_VARIANT}" ] || [[ "${TARGET_BUILD_VARIANT}" != "$DEVICE_VARIANT" ]]; then
+        print_info "Set env var TARGET_BUILD_VARIANT to $DEVICE_VARIANT"  "$LINENO"
+        export TARGET_BUILD_VARIANT="$DEVICE_VARIANT"
+    fi
+    if [ -z "${ANDROID_PRODUCT_OUT}" ] || [[ "${ANDROID_PRODUCT_OUT}" != "$PLATFORM_BUILD" ]]; then
+        print_info "Set env var ANDROID_PRODUCT_OUT to $PLATFORM_BUILD"  "$LINENO"
+        export ANDROID_PRODUCT_OUT="$PLATFORM_BUILD"
+    fi
+    if [ -z "${ANDROID_HOST_OUT}" ] || [[ "${ANDROID_HOST_OUT}" != "$PLATFORM_BUILD" ]]; then
+        print_info "Set env var ANDROID_HOST_OUT to $PLATFORM_BUILD"  "$LINENO"
+        export ANDROID_HOST_OUT="$PLATFORM_BUILD"
+    fi
+
+    if [ "$SKIP_UPDATE_BOOTLOADER" = true ]; then
+        awk '! /bootloader/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
+    fi
+    # skip update radio.img
+    #awk '! /baseband/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
+
+}
+
 function get_mix_ramdisk_script() {
     download_file_name="ab://git_main/aosp_cf_x86_64_only_phone-trunk_staging-userdebug/latest/otatools.zip"
     eval "$FETCH_SCRIPT $download_file_name"
@@ -932,12 +1122,12 @@ function get_mix_ramdisk_script() {
 }
 
 function mixing_build() {
-    if [ ! -z ${PLATFORM_REPO_ROOT_PATH} ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/$MIX_SCRIPT_NAME"]; then
+    if [ -n "${PLATFORM_REPO_ROOT_PATH}" ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/$MIX_SCRIPT_NAME" ]; then
         mix_kernel_cmd="$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/$MIX_SCRIPT_NAME"
     elif [ -f "$DOWNLOAD_PATH/$MIX_SCRIPT_NAME" ]; then
         mix_kernel_cmd="$DOWNLOAD_PATH/$MIX_SCRIPT_NAME"
     else
-        cd "$DOWNLOAD_PATH" || $(print_error "Fail to go to $DOWNLOAD_PATH" "$LINENO")
+        cd "$DOWNLOAD_PATH" || print_error "Fail to go to $DOWNLOAD_PATH" "$LINENO"
         get_mix_ramdisk_script
         mix_kernel_cmd="$PWD/$MIX_SCRIPT_NAME"
     fi
@@ -952,20 +1142,20 @@ function mixing_build() {
         fi
         PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
         mkdir -p "$PLATFORM_DIR"
-        cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR" "$LINENO")
+        cd "$PLATFORM_DIR" || print_error "Fail to go to $PLATFORM_DIR" "$LINENO"
         download_platform_build
         PLATFORM_BUILD="$PLATFORM_DIR"
-    elif [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT"* ]]; then
+    elif [ -n "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT"* ]]; then
         print_info "Copy platform build $PLATFORM_BUILD to $DOWNLOAD_PATH/device_dir" "$LINENO"
         PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
         mkdir -p "$PLATFORM_DIR"
-        cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR" "$LINENO")
+        cd "$PLATFORM_DIR" || print_error "Fail to go to $PLATFORM_DIR" "$LINENO"
         local device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img.zip)
-        if [ ! -z "device_image" ]; then
+        if [ -n "$device_image" ]; then
             cp "$device_image $PLATFORM_DIR/$PRODUCT-img-0.zip" "$PLATFORM_DIR"
         else
             device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img-*.zip)
-            if [ ! -z "device_image" ]; then
+            if [ -n "$device_image" ]; then
                 cp "$device_image $PLATFORM_DIR/$PRODUCT-img-0.zip" "$PLATFORM_DIR"
             else
                 print_error "Can't find $RPODUCT-img-*.zip in $PLATFORM_BUILD"
@@ -984,18 +1174,6 @@ function mixing_build() {
         PLATFORM_BUILD="$PLATFORM_DIR"
     fi
 
-    if [[ "$KERNEL_BUILD" == ab://* ]]; then
-        print_info "Download kernel build $KERNEL_BUILD" "$LINENO"
-        if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
-            rm -rf "$DOWNLOAD_PATH/gki_dir"
-        fi
-        GKI_DIR="$DOWNLOAD_PATH/gki_dir"
-        mkdir -p "$GKI_DIR"
-        cd "$GKI_DIR" || $(print_error "Fail to go to $GKI_DIR" "$LINENO")
-        download_gki_build $KERNEL_BUILD
-        KERNEL_BUILD="$GKI_DIR"
-    fi
-
     local new_device_dir="$DOWNLOAD_PATH/new_device_dir"
     if [ -d "$new_device_dir" ]; then
         rm -rf "$new_device_dir"
@@ -1022,59 +1200,23 @@ get_kernel_version_from_boot_image() {
     local version_output
 
     # Check for mainline kernel
-    version_output=$(strings "$boot_image_path" | grep mainline)
-    if [ ! -z "$version_output" ]; then
+    version_output=$(strings "$boot_image_path" | grep android.*-g.*-ab.* | tail -n 1)
+    if [[ "$version_output" == *-mainline* ]]; then
         KERNEL_VERSION="android-mainline"
-        return  # Exit the function early if a match is found
-    fi
-
-    # Check for Android 15 6.6 kernel
-    version_output=$(strings "$boot_image_path" | grep "android15" | grep "6.6")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android15-6.6"
-        return
-    fi
-
-    # Check for Android 14 6.1 kernel
-    version_output=$(strings "$boot_image_path" | grep "android14" | grep "6.1")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android14-6.1"
-        return
-    fi
-
-    # Check for Android 14 5.15 kernel
-    version_output=$(strings "$boot_image_path" | grep "android14" | grep "5.15")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android14-5.15"
-        return
-    fi
-
-    # Check for Android 13 5.15 kernel
-    version_output=$(strings "$boot_image_path" | grep "android13" | grep "5.15")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android13-5.15"
-        return
-    fi
-
-    # Check for Android 13 5.10 kernel
-    version_output=$(strings "$boot_image_path" | grep "android13" | grep "5.10")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android13-5.10"
-        return
-    fi
-
-    # Check for Android 12 5.10 kernel
-    version_output=$(strings "$boot_image_path" | grep "android12" | grep "5.10")
-    if [ ! -z "$version_output" ]; then
-        KERNEL_VERSION="android12-5.10"
-        return
+    elif [[ "$version_output" == *-android* ]]; then
+        # Extract the substring between the first hyphen and the second hyphen
+        KERNEL_VERSION=$(echo "$version_output" | awk -F '-' '{print $2"-"$1}' | cut -d '.' -f -2)
+    else
+       print_warn "Can not parse $version_output into kernel version" "$LINENO"
+       KERNEL_VERSION=
     fi
+    print_info "Boot image $boot_image_path has kernel version: $KERNEL_VERSION" "$LINENO"
 }
 
 function extract_device_kernel_version() {
     local kernel_string="$1"
     # Check if the string contains '-android'
-    if [[ "$kernel_string" == *"-mainline"* ]]; then
+    if [[ "$kernel_string" == *-mainline* ]]; then
         DEVICE_KERNEL_VERSION="android-mainline"
     elif [[ "$kernel_string" == *"-android"* ]]; then
         # Extract the substring between the first hyphen and the second hyphen
@@ -1082,7 +1224,7 @@ function extract_device_kernel_version() {
     else
        print_warn "Can not parse $kernel_string into kernel version" "$LINENO"
     fi
-    print_info "Device kernel version is $DEVICE_KERNEL_VERSION" "$LINENO"
+    print_info "Device $DEVICE_SERIAL_NUMBER kernel version: $DEVICE_KERNEL_VERSION" "$LINENO"
 }
 
 function find_adb_serial_number() {
@@ -1130,30 +1272,35 @@ function get_device_info_from_adb {
             print_error "Can not get device serial adb -s $ADB_SERIAL_NUMBER" "$LINENO"
         fi
     fi
-    BOARD=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.product.board)
+    PRODUCT=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.product.board)
     ABI=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
 
     # Only get PRODUCT if it's not already set
     if [ -z "$PRODUCT" ]; then
+        print_warn "$ADB_SERIAL_NUMBER does not have a valid product.board value" "$LINENO"
         PRODUCT=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.build.product)
         # Check if PRODUCT is valid after attempting to retrieve it
         if [ -z "$PRODUCT" ]; then
-            print_error "$ADB_SERIAL_NUMBER does not have a valid product value" "$LINENO"
+            print_error "$ADB_SERIAL_NUMBER does not have a valid build product value" "$LINENO"
+        fi
+        if [[ "$PRODUCT" == generic_arm64 ]]; then
+            print_error "$ADB_SERIAL_NUMBER has generic system image installed. Can not use the build.product to get hardward product value." "$LINENO"
         fi
     fi
 
     BUILD_TYPE=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.build.type)
     DEVICE_KERNEL_STRING=$(adb -s "$ADB_SERIAL_NUMBER" shell uname -r)
-    extract_device_kernel_version "$DEVICE_KERNEL_STRING"
     SYSTEM_DLKM_INFO=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop dev.mnt.blk.system_dlkm)
     if [[ "$SERIAL_NUMBER" != "$DEVICE_SERIAL_NUMBER" ]]; then
         print_info "Device $SERIAL_NUMBER has DEVICE_SERIAL_NUMBER=$DEVICE_SERIAL_NUMBER, ADB_SERIAL_NUMBER=$ADB_SERIAL_NUMBER" "$LINENO"
     fi
-    print_info "Device $SERIAL_NUMBER info: BOARD=$BOARD, ABI=$ABI, PRODUCT=$PRODUCT, BUILD_TYPE=$BUILD_TYPE \
-    SYSTEM_DLKM_INFO=$SYSTEM_DLKM_INFO, DEVICE_KERNEL_STRING=$DEVICE_KERNEL_STRING" "$LINENO"
+    local _build_fingerprint=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.build.fingerprint)
+    print_info "Device $SERIAL_NUMBER info: BUILD_FINGERPRINT=$_build_fingerprint, ABI=$ABI, PRODUCT=$PRODUCT, BUILD_TYPE=$BUILD_TYPE \
+SYSTEM_DLKM_INFO=$SYSTEM_DLKM_INFO, DEVICE_KERNEL_STRING=$DEVICE_KERNEL_STRING" "$LINENO"
+    extract_device_kernel_version "$DEVICE_KERNEL_STRING"
 }
 
-function get_device_info_from_fastboot {
+function get_device_info_from_fastboot() {
     # try get product by fastboot command
     if [ -z "$DEVICE_SERIAL_NUMBER" ]; then
         local _output=$(fastboot -s "$FASTBOOT_SERIAL_NUMBER" getvar serialno 2>&1)
@@ -1180,7 +1327,8 @@ function get_device_info_from_fastboot {
 }
 
 function get_device_info() {
-    local _adb_count=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
+    local _adb_count
+    _adb_count=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
     if (( _adb_count > 0 )); then
         print_info "$SERIAL_NUMBER is connected through adb" "$LINENO"
         ADB_SERIAL_NUMBER="$SERIAL_NUMBER"
@@ -1191,7 +1339,8 @@ function get_device_info() {
         return 0
     fi
 
-    local _fastboot_count=$(fastboot devices | grep "$SERIAL_NUMBER" | wc -l)
+    local _fastboot_count
+    _fastboot_count=$(fastboot devices | grep "$SERIAL_NUMBER" | wc -l)
     if (( _fastboot_count > 0 )); then
         print_info "$SERIAL_NUMBER is connected through fastboot" "$LINENO"
         FASTBOOT_SERIAL_NUMBER="$SERIAL_NUMBER"
@@ -1202,8 +1351,9 @@ function get_device_info() {
         return 0
     fi
 
-    if [ -x pontis ]; then
-        local _pontis_device=$(pontis devices | grep "$SERIAL_NUMBER")
+    if [[ -x "$(command -v pontis)" ]]; then
+        local _pontis_device
+        _pontis_device=$(pontis devices | grep "$SERIAL_NUMBER")
         if [[ "$_pontis_device" == *Fastboot* ]]; then
             DEVICE_SERIAL_NUMBER="$SERIAL_NUMBER"
             print_info "Device $SERIAL_NUMBER is connected through pontis in fastboot" "$LINENO"
@@ -1222,9 +1372,23 @@ function get_device_info() {
     print_error "$SERIAL_NUMBER is not connected with adb or fastboot" "$LINENO"
 }
 
-adb_checker
+SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
+SCRIPT_DIR="$( cd "$( dirname "${SCRIPT_PATH}" )" &> /dev/null && pwd -P)"
+LIB_PATH="${SCRIPT_DIR}/common_lib.sh"
+if [[ -f "$LIB_PATH" ]]; then
+    if ! . "$LIB_PATH"; then
+        echo "Fatal Error：Cannot load library '$LIB_PATH'" >&2
+        exit 1
+    fi
+else
+    echo "Fatal Error：Cannot find library '$LIB_PATH'" >&2
+    exit 1
+fi
 
-LOCAL_REPO=
+print_info "Checking required commands..." "$LINENO"
+if ! check_commands_available "${REQUIRED_COMMANDS[@]}"; then
+    print_error "One or more required commands are missing. Please install them and retry." "$LINENO"
+fi
 
 OLD_PWD=$PWD
 MY_NAME=$0
@@ -1233,54 +1397,43 @@ parse_arg "$@"
 
 if [ -z "$SERIAL_NUMBER" ]; then
     print_error "Device serial is not provided with flag -s <serial_number>." "$LINENO"
-    exit 1
+fi
+
+if [ ! -d "$DOWNLOAD_PATH" ]; then
+    mkdir -p "$DOWNLOAD_PATH" || print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO"
 fi
 
 get_device_info
 
-FULL_COMMAND_PATH=$(dirname "$PWD/$0")
-REPO_LIST_OUT=$(repo list 2>&1)
-if [[ "$REPO_LIST_OUT" == "error"* ]]; then
-    print_error "Current path $PWD is not in an Android repo. Change path to repo root." "$LINENO"
-    go_to_repo_root "$FULL_COMMAND_PATH"
-    print_info "Changed path to $PWD" "$LINENO"
-else
+if is_in_repo_workspace; then
     go_to_repo_root "$PWD"
+else
+    log_warn "Current path $PWD is not in an Android repo. Change path to repo root."
+    go_to_repo_root "$SCRIPT_DIR"
 fi
 
-REPO_ROOT_PATH="$PWD"
-FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"
+readonly REPO_ROOT_PATH="$PWD"
+readonly FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT_PATH_IN_REPO"
 
 find_repo
 
-if [[ "$PLATFORM_BUILD" == "None" ]]; then
-    PLATFORM_BUILD=
-fi
-
-if [[ "$KERNEL_BUILD" == "None" ]]; then
-    KERNEL_BUILD=
-fi
-
-if [[ "$VENDOR_KERNEL_BUILD" == "None" ]]; then
-    VENDOR_KERNEL_BUILD=
-fi
-
-if [ ! -d "$DOWNLOAD_PATH" ]; then
-    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
-fi
+[[ "$PLATFORM_BUILD" == "None" ]] && PLATFORM_BUILD=""
+[[ "$KERNEL_BUILD" == "None" ]] && KERNEL_BUILD=""
+[[ "$VENDOR_KERNEL_BUILD" == "None" ]] && VENDOR_KERNEL_BUILD=""
 
+# --- Platform Build Processing ---
 if [[ "$PLATFORM_BUILD" == ab://* ]]; then
     format_ab_platform_build_string
-elif [ ! -z "$PLATFORM_BUILD" ] && [ -d "$PLATFORM_BUILD" ]; then
+elif [ -n "$PLATFORM_BUILD" ] && [ -d "$PLATFORM_BUILD" ]; then
     # Check if PLATFORM_BUILD is an Android platform repo
-    cd "$PLATFORM_BUILD"  || $(print_error "Fail to go to $PLATFORM_BUILD" "$LINENO")
+    cd "$PLATFORM_BUILD"  || print_error "Fail to go to $PLATFORM_BUILD" "$LINENO"
     PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
         if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
             find_repo
         fi
-        if [ "$SKIP_BUILD" = false ] && [[ "$PLATFORM_BUILD" != "ab://"* ]] && [[ ! -z "$PLATFORM_BUILD" ]]; then
+        if [ "$SKIP_BUILD" = false ] && [[ "$PLATFORM_BUILD" != "ab://"* ]] && [[ -n "$PLATFORM_BUILD" ]]; then
             if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
                 if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
                     set_platform_repo "aosp_$PRODUCT"
@@ -1306,37 +1459,17 @@ elif [ ! -z "$PLATFORM_BUILD" ] && [ -d "$PLATFORM_BUILD" ]; then
     fi
 fi
 
-if [[ "$SYSTEM_BUILD" == ab://* ]]; then
-    print_warn "System build is not supoort yet" "$LINENO"
-elif [ ! -z "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
-    print_warn "System build is not supoort yet" "$LINENO"
-    # Get GSI build
-    cd "$SYSTEM_BUILD"  || $(print_error "Fail to go to $SYSTEM_BUILD" "$LINENO")
-    SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
-    if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
-        go_to_repo_root "$PWD"
-        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
-            find_repo
-        fi
-        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "_arm64" ]]; then
-            set_platform_repo "aosp_arm64"
-            if [ "$SKIP_BUILD" = false ] ; then
-                build_platform
-            fi
-            SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}/system.img"
-        fi
-    fi
-fi
-
 find_flashstation_binary
 
 if [[ "$KERNEL_BUILD" == ab://* ]]; then
     format_ab_kernel_build_string
-elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
+    download_gki_build
+elif [ -n "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
     # Check if kernel repo is provided
-    cd "$KERNEL_BUILD" || $(print_error "Fail to go to $KERNEL_BUILD" "$LINENO")
+    cd "$KERNEL_BUILD" || print_error "Fail to go to $KERNEL_BUILD" "$LINENO"
     KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
+        print_info "$KERNEL_BUILD is in a kernel tree repo"
         go_to_repo_root "$PWD"
         if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
             find_repo
@@ -1350,8 +1483,12 @@ elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
             fi
         fi
         KERNEL_BUILD="$PWD/out/kernel_aarch64/dist"
-    elif [ -f "$KERNEL_BUILD/boot*.img" ]; then
-        get_kernel_version_from_boot_image "$KERNEL_BUILD/boot*.img"
+    elif [ -f "$KERNEL_BUILD/boot.img" ]; then
+        get_kernel_version_from_boot_image "$KERNEL_BUILD/boot.img"
+    elif [ -f "$KERNEL_BUILD/boot-lz4.img" ]; then
+        get_kernel_version_from_boot_image "$KERNEL_BUILD/boot-lz4.img"
+    elif [ -f "$KERNEL_BUILD/boot-gz.img" ]; then
+        get_kernel_version_from_boot_image "$KERNEL_BUILD/boot-gz.img"
     fi
 fi
 
@@ -1363,16 +1500,16 @@ if [[ "$VENDOR_KERNEL_BUILD" == ab://* ]]; then
     fi
     VENDOR_KERNEL_DIR="$DOWNLOAD_PATH/vendor_kernel_dir"
     mkdir -p "$VENDOR_KERNEL_DIR"
-    cd "$VENDOR_KERNEL_DIR" || $(print_error "Fail to go to $VENDOR_KERNEL_DIR" "$LINENO")
+    cd "$VENDOR_KERNEL_DIR" || print_error "Fail to go to $VENDOR_KERNEL_DIR" "$LINENO"
     if [ -z "$PLATFORM_BUILD" ]; then
         download_vendor_kernel_for_direct_flash $VENDOR_KERNEL_BUILD
     else
         download_vendor_kernel_build $VENDOR_KERNEL_BUILD
     fi
     VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_DIR"
-elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
+elif [ -n "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
     # Check if vendor kernel repo is provided
-    cd "$VENDOR_KERNEL_BUILD"  || $(print_error "Fail to go to $VENDOR_KERNEL_BUILD" "$LINENO")
+    cd "$VENDOR_KERNEL_BUILD"  || print_error "Fail to go to $VENDOR_KERNEL_BUILD" "$LINENO"
     VENDOR_KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$VENDOR_KERNEL_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -1417,32 +1554,58 @@ elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
 fi
 
 if [ -z "$PLATFORM_BUILD" ]; then  # No platform build provided
-    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
+    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ] && [ -z "$SYSTEM_BUILD" ]; then
         print_info "KERNEL_BUILD=$KERNEL_BUILD VENDOR_KERNEL_BUILD=$VENDOR_KERNEL_BUILD" "$LINENO"
         print_error "Nothing to flash" "$LINENO"
     fi
-    if [ ! -z "$VENDOR_KERNEL_BUILD" ]; then
+    if [ -n "$VENDOR_KERNEL_BUILD" ]; then
         print_info "Flash kernel from $VENDOR_KERNEL_BUILD" "$LINENO"
         flash_vendor_kernel_build
     fi
-    if [ ! -z "$KERNEL_BUILD" ]; then
+    if [ -n "$KERNEL_BUILD" ]; then
         flash_gki_build
     fi
 else  # Platform build provided
     if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
-        print_info "Flash platform build only"
+        print_info "Flash platform build from $PLATFORM_BUILD"  "$LINENO"
         flash_platform_build
-    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Vendor kernel build and platform build
+    elif [ -z "$KERNEL_BUILD" ] && [ -n "$VENDOR_KERNEL_BUILD" ]; then  # Vendor kernel build and platform build
         print_info "Mix vendor kernel and platform build"
         mixing_build
         flash_platform_build
-    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then # GKI build and platform build
+    elif [ -n "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then # GKI build and platform build
         flash_platform_build
         get_device_info
         flash_gki_build
-    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # All three builds provided
+    elif [ -n "$KERNEL_BUILD" ] && [ -n "$VENDOR_KERNEL_BUILD" ]; then  # All three builds provided
         print_info "Mix GKI kernel, vendor kernel and platform build" "$LINENO"
         mixing_build
         flash_platform_build
     fi
 fi
+
+if [[ "$SYSTEM_BUILD" == ab://* ]]; then
+    format_ab_system_build_string
+elif [ -n "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
+    cd "$SYSTEM_BUILD"  || print_error "Fail to go to $SYSTEM_BUILD" "$LINENO"
+    SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
+            find_repo
+        fi
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "gsi_arm64" ]]; then
+            set_platform_repo "gsi_arm64"
+            if [ "$SKIP_BUILD" = false ] ; then
+                build_platform
+            fi
+            SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}"
+        fi
+    fi
+fi
+
+if [ -n "$SYSTEM_BUILD" ]; then
+    flash_system_build
+fi
+
+get_device_info
diff --git a/tools/launch_cvd.sh b/tools/launch_cvd.sh
index fee7e36..4ad5c83 100755
--- a/tools/launch_cvd.sh
+++ b/tools/launch_cvd.sh
@@ -3,30 +3,50 @@
 
 # A handy tool to launch CVD with local build or remote build.
 
-# Constants
-ACLOUD_PREBUILT="prebuilts/asuite/acloud/linux-x86/acloud"
-OPT_SKIP_PRERUNCHECK='--skip-pre-run-check'
-PRODUCT='aosp_cf_x86_64_phone'
-# Color constants
-#BOLD="$(tput bold)" # Unused
-END="$(tput sgr0)"
-GREEN="$(tput setaf 2)"
-RED="$(tput setaf 198)"
-YELLOW="$(tput setaf 3)"
-# BLUE="$(tput setaf 34)" # Unused
-
+# --- Configuration Constants ---
+readonly ACLOUD_PREBUILT="prebuilts/asuite/acloud/linux-x86/acloud"
+readonly OPT_SKIP_PRERUNCHECK='--skip-pre-run-check'
+PRODUCT='aosp_cf_x86_64_only_phone'
+readonly DEFAULT_GSI_PRODUCT='gsi_x86_64' # Assuming this for GSI builds
 SKIP_BUILD=false
+USE_RBE=false
 GCOV=false
 DEBUG=false
 KASAN=false
 EXTRA_OPTIONS=()
+CF_KERNEL_REPO_ROOT=""
+CF_KERNEL_VERSION=""
+PLATFORM_REPO_ROOT=""
+PLATFORM_VERSION=""
+
+readonly REQUIRED_COMMANDS=("adb" "grep" "basename" "dirname" "read" "realpath" "nproc" "bc")
 
+# --- Library Import ---
+SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
+SCRIPT_DIR="$( cd "$( dirname "${SCRIPT_PATH}" )" &> /dev/null && pwd -P)"
+LIB_PATH="${SCRIPT_DIR}/common_lib.sh"
+
+if [[ ! -f "$LIB_PATH" ]]; then
+    # Cannot use log_error yet as library isn't sourced
+    echo "FATAL ERROR: Cannot find required library '$LIB_PATH'" >&2
+    exit 1
+fi
+
+# Source the library. Check return code in case sourcing fails (e.g., missing dependency in lib)
+if ! . "$LIB_PATH"; then
+    echo "FATAL ERROR: Failed to source library '$LIB_PATH'. Check common_lib.sh dependencies." >&2
+    exit 1
+fi
+
+# --- Functions ---
 function print_help() {
     echo "Usage: $0 [OPTIONS]"
     echo ""
     echo "This script will build images and launch a Cuttlefish device."
     echo ""
     echo "Available options:"
+    echo "  --use-rbe             Enable Remote Build Execution to speed up large, non-google3 builds."
+    echo "                        Requires RBE service access; See go/build-fast for details."
     echo "  --skip-build          Skip the image build step. Will build by default if in repo."
     echo "  --gcov                Launch CVD with gcov enabled kernel"
     echo "  --debug               Launch CVD with debug enabled kernel"
@@ -58,18 +78,31 @@ function print_help() {
     echo "$0"
     echo "$0 --acloud-arg=--local-instance"
     echo "$0 -pb ab://git_main/aosp_cf_x86_64_phone-userdebug/latest"
-    echo "$0 -pb ~/aosp-main/out/target/product/vsoc_x86_64/"
+    echo "$0 -pb ~/main/out/target/product/vsoc_x86_64/"
     echo "$0 -kb ~/android-mainline/out/virtual_device_x86_64/"
     echo ""
     exit 0
 }
 
-function parse_arg() {
+# Logs an error message and exits with the specified code (default 1).
+function fail_error() {
+    local message="$1"
+    local exit_code="${2:-1}"
+    # Pass frame offset 2 to log_error to point to the caller of fail_error
+    log_error "$message" "$exit_code" 2
+    exit "$exit_code"
+}
+
+function parse_args() {
     while test $# -gt 0; do
         case "$1" in
             -h|--help)
                 print_help
                 ;;
+            --use-rbe)
+                USE_RBE=true
+                shift
+                ;;
             --skip-build)
                 SKIP_BUILD=true
                 shift
@@ -77,40 +110,40 @@ function parse_arg() {
             -pb)
                 shift
                 if test $# -gt 0; then
-                    PLATFORM_BUILD=$1
+                    PLATFORM_BUILD="$1"
                 else
-                    print_error "platform build is not specified"
+                    fail_error "platform build is not specified"
                 fi
                 shift
                 ;;
             --platform-build=*)
-                PLATFORM_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
+                PLATFORM_BUILD="$(echo "$1" | sed -e "s/^[^=]*=//g")"
                 shift
                 ;;
             -sb)
                 shift
                 if test $# -gt 0; then
-                    SYSTEM_BUILD=$1
+                    SYSTEM_BUILD="$1"
                 else
-                    print_error "system build is not specified"
+                    fail_error "system build is not specified"
                 fi
                 shift
                 ;;
             --system-build=*)
-                SYSTEM_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
+                SYSTEM_BUILD="$(echo "$1" | sed -e "s/^[^=]*=//g")"
                 shift
                 ;;
             -kb)
                 shift
                 if test $# -gt 0; then
-                    KERNEL_BUILD=$1
+                    KERNEL_BUILD="$1"
                 else
-                    print_error "kernel build path is not specified"
+                    fail_error "kernel build path is not specified"
                 fi
                 shift
                 ;;
             --kernel-build=*)
-                KERNEL_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
+                KERNEL_BUILD="$(echo "$1" | sed -e "s/^[^=]*=//g")"
                 shift
                 ;;
             --acloud-arg=*)
@@ -118,11 +151,11 @@ function parse_arg() {
                 shift
                 ;;
             --acloud-bin=*)
-                ACLOUD_BIN=$(echo "$1" | sed -e "s/^[^=]*=//g")
+                ACLOUD_BIN="$(echo "$1" | sed -e "s/^[^=]*=//g")"
                 shift
                 ;;
             --cf-product=*)
-                PRODUCT=$(echo "$1" | sed -e "s/^[^=]*=//g")
+                PRODUCT="$(echo "$1" | sed -e "s/^[^=]*=//g")"
                 shift
                 ;;
             --gcov)
@@ -138,18 +171,12 @@ function parse_arg() {
                 shift
                 ;;
             *)
-                print_error "Unsupported flag: $1" >&2
+                fail_error "Unsupported flag: $1" >&2
                 ;;
         esac
     done
 }
 
-function adb_checker() {
-    if ! which adb &> /dev/null; then
-        print_error "adb not found!"
-    fi
-}
-
 function create_kernel_build_cmd() {
     local cf_kernel_repo_root=$1
     local cf_kernel_version=$2
@@ -160,7 +187,7 @@ function create_kernel_build_cmd() {
     local build_cmd=""
     if [ -f "$cf_kernel_repo_root/common-modules/virtual-device/BUILD.bazel" ]; then
         # support android-mainline, android16, android15, android14, android13
-        build_cmd+="tools/bazel run --config=fast"
+        build_cmd+="tools/bazel run"
         if [ "$GCOV" = true ]; then
             build_cmd+=" --gcov"
         fi
@@ -210,14 +237,6 @@ function create_kernel_build_path() {
     fi
 }
 
-function go_to_repo_root() {
-    current_dir="$1"
-    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
-        current_dir=$(dirname "$current_dir")  # Go up one directory
-        cd "$current_dir" || print_error "Failed to cd to $current_dir"
-    done
-}
-
 function greater_than_or_equal_to() {
     local num1="$1"
     local num2="$2"
@@ -225,9 +244,11 @@ function greater_than_or_equal_to() {
     # This regex matches strings formatted as floating-point or integer numbers
     local num_regex="^[0]([\.][0-9]+)?$|^[1-9][0-9]*([\.][0-9]+)?$"
     if [[ ! "$num1" =~ $num_regex ]] || [[ ! "$num2" =~ $num_regex ]]; then
+        log_warn "Invalid numeric input for comparison: '$num1', '$num2'"
         return 1
     fi
 
+    # Use bc for comparison
     if [[ $(echo "$num1 >= $num2" | bc -l) -eq 1 ]]; then
         return 0
     else
@@ -235,276 +256,330 @@ function greater_than_or_equal_to() {
     fi
 }
 
-# Checks if target_path is within root_directory
-function is_path_in_root() {
-    local root_directory="$1"
-    local target_path="$2"
-
-    # expand the path variable, for example:
-    # "~/Documents" becomes "/home/user/Documents"
-    root_directory=$(eval echo "$root_directory")
-    target_path=$(eval echo "$target_path")
-
-    # remove the trailing slashes
-    root_directory=$(realpath -m "$root_directory")
-    target_path=$(realpath -m "$target_path")
-
-    # handles the corner case, for example:
-    # $root_directory="/home/user/Doc", $target_path="/home/user/Documents/"
-    root_directory="${root_directory}/"
-
-    if [[ "$target_path" = "$root_directory"* ]]; then
-        return 0
-    else
-        return 1
-    fi
-}
-
-function print_info() {
-    echo "[$MY_NAME]: ${GREEN}$1${END}"
-}
-
-function print_warn() {
-    echo "[$MY_NAME]: ${YELLOW}$1${END}"
-}
-
-function print_error() {
-    echo -e "[$MY_NAME]: ${RED}$1${END}"
-    cd "$OLD_PWD" || echo "Failed to cd to $OLD_PWD"
-    exit 1
-}
-
-function set_platform_repo() {
-    print_warn "Build target product '${TARGET_PRODUCT}' does not match expected '$1'"
-    local lunch_cli="source build/envsetup.sh && lunch $1"
-    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
-        lunch_cli+="-trunk_staging-userdebug"
-    else
-        lunch_cli+="-userdebug"
-    fi
-    print_info "Setup build environment with: $lunch_cli"
-    eval "$lunch_cli"
-}
-
 function find_repo() {
-    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
-    -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
+    manifest_output=$(grep -e "superproject" -e "common-modules/virtual-device" -e "default revision" \
+        .repo/manifests/default.xml)
     case "$manifest_output" in
         *platform/superproject*)
             PLATFORM_REPO_ROOT="$PWD"
-            PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
-            grep -oP 'revision="\K[^"]*')
-            print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION"
-            if [ -z "$PLATFORM_BUILD" ]; then
-                PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
+            PLATFORM_VERSION=$(grep -oP 'platform/superproject.*revision="\K[^"]*' <(echo "$manifest_output"))
+            if [ -z "$PLATFORM_VERSION" ]; then
+                # on main branch, <superproject> tag doesn't have a 'revision' attribute
+                # try to extract the information from <default> tag
+                PLATFORM_VERSION=$(grep -oP 'default revision="(refs/tags/)?\K[^"]*' <(echo "$manifest_output"))
+            fi
+            if [ -z "$PLATFORM_VERSION" ]; then
+                fail_error "Could not find platform version information."
             fi
+            log_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION"
             ;;
         *kernel/superproject*)
             if [[ "$manifest_output" == *common-modules/virtual-device* ]]; then
                 CF_KERNEL_REPO_ROOT="$PWD"
                 CF_KERNEL_VERSION=$(grep -e "common-modules/virtual-device" \
                 .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
-                print_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
-                if [ -z "$KERNEL_BUILD" ]; then
-                    output=$(create_kernel_build_path "$CF_KERNEL_VERSION" 2>&1)
-                    if [[ $? -ne 0 ]]; then
-                        print_error "$output"
-                    fi
-                    KERNEL_BUILD="${CF_KERNEL_REPO_ROOT}/$output"
-                    print_info "KERNEL_BUILD=$KERNEL_BUILD"
-                fi
+                log_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
             fi
             ;;
         *)
-            print_warn "Unexpected manifest output. Could not determine repository type."
+            log_warn "Unexpected manifest output. Could not determine repository type."
             ;;
     esac
 }
 
+# Rebuilds the platform images using 'm'. Assumes environment is already set (lunch).
+# WARNING: Uses 'eval'. Consider refactoring if build command becomes complex.
 function rebuild_platform() {
-    build_cmd="m -j12"
-    print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd"
-    eval "$build_cmd"
-    exit_code=$?
-    if [ $exit_code -eq 0 ]; then
-        if [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
-            print_info "$build_cmd succeeded"
+    # Conditionally add USE_RBE=false if not enabled via flag
+    $USE_RBE || set_env_var "USE_RBE" false
+    local build_cmd_parts=("m" "-j$(nproc)") # Use nproc for parallelism
+    log_warn "Flag --skip-build is not set. Rebuilding platform images at $PWD"
+    log_info "Executing build command: ${BOLD}${build_cmd_parts[*]}${END}"
+
+    # Execute the build command
+    run_command "${build_cmd_parts[@]}"
+    build_status=$?
+    if (( build_status == 0 )); then
+        if [[ -f "${ANDROID_PRODUCT_OUT}/system.img" ]]; then
+            log_info "Platform build command succeeded."
+            return 0
         else
-            print_error "${ANDROID_PRODUCT_OUT}/system.img doesn't exist"
+            fail_error "Platform build command succeeded, but required output '${ANDROID_PRODUCT_OUT}/system.img' not found." 1
         fi
     else
-        print_warn "$build_cmd returned exit_code $exit_code or ${ANDROID_PRODUCT_OUT}/system.img is not found"
-        print_error "$build_cmd failed"
+        fail_error "Platform build command failed." "$build_status"
+    fi
+}
+
+# Rebuilds the kernel images. Assumes running in the kernel repo root.
+# WARNING: Uses 'eval'. Consider refactoring.
+function rebuild_kernel() {
+    local kernel_repo_root="$1"
+    local kernel_version="$2"
+
+    log_warn "Flag --skip-build is not set. Rebuilding kernel images at $PWD"
+
+    local build_cmd build_status
+
+    # Get the build command string
+    if ! build_cmd=$(create_kernel_build_cmd "$kernel_repo_root" "$kernel_version"); then
+        fail_error "Failed to determine kernel build command." 1
+    fi
+
+    log_info "Executing kernel build command: ${BOLD}${build_cmd}${END}"
+
+    # Execute the build command
+    # Using eval here is risky. Refactor if build_cmd structure allows.
+    eval "$build_cmd"
+    build_status=$?
+    if (( build_status == 0 )); then
+        log_info "Kernel build command succeeded."
+    else
+        fail_error "Kernel build command failed" build "$build_status"
     fi
 }
 
-adb_checker
+# --- Main Script Logic ---
 
-OLD_PWD=$PWD
-MY_NAME=$0
+# 1. Check Core Dependencies
+log_info "Checking required commands..."
+if ! check_commands_available "${REQUIRED_COMMANDS[@]}"; then
+    fail_error "One or more required commands are missing. Please install them and retry." 1
+fi
 
-parse_arg "$@"
+# 2. Parse Arguments
+log_info "Parsing command line arguments..."
+parse_args "$@"
 
-FULL_COMMAND_PATH=$(dirname "$PWD/$0")
-REPO_LIST_OUT=$(repo list 2>&1)
-if [[ "$REPO_LIST_OUT" == "error"* ]]; then
-    echo -e "[$MY_NAME]: ${RED}Current path $PWD is not in an Android repo. Change path to repo root.${END}"
-    go_to_repo_root "$FULL_COMMAND_PATH"
-    print_info "Changed path to $PWD"
+# 3. Determine Repo Root and Type
+log_info "Determining repository context..."
+repository_path="$PWD"
+if ! is_in_repo_workspace; then
+    log_warn "Current directory '$PWD' is not within an Android repo workspace."
+    repository_path="$SCRIPT_DIR"
+fi
+if ! go_to_repo_root "$repository_path"; then
+    fail_error "Failed to navigate to repo root from $PWD." 1
 else
-    go_to_repo_root "$PWD"
+    find_repo
 fi
 
-find_repo
+# 4. Handle Platform Build/Path
+log_info "Processing platform build..."
+if [[ -z "$PLATFORM_BUILD" && -n "$PLATFORM_REPO_ROOT" ]]; then
+    log_info "Platform build not specified, using detected local platform repo: ${platform_repo_root}"
+    PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
+fi
 
-if [ "$SKIP_BUILD" = false ] && [ -n "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] \
-&& [ -d "$PLATFORM_BUILD" ]; then
-    # Check if PLATFORM_BUILD is an Android platform repo, if yes rebuild
-    cd "$PLATFORM_BUILD" || print_error "Failed to cd to $PLATFORM_BUILD"
-    PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
-    if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
+if [[ -n "$PLATFORM_BUILD" && "$PLATFORM_BUILD" != ab://* ]]; then
+    log_info "Local platform build path specified: ${PLATFORM_BUILD}"
+    # Resolve the path
+    if ! PLATFORM_BUILD=$(realpath -- "$PLATFORM_BUILD" 2>/dev/null); then
+        fail_error "Invalid local platform build path: ${PLATFORM_BUILD}" 1
+    fi
+    if [[ ! -d "$PLATFORM_BUILD" ]]; then
+        fail_error "Local platform build path does not exist or is not a directory: ${PLATFORM_BUILD}" 1
+    fi
+
+    cd "$PLATFORM_BUILD" || fail_error "Failed to cd to $PLATFORM_BUILD"
+
+    if is_in_repo_workspace; then
         go_to_repo_root "$PWD"
+
+        # Set up build environment (lunch)
+        log_info "Setting up platform build environment for product: $PRODUCT"
         if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "$PRODUCT" ]]; then
-            set_platform_repo "$PRODUCT"
+            log_info "TARGET_PRODUCT ('${TARGET_PRODUCT:-}') is not set or doesn't match '$PRODUCT'. Running lunch..."
+            if ! set_platform_repo "$PRODUCT" "userdebug" "$PWD"; then ## Assumes 'userdebug' variant, might need flexibility?
+                fail_error "Failed to set platform build environment (lunch)." 1
+            fi
+        else
+            log_info "Build environment already set for TARGET_PRODUCT=${TARGET_PRODUCT}."
+        fi
+
+        if [[ "$SKIP_BUILD" == false ]]; then
             rebuild_platform
-            PLATFORM_BUILD=${ANDROID_PRODUCT_OUT}
+        else
+            log_info "--skip-build specified, skipping platform rebuild."
+        fi
+        # After potential build, set platform_build to the actual output directory
+        if [[ -n "${ANDROID_PRODUCT_OUT:-}" && -d "${ANDROID_PRODUCT_OUT}" ]]; then
+            log_info "Setting platform build path to lunch output: ${ANDROID_PRODUCT_OUT}"
+            PLATFORM_BUILD="${ANDROID_PRODUCT_OUT}"
+        else
+            fail_error "ANDROID_PRODUCT_OUT ('${ANDROID_PRODUCT_OUT:-}') is not set or not a directory after lunch/build attempt." 1
+        fi
+    else
+        if [[ "$SKIP_BUILD" == false ]]; then
+            log_warn "Local platform build path provided ('${PLATFORM_BUILD}'). --skip-build was not used, but automatic rebuilding is only done when running from within the platform repo source directory."
+        else
+            log_info "Current path $PWD is not a valid Android platform repo, please ensure it contains the platform image."
         fi
     fi
 fi
 
+# 5. Handle System Build/Path
 if [ "$SKIP_BUILD" = false ] && [ -n "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" != ab://* ]] \
 && [ -d "$SYSTEM_BUILD" ]; then
     # Get GSI build
-    cd "$SYSTEM_BUILD" || print_error "Failed to cd to $SYSTEM_BUILD"
+    cd "$SYSTEM_BUILD" || fail_error "Failed to cd to $SYSTEM_BUILD"
     SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
-        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "aosp_x86_64" ]]; then
-            set_platform_repo "aosp_x86_64"
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "${DEFAULT_GSI_PRODUCT}" ]]; then
+            log_warn "Build target product '${TARGET_PRODUCT}' does not match expected '${DEFAULT_GSI_PRODUCT}'. Reset build environment."
+            set_platform_repo "${DEFAULT_GSI_PRODUCT}"
             rebuild_platform
             SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}/system.img"
         fi
     fi
 fi
 
-if [ "$SKIP_BUILD" = false ] && [ -n "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]]; then
-    if [ -d "$CF_KERNEL_REPO_ROOT" ] && [ -n "$CF_KERNEL_VERSION" ] && is_path_in_root "$CF_KERNEL_REPO_ROOT" "$KERNEL_BUILD"; then
-        # Support first-build in the local kernel repository
-        target_path="$CF_KERNEL_REPO_ROOT"
-    elif [ -d $KERNEL_BUILD ]; then
-        target_path="$KERNEL_BUILD"
-    else
-        print_error "Built kernel not found. Either build the kernel or use the default kernel from the local repository"
+# 6. Handle Kernel Build/Path
+if  [[ -n "$KERNEL_BUILD" && "$KERNEL_BUILD" != ab://* ]]; then
+    log_info "Local kernel build path specified: ${KERNEL_BUILD}"
+    # Resolve the path
+    if ! KERNEL_BUILD=$(realpath -- "$KERNEL_BUILD" 2>/dev/null); then
+         fail_error "Invalid local kernel build path: ${KERNEL_BUILD}" 1
+    fi
+    if [[ ! -d "$KERNEL_BUILD" ]]; then
+         fail_error "Local kernel build path does not exist or is not a directory: ${KERNEL_BUILD}" 1
     fi
 
-    cd "$target_path" || print_error "Failed to cd to $target_path"
-    KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
-    if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
-        go_to_repo_root "$target_path"
+    log_info "Changing directory to kernel build: ${KERNEL_BUILD}"
+    cd -- "$KERNEL_BUILD" || fail_error "Failed to cd into kernel build directory: ${KERNEL_BUILD}" 1
+
+    if is_in_repo_workspace; then
+        go_to_repo_root "$PWD"
         target_kernel_repo_root="$PWD"
         target_cf_kernel_version=$(grep -e "common-modules/virtual-device" \
         .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
 
-        print_info "target_kernel_repo_root=$target_kernel_repo_root, target_cf_kernel_version=$target_cf_kernel_version"
+        log_info "target_kernel_repo_root=$target_kernel_repo_root, target_cf_kernel_version=$target_cf_kernel_version"
+
+        # Rebuild if not skipped
+        if [[ "$SKIP_BUILD" == false ]]; then
+            rebuild_kernel "$target_kernel_repo_root" "$target_cf_kernel_version" # Assumes PWD is kernel root
+        else
+            log_info "--skip-build specified, skipping kernel rebuild."
+        fi
+
+        # Determine the expected output path after potential build
+        kernel_out_path=""
+        if ! kernel_out_path=$(create_kernel_build_path "$target_cf_kernel_version"); then
+            fail_error "Failed to determine kernel build output path for version ${cf_kernel_version}." 1
+        fi
+        full_kernel_path="${target_kernel_repo_root}/${kernel_out_path}"
 
-        output=$(create_kernel_build_cmd $PWD $target_cf_kernel_version 2>&1)
-        if [[ $? -ne 0 ]]; then
-            print_error "$output"
+        # Check if the expected output directory exists
+        if [[ -d "$full_kernel_path" ]]; then
+            log_info "Setting kernel build path to detected output: ${full_kernel_path}"
+            KERNEL_BUILD="$full_kernel_path"
+        else
+            err_msg="Expected kernel build output directory '${full_kernel_path}' not found."
+            if [[ "$SKIP_BUILD" == true ]]; then
+                err_msg+="Don't skip re-building the kernel image."
+            fi
+            fail_error "$err_msg" 1
         fi
-        build_cmd="$output"
-        print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd."
-        eval "$build_cmd" && print_info "$build_cmd succeeded" || print_error "$build_cmd failed"
     else
-        print_warn "Current path $PWD is not a valid Android repo, please ensure it contains the kernel"
+        if [[ "$SKIP_BUILD" == false ]]; then
+            log_warn "Local kernel build path provided ('${KERNEL_BUILD}'). --skip-build was not used, but automatic rebuilding is only done when running from within the kernel repo source directory."
+        else
+            log_info  "Current path $PWD is not a valid Android repo, please ensure it contains the kernel image."
+        fi
     fi
 fi
 
+# 7. Find acloud Binary
 if [ -z "$ACLOUD_BIN" ] || ! [ -x "$ACLOUD_BIN" ]; then
-    output=$(which acloud 2>&1)
-    if [ -z "$output" ]; then
-        print_info "Use acloud binary from $ACLOUD_PREBUILT"
+    log_info "Acloud binary path not specified or is not executable(--acloud-bin). Searching..."
+    if ACLOUD_BIN=$(which acloud 2>&1); then
+        log_info "Use acloud binary from: ${ACLOUD_BIN}"
+    else
+        # Fallback to prebuilt location relative to a detected repo root
+        potential_prebuilt_path=""
         if [ -n "${PLATFORM_REPO_ROOT}" ]; then
-            ACLOUD_PREBUILT="${PLATFORM_REPO_ROOT}/${ACLOUD_PREBUILT}"
+            potential_prebuilt_path="${PLATFORM_REPO_ROOT}/${ACLOUD_PREBUILT}"
         elif  [ -n "${CF_KERNEL_REPO_ROOT}" ]; then
-            ACLOUD_PREBUILT="${CF_KERNEL_REPO_ROOT}/${ACLOUD_PREBUILT}"
+            potential_prebuilt_path="${CF_KERNEL_REPO_ROOT}/${ACLOUD_PREBUILT}"
+        fi
+
+        if [[ -n "$potential_prebuilt_path" && -x "$potential_prebuilt_path" ]]; then
+            log_info "Using prebuilt acloud from repository: ${potential_prebuilt_path}"
+            ACLOUD_BIN="$potential_prebuilt_path"
         else
-            print_error "Unable to determine repository root path from repo manifest"
+            fail_error "Could not find 'acloud' in PATH and failed to locate a valid prebuilt acloud in detected repo roots (${platform_repo_root:-none}, ${cf_kernel_repo_root:-none}). Specify path using --acloud-bin."
         fi
-        ACLOUD_BIN="$ACLOUD_PREBUILT"
-    else
-        print_info "Use acloud binary from $output"
-        ACLOUD_BIN="$output"
     fi
+fi
 
-    # Check if the newly found or prebuilt ACLOUD_BIN is executable
-    if ! [ -x "$ACLOUD_BIN" ]; then
-        print_error "$ACLOUD_BIN is not executable"
-    fi
+
+# Final check if the determined/specified acloud binary is executable
+if [[ ! -x "$ACLOUD_BIN" ]]; then
+    fail_error "Acloud binary found or specified is not executable: ${ACLOUD_BIN}"
 fi
+log_info "Using acloud binary: ${BOLD}${ACLOUD_BIN}${END}"
 
-acloud_cli="$ACLOUD_BIN create"
+acloud_cmd_parts=("$ACLOUD_BIN" "create")
 EXTRA_OPTIONS+=("$OPT_SKIP_PRERUNCHECK")
 
 # Add in branch if not specified
-
+# 8. Construct acloud Command Arguments
 if [ -z "$PLATFORM_BUILD" ]; then
-    print_warn "Platform build is not specified, will use the latest aosp-main build."
-    acloud_cli+=' --branch aosp-main'
+    log_warn "Platform build was not specified, and could not be determined from local repo. Will use the latest git_main build."
+    acloud_cmd_parts+=("--branch" "git_main")
 elif [[ "$PLATFORM_BUILD" == ab://* ]]; then
-    IFS='/' read -ra array <<< "$PLATFORM_BUILD"
-    acloud_cli+=" --branch ${array[2]}"
-
-    # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
-        acloud_cli+=" --build-target ${array[3]}"
-
-        # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
-            acloud_cli+=" --build-id ${array[4]}"
-        fi
+    ab_branch="" ab_target="" ab_id=""
+    parse_ab_url "$PLATFORM_BUILD" ab_branch ab_target ab_id
+    if [[ $? -ne 0 ]]; then
+        fail_error "Platform Build URL $PLATFORM_BUILD parsing failed" 1
+    fi
+    acloud_cmd_parts+=("--branch" "${ab_branch}")
+    acloud_cmd_parts+=("--build-target" "${ab_target}")
+    if [[ "${ab_id}" != "latest" ]]; then
+        acloud_cmd_parts+=("--build-id" "${ab_id}")
     fi
 else
-    acloud_cli+=" --local-image $PLATFORM_BUILD"
+    acloud_cmd_parts+=("--local-image" "$PLATFORM_BUILD")
 fi
 
 if [ -z "$KERNEL_BUILD" ]; then
-    print_warn "Flag --kernel-build is not set, will not launch Cuttlefish with different kernel."
+    log_warn "Flag --kernel-build is not set, will not launch Cuttlefish with different kernel."
 elif [[ "$KERNEL_BUILD" == ab://* ]]; then
-    IFS='/' read -ra array <<< "$KERNEL_BUILD"
-    acloud_cli+=" --kernel-branch ${array[2]}"
-
-    # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
-        acloud_cli+=" --kernel-build-target ${array[3]}"
+    ab_branch="" ab_target="" ab_id=""
+    parse_ab_url "$KERNEL_BUILD" ab_branch ab_target ab_id
+    if [[ $? -ne 0 ]]; then
+        fail_error "Kernel Build URL $KERNEL_BUILD parsing failed" 1
+    fi
 
-        # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
-            acloud_cli+=" --kernel-build-id ${array[4]}"
-        fi
+    acloud_cmd_parts+=("--kernel-branch" "${ab_branch}")
+    acloud_cmd_parts+=("--kernel-build-target" "${ab_target}")
+    if [[ "${ab_id}" != "latest" ]]; then
+        acloud_cmd_parts+=("--kernel-build-id" "${ab_id}")
     fi
 else
-    acloud_cli+=" --local-kernel-image $KERNEL_BUILD"
+    acloud_cmd_parts+=("--local-kernel-image" "$KERNEL_BUILD")
 fi
 
 if [ -z "$SYSTEM_BUILD" ]; then
-    print_warn "System build is not specified, will not launch Cuttlefish with GSI mixed build."
+    log_warn "System build is not specified, will not launch Cuttlefish with GSI mixed build."
 elif [[ "$SYSTEM_BUILD" == ab://* ]]; then
-    IFS='/' read -ra array <<< "$SYSTEM_BUILD"
-    acloud_cli+=" --system-branch ${array[2]}"
-
-     # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
-        acloud_cli+=" --system-build-target ${array[3]}"
-
-        # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
-            acloud_cli+=" --system-build-id ${array[4]}"
-        fi
+    ab_branch="" ab_target="" ab_id=""
+    parse_ab_url "$SYSTEM_BUILD" ab_branch ab_target ab_id
+    if [[ $? -ne 0 ]]; then
+        fail_error "System Build URL $SYSTEM_BUILD parsing failed" 1
+    fi
+    acloud_cmd_parts+=("--system-branch" "${ab_branch}")
+    acloud_cmd_parts+=("--system-build-target" "${ab_target}")
+    if [[ "${ab_id}" != "latest" ]]; then
+        acloud_cmd_parts+=("--system-build-id" "${ab_id}")
     fi
 else
-    acloud_cli+=" --local-system-image $SYSTEM_BUILD"
+    acloud_cmd_parts+=("--local-system-image" "$SYSTEM_BUILD")
 fi
 
-acloud_cli+=" ${EXTRA_OPTIONS[*]}"
-print_info "Launch CVD with command: $acloud_cli"
-eval "$acloud_cli"
+# 9. Execute acloud Command
+acloud_cmd_parts+=("${EXTRA_OPTIONS[@]}")
+log_info "Launch CVD with command: ${acloud_cmd_parts[*]}"
+run_command "${acloud_cmd_parts[@]}"
diff --git a/tools/run_test_only.sh b/tools/run_test_only.sh
index 88843f5..dbb9ad5 100755
--- a/tools/run_test_only.sh
+++ b/tools/run_test_only.sh
@@ -7,39 +7,17 @@
 
 KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
 PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
-JDK_PATH=prebuilts/jdk/jdk11/linux-x86
-PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
 DEFAULT_LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
 DOWNLOAD_PATH="/tmp/downloaded_tests"
 GCOV=false
 CREATE_TRACEFILE_SCRIPT="kernel/tests/tools/create-tracefile.py"
-FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
 TRADEFED=
 TRADEFED_GCOV_OPTIONS=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
 TEST_ARGS=()
 TEST_DIR=
 TEST_NAMES=()
-
-BOLD="$(tput bold)"
-END="$(tput sgr0)"
-GREEN="$(tput setaf 2)"
-RED="$(tput setaf 198)"
-YELLOW="$(tput setaf 3)"
-BLUE="$(tput setaf 34)"
-
-function adb_checker() {
-    if ! which adb &> /dev/null; then
-        echo -e "\n${RED}Adb not found!${END}"
-    fi
-}
-
-function go_to_repo_root() {
-    current_dir="$1"
-    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
-        current_dir=$(dirname "$current_dir")  # Go up one directory
-        cd "$current_dir"
-    done
-}
+USE_RBE=false
+readonly REQUIRED_COMMANDS=("adb" "dirname")
 
 function print_info() {
     local log_prompt=$MY_NAME
@@ -90,6 +68,8 @@ function print_help() {
     echo "  -tf <tradefed_binary_path>, --tradefed-bin=<tradefed_binary_path>"
     echo "                        The alternative tradefed binary to run test with."
     echo "  --gcov                Collect coverage data from the test result"
+    echo "  --use-rbe             Enable Remote Build Execution to speed up testing process."
+    echo "                        Requires RBE service access; See go/build-fast for details."
     echo "  -h, --help            Display this help message and exit"
     echo ""
     echo "Examples:"
@@ -105,29 +85,22 @@ function print_help() {
     exit 0
 }
 
-function set_platform_repo() {
-    print_warn "Build target product '${TARGET_PRODUCT}' does not match device product '$PRODUCT'"
-    lunch_cli="source build/envsetup.sh && "
-    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
-        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
-    else
-        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
-    fi
-    print_info "Setup build environment with: $lunch_cli"
-    eval "$lunch_cli"
-}
-
 function run_test_in_platform_repo() {
-    if [ -z "${TARGET_PRODUCT}" ]; then
-        set_platform_repo
-    elif [[ "${TARGET_PRODUCT}" != *"x86"* && "${PRODUCT}" == *"x86"* ]] || \
-        [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
+    if [[ "${TARGET_PRODUCT}" != *"x86"* && "${PRODUCT}" == *"x86"* ]] || \
+    [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]] || \
+    [ -z "${TARGET_PRODUCT}" ]; then
+        print_warn "Build target product '${TARGET_PRODUCT}' does not match device product '$PRODUCT'. Reset build environment." "$LINENO"
         set_platform_repo
     fi
-    atest_cli="atest ${TEST_NAMES[*]} -s $SERIAL_NUMBER --"
+    atest_cli=""
+    if [ "$USE_RBE" = false ]; then
+        atest_cli+="USE_RBE=false RBE_ENABLED=false "
+    fi
+    atest_cli+="atest ${TEST_NAMES[*]} -s $SERIAL_NUMBER --"
     if $GCOV; then
         atest_cli+="$TRADEFED_GCOV_OPTIONS"
     fi
+    print_info "Running the test with: $atest_cli ${TEST_ARGS[*]}" "$LINENO"
     eval "$atest_cli" "${TEST_ARGS[*]}"
     exit_code=$?
 
@@ -135,12 +108,37 @@ function run_test_in_platform_repo() {
         atest_log_dir="/tmp/atest_result_$USER/LATEST"
         create_tracefile_cli="$CREATE_TRACEFILE_SCRIPT -t $atest_log_dir/log -o $atest_log_dir/cov.info"
         print_info "Skip creating tracefile. If you have full kernel source, run the following command:"
-        print_info "$create_tracefile_cli"
+        print_info "$create_tracefile_cli" "$LINENO"
     fi
     cd $OLD_PWD
     exit $exit_code
 }
 
+function unset_android_environment() {
+    for var in $(env); do
+      # Extract the variable name
+      var_name="${var%%=*}"
+      # Check if the variable name starts with "ANDROID"
+      if [[ "$var_name" == "ANDROID"* ]]; then
+        # Unset the variable
+        unset "$var_name"
+      fi
+    done
+}
+
+SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
+SCRIPT_DIR="$( cd "$( dirname "${SCRIPT_PATH}" )" &> /dev/null && pwd -P)"
+LIB_PATH="${SCRIPT_DIR}/common_lib.sh"
+if [[ -f "$LIB_PATH" ]]; then
+    if ! . "$LIB_PATH"; then
+        echo "Fatal Error：Cannot load library '$LIB_PATH'" >&2
+        exit 1
+    fi
+else
+    echo "Fatal Error：Cannot find library '$LIB_PATH'" >&2
+    exit 1
+fi
+
 OLD_PWD=$PWD
 MY_NAME=$0
 
@@ -152,85 +150,89 @@ while test $# -gt 0; do
         -s)
             shift
             if test $# -gt 0; then
-                SERIAL_NUMBER=$1
+                SERIAL_NUMBER="$1"
             else
                 print_error "device serial is not specified"
             fi
             shift
             ;;
         --serial*)
-            SERIAL_NUMBER=$(echo $1 | sed -e "s/^[^=]*=//g")
+            SERIAL_NUMBER="$(echo "$1" | sed -e "s/^[^=]*=//g")"
             shift
             ;;
         -tl)
             shift
             if test $# -gt 0; then
-                LOG_DIR=$1
+                LOG_DIR="$1"
             else
                 print_error "test log directory is not specified"
             fi
             shift
             ;;
         --test-log*)
-            LOG_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
+            LOG_DIR=$(echo "$1" | sed -e "s/^[^=]*=//g")
             shift
             ;;
         -td | -tb )
             shift
             if test $# -gt 0; then
-                TEST_DIR=$1
+                TEST_DIR="$1"
             else
                 print_error "test directory is not specified"
             fi
             shift
             ;;
         --test-dir* | --test-build*)
-            TEST_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
+            TEST_DIR=$(echo "$1" | sed -e "s/^[^=]*=//g")
             shift
             ;;
         -ta)
             shift
             if test $# -gt 0; then
-                TEST_ARGS+=$1
+                TEST_ARGS+=("$1")
             else
                 print_error "test arg is not specified"
             fi
             shift
             ;;
         --test-arg*)
-            TEST_ARGS+=$(echo $1 | sed -e "s/^[^=]*=//g")
+            TEST_ARGS+=($(echo $1 | sed -e "s/^[^=]*=//g"))
             shift
             ;;
         -t)
             shift
             if test $# -gt 0; then
-                TEST_NAMES+=$1
+                TEST_NAMES+=("$1")
             else
                 print_error "test name is not specified"
             fi
             shift
             ;;
         --test*)
-            TEST_NAMES+=$(echo $1 | sed -e "s/^[^=]*=//g")
+            TEST_NAMES+=("$(echo "$1" | sed -e "s/^[^=]*=//g")")
             shift
             ;;
         -tf)
             shift
             if test $# -gt 0; then
-                TRADEFED=$1
+                TRADEFED="$1"
             else
                 print_error "tradefed binary is not specified"
             fi
             shift
             ;;
         --tradefed-bin*)
-            TRADEFED=$(echo $1 | sed -e "s/^[^=]*=//g")
+            TRADEFED="$(echo "$1" | sed -e "s/^[^=]*=//g")"
             shift
             ;;
         --gcov)
             GCOV=true
             shift
             ;;
+        --use-rbe)
+            USE_RBE=true
+            shift
+            ;;
         *)
             ;;
     esac
@@ -257,9 +259,12 @@ else
 fi
 
 REPO_ROOT_PATH="$PWD"
-FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"
+readonly FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT_PATH_IN_REPO"
 
-adb_checker
+print_info "Checking required commands..." "$LINENO"
+if ! check_commands_available "${REQUIRED_COMMANDS[@]}"; then
+    print_error "One or more required commands are missing. Please install them and retry." "$LINENO"
+fi
 
 # Set default LOG_DIR if not provided
 if [ -z "$LOG_DIR" ]; then
@@ -277,7 +282,6 @@ if [ -z "$TEST_DIR" ]; then
         # In the platform repo
         print_info "Run test with atest" "$LINENO"
         run_test_in_platform_repo
-        return
     elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
         # In the android kernel repo
         if [[ "$ABI" == "arm64"* ]]; then
@@ -297,9 +301,9 @@ if [ -z "$TEST_DIR" ]; then
 fi
 
 TEST_FILTERS=
-for i in "$TEST_NAMES"; do
-    TEST_NAME=$(echo $i | sed "s/:/ /g")
-    TEST_FILTERS+=" --include-filter '$TEST_NAME'"
+for i in "${TEST_NAMES[@]}"; do
+    _test_name=$(echo $i | sed "s/:/ /g")
+    TEST_FILTERS+=" --include-filter '$_test_name'"
 done
 
 if [[ "$TEST_DIR" == ab://* ]]; then
@@ -322,7 +326,7 @@ if [[ "$TEST_DIR" == ab://* ]]; then
         print_error "Failed to download ${file_name}" "$LINENO"
     fi
     TEST_DIR="$DOWNLOAD_PATH/$file_name"
-elif [ ! -z "$TEST_DIR" ]; then
+elif [ -n "$TEST_DIR" ]; then
     if [ -d $TEST_DIR ]; then
         test_file_path=$TEST_DIR
     elif [ -f "$TEST_DIR" ]; then
@@ -339,7 +343,6 @@ elif [ ! -z "$TEST_DIR" ]; then
         print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest" "$LINENO"
         go_to_repo_root "$PWD"
         run_test_in_platform_repo
-        return
     fi
 fi
 
@@ -363,18 +366,20 @@ fi
 
 print_info "Will run tests with test artifacts in $TEST_DIR" "$LINENO"
 
-if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
-    TRADEFED="JAVA_HOME=${TEST_DIR}/jdk PATH=${TEST_DIR}/jdk/bin:$PATH ${TEST_DIR}/tools/vts-tradefed"
-    print_info "Will run tests with vts-tradefed from $TRADEFED" "$LINENO"
+if [[ "$TEST_DIR" == */android-vts/* ]] && [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
+    print_info "Will run tests with vts-tradefed from $TEST_DIR" "$LINENO"
     print_info "Many VTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
-    tf_cli="$TRADEFED run commandAndExit \
-    vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
+    cd "${TEST_DIR}"
+    unset_android_environment
+    tf_cli="tools/vts-tradefed run commandAndExit vts --skip-device-info \
+    --log-level-display info --log-file-path=$LOG_DIR \
     $TEST_FILTERS -s $SERIAL_NUMBER"
-elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
-    TRADEFED="JAVA_HOME=${TEST_DIR}/jdk PATH=${TEST_DIR}/jdk/bin:$PATH ${TEST_DIR}/tools/cts-tradefed"
-    print_info "Will run tests with cts-tradefed from $TRADEFED" "$LINENO"
+elif [[ "$TEST_DIR" == */android-cts/* ]] &&  [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
+    print_info "Will run tests with cts-tradefed from $TEST_DIR" "$LINENO"
     print_info "Many CTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
-    tf_cli="$TRADEFED run commandAndExit cts --skip-device-info \
+    cd "${TEST_DIR}"
+    unset_android_environment
+    tf_cli="tools/cts-tradefed run commandAndExit cts --skip-device-info \
     --log-level-display info --log-file-path=$LOG_DIR \
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
@@ -392,7 +397,7 @@ elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
     --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "$KERNEL_TF_PREBUILT" ]; then
-    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
+    TRADEFED="JAVA_HOME=$KERNEL_JDK_PATH PATH=$KERNEL_JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
     print_info "Use the tradefed prebuilt from $KERNEL_TF_PREBUILT" "$LINENO"
     tf_cli="$TRADEFED run commandAndExit template/local_min \
     --log-level-display info --log-file-path=$LOG_DIR \
@@ -429,4 +434,21 @@ if $GCOV; then
 fi
 
 cd $OLD_PWD
-exit $exit_code
+if (( exit_code > 0 )); then
+    exit $exit_code
+fi
+
+INVOCATION_SUMMARY="$TEST_DIR/results/latest/invocation_summary.txt"
+failure_number=$(grep "FAILED[[:space:]]*:" "$INVOCATION_SUMMARY" | awk -F ":" '{print $NF}' | tr -d ' ')
+
+if [ -n "$failure_number" ]; then
+    if (( failure_number == 0 )); then
+        print_info "There is no test failure"
+    elif (( failure_number == 1 )); then
+        print_error "There is a test failure"
+    else
+        print_error "There are $failure_number test failures"
+    fi
+else
+    print_error "$INVOCATION_SUMMARY doesn't have 'FAILED :' line"
+fi
```

