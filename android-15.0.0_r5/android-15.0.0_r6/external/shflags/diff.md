```diff
diff --git a/METADATA b/METADATA
index c784bbe..bd44a29 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
-name: "shFlags"
-description:
-    "shFlags is a port of the Google gflags library for Unix shell. The code is "
-    "written in a way to be as portable as possible to work across a wide array "
-    "of Unix variants. It is also tested with shUnit2 to maintain code quality."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/shflags
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "shFlags"
+description: "shFlags is a port of the Google gflags library for Unix shell. The code is written in a way to be as portable as possible to work across a wide array of Unix variants. It is also tested with shUnit2 to maintain code quality."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/kward/shflags/wiki"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 8
+    day: 22
   }
-  url {
-    type: GIT
+  homepage: "https://github.com/kward/shflags/wiki"
+  identifier {
+    type: "Git"
     value: "https://github.com/kward/shflags"
+    version: "96694d58ce92065fdd8f8761d930765cb9a8d066"
   }
-  version: "7d0daf1b3b3163c34e0108cdb439e2cd2f148152"
-  last_upgrade_date { year: 2020 month: 5 day: 18 }
-  license_type: NOTICE
 }
-
diff --git a/doc/CHANGES-1.3.md b/doc/CHANGES-1.3.md
index 248afe6..79c5d22 100644
--- a/doc/CHANGES-1.3.md
+++ b/doc/CHANGES-1.3.md
@@ -6,12 +6,14 @@
 
 *A new series was started due to the major changes required for 'set -e' support.*
 
-Upgraded shUnit2 to 2.1.9pre, which includes 'set -e' support.
+Upgraded shUnit2 to HEAD, which includes 'set -e' support.
 
 Fixed #9. shFlags now works properly with 'set -e' enabled.
 
 Fixed #50. The `FLAGS_ARGC` variable is no longer is no longer exported. The variable was marked obsolete in 1.0.3, and it is finally being removed.
 
+Issue #57. Added `shflags_issue_57.sh` to ensure 'set -o pipefail' doesn't break functionality.
+
 ---
 
 ## 1.2.x stable series
diff --git a/doc/RELEASE_NOTES-1.3.0.md b/doc/RELEASE_NOTES-1.3.0.md
new file mode 100644
index 0000000..80b491e
--- /dev/null
+++ b/doc/RELEASE_NOTES-1.3.0.md
@@ -0,0 +1,65 @@
+# shFlags 1.3.0 Release Notes
+
+https://github.com/kward/shflags
+
+## Preface
+
+This document covers any known issues and workarounds for the stated release of
+shFlags.
+
+## Release info
+
+This is the first release in the new testing series. The primary change from
+1.2.3 was reworking things so that 'set -e' is supported.
+
+Please see the `CHANGES-1.3.md` file for a complete list of changes.
+
+### Notable changes
+
+The obsolete `FLAGS_ARGC` variable was removed.
+
+### Notable bug fixes
+
+Some rewrites to ensure shell 'set -e' (as well as 'set -u' and
+'set -o pipefail') are supported as expected.
+
+## General info
+
+### The unit tests
+
+shFlags is designed to work on as many environments as possible, but not all
+environments are created equal. As such, not all of the unit tests will succeed
+on every platform. The unit tests are therefore designed to fail, indicating to
+the tester that the supported functionality is not present, but an additional
+test is present to verify that shFlags properly caught the limitation and
+presented the user with an appropriate error message.
+
+shFlags tries to support both the standard and enhanced versions of `getopt`. As
+each responds differently, and not everything is supported on the standard
+version, some unit tests will be skipped (i.e. ASSERTS will not be thrown) when
+the standard version of `getopt` is detected. The reason being that there is no
+point testing for functionality that is positively known not to exist. A tally
+of skipped tests will be kept for later reference.
+
+### Standard vs Enhanced getopt
+
+Here is a matrix of the supported features of the various `getopt` variants.
+
+Feature                                 | std | enh
+--------------------------------------- | --- | ---
+short option names                      | Y   | Y
+long option names                       | N   | Y
+spaces in string options                | N   | Y
+intermixing of flag and non-flag values | N   | Y
+
+## Known Issues
+
+The `getopt` version provided by default with all versions of Mac OS X (up to
+and including 10.13.0) and Solaris (up to and including Solaris 10 and
+OpenSolaris) is the standard version.
+
+## Workarounds
+
+The Zsh shell requires the `shwordsplit` option to be set and the special
+`FLAGS_PARENT` variable must be defined. See `src/shflags_test_helpers` to see
+how the unit tests do this.
diff --git a/lib/shunit2 b/lib/shunit2
index 2850370..57a45da 100755
--- a/lib/shunit2
+++ b/lib/shunit2
@@ -1,22 +1,22 @@
 #! /bin/sh
 # vim:et:ft=sh:sts=2:sw=2
 #
-# Copyright 2008-2020 Kate Ward. All Rights Reserved.
+# shUnit2 -- Unit testing framework for Unix shell scripts.
+#
+# Copyright 2008-2021 Kate Ward. All Rights Reserved.
 # Released under the Apache 2.0 license.
 # http://www.apache.org/licenses/LICENSE-2.0
 #
-# shUnit2 -- Unit testing framework for Unix shell scripts.
-# https://github.com/kward/shunit2
-#
 # Author: kate.ward@forestent.com (Kate Ward)
+# https://github.com/kward/shunit2
 #
 # shUnit2 is a xUnit based unit test framework for Bourne shell scripts. It is
 # based on the popular JUnit unit testing framework for Java.
 #
-# $() are not fully portable (POSIX != portable).
-#   shellcheck disable=SC2006
-# expr may be antiquated, but it is the only solution in some cases.
+# `expr` may be antiquated, but it is the only solution in some cases.
 #   shellcheck disable=SC2003
+# Allow usage of legacy backticked `...` notation instead of $(...).
+#   shellcheck disable=SC2006
 
 # Return if shunit2 already loaded.
 if test -n "${SHUNIT_VERSION:-}"; then
@@ -38,51 +38,20 @@ fi
 
 # Determine some reasonable command defaults.
 __SHUNIT_CMD_ECHO_ESC='echo -e'
-# shellcheck disable=SC2039
+# shellcheck disable=SC2039,SC3037
 if ${__SHUNIT_BUILTIN} [ "`echo -e test`" = '-e test' ]; then
   __SHUNIT_CMD_ECHO_ESC='echo'
 fi
 
-__SHUNIT_UNAME_S=`uname -s`
-case "${__SHUNIT_UNAME_S}" in
-  BSD) __SHUNIT_CMD_EXPR='gexpr' ;;
-  *) __SHUNIT_CMD_EXPR='expr' ;;
-esac
-__SHUNIT_CMD_TPUT='tput'
-
 # Commands a user can override if needed.
-SHUNIT_CMD_EXPR=${SHUNIT_CMD_EXPR:-${__SHUNIT_CMD_EXPR}}
+__SHUNIT_CMD_TPUT='tput'
 SHUNIT_CMD_TPUT=${SHUNIT_CMD_TPUT:-${__SHUNIT_CMD_TPUT}}
 
-# Enable color output. Options are 'never', 'always', or 'auto'.
+# Enable color output. Options are 'auto', 'always', or 'never'.
 SHUNIT_COLOR=${SHUNIT_COLOR:-auto}
 
-# Logging functions.
-_shunit_warn() {
-  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_yellow}shunit2:WARN${__shunit_ansi_none} $*" >&2
-}
-_shunit_error() {
-  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_red}shunit2:ERROR${__shunit_ansi_none} $*" >&2
-}
-_shunit_fatal() {
-  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_red}shunit2:FATAL${__shunit_ansi_none} $*" >&2
-  exit ${SHUNIT_ERROR}
-}
-
-# Specific shell checks.
-if ${__SHUNIT_BUILTIN} [ -n "${ZSH_VERSION:-}" ]; then
-  setopt |grep "^shwordsplit$" >/dev/null
-  if ${__SHUNIT_BUILTIN} [ $? -ne ${SHUNIT_TRUE} ]; then
-    _shunit_fatal 'zsh shwordsplit option is required for proper operation'
-  fi
-  if ${__SHUNIT_BUILTIN} [ -z "${SHUNIT_PARENT:-}" ]; then
-    _shunit_fatal "zsh does not pass \$0 through properly. please declare \
-\"SHUNIT_PARENT=\$0\" before calling shUnit2"
-  fi
-fi
-
 #
-# Constants
+# Internal constants.
 #
 
 __SHUNIT_MODE_SOURCED='sourced'
@@ -100,25 +69,6 @@ __SHUNIT_ANSI_GREEN='\033[1;32m'
 __SHUNIT_ANSI_YELLOW='\033[1;33m'
 __SHUNIT_ANSI_CYAN='\033[1;36m'
 
-# Set the constants readonly.
-__shunit_constants=`set |grep '^__SHUNIT_' |cut -d= -f1`
-echo "${__shunit_constants}" |grep '^Binary file' >/dev/null && \
-    __shunit_constants=`set |grep -a '^__SHUNIT_' |cut -d= -f1`
-for __shunit_const in ${__shunit_constants}; do
-  if ${__SHUNIT_BUILTIN} [ -z "${ZSH_VERSION:-}" ]; then
-    readonly "${__shunit_const}"
-  else
-    case ${ZSH_VERSION} in
-      [123].*) readonly "${__shunit_const}" ;;
-      *)
-        # Declare readonly constants globally.
-        # shellcheck disable=SC2039
-        readonly -g "${__shunit_const}"
-    esac
-  fi
-done
-unset __shunit_const __shunit_constants
-
 #
 # Internal variables.
 #
@@ -151,12 +101,63 @@ __shunit_assertsPassed=0
 __shunit_assertsFailed=0
 __shunit_assertsSkipped=0
 
+#
+# Internal functions.
+#
+
+# Logging.
+_shunit_warn() {
+  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_yellow}shunit2:WARN${__shunit_ansi_none} $*" >&2
+}
+_shunit_error() {
+  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_red}shunit2:ERROR${__shunit_ansi_none} $*" >&2
+}
+_shunit_fatal() {
+  ${__SHUNIT_CMD_ECHO_ESC} "${__shunit_ansi_red}shunit2:FATAL${__shunit_ansi_none} $*" >&2
+  exit ${SHUNIT_ERROR}
+}
+
 #
 # Macros.
 #
 
 # shellcheck disable=SC2016,SC2089
-_SHUNIT_LINENO_='eval __shunit_lineno=""; if ${__SHUNIT_BUILTIN} [ "${1:-}" = "--lineno" ]; then if ${__SHUNIT_BUILTIN} [ -n "$2" ]; then __shunit_lineno="[$2] "; fi; shift 2; fi'
+_SHUNIT_LINENO_='eval __shunit_lineno=""; if ${__SHUNIT_BUILTIN} [ "${1:-}" = "--lineno" ] && ${__SHUNIT_BUILTIN} [ -n "${2:-}" ]; then __shunit_lineno="[${2}]"; shift 2; fi;'
+
+#
+# Setup.
+#
+
+# Specific shell checks.
+if ${__SHUNIT_BUILTIN} [ -n "${ZSH_VERSION:-}" ]; then
+  setopt |grep "^shwordsplit$" >/dev/null
+  if ${__SHUNIT_BUILTIN} [ $? -ne ${SHUNIT_TRUE} ]; then
+    _shunit_fatal 'zsh shwordsplit option is required for proper operation'
+  fi
+  if ${__SHUNIT_BUILTIN} [ -z "${SHUNIT_PARENT:-}" ]; then
+    _shunit_fatal "zsh does not pass \$0 through properly. please declare \
+\"SHUNIT_PARENT=\$0\" before calling shUnit2"
+  fi
+fi
+
+# Set the constants readonly.
+__shunit_constants=`set |grep '^__SHUNIT_' |cut -d= -f1`
+echo "${__shunit_constants}" |grep '^Binary file' >/dev/null && \
+    __shunit_constants=`set |grep -a '^__SHUNIT_' |cut -d= -f1`
+for __shunit_const in ${__shunit_constants}; do
+  if ${__SHUNIT_BUILTIN} [ -z "${ZSH_VERSION:-}" ]; then
+    readonly "${__shunit_const}"
+  else
+    case ${ZSH_VERSION} in
+      [123].*) readonly "${__shunit_const}" ;;
+      *)
+        # Declare readonly constants globally.
+        # shellcheck disable=SC2039,SC3045
+        readonly -g "${__shunit_const}"
+    esac
+  fi
+done
+unset __shunit_const __shunit_constants
 
 #-----------------------------------------------------------------------------
 # Assertion functions.
@@ -329,7 +330,7 @@ assertNotContains() {
 # shellcheck disable=SC2016,SC2034
 _ASSERT_NOT_CONTAINS_='eval assertNotContains --lineno "${LINENO:-}"'
 
-# Assert that a value is null (i.e. an empty string)
+# Assert that a value is null (i.e. an empty string).
 #
 # Args:
 #   message: string: failure message [optional]
@@ -339,7 +340,8 @@ _ASSERT_NOT_CONTAINS_='eval assertNotContains --lineno "${LINENO:-}"'
 assertNull() {
   # shellcheck disable=SC2090
   ${_SHUNIT_LINENO_}
-  if ${__SHUNIT_BUILTIN} [ $# -lt 1 -o $# -gt 2 ]; then
+  if ${__SHUNIT_BUILTIN} [ $# -gt 2 ]; then
+    # Allowing 0 arguments as $1 might actually be null.
     _shunit_error "assertNull() requires one or two arguments; $# given"
     _shunit_assertFail
     return ${SHUNIT_ERROR}
@@ -353,7 +355,9 @@ assertNull() {
     shunit_message_="${shunit_message_}$1"
     shift
   fi
-  assertTrue "${shunit_message_}" "[ -z '$1' ]"
+  
+  ${__SHUNIT_BUILTIN} test -z "${1:-}"
+  assertTrue "${shunit_message_}" $?
   shunit_return=$?
 
   unset shunit_message_
@@ -362,7 +366,7 @@ assertNull() {
 # shellcheck disable=SC2016,SC2034
 _ASSERT_NULL_='eval assertNull --lineno "${LINENO:-}"'
 
-# Assert that a value is not null (i.e. a non-empty string)
+# Assert that a value is not null (i.e. a non-empty string).
 #
 # Args:
 #   message: string: failure message [optional]
@@ -387,12 +391,12 @@ assertNotNull() {
     shunit_message_="${shunit_message_}$1"
     shift
   fi
-  shunit_actual_=`_shunit_escapeCharactersInString "${1:-}"`
-  test -n "${shunit_actual_}"
+
+  ${__SHUNIT_BUILTIN} test -n "${1:-}"
   assertTrue "${shunit_message_}" $?
   shunit_return=$?
 
-  unset shunit_actual_ shunit_message_
+  unset shunit_message_
   return ${shunit_return}
 }
 # shellcheck disable=SC2016,SC2034
@@ -702,11 +706,12 @@ failFound() {
     shunit_message_="${shunit_message_}$1"
     shift
   fi
+  shunit_content_=$1
 
   shunit_message_=${shunit_message_%% }
-  _shunit_assertFail "${shunit_message_:+${shunit_message_} }found"
+  _shunit_assertFail "${shunit_message_:+${shunit_message_} }found:<${shunit_content_}>"
 
-  unset shunit_message_
+  unset shunit_message_ shunit_content_
   return ${SHUNIT_FALSE}
 }
 # shellcheck disable=SC2016,SC2034
@@ -826,8 +831,11 @@ _FAIL_NOT_SAME_='eval failNotSame --lineno "${LINENO:-}"'
 # the total of asserts and fails will not be altered.
 #
 # Args:
-#   None
-startSkipping() { __shunit_skip=${SHUNIT_TRUE}; }
+#   message: string: message to provide to user [optional]
+startSkipping() {
+  if ${__SHUNIT_BUILTIN} [ $# -gt 0 ]; then _shunit_warn "[skipping] $*"; fi
+  __shunit_skip=${SHUNIT_TRUE}
+}
 
 # Resume the normal recording behavior of assert and fail calls.
 #
@@ -947,7 +955,7 @@ _shunit_mktempDir() {
   fi
 
   # The standard `mktemp` didn't work. Use our own.
-  # shellcheck disable=SC2039
+  # shellcheck disable=SC2039,SC3028
   if ${__SHUNIT_BUILTIN} [ -r '/dev/urandom' -a -x '/usr/bin/od' ]; then
     _shunit_random_=`/usr/bin/od -vAn -N4 -tx4 </dev/urandom |command sed 's/^[^0-9a-f]*//'`
   elif ${__SHUNIT_BUILTIN} [ -n "${RANDOM:-}" ]; then
@@ -1038,7 +1046,7 @@ _shunit_cleanup() {
 # configureColor based on user color preference.
 #
 # Args:
-#   color: string: color mode (one of `always`, `auto`, or `none`).
+#   color: string: color mode (one of `always`, `auto`, or `never`).
 _shunit_configureColor() {
   _shunit_color_=${SHUNIT_FALSE}  # By default, no color.
   case $1 in
@@ -1048,10 +1056,11 @@ _shunit_configureColor() {
         _shunit_color_=${SHUNIT_TRUE}
       fi
       ;;
-    'none') ;;
+    'never'|'none') ;;  # Support 'none' to support legacy usage.
     *) _shunit_fatal "unrecognized color option '$1'" ;;
   esac
 
+  # shellcheck disable=SC2254
   case ${_shunit_color_} in
     ${SHUNIT_TRUE})
       __shunit_ansi_none=${__SHUNIT_ANSI_NONE}
@@ -1093,9 +1102,9 @@ _shunit_execSuite() {
     # Disable skipping.
     endSkipping
 
-    # Execute the per-test setup function.
+    # Execute the per-test setUp() function.
     if ! setUp; then
-      _shunit_fatal "setup() returned non-zero return code."
+      _shunit_fatal "setUp() returned non-zero return code."
     fi
 
     # Execute the test.
@@ -1104,10 +1113,9 @@ _shunit_execSuite() {
     if ! eval ${_shunit_test_}; then
       _shunit_error "${_shunit_test_}() returned non-zero return code."
       __shunit_testSuccess=${SHUNIT_ERROR}
-      _shunit_incFailedCount
     fi
 
-    # Execute the per-test tear-down function.
+    # Execute the per-test tearDown() function.
     if ! tearDown; then
       _shunit_fatal "tearDown() returned non-zero return code."
     fi
@@ -1177,7 +1185,7 @@ _shunit_generateReport() {
 # Returns:
 #   boolean: whether the test should be skipped (TRUE/FALSE constant)
 _shunit_shouldSkip() {
-  if test ${__shunit_skip} -eq ${SHUNIT_FALSE}; then
+  if ${__SHUNIT_BUILTIN} test ${__shunit_skip} -eq ${SHUNIT_FALSE}; then
     return ${SHUNIT_FALSE}
   fi
   _shunit_assertSkip
@@ -1251,53 +1259,6 @@ _shunit_prepForSourcing() {
   unset _shunit_script_
 }
 
-# Escape a character in a string.
-#
-# Args:
-#   c: string: unescaped character
-#   s: string: to escape character in
-# Returns:
-#   string: with escaped character(s)
-_shunit_escapeCharInStr() {
-  if ${__SHUNIT_BUILTIN} [ -z "$2" ]; then
-    return  # No point in doing work on an empty string.
-  fi
-
-  # Note: using shorter variable names to prevent conflicts with
-  # _shunit_escapeCharactersInString().
-  _shunit_c_=$1
-  _shunit_s_=$2
-
-  # Escape the character.
-  # shellcheck disable=SC1003,SC2086
-  echo ''${_shunit_s_}'' |command sed 's/\'${_shunit_c_}'/\\\'${_shunit_c_}'/g'
-
-  unset _shunit_c_ _shunit_s_
-}
-
-# Escape a character in a string.
-#
-# Args:
-#   str: string: to escape characters in
-# Returns:
-#   string: with escaped character(s)
-_shunit_escapeCharactersInString() {
-  if ${__SHUNIT_BUILTIN} [ -z "$1" ]; then
-    return  # No point in doing work on an empty string.
-  fi
-
-  _shunit_str_=$1
-
-  # Note: using longer variable names to prevent conflicts with
-  # _shunit_escapeCharInStr().
-  for _shunit_char_ in '"' '$' "'" '`'; do
-    _shunit_str_=`_shunit_escapeCharInStr "${_shunit_char_}" "${_shunit_str_}"`
-  done
-
-  echo "${_shunit_str_}"
-  unset _shunit_char_ _shunit_str_
-}
-
 # Extract list of functions to run tests against.
 #
 # Args:
@@ -1344,7 +1305,7 @@ if ! command mkdir "${SHUNIT_TMPDIR}"; then
   _shunit_fatal "error creating SHUNIT_TMPDIR '${SHUNIT_TMPDIR}'"
 fi
 
-# Setup traps to clean up after ourselves.
+# Configure traps to clean up after ourselves.
 trap '_shunit_cleanup EXIT' 0
 trap '_shunit_cleanup INT' 2
 trap '_shunit_cleanup TERM' 15
diff --git a/lib/versions b/lib/versions
index b5533ab..e4ae518 100755
--- a/lib/versions
+++ b/lib/versions
@@ -51,6 +51,10 @@ versions_osName() {
         10.13|10.13.[0-9]*) os_name_='macOS High Sierra' ;;
         10.14|10.14.[0-9]*) os_name_='macOS Mojave' ;;
         10.15|10.15.[0-9]*) os_name_='macOS Catalina' ;;
+        11.*) os_name_='macOS Big Sur' ;;
+        12.*) os_name_='macOS Monterey' ;;
+        13.*) os_name_='macOS Ventura' ;;
+        14.*) os_name_='macOS Sonoma' ;;
         *) os_name_='macOS' ;;
       esac
       ;;
diff --git a/shflags b/shflags
index 5cfab3b..8eac39a 100644
--- a/shflags
+++ b/shflags
@@ -1,6 +1,6 @@
 # vim:et:ft=sh:sts=2:sw=2
 #
-# Copyright 2008-2020 Kate Ward. All Rights Reserved.
+# Copyright 2008-2023 Kate Ward. All Rights Reserved.
 # Released under the Apache License 2.0 license.
 # http://www.apache.org/licenses/LICENSE-2.0
 #
@@ -150,16 +150,16 @@ __FLAGS_LEVEL_DEFAULT=${FLAGS_LEVEL_WARN}
 __flags_level=${__FLAGS_LEVEL_DEFAULT} # Current logging level.
 
 _flags_debug() {
-  if [ ${__flags_level} -le ${FLAGS_LEVEL_DEBUG} ]; then echo "flags:DEBUG $*" >&2; fi
+  if [ "${__flags_level}" -le "${FLAGS_LEVEL_DEBUG}" ]; then echo "flags:DEBUG $*" >&2; fi
 }
 _flags_info() {
-  if [ ${__flags_level} -le ${FLAGS_LEVEL_INFO} ]; then echo "flags:INFO $*" >&2; fi
+  if [ "${__flags_level}" -le "${FLAGS_LEVEL_INFO}" ]; then echo "flags:INFO $*" >&2; fi
 }
 _flags_warn() {
-  if [ ${__flags_level} -le ${FLAGS_LEVEL_WARN} ]; then echo "flags:WARN $*" >&2; fi
+  if [ "${__flags_level}" -le "${FLAGS_LEVEL_WARN}" ]; then echo "flags:WARN $*" >&2; fi
 }
 _flags_error() {
-  if [ ${__flags_level} -le ${FLAGS_LEVEL_ERROR} ]; then echo "flags:ERROR $*" >&2; fi
+  if [ "${__flags_level}" -le "${FLAGS_LEVEL_ERROR}" ]; then echo "flags:ERROR $*" >&2; fi
 }
 _flags_fatal() {
   echo "flags:FATAL $*" >&2
@@ -167,7 +167,7 @@ _flags_fatal() {
 }
 
 # Get the logging level.
-flags_loggingLevel() { echo ${__flags_level}; }
+flags_loggingLevel() { echo "${__flags_level}"; }
 
 # Set the logging level by overriding the `__flags_level` variable.
 #
@@ -274,7 +274,7 @@ for __flags_const in ${__flags_constants}; do
     [123].*) readonly "${__flags_const}" ;;
     *)
       # Declare readonly constants globally.
-      # shellcheck disable=SC2039
+      # shellcheck disable=SC2039,SC3045
       readonly -g "${__flags_const}" ;;
   esac
 done
@@ -370,7 +370,7 @@ _flags_define() {
   # '!' is not done because it does not work on all shells.
   if [ ${_flags_return_} -eq ${FLAGS_TRUE} ]; then
     case ${_flags_type_} in
-      ${__FLAGS_TYPE_BOOLEAN})
+      "${__FLAGS_TYPE_BOOLEAN}")
         if _flags_validBool "${_flags_default_}"; then
           case ${_flags_default_} in
             true|t|0) _flags_default_=${FLAGS_TRUE} ;;
@@ -382,7 +382,7 @@ _flags_define() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_FLOAT})
+      "${__FLAGS_TYPE_FLOAT}")
         if _flags_validFloat "${_flags_default_}"; then
           :
         else
@@ -391,7 +391,7 @@ _flags_define() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_INTEGER})
+      "${__FLAGS_TYPE_INTEGER}")
         if _flags_validInt "${_flags_default_}"; then
           :
         else
@@ -400,7 +400,7 @@ _flags_define() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_STRING}) ;;  # Everything in shell is a valid string.
+      "${__FLAGS_TYPE_STRING}") ;;  # Everything in shell is a valid string.
 
       *)
         flags_error="unrecognized flag type '${_flags_type_}'"
@@ -470,7 +470,7 @@ _flags_genOptStr() {
       _flags_fatal 'call to _flags_type_ failed'
     fi
     case ${_flags_optStrType_} in
-      ${__FLAGS_OPTSTR_SHORT})
+      "${__FLAGS_OPTSTR_SHORT}")
         _flags_shortName_="`_flags_getFlagInfo \
             "${_flags_usName_}" "${__FLAGS_INFO_SHORT}"`"
         if [ "${_flags_shortName_}" != "${__FLAGS_NULL}" ]; then
@@ -481,7 +481,7 @@ _flags_genOptStr() {
         fi
         ;;
 
-      ${__FLAGS_OPTSTR_LONG})
+      "${__FLAGS_OPTSTR_LONG}")
         _flags_opts_="${_flags_opts_:+${_flags_opts_},}${_flags_name_}"
         # getopt needs a trailing ':' to indicate a required argument
         [ "${_flags_type_}" -ne "${__FLAGS_TYPE_BOOLEAN}" ] && \
@@ -519,7 +519,7 @@ _flags_getFlagInfo() {
   eval "${_flags_strToEval_}"
   if [ -n "${_flags_infoValue_}" ]; then
     # Special value '§' indicates no help string provided.
-    [ "${_flags_gFI_info_}" = ${__FLAGS_INFO_HELP} \
+    [ "${_flags_gFI_info_}" = "${__FLAGS_INFO_HELP}" \
         -a "${_flags_infoValue_}" = '§' ] && _flags_infoValue_=''
     flags_return=${FLAGS_TRUE}
   else
@@ -684,7 +684,7 @@ _flags_validInt() {
 #   integer: a FLAGS success condition
 _flags_getoptStandard() {
   flags_return=${FLAGS_TRUE}
-  _flags_shortOpts_=`_flags_genOptStr ${__FLAGS_OPTSTR_SHORT}`
+  _flags_shortOpts_=`_flags_genOptStr "${__FLAGS_OPTSTR_SHORT}"`
 
   # Check for spaces in passed options.
   for _flags_opt_ in "$@"; do
@@ -722,10 +722,10 @@ _flags_getoptStandard() {
 #   integer: a FLAGS success condition
 _flags_getoptEnhanced() {
   flags_return=${FLAGS_TRUE}
-  _flags_shortOpts_=`_flags_genOptStr ${__FLAGS_OPTSTR_SHORT}`
+  _flags_shortOpts_=`_flags_genOptStr "${__FLAGS_OPTSTR_SHORT}"`
   _flags_boolOpts_=`echo "${__flags_boolNames}" \
       |sed 's/^ *//;s/ *$//;s/ /,/g'`
-  _flags_longOpts_=`_flags_genOptStr ${__FLAGS_OPTSTR_LONG}`
+  _flags_longOpts_=`_flags_genOptStr "${__FLAGS_OPTSTR_LONG}"`
 
   __flags_opts=`${FLAGS_GETOPT_CMD} \
       -o "${_flags_shortOpts_}" \
@@ -761,6 +761,7 @@ _flags_parseGetopt() {
     set -- $@
   else
     # Note the quotes around the `$@` -- they are essential!
+    #  shellcheck disable=SC2294
     eval set -- "$@"
   fi
 
@@ -826,12 +827,11 @@ _flags_parseGetopt() {
 
     # Set new flag value.
     _flags_usName_=`_flags_underscoreName "${_flags_name_}"`
-    [ ${_flags_type_} -eq ${__FLAGS_TYPE_NONE} ] && \
-        _flags_type_=`_flags_getFlagInfo \
-            "${_flags_usName_}" ${__FLAGS_INFO_TYPE}`
+    [ "${_flags_type_}" -eq "${__FLAGS_TYPE_NONE}" ] && \
+        _flags_type_=`_flags_getFlagInfo "${_flags_usName_}" "${__FLAGS_INFO_TYPE}"`
     case ${_flags_type_} in
-      ${__FLAGS_TYPE_BOOLEAN})
-        if [ ${_flags_len_} -eq ${__FLAGS_LEN_LONG} ]; then
+      "${__FLAGS_TYPE_BOOLEAN}")
+        if [ "${_flags_len_}" -eq "${__FLAGS_LEN_LONG}" ]; then
           if [ "${_flags_arg_}" != "${__FLAGS_NULL}" ]; then
             eval "FLAGS_${_flags_usName_}=${FLAGS_TRUE}"
           else
@@ -850,7 +850,7 @@ _flags_parseGetopt() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_FLOAT})
+      "${__FLAGS_TYPE_FLOAT}")
         if _flags_validFloat "${_flags_arg_}"; then
           eval "FLAGS_${_flags_usName_}='${_flags_arg_}'"
         else
@@ -860,7 +860,7 @@ _flags_parseGetopt() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_INTEGER})
+      "${__FLAGS_TYPE_INTEGER}")
         if _flags_validInt "${_flags_arg_}"; then
           eval "FLAGS_${_flags_usName_}='${_flags_arg_}'"
         else
@@ -870,7 +870,7 @@ _flags_parseGetopt() {
         fi
         ;;
 
-      ${__FLAGS_TYPE_STRING})
+      "${__FLAGS_TYPE_STRING}")
         eval "FLAGS_${_flags_usName_}='${_flags_arg_}'"
         ;;
     esac
@@ -888,7 +888,7 @@ _flags_parseGetopt() {
 
     # Shift the option and non-boolean arguments out.
     shift
-    [ "${_flags_type_}" != ${__FLAGS_TYPE_BOOLEAN} ] && shift
+    [ "${_flags_type_}" != "${__FLAGS_TYPE_BOOLEAN}" ] && shift
   done
 
   # Give user back non-flag arguments.
@@ -923,6 +923,7 @@ _flags_math() {
     flags_return=$?
     unset _flags_expr_
   else
+    #  shellcheck disable=SC2294
     eval expr "$@"
     flags_return=$?
   fi
@@ -961,7 +962,7 @@ _flags_strlen() {
 #   None
 # Returns:
 #   bool: true if built-ins should be used
-_flags_useBuiltin() { return ${__FLAGS_USE_BUILTIN}; }
+_flags_useBuiltin() { return "${__FLAGS_USE_BUILTIN}"; }
 
 #------------------------------------------------------------------------------
 # public functions
@@ -979,12 +980,12 @@ _flags_useBuiltin() { return ${__FLAGS_USE_BUILTIN}; }
 # and whose short name was 'x', and the default value was 'false'. This flag
 # could be explicitly set to 'true' with '--update' or by '-x', and it could be
 # explicitly set to 'false' with '--noupdate'.
-DEFINE_boolean() { _flags_define ${__FLAGS_TYPE_BOOLEAN} "$@"; }
+DEFINE_boolean() { _flags_define "${__FLAGS_TYPE_BOOLEAN}" "$@"; }
 
 # Other basic flags.
-DEFINE_float()   { _flags_define ${__FLAGS_TYPE_FLOAT} "$@"; }
-DEFINE_integer() { _flags_define ${__FLAGS_TYPE_INTEGER} "$@"; }
-DEFINE_string()  { _flags_define ${__FLAGS_TYPE_STRING} "$@"; }
+DEFINE_float()   { _flags_define "${__FLAGS_TYPE_FLOAT}" "$@"; }
+DEFINE_integer() { _flags_define "${__FLAGS_TYPE_INTEGER}" "$@"; }
+DEFINE_string()  { _flags_define "${__FLAGS_TYPE_STRING}" "$@"; }
 
 # Parse the flags.
 #
@@ -1101,13 +1102,13 @@ flags_help() {
       flags_usName_=`_flags_underscoreName "${flags_name_}"`
 
       flags_default_=`_flags_getFlagInfo \
-          "${flags_usName_}" ${__FLAGS_INFO_DEFAULT}`
+          "${flags_usName_}" "${__FLAGS_INFO_DEFAULT}"`
       flags_help_=`_flags_getFlagInfo \
-          "${flags_usName_}" ${__FLAGS_INFO_HELP}`
+          "${flags_usName_}" "${__FLAGS_INFO_HELP}"`
       flags_short_=`_flags_getFlagInfo \
-          "${flags_usName_}" ${__FLAGS_INFO_SHORT}`
+          "${flags_usName_}" "${__FLAGS_INFO_SHORT}"`
       flags_type_=`_flags_getFlagInfo \
-          "${flags_usName_}" ${__FLAGS_INFO_TYPE}`
+          "${flags_usName_}" "${__FLAGS_INFO_TYPE}"`
 
       [ "${flags_short_}" != "${__FLAGS_NULL}" ] && \
           flags_flagStr_="-${flags_short_}"
@@ -1116,23 +1117,23 @@ flags_help() {
         [ "${flags_short_}" != "${__FLAGS_NULL}" ] && \
             flags_flagStr_="${flags_flagStr_},"
         # Add [no] to long boolean flag names, except the 'help' flag.
-        [ "${flags_type_}" -eq ${__FLAGS_TYPE_BOOLEAN} \
+        [ "${flags_type_}" -eq "${__FLAGS_TYPE_BOOLEAN}" \
           -a "${flags_usName_}" != 'help' ] && \
             flags_boolStr_='[no]'
         flags_flagStr_="${flags_flagStr_}--${flags_boolStr_}${flags_name_}:"
       fi
 
       case ${flags_type_} in
-        ${__FLAGS_TYPE_BOOLEAN})
+        "${__FLAGS_TYPE_BOOLEAN}")
           if [ "${flags_default_}" -eq ${FLAGS_TRUE} ]; then
             flags_defaultStr_='true'
           else
             flags_defaultStr_='false'
           fi
           ;;
-        ${__FLAGS_TYPE_FLOAT}|${__FLAGS_TYPE_INTEGER})
+        "${__FLAGS_TYPE_FLOAT}"|"${__FLAGS_TYPE_INTEGER}")
           flags_defaultStr_=${flags_default_} ;;
-        ${__FLAGS_TYPE_STRING}) flags_defaultStr_="'${flags_default_}'" ;;
+        "${__FLAGS_TYPE_STRING}") flags_defaultStr_="'${flags_default_}'" ;;
       esac
       flags_defaultStr_="(default: ${flags_defaultStr_})"
 
@@ -1201,7 +1202,7 @@ flags_reset() {
   __flags_definedNames=' '
 
   # Reset logging level back to default.
-  flags_setLoggingLevel ${__FLAGS_LEVEL_DEFAULT}
+  flags_setLoggingLevel "${__FLAGS_LEVEL_DEFAULT}"
 
   unset flags_name_ flags_type_ flags_strToEval_ flags_usName_
 }
diff --git a/shflags_issue_57.sh b/shflags_issue_57.sh
new file mode 100755
index 0000000..51f9788
--- /dev/null
+++ b/shflags_issue_57.sh
@@ -0,0 +1,66 @@
+#! /bin/sh
+# vim:et:ft=sh:sts=2:sw=2
+#
+# shFlags unit test for Issue #57.
+# https://github.com/kward/shflags/issues/57
+#
+# Copyright 2023 Kate Ward. All Rights Reserved.
+# Released under the Apache 2.0 license.
+#
+# Author: kate.ward@forestent.com (Kate Ward)
+# https://github.com/kward/shflags
+#
+### ShellCheck (http://www.shellcheck.net/)
+# Disable source following.
+#   shellcheck disable=SC1090,SC1091
+# $() are not fully portable (POSIX != portable).
+#   shellcheck disable=SC2006
+
+# These variables will be overridden by the test helpers.
+returnF="${TMPDIR:-/tmp}/return"
+stdoutF="${TMPDIR:-/tmp}/STDOUT"
+stderrF="${TMPDIR:-/tmp}/STDERR"
+
+# Load test helpers.
+. ./shflags_test_helpers
+
+# Test proper functionality with 'set -o pipefail' enabled.
+testIssue57() {
+  # shellcheck disable=SC3040
+  set -o pipefail
+
+  th_clearReturn
+  (
+    FLAGS -h >"${stdoutF}" 2>"${stderrF}"
+    echo $? >"${returnF}"
+  )
+
+  assertFalse \
+      'short help request should have returned a false exit code.' \
+      "$(th_queryReturn)"
+  ( grep 'show this help' "${stderrF}" >/dev/null )
+  r3turn=$?
+  assertTrue \
+      'short request for help should have produced some help output.' \
+      ${r3turn}
+  [ ${r3turn} -eq "${FLAGS_TRUE}" ] || th_showOutput
+}
+
+oneTimeSetUp() {
+  th_oneTimeSetUp
+
+  if flags_getoptIsStd; then
+    th_warn 'Standard version of getopt found. Enhanced tests will be skipped.'
+    return
+  fi
+  th_warn 'Enhanced version of getopt found. Standard tests will be skipped.'
+}
+
+setUp() {
+  flags_reset
+}
+
+# Load and run shUnit2.
+# shellcheck disable=SC2034
+[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
+. "${TH_SHUNIT}"
```

