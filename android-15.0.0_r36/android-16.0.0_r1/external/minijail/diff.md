```diff
diff --git a/.clang-format b/.clang-format
index 9320a7a..f306034 100644
--- a/.clang-format
+++ b/.clang-format
@@ -2,6 +2,8 @@ BasedOnStyle: LLVM
 IndentWidth: 8
 UseTab: Always
 BreakBeforeBraces: Linux
+AlignConsecutiveMacros: true
+AllowShortEnumsOnASingleLine: false
 AllowShortIfStatementsOnASingleLine: false
 AllowShortFunctionsOnASingleLine: false
 IndentCaseLabels: false
diff --git a/.github/workflows/coverity.yml b/.github/workflows/coverity.yml
index 42839cc..1713968 100644
--- a/.github/workflows/coverity.yml
+++ b/.github/workflows/coverity.yml
@@ -29,8 +29,7 @@ jobs:
     - uses: actions/checkout@v2
     - name: Install system packages
       run: sudo apt-get install -y libcap-dev
-    - uses: vapier/coverity-scan-action@v0
+    - uses: vapier/coverity-scan-action@v1
       with:
-        project: google%2Fminijail
-        email: vapier@google.com
+        email: ${{ secrets.COVERITY_SCAN_EMAIL }}
         token: ${{ secrets.COVERITY_SCAN_TOKEN }}
diff --git a/.gitignore b/.gitignore
index a0038c4..67c9478 100644
--- a/.gitignore
+++ b/.gitignore
@@ -32,7 +32,7 @@
 *.test
 
 # Google Test.
-googletest-release*
+googletest-*
 
 # Cargo build targets.
 /rust/**/target
@@ -45,3 +45,5 @@ minijail.code-workspace
 # IntelliJ projects.
 .idea
 
+# Generated code:
+/rust/minijail-sys/libminijail.rs
diff --git a/Android.bp b/Android.bp
index d24b58d..404076b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -99,6 +99,7 @@ cc_object {
         "-E",
         "-Wall",
         "-Werror",
+        "-Wno-unused-command-line-argument",
     ],
     apex_available: [
         "//apex_available:platform",
@@ -139,6 +140,7 @@ cc_object {
         "-E",
         "-Wall",
         "-Werror",
+        "-Wno-unused-command-line-argument",
     ],
     apex_available: [
         "//apex_available:platform",
@@ -210,6 +212,7 @@ cc_object {
         "-S",
         "-O0",
         "-emit-llvm",
+        "-Wno-unused-command-line-argument",
     ],
 
     target: {
@@ -232,6 +235,7 @@ cc_object {
         "-S",
         "-O0",
         "-emit-llvm",
+        "-Wno-unused-command-line-argument",
     ],
 
     target: {
diff --git a/DIR_METADATA b/DIR_METADATA
index 4a465c7..b93bad3 100644
--- a/DIR_METADATA
+++ b/DIR_METADATA
@@ -15,3 +15,25 @@ monorail {
 }
 
 team_email: "minijail@chromium.org"
+
+chromeos {
+  cq {
+    source_test_plans {
+      test_plan_starlark_files {
+        host: "chrome-internal.googlesource.com"
+        project: "chromeos/config-internal"
+        path: "test/plans/v2/ctpv1_compatible/legacy_default_tast_hw.star"
+      }
+      test_plan_starlark_files {
+        host: "chrome-internal.googlesource.com"
+        project: "chromeos/config-internal"
+        path: "test/plans/v2/ctpv1_compatible/legacy_default_autotest_hw.star"
+      }
+      test_plan_starlark_files {
+        host: "chrome-internal.googlesource.com"
+        project: "chromeos/config-internal"
+        path: "test/plans/v2/ctpv1_compatible/legacy_default_vm.star"
+      }
+    }
+  }
+}
diff --git a/Makefile b/Makefile
index 4759736..7c1cef8 100644
--- a/Makefile
+++ b/Makefile
@@ -2,7 +2,6 @@
 # Use of this source code is governed by a BSD-style license that can be
 # found in the LICENSE file.
 
-BASE_VER=0
 include common.mk
 
 LIBDIR ?= /lib
@@ -80,6 +79,14 @@ ifeq ($(BLOCK_SYMLINKS_IN_NONINIT_MOUNTNS_TMP),yes)
 CPPFLAGS += -DBLOCK_SYMLINKS_IN_NONINIT_MOUNTNS_TMP
 endif
 
+# If specified, the `libc_compatibility_syscalls` list will be silently added to
+# all allowlists. Intended for use when upgrading core libraries (mainly libc),
+# which can lead to new syscalls being introduced in many places.
+USE_LIBC_COMPATIBILITY_ALLOWLIST ?= no
+ifeq ($(USE_LIBC_COMPATIBILITY_ALLOWLIST),yes)
+CPPFLAGS += -DALLOW_LIBC_COMPATIBILITY_SYSCALLS
+endif
+
 ifeq ($(USE_ASAN),yes)
 CPPFLAGS += -fsanitize=address -fno-omit-frame-pointer
 LDFLAGS += -fsanitize=address -fno-omit-frame-pointer
@@ -108,7 +115,7 @@ UNITTEST_DEPS := testrunner.o test_util.o
 
 USE_SYSTEM_GTEST ?= no
 ifeq ($(USE_SYSTEM_GTEST),no)
-GTEST_CXXFLAGS := -std=gnu++14
+GTEST_CXXFLAGS := -std=gnu++20
 GTEST_LIBS := gtest.a
 UNITTEST_DEPS += $(GTEST_LIBS)
 else
@@ -117,6 +124,7 @@ GTEST_CXXFLAGS := $(shell gtest-config --cxxflags 2>/dev/null || \
 GTEST_LIBS := $(shell gtest-config --libs 2>/dev/null || \
   echo "-lgtest -pthread -lpthread")
 endif
+GTEST_CXXFLAGS += -DGTEST_REMOVE_LEGACY_TEST_CASEAPI_
 UNITTEST_LIBS += $(GTEST_LIBS)
 
 CORE_OBJECT_FILES := libminijail.o syscall_filter.o signal_handler.o \
@@ -250,7 +258,7 @@ $(eval $(call add_object_rules,libconstants.gen.o,CC,c,CFLAGS))
 ifeq ($(USE_SYSTEM_GTEST),no)
 # Points to the root of Google Test, relative to where this file is.
 # Remember to tweak this if you move this file.
-GTEST_DIR = googletest-release-1.11.0/googletest
+GTEST_DIR = googletest-1.14.0/googletest
 
 # Flags passed to the preprocessor.
 # Set Google Test's header directory as a system directory, such that
diff --git a/OWNERS b/OWNERS
index 39d7470..f8d4080 100644
--- a/OWNERS
+++ b/OWNERS
@@ -8,3 +8,4 @@ victorhsieh@google.com
 # Emeritus.
 #drewry@google.com
 #keescook@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/PRESUBMIT.cfg b/PRESUBMIT.cfg
index a7ce524..8ed46e3 100644
--- a/PRESUBMIT.cfg
+++ b/PRESUBMIT.cfg
@@ -9,3 +9,7 @@ aosp_license_check: false
 
 [Hook Overrides Options]
 cros_license_check: --exclude_regex=^test/
+
+[Hook Scripts]
+cros format = cros format --check --include '*.py' --exclude 'linux-x86/*.gen.c' --exclude 'test_util.h' --exclude 'unittest_util.h' --include '*.[ch]' --include '*.policy' --include '*.conf' --include .gitignore --exclude '*' --commit ${PRESUBMIT_COMMIT} ${PRESUBMIT_FILES}
+cros lint = cros lint --include '*.py' --exclude '*.[ch]' --exclude '*.cpp' --exclude '*.cc' --exclude 'test/*.policy' --exclude 'policies/cros_default_v0.policy' --exclude 'examples/*.policy' --exclude 'rust/minijail/src/test_*.policy' --commit ${PRESUBMIT_COMMIT} ${PRESUBMIT_FILES}
diff --git a/README.md b/README.md
index fea1fe6..a33d4a9 100644
--- a/README.md
+++ b/README.md
@@ -58,6 +58,36 @@ We've got a couple of contact points.
 [crbug.com/new]: https://bugs.chromium.org/p/chromium/issues/entry?components=OS>Systems>Minijail
 [Chromium Gerrit]: https://chromium-review.googlesource.com/q/project:chromiumos/platform/minijail
 
+## GitHub Pages homepage
+
+The https://google.github.io/minijail/ homepage is maintained in the `gh-pages`
+branch, not in the `main` branch.
+Changes to it can be sent via Gerrit, but requires a little extra work.
+
+```shell
+# Make sure you have all the branches, and not only the "main" one.
+$ git fetch
+
+# Create a new local branch tracking the remote "gh-pages".
+# Git should automatically detect the remote and track it for you.
+$ git checkout gh-pages
+# If git can't auto-detect the remote, try one of these.
+$ git checkout -b gh-pages origin/gh-pages
+$ git checkout -b gh-pages cros/gh-pages
+
+# Make your changes like normal, then push them to Gerrit for review.
+# Here's a couple of different ways to post changes; you only need one!
+$ repo upload -D gh-pages
+$ git push origin HEAD:refs/for/gh-pages
+$ git push cros HEAD:refs/for/gh-pages
+
+# Now review your changes via Gerrit like normal.
+```
+
+Once a change merges into the `gh-pages` branch, there is no additional work for
+you other than waiting -- GitHub periodically syncs with our host, and then it
+will automatically regenerate the homepage when the `gh-pages` branch updates.
+
 ## Talks and presentations
 
 The following talk serves as a good introduction to Minijail and how it can be used.
@@ -68,7 +98,7 @@ The following talk serves as a good introduction to Minijail and how it can be u
 ## Example usage
 
 The ChromiumOS project has a comprehensive
-[sandboxing](https://chromium.googlesource.com/chromiumos/docs/+/master/sandboxing.md)
+[sandboxing](https://www.chromium.org/chromium-os/developer-library/guides/development/sandboxing)
 document that is largely based on Minijail.
 
 After you play with the simple examples below, you should check that out.
diff --git a/bpf.c b/bpf.c
index 3c60b47..79ea02a 100644
--- a/bpf.c
+++ b/bpf.c
@@ -232,7 +232,7 @@ size_t bpf_arg_comp(struct sock_filter **pfilter, int op, int argidx,
 	struct sock_filter *filter =
 	    calloc(filter_len, sizeof(struct sock_filter));
 	struct sock_filter *curr_block = filter;
-	size_t (*comp_function)(struct sock_filter * filter, unsigned long k,
+	size_t (*comp_function)(struct sock_filter *filter, unsigned long k,
 				unsigned char jt, unsigned char jf);
 	int flip = 0;
 
@@ -279,6 +279,8 @@ size_t bpf_arg_comp(struct sock_filter **pfilter, int op, int argidx,
 		flip = 0;
 		break;
 	default:
+		curr_block = filter;
+		free(filter);
 		*pfilter = NULL;
 		return 0;
 	}
diff --git a/bpf.h b/bpf.h
index 900a828..c7fcf09 100644
--- a/bpf.h
+++ b/bpf.h
@@ -9,7 +9,7 @@
 #ifndef BPF_H
 #define BPF_H
 
-#include <asm/bitsperlong.h>   /* for __BITS_PER_LONG */
+#include <asm/bitsperlong.h> /* for __BITS_PER_LONG */
 #include <endian.h>
 #include <linux/audit.h>
 #include <linux/filter.h>
@@ -55,7 +55,7 @@ enum {
 #define SECCOMP_RET_LOG		 0x7ffc0000U /* allow after logging */
 #define SECCOMP_RET_ALLOW	 0x7fff0000U /* allow */
 
-#define SECCOMP_RET_DATA	 0x0000ffffU /* mask for return value */
+#define SECCOMP_RET_DATA 0x0000ffffU /* mask for return value */
 
 struct seccomp_data {
 	int nr;
@@ -65,7 +65,7 @@ struct seccomp_data {
 };
 
 #define syscall_nr (offsetof(struct seccomp_data, nr))
-#define arch_nr (offsetof(struct seccomp_data, arch))
+#define arch_nr	   (offsetof(struct seccomp_data, arch))
 
 /* Size-dependent defines. */
 #if defined(BITS32)
@@ -73,17 +73,18 @@ struct seccomp_data {
  * On 32 bits, comparisons take 2 instructions: 1 for loading the argument,
  * 1 for the actual comparison.
  */
-#define BPF_LOAD_ARG_LEN		1U
-#define BPF_COMP_LEN			1U
-#define BPF_SHORT_GT_GE_COMP_LEN	1U
-#define BPF_GT_GE_COMP_LEN		1U
-#define BPF_ARG_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
-#define BPF_ARG_SHORT_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
+#define BPF_LOAD_ARG_LEN	 1U
+#define BPF_COMP_LEN		 1U
+#define BPF_SHORT_GT_GE_COMP_LEN 1U
+#define BPF_GT_GE_COMP_LEN	 1U
+#define BPF_ARG_COMP_LEN	 (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
+#define BPF_ARG_SHORT_GT_GE_COMP_LEN                                           \
+	(BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
 #define BPF_ARG_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_GT_GE_COMP_LEN)
 
-#define bpf_comp_jeq bpf_comp_jeq32
-#define bpf_comp_jgt bpf_comp_jgt32
-#define bpf_comp_jge bpf_comp_jge32
+#define bpf_comp_jeq  bpf_comp_jeq32
+#define bpf_comp_jgt  bpf_comp_jgt32
+#define bpf_comp_jge  bpf_comp_jge32
 #define bpf_comp_jset bpf_comp_jset32
 
 #define LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
@@ -93,17 +94,18 @@ struct seccomp_data {
  * On 64 bits, comparisons take 7-8 instructions: 4 for loading the argument,
  * and 3-4 for the actual comparison.
  */
-#define BPF_LOAD_ARG_LEN		4U
-#define BPF_COMP_LEN			3U
-#define BPF_SHORT_GT_GE_COMP_LEN	3U
-#define BPF_GT_GE_COMP_LEN		4U
-#define BPF_ARG_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
-#define BPF_ARG_SHORT_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
+#define BPF_LOAD_ARG_LEN	 4U
+#define BPF_COMP_LEN		 3U
+#define BPF_SHORT_GT_GE_COMP_LEN 3U
+#define BPF_GT_GE_COMP_LEN	 4U
+#define BPF_ARG_COMP_LEN	 (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
+#define BPF_ARG_SHORT_GT_GE_COMP_LEN                                           \
+	(BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
 #define BPF_ARG_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_GT_GE_COMP_LEN)
 
-#define bpf_comp_jeq bpf_comp_jeq64
-#define bpf_comp_jgt bpf_comp_jgt64
-#define bpf_comp_jge bpf_comp_jge64
+#define bpf_comp_jeq  bpf_comp_jeq64
+#define bpf_comp_jgt  bpf_comp_jgt64
+#define bpf_comp_jge  bpf_comp_jge64
 #define bpf_comp_jset bpf_comp_jset64
 
 /* Ensure that we load the logically correct offset. */
@@ -120,19 +122,19 @@ struct seccomp_data {
 #endif
 
 /* Common jump targets. */
-#define NEXT 0
-#define SKIP 1
+#define NEXT	  0
+#define SKIP	  1
 #define SKIPN(_n) (_n)
 
 /* Support for labels in BPF programs. */
-#define JUMP_JT 0xff
-#define JUMP_JF 0xff
+#define JUMP_JT	 0xff
+#define JUMP_JF	 0xff
 #define LABEL_JT 0xfe
 #define LABEL_JF 0xfe
 
 #define MAX_BPF_LABEL_LEN 32
 
-#define BPF_LABELS_MAX 512U	/* Each syscall could have an argument block. */
+#define BPF_LABELS_MAX 512U /* Each syscall could have an argument block. */
 struct bpf_labels {
 	size_t count;
 	struct __bpf_label {
@@ -153,45 +155,43 @@ static inline size_t set_bpf_instr(struct sock_filter *instr,
 	return 1U;
 }
 
-#define set_bpf_stmt(_block, _code, _k) \
+#define set_bpf_stmt(_block, _code, _k)                                        \
 	set_bpf_instr((_block), (_code), (_k), 0, 0)
 
-#define set_bpf_jump(_block, _code, _k, _jt, _jf) \
+#define set_bpf_jump(_block, _code, _k, _jt, _jf)                              \
 	set_bpf_instr((_block), (_code), (_k), (_jt), (_jf))
 
-#define set_bpf_lbl(_block, _lbl_id) \
-	set_bpf_jump((_block), BPF_JMP+BPF_JA, (_lbl_id), \
-			LABEL_JT, LABEL_JF)
+#define set_bpf_lbl(_block, _lbl_id)                                           \
+	set_bpf_jump((_block), BPF_JMP + BPF_JA, (_lbl_id), LABEL_JT, LABEL_JF)
 
-#define set_bpf_jump_lbl(_block, _lbl_id) \
-	set_bpf_jump((_block), BPF_JMP+BPF_JA, (_lbl_id), \
-			JUMP_JT, JUMP_JF)
+#define set_bpf_jump_lbl(_block, _lbl_id)                                      \
+	set_bpf_jump((_block), BPF_JMP + BPF_JA, (_lbl_id), JUMP_JT, JUMP_JF)
 
-#define set_bpf_ret_kill(_block) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_KILL)
+#define set_bpf_ret_kill(_block)                                               \
+	set_bpf_stmt((_block), BPF_RET + BPF_K, SECCOMP_RET_KILL)
 
-#define set_bpf_ret_kill_process(_block) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
+#define set_bpf_ret_kill_process(_block)                                       \
+	set_bpf_stmt((_block), BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS)
 
-#define set_bpf_ret_trap(_block) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_TRAP)
+#define set_bpf_ret_trap(_block)                                               \
+	set_bpf_stmt((_block), BPF_RET + BPF_K, SECCOMP_RET_TRAP)
 
-#define set_bpf_ret_errno(_block, _errno) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, \
-		SECCOMP_RET_ERRNO | ((_errno) & SECCOMP_RET_DATA))
+#define set_bpf_ret_errno(_block, _errno)                                      \
+	set_bpf_stmt((_block), BPF_RET + BPF_K,                                \
+		     SECCOMP_RET_ERRNO | ((_errno) & SECCOMP_RET_DATA))
 
-#define set_bpf_ret_log(_block) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_LOG)
+#define set_bpf_ret_log(_block)                                                \
+	set_bpf_stmt((_block), BPF_RET + BPF_K, SECCOMP_RET_LOG)
 
-#define set_bpf_ret_allow(_block) \
-	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
+#define set_bpf_ret_allow(_block)                                              \
+	set_bpf_stmt((_block), BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
 
-#define bpf_load_syscall_nr(_filter) \
-	set_bpf_stmt((_filter), BPF_LD+BPF_W+BPF_ABS, syscall_nr)
+#define bpf_load_syscall_nr(_filter)                                           \
+	set_bpf_stmt((_filter), BPF_LD + BPF_W + BPF_ABS, syscall_nr)
 
 /* BPF label functions. */
-int bpf_resolve_jumps(struct bpf_labels *labels,
-		struct sock_filter *filter, size_t count);
+int bpf_resolve_jumps(struct bpf_labels *labels, struct sock_filter *filter,
+		      size_t count);
 int bpf_label_id(struct bpf_labels *labels, const char *label);
 void free_label_strings(struct bpf_labels *labels);
 
@@ -210,14 +210,14 @@ size_t bpf_comp_jin(struct sock_filter *filter, unsigned long mask,
 
 /* Functions called by syscall_filter.c */
 #define ARCH_VALIDATION_LEN 3U
-#define ALLOW_SYSCALL_LEN 2U
+#define ALLOW_SYSCALL_LEN   2U
 
-size_t bpf_arg_comp(struct sock_filter **pfilter,
-		int op, int argidx, unsigned long c, unsigned int label_id);
+size_t bpf_arg_comp(struct sock_filter **pfilter, int op, int argidx,
+		    unsigned long c, unsigned int label_id);
 size_t bpf_validate_arch(struct sock_filter *filter);
 size_t bpf_allow_syscall(struct sock_filter *filter, int nr);
-size_t bpf_allow_syscall_args(struct sock_filter *filter,
-		int nr, unsigned int id);
+size_t bpf_allow_syscall_args(struct sock_filter *filter, int nr,
+			      unsigned int id);
 
 #ifdef __cplusplus
 }; /* extern "C" */
diff --git a/common.mk b/common.mk
index 48fe830..03e886c 100644
--- a/common.mk
+++ b/common.mk
@@ -7,7 +7,7 @@
 #
 # NOTE NOTE NOTE
 #  The authoritative common.mk is located in:
-#    https://chromium.googlesource.com/chromiumos/platform2/+/master/common-mk
+#    https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/common-mk
 #  Please make all changes there, then copy into place in other repos.
 # NOTE NOTE NOTE
 #
@@ -63,7 +63,7 @@
 #
 # Possible command line variables:
 #   - COLOR=[0|1] to set ANSI color output (default: 1)
-#   - VERBOSE=[0|1] to hide/show commands (default: 0)
+#   - VERBOSE=[0|1] V=[0|1] to hide/show commands (default: 0)
 #   - MODE=[opt|dbg|profiling] (default: opt)
 #          opt - Enable optimizations for release builds
 #          dbg - Turn down optimization for debugging
@@ -98,7 +98,8 @@ SPLITDEBUG ?= 0
 NOSTRIP ?= 1
 VALGRIND ?= 0
 COLOR ?= 1
-VERBOSE ?= 0
+V ?= 0
+VERBOSE ?= $(V)
 MODE ?= opt
 CXXEXCEPTIONS ?= 0
 RUN_TESTS ?= 1
@@ -123,13 +124,6 @@ override OUT := $(realpath $(OUT))/
 # $(PWD) != $(CURDIR) all the time.
 export SRC ?= $(CURDIR)
 
-# If BASE_VER is not set, read the libchrome revision number from
-# common-mk/BASE_VER file.
-ifeq ($(strip $(BASE_VER)),)
-BASE_VER := $(shell cat $(SRC)/../common-mk/BASE_VER)
-endif
-$(info Using BASE_VER=$(BASE_VER))
-
 # Re-start in the $(OUT) directory if we're not there.
 # We may be invoked using -C or bare and we need to ensure behavior
 # is consistent so we check both PWD vs OUT and PWD vs CURDIR.
@@ -266,13 +260,13 @@ $(eval $(call override_var,STRIP,strip))
 RMDIR ?= rmdir
 ECHO = /bin/echo -e
 
-ifeq ($(lastword $(subst /, ,$(CC))),clang)
+ifeq ($(filter clang,$(subst -, ,$(notdir $(CC)))),clang)
 CDRIVER = clang
 else
 CDRIVER = gcc
 endif
 
-ifeq ($(lastword $(subst /, ,$(CXX))),clang++)
+ifeq ($(filter clang++,$(subst -, ,$(notdir $(CXX)))),clang++)
 CXXDRIVER = clang
 else
 CXXDRIVER = gcc
@@ -318,12 +312,24 @@ endif
 #  CXXFLAGS := $(filter-out badflag,$(CXXFLAGS)) # Filter out a value
 # The same goes for CFLAGS.
 COMMON_CFLAGS-gcc := -fvisibility=internal -ggdb3 -Wa,--noexecstack
-COMMON_CFLAGS-clang := -fvisibility=hidden -ggdb
-COMMON_CFLAGS := -Wall -Wunused -Wno-unused-parameter -Werror -Wformat=2 \
-  -fno-strict-aliasing $(SSP_CFLAGS) -O1
-CXXFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CXXDRIVER)) -std=gnu++14
-CFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CDRIVER)) -std=gnu11
-CPPFLAGS += -D_FORTIFY_SOURCE=2
+COMMON_CFLAGS-clang := -fvisibility=hidden -ggdb -Wimplicit-fallthrough \
+  -Wstring-plus-int
+# When a class is exported through __attribute__((visibility("default"))), we
+# still want to eliminate symbols from inline class member functions to reduce
+# symbol resolution overhead. Therefore, pass -fvisibility-inlines-hidden in
+# addition to -fvisibility=hidden. (go/cros-symbol-slimming)
+COMMON_CFLAGS := -Wall -Wunused -Wno-unused-parameter -Wunreachable-code \
+  -Wbool-operation -Wstring-compare $(call check_cc,-Wxor-used-as-pow) \
+  -Wint-in-bool-context -Wfree-nonheap-object \
+  -Werror -Wformat=2 -fno-strict-aliasing  \
+  $(SSP_CFLAGS) -O1
+CXXFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CXXDRIVER)) -std=gnu++20 \
+  -fvisibility-inlines-hidden
+CFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CDRIVER)) -std=gnu17
+# We undefine _FORTIFY_SOURCE because some distros enable it by default in
+# their toolchains.  This makes the compiler issue warnings about redefines
+# and our -Werror usage breaks it all.
+CPPFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
 
 # Enable large file support.
 CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
@@ -352,7 +358,14 @@ ifeq ($(MODE),profiling)
   LDFLAGS := $(LDFLAGS) --coverage
 endif
 
-LDFLAGS := $(LDFLAGS) -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now
+# Pass -Bsymbolic-non-weak which pre-binds symbols in the same DSO to improve
+# startup performance. We don't support interposing non-weak symbols.
+# (go/cros-symbol-slimming)
+LDFLAGS := $(LDFLAGS) \
+  -z relro \
+  -z noexecstack \
+  -z now \
+  $(call check_cc,-Xlinker -Bsymbolic-non-weak)
 
 # Fancy helpers for color if a prompt is defined
 ifeq ($(COLOR),1)
diff --git a/config_parser.c b/config_parser.c
index 9b3aa22..234d91f 100644
--- a/config_parser.c
+++ b/config_parser.c
@@ -128,12 +128,16 @@ bool parse_config_file(FILE *config_file, struct config_entry_list *list)
 		}
 		++list->num_entries;
 	}
+
 	/*
 	 * getmultiline() behaves similarly with getline(3). It returns -1
-	 * when read into EOF or the following errors.
-	 * Caveat: EINVAL may happen when EOF is encountered in a valid stream.
+	 * when read into EOF or an error occurs.  Since errno is not cleared
+	 * on success or when EOF is reached, the value might be held over from
+	 * a different call, so we can't rely on it directly, at least not w/out
+	 * refactoring the loop above to clear+check it around the getline call.
+	 * Instead, let's just check if the file has been completely read.
 	 */
-	if ((errno == EINVAL && config_file == NULL) || errno == ENOMEM) {
+	if (!feof(config_file)) {
 		return false;
 	}
 
diff --git a/config_parser_unittest.cc b/config_parser_unittest.cc
index 2e4ad17..4f026b7 100644
--- a/config_parser_unittest.cc
+++ b/config_parser_unittest.cc
@@ -15,20 +15,20 @@
 namespace {
 
 class ConfigFileTest : public ::testing::Test {
-protected:
+ protected:
   virtual void SetUp() {
     list_ = new_config_entry_list();
     ASSERT_NE(list_, nullptr);
   }
   virtual void TearDown() { free_config_entry_list(list_); }
-  struct config_entry_list *list_;
+  struct config_entry_list* list_;
 };
 
-} // namespace
+}  // namespace
 
 TEST(ParsingConfigTest, valid_config_line) {
   ScopedConfigEntry entry(
-      (config_entry *)calloc(1, sizeof(struct config_entry)));
+      (config_entry*)calloc(1, sizeof(struct config_entry)));
   const std::vector<std::string> valid_conf_lines = {
       "mount=none",
       "valueless_key"
@@ -44,7 +44,7 @@ TEST(ParsingConfigTest, valid_config_line) {
 
 TEST(ParsingConfigTest, invalid_config_line) {
   ScopedConfigEntry entry(
-      (config_entry *)calloc(1, sizeof(struct config_entry)));
+      (config_entry*)calloc(1, sizeof(struct config_entry)));
   const std::vector<std::string> invalid_conf_lines = {
       "= none",
       "",
@@ -58,8 +58,9 @@ TEST(ParsingConfigTest, invalid_config_line) {
 }
 
 TEST_F(ConfigFileTest, malformed_config_line) {
-  std::string config = "% minijail-config-file v0\n"
-                       "=malformed";
+  std::string config =
+      "% minijail-config-file v0\n"
+      "=malformed";
   ScopedFILE config_file(write_to_pipe(config));
   ASSERT_NE(config_file.get(), nullptr);
 
@@ -71,8 +72,9 @@ TEST_F(ConfigFileTest, malformed_config_line) {
 }
 
 TEST_F(ConfigFileTest, bad_directive) {
-  std::string config = "% bad-directive\n"
-                       "# comments";
+  std::string config =
+      "% bad-directive\n"
+      "# comments";
   ScopedFILE config_file(write_to_pipe(config));
   ASSERT_NE(config_file.get(), nullptr);
 
@@ -84,12 +86,13 @@ TEST_F(ConfigFileTest, bad_directive) {
 }
 
 TEST_F(ConfigFileTest, wellformed_single_line) {
-  std::string config = "% minijail-config-file v0\n"
-                       "# Comments \n"
-                       "\n"
-                       "uts\n"
-                       "mount= xyz\n"
-                       "binding = none,/tmp";
+  std::string config =
+      "% minijail-config-file v0\n"
+      "# Comments \n"
+      "\n"
+      "uts\n"
+      "mount= xyz\n"
+      "binding = none,/tmp";
   ScopedFILE config_file(write_to_pipe(config));
   ASSERT_NE(config_file.get(), nullptr);
 
@@ -97,9 +100,9 @@ TEST_F(ConfigFileTest, wellformed_single_line) {
 
   ASSERT_TRUE(res);
   ASSERT_EQ(list_->num_entries, 3);
-  struct config_entry *first_entry = list_->entries;
-  struct config_entry *second_entry = list_->entries + 1;
-  struct config_entry *third_entry = list_->entries + 2;
+  struct config_entry* first_entry = list_->entries;
+  struct config_entry* second_entry = list_->entries + 1;
+  struct config_entry* third_entry = list_->entries + 2;
   ASSERT_EQ(std::string(first_entry->key), "uts");
   ASSERT_EQ(first_entry->value, nullptr);
   ASSERT_EQ(std::string(second_entry->key), "mount");
@@ -109,13 +112,14 @@ TEST_F(ConfigFileTest, wellformed_single_line) {
 }
 
 TEST_F(ConfigFileTest, wellformed_multi_line) {
-  std::string config = "% minijail-config-file v0\n"
-                       "# Comments \n"
-                       "\n"
-                       "mount = \\\n"
-                       "none\n"
-                       "binding = none,\\\n"
-                       "/tmp";
+  std::string config =
+      "% minijail-config-file v0\n"
+      "# Comments \n"
+      "\n"
+      "mount = \\\n"
+      "none\n"
+      "binding = none,\\\n"
+      "/tmp";
   ScopedFILE config_file(write_to_pipe(config));
   ASSERT_NE(config_file.get(), nullptr);
 
@@ -123,8 +127,8 @@ TEST_F(ConfigFileTest, wellformed_multi_line) {
 
   ASSERT_TRUE(res);
   ASSERT_EQ(list_->num_entries, 2);
-  struct config_entry *first_entry = list_->entries;
-  struct config_entry *second_entry = list_->entries + 1;
+  struct config_entry* first_entry = list_->entries;
+  struct config_entry* second_entry = list_->entries + 1;
   ASSERT_EQ(std::string(first_entry->key), "mount");
   ASSERT_EQ(std::string(first_entry->value), "none");
   ASSERT_EQ(std::string(second_entry->key), "binding");
diff --git a/dump_constants.cc b/dump_constants.cc
index 6a0a3ba..8491128 100644
--- a/dump_constants.cc
+++ b/dump_constants.cc
@@ -40,8 +40,8 @@ int main() {
       first = false;
     else
       std::cout << ",\n";
-    std::cout << "    \"" << entry->name << "\": "
-	      << std::to_string(entry->value);
+    std::cout << "    \"" << entry->name
+              << "\": " << std::to_string(entry->value);
   }
   std::cout << "\n  }\n";
   std::cout << "}\n";
diff --git a/elfparse.c b/elfparse.c
index 958a8cd..fd30d29 100644
--- a/elfparse.c
+++ b/elfparse.c
@@ -13,59 +13,58 @@
 #include "elfparse.h"
 #include "util.h"
 
-int is_elf_magic (const uint8_t *buf)
+int is_elf_magic(const uint8_t *buf)
 {
-	return (buf[EI_MAG0] == ELFMAG0) &&
-	       (buf[EI_MAG1] == ELFMAG1) &&
-	       (buf[EI_MAG2] == ELFMAG2) &&
-	       (buf[EI_MAG3] == ELFMAG3);
+	return (buf[EI_MAG0] == ELFMAG0) && (buf[EI_MAG1] == ELFMAG1) &&
+	       (buf[EI_MAG2] == ELFMAG2) && (buf[EI_MAG3] == ELFMAG3);
 }
 
-#define parseElftemplate(bit)                                                \
-ElfType parseElf ## bit(FILE *elf_file, uint8_t *pHead, int little_endian)   \
-{                                                                            \
-	ElfType                      ret          = ELFSTATIC;               \
-	Minijail_Elf ## bit ## _Ehdr *pHeader     = NULL;                    \
-	Minijail_Elf ## bit ## _Phdr pheader;                                \
-	uint32_t                     i            = 0;                       \
-	                                                                     \
-	if (!elf_file || !pHead)                                             \
-		return ELFERROR;                                             \
-	                                                                     \
-	pHeader = (Minijail_Elf ## bit ## _Ehdr *)pHead;                     \
-	if (little_endian) {                                                 \
-		pHeader->e_phoff = le ## bit ## toh(pHeader->e_phoff);       \
-		pHeader->e_phentsize = le16toh(pHeader->e_phentsize);        \
-		pHeader->e_phnum = le16toh(pHeader->e_phnum);                \
-	} else {                                                             \
-		pHeader->e_phoff = be ## bit ## toh(pHeader->e_phoff);       \
-		pHeader->e_phentsize = be16toh(pHeader->e_phentsize);        \
-		pHeader->e_phnum = be16toh(pHeader->e_phnum);                \
-	}                                                                    \
-	if (pHeader->e_phentsize != sizeof(Minijail_Elf ## bit ## _Phdr))    \
-		return ELFERROR;                                             \
-	                                                                     \
-	if (fseek(elf_file, pHeader->e_phoff, SEEK_SET) != 0)                \
-		return ELFERROR;                                             \
-	                                                                     \
-	for (i = 0; i < pHeader->e_phnum; i++) {                             \
-		if (fread(&pheader, sizeof(pheader), 1, elf_file) == 1) {    \
-			if (pheader.p_type == PT_INTERP) {                   \
-				ret = ELFDYNAMIC;                            \
-				break;                                       \
-			}                                                    \
-		} else {                                                     \
-			ret = ELFERROR;                                      \
-			break;                                               \
-		}                                                            \
-	}                                                                    \
-	return ret;                                                          \
-}
-parseElftemplate(64)
-parseElftemplate(32)
+#define parseElftemplate(bit)                                                  \
+	ElfType parseElf##bit(FILE *elf_file, uint8_t *pHead,                  \
+			      int little_endian)                               \
+	{                                                                      \
+		ElfType ret = ELFSTATIC;                                       \
+		Minijail_Elf##bit##_Ehdr *pHeader = NULL;                      \
+		Minijail_Elf##bit##_Phdr pheader;                              \
+		uint32_t i = 0;                                                \
+                                                                               \
+		if (!elf_file || !pHead)                                       \
+			return ELFERROR;                                       \
+                                                                               \
+		pHeader = (Minijail_Elf##bit##_Ehdr *)pHead;                   \
+		if (little_endian) {                                           \
+			pHeader->e_phoff = le##bit##toh(pHeader->e_phoff);     \
+			pHeader->e_phentsize = le16toh(pHeader->e_phentsize);  \
+			pHeader->e_phnum = le16toh(pHeader->e_phnum);          \
+		} else {                                                       \
+			pHeader->e_phoff = be##bit##toh(pHeader->e_phoff);     \
+			pHeader->e_phentsize = be16toh(pHeader->e_phentsize);  \
+			pHeader->e_phnum = be16toh(pHeader->e_phnum);          \
+		}                                                              \
+		if (pHeader->e_phentsize != sizeof(Minijail_Elf##bit##_Phdr))  \
+			return ELFERROR;                                       \
+                                                                               \
+		if (fseek(elf_file, pHeader->e_phoff, SEEK_SET) != 0)          \
+			return ELFERROR;                                       \
+                                                                               \
+		for (i = 0; i < pHeader->e_phnum; i++) {                       \
+			if (fread(&pheader, sizeof(pheader), 1, elf_file) ==   \
+			    1) {                                               \
+				if (pheader.p_type == PT_INTERP) {             \
+					ret = ELFDYNAMIC;                      \
+					break;                                 \
+				}                                              \
+			} else {                                               \
+				ret = ELFERROR;                                \
+				break;                                         \
+			}                                                      \
+		}                                                              \
+		return ret;                                                    \
+	}
+parseElftemplate(64) parseElftemplate(32)
 
-/* Public function to determine the linkage of an ELF. */
-ElfType get_elf_linkage(const char *path)
+    /* Public function to determine the linkage of an ELF. */
+    ElfType get_elf_linkage(const char *path)
 {
 	ElfType ret = ELFERROR;
 	attribute_cleanup_fp FILE *elf_file = NULL;
@@ -80,15 +79,15 @@ ElfType get_elf_linkage(const char *path)
 					/* 64-bit little endian. */
 					ret = parseElf64(elf_file, pHeader, 1);
 				} else if ((pHeader[EI_DATA] == ELFDATA2MSB) &&
-					  (pHeader[EI_CLASS] == ELFCLASS64)) {
+					   (pHeader[EI_CLASS] == ELFCLASS64)) {
 					/* 64-bit big endian. */
 					ret = parseElf64(elf_file, pHeader, 0);
 				} else if ((pHeader[EI_DATA] == ELFDATA2LSB) &&
-					  (pHeader[EI_CLASS] == ELFCLASS32)) {
+					   (pHeader[EI_CLASS] == ELFCLASS32)) {
 					/* 32-bit little endian. */
 					ret = parseElf32(elf_file, pHeader, 1);
 				} else if ((pHeader[EI_DATA] == ELFDATA2MSB) &&
-					  (pHeader[EI_CLASS] == ELFCLASS32)) {
+					   (pHeader[EI_CLASS] == ELFCLASS32)) {
 					/* 32-bit big endian. */
 					ret = parseElf32(elf_file, pHeader, 0);
 				}
diff --git a/elfparse.h b/elfparse.h
index 9083e0c..85e283a 100644
--- a/elfparse.h
+++ b/elfparse.h
@@ -23,76 +23,76 @@
 #endif
 #pragma pack(push)
 #pragma pack(1)
-typedef struct
-{
+typedef struct {
 	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
-	Elf32_Half    e_type;             /* Object file type */
-	Elf32_Half    e_machine;          /* Architecture */
-	Elf32_Word    e_version;          /* Object file version */
-	Elf32_Addr    e_entry;            /* Entry point virtual address */
-	Elf32_Off     e_phoff;            /* Program header table file offset */
-	Elf32_Off     e_shoff;            /* Section header table file offset */
-	Elf32_Word    e_flags;            /* Processor-specific flags */
-	Elf32_Half    e_ehsize;           /* ELF header size in bytes */
-	Elf32_Half    e_phentsize;        /* Program header table entry size */
-	Elf32_Half    e_phnum;            /* Program header table entry count */
-	Elf32_Half    e_shentsize;        /* Section header table entry size */
-	Elf32_Half    e_shnum;            /* Section header table entry count */
-	Elf32_Half    e_shstrndx;         /* Section header string table index */
+	Elf32_Half e_type;		  /* Object file type */
+	Elf32_Half e_machine;		  /* Architecture */
+	Elf32_Word e_version;		  /* Object file version */
+	Elf32_Addr e_entry;		  /* Entry point virtual address */
+	Elf32_Off e_phoff;		  /* Program header table file offset */
+	Elf32_Off e_shoff;		  /* Section header table file offset */
+	Elf32_Word e_flags;		  /* Processor-specific flags */
+	Elf32_Half e_ehsize;		  /* ELF header size in bytes */
+	Elf32_Half e_phentsize;		  /* Program header table entry size */
+	Elf32_Half e_phnum;		  /* Program header table entry count */
+	Elf32_Half e_shentsize;		  /* Section header table entry size */
+	Elf32_Half e_shnum;		  /* Section header table entry count */
+	Elf32_Half e_shstrndx; /* Section header string table index */
 } Minijail_Elf32_Ehdr;
 
-typedef struct
-{
+typedef struct {
 	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
-	Elf64_Half    e_type;             /* Object file type */
-	Elf64_Half    e_machine;          /* Architecture */
-	Elf64_Word    e_version;          /* Object file version */
-	Elf64_Addr    e_entry;            /* Entry point virtual address */
-	Elf64_Off     e_phoff;            /* Program header table file offset */
-	Elf64_Off     e_shoff;            /* Section header table file offset */
-	Elf64_Word    e_flags;            /* Processor-specific flags */
-	Elf64_Half    e_ehsize;           /* ELF header size in bytes */
-	Elf64_Half    e_phentsize;        /* Program header table entry size */
-	Elf64_Half    e_phnum;            /* Program header table entry count */
-	Elf64_Half    e_shentsize;        /* Section header table entry size */
-	Elf64_Half    e_shnum;            /* Section header table entry count */
-	Elf64_Half    e_shstrndx;         /* Section header string table index */
+	Elf64_Half e_type;		  /* Object file type */
+	Elf64_Half e_machine;		  /* Architecture */
+	Elf64_Word e_version;		  /* Object file version */
+	Elf64_Addr e_entry;		  /* Entry point virtual address */
+	Elf64_Off e_phoff;		  /* Program header table file offset */
+	Elf64_Off e_shoff;		  /* Section header table file offset */
+	Elf64_Word e_flags;		  /* Processor-specific flags */
+	Elf64_Half e_ehsize;		  /* ELF header size in bytes */
+	Elf64_Half e_phentsize;		  /* Program header table entry size */
+	Elf64_Half e_phnum;		  /* Program header table entry count */
+	Elf64_Half e_shentsize;		  /* Section header table entry size */
+	Elf64_Half e_shnum;		  /* Section header table entry count */
+	Elf64_Half e_shstrndx; /* Section header string table index */
 } Minijail_Elf64_Ehdr;
 
-typedef struct
-{
-	Elf32_Word      p_type;           /* Segment type */
-	Elf32_Off       p_offset;         /* Segment file offset */
-	Elf32_Addr      p_vaddr;          /* Segment virtual address */
-	Elf32_Addr      p_paddr;          /* Segment physical address */
-	Elf32_Word      p_filesz;         /* Segment size in file */
-	Elf32_Word      p_memsz;          /* Segment size in memory */
-	Elf32_Word      p_flags;          /* Segment flags */
-	Elf32_Word      p_align;          /* Segment alignment */
+typedef struct {
+	Elf32_Word p_type;   /* Segment type */
+	Elf32_Off p_offset;  /* Segment file offset */
+	Elf32_Addr p_vaddr;  /* Segment virtual address */
+	Elf32_Addr p_paddr;  /* Segment physical address */
+	Elf32_Word p_filesz; /* Segment size in file */
+	Elf32_Word p_memsz;  /* Segment size in memory */
+	Elf32_Word p_flags;  /* Segment flags */
+	Elf32_Word p_align;  /* Segment alignment */
 } Minijail_Elf32_Phdr;
 
-typedef struct
-{
-	Elf64_Word      p_type;           /* Segment type */
-	Elf64_Word      p_flags;          /* Segment flags */
-	Elf64_Off       p_offset;         /* Segment file offset */
-	Elf64_Addr      p_vaddr;          /* Segment virtual address */
-	Elf64_Addr      p_paddr;          /* Segment physical address */
-	Elf64_Xword     p_filesz;         /* Segment size in file */
-	Elf64_Xword     p_memsz;          /* Segment size in memory */
-	Elf64_Xword     p_align;          /* Segment alignment */
+typedef struct {
+	Elf64_Word p_type;    /* Segment type */
+	Elf64_Word p_flags;   /* Segment flags */
+	Elf64_Off p_offset;   /* Segment file offset */
+	Elf64_Addr p_vaddr;   /* Segment virtual address */
+	Elf64_Addr p_paddr;   /* Segment physical address */
+	Elf64_Xword p_filesz; /* Segment size in file */
+	Elf64_Xword p_memsz;  /* Segment size in memory */
+	Elf64_Xword p_align;  /* Segment alignment */
 } Minijail_Elf64_Phdr;
 #pragma pack(pop)
 /* End of definitions from elf.h */
 
-enum ElfTypeEnum { ELFERROR=0, ELFSTATIC=1, ELFDYNAMIC=2 };
+enum ElfTypeEnum {
+	ELFERROR = 0,
+	ELFSTATIC = 1,
+	ELFDYNAMIC = 2
+};
 typedef enum ElfTypeEnum ElfType;
 
 /*
  * This is the initial amount of the ELF file we try and read.
  * It is the same value that the kernel uses (BINPRM_BUF_SIZE).
  */
-#define HEADERSIZE  128
+#define HEADERSIZE 128
 
 ElfType get_elf_linkage(const char *path);
 
diff --git a/examples/cat.policy b/examples/cat.policy
index 25b4c29..521c859 100644
--- a/examples/cat.policy
+++ b/examples/cat.policy
@@ -15,4 +15,5 @@ close: 1
 fstat: 1
 # Enforce W^X.
 mmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
+mseal: 1
 fadvise64: 1
diff --git a/gen_constants-inl.h b/gen_constants-inl.h
index d09349c..129529e 100644
--- a/gen_constants-inl.h
+++ b/gen_constants-inl.h
@@ -14,6 +14,7 @@
 #include <linux/mman.h>
 #include <linux/net.h>
 #include <linux/prctl.h>
+#include <linux/random.h>
 #include <linux/sched.h>
 #include <linux/serial.h>
 #include <linux/sockios.h>
@@ -66,7 +67,7 @@ struct fscrypt_policy_v1 {
 	__u8 flags;
 	__u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
 };
-#define fscrypt_policy fscrypt_policy_v1
+#define fscrypt_policy		     fscrypt_policy_v1
 #define FS_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct fscrypt_policy)
 #define FS_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct fscrypt_policy)
 #endif /* !FS_IOC_SET_ENCRYPTION_POLICY && !FS_IOC_GET_ENCRYPTION_POLICY */
diff --git a/gen_constants.sh b/gen_constants.sh
index 628a13d..9e51406 100755
--- a/gen_constants.sh
+++ b/gen_constants.sh
@@ -17,20 +17,25 @@ if [ $# -ne 1 ] && [ $# -ne 2 ]; then
   exit 1
 fi
 
-BUILD="${CC} -dD ${SRC:-.}/gen_constants.c -E"
+build() {
+  ${CC:-cc} -dD "${SRC:-.}"/gen_constants.c -E "$@"
+}
 GEN_DEPS=1
 
 if [ $# -eq 2 ]; then
-  BUILD="cat $1"
+  build() {
+    cat "${CAT_FILE}"
+  }
+  CAT_FILE="$1"
   GEN_DEPS=0
   shift
 fi
 OUTFILE="$1"
 
-if [ ${GEN_DEPS} -eq 1 ]; then
+if [ "${GEN_DEPS}" -eq 1 ]; then
   # Generate a dependency file which helps the build tool to see when it
   # should regenerate ${OUTFILE}.
-  ${BUILD} -M -MF "${OUTFILE}.d"
+  build -M -MF "${OUTFILE}.d"
 fi
 
 # sed expression which extracts constants and converts them from:
@@ -51,7 +56,7 @@ cat <<-EOF > "${OUTFILE}"
 #include "gen_constants-inl.h"
 #include "libconstants.h"
 const struct constant_entry constant_table[] = {
-$(${BUILD} | \
+$(build | \
   grep -E '^#define [[:upper:]][[:upper:]0-9_]*[[:space:]]+[[:alnum:]_]' | \
   grep -Ev '(SIGRTMAX|SIGRTMIN|SIG_|NULL)' | \
   sort -u | \
diff --git a/gen_syscalls-inl.h b/gen_syscalls-inl.h
index e631424..518a864 100644
--- a/gen_syscalls-inl.h
+++ b/gen_syscalls-inl.h
@@ -111,3 +111,7 @@
 #define __NR_membarrier 283
 #endif
 #endif /* __NR_membarrier */
+
+#ifndef __NR_mseal
+#define __NR_mseal 462
+#endif /* __NR_mseal */
diff --git a/gen_syscalls.sh b/gen_syscalls.sh
index d5155e8..aa76bcf 100755
--- a/gen_syscalls.sh
+++ b/gen_syscalls.sh
@@ -18,20 +18,25 @@ if [ $# -ne 1 ] && [ $# -ne 2 ]; then
   exit 1
 fi
 
-BUILD="${CC} -dD ${SRC:-.}/gen_syscalls.c -E"
+build() {
+  ${CC:-cc} -dD "${SRC:-.}"/gen_syscalls.c -E "$@"
+}
 GEN_DEPS=1
 
 if [ $# -eq 2 ]; then
-  BUILD="cat $1"
+  build() {
+    cat "${CAT_FILE}"
+  }
+  CAT_FILE="$1"
   GEN_DEPS=0
   shift
 fi
 OUTFILE="$1"
 
-if [ ${GEN_DEPS} -eq 1 ]; then
+if [ "${GEN_DEPS}" -eq 1 ]; then
   # Generate a dependency file which helps the build tool to see when it
   # should regenerate ${OUTFILE}.
-  ${BUILD} -M -MF "${OUTFILE}.d"
+  build -M -MF "${OUTFILE}.d"
 fi
 
 # sed expression which extracts system calls that are
@@ -51,7 +56,7 @@ cat <<-EOF > "${OUTFILE}"
 #include "gen_syscalls-inl.h"
 #include "libsyscalls.h"
 const struct syscall_entry syscall_table[] = {
-$(${BUILD} | sed -Ene "${SED_MULTILINE}")
+$(build | sed -Ene "${SED_MULTILINE}")
   { NULL, -1 },
 };
 
diff --git a/get_googletest.sh b/get_googletest.sh
index 07910b4..f011b6f 100755
--- a/get_googletest.sh
+++ b/get_googletest.sh
@@ -1,6 +1,11 @@
-#/bin/bash
+#!/bin/bash
+# Copyright 2017 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 
-PV="1.11.0"
+PV="1.14.0"
 
-wget -q -nc --secure-protocol=TLSv1 "https://github.com/google/googletest/archive/release-${PV}.tar.gz" -O "googletest-release-${PV}.tar.gz"
-tar zxvf "googletest-release-${PV}.tar.gz"
+wget -q -nc --secure-protocol=TLSv1 \
+  "https://github.com/google/googletest/archive/v${PV}.tar.gz" \
+  -O "googletest-${PV}.tar.gz"
+tar zxvf "googletest-${PV}.tar.gz"
diff --git a/landlock.h b/landlock.h
index 1ce5b80..d16ed00 100644
--- a/landlock.h
+++ b/landlock.h
@@ -39,7 +39,7 @@ struct minijail_landlock_ruleset_attr {
  *   version.
  */
 #ifndef LANDLOCK_CREATE_RULESET_VERSION
-#define LANDLOCK_CREATE_RULESET_VERSION			(1U << 0)
+#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
 #endif
 
 /**
@@ -75,58 +75,62 @@ struct minijail_landlock_path_beneath_attr {
 	 * This struct is packed to avoid trailing reserved members.
 	 * Cf. security/landlock/syscalls.c:build_check_abi()
 	 */
-}  __attribute__((__packed__));
+} __attribute__((__packed__));
 
 #ifndef LANDLOCK_ACCESS_FS_EXECUTE
-#define LANDLOCK_ACCESS_FS_EXECUTE			(1ULL << 0)
+#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
-#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
+#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_READ_FILE
-#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
+#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_READ_DIR
-#define LANDLOCK_ACCESS_FS_READ_DIR			(1ULL << 3)
+#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
-#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 4)
+#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
-#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 5)
+#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
-#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 6)
+#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
-#define LANDLOCK_ACCESS_FS_MAKE_DIR			(1ULL << 7)
+#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_REG
-#define LANDLOCK_ACCESS_FS_MAKE_REG			(1ULL << 8)
+#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
-#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 9)
+#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
-#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 10)
+#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
-#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 11)
+#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
 #endif
 
 #ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
-#define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 12)
+#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
+#endif
+
+#ifndef LANDLOCK_ACCESS_FS_REFER
+#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
 #endif
 
 #endif /* _LANDLOCK_H */
diff --git a/landlock_util.c b/landlock_util.c
index 2aa8336..84a2a18 100644
--- a/landlock_util.c
+++ b/landlock_util.c
@@ -13,10 +13,9 @@
 
 #include "util.h"
 
-
-int landlock_create_ruleset(const struct
-			    minijail_landlock_ruleset_attr *const attr,
-			    const size_t size, const __u32 flags)
+int landlock_create_ruleset(
+    const struct minijail_landlock_ruleset_attr *const attr, const size_t size,
+    const __u32 flags)
 {
 	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
 }
@@ -25,22 +24,20 @@ int landlock_add_rule(const int ruleset_fd,
 		      const enum minijail_landlock_rule_type rule_type,
 		      const void *const rule_attr, const __u32 flags)
 {
-	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
-			rule_attr, flags);
+	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
+		       flags);
 }
 
-int landlock_restrict_self(const int ruleset_fd,
-			   const __u32 flags)
+int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
 {
 	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
 }
 
-bool populate_ruleset_internal(const char *const path,
-			       const int ruleset_fd,
+bool populate_ruleset_internal(const char *const path, const int ruleset_fd,
 			       const uint64_t allowed_access)
 {
 	struct minijail_landlock_path_beneath_attr path_beneath = {
-		.parent_fd = -1,
+	    .parent_fd = -1,
 	};
 	struct stat statbuf;
 	attribute_cleanup_fd int parent_fd = open(path, O_PATH | O_CLOEXEC);
@@ -57,7 +54,7 @@ bool populate_ruleset_internal(const char *const path,
 		path_beneath.allowed_access &= ACCESS_FILE;
 	}
 	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
-			&path_beneath, 0)) {
+			      &path_beneath, 0)) {
 		pwarn("Failed to update ruleset \"%s\"", path);
 		return false;
 	}
diff --git a/landlock_util.h b/landlock_util.h
index ab1b472..147053b 100644
--- a/landlock_util.h
+++ b/landlock_util.h
@@ -17,7 +17,6 @@
 
 #include "landlock.h"
 
-
 #ifdef __cplusplus
 extern "C" {
 #endif
@@ -34,46 +33,37 @@ extern "C" {
 #define __NR_landlock_restrict_self 446
 #endif
 
-#define ACCESS_FS_ROUGHLY_READ ( \
-	LANDLOCK_ACCESS_FS_READ_FILE | \
-	LANDLOCK_ACCESS_FS_READ_DIR)
-
-#define ACCESS_FS_ROUGHLY_READ_EXECUTE ( \
-	LANDLOCK_ACCESS_FS_EXECUTE | \
-	LANDLOCK_ACCESS_FS_READ_FILE | \
-	LANDLOCK_ACCESS_FS_READ_DIR)
-
-#define ACCESS_FS_ROUGHLY_BASIC_WRITE ( \
-	LANDLOCK_ACCESS_FS_WRITE_FILE | \
-	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
-	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
-	LANDLOCK_ACCESS_FS_MAKE_DIR | \
-	LANDLOCK_ACCESS_FS_MAKE_REG)
-
-#define ACCESS_FS_ROUGHLY_EDIT ( \
-	LANDLOCK_ACCESS_FS_WRITE_FILE | \
-	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
-	LANDLOCK_ACCESS_FS_REMOVE_FILE)
-
-#define ACCESS_FS_ROUGHLY_FULL_WRITE ( \
-	LANDLOCK_ACCESS_FS_WRITE_FILE | \
-	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
-	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
-	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
-	LANDLOCK_ACCESS_FS_MAKE_DIR | \
-	LANDLOCK_ACCESS_FS_MAKE_REG | \
-	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
-	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
-	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
-	LANDLOCK_ACCESS_FS_MAKE_SYM)
-
-#define ACCESS_FILE ( \
-	LANDLOCK_ACCESS_FS_EXECUTE | \
-	LANDLOCK_ACCESS_FS_WRITE_FILE | \
-	LANDLOCK_ACCESS_FS_READ_FILE)
-
-#define HANDLED_ACCESS_TYPES (ACCESS_FS_ROUGHLY_READ_EXECUTE | \
-	ACCESS_FS_ROUGHLY_FULL_WRITE)
+#define ACCESS_FS_ROUGHLY_READ                                                 \
+	(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
+
+#define ACCESS_FS_ROUGHLY_READ_EXECUTE                                         \
+	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |           \
+	 LANDLOCK_ACCESS_FS_READ_DIR)
+
+#define ACCESS_FS_ROUGHLY_BASIC_WRITE                                          \
+	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
+	 LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |        \
+	 LANDLOCK_ACCESS_FS_MAKE_REG)
+
+#define ACCESS_FS_ROUGHLY_EDIT                                                 \
+	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
+	 LANDLOCK_ACCESS_FS_REMOVE_FILE)
+
+#define ACCESS_FS_ROUGHLY_FULL_WRITE                                           \
+	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
+	 LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |       \
+	 LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |           \
+	 LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |         \
+	 LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM)
+
+#define ACCESS_FILE                                                            \
+	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |          \
+	 LANDLOCK_ACCESS_FS_READ_FILE)
+
+#define HANDLED_ACCESS_TYPES                                                   \
+	(ACCESS_FS_ROUGHLY_READ_EXECUTE | ACCESS_FS_ROUGHLY_FULL_WRITE)
+
+#define LANDLOCK_ABI_FS_REFER_SUPPORTED 2
 
 /*
  * Performs Landlock create ruleset syscall.
@@ -81,9 +71,9 @@ extern "C" {
  * Returns the ruleset file descriptor on success, returns an error code
  * otherwise.
  */
-extern int landlock_create_ruleset(const struct
-				   minijail_landlock_ruleset_attr *const attr,
-				   const size_t size, const __u32 flags);
+extern int
+landlock_create_ruleset(const struct minijail_landlock_ruleset_attr *const attr,
+			const size_t size, const __u32 flags);
 
 /* Performs Landlock add rule syscall. */
 extern int landlock_add_rule(const int ruleset_fd,
@@ -91,8 +81,7 @@ extern int landlock_add_rule(const int ruleset_fd,
 			     const void *const rule_attr, const __u32 flags);
 
 /* Performs Landlock restrict self syscall. */
-extern int landlock_restrict_self(const int ruleset_fd,
-				  const __u32 flags);
+extern int landlock_restrict_self(const int ruleset_fd, const __u32 flags);
 
 /* Populates the landlock ruleset for a path and any needed paths beneath. */
 extern bool populate_ruleset_internal(const char *const path,
diff --git a/libconstants.h b/libconstants.h
index 0548de9..0a78e8b 100644
--- a/libconstants.h
+++ b/libconstants.h
@@ -12,4 +12,4 @@ struct constant_entry {
 
 extern const struct constant_entry constant_table[];
 
-#endif  /* MINIJAIL_LIBCONSTANTS_H_ */
+#endif /* MINIJAIL_LIBCONSTANTS_H_ */
diff --git a/libminijail-private.h b/libminijail-private.h
index 6351f8e..1552393 100644
--- a/libminijail-private.h
+++ b/libminijail-private.h
@@ -10,6 +10,8 @@
 #ifndef LIBMINIJAIL_PRIVATE_H
 #define LIBMINIJAIL_PRIVATE_H
 
+#include <sys/types.h>
+
 #ifdef __cplusplus
 extern "C" {
 #endif
@@ -22,6 +24,8 @@ extern "C" {
 static const char kFdEnvVar[] = "__MINIJAIL_FD";
 static const char kLdPreloadEnvVar[] = "LD_PRELOAD";
 static const char kSeccompPolicyPathEnvVar[] = "SECCOMP_POLICY_PATH";
+static const char kAltSyscallNamePlaceholder[] =
+    "<unknown: alt_syscall active>";
 
 struct minijail;
 
@@ -85,6 +89,10 @@ extern void minijail_preexec(struct minijail *j);
  */
 extern void minijail_preenter(struct minijail *j);
 
+/* minijail_fd_is_open: returns true if the specified file descriptor is open.
+ */
+extern int minijail_fd_is_open(int fd);
+
 #ifdef __cplusplus
 }; /* extern "C" */
 #endif
diff --git a/libminijail.c b/libminijail.c
index bb60904..de59b8a 100644
--- a/libminijail.c
+++ b/libminijail.c
@@ -17,7 +17,6 @@
 #include <linux/filter.h>
 #include <sched.h>
 #include <signal.h>
-#include <stdbool.h>
 #include <stddef.h>
 #include <stdio.h>
 #include <stdlib.h>
@@ -27,7 +26,6 @@
 #include <sys/param.h>
 #include <sys/prctl.h>
 #include <sys/resource.h>
-#include <sys/select.h>
 #include <sys/stat.h>
 #include <sys/sysmacros.h>
 #include <sys/types.h>
@@ -74,8 +72,8 @@
 	 MS_RELATIME | MS_RDONLY)
 
 /*
- * TODO(b/235960683): Drop this after CrOS upgrades to glibc >= 2.34
- * because MS_NOSYMFOLLOW will be defined in sys/mount.h.
+ * Required for Android host glibc which is permanently stuck on 2.17. Causes
+ * no harm for newer glibc versions.
  */
 #ifndef MS_NOSYMFOLLOW
 /* Added locally in kernels 4.x+. */
@@ -122,9 +120,15 @@ struct preserved_fd {
 	int child_fd;
 };
 
+/*
+ * minijail struct: new fields should either be marshaled/unmarshaled or have a
+ * comment explaining why that's unnecessary.
+ */
 struct minijail {
 	/*
-	 * WARNING: if you add a flag here you need to make sure it's
+	 * WARNING: new bool flags should always be added to this struct,
+	 * unless you’re certain they don’t need to remain after marshaling.
+	 * If you add a flag here you need to make sure it's
 	 * accounted for in minijail_pre{enter|exec}() below.
 	 */
 	struct {
@@ -142,6 +146,7 @@ struct minijail {
 		bool ipc : 1;
 		bool uts : 1;
 		bool net : 1;
+		bool net_loopback : 1;
 		bool enter_net : 1;
 		bool ns_cgroups : 1;
 		bool userns : 1;
@@ -168,6 +173,11 @@ struct minijail {
 		bool new_session_keyring : 1;
 		bool forward_signals : 1;
 		bool setsid : 1;
+		bool using_minimalistic_mountns : 1;
+		bool enable_fs_restrictions : 1;
+		bool enable_profile_fs_restrictions : 1;
+		bool enable_default_runtime : 1;
+		bool enable_new_sessions : 1;
 	} flags;
 	uid_t uid;
 	gid_t gid;
@@ -180,12 +190,19 @@ struct minijail {
 	pid_t initpid;
 	int mountns_fd;
 	int netns_fd;
+	int fs_rules_fd;
+	int fs_rules_landlock_abi;
 	char *chrootdir;
 	char *pid_file_path;
 	char *uidmap;
 	char *gidmap;
 	char *hostname;
 	char *preload_path;
+	/*
+	 * Filename that will be executed, unless an ELF fd is used instead.
+	 * This field is only used for logs and isn't included in marshaling.
+	 */
+	char *filename;
 	size_t filter_len;
 	struct sock_fprog *filter_prog;
 	char *alt_syscall_table;
@@ -196,9 +213,9 @@ struct minijail {
 	struct minijail_remount *remounts_head;
 	struct minijail_remount *remounts_tail;
 	size_t tmpfs_size;
-	bool using_minimalistic_mountns;
 	struct fs_rule *fs_rules_head;
 	struct fs_rule *fs_rules_tail;
+	size_t fs_rules_count;
 	char *cgroups[MAX_CGROUPS];
 	size_t cgroup_count;
 	struct minijail_rlimit rlimits[MAX_RLIMITS];
@@ -246,6 +263,17 @@ static void free_remounts_list(struct minijail *j)
 	j->remounts_tail = NULL;
 }
 
+static void free_fs_rules_list(struct minijail *j)
+{
+	while (j->fs_rules_head) {
+		struct fs_rule *r = j->fs_rules_head;
+		j->fs_rules_head = j->fs_rules_head->next;
+		free(r->path);
+		free(r);
+	}
+	j->fs_rules_tail = NULL;
+}
+
 /*
  * Writes exactly n bytes from buf to file descriptor fd.
  * Returns 0 on success or a negative error code on error.
@@ -288,6 +316,7 @@ void minijail_preenter(struct minijail *j)
 	j->flags.enter_vfs = 0;
 	j->flags.ns_cgroups = 0;
 	j->flags.net = 0;
+	j->flags.net_loopback = 0;
 	j->flags.uts = 0;
 	j->flags.remount_proc_ro = 0;
 	j->flags.pids = 0;
@@ -298,13 +327,59 @@ void minijail_preenter(struct minijail *j)
 	j->flags.forward_signals = 0;
 	j->flags.setsid = 0;
 	j->remount_mode = 0;
+	j->flags.using_minimalistic_mountns = 0;
+	j->flags.enable_profile_fs_restrictions = 0;
+	j->flags.enable_default_runtime = 0;
+	j->flags.enable_new_sessions = 0;
 	free_remounts_list(j);
 }
 
+static bool fs_refer_restriction_supported(struct minijail *j)
+{
+	if (j->fs_rules_landlock_abi < 0) {
+		const int abi = landlock_create_ruleset(
+		    NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
+		/*
+		 * If we have a valid ABI, save the result. Otherwise, leave
+		 * the struct field unmodified to make sure it's correctly
+		 * marshaled and unmarshaled.
+		 */
+		if (abi > 0) {
+			j->fs_rules_landlock_abi = abi;
+		}
+	}
+
+	return j->fs_rules_landlock_abi >= LANDLOCK_ABI_FS_REFER_SUPPORTED;
+}
+
+/* Sets fs_rules_fd to an empty ruleset, if Landlock is available. */
+static int setup_fs_rules_fd(struct minijail *j)
+{
+	struct minijail_landlock_ruleset_attr ruleset_attr = {
+	    .handled_access_fs = HANDLED_ACCESS_TYPES};
+	if (fs_refer_restriction_supported(j)) {
+		ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
+	}
+
+	j->fs_rules_fd =
+	    landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
+	if (j->fs_rules_fd < 0) {
+		/*
+		 * As of Landlock ABI=3, the useful errors we expect here are
+		 * ENOSYS or EOPNOTSUPP. In both cases, Landlock is not
+		 * supported by the kernel and Minijail can silently ignore it.
+		 * TODO(b/300142205): log when we no longer have 5.4 kernels in
+		 * ChromeOS (~EoY 2024).
+		 */
+		return errno;
+	}
+
+	return 0;
+}
+
 /* Adds a rule for a given path to apply once minijail is entered. */
-int add_fs_restriction_path(struct minijail *j,
-		const char *path,
-		uint64_t landlock_flags)
+static int add_fs_restriction_path(struct minijail *j, const char *path,
+				   uint64_t landlock_flags)
 {
 	struct fs_rule *r = calloc(1, sizeof(*r));
 	if (!r)
@@ -320,18 +395,36 @@ int add_fs_restriction_path(struct minijail *j,
 		j->fs_rules_tail = r;
 	}
 
+	/*
+	 * If this is our first rule, set up the rules FD early for API users.
+	 *
+	 * This is important for users calling minijail_enter() directly.
+	 * Otherise, this is handled later inside minijail_run_internal().
+	 *
+	 * The reason for this is because setup_fs_rules_fd() needs to be
+	 * called from inside the process that applies Landlock rules. For
+	 * minijail_enter(), that's this process. For minijail_run_internal(),
+	 * that's the child process.
+	 */
+	if (j->fs_rules_count == 0)
+		setup_fs_rules_fd(j);
+
+	j->fs_rules_count++;
 	return 0;
 }
 
-bool mount_has_bind_flag(struct mountpoint *m) {
+bool mount_has_bind_flag(struct mountpoint *m)
+{
 	return !!(m->flags & MS_BIND);
 }
 
-bool mount_has_readonly_flag(struct mountpoint *m) {
+bool mount_has_readonly_flag(struct mountpoint *m)
+{
 	return !!(m->flags & MS_RDONLY);
 }
 
-bool mount_events_allowed(struct mountpoint *m) {
+bool mount_events_allowed(struct mountpoint *m)
+{
 	return !!(m->flags & MS_SHARED) || !!(m->flags & MS_SLAVE);
 }
 
@@ -345,9 +438,16 @@ void minijail_preexec(struct minijail *j)
 	int enter_vfs = j->flags.enter_vfs;
 	int ns_cgroups = j->flags.ns_cgroups;
 	int net = j->flags.net;
+	int net_loopback = j->flags.net_loopback;
 	int uts = j->flags.uts;
 	int remount_proc_ro = j->flags.remount_proc_ro;
 	int userns = j->flags.userns;
+	int using_minimalistic_mountns = j->flags.using_minimalistic_mountns;
+	int enable_fs_restrictions = j->flags.enable_fs_restrictions;
+	int enable_profile_fs_restrictions =
+	    j->flags.enable_profile_fs_restrictions;
+	int enable_default_runtime = j->flags.enable_default_runtime;
+	int enable_new_sessions = j->flags.enable_new_sessions;
 	if (j->user)
 		free(j->user);
 	j->user = NULL;
@@ -358,15 +458,23 @@ void minijail_preexec(struct minijail *j)
 		free(j->preload_path);
 	j->preload_path = NULL;
 	free_mounts_list(j);
+	free_fs_rules_list(j);
 	memset(&j->flags, 0, sizeof(j->flags));
 	/* Now restore anything we meant to keep. */
 	j->flags.vfs = vfs;
 	j->flags.enter_vfs = enter_vfs;
 	j->flags.ns_cgroups = ns_cgroups;
 	j->flags.net = net;
+	j->flags.net_loopback = net_loopback;
 	j->flags.uts = uts;
 	j->flags.remount_proc_ro = remount_proc_ro;
 	j->flags.userns = userns;
+	j->flags.using_minimalistic_mountns = using_minimalistic_mountns;
+	j->flags.enable_fs_restrictions = enable_fs_restrictions;
+	j->flags.enable_profile_fs_restrictions =
+	    enable_profile_fs_restrictions;
+	j->flags.enable_default_runtime = enable_default_runtime;
+	j->flags.enable_new_sessions = enable_new_sessions;
 	/* Note, |pids| will already have been used before this call. */
 }
 
@@ -377,7 +485,13 @@ struct minijail API *minijail_new(void)
 	struct minijail *j = calloc(1, sizeof(struct minijail));
 	if (j) {
 		j->remount_mode = MS_PRIVATE;
-		j->using_minimalistic_mountns = false;
+		j->fs_rules_fd = -1;
+		j->fs_rules_landlock_abi = -1;
+		j->flags.using_minimalistic_mountns = false;
+		j->flags.enable_fs_restrictions = true;
+		j->flags.enable_profile_fs_restrictions = true;
+		j->flags.enable_default_runtime = true;
+		j->flags.enable_new_sessions = true;
 	}
 	return j;
 }
@@ -530,23 +644,62 @@ void API minijail_log_seccomp_filter_failures(struct minijail *j)
 
 void API minijail_set_using_minimalistic_mountns(struct minijail *j)
 {
-	j->using_minimalistic_mountns = true;
+	j->flags.using_minimalistic_mountns = true;
+}
+
+void API minijail_set_enable_new_sessions(struct minijail *j,
+					  bool enable_new_sessions)
+{
+	j->flags.enable_new_sessions = enable_new_sessions;
+}
+
+void API minijail_set_enable_default_runtime(struct minijail *j,
+					     bool enable_default_runtime)
+{
+	j->flags.enable_default_runtime = enable_default_runtime;
+}
+
+bool API minijail_get_enable_default_runtime(struct minijail *j)
+{
+	return j->flags.enable_default_runtime;
+}
+
+bool API minijail_is_fs_restriction_available(void)
+{
+	const int abi =
+	    landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
+	// ABI > 0 is considered supported.
+	return abi > 0;
+}
+
+void API minijail_disable_fs_restrictions(struct minijail *j)
+{
+	j->flags.enable_fs_restrictions = false;
+}
+
+void API minijail_set_enable_profile_fs_restrictions(struct minijail *j)
+{
+	j->flags.enable_profile_fs_restrictions = true;
 }
 
 void API minijail_add_minimalistic_mountns_fs_rules(struct minijail *j)
 {
 	struct mountpoint *m = j->mounts_head;
 	bool landlock_enabled_by_profile = false;
-	if (!j->using_minimalistic_mountns)
+	if (!j->flags.using_minimalistic_mountns ||
+	    !j->flags.enable_profile_fs_restrictions)
 		return;
 
 	/* Apply Landlock rules. */
 	while (m) {
 		landlock_enabled_by_profile = true;
 		minijail_add_fs_restriction_rx(j, m->dest);
-		/* Allow rw if mounted as writable, or mount flags allow mount events.*/
+		/*
+		 * Allow rw if mounted as writable, or mount flags allow mount
+		 * events.
+		 */
 		if (!mount_has_readonly_flag(m) || mount_events_allowed(m))
-			minijail_add_fs_restriction_rw(j, m->dest);
+			minijail_add_fs_restriction_advanced_rw(j, m->dest);
 		m = m->next;
 	}
 	if (landlock_enabled_by_profile) {
@@ -570,6 +723,9 @@ void API minijail_enable_default_fs_restrictions(struct minijail *j)
 	minijail_add_fs_restriction_rx(j, "/sbin");
 	minijail_add_fs_restriction_rx(j, "/usr/sbin");
 	minijail_add_fs_restriction_rx(j, "/usr/bin");
+	// Common /etc locations.
+	minijail_add_fs_restriction_ro(j, "/etc/group");
+	minijail_add_fs_restriction_ro(j, "/etc/passwd");
 }
 
 void API minijail_use_caps(struct minijail *j, uint64_t capmask)
@@ -696,9 +852,16 @@ int API minijail_namespace_set_hostname(struct minijail *j, const char *name)
 	return 0;
 }
 
-void API minijail_namespace_net(struct minijail *j)
+void API minijail_namespace_net_loopback(struct minijail *j,
+					 bool enable_loopback)
 {
 	j->flags.net = 1;
+	j->flags.net_loopback = enable_loopback;
+}
+
+void API minijail_namespace_net(struct minijail *j)
+{
+	minijail_namespace_net_loopback(j, true);
 }
 
 void API minijail_namespace_enter_net(struct minijail *j, const char *ns_path)
@@ -913,7 +1076,7 @@ int API minijail_create_session(struct minijail *j)
 int API minijail_add_fs_restriction_rx(struct minijail *j, const char *path)
 {
 	return !add_fs_restriction_path(j, path,
-		ACCESS_FS_ROUGHLY_READ_EXECUTE);
+					ACCESS_FS_ROUGHLY_READ_EXECUTE);
 }
 
 int API minijail_add_fs_restriction_ro(struct minijail *j, const char *path)
@@ -923,22 +1086,39 @@ int API minijail_add_fs_restriction_ro(struct minijail *j, const char *path)
 
 int API minijail_add_fs_restriction_rw(struct minijail *j, const char *path)
 {
-	return !add_fs_restriction_path(j, path,
-		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_BASIC_WRITE);
+	return !add_fs_restriction_path(
+	    j, path, ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_BASIC_WRITE);
 }
 
 int API minijail_add_fs_restriction_advanced_rw(struct minijail *j,
 						const char *path)
 {
-	return !add_fs_restriction_path(j, path,
-		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_FULL_WRITE);
+	uint16_t landlock_flags =
+	    ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_FULL_WRITE;
+	if (fs_refer_restriction_supported(j)) {
+		landlock_flags |= LANDLOCK_ACCESS_FS_REFER;
+	}
+
+	return !add_fs_restriction_path(j, path, landlock_flags);
 }
 
-int API minijail_add_fs_restriction_edit(struct minijail *j,
-						const char *path)
+int API minijail_add_fs_restriction_edit(struct minijail *j, const char *path)
 {
-	return !add_fs_restriction_path(j, path,
-		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_EDIT);
+	return !add_fs_restriction_path(
+	    j, path, ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_EDIT);
+}
+
+int API minijail_add_fs_restriction_access_rights(struct minijail *j,
+						  const char *path,
+						  uint16_t landlock_flags)
+{
+	return !add_fs_restriction_path(j, path, landlock_flags);
+}
+
+bool API
+minijail_is_fs_restriction_ruleset_initialized(const struct minijail *j)
+{
+	return j->fs_rules_fd >= 0;
 }
 
 static bool is_valid_bind_path(const char *path)
@@ -1119,8 +1299,6 @@ int API minijail_add_hook(struct minijail *j, minijail_hook_t hook,
 {
 	struct hook *c;
 
-	if (hook == NULL)
-		return -EINVAL;
 	if (event >= MINIJAIL_HOOK_EVENT_MAX)
 		return -EINVAL;
 	c = calloc(1, sizeof(*c));
@@ -1311,6 +1489,10 @@ static int parse_seccomp_filters(struct minijail *j, const char *filename,
 	filteropts.allow_syscalls_for_logging =
 	    filteropts.allow_logging && !seccomp_ret_log_available();
 
+	/* Whether to also allow syscalls for libc compatibility. */
+	filteropts.include_libc_compatibility_allowlist =
+	    allow_libc_compatibility_syscalls();
+
 	/* Whether to fail on duplicate syscalls. */
 	filteropts.allow_duplicate_syscalls = allow_duplicate_syscalls();
 
@@ -1448,10 +1630,19 @@ static void marshal_mount(struct marshal_state *state,
 	marshal_append(state, (char *)&m->flags, sizeof(m->flags));
 }
 
+static void marshal_fs_rule(struct marshal_state *state,
+			    const struct fs_rule *r)
+{
+	marshal_append(state, r->path, strlen(r->path) + 1);
+	marshal_append(state, (char *)&r->landlock_flags,
+		       sizeof(r->landlock_flags));
+}
+
 static void minijail_marshal_helper(struct marshal_state *state,
 				    const struct minijail *j)
 {
 	struct mountpoint *m = NULL;
+	struct fs_rule *r = NULL;
 	size_t i;
 
 	marshal_append(state, (char *)j, sizeof(*j));
@@ -1479,6 +1670,9 @@ static void minijail_marshal_helper(struct marshal_state *state,
 	}
 	for (i = 0; i < j->cgroup_count; ++i)
 		marshal_append_string(state, j->cgroups[i]);
+	for (r = j->fs_rules_head; r; r = r->next)
+		marshal_fs_rule(state, r);
+	marshal_append(state, (char *)&j->fs_rules_fd, sizeof(j->fs_rules_fd));
 	if (j->seccomp_policy_path)
 		marshal_append_string(state, j->seccomp_policy_path);
 }
@@ -1503,6 +1697,7 @@ int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
 {
 	size_t i;
 	size_t count;
+	size_t fs_rules_count;
 	int ret = -EINVAL;
 
 	if (length < sizeof(*j))
@@ -1513,6 +1708,7 @@ int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
 
 	/* Potentially stale pointers not used as signals. */
 	j->preload_path = NULL;
+	j->filename = NULL;
 	j->pid_file_path = NULL;
 	j->uidmap = NULL;
 	j->gidmap = NULL;
@@ -1647,6 +1843,31 @@ int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
 		++j->cgroup_count;
 	}
 
+	/* Unmarshal fs_rules. */
+	fs_rules_count = j->fs_rules_count;
+	j->fs_rules_count = 0;
+	for (i = 0; i < fs_rules_count; ++i) {
+		const char *path = consumestr(&serialized, &length);
+		uint64_t landlock_flags;
+		void *landlock_flags_bytes =
+		    consumebytes(sizeof(landlock_flags), &serialized, &length);
+
+		if (!path)
+			goto bad_fs_rules;
+		memcpy(&landlock_flags, landlock_flags_bytes,
+		       sizeof(landlock_flags));
+		if (!landlock_flags)
+			goto bad_fs_rules;
+		if (add_fs_restriction_path(j, path, landlock_flags))
+			goto bad_fs_rules;
+	}
+	/* Unmarshal fs_rules_fd. */
+	void *fs_rules_fd_bytes =
+	    consumebytes(sizeof(j->fs_rules_fd), &serialized, &length);
+	memcpy(&j->fs_rules_fd, fs_rules_fd_bytes, sizeof(j->fs_rules_fd));
+	if (!j->fs_rules_fd)
+		goto bad_cgroups;
+
 	if (j->seccomp_policy_path) { /* stale pointer */
 		char *seccomp_policy_path = consumestr(&serialized, &length);
 		if (!seccomp_policy_path)
@@ -1669,6 +1890,8 @@ bad_cgroups:
 	free_remounts_list(j);
 	for (i = 0; i < j->cgroup_count; ++i)
 		free(j->cgroups[i]);
+bad_fs_rules:
+	free_fs_rules_list(j);
 bad_mounts:
 	if (j->filter_prog && j->filter_prog->filter)
 		free(j->filter_prog->filter);
@@ -1697,6 +1920,7 @@ clear_pointers:
 	j->hostname = NULL;
 	j->alt_syscall_table = NULL;
 	j->cgroup_count = 0;
+	j->fs_rules_count = 0;
 	j->seccomp_policy_path = NULL;
 out:
 	return ret;
@@ -2396,56 +2620,47 @@ static void drop_caps(const struct minijail *j, unsigned int last_valid_cap)
 	cap_free(caps);
 }
 
-/* Creates a ruleset for current inodes then calls landlock_restrict_self(). */
+/* Calls landlock_restrict_self(), based on current inodes. */
 static void apply_landlock_restrictions(const struct minijail *j)
 {
-	struct fs_rule *r;
-	attribute_cleanup_fd int ruleset_fd = -1;
-
-	r = j->fs_rules_head;
-	while (r) {
-		if (ruleset_fd < 0) {
-			struct minijail_landlock_ruleset_attr ruleset_attr = {
-				.handled_access_fs = HANDLED_ACCESS_TYPES
-			};
-			ruleset_fd = landlock_create_ruleset(
-				&ruleset_attr, sizeof(ruleset_attr), 0);
-			if (ruleset_fd < 0) {
-				const int err = errno;
-				pwarn("Failed to create a ruleset");
-				switch (err) {
-				case ENOSYS:
-					pwarn("Landlock is not supported by the current kernel");
-					break;
-				case EOPNOTSUPP:
-					pwarn("Landlock is currently disabled by kernel config");
-					break;
-				}
-				return;
-			}
+	struct fs_rule *r = j->fs_rules_head;
+	/* The ruleset_fd needs to be mutable so use a stack copy from now on.
+	 */
+	int ruleset_fd = j->fs_rules_fd;
+	if (!j->flags.enable_fs_restrictions || !r) {
+		return;
+	}
+
+	if (minijail_is_fs_restriction_available()) {
+		while (r) {
+			populate_ruleset_internal(r->path, ruleset_fd,
+						  r->landlock_flags);
+			r = r->next;
 		}
-		populate_ruleset_internal(r->path, ruleset_fd, r->landlock_flags);
-		r = r->next;
 	}
 
 	if (ruleset_fd >= 0) {
+		if (j->filename != NULL) {
+			info("applying Landlock to process %s", j->filename);
+		}
 		if (landlock_restrict_self(ruleset_fd, 0)) {
-			pdie("Failed to enforce ruleset");
+			pdie("failed to enforce ruleset");
 		}
+		close(ruleset_fd);
 	}
 }
 
-static void set_seccomp_filter(const struct minijail *j)
+static void set_no_new_privs(const struct minijail *j)
 {
-	/*
-	 * Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
-	 * in the kernel source tree for an explanation of the parameters.
-	 */
 	if (j->flags.no_new_privs) {
-		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
-			pdie("prctl(PR_SET_NO_NEW_PRIVS)");
+		if (!sys_set_no_new_privs()) {
+			die("set_no_new_privs() failed");
+		}
 	}
+}
 
+static void set_seccomp_filter(const struct minijail *j)
+{
 	/*
 	 * Code running with ASan
 	 * (https://github.com/google/sanitizers/wiki/AddressSanitizer)
@@ -2666,7 +2881,8 @@ void API minijail_enter(const struct minijail *j)
 	} else if (j->flags.net) {
 		if (unshare(CLONE_NEWNET))
 			pdie("unshare(CLONE_NEWNET) failed");
-		config_net_loopback();
+		if (j->flags.net_loopback)
+			config_net_loopback();
 	}
 
 	if (j->flags.ns_cgroups && unshare(CLONE_NEWCGROUP))
@@ -2729,8 +2945,14 @@ void API minijail_enter(const struct minijail *j)
 		drop_ugid(j);
 		drop_caps(j, last_valid_cap);
 
-		// Landlock is applied as late as possible. If no_new_privs is
-		// set, then it can be applied after dropping caps.
+		/*
+		 * Landlock is applied as late as possible. If no_new_privs is
+		 * requested, then we need to set that first because the
+		 * landlock_restrict_self() syscall has a seccomp(2) like check
+		 * for that. See:
+		 * https://elixir.bootlin.com/linux/v5.15.74/source/security/landlock/syscalls.c#L409
+		 */
+		set_no_new_privs(j);
 		apply_landlock_restrictions(j);
 		set_seccomp_filter(j);
 	} else {
@@ -2947,19 +3169,31 @@ static int close_open_fds(int *inheritable_fds, size_t size)
 }
 
 /* Return true if the specified file descriptor is already open. */
-static int fd_is_open(int fd)
+int minijail_fd_is_open(int fd)
 {
 	return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
 }
 
-static_assert(FD_SETSIZE >= MAX_PRESERVED_FDS * 2 - 1,
-	      "If true, ensure_no_fd_conflict will always find an unused fd.");
+/*
+ * Returns true if |check_fd| is one of j->preserved_fds[:max_index].child_fd.
+ */
+static bool is_preserved_child_fd(struct minijail *j, int check_fd,
+				  size_t max_index)
+{
+	max_index = MIN(max_index, j->preserved_fd_count);
+	for (size_t i = 0; i < max_index; i++) {
+		if (j->preserved_fds[i].child_fd == check_fd) {
+			return true;
+		}
+	}
+	return false;
+}
 
 /* If parent_fd will be used by a child fd, move it to an unused fd. */
-static int ensure_no_fd_conflict(const fd_set *child_fds, int child_fd,
-				 int *parent_fd)
+static int ensure_no_fd_conflict(struct minijail *j, int child_fd,
+				 int *parent_fd, size_t max_index)
 {
-	if (!FD_ISSET(*parent_fd, child_fds)) {
+	if (!is_preserved_child_fd(j, *parent_fd, max_index)) {
 		return 0;
 	}
 
@@ -2968,9 +3202,10 @@ static int ensure_no_fd_conflict(const fd_set *child_fds, int child_fd,
 	 * temporary.
 	 */
 	int fd = child_fd;
-	if (fd == -1 || fd_is_open(fd)) {
-		fd = FD_SETSIZE - 1;
-		while (FD_ISSET(fd, child_fds) || fd_is_open(fd)) {
+	if (fd == -1 || minijail_fd_is_open(fd)) {
+		fd = 1023;
+		while (is_preserved_child_fd(j, fd, j->preserved_fd_count) ||
+		       minijail_fd_is_open(fd)) {
 			--fd;
 			if (fd < 0) {
 				die("failed to find an unused fd");
@@ -2995,28 +3230,22 @@ static int ensure_no_fd_conflict(const fd_set *child_fds, int child_fd,
 }
 
 /*
- * Populate child_fds_out with the set of file descriptors that will be replaced
- * by redirect_fds().
- *
- * NOTE: This creates temporaries for parent file descriptors that would
- * otherwise be overwritten during redirect_fds().
+ * Check for contradictory mappings and create temporaries for parent file
+ * descriptors that would otherwise be overwritten during redirect_fds().
  */
-static int get_child_fds(struct minijail *j, fd_set *child_fds_out)
+static int prepare_preserved_fds(struct minijail *j)
 {
 	/* Relocate parent_fds that would be replaced by a child_fd. */
 	for (size_t i = 0; i < j->preserved_fd_count; i++) {
 		int child_fd = j->preserved_fds[i].child_fd;
-		if (FD_ISSET(child_fd, child_fds_out)) {
+		if (is_preserved_child_fd(j, child_fd, i)) {
 			die("fd %d is mapped more than once", child_fd);
 		}
 
 		int *parent_fd = &j->preserved_fds[i].parent_fd;
-		if (ensure_no_fd_conflict(child_fds_out, child_fd, parent_fd) ==
-		    -1) {
+		if (ensure_no_fd_conflict(j, child_fd, parent_fd, i) == -1) {
 			return -1;
 		}
-
-		FD_SET(child_fd, child_fds_out);
 	}
 	return 0;
 }
@@ -3037,8 +3266,8 @@ struct minijail_run_state {
 /*
  * Move pipe_fds if they conflict with a child_fd.
  */
-static int avoid_pipe_conflicts(struct minijail_run_state *state,
-				fd_set *child_fds_out)
+static int avoid_pipe_conflicts(struct minijail *j,
+				struct minijail_run_state *state)
 {
 	int *pipe_fds[] = {
 	    state->pipe_fds,   state->child_sync_pipe_fds, state->stdin_fds,
@@ -3046,13 +3275,13 @@ static int avoid_pipe_conflicts(struct minijail_run_state *state,
 	};
 	for (size_t i = 0; i < ARRAY_SIZE(pipe_fds); ++i) {
 		if (pipe_fds[i][0] != -1 &&
-		    ensure_no_fd_conflict(child_fds_out, -1, &pipe_fds[i][0]) ==
-			-1) {
+		    ensure_no_fd_conflict(j, -1, &pipe_fds[i][0],
+					  j->preserved_fd_count) == -1) {
 			return -1;
 		}
 		if (pipe_fds[i][1] != -1 &&
-		    ensure_no_fd_conflict(child_fds_out, -1, &pipe_fds[i][1]) ==
-			-1) {
+		    ensure_no_fd_conflict(j, -1, &pipe_fds[i][1],
+					  j->preserved_fd_count) == -1) {
 			return -1;
 		}
 	}
@@ -3065,7 +3294,7 @@ static int avoid_pipe_conflicts(struct minijail_run_state *state,
  * NOTE: This will clear FD_CLOEXEC since otherwise the child_fd would not be
  * inherited after the exec call.
  */
-static int redirect_fds(struct minijail *j, fd_set *child_fds)
+static int redirect_fds(struct minijail *j)
 {
 	for (size_t i = 0; i < j->preserved_fd_count; i++) {
 		if (j->preserved_fds[i].parent_fd ==
@@ -3101,7 +3330,8 @@ static int redirect_fds(struct minijail *j, fd_set *child_fds)
 	 */
 	for (size_t i = 0; i < j->preserved_fd_count; i++) {
 		int parent_fd = j->preserved_fds[i].parent_fd;
-		if (!FD_ISSET(parent_fd, child_fds)) {
+		if (!is_preserved_child_fd(j, parent_fd,
+					   j->preserved_fd_count)) {
 			close(parent_fd);
 		}
 	}
@@ -3152,25 +3382,30 @@ static void setup_child_std_fds(struct minijail *j,
 		close_and_reset(&std_pipes[i][1]);
 	}
 
+	/* Make sure we're not trying to skip setsid() with a PID namespace. */
+	if (!j->flags.enable_new_sessions && j->flags.pids) {
+		die("cannot skip setsid() with PID namespace");
+	}
+
 	/*
-	 * If any of stdin, stdout, or stderr are TTYs, or setsid flag is
-	 * set, create a new session. This prevents the jailed process from
-	 * using the TIOCSTI ioctl to push characters into the parent process
-	 * terminal's input buffer, therefore escaping the jail.
+	 * If new sessions are enabled and any of stdin, stdout, or stderr are
+	 * TTYs, or setsid flag is set, create a new session. This prevents
+	 * the jailed process from using the TIOCSTI ioctl to push characters
+	 * into the parent process terminal's input buffer, therefore escaping
+	 * the jail.
 	 *
 	 * Since it has just forked, the child will not be a process group
 	 * leader, and this call to setsid() should always succeed.
 	 */
-	if (j->flags.setsid || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) ||
-	    isatty(STDERR_FILENO)) {
+	if (j->flags.enable_new_sessions &&
+	    (j->flags.setsid || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) ||
+	     isatty(STDERR_FILENO))) {
 		if (setsid() < 0) {
 			pdie("setsid() failed");
 		}
 
 		if (isatty(STDIN_FILENO)) {
-			if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0) {
-				pwarn("failed to set controlling terminal");
-			}
+			ioctl(STDIN_FILENO, TIOCSCTTY, 0);
 		}
 	}
 }
@@ -3408,6 +3643,9 @@ static int minijail_run_internal(struct minijail *j,
 	if (config->filename != NULL && config->elf_fd != -1) {
 		die("filename and elf_fd cannot be set at the same time");
 	}
+	if (config->filename != NULL) {
+		j->filename = strdup(config->filename);
+	}
 
 	/*
 	 * Only copy the environment if we need to modify it. If this is done
@@ -3437,9 +3675,7 @@ static int minijail_run_internal(struct minijail *j,
 		if (setup_preload(j, &state_out->child_env) ||
 		    setup_pipe(&state_out->child_env, state_out->pipe_fds))
 			return -EFAULT;
-	}
-
-	if (!use_preload) {
+	} else {
 		if (j->flags.use_caps && j->caps != 0 &&
 		    !j->flags.set_ambient_caps) {
 			die("non-empty, non-ambient capabilities are not "
@@ -3512,7 +3748,7 @@ static int minijail_run_internal(struct minijail *j,
 	 * memory regions / etc attached). We'd need to keep the child around to
 	 * avoid having its children get reparented to init.
 	 *
-	 * TODO(ellyjones): figure out if the "forked child hanging around"
+	 * TODO(b/317404364): figure out if the "forked child hanging around"
 	 * problem is fixable or not. It would be nice if we worked in this
 	 * case.
 	 */
@@ -3532,12 +3768,25 @@ static int minijail_run_internal(struct minijail *j,
 			pdie("clone(CLONE_NEWPID | ...) failed");
 		}
 	} else {
+		if (j->flags.userns)
+			die("user namespaces in Minijail require a PID "
+			    "namespace");
+
 		child_pid = fork();
 
 		if (child_pid < 0)
 			pdie("fork failed");
 	}
 
+	/*
+	 * setup_fs_rules_fd() needs to be called before close_open_fds(), and
+	 * before logic for the child process.
+	 */
+	if (j->fs_rules_head) {
+		setup_fs_rules_fd(j);
+		minijail_preserve_fd(j, j->fs_rules_fd, j->fs_rules_fd);
+	}
+
 	state_out->child_pid = child_pid;
 	if (child_pid) {
 		j->initpid = child_pid;
@@ -3691,20 +3940,19 @@ static int minijail_run_internal(struct minijail *j,
 	}
 
 	/* The set of fds will be replaced. */
-	fd_set child_fds;
-	FD_ZERO(&child_fds);
-	if (get_child_fds(j, &child_fds))
+	if (prepare_preserved_fds(j))
 		die("failed to set up fd redirections");
 
-	if (avoid_pipe_conflicts(state_out, &child_fds))
+	if (avoid_pipe_conflicts(j, state_out))
 		die("failed to redirect conflicting pipes");
 
 	/* The elf_fd needs to be mutable so use a stack copy from now on. */
 	int elf_fd = config->elf_fd;
-	if (elf_fd != -1 && ensure_no_fd_conflict(&child_fds, -1, &elf_fd))
+	if (elf_fd != -1 &&
+	    ensure_no_fd_conflict(j, -1, &elf_fd, j->preserved_fd_count))
 		die("failed to redirect elf_fd");
 
-	if (redirect_fds(j, &child_fds))
+	if (redirect_fds(j))
 		die("failed to set up fd redirections");
 
 	if (sync_child)
@@ -3936,12 +4184,7 @@ void API minijail_destroy(struct minijail *j)
 		free(c);
 	}
 	j->hooks_tail = NULL;
-	while (j->fs_rules_head) {
-		struct fs_rule *r = j->fs_rules_head;
-		j->fs_rules_head = r->next;
-		free(r);
-	}
-	j->fs_rules_tail = NULL;
+	free_fs_rules_list(j);
 	if (j->user)
 		free(j->user);
 	if (j->suppl_gid_list)
@@ -3958,6 +4201,8 @@ void API minijail_destroy(struct minijail *j)
 		free(j->hostname);
 	if (j->preload_path)
 		free(j->preload_path);
+	if (j->filename)
+		free(j->filename);
 	if (j->alt_syscall_table)
 		free(j->alt_syscall_table);
 	for (i = 0; i < j->cgroup_count; ++i)
@@ -3971,3 +4216,10 @@ void API minijail_log_to_fd(int fd, int min_priority)
 {
 	init_logging(LOG_TO_FD, fd, min_priority);
 }
+
+const char API *minijail_syscall_name(const struct minijail *j, long nr)
+{
+	if (j && j->flags.alt_syscall)
+		return kAltSyscallNamePlaceholder;
+	return lookup_syscall_name(nr);
+}
diff --git a/libminijail.h b/libminijail.h
index 1125169..60bfe77 100644
--- a/libminijail.h
+++ b/libminijail.h
@@ -15,6 +15,7 @@
 #ifndef _LIBMINIJAIL_H_
 #define _LIBMINIJAIL_H_
 
+#include <stdbool.h>
 #include <stdint.h>
 #include <sys/resource.h>
 #include <sys/types.h>
@@ -27,6 +28,15 @@
 #include <linux/filter.h>
 #endif
 
+/*
+ * The specified function arguments may not be NULL.  Params starts counting
+ * from 1, not 0.  If no params are specified, then all function arguments are
+ * marked as non-NULL.  Thus, params should only be specified if a function
+ * accepts NULL pointers for any of the arguments.
+ * NB: Keep in sync with util.h style.
+ */
+#define MINIJAIL_ATTRIBUTE_NONNULL(params) __attribute__((__nonnull__ params))
+
 #ifdef __cplusplus
 extern "C" {
 #endif
@@ -39,7 +49,8 @@ enum {
 	/* Command cannot be found */
 	MINIJAIL_ERR_NO_COMMAND = 127,
 
-	/* (MINIJAIL_ERR_SIG_BASE + n) if process killed by signal n != SIGSYS */
+	/* (MINIJAIL_ERR_SIG_BASE + n) if process killed by signal n != SIGSYS
+	 */
 	MINIJAIL_ERR_SIG_BASE = 128,
 
 	/* Cannot mount a file or folder in mount namespace */
@@ -92,24 +103,52 @@ struct minijail *minijail_new(void);
  * minijail_enter() is called. See the documentation in minijail0.1 for
  * explanations in detail of what the restrictions do.
  */
-void minijail_change_uid(struct minijail *j, uid_t uid);
-void minijail_change_gid(struct minijail *j, gid_t gid);
+void minijail_change_uid(struct minijail *j, uid_t uid)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_change_gid(struct minijail *j, gid_t gid)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* Copies |list|. */
 void minijail_set_supplementary_gids(struct minijail *j, size_t size,
-				     const gid_t *list);
-void minijail_keep_supplementary_gids(struct minijail *j);
+				     const gid_t *list)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_keep_supplementary_gids(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* Stores user to change to and copies |user| for internal consistency. */
-int minijail_change_user(struct minijail *j, const char *user);
+int minijail_change_user(struct minijail *j, const char *user)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* Does not take ownership of |group|. */
-int minijail_change_group(struct minijail *j, const char *group);
-void minijail_use_seccomp(struct minijail *j);
-void minijail_no_new_privs(struct minijail *j);
-void minijail_use_seccomp_filter(struct minijail *j);
-void minijail_set_seccomp_filter_tsync(struct minijail *j);
+int minijail_change_group(struct minijail *j, const char *group)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_use_seccomp(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_no_new_privs(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_use_seccomp_filter(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_set_seccomp_filter_tsync(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* Sets using_minimalistic_mountns to true. */
-void minijail_set_using_minimalistic_mountns(struct minijail *j);
-void minijail_add_minimalistic_mountns_fs_rules(struct minijail *j);
-void minijail_enable_default_fs_restrictions(struct minijail *j);
+void minijail_set_using_minimalistic_mountns(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_set_enable_default_runtime(struct minijail *j,
+					 bool enable_default_runtime)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_set_enable_new_sessions(struct minijail *j,
+				      bool enable_new_sessions)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+/*
+ * Sets enable_profile_fs_restrictions to true.
+ *
+ * Exposed for unit tests and allowlisting services.
+ */
+bool minijail_get_enable_default_runtime(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_disable_fs_restrictions(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_set_enable_profile_fs_restrictions(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_add_minimalistic_mountns_fs_rules(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_enable_default_fs_restrictions(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /*
  * Allow speculative execution features that may cause data leaks across
  * processes, by setting the SECCOMP_FILTER_FLAG_SPEC_ALLOW seccomp flag.
@@ -118,45 +157,84 @@ void minijail_enable_default_fs_restrictions(struct minijail *j);
  * execution attacks (Branch Target Injection, and Speculative Store Bypass).
  * This is only safe to use for processes that do not execute untrusted code.
  */
-void minijail_set_seccomp_filter_allow_speculation(struct minijail *j);
+void minijail_set_seccomp_filter_allow_speculation(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* Does not take ownership of |filter|. */
 void minijail_set_seccomp_filters(struct minijail *j,
-				  const struct sock_fprog *filter);
-void minijail_parse_seccomp_filters(struct minijail *j, const char *path);
-void minijail_parse_seccomp_filters_from_fd(struct minijail *j, int fd);
-void minijail_log_seccomp_filter_failures(struct minijail *j);
+				  const struct sock_fprog *filter)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_parse_seccomp_filters(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_parse_seccomp_filters_from_fd(struct minijail *j, int fd)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_log_seccomp_filter_failures(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* 'minijail_use_caps' and 'minijail_capbset_drop' are mutually exclusive. */
-void minijail_use_caps(struct minijail *j, uint64_t capmask);
-void minijail_capbset_drop(struct minijail *j, uint64_t capmask);
+void minijail_use_caps(struct minijail *j, uint64_t capmask)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_capbset_drop(struct minijail *j, uint64_t capmask)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 /* 'minijail_set_ambient_caps' requires 'minijail_use_caps'. */
-void minijail_set_ambient_caps(struct minijail *j);
-void minijail_reset_signal_mask(struct minijail *j);
-void minijail_reset_signal_handlers(struct minijail *j);
-void minijail_namespace_vfs(struct minijail *j);
-void minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path);
-void minijail_new_session_keyring(struct minijail *j);
+void minijail_set_ambient_caps(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_reset_signal_mask(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_reset_signal_handlers(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_vfs(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_new_session_keyring(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 void minijail_skip_setting_securebits(struct minijail *j,
-				      uint64_t securebits_skip_mask);
+				      uint64_t securebits_skip_mask)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * This option is *dangerous* as it negates most of the functionality of
  * minijail_namespace_vfs(). You very likely don't need this.
  */
-void minijail_skip_remount_private(struct minijail *j);
-void minijail_remount_mode(struct minijail *j, unsigned long mode);
-void minijail_namespace_ipc(struct minijail *j);
-void minijail_namespace_uts(struct minijail *j);
-int minijail_namespace_set_hostname(struct minijail *j, const char *name);
-void minijail_namespace_net(struct minijail *j);
-void minijail_namespace_enter_net(struct minijail *j, const char *ns_path);
-void minijail_namespace_cgroups(struct minijail *j);
+void minijail_skip_remount_private(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_remount_mode(struct minijail *j, unsigned long mode)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_ipc(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_uts(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+int minijail_namespace_set_hostname(struct minijail *j, const char *name)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
+/*
+ * Starts a new network namespace with or without a loopback interface.
+ * It is rare for jails to not bring up the loopback interface, and having it
+ * available is not a security concern. Please double check you actually need to
+ * disable it before using this API.
+ *
+ * @j minijail to apply restriction to.
+ * @enable_loopback indicates whether the loopback interface should be enabled
+ * in this new network namespace.
+ */
+void minijail_namespace_net_loopback(struct minijail *j, bool enable_loopback)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
+/*
+ * Starts a new network namespace featuring a loopback interface.
+ * This has the same effect as `minijail_namespace_net_loopback(j, true)`.
+ */
+void minijail_namespace_net(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+
+void minijail_namespace_enter_net(struct minijail *j, const char *ns_path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_cgroups(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
 /* Closes all open file descriptors after forking. */
-void minijail_close_open_fds(struct minijail *j);
+void minijail_close_open_fds(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+
 /*
  * Implies namespace_vfs and remount_proc_readonly.
  * WARNING: this is NOT THREAD SAFE. See the block comment in </libminijail.c>.
  */
-void minijail_namespace_pids(struct minijail *j);
+void minijail_namespace_pids(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+
 /*
  * Implies namespace_vfs.
  * WARNING: this is NOT THREAD SAFE. See the block comment in </libminijail.c>.
@@ -165,23 +243,34 @@ void minijail_namespace_pids(struct minijail *j);
  * which might require writing to /proc, so support a weaker version of PID
  * namespacing with a RW /proc.
  */
-void minijail_namespace_pids_rw_proc(struct minijail *j);
-void minijail_namespace_user(struct minijail *j);
-void minijail_namespace_user_disable_setgroups(struct minijail *j);
-int minijail_uidmap(struct minijail *j, const char *uidmap);
-int minijail_gidmap(struct minijail *j, const char *gidmap);
-void minijail_remount_proc_readonly(struct minijail *j);
-void minijail_run_as_init(struct minijail *j);
-int minijail_write_pid_file(struct minijail *j, const char *path);
-void minijail_inherit_usergroups(struct minijail *j);
+void minijail_namespace_pids_rw_proc(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
+void minijail_namespace_user(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_namespace_user_disable_setgroups(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+int minijail_uidmap(struct minijail *j, const char *uidmap)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+int minijail_gidmap(struct minijail *j, const char *gidmap)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_remount_proc_readonly(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_run_as_init(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
+int minijail_write_pid_file(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+void minijail_inherit_usergroups(struct minijail *j)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
 /*
  * Changes the jailed process's syscall table to the alt_syscall table
  * named |table|.
  */
-int minijail_use_alt_syscall(struct minijail *j, const char *table);
+int minijail_use_alt_syscall(struct minijail *j, const char *table)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* Sets the given runtime limit. See getrlimit(2). */
-int minijail_rlimit(struct minijail *j, int type, rlim_t cur, rlim_t max);
+int minijail_rlimit(struct minijail *j, int type, rlim_t cur, rlim_t max)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Adds the jailed process to the cgroup given by |path|.  |path| should be the
@@ -189,36 +278,64 @@ int minijail_rlimit(struct minijail *j, int type, rlim_t cur, rlim_t max);
  * Example: /sys/fs/cgroup/cpu/jailed_procs/tasks adds to the "jailed_procs" cpu
  * cgroup.
  */
-int minijail_add_to_cgroup(struct minijail *j, const char *path);
+int minijail_add_to_cgroup(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * These functions are used for filesystem restrictions.
  */
 
+/*
+ * Indicates whether minijail_add_fs_restriction_* functions are available. Even
+ * if they are unavailable, minijail_add_fs_restriction_* functions would still
+ * succeed, however without any actual effects.
+ */
+bool minijail_is_fs_restriction_available(void);
+
 /* Adds a read-execute path. */
-int minijail_add_fs_restriction_rx(struct minijail *j, const char *path);
+int minijail_add_fs_restriction_rx(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* Adds a read-only path. */
-int minijail_add_fs_restriction_ro(struct minijail *j, const char *path);
+int minijail_add_fs_restriction_ro(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* Adds a path with read and basic write permissions. */
-int minijail_add_fs_restriction_rw(struct minijail *j, const char *path);
+int minijail_add_fs_restriction_rw(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* Adds a path with read and advanced write permissions. */
 int minijail_add_fs_restriction_advanced_rw(struct minijail *j,
-					    const char *path);
+					    const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* Adds a path with read and write permissions that exclude create. */
-int minijail_add_fs_restriction_edit(struct minijail *j, const char *path);
+int minijail_add_fs_restriction_edit(struct minijail *j, const char *path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
+/* Adds a path with permissions based on a bitmask of Landlock flags. */
+int minijail_add_fs_restriction_access_rights(struct minijail *j,
+					      const char *path,
+					      uint16_t landlock_flags)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
+/*
+ * Indicates whether a filesystem restriction ruleset has been initialized.
+ *
+ * Exposed primarily for testing.
+ *
+ * This only indicates initialization status, not sandboxing status.
+ */
+bool minijail_is_fs_restriction_ruleset_initialized(const struct minijail *j);
 
 /*
  * Install signal handlers in the minijail process that forward received
  * signals to the jailed child process.
  */
-int minijail_forward_signals(struct minijail *j);
+int minijail_forward_signals(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /* The jailed child process should call setsid() to create a new session. */
-int minijail_create_session(struct minijail *j);
+int minijail_create_session(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_enter_chroot: enables chroot() restriction for @j
@@ -231,8 +348,10 @@ int minijail_create_session(struct minijail *j);
  *
  * Returns 0 on success.
  */
-int minijail_enter_chroot(struct minijail *j, const char *dir);
-int minijail_enter_pivot_root(struct minijail *j, const char *dir);
+int minijail_enter_chroot(struct minijail *j, const char *dir)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+int minijail_enter_pivot_root(struct minijail *j, const char *dir)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_get_original_path: returns the path of a given file outside of the
@@ -245,26 +364,28 @@ int minijail_enter_pivot_root(struct minijail *j, const char *dir);
  *
  * Returns a string containing the path.  This must be freed by the caller.
  */
-char *minijail_get_original_path(struct minijail *j, const char *chroot_path);
+char *minijail_get_original_path(struct minijail *j, const char *chroot_path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_mount_tmp: enables mounting of a 64M tmpfs filesystem on /tmp.
  * As be rules of bind mounts, /tmp must exist in chroot.
  */
-void minijail_mount_tmp(struct minijail *j);
+void minijail_mount_tmp(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_mount_tmp_size: enables mounting of a tmpfs filesystem on /tmp.
  * As be rules of bind mounts, /tmp must exist in chroot.  Size is in bytes.
  */
-void minijail_mount_tmp_size(struct minijail *j, size_t size);
+void minijail_mount_tmp_size(struct minijail *j, size_t size)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_mount_dev: enables mounting of a tmpfs filesystem on /dev.
  * It will then be seeded with a basic set of device nodes.  For the exact
  * list, consult the minijail(0) man page.
  */
-void minijail_mount_dev(struct minijail *j);
+void minijail_mount_dev(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_mount_with_data: when entering minijail @j,
@@ -284,7 +405,8 @@ void minijail_mount_dev(struct minijail *j);
  */
 int minijail_mount_with_data(struct minijail *j, const char *src,
 			     const char *dest, const char *type,
-			     unsigned long flags, const char *data);
+			     unsigned long flags, const char *data)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3, 4));
 
 /*
  * minijail_mount: when entering minijail @j, mounts @src at @dst with @flags
@@ -298,7 +420,8 @@ int minijail_mount_with_data(struct minijail *j, const char *src,
  * of minijail_mount() calls.
  */
 int minijail_mount(struct minijail *j, const char *src, const char *dest,
-		   const char *type, unsigned long flags);
+		   const char *type, unsigned long flags)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_bind: bind-mounts @src into @j as @dest, optionally writeable
@@ -311,7 +434,7 @@ int minijail_mount(struct minijail *j, const char *src, const char *dest,
  * of minijail_bind() calls.
  */
 int minijail_bind(struct minijail *j, const char *src, const char *dest,
-		  int writeable);
+		  int writeable) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_add_remount: when entering minijail @j, remounts @mount_name and all
@@ -324,7 +447,9 @@ int minijail_bind(struct minijail *j, const char *src, const char *dest,
  * given mount.
  */
 int minijail_add_remount(struct minijail *j, const char *mount_name,
-			 unsigned long remount_mode);
+			 unsigned long remount_mode)
+    MINIJAIL_ATTRIBUTE_NONNULL();
+
 /*
  * minijail_add_hook: adds @hook to the list of hooks that will be
  * invoked when @event is reached during minijail setup. The caller is
@@ -334,9 +459,9 @@ int minijail_add_remount(struct minijail *j, const char *mount_name,
  * @payload   an opaque pointer
  * @event     the event that will trigger the hook
  */
-int minijail_add_hook(struct minijail *j,
-		      minijail_hook_t hook, void *payload,
-		      minijail_hook_event_t event);
+int minijail_add_hook(struct minijail *j, minijail_hook_t hook, void *payload,
+		      minijail_hook_event_t event)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2));
 
 /*
  * minijail_preserve_fd: preserves @parent_fd and makes it available as
@@ -347,13 +472,15 @@ int minijail_add_hook(struct minijail *j,
  * @parent_fd the fd in the parent process
  * @child_fd  the fd that will be available in the child process
  */
-int minijail_preserve_fd(struct minijail *j, int parent_fd, int child_fd);
+int minijail_preserve_fd(struct minijail *j, int parent_fd, int child_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_set_preload_path: overrides the default path for
  * libminijailpreload.so.
  */
-int minijail_set_preload_path(struct minijail *j, const char *preload_path);
+int minijail_set_preload_path(struct minijail *j, const char *preload_path)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Lock this process into the given minijail. Note that this procedure cannot
@@ -364,22 +491,23 @@ int minijail_set_preload_path(struct minijail *j, const char *preload_path);
  * Some restrictions cannot be enabled this way (pid namespaces) and attempting
  * to do so will cause an abort.
  */
-void minijail_enter(const struct minijail *j);
+void minijail_enter(const struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
  * Pass |envp| as the full environment for the child.
  */
 int minijail_run_env(struct minijail *j, const char *filename,
-		     char *const argv[], char *const envp[]);
+		     char *const argv[], char *const envp[])
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
  * If minijail_namespace_pids() or minijail_namespace_user() are used,
  * this or minijail_fork() is required instead of minijail_enter().
  */
-int minijail_run(struct minijail *j, const char *filename,
-		 char *const argv[]);
+int minijail_run(struct minijail *j, const char *filename, char *const argv[])
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -387,14 +515,15 @@ int minijail_run(struct minijail *j, const char *filename,
  * static binaries, or on systems without support for LD_PRELOAD.
  */
 int minijail_run_no_preload(struct minijail *j, const char *filename,
-			    char *const argv[]);
+			    char *const argv[]) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
  * Update |*pchild_pid| with the pid of the child.
  */
 int minijail_run_pid(struct minijail *j, const char *filename,
-		     char *const argv[], pid_t *pchild_pid);
+		     char *const argv[], pid_t *pchild_pid)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -402,7 +531,8 @@ int minijail_run_pid(struct minijail *j, const char *filename,
  * standard input.
  */
 int minijail_run_pipe(struct minijail *j, const char *filename,
-		      char *const argv[], int *pstdin_fd);
+		      char *const argv[], int *pstdin_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -416,7 +546,8 @@ int minijail_run_pipe(struct minijail *j, const char *filename,
  */
 int minijail_run_pid_pipes(struct minijail *j, const char *filename,
 			   char *const argv[], pid_t *pchild_pid,
-			   int *pstdin_fd, int *pstdout_fd, int *pstderr_fd);
+			   int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -432,7 +563,8 @@ int minijail_run_pid_pipes(struct minijail *j, const char *filename,
 int minijail_run_env_pid_pipes(struct minijail *j, const char *filename,
 			       char *const argv[], char *const envp[],
 			       pid_t *pchild_pid, int *pstdin_fd,
-			       int *pstdout_fd, int *pstderr_fd);
+			       int *pstdout_fd, int *pstderr_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Execute the specified file descriptor in the given minijail,
@@ -447,9 +579,10 @@ int minijail_run_env_pid_pipes(struct minijail *j, const char *filename,
  * standard error.
  */
 int minijail_run_fd_env_pid_pipes(struct minijail *j, int elf_fd,
-			          char *const argv[], char *const envp[],
+				  char *const argv[], char *const envp[],
 				  pid_t *pchild_pid, int *pstdin_fd,
-				  int *pstdout_fd, int *pstderr_fd);
+				  int *pstdout_fd, int *pstderr_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 3));
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -466,7 +599,8 @@ int minijail_run_fd_env_pid_pipes(struct minijail *j, int elf_fd,
 int minijail_run_pid_pipes_no_preload(struct minijail *j, const char *filename,
 				      char *const argv[], pid_t *pchild_pid,
 				      int *pstdin_fd, int *pstdout_fd,
-				      int *pstderr_fd);
+				      int *pstderr_fd)
+    MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Run the specified command in the given minijail, execve(2)-style.
@@ -481,12 +615,10 @@ int minijail_run_pid_pipes_no_preload(struct minijail *j, const char *filename,
  * Don't use LD_PRELOAD to do privilege dropping. This is useful when sandboxing
  * static binaries, or on systems without support for LD_PRELOAD.
  */
-int minijail_run_env_pid_pipes_no_preload(struct minijail *j,
-					  const char *filename,
-					  char *const argv[],
-					  char *const envp[], pid_t *pchild_pid,
-					  int *pstdin_fd, int *pstdout_fd,
-					  int *pstderr_fd);
+int minijail_run_env_pid_pipes_no_preload(
+    struct minijail *j, const char *filename, char *const argv[],
+    char *const envp[], pid_t *pchild_pid, int *pstdin_fd, int *pstdout_fd,
+    int *pstderr_fd) MINIJAIL_ATTRIBUTE_NONNULL((1, 2, 3));
 
 /*
  * Fork, jail the child, and return. This behaves similar to fork(2), except it
@@ -497,7 +629,7 @@ int minijail_run_env_pid_pipes_no_preload(struct minijail *j,
  * If minijail_namespace_pids() or minijail_namespace_user() are used,
  * this or minijail_run*() is required instead of minijail_enter().
  */
-pid_t minijail_fork(struct minijail *j);
+pid_t minijail_fork(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Send SIGTERM to the process in the minijail and wait for it to terminate.
@@ -508,7 +640,7 @@ pid_t minijail_fork(struct minijail *j);
  * This is most useful if the minijail has been created with PID namespacing
  * since, in this case, all processes inside it are atomically killed.
  */
-int minijail_kill(struct minijail *j);
+int minijail_kill(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Wait for the first process spawned in the specified minijail to exit, and
@@ -523,14 +655,14 @@ int minijail_kill(struct minijail *j);
  *   (MINIJAIL_ERR_SIG_BASE  + n) if process was killed by signal n != SIGSYS.
  *   (n & 0xFF) if process finished by returning code n.
  */
-int minijail_wait(struct minijail *j);
+int minijail_wait(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Frees the given minijail. It does not matter if the process is inside the
- * minijail or not. It will not kill the process, see minijail_kill() if that is 
+ * minijail or not. It will not kill the process, see minijail_kill() if that is
  * desired.
  */
-void minijail_destroy(struct minijail *j);
+void minijail_destroy(struct minijail *j) MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * Deep copies the minijail in |from| to |out| providing two identical jails
@@ -540,7 +672,8 @@ void minijail_destroy(struct minijail *j);
  * minijail_fork(). Many minijail_*() calls will yield undefined
  * results when called on a jail duplicated post-fork.
  */
-int minijail_copy_jail(const struct minijail *from, struct minijail *out);
+int minijail_copy_jail(const struct minijail *from, struct minijail *out)
+    MINIJAIL_ATTRIBUTE_NONNULL();
 
 /*
  * minijail_log_to_fd: redirects the module-wide logging to an FD instead of
@@ -552,6 +685,20 @@ int minijail_copy_jail(const struct minijail *from, struct minijail *out);
  */
 void minijail_log_to_fd(int fd, int min_priority);
 
+/*
+ * minijail_syscall_name: Returns the name of the provided system call on the
+ * current architecture. This is exposed to make tasks like including the
+ * system call name in crash reports possible. Note this does not support
+ * alt-syscall or other supported ABIs such as x86 (32-bit) when this is built
+ * for x86_64 (64-bit).
+ * @j            Optional minijail struct to check if features that affect
+ *               syscall tables. If NULL, the current syscall ABI is used.
+ * @nr           The system call number.
+ *
+ * Returns the system call name if found otherwise NULL.
+ */
+const char *minijail_syscall_name(const struct minijail *j, long nr);
+
 #ifdef __cplusplus
 } /* extern "C" */
 #endif
diff --git a/libminijail_unittest.cc b/libminijail_unittest.cc
index 7ffbde5..7ff12d5 100644
--- a/libminijail_unittest.cc
+++ b/libminijail_unittest.cc
@@ -11,7 +11,9 @@
 #include <fcntl.h>
 #include <sys/mman.h>
 #include <sys/mount.h>
+#include <sys/resource.h>
 #include <sys/stat.h>
+#include <sys/syscall.h>
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <unistd.h>
@@ -27,21 +29,28 @@
 #include "libminijail-private.h"
 #include "libminijail.h"
 #include "scoped_minijail.h"
+#include "test_util.h"
 #include "unittest_util.h"
 #include "util.h"
 
 namespace {
 
 #if defined(__ANDROID__)
-# define ROOT_PREFIX "/system"
+#define ROOT_PREFIX "/system"
 #else
-# define ROOT_PREFIX ""
+#define ROOT_PREFIX ""
 #endif
 
 constexpr char kShellPath[] = ROOT_PREFIX "/bin/sh";
 constexpr char kCatPath[] = ROOT_PREFIX "/bin/cat";
 constexpr char kPreloadPath[] = "./libminijailpreload.so";
 constexpr size_t kBufferSize = 128;
+constexpr bool kCompiledWithCoverage =
+#if defined(CROS_CODE_COVERAGE_ENABLED)
+    true;
+#else
+    false;
+#endif
 
 std::set<pid_t> GetProcessSubtreePids(pid_t root_pid) {
   std::set<pid_t> pids{root_pid};
@@ -89,8 +98,7 @@ std::set<pid_t> GetProcessSubtreePids(pid_t root_pid) {
 }
 
 std::map<std::string, std::string> GetNamespaces(
-    pid_t pid,
-    const std::vector<std::string>& namespace_names) {
+    pid_t pid, const std::vector<std::string>& namespace_names) {
   std::map<std::string, std::string> namespaces;
   char buf[kBufferSize];
   for (const auto& namespace_name : namespace_names) {
@@ -112,7 +120,7 @@ void set_preload_path(minijail *j) {
 #endif
   // We need to get the absolute path because entering a new mntns will
   // implicitly chdir(/) for us.
-  char *preload_path = realpath(kPreloadPath, nullptr);
+  char* preload_path = realpath(kPreloadPath, nullptr);
   ASSERT_NE(preload_path, nullptr);
   minijail_set_preload_path(j, preload_path);
   free(preload_path);
@@ -130,7 +138,7 @@ TEST(silence, silence_unused) {
 TEST(consumebytes, zero) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   EXPECT_NE(nullptr, consumebytes(0, &pos, &len));
   EXPECT_EQ(&buf[0], pos);
   EXPECT_EQ(sizeof(buf), len);
@@ -139,9 +147,9 @@ TEST(consumebytes, zero) {
 TEST(consumebytes, exact) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   /* One past the end since it consumes the whole buffer. */
-  char *end = &buf[sizeof(buf)];
+  char* end = &buf[sizeof(buf)];
   EXPECT_NE(nullptr, consumebytes(len, &pos, &len));
   EXPECT_EQ((size_t)0, len);
   EXPECT_EQ(end, pos);
@@ -150,9 +158,9 @@ TEST(consumebytes, exact) {
 TEST(consumebytes, half) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   /* One past the end since it consumes the whole buffer. */
-  char *end = &buf[sizeof(buf) / 2];
+  char* end = &buf[sizeof(buf) / 2];
   EXPECT_NE(nullptr, consumebytes(len / 2, &pos, &len));
   EXPECT_EQ(sizeof(buf) / 2, len);
   EXPECT_EQ(end, pos);
@@ -161,7 +169,7 @@ TEST(consumebytes, half) {
 TEST(consumebytes, toolong) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   /* One past the end since it consumes the whole buffer. */
   EXPECT_EQ(nullptr, consumebytes(len + 1, &pos, &len));
   EXPECT_EQ(sizeof(buf), len);
@@ -171,7 +179,7 @@ TEST(consumebytes, toolong) {
 TEST(consumestr, zero) {
   char buf[1024];
   size_t len = 0;
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   memset(buf, 0xff, sizeof(buf));
   EXPECT_EQ(nullptr, consumestr(&pos, &len));
   EXPECT_EQ((size_t)0, len);
@@ -181,7 +189,7 @@ TEST(consumestr, zero) {
 TEST(consumestr, nonul) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   memset(buf, 0xff, sizeof(buf));
   EXPECT_EQ(nullptr, consumestr(&pos, &len));
   EXPECT_EQ(sizeof(buf), len);
@@ -191,10 +199,10 @@ TEST(consumestr, nonul) {
 TEST(consumestr, full) {
   char buf[1024];
   size_t len = sizeof(buf);
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   memset(buf, 0xff, sizeof(buf));
-  buf[sizeof(buf)-1] = '\0';
-  EXPECT_EQ((void *)buf, consumestr(&pos, &len));
+  buf[sizeof(buf) - 1] = '\0';
+  EXPECT_EQ((void*)buf, consumestr(&pos, &len));
   EXPECT_EQ((size_t)0, len);
   EXPECT_EQ(&buf[sizeof(buf)], pos);
 }
@@ -202,9 +210,9 @@ TEST(consumestr, full) {
 TEST(consumestr, trailing_nul) {
   char buf[1024];
   size_t len = sizeof(buf) - 1;
-  char *pos = &buf[0];
+  char* pos = &buf[0];
   memset(buf, 0xff, sizeof(buf));
-  buf[sizeof(buf)-1] = '\0';
+  buf[sizeof(buf) - 1] = '\0';
   EXPECT_EQ(nullptr, consumestr(&pos, &len));
   EXPECT_EQ(sizeof(buf) - 1, len);
   EXPECT_EQ(&buf[0], pos);
@@ -223,8 +231,8 @@ class MarshalTest : public ::testing::Test {
   }
 
   char buf_[4096];
-  struct minijail *m_;
-  struct minijail *j_;
+  struct minijail* m_;
+  struct minijail* j_;
   size_t size_;
 };
 
@@ -243,6 +251,19 @@ TEST_F(MarshalTest, copy_empty) {
   ASSERT_EQ(0, minijail_copy_jail(m_, j_));
 }
 
+TEST_F(MarshalTest, profile_flags) {
+  minijail_bind(m_, "/var", "/var", false);
+  minijail_set_using_minimalistic_mountns(m_);
+  minijail_set_enable_profile_fs_restrictions(m_);
+  minijail_add_minimalistic_mountns_fs_rules(m_);
+  size_ = minijail_size(m_);
+  for (size_t offset = 0; offset < 8; ++offset) {
+    do_log(LOG_INFO, "offset: %zu", offset);
+    ASSERT_EQ(0, minijail_marshal(m_, buf_ + offset, sizeof(buf_) - offset));
+    EXPECT_EQ(0, minijail_unmarshal(j_, buf_ + offset, size_));
+  }
+}
+
 TEST(KillTest, running_process) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "sleep 1000", nullptr};
@@ -254,6 +275,7 @@ TEST(KillTest, running_process) {
 TEST(KillTest, process_already_awaited) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "sleep 1; exit 42", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), 42);
   EXPECT_EQ(minijail_kill(j.get()), -ESRCH);
@@ -263,6 +285,7 @@ TEST(KillTest, process_already_finished_but_not_awaited) {
   int fds[2];
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "exit 42", nullptr};
+  set_preload_path(j.get());
   ASSERT_EQ(pipe(fds), 0);
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   ASSERT_EQ(close(fds[1]), 0);
@@ -281,6 +304,7 @@ TEST(KillTest, process_not_started) {
 TEST(WaitTest, return_zero) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "exit 0", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), 0);
 }
@@ -288,6 +312,7 @@ TEST(WaitTest, return_zero) {
 TEST(WaitTest, return_max) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "exit 255", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), 255);
 }
@@ -295,6 +320,7 @@ TEST(WaitTest, return_max) {
 TEST(WaitTest, return_modulo) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "exit 256", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), 0);
 }
@@ -302,13 +328,15 @@ TEST(WaitTest, return_modulo) {
 TEST(WaitTest, killed_by_sigkill) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "kill -KILL $$; sleep 1000", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
-  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_SIG_BASE  + SIGKILL);
+  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_SIG_BASE + SIGKILL);
 }
 
 TEST(WaitTest, killed_by_sigsys) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "kill -SYS $$; sleep 1000", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_JAIL);
 }
@@ -335,6 +363,7 @@ TEST(WaitTest, no_process) {
 TEST(WaitTest, can_wait_only_once) {
   const ScopedMinijail j(minijail_new());
   char* const argv[] = {"sh", "-c", "exit 0", nullptr};
+  set_preload_path(j.get());
   EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
   EXPECT_EQ(minijail_wait(j.get()), 0);
   EXPECT_EQ(minijail_wait(j.get()), -ECHILD);
@@ -352,7 +381,11 @@ TEST(Test, minijail_preserve_fd_no_leak) {
     )";
   char* const argv[] = {"sh", "-c", script, nullptr};
 
-  const int npipes = 3;
+  struct rlimit limit {};
+  ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
+  const int high_fd = limit.rlim_cur - 1;
+
+  const int npipes = 4;
   int fds[npipes][2];
 
   // Create pipes.
@@ -360,6 +393,12 @@ TEST(Test, minijail_preserve_fd_no_leak) {
     ASSERT_EQ(pipe(fds[i]), 0);
   }
 
+  // (b/308042314) Move a pipe to > 1024 to check for a crash.
+  ASSERT_FALSE(minijail_fd_is_open(high_fd)) << "high_fd is already in use";
+  ASSERT_EQ(dup2(fds[3][1], high_fd), high_fd) << strerror(errno);
+  EXPECT_EQ(close(fds[3][1]), 0);
+  fds[3][1] = high_fd;
+
   // All pipes are output pipes except for the first one which is used as
   // input pipe.
   std::swap(fds[0][0], fds[0][1]);
@@ -439,7 +478,9 @@ TEST(Test, close_original_pipes_after_dup2) {
       read line2;
       echo "$line1$line2 and Goodbye" >&%d;
       exit 42;
-    )", to_wait[1]), 0);
+    )",
+                     to_wait[1]),
+            0);
   char* const argv[] = {"sh", "-c", program, nullptr};
 
   int in = -1;
@@ -520,7 +561,7 @@ TEST(Test, minijail_no_clobber_pipe_fd) {
   // Generate a lot of mappings to try to clobber any file descriptors generated
   // by libminijail.
   for (int offset = 0; offset < npipes * 3; offset += npipes) {
-    for (int i = 0 ; i < npipes; ++i) {
+    for (int i = 0; i < npipes; ++i) {
       const int fd = fds[i][1];
       minijail_preserve_fd(j.get(), fd, i + offset);
     }
@@ -582,20 +623,22 @@ TEST(Test, minijail_no_clobber_pipe_fd) {
 TEST(Test, minijail_run_env_pid_pipes) {
   // TODO(crbug.com/895875): The preload library interferes with ASan since they
   // both need to use LD_PRELOAD.
-  if (running_with_asan())
+  // TODO(b/238743201): This test consistently breaks with code coverage
+  // enabled. That should be fixed.
+  if (kCompiledWithCoverage || running_with_asan())
     GTEST_SKIP();
 
   ScopedMinijail j(minijail_new());
   set_preload_path(j.get());
 
-  char *argv[4];
+  char* argv[4];
   argv[0] = const_cast<char*>(kCatPath);
   argv[1] = NULL;
 
   pid_t pid;
   int child_stdin, child_stdout;
-  int mj_run_ret = minijail_run_pid_pipes(
-      j.get(), argv[0], argv, &pid, &child_stdin, &child_stdout, NULL);
+  int mj_run_ret = minijail_run_pid_pipes(j.get(), argv[0], argv, &pid,
+                                          &child_stdin, &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   char teststr[] = "test\n";
@@ -619,7 +662,7 @@ TEST(Test, minijail_run_env_pid_pipes) {
   argv[2] = "echo \"${TEST_PARENT+set}|${TEST_VAR}\" >&2";
   argv[3] = nullptr;
 
-  char *envp[2];
+  char* envp[2];
   envp[0] = "TEST_VAR=test";
   envp[1] = NULL;
 
@@ -645,19 +688,21 @@ TEST(Test, minijail_run_env_pid_pipes) {
 TEST(Test, minijail_run_fd_env_pid_pipes) {
   // TODO(crbug.com/895875): The preload library interferes with ASan since they
   // both need to use LD_PRELOAD.
-  if (running_with_asan())
+  // TODO(b/238743201): This test consistently breaks with code coverage
+  // enabled. That should be fixed.
+  if (kCompiledWithCoverage || running_with_asan())
     GTEST_SKIP();
 
   ScopedMinijail j(minijail_new());
   set_preload_path(j.get());
 
-  char *argv[4];
+  char* argv[4];
   argv[0] = const_cast<char*>(kShellPath);
   argv[1] = "-c";
   argv[2] = "echo \"${TEST_PARENT+set}|${TEST_VAR}\" >&2\n";
   argv[3] = nullptr;
 
-  char *envp[2];
+  char* envp[2];
   envp[0] = "TEST_VAR=test";
   envp[1] = nullptr;
 
@@ -695,19 +740,23 @@ TEST(Test, minijail_run_fd_env_pid_pipes) {
 TEST(Test, minijail_run_env_pid_pipes_with_local_preload) {
   // TODO(crbug.com/895875): The preload library interferes with ASan since they
   // both need to use LD_PRELOAD.
-  if (running_with_asan())
+  // TODO(b/238743201): This test consistently breaks with code coverage
+  // enabled. That should be fixed.
+  if (kCompiledWithCoverage || running_with_asan())
     GTEST_SKIP();
 
   ScopedMinijail j(minijail_new());
+  // Use the preload library from this test build.
+  set_preload_path(j.get());
 
-  char *argv[4];
+  char* argv[4];
   argv[0] = const_cast<char*>(kCatPath);
   argv[1] = NULL;
 
   pid_t pid;
   int child_stdin, child_stdout;
-  int mj_run_ret = minijail_run_pid_pipes(
-      j.get(), argv[0], argv, &pid, &child_stdin, &child_stdout, NULL);
+  int mj_run_ret = minijail_run_pid_pipes(j.get(), argv[0], argv, &pid,
+                                          &child_stdin, &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   char teststr[] = "test\n";
@@ -731,16 +780,13 @@ TEST(Test, minijail_run_env_pid_pipes_with_local_preload) {
   argv[2] = "echo \"${TEST_PARENT+set}|${TEST_VAR}\" >&2";
   argv[3] = nullptr;
 
-  char *envp[2];
+  char* envp[2];
   envp[0] = "TEST_VAR=test";
   envp[1] = NULL;
 
   // Set a canary env var in the parent that should not be present in the child.
   ASSERT_EQ(setenv("TEST_PARENT", "test", 1 /*overwrite*/), 0);
 
-  // Use the preload library from this test build.
-  set_preload_path(j.get());
-
   int child_stderr;
   mj_run_ret =
       minijail_run_env_pid_pipes(j.get(), argv[0], argv, envp, &pid,
@@ -770,7 +816,7 @@ TEST(Test, test_minijail_no_clobber_fds) {
     minijail_preserve_fd(j.get(), dev_null, i);
   }
 
-  char *argv[4];
+  char* argv[4];
   argv[0] = const_cast<char*>(kShellPath);
   argv[1] = "-c";
   argv[2] = "echo Hello; read line1; echo \"${line1}\" >&2";
@@ -815,23 +861,21 @@ TEST(Test, test_minijail_no_fd_leaks) {
   char buf[kBufferSize];
   char script[kBufferSize];
   int status;
-  char *argv[4];
+  char* argv[4];
 
   int dev_null = open("/dev/null", O_RDONLY);
   ASSERT_NE(dev_null, -1);
-  snprintf(script,
-           sizeof(script),
-           "[ -e /proc/self/fd/%d ] && echo yes || echo no",
-           dev_null);
+  snprintf(script, sizeof(script),
+           "[ -e /proc/self/fd/%d ] && echo yes || echo no", dev_null);
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   argv[0] = const_cast<char*>(kShellPath);
   argv[1] = "-c";
   argv[2] = script;
   argv[3] = NULL;
-  mj_run_ret = minijail_run_pid_pipes_no_preload(
-      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
+  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid, NULL,
+                                                 &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   read_ret = read(child_stdout, buf, sizeof(buf));
@@ -844,8 +888,8 @@ TEST(Test, test_minijail_no_fd_leaks) {
   EXPECT_EQ(WEXITSTATUS(status), 0);
 
   minijail_close_open_fds(j);
-  mj_run_ret = minijail_run_pid_pipes_no_preload(
-      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
+  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid, NULL,
+                                                 &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   read_ret = read(child_stdout, buf, sizeof(buf));
@@ -896,14 +940,13 @@ TEST(Test, test_minijail_callback) {
   pid_t pid;
   int mj_run_ret;
   int status;
-  char *argv[2];
+  char* argv[2];
   int exit_code = 42;
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
-  status =
-      minijail_add_hook(j, &early_exit, reinterpret_cast<void *>(exit_code),
-                        MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
+  status = minijail_add_hook(j, &early_exit, reinterpret_cast<void*>(exit_code),
+                             MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
   EXPECT_EQ(status, 0);
 
   argv[0] = const_cast<char*>(kCatPath);
@@ -921,14 +964,14 @@ TEST(Test, test_minijail_callback) {
 TEST(Test, test_minijail_preserve_fd) {
   int mj_run_ret;
   int status;
-  char *argv[2];
+  char* argv[2];
   char teststr[] = "test\n";
   size_t teststr_len = strlen(teststr);
   int read_pipe[2];
   int write_pipe[2];
   char buf[1024];
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   status = pipe(read_pipe);
   ASSERT_EQ(status, 0);
@@ -964,7 +1007,7 @@ TEST(Test, test_minijail_preserve_fd) {
 }
 
 TEST(Test, test_minijail_reset_signal_mask) {
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   sigset_t original_signal_mask;
   {
@@ -997,7 +1040,7 @@ TEST(Test, test_minijail_reset_signal_mask) {
 }
 
 TEST(Test, test_minijail_reset_signal_handlers) {
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   ASSERT_EQ(SIG_DFL, signal(SIGUSR1, SIG_DFL));
   ASSERT_EQ(SIG_DFL, signal(SIGUSR1, SIG_IGN));
@@ -1080,6 +1123,16 @@ TEST(Test, test_bind_mount_symlink) {
   EXPECT_EQ(unlink(path_sym.c_str()), 0);
 }
 
+// Check for error when trying to enter a user namespace without a pid
+// namespace.
+TEST(Test, test_user_ns_without_pid_ns) {
+  ScopedMinijail j(minijail_new());
+  minijail_namespace_user(j.get());
+
+  ASSERT_EXIT((void)minijail_fork(j.get()), ::testing::KilledBySignal(6),
+              "user namespaces in Minijail require a PID namespace");
+}
+
 namespace {
 
 // Tests that require userns access.
@@ -1089,9 +1142,7 @@ namespace {
 // clone for more information about failure modes with the CLONE_NEWUSER flag).
 class NamespaceTest : public ::testing::Test {
  protected:
-  static void SetUpTestCase() {
-    userns_supported_ = UsernsSupported();
-  }
+  static void SetUpTestCase() { userns_supported_ = UsernsSupported(); }
 
   // Whether userns is supported.
   static bool userns_supported_;
@@ -1101,9 +1152,20 @@ class NamespaceTest : public ::testing::Test {
     if (pid == -1)
       pdie("could not fork");
 
+    // Check that unshare(CLONE_NEWUSER) works.
     if (pid == 0)
       _exit(unshare(CLONE_NEWUSER) == 0 ? 0 : 1);
 
+    // Check that /proc/[pid]/uid_map can be opened. When pivot_root is used to
+    // enter CrOS SDK chroot, unshare() works, but libminijail fails to open
+    // /proc/[pid]/uid_map because its owner uid and gid are set to 0.
+    char* filename = nullptr;
+    if (asprintf(&filename, "/proc/%d/uid_map", pid) == -1)
+      die("asprintf failed");
+    ScopedStr filename_deleter(filename);
+    bool fd_is_valid =
+        ScopedFD(open(filename, O_WRONLY | O_CLOEXEC)).get() != -1;
+
     int status;
     if (waitpid(pid, &status, 0) < 0)
       pdie("could not wait");
@@ -1111,7 +1173,7 @@ class NamespaceTest : public ::testing::Test {
     if (!WIFEXITED(status))
       die("child did not exit properly: %#x", status);
 
-    bool ret = WEXITSTATUS(status) == 0;
+    bool ret = WEXITSTATUS(status) == 0 && fd_is_valid;
     if (!ret)
       warn("Skipping userns related tests");
     return ret;
@@ -1125,7 +1187,7 @@ bool NamespaceTest::userns_supported_;
 TEST_F(NamespaceTest, test_tmpfs_userns) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   char uidmap[kBufferSize], gidmap[kBufferSize];
   constexpr uid_t kTargetUid = 1000;  // Any non-zero value will do.
   constexpr gid_t kTargetGid = 1000;
@@ -1133,7 +1195,7 @@ TEST_F(NamespaceTest, test_tmpfs_userns) {
   if (!userns_supported_)
     GTEST_SKIP();
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_pids(j);
   minijail_namespace_vfs(j);
@@ -1214,9 +1276,8 @@ TEST_F(NamespaceTest, test_namespaces) {
       char* const argv[] = {const_cast<char*>(kCatPath), nullptr};
       pid_t container_pid;
       int child_stdin, child_stdout;
-      int mj_run_ret =
-          run_function(j.get(), argv[0], argv,
-                       &container_pid, &child_stdin, &child_stdout, nullptr);
+      int mj_run_ret = run_function(j.get(), argv[0], argv, &container_pid,
+                                    &child_stdin, &child_stdout, nullptr);
       EXPECT_EQ(mj_run_ret, 0);
 
       // Send some data to stdin and read it back to ensure that the child
@@ -1257,7 +1318,7 @@ TEST_F(NamespaceTest, test_enter_ns) {
   // We first create a child in a new userns so we have privs to run more tests.
   // We can't combine the steps as the kernel disallows many resource sharing
   // from outside the userns.
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_vfs(j);
   minijail_namespace_pids(j);
@@ -1296,7 +1357,7 @@ TEST_F(NamespaceTest, test_enter_ns) {
       minijail_namespace_enter_net(j, "/proc/self/ns/net");
       minijail_namespace_enter_vfs(j, "/proc/self/ns/mnt");
 
-      char *argv[] = {"/bin/true", nullptr};
+      char* argv[] = {"/bin/true", nullptr};
       EXPECT_EQ(0, minijail_run(j, argv[0], argv));
       EXPECT_EQ(0, minijail_wait(j));
       minijail_destroy(j);
@@ -1321,7 +1382,7 @@ TEST_F(NamespaceTest, test_remount_all_private) {
   ssize_t read_ret;
   char buf[kBufferSize];
   int status;
-  char *argv[4];
+  char* argv[4];
   char uidmap[kBufferSize], gidmap[kBufferSize];
   constexpr uid_t kTargetUid = 1000;  // Any non-zero value will do.
   constexpr gid_t kTargetGid = 1000;
@@ -1329,7 +1390,7 @@ TEST_F(NamespaceTest, test_remount_all_private) {
   if (!userns_supported_)
     GTEST_SKIP();
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_pids(j);
   minijail_namespace_vfs(j);
@@ -1350,11 +1411,12 @@ TEST_F(NamespaceTest, test_remount_all_private) {
 
   argv[0] = const_cast<char*>(kShellPath);
   argv[1] = "-c";
-  argv[2] = "grep -E 'shared:|master:|propagate_from:|unbindable:' "
-            "/proc/self/mountinfo";
+  argv[2] =
+      "grep -E 'shared:|master:|propagate_from:|unbindable:' "
+      "/proc/self/mountinfo";
   argv[3] = NULL;
-  mj_run_ret = minijail_run_pid_pipes_no_preload(
-      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
+  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid, NULL,
+                                                 &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   // There should be no output because all mounts should be remounted as
@@ -1379,7 +1441,7 @@ TEST_F(NamespaceTest, test_fail_to_remount_one_private) {
   if (!userns_supported_)
     GTEST_SKIP();
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_pids(j);
   minijail_namespace_vfs(j);
@@ -1400,7 +1462,7 @@ TEST_F(NamespaceTest, test_fail_to_remount_one_private) {
   minijail_remount_mode(j, MS_SHARED);
   minijail_add_remount(j, "/proc", MS_PRIVATE);
 
-  char *argv[] = {"/bin/true", nullptr};
+  char* argv[] = {"/bin/true", nullptr};
   minijail_run(j, argv[0], argv);
 
   status = minijail_wait(j);
@@ -1416,7 +1478,7 @@ TEST_F(NamespaceTest, test_remount_one_shared) {
   ssize_t read_ret;
   char buf[kBufferSize * 4];
   int status;
-  char *argv[4];
+  char* argv[4];
   char uidmap[kBufferSize], gidmap[kBufferSize];
   constexpr uid_t kTargetUid = 1000;  // Any non-zero value will do.
   constexpr gid_t kTargetGid = 1000;
@@ -1424,7 +1486,7 @@ TEST_F(NamespaceTest, test_remount_one_shared) {
   if (!userns_supported_)
     GTEST_SKIP();
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_pids(j);
   minijail_namespace_vfs(j);
@@ -1449,8 +1511,8 @@ TEST_F(NamespaceTest, test_remount_one_shared) {
   argv[1] = "-c";
   argv[2] = "grep -E 'shared:' /proc/self/mountinfo";
   argv[3] = NULL;
-  mj_run_ret = minijail_run_pid_pipes_no_preload(
-      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
+  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid, NULL,
+                                                 &child_stdout, NULL);
   EXPECT_EQ(mj_run_ret, 0);
 
   // There should be no output because all mounts should be remounted as
@@ -1476,7 +1538,7 @@ TEST_F(NamespaceTest, test_remount_ro_using_mount) {
   if (!userns_supported_)
     GTEST_SKIP();
 
-  struct minijail *j = minijail_new();
+  struct minijail* j = minijail_new();
 
   minijail_namespace_pids(j);
   minijail_namespace_vfs(j);
@@ -1496,7 +1558,7 @@ TEST_F(NamespaceTest, test_remount_ro_using_mount) {
   // Perform a RO remount using minijail_mount().
   minijail_mount(j, "none", "/", "none", MS_REMOUNT | MS_BIND | MS_RDONLY);
 
-  char *argv[] = {"/bin/true", nullptr};
+  char* argv[] = {"/bin/true", nullptr};
   minijail_run_no_preload(j, argv[0], argv);
 
   status = minijail_wait(j);
@@ -1523,18 +1585,18 @@ class LandlockTest : public NamespaceTest {
 
   static bool LandlockSupported() {
     // Check the Landlock version w/o creating a ruleset file descriptor.
-    int landlock_version = landlock_create_ruleset(
-      NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
+    const int landlock_version =
+        landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
     if (landlock_version <= 0) {
       const int err = errno;
       warn("Skipping Landlock tests");
       switch (err) {
-      case ENOSYS:
-        warn("Landlock not supported by the current kernel.");
-        break;
-      case EOPNOTSUPP:
-        warn("Landlock is currently disabled.");
-        break;
+        case ENOSYS:
+          warn("Landlock not supported by the current kernel.");
+          break;
+        case EOPNOTSUPP:
+          warn("Landlock is currently disabled.");
+          break;
       }
       return false;
     }
@@ -1542,7 +1604,7 @@ class LandlockTest : public NamespaceTest {
   }
 
   // Sets up a minijail to make Landlock syscalls and child processes.
-  void SetupLandlockTestingNamespaces(struct minijail *j) {
+  void SetupLandlockTestingNamespaces(struct minijail* j) {
     minijail_namespace_pids(j);
     minijail_namespace_user(j);
   }
@@ -1567,7 +1629,7 @@ constexpr char kTestSymlinkScript[] = R"(
 TEST_F(LandlockTest, test_rule_rx_allow) {
   int mj_run_ret;
   int status;
-  char *argv[3];
+  char* argv[3];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1590,7 +1652,7 @@ TEST_F(LandlockTest, test_rule_rx_allow) {
 TEST_F(LandlockTest, test_rule_rx_deny) {
   int mj_run_ret;
   int status;
-  char *argv[3];
+  char* argv[3];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1611,7 +1673,7 @@ TEST_F(LandlockTest, test_rule_rx_deny) {
 TEST_F(LandlockTest, test_rule_ro_allow) {
   int mj_run_ret;
   int status;
-  char *argv[3];
+  char* argv[3];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1636,7 +1698,7 @@ TEST_F(LandlockTest, test_rule_ro_allow) {
 TEST_F(LandlockTest, test_rule_ro_deny) {
   int mj_run_ret;
   int status;
-  char *argv[3];
+  char* argv[3];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1660,7 +1722,7 @@ TEST_F(LandlockTest, test_rule_ro_deny) {
 TEST_F(LandlockTest, test_rule_rw_allow) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1686,7 +1748,7 @@ TEST_F(LandlockTest, test_rule_rw_allow) {
 TEST_F(LandlockTest, test_rule_rw_deny) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1708,6 +1770,98 @@ TEST_F(LandlockTest, test_rule_rw_deny) {
   EXPECT_NE(status, 0);
 }
 
+TEST_F(LandlockTest, test_deny_rule_with_close_open_fds) {
+  int mj_run_ret;
+  int status;
+  char* argv[3];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  // Make sure Landlock still functions if fds are closed.
+  minijail_close_open_fds(j.get());
+  // Add irrelevant Landlock rule.
+  minijail_add_fs_restriction_rx(j.get(), "/var");
+
+  argv[0] = const_cast<char*>(kLsPath);
+  argv[1] = const_cast<char*>(kCatPath);
+  argv[2] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  // We should see 126 because /bin is not executable.
+  EXPECT_EQ(status, 126);
+}
+
+TEST_F(LandlockTest, test_fs_rules_disabled) {
+  int mj_run_ret;
+  int status;
+  char* argv[4];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_add_fs_restriction_rx(j.get(), kBinPath);
+  minijail_disable_fs_restrictions(j.get());
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec echo 'bar' > /tmp/fs-rules-test";
+  argv[3] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  // Rules aren't applied, so cmd succeeds.
+  EXPECT_EQ(status, 0);
+}
+
+TEST_F(LandlockTest, test_fs_rules_availability) {
+  char* argv[4];
+  int status;
+  bool landlock_available;
+  // We always run regardless of LandlockSupported() because we would like to
+  // test even if Landlock is unavailable.
+  if (!UsernsSupported())
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_add_fs_restriction_rx(j.get(), kBinPath);
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec echo 'bar' > /tmp/fs-rules-test";
+  argv[3] = NULL;
+
+  EXPECT_EQ(minijail_run_no_preload(j.get(), argv[0], argv), 0);
+  status = minijail_wait(j.get());
+
+  landlock_available = minijail_is_fs_restriction_available();
+  EXPECT_EQ(landlock_available, LandlockSupported());
+  if (landlock_available) {
+    // Landlock is available, writing rule should fail.
+    EXPECT_NE(status, 0);
+  } else {
+    // Rules aren't effective, so cmd succeeds.
+    EXPECT_EQ(status, 0);
+  }
+}
+
+TEST_F(LandlockTest, test_setup_fs_rules_fd) {
+  // Test that the Landlock ruleset FD is set up, because this is important
+  // behavior for API users calling minijail_enter() directly.
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  EXPECT_FALSE(minijail_is_fs_restriction_ruleset_initialized(j.get()));
+
+  minijail_add_fs_restriction_rx(j.get(), kBinPath);
+
+  EXPECT_TRUE(minijail_is_fs_restriction_ruleset_initialized(j.get()));
+}
+
 TEST_F(LandlockTest, test_rule_allow_symlinks_advanced_rw) {
   int mj_run_ret;
   int status;
@@ -1722,7 +1876,7 @@ TEST_F(LandlockTest, test_rule_allow_symlinks_advanced_rw) {
   minijail_add_fs_restriction_advanced_rw(j.get(), kTmpPath);
 
   char* const argv[] = {"sh", "-c", const_cast<char*>(kTestSymlinkScript),
-      nullptr};
+                        nullptr};
 
   mj_run_ret = minijail_run_no_preload(j.get(), kShellPath, argv);
   EXPECT_EQ(mj_run_ret, 0);
@@ -1744,7 +1898,7 @@ TEST_F(LandlockTest, test_rule_deny_symlinks_basic_rw) {
   minijail_add_fs_restriction_rw(j.get(), kTmpPath);
 
   char* const argv[] = {"sh", "-c", const_cast<char*>(kTestSymlinkScript),
-      nullptr};
+                        nullptr};
 
   mj_run_ret = minijail_run_no_preload(j.get(), kShellPath, argv);
   EXPECT_EQ(mj_run_ret, 0);
@@ -1755,7 +1909,7 @@ TEST_F(LandlockTest, test_rule_deny_symlinks_basic_rw) {
 TEST_F(LandlockTest, test_rule_rx_cannot_write) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1780,7 +1934,7 @@ TEST_F(LandlockTest, test_rule_rx_cannot_write) {
 TEST_F(LandlockTest, test_rule_ro_cannot_wx) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1805,7 +1959,7 @@ TEST_F(LandlockTest, test_rule_ro_cannot_wx) {
 TEST_F(LandlockTest, test_rule_rw_cannot_exec) {
   int mj_run_ret;
   int status;
-  char *argv[4];
+  char* argv[4];
   if (!run_landlock_tests_)
     GTEST_SKIP();
   ScopedMinijail j(minijail_new());
@@ -1827,6 +1981,120 @@ TEST_F(LandlockTest, test_rule_rw_cannot_exec) {
   EXPECT_NE(status, 0);
 }
 
+TEST_F(LandlockTest, test_access_default_paths) {
+  int mj_run_ret;
+  int status;
+  char* argv[4];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_enable_default_fs_restrictions(j.get());
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec cat /etc/group";
+  argv[3] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  EXPECT_EQ(status, 0);
+}
+
+TEST_F(LandlockTest, test_cannot_access_default_paths) {
+  int mj_run_ret;
+  int status;
+  char* argv[4];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_add_fs_restriction_rw(j.get(), kBinPath);
+  minijail_add_fs_restriction_rw(j.get(), kLibPath);
+  minijail_add_fs_restriction_rw(j.get(), kLib64Path);
+  // No call to minijail_enable_default_fs_restrictions().
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec cat /etc/group";
+  argv[3] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  EXPECT_NE(status, 0);
+}
+
+// Tests that LANDLOCK_ACCESS_FS_REFER is supported when the kernel supports
+// Landlock version ABI=2.
+TEST_F(LandlockTest, test_refer_supported) {
+  int mj_run_ret;
+  int status;
+  char* argv[4];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  const int landlock_version =
+      landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
+  if (landlock_version < LANDLOCK_ABI_FS_REFER_SUPPORTED) {
+    warn("Skipping LandlockTest test_refer_supported ABI=%i", landlock_version);
+    GTEST_SKIP();
+  }
+
+  ScopedMinijail j(minijail_new());
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_add_fs_restriction_rx(j.get(), "/");
+  // If LANDLOCK_ACCESS_FS_REFER isn’t part of the access rights handled by
+  // minijail, none of the access rights in this call will be added.
+  minijail_add_fs_restriction_access_rights(
+      j.get(), "/tmp", ACCESS_FS_ROUGHLY_FULL_WRITE | LANDLOCK_ACCESS_FS_REFER);
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec echo 'bar' > /tmp/baz";
+  argv[3] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  EXPECT_EQ(status, 0);
+}
+
+TEST_F(LandlockTest, test_refer_not_supported) {
+  int mj_run_ret;
+  int status;
+  char* argv[4];
+  if (!run_landlock_tests_)
+    GTEST_SKIP();
+  const int landlock_version =
+      landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
+  if (landlock_version >= LANDLOCK_ABI_FS_REFER_SUPPORTED) {
+    warn("Skipping LandlockTest test_refer_not_supported ABI=%i",
+         landlock_version);
+    GTEST_SKIP();
+  }
+
+  ScopedMinijail j(minijail_new());
+  std::string link_name = std::tmpnam(NULL);
+  std::string link_cmd = "exec /bin/ln -s /var " + link_name;
+  SetupLandlockTestingNamespaces(j.get());
+  minijail_add_fs_restriction_rx(j.get(), "/");
+  // This call shouldn't succeed, since we're adding an access right
+  // that doesn't have kernel support.
+  minijail_add_fs_restriction_access_rights(
+      j.get(), "/tmp", ACCESS_FS_ROUGHLY_FULL_WRITE | LANDLOCK_ACCESS_FS_REFER);
+
+  argv[0] = const_cast<char*>(kShellPath);
+  argv[1] = "-c";
+  argv[2] = "exec echo 'bar' > /tmp/baz";
+  argv[3] = NULL;
+
+  mj_run_ret = minijail_run_no_preload(j.get(), argv[0], argv);
+  EXPECT_EQ(mj_run_ret, 0);
+  status = minijail_wait(j.get());
+  EXPECT_NE(status, 0);
+}
+
 void TestCreateSession(bool create_session) {
   int status;
   int pipe_fds[2];
@@ -1870,3 +2138,28 @@ TEST(Test, default_no_new_session) {
 TEST(Test, create_new_session) {
   TestCreateSession(/*create_session=*/true);
 }
+
+TEST(Test, syscall_name_altsyscall) {
+  ScopedMinijail j(minijail_new());
+
+  // Use a placeholder since we don't need a valid table (yet).
+  minijail_use_alt_syscall(j.get(), "placeholder");
+
+  EXPECT_EQ(std::string(minijail_syscall_name(j.get(), 1)),
+            std::string(kAltSyscallNamePlaceholder));
+}
+
+TEST(Test, syscall_name) {
+  // With jail; Success.
+  ScopedMinijail j(minijail_new());
+  EXPECT_STREQ(minijail_syscall_name(j.get(), SYS_read), "read");
+
+  // Without jail; Success.
+  EXPECT_STREQ(minijail_syscall_name(nullptr, SYS_read), "read");
+
+  // With jail; Null.
+  EXPECT_EQ(minijail_syscall_name(j.get(), -1), nullptr);
+
+  // Without jail; Null.
+  EXPECT_EQ(minijail_syscall_name(nullptr, -1), nullptr);
+}
diff --git a/libminijailpreload.c b/libminijailpreload.c
index 17c8f97..876797c 100644
--- a/libminijailpreload.c
+++ b/libminijailpreload.c
@@ -9,8 +9,8 @@
  * See the minijail0.1 for a design explanation.
  */
 
-#include "libminijail.h"
 #include "libminijail-private.h"
+#include "libminijail.h"
 #include "util.h"
 
 #include <dlfcn.h>
@@ -21,7 +21,7 @@
 #include <syslog.h>
 #include <unistd.h>
 
-static int (*real_main) (int, char **, char **);
+static int (*real_main)(int, char **, char **);
 static void *libc_handle;
 
 static void truncate_preload_env(char **envp, const char *name)
diff --git a/minijail0.1 b/minijail0.1
index c323f2d..0bc3adf 100644
--- a/minijail0.1
+++ b/minijail0.1
@@ -15,11 +15,11 @@ and architectures that support the \fBPR_ALT_SYSCALL\fR option of \fBprctl\fR(2)
 \fB-b <src>[,[dest][,<writeable>]]\fR, \fB--bind-mount=<src>[,[dest][,<writeable>]]\fR
 Bind-mount \fIsrc\fR into the chroot directory at \fIdest\fR, optionally writeable.
 The \fIsrc\fR path must be an absolute path.
-
+.IP
 If \fIdest\fR is not specified, it will default to \fIsrc\fR.
 If the destination does not exist, it will be created as a file or directory
 based on the \fIsrc\fR type (including missing parent directories).
-
+.IP
 To create a writable bind-mount set \fIwritable\fR to \fB1\fR. If not specified
 it will default to \fB0\fR (read-only).
 .TP
@@ -50,12 +50,14 @@ Change root (using \fBchroot\fR(2)) to \fIdir\fR.
 \fB-d\fR, \fB--mount-dev\fR
 Create a new /dev mount with a minimal set of nodes. Implies \fB-v\fR.
 Additional nodes can be bound with the \fB-b\fR or \fB-k\fR options.
-
-.nf
-\[bu] The initial set of nodes are: full null tty urandom zero.
-\[bu] Symlinks are also created for: fd ptmx stderr stdin stdout.
-\[bu] Directores are also created for: shm.
-.re
+.RS
+.IP \(bu 3
+The initial set of nodes are: full null tty urandom zero.
+.IP \(bu
+Symlinks are also created for: fd ptmx stderr stdin stdout.
+.IP \(bu
+Directores are also created for: shm.
+.RE
 .TP
 \fB-e[file]\fR
 Enter a new network namespace, or if \fIfile\fR is specified, enter an existing
@@ -89,29 +91,29 @@ host kernel or something like 32/64-bit compatibility issues exist.)
 \fB-i\fR
 Exit immediately after \fBfork\fR(2).  The jailed process will keep running in
 the background.
-
+.IP
 Normally minijail will fork+exec the specified \fIprogram\fR so that it can set
 up the right security settings in the new child process. The initial minijail
 process will stay resident and wait for the \fIprogram\fR to exit so the script
 that ran minijail will correctly block (e.g. standalone scripts). Specifying
 \fB-i\fR makes that initial process exit immediately and free up the resources.
-
+.IP
 This option is recommended for daemons and init services when you want to
 background the long running \fIprogram\fR.
 .TP
 \fB-I\fR
 Run \fIprogram\fR as init (pid 1) inside a new pid namespace (implies \fB-p\fR).
-
+.IP
 Most programs don't expect to run as an init which is why minijail will do it
 for you by default. Basically, the \fIprogram\fR needs to reap any processes it
 forks to avoid leaving zombies behind. Signal handling needs care since the
 kernel will mask all signals that don't have handlers registered (all default
 handlers are ignored and cannot be changed).
-
+.IP
 This means a minijail process (acting as init) will remain resident by default.
 While using \fB-I\fR is recommended when possible, strict review is required to
 make sure the \fIprogram\fR continues to work as expected.
-
+.IP
 \fB-i\fR and \fB-I\fR may be safely used together. The \fB-i\fR option controls
 the first minijail process outside of the pid namespace while the \fB-I\fR
 option controls the minijail process inside of the pid namespace.
@@ -119,23 +121,23 @@ option controls the minijail process inside of the pid namespace.
 \fB-k <src>,<dest>,<type>[,<flags>[,<data>]]\fR, \fB--mount=<src>,<dest>,<type>[,<flags>[,<data>]]\fR
 Mount \fIsrc\fR, a \fItype\fR filesystem, at \fIdest\fR.  If a chroot or pivot
 root is active, \fIdest\fR will automatically be placed below that path.
-
+.IP
 The \fIflags\fR field is optional and may be a mix of \fIMS_XXX\fR or hex
 constants separated by \fI|\fR characters.  See \fBmount\fR(2) for details.
 \fIMS_NODEV|MS_NOSUID|MS_NOEXEC\fR is the default value (a writable mount
 with nodev/nosuid/noexec bits set), and it is strongly recommended that all
 mounts have these three bits set whenever possible.  If you need to disable
 all three, then specify something like \fIMS_SILENT\fR.
-
+.IP
 The \fIdata\fR field is optional and is a comma delimited string (see
 \fBmount\fR(2) for details).  It is passed directly to the kernel, so all
 fields here are filesystem specific.  For \fItmpfs\fR, if no data is specified,
 we will default to \fImode=0755,size=10M\fR.  If you want other settings, you
 will need to specify them explicitly yourself.
-
+.IP
 If the mount is not a pseudo filesystem (e.g. proc or sysfs), \fIsrc\fR path
 must be an absolute path (e.g. \fI/dev/sda1\fR and not \fIsda1\fR).
-
+.IP
 If the destination does not exist, it will be created as a directory (including
 missing parent directories).
 .TP
@@ -143,24 +145,25 @@ missing parent directories).
 Don't mark all existing mounts as MS_SLAVE.
 This option is \fBdangerous\fR as it negates most of the functionality of \fB-v\fR.
 You very likely don't need this.
-
+.IP
 You may specify a mount propagation mode in which case, that will be used
 instead of the default MS_SLAVE.  See the \fBmount\fR(2) man page and the
 kernel docs \fIDocumentation/filesystems/sharedsubtree.txt\fR for more
 technical details, but a brief guide:
-
-.IP
-\[bu] \fBslave\fR Changes in the parent mount namespace will propagate in, but
+.RS
+.IP \(bu 3
+\fBslave\fR Changes in the parent mount namespace will propagate in, but
 changes in this mount namespace will not propagate back out.  This is usually
 what people want to use, and is the default behavior if you don't specify \fB-K\fR.
-.IP
-\[bu] \fBprivate\fR No changes in either mount namespace will propagate.
+.IP \(bu
+\fBprivate\fR No changes in either mount namespace will propagate.
 This provides the most isolation.
-.IP
-\[bu] \fBshared\fR Changes in the parent and this mount namespace will freely
+.IP \(bu
+\fBshared\fR Changes in the parent and this mount namespace will freely
 propagate back and forth.  This is not recommended.
-.IP
-\[bu] \fBunbindable\fR Mark all mounts as unbindable.
+.IP \(bu
+\fBunbindable\fR Mark all mounts as unbindable.
+.RE
 .TP
 \fB-l\fR
 Run inside a new IPC namespace. This option makes the program's System V IPC
@@ -187,7 +190,7 @@ map the current gid to root inside the user namespace.
 .TP
 \fB-n\fR
 Set the process's \fIno_new_privs\fR bit. See \fBprctl\fR(2) and the kernel
-source file \fIDocumentation/prctl/no_new_privs.txt\fR for more info.
+source file \fIDocumentation/userspace-api/no_new_privs.txt\fR for more info.
 .TP
 \fB-N\fR
 Run inside a new cgroup namespace. This option runs the program with a cgroup
@@ -199,11 +202,11 @@ Run inside a new PID namespace. This option will make it impossible for the
 program to see or affect processes that are not its descendants. This implies
 \fB-v\fR and \fB-r\fR, since otherwise the process can see outside its namespace
 by inspecting /proc.
-
+.IP
 If the \fIprogram\fR exits, all of its children will be killed immediately by
 the kernel. If you need to daemonize or background things, use the \fB-i\fR
 option.
-
+.IP
 See \fBpid_namespaces\fR(7) for more info.
 .TP
 \fB-P <dir>\fR
@@ -217,9 +220,9 @@ that even if the process has write access to a system config knob in /proc
 .TP
 \fB-R <rlim_type>,<rlim_cur>,<rlim_max>\fR
 Set an rlimit value, see \fBgetrlimit\fR(2) for more details.
-
+.IP
 \fIrlim_type\fR may be specified using symbolic constants like \fIRLIMIT_AS\fR.
-
+.IP
 \fIrlim_cur\fR and \fIrlim_max\fR are specified either with a number (decimal or
 hex starting with \fI0x\fR), or with the string \fIunlimited\fR (which will
 translate to \fIRLIM_INFINITY\fR).
@@ -302,7 +305,7 @@ This option can be used several times to set any number of environment variables
 \fB--logging=<system>\fR
 Use \fIsystem\fR as the logging system. \fIsystem\fR must be one of
 \fBauto\fR (the default), \fBsyslog\fR, or \fBstderr\fR.
-
+.IP
 \fBauto\fR will use \fBstderr\fR if connected to a tty (e.g. run directly by a
 user), otherwise it will use \fBsyslog\fR.
 .TP
@@ -315,6 +318,7 @@ section below for the full list of supported values for \fIprofile\fR.
 \fB--preload-library <file path>\fR
 Allows overriding the default path of \fI/lib/libminijailpreload.so\fR.  This
 is only really useful for testing.
+.TP
 \fB--seccomp-bpf-binary <arch-specific BPF binary>\fR
 This is similar to \fB-S\fR, but
 instead of using a policy file, \fB--secomp-bpf-binary\fR expects a
@@ -330,14 +334,60 @@ disables mitigations against certain speculative execution attacks; namely
 Branch Target Injection (spectre-v2) and Speculative Store Bypass (spectre-v4).
 These mitigations incur a runtime performance hit, so it is useful to be able
 to disable them in order to quantify their performance impact.
-
+.IP
 \fBWARNING:\fR It is dangerous to use this option on programs that process
 untrusted input, which is normally what Minijail is used for. Do not enable
 this option unless you know what you're doing.
-
+.IP
 See the kernel documentation \fIDocumentation/userspace-api/spec_ctrl.rst\fR
 and \fIDocumentation/admin-guide/hw-vuln/spectre.rst\fR for more information.
 .TP
+\fB--fs-default-paths\fR
+Adds a set of allowed paths to allow running common system executables.
+.IP
+\fBLandlock support:\fR This flag, and the following \fB--fs*\fR flags, impact
+what filesystem access is available and require kernel support for Landlock in
+order to be enforced. Landlock is available on Linux kernels >= 5.13, or
+ChromeOS kernels >= 5.10, as long as it is configured to be available as
+outlined in the Landlock kernel docs at
+\fIhttps://docs.kernel.org/userspace-api/landlock.html#kernel-support\fR.
+.IP
+\fBFlag combinations:\fR As long as \fB--fs-path*\fR or
+\fB--fs-default-paths\fR are used, Minijail will utilize Landlock if it is
+available. Additional \fB--fs-path*\fR flags used will expand the allowlisted
+paths and access rights.
+.TP
+\fB--enable-profile-fs-restrictions\fR
+Limit paths available when using minimalistic-mountns.
+.TP
+\fB--fs-path-rx\fR
+Adds an allowed read-execute path.
+.TP
+\fB--fs-path-ro\fR
+Adds an allowed read-only path.
+.TP
+\fB--fs-path-rw\fR
+Adds an allowed read-write path.
+.TP
+\fB--fs-path-advanced-rw\fR
+Adds an allowed advanced read-write path.
+.TP
+\fB--no-fs-restrictions\fR
+Disables path-based filesystem restrictions.
+.TP
+\fB--no-default-runtime-environment\fR
+Disables default seccomp policy and setting of no_new_privs. The default
+runtime environment is used by Minijail if no other seccomp policy is set,
+unless this flag is set to opt out.
+.TP
+\fB--no-new-sessions\fR
+Skips having Minijail call setsid(). This is useful when running a process that
+expects to have a controlling terminal set.
+.TP
+\fB--preserve-fd\fR
+Preserves an fd and makes it available in the child process. The fd is
+preserved with the same integer value.
+.TP
 \fB--config <file path>\fR
 Use a Minijail configuration file to set options, through
 commandline-option-equivalent key-value pairs.
@@ -356,39 +406,34 @@ Set up a minimalistic mount namespace with an empty /dev path.  Equivalent to
 This program is broken up into two parts: \fBminijail0\fR (the frontend) and a helper
 library called \fBlibminijailpreload\fR.  Some jailings can only be achieved
 from the process to which they will actually apply:
-
-.IP
-\[bu] capability use (without using ambient capabilities): non-ambient
+.IP \(bu 3
+capability use (without using ambient capabilities): non-ambient
 capabilities are not inherited across \fBexecve\fR(2) unless the file being
 executed has POSIX file capabilities.  Ambient capabilities (the
 \fB--ambient\fR flag) fix capability inheritance across \fBexecve\fR(2) to
 avoid the need for file capabilities.
-
-\[bu] seccomp: a meaningful seccomp filter policy should disallow
+.IP \(bu
+seccomp: a meaningful seccomp filter policy should disallow
 \fBexecve\fR(2), to prevent a compromised process from executing a different
 binary.  However, this would prevent the seccomp policy from being applied
 before \fBexecve\fR(2).
-.RE
-
+.PP
 To this end, \fBlibminijailpreload\fR is forcibly loaded into all
 dynamically-linked target programs by default; we pass the specific
 restrictions in an environment variable which the preloaded library looks for.
 The forcibly-loaded library then applies the restrictions to the newly-loaded
 program.
-
+.PP
 This behavior can be disabled by the use of the \fB-T static\fR flag.  There
 are other cases in which the use of this flag might be useful:
-
-.IP
-\[bu] When \fIprogram\fR is linked against a different version of \fBlibc.so\fR
+.IP \(bu 3
+When \fIprogram\fR is linked against a different version of \fBlibc.so\fR
 than \fBlibminijailpreload.so\fR.
-
-\[bu] When \fBexecve\fR(2) has side-effects that interact badly with the
+.IP \(bu
+When \fBexecve\fR(2) has side-effects that interact badly with the
 jailing process.  If the system uses SELinux, \fBexecve\fR(2) can cause an
 automatic domain transition, which would then require that the target domain
 allows the operations to jail \fIprogram\fR.
-.RE
-
 .SH AUTHOR
 The ChromiumOS Authors <chromiumos-dev@chromium.org>
 .SH COPYRIGHT
diff --git a/minijail0.5 b/minijail0.5
index c0e18e8..a5b0c6f 100644
--- a/minijail0.5
+++ b/minijail0.5
@@ -5,142 +5,158 @@ minijail0 \- sandbox a process
 .PP
 Runs PROGRAM inside a sandbox. See \fBminijail0\fR(1) for details.
 .SH EXAMPLES
-
 Safely switch from user \fIroot\fR to \fInobody\fR, switch to primary group
 \fInobody\fR, drop all capabilities, and inherit any supplementary groups from
 user \fInobody\fR:
-
-  # minijail0 -u nobody -g nobody -c 0 -G /usr/bin/whoami
-  nobody
-
+.IP
+.EX
+# minijail0 -u nobody -g nobody -c 0 -G /usr/bin/whoami
+nobody
+.EE
+.PP
 Run in a PID and VFS namespace without superuser capabilities (but still
 as root) and with a private view of /proc:
-
-  # minijail0 -p -v -r -c 0 /bin/ps
-    PID TTY           TIME CMD
-      1 pts/0     00:00:00 minijail0
-      2 pts/0     00:00:00 ps
-
+.IP
+.EX
+# minijail0 -p -v -r -c 0 /bin/ps
+  PID TTY           TIME CMD
+    1 pts/0     00:00:00 minijail0
+    2 pts/0     00:00:00 ps
+.EE
+.PP
 Running a process with a seccomp filter policy at reduced privileges:
-
-  # minijail0 -S /usr/share/minijail0/$(uname -m)/cat.policy -- \\
-              /bin/cat /proc/self/seccomp_filter
-  ...
-
+.IP
+.EX
+# minijail0 -S /usr/share/minijail0/$(uname -m)/cat.policy -- \\
+            /bin/cat /proc/self/seccomp_filter
+...
+.EE
 .SH SECCOMP_FILTER POLICY
 The policy file supplied to the \fB-S\fR argument supports the following syntax:
-
-  \fB<syscall_name>\fR:\fB<ftrace filter policy>\fR
-  \fB<syscall_number>\fR:\fB<ftrace filter policy>\fR
-  \fB<empty line>\fR
-  \fB# any single line comment\fR
-
+.IP
+.EX
+\fB<syscall_name>\fR:\fB<ftrace filter policy>\fR
+\fB<syscall_number>\fR:\fB<ftrace filter policy>\fR
+\fB<empty line>\fR
+\fB# any single line comment\fR
+.EE
+.PP
 Long lines may be broken up using \\ at the end.
-
+.PP
 A policy that emulates \fBseccomp\fR(2) in mode 1 may look like:
-  read: 1
-  write: 1
-  sig_return: 1
-  exit: 1
-
+.IP
+.EX
+read: 1
+write: 1
+sig_return: 1
+exit: 1
+.EE
+.PP
 The "1" acts as a wildcard and allows any use of the mentioned system
 call.  More advanced filtering is possible if your kernel supports
 CONFIG_FTRACE_SYSCALLS.  For example, we can allow a process to open any
 file read only and mmap PROT_READ only:
-
-  # open with O_LARGEFILE|O_RDONLY|O_NONBLOCK or some combination
-  open: arg1 == 32768 || arg1 == 0 || arg1 == 34816 || arg1 == 2048
-  mmap2: arg2 == 0x0
-  munmap: 1
-  close: 1
-
+.IP
+.EX
+# open with O_LARGEFILE|O_RDONLY|O_NONBLOCK or some combination.
+open: arg1 == 32768 || arg1 == 0 || arg1 == 34816 || arg1 == 2048
+mmap2: arg2 == 0x0
+munmap: 1
+close: 1
+.EE
+.PP
 The supported arguments may be found by reviewing the system call
 prototypes in the Linux kernel source code.  Be aware that any
 non-numeric comparison may be subject to time-of-check-time-of-use
 attacks and cannot be considered safe.
-
+.PP
 \fBexecve\fR may only be used when invoking with CAP_SYS_ADMIN privileges.
-
+.PP
 In order to promote reusability, policy files can include other policy files
 using the following syntax:
-
-  \fB@include /absolute/path/to/file.policy\fR
-  \fB@include ./path/relative/to/CWD/file.policy\fR
-
+.IP
+.EX
+\fB@include /absolute/path/to/file.policy\fR
+\fB@include ./path/relative/to/CWD/file.policy\fR
+.EE
+.PP
 Inclusion is limited to a single level (i.e. files that are \fB@include\fRd
 cannot themselves \fB@include\fR more files), since that makes the policies
 harder to understand.
-
 .SH SECCOMP_FILTER SYNTAX
 More formally, the expression after the colon can be an expression in
 Disjunctive Normal Form (DNF): a disjunction ("or", \fI||\fR) of
 conjunctions ("and", \fI&&\fR) of atoms.
-
 .SS "Atom Syntax"
 Atoms are of the form \fIarg{DNUM} {OP} {VAL}\fR where:
-.IP
-\[bu] \fIDNUM\fR is a decimal number
-
-\[bu] \fIOP\fR is an unsigned comparison operator:
+.IP \(bu 3
+\fIDNUM\fR is a decimal number
+.IP \(bu
+\fIOP\fR is an unsigned comparison operator:
 \fI==\fR, \fI!=\fR, \fI<\fR, \fI<=\fR, \fI>\fR, \fI>=\fR, \fI&\fR (flags set),
 or \fIin\fR (inclusion)
-
-\[bu] \fVAL\fR is a constant expression.  It can be a named constant (like
+.IP \(bu
+\fIVAL\fR is a constant expression.  It can be a named constant (like
 \fBO_RDONLY\fR), a number (octal, decimal, or hexadecimal), a mask of constants
 separated by \fI|\fR, or a parenthesized constant expression. Constant
 expressions can also be prefixed with the bitwise complement operator \fI~\fR
 to produce their complement.
-.RE
-
+.PP
 \fI==\fR, \fI!=\fR, \fI<\fR, \fI<=\fR, \fI>\fR, and \fI>=\fR should be pretty
 self explanatory.
-
+.PP
 \fI&\fR will test for a flag being set, for example, O_RDONLY for
 .BR open (2):
-
-  open: arg1 & O_RDONLY
-
+.IP
+.EX
+open: arg1 & O_RDONLY
+.EE
+.PP
 Minijail supports most common named constants, like O_RDONLY.
 It's preferable to use named constants rather than numeric values as not all
 architectures use the same numeric value.
-
+.PP
 When the possible combinations of allowed flags grow, specifying them all can
 be cumbersome.
 This is where the \fIin\fR operator comes handy.
 The system call will be allowed iff the flags set in the argument are included
 (as a set) in the flags in the policy:
-
-  mmap: arg3 in MAP_PRIVATE|MAP_ANONYMOUS
-
+.IP
+.EX
+mmap: arg3 in MAP_PRIVATE|MAP_ANONYMOUS
+.EE
+.PP
 This will allow \fBmmap\fR(2) as long as \fIarg3\fR (flags) has any combination
 of MAP_PRIVATE and MAP_ANONYMOUS, but nothing else.  One common use of this is
 to restrict \fBmmap\fR(2) / \fBmprotect\fR(2) to only allow write^exec
 mappings:
-
-  mmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
-  mprotect: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
-
+.IP
+.EX
+mmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
+mprotect: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
+.EE
 .SS "Return Values"
-
 By default, blocked syscalls call the process to be killed.
 The \fIreturn {NUM}\fR syntax can be used to force a specific errno to be
 returned instead.
-
-  read: return EBADF
-
+.IP
+.EX
+read: return EBADF
+.EE
+.PP
 This expression will block the \fBread\fR(2) syscall, make it return -1, and set
 \fBerrno\fR to EBADF (9 on x86 platforms).
-
+.PP
 An expression can also include an optional \fIreturn <errno>\fR clause,
 separated by a semicolon:
-
-  read: arg0 == 0; return EBADF
-
+.IP
+.EX
+read: arg0 == 0; return EBADF
+.EE
+.PP
 This is, if the first argument to read is 0, then allow the syscall;
 else, block the syscall, return -1, and set \fBerrno\fR to EBADF.
-
 .SH SECCOMP_FILTER POLICY WRITING
-
 Determining policy for seccomp_filter can be time consuming.  System
 calls are often named in arch-specific, or legacy tainted, ways.  E.g.,
 geteuid versus geteuid32.  On process death due to a seccomp filter
@@ -152,32 +168,34 @@ with the output of \fBstrace -f -e raw=all <program>\fR can generate the list
 of system calls that are needed.  Note that when using libminijail or minijail
 with preloading, supporting initial process setup calls will not be required.
 Be conservative.
-
+.PP
 It's also possible to analyze the binary checking for all non-dead
 functions and determining if any of them issue system calls.  There is
 no active implementation for this, but something like
 code.google.com/p/seccompsandbox is one possible runtime variant.
-
 .SH CONFIGURATION FILE
 A configuration file can be used to specify command line options and other
 settings.
-
+.PP
 It supports the following syntax:
-  \fB% minijail-config-file v0\fR
-  \fB<option>\fR=\fB<argument>\fR
-  \fB<no-argument-option>\fR
-  \fB<empty line>\fR
-  \fB# any single line comment\fR
-
+.IP
+.EX
+\fB% minijail-config-file v0\fR
+\fB<option>\fR=\fB<argument>\fR
+\fB<no-argument-option>\fR
+\fB<empty line>\fR
+\fB# any single line comment\fR
+.EE
+.PP
 Long lines may be broken up using \\ at the end.
-
+.PP
 The special directive "% minijail-config-file v0" must occupy the first line.
 "v0" also declares the version of the config file format.
-
+.PP
 Keys contain only alphabetic characters and '-'. Values can be any non-empty
 string. Leading and trailing whitespaces around keys and
 values are permitted but will be stripped before processing.
-
+.PP
 Currently all long options are supported such as
 \fBmount\fR, \fBbind-mount\fR. For a option that has no argument, the option
 will occupy a single line, without '=' and value. Otherwise, any string that
diff --git a/minijail0.c b/minijail0.c
index 7ef74b5..d20c55a 100644
--- a/minijail0.c
+++ b/minijail0.c
@@ -6,6 +6,7 @@
 #include <dlfcn.h>
 #include <err.h>
 #include <errno.h>
+#include <stdbool.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
@@ -21,12 +22,11 @@ int main(int argc, char *argv[], char *environ[])
 	struct minijail *j = minijail_new();
 	const char *dl_mesg = NULL;
 	const char *preload_path = PRELOADPATH;
-	int exit_immediately = 0;
+	bool exit_immediately = false;
 	ElfType elftype = ELFERROR;
 	char **envp = NULL;
-	int consumed = parse_args(j, argc, argv, environ,
-				  &exit_immediately, &elftype,
-				  &preload_path, &envp);
+	int consumed = parse_args(j, argc, argv, environ, &exit_immediately,
+				  &elftype, &preload_path, &envp);
 	argc -= consumed;
 	argv += consumed;
 
diff --git a/minijail0_cli.c b/minijail0_cli.c
index 25aa930..4391524 100644
--- a/minijail0_cli.c
+++ b/minijail0_cli.c
@@ -3,6 +3,7 @@
  * found in the LICENSE file.
  */
 
+#include <ctype.h>
 #include <dlfcn.h>
 #include <err.h>
 #include <errno.h>
@@ -31,9 +32,16 @@
 #include "system.h"
 #include "util.h"
 
-#define IDMAP_LEN 32U
+#define IDMAP_LEN	 32U
 #define DEFAULT_TMP_SIZE (64 * 1024 * 1024)
 
+/* option_entry struct: tracks configuration options. */
+struct option_entry {
+	char *name;
+	char *args;
+	struct option_entry *next;
+};
+
 /*
  * A malloc() that aborts on failure.  We only implement this in the CLI as
  * the library should return ENOMEM errors when allocations fail.
@@ -124,7 +132,7 @@ static void suppl_group_add(size_t *suppl_gids_count, gid_t **suppl_gids,
 	 */
 	*suppl_gids =
 	    realloc(*suppl_gids, sizeof(gid_t) * ++(*suppl_gids_count));
-	if (!suppl_gids)
+	if (!*suppl_gids)
 		err(1, "failed to allocate memory");
 
 	(*suppl_gids)[*suppl_gids_count - 1] = gid;
@@ -313,8 +321,8 @@ static int has_cap_setgid(void)
 	return cap_value == CAP_SET;
 }
 
-static void set_ugid_mapping(struct minijail *j, int set_uidmap, uid_t uid,
-			     char *uidmap, int set_gidmap, gid_t gid,
+static void set_ugid_mapping(struct minijail *j, bool set_uidmap, uid_t uid,
+			     char *uidmap, bool set_gidmap, gid_t gid,
 			     char *gidmap)
 {
 	if (set_uidmap) {
@@ -360,29 +368,29 @@ static void set_ugid_mapping(struct minijail *j, int set_uidmap, uid_t uid,
 	}
 }
 
-static void use_chroot(struct minijail *j, const char *path, int *chroot,
-		       int pivot_root)
+static void use_chroot(struct minijail *j, const char *path, bool *chroot,
+		       bool pivot_root)
 {
 	if (pivot_root)
 		errx(1, "Could not set chroot because -P was specified");
 	if (minijail_enter_chroot(j, path))
 		errx(1, "Could not set chroot");
-	*chroot = 1;
+	*chroot = true;
 }
 
 static void use_pivot_root(struct minijail *j, const char *path,
-			   int *pivot_root, int chroot)
+			   bool *pivot_root, bool chroot)
 {
 	if (chroot)
 		errx(1, "Could not set pivot_root because -C was specified");
 	if (minijail_enter_pivot_root(j, path))
 		errx(1, "Could not set pivot_root");
 	minijail_namespace_vfs(j);
-	*pivot_root = 1;
+	*pivot_root = true;
 }
 
 static void use_profile(struct minijail *j, const char *profile,
-			int *pivot_root, int chroot, size_t *tmp_size)
+			bool *pivot_root, bool chroot, size_t *tmp_size)
 {
 	/* Note: New profiles should be added in minijail0_cli_unittest.cc. */
 
@@ -450,6 +458,20 @@ static void read_seccomp_filter(const char *filter_path,
 	}
 }
 
+static void set_seccomp_filters(struct minijail *j, const char *filter_path)
+{
+	struct sock_fprog filter;
+	read_seccomp_filter(filter_path, &filter);
+	minijail_set_seccomp_filters(j, &filter);
+	free((void *)filter.filter);
+}
+
+/* Path for v0 of default runtime environment. */
+static const char default_policy_path[] = "/etc/security/minijail/v0.bin";
+
+static const char config_flag_name[] = "config";
+static const char gen_config_flag_name[] = "gen-config";
+
 /*
  * Long options use values starting at 0x100 so that they're out of range of
  * bytes which is how command line options are processed.  Practically speaking,
@@ -468,13 +490,19 @@ enum {
 	OPT_CONFIG,
 	OPT_ENV_ADD,
 	OPT_ENV_RESET,
+	OPT_ENABLE_PROFILE_FS_RESTRICTIONS,
 	OPT_FS_DEFAULT_PATHS,
 	OPT_FS_PATH_RX,
 	OPT_FS_PATH_RO,
 	OPT_FS_PATH_RW,
 	OPT_FS_PATH_ADVANCED_RW,
+	OPT_GEN_CONFIG,
 	OPT_LOGGING,
+	OPT_NO_DEFAULT_RUNTIME,
+	OPT_NO_FS_RESTRICTIONS,
+	OPT_NO_NEW_SESSIONS,
 	OPT_PRELOAD_LIBRARY,
+	OPT_PRESERVE_FD,
 	OPT_PROFILE,
 	OPT_SECCOMP_BPF_BINARY,
 	OPT_UTS,
@@ -501,17 +529,24 @@ static const struct option long_options[] = {
     {"add-suppl-group", required_argument, 0, OPT_ADD_SUPPL_GROUP},
     {"allow-speculative-execution", no_argument, 0,
      OPT_ALLOW_SPECULATIVE_EXECUTION},
-    {"config", required_argument, 0, OPT_CONFIG},
+    {config_flag_name, required_argument, 0, OPT_CONFIG},
+    {gen_config_flag_name, required_argument, 0, OPT_GEN_CONFIG},
     {"env-add", required_argument, 0, OPT_ENV_ADD},
     {"env-reset", no_argument, 0, OPT_ENV_RESET},
     {"mount", required_argument, 0, 'k'},
     {"bind-mount", required_argument, 0, 'b'},
     {"ns-mount", no_argument, 0, 'v'},
+    {"enable-profile-fs-restrictions", no_argument, 0,
+     OPT_ENABLE_PROFILE_FS_RESTRICTIONS},
     {"fs-default-paths", no_argument, 0, OPT_FS_DEFAULT_PATHS},
     {"fs-path-rx", required_argument, 0, OPT_FS_PATH_RX},
     {"fs-path-ro", required_argument, 0, OPT_FS_PATH_RO},
     {"fs-path-rw", required_argument, 0, OPT_FS_PATH_RW},
     {"fs-path-advanced-rw", required_argument, 0, OPT_FS_PATH_ADVANCED_RW},
+    {"no-default-runtime-environment", no_argument, 0, OPT_NO_DEFAULT_RUNTIME},
+    {"no-fs-restrictions", no_argument, 0, OPT_NO_FS_RESTRICTIONS},
+    {"no-new-sessions", no_argument, 0, OPT_NO_NEW_SESSIONS},
+    {"preserve-fd", required_argument, 0, OPT_PRESERVE_FD},
     {0, 0, 0, 0},
 };
 
@@ -595,6 +630,14 @@ static const char help_text[] =
 "  --config <file>\n"
 "               Load the Minijail configuration file <file>.\n"
 "               If used, must be specified ahead of other options.\n"
+"  --gen-config <file>\n"
+"               Convert the current flags to a config file, then exit.\n"
+"               Only flags impacting the jailed process are included \n"
+"               (this flag, --config, and help messages are not).\n"
+"               This should be set first to avoid evaluating other flags, \n"
+"               or set later to evaluate users and paths currently available\n"
+"               (example: checking if -u is a valid user).\n"
+"               Path must be specified.\n"
 "  --profile <p>\n"
 "               Configure minijail0 to run with the <p> sandboxing profile,\n"
 "               which is a convenient way to express multiple flags\n"
@@ -626,6 +669,8 @@ static const char help_text[] =
 "Uncommon options:\n"
 "  --allow-speculative-execution\n"
 "               Allow speculative execution by disabling mitigations.\n"
+"  --enable-profile-fs-restrictions\n"
+"               Limit paths available when using minimalistic-mountns.\n"
 "  --fs-default-paths\n"
 "               Adds a set of allowed paths to allow running common system \n"
 "               executables.\n"
@@ -637,6 +682,17 @@ static const char help_text[] =
 "               Adds an allowed read-write path.\n"
 "  --fs-path-advanced-rw\n"
 "               Adds an allowed advanced read-write path.\n"
+"  --no-fs-restrictions\n"
+"               Disables path-based filesystem restrictions.\n"
+"  --no-default-runtime-environment\n"
+"               Disables default seccomp policy and setting of no_new_privs.\n"
+"  --no-new-sessions\n"
+"               Skips having Minijail call setsid(). This is useful when\n"
+"               running a process that expects to have a controlling\n"
+"               terminal set.\n"
+"  --preserve-fd\n"
+"               Preserves an fd and makes it available in the child process.\n"
+"               The fd is preserved with the same integer value.\n"
 "  --preload-library=<file>\n"
 "               Overrides the path to \"" PRELOADPATH "\".\n"
 "               This is only really useful for local testing.\n"
@@ -692,17 +748,25 @@ static int getopt_from_conf(const struct option *longopts,
 	/* Look up a matching long option. */
 	size_t i = 0;
 	const struct option *curr_opt;
+	bool long_option_found = false;
 	for (curr_opt = &longopts[0]; curr_opt->name != NULL;
 	     curr_opt = &longopts[++i])
-		if (streq(entry->key, curr_opt->name))
+		if (streq(entry->key, curr_opt->name)) {
+			long_option_found = true;
+			opt = curr_opt->val;
 			break;
-	if (curr_opt->name == NULL) {
+		}
+
+	/* Look up matching short option. */
+	if (!long_option_found && strlen(entry->key) == 1 &&
+	    isalpha(*entry->key) && strchr(optstring, *entry->key) != NULL) {
+		opt = *entry->key;
+	} else if (curr_opt->name == NULL) {
 		errx(1,
 		     "Unable to recognize '%s' as Minijail conf entry key, "
 		     "please refer to minijail0(5) for syntax and examples.",
 		     entry->key);
 	}
-	opt = curr_opt->val;
 	optarg = (char *)entry->value;
 	(*conf_index)++;
 	return opt;
@@ -711,7 +775,7 @@ static int getopt_from_conf(const struct option *longopts,
 /*
  * Similar to getopt(3), return the next option char/value as it
  * parses through the CLI argument list. Config entries in
- * |*conf_entry_list| will be parsed with precendences over cli options.
+ * |*conf_entry_list| will be parsed with precedence over CLI options.
  * Same as getopt(3), |optarg| is pointing to the option argument.
  */
 static int getopt_conf_or_cli(int argc, char *const argv[],
@@ -727,13 +791,40 @@ static int getopt_conf_or_cli(int argc, char *const argv[],
 	return opt;
 }
 
+static char *getname_from_opt(int opt)
+{
+	unsigned int i;
+	const struct option *entry = long_options;
+
+	for (i = 0; i < ARRAY_SIZE(long_options); i++) {
+		if (opt == entry->val) {
+			return xstrdup(entry->name);
+		}
+		entry++;
+	}
+	return NULL;
+}
+
+static void free_options_list(struct option_entry *opt_entry_head)
+{
+	while (opt_entry_head) {
+		struct option_entry *entry = opt_entry_head;
+		opt_entry_head = opt_entry_head->next;
+		free(entry->name);
+		free(entry->args);
+		free(entry);
+	}
+}
+
 static void set_child_env(char ***envp, char *arg, char *const environ[])
 {
 	/* We expect VAR=value format for arg. */
 	char *delim = strchr(arg, '=');
 	if (!delim) {
-		errx(1, "Expected an argument of the "
-		        "form VAR=value (got '%s')", arg);
+		errx(1,
+		     "Expected an argument of the "
+		     "form VAR=value (got '%s')",
+		     arg);
 	}
 	*delim = '\0';
 	const char *env_value = delim + 1;
@@ -751,50 +842,89 @@ static void set_child_env(char ***envp, char *arg, char *const environ[])
 }
 
 int parse_args(struct minijail *j, int argc, char *const argv[],
-	       char *const environ[], int *exit_immediately,
-	       ElfType *elftype, const char **preload_path,
-	       char ***envp)
+	       char *const environ[], bool *exit_immediately, ElfType *elftype,
+	       const char **preload_path, char ***envp)
 {
-	enum seccomp_type { None, Strict, Filter, BpfBinaryFilter };
+	enum seccomp_type {
+		None,
+		Strict,
+		Filter,
+		BpfBinaryFilter
+	};
 	enum seccomp_type seccomp = None;
 	int opt;
-	int use_seccomp_filter = 0;
-	int use_seccomp_filter_binary = 0;
-	int use_seccomp_log = 0;
-	int forward = 1;
-	int binding = 0;
-	int chroot = 0, pivot_root = 0;
-	int mount_ns = 0, change_remount = 0;
-	const char *remount_mode = NULL;
-	int inherit_suppl_gids = 0, keep_suppl_gids = 0;
-	int caps = 0, ambient_caps = 0;
-	bool use_uid = false, use_gid = false;
+	bool use_seccomp_filter = false;
+	bool use_seccomp_filter_binary = false;
+	bool use_seccomp_log = false;
+	bool forward_signals = true;
+	bool have_bind_mounts = false;
+	bool chroot = false;
+	bool pivot_root = false;
+	bool use_mount_ns = false;
+	bool change_remount = false;
+	char *remount_mode = NULL;
+	bool inherit_suppl_gids = false;
+	bool keep_suppl_gids = false;
+	bool caps = false;
+	bool use_ambient_caps = false;
+	bool use_uid = false;
+	bool use_gid = false;
 	uid_t uid = 0;
 	gid_t gid = 0;
 	gid_t *suppl_gids = NULL;
 	size_t suppl_gids_count = 0;
 	char *uidmap = NULL, *gidmap = NULL;
-	int set_uidmap = 0, set_gidmap = 0;
+	bool set_uidmap = false;
+	bool set_gidmap = false;
 	size_t tmp_size = 0;
-	const char *filter_path = NULL;
+	attribute_cleanup_str char *filter_path = NULL;
 	int log_to_stderr = -1;
 	struct config_entry_list *conf_entry_list = NULL;
 	size_t conf_index = 0;
+	bool parse_mode = false;
+	struct option_entry *opt_entry_head = NULL;
+	struct option_entry *opt_entry_tail = NULL;
+	char *config_path = NULL;
+	bool fs_path_flag_used = false;
+	bool fs_path_rules_enabled = true;
 
 	while ((opt = getopt_conf_or_cli(argc, argv, &conf_entry_list,
 					 &conf_index)) != -1) {
+
+		/* Track options for conf file generation. */
+		struct option_entry *opt_entry = calloc(1, sizeof(*opt_entry));
+		char *opt_name = getname_from_opt(opt);
+		if (opt_name != NULL) {
+			opt_entry->name = opt_name;
+		} else {
+			char str[2] = {opt, '\0'};
+			opt_entry->name = xstrdup(str);
+		}
+		if (optarg != NULL) {
+			opt_entry->args = xstrdup(optarg);
+		}
+
+		if (opt_entry_head) {
+			opt_entry_tail->next = opt_entry;
+		} else {
+			opt_entry_head = opt_entry;
+		}
+		opt_entry_tail = opt_entry;
+
 		switch (opt) {
 		case 'u':
 			if (use_uid)
 				errx(1, "-u provided multiple times.");
 			use_uid = true;
-			set_user(j, optarg, &uid, &gid);
+			if (!parse_mode)
+				set_user(j, optarg, &uid, &gid);
 			break;
 		case 'g':
 			if (use_gid)
 				errx(1, "-g provided multiple times.");
 			use_gid = true;
-			set_group(j, optarg, &gid);
+			if (!parse_mode)
+				set_group(j, optarg, &gid);
 			break;
 		case 'n':
 			minijail_no_new_privs(j);
@@ -814,8 +944,9 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			}
 			seccomp = Filter;
 			minijail_use_seccomp_filter(j);
-			filter_path = optarg;
-			use_seccomp_filter = 1;
+			free(filter_path);
+			filter_path = xstrdup(optarg);
+			use_seccomp_filter = true;
 			break;
 		case 'l':
 			minijail_namespace_ipc(j);
@@ -825,35 +956,39 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 				errx(1, "-L does not work with "
 					"--seccomp-bpf-binary");
 			}
-			use_seccomp_log = 1;
+			use_seccomp_log = true;
 			minijail_log_seccomp_filter_failures(j);
 			break;
 		case 'b':
-			add_binding(j, optarg);
-			binding = 1;
+			if (!parse_mode)
+				add_binding(j, optarg);
+			have_bind_mounts = true;
 			break;
 		case 'B':
 			skip_securebits(j, optarg);
 			break;
 		case 'c':
-			caps = 1;
+			caps = true;
 			use_caps(j, optarg);
 			break;
 		case 'C':
 			use_chroot(j, optarg, &chroot, pivot_root);
 			break;
 		case 'k':
-			add_mount(j, optarg);
+			if (!parse_mode)
+				add_mount(j, optarg);
 			break;
 		case 'K':
-			remount_mode = optarg;
-			change_remount = 1;
+			free(remount_mode);
+			remount_mode = optarg == NULL ? NULL : xstrdup(optarg);
+			change_remount = true;
 			break;
 		case 'P':
 			use_pivot_root(j, optarg, &pivot_root, chroot);
 			break;
 		case 'f':
-			if (0 != minijail_write_pid_file(j, optarg))
+			if (!parse_mode &&
+			    0 != minijail_write_pid_file(j, optarg))
 				errx(1, "Could not prepare pid file path");
 			break;
 		case 't':
@@ -865,9 +1000,13 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 				 */
 				tmp_size = DEFAULT_TMP_SIZE;
 			}
-			if (optarg != NULL &&
-			    0 != parse_size(&tmp_size, optarg)) {
-				errx(1, "Invalid /tmp tmpfs size");
+			if (optarg) {
+				uint64_t parsed_size;
+				if (parse_size(&parsed_size, optarg))
+					errx(1, "Invalid /tmp tmpfs size");
+				if (parsed_size > SIZE_MAX)
+					errx(1, "/tmp tmpfs size too large");
+				tmp_size = parsed_size;
 			}
 			break;
 		case 'v':
@@ -903,10 +1042,11 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			 * won't do anything.
 			 */
 			minijail_remount_mode(j, MS_SLAVE);
-			mount_ns = 1;
+			use_mount_ns = true;
 			break;
 		case 'V':
-			minijail_namespace_enter_vfs(j, optarg);
+			if (!parse_mode)
+				minijail_namespace_enter_vfs(j, optarg);
 			break;
 		case 'r':
 			minijail_remount_proc_readonly(j);
@@ -915,13 +1055,13 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			if (keep_suppl_gids)
 				errx(1, "-y and -G are not compatible");
 			minijail_inherit_usergroups(j);
-			inherit_suppl_gids = 1;
+			inherit_suppl_gids = true;
 			break;
 		case 'y':
 			if (inherit_suppl_gids)
 				errx(1, "-y and -G are not compatible");
 			minijail_keep_supplementary_gids(j);
-			keep_suppl_gids = 1;
+			keep_suppl_gids = true;
 			break;
 		case 'N':
 			minijail_namespace_cgroups(j);
@@ -930,13 +1070,15 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			minijail_namespace_pids(j);
 			break;
 		case 'e':
-			if (optarg)
-				minijail_namespace_enter_net(j, optarg);
-			else
-				minijail_namespace_net(j);
+			if (!parse_mode) {
+				if (optarg)
+					minijail_namespace_enter_net(j, optarg);
+				else
+					minijail_namespace_net(j);
+			}
 			break;
 		case 'i':
-			*exit_immediately = 1;
+			*exit_immediately = true;
 			break;
 		case 'H':
 			seccomp_filter_usage(argv[0]);
@@ -950,7 +1092,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			minijail_namespace_pids(j);
 			break;
 		case 'm':
-			set_uidmap = 1;
+			set_uidmap = true;
 			if (uidmap) {
 				free(uidmap);
 				uidmap = NULL;
@@ -959,7 +1101,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 				uidmap = xstrdup(optarg);
 			break;
 		case 'M':
-			set_gidmap = 1;
+			set_gidmap = true;
 			if (gidmap) {
 				free(gidmap);
 				gidmap = NULL;
@@ -991,7 +1133,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			minijail_set_seccomp_filter_tsync(j);
 			break;
 		case 'z':
-			forward = 0;
+			forward_signals = false;
 			break;
 		case 'd':
 			minijail_namespace_vfs(j);
@@ -999,7 +1141,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			break;
 		/* Long options. */
 		case OPT_AMBIENT:
-			ambient_caps = 1;
+			use_ambient_caps = true;
 			minijail_set_ambient_caps(j);
 			break;
 		case OPT_UTS:
@@ -1022,35 +1164,64 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			use_profile(j, optarg, &pivot_root, chroot, &tmp_size);
 			break;
 		case OPT_PRELOAD_LIBRARY:
-			*preload_path = optarg;
+			*preload_path = optarg == NULL ? NULL : xstrdup(optarg);
+			break;
+		case OPT_ENABLE_PROFILE_FS_RESTRICTIONS:
+			minijail_set_enable_profile_fs_restrictions(j);
 			break;
 		case OPT_FS_DEFAULT_PATHS:
 			minijail_enable_default_fs_restrictions(j);
+			fs_path_flag_used = true;
 			break;
 		case OPT_FS_PATH_RX:
 			minijail_add_fs_restriction_rx(j, optarg);
+			fs_path_flag_used = true;
 			break;
 		case OPT_FS_PATH_RO:
 			minijail_add_fs_restriction_ro(j, optarg);
+			fs_path_flag_used = true;
 			break;
 		case OPT_FS_PATH_RW:
 			minijail_add_fs_restriction_rw(j, optarg);
+			fs_path_flag_used = true;
 			break;
 		case OPT_FS_PATH_ADVANCED_RW:
 			minijail_add_fs_restriction_advanced_rw(j, optarg);
+			fs_path_flag_used = true;
+			break;
+		case OPT_NO_FS_RESTRICTIONS:
+			minijail_disable_fs_restrictions(j);
+			fs_path_rules_enabled = false;
+			break;
+		case OPT_NO_DEFAULT_RUNTIME:
+			minijail_set_enable_default_runtime(j, false);
 			break;
+		case OPT_NO_NEW_SESSIONS:
+			minijail_set_enable_new_sessions(j, false);
+			break;
+		case OPT_PRESERVE_FD: {
+			char *fd_end;
+			int fd_to_preserve = strtol(optarg, &fd_end, 10);
+			if (*fd_end != '\0') {
+				errx(1, "--preserve-fd must be an integer");
+			}
+
+			minijail_preserve_fd(j, fd_to_preserve, fd_to_preserve);
+			break;
+		}
 		case OPT_SECCOMP_BPF_BINARY:
 			if (seccomp != None && seccomp != BpfBinaryFilter) {
 				errx(1, "Do not use -s, -S, or "
 					"--seccomp-bpf-binary together");
 			}
-			if (use_seccomp_log == 1)
+			if (use_seccomp_log)
 				errx(1, "-L does not work with "
 					"--seccomp-bpf-binary");
 			seccomp = BpfBinaryFilter;
 			minijail_use_seccomp_filter(j);
-			filter_path = optarg;
-			use_seccomp_filter_binary = 1;
+			free(filter_path);
+			filter_path = xstrdup(optarg);
+			use_seccomp_filter_binary = true;
 			break;
 		case OPT_ADD_SUPPL_GROUP:
 			suppl_group_add(&suppl_gids_count, &suppl_gids, optarg);
@@ -1106,6 +1277,11 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 			}
 			break;
 		}
+		case OPT_GEN_CONFIG:
+			parse_mode = true;
+			free(config_path);
+			config_path = xstrdup(optarg);
+			break;
 		case OPT_ENV_ADD:
 			/*
 			 * We either copy our current env to the child env
@@ -1153,6 +1329,45 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 		}
 	}
 
+	if (fs_path_flag_used && !fs_path_rules_enabled) {
+		errx(1, "Can't combine --no-fs-restrictions "
+			"with directly using fs path flags");
+	}
+
+	/* Handle config file generation. */
+	if (parse_mode) {
+		const struct option_entry *r = opt_entry_head;
+		if (access(config_path, F_OK) == 0) {
+			errx(1, "'%s' exists. Specify a new filename.",
+			     config_path);
+		}
+		attribute_cleanup_fp FILE *fp = fopen(config_path, "w");
+		if (fp == NULL) {
+			err(1, "'%s' not writable. Specify a new filename.",
+			    config_path);
+		}
+
+		fprintf(fp, "%% minijail-config-file v0\n\n");
+		while (r != NULL) {
+			/* Add all flags except --config and --gen-config. */
+			if (!streq(r->name, config_flag_name) &&
+			    !streq(r->name, gen_config_flag_name)) {
+				if (r->args == NULL) {
+					fprintf(fp, "%s\n", r->name);
+				} else {
+					fprintf(fp, "%s = %s\n", r->name,
+						r->args);
+				}
+			}
+			r = r->next;
+		}
+
+		exit(0);
+	}
+	free_options_list(opt_entry_head);
+	opt_entry_head = NULL;
+	opt_entry_tail = NULL;
+
 	/* Set up uid/gid mapping. */
 	if (set_uidmap || set_gidmap) {
 		set_ugid_mapping(j, set_uidmap, uid, uidmap, set_gidmap, gid,
@@ -1160,20 +1375,20 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 	}
 
 	/* Can only set ambient caps when using regular caps. */
-	if (ambient_caps && !caps) {
+	if (use_ambient_caps && !caps) {
 		errx(1, "Can't set ambient capabilities (--ambient) "
 			"without actually using capabilities (-c)");
 	}
 
 	/* Set up signal handlers in minijail unless asked not to. */
-	if (forward)
+	if (forward_signals)
 		minijail_forward_signals(j);
 
 	/*
 	 * Only allow bind mounts when entering a chroot, using pivot_root, or
 	 * a new mount namespace.
 	 */
-	if (binding && !(chroot || pivot_root || mount_ns)) {
+	if (have_bind_mounts && !(chroot || pivot_root || use_mount_ns)) {
 		errx(1, "Bind mounts require a chroot, pivot_root, or "
 			" new mount namespace");
 	}
@@ -1182,7 +1397,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 	 * / is only remounted when entering a new mount namespace, so unless
 	 * that's set there is no need for the -K/-K<mode> flags.
 	 */
-	if (change_remount && !mount_ns) {
+	if (change_remount && !use_mount_ns) {
 		errx(1, "No need to use -K (skip remounting '/') or "
 			"-K<mode> (remount '/' as <mode>) "
 			"without -v (new mount namespace).\n"
@@ -1215,16 +1430,25 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 	if (use_seccomp_filter) {
 		minijail_parse_seccomp_filters(j, filter_path);
 	} else if (use_seccomp_filter_binary) {
-		struct sock_fprog filter;
-		read_seccomp_filter(filter_path, &filter);
-		minijail_set_seccomp_filters(j, &filter);
-		free((void *)filter.filter);
+		set_seccomp_filters(j, filter_path);
+	} else if (minijail_get_enable_default_runtime(j)) {
+		if (access(default_policy_path, F_OK) == 0) {
+			/* TODO(b/254506006): support more flags for runtime
+			 * options. */
+			minijail_use_seccomp_filter(j);
+			set_seccomp_filters(j, default_policy_path);
+		}
+		/* Set no_new_privs in addition to the seccomp policy. */
+		minijail_no_new_privs(j);
 	}
 
 	/* Mount a tmpfs under /tmp and set its size. */
 	if (tmp_size)
 		minijail_mount_tmp_size(j, tmp_size);
 
+	/* Add Landlock rules for each processed mount arg. */
+	minijail_add_minimalistic_mountns_fs_rules(j);
+
 	/*
 	 * Copy our current env to the child if its |*envp| has not
 	 * already been initialized from --env-(reset|add) usage.
@@ -1268,7 +1492,7 @@ int parse_args(struct minijail *j, int argc, char *const argv[],
 	 * use of ambient capabilities for them to be able to survive an
 	 * execve(2).
 	 */
-	if (caps && *elftype == ELFSTATIC && !ambient_caps) {
+	if (caps && *elftype == ELFSTATIC && !use_ambient_caps) {
 		errx(1, "Can't run statically-linked binaries with capabilities"
 			" (-c) without also setting ambient capabilities. "
 			"Try passing --ambient.");
diff --git a/minijail0_cli.h b/minijail0_cli.h
index 00a541c..3cdbd1d 100644
--- a/minijail0_cli.h
+++ b/minijail0_cli.h
@@ -8,6 +8,8 @@
 #ifndef MINIJAIL_MINIJAIL0_CLI_H_
 #define MINIJAIL_MINIJAIL0_CLI_H_
 
+#include <stdbool.h>
+
 #include "elfparse.h"
 
 #ifdef __cplusplus
@@ -17,12 +19,11 @@ extern "C" {
 struct minijail;
 
 int parse_args(struct minijail *j, int argc, char *const argv[],
-	       char *const environ[], int *exit_immediately,
-	       ElfType *elftype, const char **preload_path,
-	       char ***envp);
+	       char *const environ[], bool *exit_immediately, ElfType *elftype,
+	       const char **preload_path, char ***envp);
 
 #ifdef __cplusplus
 }; /* extern "C" */
 #endif
 
-#endif  /* MINIJAIL_MINIJAIL0_CLI_H_ */
+#endif /* MINIJAIL_MINIJAIL0_CLI_H_ */
diff --git a/minijail0_cli_unittest.cc b/minijail0_cli_unittest.cc
index 8674e07..ebbf7a8 100644
--- a/minijail0_cli_unittest.cc
+++ b/minijail0_cli_unittest.cc
@@ -9,6 +9,8 @@
  * this test, we'd have to pull that struct into a common (internal) header.
  */
 
+#include <cstdio>
+#include <fstream>
 #include <stdio.h>
 #include <stdlib.h>
 
@@ -39,7 +41,7 @@ class CliTest : public ::testing::Test {
   // need the backing memory to be writable.  The CLI might mutate the strings
   // as it parses things (which is normally permissible with argv).
   int parse_args_(const std::vector<std::string>& argv,
-                  int* exit_immediately,
+                  bool* exit_immediately,
                   ElfType* elftype) {
     // Make sure we reset the getopts state when scanning a new argv.  Setting
     // this to 0 is a GNU extension, but AOSP/BSD also checks this (as an alias
@@ -48,9 +50,9 @@ class CliTest : public ::testing::Test {
 
     // We create & destroy this for every parse_args call because some API
     // calls can dupe memory which confuses LSAN.  https://crbug.com/844615
-    struct minijail *j = minijail_new();
+    struct minijail* j = minijail_new();
 
-    std::vector<const char *> pargv;
+    std::vector<const char*> pargv;
     pargv.push_back("minijail0");
     for (const std::string& arg : argv)
       pargv.push_back(arg.c_str());
@@ -60,7 +62,7 @@ class CliTest : public ::testing::Test {
     testing::internal::CaptureStdout();
 
     const char* preload_path = PRELOADPATH;
-    char **envp = NULL;
+    char** envp = NULL;
     int ret =
         parse_args(j, pargv.size(), const_cast<char* const*>(pargv.data()),
                    NULL, exit_immediately, elftype, &preload_path, &envp);
@@ -76,7 +78,7 @@ class CliTest : public ::testing::Test {
   }
 
   ElfType elftype_;
-  int exit_immediately_;
+  bool exit_immediately_;
 };
 
 }  // namespace
@@ -239,8 +241,8 @@ TEST_F(CliTest, valid_logging) {
 
   // This should list all valid logging targets.
   const std::vector<std::string> profiles = {
-    "stderr",
-    "syslog",
+      "stderr",
+      "syslog",
   };
 
   for (const auto& profile : profiles) {
@@ -318,8 +320,8 @@ TEST_F(CliTest, valid_profile) {
 
   // This should list all valid profiles.
   const std::vector<std::string> profiles = {
-    "minimalistic-mountns",
-    "minimalistic-mountns-nodev",
+      "minimalistic-mountns",
+      "minimalistic-mountns-nodev",
   };
 
   for (const auto& profile : profiles) {
@@ -337,6 +339,23 @@ TEST_F(CliTest, invalid_profile) {
   ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
 }
 
+// Valid usage of the no-fs-restrictions option.
+TEST_F(CliTest, valid_no_fs_restrictions) {
+  std::vector<std::string> argv = {"--profile", "minimalistic-mountns",
+                                   "--no-fs-restrictions", "/bin/sh"};
+
+  ASSERT_TRUE(parse_args_(argv));
+}
+
+// Invalid usage of the no-fs-restrictions option.
+TEST_F(CliTest, invalid_no_fs_restrictions) {
+  // Using an fs-path-* flag at the same time shouldn't be allowed.
+  std::vector<std::string> argv = {"--fs-path-rx", "/", "--no-fs-restrictions",
+                                   "/bin/sh"};
+
+  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
+}
+
 // Valid calls to the chroot option.
 TEST_F(CliTest, valid_chroot) {
   std::vector<std::string> argv = {"-C", "/", "/bin/sh"};
@@ -509,10 +528,10 @@ TEST_F(CliTest, valid_remount_mode) {
 
   // This should list all valid modes.
   const std::vector<std::string> modes = {
-    "shared",
-    "private",
-    "slave",
-    "unbindable",
+      "shared",
+      "private",
+      "slave",
+      "unbindable",
   };
 
   for (const auto& mode : modes) {
@@ -558,22 +577,23 @@ TEST_F(CliTest, valid_set_env) {
   ASSERT_TRUE(parse_args_(argv1));
 
   // multiple occurences are allowed.
-  std::vector<std::string> argv2 = {"--env-add", "A=b",
-                                    "--env-add", "b=C=D", "/bin/sh"};
+  std::vector<std::string> argv2 = {"--env-add", "A=b", "--env-add", "b=C=D",
+                                    "/bin/sh"};
   ASSERT_TRUE(parse_args_(argv2));
 
   // --env-reset before any --env-add to not pass our own env.
-  std::vector<std::string> argv3 = {"--env-reset", "--env-add", "A=b", "/bin/sh"};
+  std::vector<std::string> argv3 = {"--env-reset", "--env-add", "A=b",
+                                    "/bin/sh"};
   ASSERT_TRUE(parse_args_(argv3));
 
   // --env-add before an --env-reset doesn't have any effect, but is allowed.
-  std::vector<std::string> argv4 = {"--env-add", "A=b", "--env-reset", "/bin/sh"};
+  std::vector<std::string> argv4 = {"--env-add", "A=b", "--env-reset",
+                                    "/bin/sh"};
   ASSERT_TRUE(parse_args_(argv4));
 }
 
 // Invalid calls to the set env options.
 TEST_F(CliTest, invalid_set_env) {
-
   // invalid env=value arguments.
   std::vector<std::string> argv2 = {"--env-add", "", "/bin/sh"};
 
@@ -587,6 +607,42 @@ TEST_F(CliTest, invalid_set_env) {
   ASSERT_EXIT(parse_args_(argv2), testing::ExitedWithCode(1), "");
 }
 
+// Valid calls to the gen-config option.
+TEST_F(CliTest, valid_gen_config) {
+  std::string config_path = std::tmpnam(NULL);
+  std::vector<std::string> argv = {"--gen-config=" + config_path, "--ambient",
+                                   "--fs-path-rx=/", "-n"};
+  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(0), "");
+}
+
+TEST_F(CliTest, valid_gen_config_with_users_mounts_not_found) {
+  std::string config_path = std::tmpnam(NULL);
+  std::vector<std::string> argv = {"--gen-config=" + config_path,
+                                   "--ambient",
+                                   "-u fake-user",
+                                   "-g fake-group",
+                                   "-b /fake-mount",
+                                   "-k /fake-mount",
+                                   "-e /fake-path",
+                                   "-f /fake-path",
+                                   "-V /fake-path",
+                                   "-n"};
+  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(0), "");
+}
+
+// Invalid calls to the gen-config option.
+TEST_F(CliTest, invalid_gen_config) {
+  std::vector<std::string> argv = {"--gen-config=/", "--ambient",
+                                   "--fs-path-rx=/", "-n"};
+  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
+}
+
+TEST_F(CliTest, invalid_gen_config_not_writable) {
+  std::vector<std::string> argv = {"--gen-config=/sys/foo", "--ambient",
+                                   "--fs-path-rx=/", "-n"};
+  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
+}
+
 // Android unit tests do not support data file yet.
 #if !defined(__ANDROID__)
 
@@ -598,28 +654,40 @@ TEST_F(CliTest, conf_parsing_invalid_key) {
 }
 
 TEST_F(CliTest, conf_parsing) {
-  std::vector<std::string> argv = {"--config",
-                                   source_path("test/valid.conf"),
+  std::vector<std::string> argv = {"--config", source_path("test/valid.conf"),
                                    "/bin/sh"};
 
   ASSERT_TRUE(parse_args_(argv));
 }
 
+TEST_F(CliTest, conf_parsing_seccomp) {
+  std::string seccomp_path = std::tmpnam(NULL);
+  std::ofstream seccomp_stream(seccomp_path);
+  // Intentionally empty policy.
+  std::string config_path = std::tmpnam(NULL);
+  std::ofstream config_stream(config_path);
+  config_stream << "% minijail-config-file v0\n"
+                   "S = " +
+                       seccomp_path;
+  config_stream.flush();
+
+  std::vector<std::string> argv = {"--config", config_path, "/bin/sh"};
+
+  ASSERT_TRUE(parse_args_(argv));
+}
+
 TEST_F(CliTest, conf_parsing_with_dac_override) {
   std::vector<std::string> argv = {"-c 2", "--config",
-                                   source_path("test/valid.conf"),
-                                   "/bin/sh"};
+                                   source_path("test/valid.conf"), "/bin/sh"};
 
   ASSERT_TRUE(parse_args_(argv));
 }
 
 TEST_F(CliTest, conf_fs_path) {
-  std::vector<std::string> argv = {"-c 2", "--config",
-                                   source_path("test/landlock.conf"),
-                                   "/bin/sh"};
+  std::vector<std::string> argv = {
+      "-c 2", "--config", source_path("test/landlock.conf"), "/bin/sh"};
 
   ASSERT_TRUE(parse_args_(argv));
 }
 
-
 #endif  // !__ANDROID__
diff --git a/navbar.md b/navbar.md
index 67493f2..de38293 100644
--- a/navbar.md
+++ b/navbar.md
@@ -3,7 +3,7 @@
 [home]: /README.md
 
 * [Home][home]
-* [User Docs](https://chromium.googlesource.com/chromiumos/docs/+/master/sandboxing.md)
+* [User Docs](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md)
 * [Bugs](https://crbug.com/?q=component:OS>Systems>Minijail)
 * [License](./LICENSE)
 * [Hacking](./HACKING.md)
diff --git a/parse_seccomp_policy.cc b/parse_seccomp_policy.cc
index e511156..946005e 100644
--- a/parse_seccomp_policy.cc
+++ b/parse_seccomp_policy.cc
@@ -79,8 +79,7 @@ int main(int argc, char** argv) {
     pdie("fopen(%s) failed", argv[1]);
 
   struct filter_options fopts {
-    .action = ACTION_RET_KILL,
-    .allow_logging = 0,
+    .action = ACTION_RET_KILL, .allow_logging = 0,
     .allow_syscalls_for_logging = 0,
     .allow_duplicate_syscalls = allow_duplicate_syscalls(),
   };
diff --git a/policies/cros_default_v0.policy b/policies/cros_default_v0.policy
new file mode 100644
index 0000000..6db7f54
--- /dev/null
+++ b/policies/cros_default_v0.policy
@@ -0,0 +1,4 @@
+@denylist
+# ChromeOS default runtime policy v0.
+
+bpf: return EPERM
diff --git a/rust/minijail-sys/Cargo.toml b/rust/minijail-sys/Cargo.toml
index 6745d14..f3a91b8 100644
--- a/rust/minijail-sys/Cargo.toml
+++ b/rust/minijail-sys/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "minijail-sys"
-version = "0.0.13"
+version = "0.0.14"
 description = "Provides raw (unsafe) bindings to the libminijail C library."
 authors = ["The ChromiumOS Authors"]
 edition = "2018"
@@ -13,5 +13,6 @@ path = "lib.rs"
 libc = "0.2.44"
 
 [build-dependencies]
+bindgen = "0.63"
 pkg-config = "0.3"
 which = "4.0.0"
diff --git a/rust/minijail-sys/build.rs b/rust/minijail-sys/build.rs
index a223f3a..51ddb56 100644
--- a/rust/minijail-sys/build.rs
+++ b/rust/minijail-sys/build.rs
@@ -2,16 +2,28 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-/// Minijail's build script invoked by cargo.
-///
-/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
-/// building libminijail statically.
+//! Minijail's build script invoked by cargo.
+//!
+//! This script prefers linking against a pkg-config provided libminijail, but will fall back to
+//! building libminijail statically.
+//!
+//! The build process can be modified with the following environment variables:
+//!
+//! MINIJAIL_DO_NOT_BUILD: Skip building minijail. This tends to result in a linker error later,
+//! but may be acceptable when just running clippy.
+//!
+//! MINIJAIL_BINDGEN_TARGET: Overrides which clang target is used to generate bindings.
+
 use std::env;
-use std::fs::remove_file;
 use std::io;
-use std::path::Path;
+use std::path::{Path, PathBuf};
 use std::process::Command;
 
+use bindgen::EnumVariation;
+
+const HEADER_FILENAME: &str = "libminijail.h";
+const OUT_FILENAME: &str = "libminijail.rs";
+
 /// Returns the target triplet prefix for gcc commands. No prefix is required
 /// for native builds.
 fn get_cross_compile_prefix() -> String {
@@ -35,82 +47,83 @@ fn get_cross_compile_prefix() -> String {
     return format!("{}-{}-{}-", arch, os, env);
 }
 
-fn set_up_libminijail() -> io::Result<()> {
-    // Minijail requires libcap at runtime.
-    pkg_config::Config::new().probe("libcap").unwrap();
-
+fn set_up_libminijail() -> io::Result<PathBuf> {
     // Prefer a system-provided Minijail library.
-    if pkg_config::Config::new().probe("libminijail").is_ok() {
-        return Ok(());
+    if let Ok(info) = pkg_config::Config::new().probe("libminijail") {
+        for path in info.include_paths {
+            let header_path = path.join(HEADER_FILENAME);
+            if header_path.exists() {
+                return Ok(header_path);
+            }
+        }
     }
 
-    let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap() + "/../..";
-    let out_dir = env::var("OUT_DIR").unwrap();
-    let profile = env::var("PROFILE").unwrap();
-
-    let status = Command::new("make")
-        .current_dir(&out_dir)
-        .env("OUT", &out_dir)
-        .env("MODE", if profile == "release" { "opt" } else { "debug" })
-        .env("CROSS_COMPILE", get_cross_compile_prefix())
-        .env("BUILD_STATIC_LIBS", "yes")
-        .arg("-C")
-        .arg(&current_dir)
-        .status()?;
-    if !status.success() {
-        std::process::exit(status.code().unwrap_or(1));
+    if env::var("MINIJAIL_DO_NOT_BUILD").as_deref().unwrap_or("") == "" {
+        let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap() + "/../..";
+        let out_dir = env::var("OUT_DIR").unwrap();
+        let profile = env::var("PROFILE").unwrap();
+        let jobs = env::var("JOBS").unwrap_or("4".to_string());
+
+        let status = Command::new("make")
+            .current_dir(&out_dir)
+            .env("OUT", &out_dir)
+            .env("MODE", if profile == "release" { "opt" } else { "debug" })
+            .env("CROSS_COMPILE", get_cross_compile_prefix())
+            .env("BUILD_STATIC_LIBS", "yes")
+            .arg("-C")
+            .arg(&current_dir)
+            .arg("-j")
+            .arg(&jobs)
+            .status()?;
+        if !status.success() {
+            std::process::exit(status.code().unwrap_or(1));
+        }
+        println!("cargo:rustc-link-search=native={}", &out_dir);
+        println!("cargo:rustc-link-lib=static=minijail.pic");
     }
-    println!("cargo:rustc-link-search=native={}", &out_dir);
-    println!("cargo:rustc-link-lib=static=minijail.pic");
-    Ok(())
+
+    let header_dir = Path::new("../../");
+    let header_path = header_dir.join(HEADER_FILENAME);
+    Ok(header_path)
 }
 
-fn bindings_generation() -> io::Result<()> {
-    let bindgen = match which::which("bindgen") {
-        Ok(v) => v,
-        // Use already generated copy if bindgen is not present.
-        _ => return Ok(()),
-    };
+fn bindings_generation(header_path: &str) -> io::Result<()> {
+    println!("cargo:rerun-if-changed={}", header_path);
+    println!("cargo:rerun-if-changed=build.rs");
 
-    // If CROS_RUST is set, skip generation.
-    let gen_file = Path::new("./libminijail.rs");
-    if gen_file.exists() {
-        if env::var("CROS_RUST") == Ok(String::from("1")) {
-            return Ok(());
-        }
-        remove_file(gen_file).expect("Failed to remove generated file.");
+    let mut builder = bindgen::Builder::default()
+        .header(header_path)
+        .default_enum_style(EnumVariation::Rust {
+            non_exhaustive: false,
+        })
+        .blocklist_type("__rlim64_t")
+        .raw_line("pub type __rlim64_t = u64;")
+        .blocklist_type("__u\\d{1,2}")
+        .raw_line("pub type __u8 = u8;")
+        .raw_line("pub type __u16 = u16;")
+        .raw_line("pub type __u32 = u32;")
+        .blocklist_type("__uint64_t")
+        .allowlist_function("^minijail_.*")
+        .allowlist_var("^MINIJAIL_.*")
+        .size_t_is_usize(true)
+        .layout_tests(false)
+        .disable_header_comment()
+        .clang_arg("-DUSE_BINDGEN")
+        .clang_arg("-D_FILE_OFFSET_BITS=64")
+        .clang_arg("-D_LARGEFILE_SOURCE")
+        .clang_arg("-D_LARGEFILE64_SOURCE");
+
+    if let Ok(target) = env::var("MINIJAIL_BINDGEN_TARGET") {
+        builder = builder.clang_arg(format!("--target={}", target));
     }
-    let header_dir = Path::new("../../");
-    let header_path = header_dir.join("libminijail.h");
-    println!("cargo:rerun-if-changed={}", header_path.display());
-    let status = Command::new(&bindgen)
-        .args(&["--default-enum-style", "rust"])
-        .args(&["--blocklist-type", "__rlim64_t"])
-        .args(&["--raw-line", "pub type __rlim64_t = u64;"])
-        .args(&["--blocklist-type", "__u\\d{1,2}"])
-        .args(&["--raw-line", "pub type __u8 = u8;"])
-        .args(&["--raw-line", "pub type __u16 = u16;"])
-        .args(&["--raw-line", "pub type __u32 = u32;"])
-        .args(&["--blocklist-type", "__uint64_t"])
-        .args(&["--allowlist-function", "^minijail_.*"])
-        .args(&["--allowlist-var", "^MINIJAIL_.*"])
-        .arg("--no-layout-tests")
-        .arg("--disable-header-comment")
-        .args(&["--output", gen_file.to_str().unwrap()])
-        .arg(header_path.to_str().unwrap())
-        .args(&[
-            "--",
-            "-DUSE_BINDGEN",
-            "-D_FILE_OFFSET_BITS=64",
-            "-D_LARGEFILE_SOURCE",
-            "-D_LARGEFILE64_SOURCE",
-        ])
-        .status()?;
-    assert!(status.success());
-    Ok(())
+
+    let bindings = builder.generate().expect("failed to generate bindings");
+
+    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
+    bindings.write_to_file(out_path.join(OUT_FILENAME))
 }
 
 fn main() -> io::Result<()> {
-    set_up_libminijail()?;
-    bindings_generation()
+    let header_path = set_up_libminijail()?;
+    bindings_generation(header_path.to_str().unwrap())
 }
diff --git a/rust/minijail-sys/lib.rs b/rust/minijail-sys/lib.rs
index 0285594..a527f22 100644
--- a/rust/minijail-sys/lib.rs
+++ b/rust/minijail-sys/lib.rs
@@ -4,44 +4,13 @@
 
 /// libminijail bindings for Rust.
 
-// TODO(crbug.com/1032672): Generate bindings at build time.
-//
-// Bindgen will invoke the C preprocessor to process headers, which means that the bindings
-// generated can depend on the architecture that actually ran bindgen. In particular, for
-// portability across compilers glibc defines types like __u8 and __rlim64_t in terms of C types
-// like unsigned char and unsigned long. This is problematic for __rlim64_t since that resolves to
-// unsigned long int on amd64, which will end up being 32-bit on 32-bit platforms.
-//
-// As a workaround to let us commit these bindings and still use them on 32-bit platforms, the
-// bindgen invocation blocklists some of the generated fixed-width types and redefines them
-// manually as Rust fixed-width types.
-//
-// Generated in CrOS SDK chroot with:
-// bindgen --default-enum-style rust \
-//         --blocklist-type '__rlim64_t' \
-//         --raw-line 'pub type __rlim64_t = u64;' \
-//         --blocklist-type '__u\d{1,2}' \
-//         --raw-line 'pub type __u8 = u8;' \
-//         --raw-line 'pub type __u16 = u16;' \
-//         --raw-line 'pub type __u32 = u32;' \
-//         --blocklist-type '__uint64_t' \
-//         --allowlist-function '^minijail_.*' \
-//         --allowlist-var '^MINIJAIL_.*' \
-//         --no-layout-tests \
-//         --output libminijail.rs \
-//         libminijail.h -- \
-//         -DUSE_BINDGEN \
-//         -D_FILE_OFFSET_BITS=64 \
-//         -D_LARGEFILE_SOURCE \
-//         -D_LARGEFILE64_SOURCE
-//
-// Enum variants in rust are customarily camel case, but bindgen will leave the original names
-// intact.
 #[allow(
     clippy::all,
     non_camel_case_types,
     non_snake_case,
     non_upper_case_globals
 )]
-mod libminijail;
+mod libminijail {
+    include!(concat!(env!("OUT_DIR"), "/libminijail.rs"));
+}
 pub use crate::libminijail::*;
diff --git a/rust/minijail-sys/libminijail.rs b/rust/minijail-sys/out/libminijail.rs
similarity index 100%
rename from rust/minijail-sys/libminijail.rs
rename to rust/minijail-sys/out/libminijail.rs
diff --git a/rust/minijail/Android.bp b/rust/minijail/Android.bp
index dce38b3..65d55d8 100644
--- a/rust/minijail/Android.bp
+++ b/rust/minijail/Android.bp
@@ -1,5 +1,7 @@
 // This file is generated by cargo_embargo.
-// Do not modify this file as changes will be overridden on upgrade.
+// Do not modify this file after the first "rust_*" or "genrule" module
+// because the changes will be overridden on upgrade.
+// Content before the first "rust_*" or "genrule" module is preserved.
 
 package {
     // See: http://go/android-license-faq
@@ -16,7 +18,7 @@ rust_library {
     crate_name: "minijail",
     cargo_env_compat: true,
     cargo_pkg_version: "0.2.3",
-    srcs: ["src/lib.rs"],
+    crate_root: "src/lib.rs",
     edition: "2018",
     rustlibs: [
         "liblibc",
diff --git a/rust/minijail/Cargo.toml b/rust/minijail/Cargo.toml
index 5c4087f..55bb025 100644
--- a/rust/minijail/Cargo.toml
+++ b/rust/minijail/Cargo.toml
@@ -8,3 +8,8 @@ edition = "2018"
 [dependencies]
 libc = "0.2.44"
 minijail-sys = { path = "../minijail-sys" } # provided by ebuild
+
+[[test]]
+name = "fork_remap"
+path = "tests/fork_remap.rs"
+harness = false
diff --git a/rust/minijail/src/lib.rs b/rust/minijail/src/lib.rs
index 5d7d7fe..bca7958 100644
--- a/rust/minijail/src/lib.rs
+++ b/rust/minijail/src/lib.rs
@@ -6,11 +6,12 @@ use std::ffi::CString;
 use std::fmt::{self, Display};
 use std::fs;
 use std::io;
-use std::os::raw::{c_char, c_ulong, c_ushort};
+use std::os::raw::{c_char, c_int, c_ulong, c_ushort};
 use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
 use std::path::{Path, PathBuf};
 use std::ptr::{null, null_mut};
 use std::result::Result as StdResult;
+use std::sync::Once;
 
 use libc::pid_t;
 use minijail_sys::*;
@@ -231,6 +232,8 @@ pub enum Error {
     ReturnCode(u8),
     /// Failed to wait the process.
     Wait(i32),
+    /// Failed to clone the log fd
+    CloneLogFd(io::Error),
 }
 
 impl Display for Error {
@@ -324,6 +327,7 @@ impl Display for Error {
                 "failed to wait: {}",
                 io::Error::from_raw_os_error(*errno)
             ),
+            CloneLogFd(e) => write!(f, "failed to clone log fd: {}", e),
         }
     }
 }
@@ -375,6 +379,10 @@ pub type Result<T> = StdResult<T, Error>;
 /// process.
 pub struct Minijail {
     jail: *mut minijail,
+    disable_multithreaded_check: bool,
+    // Meant to hold on to log_fd for the duration of the Minijail
+    // Is a combination of log_fd and min priority.
+    log_fd: Option<(std::os::fd::OwnedFd, libc::c_int)>,
 }
 
 #[link(name = "c")]
@@ -419,13 +427,18 @@ impl Minijail {
         if j.is_null() {
             return Err(Error::CreatingMinijail);
         }
-        Ok(Minijail { jail: j })
+        Ok(Minijail {
+            jail: j,
+            disable_multithreaded_check: false,
+            log_fd: None,
+        })
     }
 
     /// Clones self to a new `Minijail`. Useful because `fork` can only be called once on a
     /// `Minijail`.
     pub fn try_clone(&self) -> Result<Minijail> {
-        let jail_out = Minijail::new()?;
+        let mut jail_out = Minijail::new()?;
+        jail_out.disable_multithreaded_check = self.disable_multithreaded_check;
         unsafe {
             // Safe to clone one minijail to the other as minijail_clone doesn't modify the source
             // jail(`self`) and leaves a valid minijail in the destination(`jail_out`).
@@ -435,6 +448,13 @@ impl Minijail {
             }
         }
 
+        if let Some((log_fd, min_priority)) = &self.log_fd {
+            jail_out.log_to_fd(
+                log_fd.try_clone().map_err(Error::CloneLogFd)?,
+                *min_priority,
+            );
+        }
+
         Ok(jail_out)
     }
 
@@ -673,6 +693,16 @@ impl Minijail {
         }
         Ok(())
     }
+    pub fn log_to_fd(&mut self, fd: std::os::fd::OwnedFd, min_priority: c_int) {
+        // Minijail doesn't close the fd when it is destroyed, so this is safe.
+        unsafe {
+            minijail_log_to_fd(fd.as_raw_fd(), min_priority);
+        }
+        // minijail_log_to_fd "borrows" the fd  (in Rust parlance), so we need to store the
+        // fd as long as Minijail is alive for correctness.
+        self.log_fd = Some((fd, min_priority));
+    }
+
     pub fn enter_chroot<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
         let pathstring = dir
             .as_ref()
@@ -811,6 +841,19 @@ impl Minijail {
         Ok(())
     }
 
+    /// Disables the check that prevents forking in a multithreaded environment.
+    /// This is only safe if the child process calls exec immediately after
+    /// forking. The state of locks, and whether or not they will unlock
+    /// is undefined. Additionally, objects allocated on other threads that
+    /// expect to be dropped when those threads cease execution will not be
+    /// dropped.
+    /// Thus, nothing should be called that relies on shared synchronization
+    /// primitives referenced outside of the current thread. The safest
+    /// way to use this is to immediately exec in the child.
+    pub fn disable_multithreaded_check(&mut self) {
+        self.disable_multithreaded_check = true;
+    }
+
     /// Forks and execs a child and puts it in the previously configured minijail.
     /// FDs 0, 1, and 2 are overwritten with /dev/null FDs unless they are included in the
     /// inheritable_fds list. This function may abort in the child on error because a partially
@@ -906,8 +949,8 @@ impl Minijail {
         }
 
         match cmd.program {
-            Program::Filename(ref path) => path.as_path().run_command(&self, &cmd),
-            Program::FileDescriptor(fd) => fd.run_command(&self, &cmd),
+            Program::Filename(ref path) => path.as_path().run_command(self, &cmd),
+            Program::FileDescriptor(fd) => fd.run_command(self, &cmd),
         }
     }
 
@@ -942,7 +985,9 @@ impl Minijail {
     /// # Safety
     /// See `fork`.
     pub unsafe fn fork_remap(&self, inheritable_fds: &[(RawFd, RawFd)]) -> Result<pid_t> {
-        if !is_single_threaded().map_err(Error::CheckingMultiThreaded)? {
+        if !self.disable_multithreaded_check
+            && !is_single_threaded().map_err(Error::CheckingMultiThreaded)?
+        {
             // This test will fail during `cargo test` because the test harness always spawns a test
             // thread. We will make an exception for that case because the tests for this module
             // should always be run in a serial fashion using `--test-threads=1`.
@@ -1018,18 +1063,27 @@ impl Drop for Minijail {
     }
 }
 
-// Count the number of files in the directory specified by `path`.
-fn count_dir_entries<P: AsRef<Path>>(path: P) -> io::Result<usize> {
-    Ok(fs::read_dir(path)?.count())
+// Check if a `/proc/*/task/*` is a kthread.
+fn task_is_kthread(path: &Path) -> io::Result<bool> {
+    let status = fs::read_to_string(path.join("status"))?;
+    Ok(status.contains("\nKthread:\t1\n"))
+}
+
+// Count the number of threads in the current process.
+fn num_threads() -> io::Result<usize> {
+    let mut count = 0;
+    for entry in fs::read_dir("/proc/self/task")? {
+        let entry = entry?;
+        if !task_is_kthread(&entry.path())? {
+            count += 1;
+        }
+    }
+    Ok(count)
 }
 
 // Return true if the current thread is the only thread in the process.
 fn is_single_threaded() -> io::Result<bool> {
-    match count_dir_entries("/proc/self/task") {
-        Ok(1) => Ok(true),
-        Ok(_) => Ok(false),
-        Err(e) => Err(e),
-    }
+    Ok(num_threads()? == 1)
 }
 
 fn to_execve_cstring_array<S: AsRef<str>>(
@@ -1052,6 +1106,20 @@ fn to_execve_cstring_array<S: AsRef<str>>(
     Ok((vec_cstr, vec_cptr))
 }
 
+static LOGGING_INIT_LOCK: Once = Once::new();
+
+pub fn init_default_logging() {
+    LOGGING_INIT_LOCK.call_once(|| {
+        log_to_fd(libc::STDERR_FILENO, 6 /* SYSLOG_LOG_INFO */)
+    })
+}
+
+fn log_to_fd(fd: RawFd, priority: c_int) {
+    unsafe {
+        minijail_log_to_fd(fd, priority);
+    }
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -1082,6 +1150,8 @@ mod tests {
 
     #[test]
     fn create_and_free() {
+        init_default_logging();
+
         unsafe {
             let j = minijail_new();
             assert_ne!(std::ptr::null_mut(), j);
@@ -1096,16 +1166,20 @@ mod tests {
     // Test that setting a seccomp filter with no-new-privs works as non-root.
     // This is equivalent to minijail0 -n -S <seccomp_policy>
     fn seccomp_no_new_privs() {
+        init_default_logging();
+
         let mut j = Minijail::new().unwrap();
         j.no_new_privs();
         j.parse_seccomp_filters("src/test_filter.policy").unwrap();
         j.use_seccomp_filter();
-        j.run("/bin/true", &[], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
     }
 
     #[test]
     // Test that open FDs get closed and that FDs in the inherit list are left open.
     fn close_fds() {
+        init_default_logging();
+
         unsafe {
             // Using libc to open/close FDs for testing.
             const FILE_PATH: &[u8] = b"/dev/null\0";
@@ -1151,13 +1225,17 @@ fi
 
     #[test]
     fn wait_success() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
-        j.run("/bin/true", &[1, 2], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
         expect_result!(j.wait(), Ok(()));
     }
 
     #[test]
     fn wait_killed() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
         j.run(
             SHELL,
@@ -1170,22 +1248,28 @@ fi
 
     #[test]
     fn wait_returncode() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
-        j.run("/bin/false", &[1, 2], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/false", &[1, 2], EMPTY_STRING_SLICE).unwrap();
         expect_result!(j.wait(), Err(Error::ReturnCode(1)));
     }
 
     #[test]
     fn wait_noaccess() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
-        j.run("/dev/null", &[1, 2], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/dev/null", &[1, 2], EMPTY_STRING_SLICE).unwrap();
         expect_result!(j.wait(), Err(Error::NoAccess));
     }
 
     #[test]
     fn wait_nocommand() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
-        j.run("/bin/does not exist", &[1, 2], &EMPTY_STRING_SLICE)
+        j.run("/bin/does not exist", &[1, 2], EMPTY_STRING_SLICE)
             .unwrap();
         // TODO(b/194221986) Fix libminijail so that Error::NoAccess is not sometimes returned.
         assert!(matches!(
@@ -1195,18 +1279,23 @@ fi
     }
 
     #[test]
+    #[ignore] // TODO(b/323475944) Fix unit test failures.
     fn runnable_fd_success() {
+        init_default_logging();
+
         let bin_file = File::open("/bin/true").unwrap();
         // On ChromeOS targets /bin/true is actually a script, so drop CLOEXEC to prevent ENOENT.
         clear_cloexec(&bin_file).unwrap();
 
         let j = Minijail::new().unwrap();
-        j.run_fd(&bin_file, &[1, 2], &EMPTY_STRING_SLICE).unwrap();
+        j.run_fd(&bin_file, &[1, 2], EMPTY_STRING_SLICE).unwrap();
         expect_result!(j.wait(), Ok(()));
     }
 
     #[test]
     fn kill_success() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
         j.run(
             Path::new("/usr/bin/sleep"),
@@ -1221,36 +1310,46 @@ fi
     #[test]
     #[ignore] // privileged operation.
     fn chroot() {
+        init_default_logging();
+
         let mut j = Minijail::new().unwrap();
         j.enter_chroot(".").unwrap();
-        j.run("/bin/true", &[], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
     }
 
     #[test]
     #[ignore] // privileged operation.
     fn namespace_vfs() {
+        init_default_logging();
+
         let mut j = Minijail::new().unwrap();
         j.namespace_vfs();
-        j.run("/bin/true", &[], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
     }
 
     #[test]
     fn run() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
-        j.run("/bin/true", &[], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
     }
 
     #[test]
     fn run_clone() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
         let b = j.try_clone().unwrap();
         // Pass the same FDs to both clones and make sure they don't conflict.
-        j.run("/bin/true", &[1, 2], &EMPTY_STRING_SLICE).unwrap();
-        b.run("/bin/true", &[1, 2], &EMPTY_STRING_SLICE).unwrap();
+        j.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
+        b.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
     }
 
     #[test]
     fn run_string_vec() {
+        init_default_logging();
+
         let j = Minijail::new().unwrap();
         let args = vec!["ignored".to_string()];
         j.run(Path::new("/bin/true"), &[], &args).unwrap();
diff --git a/scoped_minijail.h b/scoped_minijail.h
index 160cd50..c75abe8 100644
--- a/scoped_minijail.h
+++ b/scoped_minijail.h
@@ -10,23 +10,26 @@
 
 #include "libminijail.h"
 
-namespace mj {
+namespace mj
+{
 
-namespace internal {
+namespace internal
+{
 
 struct ScopedMinijailDeleter {
-    inline void operator()(minijail *j) const {
-        if (j) {
-            minijail_destroy(j);
-        }
-    }
+	inline void operator()(minijail *j) const
+	{
+		if (j) {
+			minijail_destroy(j);
+		}
+	}
 };
 
-}   // namespace internal
+} // namespace internal
 
-}   // namespace mj
+} // namespace mj
 
 using ScopedMinijail =
-        std::unique_ptr<minijail, mj::internal::ScopedMinijailDeleter>;
+    std::unique_ptr<minijail, mj::internal::ScopedMinijailDeleter>;
 
 #endif /* _SCOPED_MINIJAIL_H_ */
diff --git a/setup.py b/setup.py
old mode 100644
new mode 100755
index ab02ddf..ce9535d
--- a/setup.py
+++ b/setup.py
@@ -1,51 +1,42 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2020 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """A file that specifies how to install minijail's python-based tool(s)."""
 
 import os
-from setuptools import setup
+
+import setuptools
 
 
 this_directory = os.path.abspath(os.path.dirname(__file__))
-with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
+with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
     long_description = f.read()
 
-setup(name='minijail',
-      version='0.12',
-      description='A set of tools for Minijail',
-      classifiers=[
-          'Programming Language :: Python :: 3',
-          'License :: OSI Approved :: Apache Software License',
-          'Operating System :: Linux',
-      ],
-      python_requires='>=3.6',
-      license='Apache License 2.0',
-      long_description=long_description,
-      long_description_content_type='text/markdown',
-      author='Minijail Developers',
-      author_email='minijail-dev@google.com',
-      url='https://google.github.io/minijail/',
-      packages=['minijail'],
-      package_dir={'minijail': 'tools'},
-      entry_points={
-          'console_scripts': [
-              'compile_seccomp_policy = minijail.compile_seccomp_policy:main',
-              'generate_seccomp_policy = minijail.generate_seccomp_policy:main',
-              'generate_constants_json = minijail.generate_constants_json:main',
-          ],
-      },
+setuptools.setup(
+    name="minijail",
+    version="18",
+    description="A set of tools for Minijail",
+    classifiers=[
+        "Programming Language :: Python :: 3",
+        "License :: OSI Approved :: BSD License",
+        "Operating System :: Linux",
+    ],
+    python_requires=">=3.8",
+    license="3-clause BSD",
+    long_description=long_description,
+    long_description_content_type="text/markdown",
+    author="Minijail Developers",
+    author_email="minijail-dev@google.com",
+    url="https://google.github.io/minijail/",
+    packages=["minijail"],
+    package_dir={"minijail": "tools"},
+    entry_points={
+        "console_scripts": [
+            "compile_seccomp_policy = minijail.compile_seccomp_policy:main",
+            "generate_seccomp_policy = minijail.generate_seccomp_policy:main",
+            "generate_constants_json = minijail.generate_constants_json:main",
+        ],
+    },
 )
diff --git a/signal_handler.c b/signal_handler.c
index 77b32ca..41439bd 100644
--- a/signal_handler.c
+++ b/signal_handler.c
@@ -20,21 +20,21 @@ static int get_si_syscall(const siginfo_t *info)
 {
 #if defined(si_syscall)
 	return info->si_syscall;
-#endif
-
+#else
 	typedef struct {
-		void		*ip;
-		int		nr;
-		unsigned int	arch;
+		void *ip;
+		int nr;
+		unsigned int arch;
 	} local_siginfo_t;
 
 	union {
 		const siginfo_t *info;
 		const local_siginfo_t *local_info;
 	} local_info = {
-		.info = info,
+	    .info = info,
 	};
 	return local_info.local_info->nr;
+#endif
 }
 
 void log_sigsys_handler(int sig attribute_unused, siginfo_t *info,
diff --git a/syscall_filter.c b/syscall_filter.c
index c986f3c..cec8b6f 100644
--- a/syscall_filter.c
+++ b/syscall_filter.c
@@ -194,14 +194,16 @@ bool insert_and_check_duplicate_syscall(struct parser_state **previous_syscalls,
 	return false;
 }
 
-void allow_logging_syscalls(struct filter_block *head)
+static void allow_selected_syscalls(struct filter_block *head,
+				    const char *const *allowlist,
+				    size_t allowlist_len, bool log_additions)
 {
 	unsigned int i;
 
-	for (i = 0; i < log_syscalls_len; i++) {
-		warn("allowing syscall: %s", log_syscalls[i]);
-		append_allow_syscall(head,
-				     lookup_syscall(log_syscalls[i], NULL));
+	for (i = 0; i < allowlist_len; i++) {
+		if (log_additions)
+			warn("allowing syscall: %s", allowlist[i]);
+		append_allow_syscall(head, lookup_syscall(allowlist[i], NULL));
 	}
 }
 
@@ -796,7 +798,13 @@ int compile_filter(const char *filename, FILE *initial_file,
 	 * some syscalls need to be unconditionally allowed.
 	 */
 	if (filteropts->allow_syscalls_for_logging)
-		allow_logging_syscalls(head);
+		allow_selected_syscalls(head, log_syscalls, log_syscalls_len,
+					true /* log_additions */);
+
+	if (filteropts->include_libc_compatibility_allowlist)
+		allow_selected_syscalls(head, libc_compatibility_syscalls,
+					libc_compatibility_syscalls_len,
+					false /* log_additions */);
 
 	if (compile_file(filename, initial_file, head, &arg_blocks, &labels,
 			 filteropts, previous_syscalls,
diff --git a/syscall_filter.h b/syscall_filter.h
index dac5c2e..2847497 100644
--- a/syscall_filter.h
+++ b/syscall_filter.h
@@ -43,6 +43,7 @@ struct filter_options {
 	int allow_logging;
 	int allow_syscalls_for_logging;
 	bool allow_duplicate_syscalls;
+	bool include_libc_compatibility_allowlist;
 };
 
 struct bpf_labels;
@@ -79,6 +80,14 @@ static inline bool allow_duplicate_syscalls(void)
 	return false;
 }
 
+static inline bool allow_libc_compatibility_syscalls(void)
+{
+#if defined(ALLOW_LIBC_COMPATIBILITY_SYSCALLS)
+	return true;
+#endif
+	return false;
+}
+
 #ifdef __cplusplus
 }; /* extern "C" */
 #endif
diff --git a/syscall_filter_unittest.cc b/syscall_filter_unittest.cc
index c202b02..5e23fab 100644
--- a/syscall_filter_unittest.cc
+++ b/syscall_filter_unittest.cc
@@ -10,6 +10,7 @@
 #include <fcntl.h> /* For O_WRONLY. */
 
 #include <gtest/gtest.h>
+#include <span>
 #include <string>
 
 #include "bpf.h"
@@ -28,50 +29,48 @@ enum ret_trap {
 };
 
 enum use_logging {
-  NO_LOGGING          = 0,
-  USE_SIGSYS_LOGGING  = 1,
+  NO_LOGGING = 0,
+  USE_SIGSYS_LOGGING = 1,
   USE_RET_LOG_LOGGING = 2,
 };
 
-int test_compile_filter(
-    const std::string& filename,
-    FILE* policy_file,
-    struct sock_fprog* prog,
-    enum block_action action = ACTION_RET_KILL,
-    enum use_logging allow_logging = NO_LOGGING,
-    bool allow_dup_syscalls = true) {
+int test_compile_filter(const std::string& filename,
+                        FILE* policy_file,
+                        struct sock_fprog* prog,
+                        enum block_action action = ACTION_RET_KILL,
+                        enum use_logging allow_logging = NO_LOGGING,
+                        bool allow_dup_syscalls = true,
+                        bool include_libc_compatibility_allowlist = false) {
   struct filter_options filteropts {
-    .action = action,
-    .allow_logging = allow_logging != NO_LOGGING,
+    .action = action, .allow_logging = allow_logging != NO_LOGGING,
     .allow_syscalls_for_logging = allow_logging == USE_SIGSYS_LOGGING,
     .allow_duplicate_syscalls = allow_dup_syscalls,
+    .include_libc_compatibility_allowlist =
+        include_libc_compatibility_allowlist,
   };
   return compile_filter(filename.c_str(), policy_file, prog, &filteropts);
 }
 
-int test_compile_file(
-    std::string filename,
-    FILE* policy_file,
-    struct filter_block* head,
-    struct filter_block** arg_blocks,
-    struct bpf_labels* labels,
-    enum block_action action = ACTION_RET_KILL,
-    enum use_logging allow_logging = NO_LOGGING,
-    unsigned int include_level = 0,
-    bool allow_dup_syscalls = false) {
+int test_compile_file(std::string filename,
+                      FILE* policy_file,
+                      struct filter_block* head,
+                      struct filter_block** arg_blocks,
+                      struct bpf_labels* labels,
+                      enum block_action action = ACTION_RET_KILL,
+                      enum use_logging allow_logging = NO_LOGGING,
+                      unsigned int include_level = 0,
+                      bool allow_dup_syscalls = false) {
   struct filter_options filteropts {
-    .action = action,
-    .allow_logging = allow_logging != NO_LOGGING,
+    .action = action, .allow_logging = allow_logging != NO_LOGGING,
     .allow_syscalls_for_logging = allow_logging == USE_SIGSYS_LOGGING,
     .allow_duplicate_syscalls = allow_dup_syscalls,
+    .include_libc_compatibility_allowlist = false,
   };
   size_t num_syscalls = get_num_syscalls();
-  struct parser_state **previous_syscalls =
-      (struct parser_state **)calloc(num_syscalls,
-                                     sizeof(struct parser_state *));
+  struct parser_state** previous_syscalls =
+      (struct parser_state**)calloc(num_syscalls, sizeof(struct parser_state*));
   int res = compile_file(filename.c_str(), policy_file, head, arg_blocks,
-                         labels, &filteropts, previous_syscalls,
-                         include_level);
+                         labels, &filteropts, previous_syscalls, include_level);
   free_previous_syscalls(previous_syscalls);
   return res;
 }
@@ -83,10 +82,14 @@ struct filter_block* test_compile_policy_line(
     unsigned int label_id,
     struct bpf_labels* labels,
     enum block_action action = ACTION_RET_KILL) {
-  return compile_policy_line(state, nr, policy_line.c_str(), label_id,
-           labels, action);
+  return compile_policy_line(state, nr, policy_line.c_str(), label_id, labels,
+                             action);
 }
 
+std::span<const char *const> get_libc_compatibility_allowlist() {
+  return std::span(libc_compatibility_syscalls,
+                   libc_compatibility_syscalls_len);
+}
 }  // namespace
 
 /* Test that setting one BPF instruction works. */
@@ -151,8 +154,8 @@ TEST(bpf, bpf_comp_jset) {
 #if defined(BITS32)
   EXPECT_EQ_BLOCK(&comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, mask, jt, jf);
 #elif defined(BITS64)
-  EXPECT_EQ_BLOCK(
-      &comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, 0x80000000, jt + 2, 0);
+  EXPECT_EQ_BLOCK(&comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, 0x80000000, jt + 2,
+                  0);
   EXPECT_EQ_STMT(&comp_jset[1], BPF_LD + BPF_MEM, 0);
   EXPECT_EQ_BLOCK(&comp_jset[2], BPF_JMP + BPF_JSET + BPF_K, O_WRONLY, jt, jf);
 #endif
@@ -171,15 +174,15 @@ TEST(bpf, bpf_comp_jin) {
 #if defined(BITS32)
   EXPECT_EQ_BLOCK(&comp_jin[0], BPF_JMP + BPF_JSET + BPF_K, ~mask, jf, jt);
 #elif defined(BITS64)
-  EXPECT_EQ_BLOCK(
-      &comp_jin[0], BPF_JMP + BPF_JSET + BPF_K, 0x7FFFFFFF, jf + 2, 0);
+  EXPECT_EQ_BLOCK(&comp_jin[0], BPF_JMP + BPF_JSET + BPF_K, 0x7FFFFFFF, jf + 2,
+                  0);
   EXPECT_EQ_STMT(&comp_jin[1], BPF_LD + BPF_MEM, 0);
   EXPECT_EQ_BLOCK(&comp_jin[2], BPF_JMP + BPF_JSET + BPF_K, ~O_WRONLY, jf, jt);
 #endif
 }
 
 TEST(bpf, bpf_arg_comp) {
-  struct sock_filter *arg_comp;
+  struct sock_filter* arg_comp;
   int op = EQ;
   const int argidx = 1;
   unsigned long c = 3;
@@ -207,6 +210,19 @@ TEST(bpf, bpf_arg_comp) {
   free(arg_comp);
 }
 
+TEST(bpf, bpf_arg_comp_invalid) {
+  struct sock_filter* arg_comp;
+  int op = MIN_OPERATOR + 32;
+  const int argidx = 1;
+  unsigned long c = 3;
+  unsigned int label_id = 0;
+
+  size_t len = bpf_arg_comp(&arg_comp, op, argidx, c, label_id);
+
+  EXPECT_EQ(len, 0);
+  free(arg_comp);
+}
+
 TEST(bpf, bpf_validate_arch) {
   struct sock_filter validate_arch[ARCH_VALIDATION_LEN];
 
@@ -323,7 +339,7 @@ TEST_F(BpfLabelTest, too_many_labels) {
 
   for (i = 0; i < BPF_LABELS_MAX; i++) {
     snprintf(label, 20, "test%u", i);
-    (void) bpf_label_id(&labels_, label);
+    (void)bpf_label_id(&labels_, label);
   }
   int id = bpf_label_id(&labels_, "test");
 
@@ -390,7 +406,7 @@ TEST_F(ArgFilterTest, arg0_equals) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -595,7 +611,7 @@ TEST_F(ArgFilterTest, arg0_mask) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -635,7 +651,7 @@ TEST_F(ArgFilterTest, arg0_flag_set_inclusion) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -676,7 +692,7 @@ TEST_F(ArgFilterTest, arg0_eq_mask) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -718,7 +734,7 @@ TEST_F(ArgFilterTest, and_or) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -773,7 +789,7 @@ TEST_F(ArgFilterTest, ret_errno) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -802,8 +818,7 @@ TEST_F(ArgFilterTest, ret_errno) {
   curr_block = curr_block->next;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
-  EXPECT_EQ_STMT(curr_block->instrs,
-                 BPF_RET + BPF_K,
+  EXPECT_EQ_STMT(curr_block->instrs, BPF_RET + BPF_K,
                  SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));
 
   /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
@@ -826,7 +841,7 @@ TEST_F(ArgFilterTest, unconditional_errno) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -835,8 +850,7 @@ TEST_F(ArgFilterTest, unconditional_errno) {
   curr_block = curr_block->next;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
-  EXPECT_EQ_STMT(curr_block->instrs,
-                 BPF_RET + BPF_K,
+  EXPECT_EQ_STMT(curr_block->instrs, BPF_RET + BPF_K,
                  SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));
 
   EXPECT_EQ(curr_block->next, nullptr);
@@ -903,16 +917,15 @@ TEST_F(ArgFilterTest, invalid_errno) {
 TEST_F(ArgFilterTest, log_no_ret_error) {
   std::string fragment = "arg0 == 0";
 
-  struct filter_block* block =
-      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_,
-                               ACTION_RET_TRAP);
+  struct filter_block* block = test_compile_policy_line(
+      &state_, nr_, fragment, id_, &labels_, ACTION_RET_TRAP);
 
   ASSERT_NE(block, nullptr);
   size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -952,7 +965,7 @@ TEST_F(ArgFilterTest, log_bad_ret_error) {
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -987,15 +1000,14 @@ TEST_F(ArgFilterTest, log_bad_ret_error) {
 TEST_F(ArgFilterTest, no_log_bad_ret_error) {
   std::string fragment = "arg0 == 0; return";
 
-  struct filter_block* block =
-      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_,
-                               ACTION_RET_TRAP);
+  struct filter_block* block = test_compile_policy_line(
+      &state_, nr_, fragment, id_, &labels_, ACTION_RET_TRAP);
   ASSERT_NE(block, nullptr);
   size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
   EXPECT_EQ(block->total_len, exp_total_len);
 
   /* First block is a label. */
-  struct filter_block *curr_block = block;
+  struct filter_block* curr_block = block;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_EQ(curr_block->len, 1U);
   EXPECT_LBL(curr_block->instrs);
@@ -1043,20 +1055,19 @@ class FileTest : public ::testing::Test {
     free_block_list(arg_blocks_);
   }
   struct bpf_labels labels_;
-  struct filter_block *head_;
-  struct filter_block *arg_blocks_;
+  struct filter_block* head_;
+  struct filter_block* arg_blocks_;
 };
 
 }  // namespace
 
 TEST_F(FileTest, malformed_policy) {
-  std::string policy =
-      "malformed";
+  std::string policy = "malformed";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
@@ -1072,8 +1083,8 @@ TEST_F(FileTest, double_free_on_compile_error) {
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
@@ -1083,13 +1094,12 @@ TEST_F(FileTest, double_free_on_compile_error) {
 }
 
 TEST_F(FileTest, invalid_return) {
-  std::string policy =
-      "read:arg0 == 0; ;";
+  std::string policy = "read:arg0 == 0; ;";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
@@ -1098,6 +1108,81 @@ TEST_F(FileTest, invalid_return) {
   ASSERT_EQ(res, -1);
 }
 
+TEST_F(FileTest, seccomp_global_allowlist) {
+  std::string policy = "";
+  FILE *policy_file = write_to_pipe(policy);
+  ASSERT_NE(policy_file, nullptr);
+
+  struct sock_fprog actual;
+  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_KILL,
+        NO_LOGGING, false /* allow_dup_syscalls */,
+        true /* include_libc_compatibility_allowlist */);
+  fclose(policy_file);
+
+  ASSERT_EQ(res, 0);
+  std::span<const char *const> allowlist = get_libc_compatibility_allowlist();
+  size_t offset_after_allowlist =
+    ARCH_VALIDATION_LEN + 1 + 2 * allowlist.size();
+  EXPECT_EQ(actual.len, offset_after_allowlist + 1);
+  EXPECT_ARCH_VALIDATION(actual.filter);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
+                 BPF_LD + BPF_W + BPF_ABS, syscall_nr);
+  for (size_t i = 0; i < allowlist.size(); ++i) {
+    int allowlist_entry_nr = lookup_syscall(allowlist[i], nullptr);
+    EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1 + 2 * i,
+                         allowlist_entry_nr);
+  }
+  EXPECT_EQ_STMT(actual.filter + offset_after_allowlist, BPF_RET + BPF_K,
+                 SECCOMP_RET_KILL);
+
+  free(actual.filter);
+}
+
+TEST_F(FileTest, seccomp_global_allowlist_does_not_conflict) {
+  std::string policy;
+  for (const char *entry : get_libc_compatibility_allowlist()) {
+    policy += entry;
+    policy += ": 1\n";
+  }
+
+  FILE* policy_file = write_to_pipe(policy);
+  ASSERT_NE(policy_file, nullptr);
+
+  struct sock_fprog actual;
+  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_KILL,
+        NO_LOGGING, false /* allow_dup_syscalls */,
+        true /* include_libc_compatibility_allowlist */);
+  fclose(policy_file);
+
+  ASSERT_EQ(res, 0);
+  std::span<const char *const> allowlist = get_libc_compatibility_allowlist();
+
+  /* NOTE: due to how the global allowlist is added, this results in duplicate
+   * allowlist entries in `actual` when both the global allowlist & the given
+   * policy share a syscall. This is suboptimal, but the existence of global
+   * allowlist entries is highly discouraged & the list should remain empty most
+   * of the time. When it does contain entries, it should generally contain
+   * fewer than five.
+   */
+  size_t offset_after_allowlist =
+      ARCH_VALIDATION_LEN + 1 + 4 * allowlist.size();
+  EXPECT_EQ(actual.len, offset_after_allowlist + 1);
+  EXPECT_ARCH_VALIDATION(actual.filter);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
+                 syscall_nr);
+  for (size_t i = 0; i < allowlist.size() * 2; ++i) {
+    int allowlist_entry_nr = lookup_syscall(allowlist[i % allowlist.size()],
+                                            nullptr);
+    EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1 + 2 * i,
+                         allowlist_entry_nr);
+  }
+  EXPECT_EQ_STMT(actual.filter + offset_after_allowlist, BPF_RET + BPF_K,
+                 SECCOMP_RET_KILL);
+
+  free(actual.filter);
+}
+
+
 TEST_F(FileTest, seccomp_mode1) {
   std::string policy =
       "read: 1\n"
@@ -1107,15 +1192,15 @@ TEST_F(FileTest, seccomp_mode1) {
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
    * Checks return value and that the blocks only allow expected syscalls.
    */
   ASSERT_EQ(res, 0);
-  struct filter_block *curr_block = head_;
+  struct filter_block* curr_block = head_;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_read);
   curr_block = curr_block->next;
@@ -1142,8 +1227,8 @@ TEST_F(FileTest, seccomp_read) {
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
@@ -1151,12 +1236,9 @@ TEST_F(FileTest, seccomp_read) {
    * labels between |head_| and |arg_blocks_| match.
    */
   ASSERT_EQ(res, 0);
-  struct filter_block *curr_block = head_;
+  struct filter_block* curr_block = head_;
   ASSERT_NE(curr_block, nullptr);
-  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs,
-                            __NR_read,
-                            LABEL_ID,
-                            JUMP_JT,
+  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs, __NR_read, LABEL_ID, JUMP_JT,
                             JUMP_JF);
   curr_block = curr_block->next;
   ASSERT_NE(curr_block, nullptr);
@@ -1209,8 +1291,8 @@ TEST_F(FileTest, multiline) {
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
-  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
-                              &labels_);
+  int res =
+      test_compile_file("policy", policy_file, head_, &arg_blocks_, &labels_);
   fclose(policy_file);
 
   /*
@@ -1219,17 +1301,14 @@ TEST_F(FileTest, multiline) {
   ASSERT_EQ(res, 0);
 
   /* First block is the read. */
-  struct filter_block *curr_block = head_;
+  struct filter_block* curr_block = head_;
   ASSERT_NE(curr_block, nullptr);
   EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_read);
 
   /* Second block is the open. */
   curr_block = curr_block->next;
   ASSERT_NE(curr_block, nullptr);
-  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs,
-                            __NR_openat,
-                            LABEL_ID,
-                            JUMP_JT,
+  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs, __NR_openat, LABEL_ID, JUMP_JT,
                             JUMP_JF);
 
   EXPECT_EQ(curr_block->next, nullptr);
@@ -1257,16 +1336,14 @@ TEST(FilterTest, seccomp_mode1) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-                 BPF_LD + BPF_W + BPF_ABS,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
                  syscall_nr);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
                        __NR_rt_sigreturn);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9,
-                 BPF_RET + BPF_K,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
                  SECCOMP_RET_KILL);
 
   free(actual.filter);
@@ -1283,9 +1360,9 @@ TEST(FilterTest, seccomp_mode1_with_check) {
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
 
-  int res = test_compile_filter("policy", policy_file, &actual,
-                                ACTION_RET_KILL, NO_LOGGING, false
-                                /* allow duplicate syscalls */);
+  int res = test_compile_filter(
+      "policy", policy_file, &actual, ACTION_RET_KILL, NO_LOGGING, false
+      /* allow duplicate syscalls */);
   fclose(policy_file);
 
   /*
@@ -1296,16 +1373,14 @@ TEST(FilterTest, seccomp_mode1_with_check) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-                 BPF_LD + BPF_W + BPF_ABS,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
                  syscall_nr);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
                        __NR_rt_sigreturn);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9,
-                 BPF_RET + BPF_K,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
                  SECCOMP_RET_KILL);
 
   free(actual.filter);
@@ -1359,10 +1434,10 @@ TEST(FilterTest, duplicate_read_with_one_arg) {
 TEST(FilterTest, seccomp_mode1_trap) {
   struct sock_fprog actual;
   std::string policy =
-    "read: 1\n"
-    "write: 1\n"
-    "rt_sigreturn: 1\n"
-    "exit: 1\n";
+      "read: 1\n"
+      "write: 1\n"
+      "rt_sigreturn: 1\n"
+      "exit: 1\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1379,18 +1454,15 @@ TEST(FilterTest, seccomp_mode1_trap) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-      BPF_LD+BPF_W+BPF_ABS, syscall_nr);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1,
-      __NR_read);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3,
-      __NR_write);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
+                 syscall_nr);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
-      __NR_rt_sigreturn);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7,
-      __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET+BPF_K,
-      SECCOMP_RET_TRAP);
+                       __NR_rt_sigreturn);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
+                 SECCOMP_RET_TRAP);
 
   free(actual.filter);
 }
@@ -1398,10 +1470,10 @@ TEST(FilterTest, seccomp_mode1_trap) {
 TEST(FilterTest, seccomp_mode1_log) {
   struct sock_fprog actual;
   std::string policy =
-    "read: 1\n"
-    "write: 1\n"
-    "rt_sigreturn: 1\n"
-    "exit: 1\n";
+      "read: 1\n"
+      "write: 1\n"
+      "rt_sigreturn: 1\n"
+      "exit: 1\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1418,18 +1490,15 @@ TEST(FilterTest, seccomp_mode1_log) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-      BPF_LD+BPF_W+BPF_ABS, syscall_nr);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1,
-      __NR_read);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3,
-      __NR_write);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
+                 syscall_nr);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
-      __NR_rt_sigreturn);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7,
-      __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET+BPF_K,
-      SECCOMP_RET_LOG);
+                       __NR_rt_sigreturn);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
+                 SECCOMP_RET_LOG);
 
   free(actual.filter);
 }
@@ -1437,10 +1506,10 @@ TEST(FilterTest, seccomp_mode1_log) {
 TEST(FilterTest, seccomp_mode1_log_fails) {
   struct sock_fprog actual;
   std::string policy =
-    "read: 1\n"
-    "write: 1\n"
-    "rt_sigreturn: 1\n"
-    "exit: 1\n";
+      "read: 1\n"
+      "write: 1\n"
+      "rt_sigreturn: 1\n"
+      "exit: 1\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1458,16 +1527,16 @@ TEST(FilterTest, seccomp_mode1_log_fails) {
 TEST(FilterTest, seccomp_mode1_ret_kill_process) {
   struct sock_fprog actual;
   std::string policy =
-    "read: 1\n"
-    "write: 1\n"
-    "rt_sigreturn: 1\n"
-    "exit: 1\n";
+      "read: 1\n"
+      "write: 1\n"
+      "rt_sigreturn: 1\n"
+      "exit: 1\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
 
-  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_KILL_PROCESS,
-                                NO_LOGGING);
+  int res = test_compile_filter("policy", policy_file, &actual,
+                                ACTION_RET_KILL_PROCESS, NO_LOGGING);
   fclose(policy_file);
 
   /*
@@ -1478,18 +1547,15 @@ TEST(FilterTest, seccomp_mode1_ret_kill_process) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-      BPF_LD+BPF_W+BPF_ABS, syscall_nr);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1,
-      __NR_read);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3,
-      __NR_write);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
+                 syscall_nr);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
-      __NR_rt_sigreturn);
-  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7,
-      __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET+BPF_K,
-      SECCOMP_RET_KILL_PROCESS);
+                       __NR_rt_sigreturn);
+  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
+                 SECCOMP_RET_KILL_PROCESS);
 
   free(actual.filter);
 }
@@ -1519,21 +1585,16 @@ TEST(FilterTest, seccomp_read_write) {
   EXPECT_EQ(actual.len, exp_total_len);
 
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-                 BPF_LD + BPF_W + BPF_ABS,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
                  syscall_nr);
-  EXPECT_ALLOW_SYSCALL_ARGS(
-      actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read, 7, 0, 0);
-  EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 3,
-                            __NR_write,
-                            12 + BPF_ARG_COMP_LEN,
-                            0,
-                            0);
+  EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read,
+                            7, 0, 0);
+  EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write,
+                            12 + BPF_ARG_COMP_LEN, 0, 0);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
                        __NR_rt_sigreturn);
   EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9,
-                 BPF_RET + BPF_K,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET + BPF_K,
                  SECCOMP_RET_KILL);
 
   free(actual.filter);
@@ -1551,9 +1612,8 @@ TEST(FilterTest, misplaced_whitespace) {
 
   /* Checks return value and filter length. */
   ASSERT_EQ(res, 0);
-  EXPECT_EQ(actual.len,
-            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ + ALLOW_SYSCALL_LEN +
-                1 /* ret kill */);
+  EXPECT_EQ(actual.len, ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
+                            ALLOW_SYSCALL_LEN + 1 /* ret kill */);
   free(actual.filter);
 }
 
@@ -1650,8 +1710,7 @@ TEST(FilterTest, log) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13 + 2 * log_syscalls_len);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-                 BPF_LD + BPF_W + BPF_ABS,
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
                  syscall_nr);
 
   index = ARCH_VALIDATION_LEN + 1;
@@ -1673,10 +1732,10 @@ TEST(FilterTest, log) {
 TEST(FilterTest, allow_log_but_kill) {
   struct sock_fprog actual;
   std::string policy =
-    "read: 1\n"
-    "write: 1\n"
-    "rt_sigreturn: 1\n"
-    "exit: 1\n";
+      "read: 1\n"
+      "write: 1\n"
+      "rt_sigreturn: 1\n"
+      "exit: 1\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1697,8 +1756,8 @@ TEST(FilterTest, allow_log_but_kill) {
   ASSERT_EQ(res, 0);
   EXPECT_EQ(actual.len, 13 + 2 * log_syscalls_len);
   EXPECT_ARCH_VALIDATION(actual.filter);
-  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
-      BPF_LD+BPF_W+BPF_ABS, syscall_nr);
+  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN, BPF_LD + BPF_W + BPF_ABS,
+                 syscall_nr);
 
   index = ARCH_VALIDATION_LEN + 1;
   for (i = 0; i < log_syscalls_len; i++)
@@ -1711,8 +1770,7 @@ TEST(FilterTest, allow_log_but_kill) {
   EXPECT_ALLOW_SYSCALL(actual.filter + index + 2, __NR_write);
   EXPECT_ALLOW_SYSCALL(actual.filter + index + 4, __NR_rt_sigreturn);
   EXPECT_ALLOW_SYSCALL(actual.filter + index + 6, __NR_exit);
-  EXPECT_EQ_STMT(actual.filter + index + 8, BPF_RET+BPF_K,
-      SECCOMP_RET_KILL);
+  EXPECT_EQ_STMT(actual.filter + index + 8, BPF_RET + BPF_K, SECCOMP_RET_KILL);
 
   free(actual.filter);
 }
@@ -1874,8 +1932,7 @@ TEST(FilterTest, include) {
 
   EXPECT_ARCH_VALIDATION(compiled_with_include.filter);
   EXPECT_EQ_STMT(compiled_with_include.filter + ARCH_VALIDATION_LEN,
-                 BPF_LD + BPF_W + BPF_ABS,
-                 syscall_nr);
+                 BPF_LD + BPF_W + BPF_ABS, syscall_nr);
   EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 1,
                        __NR_read);
   EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 3,
@@ -1885,8 +1942,7 @@ TEST(FilterTest, include) {
   EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 7,
                        __NR_exit);
   EXPECT_EQ_STMT(compiled_with_include.filter + ARCH_VALIDATION_LEN + 9,
-                 BPF_RET + BPF_K,
-                 SECCOMP_RET_KILL);
+                 BPF_RET + BPF_K, SECCOMP_RET_KILL);
 
   free(compiled_plain.filter);
   free(compiled_with_include.filter);
@@ -1899,7 +1955,8 @@ TEST(FilterTest, include_same_syscalls) {
       "write: 1\n"
       "rt_sigreturn: 1\n"
       "exit: 1\n"
-      "@include " + source_path("test/seccomp.policy") + "\n";
+      "@include " +
+      source_path("test/seccomp.policy") + "\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1908,9 +1965,9 @@ TEST(FilterTest, include_same_syscalls) {
   fclose(policy_file);
 
   ASSERT_EQ(res, 0);
-  EXPECT_EQ(actual.len,
-            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
-                2 * 8 /* check syscalls twice */ + 1 /* filter return */);
+  EXPECT_EQ(actual.len, ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
+                            2 * 8 /* check syscalls twice */ +
+                            1 /* filter return */);
   free(actual.filter);
 }
 
@@ -1921,14 +1978,15 @@ TEST(FilterTest, include_same_syscalls_with_check) {
       "write: 1\n"
       "rt_sigreturn: 1\n"
       "exit: 1\n"
-      "@include " + source_path("test/seccomp.policy") + "\n";
+      "@include " +
+      source_path("test/seccomp.policy") + "\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
 
-  int res = test_compile_filter("policy", policy_file, &actual,
-                                ACTION_RET_KILL, NO_LOGGING, false
-                                /* allow duplicate syscalls */);
+  int res = test_compile_filter(
+      "policy", policy_file, &actual, ACTION_RET_KILL, NO_LOGGING, false
+      /* allow duplicate syscalls */);
   fclose(policy_file);
 
   ASSERT_EQ(res, -1);
@@ -1936,9 +1994,8 @@ TEST(FilterTest, include_same_syscalls_with_check) {
 
 TEST(FilterTest, include_two) {
   struct sock_fprog actual;
-  std::string policy =
-      "@include " + source_path("test/seccomp.policy") + "\n" +
-      "@include " + source_path("test/seccomp.policy") + "\n";
+  std::string policy = "@include " + source_path("test/seccomp.policy") + "\n" +
+                       "@include " + source_path("test/seccomp.policy") + "\n";
 
   FILE* policy_file = write_to_pipe(policy);
   ASSERT_NE(policy_file, nullptr);
@@ -1947,9 +2004,9 @@ TEST(FilterTest, include_two) {
   fclose(policy_file);
 
   ASSERT_EQ(res, 0);
-  EXPECT_EQ(actual.len,
-            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
-                2 * 8 /* check syscalls twice */ + 1 /* filter return */);
+  EXPECT_EQ(actual.len, ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
+                            2 * 8 /* check syscalls twice */ +
+                            1 /* filter return */);
   free(actual.filter);
 }
 
@@ -1966,8 +2023,8 @@ TEST(FilterTest, include_invalid_policy) {
   ASSERT_NE(policy_file, nullptr);
 
   /* Ensure the included (invalid) policy file exists. */
-  FILE* included_file = fopen(
-      source_path("test/invalid_syscall_name.policy").c_str(), "re");
+  FILE* included_file =
+      fopen(source_path("test/invalid_syscall_name.policy").c_str(), "re");
   ASSERT_NE(included_file, nullptr);
   fclose(included_file);
 
diff --git a/syscall_filter_unittest_macros.h b/syscall_filter_unittest_macros.h
index 3848541..a160263 100644
--- a/syscall_filter_unittest_macros.h
+++ b/syscall_filter_unittest_macros.h
@@ -9,92 +9,92 @@
 #include "bpf.h"
 
 /* BPF testing macros. */
-#define EXPECT_EQ_BLOCK(_block, _code, _k, _jt, _jf)	\
-do {	\
-	EXPECT_EQ((_block)->code, _code);		\
-	EXPECT_EQ((_block)->k, (unsigned int)(_k));	\
-	EXPECT_EQ((_block)->jt, _jt);			\
-	EXPECT_EQ((_block)->jf, _jf);			\
-} while (0)
-
-#define EXPECT_EQ_STMT(_block, _code, _k) \
+#define EXPECT_EQ_BLOCK(_block, _code, _k, _jt, _jf)                           \
+	do {                                                                   \
+		EXPECT_EQ((_block)->code, _code);                              \
+		EXPECT_EQ((_block)->k, (unsigned int)(_k));                    \
+		EXPECT_EQ((_block)->jt, _jt);                                  \
+		EXPECT_EQ((_block)->jf, _jf);                                  \
+	} while (0)
+
+#define EXPECT_EQ_STMT(_block, _code, _k)                                      \
 	EXPECT_EQ_BLOCK(_block, _code, _k, 0, 0)
 
-#define EXPECT_COMP(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, BPF_ARG_COMP_LEN + 1);			\
-	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
-} while (0)
-
-#define EXPECT_GT_GE_COMP(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, BPF_ARG_GT_GE_COMP_LEN + 1);		\
-	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
-} while (0)
-
-#define EXPECT_SHORT_GT_GE_COMP(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, BPF_ARG_SHORT_GT_GE_COMP_LEN + 1);	\
-	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
-} while (0)
-
-#define EXPECT_LBL(_block) \
-do {	\
-	EXPECT_TRUE((_block)->code == (BPF_JMP+BPF_JA));	\
-	EXPECT_TRUE((_block)->jt == LABEL_JT);			\
-	EXPECT_TRUE((_block)->jf == LABEL_JF);			\
-} while (0)
-
-#define EXPECT_ACTUAL_LBL(_block, _id) \
-do {	\
-	EXPECT_TRUE((_block)->code == (BPF_JMP+BPF_JA));	\
-	EXPECT_TRUE((_block)->k == (_id));			\
-	EXPECT_TRUE((_block)->jt == LABEL_JT);			\
-	EXPECT_TRUE((_block)->jf == LABEL_JF);			\
-} while (0)
-
-#define EXPECT_JUMP_LBL(_block) \
-do {	\
-	EXPECT_EQ((_block)->code, BPF_JMP+BPF_JA);	\
-	EXPECT_EQ((_block)->jt, JUMP_JT);		\
-	EXPECT_EQ((_block)->jf, JUMP_JF);		\
-} while (0)
-
-#define EXPECT_GROUP_END(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, 2U);			\
-	EXPECT_JUMP_LBL(&(_block)->instrs[0]);		\
-	EXPECT_LBL(&(_block)->instrs[1]);		\
-} while (0)
-
-#define EXPECT_KILL(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, 1U);				\
-	EXPECT_EQ_STMT((_block)->instrs,			\
-			BPF_RET+BPF_K, SECCOMP_RET_KILL);	\
-} while (0)
-
-#define EXPECT_TRAP(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, 1U);				\
-	EXPECT_EQ_STMT((_block)->instrs,			\
-			BPF_RET+BPF_K, SECCOMP_RET_TRAP);	\
-} while (0)
-
-#define EXPECT_LOG(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, 1U);				\
-	EXPECT_EQ_STMT((_block)->instrs,			\
-			BPF_RET+BPF_K, SECCOMP_RET_LOG);	\
-} while (0)
-
-#define EXPECT_ALLOW(_block) \
-do {	\
-	EXPECT_EQ((_block)->len, 2U);				\
-	EXPECT_LBL(&(_block)->instrs[0]);			\
-	EXPECT_EQ_STMT(&(_block)->instrs[1],			\
-			BPF_RET+BPF_K, SECCOMP_RET_ALLOW);	\
-} while (0)
+#define EXPECT_COMP(_block)                                                    \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, BPF_ARG_COMP_LEN + 1);                \
+		EXPECT_EQ((_block)->instrs->code, BPF_LD + BPF_W + BPF_ABS);   \
+	} while (0)
+
+#define EXPECT_GT_GE_COMP(_block)                                              \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, BPF_ARG_GT_GE_COMP_LEN + 1);          \
+		EXPECT_EQ((_block)->instrs->code, BPF_LD + BPF_W + BPF_ABS);   \
+	} while (0)
+
+#define EXPECT_SHORT_GT_GE_COMP(_block)                                        \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, BPF_ARG_SHORT_GT_GE_COMP_LEN + 1);    \
+		EXPECT_EQ((_block)->instrs->code, BPF_LD + BPF_W + BPF_ABS);   \
+	} while (0)
+
+#define EXPECT_LBL(_block)                                                     \
+	do {                                                                   \
+		EXPECT_TRUE((_block)->code == (BPF_JMP + BPF_JA));             \
+		EXPECT_TRUE((_block)->jt == LABEL_JT);                         \
+		EXPECT_TRUE((_block)->jf == LABEL_JF);                         \
+	} while (0)
+
+#define EXPECT_ACTUAL_LBL(_block, _id)                                         \
+	do {                                                                   \
+		EXPECT_TRUE((_block)->code == (BPF_JMP + BPF_JA));             \
+		EXPECT_TRUE((_block)->k == (_id));                             \
+		EXPECT_TRUE((_block)->jt == LABEL_JT);                         \
+		EXPECT_TRUE((_block)->jf == LABEL_JF);                         \
+	} while (0)
+
+#define EXPECT_JUMP_LBL(_block)                                                \
+	do {                                                                   \
+		EXPECT_EQ((_block)->code, BPF_JMP + BPF_JA);                   \
+		EXPECT_EQ((_block)->jt, JUMP_JT);                              \
+		EXPECT_EQ((_block)->jf, JUMP_JF);                              \
+	} while (0)
+
+#define EXPECT_GROUP_END(_block)                                               \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, 2U);                                  \
+		EXPECT_JUMP_LBL(&(_block)->instrs[0]);                         \
+		EXPECT_LBL(&(_block)->instrs[1]);                              \
+	} while (0)
+
+#define EXPECT_KILL(_block)                                                    \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, 1U);                                  \
+		EXPECT_EQ_STMT((_block)->instrs, BPF_RET + BPF_K,              \
+			       SECCOMP_RET_KILL);                              \
+	} while (0)
+
+#define EXPECT_TRAP(_block)                                                    \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, 1U);                                  \
+		EXPECT_EQ_STMT((_block)->instrs, BPF_RET + BPF_K,              \
+			       SECCOMP_RET_TRAP);                              \
+	} while (0)
+
+#define EXPECT_LOG(_block)                                                     \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, 1U);                                  \
+		EXPECT_EQ_STMT((_block)->instrs, BPF_RET + BPF_K,              \
+			       SECCOMP_RET_LOG);                               \
+	} while (0)
+
+#define EXPECT_ALLOW(_block)                                                   \
+	do {                                                                   \
+		EXPECT_EQ((_block)->len, 2U);                                  \
+		EXPECT_LBL(&(_block)->instrs[0]);                              \
+		EXPECT_EQ_STMT(&(_block)->instrs[1], BPF_RET + BPF_K,          \
+			       SECCOMP_RET_ALLOW);                             \
+	} while (0)
 
 #define EXPECT_ARCH_VALIDATION(_filter)                                        \
 	do {                                                                   \
@@ -106,20 +106,20 @@ do {	\
 			       SECCOMP_RET_KILL);                              \
 	} while (0)
 
-#define EXPECT_ALLOW_SYSCALL(_filter, _nr) \
-do {	\
-	EXPECT_EQ_BLOCK(&(_filter)[0],					\
-			BPF_JMP+BPF_JEQ+BPF_K, (_nr), NEXT, SKIP);	\
-	EXPECT_EQ_STMT(&(_filter)[1],					\
-			BPF_RET+BPF_K, SECCOMP_RET_ALLOW);		\
-} while (0)
-
-#define EXPECT_ALLOW_SYSCALL_ARGS(_filter, _nr, _id, _jt, _jf) \
-do {	\
-	EXPECT_EQ_BLOCK(&(_filter)[0],					\
-			BPF_JMP+BPF_JEQ+BPF_K, (_nr), NEXT, SKIP);	\
-	EXPECT_EQ_BLOCK(&(_filter)[1],					\
-			BPF_JMP+BPF_JA, (_id), (_jt), (_jf));		\
-} while (0)
-
-#endif	// SYSCALL_FILTER_UNITTEST_MACROS_H
+#define EXPECT_ALLOW_SYSCALL(_filter, _nr)                                     \
+	do {                                                                   \
+		EXPECT_EQ_BLOCK(&(_filter)[0], BPF_JMP + BPF_JEQ + BPF_K,      \
+				(_nr), NEXT, SKIP);                            \
+		EXPECT_EQ_STMT(&(_filter)[1], BPF_RET + BPF_K,                 \
+			       SECCOMP_RET_ALLOW);                             \
+	} while (0)
+
+#define EXPECT_ALLOW_SYSCALL_ARGS(_filter, _nr, _id, _jt, _jf)                 \
+	do {                                                                   \
+		EXPECT_EQ_BLOCK(&(_filter)[0], BPF_JMP + BPF_JEQ + BPF_K,      \
+				(_nr), NEXT, SKIP);                            \
+		EXPECT_EQ_BLOCK(&(_filter)[1], BPF_JMP + BPF_JA, (_id), (_jt), \
+				(_jf));                                        \
+	} while (0)
+
+#endif // SYSCALL_FILTER_UNITTEST_MACROS_H
diff --git a/syscall_wrapper.c b/syscall_wrapper.c
index dfdbfcd..a903248 100644
--- a/syscall_wrapper.c
+++ b/syscall_wrapper.c
@@ -15,17 +15,17 @@
  * their kernel headers.
  */
 #ifndef SYS_seccomp
-# if defined(__x86_64__)
-#  define SYS_seccomp 317
-# elif defined(__i386__)
-#  define SYS_seccomp 354
-# elif defined(__aarch64__)
-#  define SYS_seccomp 277
-# elif defined(__arm__)
-#  define SYS_seccomp 383
-# else
-#  error "Update your kernel headers"
-# endif
+#if defined(__x86_64__)
+#define SYS_seccomp 317
+#elif defined(__i386__)
+#define SYS_seccomp 354
+#elif defined(__aarch64__)
+#define SYS_seccomp 277
+#elif defined(__arm__)
+#define SYS_seccomp 383
+#else
+#error "Update your kernel headers"
+#endif
 #endif
 
 int sys_seccomp(unsigned int operation, unsigned int flags, void *args)
diff --git a/syscall_wrapper.h b/syscall_wrapper.h
index c1988ac..3bf0f1b 100644
--- a/syscall_wrapper.h
+++ b/syscall_wrapper.h
@@ -12,7 +12,7 @@ extern "C" {
 
 /* Seccomp filter related flags. */
 #ifndef PR_SET_NO_NEW_PRIVS
-# define PR_SET_NO_NEW_PRIVS 38
+#define PR_SET_NO_NEW_PRIVS 38
 #endif
 
 #ifndef SECCOMP_MODE_FILTER
@@ -20,18 +20,18 @@ extern "C" {
 #endif
 
 #ifndef SECCOMP_SET_MODE_STRICT
-# define SECCOMP_SET_MODE_STRICT 0
+#define SECCOMP_SET_MODE_STRICT 0
 #endif
 #ifndef SECCOMP_SET_MODE_FILTER
-# define SECCOMP_SET_MODE_FILTER 1
+#define SECCOMP_SET_MODE_FILTER 1
 #endif
 
 #ifndef SECCOMP_FILTER_FLAG_TSYNC
-# define SECCOMP_FILTER_FLAG_TSYNC 1
+#define SECCOMP_FILTER_FLAG_TSYNC 1
 #endif
 
 #ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
-# define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1 << 2)
+#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1 << 2)
 #endif
 /* End seccomp filter related flags. */
 
diff --git a/system.c b/system.c
index f112cbc..b2f904c 100644
--- a/system.c
+++ b/system.c
@@ -175,6 +175,10 @@ unsigned int get_last_valid_cap(void)
 			pdie("fscanf(%s)", cap_file);
 		fclose(fp);
 	}
+	/* Caps are bitfields stored in 64-bit int. */
+	if (last_valid_cap > 64)
+		pdie("unable to detect last valid cap: %u > 64",
+		     last_valid_cap);
 	return last_valid_cap;
 }
 
@@ -496,9 +500,9 @@ static bool seccomp_action_is_available(const char *wanted)
 		 */
 		return false;
 	}
-	const char actions_avail_path[] =
+	static const char actions_avail_path[] =
 	    "/proc/sys/kernel/seccomp/actions_avail";
-	FILE *f = fopen(actions_avail_path, "re");
+	attribute_cleanup_fp FILE *f = fopen(actions_avail_path, "re");
 
 	if (!f) {
 		pwarn("fopen(%s) failed", actions_avail_path);
@@ -542,6 +546,20 @@ int seccomp_ret_kill_process_available(void)
 	return ret_kill_process_available;
 }
 
+bool sys_set_no_new_privs(void)
+{
+	/*
+	 * Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
+	 * in the kernel source tree for an explanation of the parameters.
+	 */
+	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
+		return true;
+	} else {
+		pwarn("prctl(PR_SET_NO_NEW_PRIVS) failed");
+		return false;
+	}
+}
+
 bool seccomp_filter_flags_available(unsigned int flags)
 {
 	return sys_seccomp(SECCOMP_SET_MODE_FILTER, flags, NULL) != -1 ||
@@ -552,6 +570,7 @@ bool is_canonical_path(const char *path)
 {
 	attribute_cleanup_str char *rp = realpath(path, NULL);
 	if (!rp) {
+		pwarn("realpath(%s) failed", path);
 		return false;
 	}
 
diff --git a/system.h b/system.h
index 8889d9d..cccc040 100644
--- a/system.h
+++ b/system.h
@@ -59,6 +59,8 @@ int setup_mount_destination(const char *source, const char *dest, uid_t uid,
 int lookup_user(const char *user, uid_t *uid, gid_t *gid);
 int lookup_group(const char *group, gid_t *gid);
 
+/* sys_set_no_new_privs: returns true if successful. */
+bool sys_set_no_new_privs(void);
 int seccomp_ret_log_available(void);
 int seccomp_ret_kill_process_available(void);
 bool seccomp_filter_flags_available(unsigned int flags);
diff --git a/system_unittest.cc b/system_unittest.cc
index 5fa8076..138bcb5 100644
--- a/system_unittest.cc
+++ b/system_unittest.cc
@@ -84,7 +84,7 @@ TEST(write_pid_to_path, basic) {
   ASSERT_TRUE(tmp.is_valid());
 
   EXPECT_EQ(0, write_pid_to_path(1234, tmp.path.c_str()));
-  FILE *fp = fopen(tmp.path.c_str(), "re");
+  FILE* fp = fopen(tmp.path.c_str(), "re");
   EXPECT_NE(nullptr, fp);
   char data[6] = {};
   EXPECT_EQ(5u, fread(data, 1, sizeof(data), fp));
@@ -181,8 +181,8 @@ TEST(setup_mount_destination, create_pseudo_fs) {
 
   // Passing -1 for user ID/group ID tells chown to make no changes.
   std::string no_chmod = dir.path + "/no_chmod";
-  EXPECT_EQ(0, setup_mount_destination("none", no_chmod.c_str(), -1, -1,
-                                       false));
+  EXPECT_EQ(0,
+            setup_mount_destination("none", no_chmod.c_str(), -1, -1, false));
   // We check it's a directory by deleting it as such.
   EXPECT_EQ(0, rmdir(no_chmod.c_str()));
 
@@ -211,8 +211,8 @@ TEST(setup_mount_destination, create_bind_dir) {
 
   // Passing -1 for user ID/group ID tells chown to make no changes.
   std::string child_dir = dir.path + "/child_dir";
-  EXPECT_EQ(0, setup_mount_destination(kValidDir, child_dir.c_str(), -1, -1,
-                                       true));
+  EXPECT_EQ(
+      0, setup_mount_destination(kValidDir, child_dir.c_str(), -1, -1, true));
   // We check it's a directory by deleting it as such.
   EXPECT_EQ(0, rmdir(child_dir.c_str()));
 }
@@ -224,8 +224,8 @@ TEST(setup_mount_destination, create_bind_file) {
 
   // Passing -1 for user ID/group ID tells chown to make no changes.
   std::string child_file = dir.path + "/child_file";
-  EXPECT_EQ(0, setup_mount_destination(kValidFile, child_file.c_str(), -1, -1,
-                                       true));
+  EXPECT_EQ(
+      0, setup_mount_destination(kValidFile, child_file.c_str(), -1, -1, true));
   // We check it's a file by deleting it as such.
   EXPECT_EQ(0, unlink(child_file.c_str()));
 }
@@ -248,6 +248,10 @@ TEST(seccomp_actions_available, smoke) {
   seccomp_ret_kill_process_available();
 }
 
+TEST(set_no_new_privs, basic) {
+  EXPECT_TRUE(sys_set_no_new_privs());
+}
+
 TEST(is_canonical_path, basic) {
   EXPECT_FALSE(is_canonical_path("/proc/self"));
   EXPECT_FALSE(is_canonical_path("relative"));
diff --git a/test/landlock.conf b/test/landlock.conf
index 65ffe81..455703e 100644
--- a/test/landlock.conf
+++ b/test/landlock.conf
@@ -4,4 +4,4 @@ fs-default-paths
 fs-path-ro = /
 fs-path-rx = /lib
 fs-path-rw = /tmp
-fs-path-advanced-rw = /tmp
\ No newline at end of file
+fs-path-advanced-rw = /tmp
diff --git a/test/read_stdin b/test/read_stdin
index 6200bb5..d3614fa 100644
--- a/test/read_stdin
+++ b/test/read_stdin
@@ -1,13 +1,13 @@
-#!/bin/bash
+#!/bin/sh
 
 # Copyright 2012 The ChromiumOS Authors
 # Use of this source code is governed by a BSD-style license that can be
 # found in the LICENSE file.
 
-read line
+read -r line
 
-if [ "$line" == "test" ]; then
-	exit 0
+if [ "${line}" = "test" ]; then
+  exit 0
 else
-	exit 1
+  exit 1
 fi
diff --git a/test/valid.conf b/test/valid.conf
index a574e6c..76477a2 100644
--- a/test/valid.conf
+++ b/test/valid.conf
@@ -6,3 +6,9 @@ ns-mount
 mount = none,/,none
 bind-mount = /,/
 mount-dev
+# Preload library.
+preload-library = /fake-path
+# Remount mode.
+K = shared
+# Single char options.
+i
diff --git a/test_util.cc b/test_util.cc
index bbe0215..7ebd7ab 100644
--- a/test_util.cc
+++ b/test_util.cc
@@ -14,47 +14,46 @@
 
 #define MAX_PIPE_CAPACITY (4096)
 
-FILE *write_to_pipe(const std::string& content)
-{
-	int pipefd[2];
-	if (pipe(pipefd) == -1) {
-		die("pipe(pipefd) failed");
-	}
-
-	size_t len = content.length();
-	if (len > MAX_PIPE_CAPACITY)
-		die("write_to_pipe cannot handle >4KB content.");
-	size_t i = 0;
-	unsigned int attempts = 0;
-	ssize_t ret;
-	while (i < len) {
-		ret = write(pipefd[1], content.c_str() + i, len - i);
-		if (ret == -1) {
-			close(pipefd[0]);
-			close(pipefd[1]);
-			return NULL;
-		}
-
-		/* If we write 0 bytes three times in a row, fail. */
-		if (ret == 0) {
-			if (++attempts >= 3) {
-				close(pipefd[0]);
-				close(pipefd[1]);
-				warn("write() returned 0 three times in a row");
-				return NULL;
-			}
-			continue;
-		}
-
-		attempts = 0;
-		i += (size_t)ret;
-	}
-
-	close(pipefd[1]);
-	return fdopen(pipefd[0], "r");
+FILE* write_to_pipe(const std::string& content) {
+  int pipefd[2];
+  if (pipe(pipefd) == -1) {
+    die("pipe(pipefd) failed");
+  }
+
+  size_t len = content.length();
+  if (len > MAX_PIPE_CAPACITY)
+    die("write_to_pipe cannot handle >4KB content.");
+  size_t i = 0;
+  unsigned int attempts = 0;
+  ssize_t ret;
+  while (i < len) {
+    ret = write(pipefd[1], content.c_str() + i, len - i);
+    if (ret == -1) {
+      close(pipefd[0]);
+      close(pipefd[1]);
+      return NULL;
+    }
+
+    /* If we write 0 bytes three times in a row, fail. */
+    if (ret == 0) {
+      if (++attempts >= 3) {
+        close(pipefd[0]);
+        close(pipefd[1]);
+        warn("write() returned 0 three times in a row");
+        return NULL;
+      }
+      continue;
+    }
+
+    attempts = 0;
+    i += (size_t)ret;
+  }
+
+  close(pipefd[1]);
+  return fdopen(pipefd[0], "r");
 }
 
 std::string source_path(const std::string& file) {
-	std::string srcdir = getenv("SRC") ? : ".";
-	return srcdir + "/" + file;
+  std::string srcdir = getenv("SRC") ?: ".";
+  return srcdir + "/" + file;
 }
diff --git a/test_util.h b/test_util.h
index 7f923ed..11cffbf 100644
--- a/test_util.h
+++ b/test_util.h
@@ -10,6 +10,7 @@
 #define _TEST_UTIL_H_
 
 #include <stdio.h>
+#include <unistd.h>
 
 #include <memory>
 #include <string>
@@ -38,6 +39,15 @@ struct ScopedConfigEntryDeleter {
   }
 };
 
+// Functor for |ScopedStr| (below).
+struct ScopedStrDeleter {
+  inline void operator()(char *str) const {
+    if (str) {
+      free(str);
+    }
+  }
+};
+
 } // namespace internal
 
 } // namespace mj
@@ -45,6 +55,24 @@ struct ScopedConfigEntryDeleter {
 using ScopedFILE = std::unique_ptr<FILE, mj::internal::ScopedFILECloser>;
 using ScopedConfigEntry =
     std::unique_ptr<config_entry, mj::internal::ScopedConfigEntryDeleter>;
+using ScopedStr = std::unique_ptr<char, mj::internal::ScopedStrDeleter>;
+
+class ScopedFD {
+ public:
+  explicit ScopedFD(int fd) : fd_(fd) {}
+  ~ScopedFD() {
+    if (fd_ != -1)
+      close(fd_);
+  }
+
+  ScopedFD(const ScopedFD&) = delete;
+  ScopedFD& operator=(const ScopedFD&) = delete;
+
+  int get() const { return fd_; }
+
+ private:
+  int fd_ = -1;
+};
 
 /*
  * write_to_pipe: write a string as the file content into a pipe based
diff --git a/testrunner.cc b/testrunner.cc
index 70010f2..d50b857 100644
--- a/testrunner.cc
+++ b/testrunner.cc
@@ -18,14 +18,12 @@ class Environment : public ::testing::Environment {
  public:
   ~Environment() override = default;
 
-  void SetUp() override {
-    init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO);
-  }
+  void SetUp() override { init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO); }
 };
 
 }  // namespace
 
-int main(int argc, char **argv) {
+int main(int argc, char** argv) {
   testing::InitGoogleTest(&argc, argv);
   ::testing::AddGlobalTestEnvironment(new Environment());
   return RUN_ALL_TESTS();
diff --git a/tools/__init__.py b/tools/__init__.py
new file mode 100644
index 0000000..e69de29
diff --git a/tools/arch.py b/tools/arch.py
index b245f38..48782d0 100644
--- a/tools/arch.py
+++ b/tools/arch.py
@@ -1,19 +1,7 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """Architecture-specific information."""
 
 import collections
@@ -21,10 +9,18 @@ import json
 
 
 class Arch(
-        collections.namedtuple('Arch', [
-            'arch_nr', 'arch_name', 'bits', 'syscalls', 'constants',
-            'syscall_groups'
-        ])):
+    collections.namedtuple(
+        "Arch",
+        [
+            "arch_nr",
+            "arch_name",
+            "bits",
+            "syscalls",
+            "constants",
+            "syscall_groups",
+        ],
+    )
+):
     """Holds architecture-specific information."""
 
     def truncate_word(self, value):
@@ -44,7 +40,7 @@ class Arch(
     @staticmethod
     def load_from_json(json_path):
         """Return an Arch from a .json file."""
-        with open(json_path, 'r') as json_file:
+        with open(json_path, "rb") as json_file:
             return Arch.load_from_json_bytes(json_file.read())
 
     @staticmethod
diff --git a/tools/bpf.py b/tools/bpf.py
index ea495f1..2dc2be5 100644
--- a/tools/bpf.py
+++ b/tools/bpf.py
@@ -1,25 +1,14 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """Tools to interact with BPF programs."""
 
 import abc
 import collections
 import struct
 
+
 # This comes from syscall(2). Most architectures only support passing 6 args to
 # syscalls, but ARM supports passing 7.
 MAX_SYSCALL_ARGUMENTS = 7
@@ -47,7 +36,7 @@ BPF_ABS = 0x20
 BPF_IND = 0x40
 BPF_MEM = 0x60
 BPF_LEN = 0x80
-BPF_MSH = 0xa0
+BPF_MSH = 0xA0
 
 # JMP fields.
 BPF_JA = 0x00
@@ -68,13 +57,13 @@ SECCOMP_RET_KILL_PROCESS = 0x80000000
 SECCOMP_RET_KILL_THREAD = 0x00000000
 SECCOMP_RET_TRAP = 0x00030000
 SECCOMP_RET_ERRNO = 0x00050000
-SECCOMP_RET_TRACE = 0x7ff00000
-SECCOMP_RET_USER_NOTIF = 0x7fc00000
-SECCOMP_RET_LOG = 0x7ffc0000
-SECCOMP_RET_ALLOW = 0x7fff0000
+SECCOMP_RET_TRACE = 0x7FF00000
+SECCOMP_RET_USER_NOTIF = 0x7FC00000
+SECCOMP_RET_LOG = 0x7FFC0000
+SECCOMP_RET_ALLOW = 0x7FFF0000
 
-SECCOMP_RET_ACTION_FULL = 0xffff0000
-SECCOMP_RET_DATA = 0x0000ffff
+SECCOMP_RET_ACTION_FULL = 0xFFFF0000
+SECCOMP_RET_DATA = 0x0000FFFF
 
 
 def arg_offset(arg_index, hi=False):
@@ -86,10 +75,12 @@ def arg_offset(arg_index, hi=False):
 
 def simulate(instructions, arch, syscall_number, *args):
     """Simulate a BPF program with the given arguments."""
-    args = ((args + (0, ) *
-             (MAX_SYSCALL_ARGUMENTS - len(args)))[:MAX_SYSCALL_ARGUMENTS])
-    input_memory = struct.pack('IIQ' + 'Q' * MAX_SYSCALL_ARGUMENTS,
-                               syscall_number, arch, 0, *args)
+    args = (args + (0,) * (MAX_SYSCALL_ARGUMENTS - len(args)))[
+        :MAX_SYSCALL_ARGUMENTS
+    ]
+    input_memory = struct.pack(
+        "IIQ" + "Q" * MAX_SYSCALL_ARGUMENTS, syscall_number, arch, 0, *args
+    )
 
     register = 0
     program_counter = 0
@@ -99,7 +90,7 @@ def simulate(instructions, arch, syscall_number, *args):
         program_counter += 1
         cost += 1
         if ins.code == BPF_LD | BPF_W | BPF_ABS:
-            register = struct.unpack('I', input_memory[ins.k:ins.k + 4])[0]
+            register = struct.unpack("I", input_memory[ins.k : ins.k + 4])[0]
         elif ins.code == BPF_JMP | BPF_JA | BPF_K:
             program_counter += ins.k
         elif ins.code == BPF_JMP | BPF_JEQ | BPF_K:
@@ -124,44 +115,42 @@ def simulate(instructions, arch, syscall_number, *args):
                 program_counter += ins.jf
         elif ins.code == BPF_RET:
             if ins.k == SECCOMP_RET_KILL_PROCESS:
-                return (cost, 'KILL_PROCESS')
+                return (cost, "KILL_PROCESS")
             if ins.k == SECCOMP_RET_KILL_THREAD:
-                return (cost, 'KILL_THREAD')
+                return (cost, "KILL_THREAD")
             if ins.k == SECCOMP_RET_TRAP:
-                return (cost, 'TRAP')
+                return (cost, "TRAP")
             if (ins.k & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO:
-                return (cost, 'ERRNO', ins.k & SECCOMP_RET_DATA)
+                return (cost, "ERRNO", ins.k & SECCOMP_RET_DATA)
             if ins.k == SECCOMP_RET_TRACE:
-                return (cost, 'TRACE')
+                return (cost, "TRACE")
             if ins.k == SECCOMP_RET_USER_NOTIF:
-                return (cost, 'USER_NOTIF')
+                return (cost, "USER_NOTIF")
             if ins.k == SECCOMP_RET_LOG:
-                return (cost, 'LOG')
+                return (cost, "LOG")
             if ins.k == SECCOMP_RET_ALLOW:
-                return (cost, 'ALLOW')
-            raise Exception('unknown return %#x' % ins.k)
+                return (cost, "ALLOW")
+            raise Exception("unknown return %#x" % ins.k)
         else:
-            raise Exception('unknown instruction %r' % (ins, ))
-    raise Exception('out-of-bounds')
+            raise Exception("unknown instruction %r" % (ins,))
+    raise Exception("out-of-bounds")
 
 
 class SockFilter(
-        collections.namedtuple('SockFilter', ['code', 'jt', 'jf', 'k'])):
+    collections.namedtuple("SockFilter", ["code", "jt", "jf", "k"])
+):
     """A representation of struct sock_filter."""
 
     __slots__ = ()
 
     def encode(self):
         """Return an encoded version of the SockFilter."""
-        return struct.pack('HBBI', self.code, self.jt, self.jf, self.k)
+        return struct.pack("HBBI", self.code, self.jt, self.jf, self.k)
 
 
 class AbstractBlock(abc.ABC):
     """A class that implements the visitor pattern."""
 
-    def __init__(self):
-        super().__init__()
-
     @abc.abstractmethod
     def accept(self, visitor):
         pass
@@ -185,7 +174,7 @@ class BasicBlock(AbstractBlock):
 
     @property
     def opcodes(self):
-        return b''.join(i.encode() for i in self._instructions)
+        return b"".join(i.encode() for i in self._instructions)
 
     def __eq__(self, o):
         if not isinstance(o, BasicBlock):
@@ -198,7 +187,8 @@ class KillProcess(BasicBlock):
 
     def __init__(self):
         super().__init__(
-            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_PROCESS)])
+            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_PROCESS)]
+        )
 
 
 class KillThread(BasicBlock):
@@ -206,7 +196,8 @@ class KillThread(BasicBlock):
 
     def __init__(self):
         super().__init__(
-            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_THREAD)])
+            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_THREAD)]
+        )
 
 
 class Trap(BasicBlock):
@@ -227,7 +218,9 @@ class UserNotify(BasicBlock):
     """A BasicBlock that unconditionally returns USER_NOTIF."""
 
     def __init__(self):
-        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_USER_NOTIF)])
+        super().__init__(
+            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_USER_NOTIF)]
+        )
 
 
 class Log(BasicBlock):
@@ -241,10 +234,16 @@ class ReturnErrno(BasicBlock):
     """A BasicBlock that unconditionally returns the specified errno."""
 
     def __init__(self, errno):
-        super().__init__([
-            SockFilter(BPF_RET, 0x00, 0x00,
-                       SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA))
-        ])
+        super().__init__(
+            [
+                SockFilter(
+                    BPF_RET,
+                    0x00,
+                    0x00,
+                    SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA),
+                )
+            ]
+        )
         self.errno = errno
 
 
@@ -306,7 +305,9 @@ class SyscallEntry(AbstractBlock):
 class WideAtom(AbstractBlock):
     """A BasicBlock that represents a 32-bit wide atom."""
 
-    def __init__(self, arg_offset, op, value, jt, jf):
+    def __init__(
+        self, arg_offset, op, value, jt, jf
+    ):  # pylint: disable=redefined-outer-name
         super().__init__()
         self.arg_offset = arg_offset
         self.op = op
@@ -327,24 +328,24 @@ class Atom(AbstractBlock):
 
     def __init__(self, arg_index, op, value, jt, jf):
         super().__init__()
-        if op == '==':
+        if op == "==":
             op = BPF_JEQ
-        elif op == '!=':
+        elif op == "!=":
             op = BPF_JEQ
             jt, jf = jf, jt
-        elif op == '>':
+        elif op == ">":
             op = BPF_JGT
-        elif op == '<=':
+        elif op == "<=":
             op = BPF_JGT
             jt, jf = jf, jt
-        elif op == '>=':
+        elif op == ">=":
             op = BPF_JGE
-        elif op == '<':
+        elif op == "<":
             op = BPF_JGE
             jt, jf = jf, jt
-        elif op == '&':
+        elif op == "&":
             op = BPF_JSET
-        elif op == 'in':
+        elif op == "in":
             op = BPF_JSET
             # The mask is negated, so the comparison will be true when the
             # argument includes a flag that wasn't listed in the original
@@ -353,7 +354,7 @@ class Atom(AbstractBlock):
             value = (~value) & ((1 << 64) - 1)
             jt, jf = jf, jt
         else:
-            raise Exception('Unknown operator %s' % op)
+            raise Exception("Unknown operator %s" % op)
 
         self.arg_index = arg_index
         self.op = op
@@ -413,7 +414,7 @@ class AbstractVisitor(abc.ABC):
         elif isinstance(block, Atom):
             self.visitAtom(block)
         else:
-            raise Exception('Unknown block type: %r' % block)
+            raise Exception("Unknown block type: %r" % block)
 
     @abc.abstractmethod
     def visitKillProcess(self, block):
@@ -519,7 +520,8 @@ class CopyingVisitor(AbstractVisitor):
     def visitValidateArch(self, block):
         assert id(block) not in self._mapping
         self._mapping[id(block)] = ValidateArch(
-            block.arch, self._mapping[id(block.next_block)])
+            self._mapping[id(block.next_block)]
+        )
 
     def visitSyscallEntry(self, block):
         assert id(block) not in self._mapping
@@ -527,19 +529,28 @@ class CopyingVisitor(AbstractVisitor):
             block.syscall_number,
             self._mapping[id(block.jt)],
             self._mapping[id(block.jf)],
-            op=block.op)
+            op=block.op,
+        )
 
     def visitWideAtom(self, block):
         assert id(block) not in self._mapping
         self._mapping[id(block)] = WideAtom(
-            block.arg_offset, block.op, block.value, self._mapping[id(
-                block.jt)], self._mapping[id(block.jf)])
+            block.arg_offset,
+            block.op,
+            block.value,
+            self._mapping[id(block.jt)],
+            self._mapping[id(block.jf)],
+        )
 
     def visitAtom(self, block):
         assert id(block) not in self._mapping
-        self._mapping[id(block)] = Atom(block.arg_index, block.op, block.value,
-                                        self._mapping[id(block.jt)],
-                                        self._mapping[id(block.jf)])
+        self._mapping[id(block)] = Atom(
+            block.arg_index,
+            block.op,
+            block.value,
+            self._mapping[id(block.jt)],
+            self._mapping[id(block.jf)],
+        )
 
 
 class LoweringVisitor(CopyingVisitor):
@@ -556,8 +567,12 @@ class LoweringVisitor(CopyingVisitor):
         hi = (block.value >> 32) & 0xFFFFFFFF
 
         lo_block = WideAtom(
-            arg_offset(block.arg_index, False), block.op, lo,
-            self._mapping[id(block.jt)], self._mapping[id(block.jf)])
+            arg_offset(block.arg_index, False),
+            block.op,
+            lo,
+            self._mapping[id(block.jt)],
+            self._mapping[id(block.jf)],
+        )
 
         if self._bits == 32:
             self._mapping[id(block)] = lo_block
@@ -571,15 +586,27 @@ class LoweringVisitor(CopyingVisitor):
                 # Special case: it's not needed to check whether |hi_1 == hi_2|,
                 # because it's true iff the JGT test fails.
                 self._mapping[id(block)] = WideAtom(
-                    arg_offset(block.arg_index, True), BPF_JGT, hi,
-                    self._mapping[id(block.jt)], lo_block)
+                    arg_offset(block.arg_index, True),
+                    BPF_JGT,
+                    hi,
+                    self._mapping[id(block.jt)],
+                    lo_block,
+                )
                 return
             hi_eq_block = WideAtom(
-                arg_offset(block.arg_index, True), BPF_JEQ, hi, lo_block,
-                self._mapping[id(block.jf)])
+                arg_offset(block.arg_index, True),
+                BPF_JEQ,
+                hi,
+                lo_block,
+                self._mapping[id(block.jf)],
+            )
             self._mapping[id(block)] = WideAtom(
-                arg_offset(block.arg_index, True), BPF_JGT, hi,
-                self._mapping[id(block.jt)], hi_eq_block)
+                arg_offset(block.arg_index, True),
+                BPF_JGT,
+                hi,
+                self._mapping[id(block.jt)],
+                hi_eq_block,
+            )
             return
         if block.op == BPF_JSET:
             # hi_1,lo_1 & hi_2,lo_2
@@ -591,8 +618,12 @@ class LoweringVisitor(CopyingVisitor):
                 self._mapping[id(block)] = lo_block
                 return
             self._mapping[id(block)] = WideAtom(
-                arg_offset(block.arg_index, True), block.op, hi,
-                self._mapping[id(block.jt)], lo_block)
+                arg_offset(block.arg_index, True),
+                block.op,
+                hi,
+                self._mapping[id(block.jt)],
+                lo_block,
+            )
             return
 
         assert block.op == BPF_JEQ, block.op
@@ -601,8 +632,12 @@ class LoweringVisitor(CopyingVisitor):
         #
         # hi_1 == hi_2 && lo_1 == lo_2
         self._mapping[id(block)] = WideAtom(
-            arg_offset(block.arg_index, True), block.op, hi, lo_block,
-            self._mapping[id(block.jf)])
+            arg_offset(block.arg_index, True),
+            block.op,
+            hi,
+            lo_block,
+            self._mapping[id(block.jf)],
+        )
 
 
 class FlatteningVisitor:
@@ -630,8 +665,9 @@ class FlatteningVisitor:
     def _emit_jmp(self, op, value, jt_distance, jf_distance):
         if jt_distance < 0x100 and jf_distance < 0x100:
             return [
-                SockFilter(BPF_JMP | op | BPF_K, jt_distance, jf_distance,
-                           value),
+                SockFilter(
+                    BPF_JMP | op | BPF_K, jt_distance, jf_distance, value
+                ),
             ]
         if jt_distance + 1 < 0x100:
             return [
@@ -661,29 +697,42 @@ class FlatteningVisitor:
         if isinstance(block, BasicBlock):
             instructions = block.instructions
         elif isinstance(block, ValidateArch):
-            instructions = [
-                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
-                SockFilter(BPF_JMP | BPF_JEQ | BPF_K,
-                           self._distance(block.next_block) + 1, 0,
-                           self._arch.arch_nr),
-            ] + self._kill_action.instructions + [
-                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
-            ]
+            instructions = (
+                [
+                    SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
+                    SockFilter(
+                        BPF_JMP | BPF_JEQ | BPF_K,
+                        self._distance(block.next_block) + 1,
+                        0,
+                        self._arch.arch_nr,
+                    ),
+                ]
+                + self._kill_action.instructions
+                + [
+                    SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
+                ]
+            )
         elif isinstance(block, SyscallEntry):
-            instructions = self._emit_jmp(block.op, block.syscall_number,
-                                          self._distance(block.jt),
-                                          self._distance(block.jf))
+            instructions = self._emit_jmp(
+                block.op,
+                block.syscall_number,
+                self._distance(block.jt),
+                self._distance(block.jf),
+            )
         elif isinstance(block, WideAtom):
-            instructions = (
-                self._emit_load_arg(block.arg_offset) + self._emit_jmp(
-                    block.op, block.value, self._distance(block.jt),
-                    self._distance(block.jf)))
+            instructions = self._emit_load_arg(
+                block.arg_offset
+            ) + self._emit_jmp(
+                block.op,
+                block.value,
+                self._distance(block.jt),
+                self._distance(block.jf),
+            )
         else:
-            raise Exception('Unknown block type: %r' % block)
+            raise Exception("Unknown block type: %r" % block)
 
         self._instructions = instructions + self._instructions
         self._offsets[id(block)] = -len(self._instructions)
-        return
 
 
 class ArgFilterForwardingVisitor:
@@ -705,9 +754,18 @@ class ArgFilterForwardingVisitor:
             return
         # But the ALLOW, KILL_PROCESS, TRAP, etc. actions are too and we don't
         # want to visit them just yet.
-        if (isinstance(block, KillProcess) or isinstance(block, KillThread)
-                or isinstance(block, Trap) or isinstance(block, ReturnErrno)
-                or isinstance(block, Trace) or isinstance(block, UserNotify)
-                or isinstance(block, Log) or isinstance(block, Allow)):
+        if isinstance(
+            block,
+            (
+                KillProcess,
+                KillThread,
+                Trap,
+                ReturnErrno,
+                Trace,
+                UserNotify,
+                Log,
+                Allow,
+            ),
+        ):
             return
         block.accept(self.visitor)
diff --git a/tools/compile_seccomp_policy.py b/tools/compile_seccomp_policy.py
index 2219ae5..66fadfe 100755
--- a/tools/compile_seccomp_policy.py
+++ b/tools/compile_seccomp_policy.py
@@ -1,36 +1,25 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """Helper tool to compile a BPF program from a Minijail seccomp filter.
 
 This script will take a Minijail seccomp policy file and compile it into a
 BPF program suitable for use with Minijail in the current architecture.
 """
 
-from __future__ import print_function
-
 import argparse
 import os
 import sys
 
+
 try:
+    import parser
+
     import arch
     import bpf
     import compiler
-    import parser
 except ImportError:
     from minijail import arch
     from minijail import bpf
@@ -60,48 +49,63 @@ static const struct {
 #endif
 """
 
+
 def parse_args(argv):
     """Return the parsed CLI arguments for this tool."""
     arg_parser = argparse.ArgumentParser(description=__doc__)
-    arg_parser.add_argument('--optimization-strategy',
-                            default=compiler.OptimizationStrategy.BST,
-                            type=compiler.OptimizationStrategy,
-                            choices=list(compiler.OptimizationStrategy))
-    arg_parser.add_argument('--include-depth-limit', default=10)
-    arg_parser.add_argument('--arch-json', default='constants.json')
     arg_parser.add_argument(
-        '--denylist',
-        action='store_true',
-        help='Compile as a denylist policy rather than the default allowlist.')
+        "--optimization-strategy",
+        default=compiler.OptimizationStrategy.BST,
+        type=compiler.OptimizationStrategy,
+        choices=list(compiler.OptimizationStrategy),
+    )
+    arg_parser.add_argument("--include-depth-limit", default=10)
+    arg_parser.add_argument("--arch-json", default="constants.json")
+    arg_parser.add_argument(
+        "--denylist",
+        action="store_true",
+        help="Compile as a denylist policy rather than the default allowlist.",
+    )
     arg_parser.add_argument(
-        '--default-action',
+        "--default-action",
         type=str,
-        help=('Use the specified default action, overriding any @default '
-              'action found in the .policy files. '
-              'This allows the use of permissive actions (allow, log, trace, '
-              'user-notify) since it is not valid to specify a permissive '
-              'action in .policy files. This is useful for debugging.'))
+        help=(
+            "Use the specified default action, overriding any @default "
+            "action found in the .policy files. "
+            "This allows the use of permissive actions (allow, log, trace, "
+            "user-notify) since it is not valid to specify a permissive "
+            "action in .policy files. This is useful for debugging."
+        ),
+    )
     arg_parser.add_argument(
-        '--use-kill-process',
-        action='store_true',
-        help=('Use SECCOMP_RET_KILL_PROCESS instead of '
-              'SECCOMP_RET_KILL_THREAD (requires Linux v4.14+).'))
+        "--use-kill-process",
+        action="store_true",
+        help=(
+            "Use SECCOMP_RET_KILL_PROCESS instead of "
+            "SECCOMP_RET_KILL_THREAD (requires Linux v4.14+)."
+        ),
+    )
     arg_parser.add_argument(
-        '--use-ret-log',
-        action='store_true',
-        help=('Change all seccomp failures to return SECCOMP_RET_LOG instead '
-              'of killing (requires SECCOMP_RET_LOG kernel support).'))
+        "--use-ret-log",
+        action="store_true",
+        help=(
+            "Change all seccomp failures to return SECCOMP_RET_LOG instead "
+            "of killing (requires SECCOMP_RET_LOG kernel support)."
+        ),
+    )
     arg_parser.add_argument(
-        '--output-header-file',
-        action='store_true',
-        help=('Output the compiled bpf to a constant variable in a C header '
-              'file instead of a binary file (output should not have a .h '
-              'extension, one will be added).'))
-    arg_parser.add_argument('policy',
-                            help='The seccomp policy.',
-                            type=argparse.FileType('r'))
-    arg_parser.add_argument('output',
-                            help='The BPF program.')
+        "--output-header-file",
+        action="store_true",
+        help=(
+            "Output the compiled bpf to a constant variable in a C header "
+            "file instead of a binary file (output should not have a .h "
+            "extension, one will be added)."
+        ),
+    )
+    arg_parser.add_argument(
+        "policy", help="The seccomp policy.", type=argparse.FileType("r")
+    )
+    arg_parser.add_argument("output", help="The BPF program.")
     return arg_parser.parse_args(argv), arg_parser
 
 
@@ -119,28 +123,30 @@ def main(argv=None):
     policy_compiler = compiler.PolicyCompiler(parsed_arch)
     # Set ret_log to true if the MINIJAIL_DEFAULT_RET_LOG environment variable
     # is present.
-    if 'MINIJAIL_DEFAULT_RET_LOG' in os.environ:
-        print("""
+    if "MINIJAIL_DEFAULT_RET_LOG" in os.environ:
+        print(
+            """
             \n**********************
 Warning: MINJAIL_DEFAULT_RET_LOG is on, policy will not have any effect
 **********************\n
-""")
+"""
+        )
         opts.use_ret_log = True
     if opts.use_ret_log:
         kill_action = bpf.Log()
     elif opts.denylist:
         # Default action for a denylist policy is return EPERM
-        kill_action = bpf.ReturnErrno(parsed_arch.constants['EPERM'])
+        kill_action = bpf.ReturnErrno(parsed_arch.constants["EPERM"])
     elif opts.use_kill_process:
         kill_action = bpf.KillProcess()
     else:
         kill_action = bpf.KillThread()
     override_default_action = None
     if opts.default_action:
-        parser_state = parser.ParserState('<memory>')
+        parser_state = parser.ParserState("<memory>")
         override_default_action = parser.PolicyParser(
-            parsed_arch, kill_action=bpf.KillProcess()).parse_action(
-                next(parser_state.tokenize([opts.default_action])))
+            parsed_arch, kill_action=bpf.KillProcess()
+        ).parse_action(next(parser_state.tokenize([opts.default_action])))
 
     compiled_policy = policy_compiler.compile_file(
         opts.policy.name,
@@ -149,23 +155,29 @@ Warning: MINJAIL_DEFAULT_RET_LOG is on, policy will not have any effect
         include_depth_limit=opts.include_depth_limit,
         override_default_action=override_default_action,
         denylist=opts.denylist,
-        ret_log=opts.use_ret_log)
+        ret_log=opts.use_ret_log,
+    )
     # Outputs the bpf binary to a c header file instead of a binary file.
     if opts.output_header_file:
         output_file_base = opts.output
-        with open(output_file_base + '.h', 'w') as output_file:
-            program = ', '.join('%i' % x for x in compiled_policy.opcodes)
-            output_file.write(HEADER_TEMPLATE % {
-                'upper_name': output_file_base.upper(),
-                'name': output_file_base,
-                'program': program,
-            })
+        with open(
+            output_file_base + ".h", "w", encoding="utf-8"
+        ) as output_file:
+            program = ", ".join("%i" % x for x in compiled_policy.opcodes)
+            output_file.write(
+                HEADER_TEMPLATE
+                % {
+                    "upper_name": output_file_base.upper(),
+                    "name": output_file_base,
+                    "program": program,
+                }
+            )
 
     else:
-        with open(opts.output, 'wb') as outf:
+        with open(opts.output, "wb") as outf:
             outf.write(compiled_policy.opcodes)
     return 0
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/compiler.py b/tools/compiler.py
index f239740..922ea0a 100644
--- a/tools/compiler.py
+++ b/tools/compiler.py
@@ -1,28 +1,16 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""A BPF compiler for the Minijail policy file."""
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 
-from __future__ import print_function
+"""A BPF compiler for the Minijail policy file."""
 
 import enum
 
+
 try:
-    import bpf
     import parser  # pylint: disable=wrong-import-order
+
+    import bpf
 except ImportError:
     from minijail import bpf
     from minijail import parser  # pylint: disable=wrong-import-order
@@ -33,11 +21,11 @@ class OptimizationStrategy(enum.Enum):
 
     # Generate a linear chain of syscall number checks. Works best for policies
     # with very few syscalls.
-    LINEAR = 'linear'
+    LINEAR = "linear"
 
     # Generate a binary search tree for the syscalls. Works best for policies
     # with a lot of syscalls, where no one syscall dominates.
-    BST = 'bst'
+    BST = "bst"
 
     def __str__(self):
         return self.value
@@ -54,17 +42,23 @@ class SyscallPolicyEntry:
         self.filter = None
 
     def __repr__(self):
-        return ('SyscallPolicyEntry<name: %s, number: %d, '
-                'frequency: %d, filter: %r>') % (
-                    self.name, self.number, self.frequency,
-                    self.filter.instructions if self.filter else None)
+        return (
+            "SyscallPolicyEntry<name: %s, number: %d, "
+            "frequency: %d, filter: %r>"
+        ) % (
+            self.name,
+            self.number,
+            self.frequency,
+            self.filter.instructions if self.filter else None,
+        )
 
     def simulate(self, arch, syscall_number, *args):
         """Simulate the policy with the given arguments."""
         if not self.filter:
-            return (0, 'ALLOW')
-        return bpf.simulate(self.filter.instructions, arch, syscall_number,
-                            *args)
+            return (0, "ALLOW")
+        return bpf.simulate(
+            self.filter.instructions, arch, syscall_number, *args
+        )
 
 
 class SyscallPolicyRange:
@@ -77,14 +71,16 @@ class SyscallPolicyRange:
         self.filter = entries[0].filter
 
     def __repr__(self):
-        return 'SyscallPolicyRange<numbers: %r, frequency: %d, filter: %r>' % (
-            self.numbers, self.frequency,
-            self.filter.instructions if self.filter else None)
+        return "SyscallPolicyRange<numbers: %r, frequency: %d, filter: %r>" % (
+            self.numbers,
+            self.frequency,
+            self.filter.instructions if self.filter else None,
+        )
 
     def simulate(self, arch, syscall_number, *args):
         """Simulate the policy with the given arguments."""
         if not self.filter:
-            return (0, 'ALLOW')
+            return (0, "ALLOW")
         return self.filter.simulate(arch, syscall_number, *args)
 
 
@@ -103,39 +99,50 @@ def _convert_to_ranges(entries):
         lower = upper
 
 
-def _compile_single_range(entry,
-                          accept_action,
-                          reject_action,
-                          lower_bound=0,
-                          upper_bound=1e99):
+def _compile_single_range(
+    entry, accept_action, reject_action, lower_bound=0, upper_bound=1e99
+):
     action = accept_action
     if entry.filter:
         action = entry.filter
     if entry.numbers[1] - entry.numbers[0] == 1:
         # Single syscall.
         # Accept if |X == nr|.
-        return (1,
-                bpf.SyscallEntry(
-                    entry.numbers[0], action, reject_action, op=bpf.BPF_JEQ))
+        return (
+            1,
+            bpf.SyscallEntry(
+                entry.numbers[0], action, reject_action, op=bpf.BPF_JEQ
+            ),
+        )
     elif entry.numbers[0] == lower_bound:
         # Syscall range aligned with the lower bound.
         # Accept if |X < nr[1]|.
-        return (1,
-                bpf.SyscallEntry(
-                    entry.numbers[1], reject_action, action, op=bpf.BPF_JGE))
+        return (
+            1,
+            bpf.SyscallEntry(
+                entry.numbers[1], reject_action, action, op=bpf.BPF_JGE
+            ),
+        )
     elif entry.numbers[1] == upper_bound:
         # Syscall range aligned with the upper bound.
         # Accept if |X >= nr[0]|.
-        return (1,
-                bpf.SyscallEntry(
-                    entry.numbers[0], action, reject_action, op=bpf.BPF_JGE))
+        return (
+            1,
+            bpf.SyscallEntry(
+                entry.numbers[0], action, reject_action, op=bpf.BPF_JGE
+            ),
+        )
     # Syscall range in the middle.
     # Accept if |nr[0] <= X < nr[1]|.
     upper_entry = bpf.SyscallEntry(
-        entry.numbers[1], reject_action, action, op=bpf.BPF_JGE)
-    return (2,
-            bpf.SyscallEntry(
-                entry.numbers[0], upper_entry, reject_action, op=bpf.BPF_JGE))
+        entry.numbers[1], reject_action, action, op=bpf.BPF_JGE
+    )
+    return (
+        2,
+        bpf.SyscallEntry(
+            entry.numbers[0], upper_entry, reject_action, op=bpf.BPF_JGE
+        ),
+    )
 
 
 def _compile_ranges_linear(ranges, accept_action, reject_action):
@@ -148,7 +155,8 @@ def _compile_ranges_linear(ranges, accept_action, reject_action):
     next_action = reject_action
     for entry in sorted(ranges, key=lambda r: r.frequency):
         current_cost, next_action = _compile_single_range(
-            entry, accept_action, next_action)
+            entry, accept_action, next_action
+        )
         accumulated_frequencies += entry.frequency
         cost += accumulated_frequencies * current_cost
     return (cost, next_action)
@@ -156,7 +164,8 @@ def _compile_ranges_linear(ranges, accept_action, reject_action):
 
 def _compile_entries_linear(entries, accept_action, reject_action):
     return _compile_ranges_linear(
-        _convert_to_ranges(entries), accept_action, reject_action)[1]
+        _convert_to_ranges(entries), accept_action, reject_action
+    )[1]
 
 
 def _compile_entries_bst(entries, accept_action, reject_action):
@@ -201,33 +210,40 @@ def _compile_entries_bst(entries, accept_action, reject_action):
 
     def _generate_syscall_bst(ranges, indices, bounds=(0, 2**64 - 1)):
         assert bounds[0] <= ranges[indices[0]].numbers[0], (indices, bounds)
-        assert ranges[indices[1] - 1].numbers[1] <= bounds[1], (indices,
-                                                                bounds)
+        assert ranges[indices[1] - 1].numbers[1] <= bounds[1], (indices, bounds)
 
         if bounds in memoized_costs:
             return memoized_costs[bounds]
         if indices[1] - indices[0] == 1:
             if bounds == ranges[indices[0]].numbers:
                 # If bounds are tight around the syscall, it costs nothing.
-                memoized_costs[bounds] = (0, ranges[indices[0]].filter
-                                          or accept_action)
+                memoized_costs[bounds] = (
+                    0,
+                    ranges[indices[0]].filter or accept_action,
+                )
                 return memoized_costs[bounds]
-            result = _compile_single_range(ranges[indices[0]], accept_action,
-                                           reject_action)
-            memoized_costs[bounds] = (result[0] * ranges[indices[0]].frequency,
-                                      result[1])
+            result = _compile_single_range(
+                ranges[indices[0]], accept_action, reject_action
+            )
+            memoized_costs[bounds] = (
+                result[0] * ranges[indices[0]].frequency,
+                result[1],
+            )
             return memoized_costs[bounds]
 
         # Try the linear model first and use that as the best estimate so far.
-        best_cost = _compile_ranges_linear(ranges[slice(*indices)],
-                                           accept_action, reject_action)
+        best_cost = _compile_ranges_linear(
+            ranges[slice(*indices)], accept_action, reject_action
+        )
 
         # Now recursively go through all possible partitions of the interval
         # currently being considered.
-        previous_accumulated = ranges[indices[0]].accumulated - ranges[
-            indices[0]].frequency
+        previous_accumulated = (
+            ranges[indices[0]].accumulated - ranges[indices[0]].frequency
+        )
         bst_comparison_cost = (
-            ranges[indices[1] - 1].accumulated - previous_accumulated)
+            ranges[indices[1] - 1].accumulated - previous_accumulated
+        )
         for i, entry in enumerate(ranges[slice(*indices)]):
             candidates = [entry.numbers[0]]
             if i:
@@ -238,19 +254,29 @@ def _compile_entries_bst(entries, accept_action, reject_action):
                 if not indices[0] < i + indices[0] < indices[1]:
                     continue
                 left_subtree = _generate_syscall_bst(
-                    ranges, (indices[0], i + indices[0]),
-                    (bounds[0], cutoff_bound))
+                    ranges,
+                    (indices[0], i + indices[0]),
+                    (bounds[0], cutoff_bound),
+                )
                 right_subtree = _generate_syscall_bst(
-                    ranges, (i + indices[0], indices[1]),
-                    (cutoff_bound, bounds[1]))
+                    ranges,
+                    (i + indices[0], indices[1]),
+                    (cutoff_bound, bounds[1]),
+                )
                 best_cost = min(
                     best_cost,
-                    (bst_comparison_cost + left_subtree[0] + right_subtree[0],
-                     bpf.SyscallEntry(
-                         cutoff_bound,
-                         right_subtree[1],
-                         left_subtree[1],
-                         op=bpf.BPF_JGE)))
+                    (
+                        bst_comparison_cost
+                        + left_subtree[0]
+                        + right_subtree[0],
+                        bpf.SyscallEntry(
+                            cutoff_bound,
+                            right_subtree[1],
+                            left_subtree[1],
+                            op=bpf.BPF_JGE,
+                        ),
+                    ),
+                )
 
         memoized_costs[bounds] = best_cost
         return memoized_costs[bounds]
@@ -264,15 +290,17 @@ class PolicyCompiler:
     def __init__(self, arch):
         self._arch = arch
 
-    def compile_file(self,
-                     policy_filename,
-                     *,
-                     optimization_strategy,
-                     kill_action,
-                     include_depth_limit=10,
-                     override_default_action=None,
-                     denylist=False,
-                     ret_log=False):
+    def compile_file(
+        self,
+        policy_filename,
+        *,
+        optimization_strategy,
+        kill_action,
+        include_depth_limit=10,
+        override_default_action=None,
+        denylist=False,
+        ret_log=False,
+    ):
         """Return a compiled BPF program from the provided policy file."""
         policy_parser = parser.PolicyParser(
             self._arch,
@@ -280,16 +308,19 @@ class PolicyCompiler:
             include_depth_limit=include_depth_limit,
             override_default_action=override_default_action,
             denylist=denylist,
-            ret_log=ret_log)
+            ret_log=ret_log,
+        )
         parsed_policy = policy_parser.parse_file(policy_filename)
         entries = [
             self.compile_filter_statement(
-                filter_statement, kill_action=kill_action, denylist=denylist)
+                filter_statement, kill_action=kill_action, denylist=denylist
+            )
             for filter_statement in parsed_policy.filter_statements
         ]
 
         visitor = bpf.FlatteningVisitor(
-            arch=self._arch, kill_action=kill_action)
+            arch=self._arch, kill_action=kill_action
+        )
         if denylist:
             accept_action = kill_action
             reject_action = bpf.Allow()
@@ -298,11 +329,13 @@ class PolicyCompiler:
             reject_action = parsed_policy.default_action
         if entries:
             if optimization_strategy == OptimizationStrategy.BST:
-                next_action = _compile_entries_bst(entries, accept_action,
-                                                   reject_action)
+                next_action = _compile_entries_bst(
+                    entries, accept_action, reject_action
+                )
             else:
-                next_action = _compile_entries_linear(entries, accept_action,
-                                                      reject_action)
+                next_action = _compile_entries_linear(
+                    entries, accept_action, reject_action
+                )
             next_action.accept(bpf.ArgFilterForwardingVisitor(visitor))
             reject_action.accept(visitor)
             accept_action.accept(visitor)
@@ -312,15 +345,15 @@ class PolicyCompiler:
             bpf.ValidateArch(reject_action).accept(visitor)
         return visitor.result
 
-    def compile_filter_statement(self,
-                                 filter_statement,
-                                 *,
-                                 kill_action,
-                                 denylist=False):
+    def compile_filter_statement(
+        self, filter_statement, *, kill_action, denylist=False
+    ):
         """Compile one parser.FilterStatement into BPF."""
-        policy_entry = SyscallPolicyEntry(filter_statement.syscall.name,
-                                          filter_statement.syscall.number,
-                                          filter_statement.frequency)
+        policy_entry = SyscallPolicyEntry(
+            filter_statement.syscall.name,
+            filter_statement.syscall.number,
+            filter_statement.frequency,
+        )
         # In each step of the way, the false action is the one that is taken if
         # the immediate boolean condition does not match. This means that the
         # false action taken here is the one that applies if the whole
@@ -339,8 +372,13 @@ class PolicyCompiler:
                 # comparison jump to the accept action if it succeeds.
                 true_action = filt.action
                 for atom in disjunction:
-                    block = bpf.Atom(atom.argument_index, atom.op, atom.value,
-                                     true_action, false_action)
+                    block = bpf.Atom(
+                        atom.argument_index,
+                        atom.op,
+                        atom.value,
+                        true_action,
+                        false_action,
+                    )
                     true_action = block
                 false_action = true_action
         policy_filter = false_action
@@ -351,7 +389,8 @@ class PolicyCompiler:
 
         # Flatten the IR DAG into a single BasicBlock.
         flattening_visitor = bpf.FlatteningVisitor(
-            arch=self._arch, kill_action=kill_action)
+            arch=self._arch, kill_action=kill_action
+        )
         policy_filter.accept(flattening_visitor)
         policy_entry.filter = flattening_visitor.result
         return policy_entry
diff --git a/tools/compiler_unittest.py b/tools/compiler_unittest.py
index 993de59..131c862 100755
--- a/tools/compiler_unittest.py
+++ b/tools/compiler_unittest.py
@@ -1,24 +1,12 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Unittests for the compiler module."""
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 
-from __future__ import print_function
+"""Unittests for the compiler module."""
 
 import os
+import parser  # pylint: disable=wrong-import-order
 import random
 import shutil
 import tempfile
@@ -28,7 +16,7 @@ from importlib import resources
 import arch
 import bpf
 import compiler
-import parser  # pylint: disable=wrong-import-order
+
 
 ARCH_64 = arch.Arch.load_from_json_bytes(
     resources.files("testdata").joinpath("arch_64.json").read_bytes()
@@ -43,50 +31,63 @@ class CompileFilterStatementTests(unittest.TestCase):
         self.compiler = compiler.PolicyCompiler(self.arch)
 
     def _compile(self, line):
-        with tempfile.NamedTemporaryFile(mode='w') as policy_file:
+        with tempfile.NamedTemporaryFile(mode="w") as policy_file:
             policy_file.write(line)
             policy_file.flush()
             policy_parser = parser.PolicyParser(
-                self.arch, kill_action=bpf.KillProcess())
+                self.arch, kill_action=bpf.KillProcess()
+            )
             parsed_policy = policy_parser.parse_file(policy_file.name)
             assert len(parsed_policy.filter_statements) == 1
             return self.compiler.compile_filter_statement(
                 parsed_policy.filter_statements[0],
-                kill_action=bpf.KillProcess())
+                kill_action=bpf.KillProcess(),
+            )
 
     def test_allow(self):
         """Accept lines where the syscall is accepted unconditionally."""
-        block = self._compile('read: allow')
+        block = self._compile("read: allow")
         self.assertEqual(block.filter, None)
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           1)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1)[1],
+            "ALLOW",
+        )
 
     def test_arg0_eq_generated_code(self):
         """Accept lines with an argument filter with ==."""
-        block = self._compile('read: arg0 == 0x100')
+        block = self._compile("read: arg0 == 0x100")
         # It might be a bit brittle to check the generated code in each test
         # case instead of just the behavior, but there should be at least one
         # test where this happens.
         self.assertEqual(
             block.filter.instructions,
             [
-                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
-                               bpf.arg_offset(0, True)),
+                bpf.SockFilter(
+                    bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS,
+                    0,
+                    0,
+                    bpf.arg_offset(0, True),
+                ),
                 # Jump to KILL_PROCESS if the high word does not match.
                 bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 0, 2, 0),
-                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
-                               bpf.arg_offset(0, False)),
+                bpf.SockFilter(
+                    bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS,
+                    0,
+                    0,
+                    bpf.arg_offset(0, False),
+                ),
                 # Jump to KILL_PROCESS if the low word does not match.
-                bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 1, 0,
-                               0x100),
-                bpf.SockFilter(bpf.BPF_RET, 0, 0,
-                               bpf.SECCOMP_RET_KILL_PROCESS),
+                bpf.SockFilter(
+                    bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 1, 0, 0x100
+                ),
+                bpf.SockFilter(bpf.BPF_RET, 0, 0, bpf.SECCOMP_RET_KILL_PROCESS),
                 bpf.SockFilter(bpf.BPF_RET, 0, 0, bpf.SECCOMP_RET_ALLOW),
-            ])
+            ],
+        )
 
     def test_arg0_comparison_operators(self):
         """Accept lines with an argument filter with comparison operators."""
@@ -94,217 +95,281 @@ class CompileFilterStatementTests(unittest.TestCase):
         # For each operator, store the expectations of simulating the program
         # against the constant plus each entry from the |biases| array.
         cases = (
-            ('==', ('KILL_PROCESS', 'ALLOW', 'KILL_PROCESS')),
-            ('!=', ('ALLOW', 'KILL_PROCESS', 'ALLOW')),
-            ('<', ('ALLOW', 'KILL_PROCESS', 'KILL_PROCESS')),
-            ('<=', ('ALLOW', 'ALLOW', 'KILL_PROCESS')),
-            ('>', ('KILL_PROCESS', 'KILL_PROCESS', 'ALLOW')),
-            ('>=', ('KILL_PROCESS', 'ALLOW', 'ALLOW')),
+            ("==", ("KILL_PROCESS", "ALLOW", "KILL_PROCESS")),
+            ("!=", ("ALLOW", "KILL_PROCESS", "ALLOW")),
+            ("<", ("ALLOW", "KILL_PROCESS", "KILL_PROCESS")),
+            ("<=", ("ALLOW", "ALLOW", "KILL_PROCESS")),
+            (">", ("KILL_PROCESS", "KILL_PROCESS", "ALLOW")),
+            (">=", ("KILL_PROCESS", "ALLOW", "ALLOW")),
         )
         for operator, expectations in cases:
-            block = self._compile('read: arg0 %s 0x100' % operator)
+            block = self._compile("read: arg0 %s 0x100" % operator)
 
             # Check the filter's behavior.
             for bias, expectation in zip(biases, expectations):
                 self.assertEqual(
-                    block.simulate(self.arch.arch_nr,
-                                   self.arch.syscalls['read'],
-                                   0x100 + bias)[1], expectation)
+                    block.simulate(
+                        self.arch.arch_nr,
+                        self.arch.syscalls["read"],
+                        0x100 + bias,
+                    )[1],
+                    expectation,
+                )
 
     def test_arg0_mask_operator(self):
         """Accept lines with an argument filter with &."""
-        block = self._compile('read: arg0 & 0x3')
+        block = self._compile("read: arg0 & 0x3")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           1)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           2)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 2)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           3)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 3)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           4)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 4)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           5)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 5)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           6)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 6)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           7)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 7)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           8)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 8)[1],
+            "KILL_PROCESS",
+        )
 
     def test_arg0_in_operator(self):
         """Accept lines with an argument filter with in."""
-        block = self._compile('read: arg0 in 0x3')
+        block = self._compile("read: arg0 in 0x3")
 
         # The 'in' operator only ensures that no bits outside the mask are set,
         # which means that 0 is always allowed.
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           1)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           2)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 2)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           3)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 3)[1],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           4)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 4)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           5)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 5)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           6)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 6)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           7)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 7)[1],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           8)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 8)[1],
+            "KILL_PROCESS",
+        )
 
     def test_arg0_short_gt_ge_comparisons(self):
         """Ensure that the short comparison optimization kicks in."""
         if self.arch.bits == 32:
             return
-        short_constant_str = '0xdeadbeef'
+        short_constant_str = "0xdeadbeef"
         short_constant = int(short_constant_str, base=0)
-        long_constant_str = '0xbadc0ffee0ddf00d'
+        long_constant_str = "0xbadc0ffee0ddf00d"
         long_constant = int(long_constant_str, base=0)
         biases = (-1, 0, 1)
         # For each operator, store the expectations of simulating the program
         # against the constant plus each entry from the |biases| array.
         cases = (
-            ('<', ('ALLOW', 'KILL_PROCESS', 'KILL_PROCESS')),
-            ('<=', ('ALLOW', 'ALLOW', 'KILL_PROCESS')),
-            ('>', ('KILL_PROCESS', 'KILL_PROCESS', 'ALLOW')),
-            ('>=', ('KILL_PROCESS', 'ALLOW', 'ALLOW')),
+            ("<", ("ALLOW", "KILL_PROCESS", "KILL_PROCESS")),
+            ("<=", ("ALLOW", "ALLOW", "KILL_PROCESS")),
+            (">", ("KILL_PROCESS", "KILL_PROCESS", "ALLOW")),
+            (">=", ("KILL_PROCESS", "ALLOW", "ALLOW")),
         )
         for operator, expectations in cases:
             short_block = self._compile(
-                'read: arg0 %s %s' % (operator, short_constant_str))
+                "read: arg0 %s %s" % (operator, short_constant_str)
+            )
             long_block = self._compile(
-                'read: arg0 %s %s' % (operator, long_constant_str))
+                "read: arg0 %s %s" % (operator, long_constant_str)
+            )
 
             # Check that the emitted code is shorter when the high word of the
             # constant is zero.
             self.assertLess(
                 len(short_block.filter.instructions),
-                len(long_block.filter.instructions))
+                len(long_block.filter.instructions),
+            )
 
             # Check the filter's behavior.
             for bias, expectation in zip(biases, expectations):
                 self.assertEqual(
-                    long_block.simulate(self.arch.arch_nr,
-                                        self.arch.syscalls['read'],
-                                        long_constant + bias)[1], expectation)
+                    long_block.simulate(
+                        self.arch.arch_nr,
+                        self.arch.syscalls["read"],
+                        long_constant + bias,
+                    )[1],
+                    expectation,
+                )
                 self.assertEqual(
                     short_block.simulate(
-                        self.arch.arch_nr, self.arch.syscalls['read'],
-                        short_constant + bias)[1], expectation)
+                        self.arch.arch_nr,
+                        self.arch.syscalls["read"],
+                        short_constant + bias,
+                    )[1],
+                    expectation,
+                )
 
     def test_and_or(self):
         """Accept lines with a complex expression in DNF."""
-        block = self._compile('read: arg0 == 0 && arg1 == 0 || arg0 == 1')
+        block = self._compile("read: arg0 == 0 && arg1 == 0 || arg0 == 1")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
-                           0)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0, 0)[
+                1
+            ],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
-                           1)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0, 1)[
+                1
+            ],
+            "KILL_PROCESS",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
-                           0)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1, 0)[
+                1
+            ],
+            "ALLOW",
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
-                           1)[1], 'ALLOW')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1, 1)[
+                1
+            ],
+            "ALLOW",
+        )
 
     def test_trap(self):
         """Accept lines that trap unconditionally."""
-        block = self._compile('read: trap')
+        block = self._compile("read: trap")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'TRAP')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "TRAP",
+        )
 
     def test_ret_errno(self):
         """Accept lines that return errno."""
-        block = self._compile('read : arg0 == 0 || arg0 == 1 ; return 1')
+        block = self._compile("read : arg0 == 0 || arg0 == 1 ; return 1")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1:], ('ERRNO', 1))
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[
+                1:
+            ],
+            ("ERRNO", 1),
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           1)[1:], ('ERRNO', 1))
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 1)[
+                1:
+            ],
+            ("ERRNO", 1),
+        )
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           2)[1], 'KILL_PROCESS')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 2)[1],
+            "KILL_PROCESS",
+        )
 
     def test_ret_errno_unconditionally(self):
         """Accept lines that return errno unconditionally."""
-        block = self._compile('read: return 1')
+        block = self._compile("read: return 1")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1:], ('ERRNO', 1))
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[
+                1:
+            ],
+            ("ERRNO", 1),
+        )
 
     def test_trace(self):
         """Accept lines that trace unconditionally."""
-        block = self._compile('read: trace')
+        block = self._compile("read: trace")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'TRACE')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "TRACE",
+        )
 
     def test_user_notify(self):
         """Accept lines that notify unconditionally."""
-        block = self._compile('read: user-notify')
+        block = self._compile("read: user-notify")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'USER_NOTIF')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "USER_NOTIF",
+        )
 
     def test_log(self):
         """Accept lines that log unconditionally."""
-        block = self._compile('read: log')
+        block = self._compile("read: log")
 
         self.assertEqual(
-            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
-                           0)[1], 'LOG')
+            block.simulate(self.arch.arch_nr, self.arch.syscalls["read"], 0)[1],
+            "LOG",
+        )
 
     def test_mmap_write_xor_exec(self):
         """Accept the idiomatic filter for mmap."""
         block = self._compile(
-            'read : arg0 in ~PROT_WRITE || arg0 in ~PROT_EXEC')
+            "read : arg0 in ~PROT_WRITE || arg0 in ~PROT_EXEC"
+        )
 
         prot_exec_and_write = 6
-        for prot in range(0, 0xf):
+        for prot in range(0, 0xF):
             if (prot & prot_exec_and_write) == prot_exec_and_write:
                 self.assertEqual(
-                    block.simulate(self.arch.arch_nr,
-                                   self.arch.syscalls['read'], prot)[1],
-                    'KILL_PROCESS')
+                    block.simulate(
+                        self.arch.arch_nr, self.arch.syscalls["read"], prot
+                    )[1],
+                    "KILL_PROCESS",
+                )
             else:
                 self.assertEqual(
-                    block.simulate(self.arch.arch_nr,
-                                   self.arch.syscalls['read'], prot)[1],
-                    'ALLOW')
+                    block.simulate(
+                        self.arch.arch_nr, self.arch.syscalls["read"], prot
+                    )[1],
+                    "ALLOW",
+                )
 
 
 class CompileFileTests(unittest.TestCase):
@@ -321,82 +386,129 @@ class CompileFileTests(unittest.TestCase):
     def _write_file(self, filename, contents):
         """Helper to write out a file for testing."""
         path = os.path.join(self.tempdir, filename)
-        with open(path, 'w') as outf:
+        with open(path, "w", encoding="utf-8") as outf:
             outf.write(contents)
         return path
 
     def test_compile(self):
         """Ensure compilation works with all strategies."""
         self._write_file(
-            'test.frequency', """
+            "test.frequency",
+            """
             read: 1
             close: 10
-        """)
+        """,
+        )
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @frequency ./test.frequency
             read: 1
             close: 1
-        """)
+        """,
+        )
 
         program = self.compiler.compile_file(
             path,
             optimization_strategy=compiler.OptimizationStrategy.LINEAR,
-            kill_action=bpf.KillProcess())
+            kill_action=bpf.KillProcess(),
+        )
         self.assertGreater(
-            bpf.simulate(program.instructions, self.arch.arch_nr,
-                         self.arch.syscalls['read'], 0)[0],
-            bpf.simulate(program.instructions, self.arch.arch_nr,
-                         self.arch.syscalls['close'], 0)[0],
+            bpf.simulate(
+                program.instructions,
+                self.arch.arch_nr,
+                self.arch.syscalls["read"],
+                0,
+            )[0],
+            bpf.simulate(
+                program.instructions,
+                self.arch.arch_nr,
+                self.arch.syscalls["close"],
+                0,
+            )[0],
         )
 
     def test_compile_bst(self):
         """Ensure compilation with BST is cheaper than the linear model."""
         self._write_file(
-            'test.frequency', """
+            "test.frequency",
+            """
             read: 1
             close: 10
-        """)
+        """,
+        )
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @frequency ./test.frequency
             read: 1
             close: 1
-        """)
+        """,
+        )
 
         for strategy in list(compiler.OptimizationStrategy):
             program = self.compiler.compile_file(
                 path,
                 optimization_strategy=strategy,
-                kill_action=bpf.KillProcess())
+                kill_action=bpf.KillProcess(),
+            )
             self.assertGreater(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls['read'], 0)[0],
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls['close'], 0)[0],
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls["read"],
+                    0,
+                )[0],
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls["close"],
+                    0,
+                )[0],
             )
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls['read'], 0)[1], 'ALLOW')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls["read"],
+                    0,
+                )[1],
+                "ALLOW",
+            )
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls['close'], 0)[1], 'ALLOW')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls["close"],
+                    0,
+                )[1],
+                "ALLOW",
+            )
 
     def test_compile_empty_file(self):
         """Accept empty files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @default kill-thread
-        """)
+        """,
+        )
 
         for strategy in list(compiler.OptimizationStrategy):
             program = self.compiler.compile_file(
                 path,
                 optimization_strategy=strategy,
-                kill_action=bpf.KillProcess())
+                kill_action=bpf.KillProcess(),
+            )
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls['read'], 0)[1], 'KILL_THREAD')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls["read"],
+                    0,
+                )[1],
+                "KILL_THREAD",
+            )
 
     def test_compile_simulate(self):
         """Ensure policy reflects script by testing some random scripts."""
@@ -405,35 +517,44 @@ class CompileFileTests(unittest.TestCase):
             num_entries = 64 * (i + 1) // iterations
             syscalls = dict(
                 zip(
-                    random.sample(
-                        list(self.arch.syscalls.keys()), num_entries),
+                    random.sample(list(self.arch.syscalls.keys()), num_entries),
                     (random.randint(1, 1024) for _ in range(num_entries)),
-                ))
+                )
+            )
 
-            frequency_contents = '\n'.join(
-                '%s: %d' % s for s in syscalls.items())
-            policy_contents = '@frequency ./test.frequency\n' + '\n'.join(
-                '%s: 1' % s[0] for s in syscalls.items())
+            frequency_contents = "\n".join(
+                "%s: %d" % s for s in syscalls.items()
+            )
+            policy_contents = "@frequency ./test.frequency\n" + "\n".join(
+                "%s: 1" % s[0] for s in syscalls.items()
+            )
 
-            self._write_file('test.frequency', frequency_contents)
-            path = self._write_file('test.policy', policy_contents)
+            self._write_file("test.frequency", frequency_contents)
+            path = self._write_file("test.policy", policy_contents)
 
             for strategy in list(compiler.OptimizationStrategy):
                 program = self.compiler.compile_file(
                     path,
                     optimization_strategy=strategy,
-                    kill_action=bpf.KillProcess())
+                    kill_action=bpf.KillProcess(),
+                )
                 for name, number in self.arch.syscalls.items():
-                    expected_result = ('ALLOW'
-                                       if name in syscalls else 'KILL_PROCESS')
+                    expected_result = (
+                        "ALLOW" if name in syscalls else "KILL_PROCESS"
+                    )
                     self.assertEqual(
-                        bpf.simulate(program.instructions, self.arch.arch_nr,
-                                     number, 0)[1], expected_result,
-                        ('syscall name: %s, syscall number: %d, '
-                         'strategy: %s, policy:\n%s') %
-                        (name, number, strategy, policy_contents))
-
-    @unittest.skipIf(not int(os.getenv('SLOW_TESTS', '0')), 'slow')
+                        bpf.simulate(
+                            program.instructions, self.arch.arch_nr, number, 0
+                        )[1],
+                        expected_result,
+                        (
+                            "syscall name: %s, syscall number: %d, "
+                            "strategy: %s, policy:\n%s"
+                        )
+                        % (name, number, strategy, policy_contents),
+                    )
+
+    @unittest.skipIf(not int(os.getenv("SLOW_TESTS", "0")), "slow")
     def test_compile_huge_policy(self):
         """Ensure jumps while compiling a huge policy are still valid."""
         # Given that the BST strategy is O(n^3), don't choose a crazy large
@@ -449,26 +570,37 @@ class CompileFileTests(unittest.TestCase):
         # Here we force every single filter to be distinct. Otherwise the
         # codegen layer will coalesce filters that compile to the same
         # instructions.
-        policy_contents = '\n'.join(
-            '%s: arg0 == %d' % s for s in syscalls.items())
+        policy_contents = "\n".join(
+            "%s: arg0 == %d" % s for s in syscalls.items()
+        )
 
-        path = self._write_file('test.policy', policy_contents)
+        path = self._write_file("test.policy", policy_contents)
 
         program = self.compiler.compile_file(
             path,
             optimization_strategy=compiler.OptimizationStrategy.BST,
-            kill_action=bpf.KillProcess())
+            kill_action=bpf.KillProcess(),
+        )
         for name, number in self.arch.syscalls.items():
-            expected_result = ('ALLOW'
-                               if name in syscalls else 'KILL_PROCESS')
+            expected_result = "ALLOW" if name in syscalls else "KILL_PROCESS"
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls[name], number)[1],
-                expected_result)
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls[name],
+                    number,
+                )[1],
+                expected_result,
+            )
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls[name], number + 1)[1],
-                'KILL_PROCESS')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls[name],
+                    number + 1,
+                )[1],
+                "KILL_PROCESS",
+            )
 
     def test_compile_huge_filter(self):
         """Ensure jumps while compiling a huge policy are still valid."""
@@ -481,30 +613,41 @@ class CompileFileTests(unittest.TestCase):
         # codegen layer will coalesce filters that compile to the same
         # instructions.
         policy_contents = []
-        for name in random.sample(
-            list(self.arch.syscalls.keys()), num_entries):
+        for name in random.sample(list(self.arch.syscalls.keys()), num_entries):
             values = random.sample(range(1024), num_entries)
             syscalls[name] = values
             policy_contents.append(
-                '%s: %s' % (name, ' || '.join('arg0 == %d' % value
-                                              for value in values)))
+                "%s: %s"
+                % (name, " || ".join("arg0 == %d" % value for value in values))
+            )
 
-        path = self._write_file('test.policy', '\n'.join(policy_contents))
+        path = self._write_file("test.policy", "\n".join(policy_contents))
 
         program = self.compiler.compile_file(
             path,
             optimization_strategy=compiler.OptimizationStrategy.LINEAR,
-            kill_action=bpf.KillProcess())
+            kill_action=bpf.KillProcess(),
+        )
         for name, values in syscalls.items():
             self.assertEqual(
-                bpf.simulate(program.instructions,
-                             self.arch.arch_nr, self.arch.syscalls[name],
-                             random.choice(values))[1], 'ALLOW')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls[name],
+                    random.choice(values),
+                )[1],
+                "ALLOW",
+            )
             self.assertEqual(
-                bpf.simulate(program.instructions, self.arch.arch_nr,
-                             self.arch.syscalls[name], 1025)[1],
-                'KILL_PROCESS')
+                bpf.simulate(
+                    program.instructions,
+                    self.arch.arch_nr,
+                    self.arch.syscalls[name],
+                    1025,
+                )[1],
+                "KILL_PROCESS",
+            )
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/tools/generate_constants_json.py b/tools/generate_constants_json.py
index 005fff8..02847bd 100755
--- a/tools/generate_constants_json.py
+++ b/tools/generate_constants_json.py
@@ -1,19 +1,8 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """Helper tool to generate cross-compiled syscall and constant tables to JSON.
 
 This script takes the LLVM IR of libconstants.gen.c and libsyscalls.gen.c and
@@ -27,17 +16,20 @@ import json
 import re
 import sys
 
+
 _STRING_CONSTANT_RE = re.compile(r'(@[a-zA-Z0-9.]+) = .*c"([^"\\]+)\\00".*')
 _TABLE_ENTRY_RE = re.compile(
-    r'%struct.(?:constant|syscall)_entry\s*{\s*([^}]+)\s*}')
+    r"%struct.(?:constant|syscall)_entry\s*{\s*([^}]+)\s*}"
+)
 # This looks something like
 #
 #  i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.5, i32 0, i32 0), i32 5
 #
 # For arm-v7a. What we are interested in are the @.str.x and the very last
 # number.
-_TABLE_ENTRY_CONTENTS = re.compile(r'.*?(null|@[a-zA-Z0-9.]+).* (-?\d+)')
+_TABLE_ENTRY_CONTENTS = re.compile(r".*?(null|@[a-zA-Z0-9.]+).* (-?\d+)")
 
+# pylint: disable=line-too-long
 # When testing clang-r458909, we found a new constant_entry pattern:
 #   %struct.constant_entry { ptr @.str.894, i32 ptrtoint (ptr @.str.895 to i32) },
 # For the same constant, current clang-r458507 generates:
@@ -51,12 +43,15 @@ _TABLE_ENTRY_CONTENTS = re.compile(r'.*?(null|@[a-zA-Z0-9.]+).* (-?\d+)')
 #   "FS_KEY_DESC_PREFIX": 0,
 # but that value does not seem to be useful or accurate.
 # So here we define a pattern to ignore such pointer constants:
-_IGNORED_ENTRY_CONTENTS = re.compile(r'.*? ptrto.* \(.*\)')
+# pylint: enable=line-too-long
+_IGNORED_ENTRY_CONTENTS = re.compile(r".*? ptrto.* \(.*\)")
 
-ParseResults = collections.namedtuple('ParseResults', ['table_name',
-                                                       'table_entries'])
+ParseResults = collections.namedtuple(
+    "ParseResults", ["table_name", "table_entries"]
+)
 
-HELP_EPILOG = """Generate LLVM IR: clang -S -emit-llvm libconstants.gen.c libsyscalls.gen.c
+HELP_EPILOG = """\
+Generate LLVM IR: clang -S -emit-llvm libconstants.gen.c libsyscalls.gen.c
 """
 
 
@@ -64,27 +59,28 @@ def parse_llvm_ir(ir):
     """Parses a single LLVM IR file."""
     string_constants = collections.OrderedDict()
     table_entries = collections.OrderedDict()
-    table_name = ''
+    table_name = ""
     for line in ir:
         string_constant_match = _STRING_CONSTANT_RE.match(line)
         if string_constant_match:
-            string_constants[string_constant_match.group(
-                1)] = string_constant_match.group(2)
+            string_constants[
+                string_constant_match.group(1)
+            ] = string_constant_match.group(2)
             continue
 
-        if '@syscall_table' in line or '@constant_table' in line:
-            if '@syscall_table' in line:
-                table_name = 'syscalls'
+        if "@syscall_table" in line or "@constant_table" in line:
+            if "@syscall_table" in line:
+                table_name = "syscalls"
             else:
-                table_name = 'constants'
+                table_name = "constants"
             for entry in _TABLE_ENTRY_RE.findall(line):
                 groups = _TABLE_ENTRY_CONTENTS.match(entry)
                 if not groups:
                     if _IGNORED_ENTRY_CONTENTS.match(entry):
                         continue
-                    raise ValueError('Failed to parse table entry %r' % entry)
+                    raise ValueError("Failed to parse table entry %r" % entry)
                 name, value = groups.groups()
-                if name == 'null':
+                if name == "null":
                     # This is the end-of-table marker.
                     break
                 table_entries[string_constants[name]] = int(value)
@@ -99,16 +95,19 @@ def main(argv=None):
         argv = sys.argv[1:]
 
     parser = argparse.ArgumentParser(description=__doc__, epilog=HELP_EPILOG)
-    parser.add_argument('--output',
-                        help='The path of the generated constants.json file.',
-                        type=argparse.FileType('w'),
-                        required=True)
     parser.add_argument(
-        'llvm_ir_files',
-        help='An LLVM IR file with one of the {constants,syscall} table.',
-        metavar='llvm_ir_file',
-        nargs='+',
-        type=argparse.FileType('r'))
+        "--output",
+        help="The path of the generated constants.json file.",
+        type=argparse.FileType("w"),
+        required=True,
+    )
+    parser.add_argument(
+        "llvm_ir_files",
+        help="An LLVM IR file with one of the {constants,syscall} table.",
+        metavar="llvm_ir_file",
+        nargs="+",
+        type=argparse.FileType("r"),
+    )
     opts = parser.parse_args(argv)
 
     constants_json = {}
@@ -117,28 +116,29 @@ def main(argv=None):
         constants_json[parse_results.table_name] = parse_results.table_entries
 
     # Populate the top-level fields.
-    constants_json['arch_nr'] = constants_json['constants']['MINIJAIL_ARCH_NR']
-    constants_json['bits'] = constants_json['constants']['MINIJAIL_ARCH_BITS']
+    constants_json["arch_nr"] = constants_json["constants"]["MINIJAIL_ARCH_NR"]
+    constants_json["bits"] = constants_json["constants"]["MINIJAIL_ARCH_BITS"]
 
     # It is a bit more complicated to generate the arch_name, since the
     # constants can only output numeric values. Use a hardcoded mapping instead.
-    if constants_json['arch_nr'] == 0xC000003E:
-        constants_json['arch_name'] = 'x86_64'
-    elif constants_json['arch_nr'] == 0x40000003:
-        constants_json['arch_name'] = 'x86'
-    elif constants_json['arch_nr'] == 0xC00000B7:
-        constants_json['arch_name'] = 'arm64'
-    elif constants_json['arch_nr'] == 0x40000028:
-        constants_json['arch_name'] = 'arm'
-    elif constants_json['arch_nr'] == 0xC00000F3:
-        constants_json['arch_name'] = 'riscv64'
+    if constants_json["arch_nr"] == 0xC000003E:
+        constants_json["arch_name"] = "x86_64"
+    elif constants_json["arch_nr"] == 0x40000003:
+        constants_json["arch_name"] = "x86"
+    elif constants_json["arch_nr"] == 0xC00000B7:
+        constants_json["arch_name"] = "arm64"
+    elif constants_json["arch_nr"] == 0x40000028:
+        constants_json["arch_name"] = "arm"
+    elif constants_json["arch_nr"] == 0xC00000F3:
+        constants_json["arch_name"] = "riscv64"
     else:
-        raise ValueError('Unknown architecture: 0x%08X' %
-                         constants_json['arch_nr'])
+        raise ValueError(
+            "Unknown architecture: 0x%08X" % constants_json["arch_nr"]
+        )
 
-    json.dump(constants_json, opts.output, indent='  ')
+    json.dump(constants_json, opts.output, indent="  ")
     return 0
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/generate_seccomp_policy.py b/tools/generate_seccomp_policy.py
index 3654123..597ac7d 100755
--- a/tools/generate_seccomp_policy.py
+++ b/tools/generate_seccomp_policy.py
@@ -1,33 +1,21 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2016 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 #
 # This script will take any number of trace files generated by strace(1)
 # and output a system call filtering policy suitable for use with Minijail.
 
 """Tool to generate a minijail seccomp filter from strace or audit output."""
 
-from __future__ import print_function
-
 import argparse
 import collections
+import datetime
 import os
 import re
 import sys
 
+
 # auparse may not be installed and is currently optional.
 try:
     import auparse
@@ -35,45 +23,51 @@ except ImportError:
     auparse = None
 
 
-NOTICE = """# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+YEAR = datetime.datetime.now().year
+NOTICE = f"""# Copyright {YEAR} The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 """
 
-ALLOW = '1'
+ALLOW = "1"
 
 # This ignores any leading PID tag and trailing <unfinished ...>, and extracts
 # the syscall name and the argument list.
-LINE_RE = re.compile(r'^\s*(?:\[[^]]*\]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)')
+LINE_RE = re.compile(r"^\s*(?:\[[^]]*\]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)")
 
 SOCKETCALLS = {
-    'accept', 'bind', 'connect', 'getpeername', 'getsockname', 'getsockopt',
-    'listen', 'recv', 'recvfrom', 'recvmsg', 'send', 'sendmsg', 'sendto',
-    'setsockopt', 'shutdown', 'socket', 'socketpair',
+    "accept",
+    "bind",
+    "connect",
+    "getpeername",
+    "getsockname",
+    "getsockopt",
+    "listen",
+    "recv",
+    "recvfrom",
+    "recvmsg",
+    "send",
+    "sendmsg",
+    "sendto",
+    "setsockopt",
+    "shutdown",
+    "socket",
+    "socketpair",
 }
 
 # List of private ARM syscalls. These can be found in any ARM specific unistd.h
 # such as Linux's arch/arm/include/uapi/asm/unistd.h.
 PRIVATE_ARM_SYSCALLS = {
-    983041: 'ARM_breakpoint',
-    983042: 'ARM_cacheflush',
-    983043: 'ARM_usr26',
-    983044: 'ARM_usr32',
-    983045: 'ARM_set_tls',
+    983041: "ARM_breakpoint",
+    983042: "ARM_cacheflush",
+    983043: "ARM_usr26",
+    983044: "ARM_usr32",
+    983045: "ARM_set_tls",
 }
 
-ArgInspectionEntry = collections.namedtuple('ArgInspectionEntry',
-                                            ('arg_index', 'value_set'))
+ArgInspectionEntry = collections.namedtuple(
+    "ArgInspectionEntry", ("arg_index", "value_set")
+)
 
 
 # pylint: disable=too-few-public-methods
@@ -81,20 +75,21 @@ class BucketInputFiles(argparse.Action):
     """Buckets input files using simple content based heuristics.
 
     Attributes:
-      audit_logs: Mutually exclusive list of audit log filenames.
-      traces: Mutually exclusive list of strace log filenames.
+        audit_logs: Mutually exclusive list of audit log filenames.
+        traces: Mutually exclusive list of strace log filenames.
     """
+
     def __call__(self, parser, namespace, values, option_string=None):
         audit_logs = []
         traces = []
 
-        strace_line_re = re.compile(r'[a-z]+[0-9]*\(.+\) += ')
-        audit_line_re = re.compile(r'type=(SYSCALL|SECCOMP)')
+        strace_line_re = re.compile(r"[a-z]+[0-9]*\(.+\) += ")
+        audit_line_re = re.compile(r"type=(SYSCALL|SECCOMP)")
 
         for filename in values:
             if not os.path.exists(filename):
-                parser.error(f'Input file {filename} not found.')
-            with open(filename, mode='r', encoding='utf8') as input_file:
+                parser.error(f"Input file {filename} not found.")
+            with open(filename, mode="r", encoding="utf-8") as input_file:
                 for line in input_file.readlines():
                     if strace_line_re.search(line):
                         traces.append(filename)
@@ -107,39 +102,63 @@ class BucketInputFiles(argparse.Action):
                     # also just in case the strace regex is imperfect.
                     traces.append(filename)
 
-        setattr(namespace, 'audit_logs', audit_logs)
-        setattr(namespace, 'traces', traces)
+        setattr(namespace, "audit_logs", audit_logs)
+        setattr(namespace, "traces", traces)
+
+
 # pylint: enable=too-few-public-methods
 
 
 def parse_args(argv):
     """Returns the parsed CLI arguments for this tool."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--verbose', action='store_true',
-                        help='output informational messages to stderr')
-    parser.add_argument('--frequency', type=argparse.FileType('w'),
-                        help='frequency file')
-    parser.add_argument('--policy', type=argparse.FileType('w'),
-                        default=sys.stdout, help='policy file')
-    parser.add_argument('input-logs', action=BucketInputFiles,
-                        help='strace and/or audit logs', nargs='+')
-    parser.add_argument('--audit-comm', type=str, metavar='PROCESS_NAME',
-                        help='relevant process name from the audit.log files')
+    parser.add_argument(
+        "--verbose",
+        action="store_true",
+        help="output informational messages to stderr",
+    )
+    parser.add_argument(
+        "--frequency", type=argparse.FileType("w"), help="frequency file"
+    )
+    parser.add_argument(
+        "--policy",
+        type=argparse.FileType("w"),
+        default=sys.stdout,
+        help="policy file",
+    )
+    parser.add_argument(
+        "input-logs",
+        action=BucketInputFiles,
+        help="strace and/or audit logs",
+        nargs="+",
+    )
+    parser.add_argument(
+        "--audit-comm",
+        type=str,
+        metavar="PROCESS_NAME",
+        help="relevant process name from the audit.log files",
+    )
     opts = parser.parse_args(argv)
 
     if opts.audit_logs and not auparse:
-        parser.error('Python bindings for the audit subsystem were not found.\n'
-                     'Please install the python3-audit (sometimes python-audit)'
-                     ' package for your distro to process audit logs: '
-                     f'{opts.audit_logs}')
+        parser.error(
+            "Python bindings for the audit subsystem were not found.\n"
+            "Please install the python3-audit (sometimes python-audit)"
+            " package for your distro to process audit logs: "
+            f"{opts.audit_logs}"
+        )
 
     if opts.audit_logs and not opts.audit_comm:
-        parser.error(f'--audit-comm is required when using audit logs as input:'
-                     f' {opts.audit_logs}')
+        parser.error(
+            f"--audit-comm is required when using audit logs as input:"
+            f" {opts.audit_logs}"
+        )
 
     if not opts.audit_logs and opts.audit_comm:
-        parser.error('--audit-comm was specified yet none of the input files '
-                     'matched our hueristic for an audit log')
+        parser.error(
+            "--audit-comm was specified yet none of the input files "
+            "matched our hueristic for an audit log"
+        )
 
     return opts
 
@@ -149,29 +168,30 @@ def get_seccomp_bpf_filter(syscall, entry):
     arg_index = entry.arg_index
     arg_values = entry.value_set
     atoms = []
-    if syscall in ('mmap', 'mmap2', 'mprotect') and arg_index == 2:
+    if syscall in ("mmap", "mmap2", "mprotect") and arg_index == 2:
         # See if there is at least one instance of any of these syscalls trying
         # to map memory with both PROT_EXEC and PROT_WRITE. If there isn't, we
         # can craft a concise expression to forbid this.
-        write_and_exec = set(('PROT_EXEC', 'PROT_WRITE'))
+        write_and_exec = set(("PROT_EXEC", "PROT_WRITE"))
         for arg_value in arg_values:
-            if write_and_exec.issubset(set(p.strip() for p in
-                                           arg_value.split('|'))):
+            if write_and_exec.issubset(
+                set(p.strip() for p in arg_value.split("|"))
+            ):
                 break
         else:
-            atoms.extend(['arg2 in ~PROT_EXEC', 'arg2 in ~PROT_WRITE'])
+            atoms.extend(["arg2 in ~PROT_EXEC", "arg2 in ~PROT_WRITE"])
             arg_values = set()
-    atoms.extend(f'arg{arg_index} == {arg_value}' for arg_value in arg_values)
-    return ' || '.join(atoms)
+    atoms.extend(f"arg{arg_index} == {arg_value}" for arg_value in arg_values)
+    return " || ".join(atoms)
 
 
 def parse_trace_file(trace_filename, syscalls, arg_inspection):
     """Parses one file produced by strace."""
-    uses_socketcall = ('i386' in trace_filename or
-                       ('x86' in trace_filename and
-                        '64' not in trace_filename))
+    uses_socketcall = "i386" in trace_filename or (
+        "x86" in trace_filename and "64" not in trace_filename
+    )
 
-    with open(trace_filename, encoding='utf8') as trace_file:
+    with open(trace_filename, encoding="utf-8") as trace_file:
         for line in trace_file:
             matches = LINE_RE.match(line)
             if not matches:
@@ -179,18 +199,18 @@ def parse_trace_file(trace_filename, syscalls, arg_inspection):
 
             syscall, args = matches.groups()
             if uses_socketcall and syscall in SOCKETCALLS:
-                syscall = 'socketcall'
+                syscall = "socketcall"
 
             # strace omits the 'ARM_' prefix on all private ARM syscalls. Add
             # it manually here as a workaround. These syscalls are exclusive
             # to ARM so we don't need to predicate this on a trace_filename
             # based heuristic for the arch.
-            if f'ARM_{syscall}' in PRIVATE_ARM_SYSCALLS.values():
-                syscall = f'ARM_{syscall}'
+            if f"ARM_{syscall}" in PRIVATE_ARM_SYSCALLS.values():
+                syscall = f"ARM_{syscall}"
 
             syscalls[syscall] += 1
 
-            args = [arg.strip() for arg in args.split(',')]
+            args = [arg.strip() for arg in args.split(",")]
 
             if syscall in arg_inspection:
                 arg_value = args[arg_inspection[syscall].arg_index]
@@ -200,20 +220,21 @@ def parse_trace_file(trace_filename, syscalls, arg_inspection):
 def parse_audit_log(audit_log, audit_comm, syscalls, arg_inspection):
     """Parses one audit.log file generated by the Linux audit subsystem."""
 
-    unknown_syscall_re = re.compile(r'unknown-syscall\((?P<syscall_num>\d+)\)')
+    unknown_syscall_re = re.compile(r"unknown-syscall\((?P<syscall_num>\d+)\)")
 
     au = auparse.AuParser(auparse.AUSOURCE_FILE, audit_log)
     # Quick validity check for whether this parses as a valid audit log. The
     # first event should have at least one record.
     if not au.first_record():
-        raise ValueError(f'Unable to parse audit log file {audit_log.name}')
+        raise ValueError(f"Unable to parse audit log file {audit_log.name}")
 
     # Iterate through events where _any_ contained record matches
     # ((type == SECCOMP || type == SYSCALL) && comm == audit_comm).
-    au.search_add_item('type', '=', 'SECCOMP', auparse.AUSEARCH_RULE_CLEAR)
-    au.search_add_item('type', '=', 'SYSCALL', auparse.AUSEARCH_RULE_OR)
-    au.search_add_item('comm', '=', f'"{audit_comm}"',
-                       auparse.AUSEARCH_RULE_AND)
+    au.search_add_item("type", "=", "SECCOMP", auparse.AUSEARCH_RULE_CLEAR)
+    au.search_add_item("type", "=", "SYSCALL", auparse.AUSEARCH_RULE_OR)
+    au.search_add_item(
+        "comm", "=", f'"{audit_comm}"', auparse.AUSEARCH_RULE_AND
+    )
 
     # auparse_find_field(3) will ignore preceding fields in the record and
     # at the same time happily cross record boundaries when looking for the
@@ -234,18 +255,22 @@ def parse_audit_log(audit_log, audit_comm, syscalls, arg_inspection):
         # The event may have multiple records. Loop through all.
         au.first_record()
         for _ in range(au.get_num_records()):
-            event_type = _find_field_in_current_record('type')
-            comm = _find_field_in_current_record('comm')
+            event_type = _find_field_in_current_record("type")
+            comm = _find_field_in_current_record("comm")
             # Some of the records in this event may not be relevant
             # despite the event-specific search filter. Skip those.
-            if (event_type not in ('SECCOMP', 'SYSCALL') or
-                    comm != f'"{audit_comm}"'):
+            if (
+                event_type not in ("SECCOMP", "SYSCALL")
+                or comm != f'"{audit_comm}"'
+            ):
                 au.next_record()
                 continue
 
-            if not _find_field_in_current_record('syscall'):
-                raise ValueError(f'Could not find field "syscall" in event of '
-                                 f'type {event_type}')
+            if not _find_field_in_current_record("syscall"):
+                raise ValueError(
+                    f'Could not find field "syscall" in event of '
+                    f"type {event_type}"
+                )
             # Intepret the syscall field that's under our 'cursor' following the
             # find. Interpreting fields yields human friendly names instead
             # of integers. E.g '16' -> 'ioctl'.
@@ -257,11 +282,12 @@ def parse_audit_log(audit_log, audit_comm, syscalls, arg_inspection):
             # disjoint set of private syscall numbers.
             match = unknown_syscall_re.match(syscall)
             if match:
-                syscall_num = int(match.group('syscall_num'))
+                syscall_num = int(match.group("syscall_num"))
                 syscall = PRIVATE_ARM_SYSCALLS.get(syscall_num, syscall)
 
-            if ((syscall in arg_inspection and event_type == 'SECCOMP') or
-                (syscall not in arg_inspection and event_type == 'SYSCALL')):
+            if (syscall in arg_inspection and event_type == "SECCOMP") or (
+                syscall not in arg_inspection and event_type == "SYSCALL"
+            ):
                 # Skip SECCOMP records for syscalls that require argument
                 # inspection. Similarly, skip SYSCALL records for syscalls
                 # that do not require argument inspection. Technically such
@@ -269,11 +295,13 @@ def parse_audit_log(audit_log, audit_comm, syscalls, arg_inspection):
                 # sometimes lets a few records slip through.
                 au.next_record()
                 continue
-            elif event_type == 'SYSCALL':
-                arg_field_name = f'a{arg_inspection[syscall].arg_index}'
+            elif event_type == "SYSCALL":
+                arg_field_name = f"a{arg_inspection[syscall].arg_index}"
                 if not _find_field_in_current_record(arg_field_name):
-                    raise ValueError(f'Could not find field "{arg_field_name}"'
-                                     f'in event of type {event_type}')
+                    raise ValueError(
+                        f'Could not find field "{arg_field_name}"'
+                        f"in event of type {event_type}"
+                    )
                 # Intepret the arg field that's under our 'cursor' following the
                 # find. This may yield a more human friendly name.
                 # E.g '5401' -> 'TCGETS'.
@@ -294,21 +322,23 @@ def main(argv=None):
     syscalls = collections.defaultdict(int)
 
     arg_inspection = {
-        'socket': ArgInspectionEntry(0, set([])),   # int domain
-        'ioctl': ArgInspectionEntry(1, set([])),    # int request
-        'prctl': ArgInspectionEntry(0, set([])),    # int option
-        'mmap': ArgInspectionEntry(2, set([])),     # int prot
-        'mmap2': ArgInspectionEntry(2, set([])),    # int prot
-        'mprotect': ArgInspectionEntry(2, set([])), # int prot
+        "socket": ArgInspectionEntry(0, set([])),  # int domain
+        "ioctl": ArgInspectionEntry(1, set([])),  # int request
+        "prctl": ArgInspectionEntry(0, set([])),  # int option
+        "mmap": ArgInspectionEntry(2, set([])),  # int prot
+        "mmap2": ArgInspectionEntry(2, set([])),  # int prot
+        "mprotect": ArgInspectionEntry(2, set([])),  # int prot
     }
 
     if opts.verbose:
-        # Print an informational message to stderr in case the filetype detection
-        # heuristics are wonky.
-        print('Generating a seccomp policy using these input files:',
-              file=sys.stderr)
-        print(f'Strace logs: {opts.traces}', file=sys.stderr)
-        print(f'Audit logs: {opts.audit_logs}', file=sys.stderr)
+        # Print an informational message to stderr in case the filetype
+        # detection heuristics are wonky.
+        print(
+            "Generating a seccomp policy using these input files:",
+            file=sys.stderr,
+        )
+        print(f"Strace logs: {opts.traces}", file=sys.stderr)
+        print(f"Audit logs: {opts.audit_logs}", file=sys.stderr)
 
     for trace_filename in opts.traces:
         parse_trace_file(trace_filename, syscalls, arg_inspection)
@@ -318,7 +348,10 @@ def main(argv=None):
 
     # Add the basic set if they are not yet present.
     basic_set = [
-        'restart_syscall', 'exit', 'exit_group', 'rt_sigreturn',
+        "restart_syscall",
+        "exit",
+        "exit_group",
+        "rt_sigreturn",
     ]
     for basic_syscall in basic_set:
         if basic_syscall not in syscalls:
@@ -331,8 +364,10 @@ def main(argv=None):
     # list).
     if opts.frequency is None:
         sorted_syscalls = list(
-            x[0] for x in sorted(syscalls.items(), key=lambda pair: pair[1],
-                                 reverse=True)
+            x[0]
+            for x in sorted(
+                syscalls.items(), key=lambda pair: pair[1], reverse=True
+            )
         )
     else:
         sorted_syscalls = list(
@@ -345,14 +380,15 @@ def main(argv=None):
 
     for syscall in sorted_syscalls:
         if syscall in arg_inspection:
-            arg_filter = get_seccomp_bpf_filter(syscall,
-                                                arg_inspection[syscall])
+            arg_filter = get_seccomp_bpf_filter(
+                syscall, arg_inspection[syscall]
+            )
         else:
             arg_filter = ALLOW
-        print(f'{syscall}: {arg_filter}', file=opts.policy)
+        print(f"{syscall}: {arg_filter}", file=opts.policy)
         if opts.frequency is not None:
-            print(f'{syscall}: {syscalls[syscall]}', file=opts.frequency)
+            print(f"{syscall}: {syscalls[syscall]}", file=opts.frequency)
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/parser.py b/tools/parser.py
index 87e1493..626f5c9 100644
--- a/tools/parser.py
+++ b/tools/parser.py
@@ -1,30 +1,15 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""A parser for the Minijail policy file."""
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 
-from __future__ import absolute_import
-from __future__ import division
-from __future__ import print_function
+"""A parser for the Minijail policy file."""
 
 import collections
 import itertools
 import os.path
 import re
 
+
 try:
     import bpf
 except ImportError:
@@ -32,63 +17,62 @@ except ImportError:
 
 
 # Representations of numbers with different radix (base) in C.
-HEX_REGEX = r'-?0[xX][0-9a-fA-F]+'
-OCTAL_REGEX = r'-?0[0-7]+'
-DECIMAL_REGEX = r'-?[0-9]+'
+HEX_REGEX = r"-?0[xX][0-9a-fA-F]+"
+OCTAL_REGEX = r"-?0[0-7]+"
+DECIMAL_REGEX = r"-?[0-9]+"
 
 
 Token = collections.namedtuple(
-    'Token', ['type', 'value', 'filename', 'line', 'line_number', 'column'])
+    "Token", ["type", "value", "filename", "line", "line_number", "column"]
+)
 
 # A regex that can tokenize a Minijail policy file line.
 _TOKEN_SPECIFICATION = (
-    ('COMMENT', r'#.*$'),
-    ('WHITESPACE', r'\s+'),
-    ('CONTINUATION', r'\\$'),
-    ('DEFAULT', r'@default\b'),
-    ('INCLUDE', r'@include\b'),
-    ('FREQUENCY', r'@frequency\b'),
-    ('DENYLIST', r'@denylist$'),
-    ('PATH', r'(?:\.)?/\S+'),
-    ('NUMERIC_CONSTANT', f'{HEX_REGEX}|{OCTAL_REGEX}|{DECIMAL_REGEX}'),
-    ('COLON', r':'),
-    ('SEMICOLON', r';'),
-    ('COMMA', r','),
-    ('BITWISE_COMPLEMENT', r'~'),
-    ('LPAREN', r'\('),
-    ('RPAREN', r'\)'),
-    ('LBRACE', r'\{'),
-    ('RBRACE', r'\}'),
-    ('RBRACKET', r'\]'),
-    ('LBRACKET', r'\['),
-    ('OR', r'\|\|'),
-    ('AND', r'&&'),
-    ('BITWISE_OR', r'\|'),
-    ('OP', r'&|\bin\b|==|!=|<=|<|>=|>'),
-    ('EQUAL', r'='),
-    ('ARGUMENT', r'\barg[0-9]+\b'),
-    ('RETURN', r'\breturn\b'),
-    ('ACTION',
-     r'\ballow\b|\bkill-process\b|\bkill-thread\b|\bkill\b|\btrap\b|'
-     r'\btrace\b|\blog\b|\buser-notify\b'
+    ("COMMENT", r"#.*$"),
+    ("WHITESPACE", r"\s+"),
+    ("CONTINUATION", r"\\$"),
+    ("DEFAULT", r"@default\b"),
+    ("INCLUDE", r"@include\b"),
+    ("FREQUENCY", r"@frequency\b"),
+    ("DENYLIST", r"@denylist$"),
+    ("PATH", r"(?:\.)?/\S+"),
+    ("NUMERIC_CONSTANT", f"{HEX_REGEX}|{OCTAL_REGEX}|{DECIMAL_REGEX}"),
+    ("COLON", r":"),
+    ("SEMICOLON", r";"),
+    ("COMMA", r","),
+    ("BITWISE_COMPLEMENT", r"~"),
+    ("LPAREN", r"\("),
+    ("RPAREN", r"\)"),
+    ("LBRACE", r"\{"),
+    ("RBRACE", r"\}"),
+    ("RBRACKET", r"\]"),
+    ("LBRACKET", r"\["),
+    ("OR", r"\|\|"),
+    ("AND", r"&&"),
+    ("BITWISE_OR", r"\|"),
+    ("OP", r"&|\bin\b|==|!=|<=|<|>=|>"),
+    ("EQUAL", r"="),
+    ("ARGUMENT", r"\barg[0-9]+\b"),
+    ("RETURN", r"\breturn\b"),
+    (
+        "ACTION",
+        r"\ballow\b|\bkill-process\b|\bkill-thread\b|\bkill\b|\btrap\b|"
+        r"\btrace\b|\blog\b|\buser-notify\b",
     ),
-    ('IDENTIFIER', r'[a-zA-Z_][a-zA-Z_0-9-@]*'),
+    ("IDENTIFIER", r"[a-zA-Z_][a-zA-Z_0-9-@]*"),
+)
+_TOKEN_RE = re.compile(
+    "|".join(r"(?P<%s>%s)" % pair for pair in _TOKEN_SPECIFICATION)
 )
-_TOKEN_RE = re.compile('|'.join(
-    r'(?P<%s>%s)' % pair for pair in _TOKEN_SPECIFICATION))
 
 
 class ParseException(Exception):
     """An exception that is raised when parsing fails."""
 
     # pylint: disable=too-many-arguments
-    def __init__(self,
-                 message,
-                 filename,
-                 *,
-                 line='',
-                 line_number=1,
-                 token=None):
+    def __init__(
+        self, message, filename, *, line="", line_number=1, token=None
+    ):
         if token:
             line = token.line
             line_number = token.line_number
@@ -98,10 +82,14 @@ class ParseException(Exception):
             column = len(line)
             length = 1
 
-        message = ('%s(%d:%d): %s') % (filename, line_number, column + 1,
-                                       message)
-        message += '\n    %s' % line
-        message += '\n    %s%s' % (' ' * column, '^' * length)
+        message = ("%s(%d:%d): %s") % (
+            filename,
+            line_number,
+            column + 1,
+            message,
+        )
+        message += "\n    %s" % line
+        message += "\n    %s%s" % (" " * column, "^" * length)
         super().__init__(message)
 
 
@@ -110,7 +98,7 @@ class ParserState:
 
     def __init__(self, filename):
         self._filename = filename
-        self._line = ''
+        self._line = ""
         self._line_number = 0
 
     @property
@@ -135,7 +123,8 @@ class ParserState:
             self.filename,
             line=self._line,
             line_number=self._line_number,
-            token=token)
+            token=token,
+        )
 
     def tokenize(self, lines):
         """Return a list of tokens for the current line."""
@@ -143,35 +132,52 @@ class ParserState:
 
         for line_number, line in enumerate(lines):
             self._line_number = line_number + 1
-            self._line = line.rstrip('\r\n')
+            self._line = line.rstrip("\r\n")
 
             last_end = 0
             for token in _TOKEN_RE.finditer(self._line):
                 if token.start() != last_end:
                     self.error(
-                        'invalid token',
-                        token=Token('INVALID',
-                                    self._line[last_end:token.start()],
-                                    self.filename, self._line,
-                                    self._line_number, last_end))
+                        "invalid token",
+                        token=Token(
+                            "INVALID",
+                            self._line[last_end : token.start()],
+                            self.filename,
+                            self._line,
+                            self._line_number,
+                            last_end,
+                        ),
+                    )
                 last_end = token.end()
 
-                # Omit whitespace and comments now to avoid sprinkling this logic
-                # elsewhere.
-                if token.lastgroup in ('WHITESPACE', 'COMMENT',
-                                       'CONTINUATION'):
+                # Omit whitespace and comments now to avoid sprinkling this
+                # logic elsewhere.
+                if token.lastgroup in ("WHITESPACE", "COMMENT", "CONTINUATION"):
                     continue
                 tokens.append(
-                    Token(token.lastgroup, token.group(), self.filename,
-                          self._line, self._line_number, token.start()))
+                    Token(
+                        token.lastgroup,
+                        token.group(),
+                        self.filename,
+                        self._line,
+                        self._line_number,
+                        token.start(),
+                    )
+                )
             if last_end != len(self._line):
                 self.error(
-                    'invalid token',
-                    token=Token('INVALID', self._line[last_end:],
-                                self.filename, self._line, self._line_number,
-                                last_end))
-
-            if self._line.endswith('\\'):
+                    "invalid token",
+                    token=Token(
+                        "INVALID",
+                        self._line[last_end:],
+                        self.filename,
+                        self._line,
+                        self._line_number,
+                        last_end,
+                    ),
+                )
+
+            if self._line.endswith("\\"):
                 # This line is not finished yet.
                 continue
 
@@ -182,10 +188,10 @@ class ParserState:
             tokens.clear()
 
 
-Atom = collections.namedtuple('Atom', ['argument_index', 'op', 'value'])
+Atom = collections.namedtuple("Atom", ["argument_index", "op", "value"])
 """A single boolean comparison within a filter expression."""
 
-Filter = collections.namedtuple('Filter', ['expression', 'action'])
+Filter = collections.namedtuple("Filter", ["expression", "action"])
 """The result of parsing a DNF filter expression, with its action.
 
 Since the expression is in Disjunctive Normal Form, it is composed of two levels
@@ -193,27 +199,30 @@ of lists, one for disjunctions and the inner one for conjunctions. The elements
 of the inner list are Atoms.
 """
 
-Syscall = collections.namedtuple('Syscall', ['name', 'number'])
+Syscall = collections.namedtuple("Syscall", ["name", "number"])
 """A system call."""
 
 ParsedFilterStatement = collections.namedtuple(
-    'ParsedFilterStatement', ['syscalls', 'filters', 'token'])
+    "ParsedFilterStatement", ["syscalls", "filters", "token"]
+)
 """The result of parsing a filter statement.
 
 Statements have a list of syscalls, and an associated list of filters that will
 be evaluated sequentially when any of the syscalls is invoked.
 """
 
-FilterStatement = collections.namedtuple('FilterStatement',
-                                         ['syscall', 'frequency', 'filters'])
+FilterStatement = collections.namedtuple(
+    "FilterStatement", ["syscall", "frequency", "filters"]
+)
 """The filter list for a particular syscall.
 
 This is a mapping from one syscall to a list of filters that are evaluated
 sequentially. The last filter is always an unconditional action.
 """
 
-ParsedPolicy = collections.namedtuple('ParsedPolicy',
-                                      ['default_action', 'filter_statements'])
+ParsedPolicy = collections.namedtuple(
+    "ParsedPolicy", ["default_action", "filter_statements"]
+)
 """The result of parsing a minijail .policy file."""
 
 
@@ -221,14 +230,16 @@ ParsedPolicy = collections.namedtuple('ParsedPolicy',
 class PolicyParser:
     """A parser for the Minijail seccomp policy file format."""
 
-    def __init__(self,
-                 arch,
-                 *,
-                 kill_action,
-                 include_depth_limit=10,
-                 override_default_action=None,
-                 denylist=False,
-                 ret_log=False):
+    def __init__(
+        self,
+        arch,
+        *,
+        kill_action,
+        include_depth_limit=10,
+        override_default_action=None,
+        denylist=False,
+        ret_log=False,
+    ):
         self._parser_states = [ParserState("<memory>")]
         self._kill_action = kill_action
         self._include_depth_limit = include_depth_limit
@@ -250,11 +261,11 @@ class PolicyParser:
     #                 | numeric-constant
     #                 ;
     def _parse_single_constant(self, token):
-        if token.type == 'IDENTIFIER':
+        if token.type == "IDENTIFIER":
             if token.value not in self._arch.constants:
-                self._parser_state.error('invalid constant', token=token)
+                self._parser_state.error("invalid constant", token=token)
             single_constant = self._arch.constants[token.value]
-        elif token.type == 'NUMERIC_CONSTANT':
+        elif token.type == "NUMERIC_CONSTANT":
             # As `int(_, 0)` in Python != `strtol(_, _, 0)` in C, to make sure
             # the number parsing behaves exactly in C, instead of using `int()`
             # directly, we list out all the possible formats for octal, decimal
@@ -271,13 +282,13 @@ class PolicyParser:
                     raise ValueError
                 single_constant = int(token.value, base=base)
             except ValueError:
-                self._parser_state.error('invalid constant', token=token)
+                self._parser_state.error("invalid constant", token=token)
         else:
-            self._parser_state.error('invalid constant', token=token)
+            self._parser_state.error("invalid constant", token=token)
         if single_constant > self._arch.max_unsigned:
-            self._parser_state.error('unsigned overflow', token=token)
+            self._parser_state.error("unsigned overflow", token=token)
         elif single_constant < self._arch.min_signed:
-            self._parser_state.error('signed underflow', token=token)
+            self._parser_state.error("signed underflow", token=token)
         elif single_constant < 0:
             # This converts the constant to an unsigned representation of the
             # same value, since BPF only uses unsigned values.
@@ -289,20 +300,22 @@ class PolicyParser:
     #          ;
     def _parse_constant(self, tokens):
         negate = False
-        if tokens[0].type == 'BITWISE_COMPLEMENT':
+        if tokens[0].type == "BITWISE_COMPLEMENT":
             negate = True
             tokens.pop(0)
             if not tokens:
-                self._parser_state.error('empty complement')
-            if tokens[0].type == 'BITWISE_COMPLEMENT':
+                self._parser_state.error("empty complement")
+            if tokens[0].type == "BITWISE_COMPLEMENT":
                 self._parser_state.error(
-                    'invalid double complement', token=tokens[0])
-        if tokens[0].type == 'LPAREN':
+                    "invalid double complement", token=tokens[0]
+                )
+        if tokens[0].type == "LPAREN":
             last_open_paren = tokens.pop(0)
             single_value = self.parse_value(tokens)
-            if not tokens or tokens[0].type != 'RPAREN':
+            if not tokens or tokens[0].type != "RPAREN":
                 self._parser_state.error(
-                    'unclosed parenthesis', token=last_open_paren)
+                    "unclosed parenthesis", token=last_open_paren
+                )
         else:
             single_value = self._parse_single_constant(tokens[0])
         tokens.pop(0)
@@ -332,32 +345,32 @@ class PolicyParser:
         value = 0
         while tokens:
             value |= self._parse_constant(tokens)
-            if not tokens or tokens[0].type != 'BITWISE_OR':
+            if not tokens or tokens[0].type != "BITWISE_OR":
                 break
             tokens.pop(0)
         else:
-            self._parser_state.error('empty constant')
+            self._parser_state.error("empty constant")
         return value
 
     # atom = argument , op , value
     #      ;
     def _parse_atom(self, tokens):
         if not tokens:
-            self._parser_state.error('missing argument')
+            self._parser_state.error("missing argument")
         argument = tokens.pop(0)
-        if argument.type != 'ARGUMENT':
-            self._parser_state.error('invalid argument', token=argument)
+        if argument.type != "ARGUMENT":
+            self._parser_state.error("invalid argument", token=argument)
 
         if not tokens:
-            self._parser_state.error('missing operator')
+            self._parser_state.error("missing operator")
         operator = tokens.pop(0)
-        if operator.type != 'OP':
-            self._parser_state.error('invalid operator', token=operator)
+        if operator.type != "OP":
+            self._parser_state.error("invalid operator", token=operator)
 
         value = self.parse_value(tokens)
         argument_index = int(argument.value[3:])
-        if not (0 <= argument_index < bpf.MAX_SYSCALL_ARGUMENTS):
-            self._parser_state.error('invalid argument', token=argument)
+        if not 0 <= argument_index < bpf.MAX_SYSCALL_ARGUMENTS:
+            self._parser_state.error("invalid argument", token=argument)
         return Atom(argument_index, operator.value, value)
 
     # clause = atom , [ { '&&' , atom } ]
@@ -366,11 +379,11 @@ class PolicyParser:
         atoms = []
         while tokens:
             atoms.append(self._parse_atom(tokens))
-            if not tokens or tokens[0].type != 'AND':
+            if not tokens or tokens[0].type != "AND":
                 break
             tokens.pop(0)
         else:
-            self._parser_state.error('empty clause')
+            self._parser_state.error("empty clause")
         return atoms
 
     # argument-expression = clause , [ { '||' , clause } ]
@@ -386,11 +399,11 @@ class PolicyParser:
         clauses = []
         while tokens:
             clauses.append(self._parse_clause(tokens))
-            if not tokens or tokens[0].type != 'OR':
+            if not tokens or tokens[0].type != "OR":
                 break
             tokens.pop(0)
         else:
-            self._parser_state.error('empty argument expression')
+            self._parser_state.error("empty argument expression")
         return clauses
 
     # default-action = 'kill-process'
@@ -401,23 +414,25 @@ class PolicyParser:
     #                ;
     def _parse_default_action(self, tokens):
         if not tokens:
-            self._parser_state.error('missing default action')
+            self._parser_state.error("missing default action")
         action_token = tokens.pop(0)
-        if action_token.type != 'ACTION':
+        if action_token.type != "ACTION":
             return self._parser_state.error(
-                'invalid default action', token=action_token)
-        if action_token.value == 'kill-process':
+                "invalid default action", token=action_token
+            )
+        if action_token.value == "kill-process":
             return bpf.KillProcess()
-        if action_token.value == 'kill-thread':
+        if action_token.value == "kill-thread":
             return bpf.KillThread()
-        if action_token.value == 'kill':
+        if action_token.value == "kill":
             return self._kill_action
-        if action_token.value == 'trap':
+        if action_token.value == "trap":
             return bpf.Trap()
-        if action_token.value == 'user-notify':
+        if action_token.value == "user-notify":
             return bpf.UserNotify()
         return self._parser_state.error(
-            'invalid permissive default action', token=action_token)
+            "invalid permissive default action", token=action_token
+        )
 
     # action = 'allow' | '1'
     #        | 'kill-process'
@@ -431,43 +446,45 @@ class PolicyParser:
     #        ;
     def parse_action(self, tokens):
         if not tokens:
-            self._parser_state.error('missing action')
+            self._parser_state.error("missing action")
         action_token = tokens.pop(0)
         # denylist policies must specify a return for every line.
         if self._denylist:
-            if action_token.type != 'RETURN':
-                self._parser_state.error('invalid denylist policy')
+            if action_token.type != "RETURN":
+                self._parser_state.error("invalid denylist policy")
 
-        if action_token.type == 'ACTION':
-            if action_token.value == 'allow':
+        if action_token.type == "ACTION":
+            if action_token.value == "allow":
                 return bpf.Allow()
-            if action_token.value == 'kill':
+            if action_token.value == "kill":
                 return self._kill_action
-            if action_token.value == 'kill-process':
+            if action_token.value == "kill-process":
                 return bpf.KillProcess()
-            if action_token.value == 'kill-thread':
+            if action_token.value == "kill-thread":
                 return bpf.KillThread()
-            if action_token.value == 'trap':
+            if action_token.value == "trap":
                 return bpf.Trap()
-            if action_token.value == 'trace':
+            if action_token.value == "trace":
                 return bpf.Trace()
-            if action_token.value == 'user-notify':
+            if action_token.value == "user-notify":
                 return bpf.UserNotify()
-            if action_token.value == 'log':
+            if action_token.value == "log":
                 return bpf.Log()
-        elif action_token.type == 'NUMERIC_CONSTANT':
+        elif action_token.type == "NUMERIC_CONSTANT":
             constant = self._parse_single_constant(action_token)
             if constant == 1:
                 return bpf.Allow()
-        elif action_token.type == 'RETURN':
+        elif action_token.type == "RETURN":
             if not tokens:
-                self._parser_state.error('missing return value')
+                self._parser_state.error("missing return value")
             if self._ret_log:
                 tokens.pop(0)
                 return bpf.Log()
             else:
-                return bpf.ReturnErrno(self._parse_single_constant(tokens.pop(0)))
-        return self._parser_state.error('invalid action', token=action_token)
+                return bpf.ReturnErrno(
+                    self._parse_single_constant(tokens.pop(0))
+                )
+        return self._parser_state.error("invalid action", token=action_token)
 
     # single-filter = action
     #               | argument-expression , [ ';' , action ]
@@ -475,11 +492,11 @@ class PolicyParser:
     #               ;
     def _parse_single_filter(self, tokens):
         if not tokens:
-            self._parser_state.error('missing filter')
-        if tokens[0].type == 'ARGUMENT':
-	    # Only argument expressions can start with an ARGUMENT token.
+            self._parser_state.error("missing filter")
+        if tokens[0].type == "ARGUMENT":
+            # Only argument expressions can start with an ARGUMENT token.
             argument_expression = self.parse_argument_expression(tokens)
-            if tokens and tokens[0].type == 'SEMICOLON':
+            if tokens and tokens[0].type == "SEMICOLON":
                 tokens.pop(0)
                 action = self.parse_action(tokens)
             else:
@@ -494,17 +511,17 @@ class PolicyParser:
     def parse_filter(self, tokens):
         """Parse a filter and return a list of Filter objects."""
         if not tokens:
-            self._parser_state.error('missing filter')
+            self._parser_state.error("missing filter")
         filters = []
-        if tokens[0].type == 'LBRACE':
+        if tokens[0].type == "LBRACE":
             opening_brace = tokens.pop(0)
             while tokens:
                 filters.append(self._parse_single_filter(tokens))
-                if not tokens or tokens[0].type != 'COMMA':
+                if not tokens or tokens[0].type != "COMMA":
                     break
                 tokens.pop(0)
-            if not tokens or tokens[0].type != 'RBRACE':
-                self._parser_state.error('unclosed brace', token=opening_brace)
+            if not tokens or tokens[0].type != "RBRACE":
+                self._parser_state.error("unclosed brace", token=opening_brace)
             tokens.pop(0)
         else:
             filters.append(self._parse_single_filter(tokens))
@@ -514,50 +531,52 @@ class PolicyParser:
     #                ;
     def _parse_key_value_pair(self, tokens):
         if not tokens:
-            self._parser_state.error('missing key')
+            self._parser_state.error("missing key")
         key = tokens.pop(0)
-        if key.type != 'IDENTIFIER':
-            self._parser_state.error('invalid key', token=key)
+        if key.type != "IDENTIFIER":
+            self._parser_state.error("invalid key", token=key)
         if not tokens:
-            self._parser_state.error('missing equal')
-        if tokens[0].type != 'EQUAL':
-            self._parser_state.error('invalid equal', token=tokens[0])
+            self._parser_state.error("missing equal")
+        if tokens[0].type != "EQUAL":
+            self._parser_state.error("invalid equal", token=tokens[0])
         tokens.pop(0)
         value_list = []
         while tokens:
             value = tokens.pop(0)
-            if value.type != 'IDENTIFIER':
-                self._parser_state.error('invalid value', token=value)
+            if value.type != "IDENTIFIER":
+                self._parser_state.error("invalid value", token=value)
             value_list.append(value.value)
-            if not tokens or tokens[0].type != 'COMMA':
+            if not tokens or tokens[0].type != "COMMA":
                 break
             tokens.pop(0)
         else:
-            self._parser_state.error('empty value')
+            self._parser_state.error("empty value")
         return (key.value, value_list)
 
     # metadata = '[' , key-value-pair , [ { ';' , key-value-pair } ] , ']'
     #          ;
     def _parse_metadata(self, tokens):
         if not tokens:
-            self._parser_state.error('missing opening bracket')
+            self._parser_state.error("missing opening bracket")
         opening_bracket = tokens.pop(0)
-        if opening_bracket.type != 'LBRACKET':
+        if opening_bracket.type != "LBRACKET":
             self._parser_state.error(
-                'invalid opening bracket', token=opening_bracket)
+                "invalid opening bracket", token=opening_bracket
+            )
         metadata = {}
         while tokens:
             first_token = tokens[0]
             key, value = self._parse_key_value_pair(tokens)
             if key in metadata:
                 self._parser_state.error(
-                    'duplicate metadata key: "%s"' % key, token=first_token)
+                    'duplicate metadata key: "%s"' % key, token=first_token
+                )
             metadata[key] = value
-            if not tokens or tokens[0].type != 'SEMICOLON':
+            if not tokens or tokens[0].type != "SEMICOLON":
                 break
             tokens.pop(0)
-        if not tokens or tokens[0].type != 'RBRACKET':
-            self._parser_state.error('unclosed bracket', token=opening_bracket)
+        if not tokens or tokens[0].type != "RBRACKET":
+            self._parser_state.error("unclosed bracket", token=opening_bracket)
         tokens.pop(0)
         return metadata
 
@@ -566,68 +585,87 @@ class PolicyParser:
     #                    ;
     def _parse_syscall_descriptor(self, tokens):
         if not tokens:
-            self._parser_state.error('missing syscall descriptor')
+            self._parser_state.error("missing syscall descriptor")
         syscall_descriptor = tokens.pop(0)
         # `kill` as a syscall name is a special case since kill is also a valid
         # action and actions have precendence over identifiers.
-        if (syscall_descriptor.type != 'IDENTIFIER' and
-            syscall_descriptor.value != 'kill'):
+        if (
+            syscall_descriptor.type != "IDENTIFIER"
+            and syscall_descriptor.value != "kill"
+        ):
             self._parser_state.error(
-                'invalid syscall descriptor', token=syscall_descriptor)
-        if tokens and tokens[0].type == 'LBRACKET':
+                "invalid syscall descriptor", token=syscall_descriptor
+            )
+        if tokens and tokens[0].type == "LBRACKET":
             metadata = self._parse_metadata(tokens)
-            if 'arch' in metadata and self._arch.arch_name not in metadata['arch']:
+            if (
+                "arch" in metadata
+                and self._arch.arch_name not in metadata["arch"]
+            ):
                 return ()
-        if '@' in syscall_descriptor.value:
+        if "@" in syscall_descriptor.value:
             # This is a syscall group.
-            subtokens = syscall_descriptor.value.split('@')
+            subtokens = syscall_descriptor.value.split("@")
             if len(subtokens) != 2:
                 self._parser_state.error(
-                    'invalid syscall group name', token=syscall_descriptor)
+                    "invalid syscall group name", token=syscall_descriptor
+                )
             syscall_group_name, syscall_namespace_name = subtokens
             if syscall_namespace_name not in self._arch.syscall_groups:
                 self._parser_state.error(
-                    'nonexistent syscall group namespace',
-                    token=syscall_descriptor)
+                    "nonexistent syscall group namespace",
+                    token=syscall_descriptor,
+                )
             syscall_namespace = self._arch.syscall_groups[
-                syscall_namespace_name]
+                syscall_namespace_name
+            ]
             if syscall_group_name not in syscall_namespace:
                 self._parser_state.error(
-                    'nonexistent syscall group', token=syscall_descriptor)
-            return (Syscall(name, self._arch.syscalls[name])
-                    for name in syscall_namespace[syscall_group_name])
+                    "nonexistent syscall group", token=syscall_descriptor
+                )
+            return (
+                Syscall(name, self._arch.syscalls[name])
+                for name in syscall_namespace[syscall_group_name]
+            )
         if syscall_descriptor.value not in self._arch.syscalls:
             self._parser_state.error(
-                'nonexistent syscall', token=syscall_descriptor)
-        return (Syscall(syscall_descriptor.value,
-                        self._arch.syscalls[syscall_descriptor.value]), )
-
-    # filter-statement = '{' , syscall-descriptor , [ { ',', syscall-descriptor } ] , '}' ,
-    #                       ':' , filter
-    #                  | syscall-descriptor , ':' , filter
-    #                  ;
+                "nonexistent syscall", token=syscall_descriptor
+            )
+        return (
+            Syscall(
+                syscall_descriptor.value,
+                self._arch.syscalls[syscall_descriptor.value],
+            ),
+        )
+
+    # filter-statement =
+    #     '{' , syscall-descriptor , [ { ',', syscall-descriptor } ] , '}' ,
+    #         ':' , filter
+    #   | syscall-descriptor , ':' , filter
+    #   ;
     def parse_filter_statement(self, tokens):
         """Parse a filter statement and return a ParsedFilterStatement."""
         if not tokens:
-            self._parser_state.error('empty filter statement')
+            self._parser_state.error("empty filter statement")
         syscall_descriptors = []
-        if tokens[0].type == 'LBRACE':
+        if tokens[0].type == "LBRACE":
             opening_brace = tokens.pop(0)
             while tokens:
                 syscall_descriptors.extend(
-                    self._parse_syscall_descriptor(tokens))
-                if not tokens or tokens[0].type != 'COMMA':
+                    self._parse_syscall_descriptor(tokens)
+                )
+                if not tokens or tokens[0].type != "COMMA":
                     break
                 tokens.pop(0)
-            if not tokens or tokens[0].type != 'RBRACE':
-                self._parser_state.error('unclosed brace', token=opening_brace)
+            if not tokens or tokens[0].type != "RBRACE":
+                self._parser_state.error("unclosed brace", token=opening_brace)
             tokens.pop(0)
         else:
             syscall_descriptors.extend(self._parse_syscall_descriptor(tokens))
         if not tokens:
-            self._parser_state.error('missing colon')
-        if tokens[0].type != 'COLON':
-            self._parser_state.error('invalid colon', token=tokens[0])
+            self._parser_state.error("missing colon")
+        if tokens[0].type != "COLON":
+            self._parser_state.error("invalid colon", token=tokens[0])
         # Given that there can be multiple syscalls and filters in a single
         # filter statement, use the colon token as the anchor for error location
         # purposes.
@@ -636,57 +674,58 @@ class PolicyParser:
         if not syscall_descriptors:
             return None
         return ParsedFilterStatement(
-            tuple(syscall_descriptors), parsed_filter, colon_token)
+            tuple(syscall_descriptors), parsed_filter, colon_token
+        )
 
     # include-statement = '@include' , posix-path
     #                   ;
     def _parse_include_statement(self, tokens):
         if not tokens:
-            self._parser_state.error('empty filter statement')
-        if tokens[0].type != 'INCLUDE':
-            self._parser_state.error('invalid include', token=tokens[0])
+            self._parser_state.error("empty filter statement")
+        if tokens[0].type != "INCLUDE":
+            self._parser_state.error("invalid include", token=tokens[0])
         tokens.pop(0)
         if not tokens:
-            self._parser_state.error('empty include path')
+            self._parser_state.error("empty include path")
         include_path = tokens.pop(0)
-        if include_path.type != 'PATH':
-            self._parser_state.error(
-                'invalid include path', token=include_path)
+        if include_path.type != "PATH":
+            self._parser_state.error("invalid include path", token=include_path)
         if len(self._parser_states) == self._include_depth_limit:
-            self._parser_state.error('@include statement nested too deep')
+            self._parser_state.error("@include statement nested too deep")
         include_filename = os.path.normpath(
             os.path.join(
-                os.path.dirname(self._parser_state.filename),
-                include_path.value))
+                os.path.dirname(self._parser_state.filename), include_path.value
+            )
+        )
         if not os.path.isfile(include_filename):
             self._parser_state.error(
-                'Could not @include %s' % include_filename, token=include_path)
+                "Could not @include %s" % include_filename, token=include_path
+            )
         return self._parse_policy_file(include_filename)
 
     def _parse_frequency_file(self, filename):
         self._parser_states.append(ParserState(filename))
         try:
             frequency_mapping = collections.defaultdict(int)
-            with open(filename) as frequency_file:
+            with open(filename, encoding="utf-8") as frequency_file:
                 for tokens in self._parser_state.tokenize(frequency_file):
                     syscall_numbers = self._parse_syscall_descriptor(tokens)
                     if not tokens:
-                        self._parser_state.error('missing colon')
-                    if tokens[0].type != 'COLON':
+                        self._parser_state.error("missing colon")
+                    if tokens[0].type != "COLON":
                         self._parser_state.error(
-                            'invalid colon', token=tokens[0])
+                            "invalid colon", token=tokens[0]
+                        )
                     tokens.pop(0)
 
                     if not tokens:
-                        self._parser_state.error('missing number')
+                        self._parser_state.error("missing number")
                     number = tokens.pop(0)
-                    if number.type != 'NUMERIC_CONSTANT':
-                        self._parser_state.error(
-                            'invalid number', token=number)
+                    if number.type != "NUMERIC_CONSTANT":
+                        self._parser_state.error("invalid number", token=number)
                     number_value = int(number.value, base=0)
                     if number_value < 0:
-                        self._parser_state.error(
-                            'invalid number', token=number)
+                        self._parser_state.error("invalid number", token=number)
 
                     for syscall_number in syscall_numbers:
                         frequency_mapping[syscall_number] += number_value
@@ -698,36 +737,40 @@ class PolicyParser:
     #                      ;
     def _parse_frequency_statement(self, tokens):
         if not tokens:
-            self._parser_state.error('empty frequency statement')
-        if tokens[0].type != 'FREQUENCY':
-            self._parser_state.error('invalid frequency', token=tokens[0])
+            self._parser_state.error("empty frequency statement")
+        if tokens[0].type != "FREQUENCY":
+            self._parser_state.error("invalid frequency", token=tokens[0])
         tokens.pop(0)
         if not tokens:
-            self._parser_state.error('empty frequency path')
+            self._parser_state.error("empty frequency path")
         frequency_path = tokens.pop(0)
-        if frequency_path.type != 'PATH':
+        if frequency_path.type != "PATH":
             self._parser_state.error(
-                'invalid frequency path', token=frequency_path)
+                "invalid frequency path", token=frequency_path
+            )
         frequency_filename = os.path.normpath(
             os.path.join(
                 os.path.dirname(self._parser_state.filename),
-                frequency_path.value))
+                frequency_path.value,
+            )
+        )
         if not os.path.isfile(frequency_filename):
             self._parser_state.error(
-                'Could not open frequency file %s' % frequency_filename,
-                token=frequency_path)
+                "Could not open frequency file %s" % frequency_filename,
+                token=frequency_path,
+            )
         return self._parse_frequency_file(frequency_filename)
 
     # default-statement = '@default' , default-action
     #                   ;
     def _parse_default_statement(self, tokens):
         if not tokens:
-            self._parser_state.error('empty default statement')
-        if tokens[0].type != 'DEFAULT':
-            self._parser_state.error('invalid default', token=tokens[0])
+            self._parser_state.error("empty default statement")
+        if tokens[0].type != "DEFAULT":
+            self._parser_state.error("invalid default", token=tokens[0])
         tokens.pop(0)
         if not tokens:
-            self._parser_state.error('empty action')
+            self._parser_state.error("empty action")
         return self._parse_default_action(tokens)
 
     def _parse_policy_file(self, filename):
@@ -735,25 +778,28 @@ class PolicyParser:
         try:
             statements = []
             denylist_header = False
-            with open(filename) as policy_file:
+            with open(filename, encoding="utf-8") as policy_file:
                 for tokens in self._parser_state.tokenize(policy_file):
-                    if tokens[0].type == 'INCLUDE':
-                        statements.extend(
-                            self._parse_include_statement(tokens))
-                    elif tokens[0].type == 'FREQUENCY':
-                        for syscall_number, frequency in self._parse_frequency_statement(
-                                tokens).items():
-                            self._frequency_mapping[
-                                syscall_number] += frequency
-                    elif tokens[0].type == 'DEFAULT':
+                    if tokens[0].type == "INCLUDE":
+                        statements.extend(self._parse_include_statement(tokens))
+                    elif tokens[0].type == "FREQUENCY":
+                        for (
+                            syscall_number,
+                            frequency,
+                        ) in self._parse_frequency_statement(tokens).items():
+                            self._frequency_mapping[syscall_number] += frequency
+                    elif tokens[0].type == "DEFAULT":
                         self._default_action = self._parse_default_statement(
-                            tokens)
-                    elif tokens[0].type == 'DENYLIST':
+                            tokens
+                        )
+                    elif tokens[0].type == "DENYLIST":
                         tokens.pop()
                         if not self._denylist:
-                            self._parser_state.error('policy is denylist, but '
-                                                     'flag --denylist not '
-                                                     'passed in.')
+                            self._parser_state.error(
+                                "policy is denylist, but "
+                                "flag --denylist not "
+                                "passed in."
+                            )
                         else:
                             denylist_header = True
                     else:
@@ -766,10 +812,13 @@ class PolicyParser:
 
                     if tokens:
                         self._parser_state.error(
-                            'extra tokens', token=tokens[0])
+                            "extra tokens", token=tokens[0]
+                        )
             if self._denylist and not denylist_header:
-                self._parser_state.error('policy must contain @denylist flag to'
-                                         ' be compiled with --denylist flag.')
+                self._parser_state.error(
+                    "policy must contain @denylist flag to"
+                    " be compiled with --denylist flag."
+                )
             return statements
         finally:
             self._parser_states.pop()
@@ -778,12 +827,13 @@ class PolicyParser:
         """Parse a file and return the list of FilterStatements."""
         self._frequency_mapping = collections.defaultdict(int)
         try:
-            statements = [x for x in self._parse_policy_file(filename)]
+            statements = self._parse_policy_file(filename)
         except RecursionError:
             raise ParseException(
-                'recursion limit exceeded',
+                "recursion limit exceeded",
                 filename,
-                line=self._parser_states[-1].line)
+                line=self._parser_states[-1].line,
+            )
 
         # Collapse statements into a single syscall-to-filter-list, remembering
         # the token for each filter for better diagnostics.
@@ -795,8 +845,9 @@ class PolicyParser:
                 if syscall not in syscall_filter_mapping:
                     filter_statements.append(
                         FilterStatement(
-                            syscall, self._frequency_mapping.get(syscall, 1),
-                            []))
+                            syscall, self._frequency_mapping.get(syscall, 1), []
+                        )
+                    )
                     syscall_filter_mapping[syscall] = filter_statements[-1]
                     syscall_filter_definitions[syscall] = []
                 for filt in filters:
@@ -805,30 +856,40 @@ class PolicyParser:
         default_action = self._override_default_action or self._default_action
         for filter_statement in filter_statements:
             unconditional_actions_suffix = list(
-                itertools.dropwhile(lambda filt: filt.expression is not None,
-                                    filter_statement.filters))
+                itertools.dropwhile(
+                    lambda filt: filt.expression is not None,
+                    filter_statement.filters,
+                )
+            )
             if len(unconditional_actions_suffix) == 1:
                 # The last filter already has an unconditional action, no need
                 # to add another one.
                 continue
             if len(unconditional_actions_suffix) > 1:
                 previous_definition_token = syscall_filter_definitions[
-                    filter_statement.syscall][
-                        -len(unconditional_actions_suffix)]
+                    filter_statement.syscall
+                ][-len(unconditional_actions_suffix)]
                 current_definition_token = syscall_filter_definitions[
-                    filter_statement.syscall][
-                        -len(unconditional_actions_suffix) + 1]
+                    filter_statement.syscall
+                ][-len(unconditional_actions_suffix) + 1]
                 raise ParseException(
-                    ('Syscall %s (number %d) already had '
-                     'an unconditional action applied') %
-                    (filter_statement.syscall.name,
-                     filter_statement.syscall.number),
+                    (
+                        "Syscall %s (number %d) already had "
+                        "an unconditional action applied"
+                    )
+                    % (
+                        filter_statement.syscall.name,
+                        filter_statement.syscall.number,
+                    ),
                     filename=current_definition_token.filename,
-                    token=current_definition_token) from ParseException(
-                        'Previous definition',
-                        filename=previous_definition_token.filename,
-                        token=previous_definition_token)
+                    token=current_definition_token,
+                ) from ParseException(
+                    "Previous definition",
+                    filename=previous_definition_token.filename,
+                    token=previous_definition_token,
+                )
             assert not unconditional_actions_suffix
             filter_statement.filters.append(
-                Filter(expression=None, action=default_action))
+                Filter(expression=None, action=default_action)
+            )
         return ParsedPolicy(default_action, filter_statements)
diff --git a/tools/parser_unittest.py b/tools/parser_unittest.py
index 5e7c8a2..31b4099 100755
--- a/tools/parser_unittest.py
+++ b/tools/parser_unittest.py
@@ -1,26 +1,12 @@
 #!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-#
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Unittests for the parser module."""
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
 
-from __future__ import absolute_import
-from __future__ import division
-from __future__ import print_function
+"""Unittests for the parser module."""
 
 import os
+import parser  # pylint: disable=wrong-import-order
 import shutil
 import tempfile
 import unittest
@@ -28,7 +14,7 @@ from importlib import resources
 
 import arch
 import bpf
-import parser  # pylint: disable=wrong-import-order
+
 
 ARCH_64 = arch.Arch.load_from_json_bytes(
     resources.files("testdata").joinpath("arch_64.json").read_bytes()
@@ -40,71 +26,95 @@ class TokenizerTests(unittest.TestCase):
 
     @staticmethod
     def _tokenize(line):
-        parser_state = parser.ParserState('<memory>')
+        parser_state = parser.ParserState("<memory>")
         return list(parser_state.tokenize([line]))[0]
 
     def test_tokenize(self):
         """Accept valid tokens."""
-        self.assertEqual([
-            (token.type, token.value)
-            for token in TokenizerTests._tokenize('@include /minijail.policy')
-        ], [
-            ('INCLUDE', '@include'),
-            ('PATH', '/minijail.policy'),
-        ])
-        self.assertEqual([
-            (token.type, token.value)
-            for token in TokenizerTests._tokenize('@include ./minijail.policy')
-        ], [
-            ('INCLUDE', '@include'),
-            ('PATH', './minijail.policy'),
-        ])
         self.assertEqual(
-            [(token.type, token.value) for token in TokenizerTests._tokenize(
-                'read: arg0 in ~0xffff || arg0 & (1|2) && arg0 == 0755; '
-                'return ENOSYS # ignored')], [
-                    ('IDENTIFIER', 'read'),
-                    ('COLON', ':'),
-                    ('ARGUMENT', 'arg0'),
-                    ('OP', 'in'),
-                    ('BITWISE_COMPLEMENT', '~'),
-                    ('NUMERIC_CONSTANT', '0xffff'),
-                    ('OR', '||'),
-                    ('ARGUMENT', 'arg0'),
-                    ('OP', '&'),
-                    ('LPAREN', '('),
-                    ('NUMERIC_CONSTANT', '1'),
-                    ('BITWISE_OR', '|'),
-                    ('NUMERIC_CONSTANT', '2'),
-                    ('RPAREN', ')'),
-                    ('AND', '&&'),
-                    ('ARGUMENT', 'arg0'),
-                    ('OP', '=='),
-                    ('NUMERIC_CONSTANT', '0755'),
-                    ('SEMICOLON', ';'),
-                    ('RETURN', 'return'),
-                    ('IDENTIFIER', 'ENOSYS'),
-                ])
+            [
+                (token.type, token.value)
+                for token in TokenizerTests._tokenize(
+                    "@include /minijail.policy"
+                )
+            ],
+            [
+                ("INCLUDE", "@include"),
+                ("PATH", "/minijail.policy"),
+            ],
+        )
+        self.assertEqual(
+            [
+                (token.type, token.value)
+                for token in TokenizerTests._tokenize(
+                    "@include ./minijail.policy"
+                )
+            ],
+            [
+                ("INCLUDE", "@include"),
+                ("PATH", "./minijail.policy"),
+            ],
+        )
+        self.assertEqual(
+            [
+                (token.type, token.value)
+                for token in TokenizerTests._tokenize(
+                    "read: arg0 in ~0xffff || arg0 & (1|2) && arg0 == 0755; "
+                    "return ENOSYS # ignored"
+                )
+            ],
+            [
+                ("IDENTIFIER", "read"),
+                ("COLON", ":"),
+                ("ARGUMENT", "arg0"),
+                ("OP", "in"),
+                ("BITWISE_COMPLEMENT", "~"),
+                ("NUMERIC_CONSTANT", "0xffff"),
+                ("OR", "||"),
+                ("ARGUMENT", "arg0"),
+                ("OP", "&"),
+                ("LPAREN", "("),
+                ("NUMERIC_CONSTANT", "1"),
+                ("BITWISE_OR", "|"),
+                ("NUMERIC_CONSTANT", "2"),
+                ("RPAREN", ")"),
+                ("AND", "&&"),
+                ("ARGUMENT", "arg0"),
+                ("OP", "=="),
+                ("NUMERIC_CONSTANT", "0755"),
+                ("SEMICOLON", ";"),
+                ("RETURN", "return"),
+                ("IDENTIFIER", "ENOSYS"),
+            ],
+        )
         # Ensure that tokens that have an otherwise valid token as prefix are
         # still matched correctly.
-        self.assertEqual([
-            (token.type, token.value)
-            for token in TokenizerTests._tokenize(
-                'inotify_wait return_sys killall trace_sys')
-        ], [
-            ('IDENTIFIER', 'inotify_wait'),
-            ('IDENTIFIER', 'return_sys'),
-            ('IDENTIFIER', 'killall'),
-            ('IDENTIFIER', 'trace_sys'),
-        ])
+        self.assertEqual(
+            [
+                (token.type, token.value)
+                for token in TokenizerTests._tokenize(
+                    "inotify_wait return_sys killall trace_sys"
+                )
+            ],
+            [
+                ("IDENTIFIER", "inotify_wait"),
+                ("IDENTIFIER", "return_sys"),
+                ("IDENTIFIER", "killall"),
+                ("IDENTIFIER", "trace_sys"),
+            ],
+        )
 
     def test_tokenize_invalid_token(self):
         """Reject tokenizer errors."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    (r'<memory>\(1:1\): invalid token\n'
-                                     r'    %invalid-token%\n'
-                                     r'    \^')):
-            TokenizerTests._tokenize('%invalid-token%')
+        with self.assertRaisesRegex(
+            parser.ParseException,
+            (
+                r"<memory>\(1:1\): invalid token\n"
+                r"    %invalid-token%\n"
+                r"    \^"
+            ),
+        ):
+            TokenizerTests._tokenize("%invalid-token%")
 
 
 class ParseConstantTests(unittest.TestCase):
@@ -113,7 +123,8 @@ class ParseConstantTests(unittest.TestCase):
     def setUp(self):
         self.arch = ARCH_64
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=bpf.KillProcess())
+            self.arch, kill_action=bpf.KillProcess()
+        )
 
     def _tokenize(self, line):
         # pylint: disable=protected-access
@@ -122,62 +133,67 @@ class ParseConstantTests(unittest.TestCase):
     def test_parse_constant_unsigned(self):
         """Accept reasonably-sized unsigned constants."""
         self.assertEqual(
-            self.parser.parse_value(self._tokenize('0x80000000')), 0x80000000)
+            self.parser.parse_value(self._tokenize("0x80000000")), 0x80000000
+        )
         if self.arch.bits == 64:
             self.assertEqual(
-                self.parser.parse_value(self._tokenize('0x8000000000000000')),
-                0x8000000000000000)
+                self.parser.parse_value(self._tokenize("0x8000000000000000")),
+                0x8000000000000000,
+            )
 
     def test_parse_constant_unsigned_too_big(self):
         """Reject unreasonably-sized unsigned constants."""
         if self.arch.bits == 32:
-            with self.assertRaisesRegex(parser.ParseException,
-                                        'unsigned overflow'):
-                self.parser.parse_value(self._tokenize('0x100000000'))
-        with self.assertRaisesRegex(parser.ParseException,
-                                    'unsigned overflow'):
-            self.parser.parse_value(self._tokenize('0x10000000000000000'))
+            with self.assertRaisesRegex(
+                parser.ParseException, "unsigned overflow"
+            ):
+                self.parser.parse_value(self._tokenize("0x100000000"))
+        with self.assertRaisesRegex(parser.ParseException, "unsigned overflow"):
+            self.parser.parse_value(self._tokenize("0x10000000000000000"))
 
     def test_parse_constant_signed(self):
         """Accept reasonably-sized signed constants."""
         self.assertEqual(
-            self.parser.parse_value(self._tokenize('-1')),
-            self.arch.max_unsigned)
+            self.parser.parse_value(self._tokenize("-1")),
+            self.arch.max_unsigned,
+        )
 
     def test_parse_constant_signed_too_negative(self):
         """Reject unreasonably-sized signed constants."""
         if self.arch.bits == 32:
-            with self.assertRaisesRegex(parser.ParseException,
-                                        'signed underflow'):
-                self.parser.parse_value(self._tokenize('-0x800000001'))
-        with self.assertRaisesRegex(parser.ParseException, 'signed underflow'):
-            self.parser.parse_value(self._tokenize('-0x8000000000000001'))
+            with self.assertRaisesRegex(
+                parser.ParseException, "signed underflow"
+            ):
+                self.parser.parse_value(self._tokenize("-0x800000001"))
+        with self.assertRaisesRegex(parser.ParseException, "signed underflow"):
+            self.parser.parse_value(self._tokenize("-0x8000000000000001"))
 
     def test_parse_mask(self):
         """Accept parsing a mask value."""
         self.assertEqual(
-            self.parser.parse_value(self._tokenize('0x1|0x2|0x4|0x8')), 0xf)
+            self.parser.parse_value(self._tokenize("0x1|0x2|0x4|0x8")), 0xF
+        )
 
     def test_parse_parenthesized_expressions(self):
         """Accept parsing parenthesized expressions."""
         bad_expressions = [
-            '(1',
-            '|(1)',
-            '(1)|',
-            '()',
-            '(',
-            '((',
-            '(()',
-            '(()1',
+            "(1",
+            "|(1)",
+            "(1)|",
+            "()",
+            "(",
+            "((",
+            "(()",
+            "(()1",
         ]
         for expression in bad_expressions:
             with self.assertRaises(parser.ParseException, msg=expression):
                 self.parser.parse_value(self._tokenize(expression))
 
         bad_partial_expressions = [
-            '1)',
-            '(1)1',
-            '1(0)',
+            "1)",
+            "(1)1",
+            "1(0)",
         ]
         for expression in bad_partial_expressions:
             tokens = self._tokenize(expression)
@@ -185,72 +201,83 @@ class ParseConstantTests(unittest.TestCase):
             self.assertNotEqual(tokens, [])
 
         good_expressions = [
-            '(3)',
-            '(1)|2',
-            '1|(2)',
-            '(1)|(2)',
-            '((3))',
-            '0|(1|2)',
-            '(0|1|2)',
+            "(3)",
+            "(1)|2",
+            "1|(2)",
+            "(1)|(2)",
+            "((3))",
+            "0|(1|2)",
+            "(0|1|2)",
         ]
         for expression in good_expressions:
             self.assertEqual(
-                self.parser.parse_value(self._tokenize(expression)), 3)
+                self.parser.parse_value(self._tokenize(expression)), 3
+            )
 
     def test_parse_constant_complements(self):
         """Accept complementing constants."""
         self.assertEqual(
-            self.parser.parse_value(self._tokenize('~0')),
-            self.arch.max_unsigned)
+            self.parser.parse_value(self._tokenize("~0")),
+            self.arch.max_unsigned,
+        )
         self.assertEqual(
-            self.parser.parse_value(self._tokenize('~0|~0')),
-            self.arch.max_unsigned)
+            self.parser.parse_value(self._tokenize("~0|~0")),
+            self.arch.max_unsigned,
+        )
         if self.arch.bits == 32:
             self.assertEqual(
                 self.parser.parse_value(
-                    self._tokenize('~0x005AF0FF|~0xFFA50FFF')), 0xFFFFFF00)
+                    self._tokenize("~0x005AF0FF|~0xFFA50FFF")
+                ),
+                0xFFFFFF00,
+            )
             self.assertEqual(
                 self.parser.parse_value(
-                    self._tokenize('0x0F|~(0x005AF000|0x00A50FFF)|0xF0')),
-                0xFF0000FF)
+                    self._tokenize("0x0F|~(0x005AF000|0x00A50FFF)|0xF0")
+                ),
+                0xFF0000FF,
+            )
         else:
             self.assertEqual(
                 self.parser.parse_value(
-                    self._tokenize('~0x00005A5AF0F0FFFF|~0xFFFFA5A50F0FFFFF')),
-                0xFFFFFFFFFFFF0000)
+                    self._tokenize("~0x00005A5AF0F0FFFF|~0xFFFFA5A50F0FFFFF")
+                ),
+                0xFFFFFFFFFFFF0000,
+            )
             self.assertEqual(
                 self.parser.parse_value(
                     self._tokenize(
-                        '0x00FF|~(0x00005A5AF0F00000|0x0000A5A50F0FFFFF)|0xFF00'
-                    )), 0xFFFF00000000FFFF)
+                        "0x00FF|~(0x00005A5AF0F00000|0x0000A5A50F0FFFFF)|0xFF00"
+                    )
+                ),
+                0xFFFF00000000FFFF,
+            )
 
     def test_parse_double_complement(self):
         """Reject double-complementing constants."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    'double complement'):
-            self.parser.parse_value(self._tokenize('~~0'))
+        with self.assertRaisesRegex(parser.ParseException, "double complement"):
+            self.parser.parse_value(self._tokenize("~~0"))
 
     def test_parse_empty_complement(self):
         """Reject complementing nothing."""
-        with self.assertRaisesRegex(parser.ParseException, 'empty complement'):
-            self.parser.parse_value(self._tokenize('0|~'))
+        with self.assertRaisesRegex(parser.ParseException, "empty complement"):
+            self.parser.parse_value(self._tokenize("0|~"))
 
     def test_parse_named_constant(self):
         """Accept parsing a named constant."""
-        self.assertEqual(
-            self.parser.parse_value(self._tokenize('O_RDONLY')), 0)
+        self.assertEqual(self.parser.parse_value(self._tokenize("O_RDONLY")), 0)
 
     def test_parse_empty_constant(self):
         """Reject parsing nothing."""
-        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
+        with self.assertRaisesRegex(parser.ParseException, "empty constant"):
             self.parser.parse_value([])
-        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
-            self.parser.parse_value(self._tokenize('0|'))
+        with self.assertRaisesRegex(parser.ParseException, "empty constant"):
+            self.parser.parse_value(self._tokenize("0|"))
 
     def test_parse_invalid_constant(self):
         """Reject parsing invalid constants."""
-        with self.assertRaisesRegex(parser.ParseException, 'invalid constant'):
-            self.parser.parse_value(self._tokenize('foo'))
+        with self.assertRaisesRegex(parser.ParseException, "invalid constant"):
+            self.parser.parse_value(self._tokenize("foo"))
 
 
 class ParseFilterExpressionTests(unittest.TestCase):
@@ -259,7 +286,8 @@ class ParseFilterExpressionTests(unittest.TestCase):
     def setUp(self):
         self.arch = ARCH_64
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=bpf.KillProcess())
+            self.arch, kill_action=bpf.KillProcess()
+        )
 
     def _tokenize(self, line):
         # pylint: disable=protected-access
@@ -270,68 +298,84 @@ class ParseFilterExpressionTests(unittest.TestCase):
         self.assertEqual(
             self.parser.parse_argument_expression(
                 self._tokenize(
-                    'arg0 in 0xffff || arg0 == PROT_EXEC && arg1 == PROT_WRITE'
-                )), [
-                    [parser.Atom(0, 'in', 0xffff)],
-                    [parser.Atom(0, '==', 4),
-                     parser.Atom(1, '==', 2)],
-                ])
+                    "arg0 in 0xffff || arg0 == PROT_EXEC && arg1 == PROT_WRITE"
+                )
+            ),
+            [
+                [parser.Atom(0, "in", 0xFFFF)],
+                [parser.Atom(0, "==", 4), parser.Atom(1, "==", 2)],
+            ],
+        )
 
     def test_parse_number_argument_expression(self):
-        """Accept valid argument expressions with any octal/decimal/hex number."""
+        """Accept argument expressions with any octal/decimal/hex number."""
         # 4607 == 010777 == 0x11ff
         self.assertEqual(
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 in 4607')), [
-                    [parser.Atom(0, 'in', 4607)],
-            ])
+                self._tokenize("arg0 in 4607")
+            ),
+            [
+                [parser.Atom(0, "in", 4607)],
+            ],
+        )
 
         self.assertEqual(
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 in 010777')), [
-                    [parser.Atom(0, 'in', 4607)],
-            ])
+                self._tokenize("arg0 in 010777")
+            ),
+            [
+                [parser.Atom(0, "in", 4607)],
+            ],
+        )
 
         self.assertEqual(
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 in 0x11ff')), [
-                    [parser.Atom(0, 'in', 4607)],
-            ])
+                self._tokenize("arg0 in 0x11ff")
+            ),
+            [
+                [parser.Atom(0, "in", 4607)],
+            ],
+        )
 
     def test_parse_empty_argument_expression(self):
         """Reject empty argument expressions."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    'empty argument expression'):
+        with self.assertRaisesRegex(
+            parser.ParseException, "empty argument expression"
+        ):
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 in 0xffff ||'))
+                self._tokenize("arg0 in 0xffff ||")
+            )
 
     def test_parse_empty_clause(self):
         """Reject empty clause."""
-        with self.assertRaisesRegex(parser.ParseException, 'empty clause'):
+        with self.assertRaisesRegex(parser.ParseException, "empty clause"):
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 in 0xffff &&'))
+                self._tokenize("arg0 in 0xffff &&")
+            )
 
     def test_parse_invalid_argument(self):
         """Reject invalid argument."""
-        with self.assertRaisesRegex(parser.ParseException, 'invalid argument'):
+        with self.assertRaisesRegex(parser.ParseException, "invalid argument"):
             self.parser.parse_argument_expression(
-                self._tokenize('argX in 0xffff'))
+                self._tokenize("argX in 0xffff")
+            )
 
     def test_parse_invalid_operator(self):
         """Reject invalid operator."""
-        with self.assertRaisesRegex(parser.ParseException, 'invalid operator'):
+        with self.assertRaisesRegex(parser.ParseException, "invalid operator"):
             self.parser.parse_argument_expression(
-                self._tokenize('arg0 = 0xffff'))
+                self._tokenize("arg0 = 0xffff")
+            )
 
     def test_parse_missing_operator(self):
         """Reject missing operator."""
-        with self.assertRaisesRegex(parser.ParseException, 'missing operator'):
-            self.parser.parse_argument_expression(self._tokenize('arg0'))
+        with self.assertRaisesRegex(parser.ParseException, "missing operator"):
+            self.parser.parse_argument_expression(self._tokenize("arg0"))
 
     def test_parse_missing_operand(self):
         """Reject missing operand."""
-        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
-            self.parser.parse_argument_expression(self._tokenize('arg0 =='))
+        with self.assertRaisesRegex(parser.ParseException, "empty constant"):
+            self.parser.parse_argument_expression(self._tokenize("arg0 =="))
 
 
 class ParseFilterTests(unittest.TestCase):
@@ -340,7 +384,8 @@ class ParseFilterTests(unittest.TestCase):
     def setUp(self):
         self.arch = ARCH_64
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=bpf.KillProcess())
+            self.arch, kill_action=bpf.KillProcess()
+        )
 
     def _tokenize(self, line):
         # pylint: disable=protected-access
@@ -349,72 +394,97 @@ class ParseFilterTests(unittest.TestCase):
     def test_parse_filter(self):
         """Accept valid filters."""
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('arg0 == 0')), [
-                parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
-            ])
+            self.parser.parse_filter(self._tokenize("arg0 == 0")),
+            [
+                parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('kill-process')), [
+            self.parser.parse_filter(self._tokenize("kill-process")),
+            [
                 parser.Filter(None, bpf.KillProcess()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('kill-thread')), [
+            self.parser.parse_filter(self._tokenize("kill-thread")),
+            [
                 parser.Filter(None, bpf.KillThread()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('trap')), [
+            self.parser.parse_filter(self._tokenize("trap")),
+            [
                 parser.Filter(None, bpf.Trap()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('return ENOSYS')), [
-                parser.Filter(None,
-                              bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
-            ])
+            self.parser.parse_filter(self._tokenize("return ENOSYS")),
+            [
+                parser.Filter(
+                    None, bpf.ReturnErrno(self.arch.constants["ENOSYS"])
+                ),
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('trace')), [
+            self.parser.parse_filter(self._tokenize("trace")),
+            [
                 parser.Filter(None, bpf.Trace()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('user-notify')), [
+            self.parser.parse_filter(self._tokenize("user-notify")),
+            [
                 parser.Filter(None, bpf.UserNotify()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('log')), [
+            self.parser.parse_filter(self._tokenize("log")),
+            [
                 parser.Filter(None, bpf.Log()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('allow')), [
+            self.parser.parse_filter(self._tokenize("allow")),
+            [
                 parser.Filter(None, bpf.Allow()),
-            ])
+            ],
+        )
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('1')), [
+            self.parser.parse_filter(self._tokenize("1")),
+            [
                 parser.Filter(None, bpf.Allow()),
-            ])
+            ],
+        )
         self.assertEqual(
             self.parser.parse_filter(
-                self._tokenize(
-                    '{ arg0 == 0, arg0 == 1; return ENOSYS, trap }')),
+                self._tokenize("{ arg0 == 0, arg0 == 1; return ENOSYS, trap }")
+            ),
             [
-                parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
-                parser.Filter([[parser.Atom(0, '==', 1)]],
-                              bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
+                parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
+                parser.Filter(
+                    [[parser.Atom(0, "==", 1)]],
+                    bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                ),
                 parser.Filter(None, bpf.Trap()),
-            ])
+            ],
+        )
 
     def test_parse_missing_return_value(self):
         """Reject missing return value."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    'missing return value'):
-            self.parser.parse_filter(self._tokenize('return'))
+        with self.assertRaisesRegex(
+            parser.ParseException, "missing return value"
+        ):
+            self.parser.parse_filter(self._tokenize("return"))
 
     def test_parse_invalid_return_value(self):
         """Reject invalid return value."""
-        with self.assertRaisesRegex(parser.ParseException, 'invalid constant'):
-            self.parser.parse_filter(self._tokenize('return arg0'))
+        with self.assertRaisesRegex(parser.ParseException, "invalid constant"):
+            self.parser.parse_filter(self._tokenize("return arg0"))
 
     def test_parse_unclosed_brace(self):
         """Reject unclosed brace."""
-        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
-            self.parser.parse_filter(self._tokenize('{ allow'))
+        with self.assertRaisesRegex(parser.ParseException, "unclosed brace"):
+            self.parser.parse_filter(self._tokenize("{ allow"))
 
 
 class ParseFilterDenylistTests(unittest.TestCase):
@@ -424,7 +494,8 @@ class ParseFilterDenylistTests(unittest.TestCase):
         self.arch = ARCH_64
         self.kill_action = bpf.KillProcess()
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=self.kill_action, denylist=True)
+            self.arch, kill_action=self.kill_action, denylist=True
+        )
 
     def _tokenize(self, line):
         # pylint: disable=protected-access
@@ -433,11 +504,16 @@ class ParseFilterDenylistTests(unittest.TestCase):
     def test_parse_filter(self):
         """Accept only filters that return an errno."""
         self.assertEqual(
-            self.parser.parse_filter(self._tokenize('arg0 == 0; return ENOSYS')),
+            self.parser.parse_filter(
+                self._tokenize("arg0 == 0; return ENOSYS")
+            ),
             [
-                parser.Filter([[parser.Atom(0, '==', 0)]],
-                bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
-            ])
+                parser.Filter(
+                    [[parser.Atom(0, "==", 0)]],
+                    bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                ),
+            ],
+        )
 
 
 class ParseFilterStatementTests(unittest.TestCase):
@@ -446,7 +522,8 @@ class ParseFilterStatementTests(unittest.TestCase):
     def setUp(self):
         self.arch = ARCH_64
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=bpf.KillProcess())
+            self.arch, kill_action=bpf.KillProcess()
+        )
 
     def _tokenize(self, line):
         # pylint: disable=protected-access
@@ -454,120 +531,139 @@ class ParseFilterStatementTests(unittest.TestCase):
 
     def assertEqualIgnoringToken(self, actual, expected, msg=None):
         """Similar to assertEqual, but ignores the token field."""
-        if (actual.syscalls != expected.syscalls or
-            actual.filters != expected.filters):
-            self.fail('%r != %r' % (actual, expected), msg)
+        if (
+            actual.syscalls != expected.syscalls
+            or actual.filters != expected.filters
+        ):
+            self.fail("%r != %r: %s" % (actual, expected, msg))
 
     def test_parse_filter_statement(self):
         """Accept valid filter statements."""
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('read: arg0 == 0')),
+                self._tokenize("read: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
-                syscalls=(parser.Syscall('read', 0), ),
+                syscalls=(parser.Syscall("read", 0),),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('{read, write}: arg0 == 0')),
+                self._tokenize("{read, write}: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
                 syscalls=(
-                    parser.Syscall('read', 0),
-                    parser.Syscall('write', 1),
+                    parser.Syscall("read", 0),
+                    parser.Syscall("write", 1),
                 ),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('io@libc: arg0 == 0')),
+                self._tokenize("io@libc: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
                 syscalls=(
-                    parser.Syscall('read', 0),
-                    parser.Syscall('write', 1),
+                    parser.Syscall("read", 0),
+                    parser.Syscall("write", 1),
                 ),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('file-io@systemd: arg0 == 0')),
+                self._tokenize("file-io@systemd: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
                 syscalls=(
-                    parser.Syscall('read', 0),
-                    parser.Syscall('write', 1),
+                    parser.Syscall("read", 0),
+                    parser.Syscall("write", 1),
                 ),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('kill: arg0 == 0')),
+                self._tokenize("kill: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
-                syscalls=(
-                    parser.Syscall('kill', 62),
-                ),
+                syscalls=(parser.Syscall("kill", 62),),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
 
     def test_parse_metadata(self):
         """Accept valid filter statements with metadata."""
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
-                self._tokenize('read[arch=test]: arg0 == 0')),
+                self._tokenize("read[arch=test]: arg0 == 0")
+            ),
             parser.ParsedFilterStatement(
-                syscalls=(
-                    parser.Syscall('read', 0),
-                ),
+                syscalls=(parser.Syscall("read", 0),),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
         self.assertEqualIgnoringToken(
             self.parser.parse_filter_statement(
                 self._tokenize(
-                    '{read, nonexistent[arch=nonexistent]}: arg0 == 0')),
+                    "{read, nonexistent[arch=nonexistent]}: arg0 == 0"
+                )
+            ),
             parser.ParsedFilterStatement(
-                syscalls=(
-                    parser.Syscall('read', 0),
-                ),
+                syscalls=(parser.Syscall("read", 0),),
                 filters=[
-                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
+                    parser.Filter([[parser.Atom(0, "==", 0)]], bpf.Allow()),
                 ],
-                token=None))
+                token=None,
+            ),
+        )
 
     def test_parse_unclosed_brace(self):
         """Reject unclosed brace."""
-        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
-            self.parser.parse_filter(self._tokenize('{ allow'))
+        with self.assertRaisesRegex(parser.ParseException, "unclosed brace"):
+            self.parser.parse_filter(self._tokenize("{ allow"))
 
     def test_parse_invalid_syscall_group(self):
         """Reject invalid syscall groups."""
-        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
+        with self.assertRaisesRegex(parser.ParseException, "unclosed brace"):
             self.parser.parse_filter_statement(
-                self._tokenize('{ read, write: arg0 == 0'))
+                self._tokenize("{ read, write: arg0 == 0")
+            )
 
     def test_parse_missing_colon(self):
         """Reject missing colon."""
-        with self.assertRaisesRegex(parser.ParseException, 'missing colon'):
-            self.parser.parse_filter_statement(self._tokenize('read'))
+        with self.assertRaisesRegex(parser.ParseException, "missing colon"):
+            self.parser.parse_filter_statement(self._tokenize("read"))
 
     def test_parse_invalid_colon(self):
         """Reject invalid colon."""
-        with self.assertRaisesRegex(parser.ParseException, 'invalid colon'):
-            self.parser.parse_filter_statement(self._tokenize('read arg0'))
+        with self.assertRaisesRegex(parser.ParseException, "invalid colon"):
+            self.parser.parse_filter_statement(self._tokenize("read arg0"))
 
     def test_parse_missing_filter(self):
         """Reject missing filter."""
-        with self.assertRaisesRegex(parser.ParseException, 'missing filter'):
-            self.parser.parse_filter_statement(self._tokenize('read:'))
+        with self.assertRaisesRegex(parser.ParseException, "missing filter"):
+            self.parser.parse_filter_statement(self._tokenize("read:"))
 
 
 class ParseFileTests(unittest.TestCase):
@@ -576,7 +672,8 @@ class ParseFileTests(unittest.TestCase):
     def setUp(self):
         self.arch = ARCH_64
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=bpf.KillProcess())
+            self.arch, kill_action=bpf.KillProcess()
+        )
         self.tempdir = tempfile.mkdtemp()
 
     def tearDown(self):
@@ -585,18 +682,20 @@ class ParseFileTests(unittest.TestCase):
     def _write_file(self, filename, contents):
         """Helper to write out a file for testing."""
         path = os.path.join(self.tempdir, filename)
-        with open(path, 'w') as outf:
+        with open(path, "w", encoding="utf-8") as outf:
             outf.write(contents)
         return path
 
     def test_parse_simple(self):
         """Allow simple policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             read: allow
             write: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -604,28 +703,34 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_multiline(self):
         """Allow simple multi-line policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             read: \
                 allow
             write: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -633,26 +738,32 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_default(self):
         """Allow defining a default action."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @default kill-thread
             read: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -660,32 +771,40 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillThread(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_default_permissive(self):
         """Reject defining a permissive default action."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @default log
             read: allow
-        """)
+        """,
+        )
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'invalid permissive default action'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"invalid permissive default action"
+        ):
             self.parser.parse_file(path)
 
     def test_parse_simple_grouped(self):
         """Allow simple policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             {read, write}: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -693,27 +812,33 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_other_arch(self):
         """Allow entries that only target another architecture."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             read[arch=nonexistent]: allow
             write: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -721,24 +846,31 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_include(self):
         """Allow including policy files."""
         path = self._write_file(
-            'test.include.policy', """
+            "test.include.policy",
+            """
             {read, write}: arg0 == 0; allow
-        """)
+        """,
+        )
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @include ./test.include.policy
             read: return ENOSYS
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -746,72 +878,94 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
-                            parser.Filter([[parser.Atom(0, '==', 0)]],
-                                          bpf.Allow()),
+                            parser.Filter(
+                                [[parser.Atom(0, "==", 0)]], bpf.Allow()
+                            ),
                             parser.Filter(
                                 None,
-                                bpf.ReturnErrno(
-                                    self.arch.constants['ENOSYS'])),
-                        ]),
+                                bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                            ),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
-                            parser.Filter([[parser.Atom(0, '==', 0)]],
-                                          bpf.Allow()),
+                            parser.Filter(
+                                [[parser.Atom(0, "==", 0)]], bpf.Allow()
+                            ),
                             parser.Filter(None, bpf.KillProcess()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_invalid_include(self):
         """Reject including invalid policy files."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'empty include path'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"empty include path"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @include
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'invalid include path'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"invalid include path"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @include arg0
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'@include statement nested too deep'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"@include statement nested too deep"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @include ./test.policy
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'Could not @include .*'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"Could not @include .*"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @include ./nonexistent.policy
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
     def test_parse_frequency(self):
         """Allow including frequency files."""
         self._write_file(
-            'test.frequency', """
+            "test.frequency",
+            """
             read: 2
             write: 3
-        """)
+        """,
+        )
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             @frequency ./test.frequency
             read: allow
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -819,109 +973,150 @@ class ParseFileTests(unittest.TestCase):
                 default_action=bpf.KillProcess(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=2,
                         filters=[
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_invalid_frequency(self):
         """Reject including invalid frequency files."""
-        path = self._write_file('test.policy',
-                                """@frequency ./test.frequency""")
+        path = self._write_file(
+            "test.policy", """@frequency ./test.frequency"""
+        )
 
-        with self.assertRaisesRegex(parser.ParseException, r'missing colon'):
-            self._write_file('test.frequency', """
+        with self.assertRaisesRegex(parser.ParseException, r"missing colon"):
+            self._write_file(
+                "test.frequency",
+                """
                 read
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException, r'invalid colon'):
-            self._write_file('test.frequency', """
+        with self.assertRaisesRegex(parser.ParseException, r"invalid colon"):
+            self._write_file(
+                "test.frequency",
+                """
                 read foo
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException, r'missing number'):
-            self._write_file('test.frequency', """
+        with self.assertRaisesRegex(parser.ParseException, r"missing number"):
+            self._write_file(
+                "test.frequency",
+                """
                 read:
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException, r'invalid number'):
-            self._write_file('test.frequency', """
+        with self.assertRaisesRegex(parser.ParseException, r"invalid number"):
+            self._write_file(
+                "test.frequency",
+                """
                 read: foo
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException, r'invalid number'):
-            self._write_file('test.frequency', """
+        with self.assertRaisesRegex(parser.ParseException, r"invalid number"):
+            self._write_file(
+                "test.frequency",
+                """
                 read: -1
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'empty frequency path'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"empty frequency path"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @frequency
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'invalid frequency path'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"invalid frequency path"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @frequency arg0
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'Could not open frequency file.*'):
+        with self.assertRaisesRegex(
+            parser.ParseException, r"Could not open frequency file.*"
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @frequency ./nonexistent.frequency
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
     def test_parse_multiple_unconditional(self):
         """Reject actions after an unconditional action."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             read: allow
             read: allow
-        """)
+        """,
+        )
 
         with self.assertRaisesRegex(
-                parser.ParseException,
-                (r'test.policy\(3:17\): '
-                 r'Syscall read.*already had an unconditional action '
-                 r'applied')):
+            parser.ParseException,
+            (
+                r"test.policy\(3:17\): "
+                r"Syscall read.*already had an unconditional action "
+                r"applied"
+            ),
+        ):
             self.parser.parse_file(path)
 
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             read: log
             read: arg0 == 0; log
-        """)
+        """,
+        )
 
         with self.assertRaisesRegex(
-                parser.ParseException,
-                (r'test.policy\(3:17\): '
-                 r'Syscall read.*already had an unconditional action '
-                 r'applied')):
+            parser.ParseException,
+            (
+                r"test.policy\(3:17\): "
+                r"Syscall read.*already had an unconditional action "
+                r"applied"
+            ),
+        ):
             self.parser.parse_file(path)
 
     def test_parse_allowlist_denylist_header(self):
         """Reject trying to compile denylist policy file as allowlist."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'policy is denylist, but flag --denylist '
-                                    'not passed in'):
+        with self.assertRaisesRegex(
+            parser.ParseException,
+            r"policy is denylist, but flag --denylist " "not passed in",
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 @denylist
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
 
@@ -932,7 +1127,8 @@ class ParseFileDenylistTests(unittest.TestCase):
         self.arch = ARCH_64
         self.kill_action = bpf.KillProcess()
         self.parser = parser.PolicyParser(
-            self.arch, kill_action=self.kill_action, denylist=True)
+            self.arch, kill_action=self.kill_action, denylist=True
+        )
         self.tempdir = tempfile.mkdtemp()
 
     def tearDown(self):
@@ -941,19 +1137,21 @@ class ParseFileDenylistTests(unittest.TestCase):
     def _write_file(self, filename, contents):
         """Helper to write out a file for testing."""
         path = os.path.join(self.tempdir, filename)
-        with open(path, 'w') as outf:
+        with open(path, "w", encoding="utf-8") as outf:
             outf.write(contents)
         return path
 
     def test_parse_simple(self):
         """Allow simple denylist policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             @denylist
             read: return ENOSYS
             write: return ENOSYS
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -961,30 +1159,40 @@ class ParseFileDenylistTests(unittest.TestCase):
                 default_action=bpf.Allow(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
-                            parser.Filter(None, bpf.ReturnErrno(
-                                    self.arch.constants['ENOSYS'])),
-                        ]),
+                            parser.Filter(
+                                None,
+                                bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                            ),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
-                            parser.Filter(None, bpf.ReturnErrno(
-                                    self.arch.constants['ENOSYS'])),
-                        ]),
-                ]))
+                            parser.Filter(
+                                None,
+                                bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                            ),
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_simple_with_arg(self):
         """Allow simple denylist policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.
             @denylist
             read: return ENOSYS
             write: arg0 == 0 ; return ENOSYS
-        """)
+        """,
+        )
 
         self.assertEqual(
             self.parser.parse_file(path),
@@ -992,33 +1200,45 @@ class ParseFileDenylistTests(unittest.TestCase):
                 default_action=bpf.Allow(),
                 filter_statements=[
                     parser.FilterStatement(
-                        syscall=parser.Syscall('read', 0),
+                        syscall=parser.Syscall("read", 0),
                         frequency=1,
                         filters=[
-                            parser.Filter(None, bpf.ReturnErrno(
-                                    self.arch.constants['ENOSYS'])),
-                        ]),
+                            parser.Filter(
+                                None,
+                                bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                            ),
+                        ],
+                    ),
                     parser.FilterStatement(
-                        syscall=parser.Syscall('write', 1),
+                        syscall=parser.Syscall("write", 1),
                         frequency=1,
                         filters=[
-                            parser.Filter([[parser.Atom(0, '==', 0)]],
-                                bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
+                            parser.Filter(
+                                [[parser.Atom(0, "==", 0)]],
+                                bpf.ReturnErrno(self.arch.constants["ENOSYS"]),
+                            ),
                             parser.Filter(None, bpf.Allow()),
-                        ]),
-                ]))
-
+                        ],
+                    ),
+                ],
+            ),
+        )
 
     def test_parse_denylist_no_header(self):
         """Reject trying to compile denylist policy file as allowlist."""
-        with self.assertRaisesRegex(parser.ParseException,
-                                    r'policy must contain @denylist flag to be '
-                                    'compiled with --denylist flag'):
+        with self.assertRaisesRegex(
+            parser.ParseException,
+            r"policy must contain @denylist flag to be "
+            "compiled with --denylist flag",
+        ):
             path = self._write_file(
-                'test.policy', """
+                "test.policy",
+                """
                 read: return ENOSYS
-            """)
+            """,
+            )
             self.parser.parse_file(path)
 
-if __name__ == '__main__':
+
+if __name__ == "__main__":
     unittest.main()
diff --git a/tools/seccomp_policy_lint.py b/tools/seccomp_policy_lint.py
index f7621b0..f138973 100755
--- a/tools/seccomp_policy_lint.py
+++ b/tools/seccomp_policy_lint.py
@@ -1,113 +1,156 @@
 #!/usr/bin/env python3
-#
-# Copyright (C) 2021 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """A linter for the Minijail seccomp policy file."""
 
 import argparse
 import re
 import sys
+from typing import List, NamedTuple, Optional, Set
 
-from typing import List, NamedTuple
 
 # The syscalls we have determined are more dangerous and need justification
 # for inclusion in a policy.
 DANGEROUS_SYSCALLS = (
-    'clone',
-    'mount',
-    'setns',
-    'kill',
-    'execve',
-    'execveat',
-    'bpf',
-    'socket',
-    'ptrace',
-    'swapon',
-    'swapoff',
+    "clone",
+    "mount",
+    "setns",
+    "kill",
+    "execve",
+    "execveat",
+    "getrandom",
+    "bpf",
+    "socket",
+    "ptrace",
+    "swapon",
+    "swapoff",
     # TODO(b/193169195): Add argument granularity for the below syscalls.
-    'prctl',
-    'ioctl',
-#   'mmap',
-#   'mprotect',
-#   'mmap2',
+    "prctl",
+    "ioctl",
+    "mmap",
+    "mmap2",
+    "mprotect",
+)
+
+
+# If a dangerous syscall uses these rules, then it's considered safe.
+SYSCALL_SAFE_RULES = {
+    "getrandom": ("arg2 in ~GRND_RANDOM",),
+    "mmap": (
+        "arg2 == PROT_READ || arg2 == PROT_NONE",
+        "arg2 in ~PROT_EXEC",
+        "arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE",
+    ),
+    "mmap2": (
+        "arg2 == PROT_READ || arg2 == PROT_NONE",
+        "arg2 in ~PROT_EXEC",
+        "arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE",
+    ),
+    "mprotect": (
+        "arg2 == PROT_READ || arg2 == PROT_NONE",
+        "arg2 in ~PROT_EXEC",
+        "arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE",
+    ),
+}
+
+GLOBAL_SAFE_RULES = (
+    "kill",
+    "kill-process",
+    "kill-thread",
+    "return 1",
 )
 
+
 class CheckPolicyReturn(NamedTuple):
     """Represents a return value from check_seccomp_policy
 
     Contains a message to print to the user and a list of errors that were
     found in the file.
     """
+
     message: str
     errors: List[str]
 
+
 def parse_args(argv):
     """Return the parsed CLI arguments for this tool."""
     parser = argparse.ArgumentParser(description=__doc__)
     parser.add_argument(
-        '--denylist',
-        action='store_true',
-        help='Check as a denylist policy rather than the default allowlist.')
+        "--denylist",
+        action="store_true",
+        help="Check as a denylist policy rather than the default allowlist.",
+    )
+    parser.add_argument(
+        "--dangerous-syscalls",
+        action="store",
+        default=",".join(DANGEROUS_SYSCALLS),
+        help="Comma-separated list of dangerous sycalls (overrides default).",
+    )
+    parser.add_argument(
+        "--assume-filename",
+        help="The filename when parsing stdin.",
+    )
     parser.add_argument(
-        '--dangerous-syscalls',
-        action='store',
-        default=','.join(DANGEROUS_SYSCALLS),
-        help='Comma-separated list of dangerous sycalls (overrides default).'
+        "policy",
+        help="The seccomp policy.",
+        type=argparse.FileType("r", encoding="utf-8"),
     )
-    parser.add_argument('policy',
-                            help='The seccomp policy.',
-                            type=argparse.FileType('r', encoding='utf-8'))
     return parser.parse_args(argv), parser
 
-def check_seccomp_policy(check_file, dangerous_syscalls):
+
+def check_seccomp_policy(
+    check_file, dangerous_syscalls: Set[str], filename: Optional[str] = None
+):
     """Fail if the seccomp policy file has dangerous, undocumented syscalls.
 
     Takes in a file object and a set of dangerous syscalls as arguments.
     """
 
+    if filename is None:
+        filename = check_file.name
     found_syscalls = set()
     errors = []
-    msg = ''
+    msg = ""
     contains_dangerous_syscall = False
     prev_line_comment = False
 
     for line_num, line in enumerate(check_file):
-        if re.match(r'^\s*#', line):
+        if re.match(r"^\s*#", line):
             prev_line_comment = True
-        elif re.match(r'^\s*$', line):
+        elif re.match(r"^\s*$", line):
             # Empty lines shouldn't reset prev_line_comment.
             continue
         else:
-            match = re.match(fr'^\s*(\w*)\s*:', line)
+            match = re.match(r"^\s*(\w*)\s*:\s*(.*)\s*", line)
             if match:
                 syscall = match.group(1)
+                rule = match.group(2)
+                err_prefix = f"{filename}:{line_num}:{syscall}:"
                 if syscall in found_syscalls:
-                    errors.append(f'{check_file.name}, line {line_num}: repeat '
-                                  f'syscall: {syscall}')
+                    errors.append(f"{err_prefix} duplicate entry found")
                 else:
                     found_syscalls.add(syscall)
-                    for dangerous in dangerous_syscalls:
-                        if dangerous == syscall:
-                            # Dangerous syscalls must be preceded with a
-                            # comment.
-                            contains_dangerous_syscall = True
-                            if not prev_line_comment:
-                                errors.append(f'{check_file.name}, line '
-                                              f'{line_num}: {syscall} syscall '
-                                              'is a dangerous syscall so '
-                                              'requires a comment on the '
-                                              'preceding line')
+                    if syscall in dangerous_syscalls:
+                        contains_dangerous_syscall = True
+                        if not prev_line_comment:
+                            # Dangerous syscalls must be commented.
+                            safe_rules = SYSCALL_SAFE_RULES.get(syscall, ())
+                            if rule in GLOBAL_SAFE_RULES or rule in safe_rules:
+                                pass
+                            elif safe_rules:
+                                # Dangerous syscalls with known safe rules must
+                                # use those rules.
+                                errors.append(
+                                    f"{err_prefix} syscall is dangerous and "
+                                    f"should use one of the rules: {safe_rules}"
+                                )
+                            else:
+                                errors.append(
+                                    f"{err_prefix} syscall is dangerous and "
+                                    "requires a comment on the preceding line"
+                                )
                 prev_line_comment = False
             else:
                 # This line is probably a continuation from the previous line.
@@ -115,18 +158,23 @@ def check_seccomp_policy(check_file, dangerous_syscalls):
                 pass
 
     if contains_dangerous_syscall:
-        msg = (f'seccomp: {check_file.name} contains dangerous syscalls, so'
-               ' requires review from chromeos-security@')
+        msg = (
+            f"seccomp: {filename} contains dangerous syscalls, so"
+            " requires review from chromeos-security@"
+        )
     else:
-        msg = (f'seccomp: {check_file.name} does not contain any dangerous'
-               ' syscalls, so does not require review from'
-               ' chromeos-security@')
+        msg = (
+            f"seccomp: {filename} does not contain any dangerous"
+            " syscalls, so does not require review from"
+            " chromeos-security@"
+        )
 
     if errors:
         return CheckPolicyReturn(msg, errors)
 
     return CheckPolicyReturn(msg, errors)
 
+
 def main(argv=None):
     """Main entrypoint."""
 
@@ -135,17 +183,20 @@ def main(argv=None):
 
     opts, _arg_parser = parse_args(argv)
 
-    check = check_seccomp_policy(opts.policy,
-                                 set(opts.dangerous_syscalls.split(',')))
+    filename = opts.assume_filename if opts.assume_filename else opts.policy
+    check = check_seccomp_policy(
+        opts.policy, set(opts.dangerous_syscalls.split(",")), filename=filename
+    )
 
-    formatted_items = ''
+    formatted_items = ""
     if check.errors:
-        item_prefix = '\n    * '
+        item_prefix = "\n    * "
         formatted_items = item_prefix + item_prefix.join(check.errors)
 
-    print('* ' + check.message + formatted_items)
+    print("* " + check.message + formatted_items)
 
     return 1 if check.errors else 0
 
-if __name__ == '__main__':
+
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/seccomp_policy_lint_unittest.py b/tools/seccomp_policy_lint_unittest.py
old mode 100644
new mode 100755
index 192739f..7acc4a4
--- a/tools/seccomp_policy_lint_unittest.py
+++ b/tools/seccomp_policy_lint_unittest.py
@@ -1,18 +1,8 @@
 #!/usr/bin/env python3
-#
-# Copyright (C) 2021 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
+# Copyright 2020 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
 """Unittests for the seccomp policy linter module."""
 
 from pathlib import Path
@@ -21,6 +11,7 @@ import unittest
 
 import seccomp_policy_lint
 
+
 class CheckSeccompPolicyTests(unittest.TestCase):
     """Tests for check_seccomp_policy."""
 
@@ -36,81 +27,109 @@ class CheckSeccompPolicyTests(unittest.TestCase):
     def test_check_simple(self):
         """Allow simple policy files."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.\n
             read: 1\n
             write: 1\n
-        """)
+        """,
+        )
 
         exp_out = seccomp_policy_lint.CheckPolicyReturn(
-                    f'seccomp: {path.resolve()} does not contain any dangerous'
-                    ' syscalls, so does not require review from'
-                    ' chromeos-security@',
-                    [])
-
-        with path.open('r', encoding='utf-8') as check_file:
-            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
-                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
-                    exp_out)
+            f"seccomp: {path.resolve()} does not contain any dangerous"
+            " syscalls, so does not require review from"
+            " chromeos-security@",
+            [],
+        )
+
+        with path.open("r", encoding="utf-8") as check_file:
+            self.assertEqual(
+                seccomp_policy_lint.check_seccomp_policy(
+                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
+                ),
+                exp_out,
+            )
 
     def test_check_dangerous_comment(self):
         """Dangerous syscalls must have a comment and need to be reviewed."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.\n\n\n
             clone: 1\n
             write: 1\n
-        """)
+        """,
+        )
 
         exp_out = seccomp_policy_lint.CheckPolicyReturn(
-                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
-                    ' so requires review from chromeos-security@',
-                    [])
-
-        with path.open('r', encoding='utf-8') as check_file:
-            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
-                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
-                    exp_out)
+            f"seccomp: {path.resolve()} contains dangerous syscalls,"
+            " so requires review from chromeos-security@",
+            [],
+        )
+
+        with path.open("r", encoding="utf-8") as check_file:
+            self.assertEqual(
+                seccomp_policy_lint.check_seccomp_policy(
+                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
+                ),
+                exp_out,
+            )
 
     def test_check_dangerous_no_comment(self):
         """Dangerous syscalls without a comment should cause an error."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.\n
             mount: 1\n
             clone: 1\n
-        """)
+        """,
+        )
 
         exp_out = seccomp_policy_lint.CheckPolicyReturn(
-                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
-                    ' so requires review from chromeos-security@',
-                   [(f'{path.resolve()}, line 5: clone syscall is a dangerous '
-                   'syscall so requires a comment on the preceding line')])
-
-        with path.open('r', encoding='utf-8') as check_file:
-            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
-                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
-                    exp_out)
+            f"seccomp: {path.resolve()} contains dangerous syscalls,"
+            " so requires review from chromeos-security@",
+            [
+                (
+                    f"{path.resolve()}:5:clone: syscall is dangerous "
+                    "and requires a comment on the preceding line"
+                )
+            ],
+        )
+
+        with path.open("r", encoding="utf-8") as check_file:
+            self.assertEqual(
+                seccomp_policy_lint.check_seccomp_policy(
+                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
+                ),
+                exp_out,
+            )
 
     def test_check_duplicate_syscall(self):
         """Policy files cannot have duplicate syscalls.."""
         path = self._write_file(
-            'test.policy', """
+            "test.policy",
+            """
             # Comment.\n
             clone: 1\n
             clone: arg0 == 3
-        """)
+        """,
+        )
 
         exp_out = seccomp_policy_lint.CheckPolicyReturn(
-                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
-                    ' so requires review from chromeos-security@',
-                   [(f'{path.resolve()}, line 5: repeat syscall: clone')])
+            f"seccomp: {path.resolve()} contains dangerous syscalls,"
+            " so requires review from chromeos-security@",
+            [f"{path.resolve()}:5:clone: duplicate entry found"],
+        )
 
-        with path.open('r', encoding='utf-8') as check_file:
-            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
-                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
-                    exp_out)
+        with path.open("r", encoding="utf-8") as check_file:
+            self.assertEqual(
+                seccomp_policy_lint.check_seccomp_policy(
+                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
+                ),
+                exp_out,
+            )
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/util.c b/util.c
index c8cf3a6..9db92ed 100644
--- a/util.c
+++ b/util.c
@@ -35,48 +35,80 @@
  */
 const char *const log_syscalls[] = {
 #if defined(__x86_64__)
-# if defined(__ANDROID__)
-  "socket", "connect", "fcntl", "writev",
-# else
-  "socket", "connect", "sendto", "writev",
-# endif
+#if defined(__ANDROID__)
+    "socket",
+    "connect",
+    "fcntl",
+    "writev",
+#else
+    "socket",
+    "connect",
+    "sendto",
+    "writev",
+#endif
 #elif defined(__i386__)
-# if defined(__ANDROID__)
-  "socketcall", "writev", "fcntl64", "clock_gettime",
-# else
-  "socketcall", "time", "writev",
-# endif
+#if defined(__ANDROID__)
+    "socketcall",
+    "writev",
+    "fcntl64",
+    "clock_gettime",
+#else
+    "socketcall",
+    "time",
+    "writev",
+#endif
 #elif defined(__arm__)
-# if defined(__ANDROID__)
-  "clock_gettime", "connect", "fcntl64", "socket", "writev",
-# else
-  "socket", "connect", "gettimeofday", "send", "writev",
-# endif
+#if defined(__ANDROID__)
+    "clock_gettime", "connect", "fcntl64", "socket", "writev",
+#else
+    "socket", "connect", "gettimeofday", "send", "writev",
+#endif
 #elif defined(__aarch64__)
-# if defined(__ANDROID__)
-  "connect", "fcntl", "sendto", "socket", "writev",
-# else
-  "socket", "connect", "send", "writev",
-# endif
-#elif defined(__hppa__) || \
-      defined(__ia64__) || \
-      defined(__mips__) || \
-      defined(__powerpc__) || \
-      defined(__sparc__)
-  "socket", "connect", "send",
+#if defined(__ANDROID__)
+    "connect", "fcntl", "sendto", "socket", "writev",
+#else
+    "socket",
+    "connect",
+    "send",
+    "writev",
+#endif
+#elif defined(__hppa__) || defined(__ia64__) || defined(__mips__) ||           \
+    defined(__powerpc__) || defined(__sparc__)
+    "socket",
+    "connect",
+    "send",
 #elif defined(__riscv)
-# if defined(__ANDROID__)
-  "connect", "fcntl", "sendto", "socket", "writev",
-# else
-  "socket", "connect", "sendto",
-# endif
+#if defined(__ANDROID__)
+    "connect", "fcntl", "sendto", "socket", "writev",
+#else
+    "socket",
+    "connect",
+    "sendto",
+#endif
 #else
-# error "Unsupported platform"
+#error "Unsupported platform"
 #endif
 };
 
 const size_t log_syscalls_len = ARRAY_SIZE(log_syscalls);
 
+/*
+ * These syscalls are globally allowed. ChromeOS devs: Do **not** add to this
+ * list without approval from the security team.
+ *
+ * This list should be made empty (and mostly remain so) after a better
+ * mechanism is implemented: b/393353891
+ */
+const char *const libc_compatibility_syscalls[] = {
+    "fstat",
+#if defined(__arm__)
+    "fstat64",
+#endif
+};
+
+const size_t libc_compatibility_syscalls_len =
+    ARRAY_SIZE(libc_compatibility_syscalls);
+
 /* clang-format off */
 static struct logging_config_t {
 	/* The logging system to use. The default is syslog. */
@@ -178,7 +210,7 @@ int lookup_syscall(const char *name, size_t *ind)
 	return -1;
 }
 
-const char *lookup_syscall_name(int nr)
+const char *lookup_syscall_name(long nr)
 {
 	const struct syscall_entry *entry = syscall_table;
 	for (; entry->name && entry->nr >= 0; ++entry)
@@ -268,9 +300,18 @@ static char *tokenize_parenthesized_expression(char **stringp)
 	return NULL;
 }
 
-long int parse_constant(char *constant_str, char **endptr)
+long int parse_constant(char *constant_str_nonnull, char **endptr)
 {
 	long int value = 0, current_value;
+	/*
+	 * The function API says both inputs have to be non-NULL.  The code
+	 * happens to handle NULL pointers because it resuses the input pointer
+	 * as it tokenizes/walks it until the tokenize functions sets it to
+	 * NULL.  But because of the attributes on the function arguments, the
+	 * compiler incorrectly assumes the variable can't become NULL in here,
+	 * so we have to create another variable to effectively cast it away.
+	 */
+	char *constant_str = constant_str_nonnull;
 	char *group, *lastpos = constant_str;
 
 	/*
@@ -348,53 +389,51 @@ long int parse_constant(char *constant_str, char **endptr)
 	return value;
 }
 
-/*
- * parse_size, specified as a string with a decimal number in bytes,
- * possibly with one 1-character suffix like "10K" or "6G".
- * Assumes both pointers are non-NULL.
- *
- * Returns 0 on success, negative errno on failure.
- * Only writes to result on success.
- */
-int parse_size(size_t *result, const char *sizespec)
+int parse_size(uint64_t *result, const char *sizespec)
 {
-	const char prefixes[] = "KMGTPE";
-	size_t i, multiplier = 1, nsize, size = 0;
+	uint64_t size;
 	unsigned long long parsed;
-	const size_t len = strlen(sizespec);
 	char *end;
 
-	if (len == 0 || sizespec[0] == '-')
+	/* strtoull supports leading whitespace, -, and + signs. */
+	if (sizespec[0] < '0' || sizespec[0] > '9')
 		return -EINVAL;
 
-	for (i = 0; i < sizeof(prefixes); ++i) {
-		if (sizespec[len - 1] == prefixes[i]) {
-#if __WORDSIZE == 32
-			if (i >= 3)
-				return -ERANGE;
-#endif
-			multiplier = 1024;
-			while (i-- > 0)
-				multiplier *= 1024;
-			break;
-		}
-	}
-
-	/* We only need size_t but strtoul(3) is too small on IL32P64. */
+	/* Clear+check errno so we handle ULLONG_MAX correctly. */
+	errno = 0;
 	parsed = strtoull(sizespec, &end, 10);
-	if (parsed == ULLONG_MAX)
+	if (errno)
 		return -errno;
-	if (parsed >= SIZE_MAX)
-		return -ERANGE;
-	if ((multiplier != 1 && end != sizespec + len - 1) ||
-	    (multiplier == 1 && end != sizespec + len))
-		return -EINVAL;
-	size = (size_t)parsed;
+	size = parsed;
+
+	/* See if there's a suffix. */
+	if (*end != '\0') {
+		static const char suffixes[] = "KMGTPE";
+		size_t i;
+
+		/* Only allow 1 suffix. */
+		if (end[1] != '\0')
+			return -EINVAL;
+
+		for (i = 0; i < sizeof(suffixes) - 1; ++i) {
+			if (*end == suffixes[i]) {
+				/* Make sure we don't overflow. */
+				const int scale = (i + 1) * 10;
+				uint64_t mask =
+				    ~((UINT64_C(1) << (64 - scale)) - 1);
+				if (size & mask)
+					return -ERANGE;
+				size <<= scale;
+				break;
+			}
+		}
 
-	nsize = size * multiplier;
-	if (nsize / multiplier != size)
-		return -ERANGE;
-	*result = nsize;
+		/* Unknown suffix. */
+		if (i == sizeof(suffixes) - 1)
+			return -EINVAL;
+	}
+
+	*result = size;
 	return 0;
 }
 
@@ -537,7 +576,8 @@ char **minijail_copy_env(char *const *env)
  * minijail_getenv, returns true if |name| is found, false if not.
  * If found, |*i| is |name|'s index. If not, |*i| is the length of |envp|.
  */
-static bool getenv_index(char **envp, const char *name, int *i) {
+static bool getenv_index(char **envp, const char *name, int *i)
+{
 	if (!envp || !name || !i)
 		return false;
 
@@ -637,7 +677,8 @@ ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream)
 	return *n - 1;
 }
 
-char *minijail_getenv(char **envp, const char *name) {
+char *minijail_getenv(char **envp, const char *name)
+{
 	if (!envp || !name)
 		return NULL;
 
diff --git a/util.h b/util.h
index c310572..0e1baf0 100644
--- a/util.h
+++ b/util.h
@@ -10,6 +10,7 @@
 #define _UTIL_H_
 
 #include <stdbool.h>
+#include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -53,9 +54,18 @@ extern "C" {
  *   foo([1] int, [2] const char *format, [3] ...): format=2 check=3
  *   foo([1] const char *format, [2] const char *, [3] ...): format=1 check=3
  */
-#define attribute_printf(format_idx, check_idx) \
+#define attribute_printf(format_idx, check_idx)                                \
 	__attribute__((__format__(__printf__, format_idx, check_idx)))
 
+/*
+ * The specified function arguments may not be NULL.  Params starts counting
+ * from 1, not 0.  If no params are specified, then all function arguments are
+ * marked as non-NULL.  Thus, params should only be specified if a function
+ * accepts NULL pointers for any of the arguments.
+ * NB: Keep in sync with libminijail.h style.
+ */
+#define attribute_nonnull(params) __attribute__((__nonnull__ params))
+
 #ifndef __cplusplus
 /* If writing C++, use std::unique_ptr with a destructor instead. */
 
@@ -65,8 +75,7 @@ extern "C" {
  * Make sure any variable using this is always initialized to something.
  * @func The function to call on (a pointer to) the variable.
  */
-#define attribute_cleanup(func) \
-	__attribute__((__cleanup__(func)))
+#define attribute_cleanup(func) __attribute__((__cleanup__(func)))
 
 /*
  * Automatically close a FILE* when exiting its scope.
@@ -144,6 +153,9 @@ static inline void _cleanup_str(char **ptr)
 extern const char *const log_syscalls[];
 extern const size_t log_syscalls_len;
 
+extern const char *const libc_compatibility_syscalls[];
+extern const size_t libc_compatibility_syscalls_len;
+
 enum logging_system_t {
 	/* Log to syslog. This is the default. */
 	LOG_TO_SYSLOG = 0,
@@ -244,19 +256,33 @@ static inline size_t get_num_syscalls(void)
 	return syscall_table_size;
 }
 
-int lookup_syscall(const char *name, size_t *ind);
-const char *lookup_syscall_name(int nr);
+int lookup_syscall(const char *name, size_t *ind) attribute_nonnull((1));
+const char *lookup_syscall_name(long nr);
+
+long int parse_single_constant(char *constant_str, char **endptr)
+    attribute_nonnull();
+long int parse_constant(char *constant_str, char **endptr)
+    attribute_nonnull((1));
 
-long int parse_single_constant(char *constant_str, char **endptr);
-long int parse_constant(char *constant_str, char **endptr);
-int parse_size(size_t *size, const char *sizespec);
+/*
+ * parse_size: parse a string to a positive integer bytes with optional suffix.
+ * @size     The output parsed size, in bytes
+ * @sizespec The input string to parse
+ *
+ * A single 1-char suffix is supported like "10K" or "6G".  These use base 1024,
+ * not base 1000.  i.e. "1K" is "1024".  It is case-sensitive.
+ *
+ * Returns 0 on success, negative errno on failure.
+ * Only writes to |size| on success.
+ */
+int parse_size(uint64_t *size, const char *sizespec) attribute_nonnull();
 
-char *strip(char *s);
+char *strip(char *s) attribute_nonnull();
 
 /*
  * streq: determine whether two strings are equal.
  */
-static inline bool streq(const char *s1, const char *s2)
+attribute_nonnull() static inline bool streq(const char *s1, const char *s2)
 {
 	return strcmp(s1, s2) == 0;
 }
@@ -274,14 +300,15 @@ static inline bool streq(const char *s1, const char *s2)
  */
 char *tokenize(char **stringp, const char *delim);
 
-char *path_join(const char *external_path, const char *internal_path);
+char *path_join(const char *external_path, const char *internal_path)
+    attribute_nonnull();
 
 /*
  * path_is_parent: checks whether @parent is a parent of @child.
  * Note: this function does not evaluate '.' or '..' nor does it resolve
  * symlinks.
  */
-bool path_is_parent(const char *parent, const char *child);
+bool path_is_parent(const char *parent, const char *child) attribute_nonnull();
 
 /*
  * consumebytes: consumes @length bytes from a buffer @buf of length @buflength
@@ -291,7 +318,8 @@ bool path_is_parent(const char *parent, const char *child);
  *
  * Returns a pointer to the base of the bytes, or NULL for errors.
  */
-void *consumebytes(size_t length, char **buf, size_t *buflength);
+void *consumebytes(size_t length, char **buf, size_t *buflength)
+    attribute_nonnull();
 
 /*
  * consumestr: consumes a C string from a buffer @buf of length @length
@@ -300,7 +328,7 @@ void *consumebytes(size_t length, char **buf, size_t *buflength);
  *
  * Returns a pointer to the base of the string, or NULL for errors.
  */
-char *consumestr(char **buf, size_t *buflength);
+char *consumestr(char **buf, size_t *buflength) attribute_nonnull();
 
 /*
  * init_logging: initializes the module-wide logging.
@@ -361,7 +389,8 @@ int minijail_setenv(char ***env, const char *name, const char *value,
  *
  * Returns number of bytes read or -1 on failure to read (including EOF).
  */
-ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream);
+ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream)
+    attribute_nonnull();
 
 /*
  * minjail_getenv: Get an environment variable from @envp. Semantics match the
diff --git a/util_unittest.cc b/util_unittest.cc
index b3a2350..87bcdae 100644
--- a/util_unittest.cc
+++ b/util_unittest.cc
@@ -19,7 +19,7 @@
 
 namespace {
 
-std::string dump_env(const char *const *env) {
+std::string dump_env(const char* const* env) {
   std::string result;
   for (; *env; ++env) {
     result += *env;
@@ -43,14 +43,14 @@ TEST(tokenize, null_stringp) {
   ASSERT_EQ(nullptr, tokenize(nullptr, ""));
   ASSERT_EQ(nullptr, tokenize(nullptr, ","));
 
-  char *p = nullptr;
+  char* p = nullptr;
   ASSERT_EQ(nullptr, tokenize(&p, nullptr));
 }
 
 // Make sure we don't crash with various "null"-like inputs.
 TEST(tokenize, null_delim) {
   char str[] = "a,b,c";
-  char *p = str;
+  char* p = str;
   ASSERT_EQ(str, tokenize(&p, nullptr));
   ASSERT_EQ(nullptr, p);
   ASSERT_EQ(str, std::string("a,b,c"));
@@ -64,7 +64,7 @@ TEST(tokenize, null_delim) {
 // Sanity check for the tokenize func.
 TEST(tokenize, basic) {
   char str[] = "a,b,c";
-  char *p = str;
+  char* p = str;
   ASSERT_EQ("a", std::string(tokenize(&p, ",")));
   ASSERT_EQ("b", std::string(tokenize(&p, ",")));
   ASSERT_EQ("c", std::string(tokenize(&p, ",")));
@@ -75,7 +75,7 @@ TEST(tokenize, basic) {
 // Check edge case with an empty string.
 TEST(tokenize, empty_string) {
   char str[] = "";
-  char *p = str;
+  char* p = str;
   ASSERT_EQ("", std::string(tokenize(&p, ",")));
   ASSERT_EQ(nullptr, p);
   ASSERT_EQ(nullptr, tokenize(&p, ","));
@@ -84,7 +84,7 @@ TEST(tokenize, empty_string) {
 // Check behavior with empty tokens at the start/middle/end.
 TEST(tokenize, empty_tokens) {
   char str[] = ",,a,b,,,c,,";
-  char *p = str;
+  char* p = str;
   ASSERT_EQ("", std::string(tokenize(&p, ",")));
   ASSERT_EQ("", std::string(tokenize(&p, ",")));
   ASSERT_EQ("a", std::string(tokenize(&p, ",")));
@@ -102,17 +102,12 @@ TEST(tokenize, empty_tokens) {
 TEST(environment, copy_and_modify) {
   minijail_free_env(nullptr);
 
-  char **env = minijail_copy_env(nullptr);
+  char** env = minijail_copy_env(nullptr);
   EXPECT_EQ("", dump_env(env));
   minijail_free_env(env);
 
-  const char *const kConstEnv[] = {
-    "val1=1",
-    "val2=2",
-    "dup=1",
-    "dup=2",
-    "empty=",
-    nullptr,
+  const char* const kConstEnv[] = {
+      "val1=1", "val2=2", "dup=1", "dup=2", "empty=", nullptr,
   };
 
   // libc unfortunately uses char* const[] as the type for the environment, and
@@ -129,7 +124,7 @@ TEST(environment, copy_and_modify) {
   EXPECT_EQ("val1=1\nval2=2\ndup=1\ndup=2\nempty=\n", dump_env(env));
 
   EXPECT_EQ(EINVAL, minijail_setenv(nullptr, "val1", "3", 1));
-  char **env_ret = nullptr;
+  char** env_ret = nullptr;
   EXPECT_EQ(EINVAL, minijail_setenv(&env_ret, "val1", "3", 1));
 
   env_ret = env;
@@ -198,7 +193,7 @@ TEST(environment, copy_and_modify) {
 }
 
 TEST(parse_single_constant, formats) {
-  char *end;
+  char* end;
   long int c = 0;
   std::string constant;
 
@@ -219,7 +214,7 @@ TEST(parse_single_constant, formats) {
 }
 
 TEST(parse_constant, unsigned) {
-  char *end;
+  char* end;
   long int c = 0;
   std::string constant;
 
@@ -234,12 +229,12 @@ TEST(parse_constant, unsigned) {
   EXPECT_EQ(0x8000000000000000UL, static_cast<unsigned long int>(c));
 
 #else
-# error "unknown bits!"
+#error "unknown bits!"
 #endif
 }
 
 TEST(parse_constant, unsigned_toobig) {
-  char *end;
+  char* end;
   long int c = 0;
   std::string constant;
 
@@ -256,12 +251,12 @@ TEST(parse_constant, unsigned_toobig) {
   EXPECT_EQ(0, c);
 
 #else
-# error "unknown bits!"
+#error "unknown bits!"
 #endif
 }
 
 TEST(parse_constant, signed) {
-  char *end;
+  char* end;
   long int c = 0;
   std::string constant = "-1";
   c = parse_constant(const_cast<char*>(constant.data()), &end);
@@ -269,7 +264,7 @@ TEST(parse_constant, signed) {
 }
 
 TEST(parse_constant, signed_toonegative) {
-  char *end;
+  char* end;
   long int c = 0;
   std::string constant;
 
@@ -286,7 +281,7 @@ TEST(parse_constant, signed_toonegative) {
   EXPECT_EQ(0, c);
 
 #else
-# error "unknown bits!"
+#error "unknown bits!"
 #endif
 }
 
@@ -312,7 +307,7 @@ TEST(parse_constant, complements) {
   EXPECT_EQ(c, 0xFFFF00000000FFFFUL);
 
 #else
-# error "unknown bits!"
+#error "unknown bits!"
 #endif
 }
 
@@ -345,7 +340,7 @@ TEST(parse_constant, parenthesized_expresions) {
 }
 
 TEST(parse_size, complete) {
-  size_t size;
+  uint64_t size;
 
   ASSERT_EQ(0, parse_size(&size, "42"));
   ASSERT_EQ(42U, size);
@@ -356,7 +351,7 @@ TEST(parse_size, complete) {
   ASSERT_EQ(0, parse_size(&size, "1M"));
   ASSERT_EQ(1024U * 1024, size);
 
-  uint64_t gigabyte = 1024ULL * 1024 * 1024;
+  uint64_t gigabyte = UINT64_C(1024) * 1024 * 1024;
   ASSERT_EQ(0, parse_size(&size, "3G"));
   ASSERT_EQ(3U, size / gigabyte);
   ASSERT_EQ(0U, size % gigabyte);
@@ -365,7 +360,6 @@ TEST(parse_size, complete) {
   ASSERT_EQ(3U, size / gigabyte);
   ASSERT_EQ(gigabyte - 2, size % gigabyte);
 
-#if __WORDSIZE == 64
   uint64_t exabyte = gigabyte * 1024 * 1024 * 1024;
   ASSERT_EQ(0, parse_size(&size, "9E"));
   ASSERT_EQ(9U, size / exabyte);
@@ -375,29 +369,39 @@ TEST(parse_size, complete) {
   ASSERT_EQ(15U, size / exabyte);
   ASSERT_EQ(0U, size % exabyte);
 
+  // Check values that don't fit in 64-bits.
+  ASSERT_EQ(-ERANGE, parse_size(&size, "16384P"));
+  ASSERT_EQ(-ERANGE, parse_size(&size, "1638400P"));
+  ASSERT_EQ(-ERANGE, parse_size(&size, "16E"));
+  ASSERT_EQ(-ERANGE, parse_size(&size, "16000000000E"));
+
+  // Check limits right around 64-bits.
   ASSERT_EQ(0, parse_size(&size, "18446744073709551614"));
-  ASSERT_EQ(15U, size / exabyte);
-  ASSERT_EQ(exabyte - 2, size % exabyte);
+  ASSERT_EQ(ULLONG_MAX - 1, size);
+  ASSERT_EQ(0, parse_size(&size, "18446744073709551615"));
+  ASSERT_EQ(ULLONG_MAX, size);
+  ASSERT_EQ(-ERANGE, parse_size(&size, "18446744073709551616"));
 
-  ASSERT_EQ(-ERANGE, parse_size(&size, "16E"));
-  ASSERT_EQ(-ERANGE, parse_size(&size, "19E"));
+  // Only allow 1 valid suffix.
   ASSERT_EQ(-EINVAL, parse_size(&size, "7GTPE"));
-#elif __WORDSIZE == 32
-  ASSERT_EQ(-ERANGE, parse_size(&size, "5G"));
-  ASSERT_EQ(-ERANGE, parse_size(&size, "9G"));
-  ASSERT_EQ(-ERANGE, parse_size(&size, "9E"));
-  ASSERT_EQ(-ERANGE, parse_size(&size, "7GTPE"));
-#endif
+
+  // Check edge cases that strto* APIs accept, but we don't.
+  ASSERT_EQ(-EINVAL, parse_size(&size, "-8"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, "+8"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, " -8"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, " +8"));
 
   ASSERT_EQ(-EINVAL, parse_size(&size, ""));
   ASSERT_EQ(-EINVAL, parse_size(&size, "14u"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, "14B"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, "14Z"));
   ASSERT_EQ(-EINVAL, parse_size(&size, "14.2G"));
-  ASSERT_EQ(-EINVAL, parse_size(&size, "-1G"));
+  ASSERT_EQ(-EINVAL, parse_size(&size, "G"));
   ASSERT_EQ(-EINVAL, parse_size(&size, "; /bin/rm -- "));
 }
 
 TEST(path_join, basic) {
-  char *path = path_join("a", "b");
+  char* path = path_join("a", "b");
   ASSERT_EQ(std::string("a/b"), path);
   free(path);
 }
@@ -418,17 +422,17 @@ TEST(path_is_parent, simple) {
 
 TEST(getmultiline, basic) {
   std::string config =
-           "\n"
-           "mount = none\n"
-           "mount =\\\n"
-           "none\n"
-           "binding = none,/tmp\n"
-           "binding = none,\\\n"
-           "/tmp";
-  FILE *config_file = write_to_pipe(config);
+      "\n"
+      "mount = none\n"
+      "mount =\\\n"
+      "none\n"
+      "binding = none,/tmp\n"
+      "binding = none,\\\n"
+      "/tmp";
+  FILE* config_file = write_to_pipe(config);
   ASSERT_NE(config_file, nullptr);
 
-  char *line = NULL;
+  char* line = NULL;
   size_t len = 0;
   ASSERT_EQ(0, getmultiline(&line, &len, config_file));
   EXPECT_EQ(std::string(line), "");
```

