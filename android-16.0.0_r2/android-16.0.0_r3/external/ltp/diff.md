```diff
diff --git a/configure.ac b/configure.ac
index 2f71d352c..17ef5d2ab 100644
--- a/configure.ac
+++ b/configure.ac
@@ -48,6 +48,7 @@ AC_CHECK_HEADERS_ONCE([ \
     emmintrin.h \
     ifaddrs.h \
     keyutils.h \
+    linux/blkdev.h \
     linux/can.h \
     linux/cgroupstats.h \
     linux/cryptouser.h \
diff --git a/include/lapi/blkdev.h b/include/lapi/blkdev.h
new file mode 100644
index 000000000..3ee058ce0
--- /dev/null
+++ b/include/lapi/blkdev.h
@@ -0,0 +1,19 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * Copyright (c) 2025 Linux Test Project
+ *  Li Wang <liwang@redhat.com>
+ */
+
+#ifndef LAPI_BLKDEV_H__
+#define LAPI_BLKDEV_H__
+
+#ifdef HAVE_LINUX_BLKDEV_H
+#include <linux/blkdev.h>
+#endif
+
+/* Define BLK_MAX_BLOCK_SIZE for older kernels */
+#ifndef BLK_MAX_BLOCK_SIZE
+#define BLK_MAX_BLOCK_SIZE 0x00010000 /* 64K */
+#endif
+
+#endif /* LAPI_BLKDEV_H */
diff --git a/testcases/kernel/controllers/memcg/control/memcg_control_test.sh b/testcases/kernel/controllers/memcg/control/memcg_control_test.sh
index 68287a70c..79b3a02a9 100644
--- a/testcases/kernel/controllers/memcg/control/memcg_control_test.sh
+++ b/testcases/kernel/controllers/memcg/control/memcg_control_test.sh
@@ -12,7 +12,6 @@ TST_NEEDS_TMPDIR=1
 
 PAGE_SIZE=$(tst_getconf PAGESIZE)
 
-TOT_MEM_LIMIT=$PAGE_SIZE
 ACTIVE_MEM_LIMIT=$PAGE_SIZE
 PROC_MEM=$((PAGE_SIZE * 2))
 
@@ -50,13 +49,22 @@ test1()
 
 	# If the kernel is built without swap, the $memsw_memory_limit file is missing
 	if [ -e "$test_dir/$memsw_memory_limit" ]; then
-		ROD echo "$TOT_MEM_LIMIT" \> "$test_dir/$memsw_memory_limit"
+		if [ "$cgroup_version" = "2" ]; then
+			# v2 does not have a combined memsw limit like v1.
+			# Disable swapping in v2 so all pages get acccounted to the non-swap counter.
+			SWAP_LIMIT=0
+		else
+			# Swapping cannot be disabled via memsw.limit_in_bytes in v1.
+			# Apply a memsw limit in v1 to capture any swapped pages
+			SWAP_LIMIT=$ACTIVE_MEM_LIMIT
+		fi
+		ROD echo "$SWAP_LIMIT" \> "$test_dir/$memsw_memory_limit"
 	fi
 
 	KILLED_CNT=0
 	test_proc_kill
 
-	if [ $PROC_MEM -gt $TOT_MEM_LIMIT ] && [ $KILLED_CNT -eq 0 ]; then
+	if [ $KILLED_CNT -eq 0 ]; then
 		tst_res TFAIL "Test #1: failed"
 	else
 		tst_res TPASS "Test #1: passed"
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop06.c b/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
index 317f693a0..ad34e83c1 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
@@ -16,7 +16,9 @@
 #include <unistd.h>
 #include <sys/types.h>
 #include <stdlib.h>
+#include "lapi/blkdev.h"
 #include "lapi/loop.h"
+#include "tst_fs.h"
 #include "tst_test.h"
 
 static char dev_path[1024];
@@ -33,7 +35,7 @@ static struct tcase {
 	"Using LOOP_SET_BLOCK_SIZE with arg < 512"},
 
 	{&invalid_value, LOOP_SET_BLOCK_SIZE,
-	"Using LOOP_SET_BLOCK_SIZE with arg > PAGE_SIZE"},
+	"Using LOOP_SET_BLOCK_SIZE with arg > BLK_MAX_BLOCK_SIZE"},
 
 	{&unalign_value, LOOP_SET_BLOCK_SIZE,
 	"Using LOOP_SET_BLOCK_SIZE with arg != power_of_2"},
@@ -42,7 +44,7 @@ static struct tcase {
 	"Using LOOP_CONFIGURE with block_size < 512"},
 
 	{&invalid_value, LOOP_CONFIGURE,
-	"Using LOOP_CONFIGURE with block_size > PAGE_SIZE"},
+	"Using LOOP_CONFIGURE with block_size > BLK_MAX_BLOCK_SIZE"},
 
 	{&unalign_value, LOOP_CONFIGURE,
 	"Using LOOP_CONFIGURE with block_size != power_of_2"},
@@ -105,10 +107,12 @@ static void setup(void)
 	if (dev_num < 0)
 		tst_brk(TBROK, "Failed to find free loop device");
 
-	tst_fill_file("test.img", 0, 1024, 1024);
+	size_t bs = (BLK_MAX_BLOCK_SIZE < TST_MB) ? 1024 : 4 * BLK_MAX_BLOCK_SIZE / 1024;
+	tst_fill_file("test.img", 0, bs, 1024);
+
 	half_value = 256;
 	pg_size = getpagesize();
-	invalid_value = pg_size * 2 ;
+	invalid_value = BLK_MAX_BLOCK_SIZE * 2;
 	unalign_value = pg_size - 1;
 
 	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
diff --git a/testcases/lib/tst_test.sh b/testcases/lib/tst_test.sh
index 10506a72b..6ea2da464 100644
--- a/testcases/lib/tst_test.sh
+++ b/testcases/lib/tst_test.sh
@@ -674,7 +674,7 @@ tst_run()
 	local ret
 
 	if [ -n "$TST_TEST_PATH" ]; then
-		for _tst_i in $(grep '^[^#]*\bTST_' "$TST_TEST_PATH" | sed "s/.*TST_//; s/$_tst_pattern//"); do
+		for _tst_i in $(grep '^[^#]*\<TST_' "$TST_TEST_PATH" | sed "s/.*TST_//; s/$_tst_pattern//"); do
 			case "$_tst_i" in
 			ALL_FILESYSTEMS|DISABLE_APPARMOR|DISABLE_SELINUX);;
 			SETUP|CLEANUP|TESTFUNC|ID|CNT|MIN_KVER);;
@@ -696,7 +696,7 @@ tst_run()
 			esac
 		done
 
-		for _tst_i in $(grep '^[^#]*\b_tst_' "$TST_TEST_PATH" | sed "s/.*_tst_//; s/$_tst_pattern//"); do
+		for _tst_i in $(grep '^[^#]*\<_tst_' "$TST_TEST_PATH" | sed "s/.*_tst_//; s/$_tst_pattern//"); do
 			tst_res TWARN "Private variable or function _tst_$_tst_i used!"
 		done
 	fi
```

