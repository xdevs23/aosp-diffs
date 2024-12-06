```diff
diff --git a/android/include/netinet/igmp.h b/android/include/netinet/igmp.h
deleted file mode 100644
index ad20b7e9c..000000000
--- a/android/include/netinet/igmp.h
+++ /dev/null
@@ -1 +0,0 @@
-#include <linux/igmp.h>
diff --git a/android/include/sys/io.h b/android/include/sys/io.h
deleted file mode 100644
index 1242daeec..000000000
--- a/android/include/sys/io.h
+++ /dev/null
@@ -1,16 +0,0 @@
-#include <sys/syscall.h>
-#include <asm/unistd.h>
-
-#ifdef __NR_iopl
-static inline int iopl(int level)
-{
-    return syscall(__NR_iopl, level);
-}
-#endif /* __NR_iopl */
-
-#ifdef __NR_ioperm
-static inline int ioperm(unsigned long from, unsigned long num, int turn_on)
-{
-    return syscall(__NR_ioperm, from, num, turn_on);
-}
-#endif /* __NR_ioperm */
diff --git a/include/lapi/syscalls/aarch64.in b/include/lapi/syscalls/aarch64.in
index 2cb6c2d87..3e7797718 100644
--- a/include/lapi/syscalls/aarch64.in
+++ b/include/lapi/syscalls/aarch64.in
@@ -296,5 +296,8 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
 _sysctl 1078
diff --git a/include/lapi/syscalls/arc.in b/include/lapi/syscalls/arc.in
index 3e2ee9061..7fde1d263 100644
--- a/include/lapi/syscalls/arc.in
+++ b/include/lapi/syscalls/arc.in
@@ -316,4 +316,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/arm.in b/include/lapi/syscalls/arm.in
index 7bdbca533..8e76ad164 100644
--- a/include/lapi/syscalls/arm.in
+++ b/include/lapi/syscalls/arm.in
@@ -394,4 +394,8 @@ pidfd_getfd (__NR_SYSCALL_BASE+438)
 faccessat2 (__NR_SYSCALL_BASE+439)
 epoll_pwait2 (__NR_SYSCALL_BASE+441)
 quotactl_fd (__NR_SYSCALL_BASE+443)
+landlock_create_ruleset (__NR_SYSCALL_BASE+444)
+landlock_add_rule (__NR_SYSCALL_BASE+445)
+landlock_restrict_self (__NR_SYSCALL_BASE+446)
+memfd_secret (__NR_SYSCALL_BASE+447)
 futex_waitv (__NR_SYSCALL_BASE+449)
diff --git a/include/lapi/syscalls/hppa.in b/include/lapi/syscalls/hppa.in
index 8ebdafafb..60c02aff2 100644
--- a/include/lapi/syscalls/hppa.in
+++ b/include/lapi/syscalls/hppa.in
@@ -43,4 +43,7 @@ close_range 436
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/i386.in b/include/lapi/syscalls/i386.in
index 1472631c4..31ec1ecb2 100644
--- a/include/lapi/syscalls/i386.in
+++ b/include/lapi/syscalls/i386.in
@@ -430,4 +430,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/ia64.in b/include/lapi/syscalls/ia64.in
index 0ea6e9722..2e56da7f9 100644
--- a/include/lapi/syscalls/ia64.in
+++ b/include/lapi/syscalls/ia64.in
@@ -343,4 +343,7 @@ pidfd_getfd 1462
 faccessat2 1463
 epoll_pwait2 1465
 quotactl_fd 1467
+landlock_create_ruleset 1468
+landlock_add_rule 1469
+landlock_restrict_self 1470
 futex_waitv 1473
diff --git a/include/lapi/syscalls/mips_n32.in b/include/lapi/syscalls/mips_n32.in
index e818c9d92..5f0fe65eb 100644
--- a/include/lapi/syscalls/mips_n32.in
+++ b/include/lapi/syscalls/mips_n32.in
@@ -370,4 +370,7 @@ process_madvise 6440
 epoll_pwait2 6441
 mount_setattr 6442
 quotactl_fd 6443
+landlock_create_ruleset 6444
+landlock_add_rule 6445
+landlock_restrict_self 6446
 futex_waitv 6449
diff --git a/include/lapi/syscalls/mips_n64.in b/include/lapi/syscalls/mips_n64.in
index 6e15f43b3..f81c60e66 100644
--- a/include/lapi/syscalls/mips_n64.in
+++ b/include/lapi/syscalls/mips_n64.in
@@ -346,4 +346,7 @@ process_madvise 5440
 epoll_pwait2 5441
 mount_setattr 5442
 quotactl_fd 5443
+landlock_create_ruleset 5444
+landlock_add_rule 5445
+landlock_restrict_self 5446
 futex_waitv 5449
diff --git a/include/lapi/syscalls/mips_o32.in b/include/lapi/syscalls/mips_o32.in
index 921d5d331..c2beffb75 100644
--- a/include/lapi/syscalls/mips_o32.in
+++ b/include/lapi/syscalls/mips_o32.in
@@ -416,4 +416,7 @@ process_madvise 4440
 epoll_pwait2 4441
 mount_setattr 4442
 quotactl_fd 4443
+landlock_create_ruleset 4444
+landlock_add_rule 4445
+landlock_restrict_self 4446
 futex_waitv 4449
diff --git a/include/lapi/syscalls/powerpc.in b/include/lapi/syscalls/powerpc.in
index 545d9d3d6..5460e4197 100644
--- a/include/lapi/syscalls/powerpc.in
+++ b/include/lapi/syscalls/powerpc.in
@@ -423,4 +423,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/powerpc64.in b/include/lapi/syscalls/powerpc64.in
index 545d9d3d6..5460e4197 100644
--- a/include/lapi/syscalls/powerpc64.in
+++ b/include/lapi/syscalls/powerpc64.in
@@ -423,4 +423,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/s390.in b/include/lapi/syscalls/s390.in
index 7213ac5f8..275b27f47 100644
--- a/include/lapi/syscalls/s390.in
+++ b/include/lapi/syscalls/s390.in
@@ -410,4 +410,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/s390x.in b/include/lapi/syscalls/s390x.in
index 879012e2b..c200d02b2 100644
--- a/include/lapi/syscalls/s390x.in
+++ b/include/lapi/syscalls/s390x.in
@@ -358,4 +358,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/sh.in b/include/lapi/syscalls/sh.in
index 7d5192a27..6f482a77b 100644
--- a/include/lapi/syscalls/sh.in
+++ b/include/lapi/syscalls/sh.in
@@ -404,4 +404,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/sparc.in b/include/lapi/syscalls/sparc.in
index 91d2fb1c2..7181e80a0 100644
--- a/include/lapi/syscalls/sparc.in
+++ b/include/lapi/syscalls/sparc.in
@@ -409,4 +409,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/sparc64.in b/include/lapi/syscalls/sparc64.in
index 1f2fc59b7..c96ab2021 100644
--- a/include/lapi/syscalls/sparc64.in
+++ b/include/lapi/syscalls/sparc64.in
@@ -374,4 +374,7 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
diff --git a/include/lapi/syscalls/x86_64.in b/include/lapi/syscalls/x86_64.in
index dc61aa56e..3082ca110 100644
--- a/include/lapi/syscalls/x86_64.in
+++ b/include/lapi/syscalls/x86_64.in
@@ -351,6 +351,9 @@ pidfd_getfd 438
 faccessat2 439
 epoll_pwait2 441
 quotactl_fd 443
+landlock_create_ruleset 444
+landlock_add_rule 445
+landlock_restrict_self 446
 futex_waitv 449
 rt_sigaction 512
 rt_sigreturn 513
diff --git a/include/tst_device.h b/include/tst_device.h
index 36258f436..1b4a55ae9 100644
--- a/include/tst_device.h
+++ b/include/tst_device.h
@@ -66,7 +66,9 @@ int tst_attach_device(const char *dev_path, const char *file_path);
 uint64_t tst_get_device_size(const char *dev_path);
 
 /*
- * Detaches a file from a loop device fd.
+ * Detaches a file from a loop device fd. @dev_fd needs to be the
+ * last descriptor opened. Call to this function will close it,
+ * it is up to caller to open it again for further usage.
  *
  * @dev_path Path to the loop device e.g. /dev/loop0
  * @dev_fd a open fd for the loop device
diff --git a/lib/tst_device.c b/lib/tst_device.c
index 3691f18d2..5f4af3f89 100644
--- a/lib/tst_device.c
+++ b/lib/tst_device.c
@@ -260,17 +260,23 @@ int tst_detach_device_by_fd(const char *dev, int dev_fd)
 
 	/* keep trying to clear LOOPDEV until we get ENXIO, a quick succession
 	 * of attach/detach might not give udev enough time to complete
+	 *
+	 * Since 18048c1af783 ("loop: Fix a race between loop detach and loop open")
+	 * device is detached only after last close.
 	 */
 	for (i = 0; i < 40; i++) {
 		ret = ioctl(dev_fd, LOOP_CLR_FD, 0);
 
-		if (ret && (errno == ENXIO))
+		if (ret && (errno == ENXIO)) {
+			SAFE_CLOSE(NULL, dev_fd);
 			return 0;
+		}
 
 		if (ret && (errno != EBUSY)) {
 			tst_resm(TWARN,
 				 "ioctl(%s, LOOP_CLR_FD, 0) unexpectedly failed with: %s",
 				 dev, tst_strerrno(errno));
+			SAFE_CLOSE(NULL, dev_fd);
 			return 1;
 		}
 
@@ -279,6 +285,7 @@ int tst_detach_device_by_fd(const char *dev, int dev_fd)
 
 	tst_resm(TWARN,
 		"ioctl(%s, LOOP_CLR_FD, 0) no ENXIO for too long", dev);
+	SAFE_CLOSE(NULL, dev_fd);
 	return 1;
 }
 
@@ -293,7 +300,6 @@ int tst_detach_device(const char *dev)
 	}
 
 	ret = tst_detach_device_by_fd(dev, dev_fd);
-	close(dev_fd);
 	return ret;
 }
 
diff --git a/testcases/kernel/sched/cfs-scheduler/starvation.c b/testcases/kernel/sched/cfs-scheduler/starvation.c
index eb9fd6ff5..e707e0865 100644
--- a/testcases/kernel/sched/cfs-scheduler/starvation.c
+++ b/testcases/kernel/sched/cfs-scheduler/starvation.c
@@ -21,11 +21,38 @@
 #include <sched.h>
 
 #include "tst_test.h"
+#include "tst_safe_clocks.h"
+#include "tst_timer.h"
 
 static char *str_loop;
-static long loop = 2000000;
+static long loop = 1000000;
 static char *str_timeout;
-static int timeout = 240;
+static int timeout;
+
+#define CALLIBRATE_LOOPS 120000000
+
+static int callibrate(void)
+{
+	int i;
+	struct timespec start, stop;
+	long long diff;
+
+	for (i = 0; i < CALLIBRATE_LOOPS; i++)
+		__asm__ __volatile__ ("" : "+g" (i) : :);
+
+	SAFE_CLOCK_GETTIME(CLOCK_MONOTONIC_RAW, &start);
+
+	for (i = 0; i < CALLIBRATE_LOOPS; i++)
+		__asm__ __volatile__ ("" : "+g" (i) : :);
+
+	SAFE_CLOCK_GETTIME(CLOCK_MONOTONIC_RAW, &stop);
+
+	diff = tst_timespec_diff_us(stop, start);
+
+	tst_res(TINFO, "CPU did %i loops in %llius", CALLIBRATE_LOOPS, diff);
+
+	return diff;
+}
 
 static int wait_for_pid(pid_t pid)
 {
@@ -49,18 +76,37 @@ again:
 static void setup(void)
 {
 	cpu_set_t mask;
+	int cpu = 0;
+	long ncpus = tst_ncpus_conf();
 
 	CPU_ZERO(&mask);
 
-	CPU_SET(0, &mask);
+	/* Restrict test to a single cpu */
+	if (sched_getaffinity(0, sizeof(mask), &mask) < 0)
+		tst_brk(TBROK | TERRNO, "sched_getaffinity() failed");
+
+	if (CPU_COUNT(&mask) == 0)
+		tst_brk(TBROK, "No cpus available");
+
+	while (CPU_ISSET(cpu, &mask) == 0 && cpu < ncpus)
+		cpu++;
+
+	CPU_ZERO(&mask);
 
-	TST_EXP_POSITIVE(sched_setaffinity(0, sizeof(mask), &mask));
+	CPU_SET(cpu, &mask);
+
+	tst_res(TINFO, "Setting affinity to CPU %d", cpu);
+
+	if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
+		tst_brk(TBROK | TERRNO, "sched_setaffinity() failed");
 
 	if (tst_parse_long(str_loop, &loop, 1, LONG_MAX))
 		tst_brk(TBROK, "Invalid number of loop number '%s'", str_loop);
 
 	if (tst_parse_int(str_timeout, &timeout, 1, INT_MAX))
 		tst_brk(TBROK, "Invalid number of timeout '%s'", str_timeout);
+	else
+		timeout = callibrate() / 1000;
 
 	tst_set_max_runtime(timeout);
 }
@@ -97,7 +143,13 @@ static void do_test(void)
 		sleep(1);
 
 	SAFE_KILL(child_pid, SIGTERM);
-	TST_EXP_PASS(wait_for_pid(child_pid));
+
+	if (!tst_remaining_runtime())
+		tst_res(TFAIL, "Scheduller starvation reproduced.");
+	else
+		tst_res(TPASS, "Haven't reproduced scheduller starvation.");
+
+	TST_EXP_PASS_SILENT(wait_for_pid(child_pid));
 }
 
 static struct tst_test test = {
diff --git a/testcases/kernel/syscalls/creat/creat07.c b/testcases/kernel/syscalls/creat/creat07.c
index 7bd32ab4d..f157e1a8f 100644
--- a/testcases/kernel/syscalls/creat/creat07.c
+++ b/testcases/kernel/syscalls/creat/creat07.c
@@ -47,7 +47,17 @@ static void verify_creat(void)
 	SAFE_WAITPID(pid, NULL, 0);
 }
 
+static void setup(void)
+{
+	if ((tst_kvercmp(6, 11, 0)) >= 0) {
+		tst_brk(TCONF, "Skipping test, write to executed file is "
+			"allowed since 6.11-rc1.\n"
+			"2a010c412853 (\"fs: don't block i_writecount during exec\")");
+	}
+}
+
 static struct tst_test test = {
+	.setup = setup,
 	.test_all = verify_creat,
 	.needs_checkpoints = 1,
 	.forks_child = 1,
diff --git a/testcases/kernel/syscalls/execve/execve04.c b/testcases/kernel/syscalls/execve/execve04.c
index 3bac642e5..7bbfece85 100644
--- a/testcases/kernel/syscalls/execve/execve04.c
+++ b/testcases/kernel/syscalls/execve/execve04.c
@@ -65,7 +65,17 @@ static void do_child(void)
 	exit(0);
 }
 
+static void setup(void)
+{
+	if ((tst_kvercmp(6, 11, 0)) >= 0) {
+		tst_brk(TCONF, "Skipping test, write to executed file is "
+			"allowed since 6.11-rc1.\n"
+			"2a010c412853 (\"fs: don't block i_writecount during exec\")");
+	}
+}
+
 static struct tst_test test = {
+	.setup = setup,
 	.test_all = verify_execve,
 	.forks_child = 1,
 	.child_needs_reinit = 1,
diff --git a/testcases/kernel/syscalls/ioctl/ioctl09.c b/testcases/kernel/syscalls/ioctl/ioctl09.c
index 9728ecb9c..23ad6e30a 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl09.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl09.c
@@ -84,6 +84,7 @@ static void verify_ioctl(void)
 	check_partition(2, true);
 
 	tst_detach_device_by_fd(dev_path, dev_fd);
+	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 	attach_flag = 0;
 }
 
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop01.c b/testcases/kernel/syscalls/ioctl/ioctl_loop01.c
index 734d803d5..6e259fb15 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop01.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop01.c
@@ -92,6 +92,7 @@ static void verify_ioctl_loop(void)
 	check_loop_value(0, LO_FLAGS_PARTSCAN, 0);
 
 	tst_detach_device_by_fd(dev_path, dev_fd);
+	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 	attach_flag = 0;
 }
 
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop02.c b/testcases/kernel/syscalls/ioctl/ioctl_loop02.c
index 12d4e8230..ce50c2ec5 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop02.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop02.c
@@ -101,6 +101,7 @@ static void verify_ioctl_loop(unsigned int n)
 
 	SAFE_CLOSE(file_fd);
 	tst_detach_device_by_fd(dev_path, dev_fd);
+	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 	attach_flag = 0;
 }
 
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop04.c b/testcases/kernel/syscalls/ioctl/ioctl_loop04.c
index 5b7506ea4..f1021cc77 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop04.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop04.c
@@ -63,6 +63,7 @@ static void verify_ioctl_loop(void)
 
 	SAFE_CLOSE(file_fd);
 	tst_detach_device_by_fd(dev_path, dev_fd);
+	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 	unlink("test.img");
 	attach_flag = 0;
 }
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop06.c b/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
index 64800b4ee..317f693a0 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop06.c
@@ -57,8 +57,10 @@ static void verify_ioctl_loop(unsigned int n)
 
 	if (TST_RET == 0) {
 		tst_res(TFAIL, "Set block size succeed unexpectedly");
-		if (tcases[n].ioctl_flag == LOOP_CONFIGURE)
+		if (tcases[n].ioctl_flag == LOOP_CONFIGURE) {
 			tst_detach_device_by_fd(dev_path, dev_fd);
+			dev_fd = SAFE_OPEN(dev_path, O_RDWR);
+		}
 		return;
 	}
 	if (TST_ERR == EINVAL)
@@ -87,6 +89,7 @@ static void run(unsigned int n)
 	}
 	if (attach_flag) {
 		tst_detach_device_by_fd(dev_path, dev_fd);
+		dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 		attach_flag = 0;
 	}
 	loopconfig.block_size = *(tc->setvalue);
diff --git a/testcases/kernel/syscalls/ioctl/ioctl_loop07.c b/testcases/kernel/syscalls/ioctl/ioctl_loop07.c
index d44f36212..68db79558 100644
--- a/testcases/kernel/syscalls/ioctl/ioctl_loop07.c
+++ b/testcases/kernel/syscalls/ioctl/ioctl_loop07.c
@@ -73,6 +73,7 @@ static void verify_ioctl_loop(unsigned int n)
 	/*Reset*/
 	if (tc->ioctl_flag == LOOP_CONFIGURE) {
 		tst_detach_device_by_fd(dev_path, dev_fd);
+		dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 	} else {
 		loopinfo.lo_sizelimit = 0;
 		TST_RETRY_FUNC(ioctl(dev_fd, LOOP_SET_STATUS, &loopinfo), TST_RETVAL_EQ0);
@@ -101,6 +102,7 @@ static void run(unsigned int n)
 	}
 	if (attach_flag) {
 		tst_detach_device_by_fd(dev_path, dev_fd);
+		dev_fd = SAFE_OPEN(dev_path, O_RDWR);
 		attach_flag = 0;
 	}
 	loopconfig.info.lo_sizelimit = tc->set_sizelimit;
diff --git a/testcases/kernel/syscalls/keyctl/keyctl05.c b/testcases/kernel/syscalls/keyctl/keyctl05.c
index 0ad106774..eee44454b 100644
--- a/testcases/kernel/syscalls/keyctl/keyctl05.c
+++ b/testcases/kernel/syscalls/keyctl/keyctl05.c
@@ -195,8 +195,10 @@ static void test_update_setperm_race(void)
 
 static void setup(void)
 {
+#ifndef __ANDROID__
 	/* There is no way to trigger automatic dns_resolver module loading. */
 	tst_cmd((const char*[]){"modprobe", MODULE, NULL}, NULL, NULL, 0);
+#endif
 
 	fips_enabled = tst_fips_enabled();
 }
```

