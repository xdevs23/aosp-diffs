```diff
diff --git a/OWNERS b/OWNERS
index 7455fd799..110c3bad8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,8 @@
 enh@google.com
 
 cferris@google.com
-chiahungduan@google.com
 danalbert@google.com
+gbiv@google.com
 rprichard@google.com
 yabinc@google.com
 
diff --git a/TEST_MAPPING b/TEST_MAPPING
index f81d34875..593e571f0 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -103,5 +103,15 @@
     {
       "name": "CtsBionicTestCases"
     }
+  ],
+  "wear-cts-presubmit": [
+    {
+      "name": "CtsAppServiceTestCases",
+      "options": [
+       {
+         "include-filter": "android.app.cts.service.ServiceTest"
+       }
+     ]
+    }
   ]
 }
diff --git a/android-changes-for-ndk-developers.md b/android-changes-for-ndk-developers.md
index 24304474d..e094a1d53 100644
--- a/android-changes-for-ndk-developers.md
+++ b/android-changes-for-ndk-developers.md
@@ -108,7 +108,7 @@ symbols will not be made available to libraries loaded by later calls
 to dlopen(3) (as opposed to being referenced by DT_NEEDED entries).
 
 
-## GNU hashes (Availible in API level >= 23)
+## GNU hashes (Available in API level >= 23)
 
 The GNU hash style available with `--hash-style=gnu` allows faster
 symbol lookup and is supported by Android's dynamic linker in API level 23 and
@@ -437,6 +437,8 @@ app-specific one. For example, to enable logging of all dlopen(3)
 adb shell setprop debug.ld.all dlerror,dlopen
 ```
 
+See also `LD_DEBUG`.
+
 
 ## dlclose interacts badly with thread local variables with non-trivial destructors
 
@@ -544,3 +546,20 @@ This was especially confusing (and hard to debug) because the restriction did
 _not_ apply if your app was debuggable. To be compatible with all API levels,
 always give files that need to be extracted a "lib" prefix and ".so" suffix,
 or avoid using `extractNativeLibs`.
+
+
+## The LD_DEBUG environment variable.
+
+On devices running API level 37 or later you can also use the `LD_DEBUG`
+environment variable when running a stand-alone executable such as a unit test.
+The syntax is broadly similar to glibc, and you can get help for the specific
+version of Android you're on by using `LD_DEBUG=help`.
+You can also enable everything by using `LD_DEBUG=all`.
+
+(Older versions of Android also supported `LD_DEBUG`,
+but used integers instead of strings.
+The meaning of those integers varied by release,
+and some releases compiled support for `LD_DEBUG` out of released builds,
+so the best advice is either "look at the corresponding source" or
+"start with `1` and keep increasing the number until you see what you want,
+or see no change in output from the previous value".)
diff --git a/apex/Android.bp b/apex/Android.bp
index d04907b5a..45a7d0878 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -5,6 +5,7 @@
 
 package {
     default_applicable_licenses: ["bionic_apex_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 license {
diff --git a/benchmarks/bionic_benchmarks.cpp b/benchmarks/bionic_benchmarks.cpp
index b88c6e56b..a03a73cc4 100644
--- a/benchmarks/bionic_benchmarks.cpp
+++ b/benchmarks/bionic_benchmarks.cpp
@@ -18,6 +18,7 @@
 #include <getopt.h>
 #include <inttypes.h>
 #include <math.h>
+#include <sys/param.h>
 #include <sys/resource.h>
 
 #include <map>
@@ -250,8 +251,8 @@ static bool ParseOnebufManualStr(std::string& arg, args_vector_t* to_populate) {
     return false;
   }
 
-  // Verify the alignment is powers of 2.
-  if (align != 0 && (align & (align - 1)) != 0) {
+  // Verify the alignment is a power of 2.
+  if (align != 0 && !powerof2(align)) {
     return false;
   }
 
@@ -296,8 +297,7 @@ static bool ParseTwobufManualStr(std::string& arg, args_vector_t* to_populate) {
   }
 
   // Verify the alignments are powers of 2.
-  if ((align1 != 0 && (align1 & (align1 - 1)) != 0)
-      || (align2 != 0 && (align2 & (align2 - 1)) != 0)) {
+  if ((align1 != 0 && !powerof2(align1)) || (align2 != 0 && !powerof2(align2))) {
     return false;
   }
 
@@ -401,8 +401,8 @@ void RegisterCliBenchmarks(bench_opts_t cmdline_opts,
   // Register any of the extra benchmarks that were specified in the options.
   args_vector_t arg_vector;
   args_vector_t* run_args = &arg_vector;
-  for (const std::string& extra_fn : cmdline_opts.extra_benchmarks) {
-    android::base::Trim(extra_fn);
+  for (std::string extra_fn : cmdline_opts.extra_benchmarks) {
+    extra_fn = android::base::Trim(extra_fn);
     size_t first_space_pos = extra_fn.find(' ');
     std::string fn_name = extra_fn.substr(0, first_space_pos);
     std::string cmd_args;
diff --git a/benchmarks/util.cpp b/benchmarks/util.cpp
index ec74147cd..78ba3de62 100644
--- a/benchmarks/util.cpp
+++ b/benchmarks/util.cpp
@@ -21,13 +21,14 @@
 #include <sched.h>
 #include <stdio.h>
 #include <string.h>
+#include <sys/param.h>
 #include <wchar.h>
 
 #include <cstdlib>
 
 // This function returns a pointer less than 2 * alignment + or_mask bytes into the array.
 char* GetAlignedMemory(char* orig_ptr, size_t alignment, size_t or_mask) {
-  if ((alignment & (alignment - 1)) != 0) {
+  if (!powerof2(alignment)) {
     errx(1, "warning: alignment passed into GetAlignedMemory is not a power of two.");
   }
   if (or_mask > alignment) {
diff --git a/cpu_target_features/Android.bp b/cpu_target_features/Android.bp
index 25f37d162..135a1106c 100644
--- a/cpu_target_features/Android.bp
+++ b/cpu_target_features/Android.bp
@@ -1,5 +1,6 @@
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 cc_binary {
diff --git a/docs/32-bit-abi.md b/docs/32-bit-abi.md
index efc681564..0554aefef 100644
--- a/docs/32-bit-abi.md
+++ b/docs/32-bit-abi.md
@@ -121,3 +121,25 @@ between -1 and -4096, set errno and return -1" code is inappropriate for
 these functions. Since LP32 is unlikely to be still supported long before
 those limits could ever matter, although -- unlike the others in this
 document -- this defect is actually fixable, it doesn't seem worth fixing.
+
+
+## `f_fsid` in `struct statvfs` is too small
+
+Linux uses 64 bits to represent a filesystem id in `struct statfs`,
+so the conversion to the POSIX `struct statvfs` with its `unsigned long`
+is necessarily lossy on ILP32 where `long` is 32-bit.
+
+We're not aware that anyone has ever hit this in practice,
+but it's recorded here for completeness.
+
+
+## `dev_t` and `ino_t` are too small
+
+Linux uses 64 bits to represent device and inode numbers,
+but by historical accident Android's 32-bit ABI has them both
+as 32-bit types.
+The corresponding fields in `struct stat` do have the right sizes,
+though this means that they have the wrong types.
+
+We're not aware that anyone has ever hit this in practice,
+but it's recorded here for completeness.
diff --git a/docs/EINTR.md b/docs/EINTR.md
index 8d1ab52e2..36f842ec3 100644
--- a/docs/EINTR.md
+++ b/docs/EINTR.md
@@ -65,11 +65,11 @@ So, for example:
 
 ### close(2)
 
-TL;DR: *never* wrap close(2) calls with `TEMP_FAILURE_RETRY`.
+TL;DR: *never* wrap close(2) calls with `TEMP_FAILURE_RETRY()`.
 
 The case of close(2) is complicated. POSIX explicitly says that close(2)
 shouldn't close the file descriptor if it returns `EINTR`, but that's *not*
-true on Linux (and thus on Android). See
+true for the Linux kernel. See
 [Returning EINTR from close()](https://lwn.net/Articles/576478/)
 for more discussion.
 
@@ -79,6 +79,11 @@ already have been reused by another thread, so the "retry" succeeds, but
 actually closes a *different* file descriptor belonging to a *different*
 thread.
 
+Since API level 23, bionic's close() never returns EINTR,
+but portable code (or code that needs to run on API level 21)
+should not wrap close() with TEMP_FAILURE_RETRY().
+
+
 ### Timeouts
 
 System calls with timeouts are the other interesting case where "just wrap
diff --git a/docs/defines.md b/docs/defines.md
index be48ad8ad..1668a7c40 100644
--- a/docs/defines.md
+++ b/docs/defines.md
@@ -12,6 +12,10 @@ the system property functions. Common alternatives on this dimension are
 `__GLIBC__`, `__APPLE__`, or `_WIN32`. Note that although bionic is most often
 seen on Android devices, it is possible to use bionic on the host too.
 
+(Note that though `__APPLE__` and `_WIN32` are defined by the compiler,
+both `__BIONIC__` and `__GLIBC__` are defined by <sys/cdefs.h>,
+which you should include before testing either of these.)
+
 ## `__ANDROID__`
 
 If your code is specific to Android devices, use `__ANDROID__`. This isn't
@@ -21,6 +25,8 @@ of the OS and needs to behave differently on the host than on the device.
 Genuine cases are quite rare, and `__BIONIC__` is often more specific (but
 remember that it is possible -- if unusual -- to use bionic on the host).
 
+(This is defined by the compiler.)
+
 ## `ANDROID` (rarely useful)
 
 Not to be confused with `__ANDROID__`, the similar-looking but very different
@@ -42,6 +48,8 @@ that for most of the year, the OS builds with this set to 10,000 rather than the
 obvious "next" API level such as 19. Once the API level has been decided, the
 value of `__ANDROID_API__` drops to that number.
 
+(This is defined by the compiler, based on the api level in your target triple.)
+
 ## `__linux__`
 
 If your code requires a Linux kernel, use `__linux__`. This is typically a good
@@ -50,6 +58,8 @@ a file in `/proc`, but aren't restricted to just Android and would work equally
 well on a desktop Linux distro, say. Common alternatives on this dimension
 are `__APPLE__` or `_WIN32`.
 
+(This is defined by the compiler.)
+
 ## `__ANDROID_NDK__`
 
 If your code can be built either as part of an app _or_ as part of the OS
@@ -57,12 +67,16 @@ itself, use `__ANDROID_NDK__` to differentiate between those two circumstances.
 This is typically a good choice when your code uses non-NDK API if it's built as
 part of the OS, but sticks to just the NDK APIs otherwise.
 
+(This is available after including <sys/cdefs.h> directly or transitively.)
+
 ## `__NDK_MAJOR__`, `__NDK_MINOR__`, `__NDK_BETA__`, `__NDK_BUILD__`, `__NDK_CANARY__`
 
 If your code can be built with a variety of different NDK versions, and needs to
-work around issues with some of them, use these macros to detect the versinon of
+work around issues with some of them, use these macros to detect the version of
 the NDK you're being built with. Usually only `__NDK_MAJOR__` will be necessary.
 
+(These are available after including <sys/cdefs.h> directly or transitively.)
+
 ## `__arm__`/`__aarch64__`, `__i386__`/`__x86_64__`, `__riscv`
 
 If your code is specific to a particular processor architecture, use
@@ -73,9 +87,13 @@ check for Android-only code. If you need to write code portable to other
 operating systems that do support riscv32, you'll also need to check
 whether `__riscv_xlen` is 32 or 64.
 
+(These are defined by the compiler.)
+
 ## `__ILP32__` and `__LP64__`
 
 If your code depends on "bitness" -- whether `long` and pointers are 32-
 or 64-bit -- use these macros to conditionally compile. Note the extra
 "I" in the 32-bit macro (since `int`, `long`, and pointers are all 32-bit
 on such systems, with `long long` being needed for a 64-bit type).
+
+(These are defined by the compiler.)
diff --git a/docs/status.md b/docs/status.md
index 034f115e1..b612108e0 100644
--- a/docs/status.md
+++ b/docs/status.md
@@ -240,88 +240,6 @@ New libc functions in M (API level 23):
   * all of <error.h>.
   * re-introduced various <resolv.h> functions: `ns_format_ttl`, `ns_get16`, `ns_get32`, `ns_initparse`, `ns_makecanon`, `ns_msg_getflag`, `ns_name_compress`, `ns_name_ntol`, `ns_name_ntop`, `ns_name_pack`, `ns_name_pton`, `ns_name_rollback`, `ns_name_skip`, `ns_name_uncompress`, `ns_name_unpack`, `ns_parserr`, `ns_put16`, `ns_put32`, `ns_samename`, `ns_skiprr`, `ns_sprintrr`, and `ns_sprintrrf`.
 
-New libc functions in L (API level 21):
-  * <android/dlext.h>.
-  * <android/set_abort_message.h>.
-  * <arpa/inet.h> `inet_lnaof`, `inet_netof`, `inet_network`, `inet_makeaddr`.
-  * <wctype.h> `iswblank`.
-  * <ctype.h> `isalnum_l`, `isalpha_l`, `isblank_l`, `icntrl_l`, `isdigit_l`, `isgraph_l`, `islower_l`, `isprint_l`, `ispunct_l`, `isspace_l`, `isupper_l`, `isxdigit_l`, `_tolower`, `tolower_l`, `_toupper`, `toupper_l`.
-  * <fcntl.h> `fallocate`, `posix_fadvise`, `posix_fallocate`, `splice`, `tee`, `vmsplice`.
-  * <inttypes.h> `wcstoimax`, `wcstoumax`.
-  * <link.h> `dl_iterate_phdr`.
-  * <mntent.h> `setmntent`, `endmntent`, `getmntent_r`.
-  * <poll.h> `ppoll`.
-  * <pthread.h> `pthread_condattr_getclock`, `pthread_condattr_setclock`, `pthread_mutex_timedlock`, `pthread_gettid_np`.
-  * <sched.h> `setns`.
-  * <search.h> `insque`, `remque`, `lfind`, `lsearch`, `twalk`.
-  * <stdio.h> `dprintf`, `vdprintf`.
-  * <stdlib.h> `initstate`, `setstate`, `getprogname`/`setprogname`, `atof`/`strtof`, `at_quick_exit`/`_Exit`/`quick_exit`, `grantpt`, `mbtowc`/`wctomb`, `posix_openpt`, `rand_r`/`rand`/`random`/`srand`/`srandom`, `strtold_l`/`strtoll_l`/`strtoull_l`.
-  * <string.h> `strcoll_l`/`strxfrm_l`, `stpcpy`/`stpncpy`.
-  * <sys/resource.h> `prlimit`.
-  * <sys/socket.h> `accept4`, `sendmmsg`.
-  * <sys/stat.h> `mkfifo`/`mknodat`.
-  * <time.h> `strftime_l`.
-  * <unistd.h> `dup3`, `execvpe`, `getpagesize`, `linkat`/`symlinkat`/`readlinkat`, `truncate`.
-  * <wchar.h> `wcstof`, `vfwscanf`/`vswscanf`/`vwscanf`, `wcstold_l`/`wcstoll`/`wcstoll_l`/`wcstoull`/`wcstoull_l`, `mbsnrtowcs`/`wcsnrtombs`, `wcscoll_l`/`wcsxfrm_l`.
-  * <wctype.h> `iswalnum_l`/`iswalpha_l`/`iswblank_l`/`iswcntrl_l`/`iswctype_l`/`iswdigit_l`/`iswgraph_l`/`iswlower_l`/`iswprint_l`/`iswpunct_l`/`iswspace_l`/`iswupper_l`/`iswxdigit_l`, `wctype_l`, `towlower_l`/`towupper_l`.
-  * all of <fts.h>.
-  * all of <locale.h>.
-  * all of <sys/epoll.h>.
-  * all of <sys/fsuid.h>.
-  * all of <sys/inotify.h>.
-  * all of <uchar.h>.
-
-New libc functions in K (API level 19):
-  * <inttypes.h> `imaxabs`, `imaxdiv`.
-  * <stdlib.h> `abs`, `labs`, `llabs`.
-  * <sys/stat.h> `futimens`.
-  * all of <sys/statvfs.h>.
-  * all of <sys/swap.h>.
-  * all of <sys/timerfd.h>.
-
-New libc functions in J-MR2 (API level 18):
-  * <stdio.h> `getdelim` and `getline`.
-  * <sys/auxv.h> `getauxval`.
-  * <sys/signalfd.h> `signalfd`.
-
-New libc functions in J-MR1 (API level 17):
-  * <ftw.h>.
-  * <signal.h> `psiginfo` and `psignal`.
-  * `getsid`, `malloc_usable_size`, `mlockall`/`munlockall`, `posix_memalign`, `unshare`.
-
-New libc functions in J (API level 16):
-  * the <search.h> tree functions `tdelete`, `tdestroy`, `tfind`, and `tsearch`.
-  * `faccessat`, `readahead`, `tgkill`.
-  * all of <sys/xattr.h>.
-
-libc function count over time:
-
-| API level | Function count |
-|-----------|----------------|
-| 16        | 842            |
-| 17        | 870            |
-| 18        | 878            |
-| 19        | 893            |
-| 21        | 1016           |
-| 22        | 1038           |
-| 23        | 1103           |
-| 24        | 1147           |
-| 25        | 1147           |
-| 26        | 1199           |
-| 27        | 1199           |
-| 28        | 1298           |
-| 29        | 1312           |
-| 30        | 1368           |
-| 31        | 1379           |
-| 32        | 1379           |
-| 33        | 1386           |
-| 34        | 1392           |
-
-Data collected by:
-```
-ndk-r26c$ for i in `ls -1v toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/*/libc.so` ; \
-  do echo $i; nm $i | grep -w T | wc -l ; done
-```
 
 ### libm
 
@@ -336,13 +254,6 @@ New libm functions in M (API level 23):
   * <complex.h> `cabs`, `carg`, `cimag`, `cacos`, `cacosh`, `casin`, `casinh`, `catan`, `catanh`, `ccos`, `ccosh`, `cexp`, `conj`, `cproj`, `csin`, `csinh`, `csqrt`, `ctan`, `ctanh`, `creal`, `cabsf`, `cargf`, `cimagf`, `cacosf`, `cacoshf`, `casinf`, `casinhf`, `catanf`, `catanhf`, `ccosf`, `ccoshf`, `cexpf`, `conjf`, `cprojf`, `csinf`, `csinhf`, `csqrtf`, `ctanf`, `ctanhf`, `crealf`, `cabsl`, `cprojl`, `csqrtl`.
   * <math.h> `lgammal_r`.
 
-New libm functions in L (API level 21):
-  * <complex.h> `cabsl`, `cprojl`, `csqrtl`.
-  * <math.h> `isinf`, `significandl`.
-
-New libm functions in J-MR2 (API level 18):
-  * <math.h> `log2`, `log2f`.
-
 
 ## Target API level behavioral differences
 
diff --git a/libc/Android.bp b/libc/Android.bp
index f5624efc1..07a4c6a0f 100644
--- a/libc/Android.bp
+++ b/libc/Android.bp
@@ -1,5 +1,6 @@
 package {
     default_applicable_licenses: ["bionic_libc_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 license {
@@ -377,14 +378,11 @@ cc_library_static {
         "upstream-freebsd/lib/libc/stdlib/hcreate_r.c",
         "upstream-freebsd/lib/libc/stdlib/hdestroy_r.c",
         "upstream-freebsd/lib/libc/stdlib/hsearch_r.c",
-        "upstream-freebsd/lib/libc/stdlib/qsort.c",
-        "upstream-freebsd/lib/libc/stdlib/qsort_r.c",
         "upstream-freebsd/lib/libc/stdlib/quick_exit.c",
         "upstream-freebsd/lib/libc/string/wcpcpy.c",
         "upstream-freebsd/lib/libc/string/wcpncpy.c",
         "upstream-freebsd/lib/libc/string/wcscasecmp.c",
         "upstream-freebsd/lib/libc/string/wcscat.c",
-        "upstream-freebsd/lib/libc/string/wcschr.c",
         "upstream-freebsd/lib/libc/string/wcscmp.c",
         "upstream-freebsd/lib/libc/string/wcscpy.c",
         "upstream-freebsd/lib/libc/string/wcscspn.c",
@@ -453,8 +451,6 @@ cc_library_static {
     srcs: [
         "upstream-netbsd/common/lib/libc/stdlib/random.c",
         "upstream-netbsd/lib/libc/gen/nice.c",
-        "upstream-netbsd/lib/libc/gen/psignal.c",
-        "upstream-netbsd/lib/libc/gen/utime.c",
         "upstream-netbsd/lib/libc/inet/nsap_addr.c",
         "upstream-netbsd/lib/libc/regex/regcomp.c",
         "upstream-netbsd/lib/libc/regex/regerror.c",
@@ -565,20 +561,9 @@ cc_library_static {
         "upstream-openbsd/lib/libc/stdio/vswscanf.c",
         "upstream-openbsd/lib/libc/stdio/wbuf.c",
         "upstream-openbsd/lib/libc/stdio/wsetup.c",
-        "upstream-openbsd/lib/libc/stdlib/abs.c",
-        "upstream-openbsd/lib/libc/stdlib/div.c",
         "upstream-openbsd/lib/libc/stdlib/getenv.c",
         "upstream-openbsd/lib/libc/stdlib/getsubopt.c",
-        "upstream-openbsd/lib/libc/stdlib/insque.c",
-        "upstream-openbsd/lib/libc/stdlib/imaxabs.c",
-        "upstream-openbsd/lib/libc/stdlib/imaxdiv.c",
-        "upstream-openbsd/lib/libc/stdlib/labs.c",
-        "upstream-openbsd/lib/libc/stdlib/ldiv.c",
-        "upstream-openbsd/lib/libc/stdlib/llabs.c",
-        "upstream-openbsd/lib/libc/stdlib/lldiv.c",
-        "upstream-openbsd/lib/libc/stdlib/lsearch.c",
         "upstream-openbsd/lib/libc/stdlib/recallocarray.c",
-        "upstream-openbsd/lib/libc/stdlib/remque.c",
         "upstream-openbsd/lib/libc/stdlib/setenv.c",
         "upstream-openbsd/lib/libc/stdlib/tfind.c",
         "upstream-openbsd/lib/libc/stdlib/tsearch.c",
@@ -1037,6 +1022,7 @@ cc_library_static {
         "bionic/umount.cpp",
         "bionic/unlink.cpp",
         "bionic/usleep.cpp",
+        "bionic/utime.cpp",
         "bionic/utmp.cpp",
         "bionic/vdso.cpp",
         "bionic/wait.cpp",
@@ -1186,6 +1172,7 @@ cc_library_static {
                 "arch-x86_64/bionic/syscall.S",
                 "arch-x86_64/bionic/vfork.S",
 
+                "arch-x86_64/string/avx2-memmove-kbl.S",
                 "arch-x86_64/string/avx2-memset-kbl.S",
                 "arch-x86_64/string/sse2-memmove-slm.S",
                 "arch-x86_64/string/sse2-memset-slm.S",
@@ -1356,24 +1343,23 @@ cc_library_static {
 
 // ========================================================
 // libc_static_dispatch.a/libc_dynamic_dispatch.a --- string/memory "ifuncs"
-// (Actually ifuncs for libc.so, but a home-grown alternative for libc.a.)
 // ========================================================
 
 cc_defaults {
-    name: "libc_dispatch_defaults",
+    name: "libc_ifunc_defaults",
     defaults: ["libc_defaults"],
     arch: {
-        x86_64: {
-            srcs: ["arch-x86_64/dynamic_function_dispatch.cpp"],
-        },
-        x86: {
-            srcs: ["arch-x86/dynamic_function_dispatch.cpp"],
-        },
         arm: {
-            srcs: ["arch-arm/dynamic_function_dispatch.cpp"],
+            srcs: ["arch-arm/ifuncs.cpp"],
         },
         arm64: {
-            srcs: ["arch-arm64/dynamic_function_dispatch.cpp"],
+            srcs: ["arch-arm64/ifuncs.cpp"],
+        },
+        x86: {
+            srcs: ["arch-x86/ifuncs.cpp"],
+        },
+        x86_64: {
+            srcs: ["arch-x86_64/ifuncs.cpp"],
         },
     },
     // Prevent the compiler from inserting calls to libc/taking the address of
@@ -1388,7 +1374,7 @@ cc_defaults {
 
 cc_library_static {
     name: "libc_static_dispatch",
-    defaults: ["libc_dispatch_defaults"],
+    defaults: ["libc_ifunc_defaults"],
     cflags: [
         "-DBIONIC_STATIC_DISPATCH",
     ],
@@ -1396,7 +1382,7 @@ cc_library_static {
 
 cc_library_static {
     name: "libc_dynamic_dispatch",
-    defaults: ["libc_dispatch_defaults"],
+    defaults: ["libc_ifunc_defaults"],
     cflags: [
         "-DBIONIC_DYNAMIC_DISPATCH",
     ],
@@ -1627,6 +1613,7 @@ cc_library {
         export_headers_as_system: true,
         export_llndk_headers: ["libc_headers"],
     },
+    afdo: true,
 }
 
 cc_library {
@@ -1708,7 +1695,6 @@ cc_library_headers {
         "//art:__subpackages__",
         "//bionic:__subpackages__",
         "//frameworks:__subpackages__",
-        "//device/generic/goldfish-opengl:__subpackages__",
         "//external/gwp_asan:__subpackages__",
         "//external/perfetto:__subpackages__",
         "//external/scudo:__subpackages__",
@@ -1957,7 +1943,7 @@ cc_defaults {
         "//apex_available:anyapex",
     ],
     // Generate NDK variants of the CRT objects for every supported API level.
-    min_sdk_version: "16",
+    min_sdk_version: "21",
     stl: "none",
     crt: true,
     cflags: [
@@ -1973,6 +1959,11 @@ cc_defaults {
 cc_defaults {
     name: "crt_defaults",
     defaults: ["crt_and_memtag_defaults"],
+    header_libs: ["libc_headers"],
+    local_include_dirs: [
+        "bionic", // crtbegin includes bionic/libc_init_common.h
+        "private", // crtbrand depends on private/bionic_asm_note.h
+    ],
     system_shared_libs: [],
 }
 
@@ -1984,9 +1975,7 @@ cc_defaults {
 
 cc_object {
     name: "crtbrand",
-    local_include_dirs: [
-        "private", // crtbrand.S depends on private/bionic_asm_note.h
-    ],
+    defaults: ["crt_so_defaults"],
     // crtbrand.S needs to know the platform SDK version.
     product_variables: {
         platform_sdk_version: {
@@ -1994,18 +1983,14 @@ cc_object {
         },
     },
     srcs: ["arch-common/bionic/crtbrand.S"],
-
-    defaults: ["crt_so_defaults"],
     // crtbrand is an intermediate artifact, not a final CRT object.
     exclude_from_ndk_sysroot: true,
 }
 
 cc_object {
     name: "crtbegin_so",
-    local_include_dirs: ["include"],
-    srcs: ["arch-common/bionic/crtbegin_so.c"],
-
     defaults: ["crt_so_defaults"],
+    srcs: ["arch-common/bionic/crtbegin_so.c"],
     objs: [
         "crtbrand",
     ],
@@ -2013,40 +1998,25 @@ cc_object {
 
 cc_object {
     name: "crtend_so",
-    local_include_dirs: [
-        "private", // crtend_so.S depends on private/bionic_asm_arm64.h
-    ],
-    srcs: ["arch-common/bionic/crtend_so.S"],
-
     defaults: ["crt_so_defaults"],
+    srcs: ["arch-common/bionic/crtend_so.S"],
 }
 
 cc_object {
     name: "crtbegin_static",
-
-    local_include_dirs: [
-        "include",
-        "bionic", // crtbegin.c includes bionic/libc_init_common.h
-    ],
-
+    defaults: ["crt_defaults"],
     cflags: ["-DCRTBEGIN_STATIC"],
-
     srcs: ["arch-common/bionic/crtbegin.c"],
     objs: [
         "crtbrand",
     ],
-    defaults: ["crt_defaults"],
     // When using libc.a, we're using the latest library regardless of target API level.
     min_sdk_version: "current",
 }
 
 cc_object {
     name: "crtbegin_dynamic",
-
-    local_include_dirs: [
-        "include",
-        "bionic", // crtbegin.c includes bionic/libc_init_common.h
-    ],
+    defaults: ["crt_defaults"],
     srcs: ["arch-common/bionic/crtbegin.c"],
     objs: [
         "crtbrand",
@@ -2059,53 +2029,42 @@ cc_object {
             ],
         },
     },
-    defaults: ["crt_defaults"],
 }
 
 cc_object {
     // We rename crtend.o to crtend_android.o to avoid a
     // name clash between gcc and bionic.
     name: "crtend_android",
-    local_include_dirs: [
-        "private", // crtend.S depends on private/bionic_asm_arm64.h
-    ],
-    srcs: ["arch-common/bionic/crtend.S"],
-
     defaults: ["crt_defaults"],
+    srcs: ["arch-common/bionic/crtend.S"],
 }
 
 cc_object {
     name: "crt_pad_segment",
-    local_include_dirs: [
-        "private", // crt_pad_segment.S depends on private/bionic_asm_note.h
-    ],
-    srcs: ["arch-common/bionic/crt_pad_segment.S"],
-
     defaults: ["crt_defaults"],
+    srcs: ["arch-common/bionic/crt_pad_segment.S"],
 }
 
 cc_library_static {
     name: "note_memtag_heap_async",
+    defaults: ["crt_and_memtag_defaults"],
     arch: {
         arm64: {
             srcs: ["arch-arm64/bionic/note_memtag_heap_async.S"],
         },
     },
     sdk_version: "minimum",
-
-    defaults: ["crt_and_memtag_defaults"],
 }
 
 cc_library_static {
     name: "note_memtag_heap_sync",
+    defaults: ["crt_and_memtag_defaults"],
     arch: {
         arm64: {
             srcs: ["arch-arm64/bionic/note_memtag_heap_sync.S"],
         },
     },
     sdk_version: "minimum",
-
-    defaults: ["crt_and_memtag_defaults"],
 }
 
 // ========================================================
@@ -2129,6 +2088,9 @@ cc_library_static {
         "-Wall",
         "-Werror",
     ],
+    asflags: [
+        "-DBIONIC_RUST_BAREMETAL",
+    ],
     srcs: [
         "bionic/fortify.cpp",
         "bionic/strtol.cpp",
@@ -2147,9 +2109,11 @@ cc_library_static {
         },
         x86_64: {
             asflags: [
-                // Statically choose the SSE2 memset_generic as memset for
-                // baremetal, where we do not have the dynamic function
-                // dispatch machinery.
+                // Statically choose the SSE2 variants for baremetal,
+                // where we do not have the dynamic function dispatch
+                // machinery.
+                "-D__memcpy_chk_generic=__memcpy_chk",
+                "-Dmemmove_generic=memmove",
                 "-Dmemset_generic=memset",
             ],
             srcs: [
@@ -2825,6 +2789,7 @@ cc_genrule {
         "kernel/android/**/*.h",
         "execinfo/include/**/*.h",
         "b64/include/**/*.h",
+        "include/*.h",
 
         "NOTICE",
 
diff --git a/libc/NOTICE b/libc/NOTICE
index c869a31ae..0eda4093a 100644
--- a/libc/NOTICE
+++ b/libc/NOTICE
@@ -1,31 +1,3 @@
- Copyright (c) 1993 John Brezak
- All rights reserved.
-
- Redistribution and use in source and binary forms, with or without
- modification, are permitted provided that the following conditions
- are met:
- 1. Redistributions of source code must retain the above copyright
-    notice, this list of conditions and the following disclaimer.
- 2. Redistributions in binary form must reproduce the above copyright
-    notice, this list of conditions and the following disclaimer in the
-    documentation and/or other materials provided with the distribution.
- 3. The name of the author may be used to endorse or promote products
-    derived from this software without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
-IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
-INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
-SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
-STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
-ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-POSSIBILITY OF SUCH DAMAGE.
-
--------------------------------------------------------------------
-
  Copyright (c) 2009-2013 The Linux Foundation. All rights reserved.
 
  Redistribution and use in source and binary forms, with or without
@@ -934,6 +906,34 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
+Copyright (C) 2025 The Android Open Source Project
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions
+are met:
+ * Redistributions of source code must retain the above copyright
+   notice, this list of conditions and the following disclaimer.
+ * Redistributions in binary form must reproduce the above copyright
+   notice, this list of conditions and the following disclaimer in
+   the documentation and/or other materials provided with the
+   distribution.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+SUCH DAMAGE.
+
+-------------------------------------------------------------------
+
 Copyright (c) 1980, 1983, 1988, 1993
    The Regents of the University of California.  All rights reserved.
 
@@ -1803,38 +1803,6 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 1989, 1993
-   The Regents of the University of California.  All rights reserved.
-
-This code is derived from software contributed to Berkeley by
-Roger L. Snyder.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions
-are met:
-1. Redistributions of source code must retain the above copyright
-   notice, this list of conditions and the following disclaimer.
-2. Redistributions in binary form must reproduce the above copyright
-   notice, this list of conditions and the following disclaimer in the
-   documentation and/or other materials provided with the distribution.
-3. Neither the name of the University nor the names of its contributors
-   may be used to endorse or promote products derived from this software
-   without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
-FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-SUCH DAMAGE.
-
--------------------------------------------------------------------
-
 Copyright (c) 1989, 1993
    The Regents of the University of California.  All rights reserved.
 (c) UNIX System Laboratories, Inc.
@@ -1869,38 +1837,6 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 1990 Regents of the University of California.
-All rights reserved.
-
-This code is derived from software contributed to Berkeley by
-Chris Torek.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions
-are met:
-1. Redistributions of source code must retain the above copyright
-   notice, this list of conditions and the following disclaimer.
-2. Redistributions in binary form must reproduce the above copyright
-   notice, this list of conditions and the following disclaimer in the
-   documentation and/or other materials provided with the distribution.
-3. Neither the name of the University nor the names of its contributors
-   may be used to endorse or promote products derived from this software
-   without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
-FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-SUCH DAMAGE.
-
--------------------------------------------------------------------
-
 Copyright (c) 1990 The Regents of the University of California.
 All rights reserved.
 
@@ -4175,6 +4111,36 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
+Copyright (c) 2024, Intel Corporation
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions are met:
+
+    * Redistributions of source code must retain the above copyright notice,
+    * this list of conditions and the following disclaimer.
+
+    * Redistributions in binary form must reproduce the above copyright notice,
+    * this list of conditions and the following disclaimer in the documentation
+    * and/or other materials provided with the distribution.
+
+    * Neither the name of Intel Corporation nor the names of its contributors
+    * may be used to endorse or promote products derived from this software
+    * without specific prior written permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
+ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
+WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
+DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
+ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
+LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
+ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
+SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+
+-------------------------------------------------------------------
+
 Copyright (c)1999 Citrus Project,
 All rights reserved.
 
@@ -4701,37 +4667,6 @@ SUCH DAMAGE.
 
 SPDX-License-Identifier: BSD-3-Clause
 
-Copyright (c) 1992, 1993
-   The Regents of the University of California.  All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions
-are met:
-1. Redistributions of source code must retain the above copyright
-   notice, this list of conditions and the following disclaimer.
-2. Redistributions in binary form must reproduce the above copyright
-   notice, this list of conditions and the following disclaimer in the
-   documentation and/or other materials provided with the distribution.
-3. Neither the name of the University nor the names of its contributors
-   may be used to endorse or promote products derived from this software
-   without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
-FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-SUCH DAMAGE.
-
--------------------------------------------------------------------
-
-SPDX-License-Identifier: BSD-3-Clause
-
 Copyright (c) 1992, 1993, 1994 Henry Spencer.
 Copyright (c) 1992, 1993, 1994
    The Regents of the University of California.  All rights reserved.
diff --git a/libc/SECCOMP_ALLOWLIST_COMMON.TXT b/libc/SECCOMP_ALLOWLIST_COMMON.TXT
index 41db4e86a..045fc8b63 100644
--- a/libc/SECCOMP_ALLOWLIST_COMMON.TXT
+++ b/libc/SECCOMP_ALLOWLIST_COMMON.TXT
@@ -79,8 +79,21 @@ sched_rr_get_interval_time64(pid_t, timespec64*) lp32
 # support seems potentially useful for Android (though the struct that
 # changes size over time is obviously problematic).
 clone3(clone_args*, size_t) all
-# Since 5.13, not in glibc. Probed for and conditionally used by
+# Since Linux 5.6, not in glibc (but coming to 2.42?). http://b/371578624
+openat2(int, const char*, open_how*, size_t) all
+# Since Linux 5.8, not in glibc. Commonly requested to reimplement faccessat()
+# for better source compatibility, but tricky to retcon into all the seccomp filters.
+faccessat2(int, const char*, int, int) all
+# Since Linux 5.13, not in glibc. Probed for and conditionally used by
 # Chrome GPU processes.
 landlock_add_rule(int, uint64_t, const void*, uint32_t) all
 landlock_create_ruleset(const landlock_ruleset_attr*, size_t, uint64_t) all
 landlock_restrict_self(int, uint64_t) all
+# Since Linux 6.6, not in glibc. Common requested to reimplement fchmodat()
+# for better source compatibility, but tricky to retcon into all the seccomp filters.
+fchmodat2(int, const char*, mode_t, int) all
+# Since Linux 6.13, not in glibc.
+setxattrat(int, const char*, unsigned, const char*, const xattr_args*, size_t) all
+getxattrat(int, const char*, unsigned, const char*, xattr_args*, size_t) all
+listxattrat(int, const char*, unsigned, char*, size_t) all
+removexattrat(int, const char*, unsigned, const char*) all
diff --git a/libc/SYSCALLS.TXT b/libc/SYSCALLS.TXT
index 31651cd88..55ca9f4f6 100644
--- a/libc/SYSCALLS.TXT
+++ b/libc/SYSCALLS.TXT
@@ -266,8 +266,8 @@ __socket:socket(int, int, int)              arm,lp64
 __socketpair:socketpair(int, int, int, int*)    arm,lp64
 bind(int, struct sockaddr*, socklen_t)  arm,lp64
 __connect:connect(int, struct sockaddr*, socklen_t)   arm,lp64
-listen(int, int)                   arm,lp64
-__accept4:accept4(int, struct sockaddr*, socklen_t*, int)  arm,lp64
+listen(int, int) all
+__accept4:accept4(int, struct sockaddr*, socklen_t*, int)  all
 getsockname(int, struct sockaddr*, socklen_t*)  arm,lp64
 getpeername(int, struct sockaddr*, socklen_t*)  arm,lp64
 __sendto:sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  arm,lp64
@@ -277,14 +277,13 @@ setsockopt(int, int, int, const void*, socklen_t)  arm,lp64
 getsockopt(int, int, int, void*, socklen_t*)    arm,lp64
 __recvmsg:recvmsg(int, struct msghdr*, unsigned int)   arm,lp64
 __sendmsg:sendmsg(int, const struct msghdr*, unsigned int)  arm,lp64
-__recvmmsg:recvmmsg(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   arm,lp64
-__sendmmsg:sendmmsg(int, struct mmsghdr*, unsigned int, int)   arm,lp64
+__recvmmsg:recvmmsg(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   all
+__sendmmsg:sendmmsg(int, struct mmsghdr*, unsigned int, int)   all
 
 # sockets for x86. These are done as an "indexed" call to socketcall syscall.
 __socket:socketcall:1(int, int, int) x86
 bind:socketcall:2(int, struct sockaddr*, int)  x86
 __connect:socketcall:3(int, struct sockaddr*, socklen_t)   x86
-listen:socketcall:4(int, int)                   x86
 getsockname:socketcall:6(int, struct sockaddr*, socklen_t*)  x86
 getpeername:socketcall:7(int, struct sockaddr*, socklen_t*)  x86
 __socketpair:socketcall:8(int, int, int, int*)    x86
@@ -295,9 +294,6 @@ setsockopt:socketcall:14(int, int, int, const void*, socklen_t)  x86
 getsockopt:socketcall:15(int, int, int, void*, socklen_t*)    x86
 __sendmsg:socketcall:16(int, const struct msghdr*, unsigned int)  x86
 __recvmsg:socketcall:17(int, struct msghdr*, unsigned int)   x86
-__accept4:socketcall:18(int, struct sockaddr*, socklen_t*, int)  x86
-__recvmmsg:socketcall:19(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   x86
-__sendmmsg:socketcall:20(int, struct mmsghdr*, unsigned int, int)   x86
 
 # scheduler & real-time
 sched_get_priority_max(int policy) all
diff --git a/libc/arch-arm/dynamic_function_dispatch.cpp b/libc/arch-arm/ifuncs.cpp
similarity index 100%
rename from libc/arch-arm/dynamic_function_dispatch.cpp
rename to libc/arch-arm/ifuncs.cpp
diff --git a/libc/arch-arm64/dynamic_function_dispatch.cpp b/libc/arch-arm64/ifuncs.cpp
similarity index 100%
rename from libc/arch-arm64/dynamic_function_dispatch.cpp
rename to libc/arch-arm64/ifuncs.cpp
diff --git a/libc/arch-common/bionic/crt_pad_segment.S b/libc/arch-common/bionic/crt_pad_segment.S
index 2fbe0b905..2c39f931d 100644
--- a/libc/arch-common/bionic/crt_pad_segment.S
+++ b/libc/arch-common/bionic/crt_pad_segment.S
@@ -26,13 +26,10 @@
  * SUCH DAMAGE.
  */
 
-#if defined(__aarch64__)
-#include <private/bionic_asm_arm64.h>
+#include <private/bionic_asm.h>
+#include <private/bionic_asm_note.h>
 
 __bionic_asm_custom_note_gnu_section()
-#endif
-
-#include <private/bionic_asm_note.h>
 
   .section ".note.android.pad_segment", "a", %note
   .balign 4
diff --git a/libc/arch-common/bionic/crtbrand.S b/libc/arch-common/bionic/crtbrand.S
index b7540e97e..26b973fec 100644
--- a/libc/arch-common/bionic/crtbrand.S
+++ b/libc/arch-common/bionic/crtbrand.S
@@ -26,13 +26,10 @@
  * SUCH DAMAGE.
  */
 
-#if defined(__aarch64__)
-#include <private/bionic_asm_arm64.h>
+#include <private/bionic_asm.h>
+#include <private/bionic_asm_note.h>
 
 __bionic_asm_custom_note_gnu_section()
-#endif
-
-#include <private/bionic_asm_note.h>
 
   .section .note.android.ident,"a",%note
   .balign 4
diff --git a/libc/arch-common/bionic/crtend.S b/libc/arch-common/bionic/crtend.S
index 74b3aa9ef..8f0bce942 100644
--- a/libc/arch-common/bionic/crtend.S
+++ b/libc/arch-common/bionic/crtend.S
@@ -28,11 +28,9 @@
 
 #include "asm_multiarch.h"
 
-#if defined(__aarch64__)
-#include <private/bionic_asm_arm64.h>
+#include <private/bionic_asm.h>
 
 __bionic_asm_custom_note_gnu_section()
-#endif
 
 	.section .note.GNU-stack, "", %progbits
 
diff --git a/libc/arch-common/bionic/crtend_so.S b/libc/arch-common/bionic/crtend_so.S
index bc4bfb6c3..1e0a3943e 100644
--- a/libc/arch-common/bionic/crtend_so.S
+++ b/libc/arch-common/bionic/crtend_so.S
@@ -26,11 +26,9 @@
  * SUCH DAMAGE.
  */
 
-#if defined(__aarch64__)
-#include <private/bionic_asm_arm64.h>
+#include <private/bionic_asm.h>
 
 __bionic_asm_custom_note_gnu_section()
-#endif
 
 	.section .note.GNU-stack, "", %progbits
 
diff --git a/libc/arch-x86/dynamic_function_dispatch.cpp b/libc/arch-x86/ifuncs.cpp
similarity index 100%
rename from libc/arch-x86/dynamic_function_dispatch.cpp
rename to libc/arch-x86/ifuncs.cpp
diff --git a/libc/arch-x86_64/dynamic_function_dispatch.cpp b/libc/arch-x86_64/ifuncs.cpp
similarity index 79%
rename from libc/arch-x86_64/dynamic_function_dispatch.cpp
rename to libc/arch-x86_64/ifuncs.cpp
index cbe68a3a0..a654a2506 100644
--- a/libc/arch-x86_64/dynamic_function_dispatch.cpp
+++ b/libc/arch-x86_64/ifuncs.cpp
@@ -32,6 +32,25 @@
 
 extern "C" {
 
+DEFINE_IFUNC_FOR(memmove) {
+  __builtin_cpu_init();
+  if (__builtin_cpu_supports("avx2")) RETURN_FUNC(memmove_func_t, memmove_avx2);
+  RETURN_FUNC(memmove_func_t, memmove_generic);
+}
+MEMMOVE_SHIM()
+
+DEFINE_IFUNC_FOR(memcpy) {
+  return memmove_resolver();
+}
+MEMCPY_SHIM()
+
+DEFINE_IFUNC_FOR(__memcpy_chk) {
+  __builtin_cpu_init();
+  if (__builtin_cpu_supports("avx2")) RETURN_FUNC(__memcpy_chk_func_t, __memcpy_chk_avx2);
+  RETURN_FUNC(__memcpy_chk_func_t, __memcpy_chk_generic);
+}
+__MEMCPY_CHK_SHIM()
+
 DEFINE_IFUNC_FOR(memset) {
   __builtin_cpu_init();
   if (__builtin_cpu_supports("avx2")) RETURN_FUNC(memset_func_t, memset_avx2);
diff --git a/libc/arch-x86_64/string/avx2-memmove-kbl.S b/libc/arch-x86_64/string/avx2-memmove-kbl.S
new file mode 100644
index 000000000..fc5758be2
--- /dev/null
+++ b/libc/arch-x86_64/string/avx2-memmove-kbl.S
@@ -0,0 +1,620 @@
+/*
+Copyright (c) 2024, Intel Corporation
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions are met:
+
+    * Redistributions of source code must retain the above copyright notice,
+    * this list of conditions and the following disclaimer.
+
+    * Redistributions in binary form must reproduce the above copyright notice,
+    * this list of conditions and the following disclaimer in the documentation
+    * and/or other materials provided with the distribution.
+
+    * Neither the name of Intel Corporation nor the names of its contributors
+    * may be used to endorse or promote products derived from this software
+    * without specific prior written permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
+ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
+WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
+DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
+ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
+LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
+ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
+SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+*/
+
+
+#ifndef MEMMOVE
+# define MEMMOVE		memmove_avx2
+#endif
+
+#ifndef L
+# define L(label)	.L##label
+#endif
+
+#ifndef cfi_startproc
+# define cfi_startproc	.cfi_startproc
+#endif
+
+#ifndef cfi_endproc
+# define cfi_endproc	.cfi_endproc
+#endif
+
+#ifndef cfi_rel_offset
+# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
+#endif
+
+#ifndef cfi_restore
+# define cfi_restore(reg)	.cfi_restore reg
+#endif
+
+#ifndef cfi_adjust_cfa_offset
+# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
+#endif
+
+#ifndef ENTRY
+# define ENTRY(name)		\
+	.type name,  @function;		\
+	.globl name;		\
+	.p2align 4;		\
+name:		\
+	cfi_startproc
+#endif
+
+#ifndef ALIAS_SYMBOL
+# define ALIAS_SYMBOL(alias, original) \
+	.globl alias; \
+	.equ alias, original
+#endif
+
+#ifndef END
+# define END(name)		\
+	cfi_endproc;		\
+	.size name, .-name
+#endif
+
+#define CFI_PUSH(REG)		\
+	cfi_adjust_cfa_offset (8);		\
+	cfi_rel_offset (REG, 0)
+
+#define CFI_POP(REG)		\
+	cfi_adjust_cfa_offset (-8);		\
+	cfi_restore (REG)
+
+#define PUSH(REG)	push REG;
+#define POP(REG)	pop REG;
+
+#define ENTRANCE	\
+	PUSH(%rbx);		\
+	CFI_PUSH (%rbx);
+#define RETURN_END	\
+	POP(%rbx);		\
+	CFI_POP (%rbx);	\
+	ret
+#define RETURN		RETURN_END;
+
+	.section .text.avx2,"ax",@progbits
+ENTRY (__memcpy_chk_avx2)
+	cmp	%rcx, %rdx
+	ja	__memcpy_chk_fail
+/* Fall through to memcpy/memmove. */
+END (__memcpy_chk_avx2)
+
+ENTRY (MEMMOVE)
+	ENTRANCE
+	mov	%rdi, %rax
+
+/* Check whether we should copy backward or forward.  */
+	cmp	%rsi, %rdi
+	je	L(mm_return)
+	jg	L(mm_len_0_or_more_backward)
+
+/* Now do checks for lengths. We do [0..16], [0..32], [0..64], [0..128]
+	separately.  */
+	cmp	$16, %rdx
+	jbe	L(mm_len_0_16_bytes_forward)
+
+	cmp	$32, %rdx
+	ja	L(mm_len_32_or_more_forward)
+
+/* Copy [0..32] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	-16(%rsi, %rdx), %xmm1
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_32_or_more_forward):
+	cmp	$64, %rdx
+	ja	L(mm_len_64_or_more_forward)
+
+/* Copy [0..64] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	-16(%rsi, %rdx), %xmm2
+	movdqu	-32(%rsi, %rdx), %xmm3
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, -16(%rdi, %rdx)
+	movdqu	%xmm3, -32(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_64_or_more_forward):
+	cmp	$128, %rdx
+	ja	L(mm_len_128_or_more_forward)
+
+/* Copy [0..128] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	32(%rsi), %xmm2
+	movdqu	48(%rsi), %xmm3
+	movdqu	-64(%rsi, %rdx), %xmm4
+	movdqu	-48(%rsi, %rdx), %xmm5
+	movdqu	-32(%rsi, %rdx), %xmm6
+	movdqu	-16(%rsi, %rdx), %xmm7
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, 32(%rdi)
+	movdqu	%xmm3, 48(%rdi)
+	movdqu	%xmm4, -64(%rdi, %rdx)
+	movdqu	%xmm5, -48(%rdi, %rdx)
+	movdqu	%xmm6, -32(%rdi, %rdx)
+	movdqu	%xmm7, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_128_or_more_forward):
+	cmp	$256, %rdx
+	ja	L(mm_len_256_or_more_forward)
+
+/* Copy [0..256] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	32(%rsi), %xmm2
+	movdqu	48(%rsi), %xmm3
+	movdqu	64(%rsi), %xmm4
+	movdqu	80(%rsi), %xmm5
+	movdqu	96(%rsi), %xmm6
+	movdqu	112(%rsi), %xmm7
+	movdqu	-128(%rsi, %rdx), %xmm8
+	movdqu	-112(%rsi, %rdx), %xmm9
+	movdqu	-96(%rsi, %rdx), %xmm10
+	movdqu	-80(%rsi, %rdx), %xmm11
+	movdqu	-64(%rsi, %rdx), %xmm12
+	movdqu	-48(%rsi, %rdx), %xmm13
+	movdqu	-32(%rsi, %rdx), %xmm14
+	movdqu	-16(%rsi, %rdx), %xmm15
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, 32(%rdi)
+	movdqu	%xmm3, 48(%rdi)
+	movdqu	%xmm4, 64(%rdi)
+	movdqu	%xmm5, 80(%rdi)
+	movdqu	%xmm6, 96(%rdi)
+	movdqu	%xmm7, 112(%rdi)
+	movdqu	%xmm8, -128(%rdi, %rdx)
+	movdqu	%xmm9, -112(%rdi, %rdx)
+	movdqu	%xmm10, -96(%rdi, %rdx)
+	movdqu	%xmm11, -80(%rdi, %rdx)
+	movdqu	%xmm12, -64(%rdi, %rdx)
+	movdqu	%xmm13, -48(%rdi, %rdx)
+	movdqu	%xmm14, -32(%rdi, %rdx)
+	movdqu	%xmm15, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_256_or_more_forward):
+/* Aligning the address of destination.  */
+/*  save first unaligned 128 bytes */
+	vmovdqu	(%rsi), %ymm0
+	vmovdqu	32(%rsi), %ymm1
+	vmovdqu	64(%rsi), %ymm2
+	vmovdqu	96(%rsi), %ymm3
+
+	lea	128(%rdi), %r8
+	and	$-128, %r8  /* r8 now aligned to next 128 byte boundary */
+	sub	%rdi, %rsi  /* rsi = src - dst = diff */
+
+	vmovdqu	(%r8, %rsi), %ymm4
+	vmovdqu	32(%r8, %rsi), %ymm5
+	vmovdqu	64(%r8, %rsi), %ymm6
+	vmovdqu	96(%r8, %rsi), %ymm7
+
+	vmovdqu	%ymm0, (%rdi)
+	vmovdqu	%ymm1, 32(%rdi)
+	vmovdqu	%ymm2, 64(%rdi)
+	vmovdqu	%ymm3, 96(%rdi)
+	vmovdqa	%ymm4, (%r8)
+	vmovaps	%ymm5, 32(%r8)
+	vmovaps	%ymm6, 64(%r8)
+	vmovaps	%ymm7, 96(%r8)
+	add	$128, %r8
+
+	lea	(%rdi, %rdx), %rbx
+	and	$-128, %rbx
+	cmp	%r8, %rbx
+	jbe	L(mm_copy_remaining_forward)
+
+	cmp	__x86_shared_cache_size_half(%rip), %rdx
+	jae	L(mm_overlapping_check_forward)
+
+		.p2align 4
+L(mm_main_loop_forward):
+	prefetcht0	128(%r8, %rsi)
+	vmovdqu	(%r8, %rsi), %ymm0
+	vmovdqu	32(%r8, %rsi), %ymm1
+	vmovdqa	%ymm0, (%r8)
+	vmovaps	%ymm1, 32(%r8)
+	lea	64(%r8), %r8
+	cmp	%r8, %rbx
+	ja	L(mm_main_loop_forward)
+
+L(mm_copy_remaining_forward):
+	add	%rdi, %rdx
+	sub	%r8, %rdx
+/* We copied all up till %rdi position in the dst.
+	In %rdx now is how many bytes are left to copy.
+	Now we need to advance %r8. */
+	lea	(%r8, %rsi), %r9
+
+L(mm_remaining_0_128_bytes_forward):
+	cmp	$64, %rdx
+	ja	L(mm_remaining_65_128_bytes_forward)
+	cmp	$32, %rdx
+	ja	L(mm_remaining_33_64_bytes_forward)
+	vzeroupper
+	cmp	$16, %rdx
+	ja	L(mm_remaining_17_32_bytes_forward)
+	test	%rdx, %rdx
+	.p2align 4,,2
+	je	L(mm_return)
+
+	cmpb	$8, %dl
+	ja	L(mm_remaining_9_16_bytes_forward)
+	cmpb	$4, %dl
+	.p2align 4,,5
+	ja	L(mm_remaining_5_8_bytes_forward)
+	cmpb	$2, %dl
+	.p2align 4,,1
+	ja	L(mm_remaining_3_4_bytes_forward)
+	movzbl	-1(%r9,%rdx), %esi
+	movzbl	(%r9), %ebx
+	movb	%sil, -1(%r8,%rdx)
+	movb	%bl, (%r8)
+	jmp	L(mm_return)
+
+L(mm_remaining_65_128_bytes_forward):
+	vmovdqu (%r9), %ymm0
+	vmovdqu 32(%r9), %ymm1
+	vmovdqu -64(%r9, %rdx), %ymm2
+	vmovdqu -32(%r9, %rdx), %ymm3
+	vmovdqu %ymm0, (%r8)
+	vmovdqu %ymm1, 32(%r8)
+	vmovdqu %ymm2, -64(%r8, %rdx)
+	vmovdqu %ymm3, -32(%r8, %rdx)
+	jmp L(mm_return_vzeroupper)
+
+L(mm_remaining_33_64_bytes_forward):
+	vmovdqu (%r9), %ymm0
+	vmovdqu -32(%r9, %rdx), %ymm1
+	vmovdqu %ymm0, (%r8)
+	vmovdqu %ymm1, -32(%r8, %rdx)
+	jmp	L(mm_return_vzeroupper)
+
+L(mm_remaining_17_32_bytes_forward):
+	movdqu	(%r9), %xmm0
+	movdqu	-16(%r9, %rdx), %xmm1
+	movdqu	%xmm0, (%r8)
+	movdqu	%xmm1, -16(%r8, %rdx)
+	jmp	L(mm_return)
+
+L(mm_remaining_5_8_bytes_forward):
+	movl	(%r9), %esi
+	movl	-4(%r9,%rdx), %ebx
+	movl	%esi, (%r8)
+	movl	%ebx, -4(%r8,%rdx)
+	jmp	L(mm_return)
+
+L(mm_remaining_9_16_bytes_forward):
+	mov	(%r9), %rsi
+	mov	-8(%r9, %rdx), %rbx
+	mov	%rsi, (%r8)
+	mov	%rbx, -8(%r8, %rdx)
+	jmp	L(mm_return)
+
+L(mm_remaining_3_4_bytes_forward):
+	movzwl	-2(%r9,%rdx), %esi
+	movzwl	(%r9), %ebx
+	movw	%si, -2(%r8,%rdx)
+	movw	%bx, (%r8)
+	jmp	L(mm_return)
+
+L(mm_len_0_16_bytes_forward):
+	testb	$24, %dl
+	jne	L(mm_len_9_16_bytes_forward)
+	testb	$4, %dl
+	.p2align 4,,5
+	jne	L(mm_len_5_8_bytes_forward)
+	test	%rdx, %rdx
+	.p2align 4,,2
+	je	L(mm_return)
+	testb	$2, %dl
+	.p2align 4,,1
+	jne	L(mm_len_2_4_bytes_forward)
+	movzbl	-1(%rsi,%rdx), %ebx
+	movzbl	(%rsi), %esi
+	movb	%bl, -1(%rdi,%rdx)
+	movb	%sil, (%rdi)
+	jmp	L(mm_return)
+
+L(mm_len_2_4_bytes_forward):
+	movzwl	-2(%rsi,%rdx), %ebx
+	movzwl	(%rsi), %esi
+	movw	%bx, -2(%rdi,%rdx)
+	movw	%si, (%rdi)
+	jmp	L(mm_return)
+
+L(mm_len_5_8_bytes_forward):
+	movl	(%rsi), %ebx
+	movl	-4(%rsi,%rdx), %esi
+	movl	%ebx, (%rdi)
+	movl	%esi, -4(%rdi,%rdx)
+	jmp	L(mm_return)
+
+L(mm_len_9_16_bytes_forward):
+	mov	(%rsi), %rbx
+	mov	-8(%rsi, %rdx), %rsi
+	mov	%rbx, (%rdi)
+	mov	%rsi, -8(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_recalc_len):
+/* Compute in %rdx how many bytes are left to copy after
+	the main loop stops.  */
+	vzeroupper
+	mov 	%rbx, %rdx
+	sub 	%rdi, %rdx
+/* The code for copying backwards.  */
+L(mm_len_0_or_more_backward):
+
+/* Now do checks for lengths. We do [0..16], [16..32], [32..64], [64..128]
+	separately.  */
+	cmp	$16, %rdx
+	jbe	L(mm_len_0_16_bytes_backward)
+
+	cmp	$32, %rdx
+	ja	L(mm_len_32_or_more_backward)
+
+/* Copy [0..32] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	-16(%rsi, %rdx), %xmm1
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_32_or_more_backward):
+	cmp	$64, %rdx
+	ja	L(mm_len_64_or_more_backward)
+
+/* Copy [0..64] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	-16(%rsi, %rdx), %xmm2
+	movdqu	-32(%rsi, %rdx), %xmm3
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, -16(%rdi, %rdx)
+	movdqu	%xmm3, -32(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_64_or_more_backward):
+	cmp	$128, %rdx
+	ja	L(mm_len_128_or_more_backward)
+
+/* Copy [0..128] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	32(%rsi), %xmm2
+	movdqu	48(%rsi), %xmm3
+	movdqu	-64(%rsi, %rdx), %xmm4
+	movdqu	-48(%rsi, %rdx), %xmm5
+	movdqu	-32(%rsi, %rdx), %xmm6
+	movdqu	-16(%rsi, %rdx), %xmm7
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, 32(%rdi)
+	movdqu	%xmm3, 48(%rdi)
+	movdqu	%xmm4, -64(%rdi, %rdx)
+	movdqu	%xmm5, -48(%rdi, %rdx)
+	movdqu	%xmm6, -32(%rdi, %rdx)
+	movdqu	%xmm7, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_128_or_more_backward):
+	cmp	$256, %rdx
+	ja	L(mm_len_256_or_more_backward)
+
+/* Copy [0..256] and return.  */
+	movdqu	(%rsi), %xmm0
+	movdqu	16(%rsi), %xmm1
+	movdqu	32(%rsi), %xmm2
+	movdqu	48(%rsi), %xmm3
+	movdqu	64(%rsi), %xmm4
+	movdqu	80(%rsi), %xmm5
+	movdqu	96(%rsi), %xmm6
+	movdqu	112(%rsi), %xmm7
+	movdqu	-128(%rsi, %rdx), %xmm8
+	movdqu	-112(%rsi, %rdx), %xmm9
+	movdqu	-96(%rsi, %rdx), %xmm10
+	movdqu	-80(%rsi, %rdx), %xmm11
+	movdqu	-64(%rsi, %rdx), %xmm12
+	movdqu	-48(%rsi, %rdx), %xmm13
+	movdqu	-32(%rsi, %rdx), %xmm14
+	movdqu	-16(%rsi, %rdx), %xmm15
+	movdqu	%xmm0, (%rdi)
+	movdqu	%xmm1, 16(%rdi)
+	movdqu	%xmm2, 32(%rdi)
+	movdqu	%xmm3, 48(%rdi)
+	movdqu	%xmm4, 64(%rdi)
+	movdqu	%xmm5, 80(%rdi)
+	movdqu	%xmm6, 96(%rdi)
+	movdqu	%xmm7, 112(%rdi)
+	movdqu	%xmm8, -128(%rdi, %rdx)
+	movdqu	%xmm9, -112(%rdi, %rdx)
+	movdqu	%xmm10, -96(%rdi, %rdx)
+	movdqu	%xmm11, -80(%rdi, %rdx)
+	movdqu	%xmm12, -64(%rdi, %rdx)
+	movdqu	%xmm13, -48(%rdi, %rdx)
+	movdqu	%xmm14, -32(%rdi, %rdx)
+	movdqu	%xmm15, -16(%rdi, %rdx)
+	jmp	L(mm_return)
+
+L(mm_len_256_or_more_backward):
+/* Aligning the address of destination. We need to save
+	128 bytes from the source in order not to overwrite them.  */
+	vmovdqu	-32(%rsi, %rdx), %ymm0
+	vmovdqu	-64(%rsi, %rdx), %ymm1
+	vmovdqu	-96(%rsi, %rdx), %ymm2
+	vmovdqu	-128(%rsi, %rdx), %ymm3
+
+	lea	(%rdi, %rdx), %r9
+	and	$-128, %r9 /* r9 = aligned dst */
+
+	mov	%rsi, %r8
+	sub	%rdi, %r8 /* r8 = src - dst, diff */
+
+	vmovdqu	-32(%r9, %r8), %ymm4
+	vmovdqu	-64(%r9, %r8), %ymm5
+	vmovdqu	-96(%r9, %r8), %ymm6
+	vmovdqu	-128(%r9, %r8), %ymm7
+
+	vmovdqu	%ymm0, -32(%rdi, %rdx)
+	vmovdqu	%ymm1, -64(%rdi, %rdx)
+	vmovdqu	%ymm2, -96(%rdi, %rdx)
+	vmovdqu	%ymm3, -128(%rdi, %rdx)
+	vmovdqa	%ymm4, -32(%r9)
+	vmovdqa	%ymm5, -64(%r9)
+	vmovdqa	%ymm6, -96(%r9)
+	vmovdqa	%ymm7, -128(%r9)
+	lea	-128(%r9), %r9
+
+	lea	128(%rdi), %rbx
+	and	$-128, %rbx
+
+	cmp	%r9, %rbx
+	jae	L(mm_recalc_len)
+
+	cmp	__x86_shared_cache_size_half(%rip), %rdx
+	jae	L(mm_overlapping_check_backward)
+
+	.p2align 4
+L(mm_main_loop_backward):
+	prefetcht0 -128(%r9, %r8)
+
+	vmovdqu	-64(%r9, %r8), %ymm0
+	vmovdqu	-32(%r9, %r8), %ymm1
+	vmovdqa	%ymm0, -64(%r9)
+	vmovaps	%ymm1, -32(%r9)
+	lea	-64(%r9), %r9
+	cmp	%r9, %rbx
+	jb	L(mm_main_loop_backward)
+	jmp	L(mm_recalc_len)
+
+/* Copy [0..16] and return.  */
+L(mm_len_0_16_bytes_backward):
+	testb	$24, %dl
+	jnz	L(mm_len_9_16_bytes_backward)
+	testb	$4, %dl
+	.p2align 4,,5
+	jnz	L(mm_len_5_8_bytes_backward)
+	test	%rdx, %rdx
+	.p2align 4,,2
+	je	L(mm_return)
+	testb	$2, %dl
+	.p2align 4,,1
+	jne	L(mm_len_3_4_bytes_backward)
+	movzbl	-1(%rsi,%rdx), %ebx
+	movzbl	(%rsi), %ecx
+	movb	%bl, -1(%rdi,%rdx)
+	movb	%cl, (%rdi)
+	jmp	L(mm_return)
+
+L(mm_len_3_4_bytes_backward):
+	movzwl	-2(%rsi,%rdx), %ebx
+	movzwl	(%rsi), %ecx
+	movw	%bx, -2(%rdi,%rdx)
+	movw	%cx, (%rdi)
+	jmp	L(mm_return)
+
+L(mm_len_9_16_bytes_backward):
+	movl	-4(%rsi,%rdx), %ebx
+	movl	-8(%rsi,%rdx), %ecx
+	movl	%ebx, -4(%rdi,%rdx)
+	movl	%ecx, -8(%rdi,%rdx)
+	sub	$8, %rdx
+	jmp	L(mm_len_0_16_bytes_backward)
+
+L(mm_len_5_8_bytes_backward):
+	movl	(%rsi), %ebx
+	movl	-4(%rsi,%rdx), %ecx
+	movl	%ebx, (%rdi)
+	movl	%ecx, -4(%rdi,%rdx)
+
+L(mm_return):
+	RETURN
+
+L(mm_return_vzeroupper):
+	vzeroupper
+	RETURN
+
+/* Big length copy forward part.  */
+
+	.p2align 4
+
+L(mm_overlapping_check_forward):
+	mov	%rsi, %r9
+	add	%rdx, %r9
+	cmp	__x86_shared_cache_size(%rip), %r9
+	jbe	L(mm_main_loop_forward)
+
+L(mm_large_page_loop_forward):
+	vmovdqu	  (%r8, %rsi), %ymm0
+	vmovdqu	  32(%r8, %rsi), %ymm1
+	vmovdqu	  64(%r8, %rsi), %ymm2
+	vmovdqu	  96(%r8, %rsi), %ymm3
+	vmovntdq  %ymm0, (%r8)
+	vmovntdq  %ymm1, 32(%r8)
+	vmovntdq  %ymm2, 64(%r8)
+	vmovntdq  %ymm3, 96(%r8)
+	lea 	  128(%r8), %r8
+	cmp	  %r8, %rbx
+	ja	  L(mm_large_page_loop_forward)
+	sfence
+	jmp	  L(mm_copy_remaining_forward)
+
+/* Big length copy backward part.  */
+	.p2align 4
+
+L(mm_overlapping_check_backward):
+	mov	%rdi, %r11
+	sub	%rsi, %r11 /* r11 = dst - src, diff */
+	add	%rdx, %r11
+	cmp	__x86_shared_cache_size(%rip), %r11
+	jbe	L(mm_main_loop_backward)
+
+L(mm_large_page_loop_backward):
+	vmovdqu	  -64(%r9, %r8), %ymm0
+	vmovdqu	  -32(%r9, %r8), %ymm1
+	vmovntdq  %ymm0, -64(%r9)
+	vmovntdq  %ymm1, -32(%r9)
+	lea 	  -64(%r9), %r9
+	cmp	  %r9, %rbx
+	jb	  L(mm_large_page_loop_backward)
+	sfence
+	jmp	  L(mm_recalc_len)
+
+END (MEMMOVE)
+
diff --git a/libc/arch-x86_64/string/sse2-memmove-slm.S b/libc/arch-x86_64/string/sse2-memmove-slm.S
index 9f5fb1213..75f8b9352 100644
--- a/libc/arch-x86_64/string/sse2-memmove-slm.S
+++ b/libc/arch-x86_64/string/sse2-memmove-slm.S
@@ -30,7 +30,7 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 
 #ifndef MEMMOVE
-# define MEMMOVE		memmove
+# define MEMMOVE		memmove_generic
 #endif
 
 #ifndef L
@@ -99,11 +99,11 @@ name:		\
 #define RETURN		RETURN_END;
 
 	.section .text.sse2,"ax",@progbits
-ENTRY (__memcpy_chk)
+ENTRY (__memcpy_chk_generic)
 	cmp	%rcx, %rdx
 	ja	__memcpy_chk_fail
 /* Fall through to memcpy/memmove. */
-END (__memcpy_chk)
+END (__memcpy_chk_generic)
 ENTRY (MEMMOVE)
 	ENTRANCE
 	mov	%rdi, %rax
@@ -541,4 +541,7 @@ L(mm_large_page_loop_backward):
 
 END (MEMMOVE)
 
+#ifdef BIONIC_RUST_BAREMETAL
 ALIAS_SYMBOL(memcpy, MEMMOVE)
+#endif
+
diff --git a/libc/async_safe/Android.bp b/libc/async_safe/Android.bp
index c7de2cec4..4ea550c9c 100644
--- a/libc/async_safe/Android.bp
+++ b/libc/async_safe/Android.bp
@@ -8,6 +8,7 @@ package {
     // to get the below license kinds:
     //   SPDX-license-identifier-BSD
     default_applicable_licenses: ["bionic_libc_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 cc_library_static {
diff --git a/libc/bionic/__libc_init_main_thread.cpp b/libc/bionic/__libc_init_main_thread.cpp
index 0d557f128..b47fed243 100644
--- a/libc/bionic/__libc_init_main_thread.cpp
+++ b/libc/bionic/__libc_init_main_thread.cpp
@@ -156,12 +156,14 @@ extern "C" void __libc_init_main_thread_final() {
   const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
   auto new_tcb = reinterpret_cast<bionic_tcb*>(mapping.static_tls + layout.offset_bionic_tcb());
   auto new_tls = reinterpret_cast<bionic_tls*>(mapping.static_tls + layout.offset_bionic_tls());
+  auto new_lb = reinterpret_cast<libgen_buffers*>(mapping.libgen_buffers);
 
   __init_static_tls(mapping.static_tls);
   new_tcb->copy_from_bootstrap(temp_tcb);
   new_tls->copy_from_bootstrap(temp_tls);
   __init_tcb(new_tcb, &main_thread);
   __init_bionic_tls_ptrs(new_tcb, new_tls);
+  __init_libgen_buffers_ptr(new_tls, new_lb);
 
   main_thread.mmap_base = mapping.mmap_base;
   main_thread.mmap_size = mapping.mmap_size;
diff --git a/libc/bionic/bionic_allocator.cpp b/libc/bionic/bionic_allocator.cpp
index 41baf8b18..fe0680ca5 100644
--- a/libc/bionic/bionic_allocator.cpp
+++ b/libc/bionic/bionic_allocator.cpp
@@ -81,7 +81,7 @@ static const uint32_t kLargeObject = 111;
 
 // Allocated pointers must be at least 16-byte aligned.  Round up the size of
 // page_info to multiple of 16.
-static constexpr size_t kPageInfoSize = __BIONIC_ALIGN(sizeof(page_info), 16);
+static constexpr size_t kPageInfoSize = __builtin_align_up(sizeof(page_info), 16);
 
 static inline uint16_t log2(size_t number) {
   uint16_t result = 0;
@@ -207,7 +207,7 @@ void BionicSmallObjectAllocator::alloc_page() {
 
   // Align the first block to block_size_.
   const uintptr_t first_block_addr =
-      __BIONIC_ALIGN(reinterpret_cast<uintptr_t>(page + 1), block_size_);
+      __builtin_align_up(reinterpret_cast<uintptr_t>(page + 1), block_size_);
   small_object_block_record* const first_block =
       reinterpret_cast<small_object_block_record*>(first_block_addr);
 
@@ -262,7 +262,7 @@ void BionicAllocator::initialize_allocators() {
 }
 
 void* BionicAllocator::alloc_mmap(size_t align, size_t size) {
-  size_t header_size = __BIONIC_ALIGN(kPageInfoSize, align);
+  size_t header_size = __builtin_align_up(kPageInfoSize, align);
   size_t allocated_size;
   if (__builtin_add_overflow(header_size, size, &allocated_size) ||
       page_end(allocated_size) < allocated_size) {
diff --git a/libc/bionic/fdsan.cpp b/libc/bionic/fdsan.cpp
index 0b0678bab..278cca53e 100644
--- a/libc/bionic/fdsan.cpp
+++ b/libc/bionic/fdsan.cpp
@@ -81,7 +81,7 @@ FdEntry* FdTableImpl<inline_fds>::at(size_t idx) {
 
     size_t required_count = max - inline_fds;
     size_t required_size = sizeof(FdTableOverflow) + required_count * sizeof(FdEntry);
-    size_t aligned_size = __BIONIC_ALIGN(required_size, page_size());
+    size_t aligned_size = __builtin_align_up(required_size, page_size());
     size_t aligned_count = (aligned_size - sizeof(FdTableOverflow)) / sizeof(FdEntry);
 
     void* allocation =
@@ -385,8 +385,11 @@ android_fdsan_error_level android_fdsan_set_error_level_from_property(
 
 int close(int fd) {
   int rc = android_fdsan_close_with_tag(fd, 0);
+
+  // See the "close" section of bionic/docs/EINTR.md for more.
   if (rc == -1 && errno == EINTR) {
     return 0;
   }
+
   return rc;
 }
diff --git a/libc/bionic/getentropy.cpp b/libc/bionic/getentropy.cpp
index 9c93e713b..11f5028f9 100644
--- a/libc/bionic/getentropy.cpp
+++ b/libc/bionic/getentropy.cpp
@@ -28,6 +28,7 @@
 
 #include <errno.h>
 #include <fcntl.h>
+#include <limits.h>
 #include <sys/random.h>
 #include <unistd.h>
 
@@ -50,8 +51,8 @@ static int getentropy_urandom(void* buffer, size_t buffer_size, int saved_errno)
 }
 
 int getentropy(void* buffer, size_t buffer_size) {
-  if (buffer_size > 256) {
-    errno = EIO;
+  if (buffer_size > GETENTROPY_MAX) {
+    errno = EINVAL;
     return -1;
   }
 
diff --git a/libc/bionic/grp_pwd.cpp b/libc/bionic/grp_pwd.cpp
index 82ee7bae9..443f418ac 100644
--- a/libc/bionic/grp_pwd.cpp
+++ b/libc/bionic/grp_pwd.cpp
@@ -585,7 +585,7 @@ static int getpasswd_r(bool by_name, const char* name, uid_t uid, struct passwd*
   ErrnoRestorer errno_restorer;
   *result = nullptr;
   char* p =
-      reinterpret_cast<char*>(__BIONIC_ALIGN(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
+      reinterpret_cast<char*>(__builtin_align_up(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
   if (p + sizeof(passwd_state_t) > buf + buflen) {
     return ERANGE;
   }
@@ -753,7 +753,7 @@ static int getgroup_r(bool by_name, const char* name, gid_t gid, struct group* g
   ErrnoRestorer errno_restorer;
   *result = nullptr;
   char* p = reinterpret_cast<char*>(
-      __BIONIC_ALIGN(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
+      __builtin_align_up(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
   if (p + sizeof(group_state_t) > buf + buflen) {
     return ERANGE;
   }
diff --git a/libc/bionic/gwp_asan_wrappers.cpp b/libc/bionic/gwp_asan_wrappers.cpp
index 2124f515d..d416775fa 100644
--- a/libc/bionic/gwp_asan_wrappers.cpp
+++ b/libc/bionic/gwp_asan_wrappers.cpp
@@ -34,6 +34,7 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#include <sys/param.h>
 #include <sys/types.h>
 
 #include "gwp_asan/crash_handler.h"
@@ -172,13 +173,8 @@ const MallocDispatch gwp_asan_dispatch __attribute__((unused)) = {
     Malloc(malloc_info),
 };
 
-bool isPowerOfTwo(uint64_t x) {
-  assert(x != 0);
-  return (x & (x - 1)) == 0;
-}
-
 bool ShouldGwpAsanSampleProcess(unsigned sample_rate) {
-  if (!isPowerOfTwo(sample_rate)) {
+  if (!powerof2(sample_rate)) {
     warning_log(
         "GWP-ASan process sampling rate of %u is not a power-of-two, and so modulo bias occurs.",
         sample_rate);
diff --git a/libc/bionic/jemalloc_wrapper.cpp b/libc/bionic/jemalloc_wrapper.cpp
index 63c9fab62..859baf579 100644
--- a/libc/bionic/jemalloc_wrapper.cpp
+++ b/libc/bionic/jemalloc_wrapper.cpp
@@ -37,7 +37,7 @@ __END_DECLS
 
 void* je_pvalloc(size_t bytes) {
   size_t pagesize = getpagesize();
-  size_t size = __BIONIC_ALIGN(bytes, pagesize);
+  size_t size = __builtin_align_up(bytes, pagesize);
   if (size < bytes) {
     return nullptr;
   }
diff --git a/libc/bionic/legacy_32_bit_support.cpp b/libc/bionic/legacy_32_bit_support.cpp
index e66126b54..19bf3c062 100644
--- a/libc/bionic/legacy_32_bit_support.cpp
+++ b/libc/bionic/legacy_32_bit_support.cpp
@@ -124,7 +124,7 @@ void* mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offse
 
   // Prevent allocations large enough for `end - start` to overflow,
   // to avoid security bugs.
-  size_t rounded = __BIONIC_ALIGN(size, page_size());
+  size_t rounded = __builtin_align_up(size, page_size());
   if (rounded < size || rounded > PTRDIFF_MAX) {
     errno = ENOMEM;
     return MAP_FAILED;
@@ -144,7 +144,7 @@ extern "C" void* __mremap(void*, size_t, size_t, int, void*);
 void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...) {
   // Prevent allocations large enough for `end - start` to overflow,
   // to avoid security bugs.
-  size_t rounded = __BIONIC_ALIGN(new_size, page_size());
+  size_t rounded = __builtin_align_up(new_size, page_size());
   if (rounded < new_size || rounded > PTRDIFF_MAX) {
     errno = ENOMEM;
     return MAP_FAILED;
diff --git a/libc/bionic/libgen.cpp b/libc/bionic/libgen.cpp
index b9528227d..f02e68a64 100644
--- a/libc/bionic/libgen.cpp
+++ b/libc/bionic/libgen.cpp
@@ -158,13 +158,13 @@ __LIBC32_LEGACY_PUBLIC__ int dirname_r(const char* path, char* buffer, size_t bu
 }
 
 char* basename(const char* path) {
-  char* buf = __get_bionic_tls().basename_buf;
-  int rc = __basename_r(path, buf, sizeof(__get_bionic_tls().basename_buf));
+  char* buf = (__get_bionic_tls().libgen_buffers_ptr)->basename_buf;
+  int rc = __basename_r(path, buf, sizeof((__get_bionic_tls().libgen_buffers_ptr)->basename_buf));
   return (rc < 0) ? nullptr : buf;
 }
 
 char* dirname(const char* path) {
-  char* buf = __get_bionic_tls().dirname_buf;
-  int rc = __dirname_r(path, buf, sizeof(__get_bionic_tls().dirname_buf));
+  char* buf = (__get_bionic_tls().libgen_buffers_ptr)->dirname_buf;
+  int rc = __dirname_r(path, buf, sizeof((__get_bionic_tls().libgen_buffers_ptr)->dirname_buf));
   return (rc < 0) ? nullptr : buf;
 }
diff --git a/libc/bionic/memset_explicit.cpp b/libc/bionic/memset_explicit.cpp
index 2bcc20c7b..6d7fdd33a 100644
--- a/libc/bionic/memset_explicit.cpp
+++ b/libc/bionic/memset_explicit.cpp
@@ -28,9 +28,5 @@
 
 #include <string.h>
 
-void* memset_explicit(void* __dst, int __ch, size_t __n) {
-  void* result = memset(__dst, __ch, __n);
-  // https://bugs.llvm.org/show_bug.cgi?id=15495
-  __asm__ __volatile__("" : : "r"(__dst) : "memory");
-  return result;
-}
+#define __BIONIC_MEMSET_EXPLICIT_INLINE /* Out of line. */
+#include <bits/memset_explicit_impl.h>
diff --git a/libc/bionic/ndk_cruft.cpp b/libc/bionic/ndk_cruft.cpp
index a69b77f77..bc06d9dc6 100644
--- a/libc/bionic/ndk_cruft.cpp
+++ b/libc/bionic/ndk_cruft.cpp
@@ -31,6 +31,8 @@
 // LP64 doesn't need to support any legacy cruft.
 #if !defined(__LP64__)
 
+#define __BIONIC_DISABLE_MALLOC_USABLE_SIZE_FORTIFY_WARNINGS
+
 #include <ctype.h>
 #include <dirent.h>
 #include <errno.h>
diff --git a/libc/bionic/pthread_create.cpp b/libc/bionic/pthread_create.cpp
index 1bd2da792..88493c4ba 100644
--- a/libc/bionic/pthread_create.cpp
+++ b/libc/bionic/pthread_create.cpp
@@ -70,22 +70,30 @@ void __init_bionic_tls_ptrs(bionic_tcb* tcb, bionic_tls* tls) {
   tcb->tls_slot(TLS_SLOT_BIONIC_TLS) = tls;
 }
 
+void __init_libgen_buffers_ptr(bionic_tls* tls, libgen_buffers* lb) {
+  tls->libgen_buffers_ptr = lb;
+}
+
+static inline size_t get_temp_bionic_tls_size() {
+  return __builtin_align_up(sizeof(bionic_tls) + sizeof(libgen_buffers), page_size());
+}
+
 // Allocate a temporary bionic_tls that the dynamic linker's main thread can
 // use while it's loading the initial set of ELF modules.
 bionic_tls* __allocate_temp_bionic_tls() {
-  size_t allocation_size = __BIONIC_ALIGN(sizeof(bionic_tls), page_size());
-  void* allocation = mmap(nullptr, allocation_size,
-                          PROT_READ | PROT_WRITE,
-                          MAP_PRIVATE | MAP_ANONYMOUS,
-                          -1, 0);
+  void* allocation = mmap(nullptr, get_temp_bionic_tls_size(), PROT_READ | PROT_WRITE,
+                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (allocation == MAP_FAILED) {
     async_safe_fatal("failed to allocate bionic_tls: %m");
   }
-  return static_cast<bionic_tls*>(allocation);
+  bionic_tls* tls = static_cast<bionic_tls*>(allocation);
+  tls->libgen_buffers_ptr =
+      reinterpret_cast<libgen_buffers*>(static_cast<char*>(allocation) + sizeof(bionic_tls));
+  return tls;
 }
 
 void __free_temp_bionic_tls(bionic_tls* tls) {
-  munmap(tls, __BIONIC_ALIGN(sizeof(bionic_tls), page_size()));
+  munmap(tls, get_temp_bionic_tls_size());
 }
 
 static void __init_alternate_signal_stack(pthread_internal_t* thread) {
@@ -216,15 +224,18 @@ int __init_thread(pthread_internal_t* thread) {
 ThreadMapping __allocate_thread_mapping(size_t stack_size, size_t stack_guard_size) {
   const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
 
-  // Allocate in order: stack guard, stack, static TLS, guard page.
+  // Allocate in order: stack guard, stack, static TLS, libgen buffers, guard page.
   size_t mmap_size;
   if (__builtin_add_overflow(stack_size, stack_guard_size, &mmap_size)) return {};
   if (__builtin_add_overflow(mmap_size, layout.size(), &mmap_size)) return {};
   if (__builtin_add_overflow(mmap_size, PTHREAD_GUARD_SIZE, &mmap_size)) return {};
+  // Add space for the dedicated libgen buffers page(s).
+  size_t libgen_buffers_padded_size = __builtin_align_up(sizeof(libgen_buffers), page_size());
+  if (__builtin_add_overflow(mmap_size, libgen_buffers_padded_size, &mmap_size)) return {};
 
   // Align the result to a page size.
   const size_t unaligned_size = mmap_size;
-  mmap_size = __BIONIC_ALIGN(mmap_size, page_size());
+  mmap_size = __builtin_align_up(mmap_size, page_size());
   if (mmap_size < unaligned_size) return {};
 
   // Create a new private anonymous map. Make the entire mapping PROT_NONE, then carve out a
@@ -255,12 +266,21 @@ ThreadMapping __allocate_thread_mapping(size_t stack_size, size_t stack_guard_si
     return {};
   }
 
+  // Layout from the end of the mmap-ed region (before the top PTHREAD_GUARD_SIZE):
+  //
+  // [ PTHREAD_GUARD_SIZE ]
+  // [ libgen_buffers_padded_size (for dedicated page(s) for libgen buffers) ]
+  // [ layout.size() (for static TLS) ]
+  // [ stack_size ]
+  // [ stack_guard_size ]
+
   ThreadMapping result = {};
   result.mmap_base = space;
   result.mmap_size = mmap_size;
   result.mmap_base_unguarded = space + stack_guard_size;
   result.mmap_size_unguarded = mmap_size - stack_guard_size - PTHREAD_GUARD_SIZE;
-  result.static_tls = space + mmap_size - PTHREAD_GUARD_SIZE - layout.size();
+  result.libgen_buffers = space + mmap_size - PTHREAD_GUARD_SIZE - libgen_buffers_padded_size;
+  result.static_tls = result.libgen_buffers - layout.size();
   result.stack_base = space;
   result.stack_top = result.static_tls;
   return result;
@@ -276,7 +296,7 @@ static int __allocate_thread(pthread_attr_t* attr, bionic_tcb** tcbp, void** chi
 
     // Make sure the guard size is a multiple of page_size().
     const size_t unaligned_guard_size = attr->guard_size;
-    attr->guard_size = __BIONIC_ALIGN(attr->guard_size, page_size());
+    attr->guard_size = __builtin_align_up(attr->guard_size, page_size());
     if (attr->guard_size < unaligned_guard_size) return EAGAIN;
 
     mapping = __allocate_thread_mapping(attr->stack_size, attr->guard_size);
@@ -309,6 +329,7 @@ static int __allocate_thread(pthread_attr_t* attr, bionic_tcb** tcbp, void** chi
   const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
   auto tcb = reinterpret_cast<bionic_tcb*>(mapping.static_tls + layout.offset_bionic_tcb());
   auto tls = reinterpret_cast<bionic_tls*>(mapping.static_tls + layout.offset_bionic_tls());
+  auto lb = reinterpret_cast<libgen_buffers*>(mapping.libgen_buffers);
 
   // Initialize TLS memory.
   __init_static_tls(mapping.static_tls);
@@ -316,6 +337,7 @@ static int __allocate_thread(pthread_attr_t* attr, bionic_tcb** tcbp, void** chi
   __init_tcb_dtv(tcb);
   __init_tcb_stack_guard(tcb);
   __init_bionic_tls_ptrs(tcb, tls);
+  __init_libgen_buffers_ptr(tls, lb);
 
   attr->stack_size = stack_top - static_cast<char*>(attr->stack_base);
   thread->attr = *attr;
diff --git a/libc/bionic/pthread_internal.h b/libc/bionic/pthread_internal.h
index ae9a7913b..c6779eb5d 100644
--- a/libc/bionic/pthread_internal.h
+++ b/libc/bionic/pthread_internal.h
@@ -195,12 +195,14 @@ struct ThreadMapping {
   char* static_tls;
   char* stack_base;
   char* stack_top;
+  char* libgen_buffers;
 };
 
 __LIBC_HIDDEN__ void __init_tcb(bionic_tcb* tcb, pthread_internal_t* thread);
 __LIBC_HIDDEN__ void __init_tcb_stack_guard(bionic_tcb* tcb);
 __LIBC_HIDDEN__ void __init_tcb_dtv(bionic_tcb* tcb);
 __LIBC_HIDDEN__ void __init_bionic_tls_ptrs(bionic_tcb* tcb, bionic_tls* tls);
+__LIBC_HIDDEN__ void __init_libgen_buffers_ptr(bionic_tls* tls, libgen_buffers* lb);
 __LIBC_HIDDEN__ bionic_tls* __allocate_temp_bionic_tls();
 __LIBC_HIDDEN__ void __free_temp_bionic_tls(bionic_tls* tls);
 __LIBC_HIDDEN__ void __init_additional_stacks(pthread_internal_t*);
diff --git a/libc/bionic/realpath.cpp b/libc/bionic/realpath.cpp
index e43d8e2ff..06d5572c9 100644
--- a/libc/bionic/realpath.cpp
+++ b/libc/bionic/realpath.cpp
@@ -55,10 +55,8 @@ char* realpath(const char* path, char* result) {
   if (fd.get() == -1) return nullptr;
 
   // (...remember the device/inode that we're talking about and...)
-  struct stat sb;
-  if (fstat(fd.get(), &sb) == -1) return nullptr;
-  dev_t st_dev = sb.st_dev;
-  ino_t st_ino = sb.st_ino;
+  struct stat sb_before;
+  if (fstat(fd.get(), &sb_before) == -1) return nullptr;
 
   // ...ask the kernel to do the hard work for us.
   FdPath fd_path(fd.get());
@@ -69,7 +67,10 @@ char* realpath(const char* path, char* result) {
 
   // What if the file was removed in the meantime? readlink(2) will have
   // returned "/a/b/c (deleted)", and we want to return ENOENT instead.
-  if (stat(dst, &sb) == -1 || st_dev != sb.st_dev || st_ino != sb.st_ino) {
+  struct stat sb_after;
+  if (stat(dst, &sb_after) == -1 ||
+      sb_before.st_dev != sb_after.st_dev ||
+      sb_before.st_ino != sb_after.st_ino) {
     errno = ENOENT;
     return nullptr;
   }
diff --git a/libc/bionic/signal.cpp b/libc/bionic/signal.cpp
index 77e6acf1f..0d6054687 100644
--- a/libc/bionic/signal.cpp
+++ b/libc/bionic/signal.cpp
@@ -29,6 +29,7 @@
 #include <errno.h>
 #include <pthread.h>
 #include <signal.h>
+#include <stdio.h>
 #include <string.h>
 #include <sys/epoll.h>
 #include <sys/signalfd.h>
@@ -305,3 +306,15 @@ int sigwaitinfo(const sigset_t* set, siginfo_t* info) {
 int sigwaitinfo64(const sigset64_t* set, siginfo_t* info) {
   return sigtimedwait64(set, info, nullptr);
 }
+
+extern "C" const char* __strsignal(int, char*, size_t);
+
+void psignal(int sig, const char* msg) {
+  if (msg == nullptr) msg = "";
+  char buf[NL_TEXTMAX];
+  fprintf(stderr, "%s%s%s\n", msg, (*msg == '\0') ? "" : ": ", __strsignal(sig, buf, sizeof(buf)));
+}
+
+void psiginfo(const siginfo_t* si, const char* msg) {
+  psignal(si->si_signo, msg);
+}
diff --git a/libc/bionic/sys_statvfs.cpp b/libc/bionic/sys_statvfs.cpp
index 3a05c3fa6..18ee340f5 100644
--- a/libc/bionic/sys_statvfs.cpp
+++ b/libc/bionic/sys_statvfs.cpp
@@ -26,7 +26,8 @@ static inline void __bionic_statfs_to_statvfs(const struct statfs* src, struct s
   dst->f_files = src->f_files;
   dst->f_ffree = src->f_ffree;
   dst->f_favail = src->f_ffree;
-  dst->f_fsid = src->f_fsid.__val[0] | static_cast<uint64_t>(src->f_fsid.__val[1]) << 32;
+  dst->f_fsid = static_cast<uint64_t>(src->f_fsid.__val[0]) |
+                static_cast<uint64_t>(src->f_fsid.__val[1]) << 32;
   dst->f_flag = src->f_flags;
   dst->f_namemax = src->f_namelen;
 }
diff --git a/libc/bionic/utime.cpp b/libc/bionic/utime.cpp
new file mode 100644
index 000000000..95079d13d
--- /dev/null
+++ b/libc/bionic/utime.cpp
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <utime.h>
+
+#include <fcntl.h>
+#include <sys/stat.h>
+
+int utime(const char* _Nonnull path, const struct utimbuf* _Nullable times) {
+  if (times == nullptr) return utimensat(AT_FDCWD, path, nullptr, 0);
+
+  timespec ts[2] = { {.tv_sec = times->actime}, {.tv_sec = times->modtime} };
+  return utimensat(AT_FDCWD, path, ts, 0);
+}
diff --git a/libc/bionic/vdso.cpp b/libc/bionic/vdso.cpp
index 0a9a9e540..1b5b13fea 100644
--- a/libc/bionic/vdso.cpp
+++ b/libc/bionic/vdso.cpp
@@ -83,12 +83,12 @@ time_t time(time_t* t) {
 }
 
 #if defined(__riscv)
-int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull pairs, size_t pair_count, size_t cpu_count,
-                    unsigned long* _Nullable cpus, unsigned flags) {
+int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull pairs, size_t pair_count, size_t cpu_set_size,
+                    cpu_set_t* _Nullable cpu_set, unsigned flags) {
   auto vdso_riscv_hwprobe =
       reinterpret_cast<decltype(&__riscv_hwprobe)>(__libc_globals->vdso[VDSO_RISCV_HWPROBE].fn);
   if (__predict_true(vdso_riscv_hwprobe)) {
-    return -vdso_riscv_hwprobe(pairs, pair_count, cpu_count, cpus, flags);
+    return -vdso_riscv_hwprobe(pairs, pair_count, cpu_set_size, cpu_set, flags);
   }
   // Inline the syscall directly in case someone's calling it from an
   // ifunc resolver where we won't be able to set errno on failure.
@@ -97,8 +97,8 @@ int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull pairs, size_t pair_count, siz
   // is to return an error value rather than setting errno.)
   register long a0 __asm__("a0") = reinterpret_cast<long>(pairs);
   register long a1 __asm__("a1") = pair_count;
-  register long a2 __asm__("a2") = cpu_count;
-  register long a3 __asm__("a3") = reinterpret_cast<long>(cpus);
+  register long a2 __asm__("a2") = cpu_set_size;
+  register long a3 __asm__("a3") = reinterpret_cast<long>(cpu_set);
   register long a4 __asm__("a4") = flags;
   register long a7 __asm__("a7") = __NR_riscv_hwprobe;
   __asm__ volatile("ecall" : "=r"(a0) : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7));
diff --git a/libc/include/android/api-level.h b/libc/include/android/api-level.h
index 2a4f7df0c..273739561 100644
--- a/libc/include/android/api-level.h
+++ b/libc/include/android/api-level.h
@@ -169,9 +169,8 @@ __BEGIN_DECLS
  * there is no known target SDK version (for code not running in the context of
  * an app).
  *
- * The returned values correspond to the named constants in `<android/api-level.h>`,
- * and is equivalent to the AndroidManifest.xml `targetSdkVersion`.
- *
+ * The returned value is the same as the AndroidManifest.xml `targetSdkVersion`.
+ * This is mostly useful for the OS to decide what behavior an app is expecting.
  * See also android_get_device_api_level().
  *
  * Available since API level 24.
@@ -180,7 +179,6 @@ __BEGIN_DECLS
 int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
 #if __ANDROID_API__ < 29
 
 /* android_get_device_api_level is a static inline before API level 29. */
@@ -192,9 +190,10 @@ int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
 
 /**
  * Returns the API level of the device we're actually running on, or -1 on failure.
- * The returned values correspond to the named constants in `<android/api-level.h>`,
- * and is equivalent to the Java `Build.VERSION.SDK_INT` API.
  *
+ * The returned value is the same as the Java `Build.VERSION.SDK_INT`.
+ * This is mostly useful for an app to work out what version of the OS it's
+ * running on.
  * See also android_get_application_target_sdk_version().
  *
  * Available since API level 29.
diff --git a/libc/include/android/crash_detail.h b/libc/include/android/crash_detail.h
index fd1312a1f..f8785af3b 100644
--- a/libc/include/android/crash_detail.h
+++ b/libc/include/android/crash_detail.h
@@ -80,10 +80,10 @@ typedef struct crash_detail_t crash_detail_t;
  *
  * \return a handle to the extra crash detail.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 crash_detail_t* _Nullable android_crash_detail_register(
     const void* _Nonnull name, size_t name_size, const void* _Nullable data, size_t data_size) __INTRODUCED_IN(35);
+    #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
 /**
  * Unregister crash detail from being logged into tombstones.
@@ -95,7 +95,9 @@ crash_detail_t* _Nullable android_crash_detail_register(
  *
  * \param crash_detail the crash_detail that should be removed.
  */
+#if __BIONIC_AVAILABILITY_GUARD(35)
 void android_crash_detail_unregister(crash_detail_t* _Nonnull crash_detail) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
 /**
  * Replace data of crash detail.
@@ -110,7 +112,9 @@ void android_crash_detail_unregister(crash_detail_t* _Nonnull crash_detail) __IN
  *             android_crash_detail_replace_data is called again with non-null data.
  * \param data_size the number of bytes of the buffer pointed to by data.
  */
+#if __BIONIC_AVAILABILITY_GUARD(35)
 void android_crash_detail_replace_data(crash_detail_t* _Nonnull crash_detail, const void* _Nullable data, size_t data_size) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
 /**
  * Replace name of crash detail.
@@ -124,8 +128,8 @@ void android_crash_detail_replace_data(crash_detail_t* _Nonnull crash_detail, co
  * \param name identifying name for this extra data.
  * \param name_size number of bytes of the buffer pointed to by name
  */
+#if __BIONIC_AVAILABILITY_GUARD(35)
 void android_crash_detail_replace_name(crash_detail_t* _Nonnull crash_detail, const void* _Nonnull name, size_t name_size) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 __END_DECLS
diff --git a/libc/include/android/fdsan.h b/libc/include/android/fdsan.h
index a04fc7e38..b9090baef 100644
--- a/libc/include/android/fdsan.h
+++ b/libc/include/android/fdsan.h
@@ -135,45 +135,53 @@ enum android_fdsan_owner_type {
 /*
  * Create an owner tag with the specified type and least significant 56 bits of tag.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(29)
 uint64_t android_fdsan_create_owner_tag(enum android_fdsan_owner_type type, uint64_t tag) __INTRODUCED_IN(29) __attribute__((__weak__));
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
 /*
  * Exchange a file descriptor's tag.
  *
  * Logs and aborts if the fd's tag does not match expected_tag.
  */
+#if __BIONIC_AVAILABILITY_GUARD(29)
 void android_fdsan_exchange_owner_tag(int fd, uint64_t expected_tag, uint64_t new_tag) __INTRODUCED_IN(29) __attribute__((__weak__));
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
 /*
  * Close a file descriptor with a tag, and resets the tag to 0.
  *
  * Logs and aborts if the tag is incorrect.
  */
+#if __BIONIC_AVAILABILITY_GUARD(29)
 int android_fdsan_close_with_tag(int fd, uint64_t tag) __INTRODUCED_IN(29) __attribute__((__weak__));
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
 /*
  * Get a file descriptor's current owner tag.
  *
  * Returns 0 for untagged and invalid file descriptors.
  */
+#if __BIONIC_AVAILABILITY_GUARD(29)
 uint64_t android_fdsan_get_owner_tag(int fd) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
 /*
  * Get an owner tag's string representation.
  *
  * The return value points to memory with static lifetime, do not attempt to modify it.
  */
+#if __BIONIC_AVAILABILITY_GUARD(29)
 const char* _Nonnull android_fdsan_get_tag_type(uint64_t tag) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
 /*
  * Get an owner tag's value, with the type masked off.
  */
+#if __BIONIC_AVAILABILITY_GUARD(29)
 uint64_t android_fdsan_get_tag_value(uint64_t tag) __INTRODUCED_IN(29);
 #endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
-
 enum android_fdsan_error_level {
   // No errors.
   ANDROID_FDSAN_ERROR_LEVEL_DISABLED,
diff --git a/libc/include/arpa/inet.h b/libc/include/arpa/inet.h
index ce9dd93dc..246b43821 100644
--- a/libc/include/arpa/inet.h
+++ b/libc/include/arpa/inet.h
@@ -31,6 +31,7 @@
 
 #include <sys/cdefs.h>
 
+#include <endian.h>
 #include <netinet/in.h>
 #include <stdint.h>
 #include <sys/types.h>
diff --git a/libc/include/bits/fortify/fcntl.h b/libc/include/bits/fortify/fcntl.h
index 05c62eb24..61386a8e4 100644
--- a/libc/include/bits/fortify/fcntl.h
+++ b/libc/include/bits/fortify/fcntl.h
@@ -47,7 +47,7 @@ int __openat_real(int, const char* _Nonnull, int, ...) __RENAME(openat);
 
 __BIONIC_ERROR_FUNCTION_VISIBILITY
 int open(const char* _Nonnull pathname, int flags, mode_t modes, ...) __overloadable
-        __errorattr(__open_too_many_args_error);
+        __clang_error_if(1, __open_too_many_args_error);
 
 /*
  * pass_object_size serves two purposes here, neither of which involve __bos: it
@@ -77,7 +77,7 @@ int open(const char* _Nonnull const __pass_object_size pathname, int flags, mode
 __BIONIC_ERROR_FUNCTION_VISIBILITY
 int openat(int dirfd, const char* _Nonnull pathname, int flags, mode_t modes, ...)
         __overloadable
-        __errorattr(__open_too_many_args_error);
+        __clang_error_if(1, __open_too_many_args_error);
 
 __BIONIC_FORTIFY_INLINE
 int openat(int dirfd, const char* _Nonnull const __pass_object_size pathname, int flags)
@@ -102,7 +102,7 @@ int openat(int dirfd, const char* _Nonnull const __pass_object_size pathname, in
 
 __BIONIC_ERROR_FUNCTION_VISIBILITY
 int open64(const char* _Nonnull pathname, int flags, mode_t modes, ...) __overloadable
-        __errorattr(__open_too_many_args_error);
+        __clang_error_if(1, __open_too_many_args_error);
 
 __BIONIC_FORTIFY_INLINE
 int open64(const char* _Nonnull const __pass_object_size pathname, int flags)
@@ -122,7 +122,7 @@ int open64(const char* _Nonnull const __pass_object_size pathname, int flags, mo
 __BIONIC_ERROR_FUNCTION_VISIBILITY
 int openat64(int dirfd, const char* _Nonnull pathname, int flags, mode_t modes, ...)
         __overloadable
-        __errorattr(__open_too_many_args_error);
+        __clang_error_if(1, __open_too_many_args_error);
 
 __BIONIC_FORTIFY_INLINE
 int openat64(int dirfd, const char* _Nonnull const __pass_object_size pathname, int flags)
diff --git a/libc/include/bits/fortify/poll.h b/libc/include/bits/fortify/poll.h
index 1b4a5bf8b..94158f05e 100644
--- a/libc/include/bits/fortify/poll.h
+++ b/libc/include/bits/fortify/poll.h
@@ -30,18 +30,18 @@
 #error "Never include this file directly; instead, include <poll.h>"
 #endif
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int __poll_chk(struct pollfd* _Nullable, nfds_t, int, size_t) __INTRODUCED_IN(23);
-int __ppoll_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset_t* _Nullable, size_t) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+int __ppoll_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset_t* _Nullable, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int __ppoll64_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset64_t* _Nullable, size_t) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 #if defined(__BIONIC_FORTIFY)
 #define __bos_fd_count_trivially_safe(bos_val, fds, fd_count)              \
   __bos_dynamic_check_impl_and((bos_val), >=, (sizeof(*fds) * (fd_count)), \
diff --git a/libc/include/bits/fortify/socket.h b/libc/include/bits/fortify/socket.h
index bd626f9f6..a582a3769 100644
--- a/libc/include/bits/fortify/socket.h
+++ b/libc/include/bits/fortify/socket.h
@@ -30,7 +30,6 @@
 #error "Never include this file directly; instead, include <sys/socket.h>"
 #endif
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 ssize_t __sendto_chk(int, const void* _Nonnull, size_t, size_t, int, const struct sockaddr* _Nullable, socklen_t) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
diff --git a/libc/include/bits/fortify/stdio.h b/libc/include/bits/fortify/stdio.h
index f9faeba87..f7f2b1d59 100644
--- a/libc/include/bits/fortify/stdio.h
+++ b/libc/include/bits/fortify/stdio.h
@@ -34,9 +34,11 @@ char* _Nullable __fgets_chk(char* _Nonnull, int, FILE* _Nonnull, size_t);
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 size_t __fread_chk(void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
-size_t __fwrite_chk(const void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
+#if __BIONIC_AVAILABILITY_GUARD(24)
+size_t __fwrite_chk(const void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 #if defined(__BIONIC_FORTIFY) && !defined(__BIONIC_NO_STDIO_FORTIFY)
 
@@ -60,7 +62,7 @@ int sprintf(char* __BIONIC_COMPLICATED_NULLNESS dest, const char* _Nonnull forma
     __overloadable
     __enable_if(__bos_unevaluated_lt(__bos(dest), __builtin_strlen(format)),
                 "format string will always overflow destination buffer")
-    __errorattr("format string will always overflow destination buffer");
+    __clang_error_if(1, "format string will always overflow destination buffer");
 
 #if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
 __BIONIC_FORTIFY_VARIADIC __printflike(2, 3)
@@ -85,14 +87,17 @@ int snprintf(char* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size dest,
 }
 #endif
 
+/* __builtin_mul_overflow cannot be used in static_assert or constexpr contexts. */
+#define __would_mul_overflow(x, y) ((__SIZE_TYPE__)-1 / (x) < (y))
+
 #define __bos_trivially_ge_mul(bos_val, size, count) \
   __bos_dynamic_check_impl_and(bos_val, >=, (size) * (count), \
-                               !__unsafe_check_mul_overflow(size, count))
+                               !__would_mul_overflow(size, count))
 
 __BIONIC_FORTIFY_INLINE
 size_t fread(void* const _Nonnull __pass_object_size0 buf, size_t size, size_t count, FILE* _Nonnull stream)
         __overloadable
-        __clang_error_if(__unsafe_check_mul_overflow(size, count),
+        __clang_error_if(__would_mul_overflow(size, count),
                          "in call to 'fread', size * count overflows")
         __clang_error_if(__bos_unevaluated_lt(__bos0(buf), size * count),
                          "in call to 'fread', size * count is too large for the given buffer") {
@@ -109,7 +114,7 @@ size_t fread(void* const _Nonnull __pass_object_size0 buf, size_t size, size_t c
 __BIONIC_FORTIFY_INLINE
 size_t fwrite(const void* const _Nonnull __pass_object_size0 buf, size_t size, size_t count, FILE* _Nonnull stream)
         __overloadable
-        __clang_error_if(__unsafe_check_mul_overflow(size, count),
+        __clang_error_if(__would_mul_overflow(size, count),
                          "in call to 'fwrite', size * count overflows")
         __clang_error_if(__bos_unevaluated_lt(__bos0(buf), size * count),
                          "in call to 'fwrite', size * count is too large for the given buffer") {
@@ -122,6 +127,8 @@ size_t fwrite(const void* const _Nonnull __pass_object_size0 buf, size_t size, s
 #endif
     return __call_bypassing_fortify(fwrite)(buf, size, count, stream);
 }
+
+#undef __would_mul_overflow
 #undef __bos_trivially_ge_mul
 
 __BIONIC_FORTIFY_INLINE
diff --git a/libc/include/bits/fortify/string.h b/libc/include/bits/fortify/string.h
index 15cb17dcb..8911b0b3f 100644
--- a/libc/include/bits/fortify/string.h
+++ b/libc/include/bits/fortify/string.h
@@ -30,9 +30,11 @@
 #error "Never include this file directly; instead, include <string.h>"
 #endif
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 void* _Nullable __memchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void* _Nullable __memrchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
@@ -80,14 +82,11 @@ void* _Nonnull memset(void* _Nonnull const s __pass_object_size0, int c, size_t
 #endif
 }
 
-#if defined(__USE_GNU)
-#if __ANDROID_API__ >= 30
+#if defined(__USE_GNU) && __ANDROID_API__ >= 30
 __BIONIC_FORTIFY_INLINE
 void* _Nonnull mempcpy(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t copy_amount)
         __diagnose_as_builtin(__builtin_mempcpy, 1, 2, 3)
-        __overloadable
-        __clang_error_if(__bos_unevaluated_lt(__bos0(dst), copy_amount),
-                         "'mempcpy' called with size bigger than buffer") {
+        __overloadable {
 #if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
     size_t bos_dst = __bos0(dst);
     if (!__bos_trivially_ge(bos_dst, copy_amount)) {
@@ -96,8 +95,7 @@ void* _Nonnull mempcpy(void* _Nonnull const dst __pass_object_size0, const void*
 #endif
     return __builtin_mempcpy(dst, src, copy_amount);
 }
-#endif /* __ANDROID_API__ >= 30 */
-#endif /* __USE_GNU */
+#endif
 
 __BIONIC_FORTIFY_INLINE
 char* _Nonnull stpcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src)
@@ -114,9 +112,7 @@ char* _Nonnull stpcpy(char* _Nonnull const dst __pass_object_size, const char* _
 __BIONIC_FORTIFY_INLINE
 char* _Nonnull strcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src)
         __diagnose_as_builtin(__builtin_strcpy, 1, 2)
-        __overloadable
-        __clang_error_if(__bos_unevaluated_le(__bos(dst), __builtin_strlen(src)),
-                         "'strcpy' called with string bigger than buffer") {
+        __overloadable {
 #if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
     return __builtin___strcpy_chk(dst, src, __bos(dst));
 #else
diff --git a/libc/include/bits/fortify/unistd.h b/libc/include/bits/fortify/unistd.h
index 9acb94239..a863208d7 100644
--- a/libc/include/bits/fortify/unistd.h
+++ b/libc/include/bits/fortify/unistd.h
@@ -29,34 +29,28 @@
 #error "Never include this file directly; instead, include <unistd.h>"
 #endif
 
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 char* _Nullable __getcwd_chk(char* _Nullable, size_t, size_t) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __pread_chk(int, void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 ssize_t __pread_real(int, void* _Nonnull, size_t, off_t) __RENAME(pread);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __pread64_chk(int, void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 ssize_t __pread64_real(int, void* _Nonnull, size_t, off64_t) __RENAME(pread64);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t __pwrite_chk(int, const void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 ssize_t __pwrite_real(int, const void* _Nonnull, size_t, off_t) __RENAME(pwrite);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t __pwrite64_chk(int, const void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
@@ -69,12 +63,13 @@ ssize_t __read_chk(int, void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t);
 ssize_t __write_chk(int, const void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __readlink_chk(const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
-ssize_t __readlinkat_chk(int dirfd, const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+ssize_t __readlinkat_chk(int dirfd, const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if defined(__BIONIC_FORTIFY)
 
diff --git a/libc/include/bits/getentropy.h b/libc/include/bits/getentropy.h
index c878470cd..c1d9d7c9e 100644
--- a/libc/include/bits/getentropy.h
+++ b/libc/include/bits/getentropy.h
@@ -48,10 +48,8 @@ __BEGIN_DECLS
  *
  * See also arc4random_buf() which is available in all API levels.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard int getentropy(void* _Nonnull __buffer, size_t __buffer_size) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 __END_DECLS
diff --git a/libc/include/bits/glibc-syscalls.h b/libc/include/bits/glibc-syscalls.h
index 8c5a91d3f..c92bc5090 100644
--- a/libc/include/bits/glibc-syscalls.h
+++ b/libc/include/bits/glibc-syscalls.h
@@ -438,6 +438,9 @@
 #if defined(__NR_getxattr)
   #define SYS_getxattr __NR_getxattr
 #endif
+#if defined(__NR_getxattrat)
+  #define SYS_getxattrat __NR_getxattrat
+#endif
 #if defined(__NR_gtty)
   #define SYS_gtty __NR_gtty
 #endif
@@ -555,6 +558,9 @@
 #if defined(__NR_listxattr)
   #define SYS_listxattr __NR_listxattr
 #endif
+#if defined(__NR_listxattrat)
+  #define SYS_listxattrat __NR_listxattrat
+#endif
 #if defined(__NR_llistxattr)
   #define SYS_llistxattr __NR_llistxattr
 #endif
@@ -921,6 +927,9 @@
 #if defined(__NR_removexattr)
   #define SYS_removexattr __NR_removexattr
 #endif
+#if defined(__NR_removexattrat)
+  #define SYS_removexattrat __NR_removexattrat
+#endif
 #if defined(__NR_rename)
   #define SYS_rename __NR_rename
 #endif
@@ -1158,6 +1167,9 @@
 #if defined(__NR_setxattr)
   #define SYS_setxattr __NR_setxattr
 #endif
+#if defined(__NR_setxattrat)
+  #define SYS_setxattrat __NR_setxattrat
+#endif
 #if defined(__NR_sgetmask)
   #define SYS_sgetmask __NR_sgetmask
 #endif
diff --git a/libc/include/bits/lockf.h b/libc/include/bits/lockf.h
index 8f922b9c7..82f4538e3 100644
--- a/libc/include/bits/lockf.h
+++ b/libc/include/bits/lockf.h
@@ -56,16 +56,16 @@ __BEGIN_DECLS
  *
  * See also flock().
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int lockf(int __fd, int __op, off_t __length) __RENAME_IF_FILE_OFFSET64(lockf64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 /**
  * Like lockf() but allows using a 64-bit length
  * even from a 32-bit process without `_FILE_OFFSET_BITS=64`.
  */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int lockf64(int __fd, int __op, off64_t __length) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
 __END_DECLS
diff --git a/libc/include/bits/memset_explicit_impl.h b/libc/include/bits/memset_explicit_impl.h
new file mode 100644
index 000000000..9562f30f4
--- /dev/null
+++ b/libc/include/bits/memset_explicit_impl.h
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+__BIONIC_MEMSET_EXPLICIT_INLINE void* _Nonnull memset_explicit(void* _Nonnull __dst, int __ch, size_t __n) {
+  void* __result = memset(__dst, __ch, __n);
+  // https://bugs.llvm.org/show_bug.cgi?id=15495
+  __asm__ __volatile__("" : : "r"(__dst) : "memory");
+  return __result;
+}
diff --git a/libc/include/bits/seek_constants.h b/libc/include/bits/seek_constants.h
index a4fffb28d..f95d37f70 100644
--- a/libc/include/bits/seek_constants.h
+++ b/libc/include/bits/seek_constants.h
@@ -35,14 +35,26 @@
 
 #include <sys/cdefs.h>
 
-/** Seek to an absolute offset. */
+/**
+ * Seek to an absolute offset.
+ *
+ * See [lseek(2)](https://man7.org/linux/man-pages/man2/lseek.2.html).
+ */
 #define SEEK_SET 0
-/** Seek relative to the current offset. */
+
+/**
+ * Seek relative to the current offset.
+ *
+ * See [lseek(2)](https://man7.org/linux/man-pages/man2/lseek.2.html).
+ */
 #define SEEK_CUR 1
-/** Seek relative to the end of the file. */
-#define SEEK_END 2
 
-#if defined(__USE_GNU)
+/**
+ * Seek relative to the end of the file.
+ *
+ * See [lseek(2)](https://man7.org/linux/man-pages/man2/lseek.2.html).
+ */
+#define SEEK_END 2
 
 /**
  * Seek to the first data (non-hole) location in the file
@@ -59,5 +71,3 @@
  * See [lseek(2)](https://man7.org/linux/man-pages/man2/lseek.2.html).
  */
 #define SEEK_HOLE 4
-
-#endif
diff --git a/libc/include/bits/strcasecmp.h b/libc/include/bits/strcasecmp.h
index d76cec9cb..c2736b006 100644
--- a/libc/include/bits/strcasecmp.h
+++ b/libc/include/bits/strcasecmp.h
@@ -51,12 +51,10 @@ int strcasecmp(const char* _Nonnull __s1, const char* _Nonnull __s2) __attribute
 /**
  * Like strcasecmp() but taking a `locale_t`.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int strcasecmp_l(const char* _Nonnull __s1, const char* _Nonnull __s2, locale_t _Nonnull __l) __attribute_pure__ __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * [strncasecmp(3)](https://man7.org/linux/man-pages/man3/strncasecmp.3.html) compares the first
  * `n` bytes of two strings ignoring case.
@@ -70,10 +68,8 @@ int strncasecmp(const char* _Nonnull __s1, const char* _Nonnull __s2, size_t __n
 /**
  * Like strncasecmp() but taking a `locale_t`.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int strncasecmp_l(const char* _Nonnull __s1, const char* _Nonnull __s2, size_t __n, locale_t _Nonnull __l) __attribute_pure__ __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/bits/wctype.h b/libc/include/bits/wctype.h
index d0cffec2c..237da1a7b 100644
--- a/libc/include/bits/wctype.h
+++ b/libc/include/bits/wctype.h
@@ -61,9 +61,11 @@ typedef const void* wctrans_t;
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 wint_t towctrans(wint_t __wc, wctrans_t _Nonnull __transform) __INTRODUCED_IN(26);
-wctrans_t _Nullable wctrans(const char* _Nonnull __name) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+wctrans_t _Nullable wctrans(const char* _Nonnull __name) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 __END_DECLS
 
diff --git a/libc/include/complex.h b/libc/include/complex.h
index 11158622c..04ead175b 100644
--- a/libc/include/complex.h
+++ b/libc/include/complex.h
@@ -56,9 +56,11 @@ __BEGIN_DECLS
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cacos(double complex __z) __INTRODUCED_IN(23);
-float complex cacosf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex cacosf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cacosl(long double complex __z) __INTRODUCED_IN(26);
@@ -68,9 +70,11 @@ long double complex cacosl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex casin(double complex __z) __INTRODUCED_IN(23);
-float complex casinf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex casinf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex casinl(long double complex __z) __INTRODUCED_IN(26);
@@ -80,9 +84,11 @@ long double complex casinl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex catan(double complex __z) __INTRODUCED_IN(23);
-float complex catanf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex catanf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex catanl(long double complex __z) __INTRODUCED_IN(26);
@@ -92,9 +98,11 @@ long double complex catanl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ccos(double complex __z) __INTRODUCED_IN(23);
-float complex ccosf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex ccosf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ccosl(long double complex __z) __INTRODUCED_IN(26);
@@ -104,9 +112,11 @@ long double complex ccosl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csin(double complex __z) __INTRODUCED_IN(23);
-float complex csinf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex csinf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex csinl(long double complex __z) __INTRODUCED_IN(26);
@@ -116,9 +126,11 @@ long double complex csinl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ctan(double complex __z) __INTRODUCED_IN(23);
-float complex ctanf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex ctanf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ctanl(long double complex __z) __INTRODUCED_IN(26);
@@ -130,9 +142,11 @@ long double complex ctanl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cacosh(double complex __z) __INTRODUCED_IN(23);
-float complex cacoshf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex cacoshf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cacoshl(long double complex __z) __INTRODUCED_IN(26);
@@ -142,9 +156,11 @@ long double complex cacoshl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex casinh(double complex __z) __INTRODUCED_IN(23);
-float complex casinhf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex casinhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex casinhl(long double complex __z) __INTRODUCED_IN(26);
@@ -154,9 +170,11 @@ long double complex casinhl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex catanh(double complex __z) __INTRODUCED_IN(23);
-float complex catanhf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex catanhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex catanhl(long double complex __z) __INTRODUCED_IN(26);
@@ -166,9 +184,11 @@ long double complex catanhl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ccosh(double complex __z) __INTRODUCED_IN(23);
-float complex ccoshf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex ccoshf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ccoshl(long double complex __z) __INTRODUCED_IN(26);
@@ -178,9 +198,11 @@ long double complex ccoshl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csinh(double complex __z) __INTRODUCED_IN(23);
-float complex csinhf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex csinhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex csinhl(long double complex __z) __INTRODUCED_IN(26);
@@ -190,9 +212,11 @@ long double complex csinhl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ctanh(double complex __z) __INTRODUCED_IN(23);
-float complex ctanhf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex ctanhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ctanhl(long double complex __z) __INTRODUCED_IN(26);
@@ -204,25 +228,42 @@ long double complex ctanhl(long double complex __z) __INTRODUCED_IN(26);
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cexp(double complex __z) __INTRODUCED_IN(23);
-float complex cexpf(float complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+float complex cexpf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cexpl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.7.2 The clog functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 double complex clog(double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 float complex clogf(float complex __z) __INTRODUCED_IN(26);
-long double complex clogl(long double complex __z) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+long double complex clogl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 /* 7.3.8 Power and absolute-value functions */
 /* 7.3.8.1 The cabs functions */
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double cabs(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float cabsf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double cabsl(long double complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
@@ -230,7 +271,13 @@ long double cabsl(long double complex __z) __INTRODUCED_IN(23);
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 double complex cpow(double complex __x, double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 float complex cpowf(float complex __x, float complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cpowl(long double complex __x, long double complex __z) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
@@ -238,32 +285,87 @@ long double complex cpowl(long double complex __x, long double complex __z) __IN
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csqrt(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float complex csqrtf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double complex csqrtl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /* 7.3.9 Manipulation functions */
 /* 7.3.9.1 The carg functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double carg(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float cargf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double cargl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 /* 7.3.9.2 The cimag functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double cimag(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float cimagf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double cimagl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 /* 7.3.9.3 The conj functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex conj(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float complex conjf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double complex conjl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 /* 7.3.9.4 The cproj functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cproj(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float complex cprojf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double complex cprojl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 /* 7.3.9.5 The creal functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double creal(double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 float crealf(float complex __z) __INTRODUCED_IN(23);
-long double creall(long double complex __z) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+long double creall(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 __END_DECLS
 
diff --git a/libc/include/dirent.h b/libc/include/dirent.h
index af22fb312..399af18c3 100644
--- a/libc/include/dirent.h
+++ b/libc/include/dirent.h
@@ -150,9 +150,9 @@ void rewinddir(DIR* _Nonnull __dir);
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 void seekdir(DIR* _Nonnull __dir, long __location) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [telldir(3)](https://man7.org/linux/man-pages/man3/telldir.3.html)
@@ -163,6 +163,7 @@ void seekdir(DIR* _Nonnull __dir, long __location) __INTRODUCED_IN(23);
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long telldir(DIR* _Nonnull __dir) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
@@ -211,8 +212,6 @@ int scandir(const char* _Nonnull __path, struct dirent* _Nonnull * _Nonnull * _N
  */
 int scandir64(const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent64* _Nonnull), int (* _Nullable __comparator)(const struct dirent64* _Nonnull * _Nonnull, const struct dirent64* _Nonnull * _Nonnull));
 
-#if defined(__USE_GNU)
-
 /**
  * [scandirat64(3)](https://man7.org/linux/man-pages/man3/scandirat.3.html)
  * scans all the directory referenced by the pair of `__dir_fd` and `__path`,
@@ -224,11 +223,11 @@ int scandir64(const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull
  * Returns the number of entries returned in the list on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 int scandirat64(int __dir_fd, const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent64* _Nonnull), int (* _Nullable __comparator)(const struct dirent64* _Nonnull * _Nonnull, const struct dirent64* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);
+#endif
 
 /**
  * [scandirat(3)](https://man7.org/linux/man-pages/man3/scandirat.3.html)
@@ -241,12 +240,10 @@ int scandirat64(int __dir_fd, const char* _Nonnull __path, struct dirent64* _Non
  * Returns the number of entries returned in the list on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 int scandirat(int __dir_fd, const char* _Nonnull __path, struct dirent* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent* _Nonnull), int (* _Nullable __comparator)(const struct dirent* _Nonnull * _Nonnull, const struct dirent* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
-
-
 #endif
 
 __END_DECLS
diff --git a/libc/include/dlfcn.h b/libc/include/dlfcn.h
index dc5b7bb99..c8fa6fd04 100644
--- a/libc/include/dlfcn.h
+++ b/libc/include/dlfcn.h
@@ -47,6 +47,10 @@ __BEGIN_DECLS
 
 /**
  * dladdr() returns information using this structure.
+ * `Dl_info` is the traditional name for this,
+ * and thus the more portable choice.
+ * POSIX accidentally standardized `Dl_info_t` instead in 2024,
+ * so we provide both names.
  */
 typedef struct {
   /** Pathname of the shared object that contains the given address. */
@@ -57,7 +61,7 @@ typedef struct {
   const char* _Nullable dli_sname;
   /** Exact address of the symbol named in `dli_sname`. */
   void* _Nullable dli_saddr;
-} Dl_info;
+} Dl_info, Dl_info_t;
 
 /**
  * [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html)
@@ -146,7 +150,6 @@ void* _Nullable dlsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char*
  * Returns the address of the symbol on success, and returns NULL on failure,
  * in which case dlerror() can be used to retrieve the specific error.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 void* _Nullable dlvsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol, const char* _Nullable __version) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
diff --git a/libc/include/error.h b/libc/include/error.h
index a9bdc2461..cf03b4ee0 100644
--- a/libc/include/error.h
+++ b/libc/include/error.h
@@ -44,9 +44,9 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 extern void (* _Nullable error_print_progname)(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [error_message_count(3)](https://man7.org/linux/man-pages/man3/error_message_count.3.html) is
@@ -54,7 +54,9 @@ extern void (* _Nullable error_print_progname)(void) __INTRODUCED_IN(23);
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 extern unsigned int error_message_count __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [error_one_per_line(3)](https://man7.org/linux/man-pages/man3/error_one_per_line.3.html) is
@@ -63,7 +65,9 @@ extern unsigned int error_message_count __INTRODUCED_IN(23);
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 extern int error_one_per_line __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [error(3)](https://man7.org/linux/man-pages/man3/error.3.html) formats the given printf()-like
@@ -72,7 +76,9 @@ extern int error_one_per_line __INTRODUCED_IN(23);
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void error(int __status, int __errno, const char* _Nonnull __fmt, ...) __printflike(3, 4) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [error_at_line(3)](https://man7.org/linux/man-pages/man3/error_at_line.3.html) formats the given
@@ -82,8 +88,8 @@ void error(int __status, int __errno, const char* _Nonnull __fmt, ...) __printfl
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void error_at_line(int __status, int __errno, const char* _Nonnull __filename, unsigned int __line_number, const char* _Nonnull __fmt, ...) __printflike(5, 6) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/execinfo.h b/libc/include/execinfo.h
index 84b637cd9..c8fc434d3 100644
--- a/libc/include/execinfo.h
+++ b/libc/include/execinfo.h
@@ -47,9 +47,9 @@ __BEGIN_DECLS
  *
  * Available since API level 33.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(33)
 int backtrace(void* _Nonnull * _Nonnull buffer, int size) __INTRODUCED_IN(33);
+#endif /* __BIONIC_AVAILABILITY_GUARD(33) */
 
 /**
  * [backtrace_symbols(3)](https://man7.org/linux/man-pages/man3/backtrace_symbols.3.html)
@@ -61,7 +61,9 @@ int backtrace(void* _Nonnull * _Nonnull buffer, int size) __INTRODUCED_IN(33);
  *
  * Available since API level 33.
  */
+#if __BIONIC_AVAILABILITY_GUARD(33)
 char* _Nullable * _Nullable backtrace_symbols(void* _Nonnull const* _Nonnull buffer, int size) __INTRODUCED_IN(33);
+#endif /* __BIONIC_AVAILABILITY_GUARD(33) */
 
 /**
  * [backtrace_symbols_fd(3)](https://man7.org/linux/man-pages/man3/backtrace_symbols_fd.3.html)
@@ -71,8 +73,8 @@ char* _Nullable * _Nullable backtrace_symbols(void* _Nonnull const* _Nonnull buf
  *
  * Available since API level 33.
  */
+#if __BIONIC_AVAILABILITY_GUARD(33)
 void backtrace_symbols_fd(void* _Nonnull const* _Nonnull buffer, int size, int fd) __INTRODUCED_IN(33);
 #endif /* __BIONIC_AVAILABILITY_GUARD(33) */
 
-
 __END_DECLS
diff --git a/libc/include/fcntl.h b/libc/include/fcntl.h
index 2bd1fc66b..4385053ea 100644
--- a/libc/include/fcntl.h
+++ b/libc/include/fcntl.h
@@ -208,15 +208,17 @@ int posix_fallocate(int __fd, off_t __offset, off_t __length) __RENAME_IF_FILE_O
 /** See posix_fallocate(). */
 int posix_fallocate64(int __fd, off64_t __offset, off64_t __length);
 
-#if defined(__USE_GNU)
-
 /**
  * [readahead(2)](https://man7.org/linux/man-pages/man2/readahead.2.html)
  * initiates readahead for the given file.
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
+ *
+ * Available when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU)
 ssize_t readahead(int __fd, off64_t __offset, size_t __length);
+#endif
 
 /**
  * [sync_file_range(2)](https://man7.org/linux/man-pages/man2/sync_file_range.2.html)
@@ -226,13 +228,11 @@ ssize_t readahead(int __fd, off64_t __offset, size_t __length);
  * `SYNC_FILE_RANGE_WAIT_AFTER`.
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
+ *
+ * Available since API level 26 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(26)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
 int sync_file_range(int __fd, off64_t __offset, off64_t __length, unsigned int __flags) __INTRODUCED_IN(26);
-#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
-
-
 #endif
 
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
diff --git a/libc/include/glob.h b/libc/include/glob.h
index ccdf2e92a..857e9c157 100644
--- a/libc/include/glob.h
+++ b/libc/include/glob.h
@@ -33,8 +33,7 @@
  * $FreeBSD$
  */
 
-#ifndef _GLOB_H_
-#define _GLOB_H_
+#pragma once
 
 #include <sys/cdefs.h>
 #include <sys/types.h>
@@ -80,25 +79,49 @@ typedef struct {
 #define GLOB_ABORTED	(-2)	/* Unignored error. */
 #define GLOB_NOMATCH	(-3)	/* No match and GLOB_NOCHECK was not set. */
 
+/** Use alternately specified directory funcs. */
 #if __USE_BSD
-#define GLOB_ALTDIRFUNC	0x0040	/* Use alternately specified directory funcs. */
-#define GLOB_BRACE	0x0080	/* Expand braces like csh. */
-#define GLOB_MAGCHAR	0x0100	/* Set in `gl_flags` if the pattern had globbing characters. */
-#define GLOB_NOMAGIC	0x0200	/* GLOB_NOCHECK without magic chars (csh). */
-#define GLOB_QUOTE	0x0400	/* Quote special chars with \. */
-#define GLOB_TILDE	0x0800	/* Expand tilde names from the passwd file. */
-#define GLOB_LIMIT	0x1000	/* limit number of returned paths */
+#define GLOB_ALTDIRFUNC	0x0040
 #endif
 
-__BEGIN_DECLS
+/** Expand braces like csh. */
+#if __USE_BSD
+#define GLOB_BRACE	0x0080
+#endif
 
+/** Set in `gl_flags` if the pattern had globbing characters. */
+#if __USE_BSD
+#define GLOB_MAGCHAR	0x0100
+#endif
+
+/** GLOB_NOCHECK without magic chars (csh). */
+#if __USE_BSD
+#define GLOB_NOMAGIC	0x0200
+#endif
+
+/** Quote special chars with \. */
+#if __USE_BSD
+#define GLOB_QUOTE	0x0400
+#endif
+
+/** Expand tilde names from the passwd file. */
+#if __USE_BSD
+#define GLOB_TILDE	0x0800
+#endif
+
+/** Limit number of returned paths. */
+#if __USE_BSD
+#define GLOB_LIMIT	0x1000
+#endif
+
+__BEGIN_DECLS
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int glob(const char* _Nonnull __pattern, int __flags, int (* _Nullable __error_callback)(const char* _Nonnull __failure_path, int __failure_errno), glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
-void globfree(glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
+void globfree(glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 __END_DECLS
-
-#endif
diff --git a/libc/include/grp.h b/libc/include/grp.h
index a48c04677..329e48795 100644
--- a/libc/include/grp.h
+++ b/libc/include/grp.h
@@ -54,14 +54,21 @@ struct group* _Nullable getgrnam(const char* _Nonnull __name);
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 struct group* _Nullable getgrent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
 void setgrent(void) __INTRODUCED_IN(26);
-void endgrent(void) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+void endgrent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int getgrgid_r(gid_t __gid, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable * _Nonnull __result) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int getgrnam_r(const char* _Nonnull __name, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable *_Nonnull __result) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
diff --git a/libc/include/iconv.h b/libc/include/iconv.h
index 35328ee9b..f120d42a7 100644
--- a/libc/include/iconv.h
+++ b/libc/include/iconv.h
@@ -60,9 +60,9 @@ typedef struct __iconv_t* iconv_t;
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 iconv_t _Nonnull iconv_open(const char* _Nonnull __dst_encoding, const char* _Nonnull __src_encoding) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [iconv(3)](https://man7.org/linux/man-pages/man3/iconv.3.html) converts characters from one
@@ -73,7 +73,9 @@ iconv_t _Nonnull iconv_open(const char* _Nonnull __dst_encoding, const char* _No
  *
  * Available since API level 28.
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 size_t iconv(iconv_t _Nonnull __converter, char* _Nullable * _Nullable __src_buf, size_t* __BIONIC_COMPLICATED_NULLNESS __src_bytes_left, char* _Nullable * _Nullable __dst_buf, size_t* __BIONIC_COMPLICATED_NULLNESS __dst_bytes_left) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [iconv_close(3)](https://man7.org/linux/man-pages/man3/iconv_close.3.html) deallocates a converter
@@ -83,8 +85,8 @@ size_t iconv(iconv_t _Nonnull __converter, char* _Nullable * _Nullable __src_buf
  *
  * Available since API level 28.
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int iconv_close(iconv_t _Nonnull __converter) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 __END_DECLS
diff --git a/libc/include/ifaddrs.h b/libc/include/ifaddrs.h
index 87d29471b..2eba91a88 100644
--- a/libc/include/ifaddrs.h
+++ b/libc/include/ifaddrs.h
@@ -80,9 +80,9 @@ struct ifaddrs {
  *
  * Available since API level 24.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int getifaddrs(struct ifaddrs* _Nullable * _Nonnull __list_ptr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 /**
  * [freeifaddrs(3)](https://man7.org/linux/man-pages/man3/freeifaddrs.3.html) frees a linked list
@@ -90,8 +90,8 @@ int getifaddrs(struct ifaddrs* _Nullable * _Nonnull __list_ptr) __INTRODUCED_IN(
  *
  * Available since API level 24.
  */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 void freeifaddrs(struct ifaddrs* _Nullable __ptr) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
 __END_DECLS
diff --git a/libc/include/inttypes.h b/libc/include/inttypes.h
index 790030e97..bb2ee43a6 100644
--- a/libc/include/inttypes.h
+++ b/libc/include/inttypes.h
@@ -327,12 +327,27 @@ typedef struct {
 } imaxdiv_t;
 
 __BEGIN_DECLS
+
+/**
+ * Returns the absolute value where possible.
+ * For the most negative value, the result is unchanged (and thus also negative).
+ */
 intmax_t imaxabs(intmax_t __i) __attribute_const__;
+
+/**
+ * Returns `__numerator / __denominator` and `__numerator % __denominator`,
+ * truncating towards zero.
+ *
+ * This function was useful for portability before C99,
+ * where `/` and `%` were also defined to truncate towards zero.
+ */
 imaxdiv_t imaxdiv(intmax_t __numerator, intmax_t __denominator) __attribute_const__;
+
 intmax_t strtoimax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base);
 uintmax_t strtoumax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base);
 intmax_t wcstoimax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base);
 uintmax_t wcstoumax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base);
+
 __END_DECLS
 
 #endif
diff --git a/libc/include/langinfo.h b/libc/include/langinfo.h
index b9d695c25..a39c259bc 100644
--- a/libc/include/langinfo.h
+++ b/libc/include/langinfo.h
@@ -92,12 +92,13 @@ __BEGIN_DECLS
 #define NOEXPR 54
 #define CRNCYSTR 55
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 char* _Nonnull nl_langinfo(nl_item __item) __INTRODUCED_IN(26);
-char* _Nonnull nl_langinfo_l(nl_item __item, locale_t _Nonnull __l) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+char* _Nonnull nl_langinfo_l(nl_item __item, locale_t _Nonnull __l) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 __END_DECLS
 
diff --git a/libc/include/limits.h b/libc/include/limits.h
index 3220415f7..cb175637f 100644
--- a/libc/include/limits.h
+++ b/libc/include/limits.h
@@ -60,6 +60,9 @@
 /* Many of the POSIX limits come from the kernel. */
 #include <linux/limits.h>
 
+/** Maximum buffer size for getentropy(). */
+#define GETENTROPY_MAX 256
+
 /** Maximum number of positional arguments in a printf()/scanf() format string. */
 #define NL_ARGMAX 9
 /** Maximum number of bytes in a $LANG name. */
diff --git a/libc/include/link.h b/libc/include/link.h
index 331070e41..2afc5dc0c 100644
--- a/libc/include/link.h
+++ b/libc/include/link.h
@@ -101,12 +101,21 @@ struct dl_phdr_info {
 
 /**
  * [dl_iterate_phdr(3)](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html)
- * calls the given callback once for every loaded shared object. The size
- * argument to the callback lets you determine whether you have a smaller
- * `dl_phdr_info` from before API level 30, or the newer full one.
+ * calls the given callback once for every loaded shared object.
+ *
+ * The size argument to the callback lets you determine whether you have a
+ * smaller `dl_phdr_info` from before API level 30, or the newer full one.
  * The data argument to the callback is whatever you pass as the data argument
  * to dl_iterate_phdr().
  *
+ * Before API level 38, iteration starts with the dynamic linker itself
+ * followed by the main executable.
+ *
+ * From API level 38, iteration starts with the main executable.
+ *
+ * On Android, the `dlpi_name` field for a dynamic executable points to
+ * its canonical path.
+ *
  * Returns the value returned by the final call to the callback.
  */
 int dl_iterate_phdr(int (* _Nonnull __callback)(struct dl_phdr_info* _Nonnull __info, size_t __size, void* _Nullable __data), void* _Nullable __data);
diff --git a/libc/include/malloc.h b/libc/include/malloc.h
index bb4916aba..6fb12a2cc 100644
--- a/libc/include/malloc.h
+++ b/libc/include/malloc.h
@@ -121,10 +121,17 @@ __nodiscard void* _Nullable memalign(size_t __alignment, size_t __byte_count) __
 /**
  * [malloc_usable_size(3)](https://man7.org/linux/man-pages/man3/malloc_usable_size.3.html)
  * returns the actual size of the given heap block.
+ *
+ * malloc_usable_size() and _FORTIFY_SOURCE>=3 are incompatible if you are using more of the
+ * allocation than originally requested. However, malloc_usable_size() can be used to keep track
+ * of allocation/deallocation byte counts and this is an exception to the incompatible rule. In this
+ * case, you can define __BIONIC_DISABLE_MALLOC_USABLE_SIZE_FORTIFY_WARNINGS to disable the
+ * compiler error.
  */
 __nodiscard size_t malloc_usable_size(const void* _Nullable __ptr)
-#if defined(_FORTIFY_SOURCE)
-    __clang_error_if(_FORTIFY_SOURCE == 3, "malloc_usable_size() and _FORTIFY_SOURCE=3 are incompatible")
+#if defined(_FORTIFY_SOURCE) && !defined(__BIONIC_DISABLE_MALLOC_USABLE_SIZE_FORTIFY_WARNINGS)
+    __clang_error_if(_FORTIFY_SOURCE >= 3,
+      "malloc_usable_size() and _FORTIFY_SOURCE>=3 are incompatible: see malloc_usable_size() documentation")
 #endif
 ;
 
@@ -199,7 +206,6 @@ struct mallinfo2 mallinfo2(void) __RENAME(mallinfo);
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int malloc_info(int __must_be_zero, FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
@@ -376,7 +382,6 @@ enum HeapTaggingLevel {
  *
  * Available since API level 26.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int mallopt(int __option, int __value) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
@@ -391,9 +396,9 @@ int mallopt(int __option, int __value) __INTRODUCED_IN(26);
  *
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 extern void* _Nonnull (*volatile _Nonnull __malloc_hook)(size_t __byte_count, const void* _Nonnull __caller) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [__realloc_hook(3)](https://man7.org/linux/man-pages/man3/__realloc_hook.3.html)
@@ -404,7 +409,9 @@ extern void* _Nonnull (*volatile _Nonnull __malloc_hook)(size_t __byte_count, co
  *
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 extern void* _Nonnull (*volatile _Nonnull __realloc_hook)(void* _Nullable __ptr, size_t __byte_count, const void* _Nonnull __caller) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [__free_hook(3)](https://man7.org/linux/man-pages/man3/__free_hook.3.html)
@@ -415,7 +422,9 @@ extern void* _Nonnull (*volatile _Nonnull __realloc_hook)(void* _Nullable __ptr,
  *
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 extern void (*volatile _Nonnull __free_hook)(void* _Nullable __ptr, const void* _Nonnull __caller) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [__memalign_hook(3)](https://man7.org/linux/man-pages/man3/__memalign_hook.3.html)
@@ -426,8 +435,8 @@ extern void (*volatile _Nonnull __free_hook)(void* _Nullable __ptr, const void*
  *
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 extern void* _Nonnull (*volatile _Nonnull __memalign_hook)(size_t __alignment, size_t __byte_count, const void* _Nonnull __caller) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 __END_DECLS
diff --git a/libc/include/math.h b/libc/include/math.h
index 59161bf0e..0d0394026 100644
--- a/libc/include/math.h
+++ b/libc/include/math.h
@@ -330,6 +330,20 @@ double yn(int __n, double __x);
 #define M_SQRT2		1.41421356237309504880	/* sqrt(2) */
 #define M_SQRT1_2	0.70710678118654752440	/* 1/sqrt(2) */
 
+#define M_El            2.718281828459045235360287471352662498L /* e */
+#define M_LOG2El        1.442695040888963407359924681001892137L /* log 2e */
+#define M_LOG10El       0.434294481903251827651128918916605082L /* log 10e */
+#define M_LN2l          0.693147180559945309417232121458176568L /* log e2 */
+#define M_LN10l         2.302585092994045684017991454684364208L /* log e10 */
+#define M_PIl           3.141592653589793238462643383279502884L /* pi */
+#define M_PI_2l         1.570796326794896619231321691639751442L /* pi/2 */
+#define M_PI_4l         0.785398163397448309615660845819875721L /* pi/4 */
+#define M_1_PIl         0.318309886183790671537767526745028724L /* 1/pi */
+#define M_2_PIl         0.636619772367581343075535053490057448L /* 2/pi */
+#define M_2_SQRTPIl     1.128379167095512573896158903121545172L /* 2/sqrt(pi) */
+#define M_SQRT2l        1.414213562373095048801688724209698079L /* sqrt(2) */
+#define M_SQRT1_2l      0.707106781186547524400844362104849039L /* 1/sqrt(2) */
+
 #define MAXFLOAT	((float)3.40282346638528860e+38)
 
 /* BSD extensions. */
@@ -342,55 +356,117 @@ double yn(int __n, double __x);
 
 #if defined(__USE_BSD) || defined(__USE_GNU)
 double gamma(double __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 double scalb(double __x, double __exponent);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 double drem(double __x, double __y);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 int finite(double __x) __attribute_const__;
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 int isinff(float __x) __attribute_const__;
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 int isnanf(float __x) __attribute_const__;
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 double gamma_r(double __x, int* _Nonnull __sign);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 double lgamma_r(double __x, int* _Nonnull __sign);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 double significand(double __x);
+#endif
 
-#if __BIONIC_AVAILABILITY_GUARD(23)
+#if (defined(__USE_BSD) || defined(__USE_GNU)) && __BIONIC_AVAILABILITY_GUARD(23)
 long double lgammal_r(long double __x, int* _Nonnull __sign) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#endif
 
+#if defined(__USE_BSD) || defined(__USE_GNU)
 long double significandl(long double __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float dremf(float __x, float __y);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 int finitef(float __x) __attribute_const__;
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float gammaf(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float j0f(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float j1f(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float jnf(int __n, float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float scalbf(float __x, float __exponent);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float y0f(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float y1f(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float ynf(int __n, float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float gammaf_r(float __x, int* _Nonnull __sign);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float lgammaf_r(float __x, int* _Nonnull __sign);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 float significandf(float __x);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 void sincos(double __x, double* _Nonnull __sin, double* _Nonnull __cos);
+#endif
+
+#if defined(__USE_BSD) || defined(__USE_GNU)
 void sincosf(float __x, float* _Nonnull __sin, float* _Nonnull __cos);
-void sincosl(long double __x, long double* _Nonnull __sin, long double* _Nonnull __cos);
 #endif
 
-/* GNU extensions. */
+#if defined(__USE_BSD) || defined(__USE_GNU)
+void sincosl(long double __x, long double* _Nonnull __sin, long double* _Nonnull __cos);
+#endif
 
 #if defined(__USE_GNU)
-#define M_El            2.718281828459045235360287471352662498L /* e */
-#define M_LOG2El        1.442695040888963407359924681001892137L /* log 2e */
-#define M_LOG10El       0.434294481903251827651128918916605082L /* log 10e */
-#define M_LN2l          0.693147180559945309417232121458176568L /* log e2 */
-#define M_LN10l         2.302585092994045684017991454684364208L /* log e10 */
-#define M_PIl           3.141592653589793238462643383279502884L /* pi */
-#define M_PI_2l         1.570796326794896619231321691639751442L /* pi/2 */
-#define M_PI_4l         0.785398163397448309615660845819875721L /* pi/4 */
-#define M_1_PIl         0.318309886183790671537767526745028724L /* 1/pi */
-#define M_2_PIl         0.636619772367581343075535053490057448L /* 2/pi */
-#define M_2_SQRTPIl     1.128379167095512573896158903121545172L /* 2/sqrt(pi) */
-#define M_SQRT2l        1.414213562373095048801688724209698079L /* sqrt(2) */
-#define M_SQRT1_2l      0.707106781186547524400844362104849039L /* 1/sqrt(2) */
 int isinfl(long double __x) __attribute_const__;
+#endif
+
+#if defined(__USE_GNU)
 int isnanl(long double __x) __attribute_const__;
 #endif
 
diff --git a/libc/include/net/if.h b/libc/include/net/if.h
index 50bc74c8b..8b3f10037 100644
--- a/libc/include/net/if.h
+++ b/libc/include/net/if.h
@@ -50,9 +50,11 @@ unsigned if_nametoindex(const char* _Nonnull __name);
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 struct if_nameindex* _Nullable if_nameindex(void) __INTRODUCED_IN(24);
-void if_freenameindex(struct if_nameindex* _Nullable __ptr) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
+#if __BIONIC_AVAILABILITY_GUARD(24)
+void if_freenameindex(struct if_nameindex* _Nullable __ptr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 __END_DECLS
 
diff --git a/libc/include/netdb.h b/libc/include/netdb.h
index 04aaf5cfd..1d8b98ce1 100644
--- a/libc/include/netdb.h
+++ b/libc/include/netdb.h
@@ -225,7 +225,6 @@ struct hostent* _Nullable gethostbyname2(const char* _Nonnull __name, int __af);
 int gethostbyname2_r(const char* _Nonnull __name, int __af, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 void endhostent(void) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
@@ -234,8 +233,11 @@ struct hostent* _Nullable gethostent(void);
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 void sethostent(int __stay_open) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /* These functions are obsolete. None of these functions return anything but nullptr. */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void endnetent(void) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
@@ -244,9 +246,14 @@ struct netent* _Nullable getnetbyname(const char* _Nonnull __name);
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 struct netent* _Nullable getnetent(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void setnetent(int __stay_open) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /* None of these functions return anything but nullptr. */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void endprotoent(void) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
@@ -255,6 +262,8 @@ struct protoent* _Nullable getprotobynumber(int __proto);
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 struct protoent* _Nullable getprotoent(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void setprotoent(int __stay_open) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
diff --git a/libc/include/netinet/if_ether.h b/libc/include/netinet/if_ether.h
index b1b9ed0fe..6f44c4122 100644
--- a/libc/include/netinet/if_ether.h
+++ b/libc/include/netinet/if_ether.h
@@ -31,40 +31,30 @@
  *	@(#)if_ether.h	8.3 (Berkeley) 5/2/95
  */
 
-#ifndef _NETINET_IF_ETHER_H_
-#define _NETINET_IF_ETHER_H_
+#pragma once
 
 #include <sys/cdefs.h>
 #include <sys/types.h>
-
-#if defined(__USE_BSD)
-
-/* pull in Ethernet-specific definitions and packet structures */
-
 #include <linux/if_ether.h>
-
-/* pull in ARP-specific definitions and packet structures */
-
-#include <net/if_arp.h>
-
 #include <net/ethernet.h>
+#include <net/if_arp.h>
 
-/* ... and define some more which we don't need anymore: */
-
-/*
+/**
  * Ethernet Address Resolution Protocol.
  *
- * See RFC 826 for protocol description.  Structure below is not
- * used by our kernel!!! Only for userland programs which are externally
- * maintained and need it.
+ * See RFC 826 for protocol description.
  */
-
-struct	ether_arp {
-	struct	 arphdr ea_hdr;			/* fixed-size header */
-	u_int8_t arp_sha[ETHER_ADDR_LEN];	/* sender hardware address */
-	u_int8_t arp_spa[4];			/* sender protocol address */
-	u_int8_t arp_tha[ETHER_ADDR_LEN];	/* target hardware address */
-	u_int8_t arp_tpa[4];			/* target protocol address */
+struct ether_arp {
+	/** Fixed-size header. */
+	struct arphdr ea_hdr;
+	/** Sender hardware address. */
+	u_int8_t arp_sha[ETHER_ADDR_LEN];
+	/** Sender protocol address. */
+	u_int8_t arp_spa[4];
+  /** Target hardware address. */
+  u_int8_t arp_tha[ETHER_ADDR_LEN];
+  /** Target protocol address. */
+  u_int8_t arp_tpa[4];
 } __packed;
 #define	arp_hrd	ea_hdr.ar_hrd
 #define	arp_pro	ea_hdr.ar_pro
@@ -72,8 +62,8 @@ struct	ether_arp {
 #define	arp_pln	ea_hdr.ar_pln
 #define	arp_op	ea_hdr.ar_op
 
-/*
- * Macro to map an IP multicast address to an Ethernet multicast address.
+/**
+ * Maps an IP multicast address to an Ethernet multicast address.
  * The high-order 25 bits of the Ethernet address are statically assigned,
  * and the low-order 23 bits are taken from the low end of the IP address.
  */
@@ -88,8 +78,9 @@ struct	ether_arp {
 	(enaddr)[4] = ((u_int8_t *)ipaddr)[2];				\
 	(enaddr)[5] = ((u_int8_t *)ipaddr)[3];				\
 }
-/*
- * Macro to map an IP6 multicast address to an Ethernet multicast address.
+
+/**
+ * Maps an IP6 multicast address to an Ethernet multicast address.
  * The high-order 16 bits of the Ethernet address are statically assigned,
  * and the low-order 32 bits are taken from the low end of the IP6 address.
  */
@@ -104,7 +95,3 @@ struct	ether_arp {
 	(enaddr)[4] = ((u_int8_t *)ip6addr)[14];			\
 	(enaddr)[5] = ((u_int8_t *)ip6addr)[15];			\
 }
-
-#endif /* __USE_BSD */
-
-#endif /* !_NET_IF_ETHER_H_ */
diff --git a/libc/include/nl_types.h b/libc/include/nl_types.h
index 172d80d91..a4b1d7a9c 100644
--- a/libc/include/nl_types.h
+++ b/libc/include/nl_types.h
@@ -62,9 +62,9 @@ typedef int nl_item;
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 nl_catd _Nonnull catopen(const char* _Nonnull __name, int __flag) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 /**
  * [catgets(3)](https://man7.org/linux/man-pages/man3/catgets.3.html) translates the given message
@@ -74,15 +74,17 @@ nl_catd _Nonnull catopen(const char* _Nonnull __name, int __flag) __INTRODUCED_I
  *
  * Available since API level 28.
  */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 char* _Nonnull catgets(nl_catd _Nonnull __catalog, int __set_number, int __msg_number, const char* _Nonnull __msg) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 /**
  * [catclose(3)](https://man7.org/linux/man-pages/man3/catclose.3.html) closes a message catalog.
  *
  * On Android, this always returns -1 with `errno` set to `EBADF`.
  */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int catclose(nl_catd _Nonnull __catalog) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 __END_DECLS
diff --git a/libc/include/poll.h b/libc/include/poll.h
index e57f81275..873f97071 100644
--- a/libc/include/poll.h
+++ b/libc/include/poll.h
@@ -69,7 +69,6 @@ int ppoll(struct pollfd* _Nullable __fds, nfds_t __count, const struct timespec*
 int ppoll64(struct pollfd* _Nullable  __fds, nfds_t __count, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
 #define _POLL_H_
 #include <bits/fortify/poll.h>
diff --git a/libc/include/pthread.h b/libc/include/pthread.h
index 5a3376ae3..06c952b2e 100644
--- a/libc/include/pthread.h
+++ b/libc/include/pthread.h
@@ -314,25 +314,46 @@ int pthread_rwlock_wrlock(pthread_rwlock_t* _Nonnull __rwlock);
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrierattr_init(pthread_barrierattr_t* _Nonnull __attr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrierattr_destroy(pthread_barrierattr_t* _Nonnull __attr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrierattr_getpshared(const pthread_barrierattr_t* _Nonnull __attr, int* _Nonnull __shared) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrierattr_setpshared(pthread_barrierattr_t* _Nonnull __attr, int __shared) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrier_init(pthread_barrier_t* _Nonnull __barrier, const pthread_barrierattr_t* _Nullable __attr, unsigned __count) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrier_destroy(pthread_barrier_t* _Nonnull __barrier) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrier_wait(pthread_barrier_t* _Nonnull __barrier) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_spin_destroy(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_spin_init(pthread_spinlock_t* _Nonnull __spinlock, int __shared) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_spin_lock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_spin_trylock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_spin_unlock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 
 pthread_t pthread_self(void) __attribute_const__;
 
-#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
 /**
  * [pthread_getname_np(3)](https://man7.org/linux/man-pages/man3/pthread_getname_np.3.html)
  * gets the name of the given thread.
@@ -340,8 +361,9 @@ pthread_t pthread_self(void) __attribute_const__;
  *
  * Returns 0 on success and returns an error number on failure.
  *
- * Available since API level 26.
+ * Available since API level 26 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
 int pthread_getname_np(pthread_t __pthread, char* _Nonnull __buf, size_t __n) __INTRODUCED_IN(26);
 #endif
 
@@ -365,7 +387,7 @@ int pthread_setname_np(pthread_t __pthread, const char* _Nonnull __name);
  *
  * Returns 0 on success and returns an error number on failure.
  *
- * Available since API level 36.
+ * Available since API level 36 when compiling with `_GNU_SOURCE`.
  * See sched_getaffinity() and pthread_gettid_np() for greater portability.
  */
 #if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(36)
@@ -378,7 +400,7 @@ int pthread_getaffinity_np(pthread_t __pthread, size_t __cpu_set_size, cpu_set_t
  *
  * Returns 0 on success and returns an error number on failure.
  *
- * Available since API level 36.
+ * Available since API level 36 when compiling with `_GNU_SOURCE`.
  * See sched_getaffinity() and pthread_gettid_np() for greater portability.
  */
 #if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(36)
diff --git a/libc/include/pty.h b/libc/include/pty.h
index 92d7fbb82..dce76915e 100644
--- a/libc/include/pty.h
+++ b/libc/include/pty.h
@@ -49,9 +49,9 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int openpty(int* _Nonnull __pty_fd, int* _Nonnull __tty_fd, char* _Nullable __tty_name, const struct termios* _Nullable __termios_ptr, const struct winsize* _Nullable __winsize_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [forkpty(3)](https://man7.org/linux/man-pages/man3/forkpty.3.html) creates
@@ -62,8 +62,8 @@ int openpty(int* _Nonnull __pty_fd, int* _Nonnull __tty_fd, char* _Nullable __tt
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int forkpty(int* _Nonnull __parent_pty_fd, char* _Nullable __child_tty_name, const struct termios* _Nullable __termios_ptr, const struct winsize* _Nullable __winsize_ptr) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/pwd.h b/libc/include/pwd.h
index 09592bcc2..464c45b53 100644
--- a/libc/include/pwd.h
+++ b/libc/include/pwd.h
@@ -87,11 +87,15 @@ struct passwd* _Nullable getpwuid(uid_t __uid);
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 struct passwd* _Nullable getpwent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
 void setpwent(void) __INTRODUCED_IN(26);
-void endpwent(void) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+void endpwent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 int getpwnam_r(const char* _Nonnull __name, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);
 int getpwuid_r(uid_t __uid, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);
diff --git a/libc/include/resolv.h b/libc/include/resolv.h
index c49cefc5f..d0f246cce 100644
--- a/libc/include/resolv.h
+++ b/libc/include/resolv.h
@@ -66,7 +66,6 @@ int res_search(const char* _Nonnull __name, int __class, int __type, u_char* _No
 u_int __res_randomid(void) __INTRODUCED_IN(29);
 #endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
-
 __END_DECLS
 
 #endif
diff --git a/libc/include/sched.h b/libc/include/sched.h
index c68ebf0bb..2a75e5420 100644
--- a/libc/include/sched.h
+++ b/libc/include/sched.h
@@ -165,8 +165,6 @@ int sched_getparam(pid_t __pid, struct sched_param* _Nonnull __param);
  */
 int sched_rr_get_interval(pid_t __pid, struct timespec* _Nonnull __quantum);
 
-#if defined(__USE_GNU)
-
 /**
  * [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html)
  * creates a new child process.
@@ -174,7 +172,9 @@ int sched_rr_get_interval(pid_t __pid, struct timespec* _Nonnull __quantum);
  * Returns the pid of the child to the caller on success and
  * returns -1 and sets `errno` on failure.
  */
+#if defined(__USE_GNU)
 int clone(int (* __BIONIC_COMPLICATED_NULLNESS __fn)(void* __BIONIC_COMPLICATED_NULLNESS ), void* __BIONIC_COMPLICATED_NULLNESS __child_stack, int __flags, void* _Nullable __arg, ...);
+#endif
 
 /**
  * [unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html)
@@ -182,7 +182,9 @@ int clone(int (* __BIONIC_COMPLICATED_NULLNESS __fn)(void* __BIONIC_COMPLICATED_
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+#if defined(__USE_GNU)
 int unshare(int __flags);
+#endif
 
 /**
  * [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html)
@@ -190,7 +192,9 @@ int unshare(int __flags);
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+#if defined(__USE_GNU)
 int setns(int __fd, int __ns_type);
+#endif
 
 /**
  * [sched_getcpu(3)](https://man7.org/linux/man-pages/man3/sched_getcpu.3.html)
@@ -199,26 +203,43 @@ int setns(int __fd, int __ns_type);
  * Returns a non-negative CPU number on success and returns -1 and sets
  * `errno` on failure.
  */
+#if defined(__USE_GNU)
 int sched_getcpu(void);
+#endif
 
+#if defined(__USE_GNU)
 #ifdef __LP64__
 #define CPU_SETSIZE 1024
 #else
 #define CPU_SETSIZE 32
 #endif
+#endif
 
+#if defined(__USE_GNU)
 #define __CPU_BITTYPE  unsigned long int  /* mandated by the kernel  */
+#endif
+
+#if defined(__USE_GNU)
 #define __CPU_BITS     (8 * sizeof(__CPU_BITTYPE))
+#endif
+
+#if defined(__USE_GNU)
 #define __CPU_ELT(x)   ((x) / __CPU_BITS)
+#endif
+
+#if defined(__USE_GNU)
 #define __CPU_MASK(x)  ((__CPU_BITTYPE)1 << ((x) & (__CPU_BITS - 1)))
+#endif
 
 /**
  * [cpu_set_t](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) is a
  * statically-sized CPU set. See `CPU_ALLOC` for dynamically-sized CPU sets.
  */
+#if defined(__USE_GNU)
 typedef struct {
   __CPU_BITTYPE  __bits[ CPU_SETSIZE / __CPU_BITS ];
 } cpu_set_t;
+#endif
 
 /**
  * [sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html)
@@ -226,7 +247,9 @@ typedef struct {
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-int sched_setaffinity(pid_t __pid, size_t __set_size, const cpu_set_t* _Nonnull __set);
+#if defined(__USE_GNU)
+int sched_setaffinity(pid_t __pid, size_t __cpu_set_size, const cpu_set_t* _Nonnull __cpu_set);
+#endif
 
 /**
  * [sched_getaffinity(2)](https://man7.org/linux/man-pages/man2/sched_getaffinity.2.html)
@@ -234,7 +257,9 @@ int sched_setaffinity(pid_t __pid, size_t __set_size, const cpu_set_t* _Nonnull
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set);
+#if defined(__USE_GNU)
+int sched_getaffinity(pid_t __pid, size_t __cpu_set_size, cpu_set_t* _Nonnull __cpu_set);
+#endif
 
 /**
  * [sched_setattr(2)](https://man7.org/linux/man-pages/man2/sched_setattr.2.html)
@@ -242,7 +267,9 @@ int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set)
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+#if defined(__USE_GNU)
 int sched_setattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __flags) __INTRODUCED_IN(37);
+#endif
 
 /**
  * [sched_getattr(2)](https://man7.org/linux/man-pages/man2/sched_getattr.2.html)
@@ -250,60 +277,81 @@ int sched_setattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __fl
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+#if defined(__USE_GNU)
 int sched_getattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __size, unsigned __flags) __INTRODUCED_IN(37);
+#endif
 
 /**
  * [CPU_ZERO](https://man7.org/linux/man-pages/man3/CPU_ZERO.3.html) clears all
  * bits in a static CPU set.
  */
+#if defined(__USE_GNU)
 #define CPU_ZERO(set)          CPU_ZERO_S(sizeof(cpu_set_t), set)
+#endif
+
 /**
  * [CPU_ZERO_S](https://man7.org/linux/man-pages/man3/CPU_ZERO_S.3.html) clears all
  * bits in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_ZERO_S(setsize, set)  __builtin_memset(set, 0, setsize)
+#endif
 
 /**
  * [CPU_SET](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) sets one
  * bit in a static CPU set.
  */
+#if defined(__USE_GNU)
 #define CPU_SET(cpu, set)      CPU_SET_S(cpu, sizeof(cpu_set_t), set)
+#endif
+
 /**
  * [CPU_SET_S](https://man7.org/linux/man-pages/man3/CPU_SET_S.3.html) sets one
  * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_SET_S(cpu, setsize, set) \
   do { \
     size_t __cpu = (cpu); \
     if (__cpu < 8 * (setsize)) \
       (set)->__bits[__CPU_ELT(__cpu)] |= __CPU_MASK(__cpu); \
   } while (0)
+#endif
 
 /**
  * [CPU_CLR](https://man7.org/linux/man-pages/man3/CPU_CLR.3.html) clears one
  * bit in a static CPU set.
  */
+#if defined(__USE_GNU)
 #define CPU_CLR(cpu, set)      CPU_CLR_S(cpu, sizeof(cpu_set_t), set)
+#endif
+
 /**
  * [CPU_CLR_S](https://man7.org/linux/man-pages/man3/CPU_CLR_S.3.html) clears one
  * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_CLR_S(cpu, setsize, set) \
   do { \
     size_t __cpu = (cpu); \
     if (__cpu < 8 * (setsize)) \
       (set)->__bits[__CPU_ELT(__cpu)] &= ~__CPU_MASK(__cpu); \
   } while (0)
+#endif
 
 /**
  * [CPU_ISSET](https://man7.org/linux/man-pages/man3/CPU_ISSET.3.html) tests
  * whether the given bit is set in a static CPU set.
  */
+#if defined(__USE_GNU)
 #define CPU_ISSET(cpu, set)    CPU_ISSET_S(cpu, sizeof(cpu_set_t), set)
+#endif
+
 /**
  * [CPU_ISSET_S](https://man7.org/linux/man-pages/man3/CPU_ISSET_S.3.html) tests
  * whether the given bit is set in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_ISSET_S(cpu, setsize, set) \
   (__extension__ ({ \
     size_t __cpu = (cpu); \
@@ -311,66 +359,95 @@ int sched_getattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __si
       ? ((set)->__bits[__CPU_ELT(__cpu)] & __CPU_MASK(__cpu)) != 0 \
       : 0; \
   }))
+#endif
 
 /**
  * [CPU_COUNT](https://man7.org/linux/man-pages/man3/CPU_COUNT.3.html) counts
  * how many bits are set in a static CPU set.
  */
+#if defined(__USE_GNU)
 #define CPU_COUNT(set)         CPU_COUNT_S(sizeof(cpu_set_t), set)
+#endif
+
 /**
  * [CPU_COUNT_S](https://man7.org/linux/man-pages/man3/CPU_COUNT_S.3.html) counts
  * how many bits are set in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_COUNT_S(setsize, set)  __sched_cpucount((setsize), (set))
-int __sched_cpucount(size_t __set_size, const cpu_set_t* _Nonnull __set);
+int __sched_cpucount(size_t __cpu_set_size, const cpu_set_t* _Nonnull __cpu_set);
+#endif
 
 /**
  * [CPU_EQUAL](https://man7.org/linux/man-pages/man3/CPU_EQUAL.3.html) tests
  * whether two static CPU sets have the same bits set and cleared as each other.
  */
+#if defined(__USE_GNU)
 #define CPU_EQUAL(set1, set2)  CPU_EQUAL_S(sizeof(cpu_set_t), set1, set2)
+#endif
+
 /**
  * [CPU_EQUAL_S](https://man7.org/linux/man-pages/man3/CPU_EQUAL_S.3.html) tests
  * whether two dynamic CPU sets allocated by `CPU_ALLOC` have the same bits
  * set and cleared as each other.
  */
+#if defined(__USE_GNU)
 #define CPU_EQUAL_S(setsize, set1, set2)  (__builtin_memcmp(set1, set2, setsize) == 0)
+#endif
 
 /**
  * [CPU_AND](https://man7.org/linux/man-pages/man3/CPU_AND.3.html) ands two
  * static CPU sets.
  */
+#if defined(__USE_GNU)
 #define CPU_AND(dst, set1, set2)  __CPU_OP(dst, set1, set2, &)
+#endif
+
 /**
  * [CPU_AND_S](https://man7.org/linux/man-pages/man3/CPU_AND_S.3.html) ands two
  * dynamic CPU sets allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_AND_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, &)
+#endif
 
 /**
  * [CPU_OR](https://man7.org/linux/man-pages/man3/CPU_OR.3.html) ors two
  * static CPU sets.
  */
+#if defined(__USE_GNU)
 #define CPU_OR(dst, set1, set2)   __CPU_OP(dst, set1, set2, |)
+#endif
+
 /**
  * [CPU_OR_S](https://man7.org/linux/man-pages/man3/CPU_OR_S.3.html) ors two
  * dynamic CPU sets allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_OR_S(setsize, dst, set1, set2)   __CPU_OP_S(setsize, dst, set1, set2, |)
+#endif
 
 /**
  * [CPU_XOR](https://man7.org/linux/man-pages/man3/CPU_XOR.3.html)
  * exclusive-ors two static CPU sets.
  */
+#if defined(__USE_GNU)
 #define CPU_XOR(dst, set1, set2)  __CPU_OP(dst, set1, set2, ^)
+#endif
+
 /**
  * [CPU_XOR_S](https://man7.org/linux/man-pages/man3/CPU_XOR_S.3.html)
  * exclusive-ors two dynamic CPU sets allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_XOR_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, ^)
+#endif
 
+#if defined(__USE_GNU)
 #define __CPU_OP(dst, set1, set2, op)  __CPU_OP_S(sizeof(cpu_set_t), dst, set1, set2, op)
+#endif
 
+#if defined(__USE_GNU)
 #define __CPU_OP_S(setsize, dstset, srcset1, srcset2, op) \
   do { \
     cpu_set_t* __dst = (dstset); \
@@ -380,28 +457,33 @@ int __sched_cpucount(size_t __set_size, const cpu_set_t* _Nonnull __set);
     for (; __nn < __nn_max; __nn++) \
       (__dst)->__bits[__nn] = __src1[__nn] op __src2[__nn]; \
   } while (0)
+#endif
 
 /**
  * [CPU_ALLOC_SIZE](https://man7.org/linux/man-pages/man3/CPU_ALLOC_SIZE.3.html)
  * returns the size of a CPU set large enough for CPUs in the range 0..count-1.
  */
+#if defined(__USE_GNU)
 #define CPU_ALLOC_SIZE(count) \
   __CPU_ELT((count) + (__CPU_BITS - 1)) * sizeof(__CPU_BITTYPE)
+#endif
 
 /**
  * [CPU_ALLOC](https://man7.org/linux/man-pages/man3/CPU_ALLOC.3.html)
  * allocates a CPU set large enough for CPUs in the range 0..count-1.
  */
+#if defined(__USE_GNU)
 #define CPU_ALLOC(count)  __sched_cpualloc((count))
 cpu_set_t* _Nullable __sched_cpualloc(size_t __count);
+#endif
 
 /**
  * [CPU_FREE](https://man7.org/linux/man-pages/man3/CPU_FREE.3.html)
  * deallocates a CPU set allocated by `CPU_ALLOC`.
  */
+#if defined(__USE_GNU)
 #define CPU_FREE(set)     __sched_cpufree((set))
-void __sched_cpufree(cpu_set_t* _Nonnull __set);
-
-#endif /* __USE_GNU */
+void __sched_cpufree(cpu_set_t* _Nonnull __cpu_set);
+#endif
 
 __END_DECLS
diff --git a/libc/include/search.h b/libc/include/search.h
index 2f43d91f2..3772010b1 100644
--- a/libc/include/search.h
+++ b/libc/include/search.h
@@ -54,8 +54,8 @@ typedef enum {
   leaf
 } VISIT;
 
-#if defined(__USE_BSD) || defined(__USE_GNU)
 /** The hash table type for hcreate_r()/hdestroy_r()/hsearch_r(). */
+#if defined(__USE_BSD) || defined(__USE_GNU)
 struct hsearch_data {
   struct __hsearch* _Nullable __hsearch;
 };
@@ -85,9 +85,9 @@ void remque(void* _Nonnull __element);
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int hcreate(size_t __n) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [hdestroy(3)](https://man7.org/linux/man-pages/man3/hdestroy.3.html) destroys
@@ -97,7 +97,9 @@ int hcreate(size_t __n) __INTRODUCED_IN(28);
  *
  * Available since API level 28.
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void hdestroy(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
 /**
  * [hsearch(3)](https://man7.org/linux/man-pages/man3/hsearch.3.html) finds or
@@ -110,31 +112,31 @@ void hdestroy(void) __INTRODUCED_IN(28);
  *
  * Available since API level 28.
  */
+#if __BIONIC_AVAILABILITY_GUARD(28)
 ENTRY* _Nullable hsearch(ENTRY __entry, ACTION __action) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
-#if defined(__USE_BSD) || defined(__USE_GNU)
-
 /**
  * [hcreate_r(3)](https://man7.org/linux/man-pages/man3/hcreate_r.3.html)
  * initializes a hash table `__table` with space for at least `__n` elements.
  *
  * Returns *non-zero* on success and returns 0 and sets `errno` on failure.
  *
- * Available since API level 28.
+ * Available since API level 28 when compiling with `_BSD_SOURCE` or `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(28)
+#if (defined(__USE_BSD) || defined(__USE_GNU)) && __BIONIC_AVAILABILITY_GUARD(28)
 int hcreate_r(size_t __n, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
+#endif
 
 /**
  * [hdestroy_r(3)](https://man7.org/linux/man-pages/man3/hdestroy_r.3.html) destroys
  * the hash table `__table`.
  *
- * Available since API level 28.
+ * Available since API level 28 when compiling with `_BSD_SOURCE` or `_GNU_SOURCE`.
  */
+#if (defined(__USE_BSD) || defined(__USE_GNU)) && __BIONIC_AVAILABILITY_GUARD(28)
 void hdestroy_r(struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
+#endif
 
 /**
  * [hsearch_r(3)](https://man7.org/linux/man-pages/man3/hsearch_r.3.html) finds or
@@ -143,12 +145,10 @@ void hdestroy_r(struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
  * Returns *non-zero* on success and returns 0 and sets `errno` on failure.
  * A pointer to the entry is returned in `*__result`.
  *
- * Available since API level 28.
+ * Available since API level 28 when compiling with `_BSD_SOURCE` or `_GNU_SOURCE`.
  */
+#if (defined(__USE_BSD) || defined(__USE_GNU)) && __BIONIC_AVAILABILITY_GUARD(28)
 int hsearch_r(ENTRY __entry, ACTION __action, ENTRY* _Nullable * _Nonnull __result, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
-#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
-
-
 #endif
 
 /**
diff --git a/libc/include/semaphore.h b/libc/include/semaphore.h
index 9c4702db6..08ee49175 100644
--- a/libc/include/semaphore.h
+++ b/libc/include/semaphore.h
@@ -45,7 +45,6 @@ typedef struct {
 
 #define SEM_FAILED __BIONIC_CAST(reinterpret_cast, sem_t*, 0)
 
-
 #if __BIONIC_AVAILABILITY_GUARD(30)
 int sem_clockwait(sem_t* _Nonnull __sem, clockid_t __clock, const struct timespec* _Nonnull __ts) __INTRODUCED_IN(30);
 #endif /* __BIONIC_AVAILABILITY_GUARD(30) */
diff --git a/libc/include/signal.h b/libc/include/signal.h
index 38dcbde3f..372565c47 100644
--- a/libc/include/signal.h
+++ b/libc/include/signal.h
@@ -65,7 +65,6 @@ int sigaction(int __signal, const struct sigaction* _Nullable __new_action, stru
 int sigaction64(int __signal, const struct sigaction64* _Nullable __new_action, struct sigaction64* _Nullable __old_action) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 int siginterrupt(int __signal, int __flag);
 
 sighandler_t _Nonnull signal(int __signal, sighandler_t _Nullable __handler);
@@ -124,24 +123,33 @@ int sigwait(const sigset_t* _Nonnull __set, int* _Nonnull __signal);
 int sigwait64(const sigset64_t* _Nonnull __set, int* _Nonnull __signal) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int sighold(int __signal)
   __attribute__((__deprecated__("use sigprocmask() or pthread_sigmask() instead")))
   __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int sigignore(int __signal)
   __attribute__((__deprecated__("use sigaction() instead"))) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int sigpause(int __signal)
   __attribute__((__deprecated__("use sigsuspend() instead"))) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int sigrelse(int __signal)
   __attribute__((__deprecated__("use sigprocmask() or pthread_sigmask() instead")))
   __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 sighandler_t _Nonnull sigset(int __signal, sighandler_t _Nullable __handler)
   __attribute__((__deprecated__("use sigaction() instead"))) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 int raise(int __signal);
 int kill(pid_t __pid, int __signal);
 int killpg(int __pgrp, int __signal);
@@ -153,12 +161,9 @@ void psiginfo(const siginfo_t* _Nonnull __info, const char* _Nullable __msg);
 void psignal(int __signal, const char* _Nullable __msg);
 
 int pthread_kill(pthread_t __pthread, int __signal);
-#if defined(__USE_GNU)
 
-#if __BIONIC_AVAILABILITY_GUARD(29)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(29)
 int pthread_sigqueue(pthread_t __pthread, int __signal, const union sigval __value) __INTRODUCED_IN(29);
-#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
-
 #endif
 
 int pthread_sigmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set);
@@ -167,29 +172,26 @@ int pthread_sigmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _N
 int pthread_sigmask64(int __how, const sigset64_t* _Nullable __new_set, sigset64_t* _Nullable __old_set) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int sigqueue(pid_t __pid, int __signal, const union sigval __value) __INTRODUCED_IN(23);
-int sigtimedwait(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
+int sigtimedwait(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int sigtimedwait64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int sigwaitinfo(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int sigwaitinfo64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 /**
  * Buffer size suitable for any call to sig2str().
  */
@@ -208,6 +210,7 @@ int sigwaitinfo64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info)
 
 #if __BIONIC_AVAILABILITY_GUARD(36)
 int sig2str(int __signal, char* _Nonnull __buf) __INTRODUCED_IN(36);
+#endif /* __BIONIC_AVAILABILITY_GUARD(36) */
 
 /**
  * [str2sig(3)](https://man7.org/linux/man-pages/man3/str2sig.3.html)
@@ -218,10 +221,10 @@ int sig2str(int __signal, char* _Nonnull __buf) __INTRODUCED_IN(36);
  *
  * Available since API level 36.
  */
+#if __BIONIC_AVAILABILITY_GUARD(36)
 int str2sig(const char* _Nonnull __name, int* _Nonnull __signal) __INTRODUCED_IN(36);
 #endif /* __BIONIC_AVAILABILITY_GUARD(36) */
 
-
 __END_DECLS
 
 #endif
diff --git a/libc/include/spawn.h b/libc/include/spawn.h
index b1057541e..3a4cd11b7 100644
--- a/libc/include/spawn.h
+++ b/libc/include/spawn.h
@@ -26,8 +26,7 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _SPAWN_H_
-#define _SPAWN_H_
+#pragma once
 
 #include <sys/cdefs.h>
 #include <sys/types.h>
@@ -44,6 +43,8 @@ __BEGIN_DECLS
 #define POSIX_SPAWN_SETSCHEDULER 32
 #if defined(__USE_GNU)
 #define POSIX_SPAWN_USEVFORK 64
+#endif
+#if defined(__USE_GNU)
 #define POSIX_SPAWN_SETSID 128
 #endif
 /**
@@ -55,52 +56,134 @@ __BEGIN_DECLS
 typedef struct __posix_spawnattr* posix_spawnattr_t;
 typedef struct __posix_spawn_file_actions* posix_spawn_file_actions_t;
 
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn(pid_t* _Nullable __pid, const char* _Nonnull __path, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnp(pid_t* _Nullable __pid, const char* _Nonnull __file, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_init(posix_spawnattr_t _Nullable * _Nonnull __attr) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_destroy(posix_spawnattr_t _Nonnull * _Nonnull __attr) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setflags(posix_spawnattr_t _Nonnull * _Nonnull __attr, short __flags) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getflags(const posix_spawnattr_t _Nonnull * _Nonnull __attr, short* _Nonnull __flags) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setpgroup(posix_spawnattr_t _Nonnull * _Nonnull __attr, pid_t __pgroup) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getpgroup(const posix_spawnattr_t _Nonnull * _Nonnull __attr, pid_t* _Nonnull __pgroup) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setsigmask(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setsigmask64(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getsigmask(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getsigmask64(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setsigdefault(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setsigdefault64(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getsigdefault(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getsigdefault64(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setschedparam(posix_spawnattr_t _Nonnull * _Nonnull __attr, const struct sched_param* _Nonnull __param) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getschedparam(const posix_spawnattr_t _Nonnull * _Nonnull __attr, struct sched_param* _Nonnull __param) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_setschedpolicy(posix_spawnattr_t _Nonnull * _Nonnull __attr, int __policy) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawnattr_getschedpolicy(const posix_spawnattr_t _Nonnull * _Nonnull __attr, int* _Nonnull __policy) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn_file_actions_init(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions) __INTRODUCED_IN(28);
+#endif
 
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, const char* _Nonnull __path, int __flags, mode_t __mode) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(28);
+#endif
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, int __new_fd) __INTRODUCED_IN(28);
-#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+#endif
 
+/** Synonym for posix_spawn_file_actions_addchdir(). */
+#if __BIONIC_AVAILABILITY_GUARD(34)
+int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, const char* _Nonnull __path) __INTRODUCED_IN(34);
+#endif
 
+/**
+ * posix_spawn_file_actions_addchdir() adds a chdir() as an action
+ * to be performed between the fork() and exec().
+ *
+ * Returns 0 on success and returns an error number on failure.
+ */
+#if __BIONIC_AVAILABILITY_GUARD(34)
+int posix_spawn_file_actions_addchdir(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, const char* _Nonnull __path) __INTRODUCED_IN(34) __RENAME(posix_spawn_file_actions_addchdir_np);
+#endif
 
+/** Synonym for posix_spawn_file_actions_addfchdir(). */
 #if __BIONIC_AVAILABILITY_GUARD(34)
-int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, const char* _Nonnull __path) __INTRODUCED_IN(34);
 int posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(34);
-#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+#endif
 
+/**
+ * posix_spawn_file_actions_addfchdir() adds an fchdir() as an action
+ * to be performed between the fork() and exec().
+ *
+ * Returns 0 on success and returns an error number on failure.
+ */
+#if __BIONIC_AVAILABILITY_GUARD(34)
+int posix_spawn_file_actions_addfchdir(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(34) __RENAME(posix_spawn_file_actions_addfchdir_np);
+#endif
 
 __END_DECLS
-
-#endif
diff --git a/libc/include/stdint.h b/libc/include/stdint.h
index 772fe8b60..a6f92e95d 100644
--- a/libc/include/stdint.h
+++ b/libc/include/stdint.h
@@ -167,23 +167,23 @@ typedef int64_t       intmax_t;
 #define INT16_MAX        (32767)
 #define INT_LEAST16_MIN  INT16_MIN
 #define INT_LEAST16_MAX  INT16_MAX
-#define INT_FAST16_MIN   INT32_MIN
-#define INT_FAST16_MAX   INT32_MAX
+#define INT_FAST16_MIN   (-__LONG_MAX__ - 1L)
+#define INT_FAST16_MAX   __LONG_MAX__
 
 #define UINT16_MAX       (65535)
 #define UINT_LEAST16_MAX UINT16_MAX
-#define UINT_FAST16_MAX  UINT32_MAX
+#define UINT_FAST16_MAX  (__LONG_MAX__ * 2UL + 1UL)
 
 #define INT32_MIN        (-2147483647-1)
 #define INT32_MAX        (2147483647)
 #define INT_LEAST32_MIN  INT32_MIN
 #define INT_LEAST32_MAX  INT32_MAX
-#define INT_FAST32_MIN   INT32_MIN
-#define INT_FAST32_MAX   INT32_MAX
+#define INT_FAST32_MIN   (-__LONG_MAX__ - 1L)
+#define INT_FAST32_MAX   __LONG_MAX__
 
 #define UINT32_MAX       (4294967295U)
 #define UINT_LEAST32_MAX UINT32_MAX
-#define UINT_FAST32_MAX  UINT32_MAX
+#define UINT_FAST32_MAX  (__LONG_MAX__ * 2UL + 1UL)
 
 #define INT64_MIN        (INT64_C(-9223372036854775807)-1)
 #define INT64_MAX        (INT64_C(9223372036854775807))
@@ -196,35 +196,65 @@ typedef int64_t       intmax_t;
 #define UINT_LEAST64_MAX UINT64_MAX
 #define UINT_FAST64_MAX  UINT64_MAX
 
-#define INTMAX_MIN       INT64_MIN
-#define INTMAX_MAX       INT64_MAX
-#define UINTMAX_MAX      UINT64_MAX
+#define INTMAX_MAX __INTMAX_MAX__
+#define INTMAX_MIN (-__INTMAX_MAX__-1)
+#define UINTMAX_MAX __UINTMAX_MAX__
 
 #define SIG_ATOMIC_MAX   INT32_MAX
 #define SIG_ATOMIC_MIN   INT32_MIN
 
-#if defined(__WINT_UNSIGNED__)
-#  define WINT_MAX       UINT32_MAX
-#  define WINT_MIN       0
-#else
-#  define WINT_MAX       INT32_MAX
-#  define WINT_MIN       INT32_MIN
-#endif
+#define WINT_MAX       UINT32_MAX
+#define WINT_MIN       0
 
-#if defined(__LP64__)
-#  define INTPTR_MIN     INT64_MIN
-#  define INTPTR_MAX     INT64_MAX
-#  define UINTPTR_MAX    UINT64_MAX
-#  define PTRDIFF_MIN    INT64_MIN
-#  define PTRDIFF_MAX    INT64_MAX
-#  define SIZE_MAX       UINT64_MAX
-#else
-#  define INTPTR_MIN     INT32_MIN
-#  define INTPTR_MAX     INT32_MAX
-#  define UINTPTR_MAX    UINT32_MAX
-#  define PTRDIFF_MIN    INT32_MIN
-#  define PTRDIFF_MAX    INT32_MAX
-#  define SIZE_MAX       UINT32_MAX
-#endif
+#define INTPTR_MAX __INTPTR_MAX__
+#define INTPTR_MIN (-__INTPTR_MAX__-1)
+#define UINTPTR_MAX __UINTPTR_MAX__
+
+#define PTRDIFF_MAX __PTRDIFF_MAX__
+#define PTRDIFF_MIN (-__PTRDIFF_MAX__-1)
+
+#define SIZE_MAX __SIZE_MAX__
+
+#define INT8_WIDTH 8
+#define UINT8_WIDTH 8
+#define INT16_WIDTH 16
+#define UINT16_WIDTH 16
+#define INT32_WIDTH 32
+#define UINT32_WIDTH 32
+#define INT64_WIDTH 64
+#define UINT64_WIDTH 64
+
+#define INT_FAST8_WIDTH 8
+#define UINT_FAST8_WIDTH 8
+#define INT_FAST16_WIDTH __WORDSIZE
+#define UINT_FAST16_WIDTH __WORDSIZE
+#define INT_FAST32_WIDTH __WORDSIZE
+#define UINT_FAST32_WIDTH __WORDSIZE
+#define INT_FAST64_WIDTH 64
+#define UINT_FAST64_WIDTH 64
+
+#define INT_LEAST8_WIDTH 8
+#define UINT_LEAST8_WIDTH 8
+#define INT_LEAST16_WIDTH 16
+#define UINT_LEAST16_WIDTH 16
+#define INT_LEAST32_WIDTH 32
+#define UINT_LEAST32_WIDTH 32
+#define INT_LEAST64_WIDTH 64
+#define UINT_LEAST64_WIDTH 64
+
+#define WCHAR_WIDTH __WCHAR_WIDTH__
+#define WINT_WIDTH __WINT_WIDTH__
+
+#define INTPTR_WIDTH __INTPTR_WIDTH__
+#define UINTPTR_WIDTH __UINTPTR_WIDTH__
+
+#define INTMAX_WIDTH __INTMAX_WIDTH__
+#define UINTMAX_WIDTH __UINTMAX_WIDTH__
+
+#define PTRDIFF_WIDTH __PTRDIFF_WIDTH__
+
+#define SIZE_WIDTH __SIZE_WIDTH__
+
+#define SIG_ATOMIC_WIDTH __SIG_ATOMIC_WIDTH__
 
 #endif /* _STDINT_H */
diff --git a/libc/include/stdio.h b/libc/include/stdio.h
index 2c2dc0173..0ffcb736e 100644
--- a/libc/include/stdio.h
+++ b/libc/include/stdio.h
@@ -140,18 +140,25 @@ int dprintf(int __fd, const char* _Nonnull __fmt, ...) __printflike(2, 3);
 int vdprintf(int __fd, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);
 
 #if (defined(__STDC_VERSION__) && __STDC_VERSION__ < 201112L) || \
-    (defined(__cplusplus) && __cplusplus <= 201103L)
-char* _Nullable gets(char* _Nonnull __buf) __attribute__((__deprecated__("gets is unsafe, use fgets instead")));
+    (defined(__cplusplus) && __cplusplus < 201402L)
+/**
+ * gets() is an unsafe version of getline() for stdin.
+ *
+ * It was removed in C11 and C++14,
+ * and should not be used by new code.
+ */
+char* _Nullable gets(char* _Nonnull __buf) __attribute__((__deprecated__("gets() is unsafe, use getline() instead")));
 #endif
+
 int sprintf(char* __BIONIC_COMPLICATED_NULLNESS __s, const char* _Nonnull __fmt, ...)
     __printflike(2, 3) __warnattr_strict("sprintf is often misused; please use snprintf");
 int vsprintf(char* __BIONIC_COMPLICATED_NULLNESS __s, const char* _Nonnull __fmt, va_list __args)
     __printflike(2, 0) __warnattr_strict("vsprintf is often misused; please use vsnprintf");
 char* _Nullable tmpnam(char* _Nullable __s)
-    __warnattr("tmpnam is unsafe, use mkstemp or tmpfile instead");
+    __attribute__((__deprecated__("tmpnam is unsafe, use mkstemp or tmpfile instead")));
 #define P_tmpdir "/tmp/" /* deprecated */
 char* _Nullable tempnam(const char* _Nullable __dir, const char* _Nullable __prefix)
-    __warnattr("tempnam is unsafe, use mkstemp or tmpfile instead");
+    __attribute__((__deprecated__("tempnam is unsafe, use mkstemp or tmpfile instead")));
 
 /**
  * [rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html) changes
@@ -169,25 +176,29 @@ int rename(const char* _Nonnull __old_path, const char* _Nonnull __new_path);
  */
 int renameat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path);
 
-#if defined(__USE_GNU)
-
 /**
  * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
  * to fail if the new path already exists.
  */
+#if defined(__USE_GNU)
 #define RENAME_NOREPLACE (1<<0)
+#endif
 
 /**
  * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
  * to atomically exchange the two paths.
  */
+#if defined(__USE_GNU)
 #define RENAME_EXCHANGE (1<<1)
+#endif
 
 /**
  * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
  * to create a union/overlay filesystem object.
  */
+#if defined(__USE_GNU)
 #define RENAME_WHITEOUT (1<<2)
+#endif
 
 /**
  * [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html) changes
@@ -195,13 +206,11 @@ int renameat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd
  * with optional `RENAME_` flags.
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ *
+ * Available since API level 30 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(30)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(30)
 int renameat2(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path, unsigned __flags) __INTRODUCED_IN(30);
-#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
-
-
 #endif
 
 int fseek(FILE* _Nonnull __fp, long __offset, int __whence);
@@ -212,56 +221,67 @@ __nodiscard long ftell(FILE* _Nonnull __fp);
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos) __RENAME(fgetpos64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fsetpos(FILE* _Nonnull __fp, const fpos_t* _Nonnull __pos) __RENAME(fsetpos64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fseeko(FILE* _Nonnull __fp, off_t __offset, int __whence) __RENAME(fseeko64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard off_t ftello(FILE* _Nonnull __fp) __RENAME(ftello64) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-#  if defined(__USE_BSD)
 /* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
-
-#if __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
               int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
               int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
               fpos_t (* _Nullable __seek_fn)(void* _Nonnull, fpos_t, int),
               int (* _Nullable __close_fn)(void* _Nonnull)) __RENAME(funopen64) __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+#endif
 
-#  endif
 #else
 int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos);
 int fsetpos(FILE* _Nonnull __fp, const fpos_t* _Nonnull __pos);
 int fseeko(FILE* _Nonnull __fp, off_t __offset, int __whence);
 __nodiscard off_t ftello(FILE* _Nonnull __fp);
-#  if defined(__USE_BSD)
+#if defined(__USE_BSD)
 /* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
 __nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
               int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
               int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
               fpos_t (* _Nullable __seek_fn)(void* _Nonnull, fpos_t, int),
               int (* _Nullable __close_fn)(void* _Nonnull));
-#  endif
+#endif
 #endif
 
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int fgetpos64(FILE* _Nonnull __fp, fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fsetpos64(FILE* _Nonnull __fp, const fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fseeko64(FILE* _Nonnull __fp, off64_t __offset, int __whence) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard off64_t ftello64(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-#if defined(__USE_BSD)
 /* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
-
-#if __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable funopen64(const void* _Nullable __cookie,
                 int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
                 int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
                 fpos64_t (* _Nullable __seek_fn)(void* _Nonnull, fpos64_t, int),
                 int (* _Nullable __close_fn)(void* _Nonnull)) __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
-
 #endif
 
 __nodiscard FILE* _Nullable fopen(const char* _Nonnull __path, const char* _Nonnull __mode);
@@ -308,14 +328,13 @@ __nodiscard int getchar_unlocked(void);
 int putc_unlocked(int __ch, FILE* _Nonnull __fp);
 int putchar_unlocked(int __ch);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 __nodiscard FILE* _Nullable fmemopen(void* _Nullable __buf, size_t __size, const char* _Nonnull __mode) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 __nodiscard FILE* _Nullable open_memstream(char* _Nonnull * _Nonnull __ptr, size_t* _Nonnull __size_ptr) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
-#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
 int  asprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, ...) __printflike(2, 3);
 char* _Nullable fgetln(FILE* _Nonnull __fp, size_t* _Nonnull __length_ptr);
 int fpurge(FILE* _Nonnull __fp);
@@ -325,38 +344,47 @@ int vasprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, va
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 void clearerr_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 __nodiscard int feof_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 __nodiscard int ferror_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard int fileno_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 #define fropen(cookie, fn) funopen(cookie, fn, 0, 0, 0)
 #define fwopen(cookie, fn) funopen(cookie, 0, fn, 0, 0)
-#endif
-
-#if defined(__USE_BSD)
 
-#if __BIONIC_AVAILABILITY_GUARD(28)
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(28)
 int fflush_unlocked(FILE* _Nullable __fp) __INTRODUCED_IN(28);
+#endif
+
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard int fgetc_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif
+
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(28)
 int fputc_unlocked(int __ch, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
-size_t fread_unlocked(void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
-size_t fwrite_unlocked(const void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
-#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+#endif
 
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(28)
+size_t fread_unlocked(void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 #endif
 
-#if defined(__USE_GNU)
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(28)
+size_t fwrite_unlocked(const void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif
 
-#if __BIONIC_AVAILABILITY_GUARD(28)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(28)
 int fputs_unlocked(const char* _Nonnull __s, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
-char* _Nullable fgets_unlocked(char* _Nonnull __buf, int __size, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
-#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+#endif
 
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(28)
+char* _Nullable fgets_unlocked(char* _Nonnull __buf, int __size, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 #endif
 
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
diff --git a/libc/include/stdio_ext.h b/libc/include/stdio_ext.h
index 9ff07da61..cc8d5b1ce 100644
--- a/libc/include/stdio_ext.h
+++ b/libc/include/stdio_ext.h
@@ -44,9 +44,9 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 size_t __fbufsize(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [__freadable(3)](https://man7.org/linux/man-pages/man3/__freadable.3.html) returns non-zero if
@@ -54,58 +54,50 @@ size_t __fbufsize(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
  *
  * Available since API level 23.
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int __freadable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * [__freading(3)](https://man7.org/linux/man-pages/man3/__freading.3.html) returns non-zero if
  * the stream's last operation was a read, 0 otherwise.
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int __freading(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 /**
  * [__fwritable(3)](https://man7.org/linux/man-pages/man3/__fwritable.3.html) returns non-zero if
  * the stream allows writing, 0 otherwise.
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int __fwritable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * [__fwriting(3)](https://man7.org/linux/man-pages/man3/__fwriting.3.html) returns non-zero if
  * the stream's last operation was a write, 0 otherwise.
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int __fwriting(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 /**
  * [__flbf(3)](https://man7.org/linux/man-pages/man3/__flbf.3.html) returns non-zero if
  * the stream is line-buffered, 0 otherwise.
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int __flbf(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * [__fpurge(3)](https://man7.org/linux/man-pages/man3/__fpurge.3.html) discards the contents of
  * the stream's buffer.
@@ -118,48 +110,40 @@ void __fpurge(FILE* _Nonnull __fp) __RENAME(fpurge);
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 size_t __fpending(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * __freadahead(3) returns the number of bytes in the input buffer.
  * See __fpending() for the output buffer.
  *
  * Available since API level 34.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(34)
 size_t __freadahead(FILE* _Nonnull __fp) __INTRODUCED_IN(34);
 #endif /* __BIONIC_AVAILABILITY_GUARD(34) */
 
-
 /**
  * [_flushlbf(3)](https://man7.org/linux/man-pages/man3/_flushlbf.3.html) flushes all
  * line-buffered streams.
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 void _flushlbf(void) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * `__fseterr` sets the
  * stream's error flag (as tested by ferror() and cleared by fclearerr()).
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 void __fseterr(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 /** __fsetlocking() constant to query locking type. */
 #define FSETLOCKING_QUERY 0
 /** __fsetlocking() constant to set locking to be maintained by stdio. */
@@ -175,10 +159,8 @@ void __fseterr(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int __fsetlocking(FILE* _Nonnull __fp, int __type) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/stdlib.h b/libc/include/stdlib.h
index 7081d7ccb..994695227 100644
--- a/libc/include/stdlib.h
+++ b/libc/include/stdlib.h
@@ -63,8 +63,14 @@ char* _Nullable mktemp(char* _Nonnull __template) __attribute__((__deprecated__(
 
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int mkostemp64(char* _Nonnull __template, int __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkostemp(char* _Nonnull __template, int __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkostemps64(char* _Nonnull __template, int __suffix_length, int __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkostemps(char* _Nonnull __template, int __suffix_length, int __flags) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
@@ -125,6 +131,9 @@ __nodiscard void* _Nullable bsearch(const void* _Nonnull __key, const void* _Nul
 /**
  * [qsort(3)](https://man7.org/linux/man-pages/man3/qsort.3.html) sorts an array
  * of n elements each of the given size, using the given comparator.
+ *
+ * qsort() is not stable, so elements with the same key might be reordered.
+ * libc++ offers both std::sort() and std::stable_sort().
  */
 void qsort(void* _Nullable __array, size_t __n, size_t __size, int (* _Nonnull __comparator)(const void* _Nullable __lhs, const void* _Nullable __rhs));
 
@@ -133,14 +142,16 @@ void qsort(void* _Nullable __array, size_t __n, size_t __size, int (* _Nonnull _
  * array of n elements each of the given size, using the given comparator,
  * and passing the given context argument to the comparator.
  *
+ * qsort_r() is not stable, so elements with the same key might be reordered.
+ * libc++ offers both std::sort() and std::stable_sort().
+ *
  * Available since API level 36.
+ * std::sort() is available at all API levels.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(36)
 void qsort_r(void* _Nullable __array, size_t __n, size_t __size, int (* _Nonnull __comparator)(const void* _Nullable __lhs, const void* _Nullable __rhs, void* _Nullable __context), void* _Nullable __context) __INTRODUCED_IN(36);
 #endif /* __BIONIC_AVAILABILITY_GUARD(36) */
 
-
 uint32_t arc4random(void);
 uint32_t arc4random_uniform(uint32_t __upper_bound);
 void arc4random_buf(void* _Nonnull __buf, size_t __n);
@@ -172,17 +183,22 @@ char* _Nullable ptsname(int __fd);
 int ptsname_r(int __fd, char* _Nonnull __buf, size_t __n);
 int unlockpt(int __fd);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int getsubopt(char* _Nonnull * _Nonnull __option, char* _Nonnull const* _Nonnull __tokens, char* _Nullable * _Nonnull __value_ptr) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 typedef struct {
   int quot;
   int rem;
 } div_t;
 
+/**
+ * Returns `__numerator / __denominator` and `__numerator % __denominator`,
+ * truncating towards zero.
+ *
+ * This function was useful for portability before C99,
+ * where `/` and `%` were also defined to truncate towards zero.
+ */
 div_t div(int __numerator, int __denominator) __attribute_const__;
 
 typedef struct {
@@ -190,6 +206,13 @@ typedef struct {
   long int rem;
 } ldiv_t;
 
+/**
+ * Returns `__numerator / __denominator` and `__numerator % __denominator`,
+ * truncating towards zero.
+ *
+ * This function was useful for portability before C99,
+ * where `/` and `%` were also defined to truncate towards zero.
+ */
 ldiv_t ldiv(long __numerator, long __denominator) __attribute_const__;
 
 typedef struct {
@@ -197,6 +220,13 @@ typedef struct {
   long long int rem;
 } lldiv_t;
 
+/**
+ * Returns `__numerator / __denominator` and `__numerator % __denominator`,
+ * truncating towards zero.
+ *
+ * This function was useful for portability before C99,
+ * where `/` and `%` were also defined to truncate towards zero.
+ */
 lldiv_t lldiv(long long __numerator, long long __denominator) __attribute_const__;
 
 /**
@@ -206,7 +236,6 @@ lldiv_t lldiv(long long __numerator, long long __denominator) __attribute_const_
  *
  * Returns the number of samples written to `__averages` (at most 3), and returns -1 on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(29)
 int getloadavg(double __averages[_Nonnull], int __n) __INTRODUCED_IN(29);
 #endif /* __BIONIC_AVAILABILITY_GUARD(29) */
@@ -216,7 +245,6 @@ int getloadavg(double __averages[_Nonnull], int __n) __INTRODUCED_IN(29);
 const char* _Nullable getprogname(void);
 void setprogname(const char* _Nonnull __name);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int mblen(const char* _Nullable __s, size_t __n) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
@@ -234,8 +262,22 @@ size_t __ctype_get_mb_cur_max(void);
 #include <bits/fortify/stdlib.h>
 #endif
 
+/**
+ * Returns the absolute value where possible.
+ * For the most negative value, the result is unchanged (and thus also negative).
+ */
 int abs(int __x) __attribute_const__;
+
+/**
+ * Returns the absolute value where possible.
+ * For the most negative value, the result is unchanged (and thus also negative).
+ */
 long labs(long __x) __attribute_const__;
+
+/**
+ * Returns the absolute value where possible.
+ * For the most negative value, the result is unchanged (and thus also negative).
+ */
 long long llabs(long long __x) __attribute_const__;
 
 int rand(void);
diff --git a/libc/include/string.h b/libc/include/string.h
index a0a7cc438..04240e77c 100644
--- a/libc/include/string.h
+++ b/libc/include/string.h
@@ -51,13 +51,11 @@ void* _Nullable memrchr(const void* _Nonnull __s, int __ch, size_t __n) __attrib
 #endif
 int memcmp(const void* _Nonnull __lhs, const void* _Nonnull __rhs, size_t __n) __attribute_pure__;
 void* _Nonnull memcpy(void* _Nonnull, const void* _Nonnull, size_t);
-#if defined(__USE_GNU)
 
-#if __BIONIC_AVAILABILITY_GUARD(23)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(23)
 void* _Nonnull mempcpy(void* _Nonnull __dst, const void* _Nonnull __src, size_t __n) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
-
 #endif
+
 void* _Nonnull memmove(void* _Nonnull __dst, const void* _Nonnull __src, size_t __n);
 
 /**
@@ -74,31 +72,28 @@ void* _Nonnull memset(void* _Nonnull __dst, int __ch, size_t __n);
  * but won't be optimized out by the compiler.
  *
  * Returns `dst`.
+ *
+ * Available from API level 34, or with __ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(34)
+#if __ANDROID_API__ >= 34
 void* _Nonnull memset_explicit(void* _Nonnull __dst, int __ch, size_t __n) __INTRODUCED_IN(34);
-#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
-
+#elif defined(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)
+#define __BIONIC_MEMSET_EXPLICIT_INLINE static __inline
+#include <bits/memset_explicit_impl.h>
+#undef __BIONIC_MEMSET_EXPLICIT_INLINE
+#endif
 
 void* _Nullable memmem(const void* _Nonnull __haystack, size_t __haystack_size, const void* _Nonnull __needle, size_t __needle_size) __attribute_pure__;
 
 char* _Nullable strchr(const char* _Nonnull __s, int __ch) __attribute_pure__;
 char* _Nullable __strchr_chk(const char* _Nonnull __s, int __ch, size_t __n);
-#if defined(__USE_GNU)
-#if defined(__cplusplus)
 
-#if __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__cplusplus)
 extern "C++" char* _Nonnull strchrnul(char* _Nonnull __s, int __ch) __RENAME(strchrnul) __attribute_pure__ __INTRODUCED_IN(24);
 extern "C++" const char* _Nonnull strchrnul(const char* _Nonnull __s, int __ch) __RENAME(strchrnul) __attribute_pure__ __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
-
 #else
-
-#if __BIONIC_AVAILABILITY_GUARD(24)
 char* _Nonnull strchrnul(const char* _Nonnull __s, int __ch) __attribute_pure__ __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
-
 #endif
 #endif
 
@@ -115,12 +110,7 @@ char* _Nonnull strcat(char* _Nonnull __dst, const char* _Nonnull __src);
 char* _Nullable strdup(const char* _Nonnull __s);
 
 char* _Nullable strstr(const char* _Nonnull __haystack, const char* _Nonnull __needle) __attribute_pure__;
-#if defined(__cplusplus)
-extern "C++" char* _Nullable strcasestr(char* _Nonnull, const char* _Nonnull) __RENAME(strcasestr) __attribute_pure__;
-extern "C++" const char* _Nullable strcasestr(const char* _Nonnull, const char* _Nonnull) __RENAME(strcasestr) __attribute_pure__;
-#else
 char* _Nullable strcasestr(const char* _Nonnull __haystack, const char* _Nonnull __needle) __attribute_pure__;
-#endif
 char* _Nullable strtok(char* _Nullable __s, const char* _Nonnull __delimiter);
 char* _Nullable strtok_r(char* _Nullable __s, const char* _Nonnull __delimiter, char* _Nonnull * _Nonnull __pos_ptr);
 
@@ -169,14 +159,10 @@ int strerror_r(int __errno_value, char* _Nonnull __buf, size_t __n);
  *
  * Returns a pointer to a string, or null for unknown errno values.
  *
- * Available since API level 35.
+ * Available since API level 35 when compiling with `_GNU_SOURCE`.
  */
-#if defined(__USE_GNU)
-
-#if __BIONIC_AVAILABILITY_GUARD(35)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(35)
 const char* _Nullable strerrorname_np(int __errno_value) __INTRODUCED_IN(35);
-#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
-
 #endif
 
 /**
@@ -185,6 +171,8 @@ const char* _Nullable strerrorname_np(int __errno_value) __INTRODUCED_IN(35);
  * does not localize, this is the same as strerror() on Android.
  *
  * Returns a pointer to a string.
+ *
+ * Available when compiling with `_GNU_SOURCE`.
  */
 #if defined(__USE_GNU)
 const char* _Nonnull strerrordesc_np(int __errno_value) __RENAME(strerror);
@@ -213,24 +201,16 @@ size_t strxfrm(char* __BIONIC_COMPLICATED_NULLNESS __dst, const char* _Nonnull _
 int strcoll_l(const char* _Nonnull __lhs, const char* _Nonnull __rhs, locale_t _Nonnull __l) __attribute_pure__;
 size_t strxfrm_l(char* __BIONIC_COMPLICATED_NULLNESS __dst, const char* _Nonnull __src, size_t __n, locale_t _Nonnull __l);
 
-#if defined(__USE_GNU) && !defined(basename)
 /*
  * glibc has a basename in <string.h> that's different to the POSIX one in <libgen.h>.
  * It doesn't modify its argument, and in C++ it's const-correct.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(23) && !defined(basename)
 #if defined(__cplusplus)
-
-#if __BIONIC_AVAILABILITY_GUARD(23)
 extern "C++" char* _Nonnull basename(char* _Nullable __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
 extern "C++" const char* _Nonnull basename(const char* _Nonnull __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
-
 #else
-
-#if __BIONIC_AVAILABILITY_GUARD(23)
 char* _Nonnull basename(const char* _Nonnull __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
-
 #endif
 #endif
 
@@ -294,8 +274,26 @@ char* _Nullable strrchr(char* _Nonnull const s __pass_object_size, int c) __pref
 }
 
 /* Functions with no FORTIFY counterpart. */
+
 inline __always_inline
-char* _Nullable __bionic_strstr(const char* _Nonnull h, const char* _Nonnull n) { return strstr(h, n); }
+char* _Nullable __bionic_strcasestr(const char* _Nonnull h, const char* _Nonnull n) {
+    return strcasestr(h, n);
+}
+
+inline __always_inline
+const char* _Nullable strcasestr(const char* _Nonnull h, const char* _Nonnull n) __prefer_this_overload {
+    return __bionic_strcasestr(h, n);
+}
+
+inline __always_inline
+char* _Nullable strcasestr(char* _Nonnull h, const char* _Nonnull n) __prefer_this_overload {
+    return __bionic_strcasestr(h, n);
+}
+
+inline __always_inline
+char* _Nullable __bionic_strstr(const char* _Nonnull h, const char* _Nonnull n) {
+    return strstr(h, n);
+}
 
 inline __always_inline
 const char* _Nullable strstr(const char* _Nonnull h, const char* _Nonnull n) __prefer_this_overload {
diff --git a/libc/include/sys/cdefs.h b/libc/include/sys/cdefs.h
index a74a5142e..fb23f200c 100644
--- a/libc/include/sys/cdefs.h
+++ b/libc/include/sys/cdefs.h
@@ -60,8 +60,6 @@
 #define __BIONIC_CAST(_k,_t,_v) ((_t) (_v))
 #endif
 
-#define __BIONIC_ALIGN(__value, __alignment) (((__value) + (__alignment)-1) & ~((__alignment)-1))
-
 /*
  * The nullness constraints of this parameter or return value are
  * quite complex. This is used to highlight spots where developers
@@ -143,19 +141,15 @@
 #define __nodiscard __attribute__((__warn_unused_result__))
 #define __wur __nodiscard
 
-#define __errorattr(msg) __attribute__((__unavailable__(msg)))
-#define __warnattr(msg) __attribute__((__deprecated__(msg)))
-#define __warnattr_real(msg) __attribute__((__deprecated__(msg)))
 #define __enable_if(cond, msg) __attribute__((__enable_if__(cond, msg)))
 #define __clang_error_if(cond, msg) __attribute__((__diagnose_if__(cond, msg, "error")))
 #define __clang_warning_if(cond, msg) __attribute__((__diagnose_if__(cond, msg, "warning")))
 
 #if defined(ANDROID_STRICT)
 /*
- * For things that are sketchy, but not necessarily an error. FIXME: Enable
- * this.
+ * For things that are sketchy, but not necessarily an error.
  */
-#  define __warnattr_strict(msg) /* __warnattr(msg) */
+#  define __warnattr_strict(msg) __attribute__((__deprecated__(msg)))
 #else
 #  define __warnattr_strict(msg)
 #endif
@@ -247,12 +241,21 @@
 #  define __bos_level 0
 #endif
 
-#define __bosn(s, n) __builtin_object_size((s), (n))
+#if _FORTIFY_SOURCE >= 3
+#  define __bosn(s, n) __builtin_dynamic_object_size((s), (n))
+#else
+#  define __bosn(s, n) __builtin_object_size((s), (n))
+#endif
 #define __bos(s) __bosn((s), __bos_level)
 
 #if defined(__BIONIC_FORTIFY)
 #  define __bos0(s) __bosn((s), 0)
-#  define __pass_object_size_n(n) __attribute__((__pass_object_size__(n)))
+#  if _FORTIFY_SOURCE >= 3
+#    define __pass_object_size_n(n) __attribute__((__pass_dynamic_object_size__(n)))
+#  else
+#    define __pass_object_size_n(n) __attribute__((__pass_object_size__(n)))
+#  endif
+
 /*
  * FORTIFY'ed functions all have either enable_if or pass_object_size, which
  * makes taking their address impossible. Saying (&read)(foo, bar, baz); will
@@ -291,8 +294,8 @@
 
 /* Intended for use in evaluated contexts. */
 #define __bos_dynamic_check_impl_and(bos_val, op, index, cond) \
-  ((bos_val) == __BIONIC_FORTIFY_UNKNOWN_SIZE ||                 \
-   (__builtin_constant_p(index) && bos_val op index && (cond)))
+  (__builtin_constant_p(bos_val) && ((bos_val) == __BIONIC_FORTIFY_UNKNOWN_SIZE || \
+   (__builtin_constant_p(index) && bos_val op index && (cond))))
 
 #define __bos_dynamic_check_impl(bos_val, op, index) \
   __bos_dynamic_check_impl_and(bos_val, op, index, 1)
@@ -324,15 +327,6 @@
 /* Used to rename functions so that the compiler emits a call to 'x' rather than the function this was applied to. */
 #define __RENAME(x) __asm__(#x)
 
-/*
- * Used when we need to check for overflow when multiplying x and y. This
- * should only be used where __builtin_umull_overflow can not work, because it makes
- * assumptions that __builtin_umull_overflow doesn't (x and y are positive, ...),
- * *and* doesn't make use of compiler intrinsics, so it's probably slower than
- * __builtin_umull_overflow.
- */
-#define __unsafe_check_mul_overflow(x, y) ((__SIZE_TYPE__)-1 / (x) < (y))
-
 #include <android/versioning.h>
 #include <android/api-level.h>
 #if __has_include(<android/ndk-version.h>)
diff --git a/libc/include/sys/endian.h b/libc/include/sys/endian.h
index 1c7448cbe..8176bf3cd 100644
--- a/libc/include/sys/endian.h
+++ b/libc/include/sys/endian.h
@@ -22,86 +22,142 @@
  * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */
 
-#ifndef _SYS_ENDIAN_H_
-#define _SYS_ENDIAN_H_
+#pragma once
+
+/**
+ * @file sys/endian.h
+ * @brief Endianness utilities.
+ */
 
 #include <sys/cdefs.h>
 
 #include <stdint.h>
 
-#define _LITTLE_ENDIAN	1234
-#define _BIG_ENDIAN	4321
-#define _PDP_ENDIAN	3412
-#define _BYTE_ORDER _LITTLE_ENDIAN
-#define __LITTLE_ENDIAN_BITFIELD
-
-#ifndef __LITTLE_ENDIAN
-#define __LITTLE_ENDIAN _LITTLE_ENDIAN
-#endif
-#ifndef __BIG_ENDIAN
-#define __BIG_ENDIAN _BIG_ENDIAN
-#endif
-#define __BYTE_ORDER _BYTE_ORDER
-
 #define __swap16 __builtin_bswap16
 #define __swap32 __builtin_bswap32
 #define __swap64(x) __BIONIC_CAST(static_cast,uint64_t,__builtin_bswap64(x))
 
-/* glibc compatibility. */
 __BEGIN_DECLS
-uint32_t htonl(uint32_t __x) __attribute_const__;
-uint16_t htons(uint16_t __x) __attribute_const__;
-uint32_t ntohl(uint32_t __x) __attribute_const__;
-uint16_t ntohs(uint16_t __x) __attribute_const__;
-__END_DECLS
 
+/* POSIX. */
+
+/** The value of BYTE_ORDER on little-endian systems. */
+#define LITTLE_ENDIAN 1234
+
+/** The value of BYTE_ORDER on big-endian systems. */
+#define BIG_ENDIAN 4321
+
+/** Android is always little-endian. */
+#define BYTE_ORDER LITTLE_ENDIAN
+
+/** Swap big-endian 16-bit quantity to host (little-endian) byte order. */
+#define be16toh(x) __swap16(x)
+/** Swap big-endian 32-bit quantity to host (little-endian) byte order. */
+#define be32toh(x) __swap32(x)
+/** Swap big-endian 64-bit quantity to host (little-endian) byte order. */
+#define be64toh(x) __swap64(x)
+
+/** Swap host (little-endian) 16-bit quantity to big-endian. */
+#define htobe16(x) __swap16(x)
+/** Swap host (little-endian) 32-bit quantity to big-endian. */
+#define htobe32(x) __swap32(x)
+/** swap host (little-endian) 64-bit quantity to big-endian. */
+#define htobe64(x) __swap64(x)
+
+/** No-op conversion of host (little-endian) 16-bit quantity to little-endian. */
+#define htole16(x) (x)
+/** No-op conversion of host (little-endian) 32-bit quantity to little-endian. */
+#define htole32(x) (x)
+/** No-op conversion of host (little-endian) 64-bit quantity to little-endian. */
+#define htole64(x) (x)
+
+/** No-op conversion of little-endian 16-bit quantity to host (little-endian) byte order. */
+#define le16toh(x) (x)
+/** No-op conversion of little-endian 32-bit quantity to host (little-endian) byte order. */
+#define le32toh(x) (x)
+/** No-op conversion of little-endian 64-bit quantity to host (little-endian) byte order. */
+#define le64toh(x) (x)
+
+/** Synonym for BIG_ENDIAN. */
+#define _BIG_ENDIAN	BIG_ENDIAN
+/** Synonym for BYTE_ORDER. */
+#define _BYTE_ORDER BYTE_ORDER
+/** Synonym for LITTLE_ENDIAN. */
+#define _LITTLE_ENDIAN LITTLE_ENDIAN
+
+/** Synonym for BIG_ENDIAN. */
+#define __BIG_ENDIAN BIG_ENDIAN
+/** Synonym for BYTE_ORDER. */
+#define __BYTE_ORDER BYTE_ORDER
+/** Synonym for LITTLE_ENDIAN. */
+#define __LITTLE_ENDIAN LITTLE_ENDIAN
+
+/** The byte order of bitfields. Accidental Linux header leakage. */
+#define __LITTLE_ENDIAN_BITFIELD
+
+
+/*
+ * POSIX has these in <arpa/inet.h>,
+ * but we have them here for glibc source compatibility.
+ */
+
+/** Swap host (little-endian) 32-bit quantity to network (big-endian). */
+uint32_t htonl(uint32_t __x) __attribute_const__;
 #define htonl(x) __swap32(x)
+
+/** Swap host (little-endian) 16-bit quantity to network (big-endian). */
+uint16_t htons(uint16_t __x) __attribute_const__;
 #define htons(x) __swap16(x)
+
+/** Swap network (big-endian) 32-bit quantity to host (little-endian). */
+uint32_t ntohl(uint32_t __x) __attribute_const__;
 #define ntohl(x) __swap32(x)
+
+/** Swap network (big-endian) 16-bit quantity to host (little-endian). */
+uint16_t ntohs(uint16_t __x) __attribute_const__;
 #define ntohs(x) __swap16(x)
 
+
 /* Bionic additions */
+
+/** Swap host (little-endian) 64-bit quantity to network (big-endian). */
 #define htonq(x) __swap64(x)
+
+/** Swap network (big-endian) 64-bit quantity to host (little-endian). */
 #define ntohq(x) __swap64(x)
 
-#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
-#define LITTLE_ENDIAN _LITTLE_ENDIAN
-#define BIG_ENDIAN _BIG_ENDIAN
-#define PDP_ENDIAN _PDP_ENDIAN
-#define BYTE_ORDER _BYTE_ORDER
 
+/* BSD extensions unconditionally exposed by bionic. */
+
+/** The value of BYTE_ORDER on PDP-endian systems. */
+#define PDP_ENDIAN 3412
+/** Synonym for PDP_ENDIAN. */
+#define _PDP_ENDIAN	PDP_ENDIAN
+
+/** In-place byte swap of 32-bit argument. */
 #define	NTOHL(x) (x) = ntohl(__BIONIC_CAST(static_cast,u_int32_t,(x)))
+/** In-place byte swap of 16-bit argument. */
 #define	NTOHS(x) (x) = ntohs(__BIONIC_CAST(static_cast,u_int16_t,(x)))
+/** In-place byte swap of 32-bit argument. */
 #define	HTONL(x) (x) = htonl(__BIONIC_CAST(static_cast,u_int32_t,(x)))
+/** In-place byte swap of 16-bit argument. */
 #define	HTONS(x) (x) = htons(__BIONIC_CAST(static_cast,u_int16_t,(x)))
 
-#define htobe16(x) __swap16(x)
-#define htobe32(x) __swap32(x)
-#define htobe64(x) __swap64(x)
+
+/* glibc extensions. */
+
+/** Swap big-endian 16-bit quantity to host (little-endian). */
 #define betoh16(x) __swap16(x)
+/** Swap big-endian 32-bit quantity to host (little-endian). */
 #define betoh32(x) __swap32(x)
+/** Swap big-endian 64-bit quantity to host (little-endian). */
 #define betoh64(x) __swap64(x)
 
-#define htole16(x) (x)
-#define htole32(x) (x)
-#define htole64(x) (x)
+/** No-op conversion of little-endian 16-bit quantity to host (little-endian). */
 #define letoh16(x) (x)
+/** No-op conversion of little-endian 32-bit quantity to host (little-endian). */
 #define letoh32(x) (x)
+/** No-op conversion of little-endian 64-bit quantity to host (little-endian). */
 #define letoh64(x) (x)
 
-/*
- * glibc-compatible beXXtoh/leXXtoh synonyms for htobeXX/htoleXX.
- * The BSDs export both sets of names, bionic historically only
- * exported the ones above (or on the rhs here), and glibc only
- * exports these names (on the lhs).
- */
-#define be16toh(x) htobe16(x)
-#define be32toh(x) htobe32(x)
-#define be64toh(x) htobe64(x)
-#define le16toh(x) htole16(x)
-#define le32toh(x) htole32(x)
-#define le64toh(x) htole64(x)
-
-#endif
-
-#endif
+__END_DECLS
diff --git a/libc/include/sys/epoll.h b/libc/include/sys/epoll.h
index bec7c6417..4d21e4371 100644
--- a/libc/include/sys/epoll.h
+++ b/libc/include/sys/epoll.h
@@ -88,28 +88,26 @@ int epoll_pwait(int __epoll_fd, struct epoll_event* _Nonnull __events, int __eve
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int epoll_pwait64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, int __timeout_ms, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 /**
  * Like epoll_pwait() but with a `struct timespec` timeout, for nanosecond resolution.
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 int epoll_pwait2(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset_t* _Nullable __mask) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
 /**
  * Like epoll_pwait2() but using a 64-bit signal mask even on 32-bit systems.
  *
  * Available since API level 35.
  */
+#if __BIONIC_AVAILABILITY_GUARD(35)
 int epoll_pwait2_64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/hwprobe.h b/libc/include/sys/hwprobe.h
index 8e69e8a2e..1b83996f1 100644
--- a/libc/include/sys/hwprobe.h
+++ b/libc/include/sys/hwprobe.h
@@ -38,6 +38,9 @@
 #include <sys/cdefs.h>
 #include <sys/types.h>
 
+/* For cpu_set_t. */
+#include <sched.h>
+
 /* Pull in struct riscv_hwprobe and corresponding constants. */
 #include <asm/hwprobe.h>
 
@@ -47,11 +50,11 @@ __BEGIN_DECLS
  * [__riscv_hwprobe(2)](https://docs.kernel.org/riscv/hwprobe.html)
  * queries hardware characteristics.
  *
- * A `__cpu_count` of 0 and null `__cpus` means "all online cpus".
+ * A `__cpu_set_size` of 0 and null `__cpu_set` means "all online cpus".
  *
  * Returns 0 on success and returns an error number on failure.
  */
-int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull __pairs, size_t __pair_count, size_t __cpu_count, unsigned long* _Nullable __cpus, unsigned __flags);
+int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull __pairs, size_t __pair_count, size_t __cpu_set_size, cpu_set_t* _Nullable __cpu_set, unsigned __flags);
 
 /**
  * The type of the second argument passed to riscv64 ifunc resolvers.
@@ -59,7 +62,7 @@ int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull __pairs, size_t __pair_count,
  * without worrying about whether that relocation is resolved before
  * the ifunc resolver is called.
  */
-typedef int (*__riscv_hwprobe_t)(struct riscv_hwprobe* _Nonnull __pairs, size_t __pair_count, size_t __cpu_count, unsigned long* _Nullable __cpus, unsigned __flags);
+typedef int (*__riscv_hwprobe_t)(struct riscv_hwprobe* _Nonnull __pairs, size_t __pair_count, size_t __cpu_set_size, cpu_set_t* _Nullable __cpu_set, unsigned __flags);
 
 __END_DECLS
 
diff --git a/libc/include/sys/mman.h b/libc/include/sys/mman.h
index 3fe1f9cbf..993ec0ff4 100644
--- a/libc/include/sys/mman.h
+++ b/libc/include/sys/mman.h
@@ -86,12 +86,6 @@ int msync(void* _Nonnull __addr, size_t __size, int __flags);
  */
 int mprotect(void* _Nonnull __addr, size_t __size, int __prot);
 
-/** Flag for mremap(). */
-#define MREMAP_MAYMOVE  1
-
-/** Flag for mremap(). */
-#define MREMAP_FIXED    2
-
 /**
  * [mremap(2)](https://man7.org/linux/man-pages/man2/mremap.2.html)
  * expands or shrinks an existing memory mapping.
@@ -133,12 +127,10 @@ int mlock(const void* _Nonnull __addr, size_t __size);
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(30)
 int mlock2(const void* _Nonnull __addr, size_t __size, int __flags) __INTRODUCED_IN(30);
 #endif /* __BIONIC_AVAILABILITY_GUARD(30) */
 
-
 /**
  * [munlock(2)](https://man7.org/linux/man-pages/man2/munlock.2.html)
  * unlocks pages (allowing swapping).
@@ -175,28 +167,20 @@ int madvise(void* _Nonnull __addr, size_t __size, int __advice);
  *
  * Returns the number of bytes advised on success, and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(31)
 ssize_t process_madvise(int __pid_fd, const struct iovec* _Nonnull __iov, size_t __count, int __advice, unsigned __flags) __INTRODUCED_IN(31);
 #endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
-
-#if defined(__USE_GNU)
-
 /**
  * [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  * creates an anonymous file.
  *
- * Available since API level 30.
- *
  * Returns an fd on success, and returns -1 and sets `errno` on failure.
+ *
+ * Available since API level 30 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(30)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(30)
 int memfd_create(const char* _Nonnull __name, unsigned __flags) __INTRODUCED_IN(30);
-#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
-
-
 #endif
 
 #if __ANDROID_API__ >= 23
@@ -232,12 +216,10 @@ int memfd_create(const char* _Nonnull __name, unsigned __flags) __INTRODUCED_IN(
  *
  * Returns 0 on success, and returns a positive error number on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int posix_madvise(void* _Nonnull __addr, size_t __size, int __advice) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 /**
  * [mseal(2)](https://man7.org/linux/man-pages/man2/mseal.2.html)
  * seals the given range to prevent modifications such as mprotect() calls.
@@ -248,10 +230,8 @@ int posix_madvise(void* _Nonnull __addr, size_t __size, int __advice) __INTRODUC
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(36)
 int mseal(void* _Nonnull __addr, size_t __size, unsigned long __flags) __INTRODUCED_IN(36);
 #endif /* __BIONIC_AVAILABILITY_GUARD(36) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/msg.h b/libc/include/sys/msg.h
index 8b619be24..31696b592 100644
--- a/libc/include/sys/msg.h
+++ b/libc/include/sys/msg.h
@@ -46,16 +46,23 @@ typedef __kernel_ulong_t msgqnum_t;
 typedef __kernel_ulong_t msglen_t;
 
 /** Not useful on Android; disallowed by SELinux. */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int msgctl(int __msg_id, int __op, struct msqid_ds* _Nullable __buf) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int msgget(key_t __key, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 ssize_t msgrcv(int __msg_id, void* _Nonnull __msgbuf_ptr, size_t __size, long __type, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int msgsnd(int __msg_id, const void* _Nonnull __msgbuf_ptr, size_t __size, int __flags) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/param.h b/libc/include/sys/param.h
index 99b6a0733..b4bca8d66 100644
--- a/libc/include/sys/param.h
+++ b/libc/include/sys/param.h
@@ -64,8 +64,8 @@
  */
 #define powerof2(x)                                               \
   ({                                                              \
-    __typeof__(x) _x = (x);                                       \
-    __typeof__(x) _x2;                                            \
+    __auto_type _x = (x);                                         \
+    __auto_type _x2 = _x;                                         \
     __builtin_add_overflow(_x, -1, &_x2) ? 1 : ((_x2 & _x) == 0); \
   })
 
diff --git a/libc/include/sys/pidfd.h b/libc/include/sys/pidfd.h
index bd2b01e9f..a18f47438 100644
--- a/libc/include/sys/pidfd.h
+++ b/libc/include/sys/pidfd.h
@@ -49,9 +49,9 @@ __BEGIN_DECLS
  *
  * Available since API level 31.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(31)
 int pidfd_open(pid_t __pid, unsigned int __flags) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
 /**
  * [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
@@ -63,7 +63,9 @@ int pidfd_open(pid_t __pid, unsigned int __flags) __INTRODUCED_IN(31);
  *
  * Available since API level 31.
  */
+#if __BIONIC_AVAILABILITY_GUARD(31)
 int pidfd_getfd(int __pidfd, int __targetfd, unsigned int __flags) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
 /**
  * [pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)
@@ -73,8 +75,8 @@ int pidfd_getfd(int __pidfd, int __targetfd, unsigned int __flags) __INTRODUCED_
  *
  * Available since API level 31.
  */
+#if __BIONIC_AVAILABILITY_GUARD(31)
 int pidfd_send_signal(int __pidfd, int __sig, siginfo_t * _Nullable __info, unsigned int __flags) __INTRODUCED_IN(31);
 #endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/quota.h b/libc/include/sys/quota.h
index af09674dd..3c854e8e6 100644
--- a/libc/include/sys/quota.h
+++ b/libc/include/sys/quota.h
@@ -51,10 +51,8 @@ __BEGIN_DECLS
  *
  * Available since API level 26.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int quotactl(int __op, const char* _Nullable __special, int __id, char* __BIONIC_COMPLICATED_NULLNESS __addr) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/random.h b/libc/include/sys/random.h
index 23d2c3aba..d2008b381 100644
--- a/libc/include/sys/random.h
+++ b/libc/include/sys/random.h
@@ -52,7 +52,6 @@ __BEGIN_DECLS
  *
  * See also arc4random_buf() which is available in all API levels.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard ssize_t getrandom(void* _Nonnull __buffer, size_t __buffer_size, unsigned int __flags) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
diff --git a/libc/include/sys/sem.h b/libc/include/sys/sem.h
index 72f567e2b..c01603afc 100644
--- a/libc/include/sys/sem.h
+++ b/libc/include/sys/sem.h
@@ -51,20 +51,20 @@ union semun {
   void* _Nullable __pad;
 };
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int semctl(int __sem_id, int __sem_num, int __op, ...) __INTRODUCED_IN(26);
-int semget(key_t __key, int __sem_count, int __flags) __INTRODUCED_IN(26);
-int semop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
-#if defined(__USE_GNU)
+#if __BIONIC_AVAILABILITY_GUARD(26)
+int semget(key_t __key, int __sem_count, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
-int semtimedop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(26);
+int semop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
+int semtimedop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(26);
 #endif
 
 __END_DECLS
diff --git a/libc/include/sys/shm.h b/libc/include/sys/shm.h
index a96078138..b4eaadff3 100644
--- a/libc/include/sys/shm.h
+++ b/libc/include/sys/shm.h
@@ -48,16 +48,23 @@ __BEGIN_DECLS
 typedef unsigned long shmatt_t;
 
 /** Not useful on Android; disallowed by SELinux. */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 void* _Nonnull shmat(int __shm_id, const void* _Nullable __addr, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int shmctl(int __shm_id, int __op, struct shmid_ds* _Nullable __buf) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int shmdt(const void* _Nonnull __addr) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /** Not useful on Android; disallowed by SELinux. */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int shmget(key_t __key, size_t __size, int __flags) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/signalfd.h b/libc/include/sys/signalfd.h
index eaea525e9..ed2c7bc8a 100644
--- a/libc/include/sys/signalfd.h
+++ b/libc/include/sys/signalfd.h
@@ -51,10 +51,8 @@ int signalfd(int __fd, const sigset_t* _Nonnull __mask, int __flags);
 /**
  * Like signalfd() but allows setting a signal mask with RT signals even from a 32-bit process.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int signalfd64(int __fd, const sigset64_t* _Nonnull __mask, int __flags) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/stat.h b/libc/include/sys/stat.h
index 12bfedc3d..344a7c33e 100644
--- a/libc/include/sys/stat.h
+++ b/libc/include/sys/stat.h
@@ -124,16 +124,33 @@ struct stat64 { __STAT64_BODY };
 #define st_mtime_nsec st_mtim.tv_nsec
 #define st_ctime_nsec st_ctim.tv_nsec
 
+/** BSD macro corresponding to `a+rwx`, useful as a mask of just the permission bits. */
 #if defined(__USE_BSD)
-/* Permission macros provided by glibc for compatibility with BSDs. */
 #define ACCESSPERMS (S_IRWXU | S_IRWXG | S_IRWXO) /* 0777 */
+#endif
+
+/** BSD macro useful as a mask of the permission bits and setuid/setgid/sticky bits. */
+#if defined(__USE_BSD)
 #define ALLPERMS    (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) /* 07777 */
+#endif
+
+/** BSD macro corresponding to `a+rw`, useful as a default. */
+#if defined(__USE_BSD)
 #define DEFFILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) /* 0666 */
 #endif
 
+/** BSD/GNU synonym for S_IRUSR. */
 #if defined(__USE_BSD) || defined(__USE_GNU)
 #define S_IREAD S_IRUSR
+#endif
+
+/** BSD/GNU synonym for S_IWUSR. */
+#if defined(__USE_BSD) || defined(__USE_GNU)
 #define S_IWRITE S_IWUSR
+#endif
+
+/** BSD/GNU synonym for S_IXUSR. */
+#if defined(__USE_BSD) || defined(__USE_GNU)
 #define S_IEXEC S_IXUSR
 #endif
 
@@ -177,12 +194,10 @@ int fchmodat(int __dir_fd, const char* _Nonnull __path, mode_t __mode, int __fla
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(36)
 int lchmod(const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(36);
 #endif /* __BIONIC_AVAILABILITY_GUARD(36) */
 
-
 /**
  * [mkdir(2)](https://man7.org/linux/man-pages/man2/mkdir.2.html)
  * creates a directory.
@@ -285,7 +300,6 @@ int mkfifo(const char* _Nonnull __path, mode_t __mode);
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int mkfifoat(int __dir_fd, const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
@@ -331,20 +345,16 @@ int utimensat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, co
  */
 int futimens(int __fd, const struct timespec __times[_Nullable 2]);
 
-#if defined(__USE_GNU)
 /**
  * [statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html) returns
  * extended file status information.
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  *
- * Available since API level 30.
+ * Available since API level 30 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(30)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(30)
 int statx(int __dir_fd, const char* _Nullable __path, int __flags, unsigned __mask, struct statx* _Nonnull __buf) __INTRODUCED_IN(30);
-#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
-
 #endif
 
 __END_DECLS
diff --git a/libc/include/sys/sysinfo.h b/libc/include/sys/sysinfo.h
index ed6a0078e..e9e95d5ca 100644
--- a/libc/include/sys/sysinfo.h
+++ b/libc/include/sys/sysinfo.h
@@ -53,9 +53,9 @@ int sysinfo(struct sysinfo* _Nonnull __info);
  *
  * See also sysconf().
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int get_nprocs_conf(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [get_nprocs(3)](https://man7.org/linux/man-pages/man3/get_nprocs.3.html) returns
@@ -65,7 +65,9 @@ int get_nprocs_conf(void) __INTRODUCED_IN(23);
  *
  * See also sysconf().
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int get_nprocs(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [get_phys_pages(3)](https://man7.org/linux/man-pages/man3/get_phys_pages.3.html) returns
@@ -75,7 +77,9 @@ int get_nprocs(void) __INTRODUCED_IN(23);
  *
  * See also sysconf().
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long get_phys_pages(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
 /**
  * [get_avphys_pages(3)](https://man7.org/linux/man-pages/man3/get_avphys_pages.3.html) returns
@@ -85,8 +89,8 @@ long get_phys_pages(void) __INTRODUCED_IN(23);
  *
  * See also sysconf().
  */
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long get_avphys_pages(void) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/system_properties.h b/libc/include/sys/system_properties.h
index 1303079f0..d850b1e28 100644
--- a/libc/include/sys/system_properties.h
+++ b/libc/include/sys/system_properties.h
@@ -71,14 +71,12 @@ const prop_info* _Nullable __system_property_find(const char* _Nonnull __name);
  *
  * Available since API level 26.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 void __system_property_read_callback(const prop_info* _Nonnull __pi,
     void (* _Nonnull __callback)(void* _Nullable __cookie, const char* _Nonnull __name, const char* _Nonnull __value, uint32_t __serial),
     void* _Nullable __cookie) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 /**
  * Passes a `prop_info` for each system property to the provided
  * callback. Use __system_property_read_callback() to read the value of
@@ -111,7 +109,6 @@ bool __system_property_wait(const prop_info* _Nullable __pi, uint32_t __old_seri
     __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
-
 /**
  * Deprecated: there's no limit on the length of a property name since
  * API level 26, though the limit on property values (PROP_VALUE_MAX) remains.
@@ -241,12 +238,10 @@ int __system_property_update(prop_info* _Nonnull __pi, const char* _Nonnull __va
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 int __system_properties_zygote_reload(void) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 /**
  * Deprecated: previously for testing, but now that SystemProperties is its own
  * testable class, there is never a reason to call this function and its
diff --git a/libc/include/sys/thread_properties.h b/libc/include/sys/thread_properties.h
index b6214ee68..fb69ccb70 100644
--- a/libc/include/sys/thread_properties.h
+++ b/libc/include/sys/thread_properties.h
@@ -54,7 +54,7 @@ __BEGIN_DECLS
 #if __BIONIC_AVAILABILITY_GUARD(31)
 void __libc_get_static_tls_bounds(void* _Nonnull * _Nonnull __static_tls_begin,
                                   void* _Nonnull * _Nonnull __static_tls_end) __INTRODUCED_IN(31);
-
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
 /**
  * Registers callback to be called right before the thread is dead.
@@ -68,7 +68,9 @@ void __libc_get_static_tls_bounds(void* _Nonnull * _Nonnull __static_tls_begin,
  *
  * Available since API level 31.
  */
+#if __BIONIC_AVAILABILITY_GUARD(31)
 void __libc_register_thread_exit_callback(void (* _Nonnull __cb)(void)) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
 /**
  * Iterates over all dynamic TLS chunks for the given thread.
@@ -77,12 +79,14 @@ void __libc_register_thread_exit_callback(void (* _Nonnull __cb)(void)) __INTROD
  *
  * Available since API level 31.
  */
+#if __BIONIC_AVAILABILITY_GUARD(31)
 void __libc_iterate_dynamic_tls(pid_t __tid,
                                 void (* _Nonnull __cb)(void* _Nonnull __dynamic_tls_begin,
                                              void* _Nonnull __dynamic_tls_end,
                                              size_t __dso_id,
                                              void* _Nullable __arg),
                                 void* _Nullable __arg) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
 /**
  * Register on_creation and on_destruction callbacks, which will be called after a dynamic
@@ -90,6 +94,7 @@ void __libc_iterate_dynamic_tls(pid_t __tid,
  *
  * Available since API level 31.
  */
+#if __BIONIC_AVAILABILITY_GUARD(31)
 void __libc_register_dynamic_tls_listeners(
     void (* _Nonnull __on_creation)(void* _Nonnull __dynamic_tls_begin,
                           void* _Nonnull __dynamic_tls_end),
@@ -97,5 +102,4 @@ void __libc_register_dynamic_tls_listeners(
                              void* _Nonnull __dynamic_tls_end)) __INTRODUCED_IN(31);
 #endif /* __BIONIC_AVAILABILITY_GUARD(31) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/time.h b/libc/include/sys/time.h
index d12c30643..a7c0ecf5c 100644
--- a/libc/include/sys/time.h
+++ b/libc/include/sys/time.h
@@ -46,16 +46,14 @@ int setitimer(int __which, const struct itimerval* _Nonnull __new_value, struct
 
 int utimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]);
 
-#if defined(__USE_BSD)
-
-#if __BIONIC_AVAILABILITY_GUARD(26)
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(26)
 int futimes(int __fd, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
-int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
-#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+#endif
 
+#if defined(__USE_BSD) && __BIONIC_AVAILABILITY_GUARD(26)
+int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
 #endif
 
-#if defined(__USE_GNU)
 /**
  * [futimesat(2)](https://man7.org/linux/man-pages/man2/futimesat.2.html) sets
  * file timestamps.
@@ -67,13 +65,10 @@ int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable
  *
  * Returns 0 on success and -1 and sets `errno` on failure.
  *
- * Available since API level 26.
+ * Available since API level 26 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(26)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
 int futimesat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
-#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
-
 #endif
 
 #define timerclear(a)   \
diff --git a/libc/include/sys/timex.h b/libc/include/sys/timex.h
index 6fb58e41b..e740da5fc 100644
--- a/libc/include/sys/timex.h
+++ b/libc/include/sys/timex.h
@@ -46,9 +46,9 @@ __BEGIN_DECLS
  *
  * Available since API level 24.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int adjtimex(struct timex* _Nonnull __buf) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
 /**
  * clock_adjtime adjusts a specific kernel clock.
@@ -57,8 +57,8 @@ int adjtimex(struct timex* _Nonnull __buf) __INTRODUCED_IN(24);
  *
  * Available since API level 24.
  */
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int clock_adjtime(clockid_t __clock, struct timex* _Nonnull __tx) __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/types.h b/libc/include/sys/types.h
index 0446260f2..99d75258c 100644
--- a/libc/include/sys/types.h
+++ b/libc/include/sys/types.h
@@ -119,29 +119,33 @@ typedef __socklen_t socklen_t;
 
 typedef __builtin_va_list __va_list;
 
-#ifndef _SSIZE_T_DEFINED_
-#define _SSIZE_T_DEFINED_
-/* Traditionally, bionic's ssize_t was "long int". This caused GCC to emit warnings when you
- * pass a ssize_t to a printf-style function. The correct type is __kernel_ssize_t, which is
- * "int", which isn't an ABI change for C code (because they're the same size) but is an ABI
- * change for C++ because "int" and "long int" mangle to "i" and "l" respectively. So until
- * we can fix the ABI, this change should not be propagated to the NDK. http://b/8253769. */
+/**
+ * A signed alternative to size_t,
+ * generally for cases that return -1 and set errno on error.
+ */
 typedef __kernel_ssize_t ssize_t;
-#endif
 
+/** BSD synonym for unsigned int that's always exposed by historical accident. */
 typedef unsigned int        uint_t;
+/** BSD synonym for unsigned int that's always exposed by historical accident. */
 typedef unsigned int        uint;
 
-#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
+/** BSD synonym for unsigned char that's always exposed by historical accident. */
 typedef unsigned char  u_char;
+/** BSD synonym for unsigned short that's always exposed by historical accident. */
 typedef unsigned short u_short;
+/** BSD synonym for unsigned int that's always exposed by historical accident. */
 typedef unsigned int   u_int;
+/** BSD synonym for unsigned long that's always exposed by historical accident. */
 typedef unsigned long  u_long;
 
+/** BSD synonym for uint32_t that's always exposed by historical accident. */
 typedef uint32_t u_int32_t;
+/** BSD synonym for uint16_t that's always exposed by historical accident. */
 typedef uint16_t u_int16_t;
+/** BSD synonym for uint8_t that's always exposed by historical accident. */
 typedef uint8_t  u_int8_t;
+/** BSD synonym for uint64_t that's always exposed by historical accident. */
 typedef uint64_t u_int64_t;
-#endif
 
 #endif
diff --git a/libc/include/sys/uio.h b/libc/include/sys/uio.h
index eff3b1473..4f14ece57 100644
--- a/libc/include/sys/uio.h
+++ b/libc/include/sys/uio.h
@@ -57,8 +57,6 @@ ssize_t readv(int __fd, const struct iovec* _Nonnull __iov, int __count);
  */
 ssize_t writev(int __fd, const struct iovec* _Nonnull __iov, int __count);
 
-#if defined(__USE_GNU)
-
 /**
  * [preadv(2)](https://man7.org/linux/man-pages/man2/preadv.2.html) reads
  * from an fd into the `__count` buffers described by `__iov`, starting at
@@ -67,11 +65,11 @@ ssize_t writev(int __fd, const struct iovec* _Nonnull __iov, int __count);
  * Returns the number of bytes read on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(24)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t preadv(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset) __RENAME_IF_FILE_OFFSET64(preadv64) __INTRODUCED_IN(24);
+#endif
 
 /**
  * [pwritev(2)](https://man7.org/linux/man-pages/man2/pwritev.2.html) writes
@@ -81,25 +79,29 @@ ssize_t preadv(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t
  * Returns the number of bytes written on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t pwritev(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset) __RENAME_IF_FILE_OFFSET64(pwritev64) __INTRODUCED_IN(24);
+#endif
 
 /**
  * Like preadv() but with a 64-bit offset even in a 32-bit process.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t preadv64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset) __INTRODUCED_IN(24);
+#endif
 
 /**
  * Like pwritev() but with a 64-bit offset even in a 32-bit process.
  *
- * Available since API level 24.
+ * Available since API level 24 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset) __INTRODUCED_IN(24);
-#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
-
+#endif
 
 /**
  * [preadv2(2)](https://man7.org/linux/man-pages/man2/preadv2.2.html) reads
@@ -109,11 +111,11 @@ ssize_t pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off
  * Returns the number of bytes read on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 33.
+ * Available since API level 33 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(33)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(33)
 ssize_t preadv2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags) __RENAME_IF_FILE_OFFSET64(preadv64v2) __INTRODUCED_IN(33);
+#endif
 
 /**
  * [pwritev2(2)](https://man7.org/linux/man-pages/man2/pwritev2.2.html) writes
@@ -123,25 +125,29 @@ ssize_t preadv2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t
  * Returns the number of bytes written on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 33.
+ * Available since API level 33 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(33)
 ssize_t pwritev2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags) __RENAME_IF_FILE_OFFSET64(pwritev64v2) __INTRODUCED_IN(33);
+#endif
 
 /**
  * Like preadv2() but with a 64-bit offset even in a 32-bit process.
  *
- * Available since API level 33.
+ * Available since API level 33 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(33)
 ssize_t preadv64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags) __INTRODUCED_IN(33);
+#endif
 
 /**
  * Like pwritev2() but with a 64-bit offset even in a 32-bit process.
  *
- * Available since API level 33.
+ * Available since API level 33 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(33)
 ssize_t pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags) __INTRODUCED_IN(33);
-#endif /* __BIONIC_AVAILABILITY_GUARD(33) */
-
+#endif
 
 /**
  * [process_vm_readv(2)](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
@@ -150,11 +156,11 @@ ssize_t pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, o
  * Returns the number of bytes read on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 23.
+ * Available since API level 23 when compiling with `_GNU_SOURCE`.
  */
-
-#if __BIONIC_AVAILABILITY_GUARD(23)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);
+#endif
 
 /**
  * [process_vm_writev(2)](https://man7.org/linux/man-pages/man2/process_vm_writev.2.html)
@@ -163,12 +169,10 @@ ssize_t process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_N
  * Returns the number of bytes read on success,
  * and returns -1 and sets `errno` on failure.
  *
- * Available since API level 23.
+ * Available since API level 23 when compiling with `_GNU_SOURCE`.
  */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t process_vm_writev(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
-
-
 #endif
 
 __END_DECLS
diff --git a/libc/include/time.h b/libc/include/time.h
index 777e64865..f4b8d927e 100644
--- a/libc/include/time.h
+++ b/libc/include/time.h
@@ -166,7 +166,6 @@ time_t mktime(struct tm* _Nonnull __tm);
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 time_t mktime_z(timezone_t _Nonnull __tz, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
@@ -204,7 +203,6 @@ struct tm* _Nullable localtime_r(const time_t* _Nonnull __t, struct tm* _Nonnull
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 struct tm* _Nullable localtime_rz(timezone_t _Nonnull __tz, const time_t* _Nonnull __t, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
@@ -322,9 +320,9 @@ void tzset(void);
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 timezone_t _Nullable tzalloc(const char* _Nullable __id) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
 /**
  * tzfree(3) frees a timezone object returned by tzalloc().
@@ -335,10 +333,10 @@ timezone_t _Nullable tzalloc(const char* _Nullable __id) __INTRODUCED_IN(35);
  *
  * Available since API level 35.
  */
+#if __BIONIC_AVAILABILITY_GUARD(35)
 void tzfree(timezone_t _Nullable __tz) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 /**
  * [clock(3)](https://man7.org/linux/man-pages/man3/clock.3.html)
  * returns an approximation of CPU time used, equivalent to
@@ -355,9 +353,8 @@ clock_t clock(void);
  * [clock_getcpuclockid(3)](https://man7.org/linux/man-pages/man3/clock_getcpuclockid.3.html)
  * gets the clock ID of the cpu-time clock for the given `pid`.
  *
- * Returns 0 on success, and returns -1 and returns an error number on failure.
+ * Returns 0 on success, and returns an error number on failure (unlike other clock functions).
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int clock_getcpuclockid(pid_t __pid, clockid_t* _Nonnull __clock) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
@@ -367,7 +364,7 @@ int clock_getcpuclockid(pid_t __pid, clockid_t* _Nonnull __clock) __INTRODUCED_I
  * [clock_getres(2)](https://man7.org/linux/man-pages/man2/clock_getres.2.html)
  * gets the resolution of the given clock.
  *
- * Returns 0 on success, and returns -1 and returns an error number on failure.
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
 int clock_getres(clockid_t __clock, struct timespec* _Nullable __resolution);
 
@@ -375,7 +372,7 @@ int clock_getres(clockid_t __clock, struct timespec* _Nullable __resolution);
  * [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
  * gets the time according to the given clock.
  *
- * Returns 0 on success, and returns -1 and returns an error number on failure.
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
 int clock_gettime(clockid_t __clock, struct timespec* _Nonnull __ts);
 
@@ -384,7 +381,7 @@ int clock_gettime(clockid_t __clock, struct timespec* _Nonnull __ts);
  * sleeps for the given time (or until the given time if the TIMER_ABSTIME flag
  * is used), as measured by the given clock.
  *
- * Returns 0 on success, and returns -1 and returns an error number on failure.
+ * Returns 0 on success, and returns an error number on failure (unlike other clock functions).
  * If the sleep was interrupted by a signal, the return value will be `EINTR`
  * and `remainder` will be the amount of time remaining.
  */
@@ -394,7 +391,7 @@ int clock_nanosleep(clockid_t __clock, int __flags, const struct timespec* _Nonn
  * [clock_settime(2)](https://man7.org/linux/man-pages/man2/clock_settime.2.html)
  * sets the time for the given clock.
  *
- * Returns 0 on success, and returns -1 and returns an error number on failure.
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
 int clock_settime(clockid_t __clock, const struct timespec* _Nonnull __ts);
 
@@ -475,12 +472,10 @@ int timer_getoverrun(timer_t _Nonnull __timer);
  * Available since API level 29 for TIME_UTC; other bases arrived later.
  * Code for Android should prefer clock_gettime().
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(29)
 int timespec_get(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(29);
 #endif /* __BIONIC_AVAILABILITY_GUARD(29) */
 
-
 /**
  * timespec_getres(3) is equivalent to clock_getres() for the clock corresponding to the given base.
  *
@@ -489,10 +484,8 @@ int timespec_get(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(29)
  * Available since API level 35.
  * Code for Android should prefer clock_gettime().
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 int timespec_getres(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 __END_DECLS
diff --git a/libc/include/unistd.h b/libc/include/unistd.h
index 808568a5e..79438b920 100644
--- a/libc/include/unistd.h
+++ b/libc/include/unistd.h
@@ -101,12 +101,10 @@ pid_t fork(void);
  *
  * Available since API level 35.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(35)
 pid_t _Fork(void) __INTRODUCED_IN(35);
 #endif /* __BIONIC_AVAILABILITY_GUARD(35) */
 
-
 /**
  * [vfork(2)](https://man7.org/linux/man-pages/man2/vfork.2.html) creates a new
  * process. vfork() differs from fork() in that it does not run any handlers
@@ -155,7 +153,6 @@ int execle(const char* _Nonnull __path, const char* _Nullable __arg0, ... /*,  c
 int fexecve(int __fd, char* _Nullable const* _Nullable __argv, char* _Nullable const* _Nullable __envp) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 int nice(int __incr);
 
 /**
@@ -260,7 +257,6 @@ char* _Nullable getlogin(void);
 int getlogin_r(char* _Nonnull __buffer, size_t __buffer_size) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 long fpathconf(int __fd, int __name);
 long pathconf(const char* _Nonnull __path, int __name);
 
@@ -294,10 +290,22 @@ int chdir(const char* _Nonnull __path);
 int fchdir(int __fd);
 
 int rmdir(const char* _Nonnull __path);
+
+/**
+ * [pipe(2)](https://man7.org/linux/man-pages/man2/pipe.2.html) creates a pipe.
+ *
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ */
 int pipe(int __fds[_Nonnull 2]);
-#if defined(__USE_GNU)
+
+/**
+ * [pipe2(2)](https://man7.org/linux/man-pages/man2/pipe2.2.html) creates a pipe,
+ * with flags.
+ *
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ */
 int pipe2(int __fds[_Nonnull 2], int __flags);
-#endif
+
 int chroot(const char* _Nonnull __path);
 int symlink(const char* _Nonnull __old_path, const char* _Nonnull __new_path);
 int symlinkat(const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path);
@@ -309,13 +317,22 @@ int fchownat(int __dir_fd, const char* _Nonnull __path, uid_t __owner, gid_t __g
 int lchown(const char* _Nonnull __path, uid_t __owner, gid_t __group);
 char* _Nullable getcwd(char* _Nullable __buf, size_t __size);
 
+/**
+ * [sync(2)](https://man7.org/linux/man-pages/man2/sync.2.html) syncs changes
+ * to disk, for all file systems.
+ */
 void sync(void);
-#if defined(__USE_GNU)
 
-#if __BIONIC_AVAILABILITY_GUARD(28)
+/**
+ * [syncfs(2)](https://man7.org/linux/man-pages/man2/sync.2.html) syncs changes
+ * to disk, for the file system corresponding to the given file descriptor.
+ *
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ *
+ * Available since API level 28 when compiling with `_GNU_SOURCE`.
+ */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(28)
 int syncfs(int __fd) __INTRODUCED_IN(28);
-#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
-
 #endif
 
 int close(int __fd);
@@ -427,6 +444,8 @@ int tcsetpgrp(int __fd, pid_t __pid);
 
 #if __BIONIC_AVAILABILITY_GUARD(26)
 int getdomainname(char* _Nonnull __buf, size_t __buf_size) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int setdomainname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
@@ -440,7 +459,6 @@ int setdomainname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(26);
  * Returns the number of bytes copied on success, and returns -1 and sets
  * `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(34)
 ssize_t copy_file_range(int __fd_in, off64_t* _Nullable __off_in, int __fd_out, off64_t* _Nullable __off_out, size_t __length, unsigned int __flags) __INTRODUCED_IN(34);
 #endif /* __BIONIC_AVAILABILITY_GUARD(34) */
@@ -464,7 +482,6 @@ void swab(const void* _Nonnull __src, void* _Nonnull __dst, ssize_t __byte_count
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(34)
 int close_range(unsigned int __min_fd, unsigned int __max_fd, int __flags) __INTRODUCED_IN(34);
 #endif /* __BIONIC_AVAILABILITY_GUARD(34) */
diff --git a/libc/include/utime.h b/libc/include/utime.h
index f06a028ab..51da492b8 100644
--- a/libc/include/utime.h
+++ b/libc/include/utime.h
@@ -41,12 +41,12 @@ __BEGIN_DECLS
 
 /**
  * [utime(2)](https://man7.org/linux/man-pages/man2/utime.2.html) changes the access and
- * modification time of `__filename`. If `__times` is null, the current time is used.
+ * modification times of the given path. If `__times` is null, the current time is used.
  *
  * New code should prefer utimensat().
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-int utime(const char* _Nonnull __filename, const struct utimbuf* _Nullable __times);
+int utime(const char* _Nonnull __path, const struct utimbuf* _Nullable __times);
 
 __END_DECLS
diff --git a/libc/include/utmp.h b/libc/include/utmp.h
index 1674491ae..45b939394 100644
--- a/libc/include/utmp.h
+++ b/libc/include/utmp.h
@@ -131,10 +131,8 @@ void endutent(void);
  *
  * Available since API level 23.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(23)
 int login_tty(int __fd) __INTRODUCED_IN(23);
 #endif /* __BIONIC_AVAILABILITY_GUARD(23) */
 
-
 __END_DECLS
diff --git a/libc/include/wchar.h b/libc/include/wchar.h
index 56594dc38..ce82cbaee 100644
--- a/libc/include/wchar.h
+++ b/libc/include/wchar.h
@@ -44,7 +44,6 @@
 
 __BEGIN_DECLS
 
-wint_t btowc(int __ch);
 int fwprintf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, ...);
 int fwscanf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, ...);
 wint_t fgetwc(FILE* _Nonnull __fp);
@@ -123,18 +122,15 @@ unsigned long wcstoul_l(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICAT
 unsigned long long wcstoull(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base);
 int wcswidth(const wchar_t* _Nonnull __s, size_t __n);
 size_t wcsxfrm(wchar_t* __BIONIC_COMPLICATED_NULLNESS __dst, const wchar_t* _Nonnull __src, size_t __n);
-int wctob(wint_t __wc);
 int wcwidth(wchar_t __wc);
 wchar_t* _Nullable wmemchr(const wchar_t* _Nonnull __src, wchar_t __wc, size_t __n);
 int wmemcmp(const wchar_t* _Nullable __lhs, const wchar_t* _Nullable __rhs, size_t __n);
 wchar_t* _Nonnull wmemcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
-#if defined(__USE_GNU)
 
-#if __BIONIC_AVAILABILITY_GUARD(23)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(23)
 wchar_t* _Nonnull wmempcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n) __INTRODUCED_IN(23);
-#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
-
 #endif
+
 wchar_t* _Nonnull wmemmove(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 wchar_t* _Nonnull wmemset(wchar_t* _Nonnull __dst, wchar_t __wc, size_t __n);
 int wprintf(const wchar_t* _Nonnull __fmt, ...);
@@ -157,6 +153,11 @@ FILE* _Nullable open_wmemstream(wchar_t* _Nonnull * _Nonnull __ptr, size_t* _Non
 wchar_t* _Nullable wcsdup(const wchar_t* _Nonnull __s);
 size_t wcsnlen(const wchar_t* _Nonnull __s, size_t __n);
 
+/** ASCII-only; use mbtowc() instead. */
+wint_t btowc(int __ch) __attribute__((__deprecated__("ASCII-only; use mbtowc() instead")));
+/** ASCII-only; use wctomb() instead. */
+int wctob(wint_t __wc) __attribute__((__deprecated__("ASCII-only; use wctomb() instead")));
+
 __END_DECLS
 
 #endif
diff --git a/libc/include/wctype.h b/libc/include/wctype.h
index 30ec04f42..b1d716cad 100644
--- a/libc/include/wctype.h
+++ b/libc/include/wctype.h
@@ -52,12 +52,13 @@ int iswxdigit_l(wint_t __wc, locale_t _Nonnull __l);
 wint_t towlower_l(wint_t __wc, locale_t _Nonnull __l);
 wint_t towupper_l(wint_t __wc, locale_t _Nonnull __l);
 
-
 #if __BIONIC_AVAILABILITY_GUARD(26)
 wint_t towctrans_l(wint_t __wc, wctrans_t _Nonnull __transform, locale_t _Nonnull __l) __INTRODUCED_IN(26);
-wctrans_t _Nonnull wctrans_l(const char* _Nonnull __name, locale_t _Nonnull __l) __INTRODUCED_IN(26);
 #endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
+wctrans_t _Nonnull wctrans_l(const char* _Nonnull __name, locale_t _Nonnull __l) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
 
 wctype_t wctype_l(const char* _Nonnull __name, locale_t _Nonnull __l);
 int iswctype_l(wint_t __wc, wctype_t __transform, locale_t _Nonnull __l);
diff --git a/libc/kernel/uapi/asm-arm/asm/unistd-eabi.h b/libc/kernel/uapi/asm-arm/asm/unistd-eabi.h
index 9c4e45901..15c72616a 100644
--- a/libc/kernel/uapi/asm-arm/asm/unistd-eabi.h
+++ b/libc/kernel/uapi/asm-arm/asm/unistd-eabi.h
@@ -421,4 +421,8 @@
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
 #define __NR_mseal (__NR_SYSCALL_BASE + 462)
+#define __NR_setxattrat (__NR_SYSCALL_BASE + 463)
+#define __NR_getxattrat (__NR_SYSCALL_BASE + 464)
+#define __NR_listxattrat (__NR_SYSCALL_BASE + 465)
+#define __NR_removexattrat (__NR_SYSCALL_BASE + 466)
 #endif
diff --git a/libc/kernel/uapi/asm-arm/asm/unistd-oabi.h b/libc/kernel/uapi/asm-arm/asm/unistd-oabi.h
index 5060c2fdf..9eb602dc5 100644
--- a/libc/kernel/uapi/asm-arm/asm/unistd-oabi.h
+++ b/libc/kernel/uapi/asm-arm/asm/unistd-oabi.h
@@ -433,4 +433,8 @@
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
 #define __NR_mseal (__NR_SYSCALL_BASE + 462)
+#define __NR_setxattrat (__NR_SYSCALL_BASE + 463)
+#define __NR_getxattrat (__NR_SYSCALL_BASE + 464)
+#define __NR_listxattrat (__NR_SYSCALL_BASE + 465)
+#define __NR_removexattrat (__NR_SYSCALL_BASE + 466)
 #endif
diff --git a/libc/kernel/uapi/asm-arm64/asm/hwcap.h b/libc/kernel/uapi/asm-arm64/asm/hwcap.h
index 45cc9453c..635eef82f 100644
--- a/libc/kernel/uapi/asm-arm64/asm/hwcap.h
+++ b/libc/kernel/uapi/asm-arm64/asm/hwcap.h
@@ -38,6 +38,22 @@
 #define HWCAP_SB (1 << 29)
 #define HWCAP_PACA (1 << 30)
 #define HWCAP_PACG (1UL << 31)
+#define HWCAP_GCS (1UL << 32)
+#define HWCAP_CMPBR (1UL << 33)
+#define HWCAP_FPRCVT (1UL << 34)
+#define HWCAP_F8MM8 (1UL << 35)
+#define HWCAP_F8MM4 (1UL << 36)
+#define HWCAP_SVE_F16MM (1UL << 37)
+#define HWCAP_SVE_ELTPERM (1UL << 38)
+#define HWCAP_SVE_AES2 (1UL << 39)
+#define HWCAP_SVE_BFSCALE (1UL << 40)
+#define HWCAP_SVE2P2 (1UL << 41)
+#define HWCAP_SME2P2 (1UL << 42)
+#define HWCAP_SME_SBITPERM (1UL << 43)
+#define HWCAP_SME_AES (1UL << 44)
+#define HWCAP_SME_SFEXPA (1UL << 45)
+#define HWCAP_SME_STMOP (1UL << 46)
+#define HWCAP_SME_SMOP4 (1UL << 47)
 #define HWCAP2_DCPODP (1 << 0)
 #define HWCAP2_SVE2 (1 << 1)
 #define HWCAP2_SVEAES (1 << 2)
diff --git a/libc/kernel/uapi/asm-arm64/asm/kvm.h b/libc/kernel/uapi/asm-arm64/asm/kvm.h
index 1818c5f51..3516add3d 100644
--- a/libc/kernel/uapi/asm-arm64/asm/kvm.h
+++ b/libc/kernel/uapi/asm-arm64/asm/kvm.h
@@ -22,7 +22,6 @@
 #define __KVM_HAVE_VCPU_EVENTS
 #define KVM_COALESCED_MMIO_PAGE_OFFSET 1
 #define KVM_DIRTY_LOG_PAGE_OFFSET 64
-#define KVM_REG_SIZE(id) (1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
 struct kvm_regs {
   struct user_pt_regs regs;
   __u64 sp_el1;
@@ -262,6 +261,7 @@ enum {
 #define KVM_PSCI_RET_INVAL PSCI_RET_INVALID_PARAMS
 #define KVM_PSCI_RET_DENIED PSCI_RET_DENIED
 #define KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2 (1ULL << 0)
+#define KVM_SYSTEM_EVENT_SHUTDOWN_FLAG_PSCI_OFF2 (1ULL << 0)
 #define KVM_EXIT_FAIL_ENTRY_CPU_UNSUPPORTED (1ULL << 0)
 enum kvm_smccc_filter_action {
   KVM_SMCCC_FILTER_HANDLE = 0,
diff --git a/libc/kernel/uapi/asm-arm64/asm/ptrace.h b/libc/kernel/uapi/asm-arm64/asm/ptrace.h
index 4541a66f2..6d79ecdb2 100644
--- a/libc/kernel/uapi/asm-arm64/asm/ptrace.h
+++ b/libc/kernel/uapi/asm-arm64/asm/ptrace.h
@@ -127,5 +127,10 @@ struct user_za_header {
 #define ZA_PT_ZAV_OFFSET(vq,n) (ZA_PT_ZA_OFFSET + ((vq * __SVE_VQ_BYTES) * n))
 #define ZA_PT_ZA_SIZE(vq) ((vq * __SVE_VQ_BYTES) * (vq * __SVE_VQ_BYTES))
 #define ZA_PT_SIZE(vq) (ZA_PT_ZA_OFFSET + ZA_PT_ZA_SIZE(vq))
+struct user_gcs {
+  __u64 features_enabled;
+  __u64 features_locked;
+  __u64 gcspr_el0;
+};
 #endif
 #endif
diff --git a/libc/kernel/uapi/asm-arm64/asm/sigcontext.h b/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
index a845a03c3..b21a44ca3 100644
--- a/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
+++ b/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
@@ -74,6 +74,13 @@ struct zt_context {
   __u16 nregs;
   __u16 __reserved[3];
 };
+#define GCS_MAGIC 0x47435300
+struct gcs_context {
+  struct _aarch64_ctx head;
+  __u64 gcspr;
+  __u64 features_enabled;
+  __u64 reserved;
+};
 #endif
 #include <asm/sve_context.h>
 #define SVE_VQ_BYTES __SVE_VQ_BYTES
diff --git a/libc/kernel/uapi/asm-arm64/asm/unistd_64.h b/libc/kernel/uapi/asm-arm64/asm/unistd_64.h
index 0a0a1c04f..6e879931d 100644
--- a/libc/kernel/uapi/asm-arm64/asm/unistd_64.h
+++ b/libc/kernel/uapi/asm-arm64/asm/unistd_64.h
@@ -324,4 +324,8 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #endif
diff --git a/libc/kernel/uapi/asm-generic/ioctl.h b/libc/kernel/uapi/asm-generic/ioctl.h
index d614feff0..88fab7f72 100644
--- a/libc/kernel/uapi/asm-generic/ioctl.h
+++ b/libc/kernel/uapi/asm-generic/ioctl.h
@@ -34,12 +34,12 @@
 #define _IOC(dir,type,nr,size) (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
 #define _IOC_TYPECHECK(t) (sizeof(t))
 #define _IO(type,nr) _IOC(_IOC_NONE, (type), (nr), 0)
-#define _IOR(type,nr,size) _IOC(_IOC_READ, (type), (nr), (_IOC_TYPECHECK(size)))
-#define _IOW(type,nr,size) _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
-#define _IOWR(type,nr,size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
-#define _IOR_BAD(type,nr,size) _IOC(_IOC_READ, (type), (nr), sizeof(size))
-#define _IOW_BAD(type,nr,size) _IOC(_IOC_WRITE, (type), (nr), sizeof(size))
-#define _IOWR_BAD(type,nr,size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))
+#define _IOR(type,nr,argtype) _IOC(_IOC_READ, (type), (nr), (_IOC_TYPECHECK(argtype)))
+#define _IOW(type,nr,argtype) _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(argtype)))
+#define _IOWR(type,nr,argtype) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(argtype)))
+#define _IOR_BAD(type,nr,argtype) _IOC(_IOC_READ, (type), (nr), sizeof(argtype))
+#define _IOW_BAD(type,nr,argtype) _IOC(_IOC_WRITE, (type), (nr), sizeof(argtype))
+#define _IOWR_BAD(type,nr,argtype) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(argtype))
 #define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
 #define _IOC_TYPE(nr) (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
 #define _IOC_NR(nr) (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
diff --git a/libc/kernel/uapi/asm-generic/mman-common.h b/libc/kernel/uapi/asm-generic/mman-common.h
index 55e0ca17e..dda66fdf4 100644
--- a/libc/kernel/uapi/asm-generic/mman-common.h
+++ b/libc/kernel/uapi/asm-generic/mman-common.h
@@ -52,6 +52,8 @@
 #define MADV_POPULATE_WRITE 23
 #define MADV_DONTNEED_LOCKED 24
 #define MADV_COLLAPSE 25
+#define MADV_GUARD_INSTALL 102
+#define MADV_GUARD_REMOVE 103
 #define MAP_FILE 0
 #define PKEY_DISABLE_ACCESS 0x1
 #define PKEY_DISABLE_WRITE 0x2
diff --git a/libc/kernel/uapi/asm-generic/mman.h b/libc/kernel/uapi/asm-generic/mman.h
index a2a5de955..d6e6d5faf 100644
--- a/libc/kernel/uapi/asm-generic/mman.h
+++ b/libc/kernel/uapi/asm-generic/mman.h
@@ -15,4 +15,6 @@
 #define MCL_CURRENT 1
 #define MCL_FUTURE 2
 #define MCL_ONFAULT 4
+#define SHADOW_STACK_SET_TOKEN (1ULL << 0)
+#define SHADOW_STACK_SET_MARKER (1ULL << 1)
 #endif
diff --git a/libc/kernel/uapi/asm-generic/socket.h b/libc/kernel/uapi/asm-generic/socket.h
index a580c4c8e..bb076553d 100644
--- a/libc/kernel/uapi/asm-generic/socket.h
+++ b/libc/kernel/uapi/asm-generic/socket.h
@@ -97,6 +97,8 @@
 #define SO_DEVMEM_DMABUF 79
 #define SCM_DEVMEM_DMABUF SO_DEVMEM_DMABUF
 #define SO_DEVMEM_DONTNEED 80
+#define SCM_TS_OPT_ID 81
+#define SO_RCVPRIORITY 82
 #if __BITS_PER_LONG == 64 || defined(__x86_64__) && defined(__ILP32__)
 #define SO_TIMESTAMP SO_TIMESTAMP_OLD
 #define SO_TIMESTAMPNS SO_TIMESTAMPNS_OLD
diff --git a/libc/kernel/uapi/asm-generic/unistd.h b/libc/kernel/uapi/asm-generic/unistd.h
index 652e7a2d0..b5f19aed7 100644
--- a/libc/kernel/uapi/asm-generic/unistd.h
+++ b/libc/kernel/uapi/asm-generic/unistd.h
@@ -411,8 +411,12 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #undef __NR_syscalls
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #if __BITS_PER_LONG == 64 && !defined(__SYSCALL_COMPAT)
 #define __NR_fcntl __NR3264_fcntl
 #define __NR_statfs __NR3264_statfs
diff --git a/libc/kernel/uapi/asm-riscv/asm/hwprobe.h b/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
index 2e5f9a421..f63be93e7 100644
--- a/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
+++ b/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
@@ -66,6 +66,7 @@ struct riscv_hwprobe {
 #define RISCV_HWPROBE_EXT_ZCF (1ULL << 46)
 #define RISCV_HWPROBE_EXT_ZCMOP (1ULL << 47)
 #define RISCV_HWPROBE_EXT_ZAWRS (1ULL << 48)
+#define RISCV_HWPROBE_EXT_SUPM (1ULL << 49)
 #define RISCV_HWPROBE_KEY_CPUPERF_0 5
 #define RISCV_HWPROBE_MISALIGNED_UNKNOWN (0 << 0)
 #define RISCV_HWPROBE_MISALIGNED_EMULATED (1 << 0)
@@ -82,5 +83,11 @@ struct riscv_hwprobe {
 #define RISCV_HWPROBE_MISALIGNED_SCALAR_SLOW 2
 #define RISCV_HWPROBE_MISALIGNED_SCALAR_FAST 3
 #define RISCV_HWPROBE_MISALIGNED_SCALAR_UNSUPPORTED 4
+#define RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF 10
+#define RISCV_HWPROBE_MISALIGNED_VECTOR_UNKNOWN 0
+#define RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW 2
+#define RISCV_HWPROBE_MISALIGNED_VECTOR_FAST 3
+#define RISCV_HWPROBE_MISALIGNED_VECTOR_UNSUPPORTED 4
+#define RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0 11
 #define RISCV_HWPROBE_WHICH_CPUS (1 << 0)
 #endif
diff --git a/libc/kernel/uapi/asm-riscv/asm/kvm.h b/libc/kernel/uapi/asm-riscv/asm/kvm.h
index 51f497747..1816bdb97 100644
--- a/libc/kernel/uapi/asm-riscv/asm/kvm.h
+++ b/libc/kernel/uapi/asm-riscv/asm/kvm.h
@@ -135,6 +135,13 @@ enum KVM_RISCV_ISA_EXT_ID {
   KVM_RISCV_ISA_EXT_ZCF,
   KVM_RISCV_ISA_EXT_ZCMOP,
   KVM_RISCV_ISA_EXT_ZAWRS,
+  KVM_RISCV_ISA_EXT_SMNPM,
+  KVM_RISCV_ISA_EXT_SSNPM,
+  KVM_RISCV_ISA_EXT_SVADE,
+  KVM_RISCV_ISA_EXT_SVADU,
+  KVM_RISCV_ISA_EXT_SVVPTC,
+  KVM_RISCV_ISA_EXT_ZABHA,
+  KVM_RISCV_ISA_EXT_ZICCRSE,
   KVM_RISCV_ISA_EXT_MAX,
 };
 enum KVM_RISCV_SBI_EXT_ID {
@@ -149,6 +156,7 @@ enum KVM_RISCV_SBI_EXT_ID {
   KVM_RISCV_SBI_EXT_VENDOR,
   KVM_RISCV_SBI_EXT_DBCN,
   KVM_RISCV_SBI_EXT_STA,
+  KVM_RISCV_SBI_EXT_SUSP,
   KVM_RISCV_SBI_EXT_MAX,
 };
 struct kvm_riscv_sbi_sta {
@@ -157,7 +165,6 @@ struct kvm_riscv_sbi_sta {
 };
 #define KVM_RISCV_TIMER_STATE_OFF 0
 #define KVM_RISCV_TIMER_STATE_ON 1
-#define KVM_REG_SIZE(id) (1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
 #define KVM_REG_RISCV_TYPE_MASK 0x00000000FF000000
 #define KVM_REG_RISCV_TYPE_SHIFT 24
 #define KVM_REG_RISCV_SUBTYPE_MASK 0x0000000000FF0000
diff --git a/libc/kernel/uapi/asm-riscv/asm/unistd_32.h b/libc/kernel/uapi/asm-riscv/asm/unistd_32.h
index 864a55691..b43610958 100644
--- a/libc/kernel/uapi/asm-riscv/asm/unistd_32.h
+++ b/libc/kernel/uapi/asm-riscv/asm/unistd_32.h
@@ -315,4 +315,8 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #endif
diff --git a/libc/kernel/uapi/asm-riscv/asm/unistd_64.h b/libc/kernel/uapi/asm-riscv/asm/unistd_64.h
index f15b65bdb..d82343b7b 100644
--- a/libc/kernel/uapi/asm-riscv/asm/unistd_64.h
+++ b/libc/kernel/uapi/asm-riscv/asm/unistd_64.h
@@ -325,4 +325,8 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #endif
diff --git a/libc/kernel/uapi/asm-riscv/asm/vendor/thead.h b/libc/kernel/uapi/asm-riscv/asm/vendor/thead.h
new file mode 100644
index 000000000..a1d9607bb
--- /dev/null
+++ b/libc/kernel/uapi/asm-riscv/asm/vendor/thead.h
@@ -0,0 +1,7 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#define RISCV_HWPROBE_VENDOR_EXT_XTHEADVECTOR (1 << 0)
diff --git a/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h b/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h
index 0d630bfb1..d7a6919a1 100644
--- a/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h
+++ b/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h
@@ -47,6 +47,12 @@ enum hsmp_message_ids {
   HSMP_GET_METRIC_TABLE_VER,
   HSMP_GET_METRIC_TABLE,
   HSMP_GET_METRIC_TABLE_DRAM_ADDR,
+  HSMP_SET_XGMI_PSTATE_RANGE,
+  HSMP_CPU_RAIL_ISO_FREQ_POLICY,
+  HSMP_DFC_ENABLE_CTRL,
+  HSMP_GET_RAPL_UNITS = 0x30,
+  HSMP_GET_RAPL_CORE_COUNTER,
+  HSMP_GET_RAPL_PACKAGE_COUNTER,
   HSMP_MSG_ID_MAX,
 };
 struct hsmp_message {
@@ -60,136 +66,21 @@ enum hsmp_msg_type {
   HSMP_RSVD = - 1,
   HSMP_SET = 0,
   HSMP_GET = 1,
+  HSMP_SET_GET = 2,
 };
 enum hsmp_proto_versions {
   HSMP_PROTO_VER2 = 2,
   HSMP_PROTO_VER3,
   HSMP_PROTO_VER4,
   HSMP_PROTO_VER5,
-  HSMP_PROTO_VER6
+  HSMP_PROTO_VER6,
+  HSMP_PROTO_VER7
 };
 struct hsmp_msg_desc {
   int num_args;
   int response_sz;
   enum hsmp_msg_type type;
 };
-static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
- {
-    0, 0, HSMP_RSVD
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    0, 0, HSMP_SET
-  }
- , {
-    0, 2, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    1, 1, HSMP_GET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 1, HSMP_SET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    1, 0, HSMP_SET
-  }
- , {
-    0, 1, HSMP_GET
-  }
- , {
-    0, 0, HSMP_GET
-  }
- , {
-    0, 2, HSMP_GET
-  }
- ,
-};
 struct hsmp_metric_table {
   __u32 accumulation_counter;
   __u32 max_socket_temperature;
diff --git a/libc/kernel/uapi/asm-x86/asm/kvm.h b/libc/kernel/uapi/asm-x86/asm/kvm.h
index 0a35412a0..be0cca838 100644
--- a/libc/kernel/uapi/asm-x86/asm/kvm.h
+++ b/libc/kernel/uapi/asm-x86/asm/kvm.h
@@ -343,6 +343,7 @@ struct kvm_sync_regs {
 #define KVM_X86_QUIRK_FIX_HYPERCALL_INSN (1 << 5)
 #define KVM_X86_QUIRK_MWAIT_NEVER_UD_FAULTS (1 << 6)
 #define KVM_X86_QUIRK_SLOT_ZAP_ALL (1 << 7)
+#define KVM_X86_QUIRK_STUFF_FEATURE_MSRS (1 << 8)
 #define KVM_STATE_NESTED_FORMAT_VMX 0
 #define KVM_STATE_NESTED_FORMAT_SVM 1
 #define KVM_STATE_NESTED_GUEST_MODE 0x00000001
@@ -709,4 +710,5 @@ struct kvm_hyperv_eventfd {
 #define KVM_X86_SEV_VM 2
 #define KVM_X86_SEV_ES_VM 3
 #define KVM_X86_SNP_VM 4
+#define KVM_X86_TDX_VM 5
 #endif
diff --git a/libc/kernel/uapi/asm-x86/asm/mman.h b/libc/kernel/uapi/asm-x86/asm/mman.h
index 90269d629..557400978 100644
--- a/libc/kernel/uapi/asm-x86/asm/mman.h
+++ b/libc/kernel/uapi/asm-x86/asm/mman.h
@@ -8,6 +8,5 @@
 #define _ASM_X86_MMAN_H
 #define MAP_32BIT 0x40
 #define MAP_ABOVE4G 0x80
-#define SHADOW_STACK_SET_TOKEN (1ULL << 0)
 #include <asm-generic/mman.h>
 #endif
diff --git a/libc/kernel/uapi/asm-x86/asm/unistd_32.h b/libc/kernel/uapi/asm-x86/asm/unistd_32.h
index 59c693de0..3110d7de5 100644
--- a/libc/kernel/uapi/asm-x86/asm/unistd_32.h
+++ b/libc/kernel/uapi/asm-x86/asm/unistd_32.h
@@ -458,4 +458,8 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #endif
diff --git a/libc/kernel/uapi/asm-x86/asm/unistd_64.h b/libc/kernel/uapi/asm-x86/asm/unistd_64.h
index d5408a33c..f59ebdd99 100644
--- a/libc/kernel/uapi/asm-x86/asm/unistd_64.h
+++ b/libc/kernel/uapi/asm-x86/asm/unistd_64.h
@@ -381,4 +381,8 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 #endif
diff --git a/libc/kernel/uapi/asm-x86/asm/unistd_x32.h b/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
index fdcf7e6bd..0ecada368 100644
--- a/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
+++ b/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
@@ -334,6 +334,10 @@
 #define __NR_lsm_set_self_attr (__X32_SYSCALL_BIT + 460)
 #define __NR_lsm_list_modules (__X32_SYSCALL_BIT + 461)
 #define __NR_mseal (__X32_SYSCALL_BIT + 462)
+#define __NR_setxattrat (__X32_SYSCALL_BIT + 463)
+#define __NR_getxattrat (__X32_SYSCALL_BIT + 464)
+#define __NR_listxattrat (__X32_SYSCALL_BIT + 465)
+#define __NR_removexattrat (__X32_SYSCALL_BIT + 466)
 #define __NR_rt_sigaction (__X32_SYSCALL_BIT + 512)
 #define __NR_rt_sigreturn (__X32_SYSCALL_BIT + 513)
 #define __NR_ioctl (__X32_SYSCALL_BIT + 514)
diff --git a/libc/kernel/uapi/drm/amdgpu_drm.h b/libc/kernel/uapi/drm/amdgpu_drm.h
index 7bbd5de4f..f05c15fac 100644
--- a/libc/kernel/uapi/drm/amdgpu_drm.h
+++ b/libc/kernel/uapi/drm/amdgpu_drm.h
@@ -225,6 +225,10 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK 0x7
 #define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT 8
 #define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK 0x3f
+#define AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_SHIFT 14
+#define AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_MASK 0x1
+#define AMDGPU_TILING_GFX12_SCANOUT_SHIFT 63
+#define AMDGPU_TILING_GFX12_SCANOUT_MASK 0x1
 #define AMDGPU_TILING_SET(field,value) (((__u64) (value) & AMDGPU_TILING_ ##field ##_MASK) << AMDGPU_TILING_ ##field ##_SHIFT)
 #define AMDGPU_TILING_GET(value,field) (((__u64) (value) >> AMDGPU_TILING_ ##field ##_SHIFT) & AMDGPU_TILING_ ##field ##_MASK)
 #define AMDGPU_GEM_METADATA_OP_SET_METADATA 1
diff --git a/libc/kernel/uapi/drm/amdxdna_accel.h b/libc/kernel/uapi/drm/amdxdna_accel.h
new file mode 100644
index 000000000..4f23e8004
--- /dev/null
+++ b/libc/kernel/uapi/drm/amdxdna_accel.h
@@ -0,0 +1,248 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_AMDXDNA_ACCEL_H_
+#define _UAPI_AMDXDNA_ACCEL_H_
+#include <linux/stddef.h>
+#include "drm.h"
+#ifdef __cplusplus
+extern "C" {
+#endif
+#define AMDXDNA_INVALID_CMD_HANDLE (~0UL)
+#define AMDXDNA_INVALID_ADDR (~0UL)
+#define AMDXDNA_INVALID_CTX_HANDLE 0
+#define AMDXDNA_INVALID_BO_HANDLE 0
+#define AMDXDNA_INVALID_FENCE_HANDLE 0
+enum amdxdna_device_type {
+  AMDXDNA_DEV_TYPE_UNKNOWN = - 1,
+  AMDXDNA_DEV_TYPE_KMQ,
+};
+enum amdxdna_drm_ioctl_id {
+  DRM_AMDXDNA_CREATE_HWCTX,
+  DRM_AMDXDNA_DESTROY_HWCTX,
+  DRM_AMDXDNA_CONFIG_HWCTX,
+  DRM_AMDXDNA_CREATE_BO,
+  DRM_AMDXDNA_GET_BO_INFO,
+  DRM_AMDXDNA_SYNC_BO,
+  DRM_AMDXDNA_EXEC_CMD,
+  DRM_AMDXDNA_GET_INFO,
+  DRM_AMDXDNA_SET_STATE,
+};
+struct amdxdna_qos_info {
+  __u32 gops;
+  __u32 fps;
+  __u32 dma_bandwidth;
+  __u32 latency;
+  __u32 frame_exec_time;
+  __u32 priority;
+};
+struct amdxdna_drm_create_hwctx {
+  __u64 ext;
+  __u64 ext_flags;
+  __u64 qos_p;
+  __u32 umq_bo;
+  __u32 log_buf_bo;
+  __u32 max_opc;
+  __u32 num_tiles;
+  __u32 mem_size;
+  __u32 umq_doorbell;
+  __u32 handle;
+  __u32 syncobj_handle;
+};
+struct amdxdna_drm_destroy_hwctx {
+  __u32 handle;
+  __u32 pad;
+};
+struct amdxdna_cu_config {
+  __u32 cu_bo;
+  __u8 cu_func;
+  __u8 pad[3];
+};
+struct amdxdna_hwctx_param_config_cu {
+  __u16 num_cus;
+  __u16 pad[3];
+  struct amdxdna_cu_config cu_configs[] __counted_by(num_cus);
+};
+enum amdxdna_drm_config_hwctx_param {
+  DRM_AMDXDNA_HWCTX_CONFIG_CU,
+  DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF,
+  DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF,
+};
+struct amdxdna_drm_config_hwctx {
+  __u32 handle;
+  __u32 param_type;
+  __u64 param_val;
+  __u32 param_val_size;
+  __u32 pad;
+};
+enum amdxdna_bo_type {
+  AMDXDNA_BO_INVALID = 0,
+  AMDXDNA_BO_SHMEM,
+  AMDXDNA_BO_DEV_HEAP,
+  AMDXDNA_BO_DEV,
+  AMDXDNA_BO_CMD,
+};
+struct amdxdna_drm_create_bo {
+  __u64 flags;
+  __u64 vaddr;
+  __u64 size;
+  __u32 type;
+  __u32 handle;
+};
+struct amdxdna_drm_get_bo_info {
+  __u64 ext;
+  __u64 ext_flags;
+  __u32 handle;
+  __u32 pad;
+  __u64 map_offset;
+  __u64 vaddr;
+  __u64 xdna_addr;
+};
+struct amdxdna_drm_sync_bo {
+  __u32 handle;
+#define SYNC_DIRECT_TO_DEVICE 0U
+#define SYNC_DIRECT_FROM_DEVICE 1U
+  __u32 direction;
+  __u64 offset;
+  __u64 size;
+};
+enum amdxdna_cmd_type {
+  AMDXDNA_CMD_SUBMIT_EXEC_BUF = 0,
+  AMDXDNA_CMD_SUBMIT_DEPENDENCY,
+  AMDXDNA_CMD_SUBMIT_SIGNAL,
+};
+struct amdxdna_drm_exec_cmd {
+  __u64 ext;
+  __u64 ext_flags;
+  __u32 hwctx;
+  __u32 type;
+  __u64 cmd_handles;
+  __u64 args;
+  __u32 cmd_count;
+  __u32 arg_count;
+  __u64 seq;
+};
+struct amdxdna_drm_query_aie_status {
+  __u64 buffer;
+  __u32 buffer_size;
+  __u32 cols_filled;
+};
+struct amdxdna_drm_query_aie_version {
+  __u32 major;
+  __u32 minor;
+};
+struct amdxdna_drm_query_aie_tile_metadata {
+  __u16 row_count;
+  __u16 row_start;
+  __u16 dma_channel_count;
+  __u16 lock_count;
+  __u16 event_reg_count;
+  __u16 pad[3];
+};
+struct amdxdna_drm_query_aie_metadata {
+  __u32 col_size;
+  __u16 cols;
+  __u16 rows;
+  struct amdxdna_drm_query_aie_version version;
+  struct amdxdna_drm_query_aie_tile_metadata core;
+  struct amdxdna_drm_query_aie_tile_metadata mem;
+  struct amdxdna_drm_query_aie_tile_metadata shim;
+};
+struct amdxdna_drm_query_clock {
+  __u8 name[16];
+  __u32 freq_mhz;
+  __u32 pad;
+};
+struct amdxdna_drm_query_clock_metadata {
+  struct amdxdna_drm_query_clock mp_npu_clock;
+  struct amdxdna_drm_query_clock h_clock;
+};
+enum amdxdna_sensor_type {
+  AMDXDNA_SENSOR_TYPE_POWER
+};
+struct amdxdna_drm_query_sensor {
+  __u8 label[64];
+  __u32 input;
+  __u32 max;
+  __u32 average;
+  __u32 highest;
+  __u8 status[64];
+  __u8 units[16];
+  __s8 unitm;
+  __u8 type;
+  __u8 pad[6];
+};
+struct amdxdna_drm_query_hwctx {
+  __u32 context_id;
+  __u32 start_col;
+  __u32 num_col;
+  __u32 pad;
+  __s64 pid;
+  __u64 command_submissions;
+  __u64 command_completions;
+  __u64 migrations;
+  __u64 preemptions;
+  __u64 errors;
+};
+enum amdxdna_power_mode_type {
+  POWER_MODE_DEFAULT,
+  POWER_MODE_LOW,
+  POWER_MODE_MEDIUM,
+  POWER_MODE_HIGH,
+  POWER_MODE_TURBO,
+};
+struct amdxdna_drm_get_power_mode {
+  __u8 power_mode;
+  __u8 pad[7];
+};
+struct amdxdna_drm_query_firmware_version {
+  __u32 major;
+  __u32 minor;
+  __u32 patch;
+  __u32 build;
+};
+enum amdxdna_drm_get_param {
+  DRM_AMDXDNA_QUERY_AIE_STATUS,
+  DRM_AMDXDNA_QUERY_AIE_METADATA,
+  DRM_AMDXDNA_QUERY_AIE_VERSION,
+  DRM_AMDXDNA_QUERY_CLOCK_METADATA,
+  DRM_AMDXDNA_QUERY_SENSORS,
+  DRM_AMDXDNA_QUERY_HW_CONTEXTS,
+  DRM_AMDXDNA_QUERY_FIRMWARE_VERSION = 8,
+  DRM_AMDXDNA_GET_POWER_MODE,
+};
+struct amdxdna_drm_get_info {
+  __u32 param;
+  __u32 buffer_size;
+  __u64 buffer;
+};
+enum amdxdna_drm_set_param {
+  DRM_AMDXDNA_SET_POWER_MODE,
+  DRM_AMDXDNA_WRITE_AIE_MEM,
+  DRM_AMDXDNA_WRITE_AIE_REG,
+};
+struct amdxdna_drm_set_state {
+  __u32 param;
+  __u32 buffer_size;
+  __u64 buffer;
+};
+struct amdxdna_drm_set_power_mode {
+  __u8 power_mode;
+  __u8 pad[7];
+};
+#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX, struct amdxdna_drm_create_hwctx)
+#define DRM_IOCTL_AMDXDNA_DESTROY_HWCTX DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_DESTROY_HWCTX, struct amdxdna_drm_destroy_hwctx)
+#define DRM_IOCTL_AMDXDNA_CONFIG_HWCTX DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CONFIG_HWCTX, struct amdxdna_drm_config_hwctx)
+#define DRM_IOCTL_AMDXDNA_CREATE_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_BO, struct amdxdna_drm_create_bo)
+#define DRM_IOCTL_AMDXDNA_GET_BO_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_BO_INFO, struct amdxdna_drm_get_bo_info)
+#define DRM_IOCTL_AMDXDNA_SYNC_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SYNC_BO, struct amdxdna_drm_sync_bo)
+#define DRM_IOCTL_AMDXDNA_EXEC_CMD DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_EXEC_CMD, struct amdxdna_drm_exec_cmd)
+#define DRM_IOCTL_AMDXDNA_GET_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_INFO, struct amdxdna_drm_get_info)
+#define DRM_IOCTL_AMDXDNA_SET_STATE DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SET_STATE, struct amdxdna_drm_set_state)
+#ifdef __cplusplus
+}
+#endif
+#endif
diff --git a/libc/kernel/uapi/drm/drm.h b/libc/kernel/uapi/drm/drm.h
index c8fab3c5d..328b5258c 100644
--- a/libc/kernel/uapi/drm/drm.h
+++ b/libc/kernel/uapi/drm/drm.h
@@ -456,6 +456,11 @@ struct drm_crtc_queue_sequence {
   __u64 sequence;
   __u64 user_data;
 };
+#define DRM_CLIENT_NAME_MAX_LEN 64
+struct drm_set_client_name {
+  __u64 name_len;
+  __u64 name;
+};
 #ifdef __cplusplus
 }
 #endif
@@ -576,6 +581,7 @@ extern "C" {
 #define DRM_IOCTL_MODE_GETFB2 DRM_IOWR(0xCE, struct drm_mode_fb_cmd2)
 #define DRM_IOCTL_SYNCOBJ_EVENTFD DRM_IOWR(0xCF, struct drm_syncobj_eventfd)
 #define DRM_IOCTL_MODE_CLOSEFB DRM_IOWR(0xD0, struct drm_mode_closefb)
+#define DRM_IOCTL_SET_CLIENT_NAME DRM_IOWR(0xD1, struct drm_set_client_name)
 #define DRM_COMMAND_BASE 0x40
 #define DRM_COMMAND_END 0xA0
 struct drm_event {
diff --git a/libc/kernel/uapi/drm/drm_fourcc.h b/libc/kernel/uapi/drm/drm_fourcc.h
index c0f5ff1f3..7109a8fbc 100644
--- a/libc/kernel/uapi/drm/drm_fourcc.h
+++ b/libc/kernel/uapi/drm/drm_fourcc.h
@@ -260,6 +260,7 @@ extern "C" {
 #define AMD_FMT_MOD_TILE_VER_GFX12 5
 #define AMD_FMT_MOD_TILE_GFX9_64K_S 9
 #define AMD_FMT_MOD_TILE_GFX9_64K_D 10
+#define AMD_FMT_MOD_TILE_GFX9_4K_D_X 22
 #define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
 #define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
 #define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
diff --git a/libc/kernel/uapi/drm/ivpu_accel.h b/libc/kernel/uapi/drm/ivpu_accel.h
index 960bd43a7..8b81ebf3c 100644
--- a/libc/kernel/uapi/drm/ivpu_accel.h
+++ b/libc/kernel/uapi/drm/ivpu_accel.h
@@ -10,8 +10,6 @@
 #ifdef __cplusplus
 extern "C" {
 #endif
-#define DRM_IVPU_DRIVER_MAJOR 1
-#define DRM_IVPU_DRIVER_MINOR 0
 #define DRM_IVPU_GET_PARAM 0x00
 #define DRM_IVPU_SET_PARAM 0x01
 #define DRM_IVPU_BO_CREATE 0x02
diff --git a/libc/kernel/uapi/drm/msm_drm.h b/libc/kernel/uapi/drm/msm_drm.h
index 582da62b9..e8b790f4e 100644
--- a/libc/kernel/uapi/drm/msm_drm.h
+++ b/libc/kernel/uapi/drm/msm_drm.h
@@ -40,6 +40,7 @@ struct drm_msm_timespec {
 #define MSM_PARAM_RAYTRACING 0x11
 #define MSM_PARAM_UBWC_SWIZZLE 0x12
 #define MSM_PARAM_MACROTILE_MODE 0x13
+#define MSM_PARAM_UCHE_TRAP_BASE 0x14
 #define MSM_PARAM_NR_RINGS MSM_PARAM_PRIORITIES
 struct drm_msm_param {
   __u32 pipe;
@@ -169,7 +170,8 @@ struct drm_msm_gem_madvise {
   __u32 madv;
   __u32 retained;
 };
-#define MSM_SUBMITQUEUE_FLAGS (0)
+#define MSM_SUBMITQUEUE_ALLOW_PREEMPT 0x00000001
+#define MSM_SUBMITQUEUE_FLAGS (MSM_SUBMITQUEUE_ALLOW_PREEMPT | 0)
 struct drm_msm_submitqueue {
   __u32 flags;
   __u32 prio;
diff --git a/libc/kernel/uapi/drm/panfrost_drm.h b/libc/kernel/uapi/drm/panfrost_drm.h
index 66a46fca3..bb55fd3ca 100644
--- a/libc/kernel/uapi/drm/panfrost_drm.h
+++ b/libc/kernel/uapi/drm/panfrost_drm.h
@@ -29,6 +29,7 @@ extern "C" {
 #define DRM_IOCTL_PANFROST_PERFCNT_ENABLE DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_PERFCNT_ENABLE, struct drm_panfrost_perfcnt_enable)
 #define DRM_IOCTL_PANFROST_PERFCNT_DUMP DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_PERFCNT_DUMP, struct drm_panfrost_perfcnt_dump)
 #define PANFROST_JD_REQ_FS (1 << 0)
+#define PANFROST_JD_REQ_CYCLE_COUNT (1 << 1)
 struct drm_panfrost_submit {
   __u64 jc;
   __u64 in_syncs;
@@ -99,6 +100,8 @@ enum drm_panfrost_param {
   DRM_PANFROST_PARAM_NR_CORE_GROUPS,
   DRM_PANFROST_PARAM_THREAD_TLS_ALLOC,
   DRM_PANFROST_PARAM_AFBC_FEATURES,
+  DRM_PANFROST_PARAM_SYSTEM_TIMESTAMP,
+  DRM_PANFROST_PARAM_SYSTEM_TIMESTAMP_FREQUENCY,
 };
 struct drm_panfrost_get_param {
   __u32 param;
diff --git a/libc/kernel/uapi/drm/panthor_drm.h b/libc/kernel/uapi/drm/panthor_drm.h
index b45c1dccf..7c87cb8c3 100644
--- a/libc/kernel/uapi/drm/panthor_drm.h
+++ b/libc/kernel/uapi/drm/panthor_drm.h
@@ -64,6 +64,8 @@ struct drm_panthor_sync_op {
 enum drm_panthor_dev_query_type {
   DRM_PANTHOR_DEV_QUERY_GPU_INFO = 0,
   DRM_PANTHOR_DEV_QUERY_CSIF_INFO,
+  DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO,
+  DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO,
 };
 struct drm_panthor_gpu_info {
   __u32 gpu_id;
@@ -108,6 +110,15 @@ struct drm_panthor_csif_info {
   __u32 unpreserved_cs_reg_count;
   __u32 pad;
 };
+struct drm_panthor_timestamp_info {
+  __u64 timestamp_frequency;
+  __u64 current_timestamp;
+  __u64 timestamp_offset;
+};
+struct drm_panthor_group_priorities_info {
+  __u8 allowed_mask;
+  __u8 pad[3];
+};
 struct drm_panthor_dev_query {
   __u32 type;
   __u32 size;
@@ -179,6 +190,7 @@ enum drm_panthor_group_priority {
   PANTHOR_GROUP_PRIORITY_LOW = 0,
   PANTHOR_GROUP_PRIORITY_MEDIUM,
   PANTHOR_GROUP_PRIORITY_HIGH,
+  PANTHOR_GROUP_PRIORITY_REALTIME,
 };
 struct drm_panthor_group_create {
   struct drm_panthor_obj_array queues;
@@ -213,6 +225,7 @@ struct drm_panthor_group_submit {
 enum drm_panthor_group_state_flags {
   DRM_PANTHOR_GROUP_STATE_TIMEDOUT = 1 << 0,
   DRM_PANTHOR_GROUP_STATE_FATAL_FAULT = 1 << 1,
+  DRM_PANTHOR_GROUP_STATE_INNOCENT = 1 << 2,
 };
 struct drm_panthor_group_get_state {
   __u32 group_handle;
diff --git a/libc/kernel/uapi/drm/v3d_drm.h b/libc/kernel/uapi/drm/v3d_drm.h
index b7aca21d1..0c0911364 100644
--- a/libc/kernel/uapi/drm/v3d_drm.h
+++ b/libc/kernel/uapi/drm/v3d_drm.h
@@ -23,6 +23,7 @@ extern "C" {
 #define DRM_V3D_PERFMON_GET_VALUES 0x0a
 #define DRM_V3D_SUBMIT_CPU 0x0b
 #define DRM_V3D_PERFMON_GET_COUNTER 0x0c
+#define DRM_V3D_PERFMON_SET_GLOBAL 0x0d
 #define DRM_IOCTL_V3D_SUBMIT_CL DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CL, struct drm_v3d_submit_cl)
 #define DRM_IOCTL_V3D_WAIT_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_WAIT_BO, struct drm_v3d_wait_bo)
 #define DRM_IOCTL_V3D_CREATE_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_CREATE_BO, struct drm_v3d_create_bo)
@@ -36,6 +37,7 @@ extern "C" {
 #define DRM_IOCTL_V3D_PERFMON_GET_VALUES DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_VALUES, struct drm_v3d_perfmon_get_values)
 #define DRM_IOCTL_V3D_SUBMIT_CPU DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CPU, struct drm_v3d_submit_cpu)
 #define DRM_IOCTL_V3D_PERFMON_GET_COUNTER DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_COUNTER, struct drm_v3d_perfmon_get_counter)
+#define DRM_IOCTL_V3D_PERFMON_SET_GLOBAL DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_PERFMON_SET_GLOBAL, struct drm_v3d_perfmon_set_global)
 #define DRM_V3D_SUBMIT_CL_FLUSH_CACHE 0x01
 #define DRM_V3D_SUBMIT_EXTENSION 0x02
 struct drm_v3d_extension {
@@ -122,6 +124,7 @@ enum drm_v3d_param {
   DRM_V3D_PARAM_SUPPORTS_MULTISYNC_EXT,
   DRM_V3D_PARAM_SUPPORTS_CPU_QUEUE,
   DRM_V3D_PARAM_MAX_PERF_COUNTERS,
+  DRM_V3D_PARAM_SUPPORTS_SUPER_PAGES,
 };
 struct drm_v3d_get_param {
   __u32 param;
@@ -337,6 +340,11 @@ struct drm_v3d_perfmon_get_counter {
   __u8 description[DRM_V3D_PERFCNT_MAX_DESCRIPTION];
   __u8 reserved[7];
 };
+#define DRM_V3D_PERFMON_CLEAR_GLOBAL 0x0001
+struct drm_v3d_perfmon_set_global {
+  __u32 flags;
+  __u32 id;
+};
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/drm/xe_drm.h b/libc/kernel/uapi/drm/xe_drm.h
index 16bc3b3d5..46159e8fe 100644
--- a/libc/kernel/uapi/drm/xe_drm.h
+++ b/libc/kernel/uapi/drm/xe_drm.h
@@ -345,6 +345,9 @@ struct drm_xe_oa_unit {
   __u32 oa_unit_type;
   __u64 capabilities;
 #define DRM_XE_OA_CAPS_BASE (1 << 0)
+#define DRM_XE_OA_CAPS_SYNCS (1 << 1)
+#define DRM_XE_OA_CAPS_OA_BUFFER_SIZE (1 << 2)
+#define DRM_XE_OA_CAPS_WAIT_NUM_REPORTS (1 << 3)
   __u64 oa_timestamp_freq;
   __u64 reserved[4];
   __u64 num_engines;
@@ -379,6 +382,10 @@ enum drm_xe_oa_property_id {
   DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID,
   DRM_XE_OA_PROPERTY_OA_ENGINE_INSTANCE,
   DRM_XE_OA_PROPERTY_NO_PREEMPT,
+  DRM_XE_OA_PROPERTY_NUM_SYNCS,
+  DRM_XE_OA_PROPERTY_SYNCS,
+  DRM_XE_OA_PROPERTY_OA_BUFFER_SIZE,
+  DRM_XE_OA_PROPERTY_WAIT_NUM_REPORTS,
 };
 struct drm_xe_oa_config {
   __u64 extensions;
diff --git a/libc/kernel/uapi/linux/audit.h b/libc/kernel/uapi/linux/audit.h
index ae50fccf5..170b70de7 100644
--- a/libc/kernel/uapi/linux/audit.h
+++ b/libc/kernel/uapi/linux/audit.h
@@ -112,6 +112,7 @@
 #define AUDIT_INTEGRITY_RULE 1805
 #define AUDIT_INTEGRITY_EVM_XATTR 1806
 #define AUDIT_INTEGRITY_POLICY_RULE 1807
+#define AUDIT_INTEGRITY_USERSPACE 1808
 #define AUDIT_KERNEL 2000
 #define AUDIT_FILTER_USER 0x00
 #define AUDIT_FILTER_TASK 0x01
diff --git a/libc/kernel/uapi/linux/batadv_packet.h b/libc/kernel/uapi/linux/batadv_packet.h
index 83e5e71b0..3c5a8591d 100644
--- a/libc/kernel/uapi/linux/batadv_packet.h
+++ b/libc/kernel/uapi/linux/batadv_packet.h
@@ -8,6 +8,7 @@
 #define _UAPI_LINUX_BATADV_PACKET_H_
 #include <asm/byteorder.h>
 #include <linux/if_ether.h>
+#include <linux/stddef.h>
 #include <linux/types.h>
 #define batadv_tp_is_error(n) ((__u8) (n) > 127 ? 1 : 0)
 enum batadv_packettype {
@@ -252,16 +253,17 @@ struct batadv_tvlv_gateway_data {
   __be32 bandwidth_down;
   __be32 bandwidth_up;
 };
-struct batadv_tvlv_tt_data {
-  __u8 flags;
-  __u8 ttvn;
-  __be16 num_vlan;
-};
 struct batadv_tvlv_tt_vlan_data {
   __be32 crc;
   __be16 vid;
   __u16 reserved;
 };
+struct batadv_tvlv_tt_data {
+  __u8 flags;
+  __u8 ttvn;
+  __be16 num_vlan;
+  struct batadv_tvlv_tt_vlan_data vlan_data[] __counted_by_be(num_vlan);
+};
 struct batadv_tvlv_tt_change {
   __u8 flags;
   __u8 reserved[3];
diff --git a/libc/kernel/uapi/linux/blk-crypto.h b/libc/kernel/uapi/linux/blk-crypto.h
new file mode 100644
index 000000000..a4a48a222
--- /dev/null
+++ b/libc/kernel/uapi/linux/blk-crypto.h
@@ -0,0 +1,33 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_LINUX_BLK_CRYPTO_H
+#define _UAPI_LINUX_BLK_CRYPTO_H
+#include <linux/ioctl.h>
+#include <linux/types.h>
+struct blk_crypto_import_key_arg {
+  __u64 raw_key_ptr;
+  __u64 raw_key_size;
+  __u64 lt_key_ptr;
+  __u64 lt_key_size;
+  __u64 reserved[4];
+};
+struct blk_crypto_generate_key_arg {
+  __u64 lt_key_ptr;
+  __u64 lt_key_size;
+  __u64 reserved[4];
+};
+struct blk_crypto_prepare_key_arg {
+  __u64 lt_key_ptr;
+  __u64 lt_key_size;
+  __u64 eph_key_ptr;
+  __u64 eph_key_size;
+  __u64 reserved[4];
+};
+#define BLKCRYPTOIMPORTKEY _IOWR(0x12, 137, struct blk_crypto_import_key_arg)
+#define BLKCRYPTOGENERATEKEY _IOWR(0x12, 138, struct blk_crypto_generate_key_arg)
+#define BLKCRYPTOPREPAREKEY _IOWR(0x12, 139, struct blk_crypto_prepare_key_arg)
+#endif
diff --git a/libc/kernel/uapi/linux/bpf.h b/libc/kernel/uapi/linux/bpf.h
index c0d862d1a..66d81fc8a 100644
--- a/libc/kernel/uapi/linux/bpf.h
+++ b/libc/kernel/uapi/linux/bpf.h
@@ -273,6 +273,7 @@ enum bpf_attach_type {
   BPF_NETKIT_PRIMARY,
   BPF_NETKIT_PEER,
   BPF_TRACE_KPROBE_SESSION,
+  BPF_TRACE_UPROBE_SESSION,
   __MAX_BPF_ATTACH_TYPE
 };
 #define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
@@ -455,6 +456,7 @@ union bpf_attr {
     __u32 core_relo_rec_size;
     __u32 log_true_size;
     __s32 prog_token_fd;
+    __u32 fd_array_cnt;
   };
   struct {
     __aligned_u64 pathname;
diff --git a/libc/kernel/uapi/linux/btrfs.h b/libc/kernel/uapi/linux/btrfs.h
index a3ebc4fdd..30aca8e28 100644
--- a/libc/kernel/uapi/linux/btrfs.h
+++ b/libc/kernel/uapi/linux/btrfs.h
@@ -486,6 +486,16 @@ struct btrfs_ioctl_encoded_io_args {
 #define BTRFS_ENCODED_IO_COMPRESSION_TYPES 8
 #define BTRFS_ENCODED_IO_ENCRYPTION_NONE 0
 #define BTRFS_ENCODED_IO_ENCRYPTION_TYPES 1
+struct btrfs_ioctl_subvol_wait {
+  __u64 subvolid;
+  __u32 mode;
+  __u32 count;
+};
+#define BTRFS_SUBVOL_SYNC_WAIT_FOR_ONE (0)
+#define BTRFS_SUBVOL_SYNC_WAIT_FOR_QUEUED (1)
+#define BTRFS_SUBVOL_SYNC_COUNT (2)
+#define BTRFS_SUBVOL_SYNC_PEEK_FIRST (3)
+#define BTRFS_SUBVOL_SYNC_PEEK_LAST (4)
 enum btrfs_err_code {
   BTRFS_ERROR_DEV_RAID1_MIN_NOT_MET = 1,
   BTRFS_ERROR_DEV_RAID10_MIN_NOT_MET,
@@ -561,6 +571,7 @@ enum btrfs_err_code {
 #define BTRFS_IOC_SNAP_DESTROY_V2 _IOW(BTRFS_IOCTL_MAGIC, 63, struct btrfs_ioctl_vol_args_v2)
 #define BTRFS_IOC_ENCODED_READ _IOR(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
 #define BTRFS_IOC_ENCODED_WRITE _IOW(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
+#define BTRFS_IOC_SUBVOL_SYNC_WAIT _IOW(BTRFS_IOCTL_MAGIC, 65, struct btrfs_ioctl_subvol_wait)
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/linux/cryptouser.h b/libc/kernel/uapi/linux/cryptouser.h
index 9ffab6d33..eefd89752 100644
--- a/libc/kernel/uapi/linux/cryptouser.h
+++ b/libc/kernel/uapi/linux/cryptouser.h
@@ -43,6 +43,7 @@ enum crypto_attr_type_t {
   CRYPTOCFGA_STAT_AKCIPHER,
   CRYPTOCFGA_STAT_KPP,
   CRYPTOCFGA_STAT_ACOMP,
+  CRYPTOCFGA_REPORT_SIG,
   __CRYPTOCFGA_MAX
 #define CRYPTOCFGA_MAX (__CRYPTOCFGA_MAX - 1)
 };
@@ -157,5 +158,8 @@ struct crypto_report_kpp {
 struct crypto_report_acomp {
   char type[CRYPTO_MAX_NAME];
 };
+struct crypto_report_sig {
+  char type[CRYPTO_MAX_NAME];
+};
 #define CRYPTO_REPORT_MAXSIZE (sizeof(struct crypto_user_alg) + sizeof(struct crypto_report_blkcipher))
 #endif
diff --git a/libc/kernel/uapi/linux/dm-ioctl.h b/libc/kernel/uapi/linux/dm-ioctl.h
index f24b44103..b7a53dd5b 100644
--- a/libc/kernel/uapi/linux/dm-ioctl.h
+++ b/libc/kernel/uapi/linux/dm-ioctl.h
@@ -94,9 +94,9 @@ enum {
 #define DM_TARGET_MSG _IOWR(DM_IOCTL, DM_TARGET_MSG_CMD, struct dm_ioctl)
 #define DM_DEV_SET_GEOMETRY _IOWR(DM_IOCTL, DM_DEV_SET_GEOMETRY_CMD, struct dm_ioctl)
 #define DM_VERSION_MAJOR 4
-#define DM_VERSION_MINOR 48
+#define DM_VERSION_MINOR 49
 #define DM_VERSION_PATCHLEVEL 0
-#define DM_VERSION_EXTRA "-ioctl(2023-03-01)"
+#define DM_VERSION_EXTRA "-ioctl(2025-01-17)"
 #define DM_READONLY_FLAG (1 << 0)
 #define DM_SUSPEND_FLAG (1 << 1)
 #define DM_PERSISTENT_DEV_FLAG (1 << 3)
diff --git a/libc/kernel/uapi/linux/dpll.h b/libc/kernel/uapi/linux/dpll.h
index 7d6182bcb..276add049 100644
--- a/libc/kernel/uapi/linux/dpll.h
+++ b/libc/kernel/uapi/linux/dpll.h
@@ -30,6 +30,18 @@ enum dpll_lock_status_error {
   __DPLL_LOCK_STATUS_ERROR_MAX,
   DPLL_LOCK_STATUS_ERROR_MAX = (__DPLL_LOCK_STATUS_ERROR_MAX - 1)
 };
+enum dpll_clock_quality_level {
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC = 1,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC,
+  DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC,
+  __DPLL_CLOCK_QUALITY_LEVEL_MAX,
+  DPLL_CLOCK_QUALITY_LEVEL_MAX = (__DPLL_CLOCK_QUALITY_LEVEL_MAX - 1)
+};
 #define DPLL_TEMP_DIVIDER 1000
 enum dpll_type {
   DPLL_TYPE_PPS = 1,
@@ -80,6 +92,7 @@ enum dpll_a {
   DPLL_A_TEMP,
   DPLL_A_TYPE,
   DPLL_A_LOCK_STATUS_ERROR,
+  DPLL_A_CLOCK_QUALITY_LEVEL,
   __DPLL_A_MAX,
   DPLL_A_MAX = (__DPLL_A_MAX - 1)
 };
diff --git a/libc/kernel/uapi/linux/elf.h b/libc/kernel/uapi/linux/elf.h
index ea40103ae..89e11f969 100644
--- a/libc/kernel/uapi/linux/elf.h
+++ b/libc/kernel/uapi/linux/elf.h
@@ -361,6 +361,7 @@ typedef struct elf64_shdr {
 #define NT_ARM_ZT 0x40d
 #define NT_ARM_FPMR 0x40e
 #define NT_ARM_POE 0x40f
+#define NT_ARM_GCS 0x410
 #define NT_ARC_V2 0x600
 #define NT_VMCOREDD 0x700
 #define NT_MIPS_DSP 0x800
@@ -368,6 +369,7 @@ typedef struct elf64_shdr {
 #define NT_MIPS_MSA 0x802
 #define NT_RISCV_CSR 0x900
 #define NT_RISCV_VECTOR 0x901
+#define NT_RISCV_TAGGED_ADDR_CTRL 0x902
 #define NT_LOONGARCH_CPUCFG 0xa00
 #define NT_LOONGARCH_CSR 0xa01
 #define NT_LOONGARCH_LSX 0xa02
diff --git a/libc/kernel/uapi/linux/ethtool.h b/libc/kernel/uapi/linux/ethtool.h
index 323c4fcc0..d47e16e90 100644
--- a/libc/kernel/uapi/linux/ethtool.h
+++ b/libc/kernel/uapi/linux/ethtool.h
@@ -255,6 +255,8 @@ enum ethtool_stringset {
   ETH_SS_STATS_ETH_MAC,
   ETH_SS_STATS_ETH_CTRL,
   ETH_SS_STATS_RMON,
+  ETH_SS_STATS_PHY,
+  ETH_SS_TS_FLAGS,
   ETH_SS_COUNT
 };
 enum ethtool_mac_stats_src {
diff --git a/libc/kernel/uapi/linux/ethtool_netlink.h b/libc/kernel/uapi/linux/ethtool_netlink.h
index 7120c03eb..5944b35ea 100644
--- a/libc/kernel/uapi/linux/ethtool_netlink.h
+++ b/libc/kernel/uapi/linux/ethtool_netlink.h
@@ -7,404 +7,8 @@
 #ifndef _UAPI_LINUX_ETHTOOL_NETLINK_H_
 #define _UAPI_LINUX_ETHTOOL_NETLINK_H_
 #include <linux/ethtool.h>
-enum {
-  ETHTOOL_MSG_USER_NONE,
-  ETHTOOL_MSG_STRSET_GET,
-  ETHTOOL_MSG_LINKINFO_GET,
-  ETHTOOL_MSG_LINKINFO_SET,
-  ETHTOOL_MSG_LINKMODES_GET,
-  ETHTOOL_MSG_LINKMODES_SET,
-  ETHTOOL_MSG_LINKSTATE_GET,
-  ETHTOOL_MSG_DEBUG_GET,
-  ETHTOOL_MSG_DEBUG_SET,
-  ETHTOOL_MSG_WOL_GET,
-  ETHTOOL_MSG_WOL_SET,
-  ETHTOOL_MSG_FEATURES_GET,
-  ETHTOOL_MSG_FEATURES_SET,
-  ETHTOOL_MSG_PRIVFLAGS_GET,
-  ETHTOOL_MSG_PRIVFLAGS_SET,
-  ETHTOOL_MSG_RINGS_GET,
-  ETHTOOL_MSG_RINGS_SET,
-  ETHTOOL_MSG_CHANNELS_GET,
-  ETHTOOL_MSG_CHANNELS_SET,
-  ETHTOOL_MSG_COALESCE_GET,
-  ETHTOOL_MSG_COALESCE_SET,
-  ETHTOOL_MSG_PAUSE_GET,
-  ETHTOOL_MSG_PAUSE_SET,
-  ETHTOOL_MSG_EEE_GET,
-  ETHTOOL_MSG_EEE_SET,
-  ETHTOOL_MSG_TSINFO_GET,
-  ETHTOOL_MSG_CABLE_TEST_ACT,
-  ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
-  ETHTOOL_MSG_TUNNEL_INFO_GET,
-  ETHTOOL_MSG_FEC_GET,
-  ETHTOOL_MSG_FEC_SET,
-  ETHTOOL_MSG_MODULE_EEPROM_GET,
-  ETHTOOL_MSG_STATS_GET,
-  ETHTOOL_MSG_PHC_VCLOCKS_GET,
-  ETHTOOL_MSG_MODULE_GET,
-  ETHTOOL_MSG_MODULE_SET,
-  ETHTOOL_MSG_PSE_GET,
-  ETHTOOL_MSG_PSE_SET,
-  ETHTOOL_MSG_RSS_GET,
-  ETHTOOL_MSG_PLCA_GET_CFG,
-  ETHTOOL_MSG_PLCA_SET_CFG,
-  ETHTOOL_MSG_PLCA_GET_STATUS,
-  ETHTOOL_MSG_MM_GET,
-  ETHTOOL_MSG_MM_SET,
-  ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
-  ETHTOOL_MSG_PHY_GET,
-  __ETHTOOL_MSG_USER_CNT,
-  ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
-};
-enum {
-  ETHTOOL_MSG_KERNEL_NONE,
-  ETHTOOL_MSG_STRSET_GET_REPLY,
-  ETHTOOL_MSG_LINKINFO_GET_REPLY,
-  ETHTOOL_MSG_LINKINFO_NTF,
-  ETHTOOL_MSG_LINKMODES_GET_REPLY,
-  ETHTOOL_MSG_LINKMODES_NTF,
-  ETHTOOL_MSG_LINKSTATE_GET_REPLY,
-  ETHTOOL_MSG_DEBUG_GET_REPLY,
-  ETHTOOL_MSG_DEBUG_NTF,
-  ETHTOOL_MSG_WOL_GET_REPLY,
-  ETHTOOL_MSG_WOL_NTF,
-  ETHTOOL_MSG_FEATURES_GET_REPLY,
-  ETHTOOL_MSG_FEATURES_SET_REPLY,
-  ETHTOOL_MSG_FEATURES_NTF,
-  ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
-  ETHTOOL_MSG_PRIVFLAGS_NTF,
-  ETHTOOL_MSG_RINGS_GET_REPLY,
-  ETHTOOL_MSG_RINGS_NTF,
-  ETHTOOL_MSG_CHANNELS_GET_REPLY,
-  ETHTOOL_MSG_CHANNELS_NTF,
-  ETHTOOL_MSG_COALESCE_GET_REPLY,
-  ETHTOOL_MSG_COALESCE_NTF,
-  ETHTOOL_MSG_PAUSE_GET_REPLY,
-  ETHTOOL_MSG_PAUSE_NTF,
-  ETHTOOL_MSG_EEE_GET_REPLY,
-  ETHTOOL_MSG_EEE_NTF,
-  ETHTOOL_MSG_TSINFO_GET_REPLY,
-  ETHTOOL_MSG_CABLE_TEST_NTF,
-  ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
-  ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
-  ETHTOOL_MSG_FEC_GET_REPLY,
-  ETHTOOL_MSG_FEC_NTF,
-  ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
-  ETHTOOL_MSG_STATS_GET_REPLY,
-  ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
-  ETHTOOL_MSG_MODULE_GET_REPLY,
-  ETHTOOL_MSG_MODULE_NTF,
-  ETHTOOL_MSG_PSE_GET_REPLY,
-  ETHTOOL_MSG_RSS_GET_REPLY,
-  ETHTOOL_MSG_PLCA_GET_CFG_REPLY,
-  ETHTOOL_MSG_PLCA_GET_STATUS_REPLY,
-  ETHTOOL_MSG_PLCA_NTF,
-  ETHTOOL_MSG_MM_GET_REPLY,
-  ETHTOOL_MSG_MM_NTF,
-  ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
-  ETHTOOL_MSG_PHY_GET_REPLY,
-  ETHTOOL_MSG_PHY_NTF,
-  __ETHTOOL_MSG_KERNEL_CNT,
-  ETHTOOL_MSG_KERNEL_MAX = __ETHTOOL_MSG_KERNEL_CNT - 1
-};
-enum ethtool_header_flags {
-  ETHTOOL_FLAG_COMPACT_BITSETS = 1 << 0,
-  ETHTOOL_FLAG_OMIT_REPLY = 1 << 1,
-  ETHTOOL_FLAG_STATS = 1 << 2,
-};
+#include <linux/ethtool_netlink_generated.h>
 #define ETHTOOL_FLAG_ALL (ETHTOOL_FLAG_COMPACT_BITSETS | ETHTOOL_FLAG_OMIT_REPLY | ETHTOOL_FLAG_STATS)
-enum {
-  ETHTOOL_A_HEADER_UNSPEC,
-  ETHTOOL_A_HEADER_DEV_INDEX,
-  ETHTOOL_A_HEADER_DEV_NAME,
-  ETHTOOL_A_HEADER_FLAGS,
-  ETHTOOL_A_HEADER_PHY_INDEX,
-  __ETHTOOL_A_HEADER_CNT,
-  ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
-};
-enum {
-  ETHTOOL_A_BITSET_BIT_UNSPEC,
-  ETHTOOL_A_BITSET_BIT_INDEX,
-  ETHTOOL_A_BITSET_BIT_NAME,
-  ETHTOOL_A_BITSET_BIT_VALUE,
-  __ETHTOOL_A_BITSET_BIT_CNT,
-  ETHTOOL_A_BITSET_BIT_MAX = __ETHTOOL_A_BITSET_BIT_CNT - 1
-};
-enum {
-  ETHTOOL_A_BITSET_BITS_UNSPEC,
-  ETHTOOL_A_BITSET_BITS_BIT,
-  __ETHTOOL_A_BITSET_BITS_CNT,
-  ETHTOOL_A_BITSET_BITS_MAX = __ETHTOOL_A_BITSET_BITS_CNT - 1
-};
-enum {
-  ETHTOOL_A_BITSET_UNSPEC,
-  ETHTOOL_A_BITSET_NOMASK,
-  ETHTOOL_A_BITSET_SIZE,
-  ETHTOOL_A_BITSET_BITS,
-  ETHTOOL_A_BITSET_VALUE,
-  ETHTOOL_A_BITSET_MASK,
-  __ETHTOOL_A_BITSET_CNT,
-  ETHTOOL_A_BITSET_MAX = __ETHTOOL_A_BITSET_CNT - 1
-};
-enum {
-  ETHTOOL_A_STRING_UNSPEC,
-  ETHTOOL_A_STRING_INDEX,
-  ETHTOOL_A_STRING_VALUE,
-  __ETHTOOL_A_STRING_CNT,
-  ETHTOOL_A_STRING_MAX = __ETHTOOL_A_STRING_CNT - 1
-};
-enum {
-  ETHTOOL_A_STRINGS_UNSPEC,
-  ETHTOOL_A_STRINGS_STRING,
-  __ETHTOOL_A_STRINGS_CNT,
-  ETHTOOL_A_STRINGS_MAX = __ETHTOOL_A_STRINGS_CNT - 1
-};
-enum {
-  ETHTOOL_A_STRINGSET_UNSPEC,
-  ETHTOOL_A_STRINGSET_ID,
-  ETHTOOL_A_STRINGSET_COUNT,
-  ETHTOOL_A_STRINGSET_STRINGS,
-  __ETHTOOL_A_STRINGSET_CNT,
-  ETHTOOL_A_STRINGSET_MAX = __ETHTOOL_A_STRINGSET_CNT - 1
-};
-enum {
-  ETHTOOL_A_STRINGSETS_UNSPEC,
-  ETHTOOL_A_STRINGSETS_STRINGSET,
-  __ETHTOOL_A_STRINGSETS_CNT,
-  ETHTOOL_A_STRINGSETS_MAX = __ETHTOOL_A_STRINGSETS_CNT - 1
-};
-enum {
-  ETHTOOL_A_STRSET_UNSPEC,
-  ETHTOOL_A_STRSET_HEADER,
-  ETHTOOL_A_STRSET_STRINGSETS,
-  ETHTOOL_A_STRSET_COUNTS_ONLY,
-  __ETHTOOL_A_STRSET_CNT,
-  ETHTOOL_A_STRSET_MAX = __ETHTOOL_A_STRSET_CNT - 1
-};
-enum {
-  ETHTOOL_A_LINKINFO_UNSPEC,
-  ETHTOOL_A_LINKINFO_HEADER,
-  ETHTOOL_A_LINKINFO_PORT,
-  ETHTOOL_A_LINKINFO_PHYADDR,
-  ETHTOOL_A_LINKINFO_TP_MDIX,
-  ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
-  ETHTOOL_A_LINKINFO_TRANSCEIVER,
-  __ETHTOOL_A_LINKINFO_CNT,
-  ETHTOOL_A_LINKINFO_MAX = __ETHTOOL_A_LINKINFO_CNT - 1
-};
-enum {
-  ETHTOOL_A_LINKMODES_UNSPEC,
-  ETHTOOL_A_LINKMODES_HEADER,
-  ETHTOOL_A_LINKMODES_AUTONEG,
-  ETHTOOL_A_LINKMODES_OURS,
-  ETHTOOL_A_LINKMODES_PEER,
-  ETHTOOL_A_LINKMODES_SPEED,
-  ETHTOOL_A_LINKMODES_DUPLEX,
-  ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,
-  ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE,
-  ETHTOOL_A_LINKMODES_LANES,
-  ETHTOOL_A_LINKMODES_RATE_MATCHING,
-  __ETHTOOL_A_LINKMODES_CNT,
-  ETHTOOL_A_LINKMODES_MAX = __ETHTOOL_A_LINKMODES_CNT - 1
-};
-enum {
-  ETHTOOL_A_LINKSTATE_UNSPEC,
-  ETHTOOL_A_LINKSTATE_HEADER,
-  ETHTOOL_A_LINKSTATE_LINK,
-  ETHTOOL_A_LINKSTATE_SQI,
-  ETHTOOL_A_LINKSTATE_SQI_MAX,
-  ETHTOOL_A_LINKSTATE_EXT_STATE,
-  ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
-  ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
-  __ETHTOOL_A_LINKSTATE_CNT,
-  ETHTOOL_A_LINKSTATE_MAX = __ETHTOOL_A_LINKSTATE_CNT - 1
-};
-enum {
-  ETHTOOL_A_DEBUG_UNSPEC,
-  ETHTOOL_A_DEBUG_HEADER,
-  ETHTOOL_A_DEBUG_MSGMASK,
-  __ETHTOOL_A_DEBUG_CNT,
-  ETHTOOL_A_DEBUG_MAX = __ETHTOOL_A_DEBUG_CNT - 1
-};
-enum {
-  ETHTOOL_A_WOL_UNSPEC,
-  ETHTOOL_A_WOL_HEADER,
-  ETHTOOL_A_WOL_MODES,
-  ETHTOOL_A_WOL_SOPASS,
-  __ETHTOOL_A_WOL_CNT,
-  ETHTOOL_A_WOL_MAX = __ETHTOOL_A_WOL_CNT - 1
-};
-enum {
-  ETHTOOL_A_FEATURES_UNSPEC,
-  ETHTOOL_A_FEATURES_HEADER,
-  ETHTOOL_A_FEATURES_HW,
-  ETHTOOL_A_FEATURES_WANTED,
-  ETHTOOL_A_FEATURES_ACTIVE,
-  ETHTOOL_A_FEATURES_NOCHANGE,
-  __ETHTOOL_A_FEATURES_CNT,
-  ETHTOOL_A_FEATURES_MAX = __ETHTOOL_A_FEATURES_CNT - 1
-};
-enum {
-  ETHTOOL_A_PRIVFLAGS_UNSPEC,
-  ETHTOOL_A_PRIVFLAGS_HEADER,
-  ETHTOOL_A_PRIVFLAGS_FLAGS,
-  __ETHTOOL_A_PRIVFLAGS_CNT,
-  ETHTOOL_A_PRIVFLAGS_MAX = __ETHTOOL_A_PRIVFLAGS_CNT - 1
-};
-enum {
-  ETHTOOL_TCP_DATA_SPLIT_UNKNOWN = 0,
-  ETHTOOL_TCP_DATA_SPLIT_DISABLED,
-  ETHTOOL_TCP_DATA_SPLIT_ENABLED,
-};
-enum {
-  ETHTOOL_A_RINGS_UNSPEC,
-  ETHTOOL_A_RINGS_HEADER,
-  ETHTOOL_A_RINGS_RX_MAX,
-  ETHTOOL_A_RINGS_RX_MINI_MAX,
-  ETHTOOL_A_RINGS_RX_JUMBO_MAX,
-  ETHTOOL_A_RINGS_TX_MAX,
-  ETHTOOL_A_RINGS_RX,
-  ETHTOOL_A_RINGS_RX_MINI,
-  ETHTOOL_A_RINGS_RX_JUMBO,
-  ETHTOOL_A_RINGS_TX,
-  ETHTOOL_A_RINGS_RX_BUF_LEN,
-  ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
-  ETHTOOL_A_RINGS_CQE_SIZE,
-  ETHTOOL_A_RINGS_TX_PUSH,
-  ETHTOOL_A_RINGS_RX_PUSH,
-  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,
-  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,
-  __ETHTOOL_A_RINGS_CNT,
-  ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
-};
-enum {
-  ETHTOOL_A_CHANNELS_UNSPEC,
-  ETHTOOL_A_CHANNELS_HEADER,
-  ETHTOOL_A_CHANNELS_RX_MAX,
-  ETHTOOL_A_CHANNELS_TX_MAX,
-  ETHTOOL_A_CHANNELS_OTHER_MAX,
-  ETHTOOL_A_CHANNELS_COMBINED_MAX,
-  ETHTOOL_A_CHANNELS_RX_COUNT,
-  ETHTOOL_A_CHANNELS_TX_COUNT,
-  ETHTOOL_A_CHANNELS_OTHER_COUNT,
-  ETHTOOL_A_CHANNELS_COMBINED_COUNT,
-  __ETHTOOL_A_CHANNELS_CNT,
-  ETHTOOL_A_CHANNELS_MAX = (__ETHTOOL_A_CHANNELS_CNT - 1)
-};
-enum {
-  ETHTOOL_A_COALESCE_UNSPEC,
-  ETHTOOL_A_COALESCE_HEADER,
-  ETHTOOL_A_COALESCE_RX_USECS,
-  ETHTOOL_A_COALESCE_RX_MAX_FRAMES,
-  ETHTOOL_A_COALESCE_RX_USECS_IRQ,
-  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ,
-  ETHTOOL_A_COALESCE_TX_USECS,
-  ETHTOOL_A_COALESCE_TX_MAX_FRAMES,
-  ETHTOOL_A_COALESCE_TX_USECS_IRQ,
-  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ,
-  ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,
-  ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX,
-  ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX,
-  ETHTOOL_A_COALESCE_PKT_RATE_LOW,
-  ETHTOOL_A_COALESCE_RX_USECS_LOW,
-  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW,
-  ETHTOOL_A_COALESCE_TX_USECS_LOW,
-  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW,
-  ETHTOOL_A_COALESCE_PKT_RATE_HIGH,
-  ETHTOOL_A_COALESCE_RX_USECS_HIGH,
-  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH,
-  ETHTOOL_A_COALESCE_TX_USECS_HIGH,
-  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH,
-  ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,
-  ETHTOOL_A_COALESCE_USE_CQE_MODE_TX,
-  ETHTOOL_A_COALESCE_USE_CQE_MODE_RX,
-  ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,
-  ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,
-  ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,
-  ETHTOOL_A_COALESCE_RX_PROFILE,
-  ETHTOOL_A_COALESCE_TX_PROFILE,
-  __ETHTOOL_A_COALESCE_CNT,
-  ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_PROFILE_UNSPEC,
-  ETHTOOL_A_PROFILE_IRQ_MODERATION,
-  __ETHTOOL_A_PROFILE_CNT,
-  ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_IRQ_MODERATION_UNSPEC,
-  ETHTOOL_A_IRQ_MODERATION_USEC,
-  ETHTOOL_A_IRQ_MODERATION_PKTS,
-  ETHTOOL_A_IRQ_MODERATION_COMPS,
-  __ETHTOOL_A_IRQ_MODERATION_CNT,
-  ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
-};
-enum {
-  ETHTOOL_A_PAUSE_UNSPEC,
-  ETHTOOL_A_PAUSE_HEADER,
-  ETHTOOL_A_PAUSE_AUTONEG,
-  ETHTOOL_A_PAUSE_RX,
-  ETHTOOL_A_PAUSE_TX,
-  ETHTOOL_A_PAUSE_STATS,
-  ETHTOOL_A_PAUSE_STATS_SRC,
-  __ETHTOOL_A_PAUSE_CNT,
-  ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_PAUSE_STAT_UNSPEC,
-  ETHTOOL_A_PAUSE_STAT_PAD,
-  ETHTOOL_A_PAUSE_STAT_TX_FRAMES,
-  ETHTOOL_A_PAUSE_STAT_RX_FRAMES,
-  __ETHTOOL_A_PAUSE_STAT_CNT,
-  ETHTOOL_A_PAUSE_STAT_MAX = (__ETHTOOL_A_PAUSE_STAT_CNT - 1)
-};
-enum {
-  ETHTOOL_A_EEE_UNSPEC,
-  ETHTOOL_A_EEE_HEADER,
-  ETHTOOL_A_EEE_MODES_OURS,
-  ETHTOOL_A_EEE_MODES_PEER,
-  ETHTOOL_A_EEE_ACTIVE,
-  ETHTOOL_A_EEE_ENABLED,
-  ETHTOOL_A_EEE_TX_LPI_ENABLED,
-  ETHTOOL_A_EEE_TX_LPI_TIMER,
-  __ETHTOOL_A_EEE_CNT,
-  ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_TSINFO_UNSPEC,
-  ETHTOOL_A_TSINFO_HEADER,
-  ETHTOOL_A_TSINFO_TIMESTAMPING,
-  ETHTOOL_A_TSINFO_TX_TYPES,
-  ETHTOOL_A_TSINFO_RX_FILTERS,
-  ETHTOOL_A_TSINFO_PHC_INDEX,
-  ETHTOOL_A_TSINFO_STATS,
-  __ETHTOOL_A_TSINFO_CNT,
-  ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
-};
-enum {
-  ETHTOOL_A_TS_STAT_UNSPEC,
-  ETHTOOL_A_TS_STAT_TX_PKTS,
-  ETHTOOL_A_TS_STAT_TX_LOST,
-  ETHTOOL_A_TS_STAT_TX_ERR,
-  __ETHTOOL_A_TS_STAT_CNT,
-  ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
-};
-enum {
-  ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
-  ETHTOOL_A_PHC_VCLOCKS_HEADER,
-  ETHTOOL_A_PHC_VCLOCKS_NUM,
-  ETHTOOL_A_PHC_VCLOCKS_INDEX,
-  __ETHTOOL_A_PHC_VCLOCKS_CNT,
-  ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
-};
-enum {
-  ETHTOOL_A_CABLE_TEST_UNSPEC,
-  ETHTOOL_A_CABLE_TEST_HEADER,
-  __ETHTOOL_A_CABLE_TEST_CNT,
-  ETHTOOL_A_CABLE_TEST_MAX = __ETHTOOL_A_CABLE_TEST_CNT - 1
-};
 enum {
   ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,
   ETHTOOL_A_CABLE_RESULT_CODE_OK,
@@ -426,58 +30,11 @@ enum {
   ETHTOOL_A_CABLE_INF_SRC_TDR,
   ETHTOOL_A_CABLE_INF_SRC_ALCD,
 };
-enum {
-  ETHTOOL_A_CABLE_RESULT_UNSPEC,
-  ETHTOOL_A_CABLE_RESULT_PAIR,
-  ETHTOOL_A_CABLE_RESULT_CODE,
-  ETHTOOL_A_CABLE_RESULT_SRC,
-  __ETHTOOL_A_CABLE_RESULT_CNT,
-  ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
-};
-enum {
-  ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
-  ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
-  ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
-  ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
-  __ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
-  ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
-};
 enum {
   ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC,
   ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED,
   ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED
 };
-enum {
-  ETHTOOL_A_CABLE_NEST_UNSPEC,
-  ETHTOOL_A_CABLE_NEST_RESULT,
-  ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,
-  __ETHTOOL_A_CABLE_NEST_CNT,
-  ETHTOOL_A_CABLE_NEST_MAX = (__ETHTOOL_A_CABLE_NEST_CNT - 1)
-};
-enum {
-  ETHTOOL_A_CABLE_TEST_NTF_UNSPEC,
-  ETHTOOL_A_CABLE_TEST_NTF_HEADER,
-  ETHTOOL_A_CABLE_TEST_NTF_STATUS,
-  ETHTOOL_A_CABLE_TEST_NTF_NEST,
-  __ETHTOOL_A_CABLE_TEST_NTF_CNT,
-  ETHTOOL_A_CABLE_TEST_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_NTF_CNT - 1)
-};
-enum {
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR,
-  __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT - 1
-};
-enum {
-  ETHTOOL_A_CABLE_TEST_TDR_UNSPEC,
-  ETHTOOL_A_CABLE_TEST_TDR_HEADER,
-  ETHTOOL_A_CABLE_TEST_TDR_CFG,
-  __ETHTOOL_A_CABLE_TEST_TDR_CNT,
-  ETHTOOL_A_CABLE_TEST_TDR_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CNT - 1
-};
 enum {
   ETHTOOL_A_CABLE_AMPLITUDE_UNSPEC,
   ETHTOOL_A_CABLE_AMPLITUDE_PAIR,
@@ -507,110 +64,14 @@ enum {
   __ETHTOOL_A_CABLE_TDR_NEST_CNT,
   ETHTOOL_A_CABLE_TDR_NEST_MAX = (__ETHTOOL_A_CABLE_TDR_NEST_CNT - 1)
 };
-enum {
-  ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC,
-  ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER,
-  ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS,
-  ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,
-  __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT,
-  ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX = __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT - 1
-};
-enum {
-  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN,
-  ETHTOOL_UDP_TUNNEL_TYPE_GENEVE,
-  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE,
-  __ETHTOOL_UDP_TUNNEL_TYPE_CNT
-};
-enum {
-  ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC,
-  ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT,
-  ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE,
-  __ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT,
-  ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX = (__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT - 1)
-};
-enum {
-  ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC,
-  ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE,
-  ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES,
-  ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY,
-  __ETHTOOL_A_TUNNEL_UDP_TABLE_CNT,
-  ETHTOOL_A_TUNNEL_UDP_TABLE_MAX = (__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_TUNNEL_UDP_UNSPEC,
-  ETHTOOL_A_TUNNEL_UDP_TABLE,
-  __ETHTOOL_A_TUNNEL_UDP_CNT,
-  ETHTOOL_A_TUNNEL_UDP_MAX = (__ETHTOOL_A_TUNNEL_UDP_CNT - 1)
-};
-enum {
-  ETHTOOL_A_TUNNEL_INFO_UNSPEC,
-  ETHTOOL_A_TUNNEL_INFO_HEADER,
-  ETHTOOL_A_TUNNEL_INFO_UDP_PORTS,
-  __ETHTOOL_A_TUNNEL_INFO_CNT,
-  ETHTOOL_A_TUNNEL_INFO_MAX = (__ETHTOOL_A_TUNNEL_INFO_CNT - 1)
-};
-enum {
-  ETHTOOL_A_FEC_UNSPEC,
-  ETHTOOL_A_FEC_HEADER,
-  ETHTOOL_A_FEC_MODES,
-  ETHTOOL_A_FEC_AUTO,
-  ETHTOOL_A_FEC_ACTIVE,
-  ETHTOOL_A_FEC_STATS,
-  __ETHTOOL_A_FEC_CNT,
-  ETHTOOL_A_FEC_MAX = (__ETHTOOL_A_FEC_CNT - 1)
-};
-enum {
-  ETHTOOL_A_FEC_STAT_UNSPEC,
-  ETHTOOL_A_FEC_STAT_PAD,
-  ETHTOOL_A_FEC_STAT_CORRECTED,
-  ETHTOOL_A_FEC_STAT_UNCORR,
-  ETHTOOL_A_FEC_STAT_CORR_BITS,
-  __ETHTOOL_A_FEC_STAT_CNT,
-  ETHTOOL_A_FEC_STAT_MAX = (__ETHTOOL_A_FEC_STAT_CNT - 1)
-};
-enum {
-  ETHTOOL_A_MODULE_EEPROM_UNSPEC,
-  ETHTOOL_A_MODULE_EEPROM_HEADER,
-  ETHTOOL_A_MODULE_EEPROM_OFFSET,
-  ETHTOOL_A_MODULE_EEPROM_LENGTH,
-  ETHTOOL_A_MODULE_EEPROM_PAGE,
-  ETHTOOL_A_MODULE_EEPROM_BANK,
-  ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS,
-  ETHTOOL_A_MODULE_EEPROM_DATA,
-  __ETHTOOL_A_MODULE_EEPROM_CNT,
-  ETHTOOL_A_MODULE_EEPROM_MAX = (__ETHTOOL_A_MODULE_EEPROM_CNT - 1)
-};
-enum {
-  ETHTOOL_A_STATS_UNSPEC,
-  ETHTOOL_A_STATS_PAD,
-  ETHTOOL_A_STATS_HEADER,
-  ETHTOOL_A_STATS_GROUPS,
-  ETHTOOL_A_STATS_GRP,
-  ETHTOOL_A_STATS_SRC,
-  __ETHTOOL_A_STATS_CNT,
-  ETHTOOL_A_STATS_MAX = (__ETHTOOL_A_STATS_CNT - 1)
-};
 enum {
   ETHTOOL_STATS_ETH_PHY,
   ETHTOOL_STATS_ETH_MAC,
   ETHTOOL_STATS_ETH_CTRL,
   ETHTOOL_STATS_RMON,
+  ETHTOOL_STATS_PHY,
   __ETHTOOL_STATS_CNT
 };
-enum {
-  ETHTOOL_A_STATS_GRP_UNSPEC,
-  ETHTOOL_A_STATS_GRP_PAD,
-  ETHTOOL_A_STATS_GRP_ID,
-  ETHTOOL_A_STATS_GRP_SS_ID,
-  ETHTOOL_A_STATS_GRP_STAT,
-  ETHTOOL_A_STATS_GRP_HIST_RX,
-  ETHTOOL_A_STATS_GRP_HIST_TX,
-  ETHTOOL_A_STATS_GRP_HIST_BKT_LOW,
-  ETHTOOL_A_STATS_GRP_HIST_BKT_HI,
-  ETHTOOL_A_STATS_GRP_HIST_VAL,
-  __ETHTOOL_A_STATS_GRP_CNT,
-  ETHTOOL_A_STATS_GRP_MAX = (__ETHTOOL_A_STATS_GRP_CNT - 1)
-};
 enum {
   ETHTOOL_A_STATS_ETH_PHY_5_SYM_ERR,
   __ETHTOOL_A_STATS_ETH_PHY_CNT,
@@ -658,114 +119,14 @@ enum {
   ETHTOOL_A_STATS_RMON_MAX = (__ETHTOOL_A_STATS_RMON_CNT - 1)
 };
 enum {
-  ETHTOOL_A_MODULE_UNSPEC,
-  ETHTOOL_A_MODULE_HEADER,
-  ETHTOOL_A_MODULE_POWER_MODE_POLICY,
-  ETHTOOL_A_MODULE_POWER_MODE,
-  __ETHTOOL_A_MODULE_CNT,
-  ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
-  ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,
-  ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,
-};
-enum {
-  ETHTOOL_A_PSE_UNSPEC,
-  ETHTOOL_A_PSE_HEADER,
-  ETHTOOL_A_PODL_PSE_ADMIN_STATE,
-  ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,
-  ETHTOOL_A_PODL_PSE_PW_D_STATUS,
-  ETHTOOL_A_C33_PSE_ADMIN_STATE,
-  ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
-  ETHTOOL_A_C33_PSE_PW_D_STATUS,
-  ETHTOOL_A_C33_PSE_PW_CLASS,
-  ETHTOOL_A_C33_PSE_ACTUAL_PW,
-  ETHTOOL_A_C33_PSE_EXT_STATE,
-  ETHTOOL_A_C33_PSE_EXT_SUBSTATE,
-  ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
-  ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,
-  __ETHTOOL_A_PSE_CNT,
-  ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
-};
-enum {
-  ETHTOOL_A_RSS_UNSPEC,
-  ETHTOOL_A_RSS_HEADER,
-  ETHTOOL_A_RSS_CONTEXT,
-  ETHTOOL_A_RSS_HFUNC,
-  ETHTOOL_A_RSS_INDIR,
-  ETHTOOL_A_RSS_HKEY,
-  ETHTOOL_A_RSS_INPUT_XFRM,
-  ETHTOOL_A_RSS_START_CONTEXT,
-  __ETHTOOL_A_RSS_CNT,
-  ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
-};
-enum {
-  ETHTOOL_A_PLCA_UNSPEC,
-  ETHTOOL_A_PLCA_HEADER,
-  ETHTOOL_A_PLCA_VERSION,
-  ETHTOOL_A_PLCA_ENABLED,
-  ETHTOOL_A_PLCA_STATUS,
-  ETHTOOL_A_PLCA_NODE_CNT,
-  ETHTOOL_A_PLCA_NODE_ID,
-  ETHTOOL_A_PLCA_TO_TMR,
-  ETHTOOL_A_PLCA_BURST_CNT,
-  ETHTOOL_A_PLCA_BURST_TMR,
-  __ETHTOOL_A_PLCA_CNT,
-  ETHTOOL_A_PLCA_MAX = (__ETHTOOL_A_PLCA_CNT - 1)
-};
-enum {
-  ETHTOOL_A_MM_STAT_UNSPEC,
-  ETHTOOL_A_MM_STAT_PAD,
-  ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,
-  ETHTOOL_A_MM_STAT_SMD_ERRORS,
-  ETHTOOL_A_MM_STAT_REASSEMBLY_OK,
-  ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,
-  ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,
-  ETHTOOL_A_MM_STAT_HOLD_COUNT,
-  __ETHTOOL_A_MM_STAT_CNT,
-  ETHTOOL_A_MM_STAT_MAX = (__ETHTOOL_A_MM_STAT_CNT - 1)
-};
-enum {
-  ETHTOOL_A_MM_UNSPEC,
-  ETHTOOL_A_MM_HEADER,
-  ETHTOOL_A_MM_PMAC_ENABLED,
-  ETHTOOL_A_MM_TX_ENABLED,
-  ETHTOOL_A_MM_TX_ACTIVE,
-  ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,
-  ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,
-  ETHTOOL_A_MM_VERIFY_ENABLED,
-  ETHTOOL_A_MM_VERIFY_STATUS,
-  ETHTOOL_A_MM_VERIFY_TIME,
-  ETHTOOL_A_MM_MAX_VERIFY_TIME,
-  ETHTOOL_A_MM_STATS,
-  __ETHTOOL_A_MM_CNT,
-  ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
-};
-enum {
-  ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
-  ETHTOOL_A_MODULE_FW_FLASH_HEADER,
-  ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
-  ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
-  ETHTOOL_A_MODULE_FW_FLASH_STATUS,
-  ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,
-  ETHTOOL_A_MODULE_FW_FLASH_DONE,
-  ETHTOOL_A_MODULE_FW_FLASH_TOTAL,
-  __ETHTOOL_A_MODULE_FW_FLASH_CNT,
-  ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
-};
-enum {
-  ETHTOOL_A_PHY_UNSPEC,
-  ETHTOOL_A_PHY_HEADER,
-  ETHTOOL_A_PHY_INDEX,
-  ETHTOOL_A_PHY_DRVNAME,
-  ETHTOOL_A_PHY_NAME,
-  ETHTOOL_A_PHY_UPSTREAM_TYPE,
-  ETHTOOL_A_PHY_UPSTREAM_INDEX,
-  ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,
-  ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,
-  __ETHTOOL_A_PHY_CNT,
-  ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+  ETHTOOL_A_STATS_PHY_RX_PKTS,
+  ETHTOOL_A_STATS_PHY_RX_BYTES,
+  ETHTOOL_A_STATS_PHY_RX_ERRORS,
+  ETHTOOL_A_STATS_PHY_TX_PKTS,
+  ETHTOOL_A_STATS_PHY_TX_BYTES,
+  ETHTOOL_A_STATS_PHY_TX_ERRORS,
+  __ETHTOOL_A_STATS_PHY_CNT,
+  ETHTOOL_A_STATS_PHY_MAX = (__ETHTOOL_A_STATS_PHY_CNT - 1)
 };
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
diff --git a/libc/kernel/uapi/linux/ethtool_netlink_generated.h b/libc/kernel/uapi/linux/ethtool_netlink_generated.h
new file mode 100644
index 000000000..789886fc1
--- /dev/null
+++ b/libc/kernel/uapi/linux/ethtool_netlink_generated.h
@@ -0,0 +1,694 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_LINUX_ETHTOOL_NETLINK_GENERATED_H
+#define _UAPI_LINUX_ETHTOOL_NETLINK_GENERATED_H
+#define ETHTOOL_FAMILY_NAME "ethtool"
+#define ETHTOOL_FAMILY_VERSION 1
+enum {
+  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN,
+  ETHTOOL_UDP_TUNNEL_TYPE_GENEVE,
+  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE,
+  __ETHTOOL_UDP_TUNNEL_TYPE_CNT,
+  ETHTOOL_UDP_TUNNEL_TYPE_MAX = (__ETHTOOL_UDP_TUNNEL_TYPE_CNT - 1)
+};
+enum ethtool_header_flags {
+  ETHTOOL_FLAG_COMPACT_BITSETS = 1,
+  ETHTOOL_FLAG_OMIT_REPLY = 2,
+  ETHTOOL_FLAG_STATS = 4,
+};
+enum {
+  ETHTOOL_PHY_UPSTREAM_TYPE_MAC,
+  ETHTOOL_PHY_UPSTREAM_TYPE_PHY,
+};
+enum ethtool_tcp_data_split {
+  ETHTOOL_TCP_DATA_SPLIT_UNKNOWN,
+  ETHTOOL_TCP_DATA_SPLIT_DISABLED,
+  ETHTOOL_TCP_DATA_SPLIT_ENABLED,
+};
+enum {
+  ETHTOOL_A_HEADER_UNSPEC,
+  ETHTOOL_A_HEADER_DEV_INDEX,
+  ETHTOOL_A_HEADER_DEV_NAME,
+  ETHTOOL_A_HEADER_FLAGS,
+  ETHTOOL_A_HEADER_PHY_INDEX,
+  __ETHTOOL_A_HEADER_CNT,
+  ETHTOOL_A_HEADER_MAX = (__ETHTOOL_A_HEADER_CNT - 1)
+};
+enum {
+  ETHTOOL_A_BITSET_BIT_UNSPEC,
+  ETHTOOL_A_BITSET_BIT_INDEX,
+  ETHTOOL_A_BITSET_BIT_NAME,
+  ETHTOOL_A_BITSET_BIT_VALUE,
+  __ETHTOOL_A_BITSET_BIT_CNT,
+  ETHTOOL_A_BITSET_BIT_MAX = (__ETHTOOL_A_BITSET_BIT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_BITSET_BITS_UNSPEC,
+  ETHTOOL_A_BITSET_BITS_BIT,
+  __ETHTOOL_A_BITSET_BITS_CNT,
+  ETHTOOL_A_BITSET_BITS_MAX = (__ETHTOOL_A_BITSET_BITS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_BITSET_UNSPEC,
+  ETHTOOL_A_BITSET_NOMASK,
+  ETHTOOL_A_BITSET_SIZE,
+  ETHTOOL_A_BITSET_BITS,
+  ETHTOOL_A_BITSET_VALUE,
+  ETHTOOL_A_BITSET_MASK,
+  __ETHTOOL_A_BITSET_CNT,
+  ETHTOOL_A_BITSET_MAX = (__ETHTOOL_A_BITSET_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STRING_UNSPEC,
+  ETHTOOL_A_STRING_INDEX,
+  ETHTOOL_A_STRING_VALUE,
+  __ETHTOOL_A_STRING_CNT,
+  ETHTOOL_A_STRING_MAX = (__ETHTOOL_A_STRING_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STRINGS_UNSPEC,
+  ETHTOOL_A_STRINGS_STRING,
+  __ETHTOOL_A_STRINGS_CNT,
+  ETHTOOL_A_STRINGS_MAX = (__ETHTOOL_A_STRINGS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STRINGSET_UNSPEC,
+  ETHTOOL_A_STRINGSET_ID,
+  ETHTOOL_A_STRINGSET_COUNT,
+  ETHTOOL_A_STRINGSET_STRINGS,
+  __ETHTOOL_A_STRINGSET_CNT,
+  ETHTOOL_A_STRINGSET_MAX = (__ETHTOOL_A_STRINGSET_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STRINGSETS_UNSPEC,
+  ETHTOOL_A_STRINGSETS_STRINGSET,
+  __ETHTOOL_A_STRINGSETS_CNT,
+  ETHTOOL_A_STRINGSETS_MAX = (__ETHTOOL_A_STRINGSETS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STRSET_UNSPEC,
+  ETHTOOL_A_STRSET_HEADER,
+  ETHTOOL_A_STRSET_STRINGSETS,
+  ETHTOOL_A_STRSET_COUNTS_ONLY,
+  __ETHTOOL_A_STRSET_CNT,
+  ETHTOOL_A_STRSET_MAX = (__ETHTOOL_A_STRSET_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PRIVFLAGS_UNSPEC,
+  ETHTOOL_A_PRIVFLAGS_HEADER,
+  ETHTOOL_A_PRIVFLAGS_FLAGS,
+  __ETHTOOL_A_PRIVFLAGS_CNT,
+  ETHTOOL_A_PRIVFLAGS_MAX = (__ETHTOOL_A_PRIVFLAGS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_RINGS_UNSPEC,
+  ETHTOOL_A_RINGS_HEADER,
+  ETHTOOL_A_RINGS_RX_MAX,
+  ETHTOOL_A_RINGS_RX_MINI_MAX,
+  ETHTOOL_A_RINGS_RX_JUMBO_MAX,
+  ETHTOOL_A_RINGS_TX_MAX,
+  ETHTOOL_A_RINGS_RX,
+  ETHTOOL_A_RINGS_RX_MINI,
+  ETHTOOL_A_RINGS_RX_JUMBO,
+  ETHTOOL_A_RINGS_TX,
+  ETHTOOL_A_RINGS_RX_BUF_LEN,
+  ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
+  ETHTOOL_A_RINGS_CQE_SIZE,
+  ETHTOOL_A_RINGS_TX_PUSH,
+  ETHTOOL_A_RINGS_RX_PUSH,
+  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,
+  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,
+  ETHTOOL_A_RINGS_HDS_THRESH,
+  ETHTOOL_A_RINGS_HDS_THRESH_MAX,
+  __ETHTOOL_A_RINGS_CNT,
+  ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_MM_STAT_UNSPEC,
+  ETHTOOL_A_MM_STAT_PAD,
+  ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,
+  ETHTOOL_A_MM_STAT_SMD_ERRORS,
+  ETHTOOL_A_MM_STAT_REASSEMBLY_OK,
+  ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,
+  ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,
+  ETHTOOL_A_MM_STAT_HOLD_COUNT,
+  __ETHTOOL_A_MM_STAT_CNT,
+  ETHTOOL_A_MM_STAT_MAX = (__ETHTOOL_A_MM_STAT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_MM_UNSPEC,
+  ETHTOOL_A_MM_HEADER,
+  ETHTOOL_A_MM_PMAC_ENABLED,
+  ETHTOOL_A_MM_TX_ENABLED,
+  ETHTOOL_A_MM_TX_ACTIVE,
+  ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,
+  ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,
+  ETHTOOL_A_MM_VERIFY_ENABLED,
+  ETHTOOL_A_MM_VERIFY_STATUS,
+  ETHTOOL_A_MM_VERIFY_TIME,
+  ETHTOOL_A_MM_MAX_VERIFY_TIME,
+  ETHTOOL_A_MM_STATS,
+  __ETHTOOL_A_MM_CNT,
+  ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
+};
+enum {
+  ETHTOOL_A_LINKINFO_UNSPEC,
+  ETHTOOL_A_LINKINFO_HEADER,
+  ETHTOOL_A_LINKINFO_PORT,
+  ETHTOOL_A_LINKINFO_PHYADDR,
+  ETHTOOL_A_LINKINFO_TP_MDIX,
+  ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
+  ETHTOOL_A_LINKINFO_TRANSCEIVER,
+  __ETHTOOL_A_LINKINFO_CNT,
+  ETHTOOL_A_LINKINFO_MAX = (__ETHTOOL_A_LINKINFO_CNT - 1)
+};
+enum {
+  ETHTOOL_A_LINKMODES_UNSPEC,
+  ETHTOOL_A_LINKMODES_HEADER,
+  ETHTOOL_A_LINKMODES_AUTONEG,
+  ETHTOOL_A_LINKMODES_OURS,
+  ETHTOOL_A_LINKMODES_PEER,
+  ETHTOOL_A_LINKMODES_SPEED,
+  ETHTOOL_A_LINKMODES_DUPLEX,
+  ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,
+  ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE,
+  ETHTOOL_A_LINKMODES_LANES,
+  ETHTOOL_A_LINKMODES_RATE_MATCHING,
+  __ETHTOOL_A_LINKMODES_CNT,
+  ETHTOOL_A_LINKMODES_MAX = (__ETHTOOL_A_LINKMODES_CNT - 1)
+};
+enum {
+  ETHTOOL_A_LINKSTATE_UNSPEC,
+  ETHTOOL_A_LINKSTATE_HEADER,
+  ETHTOOL_A_LINKSTATE_LINK,
+  ETHTOOL_A_LINKSTATE_SQI,
+  ETHTOOL_A_LINKSTATE_SQI_MAX,
+  ETHTOOL_A_LINKSTATE_EXT_STATE,
+  ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
+  ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
+  __ETHTOOL_A_LINKSTATE_CNT,
+  ETHTOOL_A_LINKSTATE_MAX = (__ETHTOOL_A_LINKSTATE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_DEBUG_UNSPEC,
+  ETHTOOL_A_DEBUG_HEADER,
+  ETHTOOL_A_DEBUG_MSGMASK,
+  __ETHTOOL_A_DEBUG_CNT,
+  ETHTOOL_A_DEBUG_MAX = (__ETHTOOL_A_DEBUG_CNT - 1)
+};
+enum {
+  ETHTOOL_A_WOL_UNSPEC,
+  ETHTOOL_A_WOL_HEADER,
+  ETHTOOL_A_WOL_MODES,
+  ETHTOOL_A_WOL_SOPASS,
+  __ETHTOOL_A_WOL_CNT,
+  ETHTOOL_A_WOL_MAX = (__ETHTOOL_A_WOL_CNT - 1)
+};
+enum {
+  ETHTOOL_A_FEATURES_UNSPEC,
+  ETHTOOL_A_FEATURES_HEADER,
+  ETHTOOL_A_FEATURES_HW,
+  ETHTOOL_A_FEATURES_WANTED,
+  ETHTOOL_A_FEATURES_ACTIVE,
+  ETHTOOL_A_FEATURES_NOCHANGE,
+  __ETHTOOL_A_FEATURES_CNT,
+  ETHTOOL_A_FEATURES_MAX = (__ETHTOOL_A_FEATURES_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CHANNELS_UNSPEC,
+  ETHTOOL_A_CHANNELS_HEADER,
+  ETHTOOL_A_CHANNELS_RX_MAX,
+  ETHTOOL_A_CHANNELS_TX_MAX,
+  ETHTOOL_A_CHANNELS_OTHER_MAX,
+  ETHTOOL_A_CHANNELS_COMBINED_MAX,
+  ETHTOOL_A_CHANNELS_RX_COUNT,
+  ETHTOOL_A_CHANNELS_TX_COUNT,
+  ETHTOOL_A_CHANNELS_OTHER_COUNT,
+  ETHTOOL_A_CHANNELS_COMBINED_COUNT,
+  __ETHTOOL_A_CHANNELS_CNT,
+  ETHTOOL_A_CHANNELS_MAX = (__ETHTOOL_A_CHANNELS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_IRQ_MODERATION_UNSPEC,
+  ETHTOOL_A_IRQ_MODERATION_USEC,
+  ETHTOOL_A_IRQ_MODERATION_PKTS,
+  ETHTOOL_A_IRQ_MODERATION_COMPS,
+  __ETHTOOL_A_IRQ_MODERATION_CNT,
+  ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PROFILE_UNSPEC,
+  ETHTOOL_A_PROFILE_IRQ_MODERATION,
+  __ETHTOOL_A_PROFILE_CNT,
+  ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_COALESCE_UNSPEC,
+  ETHTOOL_A_COALESCE_HEADER,
+  ETHTOOL_A_COALESCE_RX_USECS,
+  ETHTOOL_A_COALESCE_RX_MAX_FRAMES,
+  ETHTOOL_A_COALESCE_RX_USECS_IRQ,
+  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ,
+  ETHTOOL_A_COALESCE_TX_USECS,
+  ETHTOOL_A_COALESCE_TX_MAX_FRAMES,
+  ETHTOOL_A_COALESCE_TX_USECS_IRQ,
+  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ,
+  ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,
+  ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX,
+  ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX,
+  ETHTOOL_A_COALESCE_PKT_RATE_LOW,
+  ETHTOOL_A_COALESCE_RX_USECS_LOW,
+  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW,
+  ETHTOOL_A_COALESCE_TX_USECS_LOW,
+  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW,
+  ETHTOOL_A_COALESCE_PKT_RATE_HIGH,
+  ETHTOOL_A_COALESCE_RX_USECS_HIGH,
+  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH,
+  ETHTOOL_A_COALESCE_TX_USECS_HIGH,
+  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH,
+  ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,
+  ETHTOOL_A_COALESCE_USE_CQE_MODE_TX,
+  ETHTOOL_A_COALESCE_USE_CQE_MODE_RX,
+  ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,
+  ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,
+  ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,
+  ETHTOOL_A_COALESCE_RX_PROFILE,
+  ETHTOOL_A_COALESCE_TX_PROFILE,
+  __ETHTOOL_A_COALESCE_CNT,
+  ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PAUSE_STAT_UNSPEC,
+  ETHTOOL_A_PAUSE_STAT_PAD,
+  ETHTOOL_A_PAUSE_STAT_TX_FRAMES,
+  ETHTOOL_A_PAUSE_STAT_RX_FRAMES,
+  __ETHTOOL_A_PAUSE_STAT_CNT,
+  ETHTOOL_A_PAUSE_STAT_MAX = (__ETHTOOL_A_PAUSE_STAT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PAUSE_UNSPEC,
+  ETHTOOL_A_PAUSE_HEADER,
+  ETHTOOL_A_PAUSE_AUTONEG,
+  ETHTOOL_A_PAUSE_RX,
+  ETHTOOL_A_PAUSE_TX,
+  ETHTOOL_A_PAUSE_STATS,
+  ETHTOOL_A_PAUSE_STATS_SRC,
+  __ETHTOOL_A_PAUSE_CNT,
+  ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_EEE_UNSPEC,
+  ETHTOOL_A_EEE_HEADER,
+  ETHTOOL_A_EEE_MODES_OURS,
+  ETHTOOL_A_EEE_MODES_PEER,
+  ETHTOOL_A_EEE_ACTIVE,
+  ETHTOOL_A_EEE_ENABLED,
+  ETHTOOL_A_EEE_TX_LPI_ENABLED,
+  ETHTOOL_A_EEE_TX_LPI_TIMER,
+  __ETHTOOL_A_EEE_CNT,
+  ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TS_STAT_UNSPEC,
+  ETHTOOL_A_TS_STAT_TX_PKTS,
+  ETHTOOL_A_TS_STAT_TX_LOST,
+  ETHTOOL_A_TS_STAT_TX_ERR,
+  ETHTOOL_A_TS_STAT_TX_ONESTEP_PKTS_UNCONFIRMED,
+  __ETHTOOL_A_TS_STAT_CNT,
+  ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TS_HWTSTAMP_PROVIDER_UNSPEC,
+  ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,
+  ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,
+  __ETHTOOL_A_TS_HWTSTAMP_PROVIDER_CNT,
+  ETHTOOL_A_TS_HWTSTAMP_PROVIDER_MAX = (__ETHTOOL_A_TS_HWTSTAMP_PROVIDER_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TSINFO_UNSPEC,
+  ETHTOOL_A_TSINFO_HEADER,
+  ETHTOOL_A_TSINFO_TIMESTAMPING,
+  ETHTOOL_A_TSINFO_TX_TYPES,
+  ETHTOOL_A_TSINFO_RX_FILTERS,
+  ETHTOOL_A_TSINFO_PHC_INDEX,
+  ETHTOOL_A_TSINFO_STATS,
+  ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER,
+  __ETHTOOL_A_TSINFO_CNT,
+  ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_RESULT_UNSPEC,
+  ETHTOOL_A_CABLE_RESULT_PAIR,
+  ETHTOOL_A_CABLE_RESULT_CODE,
+  ETHTOOL_A_CABLE_RESULT_SRC,
+  __ETHTOOL_A_CABLE_RESULT_CNT,
+  ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
+  ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
+  ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
+  ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
+  __ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
+  ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_NEST_UNSPEC,
+  ETHTOOL_A_CABLE_NEST_RESULT,
+  ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,
+  __ETHTOOL_A_CABLE_NEST_CNT,
+  ETHTOOL_A_CABLE_NEST_MAX = (__ETHTOOL_A_CABLE_NEST_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_TEST_UNSPEC,
+  ETHTOOL_A_CABLE_TEST_HEADER,
+  __ETHTOOL_A_CABLE_TEST_CNT,
+  ETHTOOL_A_CABLE_TEST_MAX = (__ETHTOOL_A_CABLE_TEST_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_TEST_NTF_UNSPEC,
+  ETHTOOL_A_CABLE_TEST_NTF_HEADER,
+  ETHTOOL_A_CABLE_TEST_NTF_STATUS,
+  ETHTOOL_A_CABLE_TEST_NTF_NEST,
+  __ETHTOOL_A_CABLE_TEST_NTF_CNT,
+  ETHTOOL_A_CABLE_TEST_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_NTF_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR,
+  __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC,
+  ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER,
+  ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS,
+  ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,
+  __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT,
+  ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT - 1)
+};
+enum {
+  ETHTOOL_A_CABLE_TEST_TDR_UNSPEC,
+  ETHTOOL_A_CABLE_TEST_TDR_HEADER,
+  ETHTOOL_A_CABLE_TEST_TDR_CFG,
+  __ETHTOOL_A_CABLE_TEST_TDR_CNT,
+  ETHTOOL_A_CABLE_TEST_TDR_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC,
+  ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT,
+  ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE,
+  __ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT,
+  ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX = (__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC,
+  ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE,
+  ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES,
+  ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY,
+  __ETHTOOL_A_TUNNEL_UDP_TABLE_CNT,
+  ETHTOOL_A_TUNNEL_UDP_TABLE_MAX = (__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TUNNEL_UDP_UNSPEC,
+  ETHTOOL_A_TUNNEL_UDP_TABLE,
+  __ETHTOOL_A_TUNNEL_UDP_CNT,
+  ETHTOOL_A_TUNNEL_UDP_MAX = (__ETHTOOL_A_TUNNEL_UDP_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TUNNEL_INFO_UNSPEC,
+  ETHTOOL_A_TUNNEL_INFO_HEADER,
+  ETHTOOL_A_TUNNEL_INFO_UDP_PORTS,
+  __ETHTOOL_A_TUNNEL_INFO_CNT,
+  ETHTOOL_A_TUNNEL_INFO_MAX = (__ETHTOOL_A_TUNNEL_INFO_CNT - 1)
+};
+enum {
+  ETHTOOL_A_FEC_STAT_UNSPEC,
+  ETHTOOL_A_FEC_STAT_PAD,
+  ETHTOOL_A_FEC_STAT_CORRECTED,
+  ETHTOOL_A_FEC_STAT_UNCORR,
+  ETHTOOL_A_FEC_STAT_CORR_BITS,
+  __ETHTOOL_A_FEC_STAT_CNT,
+  ETHTOOL_A_FEC_STAT_MAX = (__ETHTOOL_A_FEC_STAT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_FEC_UNSPEC,
+  ETHTOOL_A_FEC_HEADER,
+  ETHTOOL_A_FEC_MODES,
+  ETHTOOL_A_FEC_AUTO,
+  ETHTOOL_A_FEC_ACTIVE,
+  ETHTOOL_A_FEC_STATS,
+  __ETHTOOL_A_FEC_CNT,
+  ETHTOOL_A_FEC_MAX = (__ETHTOOL_A_FEC_CNT - 1)
+};
+enum {
+  ETHTOOL_A_MODULE_EEPROM_UNSPEC,
+  ETHTOOL_A_MODULE_EEPROM_HEADER,
+  ETHTOOL_A_MODULE_EEPROM_OFFSET,
+  ETHTOOL_A_MODULE_EEPROM_LENGTH,
+  ETHTOOL_A_MODULE_EEPROM_PAGE,
+  ETHTOOL_A_MODULE_EEPROM_BANK,
+  ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS,
+  ETHTOOL_A_MODULE_EEPROM_DATA,
+  __ETHTOOL_A_MODULE_EEPROM_CNT,
+  ETHTOOL_A_MODULE_EEPROM_MAX = (__ETHTOOL_A_MODULE_EEPROM_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STATS_GRP_UNSPEC,
+  ETHTOOL_A_STATS_GRP_PAD,
+  ETHTOOL_A_STATS_GRP_ID,
+  ETHTOOL_A_STATS_GRP_SS_ID,
+  ETHTOOL_A_STATS_GRP_STAT,
+  ETHTOOL_A_STATS_GRP_HIST_RX,
+  ETHTOOL_A_STATS_GRP_HIST_TX,
+  ETHTOOL_A_STATS_GRP_HIST_BKT_LOW,
+  ETHTOOL_A_STATS_GRP_HIST_BKT_HI,
+  ETHTOOL_A_STATS_GRP_HIST_VAL,
+  __ETHTOOL_A_STATS_GRP_CNT,
+  ETHTOOL_A_STATS_GRP_MAX = (__ETHTOOL_A_STATS_GRP_CNT - 1)
+};
+enum {
+  ETHTOOL_A_STATS_UNSPEC,
+  ETHTOOL_A_STATS_PAD,
+  ETHTOOL_A_STATS_HEADER,
+  ETHTOOL_A_STATS_GROUPS,
+  ETHTOOL_A_STATS_GRP,
+  ETHTOOL_A_STATS_SRC,
+  __ETHTOOL_A_STATS_CNT,
+  ETHTOOL_A_STATS_MAX = (__ETHTOOL_A_STATS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
+  ETHTOOL_A_PHC_VCLOCKS_HEADER,
+  ETHTOOL_A_PHC_VCLOCKS_NUM,
+  ETHTOOL_A_PHC_VCLOCKS_INDEX,
+  __ETHTOOL_A_PHC_VCLOCKS_CNT,
+  ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_MODULE_UNSPEC,
+  ETHTOOL_A_MODULE_HEADER,
+  ETHTOOL_A_MODULE_POWER_MODE_POLICY,
+  ETHTOOL_A_MODULE_POWER_MODE,
+  __ETHTOOL_A_MODULE_CNT,
+  ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,
+  __ETHTOOL_A_C33_PSE_PW_LIMIT_CNT,
+  __ETHTOOL_A_C33_PSE_PW_LIMIT_MAX = (__ETHTOOL_A_C33_PSE_PW_LIMIT_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PSE_UNSPEC,
+  ETHTOOL_A_PSE_HEADER,
+  ETHTOOL_A_PODL_PSE_ADMIN_STATE,
+  ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,
+  ETHTOOL_A_PODL_PSE_PW_D_STATUS,
+  ETHTOOL_A_C33_PSE_ADMIN_STATE,
+  ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
+  ETHTOOL_A_C33_PSE_PW_D_STATUS,
+  ETHTOOL_A_C33_PSE_PW_CLASS,
+  ETHTOOL_A_C33_PSE_ACTUAL_PW,
+  ETHTOOL_A_C33_PSE_EXT_STATE,
+  ETHTOOL_A_C33_PSE_EXT_SUBSTATE,
+  ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,
+  __ETHTOOL_A_PSE_CNT,
+  ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_RSS_UNSPEC,
+  ETHTOOL_A_RSS_HEADER,
+  ETHTOOL_A_RSS_CONTEXT,
+  ETHTOOL_A_RSS_HFUNC,
+  ETHTOOL_A_RSS_INDIR,
+  ETHTOOL_A_RSS_HKEY,
+  ETHTOOL_A_RSS_INPUT_XFRM,
+  ETHTOOL_A_RSS_START_CONTEXT,
+  __ETHTOOL_A_RSS_CNT,
+  ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PLCA_UNSPEC,
+  ETHTOOL_A_PLCA_HEADER,
+  ETHTOOL_A_PLCA_VERSION,
+  ETHTOOL_A_PLCA_ENABLED,
+  ETHTOOL_A_PLCA_STATUS,
+  ETHTOOL_A_PLCA_NODE_CNT,
+  ETHTOOL_A_PLCA_NODE_ID,
+  ETHTOOL_A_PLCA_TO_TMR,
+  ETHTOOL_A_PLCA_BURST_CNT,
+  ETHTOOL_A_PLCA_BURST_TMR,
+  __ETHTOOL_A_PLCA_CNT,
+  ETHTOOL_A_PLCA_MAX = (__ETHTOOL_A_PLCA_CNT - 1)
+};
+enum {
+  ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
+  ETHTOOL_A_MODULE_FW_FLASH_HEADER,
+  ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
+  ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
+  ETHTOOL_A_MODULE_FW_FLASH_STATUS,
+  ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,
+  ETHTOOL_A_MODULE_FW_FLASH_DONE,
+  ETHTOOL_A_MODULE_FW_FLASH_TOTAL,
+  __ETHTOOL_A_MODULE_FW_FLASH_CNT,
+  ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
+};
+enum {
+  ETHTOOL_A_PHY_UNSPEC,
+  ETHTOOL_A_PHY_HEADER,
+  ETHTOOL_A_PHY_INDEX,
+  ETHTOOL_A_PHY_DRVNAME,
+  ETHTOOL_A_PHY_NAME,
+  ETHTOOL_A_PHY_UPSTREAM_TYPE,
+  ETHTOOL_A_PHY_UPSTREAM_INDEX,
+  ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,
+  ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,
+  __ETHTOOL_A_PHY_CNT,
+  ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+};
+enum {
+  ETHTOOL_A_TSCONFIG_UNSPEC,
+  ETHTOOL_A_TSCONFIG_HEADER,
+  ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER,
+  ETHTOOL_A_TSCONFIG_TX_TYPES,
+  ETHTOOL_A_TSCONFIG_RX_FILTERS,
+  ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS,
+  __ETHTOOL_A_TSCONFIG_CNT,
+  ETHTOOL_A_TSCONFIG_MAX = (__ETHTOOL_A_TSCONFIG_CNT - 1)
+};
+enum {
+  ETHTOOL_MSG_USER_NONE = 0,
+  ETHTOOL_MSG_STRSET_GET = 1,
+  ETHTOOL_MSG_LINKINFO_GET,
+  ETHTOOL_MSG_LINKINFO_SET,
+  ETHTOOL_MSG_LINKMODES_GET,
+  ETHTOOL_MSG_LINKMODES_SET,
+  ETHTOOL_MSG_LINKSTATE_GET,
+  ETHTOOL_MSG_DEBUG_GET,
+  ETHTOOL_MSG_DEBUG_SET,
+  ETHTOOL_MSG_WOL_GET,
+  ETHTOOL_MSG_WOL_SET,
+  ETHTOOL_MSG_FEATURES_GET,
+  ETHTOOL_MSG_FEATURES_SET,
+  ETHTOOL_MSG_PRIVFLAGS_GET,
+  ETHTOOL_MSG_PRIVFLAGS_SET,
+  ETHTOOL_MSG_RINGS_GET,
+  ETHTOOL_MSG_RINGS_SET,
+  ETHTOOL_MSG_CHANNELS_GET,
+  ETHTOOL_MSG_CHANNELS_SET,
+  ETHTOOL_MSG_COALESCE_GET,
+  ETHTOOL_MSG_COALESCE_SET,
+  ETHTOOL_MSG_PAUSE_GET,
+  ETHTOOL_MSG_PAUSE_SET,
+  ETHTOOL_MSG_EEE_GET,
+  ETHTOOL_MSG_EEE_SET,
+  ETHTOOL_MSG_TSINFO_GET,
+  ETHTOOL_MSG_CABLE_TEST_ACT,
+  ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
+  ETHTOOL_MSG_TUNNEL_INFO_GET,
+  ETHTOOL_MSG_FEC_GET,
+  ETHTOOL_MSG_FEC_SET,
+  ETHTOOL_MSG_MODULE_EEPROM_GET,
+  ETHTOOL_MSG_STATS_GET,
+  ETHTOOL_MSG_PHC_VCLOCKS_GET,
+  ETHTOOL_MSG_MODULE_GET,
+  ETHTOOL_MSG_MODULE_SET,
+  ETHTOOL_MSG_PSE_GET,
+  ETHTOOL_MSG_PSE_SET,
+  ETHTOOL_MSG_RSS_GET,
+  ETHTOOL_MSG_PLCA_GET_CFG,
+  ETHTOOL_MSG_PLCA_SET_CFG,
+  ETHTOOL_MSG_PLCA_GET_STATUS,
+  ETHTOOL_MSG_MM_GET,
+  ETHTOOL_MSG_MM_SET,
+  ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+  ETHTOOL_MSG_PHY_GET,
+  ETHTOOL_MSG_TSCONFIG_GET,
+  ETHTOOL_MSG_TSCONFIG_SET,
+  __ETHTOOL_MSG_USER_CNT,
+  ETHTOOL_MSG_USER_MAX = (__ETHTOOL_MSG_USER_CNT - 1)
+};
+enum {
+  ETHTOOL_MSG_KERNEL_NONE = 0,
+  ETHTOOL_MSG_STRSET_GET_REPLY = 1,
+  ETHTOOL_MSG_LINKINFO_GET_REPLY,
+  ETHTOOL_MSG_LINKINFO_NTF,
+  ETHTOOL_MSG_LINKMODES_GET_REPLY,
+  ETHTOOL_MSG_LINKMODES_NTF,
+  ETHTOOL_MSG_LINKSTATE_GET_REPLY,
+  ETHTOOL_MSG_DEBUG_GET_REPLY,
+  ETHTOOL_MSG_DEBUG_NTF,
+  ETHTOOL_MSG_WOL_GET_REPLY,
+  ETHTOOL_MSG_WOL_NTF,
+  ETHTOOL_MSG_FEATURES_GET_REPLY,
+  ETHTOOL_MSG_FEATURES_SET_REPLY,
+  ETHTOOL_MSG_FEATURES_NTF,
+  ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
+  ETHTOOL_MSG_PRIVFLAGS_NTF,
+  ETHTOOL_MSG_RINGS_GET_REPLY,
+  ETHTOOL_MSG_RINGS_NTF,
+  ETHTOOL_MSG_CHANNELS_GET_REPLY,
+  ETHTOOL_MSG_CHANNELS_NTF,
+  ETHTOOL_MSG_COALESCE_GET_REPLY,
+  ETHTOOL_MSG_COALESCE_NTF,
+  ETHTOOL_MSG_PAUSE_GET_REPLY,
+  ETHTOOL_MSG_PAUSE_NTF,
+  ETHTOOL_MSG_EEE_GET_REPLY,
+  ETHTOOL_MSG_EEE_NTF,
+  ETHTOOL_MSG_TSINFO_GET_REPLY,
+  ETHTOOL_MSG_CABLE_TEST_NTF,
+  ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
+  ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
+  ETHTOOL_MSG_FEC_GET_REPLY,
+  ETHTOOL_MSG_FEC_NTF,
+  ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
+  ETHTOOL_MSG_STATS_GET_REPLY,
+  ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
+  ETHTOOL_MSG_MODULE_GET_REPLY,
+  ETHTOOL_MSG_MODULE_NTF,
+  ETHTOOL_MSG_PSE_GET_REPLY,
+  ETHTOOL_MSG_RSS_GET_REPLY,
+  ETHTOOL_MSG_PLCA_GET_CFG_REPLY,
+  ETHTOOL_MSG_PLCA_GET_STATUS_REPLY,
+  ETHTOOL_MSG_PLCA_NTF,
+  ETHTOOL_MSG_MM_GET_REPLY,
+  ETHTOOL_MSG_MM_NTF,
+  ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
+  ETHTOOL_MSG_PHY_GET_REPLY,
+  ETHTOOL_MSG_PHY_NTF,
+  ETHTOOL_MSG_TSCONFIG_GET_REPLY,
+  ETHTOOL_MSG_TSCONFIG_SET_REPLY,
+  __ETHTOOL_MSG_KERNEL_CNT,
+  ETHTOOL_MSG_KERNEL_MAX = (__ETHTOOL_MSG_KERNEL_CNT - 1)
+};
+#endif
diff --git a/libc/kernel/uapi/linux/f2fs.h b/libc/kernel/uapi/linux/f2fs.h
index c4c8a6558..ca250faa2 100644
--- a/libc/kernel/uapi/linux/f2fs.h
+++ b/libc/kernel/uapi/linux/f2fs.h
@@ -34,6 +34,7 @@
 #define F2FS_IOC_DECOMPRESS_FILE _IO(F2FS_IOCTL_MAGIC, 23)
 #define F2FS_IOC_COMPRESS_FILE _IO(F2FS_IOCTL_MAGIC, 24)
 #define F2FS_IOC_START_ATOMIC_REPLACE _IO(F2FS_IOCTL_MAGIC, 25)
+#define F2FS_IOC_GET_DEV_ALIAS_FILE _IOR(F2FS_IOCTL_MAGIC, 26, __u32)
 #define F2FS_IOC_SHUTDOWN _IOR('X', 125, __u32)
 #define F2FS_GOING_DOWN_FULLSYNC 0x0
 #define F2FS_GOING_DOWN_METASYNC 0x1
diff --git a/libc/kernel/uapi/linux/fanotify.h b/libc/kernel/uapi/linux/fanotify.h
index 8a5a4f0a7..cdf190254 100644
--- a/libc/kernel/uapi/linux/fanotify.h
+++ b/libc/kernel/uapi/linux/fanotify.h
@@ -25,6 +25,7 @@
 #define FAN_OPEN_PERM 0x00010000
 #define FAN_ACCESS_PERM 0x00020000
 #define FAN_OPEN_EXEC_PERM 0x00040000
+#define FAN_PRE_ACCESS 0x00100000
 #define FAN_EVENT_ON_CHILD 0x08000000
 #define FAN_RENAME 0x10000000
 #define FAN_ONDIR 0x40000000
@@ -45,6 +46,7 @@
 #define FAN_REPORT_DIR_FID 0x00000400
 #define FAN_REPORT_NAME 0x00000800
 #define FAN_REPORT_TARGET_FID 0x00001000
+#define FAN_REPORT_FD_ERROR 0x00002000
 #define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
 #define FAN_REPORT_DFID_NAME_TARGET (FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID)
 #define FAN_ALL_INIT_FLAGS (FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS)
@@ -80,6 +82,7 @@ struct fanotify_event_metadata {
 #define FAN_EVENT_INFO_TYPE_DFID 3
 #define FAN_EVENT_INFO_TYPE_PIDFD 4
 #define FAN_EVENT_INFO_TYPE_ERROR 5
+#define FAN_EVENT_INFO_TYPE_RANGE 6
 #define FAN_EVENT_INFO_TYPE_OLD_DFID_NAME 10
 #define FAN_EVENT_INFO_TYPE_NEW_DFID_NAME 12
 struct fanotify_event_info_header {
@@ -101,6 +104,12 @@ struct fanotify_event_info_error {
   __s32 error;
   __u32 error_count;
 };
+struct fanotify_event_info_range {
+  struct fanotify_event_info_header hdr;
+  __u32 pad;
+  __u64 offset;
+  __u64 count;
+};
 #define FAN_RESPONSE_INFO_NONE 0
 #define FAN_RESPONSE_INFO_AUDIT_RULE 1
 struct fanotify_response {
@@ -120,6 +129,10 @@ struct fanotify_response_info_audit_rule {
 };
 #define FAN_ALLOW 0x01
 #define FAN_DENY 0x02
+#define FAN_ERRNO_BITS 8
+#define FAN_ERRNO_SHIFT (32 - FAN_ERRNO_BITS)
+#define FAN_ERRNO_MASK ((1 << FAN_ERRNO_BITS) - 1)
+#define FAN_DENY_ERRNO(err) (FAN_DENY | ((((__u32) (err)) & FAN_ERRNO_MASK) << FAN_ERRNO_SHIFT))
 #define FAN_AUDIT 0x10
 #define FAN_INFO 0x20
 #define FAN_NOFD - 1
diff --git a/libc/kernel/uapi/linux/fcntl.h b/libc/kernel/uapi/linux/fcntl.h
index 22ca65dc9..d83322b6d 100644
--- a/libc/kernel/uapi/linux/fcntl.h
+++ b/libc/kernel/uapi/linux/fcntl.h
@@ -60,4 +60,6 @@
 #define AT_REMOVEDIR 0x200
 #define AT_HANDLE_FID 0x200
 #define AT_HANDLE_MNT_ID_UNIQUE 0x001
+#define AT_HANDLE_CONNECTABLE 0x002
+#define AT_EXECVE_CHECK 0x10000
 #endif
diff --git a/libc/kernel/uapi/linux/fib_rules.h b/libc/kernel/uapi/linux/fib_rules.h
index 339ccceee..b33ac01e5 100644
--- a/libc/kernel/uapi/linux/fib_rules.h
+++ b/libc/kernel/uapi/linux/fib_rules.h
@@ -62,6 +62,8 @@ enum {
   FRA_SPORT_RANGE,
   FRA_DPORT_RANGE,
   FRA_DSCP,
+  FRA_FLOWLABEL,
+  FRA_FLOWLABEL_MASK,
   __FRA_MAX
 };
 #define FRA_MAX (__FRA_MAX - 1)
diff --git a/libc/kernel/uapi/linux/fs.h b/libc/kernel/uapi/linux/fs.h
index adab56f86..64f8a3eca 100644
--- a/libc/kernel/uapi/linux/fs.h
+++ b/libc/kernel/uapi/linux/fs.h
@@ -16,6 +16,10 @@
 #define INR_OPEN_MAX 4096
 #define BLOCK_SIZE_BITS 10
 #define BLOCK_SIZE (1 << BLOCK_SIZE_BITS)
+#define IO_INTEGRITY_CHK_GUARD (1U << 0)
+#define IO_INTEGRITY_CHK_REFTAG (1U << 1)
+#define IO_INTEGRITY_CHK_APPTAG (1U << 2)
+#define IO_INTEGRITY_VALID_FLAGS (IO_INTEGRITY_CHK_GUARD | IO_INTEGRITY_CHK_REFTAG | IO_INTEGRITY_CHK_APPTAG)
 #define SEEK_SET 0
 #define SEEK_CUR 1
 #define SEEK_END 2
@@ -195,7 +199,8 @@ typedef int __bitwise __kernel_rwf_t;
 #define RWF_APPEND (( __kernel_rwf_t) 0x00000010)
 #define RWF_NOAPPEND (( __kernel_rwf_t) 0x00000020)
 #define RWF_ATOMIC (( __kernel_rwf_t) 0x00000040)
-#define RWF_SUPPORTED (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC)
+#define RWF_DONTCACHE (( __kernel_rwf_t) 0x00000080)
+#define RWF_SUPPORTED (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC | RWF_DONTCACHE)
 #define PROCFS_IOCTL_MAGIC 'f'
 #define PAGEMAP_SCAN _IOWR(PROCFS_IOCTL_MAGIC, 16, struct pm_scan_arg)
 #define PAGE_IS_WPALLOWED (1 << 0)
diff --git a/libc/kernel/uapi/linux/fscrypt.h b/libc/kernel/uapi/linux/fscrypt.h
index 9a53f4cb1..79c5292f9 100644
--- a/libc/kernel/uapi/linux/fscrypt.h
+++ b/libc/kernel/uapi/linux/fscrypt.h
@@ -73,14 +73,16 @@ struct fscrypt_key_specifier {
 };
 struct fscrypt_provisioning_key_payload {
   __u32 type;
-  __u32 __reserved;
+  __u32 flags;
   __u8 raw[];
 };
 struct fscrypt_add_key_arg {
   struct fscrypt_key_specifier key_spec;
   __u32 raw_size;
   __u32 key_id;
-  __u32 __reserved[7];
+#define FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED 0x00000001
+  __u32 flags;
+  __u32 __reserved[6];
 #define __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED 0x00000001
   __u32 __flags;
   __u8 raw[];
diff --git a/libc/kernel/uapi/linux/fuse.h b/libc/kernel/uapi/linux/fuse.h
index c1d64ce01..ea9b91560 100644
--- a/libc/kernel/uapi/linux/fuse.h
+++ b/libc/kernel/uapi/linux/fuse.h
@@ -8,7 +8,7 @@
 #define _LINUX_FUSE_H
 #include <stdint.h>
 #define FUSE_KERNEL_VERSION 7
-#define FUSE_KERNEL_MINOR_VERSION 41
+#define FUSE_KERNEL_MINOR_VERSION 42
 #define FUSE_ROOT_ID 1
 struct fuse_attr {
   uint64_t ino;
@@ -136,6 +136,7 @@ struct fuse_file_lock {
 #define FUSE_HAS_RESEND (1ULL << 39)
 #define FUSE_DIRECT_IO_RELAX FUSE_DIRECT_IO_ALLOW_MMAP
 #define FUSE_ALLOW_IDMAP (1ULL << 40)
+#define FUSE_OVER_IO_URING (1ULL << 41)
 #define CUSE_UNRESTRICTED_IOCTL (1 << 0)
 #define FUSE_RELEASE_FLUSH (1 << 0)
 #define FUSE_RELEASE_FLOCK_UNLOCK (1 << 1)
@@ -633,4 +634,29 @@ struct fuse_supp_groups {
   uint32_t nr_groups;
   uint32_t groups[];
 };
+#define FUSE_URING_IN_OUT_HEADER_SZ 128
+#define FUSE_URING_OP_IN_OUT_SZ 128
+struct fuse_uring_ent_in_out {
+  uint64_t flags;
+  uint64_t commit_id;
+  uint32_t payload_sz;
+  uint32_t padding;
+  uint64_t reserved;
+};
+struct fuse_uring_req_header {
+  char in_out[FUSE_URING_IN_OUT_HEADER_SZ];
+  char op_in[FUSE_URING_OP_IN_OUT_SZ];
+  struct fuse_uring_ent_in_out ring_ent_in_out;
+};
+enum fuse_uring_cmd {
+  FUSE_IO_URING_CMD_INVALID = 0,
+  FUSE_IO_URING_CMD_REGISTER = 1,
+  FUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2,
+};
+struct fuse_uring_cmd_req {
+  uint64_t flags;
+  uint64_t commit_id;
+  uint16_t qid;
+  uint8_t padding[6];
+};
 #endif
diff --git a/libc/kernel/uapi/linux/if_link.h b/libc/kernel/uapi/linux/if_link.h
index c2483a20c..8e6d03a7d 100644
--- a/libc/kernel/uapi/linux/if_link.h
+++ b/libc/kernel/uapi/linux/if_link.h
@@ -158,6 +158,7 @@ enum {
   IFLA_GSO_IPV4_MAX_SIZE,
   IFLA_GRO_IPV4_MAX_SIZE,
   IFLA_DPLL_PIN,
+  IFLA_MAX_PACING_OFFLOAD_HORIZON,
   __IFLA_MAX
 };
 #define IFLA_MAX (__IFLA_MAX - 1)
@@ -461,6 +462,10 @@ enum netkit_mode {
   NETKIT_L2,
   NETKIT_L3,
 };
+enum netkit_scrub {
+  NETKIT_SCRUB_NONE,
+  NETKIT_SCRUB_DEFAULT,
+};
 enum {
   IFLA_NETKIT_UNSPEC,
   IFLA_NETKIT_PEER_INFO,
@@ -468,6 +473,10 @@ enum {
   IFLA_NETKIT_POLICY,
   IFLA_NETKIT_PEER_POLICY,
   IFLA_NETKIT_MODE,
+  IFLA_NETKIT_SCRUB,
+  IFLA_NETKIT_PEER_SCRUB,
+  IFLA_NETKIT_HEADROOM,
+  IFLA_NETKIT_TAILROOM,
   __IFLA_NETKIT_MAX,
 };
 #define IFLA_NETKIT_MAX (__IFLA_NETKIT_MAX - 1)
@@ -537,6 +546,7 @@ enum {
   IFLA_VXLAN_VNIFILTER,
   IFLA_VXLAN_LOCALBYPASS,
   IFLA_VXLAN_LABEL_POLICY,
+  IFLA_VXLAN_RESERVED_BITS,
   __IFLA_VXLAN_MAX
 };
 #define IFLA_VXLAN_MAX (__IFLA_VXLAN_MAX - 1)
@@ -968,6 +978,7 @@ struct ifla_rmnet_flags {
 enum {
   IFLA_MCTP_UNSPEC,
   IFLA_MCTP_NET,
+  IFLA_MCTP_PHYS_BINDING,
   __IFLA_MCTP_MAX,
 };
 #define IFLA_MCTP_MAX (__IFLA_MCTP_MAX - 1)
diff --git a/libc/kernel/uapi/linux/iio/types.h b/libc/kernel/uapi/linux/iio/types.h
index f40cb95ba..5e873296f 100644
--- a/libc/kernel/uapi/linux/iio/types.h
+++ b/libc/kernel/uapi/linux/iio/types.h
@@ -46,6 +46,7 @@ enum iio_chan_type {
   IIO_DELTA_VELOCITY,
   IIO_COLORTEMP,
   IIO_CHROMATICITY,
+  IIO_ATTENTION,
 };
 enum iio_modifier {
   IIO_NO_MOD,
diff --git a/libc/kernel/uapi/linux/in.h b/libc/kernel/uapi/linux/in.h
index 97bf4930c..e128d1bd4 100644
--- a/libc/kernel/uapi/linux/in.h
+++ b/libc/kernel/uapi/linux/in.h
@@ -67,6 +67,8 @@ enum {
 #define IPPROTO_MPLS IPPROTO_MPLS
   IPPROTO_ETHERNET = 143,
 #define IPPROTO_ETHERNET IPPROTO_ETHERNET
+  IPPROTO_AGGFRAG = 144,
+#define IPPROTO_AGGFRAG IPPROTO_AGGFRAG
   IPPROTO_RAW = 255,
 #define IPPROTO_RAW IPPROTO_RAW
   IPPROTO_SMC = 256,
diff --git a/libc/kernel/uapi/linux/input-event-codes.h b/libc/kernel/uapi/linux/input-event-codes.h
index 4f93d5ece..238df6647 100644
--- a/libc/kernel/uapi/linux/input-event-codes.h
+++ b/libc/kernel/uapi/linux/input-event-codes.h
@@ -455,6 +455,7 @@
 #define KEY_NOTIFICATION_CENTER 0x1bc
 #define KEY_PICKUP_PHONE 0x1bd
 #define KEY_HANGUP_PHONE 0x1be
+#define KEY_LINK_PHONE 0x1bf
 #define KEY_DEL_EOL 0x1c0
 #define KEY_DEL_EOS 0x1c1
 #define KEY_INS_LINE 0x1c2
diff --git a/libc/kernel/uapi/linux/io_uring.h b/libc/kernel/uapi/linux/io_uring.h
index 5564bff00..8f699c361 100644
--- a/libc/kernel/uapi/linux/io_uring.h
+++ b/libc/kernel/uapi/linux/io_uring.h
@@ -81,10 +81,23 @@ struct io_uring_sqe {
       __u64 addr3;
       __u64 __pad2[1];
     };
+    struct {
+      __u64 attr_ptr;
+      __u64 attr_type_mask;
+    };
     __u64 optval;
     __u8 cmd[0];
   };
 };
+#define IORING_RW_ATTR_FLAG_PI (1U << 0)
+struct io_uring_attr_pi {
+  __u16 flags;
+  __u16 app_tag;
+  __u32 len;
+  __u64 addr;
+  __u64 seed;
+  __u64 rsvd;
+};
 #define IORING_FILE_INDEX_ALLOC (~0U)
 enum io_uring_sqe_flags_bit {
   IOSQE_FIXED_FILE_BIT,
@@ -119,6 +132,7 @@ enum io_uring_sqe_flags_bit {
 #define IORING_SETUP_NO_MMAP (1U << 14)
 #define IORING_SETUP_REGISTERED_FD_ONLY (1U << 15)
 #define IORING_SETUP_NO_SQARRAY (1U << 16)
+#define IORING_SETUP_HYBRID_IOPOLL (1U << 17)
 enum io_uring_op {
   IORING_OP_NOP,
   IORING_OP_READV,
@@ -220,6 +234,9 @@ enum io_uring_msg_ring_flags {
 #define IORING_MSG_RING_FLAGS_PASS (1U << 1)
 #define IORING_FIXED_FD_NO_CLOEXEC (1U << 0)
 #define IORING_NOP_INJECT_RESULT (1U << 0)
+#define IORING_NOP_FILE (1U << 1)
+#define IORING_NOP_FIXED_FILE (1U << 2)
+#define IORING_NOP_FIXED_BUFFER (1U << 3)
 struct io_uring_cqe {
   __u64 user_data;
   __s32 res;
@@ -270,6 +287,7 @@ struct io_cqring_offsets {
 #define IORING_ENTER_EXT_ARG (1U << 3)
 #define IORING_ENTER_REGISTERED_RING (1U << 4)
 #define IORING_ENTER_ABS_TIMER (1U << 5)
+#define IORING_ENTER_EXT_ARG_REG (1U << 6)
 struct io_uring_params {
   __u32 sq_entries;
   __u32 cq_entries;
@@ -298,6 +316,7 @@ struct io_uring_params {
 #define IORING_FEAT_REG_REG_RING (1U << 13)
 #define IORING_FEAT_RECVSEND_BUNDLE (1U << 14)
 #define IORING_FEAT_MIN_TIMEOUT (1U << 15)
+#define IORING_FEAT_RW_ATTR (1U << 16)
 enum io_uring_register_op {
   IORING_REGISTER_BUFFERS = 0,
   IORING_UNREGISTER_BUFFERS = 1,
@@ -330,6 +349,9 @@ enum io_uring_register_op {
   IORING_UNREGISTER_NAPI = 28,
   IORING_REGISTER_CLOCK = 29,
   IORING_REGISTER_CLONE_BUFFERS = 30,
+  IORING_REGISTER_SEND_MSG_RING = 31,
+  IORING_REGISTER_RESIZE_RINGS = 33,
+  IORING_REGISTER_MEM_REGION = 34,
   IORING_REGISTER_LAST,
   IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
 };
@@ -342,6 +364,25 @@ struct io_uring_files_update {
   __u32 resv;
   __aligned_u64 fds;
 };
+enum {
+  IORING_MEM_REGION_TYPE_USER = 1,
+};
+struct io_uring_region_desc {
+  __u64 user_addr;
+  __u64 size;
+  __u32 flags;
+  __u32 id;
+  __u64 mmap_offset;
+  __u64 __resv[4];
+};
+enum {
+  IORING_MEM_REGION_REG_WAIT_ARG = 1,
+};
+struct io_uring_mem_region_reg {
+  __u64 region_uptr;
+  __u64 flags;
+  __u64 __resv[2];
+};
 #define IORING_RSRC_REGISTER_SPARSE (1U << 0)
 struct io_uring_rsrc_register {
   __u32 nr;
@@ -393,12 +434,16 @@ struct io_uring_clock_register {
   __u32 __resv[3];
 };
 enum {
-  IORING_REGISTER_SRC_REGISTERED = 1,
+  IORING_REGISTER_SRC_REGISTERED = (1U << 0),
+  IORING_REGISTER_DST_REPLACE = (1U << 1),
 };
 struct io_uring_clone_buffers {
   __u32 src_fd;
   __u32 flags;
-  __u32 pad[6];
+  __u32 src_off;
+  __u32 dst_off;
+  __u32 nr;
+  __u32 pad[3];
 };
 struct io_uring_buf {
   __u64 addr;
@@ -433,11 +478,23 @@ struct io_uring_buf_status {
   __u32 head;
   __u32 resv[8];
 };
+enum io_uring_napi_op {
+  IO_URING_NAPI_REGISTER_OP = 0,
+  IO_URING_NAPI_STATIC_ADD_ID = 1,
+  IO_URING_NAPI_STATIC_DEL_ID = 2
+};
+enum io_uring_napi_tracking_strategy {
+  IO_URING_NAPI_TRACKING_DYNAMIC = 0,
+  IO_URING_NAPI_TRACKING_STATIC = 1,
+  IO_URING_NAPI_TRACKING_INACTIVE = 255
+};
 struct io_uring_napi {
   __u32 busy_poll_to;
   __u8 prefer_busy_poll;
-  __u8 pad[3];
-  __u64 resv;
+  __u8 opcode;
+  __u8 pad[2];
+  __u32 op_param;
+  __u32 resv;
 };
 enum io_uring_register_restriction_op {
   IORING_RESTRICTION_REGISTER_OP = 0,
@@ -446,6 +503,18 @@ enum io_uring_register_restriction_op {
   IORING_RESTRICTION_SQE_FLAGS_REQUIRED = 3,
   IORING_RESTRICTION_LAST
 };
+enum {
+  IORING_REG_WAIT_TS = (1U << 0),
+};
+struct io_uring_reg_wait {
+  struct __kernel_timespec ts;
+  __u32 min_wait_usec;
+  __u32 flags;
+  __u64 sigmask;
+  __u32 sigmask_sz;
+  __u32 pad[3];
+  __u64 pad2[2];
+};
 struct io_uring_getevents_arg {
   __u64 sigmask;
   __u32 sigmask_sz;
diff --git a/libc/kernel/uapi/linux/iommufd.h b/libc/kernel/uapi/linux/iommufd.h
index 3bbcd40c6..5deb93277 100644
--- a/libc/kernel/uapi/linux/iommufd.h
+++ b/libc/kernel/uapi/linux/iommufd.h
@@ -26,6 +26,10 @@ enum {
   IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP = 0x8c,
   IOMMUFD_CMD_HWPT_INVALIDATE = 0x8d,
   IOMMUFD_CMD_FAULT_QUEUE_ALLOC = 0x8e,
+  IOMMUFD_CMD_IOAS_MAP_FILE = 0x8f,
+  IOMMUFD_CMD_VIOMMU_ALLOC = 0x90,
+  IOMMUFD_CMD_VDEVICE_ALLOC = 0x91,
+  IOMMUFD_CMD_IOAS_CHANGE_PROCESS = 0x92,
 };
 struct iommu_destroy {
   __u32 size;
@@ -74,6 +78,16 @@ struct iommu_ioas_map {
   __aligned_u64 iova;
 };
 #define IOMMU_IOAS_MAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP)
+struct iommu_ioas_map_file {
+  __u32 size;
+  __u32 flags;
+  __u32 ioas_id;
+  __s32 fd;
+  __aligned_u64 start;
+  __aligned_u64 length;
+  __aligned_u64 iova;
+};
+#define IOMMU_IOAS_MAP_FILE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP_FILE)
 struct iommu_ioas_copy {
   __u32 size;
   __u32 flags;
@@ -124,6 +138,7 @@ enum iommufd_hwpt_alloc_flags {
   IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
   IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
   IOMMU_HWPT_FAULT_ID_VALID = 1 << 2,
+  IOMMU_HWPT_ALLOC_PASID = 1 << 3,
 };
 enum iommu_hwpt_vtd_s1_flags {
   IOMMU_VTD_S1_SRE = 1 << 0,
@@ -136,9 +151,13 @@ struct iommu_hwpt_vtd_s1 {
   __u32 addr_width;
   __u32 __reserved;
 };
+struct iommu_hwpt_arm_smmuv3 {
+  __aligned_le64 ste[2];
+};
 enum iommu_hwpt_data_type {
   IOMMU_HWPT_DATA_NONE = 0,
   IOMMU_HWPT_DATA_VTD_S1 = 1,
+  IOMMU_HWPT_DATA_ARM_SMMUV3 = 2,
 };
 struct iommu_hwpt_alloc {
   __u32 size;
@@ -163,9 +182,17 @@ struct iommu_hw_info_vtd {
   __aligned_u64 cap_reg;
   __aligned_u64 ecap_reg;
 };
+struct iommu_hw_info_arm_smmuv3 {
+  __u32 flags;
+  __u32 __reserved;
+  __u32 idr[6];
+  __u32 iidr;
+  __u32 aidr;
+};
 enum iommu_hw_info_type {
   IOMMU_HW_INFO_TYPE_NONE = 0,
   IOMMU_HW_INFO_TYPE_INTEL_VTD = 1,
+  IOMMU_HW_INFO_TYPE_ARM_SMMUV3 = 2,
 };
 enum iommufd_hw_capabilities {
   IOMMU_HW_CAP_DIRTY_TRACKING = 1 << 0,
@@ -207,6 +234,7 @@ struct iommu_hwpt_get_dirty_bitmap {
 #define IOMMU_HWPT_GET_DIRTY_BITMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP)
 enum iommu_hwpt_invalidate_data_type {
   IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0,
+  IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3 = 1,
 };
 enum iommu_hwpt_vtd_s1_invalidate_flags {
   IOMMU_VTD_INV_FLAGS_LEAF = 1 << 0,
@@ -217,6 +245,9 @@ struct iommu_hwpt_vtd_s1_invalidate {
   __u32 flags;
   __u32 __reserved;
 };
+struct iommu_viommu_arm_smmuv3_invalidate {
+  __aligned_le64 cmd[2];
+};
 struct iommu_hwpt_invalidate {
   __u32 size;
   __u32 hwpt_id;
@@ -243,7 +274,8 @@ struct iommu_hwpt_pgfault {
   __u32 pasid;
   __u32 grpid;
   __u32 perm;
-  __u64 addr;
+  __u32 __reserved;
+  __aligned_u64 addr;
   __u32 length;
   __u32 cookie;
 };
@@ -262,4 +294,30 @@ struct iommu_fault_alloc {
   __u32 out_fault_fd;
 };
 #define IOMMU_FAULT_QUEUE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_FAULT_QUEUE_ALLOC)
+enum iommu_viommu_type {
+  IOMMU_VIOMMU_TYPE_DEFAULT = 0,
+  IOMMU_VIOMMU_TYPE_ARM_SMMUV3 = 1,
+};
+struct iommu_viommu_alloc {
+  __u32 size;
+  __u32 flags;
+  __u32 type;
+  __u32 dev_id;
+  __u32 hwpt_id;
+  __u32 out_viommu_id;
+};
+#define IOMMU_VIOMMU_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VIOMMU_ALLOC)
+struct iommu_vdevice_alloc {
+  __u32 size;
+  __u32 viommu_id;
+  __u32 dev_id;
+  __u32 out_vdevice_id;
+  __aligned_u64 virt_id;
+};
+#define IOMMU_VDEVICE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VDEVICE_ALLOC)
+struct iommu_ioas_change_process {
+  __u32 size;
+  __u32 __reserved;
+};
+#define IOMMU_IOAS_CHANGE_PROCESS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_CHANGE_PROCESS)
 #endif
diff --git a/libc/kernel/uapi/linux/ip.h b/libc/kernel/uapi/linux/ip.h
index 332c44700..9f10901d8 100644
--- a/libc/kernel/uapi/linux/ip.h
+++ b/libc/kernel/uapi/linux/ip.h
@@ -103,6 +103,20 @@ struct ip_beet_phdr {
   __u8 padlen;
   __u8 reserved;
 };
+struct ip_iptfs_hdr {
+  __u8 subtype;
+  __u8 flags;
+  __be16 block_offset;
+};
+struct ip_iptfs_cc_hdr {
+  __u8 subtype;
+  __u8 flags;
+  __be16 block_offset;
+  __be32 loss_rate;
+  __be64 rtt_adelay_xdelay;
+  __be32 tval;
+  __be32 techo;
+};
 enum {
   IPV4_DEVCONF_FORWARDING = 1,
   IPV4_DEVCONF_MC_FORWARDING,
diff --git a/libc/kernel/uapi/linux/ipsec.h b/libc/kernel/uapi/linux/ipsec.h
index 3fe7a1b5f..c525ad56a 100644
--- a/libc/kernel/uapi/linux/ipsec.h
+++ b/libc/kernel/uapi/linux/ipsec.h
@@ -14,7 +14,8 @@ enum {
   IPSEC_MODE_ANY = 0,
   IPSEC_MODE_TRANSPORT = 1,
   IPSEC_MODE_TUNNEL = 2,
-  IPSEC_MODE_BEET = 3
+  IPSEC_MODE_BEET = 3,
+  IPSEC_MODE_IPTFS = 4
 };
 enum {
   IPSEC_DIR_ANY = 0,
diff --git a/libc/kernel/uapi/linux/kfd_ioctl.h b/libc/kernel/uapi/linux/kfd_ioctl.h
index 8948a13c1..c56a8503e 100644
--- a/libc/kernel/uapi/linux/kfd_ioctl.h
+++ b/libc/kernel/uapi/linux/kfd_ioctl.h
@@ -367,7 +367,7 @@ struct kfd_ioctl_smi_events_args {
 #define KFD_EVENT_FMT_PAGEFAULT_START(ns,pid,addr,node,rw) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (rw)
 #define KFD_EVENT_FMT_PAGEFAULT_END(ns,pid,addr,node,migrate_update) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (migrate_update)
 #define KFD_EVENT_FMT_MIGRATE_START(ns,pid,start,size,from,to,prefetch_loc,preferred_loc,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %x:%x %d\n", (ns), (pid), (start), (size), (from), (to), (prefetch_loc), (preferred_loc), (migrate_trigger)
-#define KFD_EVENT_FMT_MIGRATE_END(ns,pid,start,size,from,to,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %d\n", (ns), (pid), (start), (size), (from), (to), (migrate_trigger)
+#define KFD_EVENT_FMT_MIGRATE_END(ns,pid,start,size,from,to,migrate_trigger,error_code) "%lld -%d @%lx(%lx) %x->%x %d %d\n", (ns), (pid), (start), (size), (from), (to), (migrate_trigger), (error_code)
 #define KFD_EVENT_FMT_QUEUE_EVICTION(ns,pid,node,evict_trigger) "%lld -%d %x %d\n", (ns), (pid), (node), (evict_trigger)
 #define KFD_EVENT_FMT_QUEUE_RESTORE(ns,pid,node,rescheduled) "%lld -%d %x %c\n", (ns), (pid), (node), (rescheduled)
 #define KFD_EVENT_FMT_UNMAP_FROM_GPU(ns,pid,addr,size,node,unmap_trigger) "%lld -%d @%lx(%lx) %x %d\n", (ns), (pid), (addr), (size), (node), (unmap_trigger)
diff --git a/libc/kernel/uapi/linux/kfd_sysfs.h b/libc/kernel/uapi/linux/kfd_sysfs.h
index 7771582ce..8541bf773 100644
--- a/libc/kernel/uapi/linux/kfd_sysfs.h
+++ b/libc/kernel/uapi/linux/kfd_sysfs.h
@@ -36,7 +36,8 @@
 #define HSA_CAP_FLAGS_COHERENTHOSTACCESS 0x10000000
 #define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED 0x20000000
 #define HSA_CAP_TRAP_DEBUG_PRECISE_ALU_OPERATIONS_SUPPORTED 0x40000000
-#define HSA_CAP_RESERVED 0x800f8000
+#define HSA_CAP_PER_QUEUE_RESET_SUPPORTED 0x80000000
+#define HSA_CAP_RESERVED 0x000f8000
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_MASK 0x0000000f
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_SHIFT 0
 #define HSA_DBG_WATCH_ADDR_MASK_HI_BIT_MASK 0x000003f0
diff --git a/libc/kernel/uapi/linux/kvm.h b/libc/kernel/uapi/linux/kvm.h
index 297a09d85..4775e7e31 100644
--- a/libc/kernel/uapi/linux/kvm.h
+++ b/libc/kernel/uapi/linux/kvm.h
@@ -446,7 +446,6 @@ struct kvm_ioeventfd {
 #define KVM_X86_DISABLE_EXITS_HLT (1 << 1)
 #define KVM_X86_DISABLE_EXITS_PAUSE (1 << 2)
 #define KVM_X86_DISABLE_EXITS_CSTATE (1 << 3)
-#define KVM_X86_DISABLE_VALID_EXITS (KVM_X86_DISABLE_EXITS_MWAIT | KVM_X86_DISABLE_EXITS_HLT | KVM_X86_DISABLE_EXITS_PAUSE | KVM_X86_DISABLE_EXITS_CSTATE)
 struct kvm_enable_cap {
   __u32 cap;
   __u32 flags;
@@ -822,6 +821,7 @@ struct kvm_dirty_tlb {
 #define KVM_REG_LOONGARCH 0x9000000000000000ULL
 #define KVM_REG_SIZE_SHIFT 52
 #define KVM_REG_SIZE_MASK 0x00f0000000000000ULL
+#define KVM_REG_SIZE(id) (1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
 #define KVM_REG_SIZE_U8 0x0000000000000000ULL
 #define KVM_REG_SIZE_U16 0x0010000000000000ULL
 #define KVM_REG_SIZE_U32 0x0020000000000000ULL
@@ -894,6 +894,12 @@ enum kvm_device_type {
 #define KVM_DEV_TYPE_ARM_PV_TIME KVM_DEV_TYPE_ARM_PV_TIME
   KVM_DEV_TYPE_RISCV_AIA,
 #define KVM_DEV_TYPE_RISCV_AIA KVM_DEV_TYPE_RISCV_AIA
+  KVM_DEV_TYPE_LOONGARCH_IPI,
+#define KVM_DEV_TYPE_LOONGARCH_IPI KVM_DEV_TYPE_LOONGARCH_IPI
+  KVM_DEV_TYPE_LOONGARCH_EIOINTC,
+#define KVM_DEV_TYPE_LOONGARCH_EIOINTC KVM_DEV_TYPE_LOONGARCH_EIOINTC
+  KVM_DEV_TYPE_LOONGARCH_PCHPIC,
+#define KVM_DEV_TYPE_LOONGARCH_PCHPIC KVM_DEV_TYPE_LOONGARCH_PCHPIC
   KVM_DEV_TYPE_MAX,
 };
 struct kvm_vfio_spapr_tce {
diff --git a/libc/kernel/uapi/linux/mdio.h b/libc/kernel/uapi/linux/mdio.h
index 7a4d4dbe2..d7c56f077 100644
--- a/libc/kernel/uapi/linux/mdio.h
+++ b/libc/kernel/uapi/linux/mdio.h
@@ -99,6 +99,7 @@
 #define MDIO_STAT1_LPOWERABLE 0x0002
 #define MDIO_STAT1_LSTATUS BMSR_LSTATUS
 #define MDIO_STAT1_FAULT 0x0080
+#define MDIO_PCS_STAT1_CLKSTOP_CAP 0x0040
 #define MDIO_AN_STAT1_LPABLE 0x0001
 #define MDIO_AN_STAT1_ABLE BMSR_ANEGCAPABLE
 #define MDIO_AN_STAT1_RFAULT BMSR_RFAULT
diff --git a/libc/kernel/uapi/linux/media-bus-format.h b/libc/kernel/uapi/linux/media-bus-format.h
index cb36554de..01f7054c0 100644
--- a/libc/kernel/uapi/linux/media-bus-format.h
+++ b/libc/kernel/uapi/linux/media-bus-format.h
@@ -40,6 +40,8 @@
 #define MEDIA_BUS_FMT_ARGB8888_1X32 0x100d
 #define MEDIA_BUS_FMT_RGB888_1X32_PADHI 0x100f
 #define MEDIA_BUS_FMT_RGB101010_1X30 0x1018
+#define MEDIA_BUS_FMT_RGB101010_1X7X5_SPWG 0x1026
+#define MEDIA_BUS_FMT_RGB101010_1X7X5_JEIDA 0x1027
 #define MEDIA_BUS_FMT_RGB666_1X36_CPADLO 0x1020
 #define MEDIA_BUS_FMT_RGB888_1X36_CPADLO 0x1021
 #define MEDIA_BUS_FMT_RGB121212_1X36 0x1019
diff --git a/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_config.h b/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_config.h
new file mode 100644
index 000000000..5f232376a
--- /dev/null
+++ b/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_config.h
@@ -0,0 +1,218 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_PISP_FE_CONFIG_
+#define _UAPI_PISP_FE_CONFIG_
+#include <linux/types.h>
+#include "pisp_common.h"
+#include "pisp_fe_statistics.h"
+#define PISP_FE_NUM_OUTPUTS 2
+enum pisp_fe_enable {
+  PISP_FE_ENABLE_INPUT = 0x000001,
+  PISP_FE_ENABLE_DECOMPRESS = 0x000002,
+  PISP_FE_ENABLE_DECOMPAND = 0x000004,
+  PISP_FE_ENABLE_BLA = 0x000008,
+  PISP_FE_ENABLE_DPC = 0x000010,
+  PISP_FE_ENABLE_STATS_CROP = 0x000020,
+  PISP_FE_ENABLE_DECIMATE = 0x000040,
+  PISP_FE_ENABLE_BLC = 0x000080,
+  PISP_FE_ENABLE_CDAF_STATS = 0x000100,
+  PISP_FE_ENABLE_AWB_STATS = 0x000200,
+  PISP_FE_ENABLE_RGBY = 0x000400,
+  PISP_FE_ENABLE_LSC = 0x000800,
+  PISP_FE_ENABLE_AGC_STATS = 0x001000,
+  PISP_FE_ENABLE_CROP0 = 0x010000,
+  PISP_FE_ENABLE_DOWNSCALE0 = 0x020000,
+  PISP_FE_ENABLE_COMPRESS0 = 0x040000,
+  PISP_FE_ENABLE_OUTPUT0 = 0x080000,
+  PISP_FE_ENABLE_CROP1 = 0x100000,
+  PISP_FE_ENABLE_DOWNSCALE1 = 0x200000,
+  PISP_FE_ENABLE_COMPRESS1 = 0x400000,
+  PISP_FE_ENABLE_OUTPUT1 = 0x800000
+};
+#define PISP_FE_ENABLE_CROP(i) (PISP_FE_ENABLE_CROP0 << (4 * (i)))
+#define PISP_FE_ENABLE_DOWNSCALE(i) (PISP_FE_ENABLE_DOWNSCALE0 << (4 * (i)))
+#define PISP_FE_ENABLE_COMPRESS(i) (PISP_FE_ENABLE_COMPRESS0 << (4 * (i)))
+#define PISP_FE_ENABLE_OUTPUT(i) (PISP_FE_ENABLE_OUTPUT0 << (4 * (i)))
+enum pisp_fe_dirty {
+  PISP_FE_DIRTY_GLOBAL = 0x0001,
+  PISP_FE_DIRTY_FLOATING = 0x0002,
+  PISP_FE_DIRTY_OUTPUT_AXI = 0x0004
+};
+struct pisp_fe_global_config {
+  __u32 enables;
+  __u8 bayer_order;
+  __u8 pad[3];
+} __attribute__((packed));
+struct pisp_fe_input_axi_config {
+  __u8 maxlen_flags;
+  __u8 cache_prot;
+  __u16 qos;
+} __attribute__((packed));
+struct pisp_fe_output_axi_config {
+  __u8 maxlen_flags;
+  __u8 cache_prot;
+  __u16 qos;
+  __u16 thresh;
+  __u16 throttle;
+} __attribute__((packed));
+struct pisp_fe_input_config {
+  __u8 streaming;
+  __u8 pad[3];
+  struct pisp_image_format_config format;
+  struct pisp_fe_input_axi_config axi;
+  __u8 holdoff;
+  __u8 pad2[3];
+} __attribute__((packed));
+struct pisp_fe_output_config {
+  struct pisp_image_format_config format;
+  __u16 ilines;
+  __u8 pad[2];
+} __attribute__((packed));
+struct pisp_fe_input_buffer_config {
+  __u32 addr_lo;
+  __u32 addr_hi;
+  __u16 frame_id;
+  __u16 pad;
+} __attribute__((packed));
+#define PISP_FE_DECOMPAND_LUT_SIZE 65
+struct pisp_fe_decompand_config {
+  __u16 lut[PISP_FE_DECOMPAND_LUT_SIZE];
+  __u16 pad;
+} __attribute__((packed));
+struct pisp_fe_dpc_config {
+  __u8 coeff_level;
+  __u8 coeff_range;
+  __u8 coeff_range2;
+#define PISP_FE_DPC_FLAG_FOLDBACK 1
+#define PISP_FE_DPC_FLAG_VFLAG 2
+  __u8 flags;
+} __attribute__((packed));
+#define PISP_FE_LSC_LUT_SIZE 16
+struct pisp_fe_lsc_config {
+  __u8 shift;
+  __u8 pad0;
+  __u16 scale;
+  __u16 centre_x;
+  __u16 centre_y;
+  __u16 lut[PISP_FE_LSC_LUT_SIZE];
+} __attribute__((packed));
+struct pisp_fe_rgby_config {
+  __u16 gain_r;
+  __u16 gain_g;
+  __u16 gain_b;
+  __u8 maxflag;
+  __u8 pad;
+} __attribute__((packed));
+struct pisp_fe_agc_stats_config {
+  __u16 offset_x;
+  __u16 offset_y;
+  __u16 size_x;
+  __u16 size_y;
+  __u8 weights[PISP_AGC_STATS_NUM_ZONES / 2];
+  __u16 row_offset_x;
+  __u16 row_offset_y;
+  __u16 row_size_x;
+  __u16 row_size_y;
+  __u8 row_shift;
+  __u8 float_shift;
+  __u8 pad1[2];
+} __attribute__((packed));
+struct pisp_fe_awb_stats_config {
+  __u16 offset_x;
+  __u16 offset_y;
+  __u16 size_x;
+  __u16 size_y;
+  __u8 shift;
+  __u8 pad[3];
+  __u16 r_lo;
+  __u16 r_hi;
+  __u16 g_lo;
+  __u16 g_hi;
+  __u16 b_lo;
+  __u16 b_hi;
+} __attribute__((packed));
+struct pisp_fe_floating_stats_region {
+  __u16 offset_x;
+  __u16 offset_y;
+  __u16 size_x;
+  __u16 size_y;
+} __attribute__((packed));
+struct pisp_fe_floating_stats_config {
+  struct pisp_fe_floating_stats_region regions[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+#define PISP_FE_CDAF_NUM_WEIGHTS 8
+struct pisp_fe_cdaf_stats_config {
+  __u16 noise_constant;
+  __u16 noise_slope;
+  __u16 offset_x;
+  __u16 offset_y;
+  __u16 size_x;
+  __u16 size_y;
+  __u16 skip_x;
+  __u16 skip_y;
+  __u32 mode;
+} __attribute__((packed));
+struct pisp_fe_stats_buffer_config {
+  __u32 addr_lo;
+  __u32 addr_hi;
+} __attribute__((packed));
+struct pisp_fe_crop_config {
+  __u16 offset_x;
+  __u16 offset_y;
+  __u16 width;
+  __u16 height;
+} __attribute__((packed));
+enum pisp_fe_downscale_flags {
+  DOWNSCALE_BAYER = 1,
+  DOWNSCALE_BIN = 2,
+};
+struct pisp_fe_downscale_config {
+  __u8 xin;
+  __u8 xout;
+  __u8 yin;
+  __u8 yout;
+  __u8 flags;
+  __u8 pad[3];
+  __u16 output_width;
+  __u16 output_height;
+} __attribute__((packed));
+struct pisp_fe_output_buffer_config {
+  __u32 addr_lo;
+  __u32 addr_hi;
+} __attribute__((packed));
+struct pisp_fe_output_branch_config {
+  struct pisp_fe_crop_config crop;
+  struct pisp_fe_downscale_config downscale;
+  struct pisp_compress_config compress;
+  struct pisp_fe_output_config output;
+  __u32 pad;
+} __attribute__((packed));
+struct pisp_fe_config {
+  struct pisp_fe_stats_buffer_config stats_buffer;
+  struct pisp_fe_output_buffer_config output_buffer[PISP_FE_NUM_OUTPUTS];
+  struct pisp_fe_input_buffer_config input_buffer;
+  struct pisp_fe_global_config global;
+  struct pisp_fe_input_config input;
+  struct pisp_decompress_config decompress;
+  struct pisp_fe_decompand_config decompand;
+  struct pisp_bla_config bla;
+  struct pisp_fe_dpc_config dpc;
+  struct pisp_fe_crop_config stats_crop;
+  __u32 spare1;
+  struct pisp_bla_config blc;
+  struct pisp_fe_rgby_config rgby;
+  struct pisp_fe_lsc_config lsc;
+  struct pisp_fe_agc_stats_config agc_stats;
+  struct pisp_fe_awb_stats_config awb_stats;
+  struct pisp_fe_cdaf_stats_config cdaf_stats;
+  struct pisp_fe_floating_stats_config floating_stats;
+  struct pisp_fe_output_axi_config output_axi;
+  struct pisp_fe_output_branch_config ch[PISP_FE_NUM_OUTPUTS];
+  __u32 dirty_flags;
+  __u32 dirty_flags_extra;
+} __attribute__((packed));
+#endif
diff --git a/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_statistics.h b/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_statistics.h
new file mode 100644
index 000000000..dd0789374
--- /dev/null
+++ b/libc/kernel/uapi/linux/media/raspberrypi/pisp_fe_statistics.h
@@ -0,0 +1,48 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_PISP_FE_STATISTICS_H_
+#define _UAPI_PISP_FE_STATISTICS_H_
+#include <linux/types.h>
+#define PISP_FLOATING_STATS_NUM_ZONES 4
+#define PISP_AGC_STATS_NUM_BINS 1024
+#define PISP_AGC_STATS_SIZE 16
+#define PISP_AGC_STATS_NUM_ZONES (PISP_AGC_STATS_SIZE * PISP_AGC_STATS_SIZE)
+#define PISP_AGC_STATS_NUM_ROW_SUMS 512
+struct pisp_agc_statistics_zone {
+  __u64 Y_sum;
+  __u32 counted;
+  __u32 pad;
+} __attribute__((packed));
+struct pisp_agc_statistics {
+  __u32 row_sums[PISP_AGC_STATS_NUM_ROW_SUMS];
+  __u32 histogram[PISP_AGC_STATS_NUM_BINS];
+  struct pisp_agc_statistics_zone floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+#define PISP_AWB_STATS_SIZE 32
+#define PISP_AWB_STATS_NUM_ZONES (PISP_AWB_STATS_SIZE * PISP_AWB_STATS_SIZE)
+struct pisp_awb_statistics_zone {
+  __u32 R_sum;
+  __u32 G_sum;
+  __u32 B_sum;
+  __u32 counted;
+} __attribute__((packed));
+struct pisp_awb_statistics {
+  struct pisp_awb_statistics_zone zones[PISP_AWB_STATS_NUM_ZONES];
+  struct pisp_awb_statistics_zone floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+#define PISP_CDAF_STATS_SIZE 8
+#define PISP_CDAF_STATS_NUM_FOMS (PISP_CDAF_STATS_SIZE * PISP_CDAF_STATS_SIZE)
+struct pisp_cdaf_statistics {
+  __u64 foms[PISP_CDAF_STATS_NUM_FOMS];
+  __u64 floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+struct pisp_statistics {
+  struct pisp_awb_statistics awb;
+  struct pisp_agc_statistics agc;
+  struct pisp_cdaf_statistics cdaf;
+} __attribute__((packed));
+#endif
diff --git a/libc/kernel/uapi/linux/mount.h b/libc/kernel/uapi/linux/mount.h
index c4278b532..b21687e09 100644
--- a/libc/kernel/uapi/linux/mount.h
+++ b/libc/kernel/uapi/linux/mount.h
@@ -109,7 +109,13 @@ struct statmount {
   __u32 mnt_root;
   __u32 mnt_point;
   __u64 mnt_ns_id;
-  __u64 __spare2[49];
+  __u32 fs_subtype;
+  __u32 sb_source;
+  __u32 opt_num;
+  __u32 opt_array;
+  __u32 opt_sec_num;
+  __u32 opt_sec_array;
+  __u64 __spare2[46];
   char str[];
 };
 struct mnt_id_req {
@@ -129,6 +135,10 @@ struct mnt_id_req {
 #define STATMOUNT_FS_TYPE 0x00000020U
 #define STATMOUNT_MNT_NS_ID 0x00000040U
 #define STATMOUNT_MNT_OPTS 0x00000080U
+#define STATMOUNT_FS_SUBTYPE 0x00000100U
+#define STATMOUNT_SB_SOURCE 0x00000200U
+#define STATMOUNT_OPT_ARRAY 0x00000400U
+#define STATMOUNT_OPT_SEC_ARRAY 0x00000800U
 #define LSMT_ROOT 0xffffffffffffffff
 #define LISTMOUNT_REVERSE (1 << 0)
 #endif
diff --git a/libc/kernel/uapi/linux/net_shaper.h b/libc/kernel/uapi/linux/net_shaper.h
new file mode 100644
index 000000000..bd9bb95f3
--- /dev/null
+++ b/libc/kernel/uapi/linux/net_shaper.h
@@ -0,0 +1,66 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_LINUX_NET_SHAPER_H
+#define _UAPI_LINUX_NET_SHAPER_H
+#define NET_SHAPER_FAMILY_NAME "net-shaper"
+#define NET_SHAPER_FAMILY_VERSION 1
+enum net_shaper_scope {
+  NET_SHAPER_SCOPE_UNSPEC,
+  NET_SHAPER_SCOPE_NETDEV,
+  NET_SHAPER_SCOPE_QUEUE,
+  NET_SHAPER_SCOPE_NODE,
+  __NET_SHAPER_SCOPE_MAX,
+  NET_SHAPER_SCOPE_MAX = (__NET_SHAPER_SCOPE_MAX - 1)
+};
+enum net_shaper_metric {
+  NET_SHAPER_METRIC_BPS,
+  NET_SHAPER_METRIC_PPS,
+};
+enum {
+  NET_SHAPER_A_HANDLE = 1,
+  NET_SHAPER_A_METRIC,
+  NET_SHAPER_A_BW_MIN,
+  NET_SHAPER_A_BW_MAX,
+  NET_SHAPER_A_BURST,
+  NET_SHAPER_A_PRIORITY,
+  NET_SHAPER_A_WEIGHT,
+  NET_SHAPER_A_IFINDEX,
+  NET_SHAPER_A_PARENT,
+  NET_SHAPER_A_LEAVES,
+  __NET_SHAPER_A_MAX,
+  NET_SHAPER_A_MAX = (__NET_SHAPER_A_MAX - 1)
+};
+enum {
+  NET_SHAPER_A_HANDLE_SCOPE = 1,
+  NET_SHAPER_A_HANDLE_ID,
+  __NET_SHAPER_A_HANDLE_MAX,
+  NET_SHAPER_A_HANDLE_MAX = (__NET_SHAPER_A_HANDLE_MAX - 1)
+};
+enum {
+  NET_SHAPER_A_CAPS_IFINDEX = 1,
+  NET_SHAPER_A_CAPS_SCOPE,
+  NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS,
+  NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS,
+  NET_SHAPER_A_CAPS_SUPPORT_NESTING,
+  NET_SHAPER_A_CAPS_SUPPORT_BW_MIN,
+  NET_SHAPER_A_CAPS_SUPPORT_BW_MAX,
+  NET_SHAPER_A_CAPS_SUPPORT_BURST,
+  NET_SHAPER_A_CAPS_SUPPORT_PRIORITY,
+  NET_SHAPER_A_CAPS_SUPPORT_WEIGHT,
+  __NET_SHAPER_A_CAPS_MAX,
+  NET_SHAPER_A_CAPS_MAX = (__NET_SHAPER_A_CAPS_MAX - 1)
+};
+enum {
+  NET_SHAPER_CMD_GET = 1,
+  NET_SHAPER_CMD_SET,
+  NET_SHAPER_CMD_DELETE,
+  NET_SHAPER_CMD_GROUP,
+  NET_SHAPER_CMD_CAP_GET,
+  __NET_SHAPER_CMD_MAX,
+  NET_SHAPER_CMD_MAX = (__NET_SHAPER_CMD_MAX - 1)
+};
+#endif
diff --git a/libc/kernel/uapi/linux/net_tstamp.h b/libc/kernel/uapi/linux/net_tstamp.h
index b0df34402..3bf8f9a2c 100644
--- a/libc/kernel/uapi/linux/net_tstamp.h
+++ b/libc/kernel/uapi/linux/net_tstamp.h
@@ -8,6 +8,11 @@
 #define _NET_TIMESTAMPING_H
 #include <linux/types.h>
 #include <linux/socket.h>
+enum hwtstamp_provider_qualifier {
+  HWTSTAMP_PROVIDER_QUALIFIER_PRECISE,
+  HWTSTAMP_PROVIDER_QUALIFIER_APPROX,
+  HWTSTAMP_PROVIDER_QUALIFIER_CNT,
+};
 enum {
   SOF_TIMESTAMPING_TX_HARDWARE = (1 << 0),
   SOF_TIMESTAMPING_TX_SOFTWARE = (1 << 1),
diff --git a/libc/kernel/uapi/linux/netdev.h b/libc/kernel/uapi/linux/netdev.h
index a7c570617..ad807a320 100644
--- a/libc/kernel/uapi/linux/netdev.h
+++ b/libc/kernel/uapi/linux/netdev.h
@@ -76,6 +76,9 @@ enum {
   NETDEV_A_NAPI_ID,
   NETDEV_A_NAPI_IRQ,
   NETDEV_A_NAPI_PID,
+  NETDEV_A_NAPI_DEFER_HARD_IRQS,
+  NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT,
+  NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT,
   __NETDEV_A_NAPI_MAX,
   NETDEV_A_NAPI_MAX = (__NETDEV_A_NAPI_MAX - 1)
 };
@@ -145,6 +148,7 @@ enum {
   NETDEV_CMD_NAPI_GET,
   NETDEV_CMD_QSTATS_GET,
   NETDEV_CMD_BIND_RX,
+  NETDEV_CMD_NAPI_SET,
   __NETDEV_CMD_MAX,
   NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
 };
diff --git a/libc/kernel/uapi/linux/netfilter/nf_tables.h b/libc/kernel/uapi/linux/netfilter/nf_tables.h
index bfc6e25b0..6914cae49 100644
--- a/libc/kernel/uapi/linux/netfilter/nf_tables.h
+++ b/libc/kernel/uapi/linux/netfilter/nf_tables.h
@@ -285,10 +285,14 @@ enum nft_immediate_attributes {
 };
 #define NFTA_IMMEDIATE_MAX (__NFTA_IMMEDIATE_MAX - 1)
 enum nft_bitwise_ops {
-  NFT_BITWISE_BOOL,
+  NFT_BITWISE_MASK_XOR,
   NFT_BITWISE_LSHIFT,
   NFT_BITWISE_RSHIFT,
+  NFT_BITWISE_AND,
+  NFT_BITWISE_OR,
+  NFT_BITWISE_XOR,
 };
+#define NFT_BITWISE_BOOL NFT_BITWISE_MASK_XOR
 enum nft_bitwise_attributes {
   NFTA_BITWISE_UNSPEC,
   NFTA_BITWISE_SREG,
@@ -298,6 +302,7 @@ enum nft_bitwise_attributes {
   NFTA_BITWISE_XOR,
   NFTA_BITWISE_OP,
   NFTA_BITWISE_DATA,
+  NFTA_BITWISE_SREG2,
   __NFTA_BITWISE_MAX
 };
 #define NFTA_BITWISE_MAX (__NFTA_BITWISE_MAX - 1)
diff --git a/libc/kernel/uapi/linux/netfilter/nfnetlink_conntrack.h b/libc/kernel/uapi/linux/netfilter/nfnetlink_conntrack.h
index b0a1d4199..a0e0d1090 100644
--- a/libc/kernel/uapi/linux/netfilter/nfnetlink_conntrack.h
+++ b/libc/kernel/uapi/linux/netfilter/nfnetlink_conntrack.h
@@ -56,6 +56,7 @@ enum ctattr_type {
   CTA_SYNPROXY,
   CTA_FILTER,
   CTA_STATUS_MASK,
+  CTA_TIMESTAMP_EVENT,
   __CTA_MAX
 };
 #define CTA_MAX (__CTA_MAX - 1)
diff --git a/libc/kernel/uapi/linux/nfc.h b/libc/kernel/uapi/linux/nfc.h
index 393ce7c12..0db856721 100644
--- a/libc/kernel/uapi/linux/nfc.h
+++ b/libc/kernel/uapi/linux/nfc.h
@@ -79,6 +79,7 @@ enum nfc_attrs {
   NFC_ATTR_VENDOR_ID,
   NFC_ATTR_VENDOR_SUBCMD,
   NFC_ATTR_VENDOR_DATA,
+  NFC_ATTR_TARGET_ATS,
   __NFC_ATTR_AFTER_LAST
 };
 #define NFC_ATTR_MAX (__NFC_ATTR_AFTER_LAST - 1)
@@ -102,6 +103,7 @@ enum nfc_sdp_attr {
 #define NFC_GB_MAXSIZE 48
 #define NFC_FIRMWARE_NAME_MAXSIZE 32
 #define NFC_ISO15693_UID_MAXSIZE 8
+#define NFC_ATS_MAXSIZE 20
 #define NFC_PROTO_JEWEL 1
 #define NFC_PROTO_MIFARE 2
 #define NFC_PROTO_FELICA 3
diff --git a/libc/kernel/uapi/linux/nfs4.h b/libc/kernel/uapi/linux/nfs4.h
index 6512901e8..387d862f7 100644
--- a/libc/kernel/uapi/linux/nfs4.h
+++ b/libc/kernel/uapi/linux/nfs4.h
@@ -43,7 +43,7 @@
 #define NFS4_SHARE_DENY_READ 0x0001
 #define NFS4_SHARE_DENY_WRITE 0x0002
 #define NFS4_SHARE_DENY_BOTH 0x0003
-#define NFS4_SHARE_WANT_MASK 0xFF00
+#define NFS4_SHARE_WANT_TYPE_MASK 0xFF00
 #define NFS4_SHARE_WANT_NO_PREFERENCE 0x0000
 #define NFS4_SHARE_WANT_READ_DELEG 0x0100
 #define NFS4_SHARE_WANT_WRITE_DELEG 0x0200
@@ -53,8 +53,10 @@
 #define NFS4_SHARE_WHEN_MASK 0xF0000
 #define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL 0x10000
 #define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED 0x20000
+#define NFS4_SHARE_WANT_MOD_MASK 0xF00000
 #define NFS4_SHARE_WANT_DELEG_TIMESTAMPS 0x100000
 #define NFS4_SHARE_WANT_OPEN_XOR_DELEGATION 0x200000
+#define NFS4_SHARE_WANT_MASK (NFS4_SHARE_WANT_TYPE_MASK | NFS4_SHARE_WANT_MOD_MASK)
 #define NFS4_CDFC4_FORE 0x1
 #define NFS4_CDFC4_BACK 0x2
 #define NFS4_CDFC4_BOTH 0x3
diff --git a/libc/kernel/uapi/linux/nl80211.h b/libc/kernel/uapi/linux/nl80211.h
index 1bad2f2a9..c952b206f 100644
--- a/libc/kernel/uapi/linux/nl80211.h
+++ b/libc/kernel/uapi/linux/nl80211.h
@@ -181,6 +181,8 @@ enum nl80211_commands {
   NL80211_CMD_SET_HW_TIMESTAMP,
   NL80211_CMD_LINKS_REMOVED,
   NL80211_CMD_SET_TID_TO_LINK_MAPPING,
+  NL80211_CMD_ASSOC_MLO_RECONF,
+  NL80211_CMD_EPCS_CFG,
   __NL80211_CMD_AFTER_LAST,
   NL80211_CMD_MAX = __NL80211_CMD_AFTER_LAST - 1
 };
@@ -530,6 +532,10 @@ enum nl80211_attrs {
   NL80211_ATTR_ASSOC_SPP_AMSDU,
   NL80211_ATTR_WIPHY_RADIOS,
   NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS,
+  NL80211_ATTR_VIF_RADIO_MASK,
+  NL80211_ATTR_SUPPORTED_SELECTORS,
+  NL80211_ATTR_MLO_RECONF_REM_LINKS,
+  NL80211_ATTR_EPCS,
   __NL80211_ATTR_AFTER_LAST,
   NUM_NL80211_ATTR = __NL80211_ATTR_AFTER_LAST,
   NL80211_ATTR_MAX = __NL80211_ATTR_AFTER_LAST - 1
@@ -563,6 +569,7 @@ enum nl80211_attrs {
 #define NL80211_ATTR_FEATURE_FLAGS NL80211_ATTR_FEATURE_FLAGS
 #define NL80211_WIPHY_NAME_MAXLEN 64
 #define NL80211_MAX_SUPP_RATES 32
+#define NL80211_MAX_SUPP_SELECTORS 128
 #define NL80211_MAX_SUPP_HT_RATES 77
 #define NL80211_MAX_SUPP_REG_RULES 128
 #define NL80211_TKIP_DATA_OFFSET_ENCR_KEY 0
@@ -1009,6 +1016,7 @@ enum nl80211_mntr_flags {
   NL80211_MNTR_FLAG_OTHER_BSS,
   NL80211_MNTR_FLAG_COOK_FRAMES,
   NL80211_MNTR_FLAG_ACTIVE,
+  NL80211_MNTR_FLAG_SKIP_TX,
   __NL80211_MNTR_FLAG_AFTER_LAST,
   NL80211_MNTR_FLAG_MAX = __NL80211_MNTR_FLAG_AFTER_LAST - 1
 };
@@ -1982,6 +1990,7 @@ enum nl80211_wiphy_radio_attrs {
   NL80211_WIPHY_RADIO_ATTR_INDEX,
   NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE,
   NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION,
+  NL80211_WIPHY_RADIO_ATTR_ANTENNA_MASK,
   __NL80211_WIPHY_RADIO_ATTR_LAST,
   NL80211_WIPHY_RADIO_ATTR_MAX = __NL80211_WIPHY_RADIO_ATTR_LAST - 1,
 };
diff --git a/libc/kernel/uapi/linux/ntsync.h b/libc/kernel/uapi/linux/ntsync.h
index 857b31b59..2028da486 100644
--- a/libc/kernel/uapi/linux/ntsync.h
+++ b/libc/kernel/uapi/linux/ntsync.h
@@ -8,10 +8,41 @@
 #define __LINUX_NTSYNC_H
 #include <linux/types.h>
 struct ntsync_sem_args {
-  __u32 sem;
   __u32 count;
   __u32 max;
 };
-#define NTSYNC_IOC_CREATE_SEM _IOWR('N', 0x80, struct ntsync_sem_args)
-#define NTSYNC_IOC_SEM_POST _IOWR('N', 0x81, __u32)
+struct ntsync_mutex_args {
+  __u32 owner;
+  __u32 count;
+};
+struct ntsync_event_args {
+  __u32 manual;
+  __u32 signaled;
+};
+#define NTSYNC_WAIT_REALTIME 0x1
+struct ntsync_wait_args {
+  __u64 timeout;
+  __u64 objs;
+  __u32 count;
+  __u32 index;
+  __u32 flags;
+  __u32 owner;
+  __u32 alert;
+  __u32 pad;
+};
+#define NTSYNC_MAX_WAIT_COUNT 64
+#define NTSYNC_IOC_CREATE_SEM _IOW('N', 0x80, struct ntsync_sem_args)
+#define NTSYNC_IOC_WAIT_ANY _IOWR('N', 0x82, struct ntsync_wait_args)
+#define NTSYNC_IOC_WAIT_ALL _IOWR('N', 0x83, struct ntsync_wait_args)
+#define NTSYNC_IOC_CREATE_MUTEX _IOW('N', 0x84, struct ntsync_mutex_args)
+#define NTSYNC_IOC_CREATE_EVENT _IOW('N', 0x87, struct ntsync_event_args)
+#define NTSYNC_IOC_SEM_RELEASE _IOWR('N', 0x81, __u32)
+#define NTSYNC_IOC_MUTEX_UNLOCK _IOWR('N', 0x85, struct ntsync_mutex_args)
+#define NTSYNC_IOC_MUTEX_KILL _IOW('N', 0x86, __u32)
+#define NTSYNC_IOC_EVENT_SET _IOR('N', 0x88, __u32)
+#define NTSYNC_IOC_EVENT_RESET _IOR('N', 0x89, __u32)
+#define NTSYNC_IOC_EVENT_PULSE _IOR('N', 0x8a, __u32)
+#define NTSYNC_IOC_SEM_READ _IOR('N', 0x8b, struct ntsync_sem_args)
+#define NTSYNC_IOC_MUTEX_READ _IOR('N', 0x8c, struct ntsync_mutex_args)
+#define NTSYNC_IOC_EVENT_READ _IOR('N', 0x8d, struct ntsync_event_args)
 #endif
diff --git a/libc/kernel/uapi/linux/pci_regs.h b/libc/kernel/uapi/linux/pci_regs.h
index 708339173..b134a1e8b 100644
--- a/libc/kernel/uapi/linux/pci_regs.h
+++ b/libc/kernel/uapi/linux/pci_regs.h
@@ -267,6 +267,7 @@
 #define PCI_MSIX_ENTRY_DATA 0x8
 #define PCI_MSIX_ENTRY_VECTOR_CTRL 0xc
 #define PCI_MSIX_ENTRY_CTRL_MASKBIT 0x00000001
+#define PCI_MSIX_ENTRY_CTRL_ST 0xffff0000
 #define PCI_CHSWP_CSR 2
 #define PCI_CHSWP_DHA 0x01
 #define PCI_CHSWP_EIM 0x02
@@ -548,10 +549,12 @@
 #define PCI_EXP_DEVCAP2_ATOMIC_COMP64 0x00000100
 #define PCI_EXP_DEVCAP2_ATOMIC_COMP128 0x00000200
 #define PCI_EXP_DEVCAP2_LTR 0x00000800
+#define PCI_EXP_DEVCAP2_TPH_COMP_MASK 0x00003000
 #define PCI_EXP_DEVCAP2_OBFF_MASK 0x000c0000
 #define PCI_EXP_DEVCAP2_OBFF_MSG 0x00040000
 #define PCI_EXP_DEVCAP2_OBFF_WAKE 0x00080000
 #define PCI_EXP_DEVCAP2_EE_PREFIX 0x00200000
+#define PCI_EXP_DEVCAP2_EE_PREFIX_MAX 0x00c00000
 #define PCI_EXP_DEVCTL2 0x28
 #define PCI_EXP_DEVCTL2_COMP_TIMEOUT 0x000f
 #define PCI_EXP_DEVCTL2_COMP_TMOUT_DIS 0x0010
@@ -567,6 +570,7 @@
 #define PCI_EXP_DEVSTA2 0x2a
 #define PCI_CAP_EXP_RC_ENDPOINT_SIZEOF_V2 0x2c
 #define PCI_EXP_LNKCAP2 0x2c
+#define PCI_EXP_LNKCAP2_SLS 0x000000fe
 #define PCI_EXP_LNKCAP2_SLS_2_5GB 0x00000002
 #define PCI_EXP_LNKCAP2_SLS_5_0GB 0x00000004
 #define PCI_EXP_LNKCAP2_SLS_8_0GB 0x00000008
@@ -670,6 +674,7 @@
 #define PCI_ERR_CAP_ECRC_GENE 0x00000040
 #define PCI_ERR_CAP_ECRC_CHKC 0x00000080
 #define PCI_ERR_CAP_ECRC_CHKE 0x00000100
+#define PCI_ERR_CAP_PREFIX_LOG_PRESENT 0x00000800
 #define PCI_ERR_HEADER_LOG 0x1c
 #define PCI_ERR_ROOT_COMMAND 0x2c
 #define PCI_ERR_ROOT_CMD_COR_EN 0x00000001
@@ -685,6 +690,7 @@
 #define PCI_ERR_ROOT_FATAL_RCV 0x00000040
 #define PCI_ERR_ROOT_AER_IRQ 0xf8000000
 #define PCI_ERR_ROOT_ERR_SRC 0x34
+#define PCI_ERR_PREFIX_LOG 0x38
 #define PCI_VC_PORT_CAP1 0x04
 #define PCI_VC_CAP1_EVCC 0x00000007
 #define PCI_VC_CAP1_LPEVCC 0x00000070
@@ -846,8 +852,6 @@
 #define PCI_ACS_EGRESS_BITS 0x05
 #define PCI_ACS_CTRL 0x06
 #define PCI_ACS_EGRESS_CTL_V 0x08
-#define PCI_VSEC_HDR 4
-#define PCI_VSEC_HDR_LEN_SHIFT 20
 #define PCI_SATA_REGS 4
 #define PCI_SATA_REGS_MASK 0xF
 #define PCI_SATA_REGS_INLINE 0xF
@@ -864,14 +868,30 @@
 #define PCI_DPA_CAP 4
 #define PCI_DPA_CAP_SUBSTATE_MASK 0x1F
 #define PCI_DPA_BASE_SIZEOF 16
+#define PCI_EXP_DEVCAP2_TPH_COMP_NONE 0x0
+#define PCI_EXP_DEVCAP2_TPH_COMP_TPH_ONLY 0x1
+#define PCI_EXP_DEVCAP2_TPH_COMP_EXT_TPH 0x3
 #define PCI_TPH_CAP 4
-#define PCI_TPH_CAP_LOC_MASK 0x600
-#define PCI_TPH_LOC_NONE 0x000
-#define PCI_TPH_LOC_CAP 0x200
-#define PCI_TPH_LOC_MSIX 0x400
+#define PCI_TPH_CAP_ST_NS 0x00000001
+#define PCI_TPH_CAP_ST_IV 0x00000002
+#define PCI_TPH_CAP_ST_DS 0x00000004
+#define PCI_TPH_CAP_EXT_TPH 0x00000100
+#define PCI_TPH_CAP_LOC_MASK 0x00000600
+#define PCI_TPH_LOC_NONE 0x00000000
+#define PCI_TPH_LOC_CAP 0x00000200
+#define PCI_TPH_LOC_MSIX 0x00000400
 #define PCI_TPH_CAP_ST_MASK 0x07FF0000
 #define PCI_TPH_CAP_ST_SHIFT 16
 #define PCI_TPH_BASE_SIZEOF 0xc
+#define PCI_TPH_CTRL 8
+#define PCI_TPH_CTRL_MODE_SEL_MASK 0x00000007
+#define PCI_TPH_ST_NS_MODE 0x0
+#define PCI_TPH_ST_IV_MODE 0x1
+#define PCI_TPH_ST_DS_MODE 0x2
+#define PCI_TPH_CTRL_REQ_EN_MASK 0x00000300
+#define PCI_TPH_REQ_DISABLE 0x0
+#define PCI_TPH_REQ_TPH_ONLY 0x1
+#define PCI_TPH_REQ_EXT_TPH 0x3
 #define PCI_EXP_DPC_CAP 0x04
 #define PCI_EXP_DPC_IRQ 0x001F
 #define PCI_EXP_DPC_CAP_RP_EXT 0x0020
diff --git a/libc/kernel/uapi/linux/pcitest.h b/libc/kernel/uapi/linux/pcitest.h
index 38e498d64..9118ffce0 100644
--- a/libc/kernel/uapi/linux/pcitest.h
+++ b/libc/kernel/uapi/linux/pcitest.h
@@ -16,6 +16,7 @@
 #define PCITEST_MSIX _IOW('P', 0x7, int)
 #define PCITEST_SET_IRQTYPE _IOW('P', 0x8, int)
 #define PCITEST_GET_IRQTYPE _IO('P', 0x9)
+#define PCITEST_BARS _IO('P', 0xa)
 #define PCITEST_CLEAR_IRQ _IO('P', 0x10)
 #define PCITEST_FLAGS_USE_DMA 0x00000001
 struct pci_endpoint_test_xfer_param {
diff --git a/libc/kernel/uapi/linux/perf_event.h b/libc/kernel/uapi/linux/perf_event.h
index ec9b856bb..792b96c44 100644
--- a/libc/kernel/uapi/linux/perf_event.h
+++ b/libc/kernel/uapi/linux/perf_event.h
@@ -265,7 +265,12 @@ struct perf_event_attr {
   __u16 sample_max_stack;
   __u16 __reserved_2;
   __u32 aux_sample_size;
-  __u32 __reserved_3;
+  union {
+    __u32 aux_action;
+    struct {
+      __u32 aux_start_paused : 1, aux_pause : 1, aux_resume : 1, __reserved_3 : 29;
+    };
+  };
   __u64 sig_data;
   __u64 config3;
 };
diff --git a/libc/kernel/uapi/linux/pidfd.h b/libc/kernel/uapi/linux/pidfd.h
index 9068727ff..998fe40b8 100644
--- a/libc/kernel/uapi/linux/pidfd.h
+++ b/libc/kernel/uapi/linux/pidfd.h
@@ -14,6 +14,26 @@
 #define PIDFD_SIGNAL_THREAD (1UL << 0)
 #define PIDFD_SIGNAL_THREAD_GROUP (1UL << 1)
 #define PIDFD_SIGNAL_PROCESS_GROUP (1UL << 2)
+#define PIDFD_INFO_PID (1UL << 0)
+#define PIDFD_INFO_CREDS (1UL << 1)
+#define PIDFD_INFO_CGROUPID (1UL << 2)
+#define PIDFD_INFO_SIZE_VER0 64
+struct pidfd_info {
+  __u64 mask;
+  __u64 cgroupid;
+  __u32 pid;
+  __u32 tgid;
+  __u32 ppid;
+  __u32 ruid;
+  __u32 rgid;
+  __u32 euid;
+  __u32 egid;
+  __u32 suid;
+  __u32 sgid;
+  __u32 fsuid;
+  __u32 fsgid;
+  __u32 spare0[1];
+};
 #define PIDFS_IOCTL_MAGIC 0xFF
 #define PIDFD_GET_CGROUP_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 1)
 #define PIDFD_GET_IPC_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 2)
@@ -25,4 +45,5 @@
 #define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
 #define PIDFD_GET_USER_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 9)
 #define PIDFD_GET_UTS_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 10)
+#define PIDFD_GET_INFO _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
 #endif
diff --git a/libc/kernel/uapi/linux/pkt_cls.h b/libc/kernel/uapi/linux/pkt_cls.h
index c5d8d791a..a8e07404d 100644
--- a/libc/kernel/uapi/linux/pkt_cls.h
+++ b/libc/kernel/uapi/linux/pkt_cls.h
@@ -179,12 +179,7 @@ struct tc_u32_key {
   int offmask;
 };
 struct tc_u32_sel {
-  /**
-   ** ANDROID FIX: Comment out TAG value to avoid C++ error about using
-   ** a type declared in an anonymous union. This is being fixed upstream
-   ** and should be corrected by the next kernel import.
-   */
-  __struct_group(/*tc_u32_sel_hdr*/, hdr,, unsigned char flags;
+  __struct_group(tc_u32_sel_hdr, hdr,, unsigned char flags;
   unsigned char offshift;
   unsigned char nkeys;
   __be16 offmask;
diff --git a/libc/kernel/uapi/linux/pkt_sched.h b/libc/kernel/uapi/linux/pkt_sched.h
index c3488c26f..f5ce9d91d 100644
--- a/libc/kernel/uapi/linux/pkt_sched.h
+++ b/libc/kernel/uapi/linux/pkt_sched.h
@@ -591,6 +591,7 @@ enum {
   TCA_FQ_HORIZON_DROP,
   TCA_FQ_PRIOMAP,
   TCA_FQ_WEIGHTS,
+  TCA_FQ_OFFLOAD_HORIZON,
   __TCA_FQ_MAX
 };
 #define TCA_FQ_MAX (__TCA_FQ_MAX - 1)
diff --git a/libc/kernel/uapi/linux/pps_gen.h b/libc/kernel/uapi/linux/pps_gen.h
new file mode 100644
index 000000000..e83addfec
--- /dev/null
+++ b/libc/kernel/uapi/linux/pps_gen.h
@@ -0,0 +1,19 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _PPS_GEN_H_
+#define _PPS_GEN_H_
+#include <linux/types.h>
+#include <linux/ioctl.h>
+struct pps_gen_event {
+  unsigned int event;
+  unsigned int sequence;
+};
+#define PPS_GEN_EVENT_MISSEDPULSE 1
+#define PPS_GEN_SETENABLE _IOW('p', 0xb1, unsigned int *)
+#define PPS_GEN_USESYSTEMCLOCK _IOR('p', 0xb2, unsigned int *)
+#define PPS_GEN_FETCHEVENT _IOR('p', 0xb3, struct pps_gen_event *)
+#endif
diff --git a/libc/kernel/uapi/linux/prctl.h b/libc/kernel/uapi/linux/prctl.h
index 136a10fa7..53f74dd37 100644
--- a/libc/kernel/uapi/linux/prctl.h
+++ b/libc/kernel/uapi/linux/prctl.h
@@ -149,6 +149,8 @@ struct prctl_mm_map {
 #define PR_MTE_TAG_SHIFT 3
 #define PR_MTE_TAG_MASK (0xffffUL << PR_MTE_TAG_SHIFT)
 #define PR_MTE_TCF_SHIFT 1
+#define PR_PMLEN_SHIFT 24
+#define PR_PMLEN_MASK (0x7fUL << PR_PMLEN_SHIFT)
 #define PR_SET_IO_FLUSHER 57
 #define PR_GET_IO_FLUSHER 58
 #define PR_SET_SYSCALL_USER_DISPATCH 59
@@ -207,4 +209,10 @@ struct prctl_mm_map {
 #define PR_PPC_DEXCR_CTRL_SET_ONEXEC 0x8
 #define PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC 0x10
 #define PR_PPC_DEXCR_CTRL_MASK 0x1f
+#define PR_GET_SHADOW_STACK_STATUS 74
+#define PR_SET_SHADOW_STACK_STATUS 75
+#define PR_SHADOW_STACK_ENABLE (1UL << 0)
+#define PR_SHADOW_STACK_WRITE (1UL << 1)
+#define PR_SHADOW_STACK_PUSH (1UL << 2)
+#define PR_LOCK_SHADOW_STACK_STATUS 76
 #endif
diff --git a/libc/kernel/uapi/linux/psci.h b/libc/kernel/uapi/linux/psci.h
index 343268ff8..9461c823b 100644
--- a/libc/kernel/uapi/linux/psci.h
+++ b/libc/kernel/uapi/linux/psci.h
@@ -37,6 +37,7 @@
 #define PSCI_1_1_FN_SYSTEM_RESET2 PSCI_0_2_FN(18)
 #define PSCI_1_1_FN_MEM_PROTECT PSCI_0_2_FN(19)
 #define PSCI_1_1_FN_MEM_PROTECT_CHECK_RANGE PSCI_0_2_FN(20)
+#define PSCI_1_3_FN_SYSTEM_OFF2 PSCI_0_2_FN(21)
 #define PSCI_1_0_FN64_CPU_DEFAULT_SUSPEND PSCI_0_2_FN64(12)
 #define PSCI_1_0_FN64_NODE_HW_STATE PSCI_0_2_FN64(13)
 #define PSCI_1_0_FN64_SYSTEM_SUSPEND PSCI_0_2_FN64(14)
@@ -44,6 +45,7 @@
 #define PSCI_1_0_FN64_STAT_COUNT PSCI_0_2_FN64(17)
 #define PSCI_1_1_FN64_SYSTEM_RESET2 PSCI_0_2_FN64(18)
 #define PSCI_1_1_FN64_MEM_PROTECT_CHECK_RANGE PSCI_0_2_FN64(20)
+#define PSCI_1_3_FN64_SYSTEM_OFF2 PSCI_0_2_FN64(21)
 #define PSCI_0_2_POWER_STATE_ID_MASK 0xffff
 #define PSCI_0_2_POWER_STATE_ID_SHIFT 0
 #define PSCI_0_2_POWER_STATE_TYPE_SHIFT 16
@@ -62,6 +64,7 @@
 #define PSCI_0_2_TOS_MP 2
 #define PSCI_1_1_RESET_TYPE_SYSTEM_WARM_RESET 0
 #define PSCI_1_1_RESET_TYPE_VENDOR_START 0x80000000U
+#define PSCI_1_3_OFF_TYPE_HIBERNATE_OFF BIT(0)
 #define PSCI_VERSION_MAJOR_SHIFT 16
 #define PSCI_VERSION_MINOR_MASK ((1U << PSCI_VERSION_MAJOR_SHIFT) - 1)
 #define PSCI_VERSION_MAJOR_MASK ~PSCI_VERSION_MINOR_MASK
diff --git a/libc/kernel/uapi/linux/raid/md_u.h b/libc/kernel/uapi/linux/raid/md_u.h
index f291f649a..0d0c1172a 100644
--- a/libc/kernel/uapi/linux/raid/md_u.h
+++ b/libc/kernel/uapi/linux/raid/md_u.h
@@ -57,6 +57,7 @@ typedef struct mdu_array_info_s {
   int layout;
   int chunk_size;
 } mdu_array_info_t;
+#define LEVEL_LINEAR (- 1)
 #define LEVEL_NONE (- 1000000)
 typedef struct mdu_disk_info_s {
   int number;
diff --git a/libc/kernel/uapi/linux/reiserfs_fs.h b/libc/kernel/uapi/linux/reiserfs_fs.h
deleted file mode 100644
index e0bd0a055..000000000
--- a/libc/kernel/uapi/linux/reiserfs_fs.h
+++ /dev/null
@@ -1,16 +0,0 @@
-/*
- * This file is auto-generated. Modifications will be lost.
- *
- * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
- * for more information.
- */
-#ifndef _LINUX_REISER_FS_H
-#define _LINUX_REISER_FS_H
-#include <linux/types.h>
-#include <linux/magic.h>
-#define REISERFS_IOC_UNPACK _IOW(0xCD, 1, long)
-#define REISERFS_IOC_GETFLAGS FS_IOC_GETFLAGS
-#define REISERFS_IOC_SETFLAGS FS_IOC_SETFLAGS
-#define REISERFS_IOC_GETVERSION FS_IOC_GETVERSION
-#define REISERFS_IOC_SETVERSION FS_IOC_SETVERSION
-#endif
diff --git a/libc/kernel/uapi/linux/reiserfs_xattr.h b/libc/kernel/uapi/linux/reiserfs_xattr.h
deleted file mode 100644
index 2caed3073..000000000
--- a/libc/kernel/uapi/linux/reiserfs_xattr.h
+++ /dev/null
@@ -1,20 +0,0 @@
-/*
- * This file is auto-generated. Modifications will be lost.
- *
- * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
- * for more information.
- */
-#ifndef _LINUX_REISERFS_XATTR_H
-#define _LINUX_REISERFS_XATTR_H
-#include <linux/types.h>
-#define REISERFS_XATTR_MAGIC 0x52465841
-struct reiserfs_xattr_header {
-  __le32 h_magic;
-  __le32 h_hash;
-};
-struct reiserfs_security_handle {
-  const char * name;
-  void * value;
-  __kernel_size_t length;
-};
-#endif
diff --git a/libc/kernel/uapi/linux/rtnetlink.h b/libc/kernel/uapi/linux/rtnetlink.h
index 70038f28e..384c03244 100644
--- a/libc/kernel/uapi/linux/rtnetlink.h
+++ b/libc/kernel/uapi/linux/rtnetlink.h
@@ -75,9 +75,17 @@ enum {
 #define RTM_GETACTION RTM_GETACTION
   RTM_NEWPREFIX = 52,
 #define RTM_NEWPREFIX RTM_NEWPREFIX
-  RTM_GETMULTICAST = 58,
+  RTM_NEWMULTICAST = 56,
+#define RTM_NEWMULTICAST RTM_NEWMULTICAST
+  RTM_DELMULTICAST,
+#define RTM_DELMULTICAST RTM_DELMULTICAST
+  RTM_GETMULTICAST,
 #define RTM_GETMULTICAST RTM_GETMULTICAST
-  RTM_GETANYCAST = 62,
+  RTM_NEWANYCAST = 60,
+#define RTM_NEWANYCAST RTM_NEWANYCAST
+  RTM_DELANYCAST,
+#define RTM_DELANYCAST RTM_DELANYCAST
+  RTM_GETANYCAST,
 #define RTM_GETANYCAST RTM_GETANYCAST
   RTM_NEWNEIGHTBL = 64,
 #define RTM_NEWNEIGHTBL RTM_NEWNEIGHTBL
@@ -142,7 +150,7 @@ enum {
   RTM_GETLINKPROP,
 #define RTM_GETLINKPROP RTM_GETLINKPROP
   RTM_NEWVLAN = 112,
-#define RTM_NEWNVLAN RTM_NEWVLAN
+#define RTM_NEWVLAN RTM_NEWVLAN
   RTM_DELVLAN,
 #define RTM_DELVLAN RTM_DELVLAN
   RTM_GETVLAN,
@@ -283,6 +291,7 @@ enum rtattr_type_t {
   RTA_SPORT,
   RTA_DPORT,
   RTA_NH_ID,
+  RTA_FLOWLABEL,
   __RTA_MAX
 };
 #define RTA_MAX (__RTA_MAX - 1)
@@ -563,6 +572,12 @@ enum rtnetlink_groups {
 #define RTNLGRP_TUNNEL RTNLGRP_TUNNEL
   RTNLGRP_STATS,
 #define RTNLGRP_STATS RTNLGRP_STATS
+  RTNLGRP_IPV4_MCADDR,
+#define RTNLGRP_IPV4_MCADDR RTNLGRP_IPV4_MCADDR
+  RTNLGRP_IPV6_MCADDR,
+#define RTNLGRP_IPV6_MCADDR RTNLGRP_IPV6_MCADDR
+  RTNLGRP_IPV6_ACADDR,
+#define RTNLGRP_IPV6_ACADDR RTNLGRP_IPV6_ACADDR
   __RTNLGRP_MAX
 };
 #define RTNLGRP_MAX (__RTNLGRP_MAX - 1)
diff --git a/libc/kernel/uapi/linux/securebits.h b/libc/kernel/uapi/linux/securebits.h
index b50eec994..b9f79b327 100644
--- a/libc/kernel/uapi/linux/securebits.h
+++ b/libc/kernel/uapi/linux/securebits.h
@@ -24,6 +24,15 @@
 #define SECURE_NO_CAP_AMBIENT_RAISE_LOCKED 7
 #define SECBIT_NO_CAP_AMBIENT_RAISE (issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
 #define SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED (issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE_LOCKED))
-#define SECURE_ALL_BITS (issecure_mask(SECURE_NOROOT) | issecure_mask(SECURE_NO_SETUID_FIXUP) | issecure_mask(SECURE_KEEP_CAPS) | issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
+#define SECURE_EXEC_RESTRICT_FILE 8
+#define SECURE_EXEC_RESTRICT_FILE_LOCKED 9
+#define SECBIT_EXEC_RESTRICT_FILE (issecure_mask(SECURE_EXEC_RESTRICT_FILE))
+#define SECBIT_EXEC_RESTRICT_FILE_LOCKED (issecure_mask(SECURE_EXEC_RESTRICT_FILE_LOCKED))
+#define SECURE_EXEC_DENY_INTERACTIVE 10
+#define SECURE_EXEC_DENY_INTERACTIVE_LOCKED 11
+#define SECBIT_EXEC_DENY_INTERACTIVE (issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
+#define SECBIT_EXEC_DENY_INTERACTIVE_LOCKED (issecure_mask(SECURE_EXEC_DENY_INTERACTIVE_LOCKED))
+#define SECURE_ALL_BITS (issecure_mask(SECURE_NOROOT) | issecure_mask(SECURE_NO_SETUID_FIXUP) | issecure_mask(SECURE_KEEP_CAPS) | issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE) | issecure_mask(SECURE_EXEC_RESTRICT_FILE) | issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
 #define SECURE_ALL_LOCKS (SECURE_ALL_BITS << 1)
+#define SECURE_ALL_UNPRIVILEGED (issecure_mask(SECURE_EXEC_RESTRICT_FILE) | issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
 #endif
diff --git a/libc/kernel/uapi/linux/sed-opal.h b/libc/kernel/uapi/linux/sed-opal.h
index 6274edef6..285e26b5f 100644
--- a/libc/kernel/uapi/linux/sed-opal.h
+++ b/libc/kernel/uapi/linux/sed-opal.h
@@ -169,4 +169,5 @@ struct opal_revert_lsp {
 #define IOC_OPAL_GET_GEOMETRY _IOR('p', 238, struct opal_geometry)
 #define IOC_OPAL_DISCOVERY _IOW('p', 239, struct opal_discovery)
 #define IOC_OPAL_REVERT_LSP _IOW('p', 240, struct opal_revert_lsp)
+#define IOC_OPAL_SET_SID_PW _IOW('p', 241, struct opal_new_pw)
 #endif
diff --git a/libc/kernel/uapi/linux/snmp.h b/libc/kernel/uapi/linux/snmp.h
index 0f72302ad..558359c77 100644
--- a/libc/kernel/uapi/linux/snmp.h
+++ b/libc/kernel/uapi/linux/snmp.h
@@ -141,6 +141,7 @@ enum {
   LINUX_MIB_TIMEWAITKILLED,
   LINUX_MIB_PAWSACTIVEREJECTED,
   LINUX_MIB_PAWSESTABREJECTED,
+  LINUX_MIB_PAWS_OLD_ACK,
   LINUX_MIB_DELAYEDACKS,
   LINUX_MIB_DELAYEDACKLOCKED,
   LINUX_MIB_DELAYEDACKLOST,
@@ -291,6 +292,8 @@ enum {
   LINUX_MIB_XFRMACQUIREERROR,
   LINUX_MIB_XFRMOUTSTATEDIRERROR,
   LINUX_MIB_XFRMINSTATEDIRERROR,
+  LINUX_MIB_XFRMINIPTFSERROR,
+  LINUX_MIB_XFRMOUTNOQSPACE,
   __LINUX_MIB_XFRMMAX
 };
 enum {
@@ -307,6 +310,11 @@ enum {
   LINUX_MIB_TLSRXDEVICERESYNC,
   LINUX_MIB_TLSDECRYPTRETRY,
   LINUX_MIB_TLSRXNOPADVIOL,
+  LINUX_MIB_TLSRXREKEYOK,
+  LINUX_MIB_TLSRXREKEYERROR,
+  LINUX_MIB_TLSTXREKEYOK,
+  LINUX_MIB_TLSTXREKEYERROR,
+  LINUX_MIB_TLSRXREKEYRECEIVED,
   __LINUX_MIB_TLSMAX
 };
 #endif
diff --git a/libc/kernel/uapi/linux/stat.h b/libc/kernel/uapi/linux/stat.h
index aae9ed4f5..df7703109 100644
--- a/libc/kernel/uapi/linux/stat.h
+++ b/libc/kernel/uapi/linux/stat.h
@@ -72,7 +72,7 @@ struct statx {
   __u32 stx_atomic_write_unit_min;
   __u32 stx_atomic_write_unit_max;
   __u32 stx_atomic_write_segments_max;
-  __u32 __spare1[1];
+  __u32 stx_dio_read_offset_align;
   __u64 __spare3[9];
 };
 #define STATX_TYPE 0x00000001U
@@ -93,6 +93,7 @@ struct statx {
 #define STATX_MNT_ID_UNIQUE 0x00004000U
 #define STATX_SUBVOL 0x00008000U
 #define STATX_WRITE_ATOMIC 0x00010000U
+#define STATX_DIO_READ_ALIGN 0x00020000U
 #define STATX__RESERVED 0x80000000U
 #define STATX_ALL 0x00000fffU
 #define STATX_ATTR_COMPRESSED 0x00000004
diff --git a/libc/kernel/uapi/linux/stddef.h b/libc/kernel/uapi/linux/stddef.h
index dc37c6f3f..6b69b9e04 100644
--- a/libc/kernel/uapi/linux/stddef.h
+++ b/libc/kernel/uapi/linux/stddef.h
@@ -10,7 +10,12 @@
 #ifndef __always_inline
 #define __always_inline inline
 #endif
-#define __struct_group(TAG,NAME,ATTRS,MEMBERS...) union { struct { MEMBERS } ATTRS; struct TAG { MEMBERS } ATTRS NAME; } ATTRS
+#ifndef __cplusplus
+#define __struct_group_tag(TAG) TAG
+#else
+#define __struct_group_tag(TAG)
+#endif
+#define __struct_group(TAG,NAME,ATTRS,MEMBERS...) union { struct { MEMBERS } ATTRS; struct __struct_group_tag(TAG) { MEMBERS } ATTRS NAME; } ATTRS
 #ifdef __cplusplus
 #define __DECLARE_FLEX_ARRAY(T,member) T member[0]
 #else
diff --git a/libc/kernel/uapi/linux/taskstats.h b/libc/kernel/uapi/linux/taskstats.h
index 4914b2f3f..e98c446a6 100644
--- a/libc/kernel/uapi/linux/taskstats.h
+++ b/libc/kernel/uapi/linux/taskstats.h
@@ -7,7 +7,7 @@
 #ifndef _LINUX_TASKSTATS_H
 #define _LINUX_TASKSTATS_H
 #include <linux/types.h>
-#define TASKSTATS_VERSION 14
+#define TASKSTATS_VERSION 15
 #define TS_COMM_LEN 32
 struct taskstats {
   __u16 version;
@@ -16,10 +16,16 @@ struct taskstats {
   __u8 ac_nice;
   __u64 cpu_count __attribute__((aligned(8)));
   __u64 cpu_delay_total;
+  __u64 cpu_delay_max;
+  __u64 cpu_delay_min;
   __u64 blkio_count;
   __u64 blkio_delay_total;
+  __u64 blkio_delay_max;
+  __u64 blkio_delay_min;
   __u64 swapin_count;
   __u64 swapin_delay_total;
+  __u64 swapin_delay_max;
+  __u64 swapin_delay_min;
   __u64 cpu_run_real_total;
   __u64 cpu_run_virtual_total;
   char ac_comm[TS_COMM_LEN];
@@ -54,19 +60,29 @@ struct taskstats {
   __u64 cpu_scaled_run_real_total;
   __u64 freepages_count;
   __u64 freepages_delay_total;
+  __u64 freepages_delay_max;
+  __u64 freepages_delay_min;
   __u64 thrashing_count;
   __u64 thrashing_delay_total;
+  __u64 thrashing_delay_max;
+  __u64 thrashing_delay_min;
   __u64 ac_btime64;
   __u64 compact_count;
   __u64 compact_delay_total;
+  __u64 compact_delay_max;
+  __u64 compact_delay_min;
   __u32 ac_tgid;
   __u64 ac_tgetime __attribute__((aligned(8)));
   __u64 ac_exe_dev;
   __u64 ac_exe_inode;
   __u64 wpcopy_count;
   __u64 wpcopy_delay_total;
+  __u64 wpcopy_delay_max;
+  __u64 wpcopy_delay_min;
   __u64 irq_count;
   __u64 irq_delay_total;
+  __u64 irq_delay_max;
+  __u64 irq_delay_min;
 };
 enum {
   TASKSTATS_CMD_UNSPEC = 0,
diff --git a/libc/kernel/uapi/linux/thermal.h b/libc/kernel/uapi/linux/thermal.h
index f9d67c5c3..79b4079a9 100644
--- a/libc/kernel/uapi/linux/thermal.h
+++ b/libc/kernel/uapi/linux/thermal.h
@@ -7,6 +7,8 @@
 #ifndef _UAPI_LINUX_THERMAL_H
 #define _UAPI_LINUX_THERMAL_H
 #define THERMAL_NAME_LENGTH 20
+#define THERMAL_THRESHOLD_WAY_UP 0x1
+#define THERMAL_THRESHOLD_WAY_DOWN 0x2
 enum thermal_device_mode {
   THERMAL_DEVICE_DISABLED = 0,
   THERMAL_DEVICE_ENABLED,
@@ -18,7 +20,7 @@ enum thermal_trip_type {
   THERMAL_TRIP_CRITICAL,
 };
 #define THERMAL_GENL_FAMILY_NAME "thermal"
-#define THERMAL_GENL_VERSION 0x01
+#define THERMAL_GENL_VERSION 0x02
 #define THERMAL_GENL_SAMPLING_GROUP_NAME "sampling"
 #define THERMAL_GENL_EVENT_GROUP_NAME "event"
 enum thermal_genl_attr {
@@ -46,6 +48,10 @@ enum thermal_genl_attr {
   THERMAL_GENL_ATTR_CPU_CAPABILITY_ID,
   THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE,
   THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY,
+  THERMAL_GENL_ATTR_THRESHOLD,
+  THERMAL_GENL_ATTR_THRESHOLD_TEMP,
+  THERMAL_GENL_ATTR_THRESHOLD_DIRECTION,
+  THERMAL_GENL_ATTR_TZ_PREV_TEMP,
   __THERMAL_GENL_ATTR_MAX,
 };
 #define THERMAL_GENL_ATTR_MAX (__THERMAL_GENL_ATTR_MAX - 1)
@@ -70,6 +76,11 @@ enum thermal_genl_event {
   THERMAL_GENL_EVENT_CDEV_STATE_UPDATE,
   THERMAL_GENL_EVENT_TZ_GOV_CHANGE,
   THERMAL_GENL_EVENT_CPU_CAPABILITY_CHANGE,
+  THERMAL_GENL_EVENT_THRESHOLD_ADD,
+  THERMAL_GENL_EVENT_THRESHOLD_DELETE,
+  THERMAL_GENL_EVENT_THRESHOLD_FLUSH,
+  THERMAL_GENL_EVENT_THRESHOLD_UP,
+  THERMAL_GENL_EVENT_THRESHOLD_DOWN,
   __THERMAL_GENL_EVENT_MAX,
 };
 #define THERMAL_GENL_EVENT_MAX (__THERMAL_GENL_EVENT_MAX - 1)
@@ -81,6 +92,10 @@ enum thermal_genl_cmd {
   THERMAL_GENL_CMD_TZ_GET_GOV,
   THERMAL_GENL_CMD_TZ_GET_MODE,
   THERMAL_GENL_CMD_CDEV_GET,
+  THERMAL_GENL_CMD_THRESHOLD_GET,
+  THERMAL_GENL_CMD_THRESHOLD_ADD,
+  THERMAL_GENL_CMD_THRESHOLD_DELETE,
+  THERMAL_GENL_CMD_THRESHOLD_FLUSH,
   __THERMAL_GENL_CMD_MAX,
 };
 #define THERMAL_GENL_CMD_MAX (__THERMAL_GENL_CMD_MAX - 1)
diff --git a/libc/kernel/uapi/linux/types.h b/libc/kernel/uapi/linux/types.h
index 2f57e85ba..f33febd72 100644
--- a/libc/kernel/uapi/linux/types.h
+++ b/libc/kernel/uapi/linux/types.h
@@ -24,6 +24,7 @@ typedef __u64 __bitwise __be64;
 typedef __u16 __bitwise __sum16;
 typedef __u32 __bitwise __wsum;
 #define __aligned_u64 __u64 __attribute__((aligned(8)))
+#define __aligned_s64 __s64 __attribute__((aligned(8)))
 #define __aligned_be64 __be64 __attribute__((aligned(8)))
 #define __aligned_le64 __le64 __attribute__((aligned(8)))
 typedef unsigned __bitwise __poll_t;
diff --git a/libc/kernel/uapi/linux/ublk_cmd.h b/libc/kernel/uapi/linux/ublk_cmd.h
index 8e7732b62..02c87a1b6 100644
--- a/libc/kernel/uapi/linux/ublk_cmd.h
+++ b/libc/kernel/uapi/linux/ublk_cmd.h
@@ -65,9 +65,11 @@
 #define UBLK_F_CMD_IOCTL_ENCODE (1UL << 6)
 #define UBLK_F_USER_COPY (1UL << 7)
 #define UBLK_F_ZONED (1ULL << 8)
+#define UBLK_F_USER_RECOVERY_FAIL_IO (1ULL << 9)
 #define UBLK_S_DEV_DEAD 0
 #define UBLK_S_DEV_LIVE 1
 #define UBLK_S_DEV_QUIESCED 2
+#define UBLK_S_DEV_FAIL_IO 3
 struct ublksrv_ctrl_cmd {
   __u32 dev_id;
   __u16 queue_id;
diff --git a/libc/kernel/uapi/linux/usb/video.h b/libc/kernel/uapi/linux/usb/video.h
index 8b688e1ae..8eef569f3 100644
--- a/libc/kernel/uapi/linux/usb/video.h
+++ b/libc/kernel/uapi/linux/usb/video.h
@@ -386,4 +386,39 @@ struct uvc_frame_mjpeg {
 #define UVC_FRAME_MJPEG(n) uvc_frame_mjpeg_ ##n
 #define DECLARE_UVC_FRAME_MJPEG(n) struct UVC_FRAME_MJPEG(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bFrameIndex; __u8 bmCapabilities; __le16 wWidth; __le16 wHeight; __le32 dwMinBitRate; __le32 dwMaxBitRate; __le32 dwMaxVideoFrameBufferSize; __le32 dwDefaultFrameInterval; __u8 bFrameIntervalType; __le32 dwFrameInterval[n]; \
 } __attribute__((packed))
+struct uvc_format_framebased {
+  __u8 bLength;
+  __u8 bDescriptorType;
+  __u8 bDescriptorSubType;
+  __u8 bFormatIndex;
+  __u8 bNumFrameDescriptors;
+  __u8 guidFormat[16];
+  __u8 bBitsPerPixel;
+  __u8 bDefaultFrameIndex;
+  __u8 bAspectRatioX;
+  __u8 bAspectRatioY;
+  __u8 bmInterfaceFlags;
+  __u8 bCopyProtect;
+  __u8 bVariableSize;
+} __attribute__((__packed__));
+#define UVC_DT_FORMAT_FRAMEBASED_SIZE 28
+struct uvc_frame_framebased {
+  __u8 bLength;
+  __u8 bDescriptorType;
+  __u8 bDescriptorSubType;
+  __u8 bFrameIndex;
+  __u8 bmCapabilities;
+  __u16 wWidth;
+  __u16 wHeight;
+  __u32 dwMinBitRate;
+  __u32 dwMaxBitRate;
+  __u32 dwDefaultFrameInterval;
+  __u8 bFrameIntervalType;
+  __u32 dwBytesPerLine;
+  __u32 dwFrameInterval[];
+} __attribute__((__packed__));
+#define UVC_DT_FRAME_FRAMEBASED_SIZE(n) (26 + 4 * (n))
+#define UVC_FRAME_FRAMEBASED(n) uvc_frame_framebased_ ##n
+#define DECLARE_UVC_FRAME_FRAMEBASED(n) struct UVC_FRAME_FRAMEBASED(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bFrameIndex; __u8 bmCapabilities; __u16 wWidth; __u16 wHeight; __u32 dwMinBitRate; __u32 dwMaxBitRate; __u32 dwDefaultFrameInterval; __u8 bFrameIntervalType; __u32 dwBytesPerLine; __u32 dwFrameInterval[n]; \
+} __attribute__((packed))
 #endif
diff --git a/libc/kernel/uapi/linux/version.h b/libc/kernel/uapi/linux/version.h
index 728b80a77..70598bae0 100644
--- a/libc/kernel/uapi/linux/version.h
+++ b/libc/kernel/uapi/linux/version.h
@@ -4,8 +4,8 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#define LINUX_VERSION_CODE 396288
+#define LINUX_VERSION_CODE 396800
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 12
+#define LINUX_VERSION_PATCHLEVEL 14
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/libc/kernel/uapi/linux/vfio.h b/libc/kernel/uapi/linux/vfio.h
index 5910e4099..41690e31b 100644
--- a/libc/kernel/uapi/linux/vfio.h
+++ b/libc/kernel/uapi/linux/vfio.h
@@ -14,7 +14,7 @@
 #define VFIO_TYPE1v2_IOMMU 3
 #define VFIO_DMA_CC_IOMMU 4
 #define VFIO_EEH 5
-#define VFIO_TYPE1_NESTING_IOMMU 6
+#define __VFIO_RESERVED_TYPE1_NESTING_IOMMU 6
 #define VFIO_SPAPR_TCE_v2_IOMMU 7
 #define VFIO_NOIOMMU_IOMMU 8
 #define VFIO_UNMAP_ALL 9
diff --git a/libc/kernel/uapi/linux/videodev2.h b/libc/kernel/uapi/linux/videodev2.h
index e49f5ea90..28c92539b 100644
--- a/libc/kernel/uapi/linux/videodev2.h
+++ b/libc/kernel/uapi/linux/videodev2.h
@@ -412,6 +412,7 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_S5C_UYVY_JPG v4l2_fourcc('S', '5', 'C', 'I')
 #define V4L2_PIX_FMT_Y8I v4l2_fourcc('Y', '8', 'I', ' ')
 #define V4L2_PIX_FMT_Y12I v4l2_fourcc('Y', '1', '2', 'I')
+#define V4L2_PIX_FMT_Y16I v4l2_fourcc('Y', '1', '6', 'I')
 #define V4L2_PIX_FMT_Z16 v4l2_fourcc('Z', '1', '6', ' ')
 #define V4L2_PIX_FMT_MT21C v4l2_fourcc('M', 'T', '2', '1')
 #define V4L2_PIX_FMT_MM21 v4l2_fourcc('M', 'M', '2', '1')
@@ -459,6 +460,8 @@ struct v4l2_pix_format {
 #define V4L2_META_FMT_RK_ISP1_STAT_3A v4l2_fourcc('R', 'K', '1', 'S')
 #define V4L2_META_FMT_RK_ISP1_EXT_PARAMS v4l2_fourcc('R', 'K', '1', 'E')
 #define V4L2_META_FMT_RPI_BE_CFG v4l2_fourcc('R', 'P', 'B', 'C')
+#define V4L2_META_FMT_RPI_FE_CFG v4l2_fourcc('R', 'P', 'F', 'C')
+#define V4L2_META_FMT_RPI_FE_STATS v4l2_fourcc('R', 'P', 'F', 'S')
 #define V4L2_PIX_FMT_PRIV_MAGIC 0xfeedcafe
 #define V4L2_PIX_FMT_FLAG_PREMUL_ALPHA 0x00000001
 #define V4L2_PIX_FMT_FLAG_SET_CSC 0x00000002
@@ -482,6 +485,7 @@ struct v4l2_fmtdesc {
 #define V4L2_FMT_FLAG_CSC_HSV_ENC V4L2_FMT_FLAG_CSC_YCBCR_ENC
 #define V4L2_FMT_FLAG_CSC_QUANTIZATION 0x0100
 #define V4L2_FMT_FLAG_META_LINE_BASED 0x0200
+#define V4L2_FMTDESC_FLAG_ENUM_ALL 0x80000000
 enum v4l2_frmsizetypes {
   V4L2_FRMSIZE_TYPE_DISCRETE = 1,
   V4L2_FRMSIZE_TYPE_CONTINUOUS = 2,
diff --git a/libc/kernel/uapi/linux/virtio_pci.h b/libc/kernel/uapi/linux/virtio_pci.h
index 892115570..4d1bf90c3 100644
--- a/libc/kernel/uapi/linux/virtio_pci.h
+++ b/libc/kernel/uapi/linux/virtio_pci.h
@@ -7,6 +7,7 @@
 #ifndef _LINUX_VIRTIO_PCI_H
 #define _LINUX_VIRTIO_PCI_H
 #include <linux/types.h>
+#include <linux/kernel.h>
 #ifndef VIRTIO_PCI_NO_LEGACY
 #define VIRTIO_PCI_HOST_FEATURES 0
 #define VIRTIO_PCI_GUEST_FEATURES 4
@@ -33,6 +34,7 @@
 #define VIRTIO_PCI_CAP_DEVICE_CFG 4
 #define VIRTIO_PCI_CAP_PCI_CFG 5
 #define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8
+#define VIRTIO_PCI_CAP_VENDOR_CFG 9
 struct virtio_pci_cap {
   __u8 cap_vndr;
   __u8 cap_next;
@@ -44,6 +46,13 @@ struct virtio_pci_cap {
   __le32 offset;
   __le32 length;
 };
+struct virtio_pci_vndr_data {
+  __u8 cap_vndr;
+  __u8 cap_next;
+  __u8 cap_len;
+  __u8 cfg_type;
+  __u16 vendor_id;
+};
 struct virtio_pci_cap64 {
   struct virtio_pci_cap cap;
   __le32 offset_hi;
@@ -126,6 +135,15 @@ struct virtio_pci_cfg_cap {
 #define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_WRITE 0x4
 #define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_READ 0x5
 #define VIRTIO_ADMIN_CMD_LEGACY_NOTIFY_INFO 0x6
+#define VIRTIO_ADMIN_CMD_CAP_ID_LIST_QUERY 0x7
+#define VIRTIO_ADMIN_CMD_DEVICE_CAP_GET 0x8
+#define VIRTIO_ADMIN_CMD_DRIVER_CAP_SET 0x9
+#define VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE 0xa
+#define VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY 0xd
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET 0xe
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET 0xf
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_SET 0x10
+#define VIRTIO_ADMIN_CMD_DEV_MODE_SET 0x11
 struct virtio_admin_cmd_hdr {
   __le16 opcode;
   __le16 group_type;
@@ -158,4 +176,101 @@ struct virtio_admin_cmd_notify_info_data {
 struct virtio_admin_cmd_notify_info_result {
   struct virtio_admin_cmd_notify_info_data entries[VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO];
 };
+#define VIRTIO_DEV_PARTS_CAP 0x0000
+struct virtio_dev_parts_cap {
+  __u8 get_parts_resource_objects_limit;
+  __u8 set_parts_resource_objects_limit;
+};
+#define MAX_CAP_ID __KERNEL_DIV_ROUND_UP(VIRTIO_DEV_PARTS_CAP + 1, 64)
+struct virtio_admin_cmd_query_cap_id_result {
+  __le64 supported_caps[MAX_CAP_ID];
+};
+struct virtio_admin_cmd_cap_get_data {
+  __le16 id;
+  __u8 reserved[6];
+};
+struct virtio_admin_cmd_cap_set_data {
+  __le16 id;
+  __u8 reserved[6];
+  __u8 cap_specific_data[];
+};
+struct virtio_admin_cmd_resource_obj_cmd_hdr {
+  __le16 type;
+  __u8 reserved[2];
+  __le32 id;
+};
+struct virtio_admin_cmd_resource_obj_create_data {
+  struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+  __le64 flags;
+  __u8 resource_obj_specific_data[];
+};
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS 0
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS_TYPE_GET 0
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS_TYPE_SET 1
+struct virtio_resource_obj_dev_parts {
+  __u8 type;
+  __u8 reserved[7];
+};
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_SIZE 0
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_COUNT 1
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_LIST 2
+struct virtio_admin_cmd_dev_parts_metadata_data {
+  struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+  __u8 type;
+  __u8 reserved[7];
+};
+#define VIRTIO_DEV_PART_F_OPTIONAL 0
+struct virtio_dev_part_hdr {
+  __le16 part_type;
+  __u8 flags;
+  __u8 reserved;
+  union {
+    struct {
+      __le32 offset;
+      __le32 reserved;
+    } pci_common_cfg;
+    struct {
+      __le16 index;
+      __u8 reserved[6];
+    } vq_index;
+  } selector;
+  __le32 length;
+};
+struct virtio_dev_part {
+  struct virtio_dev_part_hdr hdr;
+  __u8 value[];
+};
+struct virtio_admin_cmd_dev_parts_metadata_result {
+  union {
+    struct {
+      __le32 size;
+      __le32 reserved;
+    } parts_size;
+    struct {
+      __le32 count;
+      __le32 reserved;
+    } hdr_list_count;
+    struct {
+      __le32 count;
+      __le32 reserved;
+      struct virtio_dev_part_hdr hdrs[];
+    } hdr_list;
+  };
+};
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET_TYPE_SELECTED 0
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET_TYPE_ALL 1
+struct virtio_admin_cmd_dev_parts_get_data {
+  struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+  __u8 type;
+  __u8 reserved[7];
+  struct virtio_dev_part_hdr hdr_list[];
+};
+struct virtio_admin_cmd_dev_parts_set_data {
+  struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+  struct virtio_dev_part parts[];
+};
+#define VIRTIO_ADMIN_CMD_DEV_MODE_F_STOPPED 0
+struct virtio_admin_cmd_dev_mode_set_data {
+  __u8 flags;
+};
 #endif
diff --git a/libc/kernel/uapi/linux/vmclock-abi.h b/libc/kernel/uapi/linux/vmclock-abi.h
new file mode 100644
index 000000000..cd6737688
--- /dev/null
+++ b/libc/kernel/uapi/linux/vmclock-abi.h
@@ -0,0 +1,65 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef __VMCLOCK_ABI_H__
+#define __VMCLOCK_ABI_H__
+#include <linux/types.h>
+struct vmclock_abi {
+  __le32 magic;
+#define VMCLOCK_MAGIC 0x4b4c4356
+  __le32 size;
+  __le16 version;
+  __u8 counter_id;
+#define VMCLOCK_COUNTER_ARM_VCNT 0
+#define VMCLOCK_COUNTER_X86_TSC 1
+#define VMCLOCK_COUNTER_INVALID 0xff
+  __u8 time_type;
+#define VMCLOCK_TIME_UTC 0
+#define VMCLOCK_TIME_TAI 1
+#define VMCLOCK_TIME_MONOTONIC 2
+#define VMCLOCK_TIME_INVALID_SMEARED 3
+#define VMCLOCK_TIME_INVALID_MAYBE_SMEARED 4
+  __le32 seq_count;
+  __le64 disruption_marker;
+  __le64 flags;
+#define VMCLOCK_FLAG_TAI_OFFSET_VALID (1 << 0)
+#define VMCLOCK_FLAG_DISRUPTION_SOON (1 << 1)
+#define VMCLOCK_FLAG_DISRUPTION_IMMINENT (1 << 2)
+#define VMCLOCK_FLAG_PERIOD_ESTERROR_VALID (1 << 3)
+#define VMCLOCK_FLAG_PERIOD_MAXERROR_VALID (1 << 4)
+#define VMCLOCK_FLAG_TIME_ESTERROR_VALID (1 << 5)
+#define VMCLOCK_FLAG_TIME_MAXERROR_VALID (1 << 6)
+#define VMCLOCK_FLAG_TIME_MONOTONIC (1 << 7)
+  __u8 pad[2];
+  __u8 clock_status;
+#define VMCLOCK_STATUS_UNKNOWN 0
+#define VMCLOCK_STATUS_INITIALIZING 1
+#define VMCLOCK_STATUS_SYNCHRONIZED 2
+#define VMCLOCK_STATUS_FREERUNNING 3
+#define VMCLOCK_STATUS_UNRELIABLE 4
+  __u8 leap_second_smearing_hint;
+#define VMCLOCK_SMEARING_STRICT 0
+#define VMCLOCK_SMEARING_NOON_LINEAR 1
+#define VMCLOCK_SMEARING_UTC_SLS 2
+  __le16 tai_offset_sec;
+  __u8 leap_indicator;
+#define VMCLOCK_LEAP_NONE 0x00
+#define VMCLOCK_LEAP_PRE_POS 0x01
+#define VMCLOCK_LEAP_PRE_NEG 0x02
+#define VMCLOCK_LEAP_POS 0x03
+#define VMCLOCK_LEAP_POST_POS 0x04
+#define VMCLOCK_LEAP_POST_NEG 0x05
+  __u8 counter_period_shift;
+  __le64 counter_value;
+  __le64 counter_period_frac_sec;
+  __le64 counter_period_esterror_rate_frac_sec;
+  __le64 counter_period_maxerror_rate_frac_sec;
+  __le64 time_sec;
+  __le64 time_frac_sec;
+  __le64 time_esterror_nanosec;
+  __le64 time_maxerror_nanosec;
+};
+#endif
diff --git a/libc/kernel/uapi/linux/xattr.h b/libc/kernel/uapi/linux/xattr.h
index e126151c7..4f1bad716 100644
--- a/libc/kernel/uapi/linux/xattr.h
+++ b/libc/kernel/uapi/linux/xattr.h
@@ -5,12 +5,18 @@
  * for more information.
  */
 #include <linux/libc-compat.h>
+#include <linux/types.h>
 #ifndef _UAPI_LINUX_XATTR_H
 #define _UAPI_LINUX_XATTR_H
 #if __UAPI_DEF_XATTR
 #define __USE_KERNEL_XATTR_DEFS
 #define XATTR_CREATE 0x1
 #define XATTR_REPLACE 0x2
+struct xattr_args {
+  __aligned_u64  value;
+  __u32 size;
+  __u32 flags;
+};
 #endif
 #define XATTR_OS2_PREFIX "os2."
 #define XATTR_OS2_PREFIX_LEN (sizeof(XATTR_OS2_PREFIX) - 1)
diff --git a/libc/kernel/uapi/linux/xfrm.h b/libc/kernel/uapi/linux/xfrm.h
index 9509efe02..50cf1cd02 100644
--- a/libc/kernel/uapi/linux/xfrm.h
+++ b/libc/kernel/uapi/linux/xfrm.h
@@ -126,7 +126,8 @@ enum {
 #define XFRM_MODE_ROUTEOPTIMIZATION 2
 #define XFRM_MODE_IN_TRIGGER 3
 #define XFRM_MODE_BEET 4
-#define XFRM_MODE_MAX 5
+#define XFRM_MODE_IPTFS 5
+#define XFRM_MODE_MAX 6
 enum {
   XFRM_MSG_BASE = 0x10,
   XFRM_MSG_NEWSA = 0x10,
@@ -261,6 +262,13 @@ enum xfrm_attr_type_t {
   XFRMA_MTIMER_THRESH,
   XFRMA_SA_DIR,
   XFRMA_NAT_KEEPALIVE_INTERVAL,
+  XFRMA_SA_PCPU,
+  XFRMA_IPTFS_DROP_TIME,
+  XFRMA_IPTFS_REORDER_WINDOW,
+  XFRMA_IPTFS_DONT_FRAG,
+  XFRMA_IPTFS_INIT_DELAY,
+  XFRMA_IPTFS_MAX_QSIZE,
+  XFRMA_IPTFS_PKT_SIZE,
   __XFRMA_MAX
 #define XFRMA_OUTPUT_MARK XFRMA_SET_MARK
 #define XFRMA_MAX (__XFRMA_MAX - 1)
@@ -359,6 +367,7 @@ struct xfrm_userpolicy_info {
   __u8 flags;
 #define XFRM_POLICY_LOCALOK 1
 #define XFRM_POLICY_ICMP 2
+#define XFRM_POLICY_CPU_ACQUIRE 4
   __u8 share;
 };
 struct xfrm_userpolicy_id {
diff --git a/libc/kernel/uapi/mtd/ubi-user.h b/libc/kernel/uapi/mtd/ubi-user.h
index bb9a6cbcb..4c22a9b2f 100644
--- a/libc/kernel/uapi/mtd/ubi-user.h
+++ b/libc/kernel/uapi/mtd/ubi-user.h
@@ -17,6 +17,7 @@
 #define UBI_IOCRNVOL _IOW(UBI_IOC_MAGIC, 3, struct ubi_rnvol_req)
 #define UBI_IOCRPEB _IOW(UBI_IOC_MAGIC, 4, __s32)
 #define UBI_IOCSPEB _IOW(UBI_IOC_MAGIC, 5, __s32)
+#define UBI_IOCECNFO _IOWR(UBI_IOC_MAGIC, 6, struct ubi_ecinfo_req)
 #define UBI_CTRL_IOC_MAGIC 'o'
 #define UBI_IOCATT _IOW(UBI_CTRL_IOC_MAGIC, 64, struct ubi_attach_req)
 #define UBI_IOCDET _IOW(UBI_CTRL_IOC_MAGIC, 65, __s32)
@@ -76,6 +77,13 @@ struct ubi_rnvol_req {
     char name[UBI_MAX_VOLUME_NAME + 1];
   } ents[UBI_MAX_RNVOL];
 } __attribute__((__packed__));
+struct ubi_ecinfo_req {
+  __s32 start;
+  __s32 length;
+  __s32 read_length;
+  __s8 padding[16];
+  __s32 erase_counters[];
+} __attribute__((__packed__));
 struct ubi_leb_change_req {
   __s32 lnum;
   __s32 bytes;
diff --git a/libc/kernel/uapi/rdma/efa-abi.h b/libc/kernel/uapi/rdma/efa-abi.h
index d4a908975..3e807d29d 100644
--- a/libc/kernel/uapi/rdma/efa-abi.h
+++ b/libc/kernel/uapi/rdma/efa-abi.h
@@ -72,7 +72,8 @@ struct efa_ibv_create_qp {
   __u32 sq_ring_size;
   __u32 driver_qp_type;
   __u16 flags;
-  __u8 reserved_90[6];
+  __u8 sl;
+  __u8 reserved_98[5];
 };
 struct efa_ibv_create_qp_resp {
   __u32 comp_mask;
diff --git a/libc/kernel/uapi/rdma/mlx5-abi.h b/libc/kernel/uapi/rdma/mlx5-abi.h
index 22cf99e25..7989456d7 100644
--- a/libc/kernel/uapi/rdma/mlx5-abi.h
+++ b/libc/kernel/uapi/rdma/mlx5-abi.h
@@ -165,6 +165,7 @@ enum mlx5_ib_query_dev_resp_flags {
   MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD = 1 << 1,
   MLX5_IB_QUERY_DEV_RESP_PACKET_BASED_CREDIT_MODE = 1 << 2,
   MLX5_IB_QUERY_DEV_RESP_FLAGS_SCAT2CQE_DCT = 1 << 3,
+  MLX5_IB_QUERY_DEV_RESP_FLAGS_OOO_DP = 1 << 4,
 };
 enum mlx5_ib_tunnel_offloads {
   MLX5_IB_TUNNELED_OFFLOADS_VXLAN = 1 << 0,
@@ -321,6 +322,9 @@ struct mlx5_ib_burst_info {
   __u16 typical_pkt_sz;
   __u16 reserved;
 };
+enum mlx5_ib_modify_qp_mask {
+  MLX5_IB_MODIFY_QP_OOO_DP = 1 << 0,
+};
 struct mlx5_ib_modify_qp {
   __u32 comp_mask;
   struct mlx5_ib_burst_info burst_info;
diff --git a/libc/kernel/uapi/rdma/rdma_netlink.h b/libc/kernel/uapi/rdma/rdma_netlink.h
index 137b68ff1..593d21b14 100644
--- a/libc/kernel/uapi/rdma/rdma_netlink.h
+++ b/libc/kernel/uapi/rdma/rdma_netlink.h
@@ -339,5 +339,7 @@ enum rdma_nl_notify_event_type {
   RDMA_UNREGISTER_EVENT,
   RDMA_NETDEV_ATTACH_EVENT,
   RDMA_NETDEV_DETACH_EVENT,
+  RDMA_RENAME_EVENT,
+  RDMA_NETDEV_RENAME_EVENT,
 };
 #endif
diff --git a/libc/kernel/uapi/sound/asequencer.h b/libc/kernel/uapi/sound/asequencer.h
index 83b38f1c7..6b9d0240f 100644
--- a/libc/kernel/uapi/sound/asequencer.h
+++ b/libc/kernel/uapi/sound/asequencer.h
@@ -7,7 +7,7 @@
 #ifndef _UAPI__SOUND_ASEQUENCER_H
 #define _UAPI__SOUND_ASEQUENCER_H
 #include <sound/asound.h>
-#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 4)
+#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 5)
 #define SNDRV_SEQ_EVENT_SYSTEM 0
 #define SNDRV_SEQ_EVENT_RESULT 1
 #define SNDRV_SEQ_EVENT_NOTE 5
@@ -48,6 +48,8 @@
 #define SNDRV_SEQ_EVENT_PORT_CHANGE 65
 #define SNDRV_SEQ_EVENT_PORT_SUBSCRIBED 66
 #define SNDRV_SEQ_EVENT_PORT_UNSUBSCRIBED 67
+#define SNDRV_SEQ_EVENT_UMP_EP_CHANGE 68
+#define SNDRV_SEQ_EVENT_UMP_BLOCK_CHANGE 69
 #define SNDRV_SEQ_EVENT_USR0 90
 #define SNDRV_SEQ_EVENT_USR1 91
 #define SNDRV_SEQ_EVENT_USR2 92
@@ -152,6 +154,10 @@ struct snd_seq_ev_quote {
   unsigned short value;
   struct snd_seq_event * event;
 } __attribute__((__packed__));
+struct snd_seq_ev_ump_notify {
+  unsigned char client;
+  unsigned char block;
+};
 union snd_seq_event_data {
   struct snd_seq_ev_note note;
   struct snd_seq_ev_ctrl control;
@@ -164,6 +170,7 @@ union snd_seq_event_data {
   struct snd_seq_connect connect;
   struct snd_seq_result result;
   struct snd_seq_ev_quote quote;
+  struct snd_seq_ev_ump_notify ump_notify;
 };
 struct snd_seq_event {
   snd_seq_event_type_t type;
diff --git a/libc/kernel/uapi/sound/asound.h b/libc/kernel/uapi/sound/asound.h
index cbebef367..6048a778f 100644
--- a/libc/kernel/uapi/sound/asound.h
+++ b/libc/kernel/uapi/sound/asound.h
@@ -559,7 +559,7 @@ enum {
 #define SNDRV_PCM_IOCTL_READN_FRAMES _IOR('A', 0x53, struct snd_xfern)
 #define SNDRV_PCM_IOCTL_LINK _IOW('A', 0x60, int)
 #define SNDRV_PCM_IOCTL_UNLINK _IO('A', 0x61)
-#define SNDRV_RAWMIDI_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 4)
+#define SNDRV_RAWMIDI_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 5)
 enum {
   SNDRV_RAWMIDI_STREAM_OUTPUT = 0,
   SNDRV_RAWMIDI_STREAM_INPUT,
@@ -569,6 +569,8 @@ enum {
 #define SNDRV_RAWMIDI_INFO_INPUT 0x00000002
 #define SNDRV_RAWMIDI_INFO_DUPLEX 0x00000004
 #define SNDRV_RAWMIDI_INFO_UMP 0x00000008
+#define SNDRV_RAWMIDI_INFO_STREAM_INACTIVE 0x00000010
+#define SNDRV_RAWMIDI_DEVICE_UNKNOWN 0
 struct snd_rawmidi_info {
   unsigned int device;
   unsigned int subdevice;
@@ -580,7 +582,8 @@ struct snd_rawmidi_info {
   unsigned char subname[32];
   unsigned int subdevices_count;
   unsigned int subdevices_avail;
-  unsigned char reserved[64];
+  int tied_device;
+  unsigned char reserved[60];
 };
 #define SNDRV_RAWMIDI_MODE_FRAMING_MASK (7 << 0)
 #define SNDRV_RAWMIDI_MODE_FRAMING_SHIFT 0
diff --git a/libc/kernel/uapi/sound/compress_offload.h b/libc/kernel/uapi/sound/compress_offload.h
index db72c2974..f0144922d 100644
--- a/libc/kernel/uapi/sound/compress_offload.h
+++ b/libc/kernel/uapi/sound/compress_offload.h
@@ -9,7 +9,7 @@
 #include <linux/types.h>
 #include <sound/asound.h>
 #include <sound/compress_params.h>
-#define SNDRV_COMPRESS_VERSION SNDRV_PROTOCOL_VERSION(0, 2, 0)
+#define SNDRV_COMPRESS_VERSION SNDRV_PROTOCOL_VERSION(0, 3, 0)
 struct snd_compressed_buffer {
   __u32 fragment_size;
   __u32 fragments;
@@ -32,7 +32,8 @@ struct snd_compr_avail {
 } __attribute__((packed, aligned(4)));
 enum snd_compr_direction {
   SND_COMPRESS_PLAYBACK = 0,
-  SND_COMPRESS_CAPTURE
+  SND_COMPRESS_CAPTURE,
+  SND_COMPRESS_ACCEL
 };
 struct snd_compr_caps {
   __u32 num_codecs;
@@ -57,6 +58,29 @@ struct snd_compr_metadata {
   __u32 key;
   __u32 value[8];
 } __attribute__((packed, aligned(4)));
+#define SND_COMPRESS_TFLG_NEW_STREAM (1 << 0)
+struct snd_compr_task {
+  __u64 seqno;
+  __u64 origin_seqno;
+  int input_fd;
+  int output_fd;
+  __u64 input_size;
+  __u32 flags;
+  __u8 reserved[16];
+} __attribute__((packed, aligned(4)));
+enum snd_compr_state {
+  SND_COMPRESS_TASK_STATE_IDLE = 0,
+  SND_COMPRESS_TASK_STATE_ACTIVE,
+  SND_COMPRESS_TASK_STATE_FINISHED
+};
+struct snd_compr_task_status {
+  __u64 seqno;
+  __u64 input_size;
+  __u64 output_size;
+  __u32 output_flags;
+  __u8 state;
+  __u8 reserved[15];
+} __attribute__((packed, aligned(4)));
 #define SNDRV_COMPRESS_IOCTL_VERSION _IOR('C', 0x00, int)
 #define SNDRV_COMPRESS_GET_CAPS _IOWR('C', 0x10, struct snd_compr_caps)
 #define SNDRV_COMPRESS_GET_CODEC_CAPS _IOWR('C', 0x11, struct snd_compr_codec_caps)
@@ -73,6 +97,11 @@ struct snd_compr_metadata {
 #define SNDRV_COMPRESS_DRAIN _IO('C', 0x34)
 #define SNDRV_COMPRESS_NEXT_TRACK _IO('C', 0x35)
 #define SNDRV_COMPRESS_PARTIAL_DRAIN _IO('C', 0x36)
+#define SNDRV_COMPRESS_TASK_CREATE _IOWR('C', 0x60, struct snd_compr_task)
+#define SNDRV_COMPRESS_TASK_FREE _IOW('C', 0x61, __u64)
+#define SNDRV_COMPRESS_TASK_START _IOWR('C', 0x62, struct snd_compr_task)
+#define SNDRV_COMPRESS_TASK_STOP _IOW('C', 0x63, __u64)
+#define SNDRV_COMPRESS_TASK_STATUS _IOWR('C', 0x68, struct snd_compr_task_status)
 #define SND_COMPR_TRIGGER_DRAIN 7
 #define SND_COMPR_TRIGGER_NEXT_TRACK 8
 #define SND_COMPR_TRIGGER_PARTIAL_DRAIN 9
diff --git a/libc/kernel/uapi/sound/compress_params.h b/libc/kernel/uapi/sound/compress_params.h
index 800f8f987..892054598 100644
--- a/libc/kernel/uapi/sound/compress_params.h
+++ b/libc/kernel/uapi/sound/compress_params.h
@@ -198,6 +198,13 @@ union snd_codec_options {
   struct snd_dec_wma wma_d;
   struct snd_dec_alac alac_d;
   struct snd_dec_ape ape_d;
+  struct {
+    __u32 out_sample_rate;
+  } src_d;
+} __attribute__((packed, aligned(4)));
+struct snd_codec_desc_src {
+  __u32 out_sample_rate_min;
+  __u32 out_sample_rate_max;
 } __attribute__((packed, aligned(4)));
 struct snd_codec_desc {
   __u32 max_ch;
@@ -210,7 +217,12 @@ struct snd_codec_desc {
   __u32 modes;
   __u32 formats;
   __u32 min_buffer;
-  __u32 reserved[15];
+  __u32 pcm_formats;
+  union {
+    __u32 u_space[6];
+    struct snd_codec_desc_src src;
+  } __attribute__((packed, aligned(4)));
+  __u32 reserved[8];
 } __attribute__((packed, aligned(4)));
 struct snd_codec {
   __u32 id;
@@ -225,6 +237,7 @@ struct snd_codec {
   __u32 format;
   __u32 align;
   union snd_codec_options options;
-  __u32 reserved[3];
+  __u32 pcm_format;
+  __u32 reserved[2];
 } __attribute__((packed, aligned(4)));
 #endif
diff --git a/libc/kernel/uapi/sound/fcp.h b/libc/kernel/uapi/sound/fcp.h
new file mode 100644
index 000000000..104c5e0e3
--- /dev/null
+++ b/libc/kernel/uapi/sound/fcp.h
@@ -0,0 +1,45 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef __UAPI_SOUND_FCP_H
+#define __UAPI_SOUND_FCP_H
+#include <linux/types.h>
+#include <linux/ioctl.h>
+#define FCP_HWDEP_MAJOR 2
+#define FCP_HWDEP_MINOR 0
+#define FCP_HWDEP_SUBMINOR 0
+#define FCP_HWDEP_VERSION ((FCP_HWDEP_MAJOR << 16) | (FCP_HWDEP_MINOR << 8) | FCP_HWDEP_SUBMINOR)
+#define FCP_HWDEP_VERSION_MAJOR(v) (((v) >> 16) & 0xFF)
+#define FCP_HWDEP_VERSION_MINOR(v) (((v) >> 8) & 0xFF)
+#define FCP_HWDEP_VERSION_SUBMINOR(v) ((v) & 0xFF)
+#define FCP_IOCTL_PVERSION _IOR('S', 0x60, int)
+struct fcp_init {
+  __u16 step0_resp_size;
+  __u16 step2_resp_size;
+  __u32 init1_opcode;
+  __u32 init2_opcode;
+  __u8 resp[];
+} __attribute__((packed));
+#define FCP_IOCTL_INIT _IOWR('S', 0x64, struct fcp_init)
+struct fcp_cmd {
+  __u32 opcode;
+  __u16 req_size;
+  __u16 resp_size;
+  __u8 data[];
+} __attribute__((packed));
+#define FCP_IOCTL_CMD _IOWR('S', 0x65, struct fcp_cmd)
+struct fcp_meter_map {
+  __u16 map_size;
+  __u16 meter_slots;
+  __s16 map[];
+} __attribute__((packed));
+#define FCP_IOCTL_SET_METER_MAP _IOW('S', 0x66, struct fcp_meter_map)
+struct fcp_meter_labels {
+  __u16 labels_size;
+  char labels[];
+} __attribute__((packed));
+#define FCP_IOCTL_SET_METER_LABELS _IOW('S', 0x67, struct fcp_meter_labels)
+#endif
diff --git a/libc/kernel/uapi/sound/sof/tokens.h b/libc/kernel/uapi/sound/sof/tokens.h
index c4257d949..922dec0bd 100644
--- a/libc/kernel/uapi/sound/sof/tokens.h
+++ b/libc/kernel/uapi/sound/sof/tokens.h
@@ -86,6 +86,8 @@
 #define SOF_TKN_IMX_ESAI_MCLK_ID 1100
 #define SOF_TKN_STREAM_PLAYBACK_COMPATIBLE_D0I3 1200
 #define SOF_TKN_STREAM_CAPTURE_COMPATIBLE_D0I3 1201
+#define SOF_TKN_STREAM_PLAYBACK_PAUSE_SUPPORTED 1202
+#define SOF_TKN_STREAM_CAPTURE_PAUSE_SUPPORTED 1203
 #define SOF_TKN_MUTE_LED_USE 1300
 #define SOF_TKN_MUTE_LED_DIRECTION 1301
 #define SOF_TKN_INTEL_ALH_RATE 1400
diff --git a/libc/kernel/uapi/sound/tlv.h b/libc/kernel/uapi/sound/tlv.h
index d9df82fce..b31a5ef0a 100644
--- a/libc/kernel/uapi/sound/tlv.h
+++ b/libc/kernel/uapi/sound/tlv.h
@@ -15,6 +15,7 @@
 #define SNDRV_CTL_TLVT_CHMAP_FIXED 0x101
 #define SNDRV_CTL_TLVT_CHMAP_VAR 0x102
 #define SNDRV_CTL_TLVT_CHMAP_PAIRED 0x103
+#define SNDRV_CTL_TLVT_FCP_CHANNEL_LABELS 0x110
 #define SNDRV_CTL_TLVD_ITEM(type,...) (type), SNDRV_CTL_TLVD_LENGTH(__VA_ARGS__), __VA_ARGS__
 #define SNDRV_CTL_TLVD_LENGTH(...) ((unsigned int) sizeof((const unsigned int[]) { __VA_ARGS__ }))
 #define SNDRV_CTL_TLVO_TYPE 0
diff --git a/libc/malloc_debug/Android.bp b/libc/malloc_debug/Android.bp
index 50f24f6c7..408a04696 100644
--- a/libc/malloc_debug/Android.bp
+++ b/libc/malloc_debug/Android.bp
@@ -125,18 +125,12 @@ cc_library {
 // ==============================================================
 // Unit Tests
 // ==============================================================
-cc_test {
-    name: "malloc_debug_unit_tests",
-    test_suites: ["device-tests"],
-    isolated: true,
+cc_defaults {
+    name: "malloc_debug_tests",
 
     srcs: [
-        "tests/backtrace_fake.cpp",
         "tests/log_fake.cpp",
         "tests/libc_fake.cpp",
-        "tests/malloc_debug_config_tests.cpp",
-        "tests/malloc_debug_record_data_tests.cpp",
-        "tests/malloc_debug_unit_tests.cpp",
     ],
 
     local_include_dirs: ["tests"],
@@ -149,16 +143,15 @@ cc_test {
         "bionic_libc_platform_headers",
     ],
 
-    static_libs: [
-        "libc_malloc_debug",
-        "libtinyxml2",
-    ],
-
     shared_libs: [
         "libbase",
         "libunwindstack",
     ],
 
+    static_libs: [
+        "libc_malloc_debug",
+    ],
+
     cflags: [
         "-Wall",
         "-Werror",
@@ -167,6 +160,41 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "malloc_debug_system_record_unit_tests",
+    defaults: ["malloc_debug_tests"],
+    test_suites: ["device-tests"],
+    isolated: true,
+
+    srcs: [
+        "tests/malloc_debug_config_tests.cpp",
+        "tests/malloc_debug_record_data_tests.cpp",
+    ],
+}
+
+cc_test {
+    name: "malloc_debug_unit_tests",
+    defaults: ["malloc_debug_tests"],
+    test_suites: ["device-tests"],
+    isolated: true,
+
+    srcs: [
+        "tests/backtrace_fake.cpp",
+        "tests/malloc_debug_unit_tests.cpp",
+    ],
+
+    static_libs: [
+        "libtinyxml2",
+    ],
+
+    cflags: [
+        // This code uses malloc_usable_size(),
+        // and thus can't be built with _FORTIFY_SOURCE=3.
+        "-U_FORTIFY_SOURCE",
+        "-D_FORTIFY_SOURCE=2",
+    ],
+}
+
 // ==============================================================
 // System Tests
 // ==============================================================
diff --git a/libc/malloc_debug/Config.cpp b/libc/malloc_debug/Config.cpp
index 6be899d7e..f20bc10ce 100644
--- a/libc/malloc_debug/Config.cpp
+++ b/libc/malloc_debug/Config.cpp
@@ -282,7 +282,7 @@ bool Config::SetGuard(const std::string& option, const std::string& value) {
 
   // It's necessary to align the front guard to MINIMUM_ALIGNMENT_BYTES to
   // make sure that the header is aligned properly.
-  front_guard_bytes_ = __BIONIC_ALIGN(rear_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
+  front_guard_bytes_ = __builtin_align_up(rear_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
   return true;
 }
 
@@ -292,7 +292,7 @@ bool Config::SetFrontGuard(const std::string& option, const std::string& value)
   }
   // It's necessary to align the front guard to MINIMUM_ALIGNMENT_BYTES to
   // make sure that the header is aligned properly.
-  front_guard_bytes_ = __BIONIC_ALIGN(front_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
+  front_guard_bytes_ = __builtin_align_up(front_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
   return true;
 }
 
diff --git a/libc/malloc_debug/DebugData.cpp b/libc/malloc_debug/DebugData.cpp
index 885cc9591..e8e695b95 100644
--- a/libc/malloc_debug/DebugData.cpp
+++ b/libc/malloc_debug/DebugData.cpp
@@ -44,7 +44,7 @@ bool DebugData::Initialize(const char* options) {
   // Check to see if the options that require a header are enabled.
   if (config_.options() & HEADER_OPTIONS) {
     // Initialize all of the static header offsets.
-    pointer_offset_ = __BIONIC_ALIGN(sizeof(Header), MINIMUM_ALIGNMENT_BYTES);
+    pointer_offset_ = __builtin_align_up(sizeof(Header), MINIMUM_ALIGNMENT_BYTES);
 
     if (config_.options() & FRONT_GUARD) {
       front_guard.reset(new FrontGuardData(this, config_, &pointer_offset_));
diff --git a/libc/malloc_debug/LogAllocatorStats.cpp b/libc/malloc_debug/LogAllocatorStats.cpp
index ee6bfdfd0..6ba505e60 100644
--- a/libc/malloc_debug/LogAllocatorStats.cpp
+++ b/libc/malloc_debug/LogAllocatorStats.cpp
@@ -31,6 +31,8 @@
 #include <signal.h>
 #include <unistd.h>
 
+#include <atomic>
+
 #include "Config.h"
 #include "LogAllocatorStats.h"
 #include "debug_log.h"
diff --git a/libc/malloc_debug/PointerData.cpp b/libc/malloc_debug/PointerData.cpp
index e3a35a687..c8aaa0880 100644
--- a/libc/malloc_debug/PointerData.cpp
+++ b/libc/malloc_debug/PointerData.cpp
@@ -36,6 +36,9 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <algorithm>
+#include <atomic>
+#include <deque>
 #include <functional>
 #include <mutex>
 #include <string>
diff --git a/libc/malloc_debug/malloc_debug.cpp b/libc/malloc_debug/malloc_debug.cpp
index 7e961695f..7687e8e03 100644
--- a/libc/malloc_debug/malloc_debug.cpp
+++ b/libc/malloc_debug/malloc_debug.cpp
@@ -1195,7 +1195,7 @@ void* debug_pvalloc(size_t bytes) {
   }
 
   size_t pagesize = getpagesize();
-  size_t size = __BIONIC_ALIGN(bytes, pagesize);
+  size_t size = __builtin_align_up(bytes, pagesize);
   if (size < bytes) {
     // Overflow
     errno = ENOMEM;
diff --git a/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp b/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
index 79f946ff3..ecf6cc501 100644
--- a/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
+++ b/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
@@ -99,7 +99,7 @@ constexpr char DIVIDER[] =
     "6 malloc_debug *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n";
 
 static size_t get_tag_offset() {
-  return __BIONIC_ALIGN(sizeof(Header), MINIMUM_ALIGNMENT_BYTES);
+  return __builtin_align_up(sizeof(Header), MINIMUM_ALIGNMENT_BYTES);
 }
 
 static constexpr const char RECORD_ALLOCS_FILE[] = "/data/local/tmp/record_allocs";
@@ -185,26 +185,21 @@ std::string ShowDiffs(uint8_t* a, uint8_t* b, size_t size) {
   return diff;
 }
 
-static void VerifyRecords(std::vector<std::string>& expected, std::string& actual) {
-  ASSERT_TRUE(expected.size() != 0);
-  size_t offset = 0;
-  for (std::string& str : expected) {
-    ASSERT_STREQ(str.c_str(), actual.substr(offset, str.size()).c_str());
-    if (str.find("thread_done") != std::string::npos) {
-      offset = actual.find_first_of("\n", offset) + 1;
-      continue;
-    }
-    offset += str.size() + 1;
-    uint64_t st = strtoull(&actual[offset], nullptr, 10);
-    offset = actual.find_first_of(" ", offset) + 1;
-    uint64_t et = strtoull(&actual[offset], nullptr, 10);
-    ASSERT_GT(et, st);
-    offset = actual.find_first_of("\n", offset) + 1;
+static std::string PrintAllEntries(const std::vector<memory_trace::Entry>& expected,
+                                   const std::vector<memory_trace::Entry>& actual) {
+  std::string result = "\nAll Entries\n  Expected:\n";
+  for (const auto& entry : expected) {
+    result += "    " + memory_trace::CreateStringFromEntry(entry) + "\n";
   }
+  result += "  Actual:\n";
+  for (const auto& entry : actual) {
+    result += "    " + memory_trace::CreateStringFromEntry(entry) + "\n";
+  }
+  return result;
 }
 
 static void VerifyRecordEntries(const std::vector<memory_trace::Entry>& expected,
-                                std::string& actual) {
+                                std::string& actual, bool check_present_bytes = false) {
   ASSERT_TRUE(expected.size() != 0);
   // Convert the text to entries.
   std::vector<memory_trace::Entry> actual_entries;
@@ -217,28 +212,33 @@ static void VerifyRecordEntries(const std::vector<memory_trace::Entry>& expected
     ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
     actual_entries.emplace_back(entry);
   }
-  auto expected_iter = expected.begin();
-  for (const auto& actual_entry : actual_entries) {
-    if (actual_entry.type == memory_trace::THREAD_DONE) {
-      // Skip thread done entries.
-      continue;
-    }
-    ASSERT_NE(expected_iter, expected.end())
-        << "Found extra entry " << memory_trace::CreateStringFromEntry(*expected_iter);
+  ASSERT_EQ(actual_entries.size(), expected.size()) << PrintAllEntries(expected, actual_entries);
+  for (size_t i = 0; i < actual_entries.size(); i++) {
     SCOPED_TRACE(testing::Message()
-                 << "\nExpected entry:\n  " << memory_trace::CreateStringFromEntry(*expected_iter)
-                 << "\nActual entry:\n  " << memory_trace::CreateStringFromEntry(actual_entry));
-    EXPECT_EQ(actual_entry.type, expected_iter->type);
-    EXPECT_EQ(actual_entry.ptr, expected_iter->ptr);
-    EXPECT_EQ(actual_entry.size, expected_iter->size);
-    EXPECT_EQ(actual_entry.u.old_ptr, expected_iter->u.old_ptr);
-    EXPECT_EQ(actual_entry.present_bytes, expected_iter->present_bytes);
+                 << "\nEntry " << i + 1 << "\nExpected entry:\n  "
+                 << memory_trace::CreateStringFromEntry(expected[i]) << "\nActual entry:\n  "
+                 << memory_trace::CreateStringFromEntry(actual_entries[i]) << "\n"
+                 << PrintAllEntries(expected, actual_entries));
+    if (expected[i].tid != 0) {
+      EXPECT_EQ(actual_entries[i].tid, expected[i].tid);
+    }
+    EXPECT_EQ(actual_entries[i].type, expected[i].type);
+    EXPECT_EQ(actual_entries[i].ptr, expected[i].ptr);
+    EXPECT_EQ(actual_entries[i].size, expected[i].size);
+    EXPECT_EQ(actual_entries[i].u.old_ptr, expected[i].u.old_ptr);
+    if (check_present_bytes) {
+      EXPECT_EQ(actual_entries[i].present_bytes, expected[i].present_bytes);
+    }
     // Verify the timestamps are non-zero.
-    EXPECT_NE(actual_entry.start_ns, 0U);
-    EXPECT_NE(actual_entry.end_ns, 0U);
-    ++expected_iter;
+    if (actual_entries[i].type == memory_trace::THREAD_DONE) {
+      // Thread done sets start to 0 since we don't know when the thread started.
+      EXPECT_EQ(actual_entries[i].start_ns, 0U);
+    } else {
+      // All other entries should have a non-zero start.
+      EXPECT_NE(actual_entries[i].start_ns, 0U);
+    }
+    EXPECT_NE(actual_entries[i].end_ns, 0U);
   }
-  EXPECT_TRUE(expected_iter == expected.end()) << "Not all expected entries found.";
 }
 
 void VerifyAllocCalls(bool all_options) {
@@ -2242,61 +2242,104 @@ TEST_F(MallocDebugTest, debug_valloc) {
 #endif
 
 void VerifyRecordAllocs(const std::string& record_filename) {
-  std::vector<std::string> expected;
+  std::vector<memory_trace::Entry> expected;
 
   void* pointer = debug_malloc(10);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 10", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 10});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_calloc(20, 1);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: calloc %p 20 1", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::CALLOC,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 1,
+                                         .u.n_elements = 20});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_realloc(nullptr, 30);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: realloc %p 0x0 30", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 30,
+                                         .u.old_ptr = 0});
+
   void* old_pointer = pointer;
   pointer = debug_realloc(pointer, 2048);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(
-      android::base::StringPrintf("%d: realloc %p %p 2048", getpid(), pointer, old_pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 2048,
+                                         .u.old_ptr = reinterpret_cast<uint64_t>(old_pointer)});
+
   debug_realloc(pointer, 0);
-  expected.push_back(android::base::StringPrintf("%d: realloc 0x0 %p 0", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
+                                         .ptr = 0,
+                                         .size = 0,
+                                         .u.old_ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_memalign(16, 40);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: memalign %p 16 40", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 40,
+                                         .u.align = 16});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_aligned_alloc(32, 64);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: memalign %p 32 64", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 64,
+                                         .u.align = 32});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   ASSERT_EQ(0, debug_posix_memalign(&pointer, 32, 50));
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: memalign %p 32 50", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 50,
+                                         .u.align = 32});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
 #if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
   pointer = debug_pvalloc(60);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: memalign %p 4096 4096", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 4096,
+                                         .u.align = 4096});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_valloc(70);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: memalign %p 4096 70", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 70,
+                                         .u.align = 4096});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 #endif
 
   // Dump all of the data accumulated so far.
@@ -2305,8 +2348,7 @@ void VerifyRecordAllocs(const std::string& record_filename) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
@@ -2327,23 +2369,32 @@ TEST_F(MallocDebugTest, record_allocs_with_header) {
 TEST_F(MallocDebugTest, record_allocs_max) {
   InitRecordAllocs("record_allocs=5");
 
-  std::vector<std::string> expected;
+  std::vector<memory_trace::Entry> expected;
 
   void* pointer = debug_malloc(10);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 10", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 10});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_malloc(20);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 20", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 20});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   pointer = debug_malloc(1024);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 1024", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 1024});
+
+  // This entry will not be written since we hit the maximum number we can store.
   debug_free(pointer);
 
   // Dump all of the data accumulated so far.
@@ -2352,8 +2403,7 @@ TEST_F(MallocDebugTest, record_allocs_max) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ(
@@ -2374,10 +2424,14 @@ TEST_F(MallocDebugTest, record_allocs_thread_done) {
   });
   thread.join();
 
-  std::vector<std::string> expected;
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 100", tid, pointer));
-  expected.push_back(android::base::StringPrintf("%d: free %p", tid, pointer));
-  expected.push_back(android::base::StringPrintf("%d: thread_done 0x0", tid));
+  std::vector<memory_trace::Entry> expected;
+  expected.push_back(memory_trace::Entry{.tid = tid,
+                                         .type = memory_trace::MALLOC,
+                                         .ptr = reinterpret_cast<uint64_t>(pointer),
+                                         .size = 100});
+  expected.push_back(memory_trace::Entry{
+      .tid = tid, .type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
+  expected.push_back(memory_trace::Entry{.tid = tid, .type = memory_trace::THREAD_DONE});
 
   // Dump all of the data accumulated so far.
   ASSERT_TRUE(kill(getpid(), SIGRTMAX - 18) == 0);
@@ -2385,8 +2439,7 @@ TEST_F(MallocDebugTest, record_allocs_thread_done) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
@@ -2401,13 +2454,15 @@ TEST_F(MallocDebugTest, record_allocs_file_name_fail) {
 
   ASSERT_EQ(0, symlink("/data/local/tmp/does_not_exist", record_filename.c_str()));
 
-  std::vector<std::string> expected;
+  std::vector<memory_trace::Entry> expected;
 
   void* pointer = debug_malloc(10);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 10", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 10});
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   // Dump all of the data accumulated so far.
   ASSERT_TRUE(kill(getpid(), SIGRTMAX - 18) == 0);
@@ -2423,8 +2478,7 @@ TEST_F(MallocDebugTest, record_allocs_file_name_fail) {
   ASSERT_TRUE(kill(getpid(), SIGRTMAX - 18) == 0);
 
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   std::string expected_log = android::base::StringPrintf(
@@ -2448,13 +2502,16 @@ TEST_F(MallocDebugTest, record_allocs_no_entries_to_write) {
 TEST_F(MallocDebugTest, record_allocs_write_entries_does_not_allocate) {
   InitRecordAllocs("record_allocs=5");
 
-  std::vector<std::string> expected;
+  std::vector<memory_trace::Entry> expected;
 
   void* pointer = debug_malloc(10);
   ASSERT_TRUE(pointer != nullptr);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 10", getpid(), pointer));
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(pointer), .size = 10});
+
   debug_free(pointer);
-  expected.push_back(android::base::StringPrintf("%d: free %p", getpid(), pointer));
+  expected.push_back(
+      memory_trace::Entry{.type = memory_trace::FREE, .ptr = reinterpret_cast<uint64_t>(pointer)});
 
   malloc_disable();
   kill(getpid(), SIGRTMAX - 18);
@@ -2462,8 +2519,7 @@ TEST_F(MallocDebugTest, record_allocs_write_entries_does_not_allocate) {
 
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
@@ -2476,13 +2532,20 @@ TEST_F(MallocDebugTest, record_allocs_on_exit) {
   // Modify the variable so the file is deleted at the end of the test.
   record_filename += '.' + std::to_string(getpid());
 
-  std::vector<std::string> expected;
+  std::vector<memory_trace::Entry> expected;
+
   void* ptr = debug_malloc(100);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 100", getpid(), ptr));
+  ASSERT_TRUE(ptr != nullptr);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 100});
   ptr = debug_malloc(200);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 200", getpid(), ptr));
+  ASSERT_TRUE(ptr != nullptr);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 200});
   ptr = debug_malloc(400);
-  expected.push_back(android::base::StringPrintf("%d: malloc %p 400", getpid(), ptr));
+  ASSERT_TRUE(ptr != nullptr);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 400});
 
   // Call the exit function manually.
   debug_finalize();
@@ -2490,7 +2553,7 @@ TEST_F(MallocDebugTest, record_allocs_on_exit) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-  VerifyRecords(expected, actual);
+  VerifyRecordEntries(expected, actual);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
@@ -2509,9 +2572,9 @@ TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
       .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 100});
 
   // Make the entire allocation present.
-  memset(ptr, 1, 100);
-
   int64_t real_size = debug_malloc_usable_size(ptr);
+  memset(ptr, 1, real_size);
+
   debug_free(ptr);
   expected.push_back(memory_trace::Entry{.type = memory_trace::FREE,
                                          .ptr = reinterpret_cast<uint64_t>(ptr),
@@ -2521,8 +2584,8 @@ TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
   expected.push_back(memory_trace::Entry{
       .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 4096});
 
-  memset(ptr, 1, 4096);
   real_size = debug_malloc_usable_size(ptr);
+  memset(ptr, 1, real_size);
   void* new_ptr = debug_realloc(ptr, 8192);
   expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
                                          .ptr = reinterpret_cast<uint64_t>(new_ptr),
@@ -2530,8 +2593,8 @@ TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
                                          .u.old_ptr = reinterpret_cast<uint64_t>(ptr),
                                          .present_bytes = real_size});
 
-  memset(new_ptr, 1, 8192);
   real_size = debug_malloc_usable_size(new_ptr);
+  memset(new_ptr, 1, real_size);
   debug_free(new_ptr);
   expected.push_back(memory_trace::Entry{.type = memory_trace::FREE,
                                          .ptr = reinterpret_cast<uint64_t>(new_ptr),
@@ -2540,10 +2603,10 @@ TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
   ptr = debug_malloc(4096);
   expected.push_back(memory_trace::Entry{
       .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 4096});
-  memset(ptr, 1, 4096);
+  real_size = debug_malloc_usable_size(ptr);
+  memset(ptr, 1, real_size);
 
   // Verify a free realloc does update the present bytes.
-  real_size = debug_malloc_usable_size(ptr);
   EXPECT_TRUE(debug_realloc(ptr, 0) == nullptr);
   expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
                                          .ptr = 0,
@@ -2556,7 +2619,7 @@ TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-  VerifyRecordEntries(expected, actual);
+  VerifyRecordEntries(expected, actual, /*check_present_bytes*/ true);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
@@ -2598,7 +2661,7 @@ TEST_F(MallocDebugTest, record_allocs_not_all_bytes_present) {
   // Read all of the contents.
   std::string actual;
   ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
-  VerifyRecordEntries(expected, actual);
+  VerifyRecordEntries(expected, actual, /*check_present_bytes*/ true);
 
   ASSERT_STREQ("", getFakeLogBuf().c_str());
   ASSERT_STREQ("", getFakeLogPrint().c_str());
diff --git a/libc/malloc_hooks/Android.bp b/libc/malloc_hooks/Android.bp
index 06e91c656..c7e45a66c 100644
--- a/libc/malloc_hooks/Android.bp
+++ b/libc/malloc_hooks/Android.bp
@@ -80,7 +80,6 @@ cc_test {
     cflags: [
         "-Wall",
         "-Werror",
-        "-O1", // FIXME: http://b/169206016 - issues with aligned_alloc and -O2
     ],
     test_suites: ["general-tests"],
 }
diff --git a/libc/malloc_hooks/malloc_hooks.cpp b/libc/malloc_hooks/malloc_hooks.cpp
index 1ba869698..e0390657d 100644
--- a/libc/malloc_hooks/malloc_hooks.cpp
+++ b/libc/malloc_hooks/malloc_hooks.cpp
@@ -209,14 +209,17 @@ int hooks_posix_memalign(void** memptr, size_t alignment, size_t size) {
   return g_dispatch->posix_memalign(memptr, alignment, size);
 }
 
-int hooks_malloc_iterate(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*) {
-  return 0;
+int hooks_malloc_iterate(uintptr_t base, size_t size,
+                         void (*callback)(uintptr_t base, size_t size, void* arg), void* arg) {
+  return g_dispatch->malloc_iterate(base, size, callback, arg);
 }
 
 void hooks_malloc_disable() {
+  g_dispatch->malloc_disable();
 }
 
 void hooks_malloc_enable() {
+  g_dispatch->malloc_enable();
 }
 
 ssize_t hooks_malloc_backtrace(void*, uintptr_t*, size_t) {
@@ -230,7 +233,7 @@ bool hooks_write_malloc_leak_info(FILE*) {
 #if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
 void* hooks_pvalloc(size_t bytes) {
   size_t pagesize = getpagesize();
-  size_t size = __BIONIC_ALIGN(bytes, pagesize);
+  size_t size = __builtin_align_up(bytes, pagesize);
   if (size < bytes) {
     // Overflow
     errno = ENOMEM;
diff --git a/libc/malloc_hooks/tests/malloc_hooks_tests.cpp b/libc/malloc_hooks/tests/malloc_hooks_tests.cpp
index 3ff2537c3..582872bdd 100644
--- a/libc/malloc_hooks/tests/malloc_hooks_tests.cpp
+++ b/libc/malloc_hooks/tests/malloc_hooks_tests.cpp
@@ -26,6 +26,13 @@
  * SUCH DAMAGE.
  */
 
+// (b/291762537): This code uses malloc_usable_size(), and thus can't be
+// built with _FORTIFY_SOURCE>=3.
+#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE >= 3
+#undef _FORTIFY_SOURCE
+#define _FORTIFY_SOURCE 2
+#endif
+
 #include <fcntl.h>
 #include <malloc.h>
 #include <stdlib.h>
@@ -210,8 +217,8 @@ TEST_F(MallocHooksTest, DISABLED_extended_functions) {
 
   ASSERT_TRUE(android_mallopt(M_FREE_MALLOC_LEAK_INFO, &leak_info, sizeof(leak_info)));
 
-  malloc_enable();
   malloc_disable();
+  malloc_enable();
 
   EXPECT_EQ(0, malloc_iterate(0, 0, nullptr, nullptr));
 
diff --git a/libc/platform/bionic/dlext_namespaces.h b/libc/platform/bionic/dlext_namespaces.h
new file mode 100644
index 000000000..4f3302700
--- /dev/null
+++ b/libc/platform/bionic/dlext_namespaces.h
@@ -0,0 +1,135 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <android/dlext.h>
+
+__BEGIN_DECLS
+
+/**
+ * Initializes the anonymous namespace.
+ *
+ * `shared_libs_sonames` is a list of sonames to be shared with the default namespace,
+ * separated by colons (such as "libc.so:libm.so:libdl.so").
+ *
+ * `library_search_path` is the search path for the anonymous namespace.
+ * The anonymous namespace is used when the linker cannot identify the caller of
+ * dlopen() or dlsym(). This happens for code not loaded by the dynamic linker,
+ * such as calls from a custom JIT.
+ */
+extern bool android_init_anonymous_namespace(const char* shared_libs_sonames,
+                                             const char* library_search_path);
+
+/**
+ * Bitmask flags for the android_create_namespace() `type` argument.
+ */
+enum {
+  /**
+   * A regular namespace is a namespace with a custom search path that does
+   * not impose any restrictions on the location of native libraries.
+   */
+  ANDROID_NAMESPACE_TYPE_REGULAR = 0,
+
+  /**
+   * An isolated namespace requires all the libraries to be on the search path
+   * or under `permitted_when_isolated_path`. The search path is the union of
+   * `ld_library_path` and `default_library_path`.
+   */
+  ANDROID_NAMESPACE_TYPE_ISOLATED = 1,
+
+  /**
+   * "Share" the caller namespace's list of libraries.
+   *
+   * This actually _clones_ the list of libraries of the caller namespace
+   * upon creation rather than actually sharing:
+   *
+   * 1. Both the caller namespace and the new one will use the same copy of a
+   *    library if it was already loaded in the caller namespace.
+   *
+   * but
+   *
+   * 2. Libraries loaded after the namespace is created will not be shared.
+   *
+   * Shared namespaces can be isolated or regular.
+   *
+   * Shared namespaces do not inherit the search path or permitted path from
+   * the caller namespace.
+   */
+  ANDROID_NAMESPACE_TYPE_SHARED = 2,
+
+  /**
+   * Enable the exempt-list workaround for the namespace.
+   * See http://b/26394120 for details.
+   */
+  ANDROID_NAMESPACE_TYPE_EXEMPT_LIST_ENABLED = 0x08000000,
+
+  /**
+   * Use this namespace as the anonymous namespace.
+   *
+   * There can be only one anonymous namespace in a process.
+   * If there is already an anonymous namespace in the process,
+   * using this flag when creating a new namespace is an error.
+   */
+  ANDROID_NAMESPACE_TYPE_ALSO_USED_AS_ANONYMOUS = 0x10000000,
+
+  /** A common combination. */
+  ANDROID_NAMESPACE_TYPE_SHARED_ISOLATED = ANDROID_NAMESPACE_TYPE_SHARED |
+                                           ANDROID_NAMESPACE_TYPE_ISOLATED,
+};
+
+/**
+ * Create a new linker namespace.
+ *
+ * `ld_library_path` and `default_library_path` represent the search path
+ * for the libraries in the namespace.
+ *
+ * The libraries in the namespace are searched in the following order:
+ * 1. `ld_library_path` (think of this as a namespace-local $LD_LIBRARY_PATH).
+ * 2. In directories specified by DT_RUNPATH of the "needed by" binary.
+ * 3. `default_library_path` (think of this as a namespace-local default library path).
+ *
+ * If the ANDROID_NAMESPACE_TYPE_ISOLATED bit is set in `type`,
+ * the resulting namespace requires all of the libraries to be on the search
+ * path or under the `permitted_when_isolated_path`;
+ * the search path is `ld_library_path` followed by `default_library_path`.
+ * Note that the `permitted_when_isolated_path` path is not part of the search
+ * path and does not affect the search order: it's a way to allow loading
+ * libraries from specific locations when using absolute paths.
+ *
+ * If a library or any of its dependencies are outside of the `permitted_when_isolated_path`
+ * and search path, and not part of the public namespace, dlopen() will fail.
+ */
+extern struct android_namespace_t* android_create_namespace(const char* name,
+                                                            const char* ld_library_path,
+                                                            const char* default_library_path,
+                                                            uint64_t type,
+                                                            const char* permitted_when_isolated_path,
+                                                            android_namespace_t* parent);
+
+extern bool android_link_namespaces(android_namespace_t* from,
+                                    android_namespace_t* to,
+                                    const char* shared_libs_sonames);
+
+extern bool android_link_namespaces_all_libs(android_namespace_t* from,
+                                             android_namespace_t* to);
+
+extern struct android_namespace_t* android_get_exported_namespace(const char* name);
+
+// TODO: move this somewhere else, since it's unrelated to linker namespaces.
+extern void android_set_application_target_sdk_version(int target);
+
+__END_DECLS
diff --git a/libc/platform/bionic/mte.h b/libc/platform/bionic/mte.h
index 27cbae1d1..1d521bf8e 100644
--- a/libc/platform/bionic/mte.h
+++ b/libc/platform/bionic/mte.h
@@ -128,9 +128,10 @@ inline uintptr_t stack_mte_ringbuffer_size_add_to_pointer(uintptr_t ptr, uintptr
 }
 
 inline void stack_mte_free_ringbuffer(uintptr_t stack_mte_tls) {
-  size_t size = stack_mte_ringbuffer_size_from_pointer(stack_mte_tls);
+  size_t page_aligned_size =
+      __builtin_align_up(stack_mte_ringbuffer_size_from_pointer(stack_mte_tls), page_size());
   void* ptr = reinterpret_cast<void*>(stack_mte_tls & ((1ULL << 56ULL) - 1ULL));
-  munmap(ptr, size);
+  munmap(ptr, page_aligned_size);
 }
 
 inline void* stack_mte_ringbuffer_allocate(size_t n, const char* name) {
@@ -147,8 +148,9 @@ inline void* stack_mte_ringbuffer_allocate(size_t n, const char* name) {
   // bytes left.
   size_t size = stack_mte_ringbuffer_size(n);
   size_t pgsize = page_size();
+  size_t page_aligned_size = __builtin_align_up(size, pgsize);
 
-  size_t alloc_size = __BIONIC_ALIGN(3 * size - pgsize, pgsize);
+  size_t alloc_size = 3 * page_aligned_size - pgsize;
   void* allocation_ptr =
       mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (allocation_ptr == MAP_FAILED)
@@ -156,7 +158,7 @@ inline void* stack_mte_ringbuffer_allocate(size_t n, const char* name) {
   uintptr_t allocation = reinterpret_cast<uintptr_t>(allocation_ptr);
 
   size_t alignment = 2 * size;
-  uintptr_t aligned_allocation = __BIONIC_ALIGN(allocation, alignment);
+  uintptr_t aligned_allocation = __builtin_align_up(allocation, alignment);
   if (allocation != aligned_allocation) {
     munmap(reinterpret_cast<void*>(allocation), aligned_allocation - allocation);
   }
diff --git a/libc/platform/bionic/reserved_signals.h b/libc/platform/bionic/reserved_signals.h
index 1c7076b0c..3ee199c00 100644
--- a/libc/platform/bionic/reserved_signals.h
+++ b/libc/platform/bionic/reserved_signals.h
@@ -35,34 +35,48 @@
 #include "macros.h"
 
 // Realtime signals reserved for internal use:
+
 //   32 (__SIGRTMIN + 0)        POSIX timers
+#define BIONIC_SIGNAL_POSIX_TIMERS (__SIGRTMIN + 0)
+
 //   33 (__SIGRTMIN + 1)        libbacktrace
+#define BIONIC_SIGNAL_BACKTRACE (__SIGRTMIN + 1)
+
 //   34 (__SIGRTMIN + 2)        libcore
+// There's no constant for this because it's hard-coded in the OpenJDK source.
+// It's used to implement Java's "close() on a Socket wakes blocked readers and
+// writers" semantics.
+
 //   35 (__SIGRTMIN + 3)        debuggerd
+#define BIONIC_SIGNAL_DEBUGGER (__SIGRTMIN + 3)
+
 //   36 (__SIGRTMIN + 4)        platform profilers (heapprofd, traced_perf)
+#define BIONIC_SIGNAL_PROFILER (__SIGRTMIN + 4)
+
 //   37 (__SIGRTMIN + 5)        coverage (libprofile-extras)
-//   38 (__SIGRTMIN + 6)        heapprofd ART managed heap dumps
-//   39 (__SIGRTMIN + 7)        fdtrack
-//   40 (__SIGRTMIN + 8)        android_run_on_all_threads (bionic/pthread_internal.cpp)
-//   41 (__SIGRTMIN + 9)        re-enable MTE on thread
+// Used by the clang coverage support to flush coverage data to disk.
+#define BIONIC_SIGNAL_FLUSH_COVERAGE (__SIGRTMIN + 5)
 
-#define BIONIC_SIGNAL_POSIX_TIMERS (__SIGRTMIN + 0)
-#define BIONIC_SIGNAL_BACKTRACE (__SIGRTMIN + 1)
-#define BIONIC_SIGNAL_DEBUGGER (__SIGRTMIN + 3)
-#define BIONIC_SIGNAL_PROFILER (__SIGRTMIN + 4)
-// When used for the dumping a heap dump, BIONIC_SIGNAL_ART_PROFILER is always handled
-// gracefully without crashing.
+//   38 (__SIGRTMIN + 6)        heapprofd ART managed heap dumps
+// When used in ART for heap dumps, this is handled without crashing.
 // In debuggerd, we crash the process with this signal to indicate to init that
 // a process has been terminated by an MTEAERR SEGV. This works because there is
 // no other reason a process could have terminated with this signal.
 // This is to work around the limitation of that it is not possible to get the
 // si_code that terminated a process.
 #define BIONIC_SIGNAL_ART_PROFILER (__SIGRTMIN + 6)
+
+//   39 (__SIGRTMIN + 7)        fdtrack
 #define BIONIC_SIGNAL_FDTRACK (__SIGRTMIN + 7)
+
+//   40 (__SIGRTMIN + 8)        android_run_on_all_threads (bionic/pthread_internal.cpp)
 #define BIONIC_SIGNAL_RUN_ON_ALL_THREADS (__SIGRTMIN + 8)
+
+//   41 (__SIGRTMIN + 9)        re-enable MTE on thread
 #define BIONIC_ENABLE_MTE (__SIGRTMIN + 9)
 
 #define __SIGRT_RESERVED 10
+
 static inline __always_inline sigset64_t filter_reserved_signals(sigset64_t sigset, int how) {
   int (*block)(sigset64_t*, int);
   int (*unblock)(sigset64_t*, int);
@@ -81,17 +95,12 @@ static inline __always_inline sigset64_t filter_reserved_signals(sigset64_t sigs
   }
 
   // The POSIX timer signal must be blocked.
-  block(&sigset, __SIGRTMIN + 0);
+  block(&sigset, BIONIC_SIGNAL_POSIX_TIMERS);
 
   // Everything else must remain unblocked.
-  unblock(&sigset, __SIGRTMIN + 1);
-  unblock(&sigset, __SIGRTMIN + 2);
-  unblock(&sigset, __SIGRTMIN + 3);
-  unblock(&sigset, __SIGRTMIN + 4);
-  unblock(&sigset, __SIGRTMIN + 5);
-  unblock(&sigset, __SIGRTMIN + 6);
-  unblock(&sigset, __SIGRTMIN + 7);
-  unblock(&sigset, __SIGRTMIN + 8);
-  unblock(&sigset, __SIGRTMIN + 9);
+  for (int i = 1; i < __SIGRT_RESERVED; ++i) {
+    unblock(&sigset, __SIGRTMIN + i);
+  }
+
   return sigset;
 }
diff --git a/libc/private/CFIShadow.h b/libc/private/CFIShadow.h
index b40c06310..c62a4ef15 100644
--- a/libc/private/CFIShadow.h
+++ b/libc/private/CFIShadow.h
@@ -14,8 +14,9 @@
  * limitations under the License.
  */
 
-#ifndef CFI_SHADOW_H
-#define CFI_SHADOW_H
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <stdint.h>
 
@@ -86,5 +87,3 @@ class CFIShadow {
                            // kRegularShadowMin.
   };
 };
-
-#endif  // CFI_SHADOW_H
diff --git a/libc/private/CachedProperty.h b/libc/private/CachedProperty.h
index 7accdb37b..440db5209 100644
--- a/libc/private/CachedProperty.h
+++ b/libc/private/CachedProperty.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <string.h>
 #include <sys/system_properties.h>
 
diff --git a/libc/private/ErrnoRestorer.h b/libc/private/ErrnoRestorer.h
index cecf10382..8802604d0 100644
--- a/libc/private/ErrnoRestorer.h
+++ b/libc/private/ErrnoRestorer.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <errno.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/FdPath.h b/libc/private/FdPath.h
index 4a6a2d537..d17ac568b 100644
--- a/libc/private/FdPath.h
+++ b/libc/private/FdPath.h
@@ -16,6 +16,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
+#include <stdio.h>
+
 class FdPath {
  public:
   explicit FdPath(int fd) {
diff --git a/libc/private/KernelArgumentBlock.h b/libc/private/KernelArgumentBlock.h
index e1f655a44..53bf56939 100644
--- a/libc/private/KernelArgumentBlock.h
+++ b/libc/private/KernelArgumentBlock.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <elf.h>
 #include <link.h>
 #include <stdint.h>
diff --git a/libc/private/MallocXmlElem.h b/libc/private/MallocXmlElem.h
index f8c72ab40..3c8b69360 100644
--- a/libc/private/MallocXmlElem.h
+++ b/libc/private/MallocXmlElem.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <stdarg.h>
 #include <stdio.h>
 #include <unistd.h>
diff --git a/libc/private/ScopedFd.h b/libc/private/ScopedFd.h
index ea7f59ee3..b25847903 100644
--- a/libc/private/ScopedFd.h
+++ b/libc/private/ScopedFd.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <unistd.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/ScopedPthreadMutexLocker.h b/libc/private/ScopedPthreadMutexLocker.h
index a87750cef..8431cdacf 100644
--- a/libc/private/ScopedPthreadMutexLocker.h
+++ b/libc/private/ScopedPthreadMutexLocker.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <pthread.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/ScopedRWLock.h b/libc/private/ScopedRWLock.h
index 0af372b97..af1cf9acf 100644
--- a/libc/private/ScopedRWLock.h
+++ b/libc/private/ScopedRWLock.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <pthread.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/ScopedReaddir.h b/libc/private/ScopedReaddir.h
index 7b07921d3..a30060b20 100644
--- a/libc/private/ScopedReaddir.h
+++ b/libc/private/ScopedReaddir.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <dirent.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/ScopedSignalBlocker.h b/libc/private/ScopedSignalBlocker.h
index f6ba9ed34..c2ed68c14 100644
--- a/libc/private/ScopedSignalBlocker.h
+++ b/libc/private/ScopedSignalBlocker.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <signal.h>
 
 #include "platform/bionic/macros.h"
diff --git a/libc/private/ScopedSignalHandler.h b/libc/private/ScopedSignalHandler.h
index 703175223..edb5c4c56 100644
--- a/libc/private/ScopedSignalHandler.h
+++ b/libc/private/ScopedSignalHandler.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <signal.h>
 
 class ScopedSignalHandler {
diff --git a/libc/private/SigSetConverter.h b/libc/private/SigSetConverter.h
index 9e9df73ba..5870cc9ae 100644
--- a/libc/private/SigSetConverter.h
+++ b/libc/private/SigSetConverter.h
@@ -28,6 +28,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
+#include <signal.h>
+
 // Android's 32-bit ABI shipped with a sigset_t too small to include any
 // of the realtime signals, so we have both sigset_t and sigset64_t. Many
 // new system calls only accept a sigset64_t, so this helps paper over
diff --git a/libc/private/WriteProtected.h b/libc/private/WriteProtected.h
index f26912546..bc09fc5fe 100644
--- a/libc/private/WriteProtected.h
+++ b/libc/private/WriteProtected.h
@@ -16,9 +16,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <errno.h>
 #include <string.h>
-#include <sys/cdefs.h>
 #include <sys/mman.h>
 #include <sys/user.h>
 
diff --git a/libc/private/bionic_allocator.h b/libc/private/bionic_allocator.h
index 987266913..58dbcea31 100644
--- a/libc/private/bionic_allocator.h
+++ b/libc/private/bionic_allocator.h
@@ -29,6 +29,7 @@
 #pragma once
 
 #include <sys/cdefs.h>
+
 #include <stddef.h>
 #include <stdint.h>
 
diff --git a/libc/private/bionic_arc4random.h b/libc/private/bionic_arc4random.h
index cdc9b6dc6..f57ca5055 100644
--- a/libc/private/bionic_arc4random.h
+++ b/libc/private/bionic_arc4random.h
@@ -26,8 +26,9 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _PRIVATE_BIONIC_ARC4RANDOM_H_
-#define _PRIVATE_BIONIC_ARC4RANDOM_H_
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <stddef.h>
 
@@ -37,5 +38,3 @@
 // wrapper falls back to AT_RANDOM if the kernel doesn't have enough
 // entropy for getrandom(2) or /dev/urandom.
 void __libc_safe_arc4random_buf(void* buf, size_t n);
-
-#endif
diff --git a/libc/private/bionic_asm.h b/libc/private/bionic_asm.h
index b3b2b47c7..05af4abc0 100644
--- a/libc/private/bionic_asm.h
+++ b/libc/private/bionic_asm.h
@@ -28,8 +28,8 @@
 
 #pragma once
 
-/* https://github.com/android/ndk/issues/1422 */
-#include <features.h>
+/* This should be valid for assembler too: https://github.com/android/ndk/issues/1422 */
+#include <sys/cdefs.h>
 
 #include <asm/unistd.h> /* For system call numbers. */
 #define MAX_ERRNO 4095  /* For recognizing system call error returns. */
diff --git a/libc/private/bionic_call_ifunc_resolver.h b/libc/private/bionic_call_ifunc_resolver.h
index e0ea35bba..cdc62a0a7 100644
--- a/libc/private/bionic_call_ifunc_resolver.h
+++ b/libc/private/bionic_call_ifunc_resolver.h
@@ -28,7 +28,8 @@
 
 #pragma once
 
-#include <link.h>
 #include <sys/cdefs.h>
 
+#include <link.h>
+
 __LIBC_HIDDEN__ ElfW(Addr) __bionic_call_ifunc_resolver(ElfW(Addr) resolver_addr);
diff --git a/libc/private/bionic_config.h b/libc/private/bionic_config.h
index 0c9811c0f..6d35807f6 100644
--- a/libc/private/bionic_config.h
+++ b/libc/private/bionic_config.h
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifndef _BIONIC_CONFIG_H_
-#define _BIONIC_CONFIG_H_
+#pragma once
+
+#include <sys/cdefs.h>
 
 // valloc(3) and pvalloc(3) were removed from POSIX 2004. We do not include them
 // for LP64, but the symbols remain in LP32 for binary compatibility.
 #if !defined(__LP64__)
 #define HAVE_DEPRECATED_MALLOC_FUNCS 1
 #endif
-
-#endif // _BIONIC_CONFIG_H_
diff --git a/libc/private/bionic_constants.h b/libc/private/bionic_constants.h
index ce484d823..a56c9e695 100644
--- a/libc/private/bionic_constants.h
+++ b/libc/private/bionic_constants.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #define US_PER_S 1'000'000LL
 #define NS_PER_S 1'000'000'000LL
 
diff --git a/libc/private/bionic_defs.h b/libc/private/bionic_defs.h
index 5a48f259c..b46452f8d 100644
--- a/libc/private/bionic_defs.h
+++ b/libc/private/bionic_defs.h
@@ -26,8 +26,9 @@
  * SUCH DAMAGE.
  */
 
-#ifndef __BIONIC_PRIVATE_BIONIC_DEFS_H_
-#define __BIONIC_PRIVATE_BIONIC_DEFS_H_
+#pragma once
+
+#include <sys/cdefs.h>
 
 /*
  * This label is used to mark libc/libdl symbols that may need to be replaced
@@ -43,5 +44,3 @@
 #define __BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE
 #define __BIONIC_WEAK_FOR_NATIVE_BRIDGE_INLINE static inline
 #endif
-
-#endif /* __BIONIC_PRIVATE_BIONIC_DEFS_H_ */
diff --git a/libc/private/bionic_elf_dtv_offset.h b/libc/private/bionic_elf_dtv_offset.h
index 8d9f3b9b4..0b6fd20d3 100644
--- a/libc/private/bionic_elf_dtv_offset.h
+++ b/libc/private/bionic_elf_dtv_offset.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #if defined(__riscv)
 // TLS_DTV_OFFSET is a constant used in relocation fields, defined in RISC-V ELF Specification[1]
 // The front of the TCB contains a pointer to the DTV, and each pointer in DTV
diff --git a/libc/private/bionic_elf_tls.h b/libc/private/bionic_elf_tls.h
index 04297ad73..bc0ffa982 100644
--- a/libc/private/bionic_elf_tls.h
+++ b/libc/private/bionic_elf_tls.h
@@ -28,11 +28,12 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <link.h>
 #include <pthread.h>
 #include <stdatomic.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
 
 #include "bionic_elf_dtv_offset.h"
 
diff --git a/libc/private/bionic_fdsan.h b/libc/private/bionic_fdsan.h
index f403d08df..c511494a9 100644
--- a/libc/private/bionic_fdsan.h
+++ b/libc/private/bionic_fdsan.h
@@ -28,12 +28,13 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <android/fdsan.h>
 
 #include <errno.h>
 #include <stdatomic.h>
 #include <string.h>
-#include <sys/cdefs.h>
 #include <sys/mman.h>
 #include <sys/resource.h>
 #include <sys/user.h>
diff --git a/libc/private/bionic_fdtrack.h b/libc/private/bionic_fdtrack.h
index c05b32ba6..d3d68b255 100644
--- a/libc/private/bionic_fdtrack.h
+++ b/libc/private/bionic_fdtrack.h
@@ -28,9 +28,10 @@
 
 #pragma once
 
-#include <stdatomic.h>
 #include <sys/cdefs.h>
 
+#include <stdatomic.h>
+
 #include "platform/bionic/fdtrack.h"
 
 #include "bionic/pthread_internal.h"
diff --git a/libc/private/bionic_fortify.h b/libc/private/bionic_fortify.h
index df83360be..1b8624304 100644
--- a/libc/private/bionic_fortify.h
+++ b/libc/private/bionic_fortify.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <poll.h> // For struct pollfd.
 #include <stdarg.h>
 #include <stdlib.h>
diff --git a/libc/private/bionic_futex.h b/libc/private/bionic_futex.h
index b34069044..9af203545 100644
--- a/libc/private/bionic_futex.h
+++ b/libc/private/bionic_futex.h
@@ -25,14 +25,15 @@
  * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  * SUCH DAMAGE.
  */
-#ifndef _BIONIC_FUTEX_H
-#define _BIONIC_FUTEX_H
+
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <errno.h>
 #include <linux/futex.h>
 #include <stdbool.h>
 #include <stddef.h>
-#include <sys/cdefs.h>
 #include <sys/syscall.h>
 #include <unistd.h>
 
@@ -76,5 +77,3 @@ static inline int __futex_pi_unlock(volatile void* ftx, bool shared) {
 
 __LIBC_HIDDEN__ int __futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock,
                                        const timespec* abs_timeout);
-
-#endif /* _BIONIC_FUTEX_H */
diff --git a/libc/private/bionic_globals.h b/libc/private/bionic_globals.h
index 2346a4d8c..a7a4afe1d 100644
--- a/libc/private/bionic_globals.h
+++ b/libc/private/bionic_globals.h
@@ -26,15 +26,15 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _PRIVATE_BIONIC_GLOBALS_H
-#define _PRIVATE_BIONIC_GLOBALS_H
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <inttypes.h>
 #include <link.h>
 #include <platform/bionic/malloc.h>
 #include <pthread.h>
 #include <stdatomic.h>
-#include <sys/cdefs.h>
 
 #include "private/WriteProtected.h"
 #include "private/bionic_allocator.h"
@@ -177,5 +177,3 @@ __LIBC_HIDDEN__ extern void* __libc_sysinfo;
 extern "C" __LIBC_HIDDEN__ void __libc_int0x80();
 __LIBC_HIDDEN__ void __libc_init_sysinfo();
 #endif
-
-#endif
diff --git a/libc/private/bionic_ieee.h b/libc/private/bionic_ieee.h
index 69095f0cd..9fb3c0c11 100644
--- a/libc/private/bionic_ieee.h
+++ b/libc/private/bionic_ieee.h
@@ -45,8 +45,9 @@
  *	@(#)ieee.h	8.1 (Berkeley) 6/11/93
  */
 
-#ifndef _MACHINE_IEEE_H_
-#define _MACHINE_IEEE_H_
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <sys/types.h>
 
@@ -114,5 +115,3 @@ struct ieee_ext {
 #endif
 
 __END_DECLS
-
-#endif /* _MACHINE_IEEE_H_ */
diff --git a/libc/private/bionic_ifuncs.h b/libc/private/bionic_ifuncs.h
index b31c903de..0d480386e 100644
--- a/libc/private/bionic_ifuncs.h
+++ b/libc/private/bionic_ifuncs.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <stdint.h>
 #include <sys/ifunc.h>
 
@@ -98,6 +100,12 @@ typedef void* memcpy_func_t(void*, const void*, size_t);
     FORWARD(memcpy)(dst, src, n);                                         \
   })
 
+typedef void* __memcpy_chk_func_t(void*, const void*, size_t, size_t);
+#define __MEMCPY_CHK_SHIM()                                                                \
+  DEFINE_STATIC_SHIM(void* __memcpy_chk(void* dst, const void* src, size_t n, size_t n2) { \
+    FORWARD(__memcpy_chk)(dst, src, n, n2);                                                \
+  })
+
 typedef void* memmove_func_t(void*, const void*, size_t);
 #define MEMMOVE_SHIM()                                                     \
   DEFINE_STATIC_SHIM(void* memmove(void* dst, const void* src, size_t n) { \
diff --git a/libc/private/bionic_inline_raise.h b/libc/private/bionic_inline_raise.h
index 82a564d53..5af3fc190 100644
--- a/libc/private/bionic_inline_raise.h
+++ b/libc/private/bionic_inline_raise.h
@@ -29,6 +29,7 @@
 #pragma once
 
 #include <sys/cdefs.h>
+
 #include <sys/syscall.h>
 #include <sys/types.h>
 #include <unistd.h>
diff --git a/libc/private/bionic_lock.h b/libc/private/bionic_lock.h
index d0c6d5e22..0089675ce 100644
--- a/libc/private/bionic_lock.h
+++ b/libc/private/bionic_lock.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <stdatomic.h>
 #include "private/bionic_futex.h"
 #include "platform/bionic/macros.h"
diff --git a/libc/private/bionic_malloc_dispatch.h b/libc/private/bionic_malloc_dispatch.h
index 52d857317..f76b75b1e 100644
--- a/libc/private/bionic_malloc_dispatch.h
+++ b/libc/private/bionic_malloc_dispatch.h
@@ -26,8 +26,9 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _PRIVATE_BIONIC_MALLOC_DISPATCH_H
-#define _PRIVATE_BIONIC_MALLOC_DISPATCH_H
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <stddef.h>
 #include <stdint.h>
@@ -77,5 +78,3 @@ struct MallocDispatch {
   MallocAlignedAlloc aligned_alloc;
   MallocMallocInfo malloc_info;
 } __attribute__((aligned(32)));
-
-#endif
diff --git a/libc/private/bionic_mbstate.h b/libc/private/bionic_mbstate.h
index fb8577593..89ceda7d9 100644
--- a/libc/private/bionic_mbstate.h
+++ b/libc/private/bionic_mbstate.h
@@ -26,8 +26,9 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _BIONIC_MBSTATE_H
-#define _BIONIC_MBSTATE_H
+#pragma once
+
+#include <sys/cdefs.h>
 
 #include <errno.h>
 #include <wchar.h>
@@ -73,5 +74,3 @@ static inline __nodiscard size_t mbstate_reset_and_return(size_t _return, mbstat
 }
 
 __END_DECLS
-
-#endif // _BIONIC_MBSTATE_H
diff --git a/libc/private/bionic_ssp.h b/libc/private/bionic_ssp.h
index ea62cb931..7372d493e 100644
--- a/libc/private/bionic_ssp.h
+++ b/libc/private/bionic_ssp.h
@@ -28,9 +28,10 @@
 
 #pragma once
 
-#include <stdint.h>
 #include <sys/cdefs.h>
 
+#include <stdint.h>
+
 __BEGIN_DECLS
 
 // The compiler uses this if it's not using TLS.
diff --git a/libc/private/bionic_systrace.h b/libc/private/bionic_systrace.h
index dbe173919..57f36d026 100644
--- a/libc/private/bionic_systrace.h
+++ b/libc/private/bionic_systrace.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include "platform/bionic/macros.h"
 
 // Tracing class for bionic. To begin a trace at a specified point:
diff --git a/libc/private/bionic_time_conversions.h b/libc/private/bionic_time_conversions.h
index ce7de0dfc..5dc28d1f5 100644
--- a/libc/private/bionic_time_conversions.h
+++ b/libc/private/bionic_time_conversions.h
@@ -28,9 +28,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <errno.h>
 #include <time.h>
-#include <sys/cdefs.h>
 
 #include "private/bionic_constants.h"
 
diff --git a/libc/private/bionic_tls.h b/libc/private/bionic_tls.h
index 53fe3d508..7080fc6cf 100644
--- a/libc/private/bionic_tls.h
+++ b/libc/private/bionic_tls.h
@@ -28,10 +28,11 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <locale.h>
 #include <mntent.h>
 #include <stdio.h>
-#include <sys/cdefs.h>
 #include <sys/param.h>
 
 #include <platform/bionic/tls.h>
@@ -106,15 +107,27 @@ class pthread_key_data_t {
   void* data;
 };
 
-// ~3 pages. This struct is allocated as static TLS memory (i.e. at a fixed
-// offset from the thread pointer).
+// Defines the memory layout for the TLS buffers used by basename() and
+// dirname() in libgen.h.
+//
+// This struct is separated out from bionic TLS to ensure that the libgen
+// buffers, when mapped, occupy their own set of memory pages distinct
+// from the primary bionic_tls structure. This helps improve memory usage
+// if libgen functions are not heavily used, especially on 16KB page size
+// systems.
+struct libgen_buffers {
+  char basename_buf[MAXPATHLEN];
+  char dirname_buf[MAXPATHLEN];
+};
+
+// This struct is allocated as static TLS memory (i.e. at a fixed offset
+// from the thread pointer).
 struct bionic_tls {
   pthread_key_data_t key_data[BIONIC_PTHREAD_KEY_COUNT];
 
   locale_t locale;
 
-  char basename_buf[MAXPATHLEN];
-  char dirname_buf[MAXPATHLEN];
+  libgen_buffers* libgen_buffers_ptr;
 
   mntent mntent_buf;
   char mntent_strings[BUFSIZ];
diff --git a/libc/private/bionic_vdso.h b/libc/private/bionic_vdso.h
index 406b06418..aa0c07f8b 100644
--- a/libc/private/bionic_vdso.h
+++ b/libc/private/bionic_vdso.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #if defined(__aarch64__)
 #define VDSO_CLOCK_GETTIME_SYMBOL "__kernel_clock_gettime"
 #define VDSO_CLOCK_GETRES_SYMBOL "__kernel_clock_getres"
diff --git a/libc/private/elf_note.h b/libc/private/elf_note.h
index 6a9399bbd..59be761ab 100644
--- a/libc/private/elf_note.h
+++ b/libc/private/elf_note.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <elf.h>
 #include <link.h>
 
diff --git a/libc/private/get_cpu_count_from_string.h b/libc/private/get_cpu_count_from_string.h
index a0cb95de0..96ef7c59c 100644
--- a/libc/private/get_cpu_count_from_string.h
+++ b/libc/private/get_cpu_count_from_string.h
@@ -26,6 +26,10 @@
  * SUCH DAMAGE.
  */
 
+#pragma once
+
+#include <sys/cdefs.h>
+
 #include <ctype.h>
 #include <stdlib.h>
 
diff --git a/libc/private/grp_pwd.h b/libc/private/grp_pwd.h
index ab7958683..83b2d66ad 100644
--- a/libc/private/grp_pwd.h
+++ b/libc/private/grp_pwd.h
@@ -28,6 +28,10 @@
  * SUCH DAMAGE.
  */
 
+#pragma once
+
+#include <sys/cdefs.h>
+
 #include <grp.h>
 #include <pwd.h>
 
diff --git a/libc/private/icu4x.h b/libc/private/icu4x.h
index 8b7e1d007..2f7b74248 100644
--- a/libc/private/icu4x.h
+++ b/libc/private/icu4x.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <ctype.h>
 #include <stdint.h>
 #include <wchar.h>
diff --git a/libc/private/linker_native_bridge.h b/libc/private/linker_native_bridge.h
index bfd015322..a77251561 100644
--- a/libc/private/linker_native_bridge.h
+++ b/libc/private/linker_native_bridge.h
@@ -28,4 +28,6 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 extern "C" void __linker_reserve_bionic_tls_in_static_tls();
diff --git a/libc/private/thread_private.h b/libc/private/thread_private.h
index 1a13690ee..738cb5878 100644
--- a/libc/private/thread_private.h
+++ b/libc/private/thread_private.h
@@ -4,6 +4,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <pthread.h>
 
 __BEGIN_DECLS
diff --git a/libc/system_properties/include/system_properties/prop_area.h b/libc/system_properties/include/system_properties/prop_area.h
index 089cf5274..6bf033131 100644
--- a/libc/system_properties/include/system_properties/prop_area.h
+++ b/libc/system_properties/include/system_properties/prop_area.h
@@ -119,7 +119,7 @@ class prop_area {
     // serial is the same: if it is, the dirty backup area hasn't been
     // reused for something else and we can complete the
     // read immediately.
-    bytes_used_ +=  __BIONIC_ALIGN(PROP_VALUE_MAX, sizeof(uint_least32_t));
+    bytes_used_ +=  __builtin_align_up(PROP_VALUE_MAX, sizeof(uint_least32_t));
   }
 
   const prop_info* find(const char* name);
diff --git a/libc/system_properties/prop_area.cpp b/libc/system_properties/prop_area.cpp
index faa3edf00..58b997021 100644
--- a/libc/system_properties/prop_area.cpp
+++ b/libc/system_properties/prop_area.cpp
@@ -148,7 +148,7 @@ prop_area* prop_area::map_prop_area(const char* filename) {
 }
 
 void* prop_area::allocate_obj(const size_t size, uint_least32_t* const off) {
-  const size_t aligned = __BIONIC_ALIGN(size, sizeof(uint_least32_t));
+  const size_t aligned = __builtin_align_up(size, sizeof(uint_least32_t));
   if (bytes_used_ + aligned > pa_data_size_) {
     return nullptr;
   }
diff --git a/libc/upstream-freebsd/lib/libc/stdlib/qsort.c b/libc/upstream-freebsd/lib/libc/stdlib/qsort.c
deleted file mode 100644
index 0d65cd119..000000000
--- a/libc/upstream-freebsd/lib/libc/stdlib/qsort.c
+++ /dev/null
@@ -1,267 +0,0 @@
-/*-
- * SPDX-License-Identifier: BSD-3-Clause
- *
- * Copyright (c) 1992, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#if defined(LIBC_SCCS) && !defined(lint)
-static char sccsid[] = "@(#)qsort.c	8.1 (Berkeley) 6/4/93";
-#endif /* LIBC_SCCS and not lint */
-#include <sys/cdefs.h>
-__FBSDID("$FreeBSD$");
-
-#include <errno.h>
-#include <stdint.h>
-#include <stdlib.h>
-#include <string.h>
-#include "libc_private.h"
-
-#if defined(I_AM_QSORT_R)
-typedef int		 cmp_t(const void *, const void *, void *);
-#elif defined(I_AM_QSORT_R_COMPAT)
-typedef int		 cmp_t(void *, const void *, const void *);
-#elif defined(I_AM_QSORT_S)
-typedef int		 cmp_t(const void *, const void *, void *);
-#else
-typedef int		 cmp_t(const void *, const void *);
-#endif
-static inline char	*med3(char *, char *, char *, cmp_t *, void *);
-
-#define	MIN(a, b)	((a) < (b) ? a : b)
-
-/*
- * Qsort routine from Bentley & McIlroy's "Engineering a Sort Function".
- */
-
-static inline void
-swapfunc(char *a, char *b, size_t es)
-{
-	char t;
-
-	do {
-		t = *a;
-		*a++ = *b;
-		*b++ = t;
-	} while (--es > 0);
-}
-
-#define	vecswap(a, b, n)				\
-	if ((n) > 0) swapfunc(a, b, n)
-
-#if defined(I_AM_QSORT_R)
-#define	CMP(t, x, y) (cmp((x), (y), (t)))
-#elif defined(I_AM_QSORT_R_COMPAT)
-#define	CMP(t, x, y) (cmp((t), (x), (y)))
-#elif defined(I_AM_QSORT_S)
-#define	CMP(t, x, y) (cmp((x), (y), (t)))
-#else
-#define	CMP(t, x, y) (cmp((x), (y)))
-#endif
-
-static inline char *
-med3(char *a, char *b, char *c, cmp_t *cmp, void *thunk
-#if !defined(I_AM_QSORT_R) && !defined(I_AM_QSORT_R_COMPAT) && !defined(I_AM_QSORT_S)
-__unused
-#endif
-)
-{
-	return CMP(thunk, a, b) < 0 ?
-	       (CMP(thunk, b, c) < 0 ? b : (CMP(thunk, a, c) < 0 ? c : a ))
-	      :(CMP(thunk, b, c) > 0 ? b : (CMP(thunk, a, c) < 0 ? a : c ));
-}
-
-/*
- * The actual qsort() implementation is static to avoid preemptible calls when
- * recursing. Also give them different names for improved debugging.
- */
-#if defined(I_AM_QSORT_R)
-#define local_qsort local_qsort_r
-#elif defined(I_AM_QSORT_R_COMPAT)
-#define local_qsort local_qsort_r_compat
-#elif defined(I_AM_QSORT_S)
-#define local_qsort local_qsort_s
-#endif
-static void
-local_qsort(void *a, size_t n, size_t es, cmp_t *cmp, void *thunk)
-{
-	char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
-	size_t d1, d2;
-	int cmp_result;
-	int swap_cnt;
-
-	/* if there are less than 2 elements, then sorting is not needed */
-	if (__predict_false(n < 2))
-		return;
-loop:
-	swap_cnt = 0;
-	if (n < 7) {
-		for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
-			for (pl = pm; 
-			     pl > (char *)a && CMP(thunk, pl - es, pl) > 0;
-			     pl -= es)
-				swapfunc(pl, pl - es, es);
-		return;
-	}
-	pm = (char *)a + (n / 2) * es;
-	if (n > 7) {
-		pl = a;
-		pn = (char *)a + (n - 1) * es;
-		if (n > 40) {
-			size_t d = (n / 8) * es;
-
-			pl = med3(pl, pl + d, pl + 2 * d, cmp, thunk);
-			pm = med3(pm - d, pm, pm + d, cmp, thunk);
-			pn = med3(pn - 2 * d, pn - d, pn, cmp, thunk);
-		}
-		pm = med3(pl, pm, pn, cmp, thunk);
-	}
-	swapfunc(a, pm, es);
-	pa = pb = (char *)a + es;
-
-	pc = pd = (char *)a + (n - 1) * es;
-	for (;;) {
-		while (pb <= pc && (cmp_result = CMP(thunk, pb, a)) <= 0) {
-			if (cmp_result == 0) {
-				swap_cnt = 1;
-				swapfunc(pa, pb, es);
-				pa += es;
-			}
-			pb += es;
-		}
-		while (pb <= pc && (cmp_result = CMP(thunk, pc, a)) >= 0) {
-			if (cmp_result == 0) {
-				swap_cnt = 1;
-				swapfunc(pc, pd, es);
-				pd -= es;
-			}
-			pc -= es;
-		}
-		if (pb > pc)
-			break;
-		swapfunc(pb, pc, es);
-		swap_cnt = 1;
-		pb += es;
-		pc -= es;
-	}
-	if (swap_cnt == 0) {  /* Switch to insertion sort */
-		for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
-			for (pl = pm; 
-			     pl > (char *)a && CMP(thunk, pl - es, pl) > 0;
-			     pl -= es)
-				swapfunc(pl, pl - es, es);
-		return;
-	}
-
-	pn = (char *)a + n * es;
-	d1 = MIN(pa - (char *)a, pb - pa);
-	vecswap(a, pb - d1, d1);
-	/*
-	 * Cast es to preserve signedness of right-hand side of MIN()
-	 * expression, to avoid sign ambiguity in the implied comparison.  es
-	 * is safely within [0, SSIZE_MAX].
-	 */
-	d1 = MIN(pd - pc, pn - pd - (ssize_t)es);
-	vecswap(pb, pn - d1, d1);
-
-	d1 = pb - pa;
-	d2 = pd - pc;
-	if (d1 <= d2) {
-		/* Recurse on left partition, then iterate on right partition */
-		if (d1 > es) {
-			local_qsort(a, d1 / es, es, cmp, thunk);
-		}
-		if (d2 > es) {
-			/* Iterate rather than recurse to save stack space */
-			/* qsort(pn - d2, d2 / es, es, cmp); */
-			a = pn - d2;
-			n = d2 / es;
-			goto loop;
-		}
-	} else {
-		/* Recurse on right partition, then iterate on left partition */
-		if (d2 > es) {
-			local_qsort(pn - d2, d2 / es, es, cmp, thunk);
-		}
-		if (d1 > es) {
-			/* Iterate rather than recurse to save stack space */
-			/* qsort(a, d1 / es, es, cmp); */
-			n = d1 / es;
-			goto loop;
-		}
-	}
-}
-
-#if defined(I_AM_QSORT_R)
-void
-(qsort_r)(void *a, size_t n, size_t es, cmp_t *cmp, void *thunk)
-{
-	local_qsort_r(a, n, es, cmp, thunk);
-}
-#elif defined(I_AM_QSORT_R_COMPAT)
-void
-__qsort_r_compat(void *a, size_t n, size_t es, void *thunk, cmp_t *cmp)
-{
-	local_qsort_r_compat(a, n, es, cmp, thunk);
-}
-#elif defined(I_AM_QSORT_S)
-errno_t
-qsort_s(void *a, rsize_t n, rsize_t es, cmp_t *cmp, void *thunk)
-{
-	if (n > RSIZE_MAX) {
-		__throw_constraint_handler_s("qsort_s : n > RSIZE_MAX", EINVAL);
-		return (EINVAL);
-	} else if (es > RSIZE_MAX) {
-		__throw_constraint_handler_s("qsort_s : es > RSIZE_MAX",
-		    EINVAL);
-		return (EINVAL);
-	} else if (n != 0) {
-		if (a == NULL) {
-			__throw_constraint_handler_s("qsort_s : a == NULL",
-			    EINVAL);
-			return (EINVAL);
-		} else if (cmp == NULL) {
-			__throw_constraint_handler_s("qsort_s : cmp == NULL",
-			    EINVAL);
-			return (EINVAL);
-		} else if (es <= 0) {
-			__throw_constraint_handler_s("qsort_s : es <= 0",
-			    EINVAL);
-			return (EINVAL);
-		}
-	}
-
-	local_qsort_s(a, n, es, cmp, thunk);
-	return (0);
-}
-#else
-void
-qsort(void *a, size_t n, size_t es, cmp_t *cmp)
-{
-	local_qsort(a, n, es, cmp, NULL);
-}
-#endif
diff --git a/libc/upstream-freebsd/lib/libc/stdlib/qsort_r.c b/libc/upstream-freebsd/lib/libc/stdlib/qsort_r.c
deleted file mode 100644
index b382b40e9..000000000
--- a/libc/upstream-freebsd/lib/libc/stdlib/qsort_r.c
+++ /dev/null
@@ -1,6 +0,0 @@
-/*
- * This file is in the public domain.  Originally written by Garrett
- * A. Wollman.
- */
-#define I_AM_QSORT_R
-#include "qsort.c"
diff --git a/libc/upstream-freebsd/lib/libc/string/wcschr.c b/libc/upstream-freebsd/lib/libc/string/wcschr.c
deleted file mode 100644
index a7f1de04f..000000000
--- a/libc/upstream-freebsd/lib/libc/string/wcschr.c
+++ /dev/null
@@ -1,43 +0,0 @@
-/*-
- * SPDX-License-Identifier: BSD-2-Clause
- *
- * Copyright (c) 2002 Tim J. Robbins
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-__FBSDID("$FreeBSD$");
-
-#include <wchar.h>
-
-wchar_t *
-wcschr(const wchar_t *s, wchar_t c)
-{
-
-	while (*s != c && *s != L'\0')
-		s++;
-	if (*s == c)
-		return ((wchar_t *)s);
-	return (NULL);
-}
diff --git a/libc/upstream-netbsd/android/include/extern.h b/libc/upstream-netbsd/android/include/extern.h
deleted file mode 100644
index b8e6151a2..000000000
--- a/libc/upstream-netbsd/android/include/extern.h
+++ /dev/null
@@ -1,25 +0,0 @@
-/*
- * Copyright (C) 2012 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#pragma once
-
-#include <sys/cdefs.h>
-
-__BEGIN_DECLS
-
-const char* __strsignal(int, char*, size_t);
-
-__END_DECLS
diff --git a/libc/upstream-netbsd/lib/libc/gen/psignal.c b/libc/upstream-netbsd/lib/libc/gen/psignal.c
deleted file mode 100644
index 4472be69c..000000000
--- a/libc/upstream-netbsd/lib/libc/gen/psignal.c
+++ /dev/null
@@ -1,85 +0,0 @@
-/*	$NetBSD: psignal.c,v 1.23 2012/03/13 21:13:36 christos Exp $	*/
-
-/*
- * Copyright (c) 1983, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-#if defined(LIBC_SCCS) && !defined(lint)
-#if 0
-static char sccsid[] = "@(#)psignal.c	8.1 (Berkeley) 6/4/93";
-#else
-__RCSID("$NetBSD: psignal.c,v 1.23 2012/03/13 21:13:36 christos Exp $");
-#endif
-#endif /* LIBC_SCCS and not lint */
-
-#include "namespace.h"
-
-#include <sys/types.h>
-#include <sys/uio.h>
-
-#include <limits.h>
-#include <signal.h>
-#include <string.h>
-#include <unistd.h>
-
-#include "extern.h"
-
-#ifdef __weak_alias
-__weak_alias(psignal,_psignal)
-#endif
-
-void
-psignal(int sig, const char *s)
-{
-	struct iovec *v;
-	struct iovec iov[4];
-	char buf[NL_TEXTMAX];
-
-	v = iov;
-	if (s && *s) {
-		v->iov_base = __UNCONST(s);
-		v->iov_len = strlen(s);
-		v++;
-		v->iov_base = __UNCONST(": ");
-		v->iov_len = 2;
-		v++;
-	}
-	v->iov_base = __UNCONST(__strsignal((int)sig, buf, sizeof(buf)));
-	v->iov_len = strlen(v->iov_base);
-	v++;
-	v->iov_base = __UNCONST("\n");
-	v->iov_len = 1;
-	(void)writev(STDERR_FILENO, iov, (int)((v - iov) + 1));
-}
-
-void
-psiginfo(const siginfo_t *si, const char *s)
-{
-	psignal(si->si_signo, s);
-}
diff --git a/libc/upstream-netbsd/lib/libc/gen/utime.c b/libc/upstream-netbsd/lib/libc/gen/utime.c
deleted file mode 100644
index d41aac74c..000000000
--- a/libc/upstream-netbsd/lib/libc/gen/utime.c
+++ /dev/null
@@ -1,65 +0,0 @@
-/*	$NetBSD: utime.c,v 1.14 2012/06/25 22:32:44 abs Exp $	*/
-
-/*-
- * Copyright (c) 1990, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-#if defined(LIBC_SCCS) && !defined(lint)
-#if 0
-static char sccsid[] = "@(#)utime.c	8.1 (Berkeley) 6/4/93";
-#else
-__RCSID("$NetBSD: utime.c,v 1.14 2012/06/25 22:32:44 abs Exp $");
-#endif
-#endif /* LIBC_SCCS and not lint */
-
-#include "namespace.h"
-#include <sys/time.h>
-
-#include <assert.h>
-#include <errno.h>
-#include <stddef.h>
-#include <utime.h>
-
-int
-utime(const char *path, const struct utimbuf *times)
-{
-	struct timeval tv[2], *tvp;
-
-	_DIAGASSERT(path != NULL);
-
-	if (times == (struct utimbuf *) NULL)
-		tvp = NULL;
-	else {
-		tv[0].tv_sec = times->actime;
-		tv[1].tv_sec = times->modtime;
-		tv[0].tv_usec = tv[1].tv_usec = 0;
-		tvp = tv;
-	}
-	return (utimes(path, tvp));
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/abs.c b/libc/upstream-openbsd/lib/libc/stdlib/abs.c
deleted file mode 100644
index 0e39cc553..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/abs.c
+++ /dev/null
@@ -1,38 +0,0 @@
-/*	$OpenBSD: abs.c,v 1.6 2015/09/13 08:31:47 guenther Exp $ */
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>
-
-int
-abs(int j)
-{
-	return(j < 0 ? -j : j);
-}
-DEF_STRONG(abs);
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/div.c b/libc/upstream-openbsd/lib/libc/stdlib/div.c
deleted file mode 100644
index 5e6164f0b..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/div.c
+++ /dev/null
@@ -1,72 +0,0 @@
-/*	$OpenBSD: div.c,v 1.7 2022/12/27 17:10:06 jmc Exp $ */
-/*
- * Copyright (c) 1990 Regents of the University of California.
- * All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Chris Torek.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>		/* div_t */
-
-div_t
-div(int num, int denom)
-{
-	div_t r;
-
-	r.quot = num / denom;
-	r.rem = num % denom;
-	/*
-	 * The ANSI standard says that |r.quot| <= |n/d|, where
-	 * n/d is to be computed in infinite precision.  In other
-	 * words, we should always truncate the quotient towards
-	 * 0, never -infinity.
-	 *
-	 * Machine division and remainder may work either way when
-	 * one or both of n or d is negative.  If only one is
-	 * negative and r.quot has been truncated towards -inf,
-	 * r.rem will have the same sign as denom and the opposite
-	 * sign of num; if both are negative and r.quot has been
-	 * truncated towards -inf, r.rem will be positive (will
-	 * have the opposite sign of num).  These are considered
-	 * `wrong'.
-	 *
-	 * If both are num and denom are positive, r will always
-	 * be positive.
-	 *
-	 * This all boils down to:
-	 *	if num >= 0, but r.rem < 0, we got the wrong answer.
-	 * In that case, to get the right answer, add 1 to r.quot and
-	 * subtract denom from r.rem.
-	 */
-	if (num >= 0 && r.rem < 0) {
-		r.quot++;
-		r.rem -= denom;
-	}
-	return (r);
-}
-DEF_STRONG(div);
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/imaxabs.c b/libc/upstream-openbsd/lib/libc/stdlib/imaxabs.c
deleted file mode 100644
index b7e910eef..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/imaxabs.c
+++ /dev/null
@@ -1,38 +0,0 @@
-/*	$OpenBSD: imaxabs.c,v 1.1 2006/01/13 17:58:09 millert Exp $	*/
-
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <inttypes.h>
-
-intmax_t
-imaxabs(intmax_t j)
-{
-	return (j < 0 ? -j : j);
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/imaxdiv.c b/libc/upstream-openbsd/lib/libc/stdlib/imaxdiv.c
deleted file mode 100644
index 0515a94b9..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/imaxdiv.c
+++ /dev/null
@@ -1,50 +0,0 @@
-/*	$OpenBSD: imaxdiv.c,v 1.1 2006/01/13 17:58:09 millert Exp $	*/
-/*
- * Copyright (c) 1990 Regents of the University of California.
- * All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Chris Torek.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <inttypes.h>		/* imaxdiv_t */
-
-imaxdiv_t
-imaxdiv(intmax_t num, intmax_t denom)
-{
-	imaxdiv_t r;
-
-	/* see div.c for comments */
-
-	r.quot = num / denom;
-	r.rem = num % denom;
-	if (num >= 0 && r.rem < 0) {
-		r.quot++;
-		r.rem -= denom;
-	}
-	return (r);
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/insque.c b/libc/upstream-openbsd/lib/libc/stdlib/insque.c
deleted file mode 100644
index 590ff837b..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/insque.c
+++ /dev/null
@@ -1,54 +0,0 @@
-/*	$OpenBSD: insque.c,v 1.3 2014/08/15 04:14:36 guenther Exp $	*/
-
-/*
- *  Copyright (c) 1993 John Brezak
- *  All rights reserved.
- * 
- *  Redistribution and use in source and binary forms, with or without
- *  modification, are permitted provided that the following conditions
- *  are met:
- *  1. Redistributions of source code must retain the above copyright
- *     notice, this list of conditions and the following disclaimer.
- *  2. Redistributions in binary form must reproduce the above copyright
- *     notice, this list of conditions and the following disclaimer in the
- *     documentation and/or other materials provided with the distribution.
- *  3. The name of the author may be used to endorse or promote products
- *     derived from this software without specific prior written permission.
- * 
- * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
- * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
- * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
- * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
- * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
- * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
- * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
- * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
- * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
- * POSSIBILITY OF SUCH DAMAGE.
- */
-
-#include <stdlib.h>
-#include <search.h>
-
-struct qelem {
-        struct qelem *q_forw;
-        struct qelem *q_back;
-};
-
-void
-insque(void *entry, void *pred)
-{
-	struct qelem *e = entry;
-	struct qelem *p = pred;
-
-	if (p == NULL)
-		e->q_forw = e->q_back = NULL;
-	else {
-		e->q_forw = p->q_forw;
-		e->q_back = p;
-		if (p->q_forw != NULL)
-			p->q_forw->q_back = e;
-		p->q_forw = e;
-	}
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/labs.c b/libc/upstream-openbsd/lib/libc/stdlib/labs.c
deleted file mode 100644
index ca60b9aba..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/labs.c
+++ /dev/null
@@ -1,37 +0,0 @@
-/*	$OpenBSD: labs.c,v 1.5 2005/08/08 08:05:36 espie Exp $ */
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>
-
-long
-labs(long j)
-{
-	return(j < 0 ? -j : j);
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/ldiv.c b/libc/upstream-openbsd/lib/libc/stdlib/ldiv.c
deleted file mode 100644
index 775065f52..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/ldiv.c
+++ /dev/null
@@ -1,50 +0,0 @@
-/*	$OpenBSD: ldiv.c,v 1.5 2005/08/08 08:05:36 espie Exp $ */
-/*
- * Copyright (c) 1990 Regents of the University of California.
- * All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Chris Torek.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>		/* ldiv_t */
-
-ldiv_t
-ldiv(long num, long denom)
-{
-	ldiv_t r;
-
-	/* see div.c for comments */
-
-	r.quot = num / denom;
-	r.rem = num % denom;
-	if (num >= 0 && r.rem < 0) {
-		r.quot++;
-		r.rem -= denom;
-	}
-	return (r);
-}
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/llabs.c b/libc/upstream-openbsd/lib/libc/stdlib/llabs.c
deleted file mode 100644
index f4a260f4a..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/llabs.c
+++ /dev/null
@@ -1,40 +0,0 @@
-/*	$OpenBSD: llabs.c,v 1.4 2016/08/14 23:18:03 guenther Exp $	*/
-
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>
-
-long long
-llabs(long long j)
-{
-	return (j < 0 ? -j : j);
-}
-
-__weak_alias(qabs, llabs);
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/lldiv.c b/libc/upstream-openbsd/lib/libc/stdlib/lldiv.c
deleted file mode 100644
index 59c37b878..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/lldiv.c
+++ /dev/null
@@ -1,52 +0,0 @@
-/*	$OpenBSD: lldiv.c,v 1.2 2016/08/14 23:18:03 guenther Exp $	*/
-/*
- * Copyright (c) 1990 Regents of the University of California.
- * All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Chris Torek.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <stdlib.h>		/* lldiv_t */
-
-lldiv_t
-lldiv(long long num, long long denom)
-{
-	lldiv_t r;
-
-	/* see div.c for comments */
-
-	r.quot = num / denom;
-	r.rem = num % denom;
-	if (num >= 0 && r.rem < 0) {
-		r.quot++;
-		r.rem -= denom;
-	}
-	return (r);
-}
-
-__weak_alias(qdiv, lldiv);
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/lsearch.c b/libc/upstream-openbsd/lib/libc/stdlib/lsearch.c
deleted file mode 100644
index 95ebf49b8..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/lsearch.c
+++ /dev/null
@@ -1,70 +0,0 @@
-/*	$OpenBSD: lsearch.c,v 1.7 2021/12/08 22:06:28 cheloha Exp $	*/
-
-/*
- * Copyright (c) 1989, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Roger L. Snyder.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/types.h>
-#include <string.h>
-#include <search.h>
-
-typedef int (*cmp_fn_t)(const void *, const void *);
-
-void *
-lsearch(const void *key, void *base, size_t *nelp, size_t width,
-    	cmp_fn_t compar)
-{
-	void *element = lfind(key, base, nelp, width, compar);
-
-	/*
-	 * Use memmove(3) to ensure the key is copied cleanly into the
-	 * array, even if the key overlaps with the end of the array.
-	 */
-	if (element == NULL) {
-		element = memmove((char *)base + *nelp * width, key, width);
-		*nelp += 1;
-	}
-	return element;
-}
-
-void *
-lfind(const void *key, const void *base, size_t *nelp, size_t width,
-	cmp_fn_t compar)
-{
-	const char *element, *end;
-
-	end = (const char *)base + *nelp * width;
-	for (element = base; element < end; element += width)
-		if (!compar(key, element))		/* key found */
-			return((void *)element);
-	return NULL;
-}
-DEF_WEAK(lfind);
diff --git a/libc/upstream-openbsd/lib/libc/stdlib/remque.c b/libc/upstream-openbsd/lib/libc/stdlib/remque.c
deleted file mode 100644
index 71b74b2dc..000000000
--- a/libc/upstream-openbsd/lib/libc/stdlib/remque.c
+++ /dev/null
@@ -1,48 +0,0 @@
-/*	$OpenBSD: remque.c,v 1.3 2014/08/15 04:14:36 guenther Exp $	*/
-
-/*
- *  Copyright (c) 1993 John Brezak
- *  All rights reserved.
- * 
- *  Redistribution and use in source and binary forms, with or without
- *  modification, are permitted provided that the following conditions
- *  are met:
- *  1. Redistributions of source code must retain the above copyright
- *     notice, this list of conditions and the following disclaimer.
- *  2. Redistributions in binary form must reproduce the above copyright
- *     notice, this list of conditions and the following disclaimer in the
- *     documentation and/or other materials provided with the distribution.
- *  3. The name of the author may be used to endorse or promote products
- *     derived from this software without specific prior written permission.
- * 
- * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
- * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
- * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
- * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
- * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
- * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
- * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
- * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
- * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
- * POSSIBILITY OF SUCH DAMAGE.
- */
-
-#include <stdlib.h>
-#include <search.h>
-
-struct qelem {
-        struct qelem *q_forw;
-        struct qelem *q_back;
-};
-
-void
-remque(void *element)
-{
-	struct qelem *e = element;
-
-	if (e->q_forw != NULL)
-		e->q_forw->q_back = e->q_back;
-	if (e->q_back != NULL)
-		e->q_back->q_forw = e->q_forw;
-}
diff --git a/libdl/Android.bp b/libdl/Android.bp
index 205c4548c..9d472d17e 100644
--- a/libdl/Android.bp
+++ b/libdl/Android.bp
@@ -60,8 +60,6 @@ cc_library {
     native_bridge_supported: true,
     static_ndk_lib: true,
 
-    export_include_dirs: ["include_private"],
-
     defaults: [
         "linux_bionic_supported",
         "bug_24465209_workaround",
@@ -100,7 +98,10 @@ cc_library {
 
     nocrt: true,
     system_shared_libs: [],
-    header_libs: ["libc_headers"],
+    header_libs: [
+        "libc_headers",
+        "bionic_libc_platform_headers",
+    ],
 
     // Opt out of native_coverage when opting out of system_shared_libs
     native_coverage: false,
@@ -138,6 +139,8 @@ cc_library {
     recovery_available: true,
     native_bridge_supported: true,
 
+    export_include_dirs: ["include_private"],
+
     srcs: ["libdl_android.cpp"],
     version_script: "libdl_android.map.txt",
 
@@ -152,7 +155,12 @@ cc_library {
 
     nocrt: true,
     system_shared_libs: [],
-    header_libs: ["libc_headers"],
+    header_libs: [
+        "libc_headers",
+        "bionic_libc_platform_headers",
+    ],
+
+    export_header_lib_headers: ["bionic_libc_platform_headers"],
 
     // Opt out of native_coverage when opting out of system_shared_libs
     native_coverage: false,
diff --git a/libdl/include_private/android/dlext_private.h b/libdl/include_private/android/dlext_private.h
index fda108683..ac1a781fb 100644
--- a/libdl/include_private/android/dlext_private.h
+++ b/libdl/include_private/android/dlext_private.h
@@ -21,9 +21,6 @@
 
 __BEGIN_DECLS
 
-// TODO: libdl has several private extensions, but they have not all moved into a standard
-// private header.
-
 /**
  * Set whether to load libraries in app compat mode.
  *
diff --git a/libdl/libdl.map.txt b/libdl/libdl.map.txt
index 043ec5349..a3bffcb2f 100644
--- a/libdl/libdl.map.txt
+++ b/libdl/libdl.map.txt
@@ -16,8 +16,8 @@
 
 LIBC {
   global:
-    android_dlopen_ext; # introduced=21
-    dl_iterate_phdr; # introduced-arm=21
+    android_dlopen_ext;
+    dl_iterate_phdr;
     dl_unwind_find_exidx; # arm
     dladdr;
     dlclose;
@@ -45,5 +45,6 @@ LIBC_PLATFORM {
   global:
     android_get_LD_LIBRARY_PATH;
     __cfi_init;
+    __cfi_shadow_load;
     android_handle_signal;
 } LIBC_OMR1;
diff --git a/libdl/libdl_cfi.cpp b/libdl/libdl_cfi.cpp
index e096f9ab7..5b25e3bdc 100644
--- a/libdl/libdl_cfi.cpp
+++ b/libdl/libdl_cfi.cpp
@@ -51,6 +51,10 @@ static uint16_t shadow_load(void* p) {
   return *reinterpret_cast<uint16_t*>(shadow_base_storage.v + ofs);
 }
 
+extern "C" uint16_t __cfi_shadow_load(void* p) {
+  return shadow_load(p);
+}
+
 static uintptr_t cfi_check_addr(uint16_t v, void* Ptr) {
   uintptr_t addr = reinterpret_cast<uintptr_t>(Ptr);
   // The aligned range of [0, kShadowAlign) uses a single shadow element, therefore all pointers in
diff --git a/libm/Android.bp b/libm/Android.bp
index 86b32db67..e9fa05a6b 100644
--- a/libm/Android.bp
+++ b/libm/Android.bp
@@ -3,6 +3,7 @@
 //
 package {
     default_applicable_licenses: ["bionic_libm_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 license {
@@ -130,28 +131,14 @@ cc_library {
         "upstream-freebsd/lib/msun/src/s_fdim.c",
         "upstream-freebsd/lib/msun/src/s_finite.c",
         "upstream-freebsd/lib/msun/src/s_finitef.c",
-        "upstream-freebsd/lib/msun/src/s_fma.c",
-        "upstream-freebsd/lib/msun/src/s_fmaf.c",
-        "upstream-freebsd/lib/msun/src/s_fmax.c",
-        "upstream-freebsd/lib/msun/src/s_fmaxf.c",
-        "upstream-freebsd/lib/msun/src/s_fmin.c",
-        "upstream-freebsd/lib/msun/src/s_fminf.c",
         "upstream-freebsd/lib/msun/src/s_frexp.c",
         "upstream-freebsd/lib/msun/src/s_frexpf.c",
         "upstream-freebsd/lib/msun/src/s_ilogb.c",
         "upstream-freebsd/lib/msun/src/s_ilogbf.c",
-        "upstream-freebsd/lib/msun/src/s_llrint.c",
-        "upstream-freebsd/lib/msun/src/s_llrintf.c",
-        "upstream-freebsd/lib/msun/src/s_llround.c",
-        "upstream-freebsd/lib/msun/src/s_llroundf.c",
         "upstream-freebsd/lib/msun/src/s_log1p.c",
         "upstream-freebsd/lib/msun/src/s_log1pf.c",
         "upstream-freebsd/lib/msun/src/s_logb.c",
         "upstream-freebsd/lib/msun/src/s_logbf.c",
-        "upstream-freebsd/lib/msun/src/s_lrint.c",
-        "upstream-freebsd/lib/msun/src/s_lrintf.c",
-        "upstream-freebsd/lib/msun/src/s_lround.c",
-        "upstream-freebsd/lib/msun/src/s_lroundf.c",
         "upstream-freebsd/lib/msun/src/s_modf.c",
         "upstream-freebsd/lib/msun/src/s_modff.c",
         "upstream-freebsd/lib/msun/src/s_nan.c",
@@ -160,8 +147,6 @@ cc_library {
         "upstream-freebsd/lib/msun/src/s_nextafterf.c",
         "upstream-freebsd/lib/msun/src/s_remquo.c",
         "upstream-freebsd/lib/msun/src/s_remquof.c",
-        "upstream-freebsd/lib/msun/src/s_round.c",
-        "upstream-freebsd/lib/msun/src/s_roundf.c",
         "upstream-freebsd/lib/msun/src/s_scalbln.c",
         "upstream-freebsd/lib/msun/src/s_scalbn.c",
         "upstream-freebsd/lib/msun/src/s_scalbnf.c",
@@ -271,8 +256,18 @@ cc_library {
         arm: {
             srcs: [
                 "fenv-arm.c",
+
+                // Even armv8 arm32 doesn't have instructions for these.
+                "upstream-freebsd/lib/msun/src/s_llrint.c",
+                "upstream-freebsd/lib/msun/src/s_llrintf.c",
+                "upstream-freebsd/lib/msun/src/s_lrint.c",
+                "upstream-freebsd/lib/msun/src/s_lrintf.c",
+                "upstream-freebsd/lib/msun/src/s_llround.c",
+                "upstream-freebsd/lib/msun/src/s_llroundf.c",
+                "upstream-freebsd/lib/msun/src/s_lround.c",
+                "upstream-freebsd/lib/msun/src/s_lroundf.c",
             ],
-            armv7_a_neon: {
+            soft_ceil_floor: {
                 // armv7 arm32 has no instructions to implement these as
                 // builtins, so we build the portable implementations for armv7,
                 // because the NDK still supports armv7.
@@ -281,8 +276,16 @@ cc_library {
                     "upstream-freebsd/lib/msun/src/s_ceilf.c",
                     "upstream-freebsd/lib/msun/src/s_floor.c",
                     "upstream-freebsd/lib/msun/src/s_floorf.c",
+                    "upstream-freebsd/lib/msun/src/s_fma.c",
+                    "upstream-freebsd/lib/msun/src/s_fmaf.c",
+                    "upstream-freebsd/lib/msun/src/s_fmax.c",
+                    "upstream-freebsd/lib/msun/src/s_fmaxf.c",
+                    "upstream-freebsd/lib/msun/src/s_fmin.c",
+                    "upstream-freebsd/lib/msun/src/s_fminf.c",
                     "upstream-freebsd/lib/msun/src/s_rint.c",
                     "upstream-freebsd/lib/msun/src/s_rintf.c",
+                    "upstream-freebsd/lib/msun/src/s_round.c",
+                    "upstream-freebsd/lib/msun/src/s_roundf.c",
                     "upstream-freebsd/lib/msun/src/s_trunc.c",
                     "upstream-freebsd/lib/msun/src/s_truncf.c",
                 ],
@@ -302,24 +305,6 @@ cc_library {
             srcs: [
                 "fenv-arm64.c",
             ],
-            exclude_srcs: [
-                "upstream-freebsd/lib/msun/src/s_fma.c",
-                "upstream-freebsd/lib/msun/src/s_fmaf.c",
-                "upstream-freebsd/lib/msun/src/s_fmax.c",
-                "upstream-freebsd/lib/msun/src/s_fmaxf.c",
-                "upstream-freebsd/lib/msun/src/s_fmin.c",
-                "upstream-freebsd/lib/msun/src/s_fminf.c",
-                "upstream-freebsd/lib/msun/src/s_llrint.c",
-                "upstream-freebsd/lib/msun/src/s_llrintf.c",
-                "upstream-freebsd/lib/msun/src/s_llround.c",
-                "upstream-freebsd/lib/msun/src/s_llroundf.c",
-                "upstream-freebsd/lib/msun/src/s_lrint.c",
-                "upstream-freebsd/lib/msun/src/s_lrintf.c",
-                "upstream-freebsd/lib/msun/src/s_lround.c",
-                "upstream-freebsd/lib/msun/src/s_lroundf.c",
-                "upstream-freebsd/lib/msun/src/s_round.c",
-                "upstream-freebsd/lib/msun/src/s_roundf.c",
-            ],
             version_script: ":libm.arm64.map",
         },
 
@@ -327,37 +312,26 @@ cc_library {
             srcs: [
                 "fenv-riscv64.c",
             ],
+            version_script: ":libm.riscv64.map",
+        },
+
+        x86: {
+            srcs: [
+                "fenv-x86.c",
 
-            exclude_srcs: [
+                // These require x86-64-v3.
                 "upstream-freebsd/lib/msun/src/s_fma.c",
                 "upstream-freebsd/lib/msun/src/s_fmaf.c",
-                "upstream-freebsd/lib/msun/src/s_fmax.c",
-                "upstream-freebsd/lib/msun/src/s_fmaxf.c",
-                "upstream-freebsd/lib/msun/src/s_fmin.c",
-                "upstream-freebsd/lib/msun/src/s_fminf.c",
-                "upstream-freebsd/lib/msun/src/s_llrint.c",
-                "upstream-freebsd/lib/msun/src/s_llrintf.c",
+
+                // https://github.com/llvm/llvm-project/issues/140252
+                "upstream-freebsd/lib/msun/src/s_round.c",
+                "upstream-freebsd/lib/msun/src/s_roundf.c",
+
+                // There are no x86-64 instructions for these.
                 "upstream-freebsd/lib/msun/src/s_llround.c",
                 "upstream-freebsd/lib/msun/src/s_llroundf.c",
-                "upstream-freebsd/lib/msun/src/s_lrint.c",
-                "upstream-freebsd/lib/msun/src/s_lrintf.c",
                 "upstream-freebsd/lib/msun/src/s_lround.c",
                 "upstream-freebsd/lib/msun/src/s_lroundf.c",
-                "upstream-freebsd/lib/msun/src/s_round.c",
-                "upstream-freebsd/lib/msun/src/s_roundf.c",
-            ],
-            version_script: ":libm.riscv64.map",
-        },
-
-        x86: {
-            srcs: [
-                "fenv-x86.c",
-            ],
-            exclude_srcs: [
-                "upstream-freebsd/lib/msun/src/s_llrint.c",
-                "upstream-freebsd/lib/msun/src/s_llrintf.c",
-                "upstream-freebsd/lib/msun/src/s_lrint.c",
-                "upstream-freebsd/lib/msun/src/s_lrintf.c",
             ],
             // The x86 ABI doesn't include this, which is needed for the
             // roundss/roundsd instructions that we've used since API level 23,
@@ -369,12 +343,20 @@ cc_library {
         x86_64: {
             srcs: [
                 "fenv-x86_64.c",
-            ],
-            exclude_srcs: [
-                "upstream-freebsd/lib/msun/src/s_llrint.c",
-                "upstream-freebsd/lib/msun/src/s_llrintf.c",
-                "upstream-freebsd/lib/msun/src/s_lrint.c",
-                "upstream-freebsd/lib/msun/src/s_lrintf.c",
+
+                // These require x86-64-v3.
+                "upstream-freebsd/lib/msun/src/s_fma.c",
+                "upstream-freebsd/lib/msun/src/s_fmaf.c",
+
+                // https://github.com/llvm/llvm-project/issues/140252
+                "upstream-freebsd/lib/msun/src/s_round.c",
+                "upstream-freebsd/lib/msun/src/s_roundf.c",
+
+                // There are no x86-64 instructions for these.
+                "upstream-freebsd/lib/msun/src/s_llround.c",
+                "upstream-freebsd/lib/msun/src/s_llroundf.c",
+                "upstream-freebsd/lib/msun/src/s_lround.c",
+                "upstream-freebsd/lib/msun/src/s_lroundf.c",
             ],
             version_script: ":libm.x86_64.map",
         },
@@ -413,7 +395,6 @@ cc_library {
 
     sanitize: {
         address: false,
-        fuzzer: false,
         integer_overflow: false,
     },
     stl: "none",
@@ -486,7 +467,7 @@ genrule {
     cmd: "$(location generate-version-script) x86_64 $(in) $(out)",
 }
 
-// Because of a historical accidnt, ldexp() is in libc,
+// Because of a historical accident, ldexp() is in libc,
 // even though ldexpf() and ldexpl() are in libm.
 filegroup {
     name: "libc_ldexp_srcs",
diff --git a/libm/builtins.cpp b/libm/builtins.cpp
index 97db425d1..a638aa343 100644
--- a/libm/builtins.cpp
+++ b/libm/builtins.cpp
@@ -48,13 +48,20 @@ __weak_reference(floor, floorl);
 #endif
 #endif
 
-#if defined(__aarch64__) || defined(__riscv)
+#if (defined(__arm__) && (__ARM_ARCH >= 8)) || defined(__aarch64__) || defined(__riscv)
 float fmaf(float x, float y, float z) { return __builtin_fmaf(x, y, z); }
 double fma(double x, double y, double z) { return __builtin_fma(x, y, z); }
+#if defined(__ILP32__)
+__weak_reference(fma, fmal);
+#endif
+#endif
 
+#if (defined(__arm__) && (__ARM_ARCH <= 7))
+// armv7 arm32 has no instructions to implement these builtins,
+// so we include the msun source in the .bp file instead.
+#else
 float fmaxf(float x, float y) { return __builtin_fmaxf(x, y); }
 double fmax(double x, double y) { return __builtin_fmax(x, y); }
-
 float fminf(float x, float y) { return __builtin_fminf(x, y); }
 double fmin(double x, double y) { return __builtin_fmin(x, y); }
 #endif
@@ -84,7 +91,7 @@ __weak_reference(rint, rintl);
 #endif
 #endif
 
-#if defined(__aarch64__) || defined(__riscv)
+#if (defined(__arm__) && (__ARM_ARCH >= 8)) || defined(__aarch64__) || defined(__riscv)
 double round(double x) { return __builtin_round(x); }
 float roundf(float x) { return __builtin_roundf(x); }
 #endif
diff --git a/linker/dlfcn.cpp b/linker/dlfcn.cpp
index fc95903e0..afd899370 100644
--- a/linker/dlfcn.cpp
+++ b/linker/dlfcn.cpp
@@ -330,6 +330,8 @@ soinfo* get_libdl_info(const soinfo& linker_si) {
     __libdl_info->load_bias = linker_si.load_bias;
     __libdl_info->phdr = linker_si.phdr;
     __libdl_info->phnum = linker_si.phnum;
+    __libdl_info->base = linker_si.base;
+    __libdl_info->size = linker_si.size;
 
     __libdl_info->gnu_nbucket_ = linker_si.gnu_nbucket_;
     __libdl_info->gnu_maskwords_ = linker_si.gnu_maskwords_;
diff --git a/linker/linker.cpp b/linker/linker.cpp
index 4cf93b9ba..5580a8350 100644
--- a/linker/linker.cpp
+++ b/linker/linker.cpp
@@ -376,18 +376,21 @@ static void parse_LD_LIBRARY_PATH(const char* path) {
   g_default_namespace.set_ld_library_paths(std::move(ld_libary_paths));
 }
 
+static bool is_proc_mounted() {
+  static bool result = (access("/proc", F_OK) == 0);
+  return result;
+}
+
 static bool realpath_fd(int fd, std::string* realpath) {
   // proc_self_fd needs to be large enough to hold "/proc/self/fd/" plus an
   // integer, plus the NULL terminator.
   char proc_self_fd[32];
-  // We want to statically allocate this large buffer so that we don't grow
-  // the stack by too much.
-  static char buf[PATH_MAX];
-
   async_safe_format_buffer(proc_self_fd, sizeof(proc_self_fd), "/proc/self/fd/%d", fd);
+
+  char buf[PATH_MAX];
   auto length = readlink(proc_self_fd, buf, sizeof(buf));
   if (length == -1) {
-    if (!is_first_stage_init()) {
+    if (is_proc_mounted()) {
       DL_WARN("readlink(\"%s\" [fd=%d]) failed: %m", proc_self_fd, fd);
     }
     return false;
@@ -844,7 +847,7 @@ static const ElfW(Sym)* dlsym_handle_lookup(soinfo* si,
   // Since RTLD_GLOBAL is always set for the main executable and all dt_needed shared
   // libraries and they are loaded in breath-first (correct) order we can just execute
   // dlsym(RTLD_DEFAULT, ...); instead of doing two stage lookup.
-  if (si == solist_get_somain()) {
+  if (si == solist_get_executable()) {
     return dlsym_linear_lookup(&g_default_namespace, name, vi, found, nullptr, RTLD_DEFAULT);
   }
 
@@ -981,7 +984,7 @@ static int open_library_in_zipfile(ZipArchiveCache* zip_archive_cache,
   if (realpath_fd(fd, realpath)) {
     *realpath += separator;
   } else {
-    if (!is_first_stage_init()) {
+    if (is_proc_mounted()) {
       DL_WARN("unable to get realpath for the library \"%s\". Will use given path.",
               normalized_path.c_str());
     }
@@ -1014,7 +1017,7 @@ static int open_library_at_path(ZipArchiveCache* zip_archive_cache,
     if (fd != -1) {
       *file_offset = 0;
       if (!realpath_fd(fd, realpath)) {
-        if (!is_first_stage_init()) {
+        if (is_proc_mounted()) {
           DL_WARN("unable to get realpath for the library \"%s\". Will use given path.", path);
         }
         *realpath = path;
@@ -1326,7 +1329,7 @@ static bool load_library(android_namespace_t* ns,
 
     std::string realpath;
     if (!realpath_fd(extinfo->library_fd, &realpath)) {
-      if (!is_first_stage_init()) {
+      if (is_proc_mounted()) {
         DL_WARN("unable to get realpath for the library \"%s\" by extinfo->library_fd. "
                 "Will use given name.",
                 name);
@@ -1653,8 +1656,13 @@ bool find_libraries(android_namespace_t* ns,
       return t->get_soinfo() == si;
     };
 
-    if (!si->is_linked() &&
-        std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end() ) {
+    // If the executable depends on itself (directly or indirectly), then the executable ends up on
+    // the list of LoadTask objects (b/328822319). It is already loaded, so don't try to load it
+    // again, which will fail because its ElfReader isn't ready. This can happen if ldd is invoked
+    // on a shared library that depends on itself, which happens with HWASan-ified Bionic libraries
+    // like libc.so, libm.so, etc.
+    if (!si->is_linked() && !si->is_main_executable() &&
+        std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end()) {
       load_list.push_back(task);
     }
   }
@@ -1858,7 +1866,7 @@ static soinfo* find_library(android_namespace_t* ns,
   soinfo* si = nullptr;
 
   if (name == nullptr) {
-    si = solist_get_somain();
+    si = solist_get_head();
   } else if (!find_libraries(ns,
                              needed_by,
                              &name,
@@ -3324,7 +3332,7 @@ bool soinfo::prelink_image(bool dlext_use_relro) {
   // they could no longer be found by DT_NEEDED from another library.
   // The main executable does not need to have a DT_SONAME.
   // The linker has a DT_SONAME, but the soname_ field is initialized later on.
-  if (soname_.empty() && this != solist_get_somain() && !relocating_linker &&
+  if (soname_.empty() && this != solist_get_executable() && !relocating_linker &&
       get_application_target_sdk_version() < 23) {
     soname_ = basename(realpath_.c_str());
     // The `if` above means we don't get here for targetSdkVersion >= 23,
@@ -3711,7 +3719,7 @@ std::vector<android_namespace_t*> init_default_namespaces(const char* executable
   }
   // we can no longer rely on the fact that libdl.so is part of default namespace
   // this is why we want to add ld-android.so to all namespaces from ld.config.txt
-  soinfo* ld_android_so = solist_get_head();
+  soinfo* ld_android_so = solist_get_linker();
 
   // we also need vdso to be available for all namespaces (if present)
   soinfo* vdso = solist_get_vdso();
diff --git a/linker/linker.h b/linker/linker.h
index 86ef762a5..80ee00d0e 100644
--- a/linker/linker.h
+++ b/linker/linker.h
@@ -36,6 +36,7 @@
 #include <sys/stat.h>
 #include <unistd.h>
 
+#include "platform/bionic/dlext_namespaces.h"
 #include "platform/bionic/page.h"
 #include "linked_list.h"
 #include "linker_common_types.h"
@@ -107,45 +108,6 @@ bool get_transparent_hugepages_supported();
 void set_16kb_appcompat_mode(bool enable_app_compat);
 bool get_16kb_appcompat_mode();
 
-enum {
-  /* A regular namespace is the namespace with a custom search path that does
-   * not impose any restrictions on the location of native libraries.
-   */
-  ANDROID_NAMESPACE_TYPE_REGULAR = 0,
-
-  /* An isolated namespace requires all the libraries to be on the search path
-   * or under permitted_when_isolated_path. The search path is the union of
-   * ld_library_path and default_library_path.
-   */
-  ANDROID_NAMESPACE_TYPE_ISOLATED = 1,
-
-  /* The shared namespace clones the list of libraries of the caller namespace upon creation
-   * which means that they are shared between namespaces - the caller namespace and the new one
-   * will use the same copy of a library if it was loaded prior to android_create_namespace call.
-   *
-   * Note that libraries loaded after the namespace is created will not be shared.
-   *
-   * Shared namespaces can be isolated or regular. Note that they do not inherit the search path nor
-   * permitted_path from the caller's namespace.
-   */
-  ANDROID_NAMESPACE_TYPE_SHARED = 2,
-
-  /* This flag instructs linker to enable exempt-list workaround for the namespace.
-   * See http://b/26394120 for details.
-   */
-  ANDROID_NAMESPACE_TYPE_EXEMPT_LIST_ENABLED = 0x08000000,
-
-  /* This flag instructs linker to use this namespace as the anonymous
-   * namespace. There can be only one anonymous namespace in a process. If there
-   * already an anonymous namespace in the process, using this flag when
-   * creating a new namespace causes an error
-   */
-  ANDROID_NAMESPACE_TYPE_ALSO_USED_AS_ANONYMOUS = 0x10000000,
-
-  ANDROID_NAMESPACE_TYPE_SHARED_ISOLATED = ANDROID_NAMESPACE_TYPE_SHARED |
-                                           ANDROID_NAMESPACE_TYPE_ISOLATED,
-};
-
 bool init_anonymous_namespace(const char* shared_lib_sonames, const char* library_search_path);
 android_namespace_t* create_namespace(const void* caller_addr,
                                       const char* name,
diff --git a/linker/linker_block_allocator.cpp b/linker/linker_block_allocator.cpp
index e70e6aef7..d7f517ee0 100644
--- a/linker/linker_block_allocator.cpp
+++ b/linker/linker_block_allocator.cpp
@@ -55,7 +55,7 @@ static_assert(kBlockSizeAlign >= alignof(FreeBlockInfo));
 static_assert(kBlockSizeMin == sizeof(FreeBlockInfo));
 
 LinkerBlockAllocator::LinkerBlockAllocator(size_t block_size)
-    : block_size_(__BIONIC_ALIGN(MAX(block_size, kBlockSizeMin), kBlockSizeAlign)),
+    : block_size_(__builtin_align_up(MAX(block_size, kBlockSizeMin), kBlockSizeAlign)),
       page_list_(nullptr),
       free_block_list_(nullptr),
       allocated_(0) {}
diff --git a/linker/linker_block_allocator_test.cpp b/linker/linker_block_allocator_test.cpp
index 56fbee8b7..4dab5d582 100644
--- a/linker/linker_block_allocator_test.cpp
+++ b/linker/linker_block_allocator_test.cpp
@@ -78,7 +78,7 @@ void linker_allocator_test_helper() {
   ASSERT_TRUE(ptr2 != nullptr);
 
   // they should be next to each other.
-  size_t dist = __BIONIC_ALIGN(MAX(sizeof(Element), kBlockSizeMin), kBlockSizeAlign);
+  size_t dist = __builtin_align_up(MAX(sizeof(Element), kBlockSizeMin), kBlockSizeAlign);
   ASSERT_EQ(reinterpret_cast<uint8_t*>(ptr1) + dist, reinterpret_cast<uint8_t*>(ptr2));
 
   allocator.free(ptr1);
diff --git a/linker/linker_debug.h b/linker/linker_debug.h
index e5f17c44c..e453934ae 100644
--- a/linker/linker_debug.h
+++ b/linker/linker_debug.h
@@ -60,9 +60,10 @@ struct LinkerDebugConfig {
 
 extern LinkerDebugConfig g_linker_debug_config;
 
-__LIBC_HIDDEN__ void init_LD_DEBUG(const std::string& value);
-__LIBC_HIDDEN__ void __linker_log(int prio, const char* fmt, ...) __printflike(2, 3);
-__LIBC_HIDDEN__ void __linker_error(const char* fmt, ...) __printflike(1, 2);
+void init_LD_DEBUG(const std::string& value);
+
+void __linker_log(int prio, const char* fmt, ...) __printflike(2, 3);
+void __linker_error(const char* fmt, ...) __printflike(1, 2);
 
 #define LD_DEBUG(what, x...) \
   do { \
diff --git a/linker/linker_gdb_support.cpp b/linker/linker_gdb_support.cpp
index d120e353b..38489bf78 100644
--- a/linker/linker_gdb_support.cpp
+++ b/linker/linker_gdb_support.cpp
@@ -60,7 +60,7 @@ void insert_link_map_into_debug_map(link_map* map) {
   r_debug_tail = map;
 }
 
-void remove_link_map_from_debug_map(link_map* map) {
+static void remove_link_map_from_debug_map(link_map* map) {
   if (r_debug_tail == map) {
     r_debug_tail = map->l_prev;
   }
diff --git a/linker/linker_gdb_support.h b/linker/linker_gdb_support.h
index 4ae18ee36..3d17edcf3 100644
--- a/linker/linker_gdb_support.h
+++ b/linker/linker_gdb_support.h
@@ -34,7 +34,6 @@
 __BEGIN_DECLS
 
 void insert_link_map_into_debug_map(link_map* map);
-void remove_link_map_from_debug_map(link_map* map);
 void notify_gdb_of_load(link_map* map);
 void notify_gdb_of_unload(link_map* map);
 void notify_gdb_of_libraries();
diff --git a/linker/linker_globals.h b/linker/linker_globals.h
index 777e7b8b0..be1b1fd0d 100644
--- a/linker/linker_globals.h
+++ b/linker/linker_globals.h
@@ -105,5 +105,5 @@ class DlErrorRestorer {
   std::string saved_error_msg_;
 };
 
-__LIBC_HIDDEN__ extern bool g_is_ldd;
-__LIBC_HIDDEN__ extern pthread_mutex_t g_dl_mutex;
+extern bool g_is_ldd;
+extern pthread_mutex_t g_dl_mutex;
diff --git a/linker/linker_main.cpp b/linker/linker_main.cpp
index 425bcda67..c52f02aab 100644
--- a/linker/linker_main.cpp
+++ b/linker/linker_main.cpp
@@ -62,7 +62,7 @@
 
 #include <vector>
 
-__LIBC_HIDDEN__ extern "C" void _start();
+extern "C" void _start();
 
 static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf);
 
@@ -80,56 +80,70 @@ static void __linker_cannot_link(const char* argv0) {
   __linker_error("CANNOT LINK EXECUTABLE \"%s\": %s", argv0, linker_get_error_buffer());
 }
 
-// These should be preserved static to avoid emitting
+// These all need to be static to avoid emitting
 // RELATIVE relocations for the part of the code running
 // before linker links itself.
 
-// TODO (dimtiry): remove somain, rename solist to solist_head
-static soinfo* solist;
-static soinfo* sonext;
-static soinfo* somain; // main process, always the one after libdl_info
+/** The head of the list of all objects (including the executable and the linker itself), used for iteration. */
+static soinfo* solist_head;
+/** The tail of the list of all objects (including the executable and the linker itself), used for insertion. */
+static soinfo* solist_tail;
+
+/** The main executable. */
+static soinfo* somain;
+/** The linker. */
 static soinfo* solinker;
-static soinfo* vdso; // vdso if present
+/** The vdso (can be null). */
+static soinfo* vdso;
 
 void solist_add_soinfo(soinfo* si) {
-  sonext->next = si;
-  sonext = si;
+  if (solist_tail == nullptr) {
+    solist_head = solist_tail = si;
+  } else {
+    solist_tail->next = si;
+    solist_tail = si;
+  }
 }
 
 bool solist_remove_soinfo(soinfo* si) {
-  soinfo *prev = nullptr, *trav;
-  for (trav = solist; trav != nullptr; trav = trav->next) {
-    if (trav == si) {
+  soinfo *prev = nullptr, *it;
+  for (it = solist_get_head(); it != nullptr; it = it->next) {
+    if (it == si) {
       break;
     }
-    prev = trav;
+    prev = it;
   }
 
-  if (trav == nullptr) {
-    // si was not in solist
+  if (it == nullptr) {
     DL_WARN("name \"%s\"@%p is not in solist!", si->get_realpath(), si);
     return false;
   }
 
-  // prev will never be null, because the first entry in solist is
-  // always the static libdl_info.
+  // prev will never be null, nor the head of the list,
+  // because the main executable and linker are first,
+  // and they can't be removed.
   CHECK(prev != nullptr);
+  CHECK(prev != solist_head);
   prev->next = si->next;
-  if (si == sonext) {
-    sonext = prev;
+  if (solist_tail == si) {
+    solist_tail = prev;
   }
 
   return true;
 }
 
 soinfo* solist_get_head() {
-  return solist;
+  return solist_head;
 }
 
-soinfo* solist_get_somain() {
+soinfo* solist_get_executable() {
   return somain;
 }
 
+soinfo* solist_get_linker() {
+  return solinker;
+}
+
 soinfo* solist_get_vdso() {
   return vdso;
 }
@@ -329,6 +343,7 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   LD_DEBUG(any, "[ Linking executable \"%s\" ]", exe_info.path.c_str());
 
   // Initialize the main exe's soinfo.
+  // TODO: lose `si` and go straight to somain for clarity.
   soinfo* si = soinfo_alloc(&g_default_namespace,
                             exe_info.path.c_str(), &exe_info.file_stat,
                             0, RTLD_GLOBAL);
@@ -341,9 +356,14 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   si->dynamic = nullptr;
   si->set_main_executable();
   init_link_map_head(*si);
-
   set_bss_vma_name(si);
 
+  // Add the linker's soinfo.
+  // We need to do this manually because it's placement-new'ed by get_libdl_info(),
+  // not created by soinfo_alloc() like everything else.
+  // We do it here because we want it to come after the executable in solist.
+  solist_add_soinfo(solinker);
+
   // Use the executable's PT_INTERP string as the solinker filename in the
   // dynamic linker's module list. gdb reads both PT_INTERP and the module list,
   // and if the paths for the linker are different, gdb will report that the
@@ -393,7 +413,7 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   // and ".plt" sections. Gdb could also potentially use this to
   // relocate the offset of our exported 'rtld_db_dlactivity' symbol.
   //
-  insert_link_map_into_debug_map(&si->link_map_head);
+  insert_link_map_into_debug_map(&somain->link_map_head);
   insert_link_map_into_debug_map(&solinker->link_map_head);
 
   add_vdso();
@@ -480,7 +500,7 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   linker_finalize_static_tls();
   __libc_init_main_thread_final();
 
-  if (!get_cfi_shadow()->InitialLinkDone(solist)) __linker_cannot_link(g_argv[0]);
+  if (!get_cfi_shadow()->InitialLinkDone(solist_get_head())) __linker_cannot_link(g_argv[0]);
 
   si->call_pre_init_constructors();
   si->call_constructors();
@@ -580,7 +600,9 @@ const unsigned kRelTag = DT_REL;
 const unsigned kRelSzTag = DT_RELSZ;
 #endif
 
-extern __LIBC_HIDDEN__ ElfW(Ehdr) __ehdr_start;
+// Magic linker-provided pointer to the ELF header.
+// Hidden so it's accessible before linker relocations have been processed.
+extern "C" const ElfW(Ehdr) __ehdr_start __attribute__((__visibility__("hidden")));
 
 static void call_ifunc_resolvers_for_section(RelType* begin, RelType* end) {
   auto ehdr = reinterpret_cast<ElfW(Addr)>(&__ehdr_start);
@@ -820,22 +842,18 @@ __linker_init_post_relocation(KernelArgumentBlock& args, soinfo& tmp_linker_so)
     }
   }
 
-  // store argc/argv/envp to use them for calling constructors
+  // Store argc/argv/envp to use them for calling constructors.
   g_argc = args.argc - __libc_shared_globals()->initial_linker_arg_count;
   g_argv = args.argv + __libc_shared_globals()->initial_linker_arg_count;
   g_envp = args.envp;
   __libc_shared_globals()->init_progname = g_argv[0];
 
-  // Initialize static variables. Note that in order to
-  // get correct libdl_info we need to call constructors
-  // before get_libdl_info().
-  sonext = solist = solinker = get_libdl_info(tmp_linker_so);
+  solinker = get_libdl_info(tmp_linker_so);
   g_default_namespace.add_soinfo(solinker);
 
   ElfW(Addr) start_address = linker_main(args, exe_to_load);
 
-  LD_DEBUG(any, "[ Jumping to _start (%p)... ]", reinterpret_cast<void*>(start_address));
-
   // Return the address that the calling assembly stub should jump to.
+  LD_DEBUG(any, "[ Jumping to _start (%p)... ]", reinterpret_cast<void*>(start_address));
   return start_address;
 }
diff --git a/linker/linker_main.h b/linker/linker_main.h
index bec9d3581..7341fa84f 100644
--- a/linker/linker_main.h
+++ b/linker/linker_main.h
@@ -68,8 +68,17 @@ bool find_libraries(android_namespace_t* ns,
 
 void solist_add_soinfo(soinfo* si);
 bool solist_remove_soinfo(soinfo* si);
+
+/** Everything: the executable, the linker, and all the libraries. */
 soinfo* solist_get_head();
-soinfo* solist_get_somain();
+
+/** The executable. */
+soinfo* solist_get_executable();
+
+/** The linker. */
+soinfo* solist_get_linker();
+
+/** The VDSO. */
 soinfo* solist_get_vdso();
 
 void linker_memcpy(void* dst, const void* src, size_t n);
diff --git a/linker/linker_phdr.cpp b/linker/linker_phdr.cpp
index 5967e2d48..a905a9c2b 100644
--- a/linker/linker_phdr.cpp
+++ b/linker/linker_phdr.cpp
@@ -31,6 +31,7 @@
 #include <errno.h>
 #include <string.h>
 #include <sys/mman.h>
+#include <sys/param.h>
 #include <sys/prctl.h>
 #include <sys/types.h>
 #include <sys/stat.h>
@@ -182,8 +183,8 @@ bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file
     did_read_ = true;
   }
 
-  if (kPageSize == 16*1024 && min_align_ == 4096) {
-    // This prop needs to be read on 16KiB devices for each ELF where min_palign is 4KiB.
+  if (kPageSize == 16 * 1024 && min_align_ < kPageSize) {
+    // This prop needs to be read on 16KiB devices for each ELF where min_align_ is less than 16KiB.
     // It cannot be cached since the developer may toggle app compat on/off.
     // This check will be removed once app compat is made the default on 16KiB devices.
     should_use_16kib_app_compat_ =
@@ -552,7 +553,7 @@ bool ElfReader::CheckProgramHeaderAlignment() {
     // or a positive, integral power of two.
     // The kernel ignores loadable segments with other values,
     // so we just warn rather than reject them.
-    if ((phdr->p_align & (phdr->p_align - 1)) != 0) {
+    if (!powerof2(phdr->p_align)) {
       DL_WARN("\"%s\" has invalid p_align %zx in phdr %zu", name_.c_str(),
                      static_cast<size_t>(phdr->p_align), i);
       continue;
@@ -565,6 +566,8 @@ bool ElfReader::CheckProgramHeaderAlignment() {
     }
   }
 
+  if (kPageSize == 16 * 1024) FixMinAlignFor16KiB();
+
   return true;
 }
 
@@ -984,8 +987,8 @@ bool ElfReader::LoadSegments() {
     return false;
   }
 
-  if (!Setup16KiBAppCompat()) {
-    DL_ERR("\"%s\" failed to setup 16KiB App Compat", name_.c_str());
+  if (std::string error; !Setup16KiBAppCompat(&error)) {
+    DL_ERR_AND_LOG("%s", error.c_str());
     return false;
   }
 
@@ -1225,31 +1228,13 @@ void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_cou
     // VMA_ANON_NAME to be copied into the kernel), we can get rid of the storage here.
     // For now, that is not the case:
     // https://source.android.com/docs/core/architecture/kernel/android-common#compatibility-matrix
-    constexpr int kVmaNameLimit = 80;
     std::string& vma_name = vma_names->emplace_back(kVmaNameLimit, '\0');
-    int full_vma_length =
-        async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s+%" PRIxPTR, soname,
-                                 page_start(phdr->p_vaddr)) +
-        /* include the null terminator */ 1;
-    // There's an upper limit of 80 characters, including the null terminator, in the anonymous VMA
-    // name. If we run over that limit, we end up truncating the segment offset and parts of the
-    // DSO's name, starting on the right hand side of the basename. Because the basename is the most
-    // important thing, chop off the soname from the left hand side first.
-    //
-    // Example (with '#' as the null terminator):
-    //   - "mt:/data/nativetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000#"
-    //     is a `full_vma_length` == 86.
-    //
-    // We need to left-truncate (86 - 80) 6 characters from the soname, plus the
-    // `vma_truncation_prefix`, so 9 characters total.
-    if (full_vma_length > kVmaNameLimit) {
-      const char vma_truncation_prefix[] = "...";
-      int soname_truncated_bytes =
-          full_vma_length - kVmaNameLimit + sizeof(vma_truncation_prefix) - 1;
-      async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s%s+%" PRIxPTR,
-                               vma_truncation_prefix, soname + soname_truncated_bytes,
-                               page_start(phdr->p_vaddr));
-    }
+    // 18 characters are enough for the '+' prefix, 16 hex digits, and the null terminator.
+    char suffix_buffer[18] = {};
+    async_safe_format_buffer(suffix_buffer, sizeof(suffix_buffer), "+%" PRIxPTR,
+                             page_start(phdr->p_vaddr));
+    format_left_truncated_vma_anon_name(vma_name.data(), vma_name.size(), "mt:", soname,
+                                        suffix_buffer);
     if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(seg_page_start),
               seg_page_aligned_size, vma_name.data()) != 0) {
       DL_WARN("Failed to rename memtag global segment: %m");
@@ -1257,6 +1242,31 @@ void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_cou
   }
 }
 
+/* There's an upper limit of 80 characters, including the null terminator, on the anonymous VMA
+ * name. This limit is easily exceeded when setting the mapping's name to a path. To stay within the
+ * character limit, we must truncate the name to fit into 80 bytes. Since the most important part of
+ * a path is the basename, we start truncating from the left side.
+ *
+ * Example (with prefix = "mt:", suffix = "+e000", and '#' as the null terminator):
+ *   - "mt:/data/nativetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000#"
+ * This mapping name would have a length of 86, so we left-truncate (86 - 80 + 3) 9 characters from
+ * the path in order to add "..." to the front and fit into the 80 character limit:
+ *   - "mt:...ivetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000#"
+ */
+void format_left_truncated_vma_anon_name(char* buffer, size_t buffer_size, const char* prefix,
+                                         const char* name, const char* suffix) {
+  size_t full_vma_name_length =
+      async_safe_format_buffer(buffer, buffer_size, "%s%s%s", prefix, name, suffix) +
+      /* null terminator */ 1;
+  if (full_vma_name_length > buffer_size) {
+    const char* truncation_prefix = "...";
+    size_t truncation_prefix_length = strlen(truncation_prefix);
+    size_t truncated_bytes = full_vma_name_length - buffer_size + truncation_prefix_length;
+    async_safe_format_buffer(buffer, buffer_size, "%s%s%s%s", prefix, truncation_prefix,
+                             name + truncated_bytes, suffix);
+  }
+}
+
 /* Change the protection of all loaded segments in memory to writable.
  * This is useful before performing relocations. Once completed, you
  * will have to call phdr_table_protect_segments to restore the original
diff --git a/linker/linker_phdr.h b/linker/linker_phdr.h
index 3b68528e7..f860d4966 100644
--- a/linker/linker_phdr.h
+++ b/linker/linker_phdr.h
@@ -47,6 +47,7 @@
                                       MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
 
 static constexpr size_t kCompatPageSize = 0x1000;
+static constexpr size_t kVmaNameLimit = 80;
 
 class ElfReader {
  public:
@@ -89,7 +90,8 @@ class ElfReader {
                                    ElfW(Addr) seg_file_end);
   [[nodiscard]] bool IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr);
   [[nodiscard]] bool HasAtMostOneRelroSegment(const ElfW(Phdr)** relro_phdr);
-  [[nodiscard]] bool Setup16KiBAppCompat();
+  void FixMinAlignFor16KiB();
+  [[nodiscard]] bool Setup16KiBAppCompat(std::string* error);
   [[nodiscard]] bool LoadSegments();
   [[nodiscard]] bool FindPhdr();
   [[nodiscard]] bool FindGnuPropertySection();
@@ -202,3 +204,6 @@ void protect_memtag_globals_ro_segments(const ElfW(Phdr) * phdr_table, size_t ph
 void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
                                   ElfW(Addr) load_bias, const char* soname,
                                   std::list<std::string>* vma_names);
+
+void format_left_truncated_vma_anon_name(char* buffer, size_t buffer_size, const char* prefix,
+                                         const char* name, const char* suffix);
diff --git a/linker/linker_phdr_16kib_compat.cpp b/linker/linker_phdr_16kib_compat.cpp
index d3783cf2e..75625ba14 100644
--- a/linker/linker_phdr_16kib_compat.cpp
+++ b/linker/linker_phdr_16kib_compat.cpp
@@ -29,6 +29,7 @@
 #include "linker_phdr.h"
 
 #include <linux/prctl.h>
+#include <stdlib.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
 #include <unistd.h>
@@ -40,7 +41,13 @@
 #include "platform/bionic/macros.h"
 #include "platform/bionic/page.h"
 
+#include <android-base/stringprintf.h>
+
+#include <algorithm>
+#include <iterator>
+#include <numeric>
 #include <string>
+#include <vector>
 
 static bool g_enable_16kb_app_compat;
 
@@ -188,13 +195,150 @@ static inline ElfW(Addr) perm_boundary_offset(const ElfW(Addr) addr) {
   return offset ? page_size() - offset : 0;
 }
 
-bool ElfReader::Setup16KiBAppCompat() {
+enum relro_pos_t {
+  NONE,    // No RELRO in the LOAD segment
+  PREFIX,  // RELRO is a prefix of the LOAD segment
+  MIDDLE,  // RELRO is contained in the middle of the LOAD segment
+  SUFFIX,  // RELRO is a suffix of the LOAD segment
+  ENTIRE,  // RELRO is the entire LOAD segment
+  ERROR,   // The relro size invalid (spans multiple segments?)
+};
+
+struct segment {
+  const ElfW(Phdr)* phdr;
+  relro_pos_t relro_pos;
+};
+
+static inline relro_pos_t relro_pos(const ElfW(Phdr)* phdr, const ElfW(Phdr)* relro) {
+  // For checking the relro boundaries we use instead the LOAD segment's p_align
+  // instead of the system or compat page size.
+  uint64_t align = phdr->p_align;
+  uint64_t seg_start = __builtin_align_down(phdr->p_vaddr, align);
+  uint64_t seg_end = __builtin_align_up(phdr->p_vaddr + phdr->p_memsz, align);
+  uint64_t relro_start = __builtin_align_down(relro->p_vaddr, align);
+  uint64_t relro_end = __builtin_align_up(relro->p_vaddr + relro->p_memsz, align);
+
+  if (relro_end <= seg_start || relro_start >= seg_end) return NONE;
+
+  // Spans multiple LOAD segments?
+  if (relro_start < seg_start || relro_end > seg_end) return ERROR;
+
+  // Prefix or entire?
+  if (relro_start == seg_start) return (relro_end < seg_end) ? PREFIX : ENTIRE;
+
+  // Must be suffix or middle
+  return (relro_end == seg_end) ? SUFFIX : MIDDLE;
+}
+
+static std::vector<struct segment> elf_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count) {
+  std::vector<struct segment> segments;
+
+  for (size_t index = 0; index < phdr_count; ++index) {
+    const ElfW(Phdr)* phdr = &phdr_table[index];
+
+    if (phdr->p_type != PT_LOAD) continue;
+
+    struct segment segment = {
+        .phdr = phdr,
+        .relro_pos = NONE,
+    };
+
+    segments.emplace_back(segment);
+  }
+
+  for (size_t index = 0; index < phdr_count; ++index) {
+    const ElfW(Phdr)* relro = &phdr_table[index];
+
+    if (relro->p_type != PT_GNU_RELRO) continue;
+
+    for (struct segment& segment : segments) {
+      if (segment.relro_pos != NONE) continue;
+
+      segment.relro_pos = relro_pos(segment.phdr, relro);
+    }
+  }
+
+  // Sort by vaddr
+  std::sort(segments.begin(), segments.end(), [](const struct segment& a, const struct segment& b) {
+    return a.phdr->p_vaddr < b.phdr->p_vaddr;
+  });
+
+  return segments;
+}
+
+static inline std::string prot_str(const struct segment& segment) {
+  int prot = PFLAGS_TO_PROT(segment.phdr->p_flags);
+  std::string str;
+
+  if (prot & PROT_READ) str += "R";
+  if (prot & PROT_WRITE) str += "W";
+  if (prot & PROT_EXEC) str += "X";
+
+  return str;
+}
+
+static inline std::string relro_pos_str(const struct segment& segment) {
+  relro_pos_t relro_pos = segment.relro_pos;
+
+  switch (relro_pos) {
+    case NONE:
+      return "";
+    case PREFIX:
+      return "(PREFIX)";
+    case MIDDLE:
+      return "(MIDDLE)";
+    case SUFFIX:
+      return "(SUFFIX)";
+    case ENTIRE:
+      return "(ENTIRE)";
+    case ERROR:
+      return "(ERROR)";
+  }
+
+  // Unreachable
+  abort();
+}
+
+static inline std::string segment_format(const struct segment& segment) {
+  uint64_t align_kbytes = segment.phdr->p_align / 1024;
+  std::string format = prot_str(segment);
+
+  if (segment.relro_pos != NONE) format += " " + relro_pos_str(segment);
+
+  return format + " " + std::to_string(align_kbytes) + "K";
+}
+
+/*
+ * Returns a string representing the ELF's load segment layout.
+ *
+ * Each segment has the format: <permissions> [(<relro position>)] <p_align>
+ *
+ *   e.g. "RX 4K|RW (ENTIRE) 4K|RW 4K|RW 16K|RX 16K|R 16K|RW 16K"
+ */
+static inline std::string elf_layout(const ElfW(Phdr)* phdr_table, size_t phdr_count) {
+  std::vector<struct segment> segments = elf_segments(phdr_table, phdr_count);
+  std::vector<std::string> layout;
+
+  for (struct segment& segment : segments) {
+    layout.emplace_back(segment_format(segment));
+  }
+
+  if (layout.empty()) return "";
+
+  return std::accumulate(std::next(layout.begin()), layout.end(), layout[0],
+                         [](std::string a, std::string b) { return std::move(a) + "," + b; });
+}
+
+bool ElfReader::Setup16KiBAppCompat(std::string* error) {
   if (!should_use_16kib_app_compat_) {
     return true;
   }
 
   ElfW(Addr) rx_rw_boundary;  // Permission bounadry for compat mode
   if (!IsEligibleFor16KiBAppCompat(&rx_rw_boundary)) {
+    const std::string layout = elf_layout(phdr_table_, phdr_num_);
+    *error = android::base::StringPrintf("\"%s\" 16K app compat failed: load segments: [%s]",
+                                         name_.c_str(), layout.c_str());
     return false;
   }
 
@@ -212,9 +356,17 @@ bool ElfReader::Setup16KiBAppCompat() {
   compat_relro_start_ = reinterpret_cast<ElfW(Addr)>(load_start_);
   compat_relro_size_ = load_size_ - rw_size;
 
-  // Label the ELF VMA, since compat mode uses anonymous mappings.
-  std::string compat_name = name_ + " (compat loaded)";
-  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, load_start_, load_size_, compat_name.c_str());
+  // Label the ELF VMA, since compat mode uses anonymous mappings, and some applications may rely on
+  // them having their name set to the ELF's path.
+  // Since kernel 5.10 it is safe to use non-global storage for the VMA name because it will be
+  // copied into the kernel. 16KiB pages require a minimum kernel version of 6.1 so we can safely
+  // use a stack-allocated buffer here.
+  char vma_name_buffer[kVmaNameLimit] = {};
+  format_left_truncated_vma_anon_name(vma_name_buffer, sizeof(vma_name_buffer),
+                                      "16k:", name_.c_str(), "");
+  if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, load_start_, load_size_, vma_name_buffer) != 0) {
+    DL_WARN("Failed to rename 16KiB compat segment: %m");
+  }
 
   return true;
 }
@@ -245,3 +397,54 @@ bool ElfReader::CompatMapSegment(size_t seg_idx, size_t len) {
 
   return true;
 }
+
+static size_t phdr_table_get_relro_min_align(const ElfW(Phdr)* relro_phdr,
+                                             const ElfW(Phdr)* phdr_table, size_t phdr_count) {
+  for (size_t index = 0; index < phdr_count; ++index) {
+    const ElfW(Phdr)* phdr = &phdr_table[index];
+
+    if (phdr->p_type != PT_LOAD) {
+      continue;
+    }
+
+    // Only check for the case, where the relro segment is a prefix of a load segment. Conventional
+    // linkers will only generate binaries where the relro segment is either the prefix of the first
+    // RW load segment, or is entirely contained in the first RW segment.
+    if (phdr->p_vaddr == relro_phdr->p_vaddr) {
+      // No extra alignment checks needed if the whole load segment is relro.
+      if (phdr->p_memsz <= relro_phdr->p_memsz) {
+        return 0;
+      }
+
+      ElfW(Addr) relro_end = relro_phdr->p_vaddr + relro_phdr->p_memsz;
+      // Alignments must be powers of two, so the RELRO segment's alignment can be determined by
+      // calculating its lowest set bit with (n & -n).
+      size_t relro_align = static_cast<size_t>(relro_end & -relro_end);
+      // We only care about relro segments that are aligned to at least 4KiB. This is always
+      // expected for outputs of a conventional linker.
+      return relro_align >= kCompatPageSize ? relro_align : 0;
+    }
+  }
+  return 0;
+}
+
+/*
+ * In the base page size is 16KiB and the RELRO's end alignment is less than min_align_;
+ *  override min_align_ with the relro's end alignment. This ensures that the ELF is
+ * loaded in compat mode even if the LOAD segments are 16KB aligned.
+ * Linker bug: https://sourceware.org/bugzilla/show_bug.cgi?id=28824
+ */
+void ElfReader::FixMinAlignFor16KiB() {
+  // A binary with LOAD segment alignments of at least 16KiB can still be incompatible with 16KiB
+  // page sizes if the first RW segment has a RELRO prefix ending at a non-16KiB-aligned address. We
+  // need to check for this possibility here and adjust min_align_ accordingly.
+  // We only check if the ELF file contains a single RELRO segment, because that's what the 16KiB
+  // compatibility loader can handle.
+  const ElfW(Phdr)* relro_phdr = nullptr;
+  if (HasAtMostOneRelroSegment(&relro_phdr) && relro_phdr != nullptr) {
+    size_t relro_min_align = phdr_table_get_relro_min_align(relro_phdr, phdr_table_, phdr_num_);
+    if (relro_min_align) {
+      min_align_ = std::min(min_align_, relro_min_align);
+    }
+  }
+}
diff --git a/linker/linker_tls.cpp b/linker/linker_tls.cpp
index e90b8cb7f..d407bc42a 100644
--- a/linker/linker_tls.cpp
+++ b/linker/linker_tls.cpp
@@ -108,16 +108,16 @@ extern "C" void __linker_reserve_bionic_tls_in_static_tls() {
 }
 
 void linker_setup_exe_static_tls(const char* progname) {
-  soinfo* somain = solist_get_somain();
+  soinfo* executable = solist_get_executable();
   StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
 
   // For ldd, don't add the executable's TLS segment to the static TLS layout.
   // It is likely to trigger the underaligned TLS segment error on arm32/arm64
   // when the ldd argument is actually a shared object.
-  if (somain->get_tls() == nullptr || g_is_ldd) {
+  if (executable->get_tls() == nullptr || g_is_ldd) {
     layout.reserve_exe_segment_and_tcb(nullptr, progname);
   } else {
-    register_tls_module(somain, layout.reserve_exe_segment_and_tcb(&somain->get_tls()->segment, progname));
+    register_tls_module(executable, layout.reserve_exe_segment_and_tcb(&executable->get_tls()->segment, progname));
   }
 
   // The pthread key data is located at the very front of bionic_tls. As a
diff --git a/linker/linker_tls.h b/linker/linker_tls.h
index 87e1f0d1e..5a20a64ca 100644
--- a/linker/linker_tls.h
+++ b/linker/linker_tls.h
@@ -60,6 +60,6 @@ struct TlsDynamicResolverArg {
   TlsIndex index;
 };
 
-__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_static(size_t);
-__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_dynamic(size_t);
-__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_unresolved_weak(size_t);
+extern "C" size_t tlsdesc_resolver_static(size_t);
+extern "C" size_t tlsdesc_resolver_dynamic(size_t);
+extern "C" size_t tlsdesc_resolver_unresolved_weak(size_t);
diff --git a/linker/linker_wrapper.cpp b/linker/linker_wrapper.cpp
index 5ee2d3ee2..a5e741b86 100644
--- a/linker/linker_wrapper.cpp
+++ b/linker/linker_wrapper.cpp
@@ -34,7 +34,7 @@
 extern const char __dlwrap_linker_offset;
 
 // The real entry point of the binary to use after linker bootstrapping.
-__LIBC_HIDDEN__ extern "C" void _start();
+extern "C" void _start();
 
 /* Find the load bias and base address of an executable or shared object loaded
  * by the kernel. The ELF file's PHDR table must have a PT_PHDR entry.
diff --git a/linker/testdata/Android.bp b/linker/testdata/Android.bp
index f99818034..bfea6e585 100644
--- a/linker/testdata/Android.bp
+++ b/linker/testdata/Android.bp
@@ -14,6 +14,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 cc_library_shared {
diff --git a/tests/Android.bp b/tests/Android.bp
index 4509cc4bd..112ecb2c6 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -40,7 +40,8 @@ cc_defaults {
         },
         android: {
             header_libs: ["bionic_libc_platform_headers"],
-        },
+            shared_libs: ["libdl_android"],
+         },
         linux_bionic: {
             header_libs: ["bionic_libc_platform_headers"],
         },
@@ -349,6 +350,8 @@ cc_prebuilt_test_library_shared {
         arm64: {
             srcs: ["prebuilt-elf-files/arm64/libtest_invalid-local-tls.so"],
         },
+        // No riscv64 here because the gold linker never had riscv64 support,
+        // and this is a test for a gold-specific bug.
         x86: {
             srcs: ["prebuilt-elf-files/x86/libtest_invalid-local-tls.so"],
         },
@@ -432,6 +435,7 @@ cc_test_library {
         "locale_test.cpp",
         "malloc_iterate_test.cpp",
         "malloc_test.cpp",
+        "malloc_test_with_usable_size.cpp",
         "math_test.cpp",
         "membarrier_test.cpp",
         "memtag_globals_test.cpp",
@@ -528,6 +532,7 @@ cc_test_library {
         "unistd_nofortify_test.cpp",
         "unistd_test.cpp",
         "utils.cpp",
+        "utime_test.cpp",
         "utmp_test.cpp",
         "utmpx_test.cpp",
         "wchar_test.cpp",
@@ -647,10 +652,19 @@ cc_defaults {
 
 cc_defaults {
     name: "bionic_fortify_tests_defaults",
+    defaults: [
+        "bionic_tests_defaults",
+    ],
     cflags: [
         "-U_FORTIFY_SOURCE",
+        // Without this, HWASan will not recognize (i.e. will not detect errors involving)
+        // calls to mem* functions.
+        "-fbuiltin",
     ],
     srcs: ["fortify_test_main.cpp"],
+    shared: {
+        enabled: false,
+    },
     static_libs: [
         "libbase",
     ],
@@ -673,7 +687,8 @@ cc_test_library {
     ],
     cflags: [
         "-Werror",
-        "-D_FORTIFY_SOURCE=2",
+        "-U_FORTIFY_SOURCE",
+        "-D_FORTIFY_SOURCE=3",
         "-D__clang_analyzer__",
     ],
     srcs: ["clang_fortify_tests.cpp"],
@@ -683,40 +698,50 @@ cc_test_library {
     name: "libfortify1-tests-clang",
     defaults: [
         "bionic_fortify_tests_defaults",
-        "bionic_tests_defaults",
     ],
     cflags: [
         "-D_FORTIFY_SOURCE=1",
         "-DTEST_NAME=Fortify1_clang",
     ],
-    shared: {
-        enabled: false,
-    },
 }
 
 cc_test_library {
     name: "libfortify2-tests-clang",
     defaults: [
         "bionic_fortify_tests_defaults",
-        "bionic_tests_defaults",
     ],
     cflags: [
         "-D_FORTIFY_SOURCE=2",
         "-DTEST_NAME=Fortify2_clang",
     ],
-    shared: {
-        enabled: false,
-    },
+}
+
+cc_test_library {
+    name: "libfortify3-tests-clang",
+    defaults: [
+        "bionic_fortify_tests_defaults",
+    ],
+    cflags: [
+        "-D_FORTIFY_SOURCE=3",
+        "-DTEST_NAME=Fortify3_clang",
+    ],
 }
 
 cc_defaults {
     name: "bionic_new_fortify_tests_defaults",
     defaults: [
         "bionic_clang_fortify_tests_w_flags",
+        "bionic_tests_defaults",
     ],
     cflags: [
         "-U_FORTIFY_SOURCE",
+        // Without this, HWASan will not recognize (i.e. will not detect errors involving)
+        // calls to mem* functions.
+        "-fbuiltin",
     ],
+    shared: {
+        enabled: false,
+    },
     srcs: ["clang_fortify_tests.cpp"],
 }
 
@@ -724,30 +749,33 @@ cc_test_library {
     name: "libfortify1-new-tests-clang",
     defaults: [
         "bionic_new_fortify_tests_defaults",
-        "bionic_tests_defaults",
     ],
     cflags: [
         "-D_FORTIFY_SOURCE=1",
         "-DTEST_NAME=Fortify1_clang_new",
     ],
-    shared: {
-        enabled: false,
-    },
 }
 
 cc_test_library {
     name: "libfortify2-new-tests-clang",
     defaults: [
         "bionic_new_fortify_tests_defaults",
-        "bionic_tests_defaults",
     ],
     cflags: [
         "-D_FORTIFY_SOURCE=2",
         "-DTEST_NAME=Fortify2_clang_new",
     ],
-    shared: {
-        enabled: false,
-    },
+}
+
+cc_test_library {
+    name: "libfortify3-new-tests-clang",
+    defaults: [
+        "bionic_new_fortify_tests_defaults",
+    ],
+    cflags: [
+        "-D_FORTIFY_SOURCE=3",
+        "-DTEST_NAME=Fortify3_clang_new",
+    ],
 }
 
 cc_defaults {
@@ -783,6 +811,12 @@ cc_test_library {
     cflags: ["-D_FORTIFY_SOURCE=2"],
 }
 
+cc_test_library {
+    name: "libfortify3-c-tests-clang",
+    defaults: ["bionic_fortify_c_tests_defaults"],
+    cflags: ["-D_FORTIFY_SOURCE=3"],
+}
+
 // -----------------------------------------------------------------------------
 // Library of all tests (excluding the dynamic linker tests).
 // -----------------------------------------------------------------------------
@@ -800,6 +834,9 @@ cc_test_library {
         "libfortify2-c-tests-clang",
         "libfortify2-tests-clang",
         "libfortify2-new-tests-clang",
+        "libfortify3-c-tests-clang",
+        "libfortify3-tests-clang",
+        "libfortify3-new-tests-clang",
     ],
     shared: {
         enabled: false,
@@ -1350,6 +1387,7 @@ cc_test_host {
         "dlfcn_test.cpp",
         "dl_test.cpp",
         "execinfo_test.cpp",
+        "link_test.cpp",
         "gtest_globals.cpp",
         "gtest_main.cpp",
         "pthread_dlfcn_test.cpp",
@@ -1369,6 +1407,7 @@ cc_test_host {
         "libBionicElfTlsLoaderTests",
         "libfortify1-tests-clang",
         "libfortify2-tests-clang",
+        "libfortify3-tests-clang",
     ],
 
     static_libs: [
@@ -1405,6 +1444,7 @@ cc_test_host {
                 // Musl doesn't have fortify
                 "libfortify1-tests-clang",
                 "libfortify2-tests-clang",
+                "libfortify3-tests-clang",
             ],
         },
     },
diff --git a/tests/NOTICE b/tests/NOTICE
index de95698cf..accde4424 100644
--- a/tests/NOTICE
+++ b/tests/NOTICE
@@ -482,3 +482,31 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
+Copyright (C) 2025 The Android Open Source Project
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions
+are met:
+ * Redistributions of source code must retain the above copyright
+   notice, this list of conditions and the following disclaimer.
+ * Redistributions in binary form must reproduce the above copyright
+   notice, this list of conditions and the following disclaimer in
+   the documentation and/or other materials provided with the
+   distribution.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+SUCH DAMAGE.
+
+-------------------------------------------------------------------
+
diff --git a/tests/cfi_test.cpp b/tests/cfi_test.cpp
index 79a9e35eb..46454c5e9 100644
--- a/tests/cfi_test.cpp
+++ b/tests/cfi_test.cpp
@@ -15,6 +15,7 @@
  */
 
 #include <dlfcn.h>
+#include <link.h>
 #include <sys/stat.h>
 
 #include <vector>
@@ -33,6 +34,7 @@ extern "C" {
 void __cfi_slowpath(uint64_t CallSiteTypeId, void* Ptr);
 void __cfi_slowpath_diag(uint64_t CallSiteTypeId, void* Ptr, void* DiagData);
 size_t __cfi_shadow_size();
+uintptr_t __cfi_shadow_load(void* p);
 }
 
 // Disables debuggerd stack traces to speed up death tests, make them less
@@ -177,3 +179,28 @@ TEST(cfi_test, early_init2) {
   eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, nullptr);
 #endif
 }
+
+TEST(cfi_test, every_loaded_dso_has_valid_shadow) {
+#if defined(__BIONIC__)
+  if (__cfi_shadow_size() == 0) GTEST_SKIP();
+
+  auto callback = [](dl_phdr_info* info, size_t, void*) {
+    if (info->dlpi_phnum == 0 || !info->dlpi_phdr) return 0;
+    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
+      auto& ph = info->dlpi_phdr[i];
+      if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X)) continue;
+      uintptr_t sample_addr = info->dlpi_addr + ph.p_vaddr;
+      uint16_t v = __cfi_shadow_load(reinterpret_cast<void*>(sample_addr));
+
+      EXPECT_NE(uint16_t(CFIShadow::kInvalidShadow), v)
+          << "ERROR: cfi shadow value is invalid, " << info->dlpi_name
+          << " @ 0x" << std::hex << sample_addr
+          << " → shadow=0x" << v
+          << " (" << std::dec << v << ")";
+    }
+    return 0;
+  };
+
+  dl_iterate_phdr(callback, nullptr);
+#endif
+}
diff --git a/tests/clang_fortify_tests.cpp b/tests/clang_fortify_tests.cpp
index da7926d46..6b48d374c 100644
--- a/tests/clang_fortify_tests.cpp
+++ b/tests/clang_fortify_tests.cpp
@@ -25,7 +25,8 @@
 // (https://clang.llvm.org/doxygen/classclang_1_1VerifyDiagnosticConsumer.html#details)
 // to check diagnostics (e.g. the expected-* comments everywhere).
 //
-// 2. For run-time checks, we build and run as regular gtests.
+// 2. For run-time checks, we build and run as regular gtests (as described in
+// bionic/README.md).
 
 // Note that these tests do things like leaking memory. That's WAI.
 
@@ -125,6 +126,12 @@ __attribute__((noreturn)) static void ExitAfter(Fn&& f) {
 #define EXPECT_FORTIFY_DEATH_STRUCT EXPECT_NO_DEATH
 #endif
 
+#if __has_feature(hwaddress_sanitizer)
+#define EXPECT_FORTIFY_OR_HWASAN_DEATH(expr) DIE_WITH(expr, testing::KilledBySignal(SIGABRT), "HWAddressSanitizer")
+#else
+#define EXPECT_FORTIFY_OR_HWASAN_DEATH EXPECT_FORTIFY_DEATH
+#endif
+
 #define FORTIFY_TEST(test_name) TEST_F(FORTIFY_TEST_NAME, test_name)
 
 #else  // defined(COMPILATION_TESTS)
@@ -132,6 +139,7 @@ __attribute__((noreturn)) static void ExitAfter(Fn&& f) {
 #define EXPECT_NO_DEATH(expr) expr
 #define EXPECT_FORTIFY_DEATH(expr) expr
 #define EXPECT_FORTIFY_DEATH_STRUCT EXPECT_FORTIFY_DEATH
+#define EXPECT_FORTIFY_OR_HWASAN_DEATH EXPECT_FORTIFY_DEATH
 #define FORTIFY_TEST(test_name) void test_name()
 #endif
 
@@ -161,15 +169,13 @@ FORTIFY_TEST(string) {
   {
     char large_buffer[sizeof(small_buffer) + 1] = {};
     // expected-error@+1{{will always overflow}}
-    EXPECT_FORTIFY_DEATH(memcpy(small_buffer, large_buffer, sizeof(large_buffer)));
+    EXPECT_FORTIFY_OR_HWASAN_DEATH(memcpy(small_buffer, large_buffer, sizeof(large_buffer)));
+    // expected-error@+1{{will always overflow}}
+    EXPECT_FORTIFY_OR_HWASAN_DEATH(memmove(small_buffer, large_buffer, sizeof(large_buffer)));
     // expected-error@+1{{will always overflow}}
-    EXPECT_FORTIFY_DEATH(memmove(small_buffer, large_buffer, sizeof(large_buffer)));
-    // FIXME(gbiv): look into removing mempcpy's diagnose_if bits once the b/149839606 roll sticks.
-    // expected-error@+2{{will always overflow}}
-    // expected-error@+1{{size bigger than buffer}}
     EXPECT_FORTIFY_DEATH(mempcpy(small_buffer, large_buffer, sizeof(large_buffer)));
     // expected-error@+1{{will always overflow}}
-    EXPECT_FORTIFY_DEATH(memset(small_buffer, 0, sizeof(large_buffer)));
+    EXPECT_FORTIFY_OR_HWASAN_DEATH(memset(small_buffer, 0, sizeof(large_buffer)));
     // expected-warning@+1{{arguments got flipped?}}
     EXPECT_NO_DEATH(memset(small_buffer, sizeof(small_buffer), 0));
     // expected-error@+1{{size bigger than buffer}}
@@ -182,8 +188,7 @@ FORTIFY_TEST(string) {
     const char large_string[] = "Hello!!!";
     static_assert(sizeof(large_string) > sizeof(small_buffer), "");
 
-    // expected-error@+2{{will always overflow}}
-    // expected-error@+1{{string bigger than buffer}}
+    // expected-error@+1{{will always overflow}}
     EXPECT_FORTIFY_DEATH(strcpy(small_buffer, large_string));
     // expected-error@+1{{string bigger than buffer}}
     EXPECT_FORTIFY_DEATH(stpcpy(small_buffer, large_string));
@@ -220,8 +225,7 @@ FORTIFY_TEST(string) {
     static_assert(sizeof(small_string) > sizeof(split.tiny_buffer), "");
 
 #if _FORTIFY_SOURCE > 1
-    // expected-error@+3{{will always overflow}}
-    // expected-error@+2{{string bigger than buffer}}
+    // expected-error@+2{{will always overflow}}
 #endif
     EXPECT_FORTIFY_DEATH_STRUCT(strcpy(split.tiny_buffer, small_string));
 
diff --git a/tests/dlext_private_tests.h b/tests/dlext_private_tests.h
deleted file mode 100644
index 262af4c25..000000000
--- a/tests/dlext_private_tests.h
+++ /dev/null
@@ -1,105 +0,0 @@
-/*
- * Copyright (C) 2016 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef __ANDROID_DLEXT_NAMESPACES_H__
-#define __ANDROID_DLEXT_NAMESPACES_H__
-
-#include <android/dlext.h>
-
-__BEGIN_DECLS
-
-/*
- * Initializes anonymous namespaces. The shared_libs_sonames is the list of sonames
- * to be shared by default namespace separated by colon. Example: "libc.so:libm.so:libdl.so".
- *
- * The library_search_path is the search path for anonymous namespace. The anonymous namespace
- * is used in the case when linker cannot identify the caller of dlopen/dlsym. This happens
- * for the code not loaded by dynamic linker; for example calls from the mono-compiled code.
- */
-extern bool android_init_anonymous_namespace(const char* shared_libs_sonames,
-                                             const char* library_search_path);
-
-
-enum {
-  /* A regular namespace is the namespace with a custom search path that does
-   * not impose any restrictions on the location of native libraries.
-   */
-  ANDROID_NAMESPACE_TYPE_REGULAR = 0,
-
-  /* An isolated namespace requires all the libraries to be on the search path
-   * or under permitted_when_isolated_path. The search path is the union of
-   * ld_library_path and default_library_path.
-   */
-  ANDROID_NAMESPACE_TYPE_ISOLATED = 1,
-
-  /* The shared namespace clones the list of libraries of the caller namespace upon creation
-   * which means that they are shared between namespaces - the caller namespace and the new one
-   * will use the same copy of a library if it was loaded prior to android_create_namespace call.
-   *
-   * Note that libraries loaded after the namespace is created will not be shared.
-   *
-   * Shared namespaces can be isolated or regular. Note that they do not inherit the search path nor
-   * permitted_path from the caller's namespace.
-   */
-  ANDROID_NAMESPACE_TYPE_SHARED = 2,
-
-  /* This flag instructs linker to enable exempt-list workaround for the namespace.
-   * See http://b/26394120 for details.
-   */
-  ANDROID_NAMESPACE_TYPE_EXEMPT_LIST_ENABLED = 0x08000000,
-
-  ANDROID_NAMESPACE_TYPE_SHARED_ISOLATED = ANDROID_NAMESPACE_TYPE_SHARED |
-                                           ANDROID_NAMESPACE_TYPE_ISOLATED,
-};
-
-/*
- * Creates new linker namespace.
- * ld_library_path and default_library_path represent the search path
- * for the libraries in the namespace.
- *
- * The libraries in the namespace are searched by folowing order:
- * 1. ld_library_path (Think of this as namespace-local LD_LIBRARY_PATH)
- * 2. In directories specified by DT_RUNPATH of the "needed by" binary.
- * 3. deault_library_path (This of this as namespace-local default library path)
- *
- * When type is ANDROID_NAMESPACE_TYPE_ISOLATED the resulting namespace requires all of
- * the libraries to be on the search path or under the permitted_when_isolated_path;
- * the search_path is ld_library_path:default_library_path. Note that the
- * permitted_when_isolated_path path is not part of the search_path and
- * does not affect the search order. It is a way to allow loading libraries from specific
- * locations when using absolute path.
- * If a library or any of its dependencies are outside of the permitted_when_isolated_path
- * and search_path, and it is not part of the public namespace dlopen will fail.
- */
-extern struct android_namespace_t* android_create_namespace(const char* name,
-                                                            const char* ld_library_path,
-                                                            const char* default_library_path,
-                                                            uint64_t type,
-                                                            const char* permitted_when_isolated_path,
-                                                            android_namespace_t* parent);
-
-extern bool android_link_namespaces(android_namespace_t* from,
-                                    android_namespace_t* to,
-                                    const char* shared_libs_sonames);
-
-extern bool android_link_namespaces_all_libs(android_namespace_t* from,
-                                             android_namespace_t* to);
-
-extern void android_set_application_target_sdk_version(int target);
-
-__END_DECLS
-
-#endif /* __ANDROID_DLEXT_NAMESPACES_H__ */
diff --git a/tests/dlext_test.cpp b/tests/dlext_test.cpp
index b5bf7538b..9c56f4723 100644
--- a/tests/dlext_test.cpp
+++ b/tests/dlext_test.cpp
@@ -44,11 +44,12 @@
 #include "bionic/mte.h"
 #include "bionic/page.h"
 #include "core_shared_libs.h"
-#include "dlext_private_tests.h"
 #include "dlfcn_symlink_support.h"
 #include "gtest_globals.h"
 #include "utils.h"
 
+#include "platform/bionic/dlext_namespaces.h"
+
 #define ASSERT_DL_NOTNULL(ptr) \
     ASSERT_TRUE((ptr) != nullptr) << "dlerror: " << dlerror()
 
diff --git a/tests/dlfcn_symlink_support.cpp b/tests/dlfcn_symlink_support.cpp
index a5d3c3eae..f96c23d83 100644
--- a/tests/dlfcn_symlink_support.cpp
+++ b/tests/dlfcn_symlink_support.cpp
@@ -37,13 +37,6 @@ static int dl_callback(struct dl_phdr_info *info, size_t /* size */, void *data)
   // is disregarded intentionally since in bionic dlpi_name should always
   // be realpath to a shared object.
   const std::string suffix = std::string("/") + source_file_name;
-
-  // TODO (dimitry): remove this check once fake libdl.so is gone
-  if (info->dlpi_name == nullptr) {
-    // This is linker imposing as libdl.so - skip it
-    return 0;
-  }
-
   if (android::base::EndsWith(info->dlpi_name, suffix)) {
     std::string* path = reinterpret_cast<std::string*>(data);
     *path = info->dlpi_name;
diff --git a/tests/fcntl_test.cpp b/tests/fcntl_test.cpp
index 57766ef49..4f6fc7f7e 100644
--- a/tests/fcntl_test.cpp
+++ b/tests/fcntl_test.cpp
@@ -26,10 +26,6 @@
 #include <android-base/silent_death_test.h>
 #include <android-base/stringprintf.h>
 
-// Glibc v2.19 doesn't include these in fcntl.h so host builds will fail without.
-#if !defined(FALLOC_FL_PUNCH_HOLE) || !defined(FALLOC_FL_KEEP_SIZE)
-#include <linux/falloc.h>
-#endif
 #if !defined(EXT4_SUPER_MAGIC)
 #include <linux/magic.h>
 #endif
diff --git a/tests/fortify_test.cpp b/tests/fortify_test.cpp
index fd1680b4c..4b2cd25e1 100644
--- a/tests/fortify_test.cpp
+++ b/tests/fortify_test.cpp
@@ -29,12 +29,20 @@
 
 #include <android-base/silent_death_test.h>
 
+#include "DoNotOptimize.h"
+
 #if defined(__BIONIC__)
 #define ASSERT_FORTIFY(expr) ASSERT_EXIT(expr, testing::KilledBySignal(SIGABRT), "FORTIFY")
 #else
 #define ASSERT_FORTIFY(expr) ASSERT_EXIT(expr, testing::KilledBySignal(SIGABRT), "")
 #endif
 
+#if __has_feature(hwaddress_sanitizer)
+#define ASSERT_FORTIFY_OR_HWASAN(expr) ASSERT_EXIT(expr, testing::KilledBySignal(SIGABRT), "HWAddressSanitizer")
+#else
+#define ASSERT_FORTIFY_OR_HWASAN ASSERT_FORTIFY
+#endif
+
 // Fortify test code needs to run multiple times, so TEST_NAME macro is used to
 // distinguish different tests. TEST_NAME is defined in compilation command.
 #define DEATHTEST_PASTER(name) name##_DeathTest
@@ -294,7 +302,22 @@ TEST_F(DEATHTEST, bzero_fortified2) {
   ASSERT_FORTIFY(bzero(myfoo.b, n));
 }
 
-#endif /* defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE=2 */
+#endif /* defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE>=2 */
+
+#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE >= 3
+
+TEST_F(DEATHTEST, dynamic_object_size_malloc) {
+#if __BIONIC__  // glibc doesn't use __builtin_dynamic_object_size
+  // Volatile because we have to fool both the frontend and the optimizer.
+  volatile int i = 32;
+  volatile int j = i + 1;
+  void* mem = malloc(i);
+  ASSERT_FORTIFY(memset(mem, 0, j));
+  free(mem);
+#endif
+}
+
+#endif /* defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE>=3 */
 
 // multibyte target where we over fill (should fail)
 TEST_F(DEATHTEST, strcpy_fortified) {
@@ -415,8 +438,13 @@ TEST_F(DEATHTEST, sprintf_malloc_fortified) {
 }
 
 TEST_F(DEATHTEST, sprintf2_fortified) {
+  // glibc's fortified implementation of sprintf is smart enough to be able to detect this bug at
+  // compile time, but we want to check if it can also be detected at runtime.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wformat-overflow"
   char buf[5];
   ASSERT_FORTIFY(sprintf(buf, "aaaaa"));
+#pragma clang diagnostic pop
 }
 
 static int vsprintf_helper(const char* fmt, ...) {
@@ -480,7 +508,7 @@ TEST_F(DEATHTEST, memmove_fortified) {
   char buf[20];
   strcpy(buf, "0123456789");
   volatile size_t n = 10;
-  ASSERT_FORTIFY(memmove(buf + 11, buf, n));
+  ASSERT_FORTIFY_OR_HWASAN(DoNotOptimize(memmove(buf + 11, buf, n)));
 }
 
 TEST_F(DEATHTEST, memcpy_fortified) {
@@ -488,13 +516,13 @@ TEST_F(DEATHTEST, memcpy_fortified) {
   char bufb[10];
   strcpy(bufa, "012345678");
   volatile size_t n = 11;
-  ASSERT_FORTIFY(memcpy(bufb, bufa, n));
+  ASSERT_FORTIFY_OR_HWASAN(DoNotOptimize(memcpy(bufb, bufa, n)));
 }
 
 TEST_F(DEATHTEST, memset_fortified) {
   char buf[10];
   volatile size_t n = 11;
-  ASSERT_FORTIFY(memset(buf, 0, n));
+  ASSERT_FORTIFY_OR_HWASAN(DoNotOptimize(memset(buf, 0, n)));
 }
 
 TEST_F(DEATHTEST, stpncpy_fortified) {
diff --git a/tests/grp_pwd_test.cpp b/tests/grp_pwd_test.cpp
index 2c2208126..885a01b1f 100644
--- a/tests/grp_pwd_test.cpp
+++ b/tests/grp_pwd_test.cpp
@@ -26,7 +26,10 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <algorithm>
+#include <iterator>
 #include <set>
+#include <string>
 #include <vector>
 
 #include <android-base/file.h>
diff --git a/tests/gtest_globals.cpp b/tests/gtest_globals.cpp
index f146c08bb..64e65151d 100644
--- a/tests/gtest_globals.cpp
+++ b/tests/gtest_globals.cpp
@@ -30,7 +30,7 @@ std::string GetTestLibRoot() {
 
   std::string out_path;
   if (!android::base::Realpath(path.c_str(), &out_path)) {
-    printf("Failed to get realpath for \"%s\"\n", path.c_str());
+    fprintf(stderr, "Failed to get realpath for \"%s\"\n", path.c_str());
     abort();
   }
 
@@ -38,7 +38,7 @@ std::string GetTestLibRoot() {
 
   std::string real_path;
   if (!android::base::Realpath(out_path, &real_path)) {
-    printf("\"%s\": does not exists\n", out_path.c_str());
+    fprintf(stderr, "\"%s\": does not exist\n", out_path.c_str());
     abort();
   }
 
diff --git a/tests/headers/posix/Android.bp b/tests/headers/posix/Android.bp
index 0809cdbae..077c7cbbe 100644
--- a/tests/headers/posix/Android.bp
+++ b/tests/headers/posix/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["bionic_tests_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 cc_library_static {
@@ -27,6 +28,10 @@ cc_library_static {
         "-Werror",
         "-D_POSIX_C_SOURCE=200809L",
         "-D_XOPEN_SOURCE=700",
+
+        // Ensure that __BIONIC__ or __GLIBC__ is always defined.
+        // Any header suffices for bionic, but glibc is pretty ad hoc.
+        "-include features.h",
     ],
     host_supported: true,
     target: {
diff --git a/tests/headers/posix/dlfcn_h.c b/tests/headers/posix/dlfcn_h.c
index 3a32fdd3b..ce0b25bd5 100644
--- a/tests/headers/posix/dlfcn_h.c
+++ b/tests/headers/posix/dlfcn_h.c
@@ -11,13 +11,26 @@ static void dlfcn_h() {
   MACRO(RTLD_GLOBAL);
   MACRO(RTLD_LOCAL);
 
-#if !defined(__GLIBC__)  // Our glibc is too old.
+  // POSIX accidentally standardized `Dl_info_t`,
+  // rather than the `Dl_info` that everyone was using.
+  // See https://www.austingroupbugs.net/view.php?id=1847.
+#if !defined(__GLIBC__)
+  // Our glibc does have the old name,
+  // but only hidden behind _GNU_SOURCE as an extension.
   TYPE(Dl_info);
   STRUCT_MEMBER(Dl_info, const char*, dli_fname);
   STRUCT_MEMBER(Dl_info, void*, dli_fbase);
   STRUCT_MEMBER(Dl_info, const char*, dli_sname);
   STRUCT_MEMBER(Dl_info, void*, dli_saddr);
 #endif
+#if !defined(__GLIBC__)
+  // Our glibc is too old for the new name.
+  TYPE(Dl_info_t);
+  STRUCT_MEMBER(Dl_info_t, const char*, dli_fname);
+  STRUCT_MEMBER(Dl_info_t, void*, dli_fbase);
+  STRUCT_MEMBER(Dl_info_t, const char*, dli_sname);
+  STRUCT_MEMBER(Dl_info_t, void*, dli_saddr);
+#endif
 
 #if !defined(__GLIBC__)  // Our glibc is too old.
   FUNCTION(dladdr, int (*f)(const void*, Dl_info*));
diff --git a/tests/headers/posix/endian_h.c b/tests/headers/posix/endian_h.c
new file mode 100644
index 000000000..2b36d5e5b
--- /dev/null
+++ b/tests/headers/posix/endian_h.c
@@ -0,0 +1,35 @@
+// Copyright (C) 2025 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
+
+#include <endian.h>
+
+#include "header_checks.h"
+
+static void endian_h() {
+#if !defined(__GLIBC__) // glibc still has this POSIX 2024 header as extensions.
+  MACRO(BYTE_ORDER);
+  MACRO(LITTLE_ENDIAN);
+  MACRO(BIG_ENDIAN);
+
+  // TODO: better support for function-like macros.
+  be16toh(1234);
+  be32toh(1234);
+  be64toh(1234);
+
+  htobe16(1234);
+  htobe32(1234);
+  htobe64(1234);
+
+  htole16(1234);
+  htole32(1234);
+  htole64(1234);
+
+  le16toh(1234);
+  le32toh(1234);
+  le64toh(1234);
+
+  TYPE(uint16_t);
+  TYPE(uint32_t);
+  TYPE(uint64_t);
+#endif
+}
diff --git a/tests/headers/posix/fcntl_h.c b/tests/headers/posix/fcntl_h.c
index 5416dd1c5..0352d9753 100644
--- a/tests/headers/posix/fcntl_h.c
+++ b/tests/headers/posix/fcntl_h.c
@@ -18,6 +18,12 @@ static void fcntl_h() {
   MACRO(F_GETOWN);
   MACRO(F_SETOWN);
 
+#if !defined(__GLIBC__) // Our glibc is too old.
+  MACRO(F_OFD_GETLK);
+  MACRO(F_OFD_SETLK);
+  MACRO(F_OFD_SETLKW);
+#endif
+
   MACRO(FD_CLOEXEC);
 
   MACRO(F_RDLCK);
diff --git a/tests/headers/posix/fnmatch_h.c b/tests/headers/posix/fnmatch_h.c
index db263caec..6111035ff 100644
--- a/tests/headers/posix/fnmatch_h.c
+++ b/tests/headers/posix/fnmatch_h.c
@@ -10,6 +10,10 @@ static void fnmatch_h() {
   MACRO(FNM_PATHNAME);
   MACRO(FNM_PERIOD);
   MACRO(FNM_NOESCAPE);
+#if !defined(__GLIBC__) // Our glibc is too old.
+  MACRO(FNM_CASEFOLD);
+  MACRO(FNM_IGNORECASE);
+#endif
 
   FUNCTION(fnmatch, int (*f)(const char*, const char*, int));
 }
diff --git a/tests/headers/posix/limits_h.c b/tests/headers/posix/limits_h.c
index 4a076bb9a..06051363a 100644
--- a/tests/headers/posix/limits_h.c
+++ b/tests/headers/posix/limits_h.c
@@ -194,6 +194,10 @@ static void limits_h() {
   MACRO(USHRT_MAX);
   MACRO(WORD_BIT);
 
+#if defined(__BIONIC__)
+  MACRO(GETENTROPY_MAX);
+#endif
+
   MACRO(NL_ARGMAX);
   MACRO(NL_LANGMAX);
   MACRO(NL_MSGMAX);
diff --git a/tests/headers/posix/math_h.c b/tests/headers/posix/math_h.c
index dfd7604b2..5581f34c5 100644
--- a/tests/headers/posix/math_h.c
+++ b/tests/headers/posix/math_h.c
@@ -47,18 +47,44 @@ static void math_h() {
 #endif
 
   MACRO(M_E);
+  // TODO: MACRO(M_EGAMMA);
   MACRO(M_LOG2E);
   MACRO(M_LOG10E);
   MACRO(M_LN2);
   MACRO(M_LN10);
+  // TODO: MACRO(M_PHI);
   MACRO(M_PI);
   MACRO(M_PI_2);
   MACRO(M_PI_4);
   MACRO(M_1_PI);
+  // TODO: MACRO(M_1_SQRTPI);
   MACRO(M_2_PI);
   MACRO(M_2_SQRTPI);
   MACRO(M_SQRT2);
+  // TODO: MACRO(M_SQRT3);
   MACRO(M_SQRT1_2);
+  // TODO: MACRO(M_SQRT1_3);
+
+#if !defined(__GLIBC__) // glibc hasn't updated to POSIX 2024 yet.
+  MACRO(M_El);
+  // TODO: MACRO(M_EGAMMAl);
+  MACRO(M_LOG2El);
+  MACRO(M_LOG10El);
+  MACRO(M_LN2l);
+  MACRO(M_LN10l);
+  // TODO: MACRO(M_PHIl);
+  MACRO(M_PIl);
+  MACRO(M_PI_2l);
+  MACRO(M_PI_4l);
+  MACRO(M_1_PIl);
+  // TODO: MACRO(M_1_SQRTPIl);
+  MACRO(M_2_PIl);
+  MACRO(M_2_SQRTPIl);
+  MACRO(M_SQRT2l);
+  // TODO: MACRO(M_SQRT3l);
+  MACRO(M_SQRT1_2l);
+  // TODO: MACRO(M_SQRT1_3l);
+#endif
 
   MACRO(MAXFLOAT);
 
diff --git a/tests/headers/posix/spawn_h.c b/tests/headers/posix/spawn_h.c
index 2b436002f..0b55dcb1c 100644
--- a/tests/headers/posix/spawn_h.c
+++ b/tests/headers/posix/spawn_h.c
@@ -24,8 +24,14 @@ static void spawn_h() {
   MACRO(POSIX_SPAWN_SETSIGMASK);
 
   FUNCTION(posix_spawn, int (*f)(pid_t*, const char*, const posix_spawn_file_actions_t*, const posix_spawnattr_t*, char* const[], char* const[]));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(posix_spawn_file_actions_addchdir, int (*f)(posix_spawn_file_actions_t*, const char*));
+#endif
   FUNCTION(posix_spawn_file_actions_addclose, int (*f)(posix_spawn_file_actions_t*, int));
   FUNCTION(posix_spawn_file_actions_adddup2, int (*f)(posix_spawn_file_actions_t*, int, int));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(posix_spawn_file_actions_addfchdir, int (*f)(posix_spawn_file_actions_t*, int));
+#endif
   FUNCTION(posix_spawn_file_actions_addopen, int (*f)(posix_spawn_file_actions_t*, int, const char*, int, mode_t));
   FUNCTION(posix_spawn_file_actions_destroy, int (*f)(posix_spawn_file_actions_t*));
   FUNCTION(posix_spawn_file_actions_init, int (*f)(posix_spawn_file_actions_t*));
diff --git a/tests/headers/posix/stdio_h.c b/tests/headers/posix/stdio_h.c
index 5b1677d6c..e8ad32fc5 100644
--- a/tests/headers/posix/stdio_h.c
+++ b/tests/headers/posix/stdio_h.c
@@ -50,6 +50,9 @@ static void stdio_h() {
   fp = stdin;
   fp = stdout;
 
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(asprintf, int (*f)(char**, const char*, ...));
+#endif
   FUNCTION(clearerr, void (*f)(FILE*));
   FUNCTION(ctermid, char* (*f)(char*));
   FUNCTION(dprintf, int (*f)(int, const char*, ...));
@@ -111,6 +114,9 @@ static void stdio_h() {
   FUNCTION(tmpfile, FILE* (*f)(void));
   FUNCTION(tmpnam, char* (*f)(char*));
   FUNCTION(ungetc, int (*f)(int, FILE*));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(vasprintf, int (*f)(char**, const char*, va_list));
+#endif
   FUNCTION(vdprintf, int (*f)(int, const char*, va_list));
   FUNCTION(vfprintf, int (*f)(FILE*, const char*, va_list));
   FUNCTION(vfscanf, int (*f)(FILE*, const char*, va_list));
diff --git a/tests/headers/posix/stdlib_h.c b/tests/headers/posix/stdlib_h.c
index fc9ffed71..33858ffe2 100644
--- a/tests/headers/posix/stdlib_h.c
+++ b/tests/headers/posix/stdlib_h.c
@@ -48,6 +48,7 @@ static void stdlib_h() {
 #endif
   FUNCTION(abort, void (*f)(void));
   FUNCTION(abs, int (*f)(int));
+  FUNCTION(aligned_alloc, void* (*f)(size_t, size_t));
   FUNCTION(atexit, int (*f)(void (*)(void)));
   FUNCTION(atof, double (*f)(const char*));
   FUNCTION(atoi, int (*f)(const char*));
@@ -79,12 +80,18 @@ static void stdlib_h() {
   FUNCTION(mbstowcs, size_t (*f)(wchar_t*, const char*, size_t));
   FUNCTION(mbtowc, int (*f)(wchar_t*, const char*, size_t));
   FUNCTION(mkdtemp, char* (*f)(char*));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(mkostemp, int (*f)(char*, int));
+#endif
   FUNCTION(mkstemp, int (*f)(char*));
   FUNCTION(mrand48, long (*f)(void));
   FUNCTION(nrand48, long (*f)(unsigned short[3]));
   FUNCTION(posix_memalign, int (*f)(void**, size_t, size_t));
   FUNCTION(posix_openpt, int (*f)(int));
   FUNCTION(ptsname, char* (*f)(int));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(ptsname_r, int (*f)(int, char*, size_t));
+#endif
   FUNCTION(putenv, int (*f)(char*));
   FUNCTION(qsort, void (*f)(void*, size_t, size_t, int (*)(const void*, const void*)));
 #if !defined(__GLIBC__) // Our glibc is too old.
diff --git a/tests/headers/posix/sys_mman_h.c b/tests/headers/posix/sys_mman_h.c
index 881e4e89c..88a39fc3c 100644
--- a/tests/headers/posix/sys_mman_h.c
+++ b/tests/headers/posix/sys_mman_h.c
@@ -14,6 +14,10 @@ static void sys_mman_h() {
   MACRO(MAP_FIXED);
   MACRO(MAP_PRIVATE);
   MACRO(MAP_SHARED);
+#if !defined(__GLIBC__) // Our glibc is too old.
+  MACRO(MAP_ANON);
+  MACRO(MAP_ANONYMOUS);
+#endif
 
   MACRO(MS_ASYNC);
   MACRO(MS_INVALIDATE);
diff --git a/tests/headers/posix/sys_socket_h.c b/tests/headers/posix/sys_socket_h.c
index 7f9c91e56..35a168511 100644
--- a/tests/headers/posix/sys_socket_h.c
+++ b/tests/headers/posix/sys_socket_h.c
@@ -108,6 +108,9 @@ static void sys_socket_h() {
   TYPE(ssize_t);
 
   FUNCTION(accept, int (*f)(int, struct sockaddr*, socklen_t*));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(accept4, int (*f)(int, struct sockaddr*, socklen_t*, int));
+#endif
   FUNCTION(bind, int (*f)(int, const struct sockaddr*, socklen_t));
   FUNCTION(connect, int (*f)(int, const struct sockaddr*, socklen_t));
   FUNCTION(getpeername, int (*f)(int, struct sockaddr*, socklen_t*));
diff --git a/tests/headers/posix/unistd_h.c b/tests/headers/posix/unistd_h.c
index d2262b376..86767c0d7 100644
--- a/tests/headers/posix/unistd_h.c
+++ b/tests/headers/posix/unistd_h.c
@@ -120,6 +120,10 @@ static void unistd_h() {
   MACRO(SEEK_CUR);
   MACRO(SEEK_END);
   MACRO(SEEK_SET);
+#if !defined(__GLIBC__) // Our glibc is too old.
+  MACRO(SEEK_HOLE);
+  MACRO(SEEK_DATA);
+#endif
 
   MACRO(F_LOCK);
   MACRO(F_TEST);
@@ -292,6 +296,9 @@ static void unistd_h() {
 #endif
   FUNCTION(dup, int (*f)(int));
   FUNCTION(dup2, int (*f)(int, int));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(dup3, int (*f)(int, int, int));
+#endif
   FUNCTION(_exit, void (*f)(int));
 #if !defined(__BIONIC__)
   FUNCTION(encrypt, void (*f)(char[64], int));
@@ -334,6 +341,10 @@ static void unistd_h() {
   FUNCTION(getpgrp, pid_t (*f)(void));
   FUNCTION(getpid, pid_t (*f)(void));
   FUNCTION(getppid, pid_t (*f)(void));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(getresgid, int (*f)(gid_t*, gid_t*, gid_t*));
+  FUNCTION(getresuid, int (*f)(uid_t*, uid_t*, uid_t*));
+#endif
   FUNCTION(getsid, pid_t (*f)(pid_t));
   FUNCTION(getuid, uid_t (*f)(void));
   FUNCTION(isatty, int (*f)(int));
@@ -346,6 +357,9 @@ static void unistd_h() {
   FUNCTION(pathconf, long (*f)(const char*, int));
   FUNCTION(pause, int (*f)(void));
   FUNCTION(pipe, int (*f)(int[2]));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(pipe2, int (*f)(int[2], int));
+#endif
   FUNCTION(pread, ssize_t (*f)(int, void*, size_t, off_t));
   FUNCTION(pwrite, ssize_t (*f)(int, const void*, size_t, off_t));
   FUNCTION(read, ssize_t (*f)(int, void*, size_t));
@@ -358,6 +372,10 @@ static void unistd_h() {
   FUNCTION(setpgid, int (*f)(pid_t, pid_t));
   FUNCTION(setpgrp, pid_t (*f)(void));
   FUNCTION(setregid, int (*f)(gid_t, gid_t));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(setresgid, int (*f)(gid_t, gid_t, gid_t));
+  FUNCTION(setresuid, int (*f)(uid_t, uid_t, uid_t));
+#endif
   FUNCTION(setreuid, int (*f)(uid_t, uid_t));
   FUNCTION(setsid, pid_t (*f)(void));
   FUNCTION(setuid, int (*f)(uid_t));
diff --git a/tests/libs/Android.bp b/tests/libs/Android.bp
index 5b86e78bb..537423249 100644
--- a/tests/libs/Android.bp
+++ b/tests/libs/Android.bp
@@ -628,6 +628,7 @@ cc_test {
         "libns_hidden_child_global",
         "libdl_android",
     ],
+    include_dirs: ["bionic/libc"],
     ldflags: ["-Wl,--rpath,${ORIGIN}/.."],
 }
 
diff --git a/tests/libs/bionic_tests_zipalign.cpp b/tests/libs/bionic_tests_zipalign.cpp
index adb731f74..ec7a3d0f9 100644
--- a/tests/libs/bionic_tests_zipalign.cpp
+++ b/tests/libs/bionic_tests_zipalign.cpp
@@ -17,6 +17,7 @@
 #include <errno.h>
 #include <stdio.h>
 #include <stdlib.h>
+#include <sys/param.h>
 
 #include <algorithm>
 #include <memory>
@@ -129,7 +130,7 @@ int main(int argc, char* argv[]) {
     usage();
     return 1;
   }
-  if (((alignment - 1) & alignment) != 0) {
+  if (!powerof2(alignment)) {
     fprintf(stderr, "ALIGNMENT value is not a power of 2: %s\n", argv[1]);
     return 1;
   }
diff --git a/tests/libs/ns_hidden_child_helper.cpp b/tests/libs/ns_hidden_child_helper.cpp
index 77608e210..8f9c8162a 100644
--- a/tests/libs/ns_hidden_child_helper.cpp
+++ b/tests/libs/ns_hidden_child_helper.cpp
@@ -33,7 +33,7 @@
 #include <string>
 
 #include "../core_shared_libs.h"
-#include "../dlext_private_tests.h"
+#include "platform/bionic/dlext_namespaces.h"
 
 extern "C" void global_function();
 extern "C" void internal_function();
diff --git a/tests/limits_test.cpp b/tests/limits_test.cpp
index 64d9a3384..e7bb92745 100644
--- a/tests/limits_test.cpp
+++ b/tests/limits_test.cpp
@@ -23,6 +23,9 @@ TEST(limits, macros) {
   ASSERT_EQ(8 * static_cast<int>(sizeof(int)), WORD_BIT);
   ASSERT_EQ(2048, LINE_MAX);
   ASSERT_EQ(20, NZERO);
+#if defined(__BIONIC__)
+  ASSERT_GE(GETENTROPY_MAX, 256);
+#endif
 #if !defined(MB_LEN_MAX)
 #error MB_LEN_MAX
 #endif
diff --git a/tests/link_test.cpp b/tests/link_test.cpp
index ae3a1cd1b..04026fcaa 100644
--- a/tests/link_test.cpp
+++ b/tests/link_test.cpp
@@ -37,6 +37,8 @@
 #include <string>
 #include <unordered_map>
 
+extern "C" void* __executable_start;
+
 TEST(link, dl_iterate_phdr_early_exit) {
   static size_t call_count = 0;
   ASSERT_EQ(123, dl_iterate_phdr([](dl_phdr_info*, size_t, void*) { ++call_count; return 123; },
@@ -162,6 +164,24 @@ static r_debug* find_exe_r_debug(ElfW(Dyn)* dynamic) {
   return nullptr;
 }
 
+TEST(link, dl_iterate_phdr_order) {
+  struct Object {
+    std::string name;
+    void* addr;
+  };
+  auto callback = [](dl_phdr_info* info, size_t, void* data) {
+    std::vector<Object>& names = *static_cast<std::vector<Object>*>(data);
+    names.push_back(Object{info->dlpi_name ?: "(null)", reinterpret_cast<void*>(info->dlpi_addr)});
+    return 0;
+  };
+  std::vector<Object> objects;
+  ASSERT_EQ(0, dl_iterate_phdr(callback, &objects));
+
+  // The executable should come first.
+  ASSERT_TRUE(!objects.empty());
+  ASSERT_EQ(&__executable_start, objects[0].addr) << objects[0].name;
+}
+
 // Walk the DT_DEBUG/_r_debug global module list and compare it with the same
 // information from dl_iterate_phdr. Verify that the executable appears first
 // in _r_debug.
diff --git a/tests/malloc_iterate_test.cpp b/tests/malloc_iterate_test.cpp
index 297f637c6..c431a161d 100644
--- a/tests/malloc_iterate_test.cpp
+++ b/tests/malloc_iterate_test.cpp
@@ -14,6 +14,13 @@
  * limitations under the License.
  */
 
+// (b/291762537): This code uses malloc_usable_size(), and thus can't be
+// built with _FORTIFY_SOURCE>=3.
+#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE >= 3
+#undef _FORTIFY_SOURCE
+#define _FORTIFY_SOURCE 2
+#endif
+
 #include <gtest/gtest.h>
 
 #if defined(__BIONIC__)
diff --git a/tests/malloc_test.cpp b/tests/malloc_test.cpp
index db814dc51..837c4408b 100644
--- a/tests/malloc_test.cpp
+++ b/tests/malloc_test.cpp
@@ -53,8 +53,8 @@
 #if defined(__BIONIC__)
 
 #include "SignalUtils.h"
-#include "dlext_private_tests.h"
 
+#include "platform/bionic/dlext_namespaces.h"
 #include "platform/bionic/malloc.h"
 #include "platform/bionic/mte.h"
 #include "platform/bionic/reserved_signals.h"
@@ -72,14 +72,6 @@
 
 #endif
 
-TEST(malloc, malloc_std) {
-  // Simple malloc test.
-  void *ptr = malloc(100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  free(ptr);
-}
-
 TEST(malloc, malloc_overflow) {
   SKIP_WITH_HWASAN;
   errno = 0;
@@ -87,18 +79,6 @@ TEST(malloc, malloc_overflow) {
   ASSERT_ERRNO(ENOMEM);
 }
 
-TEST(malloc, calloc_std) {
-  // Simple calloc test.
-  size_t alloc_len = 100;
-  char *ptr = (char *)calloc(1, alloc_len);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(alloc_len, malloc_usable_size(ptr));
-  for (size_t i = 0; i < alloc_len; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-  free(ptr);
-}
-
 TEST(malloc, calloc_mem_init_disabled) {
 #if defined(__BIONIC__)
   // calloc should still zero memory if mem-init is disabled.
@@ -140,21 +120,6 @@ TEST(malloc, calloc_overflow) {
   ASSERT_ERRNO(ENOMEM);
 }
 
-TEST(malloc, memalign_multiple) {
-  SKIP_WITH_HWASAN << "hwasan requires power of 2 alignment";
-  // Memalign test where the alignment is any value.
-  for (size_t i = 0; i <= 12; i++) {
-    for (size_t alignment = 1 << i; alignment < (1U << (i+1)); alignment++) {
-      char *ptr = reinterpret_cast<char*>(memalign(alignment, 100));
-      ASSERT_TRUE(ptr != nullptr) << "Failed at alignment " << alignment;
-      ASSERT_LE(100U, malloc_usable_size(ptr)) << "Failed at alignment " << alignment;
-      ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) % ((1U << i)))
-          << "Failed at alignment " << alignment;
-      free(ptr);
-    }
-  }
-}
-
 TEST(malloc, memalign_overflow) {
   SKIP_WITH_HWASAN;
   ASSERT_EQ(nullptr, memalign(4096, SIZE_MAX));
@@ -170,179 +135,6 @@ TEST(malloc, memalign_non_power2) {
   }
 }
 
-TEST(malloc, memalign_realloc) {
-  // Memalign and then realloc the pointer a couple of times.
-  for (size_t alignment = 1; alignment <= 4096; alignment <<= 1) {
-    char *ptr = (char*)memalign(alignment, 100);
-    ASSERT_TRUE(ptr != nullptr);
-    ASSERT_LE(100U, malloc_usable_size(ptr));
-    ASSERT_EQ(0U, (intptr_t)ptr % alignment);
-    memset(ptr, 0x23, 100);
-
-    ptr = (char*)realloc(ptr, 200);
-    ASSERT_TRUE(ptr != nullptr);
-    ASSERT_LE(200U, malloc_usable_size(ptr));
-    ASSERT_TRUE(ptr != nullptr);
-    for (size_t i = 0; i < 100; i++) {
-      ASSERT_EQ(0x23, ptr[i]);
-    }
-    memset(ptr, 0x45, 200);
-
-    ptr = (char*)realloc(ptr, 300);
-    ASSERT_TRUE(ptr != nullptr);
-    ASSERT_LE(300U, malloc_usable_size(ptr));
-    for (size_t i = 0; i < 200; i++) {
-      ASSERT_EQ(0x45, ptr[i]);
-    }
-    memset(ptr, 0x67, 300);
-
-    ptr = (char*)realloc(ptr, 250);
-    ASSERT_TRUE(ptr != nullptr);
-    ASSERT_LE(250U, malloc_usable_size(ptr));
-    for (size_t i = 0; i < 250; i++) {
-      ASSERT_EQ(0x67, ptr[i]);
-    }
-    free(ptr);
-  }
-}
-
-TEST(malloc, malloc_realloc_larger) {
-  // Realloc to a larger size, malloc is used for the original allocation.
-  char *ptr = (char *)malloc(100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  memset(ptr, 67, 100);
-
-  ptr = (char *)realloc(ptr, 200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(67, ptr[i]);
-  }
-  free(ptr);
-}
-
-TEST(malloc, malloc_realloc_smaller) {
-  // Realloc to a smaller size, malloc is used for the original allocation.
-  char *ptr = (char *)malloc(200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-  memset(ptr, 67, 200);
-
-  ptr = (char *)realloc(ptr, 100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(67, ptr[i]);
-  }
-  free(ptr);
-}
-
-TEST(malloc, malloc_multiple_realloc) {
-  // Multiple reallocs, malloc is used for the original allocation.
-  char *ptr = (char *)malloc(200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-  memset(ptr, 0x23, 200);
-
-  ptr = (char *)realloc(ptr, 100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(0x23, ptr[i]);
-  }
-
-  ptr = (char*)realloc(ptr, 50);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(50U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 50; i++) {
-    ASSERT_EQ(0x23, ptr[i]);
-  }
-
-  ptr = (char*)realloc(ptr, 150);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(150U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 50; i++) {
-    ASSERT_EQ(0x23, ptr[i]);
-  }
-  memset(ptr, 0x23, 150);
-
-  ptr = (char*)realloc(ptr, 425);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(425U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 150; i++) {
-    ASSERT_EQ(0x23, ptr[i]);
-  }
-  free(ptr);
-}
-
-TEST(malloc, calloc_realloc_larger) {
-  // Realloc to a larger size, calloc is used for the original allocation.
-  char *ptr = (char *)calloc(1, 100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-
-  ptr = (char *)realloc(ptr, 200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-  free(ptr);
-}
-
-TEST(malloc, calloc_realloc_smaller) {
-  // Realloc to a smaller size, calloc is used for the original allocation.
-  char *ptr = (char *)calloc(1, 200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-
-  ptr = (char *)realloc(ptr, 100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-  free(ptr);
-}
-
-TEST(malloc, calloc_multiple_realloc) {
-  // Multiple reallocs, calloc is used for the original allocation.
-  char *ptr = (char *)calloc(1, 200);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(200U, malloc_usable_size(ptr));
-
-  ptr = (char *)realloc(ptr, 100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(100U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 100; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-
-  ptr = (char*)realloc(ptr, 50);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(50U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 50; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-
-  ptr = (char*)realloc(ptr, 150);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(150U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 50; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-  memset(ptr, 0, 150);
-
-  ptr = (char*)realloc(ptr, 425);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_LE(425U, malloc_usable_size(ptr));
-  for (size_t i = 0; i < 150; i++) {
-    ASSERT_EQ(0, ptr[i]);
-  }
-  free(ptr);
-}
-
 TEST(malloc, realloc_overflow) {
   SKIP_WITH_HWASAN;
   errno = 0;
@@ -361,19 +153,6 @@ extern "C" void* pvalloc(size_t);
 extern "C" void* valloc(size_t);
 #endif
 
-TEST(malloc, pvalloc_std) {
-#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
-  size_t pagesize = sysconf(_SC_PAGESIZE);
-  void* ptr = pvalloc(100);
-  ASSERT_TRUE(ptr != nullptr);
-  ASSERT_TRUE((reinterpret_cast<uintptr_t>(ptr) & (pagesize-1)) == 0);
-  ASSERT_LE(pagesize, malloc_usable_size(ptr));
-  free(ptr);
-#else
-  GTEST_SKIP() << "pvalloc not supported.";
-#endif
-}
-
 TEST(malloc, pvalloc_overflow) {
 #if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
   ASSERT_EQ(nullptr, pvalloc(SIZE_MAX));
@@ -538,25 +317,6 @@ TEST(malloc, malloc_info_matches_mallinfo) {
 #endif
 }
 
-TEST(malloc, calloc_usable_size) {
-  for (size_t size = 1; size <= 2048; size++) {
-    void* pointer = malloc(size);
-    ASSERT_TRUE(pointer != nullptr);
-    memset(pointer, 0xeb, malloc_usable_size(pointer));
-    free(pointer);
-
-    // We should get a previous pointer that has been set to non-zero.
-    // If calloc does not zero out all of the data, this will fail.
-    uint8_t* zero_mem = reinterpret_cast<uint8_t*>(calloc(1, size));
-    ASSERT_TRUE(pointer != nullptr);
-    size_t usable_size = malloc_usable_size(zero_mem);
-    for (size_t i = 0; i < usable_size; i++) {
-      ASSERT_EQ(0, zero_mem[i]) << "Failed at allocation size " << size << " at byte " << i;
-    }
-    free(zero_mem);
-  }
-}
-
 TEST(malloc, malloc_0) {
   void* p = malloc(0);
   ASSERT_TRUE(p != nullptr);
@@ -808,132 +568,6 @@ TEST(malloc, reallocarray_overflow) {
 #endif
 }
 
-TEST(malloc, reallocarray) {
-#if HAVE_REALLOCARRAY
-  void* p = reallocarray(nullptr, 2, 32);
-  ASSERT_TRUE(p != nullptr);
-  ASSERT_GE(malloc_usable_size(p), 64U);
-#else
-  GTEST_SKIP() << "reallocarray not available";
-#endif
-}
-
-TEST(malloc, mallinfo) {
-#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
-  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo";
-  static size_t sizes[] = {
-    8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000
-  };
-
-  static constexpr size_t kMaxAllocs = 50;
-
-  for (size_t size : sizes) {
-    // If some of these allocations are stuck in a thread cache, then keep
-    // looping until we make an allocation that changes the total size of the
-    // memory allocated.
-    // jemalloc implementations counts the thread cache allocations against
-    // total memory allocated.
-    void* ptrs[kMaxAllocs] = {};
-    bool pass = false;
-    for (size_t i = 0; i < kMaxAllocs; i++) {
-      size_t allocated = mallinfo().uordblks;
-      ptrs[i] = malloc(size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-      size_t new_allocated = mallinfo().uordblks;
-      if (allocated != new_allocated) {
-        size_t usable_size = malloc_usable_size(ptrs[i]);
-        // Only check if the total got bigger by at least allocation size.
-        // Sometimes the mallinfo numbers can go backwards due to compaction
-        // and/or freeing of cached data.
-        if (new_allocated >= allocated + usable_size) {
-          pass = true;
-          break;
-        }
-      }
-    }
-    for (void* ptr : ptrs) {
-      free(ptr);
-    }
-    ASSERT_TRUE(pass)
-        << "For size " << size << " allocated bytes did not increase after "
-        << kMaxAllocs << " allocations.";
-  }
-#else
-  GTEST_SKIP() << "glibc is broken";
-#endif
-}
-
-TEST(malloc, mallinfo2) {
-#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
-  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo2";
-  static size_t sizes[] = {8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000};
-
-  static constexpr size_t kMaxAllocs = 50;
-
-  for (size_t size : sizes) {
-    // If some of these allocations are stuck in a thread cache, then keep
-    // looping until we make an allocation that changes the total size of the
-    // memory allocated.
-    // jemalloc implementations counts the thread cache allocations against
-    // total memory allocated.
-    void* ptrs[kMaxAllocs] = {};
-    bool pass = false;
-    for (size_t i = 0; i < kMaxAllocs; i++) {
-      struct mallinfo info = mallinfo();
-      struct mallinfo2 info2 = mallinfo2();
-      // Verify that mallinfo and mallinfo2 are exactly the same.
-      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
-      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
-      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
-      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
-      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
-      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
-      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
-      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
-      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
-      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);
-
-      size_t allocated = info2.uordblks;
-      ptrs[i] = malloc(size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-
-      info = mallinfo();
-      info2 = mallinfo2();
-      // Verify that mallinfo and mallinfo2 are exactly the same.
-      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
-      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
-      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
-      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
-      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
-      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
-      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
-      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
-      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
-      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);
-
-      size_t new_allocated = info2.uordblks;
-      if (allocated != new_allocated) {
-        size_t usable_size = malloc_usable_size(ptrs[i]);
-        // Only check if the total got bigger by at least allocation size.
-        // Sometimes the mallinfo2 numbers can go backwards due to compaction
-        // and/or freeing of cached data.
-        if (new_allocated >= allocated + usable_size) {
-          pass = true;
-          break;
-        }
-      }
-    }
-    for (void* ptr : ptrs) {
-      free(ptr);
-    }
-    ASSERT_TRUE(pass) << "For size " << size << " allocated bytes did not increase after "
-                      << kMaxAllocs << " allocations.";
-  }
-#else
-  GTEST_SKIP() << "glibc is broken";
-#endif
-}
-
 template <typename Type>
 void __attribute__((optnone)) VerifyAlignment(Type* floating) {
   size_t expected_alignment = alignof(Type);
@@ -1065,69 +699,6 @@ TEST(malloc, align_check) {
   AlignCheck();
 }
 
-// Jemalloc doesn't pass this test right now, so leave it as disabled.
-TEST(malloc, DISABLED_alloc_after_fork) {
-  // Both of these need to be a power of 2.
-  static constexpr size_t kMinAllocationSize = 8;
-  static constexpr size_t kMaxAllocationSize = 2097152;
-
-  static constexpr size_t kNumAllocatingThreads = 5;
-  static constexpr size_t kNumForkLoops = 100;
-
-  std::atomic_bool stop;
-
-  // Create threads that simply allocate and free different sizes.
-  std::vector<std::thread*> threads;
-  for (size_t i = 0; i < kNumAllocatingThreads; i++) {
-    std::thread* t = new std::thread([&stop] {
-      while (!stop) {
-        for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
-          void* ptr;
-          DoNotOptimize(ptr = malloc(size));
-          free(ptr);
-        }
-      }
-    });
-    threads.push_back(t);
-  }
-
-  // Create a thread to fork and allocate.
-  for (size_t i = 0; i < kNumForkLoops; i++) {
-    pid_t pid;
-    if ((pid = fork()) == 0) {
-      for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
-        void* ptr;
-        DoNotOptimize(ptr = malloc(size));
-        ASSERT_TRUE(ptr != nullptr);
-        // Make sure we can touch all of the allocation.
-        memset(ptr, 0x1, size);
-        ASSERT_LE(size, malloc_usable_size(ptr));
-        free(ptr);
-      }
-      _exit(10);
-    }
-    ASSERT_NE(-1, pid);
-    AssertChildExited(pid, 10);
-  }
-
-  stop = true;
-  for (auto thread : threads) {
-    thread->join();
-    delete thread;
-  }
-}
-
-TEST(android_mallopt, error_on_unexpected_option) {
-#if defined(__BIONIC__)
-  const int unrecognized_option = -1;
-  errno = 0;
-  EXPECT_EQ(false, android_mallopt(unrecognized_option, nullptr, 0));
-  EXPECT_ERRNO(ENOTSUP);
-#else
-  GTEST_SKIP() << "bionic-only test";
-#endif
-}
-
 bool IsDynamic() {
 #if defined(__LP64__)
   Elf64_Ehdr ehdr;
@@ -1582,167 +1153,6 @@ TEST(malloc, realloc_mte_crash_b206701345) {
   }
 }
 
-void VerifyAllocationsAreZero(std::function<void*(size_t)> alloc_func, std::string function_name,
-                              std::vector<size_t>& test_sizes, size_t max_allocations) {
-  // Vector of zero'd data used for comparisons. Make it twice the largest size.
-  std::vector<char> zero(test_sizes.back() * 2, 0);
-
-  SCOPED_TRACE(testing::Message() << function_name << " failed to zero memory");
-
-  for (size_t test_size : test_sizes) {
-    std::vector<void*> ptrs(max_allocations);
-    for (size_t i = 0; i < ptrs.size(); i++) {
-      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
-      ptrs[i] = alloc_func(test_size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-      size_t alloc_size = malloc_usable_size(ptrs[i]);
-      ASSERT_LE(alloc_size, zero.size());
-      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));
-
-      // Set the memory to non-zero to make sure if the pointer
-      // is reused it's still zero.
-      memset(ptrs[i], 0xab, alloc_size);
-    }
-    // Free the pointers.
-    for (size_t i = 0; i < ptrs.size(); i++) {
-      free(ptrs[i]);
-    }
-    for (size_t i = 0; i < ptrs.size(); i++) {
-      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
-      ptrs[i] = malloc(test_size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-      size_t alloc_size = malloc_usable_size(ptrs[i]);
-      ASSERT_LE(alloc_size, zero.size());
-      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));
-    }
-    // Free all of the pointers later to maximize the chance of reusing from
-    // the first loop.
-    for (size_t i = 0; i < ptrs.size(); i++) {
-      free(ptrs[i]);
-    }
-  }
-}
-
-// Verify that small and medium allocations are always zero.
-// @CddTest = 9.7/C-4-1
-TEST(malloc, zeroed_allocations_small_medium_sizes) {
-#if !defined(__BIONIC__)
-  GTEST_SKIP() << "Only valid on bionic";
-#endif
-  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
-
-  if (IsLowRamDevice()) {
-    GTEST_SKIP() << "Skipped on low memory devices.";
-  }
-
-  constexpr size_t kMaxAllocations = 1024;
-  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
-  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
-                           kMaxAllocations);
-
-  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
-                           test_sizes, kMaxAllocations);
-
-  VerifyAllocationsAreZero(
-      [](size_t size) -> void* {
-        void* ptr;
-        if (posix_memalign(&ptr, 64, size) == 0) {
-          return ptr;
-        }
-        return nullptr;
-      },
-      "posix_memalign", test_sizes, kMaxAllocations);
-}
-
-// Verify that large allocations are always zero.
-// @CddTest = 9.7/C-4-1
-TEST(malloc, zeroed_allocations_large_sizes) {
-#if !defined(__BIONIC__)
-  GTEST_SKIP() << "Only valid on bionic";
-#endif
-  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
-
-  if (IsLowRamDevice()) {
-    GTEST_SKIP() << "Skipped on low memory devices.";
-  }
-
-  constexpr size_t kMaxAllocations = 20;
-  std::vector<size_t> test_sizes = {1000000, 2000000, 3000000, 4000000};
-  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
-                           kMaxAllocations);
-
-  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
-                           test_sizes, kMaxAllocations);
-
-  VerifyAllocationsAreZero(
-      [](size_t size) -> void* {
-        void* ptr;
-        if (posix_memalign(&ptr, 64, size) == 0) {
-          return ptr;
-        }
-        return nullptr;
-      },
-      "posix_memalign", test_sizes, kMaxAllocations);
-}
-
-// Verify that reallocs are zeroed when expanded.
-// @CddTest = 9.7/C-4-1
-TEST(malloc, zeroed_allocations_realloc) {
-#if !defined(__BIONIC__)
-  GTEST_SKIP() << "Only valid on bionic";
-#endif
-  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
-
-  if (IsLowRamDevice()) {
-    GTEST_SKIP() << "Skipped on low memory devices.";
-  }
-
-  // Vector of zero'd data used for comparisons.
-  constexpr size_t kMaxMemorySize = 131072;
-  std::vector<char> zero(kMaxMemorySize, 0);
-
-  constexpr size_t kMaxAllocations = 1024;
-  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
-  // Do a number of allocations and set them to non-zero.
-  for (size_t test_size : test_sizes) {
-    std::vector<void*> ptrs(kMaxAllocations);
-    for (size_t i = 0; i < kMaxAllocations; i++) {
-      ptrs[i] = malloc(test_size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-
-      // Set the memory to non-zero to make sure if the pointer
-      // is reused it's still zero.
-      memset(ptrs[i], 0xab, malloc_usable_size(ptrs[i]));
-    }
-    // Free the pointers.
-    for (size_t i = 0; i < kMaxAllocations; i++) {
-      free(ptrs[i]);
-    }
-  }
-
-  // Do the reallocs to a larger size and verify the rest of the allocation
-  // is zero.
-  constexpr size_t kInitialSize = 8;
-  for (size_t test_size : test_sizes) {
-    std::vector<void*> ptrs(kMaxAllocations);
-    for (size_t i = 0; i < kMaxAllocations; i++) {
-      ptrs[i] = malloc(kInitialSize);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-      size_t orig_alloc_size = malloc_usable_size(ptrs[i]);
-
-      ptrs[i] = realloc(ptrs[i], test_size);
-      ASSERT_TRUE(ptrs[i] != nullptr);
-      size_t new_alloc_size = malloc_usable_size(ptrs[i]);
-      char* ptr = reinterpret_cast<char*>(ptrs[i]);
-      ASSERT_EQ(0, memcmp(&ptr[orig_alloc_size], zero.data(), new_alloc_size - orig_alloc_size))
-          << "realloc from " << kInitialSize << " to size " << test_size << " at iteration " << i;
-    }
-    for (size_t i = 0; i < kMaxAllocations; i++) {
-      free(ptrs[i]);
-    }
-  }
-}
-
 TEST(android_mallopt, get_decay_time_enabled_errors) {
 #if defined(__BIONIC__)
   errno = 0;
diff --git a/tests/malloc_test_with_usable_size.cpp b/tests/malloc_test_with_usable_size.cpp
new file mode 100644
index 000000000..3b9890ebd
--- /dev/null
+++ b/tests/malloc_test_with_usable_size.cpp
@@ -0,0 +1,672 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+// (b/291762537): This code uses malloc_usable_size(), and thus can't be
+// built with _FORTIFY_SOURCE>=3.
+#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE >= 3
+#undef _FORTIFY_SOURCE
+#define _FORTIFY_SOURCE 2
+#endif
+
+#include <gtest/gtest.h>
+
+#include <elf.h>
+#include <limits.h>
+#include <malloc.h>
+#include <pthread.h>
+#include <semaphore.h>
+#include <signal.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/auxv.h>
+#include <sys/cdefs.h>
+#include <sys/prctl.h>
+#include <sys/types.h>
+#include <sys/wait.h>
+#include <unistd.h>
+
+#include <algorithm>
+#include <atomic>
+#include <functional>
+#include <string>
+#include <thread>
+#include <unordered_map>
+#include <utility>
+#include <vector>
+
+#include <tinyxml2.h>
+
+#include <android-base/file.h>
+#include <android-base/test_utils.h>
+
+#include "DoNotOptimize.h"
+#include "utils.h"
+
+#if defined(__BIONIC__)
+
+#include "SignalUtils.h"
+
+#include "platform/bionic/dlext_namespaces.h"
+#include "platform/bionic/malloc.h"
+#include "platform/bionic/mte.h"
+#include "platform/bionic/reserved_signals.h"
+#include "private/bionic_config.h"
+
+#define HAVE_REALLOCARRAY 1
+
+#elif defined(__GLIBC__)
+
+#define HAVE_REALLOCARRAY __GLIBC_PREREQ(2, 26)
+
+#elif defined(ANDROID_HOST_MUSL)
+
+#define HAVE_REALLOCARRAY 1
+
+#endif
+
+TEST(malloc, malloc_std) {
+  // Simple malloc test.
+  void* ptr = malloc(100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  free(ptr);
+}
+
+TEST(malloc, calloc_std) {
+  // Simple calloc test.
+  size_t alloc_len = 100;
+  char* ptr = (char*)calloc(1, alloc_len);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(alloc_len, malloc_usable_size(ptr));
+  for (size_t i = 0; i < alloc_len; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, memalign_multiple) {
+  SKIP_WITH_HWASAN << "hwasan requires power of 2 alignment";
+  // Memalign test where the alignment is any value.
+  for (size_t i = 0; i <= 12; i++) {
+    for (size_t alignment = 1 << i; alignment < (1U << (i + 1)); alignment++) {
+      char* ptr = reinterpret_cast<char*>(memalign(alignment, 100));
+      ASSERT_TRUE(ptr != nullptr) << "Failed at alignment " << alignment;
+      ASSERT_LE(100U, malloc_usable_size(ptr)) << "Failed at alignment " << alignment;
+      ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) % ((1U << i)))
+          << "Failed at alignment " << alignment;
+      free(ptr);
+    }
+  }
+}
+
+TEST(malloc, memalign_realloc) {
+  // Memalign and then realloc the pointer a couple of times.
+  for (size_t alignment = 1; alignment <= 4096; alignment <<= 1) {
+    char* ptr = (char*)memalign(alignment, 100);
+    ASSERT_TRUE(ptr != nullptr);
+    ASSERT_LE(100U, malloc_usable_size(ptr));
+    ASSERT_EQ(0U, (intptr_t)ptr % alignment);
+    memset(ptr, 0x23, 100);
+
+    ptr = (char*)realloc(ptr, 200);
+    ASSERT_TRUE(ptr != nullptr);
+    ASSERT_LE(200U, malloc_usable_size(ptr));
+    ASSERT_TRUE(ptr != nullptr);
+    for (size_t i = 0; i < 100; i++) {
+      ASSERT_EQ(0x23, ptr[i]);
+    }
+    memset(ptr, 0x45, 200);
+
+    ptr = (char*)realloc(ptr, 300);
+    ASSERT_TRUE(ptr != nullptr);
+    ASSERT_LE(300U, malloc_usable_size(ptr));
+    for (size_t i = 0; i < 200; i++) {
+      ASSERT_EQ(0x45, ptr[i]);
+    }
+    memset(ptr, 0x67, 300);
+
+    ptr = (char*)realloc(ptr, 250);
+    ASSERT_TRUE(ptr != nullptr);
+    ASSERT_LE(250U, malloc_usable_size(ptr));
+    for (size_t i = 0; i < 250; i++) {
+      ASSERT_EQ(0x67, ptr[i]);
+    }
+    free(ptr);
+  }
+}
+
+TEST(malloc, malloc_realloc_larger) {
+  // Realloc to a larger size, malloc is used for the original allocation.
+  char* ptr = (char*)malloc(100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  memset(ptr, 67, 100);
+
+  ptr = (char*)realloc(ptr, 200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(67, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, malloc_realloc_smaller) {
+  // Realloc to a smaller size, malloc is used for the original allocation.
+  char* ptr = (char*)malloc(200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+  memset(ptr, 67, 200);
+
+  ptr = (char*)realloc(ptr, 100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(67, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, malloc_multiple_realloc) {
+  // Multiple reallocs, malloc is used for the original allocation.
+  char* ptr = (char*)malloc(200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+  memset(ptr, 0x23, 200);
+
+  ptr = (char*)realloc(ptr, 100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(0x23, ptr[i]);
+  }
+
+  ptr = (char*)realloc(ptr, 50);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(50U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 50; i++) {
+    ASSERT_EQ(0x23, ptr[i]);
+  }
+
+  ptr = (char*)realloc(ptr, 150);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(150U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 50; i++) {
+    ASSERT_EQ(0x23, ptr[i]);
+  }
+  memset(ptr, 0x23, 150);
+
+  ptr = (char*)realloc(ptr, 425);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(425U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 150; i++) {
+    ASSERT_EQ(0x23, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, calloc_realloc_larger) {
+  // Realloc to a larger size, calloc is used for the original allocation.
+  char* ptr = (char*)calloc(1, 100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+
+  ptr = (char*)realloc(ptr, 200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, calloc_realloc_smaller) {
+  // Realloc to a smaller size, calloc is used for the original allocation.
+  char* ptr = (char*)calloc(1, 200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+
+  ptr = (char*)realloc(ptr, 100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+  free(ptr);
+}
+
+TEST(malloc, calloc_multiple_realloc) {
+  // Multiple reallocs, calloc is used for the original allocation.
+  char* ptr = (char*)calloc(1, 200);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(200U, malloc_usable_size(ptr));
+
+  ptr = (char*)realloc(ptr, 100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(100U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 100; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+
+  ptr = (char*)realloc(ptr, 50);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(50U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 50; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+
+  ptr = (char*)realloc(ptr, 150);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(150U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 50; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+  memset(ptr, 0, 150);
+
+  ptr = (char*)realloc(ptr, 425);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_LE(425U, malloc_usable_size(ptr));
+  for (size_t i = 0; i < 150; i++) {
+    ASSERT_EQ(0, ptr[i]);
+  }
+  free(ptr);
+}
+
+#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
+extern "C" void* pvalloc(size_t);
+#endif
+
+TEST(malloc, pvalloc_std) {
+#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
+  size_t pagesize = sysconf(_SC_PAGESIZE);
+  void* ptr = pvalloc(100);
+  ASSERT_TRUE(ptr != nullptr);
+  ASSERT_TRUE((reinterpret_cast<uintptr_t>(ptr) & (pagesize - 1)) == 0);
+  ASSERT_LE(pagesize, malloc_usable_size(ptr));
+  free(ptr);
+#else
+  GTEST_SKIP() << "pvalloc not supported.";
+#endif
+}
+
+TEST(malloc, calloc_usable_size) {
+  for (size_t size = 1; size <= 2048; size++) {
+    void* pointer = malloc(size);
+    ASSERT_TRUE(pointer != nullptr);
+    memset(pointer, 0xeb, malloc_usable_size(pointer));
+    free(pointer);
+
+    // We should get a previous pointer that has been set to non-zero.
+    // If calloc does not zero out all of the data, this will fail.
+    uint8_t* zero_mem = reinterpret_cast<uint8_t*>(calloc(1, size));
+    ASSERT_TRUE(pointer != nullptr);
+    size_t usable_size = malloc_usable_size(zero_mem);
+    for (size_t i = 0; i < usable_size; i++) {
+      ASSERT_EQ(0, zero_mem[i]) << "Failed at allocation size " << size << " at byte " << i;
+    }
+    free(zero_mem);
+  }
+}
+
+TEST(malloc, reallocarray) {
+#if HAVE_REALLOCARRAY
+  void* p = reallocarray(nullptr, 2, 32);
+  ASSERT_TRUE(p != nullptr);
+  ASSERT_GE(malloc_usable_size(p), 64U);
+#else
+  GTEST_SKIP() << "reallocarray not available";
+#endif
+}
+
+TEST(malloc, mallinfo) {
+#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
+  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo";
+  static size_t sizes[] = {8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000};
+
+  static constexpr size_t kMaxAllocs = 50;
+
+  for (size_t size : sizes) {
+    // If some of these allocations are stuck in a thread cache, then keep
+    // looping until we make an allocation that changes the total size of the
+    // memory allocated.
+    // jemalloc implementations counts the thread cache allocations against
+    // total memory allocated.
+    void* ptrs[kMaxAllocs] = {};
+    bool pass = false;
+    for (size_t i = 0; i < kMaxAllocs; i++) {
+      size_t allocated = mallinfo().uordblks;
+      ptrs[i] = malloc(size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+      size_t new_allocated = mallinfo().uordblks;
+      if (allocated != new_allocated) {
+        size_t usable_size = malloc_usable_size(ptrs[i]);
+        // Only check if the total got bigger by at least allocation size.
+        // Sometimes the mallinfo numbers can go backwards due to compaction
+        // and/or freeing of cached data.
+        if (new_allocated >= allocated + usable_size) {
+          pass = true;
+          break;
+        }
+      }
+    }
+    for (void* ptr : ptrs) {
+      free(ptr);
+    }
+    ASSERT_TRUE(pass) << "For size " << size << " allocated bytes did not increase after "
+                      << kMaxAllocs << " allocations.";
+  }
+#else
+  GTEST_SKIP() << "glibc is broken";
+#endif
+}
+
+TEST(malloc, mallinfo2) {
+#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
+  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo2";
+  static size_t sizes[] = {8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000};
+
+  static constexpr size_t kMaxAllocs = 50;
+
+  for (size_t size : sizes) {
+    // If some of these allocations are stuck in a thread cache, then keep
+    // looping until we make an allocation that changes the total size of the
+    // memory allocated.
+    // jemalloc implementations counts the thread cache allocations against
+    // total memory allocated.
+    void* ptrs[kMaxAllocs] = {};
+    bool pass = false;
+    for (size_t i = 0; i < kMaxAllocs; i++) {
+      struct mallinfo info = mallinfo();
+      struct mallinfo2 info2 = mallinfo2();
+      // Verify that mallinfo and mallinfo2 are exactly the same.
+      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
+      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
+      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
+      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
+      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
+      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
+      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
+      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
+      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
+      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);
+
+      size_t allocated = info2.uordblks;
+      ptrs[i] = malloc(size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+
+      info = mallinfo();
+      info2 = mallinfo2();
+      // Verify that mallinfo and mallinfo2 are exactly the same.
+      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
+      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
+      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
+      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
+      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
+      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
+      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
+      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
+      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
+      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);
+
+      size_t new_allocated = info2.uordblks;
+      if (allocated != new_allocated) {
+        size_t usable_size = malloc_usable_size(ptrs[i]);
+        // Only check if the total got bigger by at least allocation size.
+        // Sometimes the mallinfo2 numbers can go backwards due to compaction
+        // and/or freeing of cached data.
+        if (new_allocated >= allocated + usable_size) {
+          pass = true;
+          break;
+        }
+      }
+    }
+    for (void* ptr : ptrs) {
+      free(ptr);
+    }
+    ASSERT_TRUE(pass) << "For size " << size << " allocated bytes did not increase after "
+                      << kMaxAllocs << " allocations.";
+  }
+#else
+  GTEST_SKIP() << "glibc is broken";
+#endif
+}
+
+// Jemalloc doesn't pass this test right now, so leave it as disabled.
+TEST(malloc, DISABLED_alloc_after_fork) {
+  // Both of these need to be a power of 2.
+  static constexpr size_t kMinAllocationSize = 8;
+  static constexpr size_t kMaxAllocationSize = 2097152;
+
+  static constexpr size_t kNumAllocatingThreads = 5;
+  static constexpr size_t kNumForkLoops = 100;
+
+  std::atomic_bool stop;
+
+  // Create threads that simply allocate and free different sizes.
+  std::vector<std::thread*> threads;
+  for (size_t i = 0; i < kNumAllocatingThreads; i++) {
+    std::thread* t = new std::thread([&stop] {
+      while (!stop) {
+        for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
+          void* ptr;
+          DoNotOptimize(ptr = malloc(size));
+          free(ptr);
+        }
+      }
+    });
+    threads.push_back(t);
+  }
+
+  // Create a thread to fork and allocate.
+  for (size_t i = 0; i < kNumForkLoops; i++) {
+    pid_t pid;
+    if ((pid = fork()) == 0) {
+      for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
+        void* ptr;
+        DoNotOptimize(ptr = malloc(size));
+        ASSERT_TRUE(ptr != nullptr);
+        // Make sure we can touch all of the allocation.
+        memset(ptr, 0x1, size);
+        ASSERT_LE(size, malloc_usable_size(ptr));
+        free(ptr);
+      }
+      _exit(10);
+    }
+    ASSERT_NE(-1, pid);
+    AssertChildExited(pid, 10);
+  }
+
+  stop = true;
+  for (auto thread : threads) {
+    thread->join();
+    delete thread;
+  }
+}
+
+void VerifyAllocationsAreZero(std::function<void*(size_t)> alloc_func, std::string function_name,
+                              std::vector<size_t>& test_sizes, size_t max_allocations) {
+  // Vector of zero'd data used for comparisons. Make it twice the largest size.
+  std::vector<char> zero(test_sizes.back() * 2, 0);
+
+  SCOPED_TRACE(testing::Message() << function_name << " failed to zero memory");
+
+  for (size_t test_size : test_sizes) {
+    std::vector<void*> ptrs(max_allocations);
+    for (size_t i = 0; i < ptrs.size(); i++) {
+      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
+      ptrs[i] = alloc_func(test_size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+      size_t alloc_size = malloc_usable_size(ptrs[i]);
+      ASSERT_LE(alloc_size, zero.size());
+      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));
+
+      // Set the memory to non-zero to make sure if the pointer
+      // is reused it's still zero.
+      memset(ptrs[i], 0xab, alloc_size);
+    }
+    // Free the pointers.
+    for (size_t i = 0; i < ptrs.size(); i++) {
+      free(ptrs[i]);
+    }
+    for (size_t i = 0; i < ptrs.size(); i++) {
+      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
+      ptrs[i] = malloc(test_size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+      size_t alloc_size = malloc_usable_size(ptrs[i]);
+      ASSERT_LE(alloc_size, zero.size());
+      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));
+    }
+    // Free all of the pointers later to maximize the chance of reusing from
+    // the first loop.
+    for (size_t i = 0; i < ptrs.size(); i++) {
+      free(ptrs[i]);
+    }
+  }
+}
+
+// Verify that small and medium allocations are always zero.
+// @CddTest = 9.7/C-4-1
+TEST(malloc, zeroed_allocations_small_medium_sizes) {
+#if !defined(__BIONIC__)
+  GTEST_SKIP() << "Only valid on bionic";
+#endif
+  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
+
+  if (IsLowRamDevice()) {
+    GTEST_SKIP() << "Skipped on low memory devices.";
+  }
+
+  constexpr size_t kMaxAllocations = 1024;
+  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
+  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
+                           kMaxAllocations);
+
+  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
+                           test_sizes, kMaxAllocations);
+
+  VerifyAllocationsAreZero(
+      [](size_t size) -> void* {
+        void* ptr;
+        if (posix_memalign(&ptr, 64, size) == 0) {
+          return ptr;
+        }
+        return nullptr;
+      },
+      "posix_memalign", test_sizes, kMaxAllocations);
+}
+
+// Verify that large allocations are always zero.
+// @CddTest = 9.7/C-4-1
+TEST(malloc, zeroed_allocations_large_sizes) {
+#if !defined(__BIONIC__)
+  GTEST_SKIP() << "Only valid on bionic";
+#endif
+  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
+
+  if (IsLowRamDevice()) {
+    GTEST_SKIP() << "Skipped on low memory devices.";
+  }
+
+  constexpr size_t kMaxAllocations = 20;
+  std::vector<size_t> test_sizes = {1000000, 2000000, 3000000, 4000000};
+  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
+                           kMaxAllocations);
+
+  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
+                           test_sizes, kMaxAllocations);
+
+  VerifyAllocationsAreZero(
+      [](size_t size) -> void* {
+        void* ptr;
+        if (posix_memalign(&ptr, 64, size) == 0) {
+          return ptr;
+        }
+        return nullptr;
+      },
+      "posix_memalign", test_sizes, kMaxAllocations);
+}
+
+// Verify that reallocs are zeroed when expanded.
+// @CddTest = 9.7/C-4-1
+TEST(malloc, zeroed_allocations_realloc) {
+#if !defined(__BIONIC__)
+  GTEST_SKIP() << "Only valid on bionic";
+#endif
+  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";
+
+  if (IsLowRamDevice()) {
+    GTEST_SKIP() << "Skipped on low memory devices.";
+  }
+
+  // Vector of zero'd data used for comparisons.
+  constexpr size_t kMaxMemorySize = 131072;
+  std::vector<char> zero(kMaxMemorySize, 0);
+
+  constexpr size_t kMaxAllocations = 1024;
+  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
+  // Do a number of allocations and set them to non-zero.
+  for (size_t test_size : test_sizes) {
+    std::vector<void*> ptrs(kMaxAllocations);
+    for (size_t i = 0; i < kMaxAllocations; i++) {
+      ptrs[i] = malloc(test_size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+
+      // Set the memory to non-zero to make sure if the pointer
+      // is reused it's still zero.
+      memset(ptrs[i], 0xab, malloc_usable_size(ptrs[i]));
+    }
+    // Free the pointers.
+    for (size_t i = 0; i < kMaxAllocations; i++) {
+      free(ptrs[i]);
+    }
+  }
+
+  // Do the reallocs to a larger size and verify the rest of the allocation
+  // is zero.
+  constexpr size_t kInitialSize = 8;
+  for (size_t test_size : test_sizes) {
+    std::vector<void*> ptrs(kMaxAllocations);
+    for (size_t i = 0; i < kMaxAllocations; i++) {
+      ptrs[i] = malloc(kInitialSize);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+      size_t orig_alloc_size = malloc_usable_size(ptrs[i]);
+
+      ptrs[i] = realloc(ptrs[i], test_size);
+      ASSERT_TRUE(ptrs[i] != nullptr);
+      size_t new_alloc_size = malloc_usable_size(ptrs[i]);
+      char* ptr = reinterpret_cast<char*>(ptrs[i]);
+      ASSERT_EQ(0, memcmp(&ptr[orig_alloc_size], zero.data(), new_alloc_size - orig_alloc_size))
+          << "realloc from " << kInitialSize << " to size " << test_size << " at iteration " << i;
+    }
+    for (size_t i = 0; i < kMaxAllocations; i++) {
+      free(ptrs[i]);
+    }
+  }
+}
diff --git a/tests/pthread_test.cpp b/tests/pthread_test.cpp
index 680ef6e4c..ced67f3e4 100644
--- a/tests/pthread_test.cpp
+++ b/tests/pthread_test.cpp
@@ -47,6 +47,7 @@
 #include "private/bionic_constants.h"
 #include "private/bionic_time_conversions.h"
 #include "SignalUtils.h"
+#include "sme_utils.h"
 #include "utils.h"
 
 using pthread_DeathTest = SilentDeathTest;
@@ -3206,3 +3207,49 @@ TEST(pthread, pthread_setaffinity) {
   // but it ought to be safe to ask for the same affinity you already have.
   ASSERT_EQ(0, pthread_setaffinity_np(pthread_self(), sizeof(set), &set));
 }
+
+#if defined(__aarch64__)
+
+static void* sme_state_checking_thread(void*) {
+  // Expected state in the child thread:
+  //  - PSTATE.SM is 0
+  //  - PSTATE.ZA is 0
+  //  - TPIDR2_EL0 is 0
+  EXPECT_FALSE(sme_is_sm_on());
+  EXPECT_FALSE(sme_is_za_on());
+  EXPECT_EQ(0UL, sme_tpidr2_el0());
+
+  return nullptr;
+}
+
+static void create_thread() {
+  pthread_t thread;
+  // Even if these asserts fail sme_state_cleanup() will still be run.
+  ASSERT_EQ(0, pthread_create(&thread, nullptr, &sme_state_checking_thread, nullptr));
+  ASSERT_EQ(0, pthread_join(thread, nullptr));
+}
+
+// It is expected that the new thread is started with SME off.
+TEST(pthread, pthread_create_with_sme_off) {
+  if (!sme_is_enabled()) {
+    GTEST_SKIP() << "FEAT_SME is not enabled on the device.";
+  }
+
+  // It is safe to call __arm_za_disable(). This is required to avoid inter-test dependencies.
+  __arm_za_disable();
+  create_thread();
+  sme_state_cleanup();
+}
+
+// It is expected that the new thread is started with SME off.
+TEST(pthread, pthread_create_with_sme_dormant_state) {
+  if (!sme_is_enabled()) {
+    GTEST_SKIP() << "FEAT_SME is not enabled on the device.";
+  }
+
+  __arm_za_disable();
+  sme_dormant_caller(&create_thread);
+  sme_state_cleanup();
+}
+
+#endif  // defined(__aarch64__)
diff --git a/tests/setjmp_test.cpp b/tests/setjmp_test.cpp
index 836aadc4c..454390ebd 100644
--- a/tests/setjmp_test.cpp
+++ b/tests/setjmp_test.cpp
@@ -26,6 +26,7 @@
 #include <android-base/test_utils.h>
 
 #include "SignalUtils.h"
+#include "sme_utils.h"
 
 using setjmp_DeathTest = SilentDeathTest;
 
@@ -368,39 +369,35 @@ TEST(setjmp, bug_152210274) {
 
 #if defined(__aarch64__)
 TEST(setjmp, sigsetjmp_sme) {
-  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+  if (!sme_is_enabled()) {
     GTEST_SKIP() << "SME is not enabled on device.";
   }
 
-  uint64_t svcr, za_state;
   sigjmp_buf jb;
-  __asm__ __volatile__(".arch_extension sme; smstart za");
+  sme_enable_za();
   sigsetjmp(jb, 0);
-  __asm__ __volatile__(".arch_extension sme; mrs %0, SVCR" : "=r"(svcr));
-  __asm__ __volatile__(".arch_extension sme; smstop za");  // Turn ZA off anyway.
-  za_state = svcr & 0x2UL;
-  ASSERT_EQ(0UL, za_state);
+  bool za_state = sme_is_za_on();
+  sme_disable_za();  // Turn ZA off anyway.
+  ASSERT_FALSE(za_state);
 }
 
 TEST(setjmp, siglongjmp_sme) {
-  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+  if (!sme_is_enabled()) {
     GTEST_SKIP() << "SME is not enabled on device.";
   }
 
-  uint64_t svcr, za_state;
   int value;
   sigjmp_buf jb;
   if ((value = sigsetjmp(jb, 0)) == 0) {
-    __asm__ __volatile__(".arch_extension sme; smstart za");
+    sme_enable_za();
     siglongjmp(jb, 789);
-    __asm__ __volatile__(".arch_extension sme; smstop za");
+    sme_disable_za();
     FAIL();  // Unreachable.
   } else {
-    __asm__ __volatile__(".arch_extension sme; mrs %0, SVCR" : "=r"(svcr));
-    __asm__ __volatile__(".arch_extension sme; smstop za");  // Turn ZA off anyway.
-    za_state = svcr & 0x2UL;
+    bool za_state = sme_is_za_on();
+    sme_disable_za();  // Turn ZA off anyway.
     ASSERT_EQ(789, value);
-    ASSERT_EQ(0UL, za_state);
+    ASSERT_FALSE(za_state);
   }
 }
 #endif
diff --git a/tests/signal_test.cpp b/tests/signal_test.cpp
index 27f5c6cf2..d9bfa787a 100644
--- a/tests/signal_test.cpp
+++ b/tests/signal_test.cpp
@@ -26,11 +26,13 @@
 #include <thread>
 
 #include <android-base/macros.h>
+#include <android-base/test_utils.h>
 #include <android-base/threads.h>
 
 #include <gtest/gtest.h>
 
 #include "SignalUtils.h"
+#include "sme_utils.h"
 #include "utils.h"
 
 using namespace std::chrono_literals;
@@ -1073,29 +1075,28 @@ TEST(signal, str2sig) {
 }
 
 #if defined(__aarch64__)
-__attribute__((target("arch=armv9+sme"))) __arm_new("za") static void FunctionUsingZA() {
+static void raises_sigusr1() {
   raise(SIGUSR1);
 }
 
 TEST(signal, sme_tpidr2_clear) {
   // When using SME, on entering a signal handler the kernel should clear TPIDR2_EL0, but this was
   // not always correctly done. This tests checks if the kernel correctly clears it or not.
-  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+  if (!sme_is_enabled()) {
     GTEST_SKIP() << "SME is not enabled on device.";
   }
 
   static uint64_t tpidr2 = 0;
   struct sigaction handler = {};
   handler.sa_sigaction = [](int, siginfo_t*, void*) {
-    uint64_t zero = 0;
-    __asm__ __volatile__(".arch_extension sme; mrs %0, TPIDR2_EL0" : "=r"(tpidr2));
-    __asm__ __volatile__(".arch_extension sme; msr TPIDR2_EL0, %0" : : "r"(zero));  // Clear TPIDR2.
+    tpidr2 = sme_tpidr2_el0();
+    sme_set_tpidr2_el0(0UL);
   };
   handler.sa_flags = SA_SIGINFO;
 
   ASSERT_EQ(0, sigaction(SIGUSR1, &handler, nullptr));
 
-  FunctionUsingZA();
+  sme_dormant_caller(&raises_sigusr1);
 
   ASSERT_EQ(0x0UL, tpidr2)
       << "Broken kernel! TPIDR2_EL0 was not null in the signal handler! "
@@ -1103,3 +1104,42 @@ TEST(signal, sme_tpidr2_clear) {
       << "https://lore.kernel.org/linux-arm-kernel/20250417190113.3778111-1-mark.rutland@arm.com/";
 }
 #endif
+
+TEST(signal, psignal) {
+  CapturedStderr cap;
+  psignal(SIGINT, "a b c");
+  ASSERT_EQ(cap.str(), "a b c: Interrupt\n");
+}
+
+TEST(signal, psignal_null) {
+  CapturedStderr cap;
+  psignal(SIGINT, nullptr);
+  ASSERT_EQ(cap.str(), "Interrupt\n");
+}
+
+TEST(signal, psignal_empty) {
+  CapturedStderr cap;
+  psignal(SIGINT, "");
+  ASSERT_EQ(cap.str(), "Interrupt\n");
+}
+
+TEST(signal, psiginfo) {
+  CapturedStderr cap;
+  siginfo_t si{.si_signo = SIGINT};
+  psiginfo(&si, "a b c");
+  ASSERT_EQ(cap.str(), "a b c: Interrupt\n");
+}
+
+TEST(signal, psiginfo_null) {
+  CapturedStderr cap;
+  siginfo_t si{.si_signo = SIGINT};
+  psiginfo(&si, nullptr);
+  ASSERT_EQ(cap.str(), "Interrupt\n");
+}
+
+TEST(signal, psiginfo_empty) {
+  CapturedStderr cap;
+  siginfo_t si{.si_signo = SIGINT};
+  psiginfo(&si, "");
+  ASSERT_EQ(cap.str(), "Interrupt\n");
+}
diff --git a/tests/sme_utils.h b/tests/sme_utils.h
new file mode 100644
index 000000000..38db76f47
--- /dev/null
+++ b/tests/sme_utils.h
@@ -0,0 +1,147 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#pragma once
+
+#include <sys/auxv.h>
+
+#include <cstdint>
+
+#if defined(__aarch64__)
+
+#include <arm_sme.h>
+
+// Detects whether FEAT_SME is available.
+//
+// FEAT_SME is optional from Armv9.2.
+[[maybe_unused]] static bool sme_is_enabled() {
+  return ((getauxval(AT_HWCAP2) & HWCAP2_SME) != 0);
+}
+
+// Sets PSTATE.SM to 0.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static void sme_disable_sm() {
+  __asm__ __volatile__(".arch_extension sme; bti c; smstop sm; ret;");
+}
+
+// Sets PSTATE.ZA to 1.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static void sme_enable_za() {
+  __asm__ __volatile__(".arch_extension sme; bti c; smstart za; ret;");
+}
+
+// Sets PSTATE.ZA to 0.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static void sme_disable_za() {
+  __asm__ __volatile__(".arch_extension sme; bti c; smstop za; ret;");
+}
+
+// Sets TPIDR2_EL0 to a given value.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static void sme_set_tpidr2_el0(uint64_t value) {
+  __asm__ __volatile__(".arch_extension sme; bti c; msr TPIDR2_EL0, x0; ret;");
+}
+
+// Reads TPIDR2_EL0 and returns its value.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static uint64_t sme_tpidr2_el0() {
+  __asm__ __volatile__(".arch_extension sme; bti c; mrs x0, TPIDR2_EL0; ret;");
+}
+
+// Reads SVCR special register.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] __attribute__((naked)) static uint64_t sme_read_svcr() {
+  __asm__ __volatile__(".arch_extension sme; bti c; mrs x0, SVCR; ret;");
+}
+
+// Returns true if PSTATE.SM is 1, otherwise false.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] static bool sme_is_sm_on() {
+  static constexpr uint64_t kSvcrSmMask = 0x01UL;
+  return ((sme_read_svcr() & kSvcrSmMask) != 0);
+}
+
+// Returns true if PSTATE.ZA is 1, otherwise false.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] static bool sme_is_za_on() {
+  static constexpr uint64_t kSvcrZaMask = 0x02UL;
+  return ((sme_read_svcr() & kSvcrZaMask) != 0);
+}
+
+// Assembly is required to ensure the test does not depend on compiler optimizations.
+[[maybe_unused]] __attribute__((naked)) static void sme_dormant_caller(void (*fn_address)()) {
+  // clang-format off
+  __asm__ __volatile__(
+    ".arch_extension sme\n\r"
+    "bti      c\n\r"
+    "stp      x29, x30, [sp, #-16]!\n\r"
+    "mov      x29, sp\n\r"
+    // Set up a lazy-save buffer on the stack.
+    // It is 16 bytes + size according to VL.
+    "sub      sp, sp, #16\n\r"
+    "rdsvl    x8, #1\n\r"
+    "mul      x9, x8, x8\n\r"
+    "sub      sp, sp, x9\n\r"
+    "mov      x9, sp\n\r"
+    // Bytes 0-7: za_save_buffer
+    // Bytes 8-9: num_za_save_slices
+    // Other bytes are cleared.
+    "stp      x9, x8, [x29, #-16]\n\r"
+    // Finalize the lazy-save buffer.
+    "msr      TPIDR2_EL0, x9\n\r"
+    // Call the given function with dormant SME state.
+    "smstart  za\n\r"
+    "blr      x0\n\r"
+    // Set SME state to off.
+    "msr      TPIDR2_EL0, xzr\n\r"
+    "smstop   za\n\r"
+    "mov      sp, x29\n\r"
+    "ldp      x29, x30, [sp], #16\n\r"
+    "ret\n\r"
+  );
+  // clang-format on
+}
+
+// Turns all SME state off.
+//
+// Requires FEAT_SME, which is optional from Armv9.2.
+[[maybe_unused]] static void sme_state_cleanup() {
+  sme_disable_sm();
+  sme_set_tpidr2_el0(0UL);
+  sme_disable_za();
+}
+
+#endif  // defined(__aarch64__)
diff --git a/tests/spawn_test.cpp b/tests/spawn_test.cpp
index ab3e877a3..0bef16f60 100644
--- a/tests/spawn_test.cpp
+++ b/tests/spawn_test.cpp
@@ -249,10 +249,10 @@ TEST(spawn, posix_spawn_file_actions) {
   ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 56, "/proc/version", O_RDONLY, 0));
   // Test addfchdir by opening the same file a second way...
   ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 57, "/proc", O_PATH, 0));
-  ASSERT_EQ(0, posix_spawn_file_actions_addfchdir_np(&fa, 57));
+  ASSERT_EQ(0, posix_spawn_file_actions_addfchdir(&fa, 57));
   ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 58, "version", O_RDONLY, 0));
   // Test addchdir by opening the same file a third way...
-  ASSERT_EQ(0, posix_spawn_file_actions_addchdir_np(&fa, "/"));
+  ASSERT_EQ(0, posix_spawn_file_actions_addchdir(&fa, "/"));
   ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 59, "proc/version", O_RDONLY, 0));
 
   ExecTestHelper eth;
diff --git a/tests/static_tls_layout_test.cpp b/tests/static_tls_layout_test.cpp
index ada29a5ed..992b2cec9 100644
--- a/tests/static_tls_layout_test.cpp
+++ b/tests/static_tls_layout_test.cpp
@@ -163,8 +163,8 @@ TEST_F(static_tls_layout_DeathTest, arm) {
 
   // Amount of memory needed for negative TLS slots, given a segment p_align of
   // 8 or 16 words.
-  const size_t base8 = __BIONIC_ALIGN(-MIN_TLS_SLOT, 8) * sizeof(void*);
-  const size_t base16 = __BIONIC_ALIGN(-MIN_TLS_SLOT, 16) * sizeof(void*);
+  const size_t base8 = __builtin_align_up(-MIN_TLS_SLOT, 8) * sizeof(void*);
+  const size_t base16 = __builtin_align_up(-MIN_TLS_SLOT, 16) * sizeof(void*);
 
   StaticTlsLayout layout;
 
diff --git a/tests/stdint_test.cpp b/tests/stdint_test.cpp
index 5dafee310..ee609d1b2 100644
--- a/tests/stdint_test.cpp
+++ b/tests/stdint_test.cpp
@@ -14,24 +14,156 @@
  * limitations under the License.
  */
 
+#include <stdint.h>
+
 #include <gtest/gtest.h>
 
-#include <stdint.h>
+#include <limits>
 
-TEST(stdint_types, type_sizes) {
-  ASSERT_EQ(1U, sizeof(int_fast8_t));
-  ASSERT_EQ(8U, sizeof(int_fast64_t));
-  ASSERT_EQ(1U, sizeof(uint_fast8_t));
-  ASSERT_EQ(8U, sizeof(uint_fast64_t));
+TEST(stdint, fast_type_sizes) {
+  EXPECT_EQ(1U, sizeof(int_fast8_t));
+  EXPECT_EQ(8U, sizeof(int_fast64_t));
+  EXPECT_EQ(1U, sizeof(uint_fast8_t));
+  EXPECT_EQ(8U, sizeof(uint_fast64_t));
 #if defined(__LP64__)
-  ASSERT_EQ(8U, sizeof(int_fast16_t));
-  ASSERT_EQ(8U, sizeof(int_fast32_t));
-  ASSERT_EQ(8U, sizeof(uint_fast16_t));
-  ASSERT_EQ(8U, sizeof(uint_fast32_t));
+  EXPECT_EQ(8U, sizeof(int_fast16_t));
+  EXPECT_EQ(8U, sizeof(int_fast32_t));
+  EXPECT_EQ(8U, sizeof(uint_fast16_t));
+  EXPECT_EQ(8U, sizeof(uint_fast32_t));
 #else
-  ASSERT_EQ(4U, sizeof(int_fast16_t));
-  ASSERT_EQ(4U, sizeof(int_fast32_t));
-  ASSERT_EQ(4U, sizeof(uint_fast16_t));
-  ASSERT_EQ(4U, sizeof(uint_fast32_t));
+  EXPECT_EQ(4U, sizeof(int_fast16_t));
+  EXPECT_EQ(4U, sizeof(int_fast32_t));
+  EXPECT_EQ(4U, sizeof(uint_fast16_t));
+  EXPECT_EQ(4U, sizeof(uint_fast32_t));
+#endif
+}
+
+TEST(stdint, least_type_sizes) {
+  EXPECT_EQ(1U, sizeof(int_least8_t));
+  EXPECT_EQ(1U, sizeof(uint_least8_t));
+  EXPECT_EQ(2U, sizeof(int_least16_t));
+  EXPECT_EQ(2U, sizeof(uint_least16_t));
+  EXPECT_EQ(4U, sizeof(int_least32_t));
+  EXPECT_EQ(4U, sizeof(uint_least32_t));
+  EXPECT_EQ(8U, sizeof(int_least64_t));
+  EXPECT_EQ(8U, sizeof(uint_least64_t));
+}
+
+TEST(stdint, max) {
+  EXPECT_EQ(std::numeric_limits<int8_t>::max(), INT8_MAX);
+  EXPECT_EQ(std::numeric_limits<uint8_t>::max(), UINT8_MAX);
+  EXPECT_EQ(std::numeric_limits<int16_t>::max(), INT16_MAX);
+  EXPECT_EQ(std::numeric_limits<uint16_t>::max(), UINT16_MAX);
+  EXPECT_EQ(std::numeric_limits<int32_t>::max(), INT32_MAX);
+  EXPECT_EQ(std::numeric_limits<uint32_t>::max(), UINT32_MAX);
+  EXPECT_EQ(std::numeric_limits<int64_t>::max(), INT64_MAX);
+  EXPECT_EQ(std::numeric_limits<uint64_t>::max(), UINT64_MAX);
+
+  EXPECT_EQ(std::numeric_limits<int_fast8_t>::max(), INT_FAST8_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_fast8_t>::max(), UINT_FAST8_MAX);
+  EXPECT_EQ(std::numeric_limits<int_fast16_t>::max(), INT_FAST16_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_fast16_t>::max(), UINT_FAST16_MAX);
+  EXPECT_EQ(std::numeric_limits<int_fast32_t>::max(), INT_FAST32_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_fast32_t>::max(), UINT_FAST32_MAX);
+  EXPECT_EQ(std::numeric_limits<int_fast64_t>::max(), INT_FAST64_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_fast64_t>::max(), UINT_FAST64_MAX);
+
+  EXPECT_EQ(std::numeric_limits<int_least8_t>::max(), INT_LEAST8_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_least8_t>::max(), UINT_LEAST8_MAX);
+  EXPECT_EQ(std::numeric_limits<int_least16_t>::max(), INT_LEAST16_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_least16_t>::max(), UINT_LEAST16_MAX);
+  EXPECT_EQ(std::numeric_limits<int_least32_t>::max(), INT_LEAST32_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_least32_t>::max(), UINT_LEAST32_MAX);
+  EXPECT_EQ(std::numeric_limits<int_least64_t>::max(), INT_LEAST64_MAX);
+  EXPECT_EQ(std::numeric_limits<uint_least64_t>::max(), UINT_LEAST64_MAX);
+
+  EXPECT_EQ(std::numeric_limits<wchar_t>::max(), WCHAR_MAX);
+  EXPECT_EQ(std::numeric_limits<wint_t>::max(), WINT_MAX);
+
+  EXPECT_EQ(std::numeric_limits<intptr_t>::max(), INTPTR_MAX);
+  EXPECT_EQ(std::numeric_limits<uintptr_t>::max(), UINTPTR_MAX);
+  EXPECT_EQ(std::numeric_limits<intmax_t>::max(), INTMAX_MAX);
+  EXPECT_EQ(std::numeric_limits<uintmax_t>::max(), UINTMAX_MAX);
+
+  EXPECT_EQ(std::numeric_limits<ptrdiff_t>::max(), PTRDIFF_MAX);
+
+  EXPECT_EQ(std::numeric_limits<size_t>::max(), SIZE_MAX);
+
+  EXPECT_EQ(std::numeric_limits<sig_atomic_t>::max(), SIG_ATOMIC_MAX);
+}
+
+TEST(stdint, min) {
+  EXPECT_EQ(std::numeric_limits<int8_t>::min(), INT8_MIN);
+  EXPECT_EQ(std::numeric_limits<int16_t>::min(), INT16_MIN);
+  EXPECT_EQ(std::numeric_limits<int32_t>::min(), INT32_MIN);
+  EXPECT_EQ(std::numeric_limits<int64_t>::min(), INT64_MIN);
+
+  EXPECT_EQ(std::numeric_limits<int_fast8_t>::min(), INT_FAST8_MIN);
+  EXPECT_EQ(std::numeric_limits<int_fast16_t>::min(), INT_FAST16_MIN);
+  EXPECT_EQ(std::numeric_limits<int_fast32_t>::min(), INT_FAST32_MIN);
+  EXPECT_EQ(std::numeric_limits<int_fast64_t>::min(), INT_FAST64_MIN);
+
+  EXPECT_EQ(std::numeric_limits<int_least8_t>::min(), INT_LEAST8_MIN);
+  EXPECT_EQ(std::numeric_limits<int_least16_t>::min(), INT_LEAST16_MIN);
+  EXPECT_EQ(std::numeric_limits<int_least32_t>::min(), INT_LEAST32_MIN);
+  EXPECT_EQ(std::numeric_limits<int_least64_t>::min(), INT_LEAST64_MIN);
+
+  EXPECT_EQ(std::numeric_limits<wchar_t>::min(), WCHAR_MIN);
+  EXPECT_EQ(std::numeric_limits<wint_t>::min(), static_cast<uintmax_t>(WINT_MIN));
+
+  EXPECT_EQ(std::numeric_limits<intptr_t>::min(), INTPTR_MIN);
+  EXPECT_EQ(std::numeric_limits<intmax_t>::min(), INTMAX_MIN);
+
+  EXPECT_EQ(std::numeric_limits<ptrdiff_t>::min(), PTRDIFF_MIN);
+
+  EXPECT_EQ(std::numeric_limits<sig_atomic_t>::min(), SIG_ATOMIC_MIN);
+}
+template <typename T>
+static inline int bitSize() {
+  return sizeof(T) * 8;
+}
+
+TEST(stdint, widths) {
+#if defined(__BIONIC__)
+  EXPECT_EQ(bitSize<int8_t>(), INT8_WIDTH);
+  EXPECT_EQ(bitSize<uint8_t>(), UINT8_WIDTH);
+  EXPECT_EQ(bitSize<int16_t>(), INT16_WIDTH);
+  EXPECT_EQ(bitSize<uint16_t>(), UINT16_WIDTH);
+  EXPECT_EQ(bitSize<int32_t>(), INT32_WIDTH);
+  EXPECT_EQ(bitSize<uint32_t>(), UINT32_WIDTH);
+  EXPECT_EQ(bitSize<int64_t>(), INT64_WIDTH);
+  EXPECT_EQ(bitSize<uint64_t>(), UINT64_WIDTH);
+
+  EXPECT_EQ(bitSize<int_fast8_t>(), INT_FAST8_WIDTH);
+  EXPECT_EQ(bitSize<uint_fast8_t>(), UINT_FAST8_WIDTH);
+  EXPECT_EQ(bitSize<int_fast16_t>(), INT_FAST16_WIDTH);
+  EXPECT_EQ(bitSize<uint_fast16_t>(), UINT_FAST16_WIDTH);
+  EXPECT_EQ(bitSize<int_fast32_t>(), INT_FAST32_WIDTH);
+  EXPECT_EQ(bitSize<uint_fast32_t>(), UINT_FAST32_WIDTH);
+  EXPECT_EQ(bitSize<int_fast64_t>(), INT_FAST64_WIDTH);
+  EXPECT_EQ(bitSize<uint_fast64_t>(), UINT_FAST64_WIDTH);
+
+  EXPECT_EQ(bitSize<int_least8_t>(), INT_LEAST8_WIDTH);
+  EXPECT_EQ(bitSize<uint_least8_t>(), UINT_LEAST8_WIDTH);
+  EXPECT_EQ(bitSize<int_least16_t>(), INT_LEAST16_WIDTH);
+  EXPECT_EQ(bitSize<uint_least16_t>(), UINT_LEAST16_WIDTH);
+  EXPECT_EQ(bitSize<int_least32_t>(), INT_LEAST32_WIDTH);
+  EXPECT_EQ(bitSize<uint_least32_t>(), UINT_LEAST32_WIDTH);
+  EXPECT_EQ(bitSize<int_least64_t>(), INT_LEAST64_WIDTH);
+  EXPECT_EQ(bitSize<uint_least64_t>(), UINT_LEAST64_WIDTH);
+
+  EXPECT_EQ(bitSize<wchar_t>(), WCHAR_WIDTH);
+  EXPECT_EQ(bitSize<wint_t>(), WINT_WIDTH);
+
+  EXPECT_EQ(bitSize<intptr_t>(), INTPTR_WIDTH);
+  EXPECT_EQ(bitSize<uintptr_t>(), UINTPTR_WIDTH);
+  EXPECT_EQ(bitSize<intmax_t>(), INTMAX_WIDTH);
+  EXPECT_EQ(bitSize<uintmax_t>() , UINTMAX_WIDTH);
+
+  EXPECT_EQ(bitSize<ptrdiff_t>(), PTRDIFF_WIDTH);
+
+  EXPECT_EQ(bitSize<size_t>(), SIZE_WIDTH);
+
+  EXPECT_EQ(bitSize<sig_atomic_t>(), SIG_ATOMIC_WIDTH);
 #endif
 }
diff --git a/tests/stdio_test.cpp b/tests/stdio_test.cpp
index 7cdfa425a..95bd02625 100644
--- a/tests/stdio_test.cpp
+++ b/tests/stdio_test.cpp
@@ -2641,25 +2641,45 @@ TEST(STDIO_TEST, constants) {
 }
 
 TEST(STDIO_TEST, perror) {
-  ExecTestHelper eth;
-  eth.Run([&]() { errno = EINVAL; perror("a b c"); exit(0); }, 0, "a b c: Invalid argument\n");
-  eth.Run([&]() { errno = EINVAL; perror(nullptr); exit(0); }, 0, "Invalid argument\n");
-  eth.Run([&]() { errno = EINVAL; perror(""); exit(0); }, 0, "Invalid argument\n");
+  CapturedStderr cap;
+  errno = EINVAL;
+  perror("a b c");
+  ASSERT_EQ(cap.str(), "a b c: Invalid argument\n");
+}
+
+TEST(STDIO_TEST, perror_null) {
+  CapturedStderr cap;
+  errno = EINVAL;
+  perror(nullptr);
+  ASSERT_EQ(cap.str(), "Invalid argument\n");
+}
+
+TEST(STDIO_TEST, perror_empty) {
+  CapturedStderr cap;
+  errno = EINVAL;
+  perror("");
+  ASSERT_EQ(cap.str(), "Invalid argument\n");
 }
 
 TEST(STDIO_TEST, puts) {
-  ExecTestHelper eth;
-  eth.Run([&]() { exit(puts("a b c")); }, 0, "a b c\n");
+  CapturedStdout cap;
+  puts("a b c");
+  fflush(stdout);
+  ASSERT_EQ(cap.str(), "a b c\n");
 }
 
 TEST(STDIO_TEST, putchar) {
-  ExecTestHelper eth;
-  eth.Run([&]() { exit(putchar('A')); }, 65, "A");
+  CapturedStdout cap;
+  ASSERT_EQ(65, putchar('A'));
+  fflush(stdout);
+  ASSERT_EQ(cap.str(), "A");
 }
 
 TEST(STDIO_TEST, putchar_unlocked) {
-  ExecTestHelper eth;
-  eth.Run([&]() { exit(putchar('B')); }, 66, "B");
+  CapturedStdout cap;
+  ASSERT_EQ(66, putchar_unlocked('B'));
+  fflush(stdout);
+  ASSERT_EQ(cap.str(), "B");
 }
 
 TEST(STDIO_TEST, unlocked) {
diff --git a/tests/string_test.cpp b/tests/string_test.cpp
index 502405f40..7832f07cf 100644
--- a/tests/string_test.cpp
+++ b/tests/string_test.cpp
@@ -1615,6 +1615,11 @@ TEST(STRING_TEST, strcasestr_smoke) {
   ASSERT_EQ(haystack + 4, strcasestr(haystack, "Da"));
 }
 
+TEST(STRING_TEST, strcasestr_empty) {
+  const char* empty_haystack = "";
+  ASSERT_EQ(empty_haystack, strcasestr(empty_haystack, ""));
+}
+
 TEST(STRING_TEST, strcoll_smoke) {
   ASSERT_TRUE(strcoll("aab", "aac") < 0);
   ASSERT_TRUE(strcoll("aab", "aab") == 0);
diff --git a/tests/struct_layout_test.cpp b/tests/struct_layout_test.cpp
index b9fd31507..3ee3145d3 100644
--- a/tests/struct_layout_test.cpp
+++ b/tests/struct_layout_test.cpp
@@ -26,9 +26,9 @@
 template <typename CheckSize, typename CheckOffset>
 void tests(CheckSize check_size, CheckOffset check_offset) {
 #define CHECK_SIZE(name, size) \
-    check_size(#name, sizeof(name), size);
+    check_size(#name, sizeof(name), size)
 #define CHECK_OFFSET(name, field, offset) \
-    check_offset(#name, #field, offsetof(name, field), offset);
+    check_offset(#name, #field, offsetof(name, field), offset)
 #ifdef __LP64__
   CHECK_SIZE(pthread_internal_t, 824);
   CHECK_OFFSET(pthread_internal_t, next, 0);
@@ -58,22 +58,21 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
   CHECK_OFFSET(pthread_internal_t, bionic_tcb, 776);
   CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 784);
   CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 816);
-  CHECK_SIZE(bionic_tls, 12200);
+  CHECK_SIZE(bionic_tls, 4016);
   CHECK_OFFSET(bionic_tls, key_data, 0);
   CHECK_OFFSET(bionic_tls, locale, 2080);
-  CHECK_OFFSET(bionic_tls, basename_buf, 2088);
-  CHECK_OFFSET(bionic_tls, dirname_buf, 6184);
-  CHECK_OFFSET(bionic_tls, mntent_buf, 10280);
-  CHECK_OFFSET(bionic_tls, mntent_strings, 10320);
-  CHECK_OFFSET(bionic_tls, ptsname_buf, 11344);
-  CHECK_OFFSET(bionic_tls, ttyname_buf, 11376);
-  CHECK_OFFSET(bionic_tls, strerror_buf, 11440);
-  CHECK_OFFSET(bionic_tls, strsignal_buf, 11695);
-  CHECK_OFFSET(bionic_tls, group, 11952);
-  CHECK_OFFSET(bionic_tls, passwd, 12040);
-  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 12192);
-  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 12193);
-  CHECK_OFFSET(bionic_tls, padding, 12194);
+  CHECK_OFFSET(bionic_tls, libgen_buffers_ptr, 2088);
+  CHECK_OFFSET(bionic_tls, mntent_buf, 2096);
+  CHECK_OFFSET(bionic_tls, mntent_strings, 2136);
+  CHECK_OFFSET(bionic_tls, ptsname_buf, 3160);
+  CHECK_OFFSET(bionic_tls, ttyname_buf, 3192);
+  CHECK_OFFSET(bionic_tls, strerror_buf, 3256);
+  CHECK_OFFSET(bionic_tls, strsignal_buf, 3511);
+  CHECK_OFFSET(bionic_tls, group, 3768);
+  CHECK_OFFSET(bionic_tls, passwd, 3856);
+  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 4008);
+  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 4009);
+  CHECK_OFFSET(bionic_tls, padding, 4010);
 #else
   CHECK_SIZE(pthread_internal_t, 708);
   CHECK_OFFSET(pthread_internal_t, next, 0);
@@ -103,22 +102,21 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
   CHECK_OFFSET(pthread_internal_t, bionic_tcb, 668);
   CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 672);
   CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 704);
-  CHECK_SIZE(bionic_tls, 11080);
+  CHECK_SIZE(bionic_tls, 2892);
   CHECK_OFFSET(bionic_tls, key_data, 0);
   CHECK_OFFSET(bionic_tls, locale, 1040);
-  CHECK_OFFSET(bionic_tls, basename_buf, 1044);
-  CHECK_OFFSET(bionic_tls, dirname_buf, 5140);
-  CHECK_OFFSET(bionic_tls, mntent_buf, 9236);
-  CHECK_OFFSET(bionic_tls, mntent_strings, 9260);
-  CHECK_OFFSET(bionic_tls, ptsname_buf, 10284);
-  CHECK_OFFSET(bionic_tls, ttyname_buf, 10316);
-  CHECK_OFFSET(bionic_tls, strerror_buf, 10380);
-  CHECK_OFFSET(bionic_tls, strsignal_buf, 10635);
-  CHECK_OFFSET(bionic_tls, group, 10892);
-  CHECK_OFFSET(bionic_tls, passwd, 10952);
-  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 11076);
-  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 11077);
-  CHECK_OFFSET(bionic_tls, padding, 11078);
+  CHECK_OFFSET(bionic_tls, libgen_buffers_ptr, 1044);
+  CHECK_OFFSET(bionic_tls, mntent_buf, 1048);
+  CHECK_OFFSET(bionic_tls, mntent_strings, 1072);
+  CHECK_OFFSET(bionic_tls, ptsname_buf, 2096);
+  CHECK_OFFSET(bionic_tls, ttyname_buf, 2128);
+  CHECK_OFFSET(bionic_tls, strerror_buf, 2192);
+  CHECK_OFFSET(bionic_tls, strsignal_buf, 2447);
+  CHECK_OFFSET(bionic_tls, group, 2704);
+  CHECK_OFFSET(bionic_tls, passwd, 2764);
+  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 2888);
+  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 2889);
+  CHECK_OFFSET(bionic_tls, padding, 2890);
 #endif  // __LP64__
 #undef CHECK_SIZE
 #undef CHECK_OFFSET
diff --git a/tests/sys_hwprobe_test.cpp b/tests/sys_hwprobe_test.cpp
index fd59e1ddc..0111d0084 100644
--- a/tests/sys_hwprobe_test.cpp
+++ b/tests/sys_hwprobe_test.cpp
@@ -95,11 +95,13 @@ TEST(sys_hwprobe, __riscv_hwprobe_misaligned_vector) {
 #endif
 }
 
-TEST(sys_hwprobe, __riscv_hwprobe) {
-#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
-  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
-                            {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
-  ASSERT_EQ(0, __riscv_hwprobe(probes, 2, 0, nullptr, 0));
+#define key_count(probes) (sizeof(probes)/sizeof(probes[0]))
+
+TEST(sys_hwprobe, __riscv_hwprobe_extensions) {
+#if defined(__riscv)
+  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0}};
+  ASSERT_EQ(0, __riscv_hwprobe(probes, key_count(probes), 0, nullptr, 0));
+
   EXPECT_EQ(RISCV_HWPROBE_KEY_IMA_EXT_0, probes[0].key);
   EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_IMA_FD) != 0);
   EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_IMA_C) != 0);
@@ -107,41 +109,89 @@ TEST(sys_hwprobe, __riscv_hwprobe) {
   EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBA) != 0);
   EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBB) != 0);
   EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBS) != 0);
+#else
+  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
+#endif
+}
 
-  EXPECT_EQ(RISCV_HWPROBE_KEY_CPUPERF_0, probes[1].key);
-  EXPECT_TRUE((probes[1].value & RISCV_HWPROBE_MISALIGNED_MASK) == RISCV_HWPROBE_MISALIGNED_FAST);
+TEST(sys_hwprobe, __riscv_hwprobe_cpu_perf) {
+#if defined(__riscv)
+  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
+  ASSERT_EQ(0, __riscv_hwprobe(probes, key_count(probes), 0, nullptr, 0));
+
+  EXPECT_EQ(RISCV_HWPROBE_KEY_CPUPERF_0, probes[0].key);
+  EXPECT_EQ(RISCV_HWPROBE_MISALIGNED_FAST,
+            static_cast<int>(probes[0].value & RISCV_HWPROBE_MISALIGNED_MASK));
 #else
   GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
 #endif
 }
 
-TEST(sys_hwprobe, __riscv_hwprobe_syscall_vdso) {
-#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
-  riscv_hwprobe probes_vdso[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
-                                 {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
-  ASSERT_EQ(0, __riscv_hwprobe(probes_vdso, 2, 0, nullptr, 0));
+TEST(sys_hwprobe, __riscv_hwprobe_scalar_perf) {
+#if defined(__riscv)
+  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF}};
+  ASSERT_EQ(0, __riscv_hwprobe(probes, key_count(probes), 0, nullptr, 0));
 
-  riscv_hwprobe probes_syscall[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
-                                    {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
-  ASSERT_EQ(0, syscall(SYS_riscv_hwprobe, probes_syscall, 2, 0, nullptr, 0));
+  EXPECT_EQ(RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF, probes[0].key);
+  EXPECT_EQ(RISCV_HWPROBE_MISALIGNED_SCALAR_FAST, static_cast<int>(probes[0].value));
+#else
+  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
+#endif
+}
+
+TEST(sys_hwprobe, __riscv_hwprobe_vector_perf) {
+#if defined(__riscv)
+  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF}};
+  ASSERT_EQ(0, __riscv_hwprobe(probes, key_count(probes), 0, nullptr, 0));
+
+  EXPECT_EQ(RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF, probes[0].key);
+  EXPECT_EQ(RISCV_HWPROBE_MISALIGNED_VECTOR_FAST, static_cast<int>(probes[0].value));
+#else
+  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
+#endif
+}
+
+TEST(sys_hwprobe, __riscv_hwprobe_syscall_vdso) {
+#if defined(__riscv)
+  riscv_hwprobe probes_vdso[] = {
+    {.key = RISCV_HWPROBE_KEY_MVENDORID},
+    {.key = RISCV_HWPROBE_KEY_MARCHID},
+    {.key = RISCV_HWPROBE_KEY_MIMPID},
+    {.key = RISCV_HWPROBE_KEY_BASE_BEHAVIOR},
+    {.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
+    {.key = RISCV_HWPROBE_KEY_CPUPERF_0},
+    {.key = RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF},
+    {.key = RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF},
+  };
+  ASSERT_EQ(0, __riscv_hwprobe(probes_vdso, key_count(probes_vdso), 0, nullptr, 0));
+
+  riscv_hwprobe probes_syscall[] = {
+    {.key = RISCV_HWPROBE_KEY_MVENDORID},
+    {.key = RISCV_HWPROBE_KEY_MARCHID},
+    {.key = RISCV_HWPROBE_KEY_MIMPID},
+    {.key = RISCV_HWPROBE_KEY_BASE_BEHAVIOR},
+    {.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
+    {.key = RISCV_HWPROBE_KEY_CPUPERF_0},
+    {.key = RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF},
+    {.key = RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF},
+  };
+  ASSERT_EQ(0, syscall(SYS_riscv_hwprobe, key_count(probes_syscall), 0, nullptr, 0));
 
   // Check we got the same answers from the vdso and the syscall.
-  EXPECT_EQ(RISCV_HWPROBE_KEY_IMA_EXT_0, probes_syscall[0].key);
-  EXPECT_EQ(probes_vdso[0].key, probes_syscall[0].key);
-  EXPECT_EQ(probes_vdso[0].value, probes_syscall[0].value);
-  EXPECT_EQ(RISCV_HWPROBE_KEY_CPUPERF_0, probes_syscall[1].key);
-  EXPECT_EQ(probes_vdso[1].key, probes_syscall[1].key);
-  EXPECT_EQ(probes_vdso[1].value, probes_syscall[1].value);
+  for (size_t i = 0; i < key_count(probes_vdso); ++i) {
+    EXPECT_EQ(probes_vdso[i].key, probes_syscall[i].key) << i;
+    EXPECT_EQ(probes_vdso[i].value, probes_syscall[i].value) << i;
+  }
 #else
   GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
 #endif
 }
 
 TEST(sys_hwprobe, __riscv_hwprobe_fail) {
-#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
+#if defined(__riscv)
   riscv_hwprobe probes[] = {};
   ASSERT_EQ(EINVAL, __riscv_hwprobe(probes, 0, 0, nullptr, ~0));
 #else
   GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
 #endif
-}
\ No newline at end of file
+}
diff --git a/tests/sys_random_test.cpp b/tests/sys_random_test.cpp
index 4425dbaab..ca70d9ad8 100644
--- a/tests/sys_random_test.cpp
+++ b/tests/sys_random_test.cpp
@@ -62,14 +62,14 @@ TEST(sys_random, getentropy_EFAULT) {
 #pragma clang diagnostic pop
 }
 
-TEST(sys_random, getentropy_EIO) {
+TEST(sys_random, getentropy_EINVAL) {
 #if defined(HAVE_SYS_RANDOM)
   char buf[BUFSIZ];
   static_assert(BUFSIZ > 256, "BUFSIZ <= 256!");
 
   errno = 0;
   ASSERT_EQ(-1, getentropy(buf, sizeof(buf)));
-  ASSERT_ERRNO(EIO);
+  ASSERT_ERRNO(EINVAL);
 #else
   GTEST_SKIP() << "<sys/random.h> not available";
 #endif
diff --git a/tests/sys_stat_test.cpp b/tests/sys_stat_test.cpp
index 50c50dfba..d504e3c69 100644
--- a/tests/sys_stat_test.cpp
+++ b/tests/sys_stat_test.cpp
@@ -33,25 +33,24 @@
 #endif
 
 TEST(sys_stat, futimens) {
-  FILE* fp = tmpfile();
-  ASSERT_TRUE(fp != nullptr);
-
-  int fd = fileno(fp);
-  ASSERT_NE(fd, -1);
+  TemporaryFile tf;
 
   timespec times[2];
   times[0].tv_sec = 123;
   times[0].tv_nsec = 0;
   times[1].tv_sec = 456;
   times[1].tv_nsec = 0;
-  ASSERT_EQ(0, futimens(fd, times)) << strerror(errno);
+  ASSERT_EQ(0, futimens(tf.fd, times)) << strerror(errno);
 
   struct stat sb;
-  ASSERT_EQ(0, fstat(fd, &sb));
+  ASSERT_EQ(0, fstat(tf.fd, &sb));
   ASSERT_EQ(times[0].tv_sec, static_cast<long>(sb.st_atime));
   ASSERT_EQ(times[1].tv_sec, static_cast<long>(sb.st_mtime));
+}
 
-  fclose(fp);
+TEST(sys_stat, futimens_null) {
+  TemporaryFile tf;
+  ASSERT_EQ(0, futimens(tf.fd, nullptr));
 }
 
 TEST(sys_stat, futimens_EBADF) {
@@ -64,6 +63,27 @@ TEST(sys_stat, futimens_EBADF) {
   ASSERT_ERRNO(EBADF);
 }
 
+TEST(sys_stat, utimensat) {
+  TemporaryFile tf;
+
+  timespec times[2];
+  times[0].tv_sec = 123;
+  times[0].tv_nsec = 0;
+  times[1].tv_sec = 456;
+  times[1].tv_nsec = 0;
+  ASSERT_EQ(0, utimensat(AT_FDCWD, tf.path, times, 0)) << strerror(errno);
+
+  struct stat sb;
+  ASSERT_EQ(0, fstat(tf.fd, &sb));
+  ASSERT_EQ(times[0].tv_sec, static_cast<long>(sb.st_atime));
+  ASSERT_EQ(times[1].tv_sec, static_cast<long>(sb.st_mtime));
+}
+
+TEST(sys_stat, utimensat_null) {
+  TemporaryFile tf;
+  ASSERT_EQ(0, utimensat(AT_FDCWD, tf.path, nullptr, 0));
+}
+
 TEST(sys_stat, mkfifo_failure) {
   errno = 0;
   ASSERT_EQ(-1, mkfifo("/", 0666));
diff --git a/tests/unistd_test.cpp b/tests/unistd_test.cpp
index c28a46e7f..cd6231287 100644
--- a/tests/unistd_test.cpp
+++ b/tests/unistd_test.cpp
@@ -18,6 +18,7 @@
 
 #include "DoNotOptimize.h"
 #include "SignalUtils.h"
+#include "sme_utils.h"
 #include "utils.h"
 
 #include <errno.h>
@@ -1751,3 +1752,53 @@ TEST(UNISTD_TEST, copy_file_range) {
   ASSERT_EQ("hello world", content);
 #endif  // __GLIBC__
 }
+
+#if defined(__aarch64__)
+
+static bool expect_sme_off_after_fork{true};
+
+static void fork_process() {
+  const pid_t pid = fork();
+  ASSERT_NE(-1, pid);
+
+  if (pid == 0) {
+    if (expect_sme_off_after_fork) {
+      EXPECT_FALSE(sme_is_za_on());
+      EXPECT_EQ(sme_tpidr2_el0(), 0UL);
+    } else {
+      EXPECT_TRUE(sme_is_za_on());
+      EXPECT_NE(sme_tpidr2_el0(), 0UL);
+    }
+
+    exit(::testing::Test::HasFailure() ? 1 : 0);
+  } else {
+    int status;
+    ASSERT_EQ(pid, waitpid(pid, &status, 0));
+    ASSERT_TRUE(WIFEXITED(status));
+    ASSERT_EQ(0, WEXITSTATUS(status));
+  }
+}
+
+TEST(UNISTD_TEST, fork_with_sme_off) {
+  if (!sme_is_enabled()) {
+    GTEST_SKIP() << "FEAT_SME is not enabled on the device.";
+  }
+
+  __arm_za_disable();
+  expect_sme_off_after_fork = true;
+  fork_process();
+  sme_state_cleanup();
+}
+
+TEST(UNISTD_TEST, fork_with_sme_dormant_state) {
+  if (!sme_is_enabled()) {
+    GTEST_SKIP() << "FEAT_SME is not enabled on the device.";
+  }
+
+  __arm_za_disable();
+  expect_sme_off_after_fork = false;
+  sme_dormant_caller(&fork_process);
+  sme_state_cleanup();
+}
+
+#endif  // defined(__aarch64__)
diff --git a/tests/utime_test.cpp b/tests/utime_test.cpp
new file mode 100644
index 000000000..6b27e046a
--- /dev/null
+++ b/tests/utime_test.cpp
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <gtest/gtest.h>
+
+#include <utime.h>
+
+#include <android-base/file.h>
+
+TEST(utime, utime) {
+  TemporaryFile tf;
+
+  utimbuf ut;
+  ut.actime = 123;
+  ut.modtime = 456;
+  ASSERT_EQ(0, utime(tf.path, &ut)) << strerror(errno);
+
+  struct stat sb;
+  ASSERT_EQ(0, stat(tf.path, &sb));
+  ASSERT_EQ(ut.actime, static_cast<long>(sb.st_atime));
+  ASSERT_EQ(ut.modtime, static_cast<long>(sb.st_mtime));
+}
+
+TEST(utime, utime_null) {
+  TemporaryFile tf;
+  ASSERT_EQ(0, utime(tf.path, nullptr)) << strerror(errno);
+}
diff --git a/tests/wchar_test.cpp b/tests/wchar_test.cpp
index c76f80062..129901bc3 100644
--- a/tests/wchar_test.cpp
+++ b/tests/wchar_test.cpp
@@ -25,6 +25,8 @@
 #include <sys/cdefs.h>
 #include <wchar.h>
 
+#include <limits>
+
 #include "utils.h"
 
 #define NUM_WCHARS(num_bytes) ((num_bytes)/sizeof(wchar_t))
@@ -62,9 +64,28 @@ constexpr bool kLibcSupportsParsingBinaryLiterals = true;
 
 TEST(wchar, sizeof_wchar_t) {
   EXPECT_EQ(4U, sizeof(wchar_t));
+}
+
+TEST(wchar, sizeof_wint_t) {
   EXPECT_EQ(4U, sizeof(wint_t));
 }
 
+TEST(stdint, wchar_sign) {
+#if defined(__arm__) || defined(__aarch64__)
+  EXPECT_FALSE(std::numeric_limits<wchar_t>::is_signed);
+#else
+  EXPECT_TRUE(std::numeric_limits<wchar_t>::is_signed);
+#endif
+}
+
+#if !defined(__WINT_UNSIGNED__)
+#error wint_t is unsigned on Android
+#endif
+
+TEST(stdint, wint_sign) {
+  EXPECT_FALSE(std::numeric_limits<wint_t>::is_signed);
+}
+
 TEST(wchar, mbrlen) {
   char bytes[] = { 'h', 'e', 'l', 'l', 'o', '\0' };
   EXPECT_EQ(static_cast<size_t>(-2), mbrlen(&bytes[0], 0, nullptr));
@@ -1321,3 +1342,22 @@ TEST(wchar, wmemset) {
   ASSERT_EQ(dst, wmemset(dst, L'y', 0));
   ASSERT_EQ(dst[0], wchar_t(0x12345678));
 }
+
+TEST(wchar, btowc) {
+  // This function only works for single-byte "wide" characters.
+  ASSERT_EQ(wint_t('a'), btowc('a'));
+  // It _truncates_ the input to unsigned char.
+  ASSERT_EQ(wint_t(0x66), btowc(0x666));
+  // And rejects anything with the top bit set.
+  ASSERT_EQ(WEOF, btowc(0xa0));
+}
+
+TEST(wchar, wctob) {
+  // This function only works for single-byte "wide" characters.
+  ASSERT_EQ('a', wctob(L'a'));
+  // And rejects anything that would have the top bit set.
+  ASSERT_EQ(EOF, wctob(0xa0));
+  // There's no truncation here (unlike btowc()),
+  // so this is rejected rather than seen as 0x66 ('f').
+  ASSERT_EQ(EOF, wctob(0x666));
+}
diff --git a/tools/Android.bp b/tools/Android.bp
index d3ca28a5c..20b857dae 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -1,5 +1,6 @@
 package {
     default_applicable_licenses: ["bionic_tools_license"],
+    default_team: "trendy_team_native_tools_libraries",
 }
 
 license {
```

