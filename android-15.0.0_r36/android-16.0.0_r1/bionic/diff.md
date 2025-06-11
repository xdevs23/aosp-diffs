```diff
diff --git a/OWNERS b/OWNERS
index 1859b9e84..7455fd799 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,4 +6,4 @@ danalbert@google.com
 rprichard@google.com
 yabinc@google.com
 
-per-file docs/mte.md=eugenis@google.com,fmayer@google.com,pcc@google.com
+per-file docs/mte.md=fmayer@google.com,pcc@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index b4223eaf8..8aba6e4c2 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,5 +5,4 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
 notice = tools/update_notice.sh
diff --git a/README.md b/README.md
index 953e98362..4b7e42d06 100644
--- a/README.md
+++ b/README.md
@@ -268,36 +268,14 @@ A general example of adding a system call:
 https://android-review.googlesource.com/c/platform/bionic/+/2073827
 
 ### Debugging tips
-1. Key error for a new codename in libc/libc.map.txt
 
-e.g. what you add in libc/libc.map.txt is:
+If a test fails to build with an undefined symbol error,
+this is most likely the _host_ reference test against glibc,
+and you need to add an `#if defined(__GLIBC__)` to the test.
+(Search for existing examples to copy & paste,
+in particular to make sure you include the `GTEST_SKIP()`.)
 
-```
-LIBC_V { # introduced=Vanilla
-  global:
-    xxx; // the new system call you add
-} LIBC_U;
-```
-
-The error output is:
-
-```
-Traceback (most recent call last):
-  File "/path/tp/out/soong/.temp/Soong.python_qucjwd7g/symbolfile/__init__.py", line 171,
-  in decode_api_level_tag
-    decoded = str(decode_api_level(value, api_map))
-  File "/path/to/out/soong/.temp/Soong.python_qucjwd7g/symbolfile/__init__.py", line 157,
-  in decode_api_level
-    return api_map[api]
-KeyError: 'Vanilla'
-```
-
-Solution: Ask in the team and wait for the update.
-
-2. Use of undeclared identifier of the new system call in the test
-
-Possible Solution: Check everything ready in the files mentioned above first.
-Maybe glibc matters. Follow the example and try #if defined(__GLIBC__).
+When we switch to musl for the host libc, this should be less of a problem.
 
 ## Updating kernel header files
 
@@ -314,9 +292,12 @@ build your device drivers, you shouldn't modify bionic. Instead use
 
 ## Updating tzdata
 
-This is handled by the libcore team, because they own icu, and that needs to be
-updated in sync with bionic). See
-[system/timezone/README.android](https://android.googlesource.com/platform/system/timezone/+/main/README.android).
+Tzdata updates are now handled by the libcore team because it needs to be
+updated in sync with icu's copy of the data, and they own that.
+
+See
+[system/timezone/README.android](https://android.googlesource.com/platform/system/timezone/+/main/README.android)
+for more information.
 
 
 ## Verifying changes
@@ -336,14 +317,68 @@ The tests are all built from the tests/ directory. There is a separate
 directory `benchmarks/` containing benchmarks, and that has its own
 documentation on [running the benchmarks](benchmarks/README.md).
 
+### Building
+
+We assume you've already checked out the Android source tree.
+
+To build, make sure you're in the right directory and you've set up your environment:
+
+    $ cd main  # Or whatever you called your Android source tree.
+    $ source build/envsetup.sh
+
+Then choose an appropriate "lunch". If you're not testing on a device,
+two choices are particularly useful.
+
+If you want to be able to run tests and benchmarks directly on your x86-64
+host machine, use:
+
+    $ lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
+
+Alternatively, if you want to (say) check generated arm64 code without having
+a specific device in mind, use:
+
+    $ lunch aosp_cf_arm64_phone-trunk_staging-userdebug
+
+Note that in both cases,
+these targets will also build the corresponding 32-bit variant.
+See below for where the 64-bit and 32-bit files end up.
+
+See [Build Android](https://source.android.com/docs/setup/build/building)
+for more details.
+
 ### Device tests
 
-    $ mma # In $ANDROID_ROOT/bionic.
-    $ adb root && adb remount && adb sync
+Once you've completed that setup, you can build:
+
+    $ cd bionic
+    $ mm
+
+This will build everything: bionic, the benchmarks, and the tests
+(and all the dependencies).
+
+If you want to test on a device,
+the first time after flashing your device,
+you'll need to remount the filesystems to be writable:
+
+    $ adb root
+    $ adb remount
+    $ adb reboot
+    $ adb wait-for-device
+    $ adb root
+    $ adb remount
+
+Then you can sync your locally built files across:
+
+    $ adb sync
+
+And then you can run the 32-bit tests (dynamic or static):
+
     $ adb shell /data/nativetest/bionic-unit-tests/bionic-unit-tests
     $ adb shell \
         /data/nativetest/bionic-unit-tests-static/bionic-unit-tests-static
-    # Only for 64-bit targets
+
+Or the 64-bit tests (dynamic or static):
+
     $ adb shell /data/nativetest64/bionic-unit-tests/bionic-unit-tests
     $ adb shell \
         /data/nativetest64/bionic-unit-tests-static/bionic-unit-tests-static
@@ -380,15 +415,52 @@ but in cases where you really have to run CTS:
 ### Host tests
 
 The host tests require that you have `lunch`ed either an x86 or x86_64 target.
+
+(Obviously, in theory you could build for arm64 and run on an arm64 host,
+but we currently only support x86-64 host builds.)
+
+For example:
+
+    $ lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
+
+Then build as normal:
+
+    $ cd bionic
+    $ mm
+
 Note that due to ABI limitations (specifically, the size of pthread_mutex_t),
-32-bit bionic requires PIDs less than 65536. To enforce this, set /proc/sys/kernel/pid_max
-to 65536.
+32-bit bionic requires PIDs less than 65536.
+To enforce this, set /proc/sys/kernel/pid_max to 65536.
+(The tests will remind you if you forget.)
+
+The easiest way to run is to use our provided script.
+
+To run the 32-bit tests on the host:
 
     $ ./tests/run-on-host.sh 32
-    $ ./tests/run-on-host.sh 64   # For x86_64-bit *targets* only.
+
+To run the 64-bit tests on the host:
+
+    $ ./tests/run-on-host.sh 64
 
 You can supply gtest flags as extra arguments to this script.
 
+This script starts by running build/run-on-host.sh which -- despite the name --
+is actually a script to set up your host to look more like an Android device.
+In particular, it creates a /system directory with appropriate symlinks to your
+"out" directory.
+
+An alternative is to run the static binaries directly from your "out" directory.
+
+To run the static 32-bit tests:
+
+    $ ../out/target/product/vsoc_x86_64/data/nativetest/bionic-unit-tests-static/bionic-unit-tests-static
+
+To run the static 64-bit tests:
+
+    $ ../out/target/product/vsoc_x86_64/data/nativetest64/bionic-unit-tests-static/bionic-unit-tests-static
+
+
 ### Against glibc
 
 As a way to check that our tests do in fact test the correct behavior (and not
diff --git a/TEST_MAPPING b/TEST_MAPPING
index e98c2ff5a..f81d34875 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -18,6 +18,9 @@
     {
       "name": "CtsGwpAsanTestCases"
     },
+    {
+      "name": "CtsSeccompHostTestCases"
+    },
     {
       "name": "CtsTaggingHostTestCases"
     },
diff --git a/android-changes-for-ndk-developers.md b/android-changes-for-ndk-developers.md
index e9cfbacf9..24304474d 100644
--- a/android-changes-for-ndk-developers.md
+++ b/android-changes-for-ndk-developers.md
@@ -47,10 +47,12 @@ dependencies before loading their main library. Worse, until it was
 dynamic linker's caching code cached failures too, so it was necessary
 to topologically sort your libraries and load them in reverse order.
 
-If you need to support Android devices running OS versions older than
+This issue is no longer relevant to most developers,
+but if you need to support Android devices running OS versions older than
 API level 23, you might want to consider
-[ReLinker](https://github.com/KeepSafe/ReLinker) which claims to solve
-these and other problems automatically.
+[ReLinker](https://github.com/KeepSafe/ReLinker) or
+[SoLoader](https://github.com/facebook/SoLoader),
+which claim to solve these problems automatically.
 
 Alternatively, if you don't have too many dependencies, it can be easiest to
 simply link all of your code into one big library and sidestep the details of
@@ -76,6 +78,17 @@ libraries. The API level 23 dynamic linker searches the global group followed by
 the local group. This allows ASAN, for example, to ensure that it can
 intercept any symbol.
 
+This issue is no longer relevant to most developers,
+but if you need to support Android devices running OS versions older than
+API level 23, you might want to consider
+[ReLinker](https://github.com/KeepSafe/ReLinker) or
+[SoLoader](https://github.com/facebook/SoLoader),
+which claim to solve these problems automatically.
+
+Alternatively, if you don't have too many dependencies, it can be easiest to
+simply link all of your code into one big library and sidestep the details of
+library and symbol lookup changes on all past (and future) Android versions.
+
 
 ## LD_PRELOAD and 32/64 bit
 
@@ -521,3 +534,13 @@ For dynamic executables, we kept sentinel support in `crtbegin_dynamic.o` and
 `libc.so`. This ensures that executables built with newer `crtbegin_dynamic.o`
 (in NDK >= r27) work with older `libc.so` (in Android <= API level 34), and
 vice versa.
+
+
+## Only files named `lib*.so` are copied by `extractNativeLibs` (Enforced for API level <= 35)
+
+Until API level 36, PackageManager would only install files whose names match
+the glob `lib*.so` when extracting native libraries _for non-debuggable apps_.
+This was especially confusing (and hard to debug) because the restriction did
+_not_ apply if your app was debuggable. To be compatible with all API levels,
+always give files that need to be extracted a "lib" prefix and ".so" suffix,
+or avoid using `extractNativeLibs`.
diff --git a/benchmarks/stdio_benchmark.cpp b/benchmarks/stdio_benchmark.cpp
index 03f3f2903..f9ceb4c29 100644
--- a/benchmarks/stdio_benchmark.cpp
+++ b/benchmarks/stdio_benchmark.cpp
@@ -38,6 +38,13 @@ template <typename Fn>
 void ReadWriteTest(benchmark::State& state, Fn f, bool buffered) {
   size_t chunk_size = state.range(0);
 
+  // /dev/zero copies zeroes if you read from it and discards writes.
+  //
+  // This is fine for the purpose of measuring stdio overhead
+  // rather than kernel/fs performance.
+  // (Old versions of stdio would copy reads/writes larger than
+  // the stdio buffer through the stdio buffer in chunks,
+  // rather than directly to the user's destination.)
   FILE* fp = fopen("/dev/zero", "r+e");
   __fsetlocking(fp, FSETLOCKING_BYCALLER);
   char* buf = new char[chunk_size];
diff --git a/docs/32-bit-abi.md b/docs/32-bit-abi.md
index 7a96e2fec..efc681564 100644
--- a/docs/32-bit-abi.md
+++ b/docs/32-bit-abi.md
@@ -66,8 +66,8 @@ in the 64-bit ABI even though they're identical to the non-`64` names.
 ## `sigset_t` is too small for real-time signals
 
 On 32-bit Android, `sigset_t` is too small for ARM and x86. This means that
-there is no support for real-time signals in 32-bit code. Android P (API
-level 28) adds `sigset64_t` and a corresponding function for every function
+there is no support for real-time signals in 32-bit code.
+API level 28 adds `sigset64_t` and a corresponding function for every function
 that takes a `sigset_t` (so `sigprocmask64` takes a `sigset64_t` where
 `sigprocmask` takes a `sigset_t`).
 
diff --git a/docs/README.md b/docs/README.md
index 2825eac4e..d66fa68b1 100644
--- a/docs/README.md
+++ b/docs/README.md
@@ -17,6 +17,7 @@ C library, math library, and dynamic linker.
   which detects use-after-close() bugs.
 * [fdtrack](fdtrack.md) - bionic's file descriptor tracker,
   which helps debug file descriptor leaks.
+* [C23](c23.md) - dealing with C23's breaking changes.
 
 ## Maintainer documentation
 
diff --git a/docs/c23.md b/docs/c23.md
new file mode 100644
index 000000000..9ed570db7
--- /dev/null
+++ b/docs/c23.md
@@ -0,0 +1,97 @@
+# C23 language changes
+
+## Breaking changes
+
+### `void foo()` now means `void foo(void)`
+In C17 and earlier, `void foo()` means "I haven't yet told you how many
+arguments this function has". In C23, it's equivalent to C++ and means "this
+function has no arguments". This may surface as a function pointer type
+mismatch, because previously `()` matched functions taking any arguments,
+whereas in C23 it only matches functions taking no arguments.
+
+Fix: in cases where your function does have arguments, declare them.
+
+### Undeclared identifiers are now errors
+In C17 and earlier, calling `foo(123)` without a declaration for `foo()`
+produced a warning. In C23 this is an error instead. One common special case of
+this is code that's explicitly ignoring such warnings to call functions that are
+GNU extensions; such code should be fixed to ensure that `_GNU_SOURCE` is
+defined before any header is included instead (often by adding `-D_GNU_SOURCE`
+to the cflags in the build file).
+
+Fix: add the missing forward declaration or `#include` (or `-D_GNU_SOURCE`).
+
+### `bool`/`true`/`false` are now keywords
+In C17 and earlier, only code that included `<stdbool.h>` would have standard
+definitions for these (typically macros for `_Bool`/`1`/`0`). In C23 these are
+keywords and should no longer be defined in your code.
+
+Fix: delete any definitions of `bool`/`true`/`false` if you only need to build
+as C23, or switch to `#include <stdbool.h>` for compatibility back to C99.
+
+### `false` is no longer `0`
+In C17 and earlier, it was common for true and false to be defined as 1 and 0
+(either by `<stdbool.h>` or by user-provided `#define`/`enum`). This meant that
+`false` (as 0) could be implicitly converted to `NULL`. In C23, a function that
+returns (or takes) a pointer can no longer return `false` (or be passed
+`false`).
+
+Fix: return/pass `NULL` (or `nullptr` for C23-only code) instead of `false`
+in pointer contexts.
+
+### `unreachable()` is now a predefined function-like macro in `<stddef.h>`
+In C17 and earlier, `unreachable()` was available for your own macros/functions.
+In C23 there's a standard definition.
+
+Fix: delete your `unreachable()` if it was just equivalent to
+`__builtin_unreachable()` or rename it if it had different behavior.
+
+### K&R prototypes are no longer valid
+In C17 and earlier, K&R function prototypes were deprecated but still allowed.
+In C23 K&R prototypes are no longer allowed.
+
+Fix: rewrite any K&R prototypes as ANSI/ISO prototypes.
+
+
+## Non-breaking changes
+
+### Unused function parameters can now be anonymous
+In C17 and earlier you'd have to use `__attribute__((unused))` on an unused
+function parameter. In C23 you can just omit the parameter name instead,
+like `void* pthread_callback_fn(void*) {` (as in C++).
+
+### New standard attributes
+C23 adds `[[deprecated("reason")]]`, `[[fallthrough]]`, `[[nodiscard]]` (the
+equivalent of the clang attribute `warn_unused_result`),
+`[[maybe_unused]]` (the equivalent of the clang attribute `unused`),
+and `[[noreturn]]` (equivalent to C11 `_Noreturn`).
+Most of these have been available before via `__attribute__` or other syntax,
+but are now standard.
+
+### `#embed`
+You can now include binary data directly into an array or string: https://en.cppreference.com/w/c/preprocessor/embed
+
+### `void foo(...)` is now allowed
+In C17 and earlier, a varargs function needed a non-varargs argument.
+In C23 this is allowed (as in C++).
+
+### `enum` base types
+You can now say `enum E : long { ... }` to explicitly choose the base type of
+your enum (as in C++, and already supported by clang as an extension).
+
+### `nullptr` constant
+There is now a `nullptr` constant (as in C++),
+and a corresponding `nullptr_t` type for that constant.
+
+### `constexpr`
+There is now a limited form of `constexpr` for defining `const` variables
+(similar to, but much more limited than C++ constexpr).
+
+
+## Library changes
+
+Library changes are not covered here because bionic does not make library
+functionality available based on target C version, since the target API level
+distinctions are confusing enough already.
+
+See [status.md](status.md) for what functionality went into which API level.
diff --git a/docs/defines.md b/docs/defines.md
index 65cc8738b..be48ad8ad 100644
--- a/docs/defines.md
+++ b/docs/defines.md
@@ -21,6 +21,15 @@ of the OS and needs to behave differently on the host than on the device.
 Genuine cases are quite rare, and `__BIONIC__` is often more specific (but
 remember that it is possible -- if unusual -- to use bionic on the host).
 
+## `ANDROID` (rarely useful)
+
+Not to be confused with `__ANDROID__`, the similar-looking but very different
+`ANDROID` is _not_ set by the toolchain or NDK build system. This is set by
+the AOSP build system for both device and host code. For that reason, it's
+not typically very useful except as a signal when patching third-party code ---
+but even then, you'd typically _not_ want this because it's true for both
+device and host.
+
 ## `__ANDROID_API__`
 
 If your code can be built targeting a variety of different OS versions, use
diff --git a/docs/elf-tls.md b/docs/elf-tls.md
index 450f362b8..2e0b99809 100644
--- a/docs/elf-tls.md
+++ b/docs/elf-tls.md
@@ -478,7 +478,7 @@ XXX: Shared objects are less of a problem.
    this.)
  * On arm64, the primary TLS relocation (R_AARCH64_TLSDESC) is [confused with an obsolete
    R_AARCH64_TLS_DTPREL32 relocation][R_AARCH64_TLS_DTPREL32] and is [quietly ignored].
- * Android P [added compatibility checks] for TLS symbols and `DT_TLSDESC_{GOT|PLT}` entries.
+ * API level 28 [added compatibility checks] for TLS symbols and `DT_TLSDESC_{GOT|PLT}` entries.
 
 XXX: A dynamic executable using ELF TLS would have a PT_TLS segment and no other distinguishing
 marks, so running it on an older platform would result in memory corruption. Should we add something
@@ -572,7 +572,7 @@ specialized `__tls_get_addr` and TLSDESC resolver functions.
 ## Bionic Memory Layout Conflicts with Common TLS Layout
 
 Bionic already allocates thread-specific data in a way that conflicts with TLS variants 1 and 2:
-![Bionic TLS Layout in Android P](img/bionic-tls-layout-in-p.png)
+![Bionic TLS Layout in API level 28](img/bionic-tls-layout-in-p.png)
 
 TLS variant 1 allocates everything after the TP to ELF TLS (except the first two words), and variant
 2 allocates everything before the TP. Bionic currently allocates memory before and after the TP to
@@ -608,8 +608,8 @@ There are issues with rearranging this memory:
    searching for its TP-relative offset, which it assumes is nonnegative:
     * On arm32/arm64, it creates a pthread key, sets it to a magic value, then scans forward from
       the thread pointer looking for it. [The scan count was bumped to 384 to fix a reported
-      breakage happening with Android N.](https://go-review.googlesource.com/c/go/+/38636) (XXX: I
-      suspect the actual platform breakage happened with Android M's [lock-free pthread key
+      breakage happening with API level 24.](https://go-review.googlesource.com/c/go/+/38636) (XXX: I
+      suspect the actual platform breakage happened with API level 23's [lock-free pthread key
       work][bionic-lockfree-keys].)
     * On x86/x86-64, it uses a fixed offset from the thread pointer (TP+0xf8 or TP+0x1d0) and
       creates pthread keys until one of them hits the fixed offset.
@@ -803,7 +803,7 @@ slot with this magic value. This hack doesn't appear to work, however. The runti
 key, but apps segfault. Perhaps the Go runtime expects its "g" variable to be zero-initialized ([one
 example][go-tlsg-zero]). With this hack, it's never zero, but with its current allocation strategy,
 it is typically zero. After [Bionic's pthread key system was rewritten to be
-lock-free][bionic-lockfree-keys] for Android M, though, it's not guaranteed, because a key could be
+lock-free][bionic-lockfree-keys] for API level 23, though, it's not guaranteed, because a key could be
 recycled.
 
 [go-tlsg-zero]: https://go.googlesource.com/go/+/5bc1fd42f6d185b8ff0201db09fb82886978908b/src/runtime/asm_arm64.s#980
diff --git a/docs/native_allocator.md b/docs/native_allocator.md
index 13d973890..75a1a70b5 100644
--- a/docs/native_allocator.md
+++ b/docs/native_allocator.md
@@ -9,9 +9,14 @@ at least the
 
 It is important to note that there are two modes for a native allocator
 to run in on Android. The first is the normal allocator, the second is
-called the svelte config, which is designed to run on memory constrained
-systems and be a bit slower, but take less RSS. To enable the svelte config,
-add this line to the `BoardConfig.mk` for the given target:
+called the low memory config, which is designed to run on memory constrained
+systems and be a bit slower, but take less RSS. To enable the low memory
+config, add this line to the `BoardConfig.mk` for the given target:
+
+    MALLOC_LOW_MEMORY := true
+
+This is valid starting with Android V (API level 35), before that the
+way to enable the low memory config is:
 
     MALLOC_SVELTE := true
 
@@ -135,6 +140,20 @@ a limited amount of address space available in 32 bit apps, and there have
 been allocator bugs that cause memory failures when too much virtual
 address space is consumed. For 64 bit executables, this can be ignored.
 
+NOTE: The default native allocator operates differently in an application
+versus command-line tools running in the shell. In order to run the same
+as an application, follow these instructions:
+
+    > adb shell
+    # export MALLOC_USE_APP_DEFAULTS=1
+    # <Run command-line benchmarks>
+
+Running without setting this environment variable can result in different
+performance and even different RSS usage for the benchmarks mentioned below.
+The environment variable has only been available since API level 36.
+Applications using different native allocator defaults than command-line
+tools has been present since API level 26 (Android O).
+
 ### Bionic Benchmarks
 These are the microbenchmarks that are part of the bionic benchmarks suite of
 benchmarks. These benchmarks can be built using this command:
diff --git a/docs/status.md b/docs/status.md
index e7111d964..034f115e1 100644
--- a/docs/status.md
+++ b/docs/status.md
@@ -59,6 +59,9 @@ list of POSIX functions implemented by glibc but not by bionic.
 
 Current libc symbols: https://android.googlesource.com/platform/bionic/+/main/libc/libc.map.txt
 
+New libc functions in API level 37:
+  * New system call wrappers: `sched_getattr()`/`sched_setattr()` (`<sched.h>`).
+
 New libc functions in API level 36:
   * `qsort_r`, `sig2str`/`str2sig` (POSIX Issue 8 additions).
   * GNU/BSD extension `lchmod`.
diff --git a/libc/Android.bp b/libc/Android.bp
index c34023c37..f5624efc1 100644
--- a/libc/Android.bp
+++ b/libc/Android.bp
@@ -104,8 +104,6 @@ cc_defaults {
     },
 
     apex_available: ["com.android.runtime"],
-
-    tidy_disabled_srcs: ["upstream-*/**/*.c"],
 }
 
 // Workaround for b/24465209.
@@ -225,12 +223,6 @@ cc_library_static {
         "bionic/getauxval.cpp",
     ],
     arch: {
-        arm64: {
-            srcs: ["arch-arm64/bionic/__set_tls.c"],
-        },
-        riscv64: {
-            srcs: ["arch-riscv64/bionic/__set_tls.c"],
-        },
         x86: {
             srcs: [
                 "arch-x86/bionic/__libc_init_sysinfo.cpp",
@@ -238,9 +230,6 @@ cc_library_static {
                 "arch-x86/bionic/__set_tls.cpp",
             ],
         },
-        x86_64: {
-            srcs: ["arch-x86_64/bionic/__set_tls.c"],
-        },
     },
 
     defaults: ["libc_defaults"],
@@ -480,7 +469,6 @@ cc_library_static {
         "upstream-netbsd/lib/libc/stdlib/nrand48.c",
         "upstream-netbsd/lib/libc/stdlib/_rand48.c",
         "upstream-netbsd/lib/libc/stdlib/rand_r.c",
-        "upstream-netbsd/lib/libc/stdlib/reallocarr.c",
         "upstream-netbsd/lib/libc/stdlib/seed48.c",
         "upstream-netbsd/lib/libc/stdlib/srand48.c",
     ],
@@ -622,7 +610,6 @@ cc_library_static {
     arch: {
         arm: {
             srcs: [
-                "upstream-openbsd/lib/libc/string/memchr.c",
                 "upstream-openbsd/lib/libc/string/stpncpy.c",
                 "upstream-openbsd/lib/libc/string/strncat.c",
                 "upstream-openbsd/lib/libc/string/strncmp.c",
@@ -790,15 +777,56 @@ cc_library_static {
                 "arch-arm64/string/__memset_chk.S",
             ],
         },
-        riscv64: {
-            srcs: [
-                "arch-riscv64/string/__memset_chk.S",
-                "arch-riscv64/string/__memcpy_chk.S",
-            ],
-        },
     },
 }
 
+// ========================================================
+// icu4x_bionic.a - Thin Rust wrapper around ICU4X
+// ========================================================
+
+rust_ffi_static {
+    name: "libicu4x_bionic",
+    crate_name: "icu4x_bionic",
+    crate_root: "bionic/icu4x.rs",
+    edition: "2021",
+    features: [],
+    rustlibs: [
+        "//external/rust/android-crates-io/crates/icu_casemap:libicu_casemap",
+        "//external/rust/android-crates-io/crates/icu_collections:libicu_collections",
+        "//external/rust/android-crates-io/crates/icu_properties:libicu_properties",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
+    vendor_available: true,
+    product_available: true,
+    ramdisk_available: true,
+    vendor_ramdisk_available: true,
+    recovery_available: true,
+    native_bridge_supported: true,
+    sdk_version: "minimum",
+    defaults: ["linux_bionic_supported"],
+}
+
+// current rust implementation detail; will be removed as part of a larger cleanup later
+// go/android-mto-staticlibs-in-make
+cc_rustlibs_for_make {
+    name: "libstatic_rustlibs_for_make",
+    whole_static_libs: ["libicu4x_bionic"],
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
+    vendor_available: true,
+    product_available: true,
+    ramdisk_available: true,
+    vendor_ramdisk_available: true,
+    recovery_available: true,
+    native_bridge_supported: true,
+    defaults: ["linux_bionic_supported"],
+}
+
 // ========================================================
 // libc_bionic.a - home-grown C library code
 // ========================================================
@@ -880,7 +908,6 @@ cc_library_static {
         "bionic/grp_pwd_file.cpp",
         "bionic/heap_zero_init.cpp",
         "bionic/iconv.cpp",
-        "bionic/icu_wrappers.cpp",
         "bionic/ifaddrs.cpp",
         "bionic/inotify_init.cpp",
         "bionic/ioctl.cpp",
@@ -1083,11 +1110,6 @@ cc_library_static {
                 "arch-arm/krait/bionic/memset.S",
 
                 "arch-arm/kryo/bionic/memcpy.S",
-
-                "bionic/strchr.cpp",
-                "bionic/strchrnul.cpp",
-                "bionic/strnlen.cpp",
-                "bionic/strrchr.cpp",
             ],
         },
         arm64: {
@@ -1110,40 +1132,21 @@ cc_library_static {
                 "arch-riscv64/bionic/syscall.S",
                 "arch-riscv64/bionic/vfork.S",
 
-                "arch-riscv64/string/memchr_v.S",
-                "arch-riscv64/string/memcmp_v.S",
-                "arch-riscv64/string/memcpy_v.S",
-                "arch-riscv64/string/memmove_v.S",
-                "arch-riscv64/string/memset_v.S",
-                "arch-riscv64/string/stpcpy_v.S",
-                "arch-riscv64/string/strcat_v.S",
-                "arch-riscv64/string/strchr_v.S",
-                "arch-riscv64/string/strcmp_v.S",
-                "arch-riscv64/string/strcpy_v.S",
-                "arch-riscv64/string/strlen_v.S",
-                "arch-riscv64/string/strncat_v.S",
-                "arch-riscv64/string/strncmp_v.S",
-                "arch-riscv64/string/strncpy_v.S",
-                "arch-riscv64/string/strnlen_v.S",
-
-                "arch-riscv64/string/memchr.c",
-                "arch-riscv64/string/memcmp.c",
-                "arch-riscv64/string/memcpy.c",
-                "arch-riscv64/string/memmove.c",
-                "arch-riscv64/string/memset.c",
-                "arch-riscv64/string/stpcpy.c",
-                "arch-riscv64/string/strcat.c",
-                "arch-riscv64/string/strchr.c",
-                "arch-riscv64/string/strcmp.c",
-                "arch-riscv64/string/strcpy.c",
-                "arch-riscv64/string/strlen.c",
-                "arch-riscv64/string/strncat.c",
-                "arch-riscv64/string/strncmp.c",
-                "arch-riscv64/string/strncpy.c",
-                "arch-riscv64/string/strnlen.c",
-
-                "bionic/strchrnul.cpp",
-                "bionic/strrchr.cpp",
+                "arch-riscv64/string/memchr.S",
+                "arch-riscv64/string/memcmp.S",
+                "arch-riscv64/string/memcpy.S",
+                "arch-riscv64/string/memmove.S",
+                "arch-riscv64/string/memset.S",
+                "arch-riscv64/string/stpcpy.S",
+                "arch-riscv64/string/strcat.S",
+                "arch-riscv64/string/strchr.S",
+                "arch-riscv64/string/strcmp.S",
+                "arch-riscv64/string/strcpy.S",
+                "arch-riscv64/string/strlen.S",
+                "arch-riscv64/string/strncat.S",
+                "arch-riscv64/string/strncmp.S",
+                "arch-riscv64/string/strncpy.S",
+                "arch-riscv64/string/strnlen.S",
             ],
         },
 
@@ -1157,17 +1160,13 @@ cc_library_static {
                 "arch-x86/bionic/vfork.S",
                 "arch-x86/bionic/__x86.get_pc_thunk.S",
 
-                "arch-x86/string/sse2-memchr-atom.S",
                 "arch-x86/string/sse2-memmove-slm.S",
                 "arch-x86/string/sse2-memset-slm.S",
                 "arch-x86/string/sse2-stpcpy-slm.S",
                 "arch-x86/string/sse2-stpncpy-slm.S",
-                "arch-x86/string/sse2-strchr-atom.S",
                 "arch-x86/string/sse2-strcpy-slm.S",
                 "arch-x86/string/sse2-strlen-slm.S",
                 "arch-x86/string/sse2-strncpy-slm.S",
-                "arch-x86/string/sse2-strnlen-atom.S",
-                "arch-x86/string/sse2-strrchr-atom.S",
 
                 "arch-x86/string/ssse3-memcmp-atom.S",
                 "arch-x86/string/ssse3-strcat-atom.S",
@@ -1176,8 +1175,6 @@ cc_library_static {
                 "arch-x86/string/ssse3-strncmp-atom.S",
 
                 "arch-x86/string/sse4-memcmp-slm.S",
-
-                "bionic/strchrnul.cpp",
             ],
         },
         x86_64: {
@@ -1222,6 +1219,7 @@ cc_library_static {
     whole_static_libs: [
         "//external/llvm-libc:llvmlibc",
         "libsystemproperties",
+        "libicu4x_bionic",
     ],
 
     cppflags: ["-Wold-style-cast"],
@@ -1377,9 +1375,6 @@ cc_defaults {
         arm64: {
             srcs: ["arch-arm64/dynamic_function_dispatch.cpp"],
         },
-        riscv64: {
-            srcs: ["arch-riscv64/dynamic_function_dispatch.cpp"],
-        },
     },
     // Prevent the compiler from inserting calls to libc/taking the address of
     // a jump table from within an ifunc (or, in the static case, code that
@@ -1476,7 +1471,6 @@ filegroup {
         "bionic/android_mallopt.cpp",
         "bionic/gwp_asan_wrappers.cpp",
         "bionic/heap_tagging.cpp",
-        "bionic/icu.cpp",
         "bionic/malloc_common.cpp",
         "bionic/malloc_common_dynamic.cpp",
         "bionic/android_profiling_dynamic.cpp",
@@ -1495,7 +1489,6 @@ filegroup {
         "bionic/android_mallopt.cpp",
         "bionic/gwp_asan_wrappers.cpp",
         "bionic/heap_tagging.cpp",
-        "bionic/icu_static.cpp",
         "bionic/malloc_common.cpp",
         "bionic/malloc_limit.cpp",
     ],
@@ -1663,9 +1656,7 @@ cc_library {
     // which is default module for soong-defined system image.
     visibility: [
         "//bionic/apex",
-        "//build/make/target/product/generic",
-        //TODO(b/381985636) : Remove visibility to Soong-defined GSI once resolved
-        "//build/make/target/product/gsi",
+        "//visibility:any_system_partition",
     ],
 }
 
@@ -2123,6 +2114,7 @@ cc_library_static {
 
 // This library contains the following unresolved symbols:
 //     __errno
+//     __x86_shared_cache_size_half (x86_64 only)
 //     abort
 //     async_safe_fatal_va_list
 cc_library_static {
@@ -2142,14 +2134,37 @@ cc_library_static {
         "bionic/strtol.cpp",
     ],
     arch: {
+        arm: {
+            enabled: false,
+        },
         arm64: {
             srcs: [
                 "arch-arm64/string/__memcpy_chk.S",
             ],
         },
-        riscv64: {
+        x86: {
+            enabled: false,
+        },
+        x86_64: {
+            asflags: [
+                // Statically choose the SSE2 memset_generic as memset for
+                // baremetal, where we do not have the dynamic function
+                // dispatch machinery.
+                "-Dmemset_generic=memset",
+            ],
             srcs: [
-                "arch-riscv64/string/__memcpy_chk.S",
+                "arch-x86_64/string/sse2-memmove-slm.S",
+                "arch-x86_64/string/sse2-memset-slm.S",
+                "arch-x86_64/string/sse2-stpcpy-slm.S",
+                "arch-x86_64/string/sse2-stpncpy-slm.S",
+                "arch-x86_64/string/sse2-strcat-slm.S",
+                "arch-x86_64/string/sse2-strcpy-slm.S",
+                "arch-x86_64/string/sse2-strlen-slm.S",
+                "arch-x86_64/string/sse2-strncat-slm.S",
+                "arch-x86_64/string/sse2-strncpy-slm.S",
+                "arch-x86_64/string/sse4-memcmp-slm.S",
+                "arch-x86_64/string/ssse3-strcmp-slm.S",
+                "arch-x86_64/string/ssse3-strncmp-slm.S",
             ],
         },
     },
@@ -2304,6 +2319,9 @@ cc_defaults {
         "-E",
         "-Wall",
         "-Werror",
+        // Soong implicitly adds a -c argument that we override with -E.
+        // Suppress Clang's error about the unused -c argument.
+        "-Wno-unused-command-line-argument",
         "-nostdinc",
     ],
 }
@@ -2413,7 +2431,7 @@ genrule {
     name: "generate_app_zygote_blocklist",
     out: ["SECCOMP_BLOCKLIST_APP_ZYGOTE.TXT"],
     srcs: ["SECCOMP_BLOCKLIST_APP.TXT"],
-    cmd: "grep -v '^int[ \t]*setresgid' $(in) > $(out)",
+    cmd: "grep -v '^setresgid' $(in) > $(out)",
 }
 
 filegroup {
@@ -2721,6 +2739,7 @@ cc_library {
     },
 }
 
+// TODO: add this directly to musl like libexecinfo and libb64?
 cc_library_host_static {
     name: "libfts",
     srcs: [
@@ -2733,6 +2752,7 @@ cc_library_host_static {
         "upstream-openbsd/android/include",
     ],
     cflags: [
+        "-std=gnu99",
         "-include openbsd-compat.h",
         "-Wno-unused-parameter",
     ],
@@ -2772,6 +2792,7 @@ cc_library_host_static {
         "upstream-openbsd/android/include",
     ],
     cflags: [
+        "-std=gnu99",
         "-include openbsd-compat.h",
     ],
     enabled: false,
diff --git a/libc/NOTICE b/libc/NOTICE
index bca4891ed..c869a31ae 100644
--- a/libc/NOTICE
+++ b/libc/NOTICE
@@ -890,6 +890,22 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
+Copyright (C) 2024 The Android Open Source Project
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+
+-------------------------------------------------------------------
+
 Copyright (C) 2024 The Android Open Source Project
 All rights reserved.
 
@@ -4106,35 +4122,6 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 2015 Joerg Sonnenberger <joerg@NetBSD.org>.
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions
-are met:
-
-1. Redistributions of source code must retain the above copyright
-   notice, this list of conditions and the following disclaimer.
-2. Redistributions in binary form must reproduce the above copyright
-   notice, this list of conditions and the following disclaimer in
-   the documentation and/or other materials provided with the
-   distribution.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
-``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
-LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
-FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
-COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
-INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
-BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
-AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
-OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
-OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-SUCH DAMAGE.
-
--------------------------------------------------------------------
-
 Copyright (c) 2015 Nuxi, https://nuxi.nl/
 
 Redistribution and use in source and binary forms, with or without
@@ -4714,40 +4701,6 @@ SUCH DAMAGE.
 
 SPDX-License-Identifier: BSD-3-Clause
 
-Copyright (c) 1990, 1993
-   The Regents of the University of California.  All rights reserved.
-
-This code is derived from software contributed to Berkeley by
-Mike Hibler and Chris Torek.
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
 Copyright (c) 1992, 1993
    The Regents of the University of California.  All rights reserved.
 
diff --git a/libc/SECCOMP_ALLOWLIST_APP.TXT b/libc/SECCOMP_ALLOWLIST_APP.TXT
index 80b15b201..a46a33cb4 100644
--- a/libc/SECCOMP_ALLOWLIST_APP.TXT
+++ b/libc/SECCOMP_ALLOWLIST_APP.TXT
@@ -4,59 +4,59 @@
 # This file is processed by a python script named genseccomp.py.
 
 # Needed for debugging 32-bit Chrome
-int	pipe(int pipefd[2])	lp32
+pipe(int pipefd[2])	lp32
 
 # b/34651972
-int	access(const char *pathname, int mode)	lp32
-int	stat64(const char*, struct stat64*)	lp32
+access(const char *pathname, int mode)	lp32
+stat64(const char*, struct stat64*)	lp32
 
 # b/34813887
-int	open(const char *path, int oflag, ... ) lp32,x86_64
-int	getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) lp32,x86_64
+open(const char *path, int oflag, ... ) lp32,x86_64
+getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) lp32,x86_64
 
 # b/34719286
-int	eventfd(unsigned int initval, int flags)	lp32
+eventfd(unsigned int initval, int flags)	lp32
 
 # b/34817266
-int	epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)	lp32
+epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)	lp32
 
 # b/34908783
-int	epoll_create(int size)	lp32
+epoll_create(int size)	lp32
 
 # b/34979910
-int	creat(const char *pathname, mode_t mode)	lp32
-int	unlink(const char *pathname)	lp32
+creat(const char *pathname, mode_t mode)	lp32
+unlink(const char *pathname)	lp32
 
 # b/35059702
-int	lstat64(const char*, struct stat64*)	lp32
+lstat64(const char*, struct stat64*)	lp32
 
 # b/35217603
-int	fcntl(int fd, int cmd, ... /* arg */ )	lp32
-pid_t	fork()	lp32
-int	poll(struct pollfd *fds, nfds_t nfds, int timeout)	lp32
+fcntl(int fd, int cmd, ... /* arg */ )	lp32
+fork()	lp32
+poll(struct pollfd *fds, nfds_t nfds, int timeout)	lp32
 
 # b/35906875
-int	inotify_init()	lp32
-uid_t	getuid()	lp32
+inotify_init()	lp32
+getuid()	lp32
 
 # b/36435222
-int	remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags)	lp32
+remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags)	lp32
 
 # b/36449658
-int	rename(const char *oldpath, const char *newpath)	lp32
+rename(const char *oldpath, const char *newpath)	lp32
 
 # b/36726183. Note arm does not support mmap
-void*	mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)	x86
+mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)	x86
 
 # b/37769298
-int dup2(int oldfd, int newfd)	lp32
+dup2(int oldfd, int newfd)	lp32
 
 # b/62779795
-int compat_select:_newselect(int n, unsigned long* inp, unsigned long* outp, unsigned long* exp, struct timeval* timeout) lp32
+compat_select:_newselect(int n, unsigned long* inp, unsigned long* outp, unsigned long* exp, struct timeval* timeout) lp32
 
 # b/62090571
-int mkdir(const char *pathname, mode_t mode)	lp32
+mkdir(const char *pathname, mode_t mode)	lp32
 
 # Not used by bionic in U because riscv64 doesn't have it, but still
 # used by legacy apps (http://b/254179267).
-int renameat(int, const char*, int, const char*)  arm,x86,arm64,x86_64
+renameat(int, const char*, int, const char*)  arm,x86,arm64,x86_64
diff --git a/libc/SECCOMP_ALLOWLIST_COMMON.TXT b/libc/SECCOMP_ALLOWLIST_COMMON.TXT
index 1d58475a2..41db4e86a 100644
--- a/libc/SECCOMP_ALLOWLIST_COMMON.TXT
+++ b/libc/SECCOMP_ALLOWLIST_COMMON.TXT
@@ -4,81 +4,83 @@
 # This file is processed by a python script named genseccomp.py.
 
 # Syscalls needed to boot android
-int	pivot_root(const char*, const char*)	lp64
-int	ioprio_get(int, int)	lp64
-int	ioprio_set(int, int, int)	lp64
+pivot_root(const char*, const char*)	lp64
+ioprio_get(int, int)	lp64
+ioprio_set(int, int, int)	lp64
 
 # Syscalls used internally by bionic, but not exposed directly.
-pid_t	gettid()	all
-int	futex(int*, int, int, const timespec*, int*, int)	all
-pid_t	clone(int (*)(void*), void*, int, void*, ...) all
-int	sigreturn(unsigned long)	lp32
-int	rt_sigreturn(unsigned long)	all
-int	rt_tgsigqueueinfo(pid_t, pid_t, int, siginfo_t*)	all
-int	restart_syscall()	all
+gettid()	all
+futex(int*, int, int, const timespec*, int*, int)	all
+clone(int (*)(void*), void*, int, void*, ...) all
+sigreturn(unsigned long)	lp32
+rt_sigreturn(unsigned long)	all
+rt_tgsigqueueinfo(pid_t, pid_t, int, siginfo_t*)	all
+restart_syscall()	all
 
 # The public API doesn't set errno, so we call this via inline assembler.
-int riscv_hwprobe(riscv_hwprobe*, size_t, size_t, unsigned long*, unsigned) riscv64
+riscv_hwprobe(riscv_hwprobe*, size_t, size_t, unsigned long*, unsigned) riscv64
 
 # vfork is used by bionic (and java.lang.ProcessBuilder) on some
 # architectures. (The others use clone(2) directly instead.)
-pid_t	vfork()	arm,x86,x86_64
+vfork()	arm,x86,x86_64
 
 # Needed for performance tools.
-int	perf_event_open(perf_event_attr*, pid_t, int, int, unsigned long)	all
+perf_event_open(perf_event_attr*, pid_t, int, int, unsigned long)	all
 
 # Needed for strace.
-int	tkill(int, int)	all
+tkill(int, int)	all
 
 # Needed for a CTS test of seccomp (b/34763393).
-int	seccomp(unsigned, unsigned, void*)	all
+seccomp(unsigned, unsigned, void*)	all
 
 # TODO: remove these now we've updated the toolchain (http://b/229989971).
-int open(const char*, int, ...)  arm,x86,x86_64
-int stat64(const char*, stat64*)  arm,x86
-ssize_t readlink(const char*, char*, size_t)  arm,x86,x86_64
-int stat(const char*, stat*)  arm,x86,x86_64
+open(const char*, int, ...)  arm,x86,x86_64
+stat64(const char*, stat64*)  arm,x86
+readlink(const char*, char*, size_t)  arm,x86,x86_64
+stat(const char*, stat*)  arm,x86,x86_64
 
 #
 # (Potentially) useful new syscalls which we don't yet use in bionic.
 #
 
 # Since Linux 2.5, not in glibc.
-int io_setup(unsigned, aio_context_t*) all
-int io_destroy(aio_context_t) all
-int io_submit(aio_context_t, long,  iocb**) all
-int io_getevents(aio_context_t, long, long, io_event*, timespec*) all
-int io_cancel(aio_context_t, iocb*, io_event*) all
-# Since Linux 3.14, not in glibc.
-int sched_getattr(pid_t, sched_attr*, unsigned) all
-int sched_setattr(pid_t, sched_attr*, unsigned, unsigned) all
+io_setup(unsigned, aio_context_t*) all
+io_destroy(aio_context_t) all
+io_submit(aio_context_t, long,  iocb**) all
+io_getevents(aio_context_t, long, long, io_event*, timespec*) all
+io_cancel(aio_context_t, iocb*, io_event*) all
 # Since Linux 3.19, not in glibc (and not really needed to implement fexecve).
-int execveat(int, const char*, char* const*, char* const*, int)  all
+execveat(int, const char*, char* const*, char* const*, int)  all
 # Since Linux 4.3, not in glibc. Probed for and conditionally used by ART.
-int membarrier(int, int) all
-int userfaultfd(int) all
+membarrier(int, int) all
+userfaultfd(int) all
 # Since Linux 5.1, not in glibc. Not used by bionic, and not likely ever
 # to be (because the last thing anyone needs is a new 32-bit ABI in the
 # 2020s!) but http://b/138781460 showed cuttlefish needed at least the
 # clock_gettime64 syscall.
-int clock_gettime64(clockid_t, timespec64*) lp32
-int clock_settime64(clockid_t, const timespec64*) lp32
-int clock_adjtime64(clockid_t, timex64*) lp32
-int clock_getres_time64(clockid_t, timespec64*) lp32
-int clock_nanosleep_time64(clockid_t, int, const timespec64*, timespec*) lp32
-int timer_gettime64(__kernel_timer_t, itimerspec64*) lp32
-int timer_settime64(__kernel_timer_t, int, const itimerspec64*, itimerspec64*) lp32
-int timerfd_gettime64(int, itimerspec64*) lp32
-int timerfd_settime64(int, int, const itimerspec64*, itimerspec64*) lp32
-int utimensat_time64(int, const char*, const timespec64[2], int) lp32
-int pselect6_time64(int, fd_set*, fd_set*, timespec64*, void*) lp32
-int ppoll_time64(pollfd*, unsigned int, timespec64*, const sigset64_t*, size_t) lp32
-int recvmmsg_time64(int, mmsghdr*, unsigned int, int, const timespec64*) lp32
-int rt_sigtimedwait_time64(const sigset64_t*, siginfo_t*, const timespec64*, size_t) lp32
-int futex_time64(int*, int, int, const timespec64*, int*, int) lp32
-int sched_rr_get_interval_time64(pid_t, timespec64*) lp32
+clock_gettime64(clockid_t, timespec64*) lp32
+clock_settime64(clockid_t, const timespec64*) lp32
+clock_adjtime64(clockid_t, timex64*) lp32
+clock_getres_time64(clockid_t, timespec64*) lp32
+clock_nanosleep_time64(clockid_t, int, const timespec64*, timespec*) lp32
+timer_gettime64(__kernel_timer_t, itimerspec64*) lp32
+timer_settime64(__kernel_timer_t, int, const itimerspec64*, itimerspec64*) lp32
+timerfd_gettime64(int, itimerspec64*) lp32
+timerfd_settime64(int, int, const itimerspec64*, itimerspec64*) lp32
+utimensat_time64(int, const char*, const timespec64[2], int) lp32
+pselect6_time64(int, fd_set*, fd_set*, timespec64*, void*) lp32
+ppoll_time64(pollfd*, unsigned int, timespec64*, const sigset64_t*, size_t) lp32
+recvmmsg_time64(int, mmsghdr*, unsigned int, int, const timespec64*) lp32
+rt_sigtimedwait_time64(const sigset64_t*, siginfo_t*, const timespec64*, size_t) lp32
+futex_time64(int*, int, int, const timespec64*, int*, int) lp32
+sched_rr_get_interval_time64(pid_t, timespec64*) lp32
 # Since Linux 5.3, not in glibc. Not used by bionic, but increasingly
 # likely to be useful as new features are added. In particular, cgroups
 # support seems potentially useful for Android (though the struct that
 # changes size over time is obviously problematic).
-pid_t clone3(clone_args*, size_t) all
+clone3(clone_args*, size_t) all
+# Since 5.13, not in glibc. Probed for and conditionally used by
+# Chrome GPU processes.
+landlock_add_rule(int, uint64_t, const void*, uint32_t) all
+landlock_create_ruleset(const landlock_ruleset_attr*, size_t, uint64_t) all
+landlock_restrict_self(int, uint64_t) all
diff --git a/libc/SECCOMP_ALLOWLIST_SYSTEM.TXT b/libc/SECCOMP_ALLOWLIST_SYSTEM.TXT
index 756affed1..ac90aac43 100644
--- a/libc/SECCOMP_ALLOWLIST_SYSTEM.TXT
+++ b/libc/SECCOMP_ALLOWLIST_SYSTEM.TXT
@@ -3,4 +3,4 @@
 #
 # This file is processed by a python script named genseccomp.py.
 
-int bpf(int cmd, union bpf_attr *attr, unsigned int size) all
+bpf(int cmd, union bpf_attr *attr, unsigned int size) all
diff --git a/libc/SECCOMP_BLOCKLIST_APP.TXT b/libc/SECCOMP_BLOCKLIST_APP.TXT
index b9ecc0247..5c317cf8e 100644
--- a/libc/SECCOMP_BLOCKLIST_APP.TXT
+++ b/libc/SECCOMP_BLOCKLIST_APP.TXT
@@ -11,40 +11,40 @@
 # before uid change, including capset and setresuid. This is because the seccomp
 # filter must be installed while the process still has CAP_SYS_ADMIN; changing
 # the uid would remove that capability.
-int     setgid32(gid_t)     lp32
-int     setgid(gid_t)       lp64
-int     setuid32(uid_t)    lp32
-int     setuid(uid_t)      lp64
-int     setregid32(gid_t, gid_t)  lp32
-int     setregid(gid_t, gid_t)    lp64
-int     setreuid32(uid_t, uid_t)   lp32
-int     setreuid(uid_t, uid_t)     lp64
-int     setresgid32(gid_t, gid_t, gid_t)   lp32
-int     setresgid(gid_t, gid_t, gid_t)     lp64
+setgid32(gid_t)     lp32
+setgid(gid_t)       lp64
+setuid32(uid_t)    lp32
+setuid(uid_t)      lp64
+setregid32(gid_t, gid_t)  lp32
+setregid(gid_t, gid_t)    lp64
+setreuid32(uid_t, uid_t)   lp32
+setreuid(uid_t, uid_t)     lp64
+setresgid32(gid_t, gid_t, gid_t)   lp32
+setresgid(gid_t, gid_t, gid_t)     lp64
 # setresuid is explicitly allowed, see above.
-int     setfsgid32(gid_t) lp32
-int     setfsgid(gid_t)   lp64
-int     setfsuid32(uid_t) lp32
-int     setfsuid(uid_t)   lp64
-int     setgroups32(int, const gid_t*)   lp32
-int     setgroups(int, const gid_t*)     lp64
+setfsgid32(gid_t) lp32
+setfsgid(gid_t)   lp64
+setfsuid32(uid_t) lp32
+setfsuid(uid_t)   lp64
+setgroups32(int, const gid_t*)   lp32
+setgroups(int, const gid_t*)     lp64
 
 # Syscalls to modify times.
-int     adjtimex(struct timex*)   all
-int     clock_adjtime(clockid_t, struct timex*)   all
-int     clock_settime(clockid_t, const struct timespec*)  all
-int     settimeofday(const struct timeval*, const struct timezone*)   all
+adjtimex(struct timex*)   all
+clock_adjtime(clockid_t, struct timex*)   all
+clock_settime(clockid_t, const struct timespec*)  all
+settimeofday(const struct timeval*, const struct timezone*)   all
 
-int     acct(const char*  filepath)  all
-int     syslog(int, char*, int)   all
-int     chroot(const char*)  all
+acct(const char*  filepath)  all
+syslog(int, char*, int)   all
+chroot(const char*)  all
 
-int     init_module(void*, unsigned long, const char*)  all
-int     delete_module(const char*, unsigned int)   all
-int     mount(const char*, const char*, const char*, unsigned long, const void*)  all
-int     umount2(const char*, int)  all
-int     swapon(const char*, int) all
-int     swapoff(const char*) all
-int     setdomainname(const char*, size_t)  all
-int     sethostname(const char*, size_t)  all
-int     reboot(int, int, int, void*)  all
+init_module(void*, unsigned long, const char*)  all
+delete_module(const char*, unsigned int)   all
+mount(const char*, const char*, const char*, unsigned long, const void*)  all
+umount2(const char*, int)  all
+swapon(const char*, int) all
+swapoff(const char*) all
+setdomainname(const char*, size_t)  all
+sethostname(const char*, size_t)  all
+reboot(int, int, int, void*)  all
diff --git a/libc/SECCOMP_BLOCKLIST_COMMON.TXT b/libc/SECCOMP_BLOCKLIST_COMMON.TXT
index 22c9844b3..0c6e1aed8 100644
--- a/libc/SECCOMP_BLOCKLIST_COMMON.TXT
+++ b/libc/SECCOMP_BLOCKLIST_COMMON.TXT
@@ -6,5 +6,5 @@
 #
 # This file is processed by a python script named genseccomp.py.
 
-int     swapon(const char*, int) all
-int     swapoff(const char*) all
+swapon(const char*, int) all
+swapoff(const char*) all
diff --git a/libc/SYSCALLS.TXT b/libc/SYSCALLS.TXT
index 8c5572eb3..31651cd88 100644
--- a/libc/SYSCALLS.TXT
+++ b/libc/SYSCALLS.TXT
@@ -1,381 +1,392 @@
 # This file is used to automatically generate bionic's system call stubs.
 #
+# It is processed by a python script named gensyscalls.py,
+# normally run via the genrules in libc/Android.bp.
+#
 # Each non-blank, non-comment line has the following format:
 #
-# return_type func_name[|alias_list][:syscall_name[:socketcall_id]]([parameter_list]) arch_list
+#     func_name[|alias_list][:syscall_name[:socketcall_id]]([parameter_list]) arch_list
 #
 # where:
-#       arch_list ::= "all" | arches
-#       arches    ::= arch |  arch "," arches
-#       arch      ::= "arm" | "arm64" | "riscv64" | "x86" | "x86_64" | "lp32" | "lp64"
+#     arch_list ::= "all" | arches
+#     arches    ::= arch |  arch "," arches
+#     arch      ::= "arm" | "arm64" | "riscv64" | "x86" | "x86_64" | "lp32" | "lp64"
+#
+# syscall_name corresponds to the name of the syscall, which may differ from
+# the exported function name func_name. For example: the exit_group syscall
+# is exported by libc as the _exit() function, not exit() (which does more
+# work before calling _exit()).
 #
-# Note:
-#      - syscall_name corresponds to the name of the syscall, which may differ from
-#        the exported function name (example: the exit syscall is implemented by the _exit()
-#        function, which is not the same as the standard C exit() function which calls it)
+# alias_list is optional comma-separated list of function aliases.
+# For example, the traditional _exit() function has a C99 alias _Exit().
 #
-#      - alias_list is optional comma separated list of function aliases.
+# No return type is specified, because it's not needed.
 #
-#      - The call_id parameter, given that func_name and syscall_name have
-#        been provided, allows the user to specify dispatch style syscalls.
-#        For example, socket() syscall on i386 actually becomes:
-#          socketcall(__NR_socket, 1, *(rest of args on stack)).
+# The socketcall_id parameter supports x86's
+# https://man7.org/linux/man-pages/man2/socketcall.2.html
+# and can be ignored for all other syscalls and architectures.
 #
-#      - Each parameter type is assumed to be stored in 32 bits.
+# The number of registers required for the arguments is computed by the script,
+# based on the parameter list given here. It handles the need for register
+# pairs for 64-bit arguments on ILP32, and also arm32's requirement for such
+# pairs to start on an even register. This means that it's important to get
+# these types right!
 #
-# This file is processed by a python script named gensyscalls.py, run via
-# genrules in Android.bp.
 
 # Calls that have historical 16-bit variants camping on the best names (CONFIG_UID16).
-uid_t getuid:getuid32()   lp32
-uid_t getuid:getuid()     lp64
-gid_t getgid:getgid32()   lp32
-gid_t getgid:getgid()     lp64
-uid_t geteuid:geteuid32() lp32
-uid_t geteuid:geteuid()   lp64
-gid_t getegid:getegid32() lp32
-gid_t getegid:getegid()   lp64
-uid_t getresuid:getresuid32(uid_t* ruid, uid_t* euid, uid_t* suid) lp32
-uid_t getresuid:getresuid(uid_t* ruid, uid_t* euid, uid_t* suid)   lp64
-gid_t getresgid:getresgid32(gid_t* rgid, gid_t* egid, gid_t* sgid) lp32
-gid_t getresgid:getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid)   lp64
-int getgroups:getgroups32(int, gid_t*) lp32
-int getgroups:getgroups(int, gid_t*)   lp64
-int setgid:setgid32(gid_t) lp32
-int setgid:setgid(gid_t)   lp64
-int setuid:setuid32(uid_t) lp32
-int setuid:setuid(uid_t)   lp64
-int setreuid:setreuid32(uid_t, uid_t) lp32
-int setreuid:setreuid(uid_t, uid_t)   lp64
-int setresuid:setresuid32(uid_t, uid_t, uid_t) lp32
-int setresuid:setresuid(uid_t, uid_t, uid_t)   lp64
-int setresgid:setresgid32(gid_t, gid_t, gid_t) lp32
-int setresgid:setresgid(gid_t, gid_t, gid_t)   lp64
-int setfsgid:setfsgid32(gid_t) lp32
-int setfsgid:setfsgid(gid_t)   lp64
-int setfsuid:setfsuid32(uid_t) lp32
-int setfsuid:setfsuid(uid_t)   lp64
-
-ssize_t readahead(int, off64_t, size_t) all
-pid_t getpgid(pid_t) all
-pid_t getppid() all
-pid_t getsid(pid_t) all
-pid_t setsid() all
-int kill(pid_t, int) all
-int tgkill(pid_t tgid, pid_t tid, int sig) all
-
-void* __brk:brk(void*) all
-int execve(const char*, char* const*, char* const*)  all
-int __ptrace:ptrace(int request, int pid, void* addr, void* data) all
+getuid:getuid32()   lp32
+getuid:getuid()     lp64
+getgid:getgid32()   lp32
+getgid:getgid()     lp64
+geteuid:geteuid32() lp32
+geteuid:geteuid()   lp64
+getegid:getegid32() lp32
+getegid:getegid()   lp64
+getresuid:getresuid32(uid_t* ruid, uid_t* euid, uid_t* suid) lp32
+getresuid:getresuid(uid_t* ruid, uid_t* euid, uid_t* suid)   lp64
+getresgid:getresgid32(gid_t* rgid, gid_t* egid, gid_t* sgid) lp32
+getresgid:getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid)   lp64
+getgroups:getgroups32(int, gid_t*) lp32
+getgroups:getgroups(int, gid_t*)   lp64
+setgid:setgid32(gid_t) lp32
+setgid:setgid(gid_t)   lp64
+setuid:setuid32(uid_t) lp32
+setuid:setuid(uid_t)   lp64
+setreuid:setreuid32(uid_t, uid_t) lp32
+setreuid:setreuid(uid_t, uid_t)   lp64
+setresuid:setresuid32(uid_t, uid_t, uid_t) lp32
+setresuid:setresuid(uid_t, uid_t, uid_t)   lp64
+setresgid:setresgid32(gid_t, gid_t, gid_t) lp32
+setresgid:setresgid(gid_t, gid_t, gid_t)   lp64
+setfsgid:setfsgid32(gid_t) lp32
+setfsgid:setfsgid(gid_t)   lp64
+setfsuid:setfsuid32(uid_t) lp32
+setfsuid:setfsuid(uid_t)   lp64
+
+readahead(int, off64_t, size_t) all
+getpgid(pid_t) all
+getppid() all
+getsid(pid_t) all
+setsid() all
+kill(pid_t, int) all
+tgkill(pid_t tgid, pid_t tid, int sig) all
+
+__brk:brk(void*) all
+execve(const char*, char* const*, char* const*)  all
+__ptrace:ptrace(int request, int pid, void* addr, void* data) all
 
 # <sys/resource.h>
-int getrusage(int, struct rusage*)  all
-int __getpriority:getpriority(int, id_t)  all
-int setpriority(int, id_t, int)   all
+getrusage(int, struct rusage*)  all
+__getpriority:getpriority(int, id_t)  all
+setpriority(int, id_t, int)   all
 # On LP64, rlimit and rlimit64 are the same.
 # On 32-bit systems we use prlimit64 to implement the rlimit64 functions.
-int getrlimit:ugetrlimit(int, struct rlimit*)  lp32
-int getrlimit|getrlimit64(int, struct rlimit*)  lp64
-int setrlimit(int, const struct rlimit*)  lp32
-int setrlimit|setrlimit64(int, const struct rlimit*)  lp64
-int prlimit64|prlimit(pid_t, int, struct rlimit64*, const struct rlimit64*)  lp64
-int prlimit64(pid_t, int, struct rlimit64*, const struct rlimit64*)  lp32
-
-int     setgroups:setgroups32(int, const gid_t*)   lp32
-int     setgroups:setgroups(int, const gid_t*)     lp64
-int     setpgid(pid_t, pid_t)  all
-int     setregid:setregid32(gid_t, gid_t)  lp32
-int     setregid:setregid(gid_t, gid_t)    lp64
-int     chroot(const char*)  all
-int     prctl(int, unsigned long, unsigned long, unsigned long, unsigned long) all
-int     capget(cap_user_header_t header, cap_user_data_t data) all
-int     capset(cap_user_header_t header, const cap_user_data_t data) all
-int     sigaltstack(const stack_t*, stack_t*) all
-int     acct(const char*  filepath)  all
+getrlimit:ugetrlimit(int, struct rlimit*)  lp32
+getrlimit|getrlimit64(int, struct rlimit*)  lp64
+setrlimit(int, const struct rlimit*)  lp32
+setrlimit|setrlimit64(int, const struct rlimit*)  lp64
+prlimit64|prlimit(pid_t, int, struct rlimit64*, const struct rlimit64*)  lp64
+prlimit64(pid_t, int, struct rlimit64*, const struct rlimit64*)  lp32
+
+setgroups:setgroups32(int, const gid_t*)   lp32
+setgroups:setgroups(int, const gid_t*)     lp64
+setpgid(pid_t, pid_t)  all
+setregid:setregid32(gid_t, gid_t)  lp32
+setregid:setregid(gid_t, gid_t)    lp64
+chroot(const char*)  all
+prctl(int, unsigned long, unsigned long, unsigned long, unsigned long) all
+capget(cap_user_header_t header, cap_user_data_t data) all
+capset(cap_user_header_t header, const cap_user_data_t data) all
+sigaltstack(const stack_t*, stack_t*) all
+acct(const char*  filepath)  all
 
 # file descriptors
-ssize_t     read(int, void*, size_t)        all
-ssize_t     write(int, const void*, size_t)       all
-ssize_t     pread64(int, void*, size_t, off64_t) lp32
-ssize_t     pread64|pread(int, void*, size_t, off_t) lp64
-ssize_t     pwrite64(int, void*, size_t, off64_t) lp32
-ssize_t     pwrite64|pwrite(int, void*, size_t, off_t) lp64
+read(int, void*, size_t)        all
+write(int, const void*, size_t)       all
+pread64(int, void*, size_t, off64_t) lp32
+pread64|pread(int, void*, size_t, off_t) lp64
+pwrite64(int, void*, size_t, off64_t) lp32
+pwrite64|pwrite(int, void*, size_t, off_t) lp64
 
 # On LP32, preadv/pwritev don't use off64_t --- they use pairs of 32-bit
 # arguments to avoid problems on architectures like arm32 where 64-bit arguments
 # must be in a register pair starting with an even-numbered register.
 # See linux/fs/read_write.c and https://lwn.net/Articles/311630/.
 # Note that there's an unused always-0 second long even on LP64!
-ssize_t     __preadv64:preadv(int, const struct iovec*, int, long, long) all
-ssize_t     __pwritev64:pwritev(int, const struct iovec*, int, long, long) all
-ssize_t     __preadv64v2:preadv2(int, const struct iovec*, int, long, long, int) all
-ssize_t     __pwritev64v2:pwritev2(int, const struct iovec*, int, long, long, int) all
-
-int         __close:close(int)  all
-int         close_range(unsigned int, unsigned int, int) all
-ssize_t     copy_file_range(int, off64_t*, int, off64_t*, size_t, unsigned int) all
-pid_t       __getpid:getpid()  all
-int memfd_create(const char*, unsigned) all
-int         munmap(void*, size_t)  all
-int         msync(const void*, size_t, int)    all
-int         mprotect(const void*, size_t, int)  all
-int         madvise(void*, size_t, int)  all
-ssize_t     process_madvise(int, const struct iovec*, size_t, int, unsigned int)     all
-int mlock(const void* addr, size_t len)    all
-int mlock2(const void* addr, size_t len, int flags)    all
-int         munlock(const void* addr, size_t len)   all
-int         mlockall(int flags)   all
-int mseal(void*, size_t, unsigned long) lp64
-int         munlockall()   all
-int         mincore(void*  start, size_t  length, unsigned char*  vec)   all
-int         __ioctl:ioctl(int, int, void*)  all
-ssize_t     readv(int, const struct iovec*, int)   all
-ssize_t     writev(int, const struct iovec*, int)  all
-int         __fcntl64:fcntl64(int, int, void*)  lp32
-int         __fcntl:fcntl(int, int, void*)  lp64
-int         flock(int, int)   all
-int         __fchmod:fchmod(int, mode_t)  all
-int         __pipe2:pipe2(int*, int) all
-int         __dup:dup(int)  all
-int         __dup3:dup3(int, int, int)   all
-int         fsync(int)  all
-int         fdatasync(int) all
-int         fchown:fchown32(int, uid_t, gid_t)  lp32
-int         fchown:fchown(int, uid_t, gid_t)    lp64
-void        sync(void)  all
-int         syncfs(int)  all
-int         __fsetxattr:fsetxattr(int, const char*, const void*, size_t, int) all
-ssize_t     __fgetxattr:fgetxattr(int, const char*, void*, size_t) all
-ssize_t     __flistxattr:flistxattr(int, char*, size_t) all
-int         fremovexattr(int, const char*) all
-
-int __getdents64:getdents64(unsigned int, struct dirent*, unsigned int)   all
-
-int __openat:openat(int, const char*, int, mode_t) all
-int __faccessat:faccessat(int, const char*, int)  all
-int __fchmodat:fchmodat(int, const char*, mode_t)  all
-int fchownat(int, const char*, uid_t, gid_t, int)  all
-int fstatat64|fstatat:fstatat64(int, const char*, struct stat*, int)   lp32
-int fstatat64|fstatat:newfstatat(int, const char*, struct stat*, int)  lp64
-int linkat(int, const char*, int, const char*, int)  all
-int mkdirat(int, const char*, mode_t)  all
-int mknodat(int, const char*, mode_t, dev_t)  all
-ssize_t readlinkat(int, const char*, char*, size_t)  all
-int renameat2(int, const char*, int, const char*, unsigned)  all
-int symlinkat(const char*, int, const char*)  all
-int unlinkat(int, const char*, int)   all
-int utimensat(int, const char*, const struct timespec times[2], int)  all
+__preadv64:preadv(int, const struct iovec*, int, long, long) all
+__pwritev64:pwritev(int, const struct iovec*, int, long, long) all
+__preadv64v2:preadv2(int, const struct iovec*, int, long, long, int) all
+__pwritev64v2:pwritev2(int, const struct iovec*, int, long, long, int) all
+
+__close:close(int)  all
+close_range(unsigned int, unsigned int, int) all
+copy_file_range(int, off64_t*, int, off64_t*, size_t, unsigned int) all
+__getpid:getpid()  all
+memfd_create(const char*, unsigned) all
+munmap(void*, size_t)  all
+msync(const void*, size_t, int)    all
+mprotect(const void*, size_t, int)  all
+madvise(void*, size_t, int)  all
+process_madvise(int, const struct iovec*, size_t, int, unsigned int)     all
+mlock(const void* addr, size_t len)    all
+mlock2(const void* addr, size_t len, int flags)    all
+munlock(const void* addr, size_t len)   all
+mlockall(int flags)   all
+mseal(void*, size_t, unsigned long) lp64
+munlockall()   all
+mincore(void*  start, size_t  length, unsigned char*  vec)   all
+__ioctl:ioctl(int, int, void*)  all
+readv(int, const struct iovec*, int)   all
+writev(int, const struct iovec*, int)  all
+__fcntl64:fcntl64(int, int, void*)  lp32
+__fcntl:fcntl(int, int, void*)  lp64
+flock(int, int)   all
+__fchmod:fchmod(int, mode_t)  all
+__pipe2:pipe2(int*, int) all
+__dup:dup(int)  all
+__dup3:dup3(int, int, int)   all
+fsync(int)  all
+fdatasync(int) all
+fchown:fchown32(int, uid_t, gid_t)  lp32
+fchown:fchown(int, uid_t, gid_t)    lp64
+sync(void)  all
+syncfs(int)  all
+__fsetxattr:fsetxattr(int, const char*, const void*, size_t, int) all
+__fgetxattr:fgetxattr(int, const char*, void*, size_t) all
+__flistxattr:flistxattr(int, char*, size_t) all
+fremovexattr(int, const char*) all
+
+__getdents64:getdents64(unsigned int, struct dirent*, unsigned int)   all
+
+__openat:openat(int, const char*, int, mode_t) all
+__faccessat:faccessat(int, const char*, int)  all
+__fchmodat:fchmodat(int, const char*, mode_t)  all
+fchownat(int, const char*, uid_t, gid_t, int)  all
+fstatat64|fstatat:fstatat64(int, const char*, struct stat*, int)   lp32
+fstatat64|fstatat:newfstatat(int, const char*, struct stat*, int)  lp64
+linkat(int, const char*, int, const char*, int)  all
+mkdirat(int, const char*, mode_t)  all
+mknodat(int, const char*, mode_t, dev_t)  all
+readlinkat(int, const char*, char*, size_t)  all
+renameat2(int, const char*, int, const char*, unsigned)  all
+symlinkat(const char*, int, const char*)  all
+unlinkat(int, const char*, int)   all
+utimensat(int, const char*, const struct timespec times[2], int)  all
 
 # Paired off_t/off64_t system calls. On 64-bit systems,
 # sizeof(off_t) == sizeof(off64_t), so there we emit two symbols that are
 # aliases. On 32-bit systems, we have two different system calls.
 # That means that every system call in this section should take three lines.
-off_t lseek(int, off_t, int) lp32
-int __llseek:_llseek(int, unsigned long, unsigned long, off64_t*, int) lp32
-off_t lseek|lseek64(int, off_t, int) lp64
-ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count) lp32
-ssize_t sendfile64(int out_fd, int in_fd, off64_t* offset, size_t count) lp32
-ssize_t sendfile|sendfile64(int out_fd, int in_fd, off_t* offset, size_t count) lp64
-int truncate(const char*, off_t) lp32
-int truncate64(const char*, off64_t) lp32
-int truncate|truncate64(const char*, off_t) lp64
+lseek(int, off_t, int) lp32
+__llseek:_llseek(int, unsigned long, unsigned long, off64_t*, int) lp32
+lseek|lseek64(int, off_t, int) lp64
+sendfile(int out_fd, int in_fd, off_t* offset, size_t count) lp32
+sendfile64(int out_fd, int in_fd, off64_t* offset, size_t count) lp32
+sendfile|sendfile64(int out_fd, int in_fd, off_t* offset, size_t count) lp64
+truncate(const char*, off_t) lp32
+truncate64(const char*, off64_t) lp32
+truncate|truncate64(const char*, off_t) lp64
 # (fallocate only gets two lines because there is no 32-bit variant.)
-int fallocate64:fallocate(int, int, off64_t, off64_t) lp32
-int fallocate|fallocate64(int, int, off_t, off_t) lp64
+fallocate64:fallocate(int, int, off64_t, off64_t) lp32
+fallocate|fallocate64(int, int, off_t, off_t) lp64
 # (ftruncate only gets two lines because 32-bit bionic only uses the 64-bit call.)
-int ftruncate64(int, off64_t) lp32
-int ftruncate|ftruncate64(int, off_t) lp64
+ftruncate64(int, off64_t) lp32
+ftruncate|ftruncate64(int, off_t) lp64
 # (mmap only gets two lines because 32-bit bionic only uses the 64-bit call.)
-void* __mmap2:mmap2(void*, size_t, int, int, int, long) lp32
-void* mmap|mmap64(void*, size_t, int, int, int, off_t) lp64
+__mmap2:mmap2(void*, size_t, int, int, int, long) lp32
+mmap|mmap64(void*, size_t, int, int, int, off_t) lp64
 
 # mremap is in C++ for 32-bit so we can add the PTRDIFF_MAX check.
-void* __mremap:mremap(void*, size_t, size_t, int, void*) lp32
-void* mremap(void*, size_t, size_t, int, void*) lp64
+__mremap:mremap(void*, size_t, size_t, int, void*) lp32
+mremap(void*, size_t, size_t, int, void*) lp64
 
 # posix_fadvise64 is awkward: arm has shuffled arguments,
 # the POSIX functions don't set errno, and no architecture has posix_fadvise.
-int __arm_fadvise64_64:arm_fadvise64_64(int, int, off64_t, off64_t) arm
-int __fadvise64:fadvise64_64(int, off64_t, off64_t, int) x86
-int __fadvise64:fadvise64(int, off64_t, off64_t, int) lp64
+__arm_fadvise64_64:arm_fadvise64_64(int, int, off64_t, off64_t) arm
+__fadvise64:fadvise64_64(int, off64_t, off64_t, int) x86
+__fadvise64:fadvise64(int, off64_t, off64_t, int) lp64
 
-int __fstatfs64:fstatfs64(int, size_t, struct statfs*)  lp32
-int __fstatfs:fstatfs(int, struct statfs*)  lp64
-int __statfs64:statfs64(const char*, size_t, struct statfs*)  lp32
-int __statfs:statfs(const char*, struct statfs*)  lp64
+__fstatfs64:fstatfs64(int, size_t, struct statfs*)  lp32
+__fstatfs:fstatfs(int, struct statfs*)  lp64
+__statfs64:statfs64(const char*, size_t, struct statfs*)  lp32
+__statfs:statfs(const char*, struct statfs*)  lp64
 
-int fstat64|fstat:fstat64(int, struct stat*) lp32
-int fstat64|fstat:fstat(int, struct stat*) lp64
+fstat64|fstat:fstat64(int, struct stat*) lp32
+fstat64|fstat:fstat(int, struct stat*) lp64
 
 # file system
-int     chdir(const char*)              all
-int     mount(const char*, const char*, const char*, unsigned long, const void*)  all
-int     umount2(const char*, int)  all
-int     __getcwd:getcwd(char* buf, size_t size)  all
-int     fchdir(int)    all
-int     setxattr(const char*, const char*, const void*, size_t, int) all
-int     lsetxattr(const char*, const char*, const void*, size_t, int) all
-ssize_t getxattr(const char*, const char*, void*, size_t) all
-ssize_t lgetxattr(const char*, const char*, void*, size_t) all
-ssize_t listxattr(const char*, char*, size_t) all
-ssize_t llistxattr(const char*, char*, size_t) all
-int     removexattr(const char*, const char*) all
-int     lremovexattr(const char*, const char*) all
-int statx(int, const char*, int, unsigned, struct statx*) all
-int     swapon(const char*, int) all
-int     swapoff(const char*) all
+chdir(const char*)              all
+mount(const char*, const char*, const char*, unsigned long, const void*)  all
+umount2(const char*, int)  all
+__getcwd:getcwd(char* buf, size_t size)  all
+fchdir(int)    all
+setxattr(const char*, const char*, const void*, size_t, int) all
+lsetxattr(const char*, const char*, const void*, size_t, int) all
+getxattr(const char*, const char*, void*, size_t) all
+lgetxattr(const char*, const char*, void*, size_t) all
+listxattr(const char*, char*, size_t) all
+llistxattr(const char*, char*, size_t) all
+removexattr(const char*, const char*) all
+lremovexattr(const char*, const char*) all
+statx(int, const char*, int, unsigned, struct statx*) all
+swapon(const char*, int) all
+swapoff(const char*) all
 
 # time
-int           settimeofday(const struct timeval*, const struct timezone*)   all
-clock_t       times(struct tms*)       all
-int           nanosleep(const struct timespec*, struct timespec*)   all
-int           clock_settime(clockid_t, const struct timespec*)  all
-int           __clock_nanosleep:clock_nanosleep(clockid_t, int, const struct timespec*, struct timespec*)  all
-int           getitimer(int, struct itimerval*)   all
-int           setitimer(int, const struct itimerval*, struct itimerval*)  all
-int           __timer_create:timer_create(clockid_t clockid, struct sigevent* evp, __kernel_timer_t* timerid)    all
-int           __timer_settime:timer_settime(__kernel_timer_t, int, const struct itimerspec*, struct itimerspec*) all
-int           __timer_gettime:timer_gettime(__kernel_timer_t, struct itimerspec*)                                all
-int           __timer_getoverrun:timer_getoverrun(__kernel_timer_t)                                              all
-int           __timer_delete:timer_delete(__kernel_timer_t)                                                      all
-int           timerfd_create(clockid_t, int)   all
-int           timerfd_settime(int, int, const struct itimerspec*, struct itimerspec*)   all
-int           timerfd_gettime(int, struct itimerspec*)   all
-int           adjtimex(struct timex*)   all
-int           clock_adjtime(clockid_t, struct timex*)   all
+settimeofday(const struct timeval*, const struct timezone*)   all
+times(struct tms*)       all
+nanosleep(const struct timespec*, struct timespec*)   all
+clock_settime(clockid_t, const struct timespec*)  all
+__clock_nanosleep:clock_nanosleep(clockid_t, int, const struct timespec*, struct timespec*)  all
+getitimer(int, struct itimerval*)   all
+setitimer(int, const struct itimerval*, struct itimerval*)  all
+__timer_create:timer_create(clockid_t clockid, struct sigevent* evp, __kernel_timer_t* timerid)    all
+__timer_settime:timer_settime(__kernel_timer_t, int, const struct itimerspec*, struct itimerspec*) all
+__timer_gettime:timer_gettime(__kernel_timer_t, struct itimerspec*)                                all
+__timer_getoverrun:timer_getoverrun(__kernel_timer_t)                                              all
+__timer_delete:timer_delete(__kernel_timer_t)                                                      all
+timerfd_create(clockid_t, int)   all
+timerfd_settime(int, int, const struct itimerspec*, struct itimerspec*)   all
+timerfd_gettime(int, struct itimerspec*)   all
+adjtimex(struct timex*)   all
+clock_adjtime(clockid_t, struct timex*)   all
 
 # signals
-int     __sigaction:sigaction(int, const struct sigaction*, struct sigaction*)  lp32
-int     __rt_sigaction:rt_sigaction(int, const struct sigaction*, struct sigaction*, size_t)  all
-int     __rt_sigpending:rt_sigpending(sigset64_t*, size_t)  all
-int     __rt_sigprocmask:rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t)  all
-int     __rt_sigsuspend:rt_sigsuspend(const sigset64_t*, size_t)  all
-int     __rt_sigtimedwait:rt_sigtimedwait(const sigset64_t*, siginfo_t*, const timespec*, size_t)  all
-int     __rt_sigqueueinfo:rt_sigqueueinfo(pid_t, int, siginfo_t*)  all
-int     __signalfd4:signalfd4(int, const sigset64_t*, size_t, int)  all
+__sigaction:sigaction(int, const struct sigaction*, struct sigaction*)  lp32
+__rt_sigaction:rt_sigaction(int, const struct sigaction*, struct sigaction*, size_t)  all
+__rt_sigpending:rt_sigpending(sigset64_t*, size_t)  all
+__rt_sigprocmask:rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t)  all
+__rt_sigsuspend:rt_sigsuspend(const sigset64_t*, size_t)  all
+__rt_sigtimedwait:rt_sigtimedwait(const sigset64_t*, siginfo_t*, const timespec*, size_t)  all
+__rt_sigqueueinfo:rt_sigqueueinfo(pid_t, int, siginfo_t*)  all
+__signalfd4:signalfd4(int, const sigset64_t*, size_t, int)  all
 
 # sockets
-int           __socket:socket(int, int, int)              arm,lp64
-int           __socketpair:socketpair(int, int, int, int*)    arm,lp64
-int           bind(int, struct sockaddr*, socklen_t)  arm,lp64
-int           __connect:connect(int, struct sockaddr*, socklen_t)   arm,lp64
-int           listen(int, int)                   arm,lp64
-int           __accept4:accept4(int, struct sockaddr*, socklen_t*, int)  arm,lp64
-int           getsockname(int, struct sockaddr*, socklen_t*)  arm,lp64
-int           getpeername(int, struct sockaddr*, socklen_t*)  arm,lp64
-ssize_t       __sendto:sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  arm,lp64
-ssize_t       recvfrom(int, void*, size_t, unsigned int, struct sockaddr*, socklen_t*)  arm,lp64
-int           shutdown(int, int)  arm,lp64
-int           setsockopt(int, int, int, const void*, socklen_t)  arm,lp64
-int           getsockopt(int, int, int, void*, socklen_t*)    arm,lp64
-ssize_t       __recvmsg:recvmsg(int, struct msghdr*, unsigned int)   arm,lp64
-ssize_t       __sendmsg:sendmsg(int, const struct msghdr*, unsigned int)  arm,lp64
-int           __recvmmsg:recvmmsg(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   arm,lp64
-int           __sendmmsg:sendmmsg(int, struct mmsghdr*, unsigned int, int)   arm,lp64
+__socket:socket(int, int, int)              arm,lp64
+__socketpair:socketpair(int, int, int, int*)    arm,lp64
+bind(int, struct sockaddr*, socklen_t)  arm,lp64
+__connect:connect(int, struct sockaddr*, socklen_t)   arm,lp64
+listen(int, int)                   arm,lp64
+__accept4:accept4(int, struct sockaddr*, socklen_t*, int)  arm,lp64
+getsockname(int, struct sockaddr*, socklen_t*)  arm,lp64
+getpeername(int, struct sockaddr*, socklen_t*)  arm,lp64
+__sendto:sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  arm,lp64
+recvfrom(int, void*, size_t, unsigned int, struct sockaddr*, socklen_t*)  arm,lp64
+shutdown(int, int)  arm,lp64
+setsockopt(int, int, int, const void*, socklen_t)  arm,lp64
+getsockopt(int, int, int, void*, socklen_t*)    arm,lp64
+__recvmsg:recvmsg(int, struct msghdr*, unsigned int)   arm,lp64
+__sendmsg:sendmsg(int, const struct msghdr*, unsigned int)  arm,lp64
+__recvmmsg:recvmmsg(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   arm,lp64
+__sendmmsg:sendmmsg(int, struct mmsghdr*, unsigned int, int)   arm,lp64
 
 # sockets for x86. These are done as an "indexed" call to socketcall syscall.
-int           __socket:socketcall:1(int, int, int) x86
-int           bind:socketcall:2(int, struct sockaddr*, int)  x86
-int           __connect:socketcall:3(int, struct sockaddr*, socklen_t)   x86
-int           listen:socketcall:4(int, int)                   x86
-int           getsockname:socketcall:6(int, struct sockaddr*, socklen_t*)  x86
-int           getpeername:socketcall:7(int, struct sockaddr*, socklen_t*)  x86
-int           __socketpair:socketcall:8(int, int, int, int*)    x86
-ssize_t       __sendto:socketcall:11(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  x86
-ssize_t       recvfrom:socketcall:12(int, void*, size_t, unsigned int, struct sockaddr*, socklen_t*)  x86
-int           shutdown:socketcall:13(int, int)  x86
-int           setsockopt:socketcall:14(int, int, int, const void*, socklen_t)  x86
-int           getsockopt:socketcall:15(int, int, int, void*, socklen_t*)    x86
-int           __sendmsg:socketcall:16(int, const struct msghdr*, unsigned int)  x86
-int           __recvmsg:socketcall:17(int, struct msghdr*, unsigned int)   x86
-int           __accept4:socketcall:18(int, struct sockaddr*, socklen_t*, int)  x86
-int           __recvmmsg:socketcall:19(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   x86
-int           __sendmmsg:socketcall:20(int, struct mmsghdr*, unsigned int, int)   x86
+__socket:socketcall:1(int, int, int) x86
+bind:socketcall:2(int, struct sockaddr*, int)  x86
+__connect:socketcall:3(int, struct sockaddr*, socklen_t)   x86
+listen:socketcall:4(int, int)                   x86
+getsockname:socketcall:6(int, struct sockaddr*, socklen_t*)  x86
+getpeername:socketcall:7(int, struct sockaddr*, socklen_t*)  x86
+__socketpair:socketcall:8(int, int, int, int*)    x86
+__sendto:socketcall:11(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  x86
+recvfrom:socketcall:12(int, void*, size_t, unsigned int, struct sockaddr*, socklen_t*)  x86
+shutdown:socketcall:13(int, int)  x86
+setsockopt:socketcall:14(int, int, int, const void*, socklen_t)  x86
+getsockopt:socketcall:15(int, int, int, void*, socklen_t*)    x86
+__sendmsg:socketcall:16(int, const struct msghdr*, unsigned int)  x86
+__recvmsg:socketcall:17(int, struct msghdr*, unsigned int)   x86
+__accept4:socketcall:18(int, struct sockaddr*, socklen_t*, int)  x86
+__recvmmsg:socketcall:19(int, struct mmsghdr*, unsigned int, int, const struct timespec*)   x86
+__sendmmsg:socketcall:20(int, struct mmsghdr*, unsigned int, int)   x86
 
 # scheduler & real-time
-int sched_setscheduler(pid_t pid, int policy, const struct sched_param* param)  all
-int sched_getscheduler(pid_t pid)  all
-int sched_yield(void)  all
-int sched_setparam(pid_t pid, const struct sched_param* param)  all
-int sched_getparam(pid_t pid, struct sched_param* param)  all
-int sched_get_priority_max(int policy)  all
-int sched_get_priority_min(int policy)  all
-int sched_rr_get_interval(pid_t pid, struct timespec* interval)  all
-int sched_setaffinity(pid_t pid, size_t setsize, const cpu_set_t* set) all
-int setns(int, int) all
-int unshare(int) all
-int __sched_getaffinity:sched_getaffinity(pid_t pid, size_t setsize, cpu_set_t* set)  all
-int __getcpu:getcpu(unsigned*, unsigned*, void*) all
+sched_get_priority_max(int policy) all
+sched_get_priority_min(int policy) all
+__sched_getaffinity:sched_getaffinity(pid_t, size_t, cpu_set_t*) all
+sched_getattr(pid_t, sched_attr*, unsigned, unsigned) all
+sched_getparam(pid_t, sched_param*) all
+sched_getscheduler(pid_t) all
+sched_rr_get_interval(pid_t, timespec*) all
+sched_setaffinity(pid_t, size_t, const cpu_set_t*) all
+sched_setattr(pid_t, sched_attr*, unsigned) all
+sched_setparam(pid_t, const sched_param*) all
+sched_setscheduler(pid_t, int, const sched_param*)  all
+sched_yield(void) all
 
 # other
-int     uname(struct utsname*)  all
-mode_t  umask(mode_t)  all
-int     __reboot:reboot(int, int, int, void*)  all
-int     init_module(void*, unsigned long, const char*)  all
-int     delete_module(const char*, unsigned int)   all
-int     klogctl:syslog(int, char*, int)   all
-int     sysinfo(struct sysinfo*)  all
-int     personality(unsigned long)  all
+uname(struct utsname*)  all
+umask(mode_t)  all
+__reboot:reboot(int, int, int, void*)  all
+init_module(void*, unsigned long, const char*)  all
+delete_module(const char*, unsigned int)   all
+klogctl:syslog(int, char*, int)   all
+sysinfo(struct sysinfo*)  all
+personality(unsigned long)  all
+
+setns(int, int) all
+unshare(int) all
+
+__getcpu:getcpu(unsigned*, unsigned*, void*) all
 
-int     bpf(int, union bpf_attr *, unsigned int) all
+bpf(int, union bpf_attr *, unsigned int) all
 
-ssize_t tee(int, int, size_t, unsigned int)  all
-ssize_t splice(int, off64_t*, int, off64_t*, size_t, unsigned int)  all
-ssize_t vmsplice(int, const struct iovec*, size_t, unsigned int)  all
+tee(int, int, size_t, unsigned int)  all
+splice(int, off64_t*, int, off64_t*, size_t, unsigned int)  all
+vmsplice(int, const struct iovec*, size_t, unsigned int)  all
 
-int __epoll_create1:epoll_create1(int)  all
-int epoll_ctl(int, int op, int, struct epoll_event*)  all
-int __epoll_pwait:epoll_pwait(int, struct epoll_event*, int, int, const sigset64_t*, size_t)  all
-int __epoll_pwait2:epoll_pwait2(int, struct epoll_event*, int, const timespec64*, const sigset64_t*, size_t)  all
+__epoll_create1:epoll_create1(int)  all
+epoll_ctl(int, int op, int, struct epoll_event*)  all
+__epoll_pwait:epoll_pwait(int, struct epoll_event*, int, int, const sigset64_t*, size_t)  all
+__epoll_pwait2:epoll_pwait2(int, struct epoll_event*, int, const timespec64*, const sigset64_t*, size_t)  all
 
-int __eventfd:eventfd2(unsigned int, int)  all
+__eventfd:eventfd2(unsigned int, int)  all
 
-void _exit|_Exit:exit_group(int)  all
-void __exit:exit(int)  all
+_exit|_Exit:exit_group(int)  all
+__exit:exit(int)  all
 
-int inotify_init1(int)  all
-int inotify_add_watch(int, const char*, unsigned int)  all
-int inotify_rm_watch(int, unsigned int)  all
+inotify_init1(int)  all
+inotify_add_watch(int, const char*, unsigned int)  all
+inotify_rm_watch(int, unsigned int)  all
 
-int __pselect6:pselect6(int, fd_set*, fd_set*, fd_set*, timespec*, void*)  all
-int __ppoll:ppoll(pollfd*, unsigned int, timespec*, const sigset64_t*, size_t)  all
+__pselect6:pselect6(int, fd_set*, fd_set*, fd_set*, timespec*, void*)  all
+__ppoll:ppoll(pollfd*, unsigned int, timespec*, const sigset64_t*, size_t)  all
 
-ssize_t process_vm_readv(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long)  all
-ssize_t process_vm_writev(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long)  all
+process_vm_readv(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long)  all
+process_vm_writev(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long)  all
 
-int quotactl(int, const char*, int, char*)  all
+quotactl(int, const char*, int, char*)  all
 
-int __set_tid_address:set_tid_address(int*)  all
+__set_tid_address:set_tid_address(int*)  all
 
-int setdomainname(const char*, size_t)  all
-int sethostname(const char*, size_t)  all
+setdomainname(const char*, size_t)  all
+sethostname(const char*, size_t)  all
 
-int sync_file_range(int, off64_t, off64_t, unsigned int) x86,lp64
-int __sync_file_range2:sync_file_range2(int, unsigned int, off64_t, off64_t) arm
+sync_file_range(int, off64_t, off64_t, unsigned int) x86,lp64
+__sync_file_range2:sync_file_range2(int, unsigned int, off64_t, off64_t) arm
 
-pid_t wait4(pid_t, int*, int, struct rusage*)  all
-int __waitid:waitid(int, pid_t, siginfo_t*, int, void*)  all
+wait4(pid_t, int*, int, struct rusage*)  all
+__waitid:waitid(int, pid_t, siginfo_t*, int, void*)  all
 
 # ARM-specific
-int     __set_tls:__ARM_NR_set_tls(void*)                                 arm
-int     cacheflush:__ARM_NR_cacheflush(long start, long end, long flags)  arm
+__set_tls:__ARM_NR_set_tls(void*)                                 arm
+cacheflush:__ARM_NR_cacheflush(long start, long end, long flags)  arm
 
 # riscv64-specific
-int __riscv_flush_icache:riscv_flush_icache(void*, void*, unsigned long) riscv64
+__riscv_flush_icache:riscv_flush_icache(void*, void*, unsigned long) riscv64
 
 # x86-specific
-int     __set_thread_area:set_thread_area(void*) x86
-long arch_prctl(int, unsigned long) x86_64
+__set_thread_area:set_thread_area(void*) x86
+arch_prctl(int, unsigned long) x86_64
 
 # vdso stuff.
-int __clock_getres:clock_getres(clockid_t, struct timespec*) all
-int __clock_gettime:clock_gettime(clockid_t, struct timespec*) all
-int __gettimeofday:gettimeofday(struct timeval*, struct timezone*) all
+__clock_getres:clock_getres(clockid_t, struct timespec*) all
+__clock_gettime:clock_gettime(clockid_t, struct timespec*) all
+__gettimeofday:gettimeofday(struct timeval*, struct timezone*) all
 
 # <sys/random.h>
-ssize_t getrandom(void*, size_t, unsigned) all
+getrandom(void*, size_t, unsigned) all
 
 # <sys/pidfd.h>
-int __pidfd_open:pidfd_open(pid_t, unsigned int) all
-int __pidfd_getfd:pidfd_getfd(int, int, unsigned int) all
-int pidfd_send_signal(int, int, siginfo_t*, unsigned int) all
+__pidfd_open:pidfd_open(pid_t, unsigned int) all
+__pidfd_getfd:pidfd_getfd(int, int, unsigned int) all
+pidfd_send_signal(int, int, siginfo_t*, unsigned int) all
diff --git a/libc/arch-arm64/bionic/__set_tls.c b/libc/arch-arm64/bionic/__set_tls.c
deleted file mode 100644
index 0d88d111d..000000000
--- a/libc/arch-arm64/bionic/__set_tls.c
+++ /dev/null
@@ -1,33 +0,0 @@
-/*
- * Copyright (C) 2013 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-
-__LIBC_HIDDEN__ void __set_tls(void* tls) {
-  asm("msr tpidr_el0, %0" : : "r" (tls));
-}
diff --git a/libc/arch-arm64/bionic/setjmp.S b/libc/arch-arm64/bionic/setjmp.S
index c40899834..e94e5f41e 100644
--- a/libc/arch-arm64/bionic/setjmp.S
+++ b/libc/arch-arm64/bionic/setjmp.S
@@ -114,6 +114,9 @@ ENTRY_WEAK_FOR_NATIVE_BRIDGE(sigsetjmp)
   .cfi_rel_offset x0, 0
   .cfi_rel_offset x30, 8
 
+  // Commit SME's ZA lazy save. Note that the call preserves x1.
+  bl __arm_za_disable
+
   // Get the cookie and store it along with the signal flag.
   mov x0, x1
   bl __bionic_setjmp_cookie_get
@@ -183,6 +186,17 @@ END(sigsetjmp)
 
 // void siglongjmp(sigjmp_buf env, int value);
 ENTRY_WEAK_FOR_NATIVE_BRIDGE(siglongjmp)
+  // First of all, disable SME's ZA, so that it does not interfere
+  // with anything else. Note that __arm_za_disable is guaranteed to
+  // preserve x0 and x1.
+  str x30, [sp, #-16]!
+  .cfi_adjust_cfa_offset 16
+  .cfi_rel_offset x30, 0
+  bl __arm_za_disable
+  ldr x30, [sp], #16
+  .cfi_adjust_cfa_offset -16
+  .cfi_restore x30
+
   // Check the checksum before doing anything.
   m_calculate_checksum x12, x0, x2
   ldr x2, [x0, #(_JB_CHECKSUM * 8)]
diff --git a/libc/arch-riscv64/bionic/__set_tls.c b/libc/arch-riscv64/bionic/__set_tls.c
deleted file mode 100644
index 57383ab12..000000000
--- a/libc/arch-riscv64/bionic/__set_tls.c
+++ /dev/null
@@ -1,33 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-
-__LIBC_HIDDEN__ void __set_tls(void* tls) {
-  asm("mv tp, %0" : : "r"(tls));
-}
diff --git a/libc/arch-riscv64/dynamic_function_dispatch.cpp b/libc/arch-riscv64/dynamic_function_dispatch.cpp
deleted file mode 100644
index ce6c02866..000000000
--- a/libc/arch-riscv64/dynamic_function_dispatch.cpp
+++ /dev/null
@@ -1,145 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <fcntl.h>
-#include <private/bionic_ifuncs.h>
-#include <stddef.h>
-#include <sys/syscall.h>
-#include <unistd.h>
-
-extern "C" {
-
-static inline __always_inline int ifunc_faccessat(int dir_fd, const char* path, int mode) {
-  register long a0 __asm__("a0") = dir_fd;
-  register long a1 __asm__("a1") = reinterpret_cast<long>(path);
-  register long a2 __asm__("a2") = mode;
-  register long a7 __asm__("a7") = __NR_faccessat;
-  __asm__("ecall" : "=r"(a0) : "r"(a0), "r"(a1), "r"(a2), "r"(a7) : "memory");
-  return a0;
-}
-
-static bool have_fast_v() {
-  static bool result = []() {
-    // We don't want to do a full "bogomips" test, so just check for the
-    // presence of a file that would indicate that we're running in qemu.
-    return ifunc_faccessat(AT_FDCWD, "/dev/hvc0", F_OK) != 0;
-  }();
-  return result;
-}
-
-DEFINE_IFUNC_FOR(memchr) {
-  if (have_fast_v()) RETURN_FUNC(memchr_func_t, memchr_v);
-  RETURN_FUNC(memchr_func_t, memchr_gc);
-}
-MEMCHR_SHIM()
-
-DEFINE_IFUNC_FOR(memcmp) {
-  if (have_fast_v()) RETURN_FUNC(memcmp_func_t, memcmp_v);
-  RETURN_FUNC(memcmp_func_t, memcmp_gc);
-}
-MEMCMP_SHIM()
-
-DEFINE_IFUNC_FOR(memcpy) {
-  if (have_fast_v()) RETURN_FUNC(memcpy_func_t, memcpy_v);
-  RETURN_FUNC(memcpy_func_t, memcpy_gc);
-}
-MEMCPY_SHIM()
-
-DEFINE_IFUNC_FOR(memmove) {
-  if (have_fast_v()) RETURN_FUNC(memmove_func_t, memmove_v);
-  RETURN_FUNC(memmove_func_t, memmove_gc);
-}
-MEMMOVE_SHIM()
-
-DEFINE_IFUNC_FOR(memset) {
-  if (have_fast_v()) RETURN_FUNC(memset_func_t, memset_v);
-  RETURN_FUNC(memset_func_t, memset_gc);
-}
-MEMSET_SHIM()
-
-DEFINE_IFUNC_FOR(stpcpy) {
-  if (have_fast_v()) RETURN_FUNC(stpcpy_func_t, stpcpy_v);
-  RETURN_FUNC(stpcpy_func_t, stpcpy_gc);
-}
-STPCPY_SHIM()
-
-DEFINE_IFUNC_FOR(strcat) {
-  if (have_fast_v()) RETURN_FUNC(strcat_func_t, strcat_v);
-  RETURN_FUNC(strcat_func_t, strcat_gc);
-}
-STRCAT_SHIM()
-
-DEFINE_IFUNC_FOR(strchr) {
-  if (have_fast_v()) RETURN_FUNC(strchr_func_t, strchr_v);
-  RETURN_FUNC(strchr_func_t, strchr_gc);
-}
-STRCHR_SHIM()
-
-DEFINE_IFUNC_FOR(strcmp) {
-  if (have_fast_v()) RETURN_FUNC(strcmp_func_t, strcmp_v);
-  RETURN_FUNC(strcmp_func_t, strcmp_gc);
-}
-STRCMP_SHIM()
-
-DEFINE_IFUNC_FOR(strcpy) {
-  if (have_fast_v()) RETURN_FUNC(strcpy_func_t, strcpy_v);
-  RETURN_FUNC(strcpy_func_t, strcpy_gc);
-}
-STRCPY_SHIM()
-
-DEFINE_IFUNC_FOR(strlen) {
-  if (have_fast_v()) RETURN_FUNC(strlen_func_t, strlen_v);
-  RETURN_FUNC(strlen_func_t, strlen_gc);
-}
-STRLEN_SHIM()
-
-DEFINE_IFUNC_FOR(strncat) {
-  if (have_fast_v()) RETURN_FUNC(strncat_func_t, strncat_v);
-  RETURN_FUNC(strncat_func_t, strncat_gc);
-}
-STRNCAT_SHIM()
-
-DEFINE_IFUNC_FOR(strncmp) {
-  if (have_fast_v()) RETURN_FUNC(strncmp_func_t, strncmp_v);
-  RETURN_FUNC(strncmp_func_t, strncmp_gc);
-}
-STRNCMP_SHIM()
-
-DEFINE_IFUNC_FOR(strncpy) {
-  if (have_fast_v()) RETURN_FUNC(strncpy_func_t, strncpy_v);
-  RETURN_FUNC(strncpy_func_t, strncpy_gc);
-}
-STRNCPY_SHIM()
-
-DEFINE_IFUNC_FOR(strnlen) {
-  if (have_fast_v()) RETURN_FUNC(strnlen_func_t, strnlen_v);
-  RETURN_FUNC(strnlen_func_t, strnlen_gc);
-}
-STRNLEN_SHIM()
-
-}  // extern "C"
diff --git a/libc/arch-riscv64/string/__memcpy_chk.S b/libc/arch-riscv64/string/__memcpy_chk.S
deleted file mode 100644
index 4a2d13dee..000000000
--- a/libc/arch-riscv64/string/__memcpy_chk.S
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <private/bionic_asm.h>
-
-ENTRY(__memcpy_chk)
-  bleu a2, a3, 1f
-  call __memcpy_chk_fail
-
-1:
-   tail memcpy
-END(__memcpy_chk)
diff --git a/libc/arch-riscv64/string/__memset_chk.S b/libc/arch-riscv64/string/__memset_chk.S
deleted file mode 100644
index a5562cbac..000000000
--- a/libc/arch-riscv64/string/__memset_chk.S
+++ /dev/null
@@ -1,10 +0,0 @@
-#include <private/bionic_asm.h>
-
-ENTRY(__memset_chk)
-    bleu    a2, a3, 1f
-    call    __memset_chk_fail
-
-1:
-    tail   memset
-END(__memset_chk)
-
diff --git a/libc/arch-riscv64/string/bcopy.c b/libc/arch-riscv64/string/bcopy.c
deleted file mode 100644
index 57adcf6b8..000000000
--- a/libc/arch-riscv64/string/bcopy.c
+++ /dev/null
@@ -1,122 +0,0 @@
-/*-
- * SPDX-License-Identifier: BSD-3-Clause
- *
- * Copyright (c) 1990, 1993
- *	The Regents of the University of California.  All rights reserved.
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
-#include <sys/types.h>
-
-typedef	intptr_t word;		/* "word" used for optimal copy speed */
-
-#define	wsize	sizeof(word)
-#define	wmask	(wsize - 1)
-
-/*
- * Copy a block of memory, handling overlap.
- */
-#include <string.h>
-
-void *
-#ifdef MEMCOPY
-memcpy_gc
-#else
-memmove_gc
-#endif
-(void *dst0, const void *src0, size_t length)
-{
-	char *dst = dst0;
-	const char *src = src0;
-	size_t t;
-
-	if (length == 0 || dst == src)		/* nothing to do */
-		goto done;
-
-	/*
-	 * Macros: loop-t-times; and loop-t-times, t>0
-	 */
-#define	TLOOP(s) if (t) TLOOP1(s)
-#define	TLOOP1(s) do { s; } while (--t)
-
-	if ((unsigned long)dst < (unsigned long)src) {
-		/*
-		 * Copy forward.
-		 */
-		t = (uintptr_t)src;	/* only need low bits */
-		if ((t | (uintptr_t)dst) & wmask) {
-			/*
-			 * Try to align operands.  This cannot be done
-			 * unless the low bits match.
-			 */
-			if ((t ^ (uintptr_t)dst) & wmask || length < wsize)
-				t = length;
-			else
-				t = wsize - (t & wmask);
-			length -= t;
-			TLOOP1(*dst++ = *src++);
-		}
-		/*
-		 * Copy whole words, then mop up any trailing bytes.
-		 */
-		t = length / wsize;
-		TLOOP(*(word *)(void *)dst = *(const word *)(const void *)src;
-		    src += wsize; dst += wsize);
-		t = length & wmask;
-		TLOOP(*dst++ = *src++);
-	} else {
-		/*
-		 * Copy backwards.  Otherwise essentially the same.
-		 * Alignment works as before, except that it takes
-		 * (t&wmask) bytes to align, not wsize-(t&wmask).
-		 */
-		src += length;
-		dst += length;
-		t = (uintptr_t)src;
-		if ((t | (uintptr_t)dst) & wmask) {
-			if ((t ^ (uintptr_t)dst) & wmask || length <= wsize)
-				t = length;
-			else
-				t &= wmask;
-			length -= t;
-			TLOOP1(*--dst = *--src);
-		}
-		t = length / wsize;
-		TLOOP(src -= wsize; dst -= wsize;
-		    *(word *)(void *)dst = *(const word *)(const void *)src);
-		t = length & wmask;
-		TLOOP(*--dst = *--src);
-	}
-done:
-#if defined(MEMCOPY) || defined(MEMMOVE)
-	return (dst0);
-#else
-	return;
-#endif
-}
diff --git a/libc/arch-riscv64/string/memchr_v.S b/libc/arch-riscv64/string/memchr.S
similarity index 99%
rename from libc/arch-riscv64/string/memchr_v.S
rename to libc/arch-riscv64/string/memchr.S
index d4999c3f4..88334366e 100644
--- a/libc/arch-riscv64/string/memchr_v.S
+++ b/libc/arch-riscv64/string/memchr.S
@@ -68,7 +68,7 @@
 #define vData v0
 #define vMask v8
 
-ENTRY(memchr_v)
+ENTRY(memchr)
 
 L(loop):
     vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
@@ -93,4 +93,4 @@ L(found):
     add iResult, pSrc, iTemp
     ret
 
-END(memchr_v)
+END(memchr)
diff --git a/libc/arch-riscv64/string/memchr.c b/libc/arch-riscv64/string/memchr.c
deleted file mode 100644
index 34eb6d756..000000000
--- a/libc/arch-riscv64/string/memchr.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define memchr memchr_gc
-#include <upstream-openbsd/lib/libc/string/memchr.c>
diff --git a/libc/arch-riscv64/string/memcmp_v.S b/libc/arch-riscv64/string/memcmp.S
similarity index 99%
rename from libc/arch-riscv64/string/memcmp_v.S
rename to libc/arch-riscv64/string/memcmp.S
index 55e08db61..9c1ecdc48 100644
--- a/libc/arch-riscv64/string/memcmp_v.S
+++ b/libc/arch-riscv64/string/memcmp.S
@@ -71,7 +71,7 @@
 #define vData2 v8
 #define vMask v16
 
-ENTRY(memcmp_v)
+ENTRY(memcmp)
 
 L(loop):
     vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
@@ -103,4 +103,4 @@ L(found):
     sub iResult, iTemp1, iTemp2
     ret
 
-END(memcmp_v)
+END(memcmp)
diff --git a/libc/arch-riscv64/string/memcmp.c b/libc/arch-riscv64/string/memcmp.c
deleted file mode 100644
index 2d7335a20..000000000
--- a/libc/arch-riscv64/string/memcmp.c
+++ /dev/null
@@ -1,52 +0,0 @@
-/*-
- * SPDX-License-Identifier: BSD-3-Clause
- *
- * Copyright (c) 1990, 1993
- *	The Regents of the University of California.  All rights reserved.
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
-#include <string.h>
-
-/*
- * Compare memory regions.
- */
-int
-memcmp_gc(const void *s1, const void *s2, size_t n)
-{
-	if (n != 0) {
-		const unsigned char *p1 = s1, *p2 = s2;
-
-		do {
-			if (*p1++ != *p2++)
-				return (*--p1 - *--p2);
-		} while (--n != 0);
-	}
-	return (0);
-}
diff --git a/libc/arch-riscv64/string/memset_v.S b/libc/arch-riscv64/string/memcpy.S
similarity index 87%
rename from libc/arch-riscv64/string/memset_v.S
rename to libc/arch-riscv64/string/memcpy.S
index 06a2c6a65..2e4106988 100644
--- a/libc/arch-riscv64/string/memset_v.S
+++ b/libc/arch-riscv64/string/memcpy.S
@@ -55,31 +55,34 @@
 
 #include <private/bionic_asm.h>
 
-#define pDst a0
-#define iValue a1
-#define iNum a2
+// Arguments.
+#define dst a0
+#define src a1
+#define n a2
+#define dst_len a3 // __memcpy_chk() only
 
+// Locals.
 #define iVL a3
-#define iTemp a4
-#define pDstPtr a5
+#define p a4
 
-#define ELEM_LMUL_SETTING m8
-#define vData v0
+ENTRY(__memcpy_chk)
+    bleu n, dst_len, 1f
+    call __memcpy_chk_fail
+1:  // Fall through to memcpy().
+END(__memcpy_chk)
 
-ENTRY(memset_v)
-
-    mv pDstPtr, pDst
-
-    vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
-    vmv.v.x vData, iValue
+ENTRY(memcpy)
+    mv p, dst
 
 L(loop):
-    vse8.v vData, (pDstPtr)
-    sub iNum, iNum, iVL
-    add pDstPtr, pDstPtr, iVL
-    vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
-    bnez iNum, L(loop)
+    vsetvli iVL, n, e8, m8, ta, ma
 
-    ret
+    vle8.v v0, (src)
+    sub n, n, iVL
+    add src, src, iVL
+    vse8.v v0, (p)
+    add p, p, iVL
+    bnez n, L(loop)
 
-END(memset_v)
+    ret
+END(memcpy)
diff --git a/libc/arch-riscv64/string/memcpy.c b/libc/arch-riscv64/string/memcpy.c
deleted file mode 100644
index ee1150473..000000000
--- a/libc/arch-riscv64/string/memcpy.c
+++ /dev/null
@@ -1,2 +0,0 @@
-#define	MEMCOPY
-#include "bcopy.c"
diff --git a/libc/arch-riscv64/string/memmove_v.S b/libc/arch-riscv64/string/memmove.S
similarity index 99%
rename from libc/arch-riscv64/string/memmove_v.S
rename to libc/arch-riscv64/string/memmove.S
index cad2b05a7..fa70f765d 100644
--- a/libc/arch-riscv64/string/memmove_v.S
+++ b/libc/arch-riscv64/string/memmove.S
@@ -67,7 +67,7 @@
 #define ELEM_LMUL_SETTING m8
 #define vData v0
 
-ENTRY(memmove_v)
+ENTRY(memmove)
 
     mv pDstPtr, pDst
 
@@ -99,4 +99,4 @@ L(backward_copy_loop):
     bnez iNum, L(backward_copy_loop)
     ret
 
-END(memmove_v)
+END(memmove)
diff --git a/libc/arch-riscv64/string/memmove.c b/libc/arch-riscv64/string/memmove.c
deleted file mode 100644
index e9bb2c2ed..000000000
--- a/libc/arch-riscv64/string/memmove.c
+++ /dev/null
@@ -1,2 +0,0 @@
-#define	MEMMOVE
-#include "bcopy.c"
diff --git a/libc/arch-riscv64/string/memcpy_v.S b/libc/arch-riscv64/string/memset.S
similarity index 86%
rename from libc/arch-riscv64/string/memcpy_v.S
rename to libc/arch-riscv64/string/memset.S
index 93ec60f20..2ebf3e90e 100644
--- a/libc/arch-riscv64/string/memcpy_v.S
+++ b/libc/arch-riscv64/string/memset.S
@@ -55,31 +55,35 @@
 
 #include <private/bionic_asm.h>
 
-#define pDst a0
-#define pSrc a1
-#define iNum a2
+// Arguments.
+#define dst a0
+#define ch a1
+#define n a2
+#define dst_len a3 // __memset_chk() only
 
+// Locals.
 #define iVL a3
-#define pDstPtr a4
+#define iTemp a4
+#define p a5
 
-#define ELEM_LMUL_SETTING m8
-#define vData v0
+ENTRY(__memset_chk)
+    bleu n, dst_len, 1f
+    call __memset_chk_fail
+1:  // Fall through to memset().
+END(__memset_chk)
 
-ENTRY(memcpy_v)
+ENTRY(memset)
+    mv p, dst
 
-    mv pDstPtr, pDst
+    vsetvli iVL, n, e8, m8, ta, ma
+    vmv.v.x v0, ch
 
 L(loop):
-    vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
-
-    vle8.v vData, (pSrc)
-    sub iNum, iNum, iVL
-    add pSrc, pSrc, iVL
-    vse8.v vData, (pDstPtr)
-    add pDstPtr, pDstPtr, iVL
-
-    bnez iNum, L(loop)
+    vse8.v v0, (p)
+    sub n, n, iVL
+    add p, p, iVL
+    vsetvli iVL, n, e8, m8, ta, ma
+    bnez n, L(loop)
 
     ret
-
-END(memcpy_v)
+END(memset)
diff --git a/libc/arch-riscv64/string/memset.c b/libc/arch-riscv64/string/memset.c
deleted file mode 100644
index d51cbf985..000000000
--- a/libc/arch-riscv64/string/memset.c
+++ /dev/null
@@ -1,108 +0,0 @@
-/*-
- * SPDX-License-Identifier: BSD-3-Clause
- *
- * Copyright (c) 1990, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * This code is derived from software contributed to Berkeley by
- * Mike Hibler and Chris Torek.
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
-
-#include <limits.h>
-
-#define	wsize	sizeof(u_long)
-#define	wmask	(wsize - 1)
-
-#include <string.h>
-
-#define	RETURN	return (dst0)
-#define	VAL	c0
-#define	WIDEVAL	c
-
-void *
-memset_gc(void *dst0, int c0, size_t length)
-{
-	size_t t;
-	u_long c;
-	u_char *dst;
-
-	dst = dst0;
-	/*
-	 * If not enough words, just fill bytes.  A length >= 2 words
-	 * guarantees that at least one of them is `complete' after
-	 * any necessary alignment.  For instance:
-	 *
-	 *	|-----------|-----------|-----------|
-	 *	|00|01|02|03|04|05|06|07|08|09|0A|00|
-	 *	          ^---------------------^
-	 *		 dst		 dst+length-1
-	 *
-	 * but we use a minimum of 3 here since the overhead of the code
-	 * to do word writes is substantial.
-	 *
-	 * TODO: This threshold might not be sensible for 64-bit u_long.
-	 * We should benchmark and revisit this decision.
-	 */
-	if (length < 3 * wsize) {
-		while (length != 0) {
-			*dst++ = VAL;
-			--length;
-		}
-		RETURN;
-	}
-
-	if ((c = (u_char)c0) != 0) {	/* Fill the word. */
-		c = (c << 8) | c;	/* u_long is 16 bits. */
-		c = (c << 16) | c;	/* u_long is 32 bits. */
-		c = (c << 32) | c;	/* u_long is 64 bits. */
-	}
-	/* Align destination by filling in bytes. */
-	if ((t = (long)dst & wmask) != 0) {
-		t = wsize - t;
-		length -= t;
-		do {
-			*dst++ = VAL;
-		} while (--t != 0);
-	}
-
-	/* Fill words.  Length was >= 2*words so we know t >= 1 here. */
-	t = length / wsize;
-	do {
-		*(u_long *)(void *)dst = WIDEVAL;
-		dst += wsize;
-	} while (--t != 0);
-
-	/* Mop up trailing bytes, if any. */
-	t = length & wmask;
-	if (t != 0)
-		do {
-			*dst++ = VAL;
-		} while (--t != 0);
-	RETURN;
-}
diff --git a/libc/arch-riscv64/string/stpcpy_v.S b/libc/arch-riscv64/string/stpcpy.S
similarity index 99%
rename from libc/arch-riscv64/string/stpcpy_v.S
rename to libc/arch-riscv64/string/stpcpy.S
index 6a853ec1a..c5d09456f 100644
--- a/libc/arch-riscv64/string/stpcpy_v.S
+++ b/libc/arch-riscv64/string/stpcpy.S
@@ -68,7 +68,7 @@
 #define vStr1 v8
 #define vStr2 v16
 
-ENTRY(stpcpy_v)
+ENTRY(stpcpy)
 L(stpcpy_loop):
     vsetvli iVL, zero, e8, ELEM_LMUL_SETTING, ta, ma
     vle8ff.v vStr1, (pSrc)
@@ -85,4 +85,4 @@ L(stpcpy_loop):
     sub pDstPtr, pDstPtr, iCurrentVL
     add pDstPtr, pDstPtr, iActiveElemPos
     ret
-END(stpcpy_v)
+END(stpcpy)
diff --git a/libc/arch-riscv64/string/stpcpy.c b/libc/arch-riscv64/string/stpcpy.c
deleted file mode 100644
index 2afcf99df..000000000
--- a/libc/arch-riscv64/string/stpcpy.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define stpcpy stpcpy_gc
-#include <upstream-openbsd/lib/libc/string/stpcpy.c>
diff --git a/libc/arch-riscv64/string/strcat_v.S b/libc/arch-riscv64/string/strcat.S
similarity index 99%
rename from libc/arch-riscv64/string/strcat_v.S
rename to libc/arch-riscv64/string/strcat.S
index 3d348e733..5abf29532 100644
--- a/libc/arch-riscv64/string/strcat_v.S
+++ b/libc/arch-riscv64/string/strcat.S
@@ -69,7 +69,7 @@
 #define vStr1 v8
 #define vStr2 v16
 
-ENTRY(strcat_v)
+ENTRY(strcat)
 
     mv pDstPtr, pDst
 
@@ -104,4 +104,4 @@ L(strcpy_loop):
 
     ret
 
-END(strcat_v)
+END(strcat)
diff --git a/libc/arch-riscv64/string/strcat.c b/libc/arch-riscv64/string/strcat.c
deleted file mode 100644
index 5fb162177..000000000
--- a/libc/arch-riscv64/string/strcat.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define strcat strcat_gc
-#include <upstream-openbsd/lib/libc/string/strcat.c>
diff --git a/libc/arch-riscv64/string/strchr_v.S b/libc/arch-riscv64/string/strchr.S
similarity index 99%
rename from libc/arch-riscv64/string/strchr_v.S
rename to libc/arch-riscv64/string/strchr.S
index bc7b58ae9..ea13c5d88 100644
--- a/libc/arch-riscv64/string/strchr_v.S
+++ b/libc/arch-riscv64/string/strchr.S
@@ -69,7 +69,7 @@
 #define vMaskEnd v8
 #define vMaskCh v9
 
-ENTRY(strchr_v)
+ENTRY(strchr)
 
 L(strchr_loop):
     vsetvli iVL, zero, e8, ELEM_LMUL_SETTING, ta, ma
@@ -91,4 +91,4 @@ L(found_ch):
     add pStr, pStr, iChOffset
     ret
 
-END(strchr_v)
+END(strchr)
diff --git a/libc/arch-riscv64/string/strchr.c b/libc/arch-riscv64/string/strchr.c
deleted file mode 100644
index dc07766de..000000000
--- a/libc/arch-riscv64/string/strchr.c
+++ /dev/null
@@ -1,43 +0,0 @@
-/*	$OpenBSD: strchr.c,v 1.4 2018/10/01 06:37:37 martijn Exp $ */
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
-#include <string.h>
-
-char *
-strchr_gc(const char *p, int ch)
-{
-	for (;; ++p) {
-		if (*p == (char) ch)
-			return((char *)p);
-		if (!*p)
-			return((char *)NULL);
-	}
-	/* NOTREACHED */
-}
diff --git a/libc/arch-riscv64/string/strcmp_v.S b/libc/arch-riscv64/string/strcmp.S
similarity index 99%
rename from libc/arch-riscv64/string/strcmp_v.S
rename to libc/arch-riscv64/string/strcmp.S
index 01e72b154..3332c8380 100644
--- a/libc/arch-riscv64/string/strcmp_v.S
+++ b/libc/arch-riscv64/string/strcmp.S
@@ -74,7 +74,7 @@
 #define vMask1 v16
 #define vMask2 v17
 
-ENTRY(strcmp_v)
+ENTRY(strcmp)
 
     # increase the lmul using the following sequences:
     # 1/2, 1/2, 1, 2, 4, 4, 4, ...
@@ -166,4 +166,4 @@ L(check2):
     sub iResult, iTemp1, iTemp2
     ret
 
-END(strcmp_v)
+END(strcmp)
diff --git a/libc/arch-riscv64/string/strcmp.c b/libc/arch-riscv64/string/strcmp.c
deleted file mode 100644
index 7a1fefe82..000000000
--- a/libc/arch-riscv64/string/strcmp.c
+++ /dev/null
@@ -1,47 +0,0 @@
-/*	$OpenBSD: strcmp.c,v 1.9 2015/08/31 02:53:57 guenther Exp $	*/
-
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
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
-#include <string.h>
-
-/*
- * Compare strings.
- */
-int
-strcmp_gc(const char *s1, const char *s2)
-{
-	while (*s1 == *s2++)
-		if (*s1++ == 0)
-			return (0);
-	return (*(unsigned char *)s1 - *(unsigned char *)--s2);
-}
diff --git a/libc/arch-riscv64/string/strcpy_v.S b/libc/arch-riscv64/string/strcpy.S
similarity index 99%
rename from libc/arch-riscv64/string/strcpy_v.S
rename to libc/arch-riscv64/string/strcpy.S
index 084b3a510..b89b1a8a2 100644
--- a/libc/arch-riscv64/string/strcpy_v.S
+++ b/libc/arch-riscv64/string/strcpy.S
@@ -69,7 +69,7 @@
 #define vStr1 v8
 #define vStr2 v16
 
-ENTRY(strcpy_v)
+ENTRY(strcpy)
 
     mv pDstPtr, pDst
 
@@ -88,4 +88,4 @@ L(strcpy_loop):
 
     ret
 
-END(strcpy_v)
+END(strcpy)
diff --git a/libc/arch-riscv64/string/strcpy.c b/libc/arch-riscv64/string/strcpy.c
deleted file mode 100644
index a6245410a..000000000
--- a/libc/arch-riscv64/string/strcpy.c
+++ /dev/null
@@ -1,41 +0,0 @@
-/*	$OpenBSD: strcpy.c,v 1.10 2017/11/28 06:55:49 tb Exp $	*/
-
-/*
- * Copyright (c) 1988 Regents of the University of California.
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
-#include <string.h>
-
-char *
-strcpy_gc(char *to, const char *from)
-{
-	char *save = to;
-
-	for (; (*to = *from) != '\0'; ++from, ++to);
-	return(save);
-}
diff --git a/libc/arch-riscv64/string/strlen_v.S b/libc/arch-riscv64/string/strlen.S
similarity index 99%
rename from libc/arch-riscv64/string/strlen_v.S
rename to libc/arch-riscv64/string/strlen.S
index c28402172..7f7d2dd10 100644
--- a/libc/arch-riscv64/string/strlen_v.S
+++ b/libc/arch-riscv64/string/strlen.S
@@ -66,7 +66,7 @@
 #define vStr v0
 #define vMaskEnd v2
 
-ENTRY(strlen_v)
+ENTRY(strlen)
 
     mv pCopyStr, pStr
 L(loop):
@@ -84,4 +84,4 @@ L(loop):
 
     ret
 
-END(strlen_v)
+END(strlen)
diff --git a/libc/arch-riscv64/string/strlen.c b/libc/arch-riscv64/string/strlen.c
deleted file mode 100644
index ac8d27fb1..000000000
--- a/libc/arch-riscv64/string/strlen.c
+++ /dev/null
@@ -1,42 +0,0 @@
-/*	$OpenBSD: strlen.c,v 1.9 2015/08/31 02:53:57 guenther Exp $	*/
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
-#include <string.h>
-
-size_t
-strlen_gc(const char *str)
-{
-	const char *s;
-
-	for (s = str; *s; ++s)
-		;
-	return (s - str);
-}
diff --git a/libc/arch-riscv64/string/strncat_v.S b/libc/arch-riscv64/string/strncat.S
similarity index 99%
rename from libc/arch-riscv64/string/strncat_v.S
rename to libc/arch-riscv64/string/strncat.S
index adc768d39..01cb14fd9 100644
--- a/libc/arch-riscv64/string/strncat_v.S
+++ b/libc/arch-riscv64/string/strncat.S
@@ -70,7 +70,7 @@
 #define vStr1 v8
 #define vStr2 v16
 
-ENTRY(strncat_v)
+ENTRY(strncat)
 
     mv pDstPtr, pDst
 
@@ -114,4 +114,4 @@ L(fill_zero):
 L(fill_zero_end):
     ret
 
-END(strncat_v)
+END(strncat)
diff --git a/libc/arch-riscv64/string/strncat.c b/libc/arch-riscv64/string/strncat.c
deleted file mode 100644
index 8c26b95cc..000000000
--- a/libc/arch-riscv64/string/strncat.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define strncat strncat_gc
-#include <upstream-openbsd/lib/libc/string/strncat.c>
diff --git a/libc/arch-riscv64/string/strncmp_v.S b/libc/arch-riscv64/string/strncmp.S
similarity index 99%
rename from libc/arch-riscv64/string/strncmp_v.S
rename to libc/arch-riscv64/string/strncmp.S
index 1ce4817e7..b9e6ee2d7 100644
--- a/libc/arch-riscv64/string/strncmp_v.S
+++ b/libc/arch-riscv64/string/strncmp.S
@@ -71,7 +71,7 @@
 #define vMask1 v8
 #define vMask2 v9
 
-ENTRY(strncmp_v)
+ENTRY(strncmp)
 
     beqz iLength, L(zero_length)
 
@@ -116,4 +116,4 @@ L(zero_length):
     li iResult, 0
     ret
 
-END(strncmp_v)
+END(strncmp)
diff --git a/libc/arch-riscv64/string/strncmp.c b/libc/arch-riscv64/string/strncmp.c
deleted file mode 100644
index ebc53577e..000000000
--- a/libc/arch-riscv64/string/strncmp.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define strncmp strncmp_gc
-#include <upstream-openbsd/lib/libc/string/strncmp.c>
diff --git a/libc/arch-riscv64/string/strncpy_v.S b/libc/arch-riscv64/string/strncpy.S
similarity index 99%
rename from libc/arch-riscv64/string/strncpy_v.S
rename to libc/arch-riscv64/string/strncpy.S
index f133f2839..651a06437 100644
--- a/libc/arch-riscv64/string/strncpy_v.S
+++ b/libc/arch-riscv64/string/strncpy.S
@@ -71,7 +71,7 @@
 #define vStr1 v8
 #define vStr2 v16
 
-ENTRY(strncpy_v)
+ENTRY(strncpy)
 
     mv pDstPtr, pDst
 
@@ -111,4 +111,4 @@ L(fill_zero_loop):
 
     ret
 
-END(strncpy_v)
+END(strncpy)
diff --git a/libc/arch-riscv64/string/strncpy.c b/libc/arch-riscv64/string/strncpy.c
deleted file mode 100644
index bbd1bd787..000000000
--- a/libc/arch-riscv64/string/strncpy.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <upstream-openbsd/android/include/openbsd-compat.h>
-
-#define strncpy strncpy_gc
-#include <upstream-openbsd/lib/libc/string/strncpy.c>
diff --git a/libc/arch-riscv64/string/strnlen_v.S b/libc/arch-riscv64/string/strnlen.S
similarity index 99%
rename from libc/arch-riscv64/string/strnlen_v.S
rename to libc/arch-riscv64/string/strnlen.S
index bd1bb9a21..66366f04c 100644
--- a/libc/arch-riscv64/string/strnlen_v.S
+++ b/libc/arch-riscv64/string/strnlen.S
@@ -66,7 +66,7 @@
 #define vStr v0
 #define vMaskEnd v8
 
-ENTRY(strnlen_v)
+ENTRY(strnlen)
 
     mv pCopyStr, pStr
     mv iRetValue, iMaxlen
@@ -86,4 +86,4 @@ L(strnlen_loop):
 L(end_strnlen_loop):
     ret
 
-END(strnlen_v)
+END(strnlen)
diff --git a/libc/arch-riscv64/string/strnlen.c b/libc/arch-riscv64/string/strnlen.c
deleted file mode 100644
index 0e31c3bfc..000000000
--- a/libc/arch-riscv64/string/strnlen.c
+++ /dev/null
@@ -1,32 +0,0 @@
-/*	$OpenBSD: strnlen.c,v 1.9 2019/01/25 00:19:25 millert Exp $	*/
-
-/*
- * Copyright (c) 2010 Todd C. Miller <millert@openbsd.org>
- *
- * Permission to use, copy, modify, and distribute this software for any
- * purpose with or without fee is hereby granted, provided that the above
- * copyright notice and this permission notice appear in all copies.
- *
- * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
- * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
- * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
- * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
- * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
- * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
- * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- */
-
-#include <sys/types.h>
-
-#include <string.h>
-
-size_t
-strnlen_gc(const char *str, size_t maxlen)
-{
-	const char *cp;
-
-	for (cp = str; maxlen != 0 && *cp != '\0'; cp++, maxlen--)
-		;
-
-	return (size_t)(cp - str);
-}
diff --git a/libc/arch-x86/string/sse2-memchr-atom.S b/libc/arch-x86/string/sse2-memchr-atom.S
deleted file mode 100644
index 013af9b66..000000000
--- a/libc/arch-x86/string/sse2-memchr-atom.S
+++ /dev/null
@@ -1,556 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name,	.-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG) pushl REG; CFI_PUSH (REG)
-#define POP(REG) popl REG; CFI_POP (REG)
-
-#define ENTRANCE PUSH (%edi);
-#define PARMS  8
-#define RETURN  POP (%edi); ret; CFI_PUSH (%edi);
-
-#define STR1  PARMS
-#define STR2  STR1+4
-#define LEN   STR2+4
-
-	.text
-ENTRY (memchr)
-	ENTRANCE
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-	mov	LEN(%esp), %edx
-	test	%edx, %edx
-	jz	L(return_null)
-
-	punpcklbw %xmm1, %xmm1
-	mov	%ecx, %edi
-	punpcklbw %xmm1, %xmm1
-
-	and	$63, %ecx
-	pshufd	$0, %xmm1, %xmm1
-	cmp	$48, %ecx
-	ja	L(crosscache)
-
-	movdqu	(%edi), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(match_case2_prolog)
-
-	sub	$16, %edx
-	jbe	L(return_null)
-	lea	16(%edi), %edi
-	and	$15, %ecx
-	and	$-16, %edi
-	add	%ecx, %edx
-	sub	$64, %edx
-	jbe	L(exit_loop)
-	jmp	L(loop_prolog)
-
-	.p2align 4
-L(crosscache):
-	and	$15, %ecx
-	and	$-16, %edi
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	sar	%cl, %eax
-	test	%eax, %eax
-
-	jnz	L(match_case2_prolog1)
-	lea	-16(%edx), %edx
-	add	%ecx, %edx
-	jle	L(return_null)
-	lea	16(%edi), %edi
-	sub	$64, %edx
-	jbe	L(exit_loop)
-
-	.p2align 4
-L(loop_prolog):
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	xor	%ecx, %ecx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	16(%edi), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	32(%edi), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	48(%edi), %xmm4
-	pcmpeqb	%xmm1, %xmm4
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm4, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	lea	64(%edi), %edi
-	sub	$64, %edx
-	jbe	L(exit_loop)
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	xor	%ecx, %ecx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	16(%edi), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	32(%edi), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	48(%edi), %xmm4
-	pcmpeqb	%xmm1, %xmm4
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm4, %eax
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	lea	64(%edi), %edi
-	mov	%edi, %ecx
-	and	$-64, %edi
-	and	$63, %ecx
-	add	%ecx, %edx
-
-	.p2align 4
-L(align64_loop):
-	sub	$64, %edx
-	jbe	L(exit_loop)
-	movdqa	(%edi), %xmm0
-	movdqa	16(%edi), %xmm2
-	movdqa	32(%edi), %xmm3
-	movdqa	48(%edi), %xmm4
-	pcmpeqb	%xmm1, %xmm0
-	pcmpeqb	%xmm1, %xmm2
-	pcmpeqb	%xmm1, %xmm3
-	pcmpeqb	%xmm1, %xmm4
-
-	pmaxub	%xmm0, %xmm3
-	pmaxub	%xmm2, %xmm4
-	pmaxub	%xmm3, %xmm4
-	add	$64, %edi
-	pmovmskb %xmm4, %eax
-
-	test	%eax, %eax
-	jz	L(align64_loop)
-
-	sub	$64, %edi
-
-	pmovmskb %xmm0, %eax
-	xor	%ecx, %ecx
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	pmovmskb %xmm2, %eax
-	lea	16(%ecx), %ecx
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	movdqa	32(%edi), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %eax
-	lea	16(%ecx), %ecx
-	test	%eax, %eax
-	jnz	L(match_case1)
-
-	pcmpeqb	48(%edi), %xmm1
-	pmovmskb %xmm1, %eax
-	lea	16(%ecx), %ecx
-
-	.p2align 4
-L(match_case1):
-	add	%ecx, %edi
-	test	%al, %al
-	jz	L(match_case1_high)
-	mov	%al, %cl
-	and	$15, %cl
-	jz	L(match_case1_8)
-	test	$0x01, %al
-	jnz	L(exit_case1_1)
-	test	$0x02, %al
-	jnz	L(exit_case1_2)
-	test	$0x04, %al
-	jnz	L(exit_case1_3)
-	lea	3(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_8):
-	test	$0x10, %al
-	jnz	L(exit_case1_5)
-	test	$0x20, %al
-	jnz	L(exit_case1_6)
-	test	$0x40, %al
-	jnz	L(exit_case1_7)
-	lea	7(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_high):
-	mov	%ah, %ch
-	and	$15, %ch
-	jz	L(match_case1_high_8)
-	test	$0x01, %ah
-	jnz	L(exit_case1_9)
-	test	$0x02, %ah
-	jnz	L(exit_case1_10)
-	test	$0x04, %ah
-	jnz	L(exit_case1_11)
-	lea	11(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_high_8):
-	test	$0x10, %ah
-	jnz	L(exit_case1_13)
-	test	$0x20, %ah
-	jnz	L(exit_case1_14)
-	test	$0x40, %ah
-	jnz	L(exit_case1_15)
-	lea	15(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_loop):
-	add	$64, %edx
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	xor	%ecx, %ecx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(match_case2)
-	cmp	$16, %edx
-	jbe	L(return_null)
-
-	movdqa	16(%edi), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(match_case2)
-	cmp	$32, %edx
-	jbe	L(return_null)
-
-	movdqa	32(%edi), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(match_case2)
-	cmp	$48, %edx
-	jbe	L(return_null)
-
-	pcmpeqb	48(%edi), %xmm1
-	lea	16(%ecx), %ecx
-	pmovmskb %xmm1, %eax
-	test	%eax, %eax
-	jnz	L(match_case2)
-
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_1):
-	mov	%edi, %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_2):
-	lea	1(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_3):
-	lea	2(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_5):
-	lea	4(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_6):
-	lea	5(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_7):
-	lea	6(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_9):
-	lea	8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_10):
-	lea	9(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_11):
-	lea	10(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_13):
-	lea	12(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_14):
-	lea	13(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case1_15):
-	lea	14(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2):
-	sub	%ecx, %edx
-L(match_case2_prolog1):
-	add	%ecx, %edi
-L(match_case2_prolog):
-	test	%al, %al
-	jz	L(match_case2_high)
-	mov	%al, %cl
-	and	$15, %cl
-	jz	L(match_case2_8)
-	test	$0x01, %al
-	jnz	L(exit_case2_1)
-	test	$0x02, %al
-	jnz	L(exit_case2_2)
-	test	$0x04, %al
-	jnz	L(exit_case2_3)
-	sub	$4, %edx
-	jb	L(return_null)
-	lea	3(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2_8):
-	test	$0x10, %al
-	jnz	L(exit_case2_5)
-	test	$0x20, %al
-	jnz	L(exit_case2_6)
-	test	$0x40, %al
-	jnz	L(exit_case2_7)
-	sub	$8, %edx
-	jb	L(return_null)
-	lea	7(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2_high):
-	mov	%ah, %ch
-	and	$15, %ch
-	jz	L(match_case2_high_8)
-	test	$0x01, %ah
-	jnz	L(exit_case2_9)
-	test	$0x02, %ah
-	jnz	L(exit_case2_10)
-	test	$0x04, %ah
-	jnz	L(exit_case2_11)
-	sub	$12, %edx
-	jb	L(return_null)
-	lea	11(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2_high_8):
-	test	$0x10, %ah
-	jnz	L(exit_case2_13)
-	test	$0x20, %ah
-	jnz	L(exit_case2_14)
-	test	$0x40, %ah
-	jnz	L(exit_case2_15)
-	sub	$16, %edx
-	jb	L(return_null)
-	lea	15(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_1):
-	mov	%edi, %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_2):
-	sub	$2, %edx
-	jb	L(return_null)
-	lea	1(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_3):
-	sub	$3, %edx
-	jb	L(return_null)
-	lea	2(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_5):
-	sub	$5, %edx
-	jb	L(return_null)
-	lea	4(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_6):
-	sub	$6, %edx
-	jb	L(return_null)
-	lea	5(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_7):
-	sub	$7, %edx
-	jb	L(return_null)
-	lea	6(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_9):
-	sub	$9, %edx
-	jb	L(return_null)
-	lea	8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_10):
-	sub	$10, %edx
-	jb	L(return_null)
-	lea	9(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_11):
-	sub	$11, %edx
-	jb	L(return_null)
-	lea	10(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_13):
-	sub	$13, %edx
-	jb	L(return_null)
-	lea	12(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_14):
-	sub	$14, %edx
-	jb	L(return_null)
-	lea	13(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(exit_case2_15):
-	sub	$15, %edx
-	jb	L(return_null)
-	lea	14(%edi), %eax
-	RETURN
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	RETURN
-END (memchr)
diff --git a/libc/arch-x86/string/sse2-memmove-slm.S b/libc/arch-x86/string/sse2-memmove-slm.S
index 2ed4e7b65..a25b4c795 100644
--- a/libc/arch-x86/string/sse2-memmove-slm.S
+++ b/libc/arch-x86/string/sse2-memmove-slm.S
@@ -96,6 +96,13 @@ name:		\
 #define SETUP_PIC_REG(x)	call	__x86.get_pc_thunk.x
 
 	.section .text.sse2,"ax",@progbits
+ENTRY (__memcpy_chk)
+/* NOTE: We can't use LEN here because ebx has not been pushed yet. */
+	movl	12(%esp), %ecx
+	cmpl	16(%esp), %ecx
+	ja	__memcpy_chk_fail
+/* Fall through to memcpy/memmove. */
+END (__memcpy_chk)
 ENTRY (MEMMOVE)
 	ENTRANCE
 	movl	LEN(%esp), %ecx
diff --git a/libc/arch-x86/string/sse2-strchr-atom.S b/libc/arch-x86/string/sse2-strchr-atom.S
deleted file mode 100644
index e325181f4..000000000
--- a/libc/arch-x86/string/sse2-strchr-atom.S
+++ /dev/null
@@ -1,391 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name,	.-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl REG;	CFI_PUSH (REG)
-#define POP(REG)	popl REG;	CFI_POP (REG)
-
-#define PARMS	8
-#define ENTRANCE	PUSH(%edi)
-#define RETURN	POP (%edi); ret; CFI_PUSH (%edi);
-
-
-#define STR1	PARMS
-#define STR2	STR1+4
-
-	.text
-ENTRY (strchr)
-
-	ENTRANCE
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-
-	pxor	%xmm2, %xmm2
-	mov	%ecx, %edi
-	punpcklbw %xmm1, %xmm1
-	punpcklbw %xmm1, %xmm1
-	/* ECX has OFFSET. */
-	and	$15, %ecx
-	pshufd	$0, %xmm1, %xmm1
-	je	L(loop)
-
-/* Handle unaligned string.  */
-	and	$-16, %edi
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	/* Find where NULL is.  */
-	pmovmskb %xmm2, %edx
-	/* Check if there is a match.  */
-	pmovmskb %xmm0, %eax
-	/* Remove the leading bytes.  */
-	sarl	%cl, %edx
-	sarl	%cl, %eax
-	test	%eax, %eax
-	jz	L(unaligned_no_match)
-	add	%ecx, %edi
-	test	%edx, %edx
-	jz	L(match_case1)
-	jmp	L(match_case2)
-
-	.p2align 4
-L(unaligned_no_match):
-	test	%edx, %edx
-	jne	L(return_null)
-
-	pxor	%xmm2, %xmm2
-	add	$16, %edi
-
-	.p2align 4
-/* Loop start on aligned string.  */
-L(loop):
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches)
-	test	%edx, %edx
-	jnz	L(return_null)
-	add	$16, %edi
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches)
-	test	%edx, %edx
-	jnz	L(return_null)
-	add	$16, %edi
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches)
-	test	%edx, %edx
-	jnz	L(return_null)
-	add	$16, %edi
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches)
-	test	%edx, %edx
-	jnz	L(return_null)
-	add	$16, %edi
-	jmp	L(loop)
-
-L(matches):
-	/* There is a match.  First find where NULL is.  */
-	test	%edx, %edx
-	jz	L(match_case1)
-
-	.p2align 4
-L(match_case2):
-	test	%al, %al
-	jz	L(match_higth_case2)
-
-	mov	%al, %cl
-	and	$15, %cl
-	jnz	L(match_case2_4)
-
-	mov	%dl, %ch
-	and	$15, %ch
-	jnz	L(return_null)
-
-	test	$0x10, %al
-	jnz	L(Exit5)
-	test	$0x10, %dl
-	jnz	L(return_null)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	test	$0x20, %dl
-	jnz	L(return_null)
-	test	$0x40, %al
-	jnz	L(Exit7)
-	test	$0x40, %dl
-	jnz	L(return_null)
-	lea	7(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2_4):
-	test	$0x01, %al
-	jnz	L(Exit1)
-	test	$0x01, %dl
-	jnz	L(return_null)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	test	$0x02, %dl
-	jnz	L(return_null)
-	test	$0x04, %al
-	jnz	L(Exit3)
-	test	$0x04, %dl
-	jnz	L(return_null)
-	lea	3(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_higth_case2):
-	test	%dl, %dl
-	jnz	L(return_null)
-
-	mov	%ah, %cl
-	and	$15, %cl
-	jnz	L(match_case2_12)
-
-	mov	%dh, %ch
-	and	$15, %ch
-	jnz	L(return_null)
-
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	test	$0x10, %dh
-	jnz	L(return_null)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	test	$0x20, %dh
-	jnz	L(return_null)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-	test	$0x40, %dh
-	jnz	L(return_null)
-	lea	15(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case2_12):
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	test	$0x01, %dh
-	jnz	L(return_null)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	test	$0x02, %dh
-	jnz	L(return_null)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-	test	$0x04, %dh
-	jnz	L(return_null)
-	lea	11(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1):
-	test	%al, %al
-	jz	L(match_higth_case1)
-
-	test	$0x01, %al
-	jnz	L(Exit1)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	test	$0x04, %al
-	jnz	L(Exit3)
-	test	$0x08, %al
-	jnz	L(Exit4)
-	test	$0x10, %al
-	jnz	L(Exit5)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	test	$0x40, %al
-	jnz	L(Exit7)
-	lea	7(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_higth_case1):
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-	test	$0x08, %ah
-	jnz	L(Exit12)
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-	lea	15(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit1):
-	lea	(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit2):
-	lea	1(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit3):
-	lea	2(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit4):
-	lea	3(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit5):
-	lea	4(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit6):
-	lea	5(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit7):
-	lea	6(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit9):
-	lea	8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit10):
-	lea	9(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit11):
-	lea	10(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit12):
-	lea	11(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit13):
-	lea	12(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit14):
-	lea	13(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit15):
-	lea	14(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	RETURN
-
-END (strchr)
diff --git a/libc/arch-x86/string/sse2-strnlen-atom.S b/libc/arch-x86/string/sse2-strnlen-atom.S
deleted file mode 100644
index 1f89b4ec9..000000000
--- a/libc/arch-x86/string/sse2-strnlen-atom.S
+++ /dev/null
@@ -1,33 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#define USE_AS_STRNLEN 1
-#define STRLEN  strnlen
-#include "sse2-strlen-atom.S"
diff --git a/libc/arch-x86/string/sse2-strrchr-atom.S b/libc/arch-x86/string/sse2-strrchr-atom.S
deleted file mode 100644
index e916bc1e5..000000000
--- a/libc/arch-x86/string/sse2-strrchr-atom.S
+++ /dev/null
@@ -1,753 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name, @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl REG; CFI_PUSH (REG)
-#define POP(REG)	popl REG; CFI_POP (REG)
-
-#define PARMS	8
-#define ENTRANCE	PUSH(%edi);
-#define RETURN	POP (%edi); ret; CFI_PUSH (%edi);
-
-#define STR1  PARMS
-#define STR2  STR1+4
-
-	.text
-ENTRY (strrchr)
-
-	ENTRANCE
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-
-	pxor	%xmm2, %xmm2
-	mov	%ecx, %edi
-	punpcklbw %xmm1, %xmm1
-	punpcklbw %xmm1, %xmm1
-	/* ECX has OFFSET. */
-	and	$63, %ecx
-	pshufd	$0, %xmm1, %xmm1
-	cmp	$48, %ecx
-	ja	L(crosscache)
-
-/* unaligned string. */
-	movdqu	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	pcmpeqb	%xmm1, %xmm0
-	/* Find where NULL is.  */
-	pmovmskb %xmm2, %ecx
-	/* Check if there is a match.  */
-	pmovmskb %xmm0, %eax
-	add	$16, %edi
-
-	test	%eax, %eax
-	jnz	L(unaligned_match1)
-
-	test	%ecx, %ecx
-	jnz	L(return_null)
-
-	and	$-16, %edi
-
-	PUSH	(%esi)
-	PUSH	(%ebx)
-
-	xor	%ebx, %ebx
-	jmp	L(loop)
-
-	CFI_POP    (%esi)
-	CFI_POP    (%ebx)
-
-	.p2align 4
-L(unaligned_match1):
-	test	%ecx, %ecx
-	jnz	L(prolog_find_zero_1)
-
-	PUSH	(%esi)
-	PUSH	(%ebx)
-
-	mov	%eax, %ebx
-	mov	%edi, %esi
-	and	$-16, %edi
-	jmp	L(loop)
-
-	CFI_POP    (%esi)
-	CFI_POP    (%ebx)
-
-	.p2align 4
-L(crosscache):
-/* Hancle unaligned string.  */
-	and	$15, %ecx
-	and	$-16, %edi
-	pxor	%xmm3, %xmm3
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm3
-	pcmpeqb	%xmm1, %xmm0
-	/* Find where NULL is.  */
-	pmovmskb %xmm3, %edx
-	/* Check if there is a match.  */
-	pmovmskb %xmm0, %eax
-	/* Remove the leading bytes.  */
-	shr	%cl, %edx
-	shr	%cl, %eax
-	add	$16, %edi
-
-	test	%eax, %eax
-	jnz	L(unaligned_match)
-
-	test	%edx, %edx
-	jnz	L(return_null)
-
-	PUSH	(%esi)
-	PUSH	(%ebx)
-
-	xor	%ebx, %ebx
-	jmp	L(loop)
-
-	CFI_POP    (%esi)
-	CFI_POP    (%ebx)
-
-	.p2align 4
-L(unaligned_match):
-	test	%edx, %edx
-	jnz	L(prolog_find_zero)
-
-	PUSH	(%esi)
-	PUSH	(%ebx)
-
-	mov	%eax, %ebx
-	lea	(%edi, %ecx), %esi
-
-/* Loop start on aligned string.  */
-	.p2align 4
-L(loop):
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	add	$16, %edi
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm0, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	add	$16, %edi
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm0, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	add	$16, %edi
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm0, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm0
-	pcmpeqb	%xmm0, %xmm2
-	add	$16, %edi
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm0, %eax
-	or	%eax, %ecx
-	jz	L(loop)
-
-L(matches):
-	test	%eax, %eax
-	jnz	L(match)
-L(return_value):
-	test	%ebx, %ebx
-	jz	L(return_null_1)
-	mov	%ebx, %eax
-	mov	%esi, %edi
-
-	POP	(%ebx)
-	POP	(%esi)
-
-	jmp	L(match_case1)
-
-	CFI_PUSH    (%ebx)
-	CFI_PUSH    (%esi)
-
-	.p2align 4
-L(return_null_1):
-	POP	(%ebx)
-	POP	(%esi)
-
-	xor	%eax, %eax
-	RETURN
-
-	CFI_PUSH    (%ebx)
-	CFI_PUSH    (%esi)
-
-	.p2align 4
-L(match):
-	pmovmskb %xmm2, %ecx
-	test	%ecx, %ecx
-	jnz	L(find_zero)
-	mov	%eax, %ebx
-	mov	%edi, %esi
-	jmp	L(loop)
-
-	.p2align 4
-L(find_zero):
-	test	%cl, %cl
-	jz	L(find_zero_high)
-	mov	%cl, %dl
-	and	$15, %dl
-	jz	L(find_zero_8)
-	test	$0x01, %cl
-	jnz	L(FindZeroExit1)
-	test	$0x02, %cl
-	jnz	L(FindZeroExit2)
-	test	$0x04, %cl
-	jnz	L(FindZeroExit3)
-	and	$(1 << 4) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_8):
-	test	$0x10, %cl
-	jnz	L(FindZeroExit5)
-	test	$0x20, %cl
-	jnz	L(FindZeroExit6)
-	test	$0x40, %cl
-	jnz	L(FindZeroExit7)
-	and	$(1 << 8) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_high):
-	mov	%ch, %dh
-	and	$15, %dh
-	jz	L(find_zero_high_8)
-	test	$0x01, %ch
-	jnz	L(FindZeroExit9)
-	test	$0x02, %ch
-	jnz	L(FindZeroExit10)
-	test	$0x04, %ch
-	jnz	L(FindZeroExit11)
-	and	$(1 << 12) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_high_8):
-	test	$0x10, %ch
-	jnz	L(FindZeroExit13)
-	test	$0x20, %ch
-	jnz	L(FindZeroExit14)
-	test	$0x40, %ch
-	jnz	L(FindZeroExit15)
-	and	$(1 << 16) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit1):
-	and	$1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit2):
-	and	$(1 << 2) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit3):
-	and	$(1 << 3) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit5):
-	and	$(1 << 5) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit6):
-	and	$(1 << 6) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit7):
-	and	$(1 << 7) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit9):
-	and	$(1 << 9) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit10):
-	and	$(1 << 10) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit11):
-	and	$(1 << 11) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit13):
-	and	$(1 << 13) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit14):
-	and	$(1 << 14) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-	jmp     L(match_case1)
-
-	CFI_PUSH	(%ebx)
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(FindZeroExit15):
-	and	$(1 << 15) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%ebx)
-	POP	(%esi)
-
-	.p2align 4
-L(match_case1):
-	test	%ah, %ah
-	jnz	L(match_case1_high)
-	mov	%al, %dl
-	and	$15 << 4, %dl
-	jnz	L(match_case1_8)
-	test	$0x08, %al
-	jnz	L(Exit4)
-	test	$0x04, %al
-	jnz	L(Exit3)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	lea	-16(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_8):
-	test	$0x80, %al
-	jnz	L(Exit8)
-	test	$0x40, %al
-	jnz	L(Exit7)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	lea	-12(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_high):
-	mov	%ah, %dh
-	and	$15 << 4, %dh
-	jnz	L(match_case1_high_8)
-	test	$0x08, %ah
-	jnz	L(Exit12)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	lea	-8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_case1_high_8):
-	test	$0x80, %ah
-	jnz	L(Exit16)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	lea	-4(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit2):
-	lea	-15(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit3):
-	lea	-14(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit4):
-	lea	-13(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit6):
-	lea	-11(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit7):
-	lea	-10(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit8):
-	lea	-9(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit10):
-	lea	-7(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit11):
-	lea	-6(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit12):
-	lea	-5(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit14):
-	lea	-3(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit15):
-	lea	-2(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(Exit16):
-	lea	-1(%edi), %eax
-	RETURN
-
-/* Return NULL.  */
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero):
-	add	%ecx, %edi
-	mov     %edx, %ecx
-L(prolog_find_zero_1):
-	test	%cl, %cl
-	jz	L(prolog_find_zero_high)
-	mov	%cl, %dl
-	and	$15, %dl
-	jz	L(prolog_find_zero_8)
-	test	$0x01, %cl
-	jnz	L(PrologFindZeroExit1)
-	test	$0x02, %cl
-	jnz	L(PrologFindZeroExit2)
-	test	$0x04, %cl
-	jnz	L(PrologFindZeroExit3)
-	and	$(1 << 4) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_8):
-	test	$0x10, %cl
-	jnz	L(PrologFindZeroExit5)
-	test	$0x20, %cl
-	jnz	L(PrologFindZeroExit6)
-	test	$0x40, %cl
-	jnz	L(PrologFindZeroExit7)
-	and	$(1 << 8) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_high):
-	mov	%ch, %dh
-	and	$15, %dh
-	jz	L(prolog_find_zero_high_8)
-	test	$0x01, %ch
-	jnz	L(PrologFindZeroExit9)
-	test	$0x02, %ch
-	jnz	L(PrologFindZeroExit10)
-	test	$0x04, %ch
-	jnz	L(PrologFindZeroExit11)
-	and	$(1 << 12) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_high_8):
-	test	$0x10, %ch
-	jnz	L(PrologFindZeroExit13)
-	test	$0x20, %ch
-	jnz	L(PrologFindZeroExit14)
-	test	$0x40, %ch
-	jnz	L(PrologFindZeroExit15)
-	and	$(1 << 16) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit1):
-	and	$1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit2):
-	and	$(1 << 2) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit3):
-	and	$(1 << 3) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit5):
-	and	$(1 << 5) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit6):
-	and	$(1 << 6) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit7):
-	and	$(1 << 7) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit9):
-	and	$(1 << 9) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit10):
-	and	$(1 << 10) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit11):
-	and	$(1 << 11) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit13):
-	and	$(1 << 13) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit14):
-	and	$(1 << 14) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(PrologFindZeroExit15):
-	and	$(1 << 15) - 1, %eax
-	jnz	L(match_case1)
-	xor	%eax, %eax
-	RETURN
-
-END (strrchr)
diff --git a/libc/arch-x86_64/string/sse2-memmove-slm.S b/libc/arch-x86_64/string/sse2-memmove-slm.S
index 8b32680ba..9f5fb1213 100644
--- a/libc/arch-x86_64/string/sse2-memmove-slm.S
+++ b/libc/arch-x86_64/string/sse2-memmove-slm.S
@@ -79,21 +79,31 @@ name:		\
 #endif
 
 #define CFI_PUSH(REG)		\
-	cfi_adjust_cfa_offset (4);		\
+	cfi_adjust_cfa_offset (8);		\
 	cfi_rel_offset (REG, 0)
 
 #define CFI_POP(REG)		\
-	cfi_adjust_cfa_offset (-4);		\
+	cfi_adjust_cfa_offset (-8);		\
 	cfi_restore (REG)
 
 #define PUSH(REG)	push REG;
 #define POP(REG)	pop REG;
 
-#define ENTRANCE	PUSH (%rbx);
-#define RETURN_END	POP (%rbx); ret
+#define ENTRANCE	\
+    PUSH (%rbx);    \
+    CFI_PUSH (%rbx);
+#define RETURN_END	\
+    POP (%rbx);     \
+    CFI_POP (%rbx); \
+    ret
 #define RETURN		RETURN_END;
 
 	.section .text.sse2,"ax",@progbits
+ENTRY (__memcpy_chk)
+	cmp	%rcx, %rdx
+	ja	__memcpy_chk_fail
+/* Fall through to memcpy/memmove. */
+END (__memcpy_chk)
 ENTRY (MEMMOVE)
 	ENTRANCE
 	mov	%rdi, %rax
diff --git a/libc/bionic/__bionic_get_shell_path.cpp b/libc/bionic/__bionic_get_shell_path.cpp
index 3ea256deb..de79325e2 100644
--- a/libc/bionic/__bionic_get_shell_path.cpp
+++ b/libc/bionic/__bionic_get_shell_path.cpp
@@ -28,15 +28,15 @@
 
 #include "private/__bionic_get_shell_path.h"
 
+#include <unistd.h>
+
 const char* __bionic_get_shell_path() {
-  // For the host Bionic, we use the standard /bin/sh.
-  // Since P there's a /bin -> /system/bin symlink that means this will work
-  // for the device too, but as long as the NDK supports earlier API levels,
-  // we should probably make sure that this works in static binaries run on
-  // those OS versions too.
-#if !defined(__ANDROID__)
-  return "/bin/sh";
-#else
-  return "/system/bin/sh";
-#endif
+  // Since API level 28 there's a /bin -> /system/bin symlink that means
+  // /bin/sh will work for the device too, but as long as the NDK supports
+  // earlier API levels, falling back to /system/bin/sh ensures that static
+  // binaries run on those OS versions too.
+  // This whole function can be removed and replaced by hard-coded /bin/sh
+  // when we no longer support anything below API level 28.
+  static bool have_bin_sh = !access("/bin/sh", F_OK);
+  return have_bin_sh ? "/bin/sh" : "/system/bin/sh";
 }
diff --git a/libc/bionic/clock_getcpuclockid.cpp b/libc/bionic/clock_getcpuclockid.cpp
index 9ff1845fb..65ba2c7a4 100644
--- a/libc/bionic/clock_getcpuclockid.cpp
+++ b/libc/bionic/clock_getcpuclockid.cpp
@@ -34,11 +34,12 @@
 int clock_getcpuclockid(pid_t pid, clockid_t* clockid) {
   ErrnoRestorer errno_restorer;
 
-  // The tid is stored in the top bits, but negated.
+  // The pid is stored in the top bits, but negated.
   clockid_t result = ~static_cast<clockid_t>(pid) << 3;
   // Bits 0 and 1: clock type (0 = CPUCLOCK_PROF, 1 = CPUCLOCK_VIRT, 2 = CPUCLOCK_SCHED).
-  result |= 2;
-  // Bit 2: thread (set) or process (clear). Bit 2 already 0.
+  result |= 2 /* CPUCLOCK_SCHED */;
+  // Bit 2: thread (set) or process (clear).
+  result &= ~4 /* CPUCLOCK_PERTHREAD_MASK */;
 
   if (clock_getres(result, nullptr) == -1) {
     return ESRCH;
diff --git a/libc/bionic/elf_note.cpp b/libc/bionic/elf_note.cpp
index 9cc6b2159..28a400a77 100644
--- a/libc/bionic/elf_note.cpp
+++ b/libc/bionic/elf_note.cpp
@@ -42,16 +42,18 @@ bool __get_elf_note(unsigned note_type, const char* note_name, const ElfW(Addr)
 
   ElfW(Addr) p = note_addr;
   ElfW(Addr) note_end = p + phdr_note->p_memsz;
-  while (p + sizeof(ElfW(Nhdr)) <= note_end) {
+  while (p < note_end) {
     // Parse the note and check it's structurally valid.
     const ElfW(Nhdr)* note = reinterpret_cast<const ElfW(Nhdr)*>(p);
-    p += sizeof(ElfW(Nhdr));
+    if (__builtin_add_overflow(p, sizeof(ElfW(Nhdr)), &p) || p >= note_end) {
+      return false;
+    }
     const char* name = reinterpret_cast<const char*>(p);
-    if (__builtin_add_overflow(p, align_up(note->n_namesz, 4), &p)) {
+    if (__builtin_add_overflow(p, __builtin_align_up(note->n_namesz, 4), &p)) {
       return false;
     }
     const char* desc = reinterpret_cast<const char*>(p);
-    if (__builtin_add_overflow(p, align_up(note->n_descsz, 4), &p)) {
+    if (__builtin_add_overflow(p, __builtin_align_up(note->n_descsz, 4), &p)) {
       return false;
     }
     if (p > note_end) {
diff --git a/libc/bionic/fortify.cpp b/libc/bionic/fortify.cpp
index 80f7c20ac..15053d3b9 100644
--- a/libc/bionic/fortify.cpp
+++ b/libc/bionic/fortify.cpp
@@ -489,16 +489,6 @@ extern "C" char* __STRCPY_CHK(char* dst, const char* src, size_t dst_len) {
   return strcpy(dst, src);
 }
 
-#if !defined(__arm__) && !defined(__aarch64__) && !defined(__riscv)
-// Runtime implementation of __memcpy_chk (used directly by compiler, not in headers).
-// arm32,arm64,riscv have assembler implementations, and don't need this C fallback.
-extern "C" void* __memcpy_chk(void* dst, const void* src, size_t count, size_t dst_len) {
-  __check_count("memcpy", "count", count);
-  __check_buffer_access("memcpy", "write into", count, dst_len);
-  return memcpy(dst, src, count);
-}
-#endif
-
 // Runtime implementation of __mempcpy_chk (used directly by compiler, not in headers).
 extern "C" void* __mempcpy_chk(void* dst, const void* src, size_t count, size_t dst_len) {
   __check_count("mempcpy", "count", count);
diff --git a/libc/bionic/fts.c b/libc/bionic/fts.c
index c36835e3c..072d297cc 100644
--- a/libc/bionic/fts.c
+++ b/libc/bionic/fts.c
@@ -892,7 +892,9 @@ fts_sort(FTS *sp, FTSENT *head, int nitems)
 	}
 	for (ap = sp->fts_array, p = head; p; p = p->fts_link)
 		*ap++ = p;
-	qsort(sp->fts_array, nitems, sizeof(FTSENT *), sp->fts_compar);
+	// The cast here is to cast away the nullability.
+	// fts_compar is nullable, but we only enter this function if it's non-null.
+	qsort(sp->fts_array, nitems, sizeof(FTSENT *), (int (*)(const void*, const void*)) sp->fts_compar);
 	for (head = *(ap = sp->fts_array); --nitems; ++ap)
 		ap[0]->fts_link = ap[1];
 	ap[0]->fts_link = NULL;
diff --git a/libc/bionic/heap_tagging.cpp b/libc/bionic/heap_tagging.cpp
index 6741be387..c7319708c 100644
--- a/libc/bionic/heap_tagging.cpp
+++ b/libc/bionic/heap_tagging.cpp
@@ -123,6 +123,7 @@ bool SetHeapTaggingLevel(HeapTaggingLevel tag_level) {
         }
         atomic_store(&__libc_memtag_stack, false);
         atomic_store(&globals->memtag, false);
+        atomic_store(&__libc_shared_globals()->memtag_currently_on, false);
       });
 
       if (heap_tagging_level != M_HEAP_TAGGING_LEVEL_TBI) {
diff --git a/libc/bionic/icu.cpp b/libc/bionic/icu.cpp
deleted file mode 100644
index c11b9d60b..000000000
--- a/libc/bionic/icu.cpp
+++ /dev/null
@@ -1,61 +0,0 @@
-/*
- * Copyright (C) 2016 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include "private/icu.h"
-
-#include <dirent.h>
-#include <dlfcn.h>
-#include <pthread.h>
-#include <stdlib.h>
-#include <string.h>
-
-#include <async_safe/log.h>
-
-static void* g_libicu_handle = nullptr;
-
-static bool __find_icu() {
-  g_libicu_handle = dlopen("libicu.so", RTLD_LOCAL);
-  if (g_libicu_handle == nullptr) {
-    async_safe_format_log(ANDROID_LOG_ERROR, "bionic-icu", "couldn't open libicu.so: %s",
-                          dlerror());
-    return false;
-  }
-
-  return true;
-}
-
-void* __find_icu_symbol(const char* symbol_name) {
-  static bool found_icu = __find_icu();
-  if (!found_icu) return nullptr;
-
-  void* symbol = dlsym(g_libicu_handle, symbol_name);
-  if (symbol == nullptr) {
-    async_safe_format_log(ANDROID_LOG_ERROR, "bionic-icu", "couldn't find %s", symbol_name);
-  }
-  return symbol;
-}
diff --git a/libc/bionic/icu4x.rs b/libc/bionic/icu4x.rs
new file mode 100644
index 000000000..939ba2fed
--- /dev/null
+++ b/libc/bionic/icu4x.rs
@@ -0,0 +1,98 @@
+// Copyright (C) 2025 The Android Open Source Project
+// SPDX-License-Identifier: Apache-2.0
+
+#![allow(missing_docs)] // Not particularly useful to document these thin wrappers
+
+//! This is a thin wrapper around ICU4X for use in Bionic
+
+use icu_casemap::CaseMapper;
+use icu_collections::codepointtrie::TrieValue;
+use icu_properties::props::*;
+use icu_properties::{CodePointMapData, CodePointSetData};
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_general_category(ch: u32) -> u8 {
+    CodePointMapData::<GeneralCategory>::new().get32(ch) as u8
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_east_asian_width(ch: u32) -> u8 {
+    CodePointMapData::<EastAsianWidth>::new().get32(ch).to_u32() as u8
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_hangul_syllable_type(ch: u32) -> u8 {
+    CodePointMapData::<HangulSyllableType>::new().get32(ch).to_u32() as u8
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_alphabetic(ch: u32) -> bool {
+    CodePointSetData::new::<Alphabetic>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_default_ignorable_code_point(ch: u32) -> bool {
+    CodePointSetData::new::<DefaultIgnorableCodePoint>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_lowercase(ch: u32) -> bool {
+    CodePointSetData::new::<Lowercase>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_alnum(ch: u32) -> bool {
+    CodePointSetData::new::<Alnum>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_blank(ch: u32) -> bool {
+    CodePointSetData::new::<Blank>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_graph(ch: u32) -> bool {
+    CodePointSetData::new::<Graph>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_print(ch: u32) -> bool {
+    CodePointSetData::new::<Print>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_xdigit(ch: u32) -> bool {
+    CodePointSetData::new::<Xdigit>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_white_space(ch: u32) -> bool {
+    CodePointSetData::new::<WhiteSpace>().contains32(ch)
+}
+
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_is_uppercase(ch: u32) -> bool {
+    CodePointSetData::new::<Uppercase>().contains32(ch)
+}
+
+/// Convert a code point to uppercase
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_to_upper(ch: u32) -> u32 {
+    let Ok(ch) = char::try_from(ch) else {
+        return ch;
+    };
+    let cm = CaseMapper::new();
+
+    cm.simple_uppercase(ch) as u32
+}
+
+/// Convert a code point to lowercase
+#[no_mangle]
+pub extern "C" fn __icu4x_bionic_to_lower(ch: u32) -> u32 {
+    let Ok(ch) = char::try_from(ch) else {
+        return ch;
+    };
+    let cm = CaseMapper::new();
+
+    cm.simple_lowercase(ch) as u32
+}
diff --git a/libc/bionic/icu_static.cpp b/libc/bionic/icu_static.cpp
deleted file mode 100644
index cf24a381c..000000000
--- a/libc/bionic/icu_static.cpp
+++ /dev/null
@@ -1,34 +0,0 @@
-/*
- * Copyright (C) 2016 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include "private/icu.h"
-
-// We don't have dlopen/dlsym for static binaries yet.
-void* __find_icu_symbol(const char*) {
-  return nullptr;
-}
diff --git a/libc/bionic/icu_wrappers.cpp b/libc/bionic/icu_wrappers.cpp
deleted file mode 100644
index 523f5a639..000000000
--- a/libc/bionic/icu_wrappers.cpp
+++ /dev/null
@@ -1,42 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include "private/icu.h"
-
-int8_t __icu_charType(wint_t wc) {
-  typedef int8_t (*u_charType_t)(UChar32);
-  static auto u_charType = reinterpret_cast<u_charType_t>(__find_icu_symbol("u_charType"));
-  return u_charType ? u_charType(wc) : -1;
-}
-
-int32_t __icu_getIntPropertyValue(wint_t wc, UProperty property) {
-  typedef int32_t (*u_getIntPropertyValue_t)(UChar32, UProperty);
-  static auto u_getIntPropertyValue =
-      reinterpret_cast<u_getIntPropertyValue_t>(__find_icu_symbol("u_getIntPropertyValue"));
-  return u_getIntPropertyValue ? u_getIntPropertyValue(wc, property) : 0;
-}
diff --git a/libc/bionic/libc_init_common.h b/libc/bionic/libc_init_common.h
index 126f002c1..9e1581197 100644
--- a/libc/bionic/libc_init_common.h
+++ b/libc/bionic/libc_init_common.h
@@ -44,10 +44,12 @@ typedef struct {
   size_t fini_array_count;
 } structors_array_t;
 
-__BEGIN_DECLS
-
+// The main function must not be declared with a linkage-specification
+// ('extern "C"' or 'extern "C++"'), so declare it before __BEGIN_DECLS.
 extern int main(int argc, char** argv, char** env);
 
+__BEGIN_DECLS
+
 __noreturn void __libc_init(void* raw_args,
                             void (*onexit)(void),
                             int (*slingshot)(int, char**, char**),
diff --git a/libc/bionic/libc_init_mte.cpp b/libc/bionic/libc_init_mte.cpp
index 3c8ef7da6..d23b0563d 100644
--- a/libc/bionic/libc_init_mte.cpp
+++ b/libc/bionic/libc_init_mte.cpp
@@ -246,6 +246,7 @@ static int64_t __get_memtag_upgrade_secs() {
 __attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte(
     const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start, size_t phdr_ct,
     uintptr_t load_bias) {
+  if (__libc_shared_globals()->is_hwasan) return;
   bool memtag_stack = false;
   HeapTaggingLevel level =
       __get_tagging_level(memtag_dynamic_entries, phdr_start, phdr_ct, load_bias, &memtag_stack);
@@ -273,6 +274,7 @@ __attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte(
     if (prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg | PR_MTE_TCF_SYNC, 0, 0, 0) == 0 ||
         prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg, 0, 0, 0) == 0) {
       __libc_shared_globals()->initial_heap_tagging_level = level;
+      atomic_store(&__libc_shared_globals()->memtag_currently_on, true);
 
       struct sigaction action = {};
       action.sa_flags = SA_SIGINFO | SA_RESTART;
@@ -320,6 +322,5 @@ void __libc_init_mte_stack(void*) {}
 #endif  // __aarch64__
 
 bool __libc_mte_enabled() {
-  HeapTaggingLevel lvl = __libc_shared_globals()->initial_heap_tagging_level;
-  return lvl == M_HEAP_TAGGING_LEVEL_SYNC || lvl == M_HEAP_TAGGING_LEVEL_ASYNC;
+  return atomic_load(&__libc_shared_globals()->memtag_currently_on);
 }
diff --git a/libc/bionic/libc_init_static.cpp b/libc/bionic/libc_init_static.cpp
index cd963754a..9cc3060f6 100644
--- a/libc/bionic/libc_init_static.cpp
+++ b/libc/bionic/libc_init_static.cpp
@@ -28,34 +28,25 @@
 
 #include <android/api-level.h>
 #include <elf.h>
-#include <errno.h>
 #include <malloc.h>
 #include <signal.h>
 #include <stddef.h>
-#include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <sys/auxv.h>
 #include <sys/mman.h>
 
 #include "async_safe/log.h"
-#include "heap_tagging.h"
 #include "libc_init_common.h"
 #include "platform/bionic/macros.h"
-#include "platform/bionic/mte.h"
 #include "platform/bionic/page.h"
 #include "platform/bionic/reserved_signals.h"
 #include "private/KernelArgumentBlock.h"
-#include "private/bionic_asm.h"
-#include "private/bionic_asm_note.h"
 #include "private/bionic_call_ifunc_resolver.h"
 #include "private/bionic_elf_tls.h"
 #include "private/bionic_globals.h"
 #include "private/bionic_tls.h"
-#include "private/elf_note.h"
 #include "pthread_internal.h"
-#include "sys/system_properties.h"
-#include "sysprop_helpers.h"
 
 #if __has_feature(hwaddress_sanitizer)
 #include <sanitizer/hwasan_interface.h>
@@ -69,7 +60,6 @@ __LIBC_HIDDEN__ void* __libc_sysinfo;
 #endif
 
 extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
-extern "C" const char* __gnu_basename(const char* path);
 
 static void call_array(init_func_t** list, size_t count, int argc, char* argv[], char* envp[]) {
   while (count-- > 0) {
@@ -157,6 +147,7 @@ static void layout_static_tls(KernelArgumentBlock& args) {
 
   layout.finish_layout();
 }
+
 void __libc_init_profiling_handlers() {
   // The dynamic variant of this function is more interesting, but this
   // at least ensures that static binaries aren't killed by the kernel's
@@ -167,7 +158,7 @@ void __libc_init_profiling_handlers() {
 }
 
 __attribute__((no_sanitize("memtag"))) __noreturn static void __real_libc_init(
-    KernelArgumentBlock& args, void* raw_args, void (*onexit)(void) __unused,
+    KernelArgumentBlock& args, void* raw_args __unused, void (*onexit)(void) __unused,
     int (*slingshot)(int, char**, char**), structors_array_t const* const structors,
     bionic_tcb* temp_tcb) {
   BIONIC_STOP_UNWIND;
@@ -180,11 +171,14 @@ __attribute__((no_sanitize("memtag"))) __noreturn static void __real_libc_init(
   layout_static_tls(args);
   __libc_init_main_thread_final();
   __libc_init_common();
+#if !__has_feature(hwaddress_sanitizer)
   __libc_init_mte(/*memtag_dynamic_entries=*/nullptr,
                   reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR)), getauxval(AT_PHNUM),
                   /*load_bias = */ 0);
   __libc_init_mte_stack(/*stack_top = */ raw_args);
+#endif
   __libc_init_scudo();
+  __libc_globals.mutate(__libc_init_malloc);
   __libc_init_profiling_handlers();
   __libc_init_fork_handler();
 
@@ -204,8 +198,9 @@ __attribute__((no_sanitize("memtag"))) __noreturn static void __real_libc_init(
   if (structors->fini_array_count > 0) {
     __cxa_atexit(call_fini_array, const_cast<structors_array_t*>(structors), nullptr);
   }
-
+#if !__has_feature(hwaddress_sanitizer)
   __libc_init_mte_late();
+#endif
 
   exit(slingshot(args.argc, args.argv, args.envp));
 }
diff --git a/libc/bionic/malloc_common.cpp b/libc/bionic/malloc_common.cpp
index 441d88482..1e0ef142c 100644
--- a/libc/bionic/malloc_common.cpp
+++ b/libc/bionic/malloc_common.cpp
@@ -41,6 +41,7 @@
 #include <platform/bionic/malloc.h>
 #include <private/ScopedPthreadMutexLocker.h>
 #include <private/bionic_config.h>
+#include <private/bionic_defs.h>
 
 #include "gwp_asan_wrappers.h"
 #include "heap_tagging.h"
@@ -358,3 +359,37 @@ static constexpr MallocDispatch __libc_malloc_default_dispatch __attribute__((un
 const MallocDispatch* NativeAllocatorDispatch() {
   return &__libc_malloc_default_dispatch;
 }
+
+#if !defined(LIBC_STATIC)
+void MallocInitImpl(libc_globals* globals);
+#endif
+
+// Initializes memory allocation framework.
+// This routine is called from __libc_init routines in libc_init_dynamic.cpp
+// and libc_init_static.cpp.
+__BIONIC_WEAK_FOR_NATIVE_BRIDGE
+__LIBC_HIDDEN__ void __libc_init_malloc(libc_globals* globals) {
+#if !defined(LIBC_STATIC)
+  MallocInitImpl(globals);
+#endif
+  const char* value = getenv("MALLOC_USE_APP_DEFAULTS");
+  if (value == nullptr || value[0] == '\0') {
+    return;
+  }
+
+  // Normal apps currently turn off zero init for performance reasons.
+  SetHeapZeroInitialize(false);
+
+  // Do not call mallopt directly since that will try and lock the globals
+  // data structure.
+  int retval;
+  auto dispatch_table = GetDispatchTable();
+  if (__predict_false(dispatch_table != nullptr)) {
+    retval = dispatch_table->mallopt(M_DECAY_TIME, 1);
+  } else {
+    retval = Malloc(mallopt)(M_DECAY_TIME, 1);
+  }
+  if (retval == 1) {
+    globals->decay_time_enabled = true;
+  }
+}
diff --git a/libc/bionic/malloc_common_dynamic.cpp b/libc/bionic/malloc_common_dynamic.cpp
index 7b6d7d49c..e2c6eb125 100644
--- a/libc/bionic/malloc_common_dynamic.cpp
+++ b/libc/bionic/malloc_common_dynamic.cpp
@@ -375,7 +375,7 @@ extern "C" size_t __scudo_get_ring_buffer_size();
 extern "C" size_t __scudo_get_stack_depot_size();
 
 // Initializes memory allocation framework once per process.
-static void MallocInitImpl(libc_globals* globals) {
+void MallocInitImpl(libc_globals* globals) {
   char prop[PROP_VALUE_MAX];
   char* options = prop;
 
@@ -409,13 +409,6 @@ static void MallocInitImpl(libc_globals* globals) {
   }
 }
 
-// Initializes memory allocation framework.
-// This routine is called from __libc_init routines in libc_init_dynamic.cpp.
-__BIONIC_WEAK_FOR_NATIVE_BRIDGE
-__LIBC_HIDDEN__ void __libc_init_malloc(libc_globals* globals) {
-  MallocInitImpl(globals);
-}
-
 // =============================================================================
 // Functions to support dumping of native heap allocations using malloc debug.
 // =============================================================================
diff --git a/libc/bionic/ndk_cruft.cpp b/libc/bionic/ndk_cruft.cpp
index b15a3171f..a69b77f77 100644
--- a/libc/bionic/ndk_cruft.cpp
+++ b/libc/bionic/ndk_cruft.cpp
@@ -28,6 +28,9 @@
 
 // This file perpetuates the mistakes of the past.
 
+// LP64 doesn't need to support any legacy cruft.
+#if !defined(__LP64__)
+
 #include <ctype.h>
 #include <dirent.h>
 #include <errno.h>
@@ -47,10 +50,19 @@
 
 #include "platform/bionic/macros.h"
 
-extern "C" {
+#define __futex_wake __real_futex_wake
+#define __futex_wait __real_futex_wait
+#include "private/bionic_futex.h"
+#undef __futex_wake
+#undef __futex_wait
 
-// LP64 doesn't need to support any legacy cruft.
-#if !defined(__LP64__)
+#define __get_thread __real_get_thread
+#define __get_tls __real_get_tls
+#include "pthread_internal.h"
+#undef __get_thread
+#undef __get_tls
+
+extern "C" {
 
 // By the time any NDK-built code is running, there are plenty of threads.
 int __isthreaded = 1;
@@ -73,8 +85,7 @@ int __open() {
 
 // TODO: does anything still need this?
 void** __get_tls() {
-#include "platform/bionic/tls.h"
-  return __get_tls();
+  return __real_get_tls();
 }
 
 // This non-standard function was in our <string.h> for some reason.
@@ -213,12 +224,6 @@ int vfdprintf(int fd, const char* fmt, va_list ap) {
   return vdprintf(fd, fmt, ap);
 }
 
-#define __futex_wake __real_futex_wake
-#define __futex_wait __real_futex_wait
-#include "private/bionic_futex.h"
-#undef __futex_wake
-#undef __futex_wait
-
 // This used to be in <sys/atomics.h>.
 int __futex_wake(volatile void* ftx, int count) {
   return __real_futex_wake(ftx, count);
@@ -356,14 +361,6 @@ void* dlmalloc(size_t size) {
   return malloc(size);
 }
 
-} // extern "C"
-
-#define __get_thread __real_get_thread
-#include "pthread_internal.h"
-#undef __get_thread
-
-extern "C" {
-
 // Various third-party apps contain a backport of our pthread_rwlock implementation that uses this.
 pthread_internal_t* __get_thread() {
   return __real_get_thread();
@@ -388,6 +385,6 @@ int putw(int value, FILE* fp) {
     return fwrite(&value, sizeof(value), 1, fp) == 1 ? 0 : EOF;
 }
 
-#endif // !defined (__LP64__)
-
 } // extern "C"
+
+#endif // !defined (__LP64__)
diff --git a/libc/bionic/pthread_create.cpp b/libc/bionic/pthread_create.cpp
index 3fa8ee683..1bd2da792 100644
--- a/libc/bionic/pthread_create.cpp
+++ b/libc/bionic/pthread_create.cpp
@@ -129,7 +129,7 @@ static void __init_shadow_call_stack(pthread_internal_t* thread __unused) {
   // Align the address to SCS_SIZE so that we only need to store the lower log2(SCS_SIZE) bits
   // in jmp_buf. See the SCS commentary in pthread_internal.h for more detail.
   char* scs_aligned_guard_region =
-      reinterpret_cast<char*>(align_up(reinterpret_cast<uintptr_t>(scs_guard_region), SCS_SIZE));
+      reinterpret_cast<char*>(__builtin_align_up(reinterpret_cast<uintptr_t>(scs_guard_region), SCS_SIZE));
 
   // We need to ensure that [scs_offset,scs_offset+SCS_SIZE) is in the guard region and that there
   // is at least one unmapped page after the shadow call stack (to catch stack overflows). We can't
@@ -296,7 +296,7 @@ static int __allocate_thread(pthread_attr_t* attr, bionic_tcb** tcbp, void** chi
   // memory isn't counted in pthread_attr_getstacksize.
 
   // To safely access the pthread_internal_t and thread stack, we need to find a 16-byte aligned boundary.
-  stack_top = align_down(stack_top - sizeof(pthread_internal_t), 16);
+  stack_top = __builtin_align_down(stack_top - sizeof(pthread_internal_t), 16);
 
   pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(stack_top);
   if (!stack_clean) {
diff --git a/libc/bionic/pthread_getcpuclockid.cpp b/libc/bionic/pthread_getcpuclockid.cpp
index 6d1884ef7..ccadc983a 100644
--- a/libc/bionic/pthread_getcpuclockid.cpp
+++ b/libc/bionic/pthread_getcpuclockid.cpp
@@ -39,9 +39,9 @@ int pthread_getcpuclockid(pthread_t t, clockid_t* clockid) {
   // The tid is stored in the top bits, but negated.
   clockid_t result = ~static_cast<clockid_t>(tid) << 3;
   // Bits 0 and 1: clock type (0 = CPUCLOCK_PROF, 1 = CPUCLOCK_VIRT, 2 = CPUCLOCK_SCHED).
-  result |= 2;
+  result |= 2 /* CPUCLOCK_SCHED */;
   // Bit 2: thread (set) or process (clear)?
-  result |= (1 << 2);
+  result |= 4 /* CPUCLOCK_PERTHREAD_MASK */;
 
   *clockid = result;
   return 0;
diff --git a/libc/bionic/pthread_internal.h b/libc/bionic/pthread_internal.h
index cbaa9a6a9..ae9a7913b 100644
--- a/libc/bionic/pthread_internal.h
+++ b/libc/bionic/pthread_internal.h
@@ -240,8 +240,6 @@ static inline void __set_tcb_dtv(bionic_tcb* tcb, TlsDtv* val) {
   tcb->tls_slot(TLS_SLOT_DTV) = &val->generation;
 }
 
-extern "C" __LIBC_HIDDEN__ int __set_tls(void* ptr);
-
 __LIBC_HIDDEN__ void pthread_key_clean_all(void);
 
 // Address space is precious on LP32, so use the minimum unit: one page.
diff --git a/libc/bionic/pthread_key.cpp b/libc/bionic/pthread_key.cpp
index 53f0f1179..f8c765dee 100644
--- a/libc/bionic/pthread_key.cpp
+++ b/libc/bionic/pthread_key.cpp
@@ -83,11 +83,18 @@ __LIBC_HIDDEN__ void pthread_key_clean_all() {
     size_t called_destructor_count = 0;
     for (size_t i = 0; i < BIONIC_PTHREAD_KEY_COUNT; ++i) {
       uintptr_t seq = atomic_load_explicit(&key_map[i].seq, memory_order_relaxed);
-      if (SeqOfKeyInUse(seq) && seq == key_data[i].seq && key_data[i].data != nullptr) {
-        // Other threads may be calling pthread_key_delete/pthread_key_create while current thread
-        // is exiting. So we need to ensure we read the right key_destructor.
+      if (SeqOfKeyInUse(seq) && seq == key_data[i].seq) {
+        // POSIX explicitly says that the destructor is only called if the
+        // thread has a non-null value for the key.
+        if (key_data[i].data == nullptr) {
+          continue;
+        }
+
+        // Other threads can call pthread_key_delete()/pthread_key_create()
+        // while this thread is exiting, so we need to ensure we read the right
+        // key_destructor.
         // We can rely on a user-established happens-before relationship between the creation and
-        // use of pthread key to ensure that we're not getting an earlier key_destructor.
+        // use of a pthread key to ensure that we're not getting an earlier key_destructor.
         // To avoid using the key_destructor of the newly created key in the same slot, we need to
         // recheck the sequence number after reading key_destructor. As a result, we either see the
         // right key_destructor, or the sequence number must have changed when we reread it below.
@@ -107,7 +114,6 @@ __LIBC_HIDDEN__ void pthread_key_clean_all() {
         // function is responsible for manually releasing the corresponding data.
         void* data = key_data[i].data;
         key_data[i].data = nullptr;
-
         (*key_destructor)(data);
         ++called_destructor_count;
       }
@@ -163,13 +169,13 @@ void* pthread_getspecific(pthread_key_t key) {
   key &= ~KEY_VALID_FLAG;
   uintptr_t seq = atomic_load_explicit(&key_map[key].seq, memory_order_relaxed);
   pthread_key_data_t* data = &get_thread_key_data()[key];
-  // It is user's responsibility to synchornize between the creation and use of pthread keys,
+  // It is the user's responsibility to synchronize between the creation and use of pthread keys,
   // so we use memory_order_relaxed when checking the sequence number.
   if (__predict_true(SeqOfKeyInUse(seq) && data->seq == seq)) {
     return data->data;
   }
-  // We arrive here when current thread holds the seq of an deleted pthread key. So the
-  // data is for the deleted pthread key, and should be cleared.
+  // We arrive here when the current thread holds the seq of a deleted pthread key.
+  // The data is for the deleted pthread key, and should be cleared.
   data->data = nullptr;
   return nullptr;
 }
diff --git a/libc/bionic/signal.cpp b/libc/bionic/signal.cpp
index 5979ed73d..77e6acf1f 100644
--- a/libc/bionic/signal.cpp
+++ b/libc/bionic/signal.cpp
@@ -288,16 +288,14 @@ int sigwait(const sigset_t* bionic_set, int* sig) {
 }
 
 int sigwait64(const sigset64_t* set, int* sig) {
-  while (true) {
-    // __rt_sigtimedwait can return EAGAIN or EINTR, we need to loop
-    // around them since sigwait is only allowed to return EINVAL.
-    int result = sigtimedwait64(set, nullptr, nullptr);
-    if (result >= 0) {
-      *sig = result;
-      return 0;
-    }
-    if (errno != EAGAIN && errno != EINTR) return errno;
-  }
+  // sigtimedwait64() doesn't fail with EINVAL on Linux,
+  // and EAGAIN can only happen with a timeout,
+  // so the error reporting here is effectively dead code.
+  ErrnoRestorer errno_restorer;
+  int result = TEMP_FAILURE_RETRY(sigtimedwait64(set, nullptr, nullptr));
+  if (result == -1) return errno;
+  *sig = result;
+  return 0;
 }
 
 int sigwaitinfo(const sigset_t* set, siginfo_t* info) {
diff --git a/libc/bionic/strchr.cpp b/libc/bionic/strchr.cpp
deleted file mode 100644
index fd8a924a9..000000000
--- a/libc/bionic/strchr.cpp
+++ /dev/null
@@ -1,34 +0,0 @@
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
-#include <string.h>
-
-char* strchr(const char* p, int ch) {
-  return __strchr_chk(p, ch, __BIONIC_FORTIFY_UNKNOWN_SIZE);
-}
diff --git a/libc/bionic/strchrnul.cpp b/libc/bionic/strchrnul.cpp
deleted file mode 100644
index 55422e06d..000000000
--- a/libc/bionic/strchrnul.cpp
+++ /dev/null
@@ -1,22 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-extern "C" const char* strchrnul(const char* s, int ch) {
-  while (*s && *s != ch) {
-    ++s;
-  }
-  return s;
-}
diff --git a/libc/bionic/strnlen.cpp b/libc/bionic/strnlen.cpp
deleted file mode 100644
index 7101b21dc..000000000
--- a/libc/bionic/strnlen.cpp
+++ /dev/null
@@ -1,34 +0,0 @@
-/*
- * Copyright (C) 2008 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <string.h>
-
-size_t strnlen(const char* s, size_t n) {
-  const char* p = static_cast<const char*>(memchr(s, 0, n));
-  return p ? (p - s) : n;
-}
diff --git a/libc/bionic/strrchr.cpp b/libc/bionic/strrchr.cpp
deleted file mode 100644
index b6c40f442..000000000
--- a/libc/bionic/strrchr.cpp
+++ /dev/null
@@ -1,34 +0,0 @@
-/*
- * Copyright (c) 1988 Regents of the University of California.
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
-#include <string.h>
-
-char* strrchr(const char* p, int ch) {
-  return __strrchr_chk(p, ch, __BIONIC_FORTIFY_UNKNOWN_SIZE);
-}
diff --git a/libc/bionic/sysconf.cpp b/libc/bionic/sysconf.cpp
index 571370ca3..03822edb0 100644
--- a/libc/bionic/sysconf.cpp
+++ b/libc/bionic/sysconf.cpp
@@ -210,6 +210,7 @@ long sysconf(int name) {
       // are vestigial anyway, so the "maximum maximum" of NGROUPS_MAX is a good
       // enough answer for _SC_NGROUPS_MAX...
       return NGROUPS_MAX;
+    case _SC_NSIG:              return NSIG;
     case _SC_PASS_MAX:          return PASS_MAX;
     case _SC_2_C_BIND:          return _POSIX2_C_BIND;
     case _SC_2_C_DEV:           return _POSIX2_C_DEV;
diff --git a/libc/bionic/wctype.cpp b/libc/bionic/wctype.cpp
index 94597d90c..8d0733def 100644
--- a/libc/bionic/wctype.cpp
+++ b/libc/bionic/wctype.cpp
@@ -35,7 +35,7 @@
 #include <wchar.h>
 
 #include "bionic/macros.h"
-#include "private/icu.h"
+#include "private/icu4x.h"
 
 enum {
   WC_TYPE_INVALID = 0,
@@ -54,60 +54,65 @@ enum {
   WC_TYPE_MAX
 };
 
-static u_hasBinaryProperty_t __find_u_hasBinaryProperty() {
-  static auto u_hasBinaryProperty =
-      reinterpret_cast<u_hasBinaryProperty_t>(__find_icu_symbol("u_hasBinaryProperty"));
-  return u_hasBinaryProperty;
-}
-
-#define DO_ISW(icu_constant, narrow_fn) \
-  u_hasBinaryProperty_t u_hasBinaryProperty; \
-  if (__predict_true(wc < 0x80) || \
-      !(u_hasBinaryProperty = __find_u_hasBinaryProperty())) { \
-    return narrow_fn(wc); \
-  } \
-  return u_hasBinaryProperty(wc, icu_constant); \
+#define DO_ISW(prop_name, narrow_fn) \
+  if (__predict_true(wc < 0x80)) {   \
+    return narrow_fn(wc);            \
+  }                                  \
+  return __icu4x_bionic_is_##prop_name(wc);
 
-int iswalnum(wint_t wc) { DO_ISW(UCHAR_POSIX_ALNUM, isalnum); }
+int iswalnum(wint_t wc) {
+  DO_ISW(alnum, isalnum);
+}
 __strong_alias(iswalnum_l, iswalnum);
-int iswalpha(wint_t wc) { DO_ISW(UCHAR_ALPHABETIC, isalpha); }
+int iswalpha(wint_t wc) {
+  DO_ISW(alphabetic, isalpha);
+}
 __strong_alias(iswalpha_l, iswalpha);
-int iswblank(wint_t wc) { DO_ISW(UCHAR_POSIX_BLANK, isblank); }
+int iswblank(wint_t wc) {
+  DO_ISW(blank, isblank);
+}
 __strong_alias(iswblank_l, iswblank);
-int iswgraph(wint_t wc) { DO_ISW(UCHAR_POSIX_GRAPH, isgraph); }
+int iswgraph(wint_t wc) {
+  DO_ISW(graph, isgraph);
+}
 __strong_alias(iswgraph_l, iswgraph);
-int iswlower(wint_t wc) { DO_ISW(UCHAR_LOWERCASE, islower); }
+int iswlower(wint_t wc) {
+  DO_ISW(lowercase, islower);
+}
 __strong_alias(iswlower_l, iswlower);
-int iswprint(wint_t wc) { DO_ISW(UCHAR_POSIX_PRINT, isprint); }
+int iswprint(wint_t wc) {
+  DO_ISW(print, isprint);
+}
 __strong_alias(iswprint_l, iswprint);
-int iswspace(wint_t wc) { DO_ISW(UCHAR_WHITE_SPACE, isspace); }
+int iswspace(wint_t wc) {
+  DO_ISW(white_space, isspace);
+}
 __strong_alias(iswspace_l, iswspace);
-int iswupper(wint_t wc) { DO_ISW(UCHAR_UPPERCASE, isupper); }
+int iswupper(wint_t wc) {
+  DO_ISW(uppercase, isupper);
+}
 __strong_alias(iswupper_l, iswupper);
-int iswxdigit(wint_t wc) { DO_ISW(UCHAR_POSIX_XDIGIT, isxdigit); }
+int iswxdigit(wint_t wc) {
+  DO_ISW(xdigit, isxdigit);
+}
 __strong_alias(iswxdigit_l, iswxdigit);
 
 int iswcntrl(wint_t wc) {
   if (wc < 0x80) return iscntrl(wc);
-  typedef int8_t (*FnT)(UChar32);
-  static auto u_charType = reinterpret_cast<FnT>(__find_icu_symbol("u_charType"));
-  return u_charType ? (u_charType(wc) == U_CONTROL_CHAR) : iscntrl(wc);
+  return __icu4x_bionic_general_category(wc) == U_CONTROL_CHAR;
 }
 __strong_alias(iswcntrl_l, iswcntrl);
 
 int iswdigit(wint_t wc) {
   if (wc < 0x80) return isdigit(wc);
-  typedef UBool (*FnT)(UChar32);
-  static auto u_isdigit = reinterpret_cast<FnT>(__find_icu_symbol("u_isdigit"));
-  return u_isdigit ? u_isdigit(wc) : isdigit(wc);
+  return __icu4x_bionic_general_category(wc) == U_DECIMAL_NUMBER;
 }
 __strong_alias(iswdigit_l, iswdigit);
 
 int iswpunct(wint_t wc) {
   if (wc < 0x80) return ispunct(wc);
-  typedef UBool (*FnT)(UChar32);
-  static auto u_ispunct = reinterpret_cast<FnT>(__find_icu_symbol("u_ispunct"));
-  return u_ispunct ? u_ispunct(wc) : ispunct(wc);
+  int8_t chartype = __icu4x_bionic_general_category(wc);
+  return chartype >= U_DASH_PUNCTUATION && chartype <= U_OTHER_PUNCTUATION;
 }
 __strong_alias(iswpunct_l, iswpunct);
 
@@ -124,18 +129,14 @@ __strong_alias(iswctype_l, iswctype);
 wint_t towlower(wint_t wc) {
   if (wc < 0x80) return tolower(wc);
 
-  typedef UChar32 (*FnT)(UChar32);
-  static auto u_tolower = reinterpret_cast<FnT>(__find_icu_symbol("u_tolower"));
-  return u_tolower ? u_tolower(wc) : tolower(wc);
+  return __icu4x_bionic_to_lower(wc);
 }
 __strong_alias(towlower_l, towlower);
 
 wint_t towupper(wint_t wc) {
   if (wc < 0x80) return toupper(wc);
 
-  typedef UChar32 (*FnT)(UChar32);
-  static auto u_toupper = reinterpret_cast<FnT>(__find_icu_symbol("u_toupper"));
-  return u_toupper ? u_toupper(wc) : toupper(wc);
+  return __icu4x_bionic_to_upper(wc);
 }
 __strong_alias(towupper_l, towupper);
 
diff --git a/libc/bionic/wcwidth.cpp b/libc/bionic/wcwidth.cpp
index 776321fae..633d83ee5 100644
--- a/libc/bionic/wcwidth.cpp
+++ b/libc/bionic/wcwidth.cpp
@@ -28,7 +28,7 @@
 
 #include <wchar.h>
 
-#include "private/icu.h"
+#include "private/icu4x.h"
 
 int wcwidth(wchar_t wc) {
   // Fast-path ASCII.
@@ -44,38 +44,33 @@ int wcwidth(wchar_t wc) {
   // pretty arbitrary. See https://www.cl.cam.ac.uk/~mgk25/ucs/wcwidth.c for more details.
 
   // Fancy unicode control characters?
-  switch (__icu_charType(wc)) {
-   case -1:
-    // No icu4c available; give up.
-    return -1;
-   case U_CONTROL_CHAR:
-    return -1;
-   case U_NON_SPACING_MARK:
-   case U_ENCLOSING_MARK:
-    return 0;
-   case U_FORMAT_CHAR:
-    // A special case for soft hyphen (U+00AD) to match historical practice.
-    // See the tests for more commentary.
-    return (wc == 0x00ad) ? 1 : 0;
+  switch (__icu4x_bionic_general_category(wc)) {
+    case U_CONTROL_CHAR:
+      return -1;
+    case U_NON_SPACING_MARK:
+    case U_ENCLOSING_MARK:
+      return 0;
+    case U_FORMAT_CHAR:
+      // A special case for soft hyphen (U+00AD) to match historical practice.
+      // See the tests for more commentary.
+      return (wc == 0x00ad) ? 1 : 0;
   }
 
   // Medial and final jamo render as zero width when used correctly,
   // so we handle them specially rather than relying on East Asian Width.
-  switch (__icu_getIntPropertyValue(wc, UCHAR_HANGUL_SYLLABLE_TYPE)) {
-   case U_HST_VOWEL_JAMO:
-   case U_HST_TRAILING_JAMO:
-    return 0;
-   case U_HST_LEADING_JAMO:
-   case U_HST_LV_SYLLABLE:
-   case U_HST_LVT_SYLLABLE:
-    return 2;
+  switch (__icu4x_bionic_hangul_syllable_type(wc)) {
+    case U_HST_VOWEL_JAMO:
+    case U_HST_TRAILING_JAMO:
+      return 0;
+    case U_HST_LEADING_JAMO:
+    case U_HST_LV_SYLLABLE:
+    case U_HST_LVT_SYLLABLE:
+      return 2;
   }
 
   // Hangeul choseong filler U+115F is default ignorable, so we check default
   // ignorability only after we've already handled Hangeul jamo above.
-  static auto u_hasBinaryProperty =
-      reinterpret_cast<u_hasBinaryProperty_t>(__find_icu_symbol("u_hasBinaryProperty"));
-  if (u_hasBinaryProperty && u_hasBinaryProperty(wc, UCHAR_DEFAULT_IGNORABLE_CODE_POINT)) return 0;
+  if (__icu4x_bionic_is_default_ignorable_code_point(wc)) return 0;
 
   // A few weird special cases where EastAsianWidth is not helpful for us.
   if (wc >= 0x3248 && wc <= 0x4dff) {
@@ -88,15 +83,15 @@ int wcwidth(wchar_t wc) {
 
   // The EastAsianWidth property is at least defined by the Unicode standard!
   // https://www.unicode.org/reports/tr11/
-  switch (__icu_getIntPropertyValue(wc, UCHAR_EAST_ASIAN_WIDTH)) {
-   case U_EA_AMBIGUOUS:
-   case U_EA_HALFWIDTH:
-   case U_EA_NARROW:
-   case U_EA_NEUTRAL:
-    return 1;
-   case U_EA_FULLWIDTH:
-   case U_EA_WIDE:
-    return 2;
+  switch (__icu4x_bionic_east_asian_width(wc)) {
+    case U_EA_AMBIGUOUS:
+    case U_EA_HALFWIDTH:
+    case U_EA_NARROW:
+    case U_EA_NEUTRAL:
+      return 1;
+    case U_EA_FULLWIDTH:
+    case U_EA_WIDE:
+      return 2;
   }
 
   return 0;
diff --git a/libc/include/android/api-level.h b/libc/include/android/api-level.h
index c9536c165..2a4f7df0c 100644
--- a/libc/include/android/api-level.h
+++ b/libc/include/android/api-level.h
@@ -31,16 +31,21 @@
 /**
  * @defgroup apilevels API Levels
  *
- * Defines functions and constants for working with Android API levels.
+ * Defines functions for working with Android API levels.
  * @{
  */
 
 /**
  * @file android/api-level.h
- * @brief Functions and constants for dealing with multiple API levels.
+ * @brief Functions for dealing with multiple API levels.
  *
- * See
- * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md.
+ * See also
+ * https://developer.android.com/ndk/guides/using-newer-apis
+ * for more tutorial information on dealing with multiple API levels.
+ *
+ * See also
+ * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md
+ * for when to use which `#define` when writing portable code.
  */
 
 #include <sys/cdefs.h>
@@ -96,82 +101,64 @@ __BEGIN_DECLS
 #define __ANDROID_API__ __ANDROID_API_FUTURE__
 #endif
 
-/** Names the Gingerbread API level (9), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 9. Prefer numeric API levels in new code. */
 #define __ANDROID_API_G__ 9
 
-/** Names the Ice-Cream Sandwich API level (14), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 14. Prefer numeric API levels in new code. */
 #define __ANDROID_API_I__ 14
 
-/** Names the Jellybean API level (16), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 16. Prefer numeric API levels in new code. */
 #define __ANDROID_API_J__ 16
 
-/** Names the Jellybean MR1 API level (17), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 17. Prefer numeric API levels in new code. */
 #define __ANDROID_API_J_MR1__ 17
 
-/** Names the Jellybean MR2 API level (18), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 18. Prefer numeric API levels in new code. */
 #define __ANDROID_API_J_MR2__ 18
 
-/** Names the KitKat API level (19), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 19. Prefer numeric API levels in new code. */
 #define __ANDROID_API_K__ 19
 
-/** Names the Lollipop API level (21), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 21. Prefer numeric API levels in new code. */
 #define __ANDROID_API_L__ 21
 
-/** Names the Lollipop MR1 API level (22), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 22. Prefer numeric API levels in new code. */
 #define __ANDROID_API_L_MR1__ 22
 
-/** Names the Marshmallow API level (23), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 23. Prefer numeric API levels in new code. */
 #define __ANDROID_API_M__ 23
 
-/** Names the Nougat API level (24), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 24. Prefer numeric API levels in new code. */
 #define __ANDROID_API_N__ 24
 
-/** Names the Nougat MR1 API level (25), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 25. Prefer numeric API levels in new code. */
 #define __ANDROID_API_N_MR1__ 25
 
-/** Names the Oreo API level (26), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 26. Prefer numeric API levels in new code. */
 #define __ANDROID_API_O__ 26
 
-/** Names the Oreo MR1 API level (27), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 27. Prefer numeric API levels in new code. */
 #define __ANDROID_API_O_MR1__ 27
 
-/** Names the Pie API level (28), for comparison against `__ANDROID_API__`. */
+/** Deprecated name for API level 28. Prefer numeric API levels in new code. */
 #define __ANDROID_API_P__ 28
 
-/**
- * Names the Android 10 (aka "Q" or "Quince Tart") API level (29), for
- * comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 29. Prefer numeric API levels in new code. */
 #define __ANDROID_API_Q__ 29
 
-/**
- * Names the Android 11 (aka "R" or "Red Velvet Cake") API level (30), for
- * comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 30. Prefer numeric API levels in new code. */
 #define __ANDROID_API_R__ 30
 
-/**
- * Names the Android 12 (aka "S" or "Snowcone") API level (31), for
- * comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 31. Prefer numeric API levels in new code. */
 #define __ANDROID_API_S__ 31
 
-/**
- * Names the Android 13 (aka "T" or "Tiramisu") API level (33), for
- * comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 33. Prefer numeric API levels in new code. */
 #define __ANDROID_API_T__ 33
 
-/**
- * Names the Android 14 (aka "U" or "UpsideDownCake") API level (34),
- * for comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 34. Prefer numeric API levels in new code. */
 #define __ANDROID_API_U__ 34
 
-/**
- * Names the Android 15 (aka "V" or "VanillaIceCream") API level (35),
- * for comparison against `__ANDROID_API__`.
- */
+/** Deprecated name for API level 35. Prefer numeric API levels in new code. */
 #define __ANDROID_API_V__ 35
 
 /* This file is included in <features.h>, and might be used from .S files. */
@@ -189,7 +176,6 @@ __BEGIN_DECLS
  *
  * Available since API level 24.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(24)
 int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
 #endif /* __BIONIC_AVAILABILITY_GUARD(24) */
@@ -210,6 +196,8 @@ int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
  * and is equivalent to the Java `Build.VERSION.SDK_INT` API.
  *
  * See also android_get_application_target_sdk_version().
+ *
+ * Available since API level 29.
  */
 int android_get_device_api_level() __INTRODUCED_IN(29);
 
diff --git a/libc/include/bits/fortify/string.h b/libc/include/bits/fortify/string.h
index 6f0ee4ae7..15cb17dcb 100644
--- a/libc/include/bits/fortify/string.h
+++ b/libc/include/bits/fortify/string.h
@@ -42,9 +42,9 @@ size_t __strlcpy_chk(char* _Nonnull, const char* _Nonnull, size_t, size_t);
 size_t __strlcat_chk(char* _Nonnull, const char* _Nonnull, size_t, size_t);
 
 #if defined(__BIONIC_FORTIFY)
-void* _Nullable __memrchr_real(const void* _Nonnull, int, size_t) __RENAME(memrchr);
 
-#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
+/* hwasan intercepts memcpy() but not the _chk variant. */
+#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED && !__has_feature(hwaddress_sanitizer)
 /* No diag -- clang diagnoses misuses of this on its own.  */
 __BIONIC_FORTIFY_INLINE
 void* _Nonnull memcpy(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t copy_amount)
@@ -52,7 +52,10 @@ void* _Nonnull memcpy(void* _Nonnull const dst __pass_object_size0, const void*
         __overloadable {
     return __builtin___memcpy_chk(dst, src, copy_amount, __bos0(dst));
 }
+#endif
 
+/* hwasan intercepts memmove() but not the _chk variant. */
+#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED && !__has_feature(hwaddress_sanitizer)
 /* No diag -- clang diagnoses misuses of this on its own.  */
 __BIONIC_FORTIFY_INLINE
 void* _Nonnull memmove(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t len)
@@ -62,6 +65,21 @@ void* _Nonnull memmove(void* _Nonnull const dst __pass_object_size0, const void*
 }
 #endif
 
+/* TODO: remove __clang_warning_if when https://issuetracker.google.com/400937647 is fixed. */
+__BIONIC_FORTIFY_INLINE
+void* _Nonnull memset(void* _Nonnull const s __pass_object_size0, int c, size_t n)
+        __diagnose_as_builtin(__builtin_memset, 1, 2, 3)
+        __overloadable
+        /* If you're a user who wants this warning to go away: use `(&memset)(foo, bar, baz)`. */
+        __clang_warning_if(c && !n, "'memset' will set 0 bytes; maybe the arguments got flipped?") {
+/* hwasan intercepts memset() but not the _chk variant. */
+#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED && !__has_feature(hwaddress_sanitizer)
+    return __builtin___memset_chk(s, c, n, __bos0(s));
+#else
+    return __builtin_memset(s, c, n);
+#endif
+}
+
 #if defined(__USE_GNU)
 #if __ANDROID_API__ >= 30
 __BIONIC_FORTIFY_INLINE
@@ -128,19 +146,6 @@ char* _Nonnull strncat(char* _Nonnull const dst __pass_object_size, const char*
 }
 #endif
 
-/* No diag -- clang diagnoses misuses of this on its own.  */
-__BIONIC_FORTIFY_INLINE
-void* _Nonnull memset(void* _Nonnull const s __pass_object_size0, int c, size_t n) __overloadable
-        __diagnose_as_builtin(__builtin_memset, 1, 2, 3)
-        /* If you're a user who wants this warning to go away: use `(&memset)(foo, bar, baz)`. */
-        __clang_warning_if(c && !n, "'memset' will set 0 bytes; maybe the arguments got flipped?") {
-#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
-    return __builtin___memset_chk(s, c, n, __bos0(s));
-#else
-    return __builtin_memset(s, c, n);
-#endif
-}
-
 #if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
 __BIONIC_FORTIFY_INLINE
 void* _Nullable memchr(const void* _Nonnull const s __pass_object_size, int c, size_t n) __overloadable {
@@ -153,6 +158,8 @@ void* _Nullable memchr(const void* _Nonnull const s __pass_object_size, int c, s
     return __memchr_chk(s, c, n, bos);
 }
 
+void* _Nullable __memrchr_real(const void* _Nonnull, int, size_t) __RENAME(memrchr);
+
 __BIONIC_FORTIFY_INLINE
 void* _Nullable __memrchr_fortify(const void* _Nonnull const __pass_object_size s, int c, size_t n) __overloadable {
     size_t bos = __bos(s);
diff --git a/libc/include/bits/signal_types.h b/libc/include/bits/signal_types.h
index d98901c99..41a697e3b 100644
--- a/libc/include/bits/signal_types.h
+++ b/libc/include/bits/signal_types.h
@@ -34,36 +34,72 @@
 #include <linux/signal.h>
 #include <sys/types.h>
 
-/* The arm and x86 kernel header files don't define _NSIG. */
+/**
+ * The highest kernel-supported signal number, plus one.
+ *
+ * In theory this is useful for declaring an array with an entry for each signal.
+ * In practice, that's less useful than it seems because of the real-time
+ * signals and the reserved signals,
+ * and the sig2str() and str2sig() functions cover the most common use case
+ * of translating between signal numbers and signal names.
+ *
+ * Note also that although sigset_t and sigset64_t are the same type on LP64,
+ * on ILP32 only sigset64_t is large enough to refer to the upper 32 signals.
+ * NSIG does _not_ tell you anything about what can be used with sigset_t.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
+#define NSIG 65
+/** A traditional alternative name for NSIG. */
+#define _NSIG 65
+
+/*
+ * We rewrite the kernel's _NSIG to _KERNEL__NSIG
+ * (because the kernel values are off by one from the userspace values),
+ * but the kernel <asm/signal.h> headers define SIGRTMAX in terms of
+ * _KERNEL__NSIG (or _NSIG, in the original kernel source),
+ * so we need to provide a definition here.
+ * (Ideally our uapi header rewriter would just hard-code _KERNEL__NSIG to 64.)
+ */
 #ifndef _KERNEL__NSIG
 #define _KERNEL__NSIG 64
 #endif
 
-/* Userspace's NSIG is the kernel's _NSIG + 1. */
-#define _NSIG (_KERNEL__NSIG + 1)
-#define NSIG _NSIG
-
 typedef int sig_atomic_t;
 
 typedef __sighandler_t sig_t; /* BSD compatibility. */
 typedef __sighandler_t sighandler_t; /* glibc compatibility. */
 
-/* sigset_t is already large enough on LP64, but LP32's sigset_t
- * is just `unsigned long`.
- */
 #if defined(__LP64__)
+/**
+ * The kernel LP64 sigset_t is large enough to support all signals;
+ * this typedef is just for source compatibility with code that uses
+ * real-time signals on ILP32.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
 typedef sigset_t sigset64_t;
 #else
-typedef struct { unsigned long __bits[_KERNEL__NSIG/(8*sizeof(long))]; } sigset64_t;
+/**
+ * The ILP32 sigset_t is only 32 bits, so we need a 64-bit sigset64_t
+ * and associated functions to be able to support the real-time signals.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
+typedef struct { unsigned long __bits[64/(8*sizeof(long))]; } sigset64_t;
 #endif
 
-/* The kernel's struct sigaction doesn't match the POSIX one. */
+/* The kernel's struct sigaction doesn't match the POSIX one,
+ * so we define struct sigaction ourselves. */
 
 #if defined(__LP64__)
 
-/* For 64-bit, that's the only problem, and we only need two structs
- * for source compatibility with 32-bit. */
-
 #define __SIGACTION_BODY \
   int sa_flags; \
   union { \
@@ -73,22 +109,49 @@ typedef struct { unsigned long __bits[_KERNEL__NSIG/(8*sizeof(long))]; } sigset6
   sigset_t sa_mask; \
   void (*sa_restorer)(void); \
 
+/**
+ * Used with sigaction().
+ *
+ * On LP64, this supports all signals including real-time signals.
+ * On ILP32, this only supports the first 32 signals.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
 struct sigaction { __SIGACTION_BODY };
+/**
+ * Used with sigaction64().
+ *
+ * On LP64, a synonym for struct sigaction for source compatibility with ILP32.
+ * On ILP32, this is needed to support all signals including real-time signals
+ * because struct sigaction only supports the first 32 signals.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
 struct sigaction64 { __SIGACTION_BODY };
 
 #undef __SIGACTION_BODY
 
 #else
 
-/* For 32-bit, Android's ABIs used a too-small sigset_t that doesn't
- * support RT signals, so we need two different structs.
- */
-
-/* The arm32 kernel headers also pollute the namespace with these,
+/* The arm32 kernel headers pollute the namespace with these,
  * but our header scrubber doesn't know how to remove #defines. */
 #undef sa_handler
 #undef sa_sigaction
 
+/**
+ * Used with sigaction().
+ *
+ * On LP64, this supports all signals including real-time signals.
+ * On ILP32, this only supports the first 32 signals.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
 struct sigaction {
   union {
     sighandler_t sa_handler;
@@ -99,6 +162,17 @@ struct sigaction {
   void (*sa_restorer)(void);
 };
 
+/**
+ * Used with sigaction64().
+ *
+ * On LP64, a synonym for struct sigaction for source compatibility with ILP32.
+ * On ILP32, this is needed to support all signals including real-time signals
+ * because struct sigaction only supports the first 32 signals.
+ *
+ * See the
+ * (32-bit ABI bugs)[https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md#is-too-small-for-real_time-signals]
+ * documentation.
+ */
 struct sigaction64 {
   union {
     sighandler_t sa_handler;
diff --git a/libc/include/bits/sockaddr_storage.h b/libc/include/bits/sockaddr_storage.h
index effafab0c..4b3bfb61e 100644
--- a/libc/include/bits/sockaddr_storage.h
+++ b/libc/include/bits/sockaddr_storage.h
@@ -40,7 +40,7 @@
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wnullability-completeness"
 /**
- * [sockaddr_storage](https://man7.org/linux/man-pages/man3/sockaddr.3type.html)
+ * [sockaddr_storage](https://man7.org/linux/man-pages/man3/sockaddr_storage.3type.html)
  * is a structure large enough to contain any other `sockaddr_*` type, used to
  * pass socket addresses without needing to know what kind of socket address
  * you're passing.
diff --git a/libc/include/bits/stdatomic.h b/libc/include/bits/stdatomic.h
index ebdc9e5b6..0d39a61f2 100644
--- a/libc/include/bits/stdatomic.h
+++ b/libc/include/bits/stdatomic.h
@@ -53,36 +53,16 @@
  * 7.17.1 Atomic lock-free macros.
  */
 
-#ifdef __GCC_ATOMIC_BOOL_LOCK_FREE
-#define	ATOMIC_BOOL_LOCK_FREE		__GCC_ATOMIC_BOOL_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_CHAR_LOCK_FREE
-#define	ATOMIC_CHAR_LOCK_FREE		__GCC_ATOMIC_CHAR_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_CHAR16_T_LOCK_FREE
-#define	ATOMIC_CHAR16_T_LOCK_FREE	__GCC_ATOMIC_CHAR16_T_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_CHAR32_T_LOCK_FREE
-#define	ATOMIC_CHAR32_T_LOCK_FREE	__GCC_ATOMIC_CHAR32_T_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_WCHAR_T_LOCK_FREE
-#define	ATOMIC_WCHAR_T_LOCK_FREE	__GCC_ATOMIC_WCHAR_T_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_SHORT_LOCK_FREE
-#define	ATOMIC_SHORT_LOCK_FREE		__GCC_ATOMIC_SHORT_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_INT_LOCK_FREE
-#define	ATOMIC_INT_LOCK_FREE		__GCC_ATOMIC_INT_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_LONG_LOCK_FREE
-#define	ATOMIC_LONG_LOCK_FREE		__GCC_ATOMIC_LONG_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_LLONG_LOCK_FREE
-#define	ATOMIC_LLONG_LOCK_FREE		__GCC_ATOMIC_LLONG_LOCK_FREE
-#endif
-#ifdef __GCC_ATOMIC_POINTER_LOCK_FREE
-#define	ATOMIC_POINTER_LOCK_FREE	__GCC_ATOMIC_POINTER_LOCK_FREE
-#endif
+#define	ATOMIC_BOOL_LOCK_FREE			__CLANG_ATOMIC_BOOL_LOCK_FREE
+#define	ATOMIC_CHAR_LOCK_FREE			__CLANG_ATOMIC_CHAR_LOCK_FREE
+#define	ATOMIC_CHAR16_T_LOCK_FREE	__CLANG_ATOMIC_CHAR16_T_LOCK_FREE
+#define	ATOMIC_CHAR32_T_LOCK_FREE	__CLANG_ATOMIC_CHAR32_T_LOCK_FREE
+#define	ATOMIC_WCHAR_T_LOCK_FREE	__CLANG_ATOMIC_WCHAR_T_LOCK_FREE
+#define	ATOMIC_SHORT_LOCK_FREE		__CLANG_ATOMIC_SHORT_LOCK_FREE
+#define	ATOMIC_INT_LOCK_FREE			__CLANG_ATOMIC_INT_LOCK_FREE
+#define	ATOMIC_LONG_LOCK_FREE			__CLANG_ATOMIC_LONG_LOCK_FREE
+#define	ATOMIC_LLONG_LOCK_FREE		__CLANG_ATOMIC_LLONG_LOCK_FREE
+#define	ATOMIC_POINTER_LOCK_FREE	__CLANG_ATOMIC_POINTER_LOCK_FREE
 
 /*
  * 7.17.2 Initialization.
@@ -91,31 +71,6 @@
 #define	ATOMIC_VAR_INIT(value)		(value)
 #define	atomic_init(obj, value)		__c11_atomic_init(obj, value)
 
-/*
- * Clang and recent GCC both provide predefined macros for the memory
- * orderings.  If we are using a compiler that doesn't define them, use the
- * clang values - these will be ignored in the fallback path.
- */
-
-#ifndef __ATOMIC_RELAXED
-#define __ATOMIC_RELAXED		0
-#endif
-#ifndef __ATOMIC_CONSUME
-#define __ATOMIC_CONSUME		1
-#endif
-#ifndef __ATOMIC_ACQUIRE
-#define __ATOMIC_ACQUIRE		2
-#endif
-#ifndef __ATOMIC_RELEASE
-#define __ATOMIC_RELEASE		3
-#endif
-#ifndef __ATOMIC_ACQ_REL
-#define __ATOMIC_ACQ_REL		4
-#endif
-#ifndef __ATOMIC_SEQ_CST
-#define __ATOMIC_SEQ_CST		5
-#endif
-
 /*
  * 7.17.3 Order and consistency.
  *
@@ -140,11 +95,11 @@ typedef enum {
  * 7.17.4 Fences.
  */
 
-static __inline void atomic_thread_fence(memory_order __order __attribute__((__unused__))) {
+static __inline void atomic_thread_fence(memory_order __order) {
 	__c11_atomic_thread_fence(__order);
 }
 
-static __inline void atomic_signal_fence(memory_order __order __attribute__((__unused__))) {
+static __inline void atomic_signal_fence(memory_order __order) {
 	__c11_atomic_signal_fence(__order);
 }
 
@@ -261,15 +216,17 @@ typedef _Atomic(uintmax_t)		atomic_uintmax_t;
 /*
  * 7.17.8 Atomic flag type and operations.
  *
- * XXX: Assume atomic_bool can be used as an atomic_flag. Is there some
- * kind of compiler built-in type we could use?
+ * atomic_bool can be used to provide a lock-free atomic flag type on every
+ * Android architecture, so this shouldn't be needed in new Android code,
+ * but is in ISO C, and available for portability to PA-RISC and
+ * microcontrollers.
  */
 
 typedef struct {
 	atomic_bool	__flag;
 } atomic_flag;
 
-#define	ATOMIC_FLAG_INIT		{ ATOMIC_VAR_INIT(false) }
+#define	ATOMIC_FLAG_INIT {false}
 
 static __inline bool atomic_flag_test_and_set_explicit(volatile atomic_flag * _Nonnull __object, memory_order __order) {
 	return (atomic_exchange_explicit(&__object->__flag, 1, __order));
diff --git a/libc/include/bits/sysconf.h b/libc/include/bits/sysconf.h
index ecf26bad7..303f7c6ba 100644
--- a/libc/include/bits/sysconf.h
+++ b/libc/include/bits/sysconf.h
@@ -328,6 +328,8 @@
 #define _SC_LEVEL4_CACHE_ASSOC 0x009c
 /** sysconf() query for the L4 cache line size. Not available on all architectures. */
 #define _SC_LEVEL4_CACHE_LINESIZE 0x009d
+/** sysconf() query equivalent to NSIG. Available from API level 37. */
+#define _SC_NSIG 0x009e
 
 __BEGIN_DECLS
 
diff --git a/libc/include/dirent.h b/libc/include/dirent.h
index 8058cfb08..af22fb312 100644
--- a/libc/include/dirent.h
+++ b/libc/include/dirent.h
@@ -87,7 +87,7 @@ struct dirent64 { __DIRENT64_BODY };
 
 #define d_fileno d_ino
 
-/** The structure returned by opendir()/fopendir(). */
+/** The structure returned by opendir()/fdopendir(). */
 typedef struct DIR DIR;
 
 /**
@@ -99,7 +99,7 @@ typedef struct DIR DIR;
 DIR* _Nullable opendir(const char* _Nonnull __path);
 
 /**
- * [fopendir(3)](https://man7.org/linux/man-pages/man3/opendir.3.html)
+ * [fdopendir(3)](https://man7.org/linux/man-pages/man3/fdopendir.3.html)
  * opens a directory stream for the directory at `__dir_fd`.
  *
  * Returns null and sets `errno` on failure.
@@ -176,13 +176,13 @@ long telldir(DIR* _Nonnull __dir) __INTRODUCED_IN(23);
 int dirfd(DIR* _Nonnull __dir);
 
 /**
- * [alphasort](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
+ * [alphasort(3)](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
  * comparator for use with scandir() that uses strcoll().
  */
 int alphasort(const struct dirent* _Nonnull * _Nonnull __lhs, const struct dirent* _Nonnull * _Nonnull __rhs);
 
 /**
- * [alphasort64](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
+ * [alphasort64(3)](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
  * comparator for use with scandir64() that uses strcmp().
  */
 int alphasort64(const struct dirent64* _Nonnull * _Nonnull __lhs, const struct dirent64* _Nonnull * _Nonnull __rhs);
diff --git a/libc/include/dlfcn.h b/libc/include/dlfcn.h
index 81045fd71..dc5b7bb99 100644
--- a/libc/include/dlfcn.h
+++ b/libc/include/dlfcn.h
@@ -63,6 +63,22 @@ typedef struct {
  * [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html)
  * loads the given shared library.
  *
+ * See also
+ * [Android changes for NDK developers](https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md)
+ * which should cover all dynamic linker behavioral changes relevant to app development.
+ * It also explains how to debug issues with shared libraries on Android
+ * using the `debug.ld.app.*` system properties.
+ *
+ * One Android-specific extension is particularly noteworthy.
+ * The "my_zip_file.zip!/libs/libstuff.so" syntax to load a library
+ * directly from an arbitrary zip file, including but not limited to your apk
+ * (where this is how `extractNativeLibs=false` is implemented).
+ * Related to that, until API level 36 PackageManager is fussy about what
+ * files `extractNativeLibs` will actually extract.
+ * To be compatible with all API levels,
+ * always give files that need to be extracted a "lib" prefix and ".so" suffix,
+ * or avoid using `extractNativeLibs`.
+ *
  * See also android_dlopen_ext().
  *
  * Returns a pointer to an opaque handle for use with other <dlfcn.h> functions
diff --git a/libc/include/err.h b/libc/include/err.h
index 4a1841ba2..81b11e36b 100644
--- a/libc/include/err.h
+++ b/libc/include/err.h
@@ -74,7 +74,7 @@ __noreturn void verr(int __status, const char* _Nullable __fmt, va_list __args)
 __noreturn void errx(int __status, const char* _Nullable __fmt, ...) __printflike(2, 3);
 
 /**
- * [verrx(3)](https://man7.org/linux/man-pages/man3/err.3.html) outputs the program name, and
+ * [verrx(3)](https://man7.org/linux/man-pages/man3/verrx.3.html) outputs the program name, and
  * the vprintf()-like formatted message.
  *
  * Calls exit() with `__status`.
@@ -108,7 +108,7 @@ void vwarn(const char* _Nullable __fmt, va_list __args) __printflike(1, 0);
 void warnx(const char* _Nullable __fmt, ...) __printflike(1, 2);
 
 /**
- * [vwarnx(3)](https://man7.org/linux/man-pages/man3/warn.3.html) outputs the program name, and
+ * [vwarnx(3)](https://man7.org/linux/man-pages/man3/vwarnx.3.html) outputs the program name, and
  * the vprintf()-like formatted message.
  *
  * New code should consider error() in `<error.h>`.
diff --git a/libc/include/fts.h b/libc/include/fts.h
index aabe2dbea..69e17df16 100644
--- a/libc/include/fts.h
+++ b/libc/include/fts.h
@@ -38,32 +38,6 @@
 #include <sys/cdefs.h>
 #include <sys/types.h>
 
-typedef struct {
-	struct _ftsent * _Nullable fts_cur;	/* current node */
-	struct _ftsent * _Nullable fts_child;	/* linked list of children */
-	struct _ftsent * _Nullable * _Nullable fts_array;	/* sort array */
-	dev_t fts_dev;			/* starting device # */
-	char * _Nullable fts_path;			/* path for this descent */
-	int fts_rfd;			/* fd for root */
-	size_t fts_pathlen;		/* sizeof(path) */
-	int fts_nitems;			/* elements in the sort array */
-	int (* _Nullable fts_compar)();		/* compare function */
-
-#define	FTS_COMFOLLOW	0x0001		/* follow command line symlinks */
-#define	FTS_LOGICAL	0x0002		/* logical walk */
-#define	FTS_NOCHDIR	0x0004		/* don't change directories */
-#define	FTS_NOSTAT	0x0008		/* don't get stat info */
-#define	FTS_PHYSICAL	0x0010		/* physical walk */
-#define	FTS_SEEDOT	0x0020		/* return dot and dot-dot */
-#define	FTS_XDEV	0x0040		/* don't cross devices */
-#define	FTS_OPTIONMASK	0x00ff		/* valid user option mask */
-
-#define FTS_NAMEONLY 0x1000  /* (private) child names only */
-#define FTS_STOP 0x2000      /* (private) unrecoverable error */
-#define FTS_FOR_FTW 0x4000   /* (private) fts is being called by ftw/nftw */
-	int fts_options;		/* fts_open options, global flags */
-} FTS;
-
 typedef struct _ftsent {
 	struct _ftsent * _Nullable fts_cycle;	/* cycle node */
 	struct _ftsent * _Nullable fts_parent;	/* parent directory */
@@ -115,6 +89,32 @@ typedef struct _ftsent {
 	char fts_name[1];		/* file name */
 } FTSENT;
 
+typedef struct {
+	struct _ftsent * _Nullable fts_cur;	/* current node */
+	struct _ftsent * _Nullable fts_child;	/* linked list of children */
+	struct _ftsent * _Nullable * _Nullable fts_array;	/* sort array */
+	dev_t fts_dev;			/* starting device # */
+	char * _Nullable fts_path;			/* path for this descent */
+	int fts_rfd;			/* fd for root */
+	size_t fts_pathlen;		/* sizeof(path) */
+	int fts_nitems;			/* elements in the sort array */
+	int (* _Nullable fts_compar)(const FTSENT* _Nonnull * _Nonnull, const FTSENT* _Nonnull * _Nonnull);		/* compare function */
+
+#define	FTS_COMFOLLOW	0x0001		/* follow command line symlinks */
+#define	FTS_LOGICAL	0x0002		/* logical walk */
+#define	FTS_NOCHDIR	0x0004		/* don't change directories */
+#define	FTS_NOSTAT	0x0008		/* don't get stat info */
+#define	FTS_PHYSICAL	0x0010		/* physical walk */
+#define	FTS_SEEDOT	0x0020		/* return dot and dot-dot */
+#define	FTS_XDEV	0x0040		/* don't cross devices */
+#define	FTS_OPTIONMASK	0x00ff		/* valid user option mask */
+
+#define FTS_NAMEONLY 0x1000  /* (private) child names only */
+#define FTS_STOP 0x2000      /* (private) unrecoverable error */
+#define FTS_FOR_FTW 0x4000   /* (private) fts is being called by ftw/nftw */
+	int fts_options;		/* fts_open options, global flags */
+} FTS;
+
 __BEGIN_DECLS
 
 FTSENT* _Nullable fts_children(FTS* _Nonnull __fts, int __options);
diff --git a/libc/include/getopt.h b/libc/include/getopt.h
index 1a30eb7d9..56892aa86 100644
--- a/libc/include/getopt.h
+++ b/libc/include/getopt.h
@@ -70,12 +70,12 @@ struct option {
 __BEGIN_DECLS
 
 /**
- * [getopt_long(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
+ * [getopt_long(3)](https://man7.org/linux/man-pages/man3/getopt_long.3.html) parses command-line options.
  */
 int getopt_long(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);
 
 /**
- * [getopt_long_only(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
+ * [getopt_long_only(3)](https://man7.org/linux/man-pages/man3/getopt_long_only.3.html) parses command-line options.
  */
 int getopt_long_only(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);
 
diff --git a/libc/include/limits.h b/libc/include/limits.h
index 5e9ce591f..3220415f7 100644
--- a/libc/include/limits.h
+++ b/libc/include/limits.h
@@ -60,24 +60,6 @@
 /* Many of the POSIX limits come from the kernel. */
 #include <linux/limits.h>
 
-/*
- * bionic always exposed these alternative names,
- * but clang's <limits.h> considers them GNU extensions,
- * and may or may not have defined them.
- */
-#ifndef LONG_LONG_MIN
-/** Non-portable synonym; use LLONG_MIN directly instead. */
-#define LONG_LONG_MIN LLONG_MIN
-#endif
-#ifndef LONG_LONG_MAX
-/** Non-portable synonym; use LLONG_MAX directly instead. */
-#define LONG_LONG_MAX LLONG_MAX
-#endif
-#ifndef ULONG_LONG_MAX
-/** Non-portable synonym; use ULLONG_MAX directly instead. */
-#define ULONG_LONG_MAX ULLONG_MAX
-#endif
-
 /** Maximum number of positional arguments in a printf()/scanf() format string. */
 #define NL_ARGMAX 9
 /** Maximum number of bytes in a $LANG name. */
@@ -114,6 +96,12 @@
 /** Maximum value of a ssize_t. */
 #define SSIZE_MAX LONG_MAX
 
+/**
+ * POSIX 2024's name for NSIG.
+ * See the NSIG documentation for an explanation and warnings.
+ */
+#define NSIG_MAX 65
+
 /** Maximum number of bytes in a multibyte character. */
 #define MB_LEN_MAX 4
 
diff --git a/libc/include/malloc.h b/libc/include/malloc.h
index ac2746714..bb4916aba 100644
--- a/libc/include/malloc.h
+++ b/libc/include/malloc.h
@@ -77,8 +77,8 @@ __nodiscard void* _Nullable calloc(size_t __item_count, size_t __item_size) __ma
 __nodiscard void* _Nullable realloc(void* _Nullable __ptr, size_t __byte_count) __BIONIC_ALLOC_SIZE(2);
 
 /**
- * [reallocarray(3)](https://man7.org/linux/man-pages/man3/realloc.3.html) resizes
- * allocated memory on the heap.
+ * [reallocarray(3)](https://man7.org/linux/man-pages/man3/reallocarray.3.html)
+ * resizes allocated memory on the heap.
  *
  * Equivalent to `realloc(__ptr, __item_count * __item_size)` but fails if the
  * multiplication overflows.
@@ -122,7 +122,11 @@ __nodiscard void* _Nullable memalign(size_t __alignment, size_t __byte_count) __
  * [malloc_usable_size(3)](https://man7.org/linux/man-pages/man3/malloc_usable_size.3.html)
  * returns the actual size of the given heap block.
  */
-__nodiscard size_t malloc_usable_size(const void* _Nullable __ptr);
+__nodiscard size_t malloc_usable_size(const void* _Nullable __ptr)
+#if defined(_FORTIFY_SOURCE)
+    __clang_error_if(_FORTIFY_SOURCE == 3, "malloc_usable_size() and _FORTIFY_SOURCE=3 are incompatible")
+#endif
+;
 
 #define __MALLINFO_BODY \
   /** Total number of non-mmapped bytes currently allocated from OS. */ \
diff --git a/libc/include/paths.h b/libc/include/paths.h
index cfbc5b3f3..9116f4e08 100644
--- a/libc/include/paths.h
+++ b/libc/include/paths.h
@@ -38,16 +38,14 @@
 
 #include <sys/cdefs.h>
 
-#ifndef _PATH_BSHELL
 /** Path to the default system shell. Historically the 'B' was to specify the Bourne shell. */
 #define _PATH_BSHELL "/system/bin/sh"
-#endif
 
 /** Path to the system console. */
 #define _PATH_CONSOLE "/dev/console"
 
 /** Default shell search path. */
-#define _PATH_DEFPATH "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin"
+#define _PATH_DEFPATH "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin"
 
 /** Path to the directory containing device files. */
 #define _PATH_DEV "/dev/"
diff --git a/libc/include/pthread.h b/libc/include/pthread.h
index cdf1b8c6c..5a3376ae3 100644
--- a/libc/include/pthread.h
+++ b/libc/include/pthread.h
@@ -170,8 +170,6 @@ int pthread_getattr_np(pthread_t __pthread, pthread_attr_t* _Nonnull __attr);
 
 int pthread_getcpuclockid(pthread_t __pthread, clockid_t* _Nonnull __clock);
 
-void* _Nullable pthread_getspecific(pthread_key_t __key);
-
 pid_t pthread_gettid_np(pthread_t __pthread);
 
 int pthread_join(pthread_t __pthread, void* _Nullable * _Nullable __return_value_ptr);
@@ -189,6 +187,8 @@ int pthread_join(pthread_t __pthread, void* _Nullable * _Nullable __return_value
  * different language, you should consider similar implementation choices and
  * avoid a direct one-to-one mapping from thread locals to pthread keys.
  *
+ * The destructor function is only called for non-null values.
+ *
  * Returns 0 on success and returns an error number on failure.
  */
 int pthread_key_create(pthread_key_t* _Nonnull __key_ptr, void (* _Nullable __key_destructor)(void* _Nullable));
@@ -197,10 +197,28 @@ int pthread_key_create(pthread_key_t* _Nonnull __key_ptr, void (* _Nullable __ke
  * [pthread_key_delete(3)](https://man7.org/linux/man-pages/man3/pthread_key_delete.3p.html)
  * deletes a key for thread-specific data.
  *
+ * Note that pthread_key_delete() does _not_ run destructor functions:
+ * the caller must take care of any necessary cleanup of thread-specific data themselves.
+ * This function only deletes the key itself.
+ *
  * Returns 0 on success and returns an error number on failure.
  */
 int pthread_key_delete(pthread_key_t __key);
 
+/**
+ * [pthread_getspecific(3)](https://man7.org/linux/man-pages/man3/pthread_getspecific.3p.html)
+ * returns the calling thread's thread-specific value for the given key.
+ */
+void* _Nullable pthread_getspecific(pthread_key_t __key);
+
+/**
+ * [pthread_setspecific(3)](https://man7.org/linux/man-pages/man3/pthread_setspecific.3p.html)
+ * sets the calling thread's thread-specific value for the given key.
+ *
+ * Returns 0 on success and returns an error number on failure.
+ */
+int pthread_setspecific(pthread_key_t __key, const void* _Nullable __value);
+
 int pthread_mutexattr_destroy(pthread_mutexattr_t* _Nonnull __attr);
 int pthread_mutexattr_getpshared(const pthread_mutexattr_t* _Nonnull __attr, int* _Nonnull __shared);
 int pthread_mutexattr_gettype(const pthread_mutexattr_t* _Nonnull __attr, int* _Nonnull __type);
@@ -406,9 +424,6 @@ int pthread_getschedparam(pthread_t __pthread, int* _Nonnull __policy, struct sc
 int pthread_setschedprio(pthread_t __pthread, int __priority) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
-int pthread_setspecific(pthread_key_t __key, const void* _Nullable __value);
-
 typedef void (* _Nullable __pthread_cleanup_func_t)(void* _Nullable);
 
 typedef struct __pthread_cleanup_t {
diff --git a/libc/include/sched.h b/libc/include/sched.h
index 7a2dcade8..c68ebf0bb 100644
--- a/libc/include/sched.h
+++ b/libc/include/sched.h
@@ -37,6 +37,7 @@
 
 #include <bits/timespec.h>
 #include <linux/sched.h>
+#include <linux/sched/types.h>
 
 __BEGIN_DECLS
 
@@ -236,12 +237,28 @@ int sched_setaffinity(pid_t __pid, size_t __set_size, const cpu_set_t* _Nonnull
 int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set);
 
 /**
- * [CPU_ZERO](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears all
+ * [sched_setattr(2)](https://man7.org/linux/man-pages/man2/sched_setattr.2.html)
+ * sets the scheduling attributes for the given thread.
+ *
+ * Returns 0 on success and returns -1 and sets `errno` on failure.
+ */
+int sched_setattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __flags) __INTRODUCED_IN(37);
+
+/**
+ * [sched_getattr(2)](https://man7.org/linux/man-pages/man2/sched_getattr.2.html)
+ * gets the scheduling attributes for the given thread.
+ *
+ * Returns 0 on success and returns -1 and sets `errno` on failure.
+ */
+int sched_getattr(pid_t __pid, struct sched_attr* _Nonnull __attr, unsigned __size, unsigned __flags) __INTRODUCED_IN(37);
+
+/**
+ * [CPU_ZERO](https://man7.org/linux/man-pages/man3/CPU_ZERO.3.html) clears all
  * bits in a static CPU set.
  */
 #define CPU_ZERO(set)          CPU_ZERO_S(sizeof(cpu_set_t), set)
 /**
- * [CPU_ZERO_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears all
+ * [CPU_ZERO_S](https://man7.org/linux/man-pages/man3/CPU_ZERO_S.3.html) clears all
  * bits in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_ZERO_S(setsize, set)  __builtin_memset(set, 0, setsize)
@@ -252,7 +269,7 @@ int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set)
  */
 #define CPU_SET(cpu, set)      CPU_SET_S(cpu, sizeof(cpu_set_t), set)
 /**
- * [CPU_SET_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) sets one
+ * [CPU_SET_S](https://man7.org/linux/man-pages/man3/CPU_SET_S.3.html) sets one
  * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_SET_S(cpu, setsize, set) \
@@ -263,12 +280,12 @@ int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set)
   } while (0)
 
 /**
- * [CPU_CLR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears one
+ * [CPU_CLR](https://man7.org/linux/man-pages/man3/CPU_CLR.3.html) clears one
  * bit in a static CPU set.
  */
 #define CPU_CLR(cpu, set)      CPU_CLR_S(cpu, sizeof(cpu_set_t), set)
 /**
- * [CPU_CLR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears one
+ * [CPU_CLR_S](https://man7.org/linux/man-pages/man3/CPU_CLR_S.3.html) clears one
  * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_CLR_S(cpu, setsize, set) \
@@ -279,12 +296,12 @@ int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set)
   } while (0)
 
 /**
- * [CPU_ISSET](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
+ * [CPU_ISSET](https://man7.org/linux/man-pages/man3/CPU_ISSET.3.html) tests
  * whether the given bit is set in a static CPU set.
  */
 #define CPU_ISSET(cpu, set)    CPU_ISSET_S(cpu, sizeof(cpu_set_t), set)
 /**
- * [CPU_ISSET_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
+ * [CPU_ISSET_S](https://man7.org/linux/man-pages/man3/CPU_ISSET_S.3.html) tests
  * whether the given bit is set in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_ISSET_S(cpu, setsize, set) \
@@ -296,58 +313,58 @@ int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set)
   }))
 
 /**
- * [CPU_COUNT](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) counts
+ * [CPU_COUNT](https://man7.org/linux/man-pages/man3/CPU_COUNT.3.html) counts
  * how many bits are set in a static CPU set.
  */
 #define CPU_COUNT(set)         CPU_COUNT_S(sizeof(cpu_set_t), set)
 /**
- * [CPU_COUNT_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) counts
+ * [CPU_COUNT_S](https://man7.org/linux/man-pages/man3/CPU_COUNT_S.3.html) counts
  * how many bits are set in a dynamic CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_COUNT_S(setsize, set)  __sched_cpucount((setsize), (set))
 int __sched_cpucount(size_t __set_size, const cpu_set_t* _Nonnull __set);
 
 /**
- * [CPU_EQUAL](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
+ * [CPU_EQUAL](https://man7.org/linux/man-pages/man3/CPU_EQUAL.3.html) tests
  * whether two static CPU sets have the same bits set and cleared as each other.
  */
 #define CPU_EQUAL(set1, set2)  CPU_EQUAL_S(sizeof(cpu_set_t), set1, set2)
 /**
- * [CPU_EQUAL_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
+ * [CPU_EQUAL_S](https://man7.org/linux/man-pages/man3/CPU_EQUAL_S.3.html) tests
  * whether two dynamic CPU sets allocated by `CPU_ALLOC` have the same bits
  * set and cleared as each other.
  */
 #define CPU_EQUAL_S(setsize, set1, set2)  (__builtin_memcmp(set1, set2, setsize) == 0)
 
 /**
- * [CPU_AND](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ands two
+ * [CPU_AND](https://man7.org/linux/man-pages/man3/CPU_AND.3.html) ands two
  * static CPU sets.
  */
 #define CPU_AND(dst, set1, set2)  __CPU_OP(dst, set1, set2, &)
 /**
- * [CPU_AND_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ands two
+ * [CPU_AND_S](https://man7.org/linux/man-pages/man3/CPU_AND_S.3.html) ands two
  * dynamic CPU sets allocated by `CPU_ALLOC`.
  */
 #define CPU_AND_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, &)
 
 /**
- * [CPU_OR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ors two
+ * [CPU_OR](https://man7.org/linux/man-pages/man3/CPU_OR.3.html) ors two
  * static CPU sets.
  */
 #define CPU_OR(dst, set1, set2)   __CPU_OP(dst, set1, set2, |)
 /**
- * [CPU_OR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ors two
+ * [CPU_OR_S](https://man7.org/linux/man-pages/man3/CPU_OR_S.3.html) ors two
  * dynamic CPU sets allocated by `CPU_ALLOC`.
  */
 #define CPU_OR_S(setsize, dst, set1, set2)   __CPU_OP_S(setsize, dst, set1, set2, |)
 
 /**
- * [CPU_XOR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
+ * [CPU_XOR](https://man7.org/linux/man-pages/man3/CPU_XOR.3.html)
  * exclusive-ors two static CPU sets.
  */
 #define CPU_XOR(dst, set1, set2)  __CPU_OP(dst, set1, set2, ^)
 /**
- * [CPU_XOR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
+ * [CPU_XOR_S](https://man7.org/linux/man-pages/man3/CPU_XOR_S.3.html)
  * exclusive-ors two dynamic CPU sets allocated by `CPU_ALLOC`.
  */
 #define CPU_XOR_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, ^)
@@ -365,21 +382,21 @@ int __sched_cpucount(size_t __set_size, const cpu_set_t* _Nonnull __set);
   } while (0)
 
 /**
- * [CPU_ALLOC_SIZE](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
+ * [CPU_ALLOC_SIZE](https://man7.org/linux/man-pages/man3/CPU_ALLOC_SIZE.3.html)
  * returns the size of a CPU set large enough for CPUs in the range 0..count-1.
  */
 #define CPU_ALLOC_SIZE(count) \
   __CPU_ELT((count) + (__CPU_BITS - 1)) * sizeof(__CPU_BITTYPE)
 
 /**
- * [CPU_ALLOC](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
+ * [CPU_ALLOC](https://man7.org/linux/man-pages/man3/CPU_ALLOC.3.html)
  * allocates a CPU set large enough for CPUs in the range 0..count-1.
  */
 #define CPU_ALLOC(count)  __sched_cpualloc((count))
 cpu_set_t* _Nullable __sched_cpualloc(size_t __count);
 
 /**
- * [CPU_FREE](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
+ * [CPU_FREE](https://man7.org/linux/man-pages/man3/CPU_FREE.3.html)
  * deallocates a CPU set allocated by `CPU_ALLOC`.
  */
 #define CPU_FREE(set)     __sched_cpufree((set))
diff --git a/libc/include/string.h b/libc/include/string.h
index 79aac91b2..a0a7cc438 100644
--- a/libc/include/string.h
+++ b/libc/include/string.h
@@ -160,7 +160,7 @@ int strerror_r(int __errno_value, char* _Nonnull __buf, size_t __n);
 #endif
 
 /**
- * [strerrorname_np(3)](https://man7.org/linux/man-pages/man3/strerrordesc_np.3.html)
+ * [strerrorname_np(3)](https://man7.org/linux/man-pages/man3/strerrorname_np.3.html)
  * returns the name of the errno constant corresponding to its argument.
  * `strerrorname_np(38)` would return "ENOSYS", because `ENOSYS` is errno 38. This
  * is mostly useful for error reporting in cases where a string like "ENOSYS" is
diff --git a/libc/include/sys/cdefs.h b/libc/include/sys/cdefs.h
index 9bd35bb55..a74a5142e 100644
--- a/libc/include/sys/cdefs.h
+++ b/libc/include/sys/cdefs.h
@@ -238,7 +238,7 @@
 // As we move some FORTIFY checks to be always on, __bos needs to be
 // always available.
 #if defined(__BIONIC_FORTIFY)
-#  if _FORTIFY_SOURCE == 2
+#  if _FORTIFY_SOURCE > 1
 #    define __bos_level 1
 #  else
 #    define __bos_level 0
diff --git a/libc/include/sys/io.h b/libc/include/sys/io.h
index 11f3f3a10..472a744f0 100644
--- a/libc/include/sys/io.h
+++ b/libc/include/sys/io.h
@@ -30,7 +30,7 @@
 
 /**
  * @file sys/io.h
- * @brief The x86/x86-64 I/O port functions iopl() and ioperm().
+ * @brief The x86/x86-64 I/O port functions.
  */
 
 #include <sys/cdefs.h>
@@ -72,4 +72,82 @@ static __inline int ioperm(unsigned long __from, unsigned long __n, int __enable
 }
 #endif
 
+/**
+ * [inb(2)](https://man7.org/linux/man-pages/man2/inb.2.html)
+ * reads a byte from the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline unsigned char inb(unsigned short __port) {
+  unsigned char __value;
+  __asm__ __volatile__("inb %1, %0" : "=a"(__value) : "dN"(__port));
+  return __value;
+}
+#endif
+
+/**
+ * [inw(2)](https://man7.org/linux/man-pages/man2/inw.2.html)
+ * reads a 16-bit "word" from the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline unsigned short inw(unsigned short __port) {
+  unsigned short __value;
+  __asm__ __volatile__("inw %1, %0" : "=a"(__value) : "dN"(__port));
+  return __value;
+}
+#endif
+
+/**
+ * [inl(2)](https://man7.org/linux/man-pages/man2/inl.2.html)
+ * reads a 32-bit "long word" from the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline unsigned int inl(unsigned short __port) {
+  unsigned int __value;
+  __asm__ __volatile__("inl %1, %0" : "=a"(__value) : "dN"(__port));
+  return __value;
+}
+#endif
+
+/**
+ * [outb(2)](https://man7.org/linux/man-pages/man2/outb.2.html)
+ * writes the given byte to the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline void outb(unsigned char __value, unsigned short __port) {
+  __asm__ __volatile__("outb %0, %1" : : "a"(__value), "dN"(__port));
+}
+#endif
+
+/**
+ * [outw(2)](https://man7.org/linux/man-pages/man2/outw.2.html)
+ * writes the given 16-bit "word" to the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline void outw(unsigned short __value, unsigned short __port) {
+  __asm__ __volatile__("outw %0, %1" : : "a"(__value), "dN"(__port));
+}
+#endif
+
+/**
+ * [outl(2)](https://man7.org/linux/man-pages/man2/outl.2.html)
+ * writes the given 32-bit "long word" to the given x86/x86-64 I/O port.
+ *
+ * Only available for x86/x86-64.
+ */
+#if defined(__i386__) || defined(__x86_64__)
+static __inline void outl(unsigned int __value, unsigned short __port) {
+  __asm__ __volatile__("outl %0, %1" : : "a"(__value), "dN"(__port));
+}
+#endif
+
 __END_DECLS
diff --git a/libc/include/sys/klog.h b/libc/include/sys/klog.h
index 237d2e29f..6ee410f27 100644
--- a/libc/include/sys/klog.h
+++ b/libc/include/sys/klog.h
@@ -61,7 +61,7 @@ __BEGIN_DECLS
 #define KLOG_SIZE_BUFFER 10
 
 /**
- * [klogctl(2)](https://man7.org/linux/man-pages/man2/syslog.2.html) operates on the kernel log.
+ * [klogctl(3)](https://man7.org/linux/man-pages/man2/klogctl.3.html) operates on the kernel log.
  *
  * This system call is not available to applications.
  * Use syslog() or `<android/log.h>` instead.
diff --git a/libc/include/sys/mman.h b/libc/include/sys/mman.h
index 38cbf2fb7..3fe1f9cbf 100644
--- a/libc/include/sys/mman.h
+++ b/libc/include/sys/mman.h
@@ -126,7 +126,7 @@ int munlockall(void);
 int mlock(const void* _Nonnull __addr, size_t __size);
 
 /**
- * [mlock2(2)](https://man7.org/linux/man-pages/man2/mlock.2.html)
+ * [mlock2(2)](https://man7.org/linux/man-pages/man2/mlock2.2.html)
  * locks pages (preventing swapping), with optional flags.
  *
  * Available since API level 30.
diff --git a/libc/include/sys/pidfd.h b/libc/include/sys/pidfd.h
index aaf49c997..bd2b01e9f 100644
--- a/libc/include/sys/pidfd.h
+++ b/libc/include/sys/pidfd.h
@@ -54,7 +54,7 @@ __BEGIN_DECLS
 int pidfd_open(pid_t __pid, unsigned int __flags) __INTRODUCED_IN(31);
 
 /**
- * [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
+ * [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
  * dups a file descriptor from another process. This file descriptor will have
  * the close-on-exec flag set by default.
  *
diff --git a/libc/include/sys/select.h b/libc/include/sys/select.h
index a7227b071..685e6acc6 100644
--- a/libc/include/sys/select.h
+++ b/libc/include/sys/select.h
@@ -30,7 +30,9 @@
 
 /**
  * @file sys/select.h
- * @brief Wait for events on a set of file descriptors (but use <poll.h> instead).
+ * @brief Wait for events on a set of file descriptors.
+ * New code should prefer the different interface specified in <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  */
 
 #include <sys/cdefs.h>
@@ -44,8 +46,10 @@ __BEGIN_DECLS
 typedef unsigned long fd_mask;
 
 /**
- * The limit on the largest fd that can be used with fd_set.
- * Use <poll.h> instead.
+ * The limit on the largest fd that can be used with type `fd_set`.
+ * You can allocate your own memory,
+ * but new code should prefer the different interface specified in <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  */
 #define FD_SETSIZE 1024
 #define NFDBITS (8 * sizeof(fd_mask))
@@ -55,7 +59,8 @@ typedef unsigned long fd_mask;
  * The underlying system calls do not have this limit,
  * and callers can allocate their own sets with calloc().
  *
- * Use <poll.h> instead.
+ * New code should prefer the different interface specified in <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  */
 typedef struct {
   fd_mask fds_bits[FD_SETSIZE/NFDBITS];
@@ -69,28 +74,62 @@ void __FD_CLR_chk(int, fd_set* _Nonnull , size_t);
 void __FD_SET_chk(int, fd_set* _Nonnull, size_t);
 int __FD_ISSET_chk(int, const fd_set* _Nonnull, size_t);
 
-/** FD_CLR() with no bounds checking for users that allocated their own set. */
+/**
+ * FD_CLR() with no bounds checking for users that allocated their own set.
+ * New code should prefer <poll.h> instead.
+ */
 #define __FD_CLR(fd, set) (__FDS_BITS(fd_set*, set)[__FDELT(fd)] &= ~__FDMASK(fd))
-/** FD_SET() with no bounds checking for users that allocated their own set. */
+
+/**
+ * FD_SET() with no bounds checking for users that allocated their own set.
+ * New code should prefer <poll.h> instead.
+ */
 #define __FD_SET(fd, set) (__FDS_BITS(fd_set*, set)[__FDELT(fd)] |= __FDMASK(fd))
-/** FD_ISSET() with no bounds checking for users that allocated their own set. */
+
+/**
+ * FD_ISSET() with no bounds checking for users that allocated their own set.
+ * New code should prefer <poll.h> instead.
+ */
 #define __FD_ISSET(fd, set) ((__FDS_BITS(const fd_set*, set)[__FDELT(fd)] & __FDMASK(fd)) != 0)
 
-/** Removes all 1024 fds from the given set. Use <poll.h> instead. */
+/**
+ * Removes all 1024 fds from the given set.
+ * Limited to fds under 1024.
+ * New code should prefer <poll.h> instead for this reason,
+ * rather than using memset() directly.
+ */
 #define FD_ZERO(set) __builtin_memset(set, 0, sizeof(*__BIONIC_CAST(static_cast, const fd_set*, set)))
 
-/** Removes `fd` from the given set. Limited to fds under 1024. Use <poll.h> instead. */
+/**
+ * Removes `fd` from the given set.
+ * Limited to fds under 1024.
+ * New code should prefer <poll.h> instead for this reason,
+ * rather than using __FD_CLR().
+ */
 #define FD_CLR(fd, set) __FD_CLR_chk(fd, set, __bos(set))
-/** Adds `fd` to the given set. Limited to fds under 1024. Use <poll.h> instead. */
+
+/**
+ * Adds `fd` to the given set.
+ * Limited to fds under 1024.
+ * New code should prefer <poll.h> instead for this reason,
+ * rather than using __FD_SET().
+ */
 #define FD_SET(fd, set) __FD_SET_chk(fd, set, __bos(set))
-/** Tests whether `fd` is in the given set. Limited to fds under 1024. Use <poll.h> instead. */
+
+/**
+ * Tests whether `fd` is in the given set.
+ * Limited to fds under 1024.
+ * New code should prefer <poll.h> instead for this reason,
+ * rather than using __FD_ISSET().
+ */
 #define FD_ISSET(fd, set) __FD_ISSET_chk(fd, set, __bos(set))
 
 /**
  * [select(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
  * set of file descriptors.
  *
- * Use poll() instead.
+ * New code should prefer poll() from <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  *
  * Returns the number of ready file descriptors on success, 0 for timeout,
  * and returns -1 and sets `errno` on failure.
@@ -98,10 +137,11 @@ int __FD_ISSET_chk(int, const fd_set* _Nonnull, size_t);
 int select(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, struct timeval* _Nullable __timeout);
 
 /**
- * [pselect(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
+ * [pselect(2)](https://man7.org/linux/man-pages/man2/pselect.2.html) waits on a
  * set of file descriptors.
  *
- * Use ppoll() instead.
+ * New code should prefer ppoll() from <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  *
  * Returns the number of ready file descriptors on success, 0 for timeout,
  * and returns -1 and sets `errno` on failure.
@@ -112,17 +152,16 @@ int pselect(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullab
  * [pselect64(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
  * set of file descriptors.
  *
- * Use ppoll64() instead.
+ * New code should prefer ppoll64() from <poll.h> instead,
+ * because it scales better and easily avoids the limits on `fd_set` size.
  *
  * Returns the number of ready file descriptors on success, 0 for timeout,
  * and returns -1 and sets `errno` on failure.
  *
  * Available since API level 28.
  */
-
 #if __BIONIC_AVAILABILITY_GUARD(28)
 int pselect64(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
 #endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
-
 __END_DECLS
diff --git a/libc/include/sys/stat.h b/libc/include/sys/stat.h
index 0b4b248c1..12bfedc3d 100644
--- a/libc/include/sys/stat.h
+++ b/libc/include/sys/stat.h
@@ -216,10 +216,10 @@ int fstat64(int __fd, struct stat64* _Nonnull __buf);
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
-int fstatat(int __dir_fd, const char* _Nonnull __path, struct stat* _Nonnull __buf, int __flags);
+int fstatat(int __dir_fd, const char* _Nullable __path, struct stat* _Nonnull __buf, int __flags);
 
 /** An alias for fstatat(). */
-int fstatat64(int __dir_fd, const char* _Nonnull __path, struct stat64* _Nonnull __buf, int __flags);
+int fstatat64(int __dir_fd, const char* _Nullable __path, struct stat64* _Nonnull __buf, int __flags);
 
 /**
  * [lstat(2)](https://man7.org/linux/man-pages/man2/lstat.2.html)
@@ -320,7 +320,7 @@ int mkfifoat(int __dir_fd, const char* _Nonnull __path, mode_t __mode) __INTRODU
 int utimensat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timespec __times[_Nullable 2], int __flags);
 
 /**
- * [futimens(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html) sets
+ * [futimens(3)](https://man7.org/linux/man-pages/man3/futimens.3.html) sets
  * the given file descriptor's timestamp.
  *
  * `__times[0]` is the access time (atime), and `__times[1]` the last modification time (mtime).
diff --git a/libc/include/time.h b/libc/include/time.h
index 6c9b761bc..777e64865 100644
--- a/libc/include/time.h
+++ b/libc/include/time.h
@@ -281,7 +281,7 @@ size_t strftime_l(char* _Nonnull __buf, size_t __n, const char* _Nonnull __fmt,
 char* _Nullable ctime(const time_t* _Nonnull __t);
 
 /**
- * [ctime_r(3)](https://man7.org/linux/man-pages/man3/ctime.3p.html) formats
+ * [ctime_r(3)](https://man7.org/linux/man-pages/man3/ctime_r.3p.html) formats
  * the time `tm` as a string in the given buffer `buf`.
  *
  * Returns a pointer to a string on success, and returns NULL on failure.
diff --git a/libc/include/unistd.h b/libc/include/unistd.h
index e623339d3..808568a5e 100644
--- a/libc/include/unistd.h
+++ b/libc/include/unistd.h
@@ -283,7 +283,7 @@ int unlinkat(int __dirfd, const char* _Nonnull __path, int __flags);
 int chdir(const char* _Nonnull __path);
 
 /**
- * [fchdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html) changes
+ * [fchdir(2)](https://man7.org/linux/man-pages/man2/fchdir.2.html) changes
  * the current working directory to the given fd.
  *
  * This function affects all threads in the process, so is generally a bad idea
diff --git a/libc/kernel/uapi/asm-arm64/asm/hwcap.h b/libc/kernel/uapi/asm-arm64/asm/hwcap.h
index f5c720aba..45cc9453c 100644
--- a/libc/kernel/uapi/asm-arm64/asm/hwcap.h
+++ b/libc/kernel/uapi/asm-arm64/asm/hwcap.h
@@ -101,4 +101,5 @@
 #define HWCAP2_SME_SF8FMA (1UL << 60)
 #define HWCAP2_SME_SF8DP4 (1UL << 61)
 #define HWCAP2_SME_SF8DP2 (1UL << 62)
+#define HWCAP2_POE (1UL << 63)
 #endif
diff --git a/libc/kernel/uapi/asm-arm64/asm/mman.h b/libc/kernel/uapi/asm-arm64/asm/mman.h
index 15610533c..cc92abe8c 100644
--- a/libc/kernel/uapi/asm-arm64/asm/mman.h
+++ b/libc/kernel/uapi/asm-arm64/asm/mman.h
@@ -9,4 +9,8 @@
 #include <asm-generic/mman.h>
 #define PROT_BTI 0x10
 #define PROT_MTE 0x20
+#define PKEY_DISABLE_EXECUTE 0x4
+#define PKEY_DISABLE_READ 0x8
+#undef PKEY_ACCESS_MASK
+#define PKEY_ACCESS_MASK (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE | PKEY_DISABLE_READ | PKEY_DISABLE_EXECUTE)
 #endif
diff --git a/libc/kernel/uapi/asm-arm64/asm/sigcontext.h b/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
index 8e48d5581..a845a03c3 100644
--- a/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
+++ b/libc/kernel/uapi/asm-arm64/asm/sigcontext.h
@@ -32,6 +32,11 @@ struct esr_context {
   struct _aarch64_ctx head;
   __u64 esr;
 };
+#define POE_MAGIC 0x504f4530
+struct poe_context {
+  struct _aarch64_ctx head;
+  __u64 por_el0;
+};
 #define EXTRA_MAGIC 0x45585401
 struct extra_context {
   struct _aarch64_ctx head;
@@ -95,12 +100,12 @@ struct zt_context {
 #define SVE_SIG_REGS_SIZE(vq) (__SVE_FFR_OFFSET(vq) + __SVE_FFR_SIZE(vq))
 #define SVE_SIG_CONTEXT_SIZE(vq) (SVE_SIG_REGS_OFFSET + SVE_SIG_REGS_SIZE(vq))
 #define ZA_SIG_REGS_OFFSET ((sizeof(struct za_context) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
-#define ZA_SIG_REGS_SIZE(vq) ((vq * __SVE_VQ_BYTES) * (vq * __SVE_VQ_BYTES))
-#define ZA_SIG_ZAV_OFFSET(vq,n) (ZA_SIG_REGS_OFFSET + (SVE_SIG_ZREG_SIZE(vq) * n))
+#define ZA_SIG_REGS_SIZE(vq) (((vq) * __SVE_VQ_BYTES) * ((vq) * __SVE_VQ_BYTES))
+#define ZA_SIG_ZAV_OFFSET(vq,n) (ZA_SIG_REGS_OFFSET + (SVE_SIG_ZREG_SIZE(vq) * (n)))
 #define ZA_SIG_CONTEXT_SIZE(vq) (ZA_SIG_REGS_OFFSET + ZA_SIG_REGS_SIZE(vq))
 #define ZT_SIG_REG_SIZE 512
 #define ZT_SIG_REG_BYTES (ZT_SIG_REG_SIZE / 8)
 #define ZT_SIG_REGS_OFFSET sizeof(struct zt_context)
-#define ZT_SIG_REGS_SIZE(n) (ZT_SIG_REG_BYTES * n)
+#define ZT_SIG_REGS_SIZE(n) (ZT_SIG_REG_BYTES * (n))
 #define ZT_SIG_CONTEXT_SIZE(n) (sizeof(struct zt_context) + ZT_SIG_REGS_SIZE(n))
 #endif
diff --git a/libc/kernel/uapi/asm-generic/socket.h b/libc/kernel/uapi/asm-generic/socket.h
index 2d90586c1..a580c4c8e 100644
--- a/libc/kernel/uapi/asm-generic/socket.h
+++ b/libc/kernel/uapi/asm-generic/socket.h
@@ -92,6 +92,11 @@
 #define SO_RCVMARK 75
 #define SO_PASSPIDFD 76
 #define SO_PEERPIDFD 77
+#define SO_DEVMEM_LINEAR 78
+#define SCM_DEVMEM_LINEAR SO_DEVMEM_LINEAR
+#define SO_DEVMEM_DMABUF 79
+#define SCM_DEVMEM_DMABUF SO_DEVMEM_DMABUF
+#define SO_DEVMEM_DONTNEED 80
 #if __BITS_PER_LONG == 64 || defined(__x86_64__) && defined(__ILP32__)
 #define SO_TIMESTAMP SO_TIMESTAMP_OLD
 #define SO_TIMESTAMPNS SO_TIMESTAMPNS_OLD
diff --git a/libc/kernel/uapi/asm-x86/asm/elf.h b/libc/kernel/uapi/asm-x86/asm/elf.h
new file mode 100644
index 000000000..b66a2290b
--- /dev/null
+++ b/libc/kernel/uapi/asm-x86/asm/elf.h
@@ -0,0 +1,16 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_ASM_X86_ELF_H
+#define _UAPI_ASM_X86_ELF_H
+#include <linux/types.h>
+struct x86_xfeat_component {
+  __u32 type;
+  __u32 size;
+  __u32 offset;
+  __u32 flags;
+} __attribute__((__packed__));
+#endif
diff --git a/libc/kernel/uapi/asm-x86/asm/kvm.h b/libc/kernel/uapi/asm-x86/asm/kvm.h
index cd647b6d8..0a35412a0 100644
--- a/libc/kernel/uapi/asm-x86/asm/kvm.h
+++ b/libc/kernel/uapi/asm-x86/asm/kvm.h
@@ -342,6 +342,7 @@ struct kvm_sync_regs {
 #define KVM_X86_QUIRK_MISC_ENABLE_NO_MWAIT (1 << 4)
 #define KVM_X86_QUIRK_FIX_HYPERCALL_INSN (1 << 5)
 #define KVM_X86_QUIRK_MWAIT_NEVER_UD_FAULTS (1 << 6)
+#define KVM_X86_QUIRK_SLOT_ZAP_ALL (1 << 7)
 #define KVM_STATE_NESTED_FORMAT_VMX 0
 #define KVM_STATE_NESTED_FORMAT_SVM 1
 #define KVM_STATE_NESTED_GUEST_MODE 0x00000001
diff --git a/libc/kernel/uapi/drm/drm_fourcc.h b/libc/kernel/uapi/drm/drm_fourcc.h
index 4902d6c4e..c0f5ff1f3 100644
--- a/libc/kernel/uapi/drm/drm_fourcc.h
+++ b/libc/kernel/uapi/drm/drm_fourcc.h
@@ -172,6 +172,8 @@ extern "C" {
 #define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS fourcc_mod_code(INTEL, 13)
 #define I915_FORMAT_MOD_4_TILED_MTL_MC_CCS fourcc_mod_code(INTEL, 14)
 #define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC fourcc_mod_code(INTEL, 15)
+#define I915_FORMAT_MOD_4_TILED_LNL_CCS fourcc_mod_code(INTEL, 16)
+#define I915_FORMAT_MOD_4_TILED_BMG_CCS fourcc_mod_code(INTEL, 17)
 #define DRM_FORMAT_MOD_SAMSUNG_64_32_TILE fourcc_mod_code(SAMSUNG, 1)
 #define DRM_FORMAT_MOD_SAMSUNG_16_16_TILE fourcc_mod_code(SAMSUNG, 2)
 #define DRM_FORMAT_MOD_QCOM_COMPRESSED fourcc_mod_code(QCOM, 1)
diff --git a/libc/kernel/uapi/drm/msm_drm.h b/libc/kernel/uapi/drm/msm_drm.h
index 7ec5ed2a3..582da62b9 100644
--- a/libc/kernel/uapi/drm/msm_drm.h
+++ b/libc/kernel/uapi/drm/msm_drm.h
@@ -38,6 +38,8 @@ struct drm_msm_timespec {
 #define MSM_PARAM_VA_SIZE 0x0f
 #define MSM_PARAM_HIGHEST_BANK_BIT 0x10
 #define MSM_PARAM_RAYTRACING 0x11
+#define MSM_PARAM_UBWC_SWIZZLE 0x12
+#define MSM_PARAM_MACROTILE_MODE 0x13
 #define MSM_PARAM_NR_RINGS MSM_PARAM_PRIORITIES
 struct drm_msm_param {
   __u32 pipe;
diff --git a/libc/kernel/uapi/drm/xe_drm.h b/libc/kernel/uapi/drm/xe_drm.h
index a034b2921..16bc3b3d5 100644
--- a/libc/kernel/uapi/drm/xe_drm.h
+++ b/libc/kernel/uapi/drm/xe_drm.h
@@ -124,6 +124,7 @@ struct drm_xe_query_topology_mask {
 #define DRM_XE_TOPO_DSS_COMPUTE 2
 #define DRM_XE_TOPO_L3_BANK 3
 #define DRM_XE_TOPO_EU_PER_DSS 4
+#define DRM_XE_TOPO_SIMD16_EU_PER_DSS 5
   __u16 type;
   __u32 num_bytes;
   __u8 mask[];
diff --git a/libc/kernel/uapi/linux/android/binder.h b/libc/kernel/uapi/linux/android/binder.h
index 6e64ebc30..273ee5944 100644
--- a/libc/kernel/uapi/linux/android/binder.h
+++ b/libc/kernel/uapi/linux/android/binder.h
@@ -115,6 +115,11 @@ struct binder_frozen_status_info {
   __u32 sync_recv;
   __u32 async_recv;
 };
+struct binder_frozen_state_info {
+  binder_uintptr_t cookie;
+  __u32 is_frozen;
+  __u32 reserved;
+};
 struct binder_extended_error {
   __u32 id;
   __u32 command;
@@ -212,6 +217,8 @@ enum binder_driver_return_protocol {
   BR_FROZEN_REPLY = _IO('r', 18),
   BR_ONEWAY_SPAM_SUSPECT = _IO('r', 19),
   BR_TRANSACTION_PENDING_FROZEN = _IO('r', 20),
+  BR_FROZEN_BINDER = _IOR('r', 21, struct binder_frozen_state_info),
+  BR_CLEAR_FREEZE_NOTIFICATION_DONE = _IOR('r', 22, binder_uintptr_t),
 };
 enum binder_driver_command_protocol {
   BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
@@ -233,5 +240,8 @@ enum binder_driver_command_protocol {
   BC_DEAD_BINDER_DONE = _IOW('c', 16, binder_uintptr_t),
   BC_TRANSACTION_SG = _IOW('c', 17, struct binder_transaction_data_sg),
   BC_REPLY_SG = _IOW('c', 18, struct binder_transaction_data_sg),
+  BC_REQUEST_FREEZE_NOTIFICATION = _IOW('c', 19, struct binder_handle_cookie),
+  BC_CLEAR_FREEZE_NOTIFICATION = _IOW('c', 20, struct binder_handle_cookie),
+  BC_FREEZE_NOTIFICATION_DONE = _IOW('c', 21, binder_uintptr_t),
 };
 #endif
diff --git a/libc/kernel/uapi/linux/audit.h b/libc/kernel/uapi/linux/audit.h
index 98849f167..ae50fccf5 100644
--- a/libc/kernel/uapi/linux/audit.h
+++ b/libc/kernel/uapi/linux/audit.h
@@ -95,6 +95,9 @@
 #define AUDIT_MAC_UNLBL_STCDEL 1417
 #define AUDIT_MAC_CALIPSO_ADD 1418
 #define AUDIT_MAC_CALIPSO_DEL 1419
+#define AUDIT_IPE_ACCESS 1420
+#define AUDIT_IPE_CONFIG_CHANGE 1421
+#define AUDIT_IPE_POLICY_LOAD 1422
 #define AUDIT_FIRST_KERN_ANOM_MSG 1700
 #define AUDIT_LAST_KERN_ANOM_MSG 1799
 #define AUDIT_ANOM_PROMISCUOUS 1700
diff --git a/libc/kernel/uapi/linux/auto_fs.h b/libc/kernel/uapi/linux/auto_fs.h
index dd11a9328..a48a8874b 100644
--- a/libc/kernel/uapi/linux/auto_fs.h
+++ b/libc/kernel/uapi/linux/auto_fs.h
@@ -12,7 +12,7 @@
 #define AUTOFS_PROTO_VERSION 5
 #define AUTOFS_MIN_PROTO_VERSION 3
 #define AUTOFS_MAX_PROTO_VERSION 5
-#define AUTOFS_PROTO_SUBVERSION 5
+#define AUTOFS_PROTO_SUBVERSION 6
 #if defined(__ia64__) || defined(__alpha__)
 typedef unsigned long autofs_wqt_t;
 #else
diff --git a/libc/kernel/uapi/linux/bits.h b/libc/kernel/uapi/linux/bits.h
index d747e2427..2b8dbe2e4 100644
--- a/libc/kernel/uapi/linux/bits.h
+++ b/libc/kernel/uapi/linux/bits.h
@@ -8,4 +8,5 @@
 #define _UAPI_LINUX_BITS_H
 #define __GENMASK(h,l) (((~_UL(0)) - (_UL(1) << (l)) + 1) & (~_UL(0) >> (__BITS_PER_LONG - 1 - (h))))
 #define __GENMASK_ULL(h,l) (((~_ULL(0)) - (_ULL(1) << (l)) + 1) & (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
+#define __GENMASK_U128(h,l) ((_BIT128((h)) << 1) - (_BIT128(l)))
 #endif
diff --git a/libc/kernel/uapi/linux/blkdev.h b/libc/kernel/uapi/linux/blkdev.h
new file mode 100644
index 000000000..103fa0f43
--- /dev/null
+++ b/libc/kernel/uapi/linux/blkdev.h
@@ -0,0 +1,12 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_LINUX_BLKDEV_H
+#define _UAPI_LINUX_BLKDEV_H
+#include <linux/ioctl.h>
+#include <linux/types.h>
+#define BLOCK_URING_CMD_DISCARD _IO(0x12, 0)
+#endif
diff --git a/libc/kernel/uapi/linux/bpf.h b/libc/kernel/uapi/linux/bpf.h
index 8d648164c..c0d862d1a 100644
--- a/libc/kernel/uapi/linux/bpf.h
+++ b/libc/kernel/uapi/linux/bpf.h
@@ -670,9 +670,6 @@ enum {
   BPF_F_MARK_MANGLED_0 = (1ULL << 5),
   BPF_F_MARK_ENFORCE = (1ULL << 6),
 };
-enum {
-  BPF_F_INGRESS = (1ULL << 0),
-};
 enum {
   BPF_F_TUNINFO_IPV6 = (1ULL << 0),
 };
@@ -768,8 +765,10 @@ enum {
   BPF_F_BPRM_SECUREEXEC = (1ULL << 0),
 };
 enum {
+  BPF_F_INGRESS = (1ULL << 0),
   BPF_F_BROADCAST = (1ULL << 3),
   BPF_F_EXCLUDE_INGRESS = (1ULL << 4),
+#define BPF_F_REDIRECT_FLAGS (BPF_F_INGRESS | BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)
 };
 #define __bpf_md_ptr(type,name) union { type name; __u64 : 64; \
 } __attribute__((aligned(8)))
@@ -1275,6 +1274,7 @@ enum {
   TCP_BPF_SYN = 1005,
   TCP_BPF_SYN_IP = 1006,
   TCP_BPF_SYN_MAC = 1007,
+  TCP_BPF_SOCK_OPS_CB_FLAGS = 1008,
 };
 enum {
   BPF_LOAD_HDR_OPT_TCP_SYN = (1ULL << 0),
@@ -1528,4 +1528,7 @@ enum {
 struct bpf_iter_num {
   __u64 __opaque[1];
 } __attribute__((aligned(8)));
+enum bpf_kfunc_flags {
+  BPF_F_PAD_ZEROS = (1ULL << 0),
+};
 #endif
diff --git a/libc/kernel/uapi/linux/cec.h b/libc/kernel/uapi/linux/cec.h
index 43e845669..91f4d676c 100644
--- a/libc/kernel/uapi/linux/cec.h
+++ b/libc/kernel/uapi/linux/cec.h
@@ -27,6 +27,7 @@ struct cec_msg {
 };
 #define CEC_MSG_FL_REPLY_TO_FOLLOWERS (1 << 0)
 #define CEC_MSG_FL_RAW (1 << 1)
+#define CEC_MSG_FL_REPLY_VENDOR_ID (1 << 2)
 #define CEC_TX_STATUS_OK (1 << 0)
 #define CEC_TX_STATUS_ARB_LOST (1 << 1)
 #define CEC_TX_STATUS_NACK (1 << 2)
@@ -96,6 +97,7 @@ struct cec_msg {
 #define CEC_CAP_NEEDS_HPD (1 << 6)
 #define CEC_CAP_MONITOR_PIN (1 << 7)
 #define CEC_CAP_CONNECTOR_INFO (1 << 8)
+#define CEC_CAP_REPLY_VENDOR_ID (1 << 9)
 struct cec_caps {
   char driver[32];
   char name[32];
diff --git a/libc/kernel/uapi/linux/const.h b/libc/kernel/uapi/linux/const.h
index c091f8dfa..b45b7221f 100644
--- a/libc/kernel/uapi/linux/const.h
+++ b/libc/kernel/uapi/linux/const.h
@@ -18,6 +18,9 @@
 #define _ULL(x) (_AC(x, ULL))
 #define _BITUL(x) (_UL(1) << (x))
 #define _BITULL(x) (_ULL(1) << (x))
+#ifndef __ASSEMBLY__
+#define _BIT128(x) ((unsigned __int128) (1) << (x))
+#endif
 #define __ALIGN_KERNEL(x,a) __ALIGN_KERNEL_MASK(x, (__typeof__(x)) (a) - 1)
 #define __ALIGN_KERNEL_MASK(x,mask) (((x) + (mask)) & ~(mask))
 #define __KERNEL_DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
diff --git a/libc/kernel/uapi/linux/dpll.h b/libc/kernel/uapi/linux/dpll.h
index dd692f6ed..7d6182bcb 100644
--- a/libc/kernel/uapi/linux/dpll.h
+++ b/libc/kernel/uapi/linux/dpll.h
@@ -108,6 +108,9 @@ enum dpll_a_pin {
   DPLL_A_PIN_PHASE_ADJUST,
   DPLL_A_PIN_PHASE_OFFSET,
   DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
+  DPLL_A_PIN_ESYNC_FREQUENCY,
+  DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED,
+  DPLL_A_PIN_ESYNC_PULSE,
   __DPLL_A_PIN_MAX,
   DPLL_A_PIN_MAX = (__DPLL_A_PIN_MAX - 1)
 };
diff --git a/libc/kernel/uapi/linux/elf.h b/libc/kernel/uapi/linux/elf.h
index f1cf52293..ea40103ae 100644
--- a/libc/kernel/uapi/linux/elf.h
+++ b/libc/kernel/uapi/linux/elf.h
@@ -329,6 +329,7 @@ typedef struct elf64_shdr {
 #define NT_386_IOPERM 0x201
 #define NT_X86_XSTATE 0x202
 #define NT_X86_SHSTK 0x204
+#define NT_X86_XSAVE_LAYOUT 0x205
 #define NT_S390_HIGH_GPRS 0x300
 #define NT_S390_TIMER 0x301
 #define NT_S390_TODCMP 0x302
@@ -359,6 +360,7 @@ typedef struct elf64_shdr {
 #define NT_ARM_ZA 0x40c
 #define NT_ARM_ZT 0x40d
 #define NT_ARM_FPMR 0x40e
+#define NT_ARM_POE 0x40f
 #define NT_ARC_V2 0x600
 #define NT_VMCOREDD 0x700
 #define NT_MIPS_DSP 0x800
diff --git a/libc/kernel/uapi/linux/ethtool.h b/libc/kernel/uapi/linux/ethtool.h
index e213ba1b8..323c4fcc0 100644
--- a/libc/kernel/uapi/linux/ethtool.h
+++ b/libc/kernel/uapi/linux/ethtool.h
@@ -1026,4 +1026,8 @@ struct ethtool_link_settings {
   __u32 reserved[7];
   __u32 link_mode_masks[];
 };
+enum phy_upstream {
+  PHY_UPSTREAM_MAC,
+  PHY_UPSTREAM_PHY,
+};
 #endif
diff --git a/libc/kernel/uapi/linux/ethtool_netlink.h b/libc/kernel/uapi/linux/ethtool_netlink.h
index ac6391a0b..7120c03eb 100644
--- a/libc/kernel/uapi/linux/ethtool_netlink.h
+++ b/libc/kernel/uapi/linux/ethtool_netlink.h
@@ -53,6 +53,7 @@ enum {
   ETHTOOL_MSG_MM_GET,
   ETHTOOL_MSG_MM_SET,
   ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+  ETHTOOL_MSG_PHY_GET,
   __ETHTOOL_MSG_USER_CNT,
   ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
 };
@@ -102,6 +103,8 @@ enum {
   ETHTOOL_MSG_MM_GET_REPLY,
   ETHTOOL_MSG_MM_NTF,
   ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
+  ETHTOOL_MSG_PHY_GET_REPLY,
+  ETHTOOL_MSG_PHY_NTF,
   __ETHTOOL_MSG_KERNEL_CNT,
   ETHTOOL_MSG_KERNEL_MAX = __ETHTOOL_MSG_KERNEL_CNT - 1
 };
@@ -116,6 +119,7 @@ enum {
   ETHTOOL_A_HEADER_DEV_INDEX,
   ETHTOOL_A_HEADER_DEV_NAME,
   ETHTOOL_A_HEADER_FLAGS,
+  ETHTOOL_A_HEADER_PHY_INDEX,
   __ETHTOOL_A_HEADER_CNT,
   ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
 };
@@ -408,6 +412,8 @@ enum {
   ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
   ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
   ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
+  ETHTOOL_A_CABLE_RESULT_CODE_NOISE,
+  ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE,
 };
 enum {
   ETHTOOL_A_CABLE_PAIR_A,
@@ -415,10 +421,16 @@ enum {
   ETHTOOL_A_CABLE_PAIR_C,
   ETHTOOL_A_CABLE_PAIR_D,
 };
+enum {
+  ETHTOOL_A_CABLE_INF_SRC_UNSPEC,
+  ETHTOOL_A_CABLE_INF_SRC_TDR,
+  ETHTOOL_A_CABLE_INF_SRC_ALCD,
+};
 enum {
   ETHTOOL_A_CABLE_RESULT_UNSPEC,
   ETHTOOL_A_CABLE_RESULT_PAIR,
   ETHTOOL_A_CABLE_RESULT_CODE,
+  ETHTOOL_A_CABLE_RESULT_SRC,
   __ETHTOOL_A_CABLE_RESULT_CNT,
   ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
 };
@@ -426,6 +438,7 @@ enum {
   ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
   ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
   ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
+  ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
   __ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
   ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
 };
@@ -683,6 +696,7 @@ enum {
   ETHTOOL_A_RSS_INDIR,
   ETHTOOL_A_RSS_HKEY,
   ETHTOOL_A_RSS_INPUT_XFRM,
+  ETHTOOL_A_RSS_START_CONTEXT,
   __ETHTOOL_A_RSS_CNT,
   ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
 };
@@ -740,6 +754,19 @@ enum {
   __ETHTOOL_A_MODULE_FW_FLASH_CNT,
   ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
 };
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
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
 #define ETHTOOL_MCGRP_MONITOR_NAME "monitor"
diff --git a/libc/kernel/uapi/linux/exfat.h b/libc/kernel/uapi/linux/exfat.h
new file mode 100644
index 000000000..b8135811d
--- /dev/null
+++ b/libc/kernel/uapi/linux/exfat.h
@@ -0,0 +1,15 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_LINUX_EXFAT_H
+#define _UAPI_LINUX_EXFAT_H
+#include <linux/types.h>
+#include <linux/ioctl.h>
+#define EXFAT_IOC_SHUTDOWN _IOR('X', 125, __u32)
+#define EXFAT_GOING_DOWN_DEFAULT 0x0
+#define EXFAT_GOING_DOWN_FULLSYNC 0x1
+#define EXFAT_GOING_DOWN_NOSYNC 0x2
+#endif
diff --git a/libc/kernel/uapi/linux/falloc.h b/libc/kernel/uapi/linux/falloc.h
index cca488ed8..cd7017e9c 100644
--- a/libc/kernel/uapi/linux/falloc.h
+++ b/libc/kernel/uapi/linux/falloc.h
@@ -6,6 +6,7 @@
  */
 #ifndef _UAPI_FALLOC_H_
 #define _UAPI_FALLOC_H_
+#define FALLOC_FL_ALLOCATE_RANGE 0x00
 #define FALLOC_FL_KEEP_SIZE 0x01
 #define FALLOC_FL_PUNCH_HOLE 0x02
 #define FALLOC_FL_NO_HIDE_STALE 0x04
diff --git a/libc/kernel/uapi/linux/fcntl.h b/libc/kernel/uapi/linux/fcntl.h
index 9f32f9fb1..22ca65dc9 100644
--- a/libc/kernel/uapi/linux/fcntl.h
+++ b/libc/kernel/uapi/linux/fcntl.h
@@ -12,6 +12,7 @@
 #define F_GETLEASE (F_LINUX_SPECIFIC_BASE + 1)
 #define F_NOTIFY (F_LINUX_SPECIFIC_BASE + 2)
 #define F_DUPFD_QUERY (F_LINUX_SPECIFIC_BASE + 3)
+#define F_CREATED_QUERY (F_LINUX_SPECIFIC_BASE + 4)
 #define F_CANCELLK (F_LINUX_SPECIFIC_BASE + 5)
 #define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)
 #define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
@@ -44,8 +45,6 @@
 #define DN_MULTISHOT 0x80000000
 #define AT_FDCWD - 100
 #define AT_SYMLINK_NOFOLLOW 0x100
-#define AT_EACCESS 0x200
-#define AT_REMOVEDIR 0x200
 #define AT_SYMLINK_FOLLOW 0x400
 #define AT_NO_AUTOMOUNT 0x800
 #define AT_EMPTY_PATH 0x1000
@@ -54,5 +53,11 @@
 #define AT_STATX_FORCE_SYNC 0x2000
 #define AT_STATX_DONT_SYNC 0x4000
 #define AT_RECURSIVE 0x8000
-#define AT_HANDLE_FID AT_REMOVEDIR
+#define AT_RENAME_NOREPLACE 0x0001
+#define AT_RENAME_EXCHANGE 0x0002
+#define AT_RENAME_WHITEOUT 0x0004
+#define AT_EACCESS 0x200
+#define AT_REMOVEDIR 0x200
+#define AT_HANDLE_FID 0x200
+#define AT_HANDLE_MNT_ID_UNIQUE 0x001
 #endif
diff --git a/libc/kernel/uapi/linux/fib_rules.h b/libc/kernel/uapi/linux/fib_rules.h
index ee9cabcde..339ccceee 100644
--- a/libc/kernel/uapi/linux/fib_rules.h
+++ b/libc/kernel/uapi/linux/fib_rules.h
@@ -61,6 +61,7 @@ enum {
   FRA_IP_PROTO,
   FRA_SPORT_RANGE,
   FRA_DPORT_RANGE,
+  FRA_DSCP,
   __FRA_MAX
 };
 #define FRA_MAX (__FRA_MAX - 1)
diff --git a/libc/kernel/uapi/linux/fuse.h b/libc/kernel/uapi/linux/fuse.h
index 4ac2d2c65..c1d64ce01 100644
--- a/libc/kernel/uapi/linux/fuse.h
+++ b/libc/kernel/uapi/linux/fuse.h
@@ -8,7 +8,7 @@
 #define _LINUX_FUSE_H
 #include <stdint.h>
 #define FUSE_KERNEL_VERSION 7
-#define FUSE_KERNEL_MINOR_VERSION 40
+#define FUSE_KERNEL_MINOR_VERSION 41
 #define FUSE_ROOT_ID 1
 struct fuse_attr {
   uint64_t ino;
@@ -135,6 +135,7 @@ struct fuse_file_lock {
 #define FUSE_NO_EXPORT_SUPPORT (1ULL << 38)
 #define FUSE_HAS_RESEND (1ULL << 39)
 #define FUSE_DIRECT_IO_RELAX FUSE_DIRECT_IO_ALLOW_MMAP
+#define FUSE_ALLOW_IDMAP (1ULL << 40)
 #define CUSE_UNRESTRICTED_IOCTL (1 << 0)
 #define FUSE_RELEASE_FLUSH (1 << 0)
 #define FUSE_RELEASE_FLOCK_UNLOCK (1 << 1)
@@ -214,6 +215,7 @@ enum fuse_opcode {
   FUSE_SYNCFS = 50,
   FUSE_TMPFILE = 51,
   FUSE_STATX = 52,
+  FUSE_CANONICAL_PATH = 2016,
   CUSE_INIT = 4096,
   CUSE_INIT_BSWAP_RESERVED = 1048576,
   FUSE_INIT_BSWAP_RESERVED = 436207616,
@@ -497,6 +499,7 @@ struct fuse_fallocate_in {
   uint32_t padding;
 };
 #define FUSE_UNIQUE_RESEND (1ULL << 63)
+#define FUSE_INVALID_UIDGID ((uint32_t) (- 1))
 struct fuse_in_header {
   uint32_t len;
   uint32_t opcode;
diff --git a/libc/kernel/uapi/linux/hidraw.h b/libc/kernel/uapi/linux/hidraw.h
index 25a9a1773..1eb024cde 100644
--- a/libc/kernel/uapi/linux/hidraw.h
+++ b/libc/kernel/uapi/linux/hidraw.h
@@ -29,6 +29,7 @@ struct hidraw_devinfo {
 #define HIDIOCGINPUT(len) _IOC(_IOC_WRITE | _IOC_READ, 'H', 0x0A, len)
 #define HIDIOCSOUTPUT(len) _IOC(_IOC_WRITE | _IOC_READ, 'H', 0x0B, len)
 #define HIDIOCGOUTPUT(len) _IOC(_IOC_WRITE | _IOC_READ, 'H', 0x0C, len)
+#define HIDIOCREVOKE _IOW('H', 0x0D, int)
 #define HIDRAW_FIRST_MINOR 0
 #define HIDRAW_MAX_DEVICES 64
 #define HIDRAW_BUFFER_SIZE 64
diff --git a/libc/kernel/uapi/linux/io_uring.h b/libc/kernel/uapi/linux/io_uring.h
index 6b4f2ea9b..5564bff00 100644
--- a/libc/kernel/uapi/linux/io_uring.h
+++ b/libc/kernel/uapi/linux/io_uring.h
@@ -230,6 +230,7 @@ struct io_uring_cqe {
 #define IORING_CQE_F_MORE (1U << 1)
 #define IORING_CQE_F_SOCK_NONEMPTY (1U << 2)
 #define IORING_CQE_F_NOTIF (1U << 3)
+#define IORING_CQE_F_BUF_MORE (1U << 4)
 #define IORING_CQE_BUFFER_SHIFT 16
 #define IORING_OFF_SQ_RING 0ULL
 #define IORING_OFF_CQ_RING 0x8000000ULL
@@ -268,6 +269,7 @@ struct io_cqring_offsets {
 #define IORING_ENTER_SQ_WAIT (1U << 2)
 #define IORING_ENTER_EXT_ARG (1U << 3)
 #define IORING_ENTER_REGISTERED_RING (1U << 4)
+#define IORING_ENTER_ABS_TIMER (1U << 5)
 struct io_uring_params {
   __u32 sq_entries;
   __u32 cq_entries;
@@ -295,6 +297,7 @@ struct io_uring_params {
 #define IORING_FEAT_LINKED_FILE (1U << 12)
 #define IORING_FEAT_REG_REG_RING (1U << 13)
 #define IORING_FEAT_RECVSEND_BUNDLE (1U << 14)
+#define IORING_FEAT_MIN_TIMEOUT (1U << 15)
 enum io_uring_register_op {
   IORING_REGISTER_BUFFERS = 0,
   IORING_UNREGISTER_BUFFERS = 1,
@@ -325,6 +328,8 @@ enum io_uring_register_op {
   IORING_REGISTER_PBUF_STATUS = 26,
   IORING_REGISTER_NAPI = 27,
   IORING_UNREGISTER_NAPI = 28,
+  IORING_REGISTER_CLOCK = 29,
+  IORING_REGISTER_CLONE_BUFFERS = 30,
   IORING_REGISTER_LAST,
   IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
 };
@@ -383,6 +388,18 @@ struct io_uring_restriction {
   __u8 resv;
   __u32 resv2[3];
 };
+struct io_uring_clock_register {
+  __u32 clockid;
+  __u32 __resv[3];
+};
+enum {
+  IORING_REGISTER_SRC_REGISTERED = 1,
+};
+struct io_uring_clone_buffers {
+  __u32 src_fd;
+  __u32 flags;
+  __u32 pad[6];
+};
 struct io_uring_buf {
   __u64 addr;
   __u32 len;
@@ -402,6 +419,7 @@ struct io_uring_buf_ring {
 };
 enum io_uring_register_pbuf_ring_flags {
   IOU_PBUF_RING_MMAP = 1,
+  IOU_PBUF_RING_INC = 2,
 };
 struct io_uring_buf_reg {
   __u64 ring_addr;
@@ -431,7 +449,7 @@ enum io_uring_register_restriction_op {
 struct io_uring_getevents_arg {
   __u64 sigmask;
   __u32 sigmask_sz;
-  __u32 pad;
+  __u32 min_wait_usec;
   __u64 ts;
 };
 struct io_uring_sync_cancel_reg {
diff --git a/libc/kernel/uapi/linux/ioam6_iptunnel.h b/libc/kernel/uapi/linux/ioam6_iptunnel.h
index 34317fc63..e1a02239e 100644
--- a/libc/kernel/uapi/linux/ioam6_iptunnel.h
+++ b/libc/kernel/uapi/linux/ioam6_iptunnel.h
@@ -24,6 +24,7 @@ enum {
 #define IOAM6_IPTUNNEL_FREQ_MAX 1000000
   IOAM6_IPTUNNEL_FREQ_K,
   IOAM6_IPTUNNEL_FREQ_N,
+  IOAM6_IPTUNNEL_SRC,
   __IOAM6_IPTUNNEL_MAX,
 };
 #define IOAM6_IPTUNNEL_MAX (__IOAM6_IPTUNNEL_MAX - 1)
diff --git a/libc/kernel/uapi/linux/iommufd.h b/libc/kernel/uapi/linux/iommufd.h
index 6f663b410..3bbcd40c6 100644
--- a/libc/kernel/uapi/linux/iommufd.h
+++ b/libc/kernel/uapi/linux/iommufd.h
@@ -6,8 +6,8 @@
  */
 #ifndef _UAPI_IOMMUFD_H
 #define _UAPI_IOMMUFD_H
-#include <linux/types.h>
 #include <linux/ioctl.h>
+#include <linux/types.h>
 #define IOMMUFD_TYPE (';')
 enum {
   IOMMUFD_CMD_BASE = 0x80,
diff --git a/libc/kernel/uapi/linux/kfd_ioctl.h b/libc/kernel/uapi/linux/kfd_ioctl.h
index 193dd8e6d..8948a13c1 100644
--- a/libc/kernel/uapi/linux/kfd_ioctl.h
+++ b/libc/kernel/uapi/linux/kfd_ioctl.h
@@ -9,7 +9,7 @@
 #include <drm/drm.h>
 #include <linux/ioctl.h>
 #define KFD_IOCTL_MAJOR_VERSION 1
-#define KFD_IOCTL_MINOR_VERSION 16
+#define KFD_IOCTL_MINOR_VERSION 17
 struct kfd_ioctl_get_version_args {
   __u32 major_version;
   __u32 minor_version;
@@ -18,6 +18,7 @@ struct kfd_ioctl_get_version_args {
 #define KFD_IOC_QUEUE_TYPE_SDMA 0x1
 #define KFD_IOC_QUEUE_TYPE_COMPUTE_AQL 0x2
 #define KFD_IOC_QUEUE_TYPE_SDMA_XGMI 0x3
+#define KFD_IOC_QUEUE_TYPE_SDMA_BY_ENG_ID 0x4
 #define KFD_MAX_QUEUE_PERCENTAGE 100
 #define KFD_MAX_QUEUE_PRIORITY 15
 struct kfd_ioctl_create_queue_args {
@@ -36,6 +37,8 @@ struct kfd_ioctl_create_queue_args {
   __u64 ctx_save_restore_address;
   __u32 ctx_save_restore_size;
   __u32 ctl_stack_size;
+  __u32 sdma_engine_id;
+  __u32 pad;
 };
 struct kfd_ioctl_destroy_queue_args {
   __u32 queue_id;
@@ -358,6 +361,16 @@ struct kfd_ioctl_smi_events_args {
   __u32 gpuid;
   __u32 anon_fd;
 };
+#define KFD_EVENT_FMT_UPDATE_GPU_RESET(reset_seq_num,reset_cause) "%x %s\n", (reset_seq_num), (reset_cause)
+#define KFD_EVENT_FMT_THERMAL_THROTTLING(bitmask,counter) "%llx:%llx\n", (bitmask), (counter)
+#define KFD_EVENT_FMT_VMFAULT(pid,task_name) "%x:%s\n", (pid), (task_name)
+#define KFD_EVENT_FMT_PAGEFAULT_START(ns,pid,addr,node,rw) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (rw)
+#define KFD_EVENT_FMT_PAGEFAULT_END(ns,pid,addr,node,migrate_update) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (migrate_update)
+#define KFD_EVENT_FMT_MIGRATE_START(ns,pid,start,size,from,to,prefetch_loc,preferred_loc,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %x:%x %d\n", (ns), (pid), (start), (size), (from), (to), (prefetch_loc), (preferred_loc), (migrate_trigger)
+#define KFD_EVENT_FMT_MIGRATE_END(ns,pid,start,size,from,to,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %d\n", (ns), (pid), (start), (size), (from), (to), (migrate_trigger)
+#define KFD_EVENT_FMT_QUEUE_EVICTION(ns,pid,node,evict_trigger) "%lld -%d %x %d\n", (ns), (pid), (node), (evict_trigger)
+#define KFD_EVENT_FMT_QUEUE_RESTORE(ns,pid,node,rescheduled) "%lld -%d %x %c\n", (ns), (pid), (node), (rescheduled)
+#define KFD_EVENT_FMT_UNMAP_FROM_GPU(ns,pid,addr,size,node,unmap_trigger) "%lld -%d @%lx(%lx) %x %d\n", (ns), (pid), (addr), (size), (node), (unmap_trigger)
 enum kfd_criu_op {
   KFD_CRIU_OP_PROCESS_INFO,
   KFD_CRIU_OP_CHECKPOINT,
diff --git a/libc/kernel/uapi/linux/landlock.h b/libc/kernel/uapi/linux/landlock.h
index f903ae649..8f837805a 100644
--- a/libc/kernel/uapi/linux/landlock.h
+++ b/libc/kernel/uapi/linux/landlock.h
@@ -10,6 +10,7 @@
 struct landlock_ruleset_attr {
   __u64 handled_access_fs;
   __u64 handled_access_net;
+  __u64 scoped;
 };
 #define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
 enum landlock_rule_type {
@@ -42,4 +43,6 @@ struct landlock_net_port_attr {
 #define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
 #define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
 #define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
+#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
+#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
 #endif
diff --git a/libc/kernel/uapi/linux/libc-compat.h b/libc/kernel/uapi/linux/libc-compat.h
index 289b7c506..0b5ba60c1 100644
--- a/libc/kernel/uapi/linux/libc-compat.h
+++ b/libc/kernel/uapi/linux/libc-compat.h
@@ -59,19 +59,6 @@
 #define __UAPI_DEF_IN6_PKTINFO 1
 #define __UAPI_DEF_IP6_MTUINFO 1
 #endif
-#ifdef __NETIPX_IPX_H
-#define __UAPI_DEF_SOCKADDR_IPX 0
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION 0
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION 0
-#define __UAPI_DEF_IPX_CONFIG_DATA 0
-#define __UAPI_DEF_IPX_ROUTE_DEF 0
-#else
-#define __UAPI_DEF_SOCKADDR_IPX 1
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION 1
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION 1
-#define __UAPI_DEF_IPX_CONFIG_DATA 1
-#define __UAPI_DEF_IPX_ROUTE_DEF 1
-#endif
 #ifdef _SYS_XATTR_H
 #define __UAPI_DEF_XATTR 0
 #else
@@ -138,21 +125,6 @@
 #ifndef __UAPI_DEF_IP6_MTUINFO
 #define __UAPI_DEF_IP6_MTUINFO 1
 #endif
-#ifndef __UAPI_DEF_SOCKADDR_IPX
-#define __UAPI_DEF_SOCKADDR_IPX 1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEFINITION
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION 1
-#endif
-#ifndef __UAPI_DEF_IPX_INTERFACE_DEFINITION
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION 1
-#endif
-#ifndef __UAPI_DEF_IPX_CONFIG_DATA
-#define __UAPI_DEF_IPX_CONFIG_DATA 1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEF
-#define __UAPI_DEF_IPX_ROUTE_DEF 1
-#endif
 #ifndef __UAPI_DEF_XATTR
 #define __UAPI_DEF_XATTR 1
 #endif
diff --git a/libc/kernel/uapi/linux/lsm.h b/libc/kernel/uapi/linux/lsm.h
index 3a3f15226..b12ca645e 100644
--- a/libc/kernel/uapi/linux/lsm.h
+++ b/libc/kernel/uapi/linux/lsm.h
@@ -30,6 +30,7 @@ struct lsm_ctx {
 #define LSM_ID_LANDLOCK 110
 #define LSM_ID_IMA 111
 #define LSM_ID_EVM 112
+#define LSM_ID_IPE 113
 #define LSM_ATTR_UNDEF 0
 #define LSM_ATTR_CURRENT 100
 #define LSM_ATTR_EXEC 101
diff --git a/libc/kernel/uapi/linux/mdio.h b/libc/kernel/uapi/linux/mdio.h
index 7b51b7384..7a4d4dbe2 100644
--- a/libc/kernel/uapi/linux/mdio.h
+++ b/libc/kernel/uapi/linux/mdio.h
@@ -15,6 +15,7 @@
 #define MDIO_MMD_DTEXS 5
 #define MDIO_MMD_TC 6
 #define MDIO_MMD_AN 7
+#define MDIO_MMD_POWER_UNIT 13
 #define MDIO_MMD_C22EXT 29
 #define MDIO_MMD_VEND1 30
 #define MDIO_MMD_VEND2 31
diff --git a/libc/kernel/uapi/linux/nbd.h b/libc/kernel/uapi/linux/nbd.h
index d47c28fc3..110220f33 100644
--- a/libc/kernel/uapi/linux/nbd.h
+++ b/libc/kernel/uapi/linux/nbd.h
@@ -23,15 +23,19 @@ enum {
   NBD_CMD_WRITE = 1,
   NBD_CMD_DISC = 2,
   NBD_CMD_FLUSH = 3,
-  NBD_CMD_TRIM = 4
+  NBD_CMD_TRIM = 4,
+  NBD_CMD_WRITE_ZEROES = 6,
 };
 #define NBD_FLAG_HAS_FLAGS (1 << 0)
 #define NBD_FLAG_READ_ONLY (1 << 1)
 #define NBD_FLAG_SEND_FLUSH (1 << 2)
 #define NBD_FLAG_SEND_FUA (1 << 3)
+#define NBD_FLAG_ROTATIONAL (1 << 4)
 #define NBD_FLAG_SEND_TRIM (1 << 5)
+#define NBD_FLAG_SEND_WRITE_ZEROES (1 << 6)
 #define NBD_FLAG_CAN_MULTI_CONN (1 << 8)
 #define NBD_CMD_FLAG_FUA (1 << 16)
+#define NBD_CMD_FLAG_NO_HOLE (1 << 17)
 #define NBD_CFLAG_DESTROY_ON_DISCONNECT (1 << 0)
 #define NBD_CFLAG_DISCONNECT_ON_CLOSE (1 << 1)
 #define NBD_REQUEST_MAGIC 0x25609513
diff --git a/libc/kernel/uapi/linux/net_tstamp.h b/libc/kernel/uapi/linux/net_tstamp.h
index 9bbd3090e..b0df34402 100644
--- a/libc/kernel/uapi/linux/net_tstamp.h
+++ b/libc/kernel/uapi/linux/net_tstamp.h
@@ -26,7 +26,8 @@ enum {
   SOF_TIMESTAMPING_OPT_TX_SWHW = (1 << 14),
   SOF_TIMESTAMPING_BIND_PHC = (1 << 15),
   SOF_TIMESTAMPING_OPT_ID_TCP = (1 << 16),
-  SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_ID_TCP,
+  SOF_TIMESTAMPING_OPT_RX_FILTER = (1 << 17),
+  SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_RX_FILTER,
   SOF_TIMESTAMPING_MASK = (SOF_TIMESTAMPING_LAST - 1) | SOF_TIMESTAMPING_LAST
 };
 #define SOF_TIMESTAMPING_TX_RECORD_MASK (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_SCHED | SOF_TIMESTAMPING_TX_ACK)
diff --git a/libc/kernel/uapi/linux/netdev.h b/libc/kernel/uapi/linux/netdev.h
index b0842970a..a7c570617 100644
--- a/libc/kernel/uapi/linux/netdev.h
+++ b/libc/kernel/uapi/linux/netdev.h
@@ -51,6 +51,7 @@ enum {
   NETDEV_A_PAGE_POOL_INFLIGHT,
   NETDEV_A_PAGE_POOL_INFLIGHT_MEM,
   NETDEV_A_PAGE_POOL_DETACH_TIME,
+  NETDEV_A_PAGE_POOL_DMABUF,
   __NETDEV_A_PAGE_POOL_MAX,
   NETDEV_A_PAGE_POOL_MAX = (__NETDEV_A_PAGE_POOL_MAX - 1)
 };
@@ -83,6 +84,7 @@ enum {
   NETDEV_A_QUEUE_IFINDEX,
   NETDEV_A_QUEUE_TYPE,
   NETDEV_A_QUEUE_NAPI_ID,
+  NETDEV_A_QUEUE_DMABUF,
   __NETDEV_A_QUEUE_MAX,
   NETDEV_A_QUEUE_MAX = (__NETDEV_A_QUEUE_MAX - 1)
 };
@@ -121,6 +123,14 @@ enum {
   __NETDEV_A_QSTATS_MAX,
   NETDEV_A_QSTATS_MAX = (__NETDEV_A_QSTATS_MAX - 1)
 };
+enum {
+  NETDEV_A_DMABUF_IFINDEX = 1,
+  NETDEV_A_DMABUF_QUEUES,
+  NETDEV_A_DMABUF_FD,
+  NETDEV_A_DMABUF_ID,
+  __NETDEV_A_DMABUF_MAX,
+  NETDEV_A_DMABUF_MAX = (__NETDEV_A_DMABUF_MAX - 1)
+};
 enum {
   NETDEV_CMD_DEV_GET = 1,
   NETDEV_CMD_DEV_ADD_NTF,
@@ -134,6 +144,7 @@ enum {
   NETDEV_CMD_QUEUE_GET,
   NETDEV_CMD_NAPI_GET,
   NETDEV_CMD_QSTATS_GET,
+  NETDEV_CMD_BIND_RX,
   __NETDEV_CMD_MAX,
   NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
 };
diff --git a/libc/kernel/uapi/linux/nexthop.h b/libc/kernel/uapi/linux/nexthop.h
index 5726a66d8..2443c182b 100644
--- a/libc/kernel/uapi/linux/nexthop.h
+++ b/libc/kernel/uapi/linux/nexthop.h
@@ -17,7 +17,7 @@ struct nhmsg {
 struct nexthop_grp {
   __u32 id;
   __u8 weight;
-  __u8 resvd1;
+  __u8 weight_high;
   __u16 resvd2;
 };
 enum {
@@ -28,6 +28,7 @@ enum {
 #define NEXTHOP_GRP_TYPE_MAX (__NEXTHOP_GRP_TYPE_MAX - 1)
 #define NHA_OP_FLAG_DUMP_STATS BIT(0)
 #define NHA_OP_FLAG_DUMP_HW_STATS BIT(1)
+#define NHA_OP_FLAG_RESP_GRP_RESVD_0 BIT(31)
 enum {
   NHA_UNSPEC,
   NHA_ID,
diff --git a/libc/kernel/uapi/linux/nsfs.h b/libc/kernel/uapi/linux/nsfs.h
index c8f22089d..870afe7c3 100644
--- a/libc/kernel/uapi/linux/nsfs.h
+++ b/libc/kernel/uapi/linux/nsfs.h
@@ -18,4 +18,13 @@
 #define NS_GET_TGID_FROM_PIDNS _IOR(NSIO, 0x7, int)
 #define NS_GET_PID_IN_PIDNS _IOR(NSIO, 0x8, int)
 #define NS_GET_TGID_IN_PIDNS _IOR(NSIO, 0x9, int)
+struct mnt_ns_info {
+  __u32 size;
+  __u32 nr_mounts;
+  __u64 mnt_ns_id;
+};
+#define MNT_NS_INFO_SIZE_VER0 16
+#define NS_MNT_GET_INFO _IOR(NSIO, 10, struct mnt_ns_info)
+#define NS_MNT_GET_NEXT _IOR(NSIO, 11, struct mnt_ns_info)
+#define NS_MNT_GET_PREV _IOR(NSIO, 12, struct mnt_ns_info)
 #endif
diff --git a/libc/kernel/uapi/linux/pci_regs.h b/libc/kernel/uapi/linux/pci_regs.h
index 703d398e5..708339173 100644
--- a/libc/kernel/uapi/linux/pci_regs.h
+++ b/libc/kernel/uapi/linux/pci_regs.h
@@ -531,9 +531,11 @@
 #define PCI_EXP_RTCTL_SENFEE 0x0002
 #define PCI_EXP_RTCTL_SEFEE 0x0004
 #define PCI_EXP_RTCTL_PMEIE 0x0008
-#define PCI_EXP_RTCTL_CRSSVE 0x0010
+#define PCI_EXP_RTCTL_RRS_SVE 0x0010
+#define PCI_EXP_RTCTL_CRSSVE PCI_EXP_RTCTL_RRS_SVE
 #define PCI_EXP_RTCAP 0x1e
-#define PCI_EXP_RTCAP_CRSVIS 0x0001
+#define PCI_EXP_RTCAP_RRS_SV 0x0001
+#define PCI_EXP_RTCAP_CRSVIS PCI_EXP_RTCAP_RRS_SV
 #define PCI_EXP_RTSTA 0x20
 #define PCI_EXP_RTSTA_PME_RQ_ID 0x0000ffff
 #define PCI_EXP_RTSTA_PME 0x00010000
@@ -626,6 +628,7 @@
 #define PCI_EXT_CAP_ID_DVSEC 0x23
 #define PCI_EXT_CAP_ID_DLF 0x25
 #define PCI_EXT_CAP_ID_PL_16GT 0x26
+#define PCI_EXT_CAP_ID_NPEM 0x29
 #define PCI_EXT_CAP_ID_PL_32GT 0x2A
 #define PCI_EXT_CAP_ID_DOE 0x2E
 #define PCI_EXT_CAP_ID_MAX PCI_EXT_CAP_ID_DOE
@@ -944,6 +947,31 @@
 #define PCI_PL_16GT_LE_CTRL_DSP_TX_PRESET_MASK 0x0000000F
 #define PCI_PL_16GT_LE_CTRL_USP_TX_PRESET_MASK 0x000000F0
 #define PCI_PL_16GT_LE_CTRL_USP_TX_PRESET_SHIFT 4
+#define PCI_NPEM_CAP 0x04
+#define PCI_NPEM_CAP_CAPABLE 0x00000001
+#define PCI_NPEM_CTRL 0x08
+#define PCI_NPEM_CTRL_ENABLE 0x00000001
+#define PCI_NPEM_CMD_RESET 0x00000002
+#define PCI_NPEM_IND_OK 0x00000004
+#define PCI_NPEM_IND_LOCATE 0x00000008
+#define PCI_NPEM_IND_FAIL 0x00000010
+#define PCI_NPEM_IND_REBUILD 0x00000020
+#define PCI_NPEM_IND_PFA 0x00000040
+#define PCI_NPEM_IND_HOTSPARE 0x00000080
+#define PCI_NPEM_IND_ICA 0x00000100
+#define PCI_NPEM_IND_IFA 0x00000200
+#define PCI_NPEM_IND_IDT 0x00000400
+#define PCI_NPEM_IND_DISABLED 0x00000800
+#define PCI_NPEM_IND_SPEC_0 0x01000000
+#define PCI_NPEM_IND_SPEC_1 0x02000000
+#define PCI_NPEM_IND_SPEC_2 0x04000000
+#define PCI_NPEM_IND_SPEC_3 0x08000000
+#define PCI_NPEM_IND_SPEC_4 0x10000000
+#define PCI_NPEM_IND_SPEC_5 0x20000000
+#define PCI_NPEM_IND_SPEC_6 0x40000000
+#define PCI_NPEM_IND_SPEC_7 0x80000000
+#define PCI_NPEM_STATUS 0x0c
+#define PCI_NPEM_STATUS_CC 0x00000001
 #define PCI_DOE_CAP 0x04
 #define PCI_DOE_CAP_INT_SUP 0x00000001
 #define PCI_DOE_CAP_INT_MSG_NUM 0x00000ffe
diff --git a/libc/kernel/uapi/linux/pkt_cls.h b/libc/kernel/uapi/linux/pkt_cls.h
index bdca5532c..c5d8d791a 100644
--- a/libc/kernel/uapi/linux/pkt_cls.h
+++ b/libc/kernel/uapi/linux/pkt_cls.h
@@ -179,7 +179,12 @@ struct tc_u32_key {
   int offmask;
 };
 struct tc_u32_sel {
-  unsigned char flags;
+  /**
+   ** ANDROID FIX: Comment out TAG value to avoid C++ error about using
+   ** a type declared in an anonymous union. This is being fixed upstream
+   ** and should be corrected by the next kernel import.
+   */
+  __struct_group(/*tc_u32_sel_hdr*/, hdr,, unsigned char flags;
   unsigned char offshift;
   unsigned char nkeys;
   __be16 offmask;
@@ -187,6 +192,7 @@ struct tc_u32_sel {
   short offoff;
   short hoff;
   __be32 hmask;
+ );
   struct tc_u32_key keys[];
 };
 struct tc_u32_mark {
diff --git a/libc/kernel/uapi/linux/ptp_clock.h b/libc/kernel/uapi/linux/ptp_clock.h
index 5014936c1..88c67864b 100644
--- a/libc/kernel/uapi/linux/ptp_clock.h
+++ b/libc/kernel/uapi/linux/ptp_clock.h
@@ -65,7 +65,8 @@ struct ptp_sys_offset {
 };
 struct ptp_sys_offset_extended {
   unsigned int n_samples;
-  unsigned int rsv[3];
+  __kernel_clockid_t clockid;
+  unsigned int rsv[2];
   struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
 };
 struct ptp_sys_offset_precise {
diff --git a/libc/kernel/uapi/linux/rkisp1-config.h b/libc/kernel/uapi/linux/rkisp1-config.h
index d4206a01f..d5cf92a6e 100644
--- a/libc/kernel/uapi/linux/rkisp1-config.h
+++ b/libc/kernel/uapi/linux/rkisp1-config.h
@@ -88,6 +88,7 @@
 #define RKISP1_CIF_ISP_DPCC_RND_OFFS_n_RB(n,v) ((v) << ((n) * 4 + 2))
 #define RKISP1_CIF_ISP_DPF_MAX_NLF_COEFFS 17
 #define RKISP1_CIF_ISP_DPF_MAX_SPATIAL_COEFFS 6
+#define RKISP1_CIF_ISP_COMPAND_NUM_POINTS 64
 #define RKISP1_CIF_ISP_STAT_AWB (1U << 0)
 #define RKISP1_CIF_ISP_STAT_AUTOEXP (1U << 1)
 #define RKISP1_CIF_ISP_STAT_AFM (1U << 2)
@@ -348,6 +349,17 @@ struct rkisp1_params_cfg {
   struct rkisp1_cif_isp_isp_meas_cfg meas;
   struct rkisp1_cif_isp_isp_other_cfg others;
 };
+struct rkisp1_cif_isp_compand_bls_config {
+  __u32 r;
+  __u32 gr;
+  __u32 gb;
+  __u32 b;
+};
+struct rkisp1_cif_isp_compand_curve_config {
+  __u8 px[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+  __u32 x[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+  __u32 y[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+};
 struct rkisp1_cif_isp_awb_meas {
   __u32 cnt;
   __u8 mean_y_or_g;
@@ -388,4 +400,118 @@ struct rkisp1_stat_buffer {
   __u32 frame_id;
   struct rkisp1_cif_isp_stat params;
 };
+enum rkisp1_ext_params_block_type {
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_SDG,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_GAIN,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_FLT,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_BDM,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_CTK,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_GOC,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF_STRENGTH,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_CPROC,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_IE,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_LSC,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_MEAS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_HST_MEAS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_AEC_MEAS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_AFC_MEAS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_BLS,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_EXPAND,
+  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_COMPRESS,
+};
+#define RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE (1U << 0)
+#define RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE (1U << 1)
+struct rkisp1_ext_params_block_header {
+  __u16 type;
+  __u16 flags;
+  __u32 size;
+};
+struct rkisp1_ext_params_bls_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_bls_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_dpcc_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_dpcc_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_sdg_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_sdg_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_lsc_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_lsc_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_awb_gain_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_awb_gain_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_flt_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_flt_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_bdm_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_bdm_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_ctk_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_ctk_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_goc_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_goc_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_dpf_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_dpf_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_dpf_strength_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_dpf_strength_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_cproc_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_cproc_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_ie_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_ie_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_awb_meas_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_awb_meas_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_hst_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_hst_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_aec_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_aec_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_afc_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_afc_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_compand_bls_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_compand_bls_config config;
+} __attribute__((aligned(8)));
+struct rkisp1_ext_params_compand_curve_config {
+  struct rkisp1_ext_params_block_header header;
+  struct rkisp1_cif_isp_compand_curve_config config;
+} __attribute__((aligned(8)));
+#define RKISP1_EXT_PARAMS_MAX_SIZE (sizeof(struct rkisp1_ext_params_bls_config) + sizeof(struct rkisp1_ext_params_dpcc_config) + sizeof(struct rkisp1_ext_params_sdg_config) + sizeof(struct rkisp1_ext_params_lsc_config) + sizeof(struct rkisp1_ext_params_awb_gain_config) + sizeof(struct rkisp1_ext_params_flt_config) + sizeof(struct rkisp1_ext_params_bdm_config) + sizeof(struct rkisp1_ext_params_ctk_config) + sizeof(struct rkisp1_ext_params_goc_config) + sizeof(struct rkisp1_ext_params_dpf_config) + sizeof(struct rkisp1_ext_params_dpf_strength_config) + sizeof(struct rkisp1_ext_params_cproc_config) + sizeof(struct rkisp1_ext_params_ie_config) + sizeof(struct rkisp1_ext_params_awb_meas_config) + sizeof(struct rkisp1_ext_params_hst_config) + sizeof(struct rkisp1_ext_params_aec_config) + sizeof(struct rkisp1_ext_params_afc_config) + sizeof(struct rkisp1_ext_params_compand_bls_config) + sizeof(struct rkisp1_ext_params_compand_curve_config) + sizeof(struct rkisp1_ext_params_compand_curve_config))
+enum rksip1_ext_param_buffer_version {
+  RKISP1_EXT_PARAM_BUFFER_V1 = 1,
+};
+struct rkisp1_ext_params_cfg {
+  __u32 version;
+  __u32 data_size;
+  __u8 data[RKISP1_EXT_PARAMS_MAX_SIZE];
+};
 #endif
diff --git a/libc/kernel/uapi/linux/sched.h b/libc/kernel/uapi/linux/sched.h
index ae914f7f1..eaeeee3f8 100644
--- a/libc/kernel/uapi/linux/sched.h
+++ b/libc/kernel/uapi/linux/sched.h
@@ -59,6 +59,7 @@ struct clone_args {
 #define SCHED_BATCH 3
 #define SCHED_IDLE 5
 #define SCHED_DEADLINE 6
+#define SCHED_EXT 7
 #define SCHED_RESET_ON_FORK 0x40000000
 #define SCHED_FLAG_RESET_ON_FORK 0x01
 #define SCHED_FLAG_RECLAIM 0x02
diff --git a/libc/kernel/uapi/linux/serio.h b/libc/kernel/uapi/linux/serio.h
index 424144e6f..0f0668f93 100644
--- a/libc/kernel/uapi/linux/serio.h
+++ b/libc/kernel/uapi/linux/serio.h
@@ -66,4 +66,5 @@
 #define SERIO_PULSE8_CEC 0x40
 #define SERIO_RAINSHADOW_CEC 0x41
 #define SERIO_FSIA6B 0x42
+#define SERIO_EXTRON_DA_HD_4K_PLUS 0x43
 #endif
diff --git a/libc/kernel/uapi/linux/smc.h b/libc/kernel/uapi/linux/smc.h
index 5e75fac0e..52a0da103 100644
--- a/libc/kernel/uapi/linux/smc.h
+++ b/libc/kernel/uapi/linux/smc.h
@@ -103,6 +103,8 @@ enum {
   SMC_NLA_LGR_R_NET_COOKIE,
   SMC_NLA_LGR_R_PAD,
   SMC_NLA_LGR_R_BUF_TYPE,
+  SMC_NLA_LGR_R_SNDBUF_ALLOC,
+  SMC_NLA_LGR_R_RMB_ALLOC,
   __SMC_NLA_LGR_R_MAX,
   SMC_NLA_LGR_R_MAX = __SMC_NLA_LGR_R_MAX - 1
 };
@@ -134,6 +136,8 @@ enum {
   SMC_NLA_LGR_D_V2_COMMON,
   SMC_NLA_LGR_D_EXT_GID,
   SMC_NLA_LGR_D_PEER_EXT_GID,
+  SMC_NLA_LGR_D_SNDBUF_ALLOC,
+  SMC_NLA_LGR_D_DMB_ALLOC,
   __SMC_NLA_LGR_D_MAX,
   SMC_NLA_LGR_D_MAX = __SMC_NLA_LGR_D_MAX - 1
 };
@@ -210,6 +214,8 @@ enum {
   SMC_NLA_STATS_T_TX_BYTES,
   SMC_NLA_STATS_T_RX_CNT,
   SMC_NLA_STATS_T_TX_CNT,
+  SMC_NLA_STATS_T_RX_RMB_USAGE,
+  SMC_NLA_STATS_T_TX_RMB_USAGE,
   __SMC_NLA_STATS_T_MAX,
   SMC_NLA_STATS_T_MAX = __SMC_NLA_STATS_T_MAX - 1
 };
diff --git a/libc/kernel/uapi/linux/spi/spi.h b/libc/kernel/uapi/linux/spi/spi.h
index 45c45cd26..d0ead4bcf 100644
--- a/libc/kernel/uapi/linux/spi/spi.h
+++ b/libc/kernel/uapi/linux/spi/spi.h
@@ -30,5 +30,6 @@
 #define SPI_3WIRE_HIZ _BITUL(15)
 #define SPI_RX_CPHA_FLIP _BITUL(16)
 #define SPI_MOSI_IDLE_LOW _BITUL(17)
-#define SPI_MODE_USER_MASK (_BITUL(18) - 1)
+#define SPI_MOSI_IDLE_HIGH _BITUL(18)
+#define SPI_MODE_USER_MASK (_BITUL(19) - 1)
 #endif
diff --git a/libc/kernel/uapi/linux/uio.h b/libc/kernel/uapi/linux/uio.h
index 70d6962e1..338430970 100644
--- a/libc/kernel/uapi/linux/uio.h
+++ b/libc/kernel/uapi/linux/uio.h
@@ -12,6 +12,17 @@ struct iovec {
   void  * iov_base;
   __kernel_size_t iov_len;
 };
+struct dmabuf_cmsg {
+  __u64 frag_offset;
+  __u32 frag_size;
+  __u32 frag_token;
+  __u32 dmabuf_id;
+  __u32 flags;
+};
+struct dmabuf_token {
+  __u32 token_start;
+  __u32 token_count;
+};
 #define UIO_FASTIOV 8
 #define UIO_MAXIOV 1024
 #endif
diff --git a/libc/kernel/uapi/linux/usb/ch9.h b/libc/kernel/uapi/linux/usb/ch9.h
index 676277385..c1121fbd8 100644
--- a/libc/kernel/uapi/linux/usb/ch9.h
+++ b/libc/kernel/uapi/linux/usb/ch9.h
@@ -119,6 +119,7 @@ struct usb_ctrlrequest {
 #define USB_DT_DEVICE_CAPABILITY 0x10
 #define USB_DT_WIRELESS_ENDPOINT_COMP 0x11
 #define USB_DT_WIRE_ADAPTER 0x21
+#define USB_DT_DFU_FUNCTIONAL 0x21
 #define USB_DT_RPIPE 0x22
 #define USB_DT_CS_RADIO_CONTROL 0x23
 #define USB_DT_PIPE_USAGE 0x24
@@ -170,6 +171,7 @@ struct usb_device_descriptor {
 #define USB_CLASS_USB_TYPE_C_BRIDGE 0x12
 #define USB_CLASS_MISC 0xef
 #define USB_CLASS_APP_SPEC 0xfe
+#define USB_SUBCLASS_DFU 0x01
 #define USB_CLASS_VENDOR_SPEC 0xff
 #define USB_SUBCLASS_VENDOR_SPEC 0xff
 struct usb_config_descriptor {
diff --git a/libc/kernel/uapi/linux/usb/functionfs.h b/libc/kernel/uapi/linux/usb/functionfs.h
index 095e937a6..e838363f1 100644
--- a/libc/kernel/uapi/linux/usb/functionfs.h
+++ b/libc/kernel/uapi/linux/usb/functionfs.h
@@ -6,6 +6,7 @@
  */
 #ifndef _UAPI__LINUX_FUNCTIONFS_H__
 #define _UAPI__LINUX_FUNCTIONFS_H__
+#include <linux/const.h>
 #include <linux/types.h>
 #include <linux/ioctl.h>
 #include <linux/usb/ch9.h>
@@ -32,6 +33,18 @@ struct usb_endpoint_descriptor_no_audio {
   __le16 wMaxPacketSize;
   __u8 bInterval;
 } __attribute__((packed));
+struct usb_dfu_functional_descriptor {
+  __u8 bLength;
+  __u8 bDescriptorType;
+  __u8 bmAttributes;
+  __le16 wDetachTimeOut;
+  __le16 wTransferSize;
+  __le16 bcdDFUVersion;
+} __attribute__((packed));
+#define DFU_FUNC_ATT_CAN_DOWNLOAD _BITUL(0)
+#define DFU_FUNC_ATT_CAN_UPLOAD _BITUL(1)
+#define DFU_FUNC_ATT_MANIFEST_TOLERANT _BITUL(2)
+#define DFU_FUNC_ATT_WILL_DETACH _BITUL(3)
 struct usb_functionfs_descs_head_v2 {
   __le32 magic;
   __le32 length;
diff --git a/libc/kernel/uapi/linux/usb/g_hid.h b/libc/kernel/uapi/linux/usb/g_hid.h
new file mode 100644
index 000000000..db5073895
--- /dev/null
+++ b/libc/kernel/uapi/linux/usb/g_hid.h
@@ -0,0 +1,20 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef __UAPI_LINUX_USB_G_HID_H
+#define __UAPI_LINUX_USB_G_HID_H
+#include <linux/types.h>
+#define MAX_REPORT_LENGTH 64
+struct usb_hidg_report {
+  __u8 report_id;
+  __u8 userspace_req;
+  __u16 length;
+  __u8 data[MAX_REPORT_LENGTH];
+  __u8 padding[4];
+};
+#define GADGET_HID_READ_GET_REPORT_ID _IOR('g', 0x41, __u8)
+#define GADGET_HID_WRITE_GET_REPORT _IOW('g', 0x42, struct usb_hidg_report)
+#endif
diff --git a/libc/kernel/uapi/linux/vbox_vmmdev_types.h b/libc/kernel/uapi/linux/vbox_vmmdev_types.h
index 7123c0284..cd0dcd919 100644
--- a/libc/kernel/uapi/linux/vbox_vmmdev_types.h
+++ b/libc/kernel/uapi/linux/vbox_vmmdev_types.h
@@ -177,6 +177,9 @@ struct vmmdev_hgcm_pagelist {
   __u32 flags;
   __u16 offset_first_page;
   __u16 page_count;
-  __u64 pages[1];
+  union {
+    __u64 unused;
+    __DECLARE_FLEX_ARRAY(__u64, pages);
+  };
 };
 #endif
diff --git a/libc/kernel/uapi/linux/vdpa.h b/libc/kernel/uapi/linux/vdpa.h
index 462d57947..a689f0d5d 100644
--- a/libc/kernel/uapi/linux/vdpa.h
+++ b/libc/kernel/uapi/linux/vdpa.h
@@ -17,6 +17,7 @@ enum vdpa_command {
   VDPA_CMD_DEV_GET,
   VDPA_CMD_DEV_CONFIG_GET,
   VDPA_CMD_DEV_VSTATS_GET,
+  VDPA_CMD_DEV_ATTR_SET,
 };
 enum vdpa_attr {
   VDPA_ATTR_UNSPEC,
diff --git a/libc/kernel/uapi/linux/version.h b/libc/kernel/uapi/linux/version.h
index 0cc45cfe9..728b80a77 100644
--- a/libc/kernel/uapi/linux/version.h
+++ b/libc/kernel/uapi/linux/version.h
@@ -4,8 +4,8 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#define LINUX_VERSION_CODE 396032
+#define LINUX_VERSION_CODE 396288
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 11
+#define LINUX_VERSION_PATCHLEVEL 12
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/libc/kernel/uapi/linux/videodev2.h b/libc/kernel/uapi/linux/videodev2.h
index fb69a8aab..e49f5ea90 100644
--- a/libc/kernel/uapi/linux/videodev2.h
+++ b/libc/kernel/uapi/linux/videodev2.h
@@ -173,6 +173,7 @@ struct v4l2_capability {
 #define V4L2_CAP_SDR_OUTPUT 0x00400000
 #define V4L2_CAP_META_CAPTURE 0x00800000
 #define V4L2_CAP_READWRITE 0x01000000
+#define V4L2_CAP_EDID 0x02000000
 #define V4L2_CAP_STREAMING 0x04000000
 #define V4L2_CAP_META_OUTPUT 0x08000000
 #define V4L2_CAP_TOUCH 0x10000000
@@ -456,6 +457,7 @@ struct v4l2_pix_format {
 #define V4L2_META_FMT_VIVID v4l2_fourcc('V', 'I', 'V', 'D')
 #define V4L2_META_FMT_RK_ISP1_PARAMS v4l2_fourcc('R', 'K', '1', 'P')
 #define V4L2_META_FMT_RK_ISP1_STAT_3A v4l2_fourcc('R', 'K', '1', 'S')
+#define V4L2_META_FMT_RK_ISP1_EXT_PARAMS v4l2_fourcc('R', 'K', '1', 'E')
 #define V4L2_META_FMT_RPI_BE_CFG v4l2_fourcc('R', 'P', 'B', 'C')
 #define V4L2_PIX_FMT_PRIV_MAGIC 0xfeedcafe
 #define V4L2_PIX_FMT_FLAG_PREMUL_ALPHA 0x00000001
diff --git a/libc/kernel/uapi/linux/virtio_balloon.h b/libc/kernel/uapi/linux/virtio_balloon.h
index f37c14897..3cf880721 100644
--- a/libc/kernel/uapi/linux/virtio_balloon.h
+++ b/libc/kernel/uapi/linux/virtio_balloon.h
@@ -38,8 +38,14 @@ struct virtio_balloon_config {
 #define VIRTIO_BALLOON_S_CACHES 7
 #define VIRTIO_BALLOON_S_HTLB_PGALLOC 8
 #define VIRTIO_BALLOON_S_HTLB_PGFAIL 9
-#define VIRTIO_BALLOON_S_NR 10
-#define VIRTIO_BALLOON_S_NAMES_WITH_PREFIX(VIRTIO_BALLOON_S_NAMES_prefix) { VIRTIO_BALLOON_S_NAMES_prefix "swap-in", VIRTIO_BALLOON_S_NAMES_prefix "swap-out", VIRTIO_BALLOON_S_NAMES_prefix "major-faults", VIRTIO_BALLOON_S_NAMES_prefix "minor-faults", VIRTIO_BALLOON_S_NAMES_prefix "free-memory", VIRTIO_BALLOON_S_NAMES_prefix "total-memory", VIRTIO_BALLOON_S_NAMES_prefix "available-memory", VIRTIO_BALLOON_S_NAMES_prefix "disk-caches", VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-allocations", VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-failures" \
+#define VIRTIO_BALLOON_S_OOM_KILL 10
+#define VIRTIO_BALLOON_S_ALLOC_STALL 11
+#define VIRTIO_BALLOON_S_ASYNC_SCAN 12
+#define VIRTIO_BALLOON_S_DIRECT_SCAN 13
+#define VIRTIO_BALLOON_S_ASYNC_RECLAIM 14
+#define VIRTIO_BALLOON_S_DIRECT_RECLAIM 15
+#define VIRTIO_BALLOON_S_NR 16
+#define VIRTIO_BALLOON_S_NAMES_WITH_PREFIX(VIRTIO_BALLOON_S_NAMES_prefix) { VIRTIO_BALLOON_S_NAMES_prefix "swap-in", VIRTIO_BALLOON_S_NAMES_prefix "swap-out", VIRTIO_BALLOON_S_NAMES_prefix "major-faults", VIRTIO_BALLOON_S_NAMES_prefix "minor-faults", VIRTIO_BALLOON_S_NAMES_prefix "free-memory", VIRTIO_BALLOON_S_NAMES_prefix "total-memory", VIRTIO_BALLOON_S_NAMES_prefix "available-memory", VIRTIO_BALLOON_S_NAMES_prefix "disk-caches", VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-allocations", VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-failures", VIRTIO_BALLOON_S_NAMES_prefix "oom-kills", VIRTIO_BALLOON_S_NAMES_prefix "alloc-stalls", VIRTIO_BALLOON_S_NAMES_prefix "async-scans", VIRTIO_BALLOON_S_NAMES_prefix "direct-scans", VIRTIO_BALLOON_S_NAMES_prefix "async-reclaims", VIRTIO_BALLOON_S_NAMES_prefix "direct-reclaims" \
 }
 #define VIRTIO_BALLOON_S_NAMES VIRTIO_BALLOON_S_NAMES_WITH_PREFIX("")
 struct virtio_balloon_stat {
diff --git a/libc/kernel/uapi/linux/virtio_gpu.h b/libc/kernel/uapi/linux/virtio_gpu.h
index c3f0fccfb..bf35cf7b8 100644
--- a/libc/kernel/uapi/linux/virtio_gpu.h
+++ b/libc/kernel/uapi/linux/virtio_gpu.h
@@ -195,6 +195,7 @@ struct virtio_gpu_cmd_submit {
 #define VIRTIO_GPU_CAPSET_VIRGL 1
 #define VIRTIO_GPU_CAPSET_VIRGL2 2
 #define VIRTIO_GPU_CAPSET_VENUS 4
+#define VIRTIO_GPU_CAPSET_DRM 6
 struct virtio_gpu_get_capset_info {
   struct virtio_gpu_ctrl_hdr hdr;
   __le32 capset_index;
diff --git a/libc/kernel/uapi/rdma/bnxt_re-abi.h b/libc/kernel/uapi/rdma/bnxt_re-abi.h
index 50f8b8a8c..38bfb1b98 100644
--- a/libc/kernel/uapi/rdma/bnxt_re-abi.h
+++ b/libc/kernel/uapi/rdma/bnxt_re-abi.h
@@ -27,6 +27,7 @@ enum bnxt_re_wqe_mode {
 };
 enum {
   BNXT_RE_COMP_MASK_REQ_UCNTX_POW2_SUPPORT = 0x01,
+  BNXT_RE_COMP_MASK_REQ_UCNTX_VAR_WQE_SUPPORT = 0x02,
 };
 struct bnxt_re_uctx_req {
   __aligned_u64 comp_mask;
@@ -66,10 +67,15 @@ struct bnxt_re_cq_resp {
 struct bnxt_re_resize_cq_req {
   __aligned_u64 cq_va;
 };
+enum bnxt_re_qp_mask {
+  BNXT_RE_QP_REQ_MASK_VAR_WQE_SQ_SLOTS = 0x1,
+};
 struct bnxt_re_qp_req {
   __aligned_u64 qpsva;
   __aligned_u64 qprva;
   __aligned_u64 qp_handle;
+  __aligned_u64 comp_mask;
+  __u32 sq_slots;
 };
 struct bnxt_re_qp_resp {
   __u32 qpid;
@@ -79,8 +85,13 @@ struct bnxt_re_srq_req {
   __aligned_u64 srqva;
   __aligned_u64 srq_handle;
 };
+enum bnxt_re_srq_mask {
+  BNXT_RE_SRQ_TOGGLE_PAGE_SUPPORT = 0x1,
+};
 struct bnxt_re_srq_resp {
   __u32 srqid;
+  __u32 rsvd;
+  __aligned_u64 comp_mask;
 };
 enum bnxt_re_shpg_offt {
   BNXT_RE_BEG_RESV_OFFT = 0x00,
diff --git a/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h b/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
index ebafb00fd..2e61c7168 100644
--- a/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
+++ b/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
@@ -204,6 +204,9 @@ enum mlx5_ib_device_query_context_attrs {
 enum mlx5_ib_create_cq_attrs {
   MLX5_IB_ATTR_CREATE_CQ_UAR_INDEX = UVERBS_ID_DRIVER_NS_WITH_UHW,
 };
+enum mlx5_ib_reg_dmabuf_mr_attrs {
+  MLX5_IB_ATTR_REG_DMABUF_MR_ACCESS_FLAGS = (1U << UVERBS_ID_NS_SHIFT),
+};
 #define MLX5_IB_DW_MATCH_PARAM 0xA0
 struct mlx5_ib_match_params {
   __u32 match_params[MLX5_IB_DW_MATCH_PARAM];
@@ -261,9 +264,13 @@ enum mlx5_ib_pd_methods {
 };
 enum mlx5_ib_device_methods {
   MLX5_IB_METHOD_QUERY_PORT = (1U << UVERBS_ID_NS_SHIFT),
+  MLX5_IB_METHOD_GET_DATA_DIRECT_SYSFS_PATH,
 };
 enum mlx5_ib_query_port_attrs {
   MLX5_IB_ATTR_QUERY_PORT_PORT_NUM = (1U << UVERBS_ID_NS_SHIFT),
   MLX5_IB_ATTR_QUERY_PORT,
 };
+enum mlx5_ib_get_data_direct_sysfs_path_attrs {
+  MLX5_IB_ATTR_GET_DATA_DIRECT_SYSFS_PATH = (1U << UVERBS_ID_NS_SHIFT),
+};
 #endif
diff --git a/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.h b/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.h
index f087ee81f..3fe3c82a6 100644
--- a/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.h
+++ b/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.h
@@ -23,6 +23,9 @@ enum mlx5_ib_uapi_flow_action_packet_reformat_type {
   MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2 = 0x2,
   MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL = 0x3,
 };
+enum mlx5_ib_uapi_reg_dmabuf_flags {
+  MLX5_IB_UAPI_REG_DMABUF_ACCESS_DATA_DIRECT = 1 << 0,
+};
 struct mlx5_ib_uapi_devx_async_cmd_hdr {
   __aligned_u64 wr_id;
   __u8 out_data[];
diff --git a/libc/kernel/uapi/rdma/rdma_netlink.h b/libc/kernel/uapi/rdma/rdma_netlink.h
index ac027ac76..137b68ff1 100644
--- a/libc/kernel/uapi/rdma/rdma_netlink.h
+++ b/libc/kernel/uapi/rdma/rdma_netlink.h
@@ -17,6 +17,7 @@ enum {
 enum {
   RDMA_NL_GROUP_IWPM = 2,
   RDMA_NL_GROUP_LS,
+  RDMA_NL_GROUP_NOTIFY,
   RDMA_NL_NUM_GROUPS
 };
 #define RDMA_NL_GET_CLIENT(type) ((type & (((1 << 6) - 1) << 10)) >> 10)
@@ -201,6 +202,7 @@ enum rdma_nldev_command {
   RDMA_NLDEV_CMD_RES_SRQ_GET_RAW,
   RDMA_NLDEV_CMD_NEWDEV,
   RDMA_NLDEV_CMD_DELDEV,
+  RDMA_NLDEV_CMD_MONITOR,
   RDMA_NLDEV_NUM_OPS
 };
 enum rdma_nldev_print_type {
@@ -311,6 +313,8 @@ enum rdma_nldev_attr {
   RDMA_NLDEV_ATTR_DEV_TYPE,
   RDMA_NLDEV_ATTR_PARENT_NAME,
   RDMA_NLDEV_ATTR_NAME_ASSIGN_TYPE,
+  RDMA_NLDEV_ATTR_EVENT_TYPE,
+  RDMA_NLDEV_SYS_ATTR_MONITOR_MODE,
   RDMA_NLDEV_ATTR_MAX
 };
 enum rdma_nl_counter_mode {
@@ -330,4 +334,10 @@ enum rdma_nl_name_assign_type {
   RDMA_NAME_ASSIGN_TYPE_UNKNOWN = 0,
   RDMA_NAME_ASSIGN_TYPE_USER = 1,
 };
+enum rdma_nl_notify_event_type {
+  RDMA_REGISTER_EVENT,
+  RDMA_UNREGISTER_EVENT,
+  RDMA_NETDEV_ATTACH_EVENT,
+  RDMA_NETDEV_DETACH_EVENT,
+};
 #endif
diff --git a/libc/kernel/uapi/sound/asequencer.h b/libc/kernel/uapi/sound/asequencer.h
index a3826a585..83b38f1c7 100644
--- a/libc/kernel/uapi/sound/asequencer.h
+++ b/libc/kernel/uapi/sound/asequencer.h
@@ -298,6 +298,7 @@ struct snd_seq_remove_events {
 #define SNDRV_SEQ_PORT_FLG_GIVEN_PORT (1 << 0)
 #define SNDRV_SEQ_PORT_FLG_TIMESTAMP (1 << 1)
 #define SNDRV_SEQ_PORT_FLG_TIME_REAL (1 << 2)
+#define SNDRV_SEQ_PORT_FLG_IS_MIDI1 (1 << 3)
 #define SNDRV_SEQ_PORT_DIR_UNKNOWN 0
 #define SNDRV_SEQ_PORT_DIR_INPUT 1
 #define SNDRV_SEQ_PORT_DIR_OUTPUT 2
diff --git a/libc/kernel/uapi/sound/asoc.h b/libc/kernel/uapi/sound/asoc.h
index f7992cb57..22e750d89 100644
--- a/libc/kernel/uapi/sound/asoc.h
+++ b/libc/kernel/uapi/sound/asoc.h
@@ -53,7 +53,7 @@
 #define SND_SOC_TPLG_MAGIC 0x41536F43
 #define SND_SOC_TPLG_NUM_TEXTS 16
 #define SND_SOC_TPLG_ABI_VERSION 0x5
-#define SND_SOC_TPLG_ABI_VERSION_MIN 0x4
+#define SND_SOC_TPLG_ABI_VERSION_MIN 0x5
 #define SND_SOC_TPLG_TLV_SIZE 32
 #define SND_SOC_TPLG_TYPE_MIXER 1
 #define SND_SOC_TPLG_TYPE_BYTES 2
diff --git a/libc/kernel/uapi/sound/asound.h b/libc/kernel/uapi/sound/asound.h
index cfe9f669a..cbebef367 100644
--- a/libc/kernel/uapi/sound/asound.h
+++ b/libc/kernel/uapi/sound/asound.h
@@ -676,7 +676,7 @@ struct snd_ump_block_info {
 #define SNDRV_RAWMIDI_IOCTL_DRAIN _IOW('W', 0x31, int)
 #define SNDRV_UMP_IOCTL_ENDPOINT_INFO _IOR('W', 0x40, struct snd_ump_endpoint_info)
 #define SNDRV_UMP_IOCTL_BLOCK_INFO _IOR('W', 0x41, struct snd_ump_block_info)
-#define SNDRV_TIMER_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 7)
+#define SNDRV_TIMER_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 8)
 enum {
   SNDRV_TIMER_CLASS_NONE = - 1,
   SNDRV_TIMER_CLASS_SLAVE = 0,
@@ -696,6 +696,7 @@ enum {
 #define SNDRV_TIMER_GLOBAL_RTC 1
 #define SNDRV_TIMER_GLOBAL_HPET 2
 #define SNDRV_TIMER_GLOBAL_HRTIMER 3
+#define SNDRV_TIMER_GLOBAL_UDRIVEN 4
 #define SNDRV_TIMER_FLG_SLAVE (1 << 0)
 struct snd_timer_id {
   int dev_class;
@@ -762,6 +763,12 @@ struct snd_timer_status {
   unsigned int queue;
   unsigned char reserved[64];
 };
+struct snd_timer_uinfo {
+  __u64 resolution;
+  int fd;
+  unsigned int id;
+  unsigned char reserved[16];
+};
 #define SNDRV_TIMER_IOCTL_PVERSION _IOR('T', 0x00, int)
 #define SNDRV_TIMER_IOCTL_NEXT_DEVICE _IOWR('T', 0x01, struct snd_timer_id)
 #define SNDRV_TIMER_IOCTL_TREAD_OLD _IOW('T', 0x02, int)
@@ -777,6 +784,8 @@ struct snd_timer_status {
 #define SNDRV_TIMER_IOCTL_CONTINUE _IO('T', 0xa2)
 #define SNDRV_TIMER_IOCTL_PAUSE _IO('T', 0xa3)
 #define SNDRV_TIMER_IOCTL_TREAD64 _IOW('T', 0xa4, int)
+#define SNDRV_TIMER_IOCTL_CREATE _IOWR('T', 0xa5, struct snd_timer_uinfo)
+#define SNDRV_TIMER_IOCTL_TRIGGER _IO('T', 0xa6)
 #if __BITS_PER_LONG == 64
 #define SNDRV_TIMER_IOCTL_TREAD SNDRV_TIMER_IOCTL_TREAD_OLD
 #else
diff --git a/libc/kernel/uapi/xen/privcmd.h b/libc/kernel/uapi/xen/privcmd.h
index 05972470b..0874e4bf2 100644
--- a/libc/kernel/uapi/xen/privcmd.h
+++ b/libc/kernel/uapi/xen/privcmd.h
@@ -77,6 +77,10 @@ struct privcmd_ioeventfd {
   domid_t dom;
   __u8 pad[2];
 };
+struct privcmd_pcidev_get_gsi {
+  __u32 sbdf;
+  __u32 gsi;
+};
 #define IOCTL_PRIVCMD_HYPERCALL _IOC(_IOC_NONE, 'P', 0, sizeof(struct privcmd_hypercall))
 #define IOCTL_PRIVCMD_MMAP _IOC(_IOC_NONE, 'P', 2, sizeof(struct privcmd_mmap))
 #define IOCTL_PRIVCMD_MMAPBATCH _IOC(_IOC_NONE, 'P', 3, sizeof(struct privcmd_mmapbatch))
@@ -86,4 +90,5 @@ struct privcmd_ioeventfd {
 #define IOCTL_PRIVCMD_MMAP_RESOURCE _IOC(_IOC_NONE, 'P', 7, sizeof(struct privcmd_mmap_resource))
 #define IOCTL_PRIVCMD_IRQFD _IOW('P', 8, struct privcmd_irqfd)
 #define IOCTL_PRIVCMD_IOEVENTFD _IOW('P', 9, struct privcmd_ioeventfd)
+#define IOCTL_PRIVCMD_PCIDEV_GET_GSI _IOC(_IOC_NONE, 'P', 10, sizeof(struct privcmd_pcidev_get_gsi))
 #endif
diff --git a/libc/libc.map.txt b/libc/libc.map.txt
index 86dcc3975..3e9f8505f 100644
--- a/libc/libc.map.txt
+++ b/libc/libc.map.txt
@@ -1619,6 +1619,12 @@ LIBC_36 { # introduced=36
     str2sig;
 } LIBC_V;
 
+LIBC_37 { # introduced=37
+  global:
+    sched_getattr;
+    sched_setattr;
+} LIBC_36;
+
 LIBC_PRIVATE {
   global:
     __accept4; # arm x86
diff --git a/libc/malloc_debug/Android.bp b/libc/malloc_debug/Android.bp
index 5d61801ff..50f24f6c7 100644
--- a/libc/malloc_debug/Android.bp
+++ b/libc/malloc_debug/Android.bp
@@ -135,6 +135,7 @@ cc_test {
         "tests/log_fake.cpp",
         "tests/libc_fake.cpp",
         "tests/malloc_debug_config_tests.cpp",
+        "tests/malloc_debug_record_data_tests.cpp",
         "tests/malloc_debug_unit_tests.cpp",
     ],
 
@@ -182,11 +183,6 @@ cc_test {
         "bionic_libc_platform_headers",
     ],
 
-    // The clang-analyzer-unix.Malloc and other warnings in these
-    // unit tests are either false positive or in
-    // negative tests that can be ignored.
-    tidy: false,
-
     srcs: [
         "tests/malloc_debug_system_tests.cpp",
     ],
diff --git a/libc/malloc_debug/README.md b/libc/malloc_debug/README.md
index 750a46907..badbc5a82 100644
--- a/libc/malloc_debug/README.md
+++ b/libc/malloc_debug/README.md
@@ -4,7 +4,7 @@ Malloc Debug
 Malloc debug is a method of debugging native memory problems. It can help
 detect memory corruption, memory leaks, and use after free issues.
 
-This documentation describes how to enable this feature on Android N or later
+This documentation describes how to enable this feature on API level 24 or later
 versions of the Android OS. (See the "Examples" section.)
 
 The documentation for malloc debug on older versions of Android is
@@ -215,7 +215,7 @@ As of U, add shorter aliases for backtrace related options to avoid property len
 | bt\_sz          | backtrace\_size               |
 
 ### check\_unreachable\_on\_signal
-As of Android U, this option will trigger a check for unreachable memory
+As of API level 34, this option will trigger a check for unreachable memory
 in a process. Specifically, if the signal SIGRTMAX - 16 (which is 48 on
 Android devices). The best way to see the exact signal being used is to
 enable the verbose option then look at the log for the message:
@@ -341,7 +341,7 @@ Example leak error found in the log:
     04-15 12:35:33.305  7412  7412 E malloc_debug:           #03  pc 000a28a8  /system/lib/libc++.so
 
 ### log\_allocator\_stats\_on\_signal
-As of Android V, this option will trigger a call to:
+As of API level 35, this option will trigger a call to:
 
     mallopt(M_LOG_STATS, 0);
 
@@ -497,13 +497,13 @@ log message.
 detected when the process is exiting.
 
 ### verbose
-As of Android Q, all info messages will be turned off by default. For example,
-in Android P and older, enabling malloc debug would result in this message
+As of API level 29, all info messages will be turned off by default. For example,
+in API level 28 and older, enabling malloc debug would result in this message
 in the log:
 
     08-16 15:54:16.060 26947 26947 I libc    : /system/bin/app_process64: malloc debug enabled
 
-In android Q, this message will not be displayed because these info messages
+In API level 29, this message will not be displayed because these info messages
 slow down process start up. However, if you want to re-enable these messages,
 add the verbose option. All of the "Run XXX" messages are also silenced unless
 the verbose option is specified. This is an example of the type
@@ -614,7 +614,7 @@ decode the frames in the backtraces.
 
 There are now multiple versions of the file:
 
-Android P produces version v1.1 of the heap dump.
+API level 28 produces version v1.1 of the heap dump.
 
     Android Native Heap Dump v1.1
 
@@ -624,7 +624,7 @@ NUM\_ALLOCATIONS to an incorrect value. For heap dump v1.0, the
 NUM\_ALLOCATIONS value should be treated as always 1 no matter what is
 actually present.
 
-Android Q introduces v1.2 of the heap dump. The new header looks like this:
+API level 29 introduces v1.2 of the heap dump. The new header looks like this:
 
     Android Native Heap Dump v1.2
 
@@ -711,7 +711,7 @@ Enable malloc debug using an environment variable (pre-O Android release):
     # export LIBC_DEBUG_MALLOC_ENABLE=1
     # ls
 
-Enable malloc debug using an environment variable (Android O or later):
+Enable malloc debug using an environment variable (API level 26 or later):
 
     adb shell
     # export LIBC_DEBUG_MALLOC_OPTIONS=backtrace
@@ -733,7 +733,7 @@ contain any data.
 
 App developers should check the NDK documentation about
 [wrap.sh](https://developer.android.com/ndk/guides/wrap-script.html)
-for the best way to use malloc debug in Android O or later on non-rooted
+for the best way to use malloc debug in API level 26 or later on non-rooted
 devices.
 
 **NOTE**: Android 12 introduced a bug that can cause the wrap.\<APP\> property to
@@ -744,7 +744,7 @@ no longer work. Use the commands below so that the wrap.\<APP\> instructions wil
     adb shell start
 
 If you do have a rooted device, you can enable malloc debug for a specific
-program/application (Android O or later):
+program/application (API level 26 or later):
 
     adb shell setprop wrap.<APP> '"LIBC_DEBUG_MALLOC_OPTIONS=backtrace logwrapper"'
 
@@ -753,7 +753,7 @@ them like so:
 
     adb shell setprop wrap.<APP> '"LIBC_DEBUG_MALLOC_OPTIONS=backtrace\ leak_track\ fill logwrapper"'
 
-For example, to enable malloc debug for the google search box (Android O or later):
+For example, to enable malloc debug for the google search box (API level 26 or later):
 
     adb shell setprop wrap.com.google.android.googlequicksearchbox '"LIBC_DEBUG_MALLOC_OPTIONS=backtrace logwrapper"'
     adb shell am force-stop com.google.android.googlequicksearchbox
diff --git a/libc/malloc_debug/RecordData.cpp b/libc/malloc_debug/RecordData.cpp
index 1641732cb..1df0b0c0a 100644
--- a/libc/malloc_debug/RecordData.cpp
+++ b/libc/malloc_debug/RecordData.cpp
@@ -38,7 +38,6 @@
 
 #include <mutex>
 
-#include <android-base/stringprintf.h>
 #include <memory_trace/MemoryTrace.h>
 
 #include "Config.h"
@@ -55,7 +54,7 @@ struct ThreadData {
   size_t count = 0;
 };
 
-static void ThreadKeyDelete(void* data) {
+void RecordData::ThreadKeyDelete(void* data) {
   ThreadData* thread_data = reinterpret_cast<ThreadData*>(data);
 
   thread_data->count++;
@@ -64,8 +63,11 @@ static void ThreadKeyDelete(void* data) {
   if (thread_data->count == 4) {
     ScopedDisableDebugCalls disable;
 
-    thread_data->record_data->AddEntryOnly(memory_trace::Entry{
-        .tid = gettid(), .type = memory_trace::THREAD_DONE, .end_ns = Nanotime()});
+    memory_trace::Entry* entry = thread_data->record_data->InternalReserveEntry();
+    if (entry != nullptr) {
+      *entry = memory_trace::Entry{
+          .tid = gettid(), .type = memory_trace::THREAD_DONE, .end_ns = Nanotime()};
+    }
     delete thread_data;
   } else {
     pthread_setspecific(thread_data->record_data->key(), data);
@@ -107,6 +109,11 @@ void RecordData::WriteEntries(const std::string& file) {
   }
 
   for (size_t i = 0; i < cur_index_; i++) {
+    if (entries_[i].type == memory_trace::UNKNOWN) {
+      // This can happen if an entry was reserved but not filled in due to some
+      // type of error during the operation.
+      continue;
+    }
     if (!memory_trace::WriteEntryToFd(dump_fd, entries_[i])) {
       error_log("Failed to write record alloc information: %s", strerror(errno));
       break;
@@ -142,32 +149,118 @@ bool RecordData::Initialize(const Config& config) {
   cur_index_ = 0U;
   file_ = config.record_allocs_file();
 
+  pagemap_fd_ = TEMP_FAILURE_RETRY(open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC));
+  if (pagemap_fd_ == -1) {
+    error_log("Unable to open /proc/self/pagemap: %s", strerror(errno));
+    return false;
+  }
+
   return true;
 }
 
 RecordData::~RecordData() {
+  if (pagemap_fd_ != -1) {
+    close(pagemap_fd_);
+  }
+
   pthread_key_delete(key_);
 }
 
-void RecordData::AddEntryOnly(const memory_trace::Entry& entry) {
+memory_trace::Entry* RecordData::InternalReserveEntry() {
   std::lock_guard<std::mutex> entries_lock(entries_lock_);
   if (cur_index_ == entries_.size()) {
-    // Maxed out, throw the entry away.
-    return;
+    return nullptr;
   }
 
-  entries_[cur_index_++] = entry;
-  if (cur_index_ == entries_.size()) {
+  memory_trace::Entry* entry = &entries_[cur_index_];
+  entry->type = memory_trace::UNKNOWN;
+  if (++cur_index_ == entries_.size()) {
     info_log("Maximum number of records added, all new operations will be dropped.");
   }
+  return entry;
 }
 
-void RecordData::AddEntry(const memory_trace::Entry& entry) {
+memory_trace::Entry* RecordData::ReserveEntry() {
   void* data = pthread_getspecific(key_);
   if (data == nullptr) {
     ThreadData* thread_data = new ThreadData(this);
     pthread_setspecific(key_, thread_data);
   }
 
-  AddEntryOnly(entry);
+  return InternalReserveEntry();
+}
+
+static inline bool IsPagePresent(uint64_t page_data) {
+  // Page Present is bit 63
+  return (page_data & (1ULL << 63)) != 0;
+}
+
+int64_t RecordData::GetPresentBytes(void* ptr, size_t alloc_size) {
+  uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
+  if (addr == 0 || alloc_size == 0) {
+    return -1;
+  }
+
+  uintptr_t page_size = getpagesize();
+  uintptr_t page_size_mask = page_size - 1;
+
+  size_t start_page = (addr & ~page_size_mask) / page_size;
+  size_t last_page = ((addr + alloc_size - 1) & ~page_size_mask) / page_size;
+
+  constexpr size_t kMaxReadPages = 1024;
+  uint64_t page_data[kMaxReadPages];
+
+  int64_t present_bytes = 0;
+  size_t cur_page = start_page;
+  while (cur_page <= last_page) {
+    size_t num_pages = last_page - cur_page + 1;
+    size_t last_page_index;
+    if (num_pages > kMaxReadPages) {
+      num_pages = kMaxReadPages;
+      last_page_index = num_pages;
+    } else {
+      // Handle the last page differently, so do not handle it in the loop.
+      last_page_index = num_pages - 1;
+    }
+    ssize_t bytes_read =
+        pread64(pagemap_fd_, page_data, num_pages * sizeof(uint64_t), cur_page * sizeof(uint64_t));
+    if (bytes_read <= 0) {
+      error_log("Failed to read page data: %s", strerror(errno));
+      return -1;
+    }
+
+    size_t page_index = 0;
+    // Handling the first page is special, handle it separately.
+    if (cur_page == start_page) {
+      if (IsPagePresent(page_data[0])) {
+        present_bytes = page_size - (addr & page_size_mask);
+        if (present_bytes >= alloc_size) {
+          // The allocation fits on a single page and that page is present.
+          return alloc_size;
+        }
+      } else if (start_page == last_page) {
+        // Only one page that isn't present.
+        return 0;
+      }
+      page_index = 1;
+    }
+
+    for (; page_index < last_page_index; page_index++) {
+      if (IsPagePresent(page_data[page_index])) {
+        present_bytes += page_size;
+      }
+    }
+
+    cur_page += last_page_index;
+
+    // Check the last page in the allocation.
+    if (cur_page == last_page) {
+      if (IsPagePresent(page_data[num_pages - 1])) {
+        present_bytes += ((addr + alloc_size - 1) & page_size_mask) + 1;
+      }
+      return present_bytes;
+    }
+  }
+
+  return present_bytes;
 }
diff --git a/libc/malloc_debug/RecordData.h b/libc/malloc_debug/RecordData.h
index f4b0d82ca..bf5cc571a 100644
--- a/libc/malloc_debug/RecordData.h
+++ b/libc/malloc_debug/RecordData.h
@@ -51,26 +51,32 @@ class RecordData {
 
   bool Initialize(const Config& config);
 
-  void AddEntry(const memory_trace::Entry& entry);
-  void AddEntryOnly(const memory_trace::Entry& entry);
+  memory_trace::Entry* ReserveEntry();
 
   const std::string& file() { return file_; }
   pthread_key_t key() { return key_; }
 
+  int64_t GetPresentBytes(void* pointer, size_t size);
+
   static void WriteEntriesOnExit();
 
  private:
   static void WriteData(int, siginfo_t*, void*);
   static RecordData* record_obj_;
 
+  static void ThreadKeyDelete(void* data);
+
   void WriteEntries();
   void WriteEntries(const std::string& file);
 
+  memory_trace::Entry* InternalReserveEntry();
+
   std::mutex entries_lock_;
   pthread_key_t key_;
   std::vector<memory_trace::Entry> entries_;
   size_t cur_index_;
   std::string file_;
+  int pagemap_fd_ = -1;
 
   BIONIC_DISALLOW_COPY_AND_ASSIGN(RecordData);
 };
diff --git a/libc/malloc_debug/malloc_debug.cpp b/libc/malloc_debug/malloc_debug.cpp
index c183897b7..7e961695f 100644
--- a/libc/malloc_debug/malloc_debug.cpp
+++ b/libc/malloc_debug/malloc_debug.cpp
@@ -590,16 +590,22 @@ void* debug_malloc(size_t size) {
   ScopedDisableDebugCalls disable;
   ScopedBacktraceSignalBlocker blocked;
 
+  memory_trace::Entry* entry = nullptr;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // In order to preserve the order of operations, reserve the entry before
+    // performing the operation.
+    entry = g_debug->record->ReserveEntry();
+  }
+
   TimedResult result = InternalMalloc(size);
 
-  if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(
-        memory_trace::Entry{.tid = gettid(),
-                            .type = memory_trace::MALLOC,
-                            .ptr = reinterpret_cast<uint64_t>(result.getValue<void*>()),
-                            .size = size,
-                            .start_ns = result.GetStartTimeNS(),
-                            .end_ns = result.GetEndTimeNS()});
+  if (entry != nullptr) {
+    *entry = memory_trace::Entry{.tid = gettid(),
+                                 .type = memory_trace::MALLOC,
+                                 .ptr = reinterpret_cast<uint64_t>(result.getValue<void*>()),
+                                 .size = size,
+                                 .start_ns = result.GetStartTimeNS(),
+                                 .end_ns = result.GetEndTimeNS()};
   }
 
   return result.getValue<void*>();
@@ -676,6 +682,13 @@ void debug_free(void* pointer) {
   if (DebugCallsDisabled() || pointer == nullptr) {
     return g_dispatch->free(pointer);
   }
+
+  size_t size;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // Need to get the size before disabling debug calls.
+    size = debug_malloc_usable_size(pointer);
+  }
+
   ScopedConcurrentLock lock;
   ScopedDisableDebugCalls disable;
   ScopedBacktraceSignalBlocker blocked;
@@ -684,14 +697,27 @@ void debug_free(void* pointer) {
     return;
   }
 
+  int64_t present_bytes = -1;
+  memory_trace::Entry* entry = nullptr;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // In order to preserve the order of operations, reserve the entry before
+    // performing the operation.
+    entry = g_debug->record->ReserveEntry();
+
+    // Need to get the present bytes before the pointer is freed in case the
+    // memory is released during the free call.
+    present_bytes = g_debug->record->GetPresentBytes(pointer, size);
+  }
+
   TimedResult result = InternalFree(pointer);
 
-  if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
-                                                  .type = memory_trace::FREE,
-                                                  .ptr = reinterpret_cast<uint64_t>(pointer),
-                                                  .start_ns = result.GetStartTimeNS(),
-                                                  .end_ns = result.GetEndTimeNS()});
+  if (entry != nullptr) {
+    *entry = memory_trace::Entry{.tid = gettid(),
+                                 .type = memory_trace::FREE,
+                                 .ptr = reinterpret_cast<uint64_t>(pointer),
+                                 .present_bytes = present_bytes,
+                                 .start_ns = result.GetStartTimeNS(),
+                                 .end_ns = result.GetEndTimeNS()};
   }
 }
 
@@ -714,6 +740,13 @@ void* debug_memalign(size_t alignment, size_t bytes) {
     return nullptr;
   }
 
+  memory_trace::Entry* entry = nullptr;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // In order to preserve the order of operations, reserve the entry before
+    // performing the operation.
+    entry = g_debug->record->ReserveEntry();
+  }
+
   TimedResult result;
   void* pointer;
   if (g_debug->HeaderEnabled()) {
@@ -761,27 +794,29 @@ void* debug_memalign(size_t alignment, size_t bytes) {
     pointer = result.getValue<void*>();
   }
 
-  if (pointer != nullptr) {
-    if (g_debug->TrackPointers()) {
-      PointerData::Add(pointer, bytes);
-    }
+  if (pointer == nullptr) {
+    return nullptr;
+  }
 
-    if (g_debug->config().options() & FILL_ON_ALLOC) {
-      size_t bytes = InternalMallocUsableSize(pointer);
-      size_t fill_bytes = g_debug->config().fill_on_alloc_bytes();
-      bytes = (bytes < fill_bytes) ? bytes : fill_bytes;
-      memset(pointer, g_debug->config().fill_alloc_value(), bytes);
-    }
+  if (g_debug->TrackPointers()) {
+    PointerData::Add(pointer, bytes);
+  }
 
-    if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
-                                                    .type = memory_trace::MEMALIGN,
-                                                    .ptr = reinterpret_cast<uint64_t>(pointer),
-                                                    .size = bytes,
-                                                    .u.align = alignment,
-                                                    .start_ns = result.GetStartTimeNS(),
-                                                    .end_ns = result.GetEndTimeNS()});
-    }
+  if (g_debug->config().options() & FILL_ON_ALLOC) {
+    size_t bytes = InternalMallocUsableSize(pointer);
+    size_t fill_bytes = g_debug->config().fill_on_alloc_bytes();
+    bytes = (bytes < fill_bytes) ? bytes : fill_bytes;
+    memset(pointer, g_debug->config().fill_alloc_value(), bytes);
+  }
+
+  if (entry != nullptr) {
+    *entry = memory_trace::Entry{.tid = gettid(),
+                                 .type = memory_trace::MEMALIGN,
+                                 .ptr = reinterpret_cast<uint64_t>(pointer),
+                                 .size = bytes,
+                                 .u.align = alignment,
+                                 .start_ns = result.GetStartTimeNS(),
+                                 .end_ns = result.GetEndTimeNS()};
   }
 
   return pointer;
@@ -793,21 +828,35 @@ void* debug_realloc(void* pointer, size_t bytes) {
   if (DebugCallsDisabled()) {
     return g_dispatch->realloc(pointer, bytes);
   }
+
+  size_t old_size;
+  if (pointer != nullptr && g_debug->config().options() & RECORD_ALLOCS) {
+    // Need to get the size before disabling debug calls.
+    old_size = debug_malloc_usable_size(pointer);
+  }
+
   ScopedConcurrentLock lock;
   ScopedDisableDebugCalls disable;
   ScopedBacktraceSignalBlocker blocked;
 
+  memory_trace::Entry* entry = nullptr;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // In order to preserve the order of operations, reserve the entry before
+    // performing the operation.
+    entry = g_debug->record->ReserveEntry();
+  }
+
   if (pointer == nullptr) {
     TimedResult result = InternalMalloc(bytes);
     pointer = result.getValue<void*>();
-    if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
-                                                    .type = memory_trace::REALLOC,
-                                                    .ptr = reinterpret_cast<uint64_t>(pointer),
-                                                    .size = bytes,
-                                                    .u.old_ptr = 0,
-                                                    .start_ns = result.GetStartTimeNS(),
-                                                    .end_ns = result.GetEndTimeNS()});
+    if (entry != nullptr) {
+      *entry = memory_trace::Entry{.tid = gettid(),
+                                   .type = memory_trace::REALLOC,
+                                   .ptr = reinterpret_cast<uint64_t>(pointer),
+                                   .size = bytes,
+                                   .u.old_ptr = 0,
+                                   .start_ns = result.GetStartTimeNS(),
+                                   .end_ns = result.GetEndTimeNS()};
     }
     return pointer;
   }
@@ -816,18 +865,25 @@ void* debug_realloc(void* pointer, size_t bytes) {
     return nullptr;
   }
 
+  int64_t present_bytes = -1;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // Need to get the present bytes before the pointer is freed in case the
+    // memory is released during the free call.
+    present_bytes = g_debug->record->GetPresentBytes(pointer, old_size);
+  }
+
   if (bytes == 0) {
     TimedResult result = InternalFree(pointer);
 
-    if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(
-          memory_trace::Entry{.tid = gettid(),
-                              .type = memory_trace::REALLOC,
-                              .ptr = 0,
-                              .size = 0,
-                              .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
-                              .start_ns = result.GetStartTimeNS(),
-                              .end_ns = result.GetEndTimeNS()});
+    if (entry != nullptr) {
+      *entry = memory_trace::Entry{.tid = gettid(),
+                                   .type = memory_trace::REALLOC,
+                                   .ptr = 0,
+                                   .size = 0,
+                                   .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
+                                   .present_bytes = present_bytes,
+                                   .start_ns = result.GetStartTimeNS(),
+                                   .end_ns = result.GetEndTimeNS()};
     }
 
     return nullptr;
@@ -923,14 +979,15 @@ void* debug_realloc(void* pointer, size_t bytes) {
     }
   }
 
-  if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
-                                                  .type = memory_trace::REALLOC,
-                                                  .ptr = reinterpret_cast<uint64_t>(new_pointer),
-                                                  .size = bytes,
-                                                  .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
-                                                  .start_ns = result.GetStartTimeNS(),
-                                                  .end_ns = result.GetEndTimeNS()});
+  if (entry != nullptr) {
+    *entry = memory_trace::Entry{.tid = gettid(),
+                                 .type = memory_trace::REALLOC,
+                                 .ptr = reinterpret_cast<uint64_t>(new_pointer),
+                                 .size = bytes,
+                                 .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
+                                 .present_bytes = present_bytes,
+                                 .start_ns = result.GetStartTimeNS(),
+                                 .end_ns = result.GetEndTimeNS()};
   }
 
   return new_pointer;
@@ -969,6 +1026,13 @@ void* debug_calloc(size_t nmemb, size_t bytes) {
     return nullptr;
   }
 
+  memory_trace::Entry* entry = nullptr;
+  if (g_debug->config().options() & RECORD_ALLOCS) {
+    // In order to preserve the order of operations, reserve the entry before
+    // performing the operation.
+    entry = g_debug->record->ReserveEntry();
+  }
+
   void* pointer;
   TimedResult result;
   if (g_debug->HeaderEnabled()) {
@@ -985,14 +1049,14 @@ void* debug_calloc(size_t nmemb, size_t bytes) {
     pointer = result.getValue<void*>();
   }
 
-  if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
-                                                  .type = memory_trace::CALLOC,
-                                                  .ptr = reinterpret_cast<uint64_t>(pointer),
-                                                  .size = bytes,
-                                                  .u.n_elements = nmemb,
-                                                  .start_ns = result.GetStartTimeNS(),
-                                                  .end_ns = result.GetEndTimeNS()});
+  if (entry != nullptr) {
+    *entry = memory_trace::Entry{.tid = gettid(),
+                                 .type = memory_trace::CALLOC,
+                                 .ptr = reinterpret_cast<uint64_t>(pointer),
+                                 .size = bytes,
+                                 .u.n_elements = nmemb,
+                                 .start_ns = result.GetStartTimeNS(),
+                                 .end_ns = result.GetEndTimeNS()};
   }
 
   if (pointer != nullptr && g_debug->TrackPointers()) {
@@ -1091,18 +1155,20 @@ int debug_malloc_iterate(uintptr_t base, size_t size, void (*callback)(uintptr_t
 
 void debug_malloc_disable() {
   ScopedConcurrentLock lock;
-  g_dispatch->malloc_disable();
   if (g_debug->pointer) {
+    // Acquire the pointer locks first, otherwise, the code can be holding
+    // the allocation lock and deadlock trying to acquire a pointer lock.
     g_debug->pointer->PrepareFork();
   }
+  g_dispatch->malloc_disable();
 }
 
 void debug_malloc_enable() {
   ScopedConcurrentLock lock;
+  g_dispatch->malloc_enable();
   if (g_debug->pointer) {
     g_debug->pointer->PostForkParent();
   }
-  g_dispatch->malloc_enable();
 }
 
 ssize_t debug_malloc_backtrace(void* pointer, uintptr_t* frames, size_t max_frames) {
diff --git a/libc/malloc_debug/tests/malloc_debug_record_data_tests.cpp b/libc/malloc_debug/tests/malloc_debug_record_data_tests.cpp
new file mode 100644
index 000000000..b94dc8f73
--- /dev/null
+++ b/libc/malloc_debug/tests/malloc_debug_record_data_tests.cpp
@@ -0,0 +1,121 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <stdlib.h>
+#include <sys/mman.h>
+#include <unistd.h>
+
+#include <gtest/gtest.h>
+
+#include "Config.h"
+#include "RecordData.h"
+
+#include "log_fake.h"
+
+class MallocDebugRecordDataTest : public ::testing::Test {
+ protected:
+  void SetUp() override {
+    page_size_ = getpagesize();
+    Config config;
+    ASSERT_TRUE(config.Init("record_allocs"));
+    ASSERT_TRUE(record_.Initialize(config));
+  }
+
+  uint8_t* AllocPageAligned(size_t alloc_pages) {
+    uint8_t* ptr = reinterpret_cast<uint8_t*>(memalign(page_size_, alloc_pages * page_size_));
+    if (ptr == nullptr) {
+      return nullptr;
+    }
+    // Release all the pages so the test can make them present.
+    EXPECT_EQ(0, madvise(ptr, page_size_ * alloc_pages, MADV_DONTNEED));
+    return ptr;
+  }
+
+  size_t page_size_;
+  RecordData record_;
+};
+
+TEST_F(MallocDebugRecordDataTest, get_present_bytes_error) {
+  EXPECT_EQ(-1, record_.GetPresentBytes(nullptr, 1000));
+  EXPECT_EQ(-1, record_.GetPresentBytes(reinterpret_cast<void*>(1000), 0));
+}
+
+TEST_F(MallocDebugRecordDataTest, get_present_bytes_edge_cases) {
+  // Need two pages to check allocations crossing over the page.
+  size_t alloc_pages = 2;
+  uint8_t* ptr = AllocPageAligned(alloc_pages);
+  ASSERT_TRUE(ptr != nullptr);
+  memset(ptr, 1, alloc_pages * page_size_);
+
+  EXPECT_EQ(20, record_.GetPresentBytes(ptr, 20));
+  EXPECT_EQ(page_size_ + 20, record_.GetPresentBytes(ptr, page_size_ + 20));
+  EXPECT_EQ(17, record_.GetPresentBytes(&ptr[page_size_ - 20], 17));
+  EXPECT_EQ(32, record_.GetPresentBytes(&ptr[page_size_ - 16], 32));
+  EXPECT_EQ(page_size_, record_.GetPresentBytes(ptr, page_size_));
+  EXPECT_EQ(page_size_ * 2, record_.GetPresentBytes(ptr, page_size_ * 2));
+}
+
+TEST_F(MallocDebugRecordDataTest, get_present_bytes_first_page_not_present) {
+  uint8_t* ptr = AllocPageAligned(2);
+  ASSERT_TRUE(ptr != nullptr);
+  ptr[page_size_] = 1;
+
+  EXPECT_EQ(0, record_.GetPresentBytes(ptr, page_size_));
+  EXPECT_EQ(3996, record_.GetPresentBytes(&ptr[100], page_size_ * 2 - 200));
+}
+
+TEST_F(MallocDebugRecordDataTest, get_present_bytes_last_page_not_present) {
+  uint8_t* ptr = AllocPageAligned(2);
+  ASSERT_TRUE(ptr != nullptr);
+  ptr[0] = 1;
+
+  EXPECT_EQ(3596, record_.GetPresentBytes(&ptr[500], page_size_ * 2 - 600));
+}
+
+TEST_F(MallocDebugRecordDataTest, get_present_bytes_large) {
+  // Needs to match the kMaxReadPages from GetPresentBytes
+  constexpr size_t kMaxReadPages = 1024;
+  // Allocate large enough that it requires at least two preads.
+  size_t alloc_pages = 2 * kMaxReadPages;
+  uint8_t* ptr = AllocPageAligned(alloc_pages);
+  ASSERT_TRUE(ptr != nullptr);
+  // Make sure that there are different number of pages present in the first
+  // read than in the second read.
+  ptr[0] = 1;
+  ptr[page_size_] = 1;
+  ptr[page_size_ * 4] = 1;
+  // Should be in the second read.
+  size_t start = kMaxReadPages * page_size_;
+  ptr[start + page_size_ * 2] = 1;
+  ptr[start + page_size_ * 4] = 1;
+  ptr[start + page_size_ * 8] = 1;
+  ptr[start + page_size_ * 9] = 1;
+
+  EXPECT_EQ(page_size_ * 7, record_.GetPresentBytes(ptr, alloc_pages * page_size_));
+
+  // Make the entire allocation resident for the next few tests.
+  for (size_t i = 0; i < alloc_pages; i++) {
+    ptr[i * page_size_] = 1;
+  }
+
+  EXPECT_EQ(page_size_ * kMaxReadPages, record_.GetPresentBytes(ptr, page_size_ * kMaxReadPages));
+  EXPECT_EQ(page_size_ * (kMaxReadPages + 1),
+            record_.GetPresentBytes(ptr, page_size_ * (kMaxReadPages + 1)));
+  EXPECT_EQ(page_size_ * kMaxReadPages - 50,
+            record_.GetPresentBytes(ptr, page_size_ * kMaxReadPages - 50));
+  EXPECT_EQ(page_size_ * (kMaxReadPages + 1) - 50,
+            record_.GetPresentBytes(ptr, page_size_ * (kMaxReadPages + 1) - 50));
+}
diff --git a/libc/malloc_debug/tests/malloc_debug_system_tests.cpp b/libc/malloc_debug/tests/malloc_debug_system_tests.cpp
index d7a7a4f12..080242c0b 100644
--- a/libc/malloc_debug/tests/malloc_debug_system_tests.cpp
+++ b/libc/malloc_debug/tests/malloc_debug_system_tests.cpp
@@ -57,6 +57,12 @@
 #include <bionic/malloc.h>
 #include <tests/utils.h>
 
+// exported from bionic
+__BEGIN_DECLS
+extern void malloc_disable();
+extern void malloc_enable();
+__END_DECLS
+
 // All DISABLED_ tests are designed to be executed after malloc debug
 // is enabled. These tests don't run be default, and are executed
 // by wrappers that will enable various malloc debug features.
@@ -788,3 +794,34 @@ TEST_F(MallocDebugSystemTest, malloc_and_backtrace_deadlock) {
   unexpected_log_strings_.push_back("Timed out waiting for ");
   Exec("MallocTests.DISABLED_malloc_and_backtrace_deadlock", "verbose verify_pointers", 0);
 }
+
+// Creates two threads: one that calls malloc_disable() and malloc_enable() in a loop and
+// the other that performs a bunch of allocations.
+TEST(MallocTests, DISABLED_malloc_disable_deadlock) {
+  std::atomic_bool running(true);
+
+  std::thread t1([&] {
+    while (running) {
+      malloc_disable();
+      malloc_enable();
+    }
+  });
+
+  std::thread t2([&] {
+    while (running) {
+      void* p = malloc(100);
+      free(p);
+    }
+  });
+
+  // let the threads run for a while, then tell them to stop and wait for shutdown
+  std::this_thread::sleep_for(std::chrono::seconds(5));
+
+  running = false;
+  t1.join();
+  t2.join();
+}
+
+TEST_F(MallocDebugSystemTest, malloc_disable_deadlock) {
+  Exec("MallocTests.DISABLED_malloc_disable_deadlock", "verbose backtrace");
+}
diff --git a/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp b/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
index c808dc089..79f946ff3 100644
--- a/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
+++ b/libc/malloc_debug/tests/malloc_debug_unit_tests.cpp
@@ -45,6 +45,7 @@
 #include <platform/bionic/macros.h>
 #include <private/bionic_malloc_dispatch.h>
 
+#include <memory_trace/MemoryTrace.h>
 #include <unwindstack/Unwinder.h>
 
 #include "Config.h"
@@ -202,6 +203,44 @@ static void VerifyRecords(std::vector<std::string>& expected, std::string& actua
   }
 }
 
+static void VerifyRecordEntries(const std::vector<memory_trace::Entry>& expected,
+                                std::string& actual) {
+  ASSERT_TRUE(expected.size() != 0);
+  // Convert the text to entries.
+  std::vector<memory_trace::Entry> actual_entries;
+  for (const auto& line : android::base::Split(actual, "\n")) {
+    if (line.empty()) {
+      continue;
+    }
+    memory_trace::Entry entry;
+    std::string error;
+    ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+    actual_entries.emplace_back(entry);
+  }
+  auto expected_iter = expected.begin();
+  for (const auto& actual_entry : actual_entries) {
+    if (actual_entry.type == memory_trace::THREAD_DONE) {
+      // Skip thread done entries.
+      continue;
+    }
+    ASSERT_NE(expected_iter, expected.end())
+        << "Found extra entry " << memory_trace::CreateStringFromEntry(*expected_iter);
+    SCOPED_TRACE(testing::Message()
+                 << "\nExpected entry:\n  " << memory_trace::CreateStringFromEntry(*expected_iter)
+                 << "\nActual entry:\n  " << memory_trace::CreateStringFromEntry(actual_entry));
+    EXPECT_EQ(actual_entry.type, expected_iter->type);
+    EXPECT_EQ(actual_entry.ptr, expected_iter->ptr);
+    EXPECT_EQ(actual_entry.size, expected_iter->size);
+    EXPECT_EQ(actual_entry.u.old_ptr, expected_iter->u.old_ptr);
+    EXPECT_EQ(actual_entry.present_bytes, expected_iter->present_bytes);
+    // Verify the timestamps are non-zero.
+    EXPECT_NE(actual_entry.start_ns, 0U);
+    EXPECT_NE(actual_entry.end_ns, 0U);
+    ++expected_iter;
+  }
+  EXPECT_TRUE(expected_iter == expected.end()) << "Not all expected entries found.";
+}
+
 void VerifyAllocCalls(bool all_options) {
   size_t alloc_size = 1024;
 
@@ -2457,6 +2496,114 @@ TEST_F(MallocDebugTest, record_allocs_on_exit) {
   ASSERT_STREQ("", getFakeLogPrint().c_str());
 }
 
+TEST_F(MallocDebugTest, record_allocs_present_bytes_check) {
+  InitRecordAllocs("record_allocs record_allocs_on_exit");
+
+  // The filename created on exit always appends the pid.
+  // Modify the variable so the file is deleted at the end of the test.
+  record_filename += '.' + std::to_string(getpid());
+
+  std::vector<memory_trace::Entry> expected;
+  void* ptr = debug_malloc(100);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 100});
+
+  // Make the entire allocation present.
+  memset(ptr, 1, 100);
+
+  int64_t real_size = debug_malloc_usable_size(ptr);
+  debug_free(ptr);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::FREE,
+                                         .ptr = reinterpret_cast<uint64_t>(ptr),
+                                         .present_bytes = real_size});
+
+  ptr = debug_malloc(4096);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 4096});
+
+  memset(ptr, 1, 4096);
+  real_size = debug_malloc_usable_size(ptr);
+  void* new_ptr = debug_realloc(ptr, 8192);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
+                                         .ptr = reinterpret_cast<uint64_t>(new_ptr),
+                                         .size = 8192,
+                                         .u.old_ptr = reinterpret_cast<uint64_t>(ptr),
+                                         .present_bytes = real_size});
+
+  memset(new_ptr, 1, 8192);
+  real_size = debug_malloc_usable_size(new_ptr);
+  debug_free(new_ptr);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::FREE,
+                                         .ptr = reinterpret_cast<uint64_t>(new_ptr),
+                                         .present_bytes = real_size});
+
+  ptr = debug_malloc(4096);
+  expected.push_back(memory_trace::Entry{
+      .type = memory_trace::MALLOC, .ptr = reinterpret_cast<uint64_t>(ptr), .size = 4096});
+  memset(ptr, 1, 4096);
+
+  // Verify a free realloc does update the present bytes.
+  real_size = debug_malloc_usable_size(ptr);
+  EXPECT_TRUE(debug_realloc(ptr, 0) == nullptr);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::REALLOC,
+                                         .ptr = 0,
+                                         .u.old_ptr = reinterpret_cast<uint64_t>(ptr),
+                                         .present_bytes = real_size});
+
+  // Call the exit function manually.
+  debug_finalize();
+
+  // Read all of the contents.
+  std::string actual;
+  ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
+  VerifyRecordEntries(expected, actual);
+
+  ASSERT_STREQ("", getFakeLogBuf().c_str());
+  ASSERT_STREQ("", getFakeLogPrint().c_str());
+}
+
+TEST_F(MallocDebugTest, record_allocs_not_all_bytes_present) {
+  InitRecordAllocs("record_allocs record_allocs_on_exit");
+
+  // The filename created on exit always appends the pid.
+  // Modify the variable so the file is deleted at the end of the test.
+  record_filename += '.' + std::to_string(getpid());
+
+  std::vector<memory_trace::Entry> expected;
+  size_t pagesize = getpagesize();
+  void* ptr = debug_memalign(pagesize, pagesize * 8);
+  ASSERT_TRUE(ptr != nullptr);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::MEMALIGN,
+                                         .ptr = reinterpret_cast<uint64_t>(ptr),
+                                         .size = pagesize * 8,
+                                         .u.align = pagesize});
+
+  // Mark only some pages in use.
+  uint8_t* data = reinterpret_cast<uint8_t*>(ptr);
+  // Make sure the memory is not in use.
+  ASSERT_EQ(0, madvise(ptr, pagesize * 8, MADV_DONTNEED));
+  // Dirty three non-consecutive pages.
+  data[0] = 1;
+  data[pagesize * 2] = 1;
+  data[pagesize * 4] = 1;
+
+  debug_free(ptr);
+  expected.push_back(memory_trace::Entry{.type = memory_trace::FREE,
+                                         .ptr = reinterpret_cast<uint64_t>(ptr),
+                                         .present_bytes = static_cast<int64_t>(pagesize) * 3});
+
+  // Call the exit function manually.
+  debug_finalize();
+
+  // Read all of the contents.
+  std::string actual;
+  ASSERT_TRUE(android::base::ReadFileToString(record_filename, &actual));
+  VerifyRecordEntries(expected, actual);
+
+  ASSERT_STREQ("", getFakeLogBuf().c_str());
+  ASSERT_STREQ("", getFakeLogPrint().c_str());
+}
+
 TEST_F(MallocDebugTest, verify_pointers) {
   Init("verify_pointers");
 
diff --git a/libc/malloc_hooks/Android.bp b/libc/malloc_hooks/Android.bp
index 3f0640b30..06e91c656 100644
--- a/libc/malloc_hooks/Android.bp
+++ b/libc/malloc_hooks/Android.bp
@@ -60,11 +60,6 @@ cc_test {
     name: "malloc_hooks_system_tests",
     isolated: true,
 
-    // The clang-analyzer-unix.Malloc and other warnings in these
-    // unit tests are either false positive or in
-    // negative tests that can be ignored.
-    tidy: false,
-
     srcs: [
         "tests/malloc_hooks_tests.cpp",
     ],
diff --git a/libc/malloc_hooks/README.md b/libc/malloc_hooks/README.md
index 1747e8d41..97ae9ce8f 100644
--- a/libc/malloc_hooks/README.md
+++ b/libc/malloc_hooks/README.md
@@ -2,7 +2,7 @@ Malloc Hooks
 ============
 
 Malloc hooks allows a program to intercept all allocation/free calls that
-happen during execution. It is only available in Android P and newer versions
+happen during execution. It is only available in API level 28 and newer versions
 of the OS.
 
 There are two ways to enable these hooks, set a special system
diff --git a/libc/platform/bionic/macros.h b/libc/platform/bionic/macros.h
index b2d6f9649..c4af3b9eb 100644
--- a/libc/platform/bionic/macros.h
+++ b/libc/platform/bionic/macros.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <stddef.h>
 #include <stdint.h>
 
 #define BIONIC_DISALLOW_COPY_AND_ASSIGN(TypeName) \
@@ -31,24 +32,6 @@
     ? (1UL << (64 - __builtin_clzl(static_cast<unsigned long>(value)))) \
     : (1UL << (32 - __builtin_clz(static_cast<unsigned int>(value)))))
 
-static constexpr uintptr_t align_down(uintptr_t p, size_t align) {
-  return p & ~(align - 1);
-}
-
-static constexpr uintptr_t align_up(uintptr_t p, size_t align) {
-  return (p + align - 1) & ~(align - 1);
-}
-
-template <typename T>
-static inline T* _Nonnull align_down(T* _Nonnull p, size_t align) {
-  return reinterpret_cast<T*>(align_down(reinterpret_cast<uintptr_t>(p), align));
-}
-
-template <typename T>
-static inline T* _Nonnull align_up(T* _Nonnull p, size_t align) {
-  return reinterpret_cast<T*>(align_up(reinterpret_cast<uintptr_t>(p), align));
-}
-
 #if defined(__arm__)
 #define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined r14")
 #elif defined(__aarch64__)
diff --git a/libc/platform/bionic/mte.h b/libc/platform/bionic/mte.h
index 610cb45d0..27cbae1d1 100644
--- a/libc/platform/bionic/mte.h
+++ b/libc/platform/bionic/mte.h
@@ -50,6 +50,16 @@ inline bool mte_supported() {
   return supported;
 }
 
+static inline bool mte_enabled() {
+#ifdef __aarch64__
+  int level = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+  return level >= 0 && (level & PR_TAGGED_ADDR_ENABLE) &&
+         (level & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE;
+#else
+  return false;
+#endif
+}
+
 inline void* get_tagged_address(const void* ptr) {
 #if defined(__aarch64__)
   if (mte_supported()) {
diff --git a/libc/platform/bionic/reserved_signals.h b/libc/platform/bionic/reserved_signals.h
index eb423f6af..1c7076b0c 100644
--- a/libc/platform/bionic/reserved_signals.h
+++ b/libc/platform/bionic/reserved_signals.h
@@ -50,6 +50,13 @@
 #define BIONIC_SIGNAL_BACKTRACE (__SIGRTMIN + 1)
 #define BIONIC_SIGNAL_DEBUGGER (__SIGRTMIN + 3)
 #define BIONIC_SIGNAL_PROFILER (__SIGRTMIN + 4)
+// When used for the dumping a heap dump, BIONIC_SIGNAL_ART_PROFILER is always handled
+// gracefully without crashing.
+// In debuggerd, we crash the process with this signal to indicate to init that
+// a process has been terminated by an MTEAERR SEGV. This works because there is
+// no other reason a process could have terminated with this signal.
+// This is to work around the limitation of that it is not possible to get the
+// si_code that terminated a process.
 #define BIONIC_SIGNAL_ART_PROFILER (__SIGRTMIN + 6)
 #define BIONIC_SIGNAL_FDTRACK (__SIGRTMIN + 7)
 #define BIONIC_SIGNAL_RUN_ON_ALL_THREADS (__SIGRTMIN + 8)
diff --git a/libc/platform/bionic/tls.h b/libc/platform/bionic/tls.h
index e01eccd74..3e0ef53c6 100644
--- a/libc/platform/bionic/tls.h
+++ b/libc/platform/bionic/tls.h
@@ -28,16 +28,78 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #if defined(__aarch64__)
-# define __get_tls() ({ void** __val; __asm__("mrs %0, tpidr_el0" : "=r"(__val)); __val; })
+
+static inline void** __get_tls(void) {
+  void** result;
+  __asm__("mrs %0, tpidr_el0" : "=r"(result));
+  return result;
+}
+
+static inline void __set_tls(void* tls) {
+  __asm__("msr tpidr_el0, %0" : : "r" (tls));
+}
+
 #elif defined(__arm__)
-# define __get_tls() ({ void** __val; __asm__("mrc p15, 0, %0, c13, c0, 3" : "=r"(__val)); __val; })
+
+static inline void** __get_tls(void) {
+  void** result;
+  __asm__("mrc p15, 0, %0, c13, c0, 3" : "=r"(result));
+  return result;
+}
+
+// arm32 requires a syscall to set the thread pointer.
+// By historical accident it's public API, but not in any header except this one.
+__BEGIN_DECLS
+int __set_tls(void* tls);
+__END_DECLS
+
 #elif defined(__i386__)
-# define __get_tls() ({ void** __val; __asm__("movl %%gs:0, %0" : "=r"(__val)); __val; })
+
+static inline void** __get_tls(void) {
+  void** result;
+  __asm__("movl %%gs:0, %0" : "=r"(result));
+  return result;
+}
+
+// x86 is really hairy, so we keep that out of line.
+__BEGIN_DECLS
+int __set_tls(void* tls);
+__END_DECLS
+
 #elif defined(__riscv)
-# define __get_tls() ({ void** __val; __asm__("mv %0, tp" : "=r"(__val)); __val; })
+
+static inline void** __get_tls(void) {
+  void** result;
+  __asm__("mv %0, tp" : "=r"(result));
+  return result;
+}
+
+static inline void __set_tls(void* tls) {
+  __asm__("mv tp, %0" : : "r"(tls));
+}
+
 #elif defined(__x86_64__)
-# define __get_tls() ({ void** __val; __asm__("mov %%fs:0, %0" : "=r"(__val)); __val; })
+
+static inline void** __get_tls(void) {
+  void** result;
+  __asm__("mov %%fs:0, %0" : "=r"(result));
+  return result;
+}
+
+// ARCH_SET_FS is not exposed via <sys/prctl.h> or <linux/prctl.h>.
+#include <asm/prctl.h>
+// This syscall stub is generated but it's not declared in any header.
+__BEGIN_DECLS
+int arch_prctl(int, unsigned long);
+__END_DECLS
+
+static inline int __set_tls(void* tls) {
+  return arch_prctl(ARCH_SET_FS, reinterpret_cast<unsigned long>(tls));
+}
+
 #else
 #error unsupported architecture
 #endif
diff --git a/libc/platform/bionic/tls_defines.h b/libc/platform/bionic/tls_defines.h
index 06c66172a..dd3563d67 100644
--- a/libc/platform/bionic/tls_defines.h
+++ b/libc/platform/bionic/tls_defines.h
@@ -66,8 +66,8 @@
 //  - TLS_SLOT_BIONIC_TLS: Optimizes accesses to bionic_tls by one load versus
 //    finding it using __get_thread().
 //
-//  - TLS_SLOT_APP: Available for use by apps in Android Q and later. (This slot
-//    was used for errno in P and earlier.)
+//  - TLS_SLOT_APP: Available for use by apps in API level 29 and later.
+//    (This slot was used for errno in API level 28 and earlier.)
 //
 //  - TLS_SLOT_NATIVE_BRIDGE_GUEST_STATE: Pointer to the guest state for native
 //    bridge implementations. It is (to be) used by debuggerd to access this
diff --git a/libc/private/CFIShadow.h b/libc/private/CFIShadow.h
index cbdf0f706..b40c06310 100644
--- a/libc/private/CFIShadow.h
+++ b/libc/private/CFIShadow.h
@@ -40,7 +40,7 @@ constexpr size_t kLibraryAlignment = 1UL << kLibraryAlignmentBits;
 // below) are interpreted as follows.
 //
 // For an address P and corresponding shadow value V, the address of __cfi_check is calculated as
-//   align_up(P, 2**kShadowGranularity) - (V - 2) * (2 ** kCfiCheckGranularity)
+//   __builtin_align_up(P, 2**kShadowGranularity) - (V - 2) * (2 ** kCfiCheckGranularity)
 //
 // Special shadow values:
 //        0 = kInvalidShadow, this memory range has no valid CFI targets.
diff --git a/libc/private/bionic_globals.h b/libc/private/bionic_globals.h
index cd6dca977..2346a4d8c 100644
--- a/libc/private/bionic_globals.h
+++ b/libc/private/bionic_globals.h
@@ -146,11 +146,14 @@ struct libc_shared_globals {
   size_t scudo_stack_depot_size = 0;
 
   HeapTaggingLevel initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_NONE;
+  _Atomic(bool) memtag_currently_on = false;
   // See comments for __libc_memtag_stack / __libc_memtag_stack_abi above.
   bool initial_memtag_stack = false;
   bool initial_memtag_stack_abi = false;
   int64_t heap_tagging_upgrade_timer_sec = 0;
 
+  bool is_hwasan = false;
+
   void (*memtag_stack_dlopen_callback)() = nullptr;
   pthread_mutex_t crash_detail_page_lock = PTHREAD_MUTEX_INITIALIZER;
   crash_detail_page_t* crash_detail_page = nullptr;
diff --git a/libc/private/icu.h b/libc/private/icu4x.h
similarity index 68%
rename from libc/private/icu.h
rename to libc/private/icu4x.h
index 8e4aa8022..8b7e1d007 100644
--- a/libc/private/icu.h
+++ b/libc/private/icu4x.h
@@ -26,38 +26,20 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _PRIVATE_ICU_H
-#define _PRIVATE_ICU_H
+#pragma once
 
+#include <ctype.h>
 #include <stdint.h>
 #include <wchar.h>
 
-typedef int8_t UBool;
-#define FALSE 0
-#define TRUE 1
-
-typedef int32_t UChar32;
-
-enum UProperty {
-  UCHAR_ALPHABETIC = 0,
-  UCHAR_DEFAULT_IGNORABLE_CODE_POINT = 5,
-  UCHAR_LOWERCASE = 22,
-  UCHAR_POSIX_ALNUM = 44,
-  UCHAR_POSIX_BLANK = 45,
-  UCHAR_POSIX_GRAPH = 46,
-  UCHAR_POSIX_PRINT = 47,
-  UCHAR_POSIX_XDIGIT = 48,
-  UCHAR_UPPERCASE = 30,
-  UCHAR_WHITE_SPACE = 31,
-  UCHAR_EAST_ASIAN_WIDTH = 0x1004,
-  UCHAR_HANGUL_SYLLABLE_TYPE = 0x100b,
-};
-
 enum UCharCategory {
   U_NON_SPACING_MARK = 6,
   U_ENCLOSING_MARK = 7,
+  U_DECIMAL_NUMBER = 9,
   U_CONTROL_CHAR = 15,
   U_FORMAT_CHAR = 16,
+  U_DASH_PUNCTUATION = 19,
+  U_OTHER_PUNCTUATION = 23,
 };
 
 enum UEastAsianWidth {
@@ -78,11 +60,24 @@ enum UHangulSyllableType {
   U_HST_LVT_SYLLABLE,
 };
 
-int8_t __icu_charType(wint_t wc);
-int32_t __icu_getIntPropertyValue(wint_t wc, UProperty property);
+__BEGIN_DECLS
+
+uint8_t __icu4x_bionic_general_category(uint32_t cp);
+uint8_t __icu4x_bionic_east_asian_width(uint32_t cp);
+uint8_t __icu4x_bionic_hangul_syllable_type(uint32_t cp);
 
-typedef UBool (*u_hasBinaryProperty_t)(UChar32, UProperty);
+bool __icu4x_bionic_is_alphabetic(uint32_t cp);
+bool __icu4x_bionic_is_default_ignorable_code_point(uint32_t cp);
+bool __icu4x_bionic_is_lowercase(uint32_t cp);
+bool __icu4x_bionic_is_alnum(uint32_t cp);
+bool __icu4x_bionic_is_blank(uint32_t cp);
+bool __icu4x_bionic_is_graph(uint32_t cp);
+bool __icu4x_bionic_is_print(uint32_t cp);
+bool __icu4x_bionic_is_xdigit(uint32_t cp);
+bool __icu4x_bionic_is_white_space(uint32_t cp);
+bool __icu4x_bionic_is_uppercase(uint32_t cp);
 
-void* __find_icu_symbol(const char* symbol_name);
+uint32_t __icu4x_bionic_to_upper(uint32_t ch);
+uint32_t __icu4x_bionic_to_lower(uint32_t ch);
 
-#endif  // _PRIVATE_ICU_H
+__END_DECLS
diff --git a/libc/system_properties/prop_area.cpp b/libc/system_properties/prop_area.cpp
index 9b153ca7a..faa3edf00 100644
--- a/libc/system_properties/prop_area.cpp
+++ b/libc/system_properties/prop_area.cpp
@@ -72,7 +72,7 @@ prop_area* prop_area::map_prop_area_rw(const char* filename, const char* context
   if (context) {
     if (fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0) {
       async_safe_format_log(ANDROID_LOG_ERROR, "libc",
-                            "fsetxattr failed to set context (%s) for \"%s\"", context, filename);
+                            "fsetxattr failed to set context (%s) for \"%s\": %m", context, filename);
       /*
        * fsetxattr() will fail during system properties tests due to selinux policy.
        * We do not want to create a custom policy for the tester, so we will continue in
diff --git a/libc/tools/generate_notice.py b/libc/tools/generate_notice.py
index c998e3265..034a3b300 100755
--- a/libc/tools/generate_notice.py
+++ b/libc/tools/generate_notice.py
@@ -151,6 +151,12 @@ def do_file(path: str) -> None:
              (path, len(lines)))
         return
 
+    # Skip over our own files if they're SPDX licensed.
+    # Because we use the // comment style, without this we'd copy the whole source file!
+    if re.compile('^// Copyright \(C\) 2\d\d\d The Android Open Source Project\n' + \
+                  '// SPDX-License-Identifier: ').match(content):
+        return
+
     # Manually iterate because extract_copyright_at tells us how many lines to
     # skip.
     i = 0
diff --git a/libc/tools/gensyscalls.py b/libc/tools/gensyscalls.py
index d7afe2afa..d371b721d 100755
--- a/libc/tools/gensyscalls.py
+++ b/libc/tools/gensyscalls.py
@@ -27,6 +27,7 @@ ENTRY(%(func)s)
 # ARM assembler templates for each syscall stub
 #
 
+# ARM assembler template for a syscall stub needing 4 or fewer registers
 arm_call_default = syscall_stub_header + """\
     mov     ip, r7
     .cfi_register r7, ip
@@ -41,6 +42,7 @@ arm_call_default = syscall_stub_header + """\
 END(%(func)s)
 """
 
+# ARM assembler template for a syscall stub needing more than 4 registers
 arm_call_long = syscall_stub_header + """\
     mov     ip, sp
     stmfd   sp!, {r4, r5, r6, r7}
@@ -165,13 +167,13 @@ def param_uses_64bits(param):
 
     # Second, check that there is no pointer type here
     if param.find("*") >= 0:
-            return False
+        return False
 
     # Ok
     return True
 
 
-def count_arm_param_registers(params):
+def count_param_registers_arm32(params):
     """This function is used to count the number of register used
        to pass parameters when invoking an ARM system call.
        This is because the ARM EABI mandates that 64-bit quantities
@@ -196,7 +198,7 @@ def count_arm_param_registers(params):
     return count
 
 
-def count_generic_param_registers(params):
+def count_param_registers_x86(params):
     count = 0
     for param in params:
         if param_uses_64bits(param):
@@ -206,13 +208,6 @@ def count_generic_param_registers(params):
     return count
 
 
-def count_generic_param_registers64(params):
-    count = 0
-    for param in params:
-        count += 1
-    return count
-
-
 # This lets us support regular system calls like __NR_write and also weird
 # ones like __ARM_NR_cacheflush, where the NR doesn't come at the start.
 def make__NR_name(name):
@@ -231,7 +226,7 @@ def add_footer(pointer_length, stub, syscall):
 
 
 def arm_genstub(syscall):
-    num_regs = count_arm_param_registers(syscall["params"])
+    num_regs = count_param_registers_arm32(syscall["params"])
     if num_regs > 4:
         return arm_call_long % syscall
     return arm_call_default % syscall
@@ -248,7 +243,7 @@ def riscv64_genstub(syscall):
 def x86_genstub(syscall):
     result     = syscall_stub_header % syscall
 
-    numparams = count_generic_param_registers(syscall["params"])
+    numparams = count_param_registers_x86(syscall["params"])
     stack_bias = numparams*4 + 8
     offset = 0
     mov_result = ""
@@ -316,7 +311,7 @@ def x86_genstub_socketcall(syscall):
 
 def x86_64_genstub(syscall):
     result = syscall_stub_header % syscall
-    num_regs = count_generic_param_registers64(syscall["params"])
+    num_regs = len(syscall["params"])
     if (num_regs > 3):
         # rcx is used as 4th argument. Kernel wants it at r10.
         result += "    movq    %rcx, %r10\n"
@@ -338,8 +333,11 @@ class SysCallsTxtParser:
     def parse_line(self, line):
         """ parse a syscall spec line.
 
-        line processing, format is
-           return type    func_name[|alias_list][:syscall_name[:socketcall_id]] ( [paramlist] ) architecture_list
+        format is one syscall per line:
+
+           func_name[|alias_list][:syscall_name[:socketcall_id]] ( [paramlist] ) architecture_list
+
+        with no line breaking/continuation allowed.
         """
         pos_lparen = line.find('(')
         E          = self.E
@@ -352,13 +350,7 @@ class SysCallsTxtParser:
             E("missing or misplaced right parenthesis in '%s'" % line)
             return
 
-        return_type = line[:pos_lparen].strip().split()
-        if len(return_type) < 2:
-            E("missing return type in '%s'" % line)
-            return
-
-        syscall_func = return_type[-1]
-        return_type  = ' '.join(return_type[:-1])
+        syscall_func = line[:pos_lparen]
         socketcall_id = -1
 
         pos_colon = syscall_func.find(':')
@@ -396,17 +388,14 @@ class SysCallsTxtParser:
 
         if pos_rparen > pos_lparen+1:
             syscall_params = line[pos_lparen+1:pos_rparen].split(',')
-            params         = ','.join(syscall_params)
         else:
             syscall_params = []
-            params         = "void"
 
         t = {
               "name"    : syscall_name,
               "func"    : syscall_func,
               "aliases" : syscall_aliases,
               "params"  : syscall_params,
-              "decl"    : "%-15s  %s (%s);" % (return_type, syscall_func, params),
               "socketcall_id" : socketcall_id
         }
 
diff --git a/libc/upstream-netbsd/android/include/netbsd-compat.h b/libc/upstream-netbsd/android/include/netbsd-compat.h
index a625f06d2..dc520026e 100644
--- a/libc/upstream-netbsd/android/include/netbsd-compat.h
+++ b/libc/upstream-netbsd/android/include/netbsd-compat.h
@@ -35,16 +35,4 @@
  */
 #define __UNCONST(a)    ((void *)(unsigned long)(const void *)(a))
 
-// TODO: we don't yet have thread-safe environment variables.
-#define __readlockenv() 0
-#define __unlockenv() 0
-
-#include <sys/cdefs.h>
-#include <stddef.h>
-int reallocarr(void*, size_t, size_t);
-
 #define __arraycount(a) (sizeof(a) / sizeof(a[0]))
-
-/* Use appropriate shell depending on process's executable. */
-__LIBC_HIDDEN__ extern const char* __bionic_get_shell_path();
-#define _PATH_BSHELL __bionic_get_shell_path()
diff --git a/libc/upstream-netbsd/lib/libc/regex/regcomp.c b/libc/upstream-netbsd/lib/libc/regex/regcomp.c
index 86321c153..b0f29d6fe 100644
--- a/libc/upstream-netbsd/lib/libc/regex/regcomp.c
+++ b/libc/upstream-netbsd/lib/libc/regex/regcomp.c
@@ -1,4 +1,4 @@
-/*	$NetBSD: regcomp.c,v 1.47 2022/12/21 17:44:15 wiz Exp $	*/
+/*	$NetBSD: regcomp.c,v 1.49 2025/01/01 18:19:50 christos Exp $	*/
 
 /*-
  * SPDX-License-Identifier: BSD-3-Clause
@@ -51,7 +51,7 @@
 static char sccsid[] = "@(#)regcomp.c	8.5 (Berkeley) 3/20/94";
 __FBSDID("$FreeBSD: head/lib/libc/regex/regcomp.c 368359 2020-12-05 03:18:48Z kevans $");
 #endif
-__RCSID("$NetBSD: regcomp.c,v 1.47 2022/12/21 17:44:15 wiz Exp $");
+__RCSID("$NetBSD: regcomp.c,v 1.49 2025/01/01 18:19:50 christos Exp $");
 
 #ifndef LIBHACK
 #define REGEX_GNU_EXTENSIONS
@@ -898,10 +898,10 @@ p_simp_re(struct parse *p, struct branchc *bc)
 	handled = false;
 
 	assert(MORE());		/* caller should have ensured this */
-	c = GETNEXT();
+	c = (uch)GETNEXT();
 	if (c == '\\') {
 		(void)REQUIRE(MORE(), REG_EESCAPE);
-		cc = GETNEXT();
+		cc = (uch)GETNEXT();
 		c = BACKSL | cc;
 #ifdef REGEX_GNU_EXTENSIONS
 		if (p->gnuext) {
@@ -1083,7 +1083,7 @@ p_count(struct parse *p)
 	int ndigits = 0;
 
 	while (MORE() && isdigit((uch)PEEK()) && count <= DUPMAX) {
-		count = count*10 + (GETNEXT() - '0');
+		count = count*10 + ((uch)GETNEXT() - '0');
 		ndigits++;
 	}
 
@@ -1422,7 +1422,7 @@ may_escape(struct parse *p, const wint_t ch)
 
 	if ((p->pflags & PFLAG_LEGACY_ESC) != 0)
 		return (true);
-	if (isalpha(ch) || ch == '\'' || ch == '`')
+	if (iswalpha(ch) || ch == '\'' || ch == '`')
 		return (false);
 	return (true);
 #ifdef NOTYET
@@ -1764,8 +1764,7 @@ CHadd(struct parse *p, cset *cs, wint_t ch)
 	_DIAGASSERT(p != NULL);
 	_DIAGASSERT(cs != NULL);
 
-	assert(ch >= 0);
-	if (ch < NC)
+	if ((unsigned)ch < NC)
 		cs->bmp[(unsigned)ch >> 3] |= 1 << (ch & 7);
 	else {
 		newwides = reallocarray(cs->wides, cs->nwides + 1,
@@ -1778,9 +1777,9 @@ CHadd(struct parse *p, cset *cs, wint_t ch)
 		cs->wides[cs->nwides++] = ch;
 	}
 	if (cs->icase) {
-		if ((nch = towlower(ch)) < NC)
+		if ((unsigned)(nch = towlower(ch)) < NC)
 			cs->bmp[(unsigned)nch >> 3] |= 1 << (nch & 7);
-		if ((nch = towupper(ch)) < NC)
+		if ((unsigned)(nch = towupper(ch)) < NC)
 			cs->bmp[(unsigned)nch >> 3] |= 1 << (nch & 7);
 	}
 }
diff --git a/libc/upstream-netbsd/lib/libc/regex/regex2.h b/libc/upstream-netbsd/lib/libc/regex/regex2.h
index fbfff0daf..d44785fd5 100644
--- a/libc/upstream-netbsd/lib/libc/regex/regex2.h
+++ b/libc/upstream-netbsd/lib/libc/regex/regex2.h
@@ -1,4 +1,4 @@
-/*	$NetBSD: regex2.h,v 1.15 2021/02/24 18:13:21 christos Exp $	*/
+/*	$NetBSD: regex2.h,v 1.16 2025/01/01 18:19:50 christos Exp $	*/
 
 /*-
  * SPDX-License-Identifier: BSD-3-Clause
@@ -135,8 +135,7 @@ CHIN1(cset *cs, wint_t ch)
 {
 	unsigned int i;
 
-	assert(ch >= 0);
-	if (ch < NC)
+	if ((unsigned)ch < NC)
 		return (((cs->bmp[(unsigned)ch >> 3] & (1 << (ch & 7))) != 0) ^
 		    cs->invert);
 	for (i = 0; i < cs->nwides; i++) {
@@ -160,8 +159,7 @@ static __inline int
 CHIN(cset *cs, wint_t ch)
 {
 
-	assert(ch >= 0);
-	if (ch < NC)
+	if ((unsigned)ch < NC)
 		return (((cs->bmp[(unsigned)ch >> 3] & (1 << (ch & 7))) != 0) ^
 		    cs->invert);
 	else if (cs->icase)
diff --git a/libc/upstream-netbsd/lib/libc/regex/utils.h b/libc/upstream-netbsd/lib/libc/regex/utils.h
index 972f55560..8650dd4dc 100644
--- a/libc/upstream-netbsd/lib/libc/regex/utils.h
+++ b/libc/upstream-netbsd/lib/libc/regex/utils.h
@@ -63,6 +63,7 @@ extern int __regex_iswctype(wint_t, wctype_t);
 
 /* utility definitions */
 #define	DUPMAX		_POSIX2_RE_DUP_MAX	/* xxx is this right? */
+#undef INFINITY // Android-added: avoid collision with C23 <float.h> INFINITY (via <limits.h>)
 #define	INFINITY	(DUPMAX + 1)
 
 #define	NC_MAX		(CHAR_MAX - CHAR_MIN + 1)
diff --git a/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.c b/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.c
deleted file mode 100644
index 6ffe8114e..000000000
--- a/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.c
+++ /dev/null
@@ -1,95 +0,0 @@
-/* $NetBSD: reallocarr.c,v 1.5 2015/08/20 22:27:49 kamil Exp $ */
-
-/*-
- * Copyright (c) 2015 Joerg Sonnenberger <joerg@NetBSD.org>.
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
- * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
- * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#if HAVE_NBTOOL_CONFIG_H
-#include "nbtool_config.h"
-#endif
-
-#include <sys/cdefs.h>
-__RCSID("$NetBSD: reallocarr.c,v 1.5 2015/08/20 22:27:49 kamil Exp $");
-
-#include "namespace.h"
-#include <errno.h>
-/* Old POSIX has SIZE_MAX in limits.h */
-#include <limits.h>
-#include <stdint.h>
-#include <stdlib.h>
-#include <string.h>
-
-#ifdef _LIBC
-#ifdef __weak_alias
-__weak_alias(reallocarr, _reallocarr)
-#endif
-#endif
-
-#define SQRT_SIZE_MAX (((size_t)1) << (sizeof(size_t) * CHAR_BIT / 2))
-
-#if !HAVE_REALLOCARR
-int
-reallocarr(void *ptr, size_t number, size_t size)
-{
-	int saved_errno, result;
-	void *optr;
-	void *nptr;
-
-	saved_errno = errno;
-	memcpy(&optr, ptr, sizeof(ptr));
-	if (number == 0 || size == 0) {
-		free(optr);
-		nptr = NULL;
-		memcpy(ptr, &nptr, sizeof(ptr));
-		errno = saved_errno;
-		return 0;
-	}
-
-	/*
-	 * Try to avoid division here.
-	 *
-	 * It isn't possible to overflow during multiplication if neither
-	 * operand uses any of the most significant half of the bits.
-	 */
-	if (__predict_false((number|size) >= SQRT_SIZE_MAX &&
-	                    number > SIZE_MAX / size)) {
-		errno = saved_errno;
-		return EOVERFLOW;
-	}
-
-	nptr = realloc(optr, number * size);
-	if (__predict_false(nptr == NULL)) {
-		result = errno;
-	} else {
-		result = 0;
-		memcpy(ptr, &nptr, sizeof(ptr));
-	}
-	errno = saved_errno;
-	return result;
-}
-#endif
diff --git a/libc/upstream-openbsd/android/include/openbsd-compat.h b/libc/upstream-openbsd/android/include/openbsd-compat.h
index ac6840ac9..19f28ad55 100644
--- a/libc/upstream-openbsd/android/include/openbsd-compat.h
+++ b/libc/upstream-openbsd/android/include/openbsd-compat.h
@@ -48,17 +48,7 @@ extern const char* __progname;
 #define __LIBC_HIDDEN__ __attribute__((visibility("hidden")))
 #endif
 
-/* OpenBSD has this in paths.h. But this directory doesn't normally exist.
- * Even when it does exist, only the 'shell' user has permissions.
- */
-#define _PATH_TMP "/data/local/tmp/"
-
-/* Use appropriate shell depending on process's executable. */
-__LIBC_HIDDEN__ extern const char* __bionic_get_shell_path();
-#define _PATH_BSHELL __bionic_get_shell_path()
-
 __LIBC_HIDDEN__ extern char* __findenv(const char*, int, int*);
-__LIBC_HIDDEN__ extern char* _mktemp(char*);
 
 // Only OpenBSD has this at the moment, and we're more likely to just say
 // "malloc is always calloc", so we don't expose this as libc API.
diff --git a/libc/upstream-openbsd/lib/libc/string/memchr.c b/libc/upstream-openbsd/lib/libc/string/memchr.c
deleted file mode 100644
index a6a4bd60d..000000000
--- a/libc/upstream-openbsd/lib/libc/string/memchr.c
+++ /dev/null
@@ -1,49 +0,0 @@
-/*	$OpenBSD: memchr.c,v 1.8 2015/08/31 02:53:57 guenther Exp $ */
-/*-
- * Copyright (c) 1990 The Regents of the University of California.
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
-#include <string.h>
-
-void *
-memchr(const void *s, int c, size_t n)
-{
-	if (n != 0) {
-		const unsigned char *p = s;
-
-		do {
-			if (*p++ == (unsigned char)c)
-				return ((void *)(p - 1));
-		} while (--n != 0);
-	}
-	return (NULL);
-}
-DEF_STRONG(memchr);
diff --git a/libdl/Android.bp b/libdl/Android.bp
index 87db4b1c7..205c4548c 100644
--- a/libdl/Android.bp
+++ b/libdl/Android.bp
@@ -60,6 +60,8 @@ cc_library {
     native_bridge_supported: true,
     static_ndk_lib: true,
 
+    export_include_dirs: ["include_private"],
+
     defaults: [
         "linux_bionic_supported",
         "bug_24465209_workaround",
diff --git a/libdl/NOTICE b/libdl/NOTICE
index fce010459..80038fc25 100644
--- a/libdl/NOTICE
+++ b/libdl/NOTICE
@@ -30,3 +30,19 @@ limitations under the License.
 
 -------------------------------------------------------------------
 
+Copyright (C) 2024 The Android Open Source Project
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+
+-------------------------------------------------------------------
+
diff --git a/libdl/include_private/android/dlext_private.h b/libdl/include_private/android/dlext_private.h
new file mode 100644
index 000000000..fda108683
--- /dev/null
+++ b/libdl/include_private/android/dlext_private.h
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <stdbool.h>
+#include <sys/cdefs.h>
+
+__BEGIN_DECLS
+
+// TODO: libdl has several private extensions, but they have not all moved into a standard
+// private header.
+
+/**
+ * Set whether to load libraries in app compat mode.
+ *
+ * Any library which is not 16 KB aligned on a 4 KB aligned
+ * will be loaded in a special mode, which may load some R-only
+ * code as RW, in order to increase compatibility.
+ *
+ * \param enable_app_compat whether the mode is enabled for additional
+ *     library loads.
+ */
+void android_set_16kb_appcompat_mode(bool enable_app_compat);
+
+__END_DECLS
diff --git a/libdl/libdl_cfi.cpp b/libdl/libdl_cfi.cpp
index 8adc342ac..e096f9ab7 100644
--- a/libdl/libdl_cfi.cpp
+++ b/libdl/libdl_cfi.cpp
@@ -55,8 +55,8 @@ static uintptr_t cfi_check_addr(uint16_t v, void* Ptr) {
   uintptr_t addr = reinterpret_cast<uintptr_t>(Ptr);
   // The aligned range of [0, kShadowAlign) uses a single shadow element, therefore all pointers in
   // this range must get the same aligned_addr below. This matches CFIShadowWriter::Add; not the
-  // same as align_up().
-  uintptr_t aligned_addr = align_down(addr, CFIShadow::kShadowAlign) + CFIShadow::kShadowAlign;
+  // same as just __builtin_align_up().
+  uintptr_t aligned_addr = __builtin_align_down(addr, CFIShadow::kShadowAlign) + CFIShadow::kShadowAlign;
   uintptr_t p = aligned_addr - (static_cast<uintptr_t>(v - CFIShadow::kRegularShadowMin)
                                 << CFIShadow::kCfiCheckGranularity);
 #ifdef __arm__
diff --git a/libm/Android.bp b/libm/Android.bp
index ee869595c..86b32db67 100644
--- a/libm/Android.bp
+++ b/libm/Android.bp
@@ -32,7 +32,6 @@ cc_library {
 
     whole_static_libs: ["libarm-optimized-routines-math"],
 
-    tidy_disabled_srcs: ["upstream-*/**/*.c"],
     srcs: [
         "upstream-freebsd/lib/msun/bsdsrc/b_tgamma.c",
         "upstream-freebsd/lib/msun/src/catrig.c",
@@ -361,7 +360,8 @@ cc_library {
                 "upstream-freebsd/lib/msun/src/s_lrintf.c",
             ],
             // The x86 ABI doesn't include this, which is needed for the
-            // roundss/roundsd instructions that we've used since Android M.
+            // roundss/roundsd instructions that we've used since API level 23,
+            // originally by hand-written assembler but later via intrinsics.
             cflags: ["-msse4.1"],
             version_script: ":libm.x86.map",
         },
@@ -404,9 +404,6 @@ cc_library {
         "-Wl,--Bsymbolic-functions",
     ],
 
-    // b/120614316, non-critical readibility check
-    tidy_checks: ["-cert-dcl16-c"],
-
     include_dirs: ["bionic/libc"],
     target: {
         bionic: {
diff --git a/linker/Android.bp b/linker/Android.bp
index 4863b9207..ea4e69965 100644
--- a/linker/Android.bp
+++ b/linker/Android.bp
@@ -76,14 +76,6 @@ cc_object {
 // Configuration for the linker binary and any of its static libraries.
 cc_defaults {
     name: "linker_defaults",
-    arch: {
-        arm: {
-            cflags: ["-D__work_around_b_24465209__"],
-        },
-        x86: {
-            cflags: ["-D__work_around_b_24465209__"],
-        },
-    },
 
     cflags: linker_common_flags,
     asflags: linker_common_flags,
@@ -350,11 +342,10 @@ cc_defaults {
 // linker[_asan][64] binary
 // ========================================================
 
-cc_binary {
-    name: "linker",
+cc_defaults {
+    name: "linker_binary_defaults",
     defaults: [
         "linker_bin_template",
-        "linux_bionic_supported",
         "linker_version_script_overlay",
     ],
 
@@ -376,8 +367,6 @@ cc_binary {
 
     compile_multilib: "both",
 
-    recovery_available: true,
-    vendor_ramdisk_available: true,
     apex_available: [
         "//apex_available:platform",
         "com.android.runtime",
@@ -403,6 +392,26 @@ cc_binary {
     afdo: true,
 }
 
+cc_binary {
+    name: "linker",
+    defaults: [
+        "linux_bionic_supported",
+        "linker_binary_defaults",
+    ],
+
+    vendor_ramdisk_available: true,
+}
+
+cc_binary {
+    name: "linker.recovery",
+    defaults: [
+        "linker_binary_defaults",
+    ],
+
+    recovery: true,
+    stem: "linker",
+}
+
 // ========================================================
 // assorted modules
 // ========================================================
@@ -542,3 +551,32 @@ cc_benchmark {
         },
     },
 }
+
+cc_fuzz {
+    name: "ElfReader_fuzzer",
+    srcs: [
+        "ElfReader_fuzzer.cpp",
+        "linker.cpp",
+        "linker_block_allocator.cpp",
+        "linker_debug.cpp",
+        "linker_dlwarning.cpp",
+        "linker_globals.cpp",
+        "linker_mapped_file_fragment.cpp",
+        "linker_phdr.cpp",
+        "linker_phdr_16kib_compat.cpp",
+        "linker_sdk_versions.cpp",
+        "linker_utils.cpp",
+        ":elf_note_sources",
+    ],
+    static_libs: [
+        "libasync_safe",
+        "libbase",
+        "libziparchive",
+    ],
+    include_dirs: ["bionic/libc"],
+    // TODO: use all the architectures' files.
+    // We'll either need to give them unique names across architectures,
+    // or change soong to preserve subdirectories in `corpus:`,
+    // and maybe also the [deprecated] LLVM fuzzer infrastructure?
+    corpus: [":bionic_prebuilt_test_elf_files_arm64"],
+}
diff --git a/libc/arch-x86_64/bionic/__set_tls.c b/linker/ElfReader_fuzzer.cpp
similarity index 73%
rename from libc/arch-x86_64/bionic/__set_tls.c
rename to linker/ElfReader_fuzzer.cpp
index 9460a037c..a23132bde 100644
--- a/libc/arch-x86_64/bionic/__set_tls.c
+++ b/linker/ElfReader_fuzzer.cpp
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2013 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
@@ -26,13 +26,21 @@
  * SUCH DAMAGE.
  */
 
-#include <sys/cdefs.h>
+#include "linker_phdr.h"
 
-// ARCH_SET_FS is not exposed via <sys/prctl.h> or <linux/prctl.h>.
-#include <asm/prctl.h>
+#include <stddef.h>
+#include <stdint.h>
 
-extern int arch_prctl(int, unsigned long);
+#include <android-base/file.h>
 
-__LIBC_HIDDEN__ int __set_tls(void* ptr) {
-  return arch_prctl(ARCH_SET_FS, (unsigned long) ptr);
+// See current fuzz coverage here:
+// https://android-coverage.googleplex.com/fuzz_targets/ElfReader_fuzzer/index.html
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+  TemporaryFile tf;
+  android::base::WriteFully(tf.fd, data, size);
+
+  ElfReader er;
+  er.Read(tf.path, tf.fd, 0, size);
+  return 0;
 }
diff --git a/linker/dlfcn.cpp b/linker/dlfcn.cpp
index f811d6d17..fc95903e0 100644
--- a/linker/dlfcn.cpp
+++ b/linker/dlfcn.cpp
@@ -345,7 +345,7 @@ soinfo* get_libdl_info(const soinfo& linker_si) {
     __libdl_info->soname_ = linker_si.soname_;
     __libdl_info->target_sdk_version_ = __ANDROID_API__;
     __libdl_info->generate_handle();
-#if defined(__work_around_b_24465209__)
+#if !defined(__LP64__)
     strlcpy(__libdl_info->old_name_, __libdl_info->soname_.c_str(),
             sizeof(__libdl_info->old_name_));
 #endif
diff --git a/linker/linker.cpp b/linker/linker.cpp
index 8f7891558..4cf93b9ba 100644
--- a/linker/linker.cpp
+++ b/linker/linker.cpp
@@ -346,7 +346,7 @@ static void soinfo_free(soinfo* si) {
     }
   }
 
-  if (si->has_min_version(6) && si->get_gap_size()) {
+  if (si->is_lp64_or_has_min_version(6) && si->get_gap_size()) {
     munmap(reinterpret_cast<void*>(si->get_gap_start()), si->get_gap_size());
   }
 
@@ -798,7 +798,7 @@ static const ElfW(Sym)* dlsym_linear_lookup(android_namespace_t* ns,
   for (auto it = start, end = soinfo_list.end(); it != end; ++it) {
     soinfo* si = *it;
     // Do not skip RTLD_LOCAL libraries in dlsym(RTLD_DEFAULT, ...)
-    // if the library is opened by application with target api level < M.
+    // if the library is opened by an application with target sdk version < 23.
     // See http://b/21565766
     if ((si->get_rtld_flags() & RTLD_GLOBAL) == 0 && si->get_target_sdk_version() >= 23) {
       continue;
@@ -1084,33 +1084,21 @@ int open_executable(const char* path, off64_t* file_offset, std::string* realpat
 
 const char* fix_dt_needed(const char* dt_needed, const char* sopath __unused) {
 #if !defined(__LP64__)
-  // Work around incorrect DT_NEEDED entries for old apps: http://b/21364029
-  int app_target_api_level = get_application_target_sdk_version();
-  if (app_target_api_level < 23) {
+  if (get_application_target_sdk_version() < 23) {
     const char* bname = basename(dt_needed);
     if (bname != dt_needed) {
-      DL_WARN_documented_change(23,
-                                "invalid-dt_needed-entries-enforced-for-api-level-23",
-                                "library \"%s\" has invalid DT_NEEDED entry \"%s\"",
-                                sopath, dt_needed, app_target_api_level);
-      add_dlwarning(sopath, "invalid DT_NEEDED entry",  dt_needed);
+      // Work around incorrect DT_NEEDED entries for old apps: http://b/21364029
+      if (!DL_ERROR_AFTER(23, "library \"%s\" has invalid DT_NEEDED entry \"%s\"",
+                          sopath, dt_needed)) {
+        add_dlwarning(sopath, "invalid DT_NEEDED entry",  dt_needed);
+        return bname;
+      }
     }
-
-    return bname;
   }
 #endif
   return dt_needed;
 }
 
-template<typename F>
-static void for_each_dt_needed(const ElfReader& elf_reader, F action) {
-  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
-    if (d->d_tag == DT_NEEDED) {
-      action(fix_dt_needed(elf_reader.get_string(d->d_un.d_val), elf_reader.name()));
-    }
-  }
-}
-
 static bool find_loaded_library_by_inode(android_namespace_t* ns,
                                          const struct stat& file_stat,
                                          off64_t file_offset,
@@ -1236,11 +1224,12 @@ static bool load_library(android_namespace_t* ns,
         const soinfo* needed_or_dlopened_by = task->get_needed_by();
         const char* sopath = needed_or_dlopened_by == nullptr ? "(unknown)" :
                                                       needed_or_dlopened_by->get_realpath();
-        DL_WARN_documented_change(24,
-                                  "private-api-enforced-for-api-level-24",
-                                  "library \"%s\" (\"%s\") needed or dlopened by \"%s\" "
-                                  "is not accessible by namespace \"%s\"",
-                                  name, realpath.c_str(), sopath, ns->get_name());
+        // is_exempt_lib() always returns true for targetSdkVersion < 24,
+        // so no need to check the return value of DL_ERROR_AFTER().
+        // We still call it rather than DL_WARN() to get the extra clarification.
+        DL_ERROR_AFTER(24, "library \"%s\" (\"%s\") needed or dlopened by \"%s\" "
+                       "is not accessible by namespace \"%s\"",
+                       name, realpath.c_str(), sopath, ns->get_name());
         add_dlwarning(sopath, "unauthorized access to",  name);
       }
     } else {
@@ -1307,11 +1296,14 @@ static bool load_library(android_namespace_t* ns,
   }
 #endif
 
-  for_each_dt_needed(task->get_elf_reader(), [&](const char* name) {
-    LD_LOG(kLogDlopen, "load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
-           ns->get_name(), task->get_name(), name);
-    load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
-  });
+  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
+    if (d->d_tag == DT_NEEDED) {
+      const char* name = fix_dt_needed(elf_reader.get_string(d->d_un.d_val), elf_reader.name());
+      LD_LOG(kLogDlopen, "load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
+             ns->get_name(), task->get_name(), name);
+      load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
+    }
+  }
 
   return true;
 }
@@ -1915,7 +1907,7 @@ static void soinfo_unload_impl(soinfo* root) {
 
     local_unload_list.push_back(si);
 
-    if (si->has_min_version(0)) {
+    if (si->is_lp64_or_has_min_version(0)) {
       soinfo* child = nullptr;
       while ((child = si->get_children().pop_front()) != nullptr) {
         LD_DEBUG(any, "%s@%p needs to unload %s@%p", si->get_realpath(), si,
@@ -2369,8 +2361,10 @@ bool do_dlsym(void* handle,
         }
         void* tls_block = get_tls_block_for_this_thread(tls_module, /*should_alloc=*/true);
         *symbol = static_cast<char*>(tls_block) + sym->st_value;
-      } else {
+      } else if (__libc_mte_enabled()) {
         *symbol = get_tagged_address(reinterpret_cast<void*>(found->resolve_symbol_address(sym)));
+      } else {
+        *symbol = reinterpret_cast<void*>(found->resolve_symbol_address(sym));
       }
       failure_guard.Disable();
       LD_LOG(kLogDlsym,
@@ -2677,7 +2671,7 @@ bool VersionTracker::init_verneed(const soinfo* si_from) {
 
 template <typename F>
 static bool for_each_verdef(const soinfo* si, F functor) {
-  if (!si->has_min_version(2)) {
+  if (!si->is_lp64_or_has_min_version(2)) {
     return true;
   }
 
@@ -2768,7 +2762,7 @@ bool VersionTracker::init_verdef(const soinfo* si_from) {
 }
 
 bool VersionTracker::init(const soinfo* si_from) {
-  if (!si_from->has_min_version(2)) {
+  if (!si_from->is_lp64_or_has_min_version(2)) {
     return true;
   }
 
@@ -3325,19 +3319,19 @@ bool soinfo::prelink_image(bool dlext_use_relro) {
     }
   }
 
-  // Before M release, linker was using basename in place of soname. In the case when DT_SONAME is
-  // absent some apps stop working because they can't find DT_NEEDED library by soname. This
-  // workaround should keep them working. (Applies only for apps targeting sdk version < M.) Make
-  // an exception for the main executable, which does not need to have DT_SONAME. The linker has an
-  // DT_SONAME but the soname_ field is initialized later on.
+  // Before API 23, the linker used the basename in place of DT_SONAME.
+  // After we switched, apps with libraries without a DT_SONAME stopped working:
+  // they could no longer be found by DT_NEEDED from another library.
+  // The main executable does not need to have a DT_SONAME.
+  // The linker has a DT_SONAME, but the soname_ field is initialized later on.
   if (soname_.empty() && this != solist_get_somain() && !relocating_linker &&
       get_application_target_sdk_version() < 23) {
     soname_ = basename(realpath_.c_str());
-    DL_WARN_documented_change(23, "missing-soname-enforced-for-api-level-23",
-                              "\"%s\" has no DT_SONAME (will use %s instead)", get_realpath(),
-                              soname_.c_str());
-
-    // Don't call add_dlwarning because a missing DT_SONAME isn't important enough to show in the UI
+    // The `if` above means we don't get here for targetSdkVersion >= 23,
+    // so no need to check the return value of DL_ERROR_AFTER().
+    // We still call it rather than DL_WARN() to get the extra clarification.
+    DL_ERROR_AFTER(23, "\"%s\" has no DT_SONAME (will use %s instead)",
+                   get_realpath(), soname_.c_str());
   }
 
   // Validate each library's verdef section once, so we don't have to validate
@@ -3383,20 +3377,12 @@ bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group
 
 #if !defined(__LP64__)
   if (has_text_relocations) {
-    // Fail if app is targeting M or above.
-    int app_target_api_level = get_application_target_sdk_version();
-    if (app_target_api_level >= 23) {
-      DL_ERR_AND_LOG("\"%s\" has text relocations (%s#Text-Relocations-Enforced-for-API-level-23)",
-                     get_realpath(), kBionicChangesUrl);
+    if (DL_ERROR_AFTER(23, "\"%s\" has text relocations", get_realpath())) {
       return false;
     }
+    add_dlwarning(get_realpath(), "text relocations");
     // Make segments writable to allow text relocations to work properly. We will later call
     // phdr_table_protect_segments() after all of them are applied.
-    DL_WARN_documented_change(23,
-                              "Text-Relocations-Enforced-for-API-level-23",
-                              "\"%s\" has text relocations",
-                              get_realpath());
-    add_dlwarning(get_realpath(), "text relocations");
     if (phdr_table_unprotect_segments(phdr, phnum, load_bias, should_pad_segments_,
                                       should_use_16kib_app_compat_) < 0) {
       DL_ERR("can't unprotect loadable segments for \"%s\": %m", get_realpath());
@@ -3628,14 +3614,7 @@ static std::string get_ld_config_file_path(const char* executable_path) {
   return kLdConfigFilePath;
 }
 
-
-std::vector<android_namespace_t*> init_default_namespaces(const char* executable_path) {
-  g_default_namespace.set_name("(default)");
-
-  soinfo* somain = solist_get_somain();
-
-  const char *interp = phdr_table_get_interpreter_name(somain->phdr, somain->phnum,
-                                                       somain->load_bias);
+void init_sanitizer_mode(const char *interp ) {
   const char* bname = (interp != nullptr) ? basename(interp) : nullptr;
 
   g_is_asan = bname != nullptr &&
@@ -3651,7 +3630,13 @@ std::vector<android_namespace_t*> init_default_namespaces(const char* executable
   g_is_hwasan = (bname != nullptr &&
               strcmp(bname, "linker_hwasan64") == 0) ||
               (hwasan_env != nullptr && !getauxval(AT_SECURE) && strcmp(hwasan_env, "1") == 0);
+  __libc_shared_globals()->is_hwasan = g_is_hwasan;
 #endif
+}
+
+std::vector<android_namespace_t*> init_default_namespaces(const char* executable_path) {
+  g_default_namespace.set_name("(default)");
+
   const Config* config = nullptr;
 
   {
diff --git a/linker/linker.h b/linker/linker.h
index 7afa0d730..86ef762a5 100644
--- a/linker/linker.h
+++ b/linker/linker.h
@@ -71,10 +71,6 @@ class VersionTracker {
   DISALLOW_COPY_AND_ASSIGN(VersionTracker);
 };
 
-static constexpr const char* kBionicChangesUrl =
-    "https://android.googlesource.com/platform/bionic/+/main/"
-    "android-changes-for-ndk-developers.md";
-
 soinfo* get_libdl_info(const soinfo& linker_si);
 
 soinfo* find_containing_library(const void* p);
diff --git a/linker/linker_globals.cpp b/linker/linker_globals.cpp
index 4a17d0918..0d820b68d 100644
--- a/linker/linker_globals.cpp
+++ b/linker/linker_globals.cpp
@@ -52,19 +52,26 @@ size_t linker_get_error_buffer_size() {
   return sizeof(__linker_dl_err_buf);
 }
 
-void DL_WARN_documented_change(int api_level, const char* doc_fragment, const char* fmt, ...) {
-  std::string result{"Warning: "};
-
+bool DL_ERROR_AFTER(int target_sdk_version, const char* fmt, ...) {
+  std::string result;
   va_list ap;
   va_start(ap, fmt);
   android::base::StringAppendV(&result, fmt, ap);
   va_end(ap);
 
-  android::base::StringAppendF(&result,
-                               " and will not work when the app moves to API level %d or later "
-                               "(%s#%s) (allowing for now because this app's target API level is "
-                               "still %d)",
-                               api_level, kBionicChangesUrl, doc_fragment,
-                               get_application_target_sdk_version());
-  DL_WARN("%s", result.c_str());
+  if (get_application_target_sdk_version() < target_sdk_version) {
+    android::base::StringAppendF(&result,
+                                 " and will not work when the app moves to "
+                                 "targetSdkVersion %d or later "
+                                 "(see https://android.googlesource.com/platform/bionic/+/main/"
+                                 "android-changes-for-ndk-developers.md); "
+                                 "allowing for now because this app's "
+                                 "targetSdkVersion is still %d",
+                                 target_sdk_version,
+                                 get_application_target_sdk_version());
+    DL_WARN("Warning: %s", result.c_str());
+    return false;
+  }
+  DL_ERR_AND_LOG("%s", result.c_str());
+  return true;
 }
diff --git a/linker/linker_globals.h b/linker/linker_globals.h
index 2bfdccd12..777e7b8b0 100644
--- a/linker/linker_globals.h
+++ b/linker/linker_globals.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include "linker_debug.h"
+
 #include <link.h>
 #include <stddef.h>
 
@@ -49,7 +51,7 @@
       async_safe_format_fd(2, "\n"); \
     } while (false)
 
-void DL_WARN_documented_change(int api_level, const char* doc_link, const char* fmt, ...);
+bool DL_ERROR_AFTER(int target_sdk_version, const char* fmt, ...) __printflike(2, 3);
 
 #define DL_ERR_AND_LOG(fmt, x...) \
   do { \
diff --git a/linker/linker_main.cpp b/linker/linker_main.cpp
index f65f82d5b..425bcda67 100644
--- a/linker/linker_main.cpp
+++ b/linker/linker_main.cpp
@@ -366,6 +366,7 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   }
   solinker->set_realpath(interp);
   init_link_map_head(*solinker);
+  init_sanitizer_mode(interp);
 
 #if defined(__aarch64__)
   __libc_init_mte(somain->memtag_dynamic_entries(), somain->phdr, somain->phnum, somain->load_bias);
@@ -435,9 +436,12 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
     ++ld_preloads_count;
   }
 
-  for_each_dt_needed(si, [&](const char* name) {
-    needed_library_name_list.push_back(name);
-  });
+  for (const ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
+    if (d->d_tag == DT_NEEDED) {
+      const char* name = fix_dt_needed(si->get_string(d->d_un.d_val), si->get_realpath());
+      needed_library_name_list.push_back(name);
+    }
+  }
 
   const char** needed_library_names = &needed_library_name_list[0];
   size_t needed_libraries_count = needed_library_name_list.size();
diff --git a/linker/linker_main.h b/linker/linker_main.h
index ffbcf0f73..bec9d3581 100644
--- a/linker/linker_main.h
+++ b/linker/linker_main.h
@@ -48,6 +48,7 @@ class ProtectedDataGuard {
 
 class ElfReader;
 
+void init_sanitizer_mode(const char *interp);
 std::vector<android_namespace_t*> init_default_namespaces(const char* executable_path);
 soinfo* soinfo_alloc(android_namespace_t* ns, const char* name,
                      const struct stat* file_stat, off64_t file_offset,
diff --git a/linker/linker_namespaces.cpp b/linker/linker_namespaces.cpp
index eb9dae97e..55168fda8 100644
--- a/linker/linker_namespaces.cpp
+++ b/linker/linker_namespaces.cpp
@@ -73,7 +73,7 @@ bool android_namespace_t::is_accessible(soinfo* s) {
   auto is_accessible_ftor = [this] (soinfo* si, bool allow_secondary) {
     // This is workaround for apps hacking into soinfo list.
     // and inserting their own entries into it. (http://b/37191433)
-    if (!si->has_min_version(3)) {
+    if (!si->is_lp64_or_has_min_version(3)) {
       DL_WARN("Warning: invalid soinfo version for \"%s\" (assuming inaccessible)",
               si->get_soname());
       return false;
diff --git a/linker/linker_note_gnu_property.cpp b/linker/linker_note_gnu_property.cpp
index 082a604ec..d221b8d6c 100644
--- a/linker/linker_note_gnu_property.cpp
+++ b/linker/linker_note_gnu_property.cpp
@@ -137,7 +137,7 @@ bool GnuPropertySection::Parse(const ElfW(NhdrGNUProperty)* note_nhdr, const cha
     // Loop on program property array.
     const ElfW(Prop)* property = reinterpret_cast<const ElfW(Prop)*>(&note_nhdr->n_desc[offset]);
     const ElfW(Word) property_size =
-        align_up(sizeof(ElfW(Prop)) + property->pr_datasz, sizeof(ElfW(Addr)));
+        __builtin_align_up(sizeof(ElfW(Prop)) + property->pr_datasz, sizeof(ElfW(Addr)));
     if ((note_nhdr->nhdr.n_descsz - offset) < property_size) {
       DL_ERR_AND_LOG(
           "\"%s\" .note.gnu.property: property descriptor size is "
diff --git a/linker/linker_note_gnu_property_test.cpp b/linker/linker_note_gnu_property_test.cpp
index 960118c68..2a5eddc41 100644
--- a/linker/linker_note_gnu_property_test.cpp
+++ b/linker/linker_note_gnu_property_test.cpp
@@ -107,7 +107,7 @@ class GnuPropertySectionBuilder {
   template <typename T>
   bool push(ElfW(Word) pr_type, ElfW(Word) pr_datasz, const T* pr_data) {
     // Must be aligned.
-    const uintptr_t addition = align_up(pr_datasz, sizeof(ElfW(Addr)));
+    const uintptr_t addition = __builtin_align_up(pr_datasz, sizeof(ElfW(Addr)));
     if ((offset() + addition) > kMaxSectionSize) {
       return false;
     }
diff --git a/linker/linker_phdr.cpp b/linker/linker_phdr.cpp
index e5369ac61..5967e2d48 100644
--- a/linker/linker_phdr.cpp
+++ b/linker/linker_phdr.cpp
@@ -159,8 +159,8 @@ static const size_t kPmdSize = (kPageSize / sizeof(uint64_t)) * kPageSize;
 ElfReader::ElfReader()
     : did_read_(false), did_load_(false), fd_(-1), file_offset_(0), file_size_(0), phdr_num_(0),
       phdr_table_(nullptr), shdr_table_(nullptr), shdr_num_(0), dynamic_(nullptr), strtab_(nullptr),
-      strtab_size_(0), load_start_(nullptr), load_size_(0), load_bias_(0), loaded_phdr_(nullptr),
-      mapped_by_caller_(false) {
+      strtab_size_(0), load_start_(nullptr), load_size_(0), load_bias_(0), max_align_(0), min_align_(0),
+      loaded_phdr_(nullptr), mapped_by_caller_(false) {
 }
 
 bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file_size) {
@@ -175,13 +175,14 @@ bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file
   if (ReadElfHeader() &&
       VerifyElfHeader() &&
       ReadProgramHeaders() &&
+      CheckProgramHeaderAlignment() &&
       ReadSectionHeaders() &&
       ReadDynamicSection() &&
       ReadPadSegmentNote()) {
     did_read_ = true;
   }
 
-  if (kPageSize == 0x4000 && phdr_table_get_minimum_alignment(phdr_table_, phdr_num_) == 0x1000) {
+  if (kPageSize == 16*1024 && min_align_ == 4096) {
     // This prop needs to be read on 16KiB devices for each ELF where min_palign is 4KiB.
     // It cannot be cached since the developer may toggle app compat on/off.
     // This check will be removed once app compat is made the default on 16KiB devices.
@@ -307,26 +308,17 @@ bool ElfReader::VerifyElfHeader() {
   }
 
   if (header_.e_shentsize != sizeof(ElfW(Shdr))) {
-    if (get_application_target_sdk_version() >= 26) {
-      DL_ERR_AND_LOG("\"%s\" has unsupported e_shentsize: 0x%x (expected 0x%zx)",
-                     name_.c_str(), header_.e_shentsize, sizeof(ElfW(Shdr)));
+    if (DL_ERROR_AFTER(26, "\"%s\" has unsupported e_shentsize: 0x%x (expected 0x%zx)",
+                       name_.c_str(), header_.e_shentsize, sizeof(ElfW(Shdr)))) {
       return false;
     }
-    DL_WARN_documented_change(26,
-                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
-                              "\"%s\" has unsupported e_shentsize 0x%x (expected 0x%zx)",
-                              name_.c_str(), header_.e_shentsize, sizeof(ElfW(Shdr)));
     add_dlwarning(name_.c_str(), "has invalid ELF header");
   }
 
   if (header_.e_shstrndx == 0) {
-    if (get_application_target_sdk_version() >= 26) {
-      DL_ERR_AND_LOG("\"%s\" has invalid e_shstrndx", name_.c_str());
+    if (DL_ERROR_AFTER(26, "\"%s\" has invalid e_shstrndx", name_.c_str())) {
       return false;
     }
-    DL_WARN_documented_change(26,
-                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
-                              "\"%s\" has invalid e_shstrndx", name_.c_str());
     add_dlwarning(name_.c_str(), "has invalid ELF header");
   }
 
@@ -433,40 +425,24 @@ bool ElfReader::ReadDynamicSection() {
   }
 
   if (pt_dynamic_offset != dynamic_shdr->sh_offset) {
-    if (get_application_target_sdk_version() >= 26) {
-      DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid offset: 0x%zx, "
-                     "expected to match PT_DYNAMIC offset: 0x%zx",
-                     name_.c_str(),
-                     static_cast<size_t>(dynamic_shdr->sh_offset),
-                     pt_dynamic_offset);
+    if (DL_ERROR_AFTER(26, "\"%s\" .dynamic section has invalid offset: 0x%zx, "
+                       "expected to match PT_DYNAMIC offset: 0x%zx",
+                       name_.c_str(),
+                       static_cast<size_t>(dynamic_shdr->sh_offset),
+                       pt_dynamic_offset)) {
       return false;
     }
-    DL_WARN_documented_change(26,
-                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
-                              "\"%s\" .dynamic section has invalid offset: 0x%zx "
-                              "(expected to match PT_DYNAMIC offset 0x%zx)",
-                              name_.c_str(),
-                              static_cast<size_t>(dynamic_shdr->sh_offset),
-                              pt_dynamic_offset);
     add_dlwarning(name_.c_str(), "invalid .dynamic section");
   }
 
   if (pt_dynamic_filesz != dynamic_shdr->sh_size) {
-    if (get_application_target_sdk_version() >= 26) {
-      DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid size: 0x%zx, "
-                     "expected to match PT_DYNAMIC filesz: 0x%zx",
-                     name_.c_str(),
-                     static_cast<size_t>(dynamic_shdr->sh_size),
-                     pt_dynamic_filesz);
+    if (DL_ERROR_AFTER(26, "\"%s\" .dynamic section has invalid size: 0x%zx "
+                       "(expected to match PT_DYNAMIC filesz 0x%zx)",
+                       name_.c_str(),
+                       static_cast<size_t>(dynamic_shdr->sh_size),
+                       pt_dynamic_filesz)) {
       return false;
     }
-    DL_WARN_documented_change(26,
-                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
-                              "\"%s\" .dynamic section has invalid size: 0x%zx "
-                              "(expected to match PT_DYNAMIC filesz 0x%zx)",
-                              name_.c_str(),
-                              static_cast<size_t>(dynamic_shdr->sh_size),
-                              pt_dynamic_filesz);
     add_dlwarning(name_.c_str(), "invalid .dynamic section");
   }
 
@@ -562,52 +538,34 @@ size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
   return max_vaddr - min_vaddr;
 }
 
-// Returns the maximum p_align associated with a loadable segment in the ELF
-// program header table. Used to determine whether the file should be loaded at
-// a specific virtual address alignment for use with huge pages.
-size_t phdr_table_get_maximum_alignment(const ElfW(Phdr)* phdr_table, size_t phdr_count) {
-  size_t maximum_alignment = page_size();
+bool ElfReader::CheckProgramHeaderAlignment() {
+  max_align_ = min_align_ = page_size();
 
-  for (size_t i = 0; i < phdr_count; ++i) {
-    const ElfW(Phdr)* phdr = &phdr_table[i];
+  for (size_t i = 0; i < phdr_num_; ++i) {
+    const ElfW(Phdr)* phdr = &phdr_table_[i];
 
-    // p_align must be 0, 1, or a positive, integral power of two.
-    if (phdr->p_type != PT_LOAD || ((phdr->p_align & (phdr->p_align - 1)) != 0)) {
+    if (phdr->p_type != PT_LOAD) {
       continue;
     }
 
-    maximum_alignment = std::max(maximum_alignment, static_cast<size_t>(phdr->p_align));
-  }
-
-#if defined(__LP64__)
-  return maximum_alignment;
-#else
-  return page_size();
-#endif
-}
-
-// Returns the minimum p_align associated with a loadable segment in the ELF
-// program header table. Used to determine if the program alignment is compatible
-// with the page size of this system.
-size_t phdr_table_get_minimum_alignment(const ElfW(Phdr)* phdr_table, size_t phdr_count) {
-  size_t minimum_alignment = page_size();
-
-  for (size_t i = 0; i < phdr_count; ++i) {
-    const ElfW(Phdr)* phdr = &phdr_table[i];
-
-    // p_align must be 0, 1, or a positive, integral power of two.
-    if (phdr->p_type != PT_LOAD || ((phdr->p_align & (phdr->p_align - 1)) != 0)) {
+    // For loadable segments, p_align must be 0, 1,
+    // or a positive, integral power of two.
+    // The kernel ignores loadable segments with other values,
+    // so we just warn rather than reject them.
+    if ((phdr->p_align & (phdr->p_align - 1)) != 0) {
+      DL_WARN("\"%s\" has invalid p_align %zx in phdr %zu", name_.c_str(),
+                     static_cast<size_t>(phdr->p_align), i);
       continue;
     }
 
-    if (phdr->p_align <= 1) {
-      continue;
-    }
+    max_align_ = std::max(max_align_, static_cast<size_t>(phdr->p_align));
 
-    minimum_alignment = std::min(minimum_alignment, static_cast<size_t>(phdr->p_align));
+    if (phdr->p_align > 1) {
+      min_align_ = std::min(min_align_, static_cast<size_t>(phdr->p_align));
+    }
   }
 
-  return minimum_alignment;
+  return true;
 }
 
 // Reserve a virtual address range such that if it's limits were extended to the next 2**align
@@ -628,24 +586,23 @@ static void* ReserveWithAlignmentPadding(size_t size, size_t mapping_align, size
   // Minimum alignment of shared library gap. For efficiency, this should match the second level
   // page size of the platform.
 #if defined(__LP64__)
-  constexpr size_t kGapAlignment = 1ul << 21;  // 2MB
-#else
-  constexpr size_t kGapAlignment = 0;
+  constexpr size_t kGapAlignment = 2 * 1024 * 1024;
 #endif
   // Maximum gap size, in the units of kGapAlignment.
   constexpr size_t kMaxGapUnits = 32;
   // Allocate enough space so that the end of the desired region aligned up is still inside the
   // mapping.
-  size_t mmap_size = align_up(size, mapping_align) + mapping_align - page_size();
+  size_t mmap_size = __builtin_align_up(size, mapping_align) + mapping_align - page_size();
   uint8_t* mmap_ptr =
       reinterpret_cast<uint8_t*>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1, 0));
   if (mmap_ptr == MAP_FAILED) {
     return nullptr;
   }
   size_t gap_size = 0;
-  size_t first_byte = reinterpret_cast<size_t>(align_up(mmap_ptr, mapping_align));
-  size_t last_byte = reinterpret_cast<size_t>(align_down(mmap_ptr + mmap_size, mapping_align) - 1);
-  if (kGapAlignment && first_byte / kGapAlignment != last_byte / kGapAlignment) {
+  size_t first_byte = reinterpret_cast<size_t>(__builtin_align_up(mmap_ptr, mapping_align));
+  size_t last_byte = reinterpret_cast<size_t>(__builtin_align_down(mmap_ptr + mmap_size, mapping_align) - 1);
+#if defined(__LP64__)
+  if (first_byte / kGapAlignment != last_byte / kGapAlignment) {
     // This library crosses a 2MB boundary and will fragment a new huge page.
     // Lets take advantage of that and insert a random number of inaccessible huge pages before that
     // to improve address randomization and make it harder to locate this library code by probing.
@@ -653,23 +610,24 @@ static void* ReserveWithAlignmentPadding(size_t size, size_t mapping_align, size
     mapping_align = std::max(mapping_align, kGapAlignment);
     gap_size =
         kGapAlignment * (is_first_stage_init() ? 1 : arc4random_uniform(kMaxGapUnits - 1) + 1);
-    mmap_size = align_up(size + gap_size, mapping_align) + mapping_align - page_size();
+    mmap_size = __builtin_align_up(size + gap_size, mapping_align) + mapping_align - page_size();
     mmap_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1, 0));
     if (mmap_ptr == MAP_FAILED) {
       return nullptr;
     }
   }
+#endif
 
-  uint8_t *gap_end, *gap_start;
+  uint8_t* gap_end = mmap_ptr + mmap_size;
+#if defined(__LP64__)
   if (gap_size) {
-    gap_end = align_down(mmap_ptr + mmap_size, kGapAlignment);
-    gap_start = gap_end - gap_size;
-  } else {
-    gap_start = gap_end = mmap_ptr + mmap_size;
+    gap_end = __builtin_align_down(gap_end, kGapAlignment);
   }
+#endif
+  uint8_t* gap_start = gap_end - gap_size;
 
-  uint8_t* first = align_up(mmap_ptr, mapping_align);
-  uint8_t* last = align_down(gap_start, mapping_align) - size;
+  uint8_t* first = __builtin_align_up(mmap_ptr, mapping_align);
+  uint8_t* last = __builtin_align_down(gap_start, mapping_align) - size;
 
   // arc4random* is not available in first stage init because /dev/urandom hasn't yet been
   // created. Don't randomize then.
@@ -717,10 +675,9 @@ bool ElfReader::ReserveAddressSpace(address_space_params* address_space) {
     }
     size_t start_alignment = page_size();
     if (get_transparent_hugepages_supported() && get_application_target_sdk_version() >= 31) {
-      size_t maximum_alignment = phdr_table_get_maximum_alignment(phdr_table_, phdr_num_);
       // Limit alignment to PMD size as other alignments reduce the number of
       // bits available for ASLR for no benefit.
-      start_alignment = maximum_alignment == kPmdSize ? kPmdSize : page_size();
+      start_alignment = max_align_ == kPmdSize ? kPmdSize : page_size();
     }
     start = ReserveWithAlignmentPadding(load_size_, kLibraryAlignment, start_alignment, &gap_start_,
                                         &gap_size_);
@@ -792,22 +749,29 @@ bool ElfReader::ReadPadSegmentNote() {
       continue;
     }
 
-    // If the PT_NOTE extends beyond the file. The ELF is doing something
-    // strange -- obfuscation, embedding hidden loaders, ...
-    //
-    // It doesn't contain the pad_segment note. Skip it to avoid SIGBUS
-    // by accesses beyond the file.
-    off64_t note_end_off = file_offset_ + phdr->p_offset + phdr->p_filesz;
-    if (note_end_off > file_size_) {
-      continue;
+    // Reject notes that claim to extend past the end of the file.
+    off64_t note_end_off = file_offset_;
+    if (__builtin_add_overflow(note_end_off, phdr->p_offset, &note_end_off) ||
+        __builtin_add_overflow(note_end_off, phdr->p_filesz, &note_end_off) ||
+        phdr->p_filesz != phdr->p_memsz ||
+        note_end_off > file_size_) {
+
+      if (get_application_target_sdk_version() < 37) {
+        // Some in-market apps have invalid ELF notes (http://b/390328213),
+        // so ignore them until/unless they bump their target sdk version.
+        continue;
+      }
+
+      DL_ERR_AND_LOG("\"%s\": ELF note (phdr %zu) runs off end of file", name_.c_str(), i);
+      return false;
     }
 
-    // note_fragment is scoped to within the loop so that there is
-    // at most 1 PT_NOTE mapped at anytime during this search.
+    // We scope note_fragment to within the loop so that there is
+    // at most one PT_NOTE mapped at any time.
     MappedFileFragment note_fragment;
-    if (!note_fragment.Map(fd_, file_offset_, phdr->p_offset, phdr->p_memsz)) {
+    if (!note_fragment.Map(fd_, file_offset_, phdr->p_offset, phdr->p_filesz)) {
       DL_ERR("\"%s\": PT_NOTE mmap(nullptr, %p, PROT_READ, MAP_PRIVATE, %d, %p) failed: %m",
-             name_.c_str(), reinterpret_cast<void*>(phdr->p_memsz), fd_,
+             name_.c_str(), reinterpret_cast<void*>(phdr->p_filesz), fd_,
              reinterpret_cast<void*>(page_start(file_offset_ + phdr->p_offset)));
       return false;
     }
@@ -821,7 +785,7 @@ bool ElfReader::ReadPadSegmentNote() {
     }
 
     if (note_hdr->n_descsz != sizeof(ElfW(Word))) {
-      DL_ERR("\"%s\" NT_ANDROID_TYPE_PAD_SEGMENT note has unexpected n_descsz: %u",
+      DL_ERR("\"%s\": NT_ANDROID_TYPE_PAD_SEGMENT note has unexpected n_descsz: %u",
              name_.c_str(), reinterpret_cast<unsigned int>(note_hdr->n_descsz));
       return false;
     }
@@ -1011,13 +975,12 @@ bool ElfReader::LoadSegments() {
   // are not 16KiB aligned.
   size_t seg_align = should_use_16kib_app_compat_ ? kCompatPageSize : kPageSize;
 
-  size_t min_palign = phdr_table_get_minimum_alignment(phdr_table_, phdr_num_);
   // Only enforce this on 16 KB systems with app compat disabled.
   // Apps may rely on undefined behavior here on 4 KB systems,
   // which is the norm before this change is introduced
-  if (kPageSize >= 16384 && min_palign < kPageSize && !should_use_16kib_app_compat_) {
-    DL_ERR("\"%s\" program alignment (%zu) cannot be smaller than system page size (%zu)",
-           name_.c_str(), min_palign, kPageSize);
+  if (kPageSize >= 16384 && min_align_ < kPageSize && !should_use_16kib_app_compat_) {
+    DL_ERR_AND_LOG("\"%s\" program alignment (%zu) cannot be smaller than system page size (%zu)",
+                   name_.c_str(), min_align_, kPageSize);
     return false;
   }
 
@@ -1042,7 +1005,7 @@ bool ElfReader::LoadSegments() {
     ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
     ElfW(Addr) seg_end = seg_start + p_memsz;
 
-    ElfW(Addr) seg_page_end = align_up(seg_end, seg_align);
+    ElfW(Addr) seg_page_end = __builtin_align_up(seg_end, seg_align);
 
     ElfW(Addr) seg_file_end = seg_start + p_filesz;
 
@@ -1050,7 +1013,7 @@ bool ElfReader::LoadSegments() {
     ElfW(Addr) file_start = phdr->p_offset;
     ElfW(Addr) file_end = file_start + p_filesz;
 
-    ElfW(Addr) file_page_start = align_down(file_start, seg_align);
+    ElfW(Addr) file_page_start = __builtin_align_down(file_start, seg_align);
     ElfW(Addr) file_length = file_end - file_page_start;
 
     if (file_size_ <= 0) {
@@ -1070,15 +1033,10 @@ bool ElfReader::LoadSegments() {
     if (file_length != 0) {
       int prot = PFLAGS_TO_PROT(phdr->p_flags);
       if ((prot & (PROT_EXEC | PROT_WRITE)) == (PROT_EXEC | PROT_WRITE)) {
-        // W + E PT_LOAD segments are not allowed in O.
-        if (get_application_target_sdk_version() >= 26) {
-          DL_ERR_AND_LOG("\"%s\": W+E load segments are not allowed", name_.c_str());
+        if (DL_ERROR_AFTER(26, "\"%s\" has load segments that are both writable and executable",
+                           name_.c_str())) {
           return false;
         }
-        DL_WARN_documented_change(26,
-                                  "writable-and-executable-segments-enforced-for-api-level-26",
-                                  "\"%s\" has load segments that are both writable and executable",
-                                  name_.c_str());
         add_dlwarning(name_.c_str(), "W+E load segments");
       }
 
diff --git a/linker/linker_phdr.h b/linker/linker_phdr.h
index e15ece419..3b68528e7 100644
--- a/linker/linker_phdr.h
+++ b/linker/linker_phdr.h
@@ -76,6 +76,7 @@ class ElfReader {
   [[nodiscard]] bool ReadElfHeader();
   [[nodiscard]] bool VerifyElfHeader();
   [[nodiscard]] bool ReadProgramHeaders();
+  [[nodiscard]] bool CheckProgramHeaderAlignment();
   [[nodiscard]] bool ReadSectionHeaders();
   [[nodiscard]] bool ReadDynamicSection();
   [[nodiscard]] bool ReadPadSegmentNote();
@@ -130,6 +131,10 @@ class ElfReader {
   // Load bias.
   ElfW(Addr) load_bias_;
 
+  // Maximum and minimum alignment requirements across all phdrs.
+  size_t max_align_;
+  size_t min_align_;
+
   // Loaded phdr.
   const ElfW(Phdr)* loaded_phdr_;
 
@@ -153,9 +158,6 @@ class ElfReader {
 size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr)* min_vaddr = nullptr, ElfW(Addr)* max_vaddr = nullptr);
 
-size_t phdr_table_get_maximum_alignment(const ElfW(Phdr)* phdr_table, size_t phdr_count);
-size_t phdr_table_get_minimum_alignment(const ElfW(Phdr)* phdr_table, size_t phdr_count);
-
 int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr) load_bias, bool should_pad_segments,
                                 bool should_use_16kib_app_compat,
diff --git a/linker/linker_phdr_16kib_compat.cpp b/linker/linker_phdr_16kib_compat.cpp
index bad20baef..d3783cf2e 100644
--- a/linker/linker_phdr_16kib_compat.cpp
+++ b/linker/linker_phdr_16kib_compat.cpp
@@ -158,7 +158,7 @@ bool ElfReader::IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr) {
   }
 
   if (!relro_phdr) {
-    *vaddr = align_down(first_rw->p_vaddr, kCompatPageSize);
+    *vaddr = __builtin_align_down(first_rw->p_vaddr, kCompatPageSize);
     return true;
   }
 
@@ -175,7 +175,7 @@ bool ElfReader::IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr) {
     return false;
   }
 
-  *vaddr = align_up(end, kCompatPageSize);
+  *vaddr = __builtin_align_up(end, kCompatPageSize);
   return true;
 }
 
@@ -227,11 +227,11 @@ bool ElfReader::CompatMapSegment(size_t seg_idx, size_t len) {
   // will lead to overwriting adjacent segments since the ELF's segment(s)
   // are not 16KiB aligned.
 
-  void* start = reinterpret_cast<void*>(align_down(phdr->p_vaddr + load_bias_, kCompatPageSize));
+  void* start = reinterpret_cast<void*>(__builtin_align_down(phdr->p_vaddr + load_bias_, kCompatPageSize));
 
   // The ELF could be being loaded directly from a zipped APK,
   // the zip offset must be added to find the segment offset.
-  const ElfW(Addr) offset = file_offset_ + align_down(phdr->p_offset, kCompatPageSize);
+  const ElfW(Addr) offset = file_offset_ + __builtin_align_down(phdr->p_offset, kCompatPageSize);
 
   CHECK(should_use_16kib_app_compat_);
 
diff --git a/linker/linker_relocate.cpp b/linker/linker_relocate.cpp
index bbf83590b..94281cb4f 100644
--- a/linker/linker_relocate.cpp
+++ b/linker/linker_relocate.cpp
@@ -605,7 +605,7 @@ bool soinfo::relocate(const SymbolLookupList& lookup_list) {
   Relocator relocator(version_tracker, lookup_list);
   relocator.si = this;
   relocator.si_strtab = strtab_;
-  relocator.si_strtab_size = has_min_version(1) ? strtab_size_ : SIZE_MAX;
+  relocator.si_strtab_size = is_lp64_or_has_min_version(1) ? strtab_size_ : SIZE_MAX;
   relocator.si_symtab = symtab_;
   relocator.tlsdesc_args = &tlsdesc_args_;
   relocator.tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();
diff --git a/linker/linker_soinfo.cpp b/linker/linker_soinfo.cpp
index 176c13334..b3b9da3a8 100644
--- a/linker/linker_soinfo.cpp
+++ b/linker/linker_soinfo.cpp
@@ -217,7 +217,7 @@ soinfo::~soinfo() {
 }
 
 void soinfo::set_dt_runpath(const char* path) {
-  if (!has_min_version(3)) {
+  if (!is_lp64_or_has_min_version(3)) {
     return;
   }
 
@@ -244,35 +244,19 @@ const ElfW(Versym)* soinfo::get_versym(size_t n) const {
 }
 
 ElfW(Addr) soinfo::get_verneed_ptr() const {
-  if (has_min_version(2)) {
-    return verneed_ptr_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(2)? verneed_ptr_ : 0;
 }
 
 size_t soinfo::get_verneed_cnt() const {
-  if (has_min_version(2)) {
-    return verneed_cnt_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(2) ? verneed_cnt_ : 0;
 }
 
 ElfW(Addr) soinfo::get_verdef_ptr() const {
-  if (has_min_version(2)) {
-    return verdef_ptr_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(2) ? verdef_ptr_ : 0;
 }
 
 size_t soinfo::get_verdef_cnt() const {
-  if (has_min_version(2)) {
-    return verdef_cnt_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(2) ? verdef_cnt_ : 0;
 }
 
 SymbolLookupLib soinfo::get_lookup_lib() {
@@ -530,14 +514,14 @@ void soinfo::call_destructors() {
 }
 
 void soinfo::add_child(soinfo* child) {
-  if (has_min_version(0)) {
+  if (is_lp64_or_has_min_version(0)) {
     child->parents_.push_back(this);
     this->children_.push_back(child);
   }
 }
 
 void soinfo::remove_all_links() {
-  if (!has_min_version(0)) {
+  if (!is_lp64_or_has_min_version(0)) {
     return;
   }
 
@@ -571,47 +555,27 @@ void soinfo::remove_all_links() {
 }
 
 dev_t soinfo::get_st_dev() const {
-  if (has_min_version(0)) {
-    return st_dev_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(0) ? st_dev_ : 0;
 };
 
 ino_t soinfo::get_st_ino() const {
-  if (has_min_version(0)) {
-    return st_ino_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(0) ? st_ino_ : 0;
 }
 
 off64_t soinfo::get_file_offset() const {
-  if (has_min_version(1)) {
-    return file_offset_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(1) ? file_offset_ : 0;
 }
 
 uint32_t soinfo::get_rtld_flags() const {
-  if (has_min_version(1)) {
-    return rtld_flags_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(1) ? rtld_flags_ : 0;
 }
 
 uint32_t soinfo::get_dt_flags_1() const {
-  if (has_min_version(1)) {
-    return dt_flags_1_;
-  }
-
-  return 0;
+  return is_lp64_or_has_min_version(1) ? dt_flags_1_ : 0;
 }
 
 void soinfo::set_dt_flags_1(uint32_t dt_flags_1) {
-  if (has_min_version(1)) {
+  if (is_lp64_or_has_min_version(1)) {
     if ((dt_flags_1 & DF_1_GLOBAL) != 0) {
       rtld_flags_ |= RTLD_GLOBAL;
     }
@@ -629,47 +593,33 @@ void soinfo::set_nodelete() {
 }
 
 void soinfo::set_realpath(const char* path) {
-#if defined(__work_around_b_24465209__)
-  if (has_min_version(2)) {
+  if (is_lp64_or_has_min_version(2)) {
     realpath_ = path;
   }
-#else
-  realpath_ = path;
-#endif
 }
 
 const char* soinfo::get_realpath() const {
-#if defined(__work_around_b_24465209__)
-  if (has_min_version(2)) {
-    return realpath_.c_str();
-  } else {
-    return old_name_;
-  }
-#else
+#if defined(__LP64__)
   return realpath_.c_str();
+#else
+  return is_lp64_or_has_min_version(2) ? realpath_.c_str() : old_name_;
 #endif
 }
 
 void soinfo::set_soname(const char* soname) {
-#if defined(__work_around_b_24465209__)
-  if (has_min_version(2)) {
+  if (is_lp64_or_has_min_version(2)) {
     soname_ = soname;
   }
+#if !defined(__LP64__)
   strlcpy(old_name_, soname_.c_str(), sizeof(old_name_));
-#else
-  soname_ = soname;
 #endif
 }
 
 const char* soinfo::get_soname() const {
-#if defined(__work_around_b_24465209__)
-  if (has_min_version(2)) {
-    return soname_.c_str();
-  } else {
-    return old_name_;
-  }
-#else
+#if defined(__LP64__)
   return soname_.c_str();
+#else
+  return is_lp64_or_has_min_version(2) ? soname_.c_str() : old_name_;
 #endif
 }
 
@@ -678,59 +628,39 @@ const char* soinfo::get_soname() const {
 static soinfo_list_t g_empty_list;
 
 soinfo_list_t& soinfo::get_children() {
-  if (has_min_version(0)) {
-    return children_;
-  }
-
-  return g_empty_list;
+  return is_lp64_or_has_min_version(0) ? children_ : g_empty_list;
 }
 
 const soinfo_list_t& soinfo::get_children() const {
-  if (has_min_version(0)) {
-    return children_;
-  }
-
-  return g_empty_list;
+  return is_lp64_or_has_min_version(0) ? children_ : g_empty_list;
 }
 
 soinfo_list_t& soinfo::get_parents() {
-  if (has_min_version(0)) {
-    return parents_;
-  }
-
-  return g_empty_list;
+  return is_lp64_or_has_min_version(0) ? parents_ : g_empty_list;
 }
 
 static std::vector<std::string> g_empty_runpath;
 
 const std::vector<std::string>& soinfo::get_dt_runpath() const {
-  if (has_min_version(3)) {
-    return dt_runpath_;
-  }
-
-  return g_empty_runpath;
+  return is_lp64_or_has_min_version(3) ? dt_runpath_ : g_empty_runpath;
 }
 
 android_namespace_t* soinfo::get_primary_namespace() {
-  if (has_min_version(3)) {
-    return primary_namespace_;
-  }
-
-  return &g_default_namespace;
+  return is_lp64_or_has_min_version(3) ? primary_namespace_ : &g_default_namespace;
 }
 
 void soinfo::add_secondary_namespace(android_namespace_t* secondary_ns) {
-  CHECK(has_min_version(3));
+  CHECK(is_lp64_or_has_min_version(3));
   secondary_namespaces_.push_back(secondary_ns);
 }
 
 android_namespace_list_t& soinfo::get_secondary_namespaces() {
-  CHECK(has_min_version(3));
+  CHECK(is_lp64_or_has_min_version(3));
   return secondary_namespaces_;
 }
 
 const char* soinfo::get_string(ElfW(Word) index) const {
-  if (has_min_version(1) && (index >= strtab_size_)) {
+  if (is_lp64_or_has_min_version(1) && (index >= strtab_size_)) {
     async_safe_fatal("%s: strtab out of bounds error; STRSZ=%zd, name=%d",
         get_realpath(), strtab_size_, index);
   }
@@ -811,9 +741,9 @@ bool soinfo::is_mapped_by_caller() const {
 
 // This function returns api-level at the time of
 // dlopen/load. Note that libraries opened by system
-// will always have 'current' api level.
+// will always have 'current' target sdk version.
 int soinfo::get_target_sdk_version() const {
-  if (!has_min_version(2)) {
+  if (!is_lp64_or_has_min_version(2)) {
     return __ANDROID_API__;
   }
 
@@ -821,13 +751,13 @@ int soinfo::get_target_sdk_version() const {
 }
 
 uintptr_t soinfo::get_handle() const {
-  CHECK(has_min_version(3));
+  CHECK(is_lp64_or_has_min_version(3));
   CHECK(handle_ != 0);
   return handle_;
 }
 
 void* soinfo::to_handle() {
-  if (get_application_target_sdk_version() < 24 || !has_min_version(3)) {
+  if (get_application_target_sdk_version() < 24 || !is_lp64_or_has_min_version(3)) {
     return this;
   }
 
@@ -835,7 +765,7 @@ void* soinfo::to_handle() {
 }
 
 void soinfo::generate_handle() {
-  CHECK(has_min_version(3));
+  CHECK(is_lp64_or_has_min_version(3));
   CHECK(handle_ == 0); // Make sure this is the first call
 
   // Make sure the handle is unique and does not collide
@@ -861,20 +791,20 @@ void soinfo::generate_handle() {
 }
 
 void soinfo::set_gap_start(ElfW(Addr) gap_start) {
-  CHECK(has_min_version(6));
+  CHECK(is_lp64_or_has_min_version(6));
   gap_start_ = gap_start;
 }
 ElfW(Addr) soinfo::get_gap_start() const {
-  CHECK(has_min_version(6));
+  CHECK(is_lp64_or_has_min_version(6));
   return gap_start_;
 }
 
 void soinfo::set_gap_size(size_t gap_size) {
-  CHECK(has_min_version(6));
+  CHECK(is_lp64_or_has_min_version(6));
   gap_size_ = gap_size;
 }
 size_t soinfo::get_gap_size() const {
-  CHECK(has_min_version(6));
+  CHECK(is_lp64_or_has_min_version(6));
   return gap_size_;
 }
 
diff --git a/linker/linker_soinfo.h b/linker/linker_soinfo.h
index 4d0267643..8f56c9fa8 100644
--- a/linker/linker_soinfo.h
+++ b/linker/linker_soinfo.h
@@ -154,31 +154,27 @@ struct soinfo_tls {
   size_t module_id = kTlsUninitializedModuleId;
 };
 
-#if defined(__work_around_b_24465209__)
-#define SOINFO_NAME_LEN 128
-#endif
-
 struct soinfo {
-#if defined(__work_around_b_24465209__)
+#if !defined(__LP64__)
  private:
-  char old_name_[SOINFO_NAME_LEN];
+  char old_name_[128];
 #endif
  public:
   const ElfW(Phdr)* phdr;
   size_t phnum;
-#if defined(__work_around_b_24465209__)
+#if !defined(__LP64__)
   ElfW(Addr) unused0; // DO NOT USE, maintained for compatibility.
 #endif
   ElfW(Addr) base;
   size_t size;
 
-#if defined(__work_around_b_24465209__)
+#if !defined(__LP64__)
   uint32_t unused1;  // DO NOT USE, maintained for compatibility.
 #endif
 
   ElfW(Dyn)* dynamic;
 
-#if defined(__work_around_b_24465209__)
+#if !defined(__LP64__)
   uint32_t unused2; // DO NOT USE, maintained for compatibility
   uint32_t unused3; // DO NOT USE, maintained for compatibility
 #endif
@@ -294,19 +290,16 @@ struct soinfo {
   bool can_unload() const;
   bool is_gnu_hash() const;
 
-  bool inline has_min_version(uint32_t min_version __unused) const {
-#if defined(__work_around_b_24465209__)
-    return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
-#else
-    // If you make this return non-true in the case where
-    // __work_around_b_24465209__ is not defined, you will have to change
-    // memtag_dynamic_entries() and vma_names().
+  inline bool is_lp64_or_has_min_version(uint32_t min_version __unused) const {
+#if defined(__LP64__)
     return true;
+#else
+    return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
 #endif
   }
 
   const ElfW(Versym)* get_versym_table() const {
-    return has_min_version(2) ? versym_ : nullptr;
+    return is_lp64_or_has_min_version(2) ? versym_ : nullptr;
   }
 
   bool is_linked() const;
@@ -343,7 +336,7 @@ struct soinfo {
   android_namespace_list_t& get_secondary_namespaces();
 
   soinfo_tls* get_tls() const {
-    return has_min_version(5) ? tls_.get() : nullptr;
+    return is_lp64_or_has_min_version(5) ? tls_.get() : nullptr;
   }
 
   void set_mapped_by_caller(bool reserved_map);
@@ -362,13 +355,11 @@ struct soinfo {
   size_t get_gap_size() const;
 
   const memtag_dynamic_entries_t* memtag_dynamic_entries() const {
-#ifdef __aarch64__
-#ifdef __work_around_b_24465209__
-#error "Assuming aarch64 does not use versioned soinfo."
-#endif
+#if defined(__aarch64__)
     return &memtag_dynamic_entries_;
-#endif
+#else
     return nullptr;
+#endif
   }
   void* memtag_globals() const {
     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
@@ -403,13 +394,11 @@ struct soinfo {
     return !is_linker() && memtag_globals() && memtag_globalssz() > 0 && __libc_mte_enabled();
   }
   std::list<std::string>* vma_names() {
-#ifdef __aarch64__
-#ifdef __work_around_b_24465209__
-#error "Assuming aarch64 does not use versioned soinfo."
-#endif
+#if defined(__aarch64__)
     return &vma_names_;
-#endif
+#else
     return nullptr;
+#endif
 };
 
   void set_should_use_16kib_app_compat(bool should_use_16kib_app_compat) {
@@ -524,14 +513,5 @@ uint32_t calculate_elf_hash(const char* name);
 
 const char* fix_dt_needed(const char* dt_needed, const char* sopath);
 
-template<typename F>
-void for_each_dt_needed(const soinfo* si, F action) {
-  for (const ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
-    if (d->d_tag == DT_NEEDED) {
-      action(fix_dt_needed(si->get_string(d->d_un.d_val), si->get_realpath()));
-    }
-  }
-}
-
 const ElfW(Sym)* soinfo_do_lookup(const char* name, const version_info* vi,
                                   soinfo** si_found_in, const SymbolLookupList& lookup_list);
diff --git a/linker/linker_test_globals.cpp b/linker/linker_test_globals.cpp
index 27ec6f7ec..5b4ffe325 100644
--- a/linker/linker_test_globals.cpp
+++ b/linker/linker_test_globals.cpp
@@ -27,7 +27,7 @@
  */
 
 // Stub some symbols to avoid linking issues
-void DL_WARN_documented_change(int api_level [[maybe_unused]],
-                               const char* doc_link [[maybe_unused]],
-                               const char* fmt [[maybe_unused]], ...) {}
-
+bool DL_ERROR_AFTER(int target_sdk_version [[maybe_unused]],
+                    const char* fmt [[maybe_unused]], ...) {
+  return false;
+}
diff --git a/tests/Android.bp b/tests/Android.bp
index a97f5a824..4509cc4bd 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -94,6 +94,13 @@ cc_defaults {
 // Prebuilt shared libraries for use in tests.
 // -----------------------------------------------------------------------------
 
+filegroup {
+    name: "bionic_prebuilt_test_elf_files_arm64",
+    srcs: [
+        "prebuilt-elf-files/arm64/*.so",
+    ],
+}
+
 cc_prebuilt_test_library_shared {
     name: "libtest_invalid-rw_load_segment",
     strip: {
@@ -372,9 +379,6 @@ cc_test_library {
         "bionic_tests_defaults",
         "large_system_property_node_defaults",
     ],
-    tidy_disabled_srcs: [
-        "malloc_test.cpp", // timed out with clang-tidy, and too many warnings
-    ],
     srcs: [
         "__aeabi_read_tp_test.cpp",
         "__cxa_atexit_test.cpp",
@@ -650,7 +654,6 @@ cc_defaults {
     static_libs: [
         "libbase",
     ],
-    tidy: false,
     target: {
         musl: {
             // Musl doesn't have fortify
@@ -659,12 +662,12 @@ cc_defaults {
     },
 }
 
-// Ensure we don't use FORTIFY'ed functions with the static analyzer/clang-tidy:
+// Ensure we don't use FORTIFY'ed functions with the clang static analyzer:
 // it can confuse these tools pretty easily. If this builds successfully, then
 // __clang_analyzer__ overrode FORTIFY. Otherwise, FORTIFY was incorrectly
 // enabled. The library that results from building this is meant to be unused.
 cc_test_library {
-    name: "fortify_disabled_for_tidy",
+    name: "fortify_disabled_for_clang_analyzer",
     defaults: [
         "bionic_clang_fortify_tests_w_flags",
     ],
@@ -674,7 +677,6 @@ cc_test_library {
         "-D__clang_analyzer__",
     ],
     srcs: ["clang_fortify_tests.cpp"],
-    tidy: false,
 }
 
 cc_test_library {
@@ -716,7 +718,6 @@ cc_defaults {
         "-U_FORTIFY_SOURCE",
     ],
     srcs: ["clang_fortify_tests.cpp"],
-    tidy: false,
 }
 
 cc_test_library {
@@ -765,7 +766,6 @@ cc_defaults {
     srcs: [
         "clang_fortify_c_only_tests.c",
     ],
-    tidy: false,
     shared: {
         enabled: false,
     },
@@ -1124,7 +1124,7 @@ cc_test {
     defaults: [
         "bionic_unit_tests_defaults",
     ],
-    test_suites: ["device-tests"],
+    test_suites: ["general-tests"],
     data: [
         ":libdlext_test_runpath_zip_zipaligned",
         ":libdlext_test_zip_zipaligned",
@@ -1152,7 +1152,7 @@ cc_defaults {
         "libtest_simple_hwasan_nohwasan",
     ],
     header_libs: ["bionic_libc_platform_headers"],
-    test_suites: ["device-tests"],
+    test_suites: ["general-tests"],
 }
 
 cc_test {
@@ -1203,7 +1203,7 @@ cc_test {
         "testbinary_is_stack_mte_after_dlopen",
     ],
     header_libs: ["bionic_libc_platform_headers"],
-    test_suites: ["device-tests"],
+    test_suites: ["general-tests"],
 }
 
 cc_test {
@@ -1232,7 +1232,7 @@ cc_test {
         "memtag_stack_abi_test.cpp",
     ],
     header_libs: ["bionic_libc_platform_headers"],
-    test_suites: ["device-tests"],
+    test_suites: ["general-tests"],
 }
 
 cc_test {
@@ -1276,7 +1276,7 @@ cc_test {
     name: "bionic-unit-tests-static",
     gtest: false,
     defaults: ["bionic_tests_defaults"],
-    test_suites: ["device-tests"],
+    test_suites: ["general-tests"],
     host_supported: false,
 
     srcs: [
@@ -1412,16 +1412,7 @@ cc_test_host {
 
 cc_defaults {
     name: "bionic_compile_time_tests_defaults",
-    enabled: false,
-    target: {
-        linux_x86: {
-            enabled: true,
-        },
-        linux_x86_64: {
-            enabled: true,
-        },
-    },
-    tidy: false,
+    enabled: true,
     clang_verify: true,
     cflags: [
         "-Wall",
@@ -1454,3 +1445,13 @@ cc_library_static {
         "-D_FORTIFY_SOURCE=2",
     ],
 }
+
+cc_library_static {
+    name: "bionic-compile-time-tests3-clang++",
+    defaults: [
+        "bionic_compile_time_tests_defaults",
+    ],
+    cppflags: [
+        "-D_FORTIFY_SOURCE=3",
+    ],
+}
diff --git a/tests/android_unsafe_frame_pointer_chase_test.cpp b/tests/android_unsafe_frame_pointer_chase_test.cpp
index 7fa50e149..409cfabc0 100644
--- a/tests/android_unsafe_frame_pointer_chase_test.cpp
+++ b/tests/android_unsafe_frame_pointer_chase_test.cpp
@@ -124,6 +124,7 @@ static void* SignalBacktraceThread(void* sp) {
   sigaction(SIGRTMIN, &s, nullptr);
 
   raise(SIGRTMIN);
+  sigaltstack(nullptr, nullptr);
   return nullptr;
 }
 
@@ -155,4 +156,25 @@ TEST(android_unsafe_frame_pointer_chase, sigaltstack) {
   munmap(stacks, kStackSize * 2);
 }
 
+static void* SigaltstackOnCallerStack(void*) {
+  char altstack[kStackSize];
+  SignalBacktraceThread(altstack);
+  EXPECT_TRUE(g_handler_called);
+  EXPECT_EQ(nullptr, g_handler_tester_result);
+  g_handler_called = false;
+  return nullptr;
+}
+
+TEST(android_unsafe_frame_pointer_chase, sigaltstack_on_main_thread) {
+  SigaltstackOnCallerStack(nullptr);
+}
+
+TEST(android_unsafe_frame_pointer_chase, sigaltstack_on_pthread) {
+  pthread_t t;
+  ASSERT_EQ(0, pthread_create(&t, nullptr, SigaltstackOnCallerStack, nullptr));
+  void* retval;
+  ASSERT_EQ(0, pthread_join(t, &retval));
+  EXPECT_EQ(nullptr, retval);
+}
+
 #endif // __BIONIC__
diff --git a/tests/complex_test.cpp b/tests/complex_test.cpp
index ed0109a21..456efa757 100644
--- a/tests/complex_test.cpp
+++ b/tests/complex_test.cpp
@@ -28,6 +28,10 @@
 // have to be naughty.
 #include "../libc/include/complex.h"
 
+// Ensure that libc++'s complex.h and __fwd/complex.h headers are no-ops.
+#define _LIBCPP_COMPLEX_H
+#define _LIBCPP___FWD_COMPLEX_H
+
 // (libc++ also seems to have really bad implementations of its own that ignore
 // the intricacies of floating point math.)
 // http://llvm.org/bugs/show_bug.cgi?id=21504
diff --git a/tests/cpu_target_features_test.cpp b/tests/cpu_target_features_test.cpp
index d77377251..3458bca9e 100644
--- a/tests/cpu_target_features_test.cpp
+++ b/tests/cpu_target_features_test.cpp
@@ -54,3 +54,15 @@ TEST(cpu_target_features, has_expected_aarch64_compiler_values) {
   GTEST_SKIP() << "Not targeting an aarch64 architecture.";
 #endif
 }
+
+TEST(cpu_target_features, has_expected_arm_compiler_values) {
+#if defined(__arm__)
+  ExecTestHelper eth;
+  char* const argv[] = {nullptr};
+  const auto invocation = [&] { execvp("cpu-target-features", argv); };
+  eth.Run(invocation, 0, "(^|\n)__ARM_FEATURE_AES=1($|\n)");
+  eth.Run(invocation, 0, "(^|\n)__ARM_FEATURE_CRC32=1($|\n)");
+#else
+  GTEST_SKIP() << "Not targeting an arm architecture.";
+#endif
+}
diff --git a/tests/dlext_private.h b/tests/dlext_private_tests.h
similarity index 100%
rename from tests/dlext_private.h
rename to tests/dlext_private_tests.h
diff --git a/tests/dlext_test.cpp b/tests/dlext_test.cpp
index 8b26cb0d4..b5bf7538b 100644
--- a/tests/dlext_test.cpp
+++ b/tests/dlext_test.cpp
@@ -44,7 +44,7 @@
 #include "bionic/mte.h"
 #include "bionic/page.h"
 #include "core_shared_libs.h"
-#include "dlext_private.h"
+#include "dlext_private_tests.h"
 #include "dlfcn_symlink_support.h"
 #include "gtest_globals.h"
 #include "utils.h"
@@ -968,7 +968,6 @@ TEST(dlext, dlopen_ext_use_memfd) {
 
   // create memfd
   int memfd = memfd_create("foobar", MFD_CLOEXEC);
-  if (memfd == -1 && errno == ENOSYS) GTEST_SKIP() << "no memfd_create() in this kernel";
   ASSERT_TRUE(memfd != -1) << strerror(errno);
 
   // Check st.f_type is TMPFS_MAGIC for memfd
diff --git a/tests/dlfcn_test.cpp b/tests/dlfcn_test.cpp
index c27adb6d1..57982b9f4 100644
--- a/tests/dlfcn_test.cpp
+++ b/tests/dlfcn_test.cpp
@@ -1584,7 +1584,7 @@ TEST(dlfcn, dlopen_invalid_rw_load_segment) {
   const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-rw_load_segment.so";
   void* handle = dlopen(libpath.c_str(), RTLD_NOW);
   ASSERT_TRUE(handle == nullptr);
-  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\": W+E load segments are not allowed";
+  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has load segments that are both writable and executable";
   ASSERT_STREQ(expected_dlerror.c_str(), dlerror());
 }
 
diff --git a/tests/fortify_test.cpp b/tests/fortify_test.cpp
index cb96f9fdf..fd1680b4c 100644
--- a/tests/fortify_test.cpp
+++ b/tests/fortify_test.cpp
@@ -43,7 +43,7 @@
 
 using DEATHTEST = SilentDeathTest;
 
-#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 2
+#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE >= 2
 struct foo {
   char empty[0];
   char one[1];
@@ -53,26 +53,24 @@ struct foo {
 
 TEST_F(DEATHTEST, stpncpy_fortified2) {
   foo myfoo;
-  int copy_amt = atoi("11");
+  volatile int copy_amt = 11;
   ASSERT_FORTIFY(stpncpy(myfoo.a, "01234567890", copy_amt));
 }
 
 TEST_F(DEATHTEST, stpncpy2_fortified2) {
-  foo myfoo;
-  memset(&myfoo, 0, sizeof(myfoo));
+  foo myfoo = {};
   myfoo.one[0] = 'A'; // not null terminated string
   ASSERT_FORTIFY(stpncpy(myfoo.b, myfoo.one, sizeof(myfoo.b)));
 }
 
 TEST_F(DEATHTEST, strncpy_fortified2) {
   foo myfoo;
-  int copy_amt = atoi("11");
+  volatile int copy_amt = 11;
   ASSERT_FORTIFY(strncpy(myfoo.a, "01234567890", copy_amt));
 }
 
 TEST_F(DEATHTEST, strncpy2_fortified2) {
-  foo myfoo;
-  memset(&myfoo, 0, sizeof(myfoo));
+  foo myfoo = {};
   myfoo.one[0] = 'A'; // not null terminated string
   ASSERT_FORTIFY(strncpy(myfoo.b, myfoo.one, sizeof(myfoo.b)));
 }
@@ -89,13 +87,11 @@ TEST_F(DEATHTEST, sprintf2_fortified2) {
   ASSERT_FORTIFY(sprintf(myfoo.a, "0123456789"));
 }
 
-static int vsprintf_helper2(const char *fmt, ...) {
-  foo myfoo;
+static int vsprintf_helper2(const char* fmt, ...) {
   va_list va;
-  int result;
-
   va_start(va, fmt);
-  result = vsprintf(myfoo.a, fmt, va); // should crash here
+  foo myfoo;
+  int result = vsprintf(myfoo.a, fmt, va); // should crash here
   va_end(va);
   return result;
 }
@@ -108,14 +104,12 @@ TEST_F(DEATHTEST, vsprintf2_fortified2) {
   ASSERT_FORTIFY(vsprintf_helper2("0123456789"));
 }
 
-static int vsnprintf_helper2(const char *fmt, ...) {
-  foo myfoo;
+static int vsnprintf_helper2(const char* fmt, ...) {
   va_list va;
-  int result;
-  size_t size = atoi("11");
-
   va_start(va, fmt);
-  result = vsnprintf(myfoo.a, size, fmt, va); // should crash here
+  foo myfoo;
+  volatile size_t size = 11;
+  int result = vsnprintf(myfoo.a, size, fmt, va); // should crash here
   va_end(va);
   return result;
 }
@@ -251,7 +245,7 @@ TEST_F(DEATHTEST, strlcat_fortified2) {
 
 TEST_F(DEATHTEST, strncat_fortified2) {
   foo myfoo;
-  size_t n = atoi("10"); // avoid compiler optimizations
+  volatile size_t n = 10;
   strncpy(myfoo.a, "012345678", n);
   ASSERT_FORTIFY(strncat(myfoo.a, "9", n));
 }
@@ -259,7 +253,7 @@ TEST_F(DEATHTEST, strncat_fortified2) {
 TEST_F(DEATHTEST, strncat2_fortified2) {
   foo myfoo;
   myfoo.a[0] = '\0';
-  size_t n = atoi("10"); // avoid compiler optimizations
+  volatile size_t n = 10;
   ASSERT_FORTIFY(strncat(myfoo.a, "0123456789", n));
 }
 
@@ -267,7 +261,7 @@ TEST_F(DEATHTEST, strncat3_fortified2) {
   foo myfoo;
   memcpy(myfoo.a, "0123456789", sizeof(myfoo.a)); // unterminated string
   myfoo.b[0] = '\0';
-  size_t n = atoi("10"); // avoid compiler optimizations
+  volatile size_t n = 10;
   ASSERT_FORTIFY(strncat(myfoo.b, myfoo.a, n));
 }
 
@@ -296,7 +290,7 @@ TEST_F(DEATHTEST, snprintf_fortified2) {
 TEST_F(DEATHTEST, bzero_fortified2) {
   foo myfoo;
   memcpy(myfoo.b, "0123456789", sizeof(myfoo.b));
-  size_t n = atoi("11");
+  volatile size_t n = 11;
   ASSERT_FORTIFY(bzero(myfoo.b, n));
 }
 
@@ -306,7 +300,7 @@ TEST_F(DEATHTEST, bzero_fortified2) {
 TEST_F(DEATHTEST, strcpy_fortified) {
 #if defined(__BIONIC__)
   char buf[10];
-  char *orig = strdup("0123456789");
+  char* orig = strdup("0123456789");
   ASSERT_FORTIFY(strcpy(buf, orig));
   free(orig);
 #else // __BIONIC__
@@ -318,7 +312,7 @@ TEST_F(DEATHTEST, strcpy_fortified) {
 TEST_F(DEATHTEST, strcpy2_fortified) {
 #if defined(__BIONIC__)
   char buf[0];
-  char *orig = strdup("");
+  char* orig = strdup("");
   ASSERT_FORTIFY(strcpy(buf, orig));
   free(orig);
 #else // __BIONIC__
@@ -330,7 +324,7 @@ TEST_F(DEATHTEST, strcpy2_fortified) {
 TEST_F(DEATHTEST, strcpy3_fortified) {
 #if defined(__BIONIC__)
   char buf[0];
-  char *orig = strdup("1");
+  char* orig = strdup("1");
   ASSERT_FORTIFY(strcpy(buf, orig));
   free(orig);
 #else // __BIONIC__
@@ -342,7 +336,7 @@ TEST_F(DEATHTEST, strcpy3_fortified) {
 TEST_F(DEATHTEST, strcpy4_fortified) {
 #if defined(__BIONIC__)
   char buf[1];
-  char *orig = strdup("12");
+  char* orig = strdup("12");
   ASSERT_FORTIFY(strcpy(buf, orig));
   free(orig);
 #else // __BIONIC__
@@ -413,7 +407,7 @@ TEST_F(DEATHTEST, sprintf_fortified) {
 }
 
 TEST_F(DEATHTEST, sprintf_malloc_fortified) {
-  char* buf = (char *) malloc(10);
+  char* buf = static_cast<char*>(malloc(10));
   char source_buf[11];
   memcpy(source_buf, "1234567890", 11);
   ASSERT_FORTIFY(sprintf(buf, "%s", source_buf));
@@ -425,13 +419,11 @@ TEST_F(DEATHTEST, sprintf2_fortified) {
   ASSERT_FORTIFY(sprintf(buf, "aaaaa"));
 }
 
-static int vsprintf_helper(const char *fmt, ...) {
-  char buf[10];
+static int vsprintf_helper(const char* fmt, ...) {
   va_list va;
-  int result;
-
   va_start(va, fmt);
-  result = vsprintf(buf, fmt, va); // should crash here
+  char buf[10];
+  int result = vsprintf(buf, fmt, va); // should crash here
   va_end(va);
   return result;
 }
@@ -444,14 +436,12 @@ TEST_F(DEATHTEST, vsprintf2_fortified) {
   ASSERT_FORTIFY(vsprintf_helper("0123456789"));
 }
 
-static int vsnprintf_helper(const char *fmt, ...) {
-  char buf[10];
+static int vsnprintf_helper(const char* fmt, ...) {
   va_list va;
-  int result;
-  size_t size = atoi("11");
-
   va_start(va, fmt);
-  result = vsnprintf(buf, size, fmt, va); // should crash here
+  char buf[10];
+  volatile size_t size = 11;
+  int result = vsnprintf(buf, size, fmt, va); // should crash here
   va_end(va);
   return result;
 }
@@ -466,7 +456,7 @@ TEST_F(DEATHTEST, vsnprintf2_fortified) {
 
 TEST_F(DEATHTEST, strncat_fortified) {
   char buf[10];
-  size_t n = atoi("10"); // avoid compiler optimizations
+  volatile size_t n = 10;
   strncpy(buf, "012345678", n);
   ASSERT_FORTIFY(strncat(buf, "9", n));
 }
@@ -474,7 +464,7 @@ TEST_F(DEATHTEST, strncat_fortified) {
 TEST_F(DEATHTEST, strncat2_fortified) {
   char buf[10];
   buf[0] = '\0';
-  size_t n = atoi("10"); // avoid compiler optimizations
+  volatile size_t n = 10;
   ASSERT_FORTIFY(strncat(buf, "0123456789", n));
 }
 
@@ -489,7 +479,7 @@ TEST_F(DEATHTEST, strcat_fortified) {
 TEST_F(DEATHTEST, memmove_fortified) {
   char buf[20];
   strcpy(buf, "0123456789");
-  size_t n = atoi("10");
+  volatile size_t n = 10;
   ASSERT_FORTIFY(memmove(buf + 11, buf, n));
 }
 
@@ -497,13 +487,13 @@ TEST_F(DEATHTEST, memcpy_fortified) {
   char bufa[10];
   char bufb[10];
   strcpy(bufa, "012345678");
-  size_t n = atoi("11");
+  volatile size_t n = 11;
   ASSERT_FORTIFY(memcpy(bufb, bufa, n));
 }
 
 TEST_F(DEATHTEST, memset_fortified) {
   char buf[10];
-  size_t n = atoi("11");
+  volatile size_t n = 11;
   ASSERT_FORTIFY(memset(buf, 0, n));
 }
 
@@ -549,31 +539,30 @@ TEST_F(DEATHTEST, snprintf_fortified) {
 TEST_F(DEATHTEST, bzero_fortified) {
   char buf[10];
   memcpy(buf, "0123456789", sizeof(buf));
-  size_t n = atoi("11");
+  size_t n = 11;
   ASSERT_FORTIFY(bzero(buf, n));
 }
 
 TEST_F(DEATHTEST, umask_fortified) {
-  mode_t mask = atoi("1023");  // 01777 in octal
+  volatile mode_t mask = 01777;
   ASSERT_FORTIFY(umask(mask));
 }
 
 TEST_F(DEATHTEST, recv_fortified) {
-  size_t data_len = atoi("11"); // suppress compiler optimizations
+  volatile size_t data_len = 11;
   char buf[10];
   ASSERT_FORTIFY(recv(0, buf, data_len, 0));
 }
 
 TEST_F(DEATHTEST, send_fortified) {
-  size_t data_len = atoi("11"); // suppress compiler optimizations
+  volatile size_t data_len = 11;
   char buf[10] = {0};
   ASSERT_FORTIFY(send(0, buf, data_len, 0));
 }
 
 TEST_F(DEATHTEST, FD_ISSET_fortified) {
 #if defined(__BIONIC__) // glibc catches this at compile-time.
-  fd_set set;
-  memset(&set, 0, sizeof(set));
+  fd_set set = {};
   ASSERT_FORTIFY(FD_ISSET(-1, &set));
 #endif
 }
@@ -586,84 +575,84 @@ TEST_F(DEATHTEST, FD_ISSET_2_fortified) {
 
 TEST_F(DEATHTEST, getcwd_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
-  ASSERT_FORTIFY(getcwd(buf, ct));
+  volatile size_t n = 2;
+  ASSERT_FORTIFY(getcwd(buf, n));
 }
 
 TEST_F(DEATHTEST, pread_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_RDONLY);
-  ASSERT_FORTIFY(pread(fd, buf, ct, 0));
+  ASSERT_FORTIFY(pread(fd, buf, n, 0));
   close(fd);
 }
 
 TEST_F(DEATHTEST, pread64_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_RDONLY);
-  ASSERT_FORTIFY(pread64(fd, buf, ct, 0));
+  ASSERT_FORTIFY(pread64(fd, buf, n, 0));
   close(fd);
 }
 
 TEST_F(DEATHTEST, pwrite_fortified) {
   char buf[1] = {0};
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_WRONLY);
-  ASSERT_FORTIFY(pwrite(fd, buf, ct, 0));
+  ASSERT_FORTIFY(pwrite(fd, buf, n, 0));
   close(fd);
 }
 
 TEST_F(DEATHTEST, pwrite64_fortified) {
   char buf[1] = {0};
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_WRONLY);
-  ASSERT_FORTIFY(pwrite64(fd, buf, ct, 0));
+  ASSERT_FORTIFY(pwrite64(fd, buf, n, 0));
   close(fd);
 }
 
 TEST_F(DEATHTEST, read_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_RDONLY);
-  ASSERT_FORTIFY(read(fd, buf, ct));
+  ASSERT_FORTIFY(read(fd, buf, n));
   close(fd);
 }
 
 TEST_F(DEATHTEST, write_fortified) {
   char buf[1] = {0};
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   int fd = open("/dev/null", O_WRONLY);
-  ASSERT_EXIT(write(fd, buf, ct), testing::KilledBySignal(SIGABRT), "");
+  ASSERT_FORTIFY(write(fd, buf, n));
   close(fd);
 }
 
 TEST_F(DEATHTEST, fread_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   FILE* fp = fopen("/dev/null", "r");
-  ASSERT_FORTIFY(fread(buf, 1, ct, fp));
+  ASSERT_FORTIFY(fread(buf, 1, n, fp));
   fclose(fp);
 }
 
 TEST_F(DEATHTEST, fwrite_fortified) {
   char buf[1] = {0};
-  size_t ct = atoi("2"); // prevent optimizations
+  volatile size_t n = 2;
   FILE* fp = fopen("/dev/null", "w");
-  ASSERT_FORTIFY(fwrite(buf, 1, ct, fp));
+  ASSERT_FORTIFY(fwrite(buf, 1, n, fp));
   fclose(fp);
 }
 
 TEST_F(DEATHTEST, readlink_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
-  ASSERT_FORTIFY(readlink("/dev/null", buf, ct));
+  volatile size_t n = 2;
+  ASSERT_FORTIFY(readlink("/dev/null", buf, n));
 }
 
 TEST_F(DEATHTEST, readlinkat_fortified) {
   char buf[1];
-  size_t ct = atoi("2"); // prevent optimizations
-  ASSERT_FORTIFY(readlinkat(AT_FDCWD, "/dev/null", buf, ct));
+  volatile size_t n = 2;
+  ASSERT_FORTIFY(readlinkat(AT_FDCWD, "/dev/null", buf, n));
 }
 
 TEST(TEST_NAME, snprintf_nullptr_valid) {
@@ -907,7 +896,8 @@ TEST(TEST_NAME, strcat_chk_max_int_size) {
   memset(buf, 'A', sizeof(buf));
   buf[0] = 'a';
   buf[1] = '\0';
-  char* res = __strcat_chk(buf, "01234567", (size_t)-1);
+  volatile size_t n = -1;
+  char* res = __strcat_chk(buf, "01234567", n);
   ASSERT_EQ(buf, res);
   ASSERT_EQ('a',  buf[0]);
   ASSERT_EQ('0',  buf[1]);
@@ -943,7 +933,8 @@ extern "C" char* __stpcpy_chk(char*, const char*, size_t);
 
 TEST(TEST_NAME, stpcpy_chk_max_int_size) {
   char buf[10];
-  char* res = __stpcpy_chk(buf, "012345678", (size_t)-1);
+  volatile size_t n = -1;
+  char* res = __stpcpy_chk(buf, "012345678", n);
   ASSERT_EQ(buf + strlen("012345678"), res);
   ASSERT_STREQ("012345678", buf);
 }
@@ -952,16 +943,52 @@ extern "C" char* __strcpy_chk(char*, const char*, size_t);
 
 TEST(TEST_NAME, strcpy_chk_max_int_size) {
   char buf[10];
-  char* res = __strcpy_chk(buf, "012345678", (size_t)-1);
+  volatile size_t n = -1;
+  char* res = __strcpy_chk(buf, "012345678", n);
   ASSERT_EQ(buf, res);
   ASSERT_STREQ("012345678", buf);
 }
 
 extern "C" void* __memcpy_chk(void*, const void*, size_t, size_t);
 
+TEST(TEST_NAME, memcpy_chk_smaller) {
+  char buf[10] = "XXXXXXXXX";
+  volatile size_t n = 5;
+  void* res = __memcpy_chk(buf, "012346578", n, sizeof(buf));
+  ASSERT_EQ((void*)buf, res);
+  ASSERT_EQ('0',  buf[0]);
+  ASSERT_EQ('1',  buf[1]);
+  ASSERT_EQ('2',  buf[2]);
+  ASSERT_EQ('3',  buf[3]);
+  ASSERT_EQ('4',  buf[4]);
+  ASSERT_EQ('X',  buf[5]);
+  ASSERT_EQ('X',  buf[6]);
+  ASSERT_EQ('X',  buf[7]);
+  ASSERT_EQ('X',  buf[8]);
+  ASSERT_EQ('\0', buf[9]);
+}
+
+TEST(TEST_NAME, memcpy_chk_exact_size) {
+  char buf[10] = "XXXXXXXXX";
+  volatile size_t n = 10;
+  void* res = __memcpy_chk(buf, "012345678", n, sizeof(buf));
+  ASSERT_EQ((void*)buf, res);
+  ASSERT_EQ('0',  buf[0]);
+  ASSERT_EQ('1',  buf[1]);
+  ASSERT_EQ('2',  buf[2]);
+  ASSERT_EQ('3',  buf[3]);
+  ASSERT_EQ('4',  buf[4]);
+  ASSERT_EQ('5',  buf[5]);
+  ASSERT_EQ('6',  buf[6]);
+  ASSERT_EQ('7',  buf[7]);
+  ASSERT_EQ('8',  buf[8]);
+  ASSERT_EQ('\0', buf[9]);
+}
+
 TEST(TEST_NAME, memcpy_chk_max_int_size) {
   char buf[10];
-  void* res = __memcpy_chk(buf, "012345678", sizeof(buf), (size_t)-1);
+  volatile size_t n = -1;
+  void* res = __memcpy_chk(buf, "012345678", sizeof(buf), n);
   ASSERT_EQ((void*)buf, res);
   ASSERT_EQ('0',  buf[0]);
   ASSERT_EQ('1',  buf[1]);
@@ -994,38 +1021,36 @@ TEST(TEST_NAME, s_n_printf_macro_expansion) {
 }
 
 TEST_F(DEATHTEST, poll_fortified) {
-  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
+  volatile nfds_t fd_count = 2;
   pollfd buf[1] = {{0, POLLIN, 0}};
   // Set timeout to zero to prevent waiting in poll when fortify test fails.
   ASSERT_FORTIFY(poll(buf, fd_count, 0));
 }
 
 TEST_F(DEATHTEST, ppoll_fortified) {
-  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
+  volatile nfds_t fd_count = 2;
   pollfd buf[1] = {{0, POLLIN, 0}};
-  // Set timeout to zero to prevent waiting in ppoll when fortify test fails.
-  timespec timeout;
-  timeout.tv_sec = timeout.tv_nsec = 0;
+  // Set timeout to zero to prevent waiting in ppoll if fortify test fails.
+  timespec timeout = {};
   ASSERT_FORTIFY(ppoll(buf, fd_count, &timeout, nullptr));
 }
 
 TEST_F(DEATHTEST, ppoll64_fortified) {
 #if defined(__BIONIC__)        // glibc doesn't have ppoll64.
-  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
+  volatile nfds_t fd_count = 2;
   pollfd buf[1] = {{0, POLLIN, 0}};
-  // Set timeout to zero to prevent waiting in ppoll when fortify test fails.
-  timespec timeout;
-  timeout.tv_sec = timeout.tv_nsec = 0;
+  // Set timeout to zero to prevent waiting in ppoll if fortify test fails.
+  timespec timeout= {};
   ASSERT_FORTIFY(ppoll64(buf, fd_count, &timeout, nullptr));
 #endif
 }
 
 TEST_F(DEATHTEST, open_O_CREAT_without_mode_fortified) {
-  int flags = O_CREAT; // Fool the compiler.
+  volatile int flags = O_CREAT;
   ASSERT_FORTIFY(open("", flags));
 }
 
 TEST_F(DEATHTEST, open_O_TMPFILE_without_mode_fortified) {
-  int flags = O_TMPFILE; // Fool the compiler.
+  volatile int flags = O_TMPFILE;
   ASSERT_FORTIFY(open("", flags));
 }
diff --git a/tests/grp_pwd_test.cpp b/tests/grp_pwd_test.cpp
index 3f93c8a93..2c2208126 100644
--- a/tests/grp_pwd_test.cpp
+++ b/tests/grp_pwd_test.cpp
@@ -492,6 +492,18 @@ static void expect_ids(T ids, bool is_group) {
       EXPECT_STREQ(getpwuid(AID_MMD)->pw_name, "mmd");
     }
   }
+  // AID_UPDATE_ENGINE_LOG (1096) was added in API level 36, but "trunk stable" means
+  // that the 2024Q* builds are tested with the _previous_ release's CTS.
+  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 35) {
+#if !defined(AID_UPDATE_ENGINE_LOG)
+#define AID_UPDATE_ENGINE_LOG 1096
+#endif
+    ids.erase(AID_UPDATE_ENGINE_LOG);
+    expected_ids.erase(AID_UPDATE_ENGINE_LOG);
+    if (getpwuid(AID_UPDATE_ENGINE_LOG)) {
+      EXPECT_STREQ(getpwuid(AID_UPDATE_ENGINE_LOG)->pw_name, "update_engine_log");
+    }
+  }
 
   EXPECT_EQ(expected_ids, ids) << return_differences();
 }
diff --git a/tests/headers/posix/arpa_inet_h.c b/tests/headers/posix/arpa_inet_h.c
index 51df1c7b8..23ba6548e 100644
--- a/tests/headers/posix/arpa_inet_h.c
+++ b/tests/headers/posix/arpa_inet_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <arpa/inet.h>
 
diff --git a/tests/headers/posix/assert_h.c b/tests/headers/posix/assert_h.c
index 81c577a66..d71e26012 100644
--- a/tests/headers/posix/assert_h.c
+++ b/tests/headers/posix/assert_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #undef NDEBUG
 
diff --git a/tests/headers/posix/complex_h.c b/tests/headers/posix/complex_h.c
index 5003139cc..15320142d 100644
--- a/tests/headers/posix/complex_h.c
+++ b/tests/headers/posix/complex_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <complex.h>
 
diff --git a/tests/headers/posix/cpio_h.c b/tests/headers/posix/cpio_h.c
index 0dd24075b..f0f063af3 100644
--- a/tests/headers/posix/cpio_h.c
+++ b/tests/headers/posix/cpio_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <cpio.h>
 
diff --git a/tests/headers/posix/ctype_h.c b/tests/headers/posix/ctype_h.c
index c901284bf..716962777 100644
--- a/tests/headers/posix/ctype_h.c
+++ b/tests/headers/posix/ctype_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <ctype.h>
 
diff --git a/tests/headers/posix/dirent_h.c b/tests/headers/posix/dirent_h.c
index 4ce0f18d8..e9b947016 100644
--- a/tests/headers/posix/dirent_h.c
+++ b/tests/headers/posix/dirent_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <dirent.h>
 
diff --git a/tests/headers/posix/dlfcn_h.c b/tests/headers/posix/dlfcn_h.c
index 480007596..3a32fdd3b 100644
--- a/tests/headers/posix/dlfcn_h.c
+++ b/tests/headers/posix/dlfcn_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <dlfcn.h>
 
@@ -36,6 +11,17 @@ static void dlfcn_h() {
   MACRO(RTLD_GLOBAL);
   MACRO(RTLD_LOCAL);
 
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  TYPE(Dl_info);
+  STRUCT_MEMBER(Dl_info, const char*, dli_fname);
+  STRUCT_MEMBER(Dl_info, void*, dli_fbase);
+  STRUCT_MEMBER(Dl_info, const char*, dli_sname);
+  STRUCT_MEMBER(Dl_info, void*, dli_saddr);
+#endif
+
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(dladdr, int (*f)(const void*, Dl_info*));
+#endif
   FUNCTION(dlclose, int (*f)(void*));
   FUNCTION(dlerror, char* (*f)(void));
   FUNCTION(dlopen, void* (*f)(const char*, int));
diff --git a/tests/headers/posix/errno_h.c b/tests/headers/posix/errno_h.c
index 9eabfd50c..4cf36d723 100644
--- a/tests/headers/posix/errno_h.c
+++ b/tests/headers/posix/errno_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <errno.h>
 
diff --git a/tests/headers/posix/fcntl_h.c b/tests/headers/posix/fcntl_h.c
index 418add072..5416dd1c5 100644
--- a/tests/headers/posix/fcntl_h.c
+++ b/tests/headers/posix/fcntl_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <fcntl.h>
 
diff --git a/tests/headers/posix/fenv_h.c b/tests/headers/posix/fenv_h.c
index cabe4ae95..80af27cb5 100644
--- a/tests/headers/posix/fenv_h.c
+++ b/tests/headers/posix/fenv_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <fenv.h>
 
diff --git a/tests/headers/posix/float_h.c b/tests/headers/posix/float_h.c
index 5f12fa20c..280dd9497 100644
--- a/tests/headers/posix/float_h.c
+++ b/tests/headers/posix/float_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <float.h>
 
diff --git a/tests/headers/posix/fnmatch_h.c b/tests/headers/posix/fnmatch_h.c
index 3dd41d766..db263caec 100644
--- a/tests/headers/posix/fnmatch_h.c
+++ b/tests/headers/posix/fnmatch_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <fnmatch.h>
 
diff --git a/tests/headers/posix/ftw_h.c b/tests/headers/posix/ftw_h.c
index 0a78d944b..dc149cc6e 100644
--- a/tests/headers/posix/ftw_h.c
+++ b/tests/headers/posix/ftw_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <ftw.h>
 
diff --git a/tests/headers/posix/glob_h.c b/tests/headers/posix/glob_h.c
index b399e524e..255a0a385 100644
--- a/tests/headers/posix/glob_h.c
+++ b/tests/headers/posix/glob_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <glob.h>
 
diff --git a/tests/headers/posix/grp_h.c b/tests/headers/posix/grp_h.c
index 7042e83ff..8eb875219 100644
--- a/tests/headers/posix/grp_h.c
+++ b/tests/headers/posix/grp_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <grp.h>
 
diff --git a/tests/headers/posix/header_checks.h b/tests/headers/posix/header_checks.h
index 2ce6da996..9730d585e 100644
--- a/tests/headers/posix/header_checks.h
+++ b/tests/headers/posix/header_checks.h
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #define FUNCTION(f_, t_) { t_ = f_; }
 #define MACRO(m_) { typeof(m_) v = m_; }
diff --git a/tests/headers/posix/iconv_h.c b/tests/headers/posix/iconv_h.c
index d92d873bd..757c4a07d 100644
--- a/tests/headers/posix/iconv_h.c
+++ b/tests/headers/posix/iconv_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <iconv.h>
 
diff --git a/tests/headers/posix/inttypes_h.c b/tests/headers/posix/inttypes_h.c
index 1eba4b82e..73b13996f 100644
--- a/tests/headers/posix/inttypes_h.c
+++ b/tests/headers/posix/inttypes_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <inttypes.h>
 
diff --git a/tests/headers/posix/iso646_h.c b/tests/headers/posix/iso646_h.c
index be2a18972..a834d904a 100644
--- a/tests/headers/posix/iso646_h.c
+++ b/tests/headers/posix/iso646_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <iso646.h>
 
diff --git a/tests/headers/posix/langinfo_h.c b/tests/headers/posix/langinfo_h.c
index d38d41bd5..d29c2e459 100644
--- a/tests/headers/posix/langinfo_h.c
+++ b/tests/headers/posix/langinfo_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <langinfo.h>
 
diff --git a/tests/headers/posix/libgen_h.c b/tests/headers/posix/libgen_h.c
index d839a06ac..f65ab0a39 100644
--- a/tests/headers/posix/libgen_h.c
+++ b/tests/headers/posix/libgen_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <libgen.h>
 
diff --git a/tests/headers/posix/limits_h.c b/tests/headers/posix/limits_h.c
index 0ca80a5ca..4a076bb9a 100644
--- a/tests/headers/posix/limits_h.c
+++ b/tests/headers/posix/limits_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <limits.h>
 
@@ -58,6 +33,9 @@ static void limits_h() {
 #if !defined(__BIONIC__)
   MACRO(MQ_PRIO_MAX);
 #endif
+#if defined(__BIONIC__)
+  MACRO(NSIG_MAX);
+#endif
 #if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
   MACRO(OPEN_MAX);
 #endif
diff --git a/tests/headers/posix/locale_h.c b/tests/headers/posix/locale_h.c
index 68051c84c..18bd839e7 100644
--- a/tests/headers/posix/locale_h.c
+++ b/tests/headers/posix/locale_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <locale.h>
 
diff --git a/tests/headers/posix/math_h.c b/tests/headers/posix/math_h.c
index 0f8ad2b7b..dfd7604b2 100644
--- a/tests/headers/posix/math_h.c
+++ b/tests/headers/posix/math_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <math.h>
 
diff --git a/tests/headers/posix/net_if_h.c b/tests/headers/posix/net_if_h.c
index 4b3df1877..0c983e7b7 100644
--- a/tests/headers/posix/net_if_h.c
+++ b/tests/headers/posix/net_if_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <net/if.h>
 
diff --git a/tests/headers/posix/netdb_h.c b/tests/headers/posix/netdb_h.c
index 62fd0839b..fb3939fb8 100644
--- a/tests/headers/posix/netdb_h.c
+++ b/tests/headers/posix/netdb_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <netdb.h>
 
diff --git a/tests/headers/posix/netinet_in_h.c b/tests/headers/posix/netinet_in_h.c
index cd896851b..a407ae87a 100644
--- a/tests/headers/posix/netinet_in_h.c
+++ b/tests/headers/posix/netinet_in_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <netinet/in.h>
 
diff --git a/tests/headers/posix/netinet_tcp_h.c b/tests/headers/posix/netinet_tcp_h.c
index afb64181a..3927c6ccc 100644
--- a/tests/headers/posix/netinet_tcp_h.c
+++ b/tests/headers/posix/netinet_tcp_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <netinet/tcp.h>
 
diff --git a/tests/headers/posix/nl_types_h.c b/tests/headers/posix/nl_types_h.c
index 5a3c8174a..d066842ea 100644
--- a/tests/headers/posix/nl_types_h.c
+++ b/tests/headers/posix/nl_types_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <nl_types.h>
 
diff --git a/tests/headers/posix/poll_h.c b/tests/headers/posix/poll_h.c
index 4fce5e532..e5d0d8aa0 100644
--- a/tests/headers/posix/poll_h.c
+++ b/tests/headers/posix/poll_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <poll.h>
 
@@ -36,6 +11,11 @@ static void poll_h() {
   STRUCT_MEMBER(struct pollfd, short, events);
   STRUCT_MEMBER(struct pollfd, short, revents);
 
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  TYPE(sigset_t);
+  TYPE(struct timespec);
+#endif
+
   TYPE(nfds_t);
 
   MACRO(POLLIN);
@@ -50,4 +30,7 @@ static void poll_h() {
   MACRO(POLLNVAL);
 
   FUNCTION(poll, int (*f)(struct pollfd[], nfds_t, int));
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(ppoll, int (*f)(struct pollfd[], nfds_t, const struct timespec*, const sigset_t*));
+#endif
 }
diff --git a/tests/headers/posix/pthread_h.c b/tests/headers/posix/pthread_h.c
index 4be822c70..dd428123e 100644
--- a/tests/headers/posix/pthread_h.c
+++ b/tests/headers/posix/pthread_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <pthread.h>
 
@@ -116,6 +91,9 @@ static void pthread_h() {
   FUNCTION(pthread_cancel, int (*f)(pthread_t));
 #endif
   FUNCTION(pthread_cond_broadcast, int (*f)(pthread_cond_t*));
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(pthread_cond_clockwait, int (*f)(pthread_cond_t*, pthread_mutex_t*, clockid_t, const struct timespec*));
+#endif
   FUNCTION(pthread_cond_destroy, int (*f)(pthread_cond_t*));
   FUNCTION(pthread_cond_init, int (*f)(pthread_cond_t*, const pthread_condattr_t*));
   FUNCTION(pthread_cond_signal, int (*f)(pthread_cond_t*));
@@ -140,6 +118,9 @@ static void pthread_h() {
   FUNCTION(pthread_join, int (*f)(pthread_t, void**));
   FUNCTION(pthread_key_create, int (*f)(pthread_key_t*, void (*)(void*)));
   FUNCTION(pthread_key_delete, int (*f)(pthread_key_t));
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(pthread_mutex_clocklock, int (*f)(pthread_mutex_t*, clockid_t, const struct timespec*));
+#endif
 #if !defined(__BIONIC__) // No robust mutexes on Android.
   FUNCTION(pthread_mutex_consistent, int (*f)(pthread_mutex_t*));
 #endif
@@ -176,6 +157,10 @@ static void pthread_h() {
 #endif
   FUNCTION(pthread_mutexattr_settype, int (*f)(pthread_mutexattr_t*, int));
   FUNCTION(pthread_once, int (*f)(pthread_once_t*, void (*)(void)));
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(pthread_rwlock_clockrdlock, int (*f)(pthread_rwlock_t*, clockid_t, const struct timespec*));
+  FUNCTION(pthread_rwlock_clockwrlock, int (*f)(pthread_rwlock_t*, clockid_t, const struct timespec*));
+#endif
   FUNCTION(pthread_rwlock_destroy, int (*f)(pthread_rwlock_t*));
   FUNCTION(pthread_rwlock_init, int (*f)(pthread_rwlock_t*, const pthread_rwlockattr_t*));
   FUNCTION(pthread_rwlock_rdlock, int (*f)(pthread_rwlock_t*));
diff --git a/tests/headers/posix/pwd_h.c b/tests/headers/posix/pwd_h.c
index 3d208653f..eedab08d6 100644
--- a/tests/headers/posix/pwd_h.c
+++ b/tests/headers/posix/pwd_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <pwd.h>
 
diff --git a/tests/headers/posix/regex_h.c b/tests/headers/posix/regex_h.c
index 381004c1b..8e80339b4 100644
--- a/tests/headers/posix/regex_h.c
+++ b/tests/headers/posix/regex_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <regex.h>
 
diff --git a/tests/headers/posix/sched_h.c b/tests/headers/posix/sched_h.c
index e9b98d6cb..f0ebeb533 100644
--- a/tests/headers/posix/sched_h.c
+++ b/tests/headers/posix/sched_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if !defined(DO_NOT_INCLUDE_SCHED_H)
 #include <sched.h>
diff --git a/tests/headers/posix/search_h.c b/tests/headers/posix/search_h.c
index 9de079a51..ad46b1485 100644
--- a/tests/headers/posix/search_h.c
+++ b/tests/headers/posix/search_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <search.h>
 
diff --git a/tests/headers/posix/semaphore_h.c b/tests/headers/posix/semaphore_h.c
index 9d5c7e124..2f9a31488 100644
--- a/tests/headers/posix/semaphore_h.c
+++ b/tests/headers/posix/semaphore_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <semaphore.h>
 
@@ -35,6 +10,9 @@ static void semaphore_h() {
 
   MACRO(SEM_FAILED);
 
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  FUNCTION(sem_clockwait, int (*f)(sem_t*, clockid_t, const struct timespec*));
+#endif
   FUNCTION(sem_close, int (*f)(sem_t*));
   FUNCTION(sem_destroy, int (*f)(sem_t*));
   FUNCTION(sem_getvalue, int (*f)(sem_t*, int*));
diff --git a/tests/headers/posix/setjmp_h.c b/tests/headers/posix/setjmp_h.c
index 6544d2a88..5c1872328 100644
--- a/tests/headers/posix/setjmp_h.c
+++ b/tests/headers/posix/setjmp_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <setjmp.h>
 
diff --git a/tests/headers/posix/signal_h.c b/tests/headers/posix/signal_h.c
index 82751f4fc..45d4e4c18 100644
--- a/tests/headers/posix/signal_h.c
+++ b/tests/headers/posix/signal_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <signal.h>
 
@@ -75,6 +50,10 @@ static void signal_h() {
   i = SIGRTMIN;
   i = SIGRTMAX;
 
+#if !defined(__GLIBC__)  // Our glibc is too old.
+  MACRO(SIG2STR_MAX);
+#endif
+
   MACRO(SIGABRT);
   MACRO(SIGALRM);
   MACRO(SIGBUS);
diff --git a/tests/headers/posix/spawn_h.c b/tests/headers/posix/spawn_h.c
index 48f8390a1..2b436002f 100644
--- a/tests/headers/posix/spawn_h.c
+++ b/tests/headers/posix/spawn_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <spawn.h>
 
diff --git a/tests/headers/posix/stdarg_h.c b/tests/headers/posix/stdarg_h.c
index ef1e8af74..be7ccba5f 100644
--- a/tests/headers/posix/stdarg_h.c
+++ b/tests/headers/posix/stdarg_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdarg.h>
 
diff --git a/tests/headers/posix/stdatomic_h.c b/tests/headers/posix/stdatomic_h.c
index 05be859e9..270faaeb8 100644
--- a/tests/headers/posix/stdatomic_h.c
+++ b/tests/headers/posix/stdatomic_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2024 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdatomic.h>
 
@@ -91,12 +66,12 @@ static void stdatomic_h() {
   MACRO(ATOMIC_POINTER_LOCK_FREE);
 
   atomic_flag f = ATOMIC_FLAG_INIT;
+
+  // ATOMIC_VAR_INIT() has been removed from C23,
+  // but not from POSIX 2024.
   atomic_int i = ATOMIC_VAR_INIT(123);
 
-  // TODO: remove this #if after the next toolchain update (http://b/374104004).
-#if !defined(__GLIBC__)
   i = kill_dependency(i);
-#endif
 
 #if !defined(atomic_compare_exchange_strong)
 #error atomic_compare_exchange_strong
diff --git a/tests/headers/posix/stdbool_h.c b/tests/headers/posix/stdbool_h.c
index 830c33cea..3467da4ad 100644
--- a/tests/headers/posix/stdbool_h.c
+++ b/tests/headers/posix/stdbool_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdbool.h>
 
diff --git a/tests/headers/posix/stddef_h.c b/tests/headers/posix/stddef_h.c
index 7cdfd7620..dd6144b4d 100644
--- a/tests/headers/posix/stddef_h.c
+++ b/tests/headers/posix/stddef_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stddef.h>
 
diff --git a/tests/headers/posix/stdint_h.c b/tests/headers/posix/stdint_h.c
index a8f3346e4..97eb2285e 100644
--- a/tests/headers/posix/stdint_h.c
+++ b/tests/headers/posix/stdint_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdint.h>
 
diff --git a/tests/headers/posix/stdio_h.c b/tests/headers/posix/stdio_h.c
index 57be0a0c2..5b1677d6c 100644
--- a/tests/headers/posix/stdio_h.c
+++ b/tests/headers/posix/stdio_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdio.h>
 
diff --git a/tests/headers/posix/stdlib_h.c b/tests/headers/posix/stdlib_h.c
index 95769b4a0..fc9ffed71 100644
--- a/tests/headers/posix/stdlib_h.c
+++ b/tests/headers/posix/stdlib_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <stdlib.h>
 
@@ -119,6 +94,9 @@ static void stdlib_h() {
   FUNCTION(rand_r, int (*f)(unsigned*));
   FUNCTION(random, long (*f)(void));
   FUNCTION(realloc, void* (*f)(void*, size_t));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(reallocarray, void* (*f)(void*, size_t, size_t));
+#endif
   FUNCTION(realpath, char* (*f)(const char*, char*));
   FUNCTION(seed48, unsigned short* (*f)(unsigned short[3]));
   FUNCTION(setenv, int (*f)(const char*, const char*, int));
diff --git a/tests/headers/posix/string_h.c b/tests/headers/posix/string_h.c
index 2440050d9..8c3ace68f 100644
--- a/tests/headers/posix/string_h.c
+++ b/tests/headers/posix/string_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <string.h>
 
@@ -39,6 +14,9 @@ static void string_h() {
   FUNCTION(memchr, void* (*f)(const void*, int, size_t));
   FUNCTION(memcmp, int (*f)(const void*, const void*, size_t));
   FUNCTION(memcpy, void* (*f)(void*, const void*, size_t));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(memmem, void* (*f)(const void*, size_t, const void*, size_t));
+#endif
   FUNCTION(memmove, void* (*f)(void*, const void*, size_t));
   FUNCTION(memset, void* (*f)(void*, int, size_t));
   FUNCTION(stpcpy, char* (*f)(char*, const char*));
@@ -54,6 +32,10 @@ static void string_h() {
   FUNCTION(strerror, char* (*f)(int));
   FUNCTION(strerror_l, char* (*f)(int, locale_t));
   FUNCTION(strerror_r, int (*f)(int, char*, size_t));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(strlcat, size_t (*f)(char*, const char*, size_t));
+  FUNCTION(strlcpy, size_t (*f)(char*, const char*, size_t));
+#endif
   FUNCTION(strlen, size_t (*f)(const char*));
   FUNCTION(strncat, char* (*f)(char*, const char*, size_t));
   FUNCTION(strncmp, int (*f)(const char*, const char*, size_t));
diff --git a/tests/headers/posix/strings_h.c b/tests/headers/posix/strings_h.c
index 2051c8b3a..b04e7cef3 100644
--- a/tests/headers/posix/strings_h.c
+++ b/tests/headers/posix/strings_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <strings.h>
 
diff --git a/tests/headers/posix/sys_ipc_h.c b/tests/headers/posix/sys_ipc_h.c
index 48273e4d3..af07629e2 100644
--- a/tests/headers/posix/sys_ipc_h.c
+++ b/tests/headers/posix/sys_ipc_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/ipc.h>
 
diff --git a/tests/headers/posix/sys_mman_h.c b/tests/headers/posix/sys_mman_h.c
index 5ec889cde..881e4e89c 100644
--- a/tests/headers/posix/sys_mman_h.c
+++ b/tests/headers/posix/sys_mman_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/mman.h>
 
diff --git a/tests/headers/posix/sys_msg_h.c b/tests/headers/posix/sys_msg_h.c
index b02cd475b..3454b929d 100644
--- a/tests/headers/posix/sys_msg_h.c
+++ b/tests/headers/posix/sys_msg_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if defined(__BIONIC__)
 
diff --git a/tests/headers/posix/sys_resource_h.c b/tests/headers/posix/sys_resource_h.c
index 0e95fd52d..cda68a2ae 100644
--- a/tests/headers/posix/sys_resource_h.c
+++ b/tests/headers/posix/sys_resource_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/resource.h>
 
diff --git a/tests/headers/posix/sys_select_h.c b/tests/headers/posix/sys_select_h.c
index 32c6f5741..c1430a3bf 100644
--- a/tests/headers/posix/sys_select_h.c
+++ b/tests/headers/posix/sys_select_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/select.h>
 
diff --git a/tests/headers/posix/sys_sem_h.c b/tests/headers/posix/sys_sem_h.c
index 49b236f8c..c502a1bb2 100644
--- a/tests/headers/posix/sys_sem_h.c
+++ b/tests/headers/posix/sys_sem_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if defined(__BIONIC__)
 
diff --git a/tests/headers/posix/sys_shm_h.c b/tests/headers/posix/sys_shm_h.c
index 03d681528..aca9e1825 100644
--- a/tests/headers/posix/sys_shm_h.c
+++ b/tests/headers/posix/sys_shm_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if defined(__BIONIC__)
 
diff --git a/tests/headers/posix/sys_socket_h.c b/tests/headers/posix/sys_socket_h.c
index ed437f373..7f9c91e56 100644
--- a/tests/headers/posix/sys_socket_h.c
+++ b/tests/headers/posix/sys_socket_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/socket.h>
 
diff --git a/tests/headers/posix/sys_stat_h.c b/tests/headers/posix/sys_stat_h.c
index a299426eb..efebf93b7 100644
--- a/tests/headers/posix/sys_stat_h.c
+++ b/tests/headers/posix/sys_stat_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/stat.h>
 
diff --git a/tests/headers/posix/sys_stat_h_file_type_test_macros.h b/tests/headers/posix/sys_stat_h_file_type_test_macros.h
index 5e09fdb7f..4e92d5cad 100644
--- a/tests/headers/posix/sys_stat_h_file_type_test_macros.h
+++ b/tests/headers/posix/sys_stat_h_file_type_test_macros.h
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if !defined(S_ISBLK)
 #error S_ISBLK
diff --git a/tests/headers/posix/sys_stat_h_mode_constants.h b/tests/headers/posix/sys_stat_h_mode_constants.h
index cce84693e..bf85173d1 100644
--- a/tests/headers/posix/sys_stat_h_mode_constants.h
+++ b/tests/headers/posix/sys_stat_h_mode_constants.h
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
   MACRO(S_IFMT);
   MACRO(S_IFBLK);
diff --git a/tests/headers/posix/sys_statvfs_h.c b/tests/headers/posix/sys_statvfs_h.c
index b44a93aa3..af67a56d0 100644
--- a/tests/headers/posix/sys_statvfs_h.c
+++ b/tests/headers/posix/sys_statvfs_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/statvfs.h>
 
diff --git a/tests/headers/posix/sys_time_h.c b/tests/headers/posix/sys_time_h.c
index 394abd22a..d3c75eb9e 100644
--- a/tests/headers/posix/sys_time_h.c
+++ b/tests/headers/posix/sys_time_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/time.h>
 
diff --git a/tests/headers/posix/sys_times_h.c b/tests/headers/posix/sys_times_h.c
index 195d11b36..a1f1a2ab0 100644
--- a/tests/headers/posix/sys_times_h.c
+++ b/tests/headers/posix/sys_times_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/times.h>
 
diff --git a/tests/headers/posix/sys_types_h.c b/tests/headers/posix/sys_types_h.c
index 3b0f55f39..7dfa04a62 100644
--- a/tests/headers/posix/sys_types_h.c
+++ b/tests/headers/posix/sys_types_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/types.h>
 
diff --git a/tests/headers/posix/sys_uio_h.c b/tests/headers/posix/sys_uio_h.c
index 90b210dad..9fc68f432 100644
--- a/tests/headers/posix/sys_uio_h.c
+++ b/tests/headers/posix/sys_uio_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/uio.h>
 
diff --git a/tests/headers/posix/sys_un_h.c b/tests/headers/posix/sys_un_h.c
index d48ac6117..b1ffee01a 100644
--- a/tests/headers/posix/sys_un_h.c
+++ b/tests/headers/posix/sys_un_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/un.h>
 
diff --git a/tests/headers/posix/sys_utsname_h.c b/tests/headers/posix/sys_utsname_h.c
index 5ebd70324..4b909c597 100644
--- a/tests/headers/posix/sys_utsname_h.c
+++ b/tests/headers/posix/sys_utsname_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/utsname.h>
 
diff --git a/tests/headers/posix/sys_wait_h.c b/tests/headers/posix/sys_wait_h.c
index 406e0518d..4018a8609 100644
--- a/tests/headers/posix/sys_wait_h.c
+++ b/tests/headers/posix/sys_wait_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <sys/wait.h>
 
diff --git a/tests/headers/posix/syslog_h.c b/tests/headers/posix/syslog_h.c
index b43f49ebc..7835c31d7 100644
--- a/tests/headers/posix/syslog_h.c
+++ b/tests/headers/posix/syslog_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <syslog.h>
 
diff --git a/tests/headers/posix/tar_h.c b/tests/headers/posix/tar_h.c
index bd22c179d..01691d7b1 100644
--- a/tests/headers/posix/tar_h.c
+++ b/tests/headers/posix/tar_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <tar.h>
 
diff --git a/tests/headers/posix/termios_h.c b/tests/headers/posix/termios_h.c
index 0a67eaabe..177914150 100644
--- a/tests/headers/posix/termios_h.c
+++ b/tests/headers/posix/termios_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <termios.h>
 
diff --git a/tests/headers/posix/tgmath_h.c b/tests/headers/posix/tgmath_h.c
index c3a431164..068c245c6 100644
--- a/tests/headers/posix/tgmath_h.c
+++ b/tests/headers/posix/tgmath_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <tgmath.h>
 
diff --git a/tests/headers/posix/threads_h.c b/tests/headers/posix/threads_h.c
index c9329f4e8..fd04cb213 100644
--- a/tests/headers/posix/threads_h.c
+++ b/tests/headers/posix/threads_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2019 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if __has_include(<threads.h>)
 
diff --git a/tests/headers/posix/time_h.c b/tests/headers/posix/time_h.c
index d3e088ad3..c3a499927 100644
--- a/tests/headers/posix/time_h.c
+++ b/tests/headers/posix/time_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #if !defined(DO_NOT_INCLUDE_TIME_H)
 #include <time.h>
diff --git a/tests/headers/posix/unistd_h.c b/tests/headers/posix/unistd_h.c
index f66609df6..d2262b376 100644
--- a/tests/headers/posix/unistd_h.c
+++ b/tests/headers/posix/unistd_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <unistd.h>
 
@@ -221,6 +196,9 @@ static void unistd_h() {
   MACRO(_SC_MQ_OPEN_MAX);
   MACRO(_SC_MQ_PRIO_MAX);
   MACRO(_SC_NGROUPS_MAX);
+#if defined(__BIONIC__) // New in POSIX 2024.
+  MACRO(_SC_NSIG);
+#endif
   MACRO(_SC_OPEN_MAX);
   MACRO(_SC_PAGE_SIZE);
   MACRO(_SC_PAGESIZE);
@@ -339,6 +317,9 @@ static void unistd_h() {
   FUNCTION(ftruncate, int (*f)(int, off_t));
   FUNCTION(getcwd, char* (*f)(char*, size_t));
   FUNCTION(getegid, gid_t (*f)(void));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(getentropy, int (*f)(void*, size_t));
+#endif
   FUNCTION(geteuid, uid_t (*f)(void));
   FUNCTION(getgid, gid_t (*f)(void));
   FUNCTION(getgroups, int (*f)(int, gid_t[]));
diff --git a/tests/headers/posix/utime_h.c b/tests/headers/posix/utime_h.c
index c5b304b8d..ca8a86960 100644
--- a/tests/headers/posix/utime_h.c
+++ b/tests/headers/posix/utime_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <utime.h>
 
diff --git a/tests/headers/posix/utmpx_h.c b/tests/headers/posix/utmpx_h.c
index 44dfac9ce..54f449233 100644
--- a/tests/headers/posix/utmpx_h.c
+++ b/tests/headers/posix/utmpx_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2023 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <utmpx.h>
 
diff --git a/tests/headers/posix/wchar_h.c b/tests/headers/posix/wchar_h.c
index 48b3b92bf..7eaa125fd 100644
--- a/tests/headers/posix/wchar_h.c
+++ b/tests/headers/posix/wchar_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <wchar.h>
 
@@ -86,6 +61,10 @@ static void wchar_h() {
   FUNCTION(wcscspn, size_t (*f)(const wchar_t*, const wchar_t*));
   FUNCTION(wcsdup, wchar_t* (*f)(const wchar_t*));
   FUNCTION(wcsftime, size_t (*f)(wchar_t*, size_t, const wchar_t*, const struct tm*));
+#if !defined(__GLIBC__) // Our glibc is too old.
+  FUNCTION(wcslcat, size_t (*f)(wchar_t*, const wchar_t*, size_t));
+  FUNCTION(wcslcpy, size_t (*f)(wchar_t*, const wchar_t*, size_t));
+#endif
   FUNCTION(wcslen, size_t (*f)(const wchar_t*));
   FUNCTION(wcsncasecmp, int (*f)(const wchar_t*, const wchar_t*, size_t));
   FUNCTION(wcsncasecmp_l, int (*f)(const wchar_t*, const wchar_t*, size_t, locale_t));
diff --git a/tests/headers/posix/wctype_h.c b/tests/headers/posix/wctype_h.c
index c5839d55d..e8bd6628e 100644
--- a/tests/headers/posix/wctype_h.c
+++ b/tests/headers/posix/wctype_h.c
@@ -1,30 +1,5 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
+// Copyright (C) 2017 The Android Open Source Project
+// SPDX-License-Identifier: BSD-2-Clause
 
 #include <wctype.h>
 
diff --git a/tests/heap_tagging_level_test.cpp b/tests/heap_tagging_level_test.cpp
index c0aa176fe..4defc5d55 100644
--- a/tests/heap_tagging_level_test.cpp
+++ b/tests/heap_tagging_level_test.cpp
@@ -105,7 +105,7 @@ class Or {
 
 TEST(heap_tagging_level, sync_async_bad_accesses_die) {
 #if defined(__BIONIC__) && defined(__aarch64__)
-  if (!mte_supported() || !running_with_mte()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "requires MTE to be enabled";
   }
 
@@ -177,7 +177,7 @@ TEST(heap_tagging_level, tagging_level_transitions) {
     EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
     EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
     EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
-  } else if (mte_supported() && running_with_mte()) {
+  } else if (mte_supported() && mte_enabled()) {
     // ASYNC -> ...
     EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
     EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
@@ -211,7 +211,7 @@ TEST(heap_tagging_level, tagging_level_transition_sync_none) {
 #if defined(__BIONIC__) && defined(__aarch64__)
   // We can't test SYNC -> NONE in tagging_level_transitions because we can only make one transition
   // to NONE (which we use to test ASYNC -> NONE), so we test it here separately.
-  if (!mte_supported() || !running_with_mte()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "requires MTE to be enabled";
   }
 
diff --git a/tests/ifaddrs_test.cpp b/tests/ifaddrs_test.cpp
index da6477086..01779f7a3 100644
--- a/tests/ifaddrs_test.cpp
+++ b/tests/ifaddrs_test.cpp
@@ -116,9 +116,7 @@ TEST(ifaddrs, getifaddrs_interfaces) {
 
 static void CheckAddressIsInSet(const std::string& if_name, bool unicast,
                                 const std::set<in_addr_t>& addrs) {
-  ifreq ifr;
-  memset(&ifr, 0, sizeof(ifr));
-  ifr.ifr_addr.sa_family = AF_INET;
+  ifreq ifr = {.ifr_addr.sa_family = AF_INET};
   if_name.copy(ifr.ifr_name, IFNAMSIZ - 1);
 
   int fd = socket(AF_INET, SOCK_DGRAM, 0);
diff --git a/tests/libs/ns_hidden_child_helper.cpp b/tests/libs/ns_hidden_child_helper.cpp
index c2140f10b..77608e210 100644
--- a/tests/libs/ns_hidden_child_helper.cpp
+++ b/tests/libs/ns_hidden_child_helper.cpp
@@ -33,7 +33,7 @@
 #include <string>
 
 #include "../core_shared_libs.h"
-#include "../dlext_private.h"
+#include "../dlext_private_tests.h"
 
 extern "C" void global_function();
 extern "C" void internal_function();
diff --git a/tests/libs/testbinary_is_stack_mte.cpp b/tests/libs/testbinary_is_stack_mte.cpp
index 0cdc466f5..3b6c79c5c 100644
--- a/tests/libs/testbinary_is_stack_mte.cpp
+++ b/tests/libs/testbinary_is_stack_mte.cpp
@@ -35,7 +35,7 @@
 
 #if defined(__BIONIC__) && defined(__aarch64__)
 
-extern "C" int main(int, char**) {
+int main(int, char**) {
   void* mte_tls_ptr = mte_tls();
   *reinterpret_cast<uintptr_t*>(mte_tls_ptr) = 1;
   int ret = is_stack_mte_on() && mte_tls_ptr != nullptr ? 0 : 1;
@@ -45,7 +45,7 @@ extern "C" int main(int, char**) {
 
 #else
 
-extern "C" int main(int, char**) {
+int main(int, char**) {
   printf("RAN\n");
   return 1;
 }
diff --git a/tests/libs/testbinary_is_stack_mte_after_dlopen.cpp b/tests/libs/testbinary_is_stack_mte_after_dlopen.cpp
index 35af8f4fd..93b667001 100644
--- a/tests/libs/testbinary_is_stack_mte_after_dlopen.cpp
+++ b/tests/libs/testbinary_is_stack_mte_after_dlopen.cpp
@@ -84,7 +84,7 @@ unsigned int fault_new_stack_page(uintptr_t low, Fn f) {
   // Useless, but should defeat TCO.
   return new_low + fault_new_stack_page(low, f);
 }
-extern "C" int main(int argc, char** argv) {
+int main(int argc, char** argv) {
   if (argc < 2) {
     return 1;
   }
@@ -150,7 +150,7 @@ extern "C" int main(int argc, char** argv) {
 }
 
 #else
-extern "C" int main(int, char**) {
+int main(int, char**) {
   return 1;
 }
 #endif
diff --git a/tests/limits_test.cpp b/tests/limits_test.cpp
index bc13a3f7f..64d9a3384 100644
--- a/tests/limits_test.cpp
+++ b/tests/limits_test.cpp
@@ -78,3 +78,11 @@ TEST(limits, macros) {
 #error ULLONG_MAX
 #endif
 }
+
+TEST(limits, highest_signal_plus_one) {
+#if defined(__BIONIC__)
+  ASSERT_EQ(65, NSIG_MAX);
+#endif
+  ASSERT_EQ(65, NSIG);
+  ASSERT_EQ(65, _NSIG);
+}
diff --git a/tests/malloc_stress_test.cpp b/tests/malloc_stress_test.cpp
index 00f591952..210eb3a0f 100644
--- a/tests/malloc_stress_test.cpp
+++ b/tests/malloc_stress_test.cpp
@@ -57,7 +57,7 @@ static void PrintLogStats(uint64_t& last_time) {
       }
       // EAGAIN means there is nothing left to read when ANDROID_LOG_NONBLOCK is set.
       if (retval != -EAGAIN) {
-        printf("Failed to read log entry: %s\n", strerrordesc_np(retval));
+        printf("Failed to read log entry: %m");
       }
       break;
     }
diff --git a/tests/malloc_test.cpp b/tests/malloc_test.cpp
index 3f1ba7959..db814dc51 100644
--- a/tests/malloc_test.cpp
+++ b/tests/malloc_test.cpp
@@ -53,7 +53,7 @@
 #if defined(__BIONIC__)
 
 #include "SignalUtils.h"
-#include "dlext_private.h"
+#include "dlext_private_tests.h"
 
 #include "platform/bionic/malloc.h"
 #include "platform/bionic/mte.h"
@@ -466,6 +466,7 @@ TEST(malloc, malloc_info) {
     // Do not verify output for debug malloc.
     ASSERT_TRUE(version == "debug-malloc-1") << "Unknown version: " << version;
   }
+  printf("Allocator version: %s\n", version.c_str());
 #endif
 }
 
@@ -1778,3 +1779,32 @@ TEST(android_mallopt, get_decay_time_enabled) {
   GTEST_SKIP() << "bionic-only test";
 #endif
 }
+
+TEST(android_mallopt, DISABLED_verify_decay_time_on) {
+#if defined(__BIONIC__)
+  bool value;
+  EXPECT_TRUE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
+  EXPECT_TRUE(value) << "decay time did not get enabled properly.";
+#endif
+}
+
+TEST(android_mallopt, decay_time_set_using_env_variable) {
+#if defined(__BIONIC__)
+  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
+
+  bool value;
+  ASSERT_TRUE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
+  ASSERT_FALSE(value) << "decay time did not get disabled properly.";
+
+  // Verify that setting the environment variable here will be carried into
+  // fork'd and exec'd processes.
+  ASSERT_EQ(0, setenv("MALLOC_USE_APP_DEFAULTS", "1", 1));
+  ExecTestHelper eth;
+  std::string executable(testing::internal::GetArgvs()[0]);
+  eth.SetArgs({executable.c_str(), "--gtest_also_run_disabled_tests",
+               "--gtest_filter=android_mallopt.DISABLED_verify_decay_time_on", nullptr});
+  eth.Run([&]() { execv(executable.c_str(), eth.GetArgs()); }, 0, R"(\[  PASSED  \] 1 test)");
+#else
+  GTEST_SKIP() << "bionic-only test";
+#endif
+}
diff --git a/tests/memtag_globals_test.cpp b/tests/memtag_globals_test.cpp
index ff93e7b5d..40023b92c 100644
--- a/tests/memtag_globals_test.cpp
+++ b/tests/memtag_globals_test.cpp
@@ -46,6 +46,7 @@ class MemtagGlobalsTest : public testing::TestWithParam<bool> {};
 TEST_P(MemtagGlobalsTest, test) {
   SKIP_WITH_HWASAN << "MTE globals tests are incompatible with HWASan";
 #if defined(__BIONIC__) && defined(__aarch64__)
+  SKIP_WITH_NATIVE_BRIDGE;  // http://b/242170715
   std::string binary = GetTestLibRoot() + "/memtag_globals_binary";
   bool is_static = MemtagGlobalsTest::GetParam();
   if (is_static) {
diff --git a/tests/memtag_stack_dlopen_test.cpp b/tests/memtag_stack_dlopen_test.cpp
index 68ddb81bd..eb69a620a 100644
--- a/tests/memtag_stack_dlopen_test.cpp
+++ b/tests/memtag_stack_dlopen_test.cpp
@@ -38,9 +38,13 @@
 #include "mte_utils.h"
 #include "utils.h"
 
+#if defined(__BIONIC__)
+#include <bionic/mte.h>
+#endif
+
 TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack) {
 #if defined(__BIONIC__) && defined(__aarch64__)
-  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
+  if (!mte_enabled()) GTEST_SKIP() << "Test requires MTE.";
   if (is_stack_mte_on())
     GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";
 
@@ -58,7 +62,7 @@ TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack) {
 
 TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack2) {
 #if defined(__BIONIC__) && defined(__aarch64__)
-  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
+  if (!mte_enabled()) GTEST_SKIP() << "Test requires MTE.";
   if (is_stack_mte_on())
     GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";
 
@@ -77,7 +81,7 @@ TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack2) {
 TEST(MemtagStackDlopenTest, DlopenRemapsStack) {
 #if defined(__BIONIC__) && defined(__aarch64__)
   // If this test is failing, look at crash logcat for why the test binary died.
-  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
+  if (!mte_enabled()) GTEST_SKIP() << "Test requires MTE.";
   if (is_stack_mte_on())
     GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";
 
@@ -98,7 +102,7 @@ TEST(MemtagStackDlopenTest, DlopenRemapsStack) {
 TEST(MemtagStackDlopenTest, DlopenRemapsStack2) {
 #if defined(__BIONIC__) && defined(__aarch64__)
   // If this test is failing, look at crash logcat for why the test binary died.
-  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
+  if (!mte_enabled()) GTEST_SKIP() << "Test requires MTE.";
   if (is_stack_mte_on())
     GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";
 
diff --git a/tests/memtag_stack_test.cpp b/tests/memtag_stack_test.cpp
index 9d0283010..98e340a4c 100644
--- a/tests/memtag_stack_test.cpp
+++ b/tests/memtag_stack_test.cpp
@@ -19,6 +19,7 @@
 #include <gtest/gtest.h>
 
 #if defined(__BIONIC__)
+#include <android-base/test_utils.h>
 #include "gtest_globals.h"
 #include "platform/bionic/mte.h"
 #include "utils.h"
@@ -32,6 +33,9 @@ TEST_P(MemtagStackTest, test) {
     GTEST_SKIP() << "MTE unsupported";
   }
   bool is_static = std::get<1>(GetParam());
+  if (running_with_hwasan() && !is_static) {
+    GTEST_SKIP() << "Can't run with HWASanified libc.so";
+  }
   std::string helper =
       GetTestLibRoot() + (is_static ? "/stack_tagging_static_helper" : "/stack_tagging_helper");
   const char* arg = std::get<0>(GetParam());
diff --git a/tests/mte_test.cpp b/tests/mte_test.cpp
index 5eb804f80..67db8209c 100644
--- a/tests/mte_test.cpp
+++ b/tests/mte_test.cpp
@@ -39,7 +39,7 @@ static void test_tag_mismatch() {
 #endif
   }
 #if defined(__aarch64__)
-  if (mte_supported() && running_with_mte()) {
+  if (mte_supported() && mte_enabled()) {
     EXPECT_DEATH(
         {
           volatile int load ATTRIBUTE_UNUSED = *mistagged_p;
diff --git a/tests/netdb_test.cpp b/tests/netdb_test.cpp
index 1cb569cc8..f6e8a32d2 100644
--- a/tests/netdb_test.cpp
+++ b/tests/netdb_test.cpp
@@ -79,11 +79,7 @@ TEST(netdb, getaddrinfo_service_lookup) {
 }
 
 TEST(netdb, getaddrinfo_hints) {
-  addrinfo hints;
-  memset(&hints, 0, sizeof(hints));
-  hints.ai_family = AF_INET;
-  hints.ai_socktype = SOCK_STREAM;
-  hints.ai_protocol = IPPROTO_TCP;
+  addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP};
 
   addrinfo* ai = nullptr;
   ASSERT_EQ(0, getaddrinfo( "localhost", "9999", &hints, &ai));
@@ -113,8 +109,7 @@ TEST(netdb, getaddrinfo_ip6_localhost) {
 }
 
 TEST(netdb, getnameinfo_salen) {
-  sockaddr_storage ss;
-  memset(&ss, 0, sizeof(ss));
+  sockaddr_storage ss = {};
   sockaddr* sa = reinterpret_cast<sockaddr*>(&ss);
   char tmp[16];
 
@@ -142,11 +137,8 @@ TEST(netdb, getnameinfo_salen) {
 }
 
 TEST(netdb, getnameinfo_localhost) {
-  sockaddr_in addr;
   char host[NI_MAXHOST];
-  memset(&addr, 0, sizeof(sockaddr_in));
-  addr.sin_family = AF_INET;
-  addr.sin_addr.s_addr = htonl(0x7f000001);
+  sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001)};
   ASSERT_EQ(0, getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                            host, sizeof(host), nullptr, 0, 0));
   ASSERT_STREQ(host, "localhost");
@@ -160,11 +152,8 @@ static void VerifyLocalhostName(const char* name) {
 }
 
 TEST(netdb, getnameinfo_ip6_localhost) {
-  sockaddr_in6 addr;
   char host[NI_MAXHOST];
-  memset(&addr, 0, sizeof(sockaddr_in6));
-  addr.sin6_family = AF_INET6;
-  addr.sin6_addr = in6addr_loopback;
+  sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_addr = in6addr_loopback};
   ASSERT_EQ(0, getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                            host, sizeof(host), nullptr, 0, 0));
   VerifyLocalhostName(host);
diff --git a/tests/netinet_ether_test.cpp b/tests/netinet_ether_test.cpp
index d7b81eb8d..a9de9bfd4 100644
--- a/tests/netinet_ether_test.cpp
+++ b/tests/netinet_ether_test.cpp
@@ -32,8 +32,7 @@ TEST(netinet_ether, ether_aton__ether_ntoa) {
 }
 
 TEST(netinet_ether, ether_aton_r__ether_ntoa_r) {
-  ether_addr addr;
-  memset(&addr, 0, sizeof(addr));
+  ether_addr addr = {};
   ether_addr* a = ether_aton_r("12:34:56:78:9a:Bc", &addr);
   ASSERT_EQ(&addr, a);
   ASSERT_EQ(0x12, addr.ether_addr_octet[0]);
diff --git a/tests/page_size_16kib_compat_test.cpp b/tests/page_size_16kib_compat_test.cpp
index a5d91b8c8..cfd52e255 100644
--- a/tests/page_size_16kib_compat_test.cpp
+++ b/tests/page_size_16kib_compat_test.cpp
@@ -26,11 +26,17 @@
  * SUCH DAMAGE.
  */
 
+#if __has_include (<android/dlext_private.h>)
+#define IS_ANDROID_DL
+#endif
+
 #include "page_size_compat_helpers.h"
 
 #include <android-base/properties.h>
 
-extern "C" void android_set_16kb_appcompat_mode(bool enable_app_compat);
+#if defined(IS_ANDROID_DL)
+#include <android/dlext_private.h>
+#endif
 
 TEST(PageSize16KiBCompatTest, ElfAlignment4KiB_LoadElf) {
   if (getpagesize() != 0x4000) {
@@ -52,11 +58,17 @@ TEST(PageSize16KiBCompatTest, ElfAlignment4KiB_LoadElf_perAppOption) {
     GTEST_SKIP() << "This test is only applicable to 16kB page-size devices";
   }
 
+#if defined(IS_ANDROID_DL)
   android_set_16kb_appcompat_mode(true);
+#endif
+
   std::string lib = GetTestLibRoot() + "/libtest_elf_max_page_size_4kib.so";
   void* handle = nullptr;
 
   OpenTestLibrary(lib, false /*should_fail*/, &handle);
   CallTestFunction(handle);
+
+#if defined(IS_ANDROID_DL)
   android_set_16kb_appcompat_mode(false);
+#endif
 }
diff --git a/tests/pthread_test.cpp b/tests/pthread_test.cpp
index 5ce7d4d71..680ef6e4c 100644
--- a/tests/pthread_test.cpp
+++ b/tests/pthread_test.cpp
@@ -59,6 +59,39 @@ TEST(pthread, pthread_key_create) {
   ASSERT_EQ(EINVAL, pthread_key_delete(key));
 }
 
+static std::vector<void*> example_key_destructor_data;
+static pthread_key_t example_key;
+static void example_key_destructor(void *data) {
+  // By the time the destructor function is running,
+  // this thread's value for the key should have been zeroed.
+  ASSERT_EQ(NULL, pthread_getspecific(example_key));
+
+  // Store the value so we can check we got the expected result.
+  example_key_destructor_data.push_back(data);
+}
+
+TEST(pthread, pthread_key_destructors) {
+  ASSERT_EQ(0, pthread_key_create(&example_key, example_key_destructor));
+
+  // Check that the destructor isn't called for a default null value.
+  std::thread([]() {}).join();
+  ASSERT_TRUE(example_key_destructor_data.empty());
+
+  // Check that the destructor isn't called for an explicit null value.
+  std::thread([]() {
+    ASSERT_EQ(0, pthread_setspecific(example_key, (void*) 1234));
+    ASSERT_EQ(0, pthread_setspecific(example_key, nullptr));
+  }).join();
+  ASSERT_TRUE(example_key_destructor_data.empty());
+
+  // Check that the destructor is called for a non-null value.
+  std::thread([]() { ASSERT_EQ(0, pthread_setspecific(example_key, (void*) 1234)); }).join();
+  ASSERT_EQ(1u, example_key_destructor_data.size());
+  ASSERT_EQ((void*) 1234, example_key_destructor_data[0]);
+
+  ASSERT_EQ(0, pthread_key_delete(example_key));
+}
+
 TEST(pthread, pthread_keys_max) {
   // POSIX says PTHREAD_KEYS_MAX should be at least _POSIX_THREAD_KEYS_MAX.
   ASSERT_GE(PTHREAD_KEYS_MAX, _POSIX_THREAD_KEYS_MAX);
diff --git a/tests/pty_test.cpp b/tests/pty_test.cpp
index d5d8994be..a5e5a570f 100644
--- a/tests/pty_test.cpp
+++ b/tests/pty_test.cpp
@@ -139,9 +139,10 @@ TEST(pty, bug_28979140) {
   arg.fd = tty;
   arg.data_count = TEST_DATA_COUNT;
   arg.matched = true;
-  ASSERT_EQ(0, pthread_create(&thread, nullptr,
-                              reinterpret_cast<void*(*)(void*)>(PtyReader_28979140),
-                              &arg));
+  ASSERT_EQ(0, pthread_create(&thread, nullptr, [](void* arg)->void* {
+    PtyReader_28979140(static_cast<PtyReader_28979140_Arg*>(arg));
+    return nullptr;
+  }, &arg));
 
   CPU_ZERO(&cpus);
   CPU_SET(arg.main_cpu_id, &cpus);
diff --git a/tests/sched_test.cpp b/tests/sched_test.cpp
index 448fae980..4009e1dbe 100644
--- a/tests/sched_test.cpp
+++ b/tests/sched_test.cpp
@@ -165,7 +165,6 @@ TEST(sched, cpu_op) {
   }
 }
 
-
 TEST(sched, cpu_alloc_small) {
   cpu_set_t* set = CPU_ALLOC(17);
   size_t size = CPU_ALLOC_SIZE(17);
@@ -313,7 +312,7 @@ TEST(sched, sched_getaffinity_failure) {
 #pragma clang diagnostic pop
 }
 
-TEST(pthread, sched_getaffinity) {
+TEST(sched, sched_getaffinity) {
   cpu_set_t set;
   CPU_ZERO(&set);
   ASSERT_EQ(0, sched_getaffinity(getpid(), sizeof(set), &set));
@@ -329,7 +328,7 @@ TEST(sched, sched_setaffinity_failure) {
 #pragma clang diagnostic pop
 }
 
-TEST(pthread, sched_setaffinity) {
+TEST(sched, sched_setaffinity) {
   cpu_set_t set;
   CPU_ZERO(&set);
   ASSERT_EQ(0, sched_getaffinity(getpid(), sizeof(set), &set));
@@ -337,3 +336,25 @@ TEST(pthread, sched_setaffinity) {
   // but it ought to be safe to ask for the same affinity you already have.
   ASSERT_EQ(0, sched_setaffinity(getpid(), sizeof(set), &set));
 }
+
+TEST(sched, sched_getattr) {
+#if defined(__BIONIC__)
+  struct sched_attr sa;
+  ASSERT_EQ(0, sched_getattr(getpid(), &sa, sizeof(sa), 0));
+#else
+  GTEST_SKIP() << "our glibc is too old";
+#endif
+}
+
+TEST(sched, sched_setattr_failure) {
+#if defined(__BIONIC__)
+  // Trivial test of the errno-preserving/returning behavior.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wnonnull"
+  ASSERT_EQ(-1, sched_setattr(getpid(), nullptr, 0));
+  ASSERT_ERRNO(EINVAL);
+#pragma clang diagnostic pop
+#else
+  GTEST_SKIP() << "our glibc is too old";
+#endif
+}
diff --git a/tests/setjmp_test.cpp b/tests/setjmp_test.cpp
index 946928517..836aadc4c 100644
--- a/tests/setjmp_test.cpp
+++ b/tests/setjmp_test.cpp
@@ -18,6 +18,7 @@
 
 #include <setjmp.h>
 #include <stdlib.h>
+#include <sys/auxv.h>
 #include <sys/syscall.h>
 #include <unistd.h>
 
@@ -364,3 +365,42 @@ TEST(setjmp, bug_152210274) {
   GTEST_SKIP() << "tests uses functions not in glibc";
 #endif
 }
+
+#if defined(__aarch64__)
+TEST(setjmp, sigsetjmp_sme) {
+  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+    GTEST_SKIP() << "SME is not enabled on device.";
+  }
+
+  uint64_t svcr, za_state;
+  sigjmp_buf jb;
+  __asm__ __volatile__(".arch_extension sme; smstart za");
+  sigsetjmp(jb, 0);
+  __asm__ __volatile__(".arch_extension sme; mrs %0, SVCR" : "=r"(svcr));
+  __asm__ __volatile__(".arch_extension sme; smstop za");  // Turn ZA off anyway.
+  za_state = svcr & 0x2UL;
+  ASSERT_EQ(0UL, za_state);
+}
+
+TEST(setjmp, siglongjmp_sme) {
+  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+    GTEST_SKIP() << "SME is not enabled on device.";
+  }
+
+  uint64_t svcr, za_state;
+  int value;
+  sigjmp_buf jb;
+  if ((value = sigsetjmp(jb, 0)) == 0) {
+    __asm__ __volatile__(".arch_extension sme; smstart za");
+    siglongjmp(jb, 789);
+    __asm__ __volatile__(".arch_extension sme; smstop za");
+    FAIL();  // Unreachable.
+  } else {
+    __asm__ __volatile__(".arch_extension sme; mrs %0, SVCR" : "=r"(svcr));
+    __asm__ __volatile__(".arch_extension sme; smstop za");  // Turn ZA off anyway.
+    za_state = svcr & 0x2UL;
+    ASSERT_EQ(789, value);
+    ASSERT_EQ(0UL, za_state);
+  }
+}
+#endif
diff --git a/tests/signal_test.cpp b/tests/signal_test.cpp
index c1719dc0e..27f5c6cf2 100644
--- a/tests/signal_test.cpp
+++ b/tests/signal_test.cpp
@@ -16,6 +16,7 @@
 
 #include <errno.h>
 #include <signal.h>
+#include <sys/auxv.h>
 #include <sys/cdefs.h>
 #include <sys/syscall.h>
 #include <sys/types.h>
@@ -804,10 +805,7 @@ TEST(signal, rt_tgsigqueueinfo) {
 
   ASSERT_EQ(0, sigaction(SIGUSR1, &handler, nullptr));
 
-  siginfo sent;
-  memset(&sent, 0, sizeof(sent));
-
-  sent.si_code = SI_TKILL;
+  siginfo sent = {.si_code = SI_TKILL};
   ASSERT_EQ(0, syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &sent))
     << "rt_tgsigqueueinfo failed: " << strerror(errno) << error_msg;
   ASSERT_EQ(sent.si_code, received.si_code) << "rt_tgsigqueueinfo modified si_code, expected "
@@ -1073,3 +1071,35 @@ TEST(signal, str2sig) {
   GTEST_SKIP() << "our old glibc doesn't have str2sig";
 #endif
 }
+
+#if defined(__aarch64__)
+__attribute__((target("arch=armv9+sme"))) __arm_new("za") static void FunctionUsingZA() {
+  raise(SIGUSR1);
+}
+
+TEST(signal, sme_tpidr2_clear) {
+  // When using SME, on entering a signal handler the kernel should clear TPIDR2_EL0, but this was
+  // not always correctly done. This tests checks if the kernel correctly clears it or not.
+  if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
+    GTEST_SKIP() << "SME is not enabled on device.";
+  }
+
+  static uint64_t tpidr2 = 0;
+  struct sigaction handler = {};
+  handler.sa_sigaction = [](int, siginfo_t*, void*) {
+    uint64_t zero = 0;
+    __asm__ __volatile__(".arch_extension sme; mrs %0, TPIDR2_EL0" : "=r"(tpidr2));
+    __asm__ __volatile__(".arch_extension sme; msr TPIDR2_EL0, %0" : : "r"(zero));  // Clear TPIDR2.
+  };
+  handler.sa_flags = SA_SIGINFO;
+
+  ASSERT_EQ(0, sigaction(SIGUSR1, &handler, nullptr));
+
+  FunctionUsingZA();
+
+  ASSERT_EQ(0x0UL, tpidr2)
+      << "Broken kernel! TPIDR2_EL0 was not null in the signal handler! "
+      << "Please make sure the following patch has been applied to the kernel: "
+      << "https://lore.kernel.org/linux-arm-kernel/20250417190113.3778111-1-mark.rutland@arm.com/";
+}
+#endif
diff --git a/tests/stack_unwinding_test.cpp b/tests/stack_unwinding_test.cpp
index 2f891a6e1..fc6c25c10 100644
--- a/tests/stack_unwinding_test.cpp
+++ b/tests/stack_unwinding_test.cpp
@@ -43,8 +43,7 @@ _Unwind_Reason_Code FrameCounter(_Unwind_Context* ctx __unused, void* arg) {
   const char* symbol = "<unknown>";
   int offset = 0;
 
-  Dl_info info;
-  memset(&info, 0, sizeof(info));
+  Dl_info info = {};
   if (dladdr(ip, &info) != 0) {
     symbol = info.dli_sname;
     if (info.dli_saddr != nullptr) {
diff --git a/tests/stdatomic_test.cpp b/tests/stdatomic_test.cpp
index 8a5408060..23e9b3e58 100644
--- a/tests/stdatomic_test.cpp
+++ b/tests/stdatomic_test.cpp
@@ -16,8 +16,13 @@
 
 #include <gtest/gtest.h>
 
-// The real <stdatomic.h> checks for the availability of C++'s atomics and uses them if present. Since
-// we want to test the libc versions, we instead include <bits/stdatomic.h> where they're actually defined.
+// The real <stdatomic.h> checks for the availability of C++'s <atomic> and
+// uses that instead if present.
+// We want to test the C interfaces, so we instead include
+// <bits/stdatomic.h> directly.
+// This doesn't entirely work because gtest also (transitively) pulls in <atomic>.
+// It's not clear there's a good fix for this,
+// other than switching to a non-C++ unit test framework for bionic.
 #include <bits/stdatomic.h>
 
 #include <pthread.h>
@@ -37,8 +42,18 @@ TEST(stdatomic, LOCK_FREE) {
 }
 
 TEST(stdatomic, init) {
-  atomic_int v = 123;
+  // ATOMIC_VAR_INIT has been removed from C23,
+  // but is still in POSIX 2024.
+  // Even if it is removed from there,
+  // we should probably keep it indefinitely for source compatibility.
+  // libc++'s <atomic> (which we can't entirely avoid: see above)
+  // marks the macro deprecated,
+  // so we need to silence that.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-pragma"
+  atomic_int v = ATOMIC_VAR_INIT(123);
   ASSERT_EQ(123, atomic_load(&v));
+#pragma clang diagnostic pop
 
   atomic_store_explicit(&v, 456, memory_order_relaxed);
   ASSERT_EQ(456, atomic_load(&v));
diff --git a/tests/stdio_ext_test.cpp b/tests/stdio_ext_test.cpp
index dce1a662f..dc0e9efb0 100644
--- a/tests/stdio_ext_test.cpp
+++ b/tests/stdio_ext_test.cpp
@@ -29,6 +29,8 @@
 #include <wchar.h>
 #include <locale.h>
 
+#include <thread>
+
 #include <android-base/file.h>
 
 #include "utils.h"
@@ -235,23 +237,20 @@ TEST(stdio_ext, __fsetlocking) {
   fclose(fp);
 }
 
-static void LockingByCallerHelper(std::atomic<pid_t>* pid) {
-  *pid = gettid();
-  flockfile(stdout);
-  funlockfile(stdout);
-}
-
 TEST(stdio_ext, __fsetlocking_BYCALLER) {
   // Check if users can use flockfile/funlockfile to protect stdio operations.
   int old_state = __fsetlocking(stdout, FSETLOCKING_BYCALLER);
   flockfile(stdout);
-  pthread_t thread;
+
   std::atomic<pid_t> pid(0);
-  ASSERT_EQ(0, pthread_create(&thread, nullptr,
-                              reinterpret_cast<void* (*)(void*)>(LockingByCallerHelper), &pid));
+  std::thread thread([&]() {
+    pid = gettid();
+    flockfile(stdout);
+    funlockfile(stdout);
+  });
   WaitUntilThreadSleep(pid);
   funlockfile(stdout);
 
-  ASSERT_EQ(0, pthread_join(thread, nullptr));
+  thread.join();
   __fsetlocking(stdout, old_state);
 }
diff --git a/tests/sys_mman_test.cpp b/tests/sys_mman_test.cpp
index 54a0b6463..85096bb18 100644
--- a/tests/sys_mman_test.cpp
+++ b/tests/sys_mman_test.cpp
@@ -295,7 +295,6 @@ TEST(sys_mman, memfd_create) {
   // Is the MFD_CLOEXEC flag obeyed?
   errno = 0;
   int fd = memfd_create("doesn't matter", 0);
-  if (fd == -1 && errno == ENOSYS) GTEST_SKIP() << "no memfd_create() in this kernel";
   ASSERT_NE(-1, fd) << strerror(errno);
 
   int f = fcntl(fd, F_GETFD);
diff --git a/tests/sys_msg_test.cpp b/tests/sys_msg_test.cpp
index b2d855d41..26e45595c 100644
--- a/tests/sys_msg_test.cpp
+++ b/tests/sys_msg_test.cpp
@@ -45,8 +45,7 @@ TEST(sys_msg, smoke) {
   ASSERT_NE(id, -1);
 
   // Queue should be empty.
-  msqid_ds ds;
-  memset(&ds, 0, sizeof(ds));
+  msqid_ds ds = {};
   ASSERT_EQ(0, msgctl(id, IPC_STAT, &ds));
   ASSERT_EQ(0U, ds.msg_qnum);
   ASSERT_EQ(0U, ds.msg_cbytes);
@@ -64,7 +63,7 @@ TEST(sys_msg, smoke) {
   ASSERT_EQ(sizeof(msg.data), ds.msg_cbytes);
 
   // Read the message.
-  memset(&msg, 0, sizeof(msg));
+  msg = {};
   ASSERT_EQ(static_cast<ssize_t>(sizeof(msg.data)),
             msgrcv(id, &msg, sizeof(msg.data), 0, 0));
   ASSERT_EQ(1, msg.type);
diff --git a/tests/sys_procfs_test.cpp b/tests/sys_procfs_test.cpp
index 4a64742b4..d707c5d57 100644
--- a/tests/sys_procfs_test.cpp
+++ b/tests/sys_procfs_test.cpp
@@ -20,20 +20,11 @@
 #include <sys/procfs.h>
 
 TEST(sys_procfs, types) {
-  elf_greg_t reg;
-  memset(&reg, 0, sizeof(reg));
-
-  elf_gregset_t regs;
-  memset(&regs, 0, sizeof(regs));
-
-  elf_fpregset_t fp_regs;
-  memset(&fp_regs, 0, sizeof(fp_regs));
-
-  prgregset_t pr_g_regs;
-  memset(&pr_g_regs, 0, sizeof(pr_g_regs));
-
-  prfpregset_t pr_fp_regs;
-  memset(&pr_fp_regs, 0, sizeof(pr_fp_regs));
+  elf_greg_t reg = {};
+  elf_gregset_t regs = {};
+  elf_fpregset_t fp_regs = {};
+  prgregset_t pr_g_regs = {};
+  prfpregset_t pr_fp_regs = {};
 
   static_assert(sizeof(prgregset_t) == sizeof(elf_gregset_t), "");
   static_assert(sizeof(prfpregset_t) == sizeof(elf_fpregset_t), "");
diff --git a/tests/sys_ptrace_test.cpp b/tests/sys_ptrace_test.cpp
index 499adbb15..1f9c2a298 100644
--- a/tests/sys_ptrace_test.cpp
+++ b/tests/sys_ptrace_test.cpp
@@ -116,8 +116,7 @@ static void set_watchpoint(pid_t child, uintptr_t address, size_t size) {
   ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -1, &address)) << strerror(errno);
   ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -2, &control)) << strerror(errno);
 #else // aarch64
-  user_hwdebug_state dreg_state;
-  memset(&dreg_state, 0, sizeof dreg_state);
+  user_hwdebug_state dreg_state = {};
   dreg_state.dbg_regs[0].addr = address;
   dreg_state.dbg_regs[0].ctrl = control;
 
@@ -304,8 +303,7 @@ static void set_breakpoint(pid_t child) {
   ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, 1, &address)) << strerror(errno);
   ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, 2, &control)) << strerror(errno);
 #else  // aarch64
-  user_hwdebug_state dreg_state;
-  memset(&dreg_state, 0, sizeof dreg_state);
+  user_hwdebug_state dreg_state = {};
   dreg_state.dbg_regs[0].addr = reinterpret_cast<uintptr_t>(address);
   dreg_state.dbg_regs[0].ctrl = control;
 
diff --git a/tests/sys_sem_test.cpp b/tests/sys_sem_test.cpp
index 27943cfbf..0b7a7ffbe 100644
--- a/tests/sys_sem_test.cpp
+++ b/tests/sys_sem_test.cpp
@@ -47,8 +47,7 @@ TEST(sys_sem, smoke) {
   ASSERT_NE(id, -1);
 
   // Check semaphore info.
-  semid_ds ds;
-  memset(&ds, 0, sizeof(ds));
+  semid_ds ds = {};
   ASSERT_EQ(0, semctl(id, 0, IPC_STAT, &ds));
   ASSERT_EQ(1U, ds.sem_nsems);
 
diff --git a/tests/sys_shm_test.cpp b/tests/sys_shm_test.cpp
index 65f9ebab0..74d13b5a4 100644
--- a/tests/sys_shm_test.cpp
+++ b/tests/sys_shm_test.cpp
@@ -44,8 +44,7 @@ TEST(sys_shm, smoke) {
   ASSERT_NE(id, -1);
 
   // Check segment info.
-  shmid_ds ds;
-  memset(&ds, 0, sizeof(ds));
+  shmid_ds ds = {};
   ASSERT_EQ(0, shmctl(id, IPC_STAT, &ds));
   ASSERT_EQ(1234U, ds.shm_segsz);
 
diff --git a/tests/sys_socket_test.cpp b/tests/sys_socket_test.cpp
index 1cfbfb2cf..559ee7d68 100644
--- a/tests/sys_socket_test.cpp
+++ b/tests/sys_socket_test.cpp
@@ -42,10 +42,7 @@ static void* ConnectFn(void* data) {
     return reinterpret_cast<void*>(-1);
   }
 
-  struct sockaddr_un addr;
-  memset(&addr, 0, sizeof(addr));
-  addr.sun_family = AF_UNIX;
-  addr.sun_path[0] = '\0';
+  struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path[0] = '\0'};
   strcpy(addr.sun_path + 1, pdata->sock_path);
 
   if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
@@ -66,10 +63,7 @@ static void RunTest(void (*test_fn)(struct sockaddr_un*, int),
   int fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
   ASSERT_NE(fd, -1) << strerror(errno);
 
-  struct sockaddr_un addr;
-  memset(&addr, 0, sizeof(addr));
-  addr.sun_family = AF_UNIX;
-  addr.sun_path[0] = '\0';
+  struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path[0] = '\0'};
   strcpy(addr.sun_path + 1, sock_path);
 
   ASSERT_NE(-1, bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr))) << strerror(errno);
@@ -141,9 +135,7 @@ static void TestRecvMMsg(struct sockaddr_un *addr, int fd) {
   int fd_acc = accept(fd, reinterpret_cast<struct sockaddr*>(addr), &len);
   ASSERT_NE(fd_acc, -1) << strerror(errno);
 
-  struct mmsghdr msgs[NUM_RECV_MSGS];
-  memset(msgs, 0, sizeof(struct mmsghdr)*NUM_RECV_MSGS);
-
+  struct mmsghdr msgs[NUM_RECV_MSGS] = {};
   struct iovec io[NUM_RECV_MSGS];
   char bufs[NUM_RECV_MSGS][100];
   for (size_t i = 0; i < NUM_RECV_MSGS; i++) {
@@ -155,10 +147,7 @@ static void TestRecvMMsg(struct sockaddr_un *addr, int fd) {
     msgs[i].msg_len = sizeof(struct msghdr);
   }
 
-  struct timespec ts;
-  memset(&ts, 0, sizeof(ts));
-  ts.tv_sec = 5;
-  ts.tv_nsec = 0;
+  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
   ASSERT_EQ(NUM_RECV_MSGS,
             static_cast<size_t>(recvmmsg(fd_acc, msgs, NUM_RECV_MSGS, 0, &ts)))
            << strerror(errno);
@@ -189,8 +178,7 @@ const char* g_SendMsgs[] = {
 #define NUM_SEND_MSGS (sizeof(g_SendMsgs)/sizeof(const char*))
 
 static bool SendMMsg(int fd) {
-  struct mmsghdr msgs[NUM_SEND_MSGS];
-  memset(msgs, 0, sizeof(struct mmsghdr)*NUM_SEND_MSGS);
+  struct mmsghdr msgs[NUM_SEND_MSGS] = {};
   struct iovec io[NUM_SEND_MSGS];
   for (size_t i = 0; i < NUM_SEND_MSGS; i++) {
     io[i].iov_base = reinterpret_cast<void*>(const_cast<char*>(g_SendMsgs[i]));
diff --git a/tests/sys_sysinfo_test.cpp b/tests/sys_sysinfo_test.cpp
index 69656ad38..b8bcf924c 100644
--- a/tests/sys_sysinfo_test.cpp
+++ b/tests/sys_sysinfo_test.cpp
@@ -39,8 +39,7 @@ TEST(sys_sysinfo, smoke) {
 }
 
 TEST(sys_sysinfo, sysinfo) {
-  struct sysinfo si;
-  memset(&si, 0, sizeof(si));
+  struct sysinfo si = {};
   ASSERT_EQ(0, sysinfo(&si));
 
   ASSERT_GT(static_cast<long>(si.uptime), 10);  // You're not running CTS within 10s of booting!
diff --git a/tests/sys_timex_test.cpp b/tests/sys_timex_test.cpp
index 44b73c994..627c1ee73 100644
--- a/tests/sys_timex_test.cpp
+++ b/tests/sys_timex_test.cpp
@@ -21,15 +21,13 @@
 #include <gtest/gtest.h>
 
 TEST(sys_timex, adjtimex_smoke) {
-  timex t;
-  memset(&t, 0, sizeof(t));
+  timex t = {};
   // adjtimex/clock_adjtime return the clock state on success, -1 on failure.
   ASSERT_NE(-1, adjtimex(&t));
 }
 
 TEST(sys_timex, clock_adjtime_smoke) {
-  timex t;
-  memset(&t, 0, sizeof(t));
+  timex t = {};
   // adjtimex/clock_adjtime return the clock state on success, -1 on failure.
   ASSERT_NE(-1, clock_adjtime(CLOCK_REALTIME, &t));
 }
diff --git a/tests/time_test.cpp b/tests/time_test.cpp
index baafbf666..cf4de06a5 100644
--- a/tests/time_test.cpp
+++ b/tests/time_test.cpp
@@ -126,8 +126,7 @@ TEST(time, mktime_empty_TZ) {
   // tzcode used to have a bug where it didn't reinitialize some internal state.
 
   // Choose a time where DST is set.
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
   t.tm_year = 1980 - 1900;
   t.tm_mon = 6;
   t.tm_mday = 2;
@@ -136,7 +135,7 @@ TEST(time, mktime_empty_TZ) {
   tzset();
   ASSERT_EQ(static_cast<time_t>(331372800U), mktime(&t));
 
-  memset(&t, 0, sizeof(tm));
+  t = {};
   t.tm_year = 1980 - 1900;
   t.tm_mon = 6;
   t.tm_mday = 2;
@@ -173,8 +172,7 @@ TEST(time, mktime_10310929) {
 TEST(time, mktime_EOVERFLOW) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
 
   // LP32 year range is 1901-2038, so this year is guaranteed not to overflow.
   t.tm_year = 2016 - 1900;
@@ -212,8 +210,7 @@ TEST(time, mktime_EOVERFLOW) {
 TEST(time, mktime_invalid_tm_TZ_combination) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
   t.tm_year = 2022 - 1900;
   t.tm_mon = 11;
   t.tm_mday = 31;
@@ -248,8 +245,7 @@ TEST(time, mktime_after_2100) {
 TEST(time, strftime) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
   t.tm_year = 200;
   t.tm_mon = 2;
   t.tm_mday = 10;
@@ -270,8 +266,7 @@ TEST(time, strftime) {
 TEST(time, strftime_second_before_epoch) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
   t.tm_year = 1969 - 1900;
   t.tm_mon = 11;
   t.tm_mday = 31;
@@ -287,9 +282,7 @@ TEST(time, strftime_second_before_epoch) {
 
 TEST(time, strftime_Z_null_tm_zone) {
   // Netflix on Nexus Player wouldn't start (http://b/25170306).
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
-
+  struct tm t = {};
   char buf[64];
 
   setenv("TZ", "America/Los_Angeles", 1);
@@ -409,8 +402,7 @@ TEST(time, strftime_l) {
 
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
+  struct tm t = {};
   t.tm_year = 200;
   t.tm_mon = 2;
   t.tm_mday = 10;
@@ -427,15 +419,14 @@ TEST(time, strftime_l) {
 TEST(time, strptime) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
+  struct tm t = {};
   char buf[64];
 
-  memset(&t, 0, sizeof(t));
   strptime("11:14", "%R", &t);
   strftime(buf, sizeof(buf), "%H:%M", &t);
   EXPECT_STREQ("11:14", buf);
 
-  memset(&t, 0, sizeof(t));
+  t = {};
   strptime("09:41:53", "%T", &t);
   strftime(buf, sizeof(buf), "%H:%M:%S", &t);
   EXPECT_STREQ("09:41:53", buf);
@@ -445,15 +436,14 @@ TEST(time, strptime_l) {
 #if !defined(ANDROID_HOST_MUSL)
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
+  struct tm t = {};
   char buf[64];
 
-  memset(&t, 0, sizeof(t));
   strptime_l("11:14", "%R", &t, LC_GLOBAL_LOCALE);
   strftime_l(buf, sizeof(buf), "%H:%M", &t, LC_GLOBAL_LOCALE);
   EXPECT_STREQ("11:14", buf);
 
-  memset(&t, 0, sizeof(t));
+  t = {};
   strptime_l("09:41:53", "%T", &t, LC_GLOBAL_LOCALE);
   strftime_l(buf, sizeof(buf), "%H:%M:%S", &t, LC_GLOBAL_LOCALE);
   EXPECT_STREQ("09:41:53", buf);
@@ -637,8 +627,7 @@ static void NoOpNotifyFunction(sigval) {
 }
 
 TEST(time, timer_create) {
-  sigevent se;
-  memset(&se, 0, sizeof(se));
+  sigevent se = {};
   se.sigev_notify = SIGEV_THREAD;
   se.sigev_notify_function = NoOpNotifyFunction;
   timer_t timer_id;
@@ -666,8 +655,7 @@ static void timer_create_SIGEV_SIGNAL_signal_handler(int signal_number) {
 }
 
 TEST(time, timer_create_SIGEV_SIGNAL) {
-  sigevent se;
-  memset(&se, 0, sizeof(se));
+  sigevent se = {};
   se.sigev_notify = SIGEV_SIGNAL;
   se.sigev_signo = SIGUSR1;
 
@@ -705,10 +693,7 @@ struct Counter {
 
  public:
   explicit Counter(void (*fn)(sigval)) : value(0), timer_valid(false) {
-    memset(&se, 0, sizeof(se));
-    se.sigev_notify = SIGEV_THREAD;
-    se.sigev_notify_function = fn;
-    se.sigev_value.sival_ptr = this;
+    se = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = fn, .sigev_value.sival_ptr = this};
     Create();
   }
   void DeleteTimer() {
@@ -909,9 +894,7 @@ static void TimerDeleteCallback(sigval value) {
 
 TEST(time, timer_delete_from_timer_thread) {
   TimerDeleteData tdd;
-  sigevent se;
-
-  memset(&se, 0, sizeof(se));
+  sigevent se = {};
   se.sigev_notify = SIGEV_THREAD;
   se.sigev_notify_function = TimerDeleteCallback;
   se.sigev_value.sival_ptr = &tdd;
@@ -1252,11 +1235,9 @@ TEST(time, strftime_strptime_s) {
   strftime(buf, sizeof(buf), "<%s>", &tm0);
   EXPECT_STREQ("<378691200>", buf);
 
-  struct tm tm;
-
   setenv("TZ", "America/Los_Angeles", 1);
   tzset();
-  memset(&tm, 0xff, sizeof(tm));
+  struct tm tm = {};
   char* p = strptime("378720000x", "%s", &tm);
   ASSERT_EQ('x', *p);
   EXPECT_EQ(0, tm.tm_sec);
@@ -1271,7 +1252,7 @@ TEST(time, strftime_strptime_s) {
 
   setenv("TZ", "UTC", 1);
   tzset();
-  memset(&tm, 0xff, sizeof(tm));
+  tm = {};
   p = strptime("378691200x", "%s", &tm);
   ASSERT_EQ('x', *p);
   EXPECT_EQ(0, tm.tm_sec);
diff --git a/tests/uchar_test.cpp b/tests/uchar_test.cpp
index fd3b3322e..b554ee5bc 100644
--- a/tests/uchar_test.cpp
+++ b/tests/uchar_test.cpp
@@ -73,9 +73,8 @@ TEST(uchar, start_state) {
   uselocale(LC_GLOBAL_LOCALE);
 
   char out[MB_LEN_MAX];
-  mbstate_t ps;
+  mbstate_t ps = {};
 
-  memset(&ps, 0, sizeof(ps));
   EXPECT_EQ(static_cast<size_t>(-2), mbrtoc32(nullptr, "\xc2", 1, &ps));
   errno = 0;
   EXPECT_EQ(static_cast<size_t>(-1), c32rtomb(out, 0x00a2, &ps));
@@ -86,12 +85,12 @@ TEST(uchar, start_state) {
 
   // If the first argument to c32rtomb is nullptr or the second is L'\0' the shift
   // state should be reset.
-  memset(&ps, 0, sizeof(ps));
+  ps = {};
   EXPECT_EQ(static_cast<size_t>(-2), mbrtoc32(nullptr, "\xc2", 1, &ps));
   EXPECT_EQ(1U, c32rtomb(nullptr, 0x00a2, &ps));
   EXPECT_TRUE(mbsinit(&ps));
 
-  memset(&ps, 0, sizeof(ps));
+  ps = {};
   EXPECT_EQ(static_cast<size_t>(-2), mbrtoc32(nullptr, "\xf0\xa4", 1, &ps));
   EXPECT_EQ(1U, c32rtomb(out, L'\0', &ps));
   EXPECT_TRUE(mbsinit(&ps));
@@ -299,8 +298,7 @@ TEST(uchar, mbrtoc16_incomplete) {
   ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
   uselocale(LC_GLOBAL_LOCALE);
 
-  mbstate_t ps;
-  memset(&ps, 0, sizeof(ps));
+  mbstate_t ps = {};
 
   test_mbrtoc16_incomplete(&ps);
   test_mbrtoc16_incomplete(nullptr);
@@ -475,8 +473,7 @@ TEST(uchar, mbrtoc32_incomplete) {
   ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
   uselocale(LC_GLOBAL_LOCALE);
 
-  mbstate_t ps;
-  memset(&ps, 0, sizeof(ps));
+  mbstate_t ps = {};
 
   test_mbrtoc32_incomplete(&ps);
   test_mbrtoc32_incomplete(nullptr);
diff --git a/tests/unistd_test.cpp b/tests/unistd_test.cpp
index 9ad3b6dd4..c28a46e7f 100644
--- a/tests/unistd_test.cpp
+++ b/tests/unistd_test.cpp
@@ -1000,6 +1000,9 @@ TEST(UNISTD_TEST, sysconf) {
   VERIFY_SYSCONF_POSITIVE(_SC_EXPR_NEST_MAX);
   VERIFY_SYSCONF_POSITIVE(_SC_LINE_MAX);
   VerifySysconf(_SC_NGROUPS_MAX, "_SC_NGROUPS_MAX", [](long v){return v >= 0 && v <= NGROUPS_MAX;});
+#if defined(__BIONIC__) || defined(_SC_NSIG) // New in POSIX 2024.
+  EXPECT_EQ(NSIG, sysconf(_SC_NSIG));
+#endif
   VERIFY_SYSCONF_POSITIVE(_SC_OPEN_MAX);
   VERIFY_SYSCONF_POSITIVE(_SC_PASS_MAX);
   VERIFY_SYSCONF_POSIX_VERSION(_SC_2_C_BIND);
@@ -1393,9 +1396,7 @@ TEST(UNISTD_TEST, getdomainname) {
 }
 
 TEST(UNISTD_TEST, setdomainname) {
-  __user_cap_header_struct header;
-  memset(&header, 0, sizeof(header));
-  header.version = _LINUX_CAPABILITY_VERSION_3;
+  __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
 
   __user_cap_data_struct old_caps[_LINUX_CAPABILITY_U32S_3];
   ASSERT_EQ(0, capget(&header, &old_caps[0]));
diff --git a/tests/utils.h b/tests/utils.h
index 4740e59ef..281e4feb8 100644
--- a/tests/utils.h
+++ b/tests/utils.h
@@ -65,12 +65,6 @@
 #define KNOWN_FAILURE_ON_BIONIC(x) x
 #endif
 
-// bionic's dlsym doesn't work in static binaries, so we can't access icu,
-// so any unicode test case will fail.
-static inline bool have_dl() {
-  return (dlopen("libc.so", 0) != nullptr);
-}
-
 static inline bool running_with_native_bridge() {
 #if defined(__BIONIC__)
   static const prop_info* pi = __system_property_find("ro.dalvik.vm.isa." ABI_STRING);
@@ -295,16 +289,6 @@ class FdLeakChecker {
   size_t start_count_ = CountOpenFds();
 };
 
-static inline bool running_with_mte() {
-#ifdef __aarch64__
-  int level = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
-  return level >= 0 && (level & PR_TAGGED_ADDR_ENABLE) &&
-         (level & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE;
-#else
-  return false;
-#endif
-}
-
 bool IsLowRamDevice();
 
 int64_t NanoTime();
diff --git a/tests/wchar_test.cpp b/tests/wchar_test.cpp
index a811fd84d..c76f80062 100644
--- a/tests/wchar_test.cpp
+++ b/tests/wchar_test.cpp
@@ -130,22 +130,21 @@ TEST(wchar, wcrtomb_start_state) {
   uselocale(LC_GLOBAL_LOCALE);
 
   char out[MB_LEN_MAX];
-  mbstate_t ps;
+  mbstate_t ps = {};
 
   // Any non-initial state is invalid when calling wcrtomb.
-  memset(&ps, 0, sizeof(ps));
   EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
   EXPECT_EQ(static_cast<size_t>(-1), wcrtomb(out, 0x00a2, &ps));
   EXPECT_ERRNO(EILSEQ);
 
   // If the first argument to wcrtomb is NULL or the second is L'\0' the shift
   // state should be reset.
-  memset(&ps, 0, sizeof(ps));
+  ps = {};
   EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
   EXPECT_EQ(1U, wcrtomb(nullptr, 0x00a2, &ps));
   EXPECT_TRUE(mbsinit(&ps));
 
-  memset(&ps, 0, sizeof(ps));
+  ps = {};
   EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xf0\xa4", 1, &ps));
   EXPECT_EQ(1U, wcrtomb(out, L'\0', &ps));
   EXPECT_TRUE(mbsinit(&ps));
@@ -253,9 +252,8 @@ TEST(wchar, wcstombs_wcrtombs) {
   EXPECT_STREQ("hix", bytes);
 
   // Any non-initial state is invalid when calling wcsrtombs.
-  mbstate_t ps;
+  mbstate_t ps = {};
   src = chars;
-  memset(&ps, 0, sizeof(ps));
   ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
   EXPECT_EQ(static_cast<size_t>(-1), wcsrtombs(nullptr, &src, 0, &ps));
   EXPECT_ERRNO(EILSEQ);
@@ -449,8 +447,7 @@ static void test_mbrtowc_incomplete(mbstate_t* ps) {
 }
 
 TEST(wchar, mbrtowc_incomplete) {
-  mbstate_t ps;
-  memset(&ps, 0, sizeof(ps));
+  mbstate_t ps = {};
 
   test_mbrtowc_incomplete(&ps);
   test_mbrtowc_incomplete(nullptr);
@@ -508,8 +505,7 @@ TEST(wchar, mbsrtowcs) {
   ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
   uselocale(LC_GLOBAL_LOCALE);
 
-  mbstate_t ps;
-  memset(&ps, 0, sizeof(ps));
+  mbstate_t ps = {};
   test_mbsrtowcs(&ps);
   test_mbsrtowcs(nullptr);
 
@@ -659,12 +655,7 @@ TEST(wchar, mbsnrtowcs) {
 TEST(wchar, wcsftime__wcsftime_l) {
   setenv("TZ", "UTC", 1);
 
-  struct tm t;
-  memset(&t, 0, sizeof(tm));
-  t.tm_year = 200;
-  t.tm_mon = 2;
-  t.tm_mday = 10;
-
+  struct tm t = {.tm_year = 200, .tm_mon = 2, .tm_mday = 10};
   wchar_t buf[64];
 
   EXPECT_EQ(24U, wcsftime(buf, sizeof(buf), L"%c", &t));
@@ -1071,16 +1062,12 @@ TEST(wchar, wcwidth_controls) {
 }
 
 TEST(wchar, wcwidth_non_spacing_and_enclosing_marks_and_format) {
-  if (!have_dl()) return;
-
   EXPECT_EQ(0, wcwidth(0x0300)); // Combining grave.
   EXPECT_EQ(0, wcwidth(0x20dd)); // Combining enclosing circle.
   EXPECT_EQ(0, wcwidth(0x200b)); // Zero width space.
 }
 
 TEST(wchar, wcwidth_non_spacing_special_cases) {
-  if (!have_dl()) return;
-
   // U+00AD is a soft hyphen, which normally shouldn't be rendered at all.
   // I think the assumption here is that you elide the soft hyphen character
   // completely in that case, and never call wcwidth() if you don't want to
@@ -1109,8 +1096,6 @@ TEST(wchar, wcwidth_non_spacing_special_cases) {
 }
 
 TEST(wchar, wcwidth_cjk) {
-  if (!have_dl()) return;
-
   EXPECT_EQ(2, wcwidth(0x4e00)); // Start of CJK unified block.
   EXPECT_EQ(2, wcwidth(0x9fff)); // End of CJK unified block.
   EXPECT_EQ(2, wcwidth(0x3400)); // Start of CJK extension A block.
@@ -1120,16 +1105,12 @@ TEST(wchar, wcwidth_cjk) {
 }
 
 TEST(wchar, wcwidth_korean_combining_jamo) {
-  if (!have_dl()) return;
-
   AssertWcwidthRange(0x1160, 0x1200, 0); // Original range.
   EXPECT_EQ(0, wcwidth(0xd7b0)); // Newer.
   EXPECT_EQ(0, wcwidth(0xd7cb));
 }
 
 TEST(wchar, wcwidth_korean_jeongeul_syllables) {
-  if (!have_dl()) return;
-
   EXPECT_EQ(2, wcwidth(0xac00)); // Start of block.
   EXPECT_EQ(2, wcwidth(0xd7a3)); // End of defined code points as of Unicode 15.
 
@@ -1138,8 +1119,6 @@ TEST(wchar, wcwidth_korean_jeongeul_syllables) {
 }
 
 TEST(wchar, wcwidth_kana) {
-  if (!have_dl()) return;
-
   // Hiragana (most, not undefined).
   AssertWcwidthRange(0x3041, 0x3097, 2);
   // Katakana.
@@ -1147,30 +1126,22 @@ TEST(wchar, wcwidth_kana) {
 }
 
 TEST(wchar, wcwidth_circled_two_digit_cjk) {
-  if (!have_dl()) return;
-
   // Circled two-digit CJK "speed sign" numbers are wide,
   // though EastAsianWidth is ambiguous.
   AssertWcwidthRange(0x3248, 0x3250, 2);
 }
 
 TEST(wchar, wcwidth_hexagrams) {
-  if (!have_dl()) return;
-
   // Hexagrams are wide, though EastAsianWidth is neutral.
   AssertWcwidthRange(0x4dc0, 0x4e00, 2);
 }
 
 TEST(wchar, wcwidth_default_ignorables) {
-  if (!have_dl()) return;
-
   AssertWcwidthRange(0xfff0, 0xfff8, 0); // Unassigned by default ignorable.
   EXPECT_EQ(0, wcwidth(0xe0000)); // ...through 0xe0fff.
 }
 
 TEST(wchar, wcwidth_hangeul_compatibility_jamo) {
-  if (!have_dl()) return;
-
   // These are actually the *compatibility* jamo code points, *not* the regular
   // jamo code points (U+1100-U+11FF) using a jungseong filler. If you use the
   // Android IME to type any of these, you get these code points.
diff --git a/tests/wctype_test.cpp b/tests/wctype_test.cpp
index f4b7a8fa4..1a2bbc18f 100644
--- a/tests/wctype_test.cpp
+++ b/tests/wctype_test.cpp
@@ -37,20 +37,14 @@ static void TestIsWideFn(int fn(wint_t),
   for (const wchar_t* p = trues; *p; ++p) {
     const wchar_t val_ch = *p;
     const int val_int = static_cast<int>(val_ch);
-    if (!have_dl() && val_ch > 0x7f) {
-      GTEST_LOG_(INFO) << "skipping unicode test " << val_int;
-      continue;
-    }
+
     EXPECT_TRUE(fn(val_ch)) << val_int;
     EXPECT_TRUE(fn_l(val_ch, l.l)) << val_int;
   }
   for (const wchar_t* p = falses; *p; ++p) {
     const wchar_t val_ch = *p;
     const int val_int = static_cast<int>(val_ch);
-    if (!have_dl() && val_ch > 0x7f) {
-      GTEST_LOG_(INFO) << "skipping unicode test " << val_int;
-      continue;
-    }
+
     EXPECT_FALSE(fn(val_ch)) << val_int;
     EXPECT_FALSE(fn_l(val_ch, l.l)) << val_int;
   }
@@ -111,14 +105,10 @@ TEST(wctype, towlower) {
   EXPECT_EQ(wint_t('a'), towlower(L'A'));
   EXPECT_EQ(wint_t('z'), towlower(L'z'));
   EXPECT_EQ(wint_t('z'), towlower(L'Z'));
-  if (have_dl()) {
-    EXPECT_EQ(wint_t(L'ç'), towlower(L'ç'));
-    EXPECT_EQ(wint_t(L'ç'), towlower(L'Ç'));
-    EXPECT_EQ(wint_t(L'δ'), towlower(L'δ'));
-    EXPECT_EQ(wint_t(L'δ'), towlower(L'Δ'));
-  } else {
-    GTEST_SKIP() << "icu not available";
-  }
+  EXPECT_EQ(wint_t(L'ç'), towlower(L'ç'));
+  EXPECT_EQ(wint_t(L'ç'), towlower(L'Ç'));
+  EXPECT_EQ(wint_t(L'δ'), towlower(L'δ'));
+  EXPECT_EQ(wint_t(L'δ'), towlower(L'Δ'));
 }
 
 TEST(wctype, towlower_l) {
@@ -129,14 +119,10 @@ TEST(wctype, towlower_l) {
   EXPECT_EQ(wint_t('a'), towlower_l(L'A', l.l));
   EXPECT_EQ(wint_t('z'), towlower_l(L'z', l.l));
   EXPECT_EQ(wint_t('z'), towlower_l(L'Z', l.l));
-  if (have_dl()) {
-    EXPECT_EQ(wint_t(L'ç'), towlower_l(L'ç', l.l));
-    EXPECT_EQ(wint_t(L'ç'), towlower_l(L'Ç', l.l));
-    EXPECT_EQ(wint_t(L'δ'), towlower_l(L'δ', l.l));
-    EXPECT_EQ(wint_t(L'δ'), towlower_l(L'Δ', l.l));
-  } else {
-    GTEST_SKIP() << "icu not available";
-  }
+  EXPECT_EQ(wint_t(L'ç'), towlower_l(L'ç', l.l));
+  EXPECT_EQ(wint_t(L'ç'), towlower_l(L'Ç', l.l));
+  EXPECT_EQ(wint_t(L'δ'), towlower_l(L'δ', l.l));
+  EXPECT_EQ(wint_t(L'δ'), towlower_l(L'Δ', l.l));
 }
 
 TEST(wctype, towupper) {
@@ -146,14 +132,10 @@ TEST(wctype, towupper) {
   EXPECT_EQ(wint_t('A'), towupper(L'A'));
   EXPECT_EQ(wint_t('Z'), towupper(L'z'));
   EXPECT_EQ(wint_t('Z'), towupper(L'Z'));
-  if (have_dl()) {
-    EXPECT_EQ(wint_t(L'Ç'), towupper(L'ç'));
-    EXPECT_EQ(wint_t(L'Ç'), towupper(L'Ç'));
-    EXPECT_EQ(wint_t(L'Δ'), towupper(L'δ'));
-    EXPECT_EQ(wint_t(L'Δ'), towupper(L'Δ'));
-  } else {
-    GTEST_SKIP() << "icu not available";
-  }
+  EXPECT_EQ(wint_t(L'Ç'), towupper(L'ç'));
+  EXPECT_EQ(wint_t(L'Ç'), towupper(L'Ç'));
+  EXPECT_EQ(wint_t(L'Δ'), towupper(L'δ'));
+  EXPECT_EQ(wint_t(L'Δ'), towupper(L'Δ'));
 }
 
 TEST(wctype, towupper_l) {
@@ -164,14 +146,10 @@ TEST(wctype, towupper_l) {
   EXPECT_EQ(wint_t('A'), towupper_l(L'A', l.l));
   EXPECT_EQ(wint_t('Z'), towupper_l(L'z', l.l));
   EXPECT_EQ(wint_t('Z'), towupper_l(L'Z', l.l));
-  if (have_dl()) {
-    EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'ç', l.l));
-    EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'Ç', l.l));
-    EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'δ', l.l));
-    EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'Δ', l.l));
-  } else {
-    GTEST_SKIP() << "icu not available";
-  }
+  EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'ç', l.l));
+  EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'Ç', l.l));
+  EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'δ', l.l));
+  EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'Δ', l.l));
 }
 
 TEST(wctype, wctype) {
```

