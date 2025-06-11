```diff
diff --git a/BUILD.bazel b/BUILD.bazel
index 0b832cf..adea02a 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -2,6 +2,8 @@ load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
 
 licenses(["notice"])
 
+exports_files(["LICENSE"])
+
 ############################## pthreadpool library #############################
 
 INTERNAL_HDRS = [
@@ -39,18 +41,22 @@ cc_library(
         ":emscripten": INTERNAL_HDRS + SHIM_IMPL_SRCS,
         ":macos_x86": INTERNAL_HDRS + GCD_IMPL_SRCS,
         ":macos_x86_64": INTERNAL_HDRS + GCD_IMPL_SRCS,
+        ":macos_arm64": INTERNAL_HDRS + GCD_IMPL_SRCS,
         ":ios": INTERNAL_HDRS + GCD_IMPL_SRCS,
         ":watchos": INTERNAL_HDRS + GCD_IMPL_SRCS,
         ":tvos": INTERNAL_HDRS + GCD_IMPL_SRCS,
         ":windows_x86_64": INTERNAL_HDRS + WINDOWS_IMPL_SRCS,
+        ":windows_arm64": INTERNAL_HDRS + WINDOWS_IMPL_SRCS,
         "//conditions:default": INTERNAL_HDRS + PTHREADS_IMPL_SRCS,
     }) + select({
         ":linux_x86_64": ARCH_SPECIFIC_SRCS,
         ":android_x86": ARCH_SPECIFIC_SRCS,
         ":android_x86_64": ARCH_SPECIFIC_SRCS,
         ":windows_x86_64": ARCH_SPECIFIC_SRCS,
+        ":windows_arm64": ARCH_SPECIFIC_SRCS,
         ":macos_x86": ARCH_SPECIFIC_SRCS,
         ":macos_x86_64": ARCH_SPECIFIC_SRCS,
+        ":macos_arm64": ARCH_SPECIFIC_SRCS,
         ":ios_x86": ARCH_SPECIFIC_SRCS,
         ":ios_x86_64": ARCH_SPECIFIC_SRCS,
         ":watchos_x86": ARCH_SPECIFIC_SRCS,
@@ -103,8 +109,10 @@ cc_library(
         ":android_x86": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":android_x86_64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":windows_x86_64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
+        ":windows_arm64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":macos_x86": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":macos_x86_64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
+        ":macos_arm64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":ios_x86": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":ios_x86_64": ["-DPTHREADPOOL_USE_FASTPATH=1"],
         ":watchos_x86": ["-DPTHREADPOOL_USE_FASTPATH=1"],
@@ -168,6 +176,19 @@ cc_test(
     ],
 )
 
+cc_test(
+    name = "pthreadpool_cxx_test",
+    srcs = ["test/pthreadpool-cxx.cc"],
+    linkopts = select({
+        ":emscripten": EMSCRIPTEN_TEST_LINKOPTS,
+        "//conditions:default": [],
+    }),
+    deps = [
+        ":pthreadpool",
+        "@com_google_googletest//:gtest_main",
+    ],
+)
+
 ################################## Benchmarks ##################################
 
 EMSCRIPTEN_BENCHMARK_LINKOPTS = [
@@ -317,6 +338,14 @@ config_setting(
     },
 )
 
+config_setting(
+    name = "macos_arm64",
+    values = {
+        "apple_platform_type": "macos",
+        "cpu": "darwin_arm64",
+    },
+)
+
 config_setting(
     name = "ios",
     values = {
@@ -388,6 +417,13 @@ config_setting(
     },
 )
 
+config_setting(
+    name = "windows_arm64",
+    values = {
+        "cpu": "arm64_windows",
+    },
+)
+
 config_setting(
     name = "emscripten",
     values = {
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 0db3264..7fa4285 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,7 +1,7 @@
 CMAKE_MINIMUM_REQUIRED(VERSION 3.5 FATAL_ERROR)
 
 # ---[ Project
-PROJECT(pthreadpool C CXX)
+PROJECT(pthreadpool C)
 
 # ---[ Options.
 SET(PTHREADPOOL_LIBRARY_TYPE "default" CACHE STRING "Type of library (shared, static, or default) to build")
@@ -25,6 +25,10 @@ ENDIF()
 # ---[ CMake options
 INCLUDE(GNUInstallDirs)
 
+IF(PTHREADPOOL_BUILD_TESTS OR PTHREADPOOL_BUILD_BENCHMARKS)
+  ENABLE_LANGUAGE(CXX)
+ENDIF()
+
 IF(PTHREADPOOL_BUILD_TESTS)
   ENABLE_TESTING()
 ENDIF()
@@ -123,9 +127,9 @@ ELSEIF(NOT PTHREADPOOL_SYNC_PRIMITIVE STREQUAL "default")
   MESSAGE(FATAL_ERROR "Unsupported synchronization primitive ${PTHREADPOOL_SYNC_PRIMITIVE}")
 ENDIF()
 IF(PTHREADPOOL_ENABLE_FASTPATH)
-  TARGET_COMPILE_DEFINITIONS(pthreadpool PRIVATE PTHREADPOOL_ENABLE_FASTPATH=1)
+  TARGET_COMPILE_DEFINITIONS(pthreadpool PRIVATE PTHREADPOOL_USE_FASTPATH=1)
 ELSE()
-  TARGET_COMPILE_DEFINITIONS(pthreadpool PRIVATE PTHREADPOOL_ENABLE_FASTPATH=0)
+  TARGET_COMPILE_DEFINITIONS(pthreadpool PRIVATE PTHREADPOOL_USE_FASTPATH=0)
 ENDIF()
 
 SET_TARGET_PROPERTIES(pthreadpool PROPERTIES
@@ -178,6 +182,13 @@ IF(PTHREADPOOL_BUILD_TESTS)
     CXX_EXTENSIONS NO)
   TARGET_LINK_LIBRARIES(pthreadpool-test pthreadpool gtest gtest_main)
   ADD_TEST(pthreadpool pthreadpool-test)
+
+  ADD_EXECUTABLE(pthreadpool-cxx-test test/pthreadpool-cxx.cc)
+  SET_TARGET_PROPERTIES(pthreadpool-cxx-test PROPERTIES
+    CXX_STANDARD 11
+    CXX_EXTENSIONS NO)
+  TARGET_LINK_LIBRARIES(pthreadpool-cxx-test pthreadpool gtest gtest_main)
+  ADD_TEST(pthreadpool-cxx pthreadpool-cxx-test)
 ENDIF()
 
 IF(PTHREADPOOL_BUILD_BENCHMARKS)
diff --git a/METADATA b/METADATA
index b17869f..17c6d95 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/pthreadpool
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "pthreadpool"
 description: "pthreadpool is a portable and efficient thread pool implementation. It provides similar functionality to #pragma omp parallel for, but with additional features."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/Maratyszcza/pthreadpool"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/Maratyszcza/pthreadpool"
-  }
-  version: "344531b40881b1ee41508a9c70c8fbbef3bd6cad"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2020
-    month: 12
-    day: 7
+    year: 2025
+    month: 1
+    day: 16
+  }
+  homepage: "https://github.com/Maratyszcza/pthreadpool"
+  identifier {
+    type: "Git"
+    value: "https://github.com/Maratyszcza/pthreadpool"
+    version: "560c60d342a76076f0557a3946924c6478470044"
   }
 }
diff --git a/OWNERS b/OWNERS
index 196fe51..dc0d96b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/packages/modules/NeuralNetworks:/NNAPI_OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/WORKSPACE b/WORKSPACE
index 4a44079..53ec787 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -5,14 +5,14 @@ load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 # Bazel rule definitions
 http_archive(
     name = "rules_cc",
-    strip_prefix = "rules_cc-master",
+    strip_prefix = "rules_cc-main",
     urls = ["https://github.com/bazelbuild/rules_cc/archive/master.zip"],
 )
 
 # Google Test framework, used by most unit-tests.
 http_archive(
     name = "com_google_googletest",
-    strip_prefix = "googletest-master",
+    strip_prefix = "googletest-main",
     urls = ["https://github.com/google/googletest/archive/master.zip"],
 )
 
@@ -26,9 +26,9 @@ http_archive(
 # FXdiv library, used for repeated integer division by the same factor
 http_archive(
     name = "FXdiv",
-    strip_prefix = "FXdiv-f7dd0576a1c8289ef099d4fd8b136b1c4487a873",
-    sha256 = "6e4b6e3c58e67c3bb090e286c4f235902c89b98cf3e67442a18f9167963aa286",
-    urls = ["https://github.com/Maratyszcza/FXdiv/archive/f7dd0576a1c8289ef099d4fd8b136b1c4487a873.zip"],
+    strip_prefix = "FXdiv-63058eff77e11aa15bf531df5dd34395ec3017c8",
+    sha256 = "3d7b0e9c4c658a84376a1086126be02f9b7f753caa95e009d9ac38d11da444db",
+    urls = ["https://github.com/Maratyszcza/FXdiv/archive/63058eff77e11aa15bf531df5dd34395ec3017c8.zip"],
 )
 
 # Android NDK location and version is auto-detected from $ANDROID_NDK_HOME environment variable
diff --git a/cmake/DownloadGoogleBenchmark.cmake b/cmake/DownloadGoogleBenchmark.cmake
index d042e07..bae6b0e 100644
--- a/cmake/DownloadGoogleBenchmark.cmake
+++ b/cmake/DownloadGoogleBenchmark.cmake
@@ -4,8 +4,8 @@ PROJECT(googlebenchmark-download NONE)
 
 INCLUDE(ExternalProject)
 ExternalProject_Add(googlebenchmark
-	URL https://github.com/google/benchmark/archive/v1.5.0.zip
-	URL_HASH SHA256=2d22dd3758afee43842bb504af1a8385cccb3ee1f164824e4837c1c1b04d92a0
+	URL https://github.com/google/benchmark/archive/v1.5.3.zip
+	URL_HASH SHA256=bdefa4b03c32d1a27bd50e37ca466d8127c1688d834800c38f3c587a396188ee
 	SOURCE_DIR "${CMAKE_BINARY_DIR}/googlebenchmark-source"
 	BINARY_DIR "${CMAKE_BINARY_DIR}/googlebenchmark"
 	CONFIGURE_COMMAND ""
diff --git a/cmake/DownloadGoogleTest.cmake b/cmake/DownloadGoogleTest.cmake
index 2231ff7..d2d9ce4 100644
--- a/cmake/DownloadGoogleTest.cmake
+++ b/cmake/DownloadGoogleTest.cmake
@@ -4,8 +4,8 @@ PROJECT(googletest-download NONE)
 
 INCLUDE(ExternalProject)
 ExternalProject_Add(googletest
-	URL https://github.com/google/googletest/archive/release-1.10.0.zip
-	URL_HASH SHA256=94c634d499558a76fa649edb13721dce6e98fb1e7018dfaeba3cd7a083945e91
+	URL https://github.com/google/googletest/archive/release-1.12.0.zip
+	URL_HASH SHA256=ce7366fe57eb49928311189cb0e40e0a8bf3d3682fca89af30d884c25e983786
     SOURCE_DIR "${CMAKE_BINARY_DIR}/googletest-source"
     BINARY_DIR "${CMAKE_BINARY_DIR}/googletest"
 	CONFIGURE_COMMAND ""
diff --git a/include/pthreadpool.h b/include/pthreadpool.h
index 59c4abf..953ccc4 100644
--- a/include/pthreadpool.h
+++ b/include/pthreadpool.h
@@ -7,12 +7,15 @@
 typedef struct pthreadpool* pthreadpool_t;
 
 typedef void (*pthreadpool_task_1d_t)(void*, size_t);
+typedef void (*pthreadpool_task_1d_with_thread_t)(void*, size_t, size_t);
 typedef void (*pthreadpool_task_1d_tile_1d_t)(void*, size_t, size_t);
 typedef void (*pthreadpool_task_2d_t)(void*, size_t, size_t);
+typedef void (*pthreadpool_task_2d_with_thread_t)(void*, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_2d_tile_1d_t)(void*, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_2d_tile_2d_t)(void*, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_3d_t)(void*, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_3d_tile_1d_t)(void*, size_t, size_t, size_t, size_t);
+typedef void (*pthreadpool_task_3d_tile_1d_with_thread_t)(void*, size_t, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_3d_tile_2d_t)(void*, size_t, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_4d_t)(void*, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_4d_tile_1d_t)(void*, size_t, size_t, size_t, size_t, size_t);
@@ -25,10 +28,15 @@ typedef void (*pthreadpool_task_6d_tile_1d_t)(void*, size_t, size_t, size_t, siz
 typedef void (*pthreadpool_task_6d_tile_2d_t)(void*, size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t);
 
 typedef void (*pthreadpool_task_1d_with_id_t)(void*, uint32_t, size_t);
+typedef void (*pthreadpool_task_2d_tile_1d_with_id_t)(void*, uint32_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_2d_tile_2d_with_id_t)(void*, uint32_t, size_t, size_t, size_t, size_t);
+typedef void (*pthreadpool_task_3d_tile_1d_with_id_t)(void*, uint32_t, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_3d_tile_2d_with_id_t)(void*, uint32_t, size_t, size_t, size_t, size_t, size_t);
 typedef void (*pthreadpool_task_4d_tile_2d_with_id_t)(void*, uint32_t, size_t, size_t, size_t, size_t, size_t, size_t);
 
+typedef void (*pthreadpool_task_2d_tile_1d_with_id_with_thread_t)(void*, uint32_t, size_t, size_t, size_t, size_t);
+typedef void (*pthreadpool_task_3d_tile_1d_with_id_with_thread_t)(void*, uint32_t, size_t, size_t, size_t, size_t, size_t);
+
 
 /**
  * Disable support for denormalized numbers to the maximum extent possible for
@@ -115,6 +123,36 @@ void pthreadpool_parallelize_1d(
 	size_t range,
 	uint32_t flags);
 
+/**
+ * Process items on a 1D grid passing along the current thread id.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range; i++)
+ *     function(context, thread_index, i);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each item.
+ * @param context     the first argument passed to the specified function.
+ * @param range       the number of items on the 1D grid to process. The
+ *    specified function will be called once for each item.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_1d_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_1d_with_thread_t function,
+	void* context,
+	size_t range,
+	uint32_t flags);
+
 /**
  * Process items on a 1D grid using a microarchitecture-aware task function.
  *
@@ -227,6 +265,40 @@ void pthreadpool_parallelize_2d(
 	size_t range_j,
 	uint32_t flags);
 
+/**
+ * Process items on a 2D grid passing along the current thread id.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       function(context, thread_index, i, j);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each item.
+ * @param context     the first argument passed to the specified function.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_2d_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_with_thread_t function,
+	void* context,
+	size_t range_i,
+	size_t range_j,
+	uint32_t flags);
+
 /**
  * Process items on a 2D grid with the specified maximum tile size along the
  * last grid dimension.
@@ -265,6 +337,109 @@ void pthreadpool_parallelize_2d_tile_1d(
 	size_t tile_j,
 	uint32_t flags);
 
+/**
+ * Process items on a 2D grid with the specified maximum tile size along the
+ * last grid dimension using a microarchitecture-aware task function.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   uint32_t uarch_index = cpuinfo_initialize() ?
+ *       cpuinfo_get_current_uarch_index() : default_uarch_index;
+ *   if (uarch_index > max_uarch_index) uarch_index = default_uarch_index;
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       function(context, uarch_index, i, j, min(range_j - j, tile_j));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each tile.
+ * @param context     the first argument passed to the specified function.
+ * @param default_uarch_index  the microarchitecture index to use when
+ *    pthreadpool is configured without cpuinfo, cpuinfo initialization failed,
+ *    or index returned by cpuinfo_get_current_uarch_index() exceeds the
+ *    max_uarch_index value.
+ * @param max_uarch_index      the maximum microarchitecture index expected by
+ *    the specified function. If the index returned by
+ *    cpuinfo_get_current_uarch_index() exceeds this value, default_uarch_index
+ *    will be used instead. default_uarch_index can exceed max_uarch_index.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 2D grid to process in one function call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_2d_tile_1d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_t function,
+	void* context,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags);
+
+/**
+ * Process items on a 2D grid with the specified maximum tile size along the
+ * last grid dimension using a microarchitecture-aware task function and passing
+ * along the current thread id.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   uint32_t uarch_index = cpuinfo_initialize() ?
+ *       cpuinfo_get_current_uarch_index() : default_uarch_index;
+ *   if (uarch_index > max_uarch_index) uarch_index = default_uarch_index;
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       function(context, uarch_index, thread_index, i, j, min(range_j - j, tile_j));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each tile.
+ * @param context     the first argument passed to the specified function.
+ * @param default_uarch_index  the microarchitecture index to use when
+ *    pthreadpool is configured without cpuinfo, cpuinfo initialization failed,
+ *    or index returned by cpuinfo_get_current_uarch_index() exceeds the
+ *    max_uarch_index value.
+ * @param max_uarch_index      the maximum microarchitecture index expected by
+ *    the specified function. If the index returned by
+ *    cpuinfo_get_current_uarch_index() exceeds this value, default_uarch_index
+ *    will be used instead. default_uarch_index can exceed max_uarch_index.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 2D grid to process in one function call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_with_thread_t function,
+	void* context,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags);
+
 /**
  * Process items on a 2D grid with the specified maximum tile size along each
  * grid dimension.
@@ -449,15 +624,14 @@ void pthreadpool_parallelize_3d_tile_1d(
 
 /**
  * Process items on a 3D grid with the specified maximum tile size along the
- * last two grid dimensions.
+ * last grid dimension and passing along the current thread id.
  *
  * The function implements a parallel version of the following snippet:
  *
  *   for (size_t i = 0; i < range_i; i++)
- *     for (size_t j = 0; j < range_j; j += tile_j)
+ *     for (size_t j = 0; j < range_j; j++)
  *       for (size_t k = 0; k < range_k; k += tile_k)
- *         function(context, i, j, k,
- *           min(range_j - j, tile_j), min(range_k - k, tile_k));
+ *         function(context, thread_index, i, j, k, min(range_k - k, tile_k));
  *
  * When the function returns, all items have been processed and the thread pool
  * is ready for a new task.
@@ -475,27 +649,24 @@ void pthreadpool_parallelize_3d_tile_1d(
  *    of the 3D grid.
  * @param range_k     the number of items to process along the third dimension
  *    of the 3D grid.
- * @param tile_j      the maximum number of items along the second dimension of
- *    the 3D grid to process in one function call.
  * @param tile_k      the maximum number of items along the third dimension of
  *    the 3D grid to process in one function call.
  * @param flags       a bitwise combination of zero or more optional flags
  *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
  */
-void pthreadpool_parallelize_3d_tile_2d(
-	pthreadpool_t threadpool,
-	pthreadpool_task_3d_tile_2d_t function,
-	void* context,
-	size_t range_i,
-	size_t range_j,
-	size_t range_k,
-	size_t tile_j,
-	size_t tile_k,
-	uint32_t flags);
+void pthreadpool_parallelize_3d_tile_1d_with_thread(
+  pthreadpool_t threadpool,
+  pthreadpool_task_3d_tile_1d_with_thread_t function,
+  void* context,
+  size_t range_i,
+  size_t range_j,
+  size_t range_k,
+  size_t tile_k,
+  uint32_t flags);
 
 /**
  * Process items on a 3D grid with the specified maximum tile size along the
- * last two grid dimensions using a microarchitecture-aware task function.
+ * last grid dimension using a microarchitecture-aware task function.
  *
  * The function implements a parallel version of the following snippet:
  *
@@ -503,10 +674,9 @@ void pthreadpool_parallelize_3d_tile_2d(
  *       cpuinfo_get_current_uarch_index() : default_uarch_index;
  *   if (uarch_index > max_uarch_index) uarch_index = default_uarch_index;
  *   for (size_t i = 0; i < range_i; i++)
- *     for (size_t j = 0; j < range_j; j += tile_j)
+ *     for (size_t j = 0; j < range_j; j++)
  *       for (size_t k = 0; k < range_k; k += tile_k)
- *         function(context, uarch_index, i, j, k,
- *           min(range_j - j, tile_j), min(range_k - k, tile_k));
+ *         function(context, uarch_index, i, j, k, min(range_k - k, tile_k));
  *
  * When the function returns, all items have been processed and the thread pool
  * is ready for a new task.
@@ -534,37 +704,38 @@ void pthreadpool_parallelize_3d_tile_2d(
  *    dimension of the 3D grid.
  * @param range_k              the number of items to process along the third
  *    dimension of the 3D grid.
- * @param tile_j               the maximum number of items along the second
- *    dimension of the 3D grid to process in one function call.
  * @param tile_k               the maximum number of items along the third
  *    dimension of the 3D grid to process in one function call.
  * @param flags                a bitwise combination of zero or more optional
  *    flags (PTHREADPOOL_FLAG_DISABLE_DENORMALS or
  *    PTHREADPOOL_FLAG_YIELD_WORKERS)
  */
-void pthreadpool_parallelize_3d_tile_2d_with_uarch(
+void pthreadpool_parallelize_3d_tile_1d_with_uarch(
 	pthreadpool_t threadpool,
-	pthreadpool_task_3d_tile_2d_with_id_t function,
+	pthreadpool_task_3d_tile_1d_with_id_t function,
 	void* context,
 	uint32_t default_uarch_index,
 	uint32_t max_uarch_index,
 	size_t range_i,
 	size_t range_j,
 	size_t range_k,
-	size_t tile_j,
 	size_t tile_k,
 	uint32_t flags);
 
 /**
- * Process items on a 4D grid.
+ * Process items on a 3D grid with the specified maximum tile size along the
+ * last grid dimension using a microarchitecture-aware task function and passing
+ * along the current thread id.
  *
  * The function implements a parallel version of the following snippet:
  *
+ *   uint32_t uarch_index = cpuinfo_initialize() ?
+ *       cpuinfo_get_current_uarch_index() : default_uarch_index;
+ *   if (uarch_index > max_uarch_index) uarch_index = default_uarch_index;
  *   for (size_t i = 0; i < range_i; i++)
  *     for (size_t j = 0; j < range_j; j++)
- *       for (size_t k = 0; k < range_k; k++)
- *         for (size_t l = 0; l < range_l; l++)
- *           function(context, i, j, k, l);
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         function(context, uarch_index, thread_index, i, j, k, min(range_k - k, tile_k));
  *
  * When the function returns, all items have been processed and the thread pool
  * is ready for a new task.
@@ -572,42 +743,55 @@ void pthreadpool_parallelize_3d_tile_2d_with_uarch(
  * @note If multiple threads call this function with the same thread pool, the
  *    calls are serialized.
  *
- * @param threadpool  the thread pool to use for parallelisation. If threadpool
- *    is NULL, all items are processed serially on the calling thread.
- * @param function    the function to call for each tile.
- * @param context     the first argument passed to the specified function.
- * @param range_i     the number of items to process along the first dimension
- *    of the 4D grid.
- * @param range_j     the number of items to process along the second dimension
- *    of the 4D grid.
- * @param range_k     the number of items to process along the third dimension
- *    of the 4D grid.
- * @param range_l     the number of items to process along the fourth dimension
- *    of the 4D grid.
- * @param flags       a bitwise combination of zero or more optional flags
- *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ * @param threadpool           the thread pool to use for parallelisation. If
+ *    threadpool is NULL, all items are processed serially on the calling
+ *    thread.
+ * @param function             the function to call for each tile.
+ * @param context              the first argument passed to the specified
+ *    function.
+ * @param default_uarch_index  the microarchitecture index to use when
+ *    pthreadpool is configured without cpuinfo, cpuinfo initialization failed,
+ *    or index returned by cpuinfo_get_current_uarch_index() exceeds the
+ *    max_uarch_index value.
+ * @param max_uarch_index      the maximum microarchitecture index expected by
+ *    the specified function. If the index returned by
+ *    cpuinfo_get_current_uarch_index() exceeds this value, default_uarch_index
+ *    will be used instead. default_uarch_index can exceed max_uarch_index.
+ * @param range_i              the number of items to process along the first
+ *    dimension of the 3D grid.
+ * @param range_j              the number of items to process along the second
+ *    dimension of the 3D grid.
+ * @param range_k              the number of items to process along the third
+ *    dimension of the 3D grid.
+ * @param tile_k               the maximum number of items along the third
+ *    dimension of the 3D grid to process in one function call.
+ * @param flags                a bitwise combination of zero or more optional
+ *    flags (PTHREADPOOL_FLAG_DISABLE_DENORMALS or
+ *    PTHREADPOOL_FLAG_YIELD_WORKERS)
  */
-void pthreadpool_parallelize_4d(
+void pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 	pthreadpool_t threadpool,
-	pthreadpool_task_4d_t function,
+	pthreadpool_task_3d_tile_1d_with_id_with_thread_t function,
 	void* context,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
 	size_t range_i,
 	size_t range_j,
 	size_t range_k,
-	size_t range_l,
+	size_t tile_k,
 	uint32_t flags);
 
 /**
- * Process items on a 4D grid with the specified maximum tile size along the
- * last grid dimension.
+ * Process items on a 3D grid with the specified maximum tile size along the
+ * last two grid dimensions.
  *
  * The function implements a parallel version of the following snippet:
  *
  *   for (size_t i = 0; i < range_i; i++)
- *     for (size_t j = 0; j < range_j; j++)
- *       for (size_t k = 0; k < range_k; k++)
- *         for (size_t l = 0; l < range_l; l += tile_l)
- *           function(context, i, j, k, l, min(range_l - l, tile_l));
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         function(context, i, j, k,
+ *           min(range_j - j, tile_j), min(range_k - k, tile_k));
  *
  * When the function returns, all items have been processed and the thread pool
  * is ready for a new task.
@@ -620,12 +804,162 @@ void pthreadpool_parallelize_4d(
  * @param function    the function to call for each tile.
  * @param context     the first argument passed to the specified function.
  * @param range_i     the number of items to process along the first dimension
- *    of the 4D grid.
+ *    of the 3D grid.
  * @param range_j     the number of items to process along the second dimension
- *    of the 4D grid.
+ *    of the 3D grid.
  * @param range_k     the number of items to process along the third dimension
- *    of the 4D grid.
- * @param range_l     the number of items to process along the fourth dimension
+ *    of the 3D grid.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 3D grid to process in one function call.
+ * @param tile_k      the maximum number of items along the third dimension of
+ *    the 3D grid to process in one function call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_3d_tile_2d(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_2d_t function,
+	void* context,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_j,
+	size_t tile_k,
+	uint32_t flags);
+
+/**
+ * Process items on a 3D grid with the specified maximum tile size along the
+ * last two grid dimensions using a microarchitecture-aware task function.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   uint32_t uarch_index = cpuinfo_initialize() ?
+ *       cpuinfo_get_current_uarch_index() : default_uarch_index;
+ *   if (uarch_index > max_uarch_index) uarch_index = default_uarch_index;
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         function(context, uarch_index, i, j, k,
+ *           min(range_j - j, tile_j), min(range_k - k, tile_k));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool           the thread pool to use for parallelisation. If
+ *    threadpool is NULL, all items are processed serially on the calling
+ *    thread.
+ * @param function             the function to call for each tile.
+ * @param context              the first argument passed to the specified
+ *    function.
+ * @param default_uarch_index  the microarchitecture index to use when
+ *    pthreadpool is configured without cpuinfo, cpuinfo initialization failed,
+ *    or index returned by cpuinfo_get_current_uarch_index() exceeds the
+ *    max_uarch_index value.
+ * @param max_uarch_index      the maximum microarchitecture index expected by
+ *    the specified function. If the index returned by
+ *    cpuinfo_get_current_uarch_index() exceeds this value, default_uarch_index
+ *    will be used instead. default_uarch_index can exceed max_uarch_index.
+ * @param range_i              the number of items to process along the first
+ *    dimension of the 3D grid.
+ * @param range_j              the number of items to process along the second
+ *    dimension of the 3D grid.
+ * @param range_k              the number of items to process along the third
+ *    dimension of the 3D grid.
+ * @param tile_j               the maximum number of items along the second
+ *    dimension of the 3D grid to process in one function call.
+ * @param tile_k               the maximum number of items along the third
+ *    dimension of the 3D grid to process in one function call.
+ * @param flags                a bitwise combination of zero or more optional
+ *    flags (PTHREADPOOL_FLAG_DISABLE_DENORMALS or
+ *    PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_3d_tile_2d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_2d_with_id_t function,
+	void* context,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_j,
+	size_t tile_k,
+	uint32_t flags);
+
+/**
+ * Process items on a 4D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           function(context, i, j, k, l);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each tile.
+ * @param context     the first argument passed to the specified function.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 4D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 4D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 4D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 4D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+void pthreadpool_parallelize_4d(
+	pthreadpool_t threadpool,
+	pthreadpool_task_4d_t function,
+	void* context,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	uint32_t flags);
+
+/**
+ * Process items on a 4D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l += tile_l)
+ *           function(context, i, j, k, l, min(range_l - l, tile_l));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param function    the function to call for each tile.
+ * @param context     the first argument passed to the specified function.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 4D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 4D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 4D grid.
+ * @param range_l     the number of items to process along the fourth dimension
  *    of the 4D grid.
  * @param tile_l      the maximum number of items along the fourth dimension of
  *    the 4D grid to process in one function call.
@@ -950,16 +1284,16 @@ void pthreadpool_parallelize_5d_tile_2d(
  *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
  */
 void pthreadpool_parallelize_6d(
-  pthreadpool_t threadpool,
-  pthreadpool_task_6d_t function,
-  void* context,
-  size_t range_i,
-  size_t range_j,
-  size_t range_k,
-  size_t range_l,
-  size_t range_m,
-  size_t range_n,
-  uint32_t flags);
+	pthreadpool_t threadpool,
+	pthreadpool_task_6d_t function,
+	void* context,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t range_n,
+	uint32_t flags);
 
 /**
  * Process items on a 6D grid with the specified maximum tile size along the
@@ -1003,17 +1337,17 @@ void pthreadpool_parallelize_6d(
  *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
  */
 void pthreadpool_parallelize_6d_tile_1d(
-  pthreadpool_t threadpool,
-  pthreadpool_task_6d_tile_1d_t function,
-  void* context,
-  size_t range_i,
-  size_t range_j,
-  size_t range_k,
-  size_t range_l,
-  size_t range_m,
-  size_t range_n,
-  size_t tile_n,
-  uint32_t flags);
+	pthreadpool_t threadpool,
+	pthreadpool_task_6d_tile_1d_t function,
+	void* context,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t range_n,
+	size_t tile_n,
+	uint32_t flags);
 
 /**
  * Process items on a 6D grid with the specified maximum tile size along the
@@ -1083,7 +1417,6 @@ void pthreadpool_parallelize_6d_tile_2d(
  */
 void pthreadpool_destroy(pthreadpool_t threadpool);
 
-
 #ifndef PTHREADPOOL_NO_DEPRECATED_API
 
 /* Legacy API for compatibility with pre-existing users (e.g. NNPACK) */
@@ -1093,12 +1426,12 @@ void pthreadpool_destroy(pthreadpool_t threadpool);
 	#define PTHREADPOOL_DEPRECATED
 #endif
 
-typedef void (*pthreadpool_function_1d_t)(void*, size_t) PTHREADPOOL_DEPRECATED;
-typedef void (*pthreadpool_function_1d_tiled_t)(void*, size_t, size_t) PTHREADPOOL_DEPRECATED;
-typedef void (*pthreadpool_function_2d_t)(void*, size_t, size_t) PTHREADPOOL_DEPRECATED;
-typedef void (*pthreadpool_function_2d_tiled_t)(void*, size_t, size_t, size_t, size_t) PTHREADPOOL_DEPRECATED;
-typedef void (*pthreadpool_function_3d_tiled_t)(void*, size_t, size_t, size_t, size_t, size_t, size_t) PTHREADPOOL_DEPRECATED;
-typedef void (*pthreadpool_function_4d_tiled_t)(void*, size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t) PTHREADPOOL_DEPRECATED;
+typedef void (*pthreadpool_function_1d_t)(void*, size_t);
+typedef void (*pthreadpool_function_1d_tiled_t)(void*, size_t, size_t);
+typedef void (*pthreadpool_function_2d_t)(void*, size_t, size_t);
+typedef void (*pthreadpool_function_2d_tiled_t)(void*, size_t, size_t, size_t, size_t);
+typedef void (*pthreadpool_function_3d_tiled_t)(void*, size_t, size_t, size_t, size_t, size_t, size_t);
+typedef void (*pthreadpool_function_4d_tiled_t)(void*, size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t);
 
 void pthreadpool_compute_1d(
 	pthreadpool_t threadpool,
@@ -1159,4 +1492,1064 @@ void pthreadpool_compute_4d_tiled(
 } /* extern "C" */
 #endif
 
+#ifdef __cplusplus
+
+namespace libpthreadpool {
+namespace detail {
+namespace {
+
+template<class T>
+void call_wrapper_1d(void* arg, size_t i) {
+	(*static_cast<const T*>(arg))(i);
+}
+
+template<class T>
+void call_wrapper_1d_tile_1d(void* arg, size_t range_i, size_t tile_i) {
+	(*static_cast<const T*>(arg))(range_i, tile_i);
+}
+
+template<class T>
+void call_wrapper_2d(void* functor, size_t i, size_t j) {
+	(*static_cast<const T*>(functor))(i, j);
+}
+
+template<class T>
+void call_wrapper_2d_tile_1d(void* functor,
+		                         size_t i, size_t range_j, size_t tile_j)
+{
+	(*static_cast<const T*>(functor))(i, range_j, tile_j);
+}
+
+template<class T>
+void call_wrapper_2d_tile_2d(void* functor,
+		                         size_t range_i, size_t range_j,
+		                         size_t tile_i, size_t tile_j)
+{
+	(*static_cast<const T*>(functor))(range_i, range_j, tile_i, tile_j);
+}
+
+template<class T>
+void call_wrapper_3d(void* functor, size_t i, size_t j, size_t k) {
+	(*static_cast<const T*>(functor))(i, j, k);
+}
+
+template<class T>
+void call_wrapper_3d_tile_1d(void* functor,
+		                         size_t i, size_t j, size_t range_k,
+		                         size_t tile_k)
+{
+	(*static_cast<const T*>(functor))(i, j, range_k, tile_k);
+}
+
+template<class T>
+void call_wrapper_3d_tile_2d(void* functor,
+		                         size_t i, size_t range_j, size_t range_k,
+		                         size_t tile_j, size_t tile_k)
+{
+	(*static_cast<const T*>(functor))(i, range_j, range_k, tile_j, tile_k);
+}
+
+template<class T>
+void call_wrapper_4d(void* functor, size_t i, size_t j, size_t k, size_t l) {
+	(*static_cast<const T*>(functor))(i, j, k, l);
+}
+
+template<class T>
+void call_wrapper_4d_tile_1d(void* functor,
+		                         size_t i, size_t j, size_t k, size_t range_l,
+		                         size_t tile_l)
+{
+	(*static_cast<const T*>(functor))(i, j, k, range_l, tile_l);
+}
+
+template<class T>
+void call_wrapper_4d_tile_2d(void* functor,
+		                         size_t i, size_t j, size_t range_k, size_t range_l,
+		                         size_t tile_k, size_t tile_l)
+{
+	(*static_cast<const T*>(functor))(i, j, range_k, range_l, tile_k, tile_l);
+}
+
+template<class T>
+void call_wrapper_5d(void* functor, size_t i, size_t j, size_t k, size_t l, size_t m) {
+	(*static_cast<const T*>(functor))(i, j, k, l, m);
+}
+
+template<class T>
+void call_wrapper_5d_tile_1d(void* functor,
+		                         size_t i, size_t j, size_t k, size_t l, size_t range_m,
+		                         size_t tile_m)
+{
+	(*static_cast<const T*>(functor))(i, j, k, l, range_m, tile_m);
+}
+
+template<class T>
+void call_wrapper_5d_tile_2d(void* functor,
+		                         size_t i, size_t j, size_t k, size_t range_l, size_t range_m,
+		                         size_t tile_l, size_t tile_m)
+{
+	(*static_cast<const T*>(functor))(i, j, k, range_l, range_m, tile_l, tile_m);
+}
+
+template<class T>
+void call_wrapper_6d(void* functor, size_t i, size_t j, size_t k, size_t l, size_t m, size_t n) {
+	(*static_cast<const T*>(functor))(i, j, k, l, m, n);
+}
+
+template<class T>
+void call_wrapper_6d_tile_1d(void* functor,
+		                         size_t i, size_t j, size_t k, size_t l, size_t m, size_t range_n,
+		                         size_t tile_n)
+{
+	(*static_cast<const T*>(functor))(i, j, k, l, m, range_n, tile_n);
+}
+
+template<class T>
+void call_wrapper_6d_tile_2d(void* functor,
+		                         size_t i, size_t j, size_t k, size_t l, size_t range_m, size_t range_n,
+		                         size_t tile_m, size_t tile_n)
+{
+	(*static_cast<const T*>(functor))(i, j, k, l, range_m, range_n, tile_m, tile_n);
+}
+
+}  /* namespace */
+}  /* namespace detail */
+}  /* namespace libpthreadpool */
+
+/**
+ * Process items on a 1D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range; i++)
+ *     functor(i);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each item.
+ * @param range       the number of items on the 1D grid to process. The
+ *    specified functor will be called once for each item.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range,
+		flags);
+}
+
+/**
+ * Process items on a 1D grid with specified maximum tile size.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range; i += tile)
+ *     functor(i, min(range - i, tile));
+ *
+ * When the call returns, all items have been processed and the thread pool is
+ * ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool,
+ *    the calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range       the number of items on the 1D grid to process.
+ * @param tile        the maximum number of items on the 1D grid to process in
+ *    one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_1d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range,
+	size_t tile,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_1d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range,
+		tile,
+		flags);
+}
+
+/**
+ * Process items on a 2D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       functor(i, j);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each item.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		flags);
+}
+
+/**
+ * Process items on a 2D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       functor(i, j, min(range_j - j, tile_j));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 2D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_2d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		tile_j,
+		flags);
+}
+
+/**
+ * Process items on a 2D grid with the specified maximum tile size along each
+ * grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i += tile_i)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       functor(i, j,
+ *         min(range_i - i, tile_i), min(range_j - j, tile_j));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 2D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 2D grid.
+ * @param tile_j      the maximum number of items along the first dimension of
+ *    the 2D grid to process in one functor call.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 2D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_i,
+	size_t tile_j,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_2d_tile_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		tile_i,
+		tile_j,
+		flags);
+}
+
+/**
+ * Process items on a 3D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         functor(i, j, k);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 3D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 3D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 3D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_3d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_3d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_3d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		flags);
+}
+
+/**
+ * Process items on a 3D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         functor(i, j, k, min(range_k - k, tile_k));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 3D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 3D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 3D grid.
+ * @param tile_k      the maximum number of items along the third dimension of
+ *    the 3D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_3d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		tile_k,
+		flags);
+}
+
+/**
+ * Process items on a 3D grid with the specified maximum tile size along the
+ * last two grid dimensions.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j += tile_j)
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         functor(i, j, k,
+ *           min(range_j - j, tile_j), min(range_k - k, tile_k));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 3D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 3D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 3D grid.
+ * @param tile_j      the maximum number of items along the second dimension of
+ *    the 3D grid to process in one functor call.
+ * @param tile_k      the maximum number of items along the third dimension of
+ *    the 3D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_3d_tile_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_j,
+	size_t tile_k,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_3d_tile_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		tile_j,
+		tile_k,
+		flags);
+}
+
+/**
+ * Process items on a 4D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           functor(i, j, k, l);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 4D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 4D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 4D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 4D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_4d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_4d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_4d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		flags);
+}
+
+/**
+ * Process items on a 4D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l += tile_l)
+ *           functor(i, j, k, l, min(range_l - l, tile_l));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 4D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 4D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 4D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 4D grid.
+ * @param tile_l      the maximum number of items along the fourth dimension of
+ *    the 4D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_4d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t tile_l,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_4d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		tile_l,
+		flags);
+}
+
+/**
+ * Process items on a 4D grid with the specified maximum tile size along the
+ * last two grid dimensions.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k += tile_k)
+ *         for (size_t l = 0; l < range_l; l += tile_l)
+ *           functor(i, j, k, l,
+ *             min(range_k - k, tile_k), min(range_l - l, tile_l));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 4D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 4D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 4D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 4D grid.
+ * @param tile_k      the maximum number of items along the third dimension of
+ *    the 4D grid to process in one functor call.
+ * @param tile_l      the maximum number of items along the fourth dimension of
+ *    the 4D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_4d_tile_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t tile_k,
+	size_t tile_l,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_4d_tile_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		tile_k,
+		tile_l,
+		flags);
+}
+
+/**
+ * Process items on a 5D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           for (size_t m = 0; m < range_m; m++)
+ *             functor(i, j, k, l, m);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 5D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 5D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 5D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 5D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 5D grid.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_5d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_5d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_5d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		flags);
+}
+
+/**
+ * Process items on a 5D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           for (size_t m = 0; m < range_m; m += tile_m)
+ *             functor(i, j, k, l, m, min(range_m - m, tile_m));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 5D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 5D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 5D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 5D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 5D grid.
+ * @param tile_m      the maximum number of items along the fifth dimension of
+ *    the 5D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_5d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t tile_m,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_5d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		tile_m,
+		flags);
+}
+
+/**
+ * Process items on a 5D grid with the specified maximum tile size along the
+ * last two grid dimensions.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l += tile_l)
+ *           for (size_t m = 0; m < range_m; m += tile_m)
+ *             functor(i, j, k, l, m,
+ *               min(range_l - l, tile_l), min(range_m - m, tile_m));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 5D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 5D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 5D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 5D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 5D grid.
+ * @param tile_l      the maximum number of items along the fourth dimension of
+ *    the 5D grid to process in one functor call.
+ * @param tile_m      the maximum number of items along the fifth dimension of
+ *    the 5D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_5d_tile_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t tile_l,
+	size_t tile_m,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_5d_tile_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		tile_l,
+		tile_m,
+		flags);
+}
+
+/**
+ * Process items on a 6D grid.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           for (size_t m = 0; m < range_m; m++)
+ *             for (size_t n = 0; n < range_n; n++)
+ *               functor(i, j, k, l, m, n);
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 6D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 6D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 6D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 6D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 6D grid.
+ * @param range_n     the number of items to process along the sixth dimension
+ *    of the 6D grid.
+ * @param tile_n      the maximum number of items along the sixth dimension of
+ *    the 6D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_6d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t range_n,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_6d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_6d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		range_n,
+		flags);
+}
+
+/**
+ * Process items on a 6D grid with the specified maximum tile size along the
+ * last grid dimension.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           for (size_t m = 0; m < range_m; m++)
+ *             for (size_t n = 0; n < range_n; n += tile_n)
+ *               functor(i, j, k, l, m, n, min(range_n - n, tile_n));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 6D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 6D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 6D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 6D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 6D grid.
+ * @param range_n     the number of items to process along the sixth dimension
+ *    of the 6D grid.
+ * @param tile_n      the maximum number of items along the sixth dimension of
+ *    the 6D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_6d_tile_1d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t range_n,
+	size_t tile_n,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_6d_tile_1d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_6d_tile_1d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		range_n,
+		tile_n,
+		flags);
+}
+
+/**
+ * Process items on a 6D grid with the specified maximum tile size along the
+ * last two grid dimensions.
+ *
+ * The function implements a parallel version of the following snippet:
+ *
+ *   for (size_t i = 0; i < range_i; i++)
+ *     for (size_t j = 0; j < range_j; j++)
+ *       for (size_t k = 0; k < range_k; k++)
+ *         for (size_t l = 0; l < range_l; l++)
+ *           for (size_t m = 0; m < range_m; m += tile_m)
+ *             for (size_t n = 0; n < range_n; n += tile_n)
+ *               functor(i, j, k, l, m, n,
+ *                 min(range_m - m, tile_m), min(range_n - n, tile_n));
+ *
+ * When the function returns, all items have been processed and the thread pool
+ * is ready for a new task.
+ *
+ * @note If multiple threads call this function with the same thread pool, the
+ *    calls are serialized.
+ *
+ * @param threadpool  the thread pool to use for parallelisation. If threadpool
+ *    is NULL, all items are processed serially on the calling thread.
+ * @param functor     the functor to call for each tile.
+ * @param range_i     the number of items to process along the first dimension
+ *    of the 6D grid.
+ * @param range_j     the number of items to process along the second dimension
+ *    of the 6D grid.
+ * @param range_k     the number of items to process along the third dimension
+ *    of the 6D grid.
+ * @param range_l     the number of items to process along the fourth dimension
+ *    of the 6D grid.
+ * @param range_m     the number of items to process along the fifth dimension
+ *    of the 6D grid.
+ * @param range_n     the number of items to process along the sixth dimension
+ *    of the 6D grid.
+ * @param tile_m      the maximum number of items along the fifth dimension of
+ *    the 6D grid to process in one functor call.
+ * @param tile_n      the maximum number of items along the sixth dimension of
+ *    the 6D grid to process in one functor call.
+ * @param flags       a bitwise combination of zero or more optional flags
+ *    (PTHREADPOOL_FLAG_DISABLE_DENORMALS or PTHREADPOOL_FLAG_YIELD_WORKERS)
+ */
+template<class T>
+inline void pthreadpool_parallelize_6d_tile_2d(
+	pthreadpool_t threadpool,
+	const T& functor,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t range_l,
+	size_t range_m,
+	size_t range_n,
+	size_t tile_m,
+	size_t tile_n,
+	uint32_t flags = 0)
+{
+	pthreadpool_parallelize_6d_tile_2d(
+		threadpool,
+		&libpthreadpool::detail::call_wrapper_6d_tile_2d<const T>,
+		const_cast<void*>(static_cast<const void*>(&functor)),
+		range_i,
+		range_j,
+		range_k,
+		range_l,
+		range_m,
+		range_n,
+		tile_m,
+		tile_n,
+		flags);
+}
+
+#endif  /* __cplusplus */
+
 #endif /* PTHREADPOOL_H_ */
diff --git a/src/fastpath.c b/src/fastpath.c
index b914ff0..64485e7 100644
--- a/src/fastpath.c
+++ b/src/fastpath.c
@@ -58,6 +58,42 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_fastpath(
 	pthreadpool_fence_release();
 }
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_1d_with_thread_t task = (pthreadpool_task_1d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t thread_number = thread->thread_number;
+	size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, thread_number, range_start++);
+	}
+
+	/* There still may be other threads with work */
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			task(argument, thread_number, index);
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_with_uarch_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread)
@@ -191,6 +227,52 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_fastpath(
 	pthreadpool_fence_release();
 }
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_with_thread_t task = (pthreadpool_task_2d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_2d.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(range_start, range_j);
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+
+	const size_t thread_number = thread->thread_number;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, thread_number, i, j);
+		if (++j == range_j.value) {
+			j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(linear_index, range_j);
+			task(argument, thread_number, index_i_j.quotient, index_i_j.remainder);
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread)
@@ -241,6 +323,125 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_fastpath(
 	pthreadpool_fence_release();
 }
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_tile_1d_with_id_t task = (pthreadpool_task_2d_tile_1d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_2d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_2d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(range_start, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_j;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+
+	const size_t range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.range_j;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, uarch_index, i, start_j, min(range_j - start_j, tile_j));
+		start_j += tile_j;
+		if (start_j >= range_j) {
+			start_j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(linear_index, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			task(argument, uarch_index, tile_index_i_j.quotient, start_j, min(range_j - start_j, tile_j));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_tile_1d_with_id_with_thread_t task =
+		(pthreadpool_task_2d_tile_1d_with_id_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_2d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_2d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(range_start, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_j;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+
+	const size_t range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.range_j;
+	const size_t thread_number = thread->thread_number;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, uarch_index, thread_number, i, start_j, min(range_j - start_j, tile_j));
+		start_j += tile_j;
+		if (start_j >= range_j) {
+			start_j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(linear_index, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			task(argument, uarch_index, thread_number, tile_index_i_j.quotient, start_j, min(range_j - start_j, tile_j));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_2d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread)
@@ -466,6 +667,196 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_fastpath(
 	pthreadpool_fence_release();
 }
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_3d_tile_1d_with_thread_t task = (pthreadpool_task_3d_tile_1d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d.tile_k;
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
+
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d.range_k;
+	const size_t thread_number = thread->thread_number;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, thread_number, i, j, start_k, min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			if (++j == range_j.value) {
+				j = 0;
+				i += 1;
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, thread_number, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_3d_tile_1d_with_id_t task = (pthreadpool_task_3d_tile_1d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_3d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_k;
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
+
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_k;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, uarch_index, i, j, start_k, min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			if (++j == range_j.value) {
+				j = 0;
+				i += 1;
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, uarch_index, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread)
+{
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_3d_tile_1d_with_id_with_thread_t task =
+		(pthreadpool_task_3d_tile_1d_with_id_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_3d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	const size_t threads_count = threadpool->threads_count.value;
+	const size_t range_threshold = -threads_count;
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_k;
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
+
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_k;
+	const size_t thread_number = thread->thread_number;
+	while (pthreadpool_decrement_fetch_relaxed_size_t(&thread->range_length) < range_threshold) {
+		task(argument, uarch_index, thread_number, i, j, start_k, min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			if (++j == range_j.value) {
+				j = 0;
+				i += 1;
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_length) < range_threshold) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, uarch_index, thread_number, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_2d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread)
diff --git a/src/portable-api.c b/src/portable-api.c
index 42d0369..7cd1970 100644
--- a/src/portable-api.c
+++ b/src/portable-api.c
@@ -60,6 +60,37 @@ static void thread_parallelize_1d(struct pthreadpool* threadpool, struct thread_
 	pthreadpool_fence_release();
 }
 
+static void thread_parallelize_1d_with_thread(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_1d_with_thread_t task = (pthreadpool_task_1d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const size_t thread_number = thread->thread_number;
+	/* Process thread's own range of items */
+	size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, thread_number, range_start++);
+	}
+
+	/* There still may be other threads with work */
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			task(argument, thread_number, index);
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 static void thread_parallelize_1d_with_uarch(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
@@ -178,6 +209,47 @@ static void thread_parallelize_2d(struct pthreadpool* threadpool, struct thread_
 	pthreadpool_fence_release();
 }
 
+static void thread_parallelize_2d_with_thread(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_with_thread_t task = (pthreadpool_task_2d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_2d.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(range_start, range_j);
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+
+	const size_t thread_number = thread->thread_number;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, thread_number, i, j);
+		if (++j == range_j.value) {
+			j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(linear_index, range_j);
+			task(argument, thread_number, index_i_j.quotient, index_i_j.remainder);
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 static void thread_parallelize_2d_tile_1d(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
@@ -223,6 +295,115 @@ static void thread_parallelize_2d_tile_1d(struct pthreadpool* threadpool, struct
 	pthreadpool_fence_release();
 }
 
+static void thread_parallelize_2d_tile_1d_with_uarch(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_tile_1d_with_id_t task = (pthreadpool_task_2d_tile_1d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_2d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_2d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(range_start, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_j;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+
+	const size_t range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.range_j;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, uarch_index, i, start_j, min(range_j - start_j, tile_j));
+		start_j += tile_j;
+		if (start_j >= range_j) {
+			start_j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(linear_index, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			task(argument, uarch_index, tile_index_i_j.quotient, start_j, min(range_j - start_j, tile_j));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+static void thread_parallelize_2d_tile_1d_with_uarch_with_thread(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_2d_tile_1d_with_id_with_thread_t task =
+		(pthreadpool_task_2d_tile_1d_with_id_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_2d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_2d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(range_start, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.tile_j;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+
+	const size_t thread_number = thread->thread_number;
+	const size_t range_j = threadpool->params.parallelize_2d_tile_1d_with_uarch.range_j;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, uarch_index, thread_number, i, start_j, min(range_j - start_j, tile_j));
+		start_j += tile_j;
+		if (start_j >= range_j) {
+			start_j = 0;
+			i += 1;
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(linear_index, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			task(argument, uarch_index, thread_number, tile_index_i_j.quotient, start_j, min(range_j - start_j, tile_j));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
 static void thread_parallelize_2d_tile_2d(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
@@ -428,42 +609,39 @@ static void thread_parallelize_3d_tile_1d(struct pthreadpool* threadpool, struct
 	pthreadpool_fence_release();
 }
 
-static void thread_parallelize_3d_tile_2d(struct pthreadpool* threadpool, struct thread_info* thread) {
+static void thread_parallelize_3d_tile_1d_with_thread(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
 
-	const pthreadpool_task_3d_tile_2d_t task = (pthreadpool_task_3d_tile_2d_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	const pthreadpool_task_3d_tile_1d_with_thread_t task = (pthreadpool_task_3d_tile_1d_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
 	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
 
 	/* Process thread's own range of items */
 	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
-	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_2d.tile_range_k;
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d.tile_range_k;
 	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
-	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_3d_tile_2d.tile_range_j;
-	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
-	const size_t tile_j = threadpool->params.parallelize_3d_tile_2d.tile_j;
-	const size_t tile_k = threadpool->params.parallelize_3d_tile_2d.tile_k;
-	size_t i = tile_index_i_j.quotient;
-	size_t start_j = tile_index_i_j.remainder * tile_j;
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d.tile_k;
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
 	size_t start_k = tile_index_ij_k.remainder * tile_k;
 
-	const size_t range_k = threadpool->params.parallelize_3d_tile_2d.range_k;
-	const size_t range_j = threadpool->params.parallelize_3d_tile_2d.range_j;
+	const size_t thread_number = thread->thread_number;
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d.range_k;
 	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
-		task(argument, i, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		task(argument, thread_number, i, j, start_k, min(range_k - start_k, tile_k));
 		start_k += tile_k;
 		if (start_k >= range_k) {
 			start_k = 0;
-			start_j += tile_j;
-			if (start_j >= range_j) {
-				start_j = 0;
+			if (++j == range_j.value) {
+				j = 0;
 				i += 1;
 			}
 		}
 	}
 
 	/* There still may be other threads with work */
-	const size_t thread_number = thread->thread_number;
 	const size_t threads_count = threadpool->threads_count.value;
 	for (size_t tid = modulo_decrement(thread_number, threads_count);
 		tid != thread_number;
@@ -473,10 +651,9 @@ static void thread_parallelize_3d_tile_2d(struct pthreadpool* threadpool, struct
 		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
 			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
 			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
-			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
-			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
 			const size_t start_k = tile_index_ij_k.remainder * tile_k;
-			task(argument, tile_index_i_j.quotient, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+			task(argument, thread_number, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
 		}
 	}
 
@@ -484,44 +661,41 @@ static void thread_parallelize_3d_tile_2d(struct pthreadpool* threadpool, struct
 	pthreadpool_fence_release();
 }
 
-static void thread_parallelize_3d_tile_2d_with_uarch(struct pthreadpool* threadpool, struct thread_info* thread) {
+static void thread_parallelize_3d_tile_1d_with_uarch(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
 
-	const pthreadpool_task_3d_tile_2d_with_id_t task = (pthreadpool_task_3d_tile_2d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	const pthreadpool_task_3d_tile_1d_with_id_t task = (pthreadpool_task_3d_tile_1d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
 	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
 
-	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_2d_with_uarch.default_uarch_index;
+	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_1d_with_uarch.default_uarch_index;
 	uint32_t uarch_index = default_uarch_index;
 	#if PTHREADPOOL_USE_CPUINFO
 		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
-		if (uarch_index > threadpool->params.parallelize_3d_tile_2d_with_uarch.max_uarch_index) {
+		if (uarch_index > threadpool->params.parallelize_3d_tile_1d_with_uarch.max_uarch_index) {
 			uarch_index = default_uarch_index;
 		}
 	#endif
 
 	/* Process thread's own range of items */
 	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
-	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_range_k;
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_range_k;
 	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
-	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_range_j;
-	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
-	const size_t tile_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_j;
-	const size_t tile_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_k;
-	size_t i = tile_index_i_j.quotient;
-	size_t start_j = tile_index_i_j.remainder * tile_j;
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_k;
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
 	size_t start_k = tile_index_ij_k.remainder * tile_k;
 
-	const size_t range_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.range_k;
-	const size_t range_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.range_j;
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_k;
 	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
-		task(argument, uarch_index, i, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		task(argument, uarch_index, i, j, start_k, min(range_k - start_k, tile_k));
 		start_k += tile_k;
 		if (start_k >= range_k) {
 			start_k = 0;
-			start_j += tile_j;
-			if (start_j >= range_j) {
-				start_j = 0;
+			if (++j == range_j.value) {
+				j = 0;
 				i += 1;
 			}
 		}
@@ -538,10 +712,9 @@ static void thread_parallelize_3d_tile_2d_with_uarch(struct pthreadpool* threadp
 		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
 			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
 			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
-			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
-			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
 			const size_t start_k = tile_index_ij_k.remainder * tile_k;
-			task(argument, uarch_index, tile_index_i_j.quotient, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+			task(argument, uarch_index, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
 		}
 	}
 
@@ -549,43 +722,49 @@ static void thread_parallelize_3d_tile_2d_with_uarch(struct pthreadpool* threadp
 	pthreadpool_fence_release();
 }
 
-static void thread_parallelize_4d(struct pthreadpool* threadpool, struct thread_info* thread) {
+static void thread_parallelize_3d_tile_1d_with_uarch_with_thread(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
 
-	const pthreadpool_task_4d_t task = (pthreadpool_task_4d_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	const pthreadpool_task_3d_tile_1d_with_id_with_thread_t task =
+		(pthreadpool_task_3d_tile_1d_with_id_with_thread_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
 	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
 
+	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_1d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_3d_tile_1d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
 	/* Process thread's own range of items */
 	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
-	const struct fxdiv_divisor_size_t range_kl = threadpool->params.parallelize_4d.range_kl;
-	const struct fxdiv_result_size_t index_ij_kl = fxdiv_divide_size_t(range_start, range_kl);
-	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_4d.range_j;
-	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(index_ij_kl.quotient, range_j);
-	const struct fxdiv_divisor_size_t range_l = threadpool->params.parallelize_4d.range_l;
-	const struct fxdiv_result_size_t index_k_l = fxdiv_divide_size_t(index_ij_kl.remainder, range_l);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.tile_k;
 	size_t i = index_i_j.quotient;
 	size_t j = index_i_j.remainder;
-	size_t k = index_k_l.quotient;
-	size_t l = index_k_l.remainder;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
 
-	const size_t range_k = threadpool->params.parallelize_4d.range_k;
+	const size_t thread_number = thread->thread_number;
+	const size_t range_k = threadpool->params.parallelize_3d_tile_1d_with_uarch.range_k;
 	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
-		task(argument, i, j, k, l);
-		if (++l == range_l.value) {
-			l = 0;
-			if (++k == range_k) {
-				k = 0;
-				if (++j == range_j.value) {
-					j = 0;
-					i += 1;
-				}
+		task(argument, uarch_index, thread_number, i, j, start_k, min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			if (++j == range_j.value) {
+				j = 0;
+				i += 1;
 			}
 		}
 	}
 
 	/* There still may be other threads with work */
-	const size_t thread_number = thread->thread_number;
 	const size_t threads_count = threadpool->threads_count.value;
 	for (size_t tid = modulo_decrement(thread_number, threads_count);
 		tid != thread_number;
@@ -594,10 +773,10 @@ static void thread_parallelize_4d(struct pthreadpool* threadpool, struct thread_
 		struct thread_info* other_thread = &threadpool->threads[tid];
 		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
 			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
-			const struct fxdiv_result_size_t index_ij_kl = fxdiv_divide_size_t(linear_index, range_kl);
-			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(index_ij_kl.quotient, range_j);
-			const struct fxdiv_result_size_t index_k_l = fxdiv_divide_size_t(index_ij_kl.remainder, range_l);
-			task(argument, index_i_j.quotient, index_i_j.remainder, index_k_l.quotient, index_k_l.remainder);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, range_j);
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, uarch_index, thread_number, index_i_j.quotient, index_i_j.remainder, start_k, min(range_k - start_k, tile_k));
 		}
 	}
 
@@ -605,7 +784,184 @@ static void thread_parallelize_4d(struct pthreadpool* threadpool, struct thread_
 	pthreadpool_fence_release();
 }
 
-static void thread_parallelize_4d_tile_1d(struct pthreadpool* threadpool, struct thread_info* thread) {
+static void thread_parallelize_3d_tile_2d(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_3d_tile_2d_t task = (pthreadpool_task_3d_tile_2d_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_2d.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_3d_tile_2d.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_3d_tile_2d.tile_j;
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_2d.tile_k;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
+
+	const size_t range_k = threadpool->params.parallelize_3d_tile_2d.range_k;
+	const size_t range_j = threadpool->params.parallelize_3d_tile_2d.range_j;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, i, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			start_j += tile_j;
+			if (start_j >= range_j) {
+				start_j = 0;
+				i += 1;
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, tile_index_i_j.quotient, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+static void thread_parallelize_3d_tile_2d_with_uarch(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_3d_tile_2d_with_id_t task = (pthreadpool_task_3d_tile_2d_with_id_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	const uint32_t default_uarch_index = threadpool->params.parallelize_3d_tile_2d_with_uarch.default_uarch_index;
+	uint32_t uarch_index = default_uarch_index;
+	#if PTHREADPOOL_USE_CPUINFO
+		uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+		if (uarch_index > threadpool->params.parallelize_3d_tile_2d_with_uarch.max_uarch_index) {
+			uarch_index = default_uarch_index;
+		}
+	#endif
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t tile_range_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_range_k;
+	const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(range_start, tile_range_k);
+	const struct fxdiv_divisor_size_t tile_range_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_range_j;
+	const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
+	const size_t tile_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_j;
+	const size_t tile_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.tile_k;
+	size_t i = tile_index_i_j.quotient;
+	size_t start_j = tile_index_i_j.remainder * tile_j;
+	size_t start_k = tile_index_ij_k.remainder * tile_k;
+
+	const size_t range_k = threadpool->params.parallelize_3d_tile_2d_with_uarch.range_k;
+	const size_t range_j = threadpool->params.parallelize_3d_tile_2d_with_uarch.range_j;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, uarch_index, i, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		start_k += tile_k;
+		if (start_k >= range_k) {
+			start_k = 0;
+			start_j += tile_j;
+			if (start_j >= range_j) {
+				start_j = 0;
+				i += 1;
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t tile_index_ij_k = fxdiv_divide_size_t(linear_index, tile_range_k);
+			const struct fxdiv_result_size_t tile_index_i_j = fxdiv_divide_size_t(tile_index_ij_k.quotient, tile_range_j);
+			const size_t start_j = tile_index_i_j.remainder * tile_j;
+			const size_t start_k = tile_index_ij_k.remainder * tile_k;
+			task(argument, uarch_index, tile_index_i_j.quotient, start_j, start_k, min(range_j - start_j, tile_j), min(range_k - start_k, tile_k));
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+static void thread_parallelize_4d(struct pthreadpool* threadpool, struct thread_info* thread) {
+	assert(threadpool != NULL);
+	assert(thread != NULL);
+
+	const pthreadpool_task_4d_t task = (pthreadpool_task_4d_t) pthreadpool_load_relaxed_void_p(&threadpool->task);
+	void *const argument = pthreadpool_load_relaxed_void_p(&threadpool->argument);
+
+	/* Process thread's own range of items */
+	const size_t range_start = pthreadpool_load_relaxed_size_t(&thread->range_start);
+	const struct fxdiv_divisor_size_t range_kl = threadpool->params.parallelize_4d.range_kl;
+	const struct fxdiv_result_size_t index_ij_kl = fxdiv_divide_size_t(range_start, range_kl);
+	const struct fxdiv_divisor_size_t range_j = threadpool->params.parallelize_4d.range_j;
+	const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(index_ij_kl.quotient, range_j);
+	const struct fxdiv_divisor_size_t range_l = threadpool->params.parallelize_4d.range_l;
+	const struct fxdiv_result_size_t index_k_l = fxdiv_divide_size_t(index_ij_kl.remainder, range_l);
+	size_t i = index_i_j.quotient;
+	size_t j = index_i_j.remainder;
+	size_t k = index_k_l.quotient;
+	size_t l = index_k_l.remainder;
+
+	const size_t range_k = threadpool->params.parallelize_4d.range_k;
+	while (pthreadpool_try_decrement_relaxed_size_t(&thread->range_length)) {
+		task(argument, i, j, k, l);
+		if (++l == range_l.value) {
+			l = 0;
+			if (++k == range_k) {
+				k = 0;
+				if (++j == range_j.value) {
+					j = 0;
+					i += 1;
+				}
+			}
+		}
+	}
+
+	/* There still may be other threads with work */
+	const size_t thread_number = thread->thread_number;
+	const size_t threads_count = threadpool->threads_count.value;
+	for (size_t tid = modulo_decrement(thread_number, threads_count);
+		tid != thread_number;
+		tid = modulo_decrement(tid, threads_count))
+	{
+		struct thread_info* other_thread = &threadpool->threads[tid];
+		while (pthreadpool_try_decrement_relaxed_size_t(&other_thread->range_length)) {
+			const size_t linear_index = pthreadpool_decrement_fetch_relaxed_size_t(&other_thread->range_end);
+			const struct fxdiv_result_size_t index_ij_kl = fxdiv_divide_size_t(linear_index, range_kl);
+			const struct fxdiv_result_size_t index_i_j = fxdiv_divide_size_t(index_ij_kl.quotient, range_j);
+			const struct fxdiv_result_size_t index_k_l = fxdiv_divide_size_t(index_ij_kl.remainder, range_l);
+			task(argument, index_i_j.quotient, index_i_j.remainder, index_k_l.quotient, index_k_l.remainder);
+		}
+	}
+
+	/* Make changes by this thread visible to other threads */
+	pthreadpool_fence_release();
+}
+
+static void thread_parallelize_4d_tile_1d(struct pthreadpool* threadpool, struct thread_info* thread) {
 	assert(threadpool != NULL);
 	assert(thread != NULL);
 
@@ -1263,6 +1619,41 @@ void pthreadpool_parallelize_1d(
 	}
 }
 
+void pthreadpool_parallelize_1d_with_thread(
+	struct pthreadpool* threadpool,
+	pthreadpool_task_1d_with_thread_t task,
+	void* argument,
+	size_t range,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || range <= 1) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range; i++) {
+			task(argument, 0, i);
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		thread_function_t parallelize_1d_with_thread = &thread_parallelize_1d_with_thread;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (range < range_threshold) {
+				parallelize_1d_with_thread = &pthreadpool_thread_parallelize_1d_with_thread_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_1d_with_thread, NULL, 0,
+			(void*) task, argument, range, flags);
+	}
+}
+
 void pthreadpool_parallelize_1d_with_uarch(
 	pthreadpool_t threadpool,
 	pthreadpool_task_1d_with_id_t task,
@@ -1396,6 +1787,48 @@ void pthreadpool_parallelize_2d(
 	}
 }
 
+void pthreadpool_parallelize_2d_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_with_thread_t task,
+	void* argument,
+	size_t range_i,
+	size_t range_j,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || (range_i | range_j) <= 1) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j++) {
+				task(argument, 0, i, j);
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t range = range_i * range_j;
+		const struct pthreadpool_2d_params params = {
+			.range_j = fxdiv_init_size_t(range_j),
+		};
+		thread_function_t parallelize_2d_with_thread = &thread_parallelize_2d_with_thread;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (range < range_threshold) {
+				parallelize_2d_with_thread = &pthreadpool_thread_parallelize_2d_with_thread_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_2d_with_thread, &params, sizeof(params),
+			task, argument, range, flags);
+	}
+}
+
 void pthreadpool_parallelize_2d_tile_1d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_2d_tile_1d_t task,
@@ -1442,6 +1875,124 @@ void pthreadpool_parallelize_2d_tile_1d(
 	}
 }
 
+void pthreadpool_parallelize_2d_tile_1d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || (range_i <= 1 && range_j <= tile_j)) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+
+		uint32_t uarch_index = default_uarch_index;
+		#if PTHREADPOOL_USE_CPUINFO
+			uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+			if (uarch_index > max_uarch_index) {
+				uarch_index = default_uarch_index;
+			}
+		#endif
+
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j += tile_j) {
+				task(argument, uarch_index, i, j, min(range_j - j, tile_j));
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t tile_range_j = divide_round_up(range_j, tile_j);
+		const size_t tile_range = range_i * tile_range_j;
+		const struct pthreadpool_2d_tile_1d_with_uarch_params params = {
+			.default_uarch_index = default_uarch_index,
+			.max_uarch_index = max_uarch_index,
+			.range_j = range_j,
+			.tile_j = tile_j,
+			.tile_range_j = fxdiv_init_size_t(tile_range_j),
+		};
+		thread_function_t parallelize_2d_tile_1d_with_uarch = &thread_parallelize_2d_tile_1d_with_uarch;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (tile_range < range_threshold) {
+				parallelize_2d_tile_1d_with_uarch = &pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_2d_tile_1d_with_uarch, &params, sizeof(params),
+			task, argument, tile_range, flags);
+	}
+}
+
+void pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_with_thread_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || (range_i <= 1 && range_j <= tile_j)) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+
+		uint32_t uarch_index = default_uarch_index;
+		#if PTHREADPOOL_USE_CPUINFO
+			uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+			if (uarch_index > max_uarch_index) {
+				uarch_index = default_uarch_index;
+			}
+		#endif
+
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j += tile_j) {
+				task(argument, uarch_index, 0, i, j, min(range_j - j, tile_j));
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t tile_range_j = divide_round_up(range_j, tile_j);
+		const size_t tile_range = range_i * tile_range_j;
+		const struct pthreadpool_2d_tile_1d_with_uarch_params params = {
+			.default_uarch_index = default_uarch_index,
+			.max_uarch_index = max_uarch_index,
+			.range_j = range_j,
+			.tile_j = tile_j,
+			.tile_range_j = fxdiv_init_size_t(tile_range_j),
+		};
+		thread_function_t parallelize_2d_tile_1d_with_uarch_with_thread = &thread_parallelize_2d_tile_1d_with_uarch_with_thread;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (tile_range < range_threshold) {
+				parallelize_2d_tile_1d_with_uarch_with_thread = &pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_with_thread_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_2d_tile_1d_with_uarch_with_thread, &params, sizeof(params),
+			task, argument, tile_range, flags);
+	}
+}
+
 void pthreadpool_parallelize_2d_tile_2d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_2d_tile_2d_t task,
@@ -1651,6 +2202,182 @@ void pthreadpool_parallelize_3d_tile_1d(
 	}
 }
 
+void pthreadpool_parallelize_3d_tile_1d_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_thread_t task,
+	void* argument,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || ((range_i | range_j) <= 1 && range_k <= tile_k)) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j++) {
+				for (size_t k = 0; k < range_k; k += tile_k) {
+					task(argument, 0, i, j, k, min(range_k - k, tile_k));
+				}
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t tile_range_k = divide_round_up(range_k, tile_k);
+		const size_t tile_range = range_i * range_j * tile_range_k;
+		const struct pthreadpool_3d_tile_1d_params params = {
+			.range_k = range_k,
+			.tile_k = tile_k,
+			.range_j = fxdiv_init_size_t(range_j),
+			.tile_range_k = fxdiv_init_size_t(tile_range_k),
+		};
+		thread_function_t parallelize_3d_tile_1d_with_thread = &thread_parallelize_3d_tile_1d_with_thread;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (tile_range < range_threshold) {
+				parallelize_3d_tile_1d_with_thread = &pthreadpool_thread_parallelize_3d_tile_1d_with_thread_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_3d_tile_1d_with_thread, &params, sizeof(params),
+			task, argument, tile_range, flags);
+	}
+}
+
+void pthreadpool_parallelize_3d_tile_1d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_id_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || ((range_i | range_j) <= 1 && range_k <= tile_k)) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+
+		uint32_t uarch_index = default_uarch_index;
+		#if PTHREADPOOL_USE_CPUINFO
+			uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+			if (uarch_index > max_uarch_index) {
+				uarch_index = default_uarch_index;
+			}
+		#endif
+
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j++) {
+				for (size_t k = 0; k < range_k; k += tile_k) {
+					task(argument, uarch_index, i, j, k, min(range_k - k, tile_k));
+				}
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t tile_range_k = divide_round_up(range_k, tile_k);
+		const size_t tile_range = range_i * range_j * tile_range_k;
+		const struct pthreadpool_3d_tile_1d_with_uarch_params params = {
+			.default_uarch_index = default_uarch_index,
+			.max_uarch_index = max_uarch_index,
+			.range_k = range_k,
+			.tile_k = tile_k,
+			.range_j = fxdiv_init_size_t(range_j),
+			.tile_range_k = fxdiv_init_size_t(tile_range_k),
+		};
+		thread_function_t parallelize_3d_tile_1d_with_uarch = &thread_parallelize_3d_tile_1d_with_uarch;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (tile_range < range_threshold) {
+				parallelize_3d_tile_1d_with_uarch = &pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_3d_tile_1d_with_uarch, &params, sizeof(params),
+			task, argument, tile_range, flags);
+	}
+}
+
+void pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_id_with_thread_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	size_t threads_count;
+	if (threadpool == NULL || (threads_count = threadpool->threads_count.value) <= 1 || ((range_i | range_j) <= 1 && range_k <= tile_k)) {
+		/* No thread pool used: execute task sequentially on the calling thread */
+
+		uint32_t uarch_index = default_uarch_index;
+		#if PTHREADPOOL_USE_CPUINFO
+			uarch_index = cpuinfo_get_current_uarch_index_with_default(default_uarch_index);
+			if (uarch_index > max_uarch_index) {
+				uarch_index = default_uarch_index;
+			}
+		#endif
+
+		struct fpu_state saved_fpu_state = { 0 };
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			saved_fpu_state = get_fpu_state();
+			disable_fpu_denormals();
+		}
+		for (size_t i = 0; i < range_i; i++) {
+			for (size_t j = 0; j < range_j; j++) {
+				for (size_t k = 0; k < range_k; k += tile_k) {
+					task(argument, uarch_index, 0, i, j, k, min(range_k - k, tile_k));
+				}
+			}
+		}
+		if (flags & PTHREADPOOL_FLAG_DISABLE_DENORMALS) {
+			set_fpu_state(saved_fpu_state);
+		}
+	} else {
+		const size_t tile_range_k = divide_round_up(range_k, tile_k);
+		const size_t tile_range = range_i * range_j * tile_range_k;
+		const struct pthreadpool_3d_tile_1d_with_uarch_params params = {
+			.default_uarch_index = default_uarch_index,
+			.max_uarch_index = max_uarch_index,
+			.range_k = range_k,
+			.tile_k = tile_k,
+			.range_j = fxdiv_init_size_t(range_j),
+			.tile_range_k = fxdiv_init_size_t(tile_range_k),
+		};
+		thread_function_t parallelize_3d_tile_1d_with_uarch_with_thread = &thread_parallelize_3d_tile_1d_with_uarch_with_thread;
+		#if PTHREADPOOL_USE_FASTPATH
+			const size_t range_threshold = -threads_count;
+			if (tile_range < range_threshold) {
+				parallelize_3d_tile_1d_with_uarch_with_thread = &pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_with_thread_fastpath;
+			}
+		#endif
+		pthreadpool_parallelize(
+			threadpool, parallelize_3d_tile_1d_with_uarch_with_thread, &params, sizeof(params),
+			task, argument, tile_range, flags);
+	}
+}
+
 void pthreadpool_parallelize_3d_tile_2d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_3d_tile_2d_t task,
diff --git a/src/pthreads.c b/src/pthreads.c
index 430ca79..cdead94 100644
--- a/src/pthreads.c
+++ b/src/pthreads.c
@@ -79,7 +79,7 @@
 
 static void checkin_worker_thread(struct pthreadpool* threadpool) {
 	#if PTHREADPOOL_USE_FUTEX
-		if (pthreadpool_decrement_fetch_relaxed_size_t(&threadpool->active_threads) == 0) {
+		if (pthreadpool_decrement_fetch_acquire_release_size_t(&threadpool->active_threads) == 0) {
 			pthreadpool_store_release_uint32_t(&threadpool->has_active_threads, 0);
 			futex_wake_all(&threadpool->has_active_threads);
 		}
diff --git a/src/shim.c b/src/shim.c
index 39ec884..36f7c00 100644
--- a/src/shim.c
+++ b/src/shim.c
@@ -38,6 +38,18 @@ void pthreadpool_parallelize_1d(
 	}
 }
 
+void pthreadpool_parallelize_1d_with_thread(
+	struct pthreadpool* threadpool,
+	pthreadpool_task_1d_with_thread_t task,
+	void* argument,
+	size_t range,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range; i++) {
+		task(argument, 0, i);
+	}
+}
+
 void pthreadpool_parallelize_1d_with_uarch(
 	pthreadpool_t threadpool,
 	pthreadpool_task_1d_with_id_t task,
@@ -80,6 +92,21 @@ void pthreadpool_parallelize_2d(
 	}
 }
 
+void pthreadpool_parallelize_2d_with_thread(
+	struct pthreadpool* threadpool,
+	pthreadpool_task_2d_with_thread_t task,
+	void* argument,
+	size_t range_i,
+	size_t range_j,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j++) {
+			task(argument, 0, i, j);
+		}
+	}
+}
+
 void pthreadpool_parallelize_2d_tile_1d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_2d_tile_1d_t task,
@@ -96,6 +123,42 @@ void pthreadpool_parallelize_2d_tile_1d(
 	}
 }
 
+void pthreadpool_parallelize_2d_tile_1d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j += tile_j) {
+			task(argument, default_uarch_index, i, j, min(range_j - j, tile_j));
+		}
+	}
+}
+
+void pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_2d_tile_1d_with_id_with_thread_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t tile_j,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j += tile_j) {
+			task(argument, default_uarch_index, 0, i, j, min(range_j - j, tile_j));
+		}
+	}
+}
+
 void pthreadpool_parallelize_2d_tile_2d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_2d_tile_2d_t task,
@@ -170,6 +233,67 @@ void pthreadpool_parallelize_3d_tile_1d(
 	}
 }
 
+void pthreadpool_parallelize_3d_tile_1d_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_thread_t task,
+	void* argument,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j++) {
+			for (size_t k = 0; k < range_k; k += tile_k) {
+				task(argument, 0, i, j, k, min(range_k - k, tile_k));
+			}
+		}
+	}
+}
+
+void pthreadpool_parallelize_3d_tile_1d_with_uarch(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_id_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j++) {
+			for (size_t k = 0; k < range_k; k += tile_k) {
+				task(argument, default_uarch_index, i, j, k, min(range_k - k, tile_k));
+			}
+		}
+	}
+}
+
+void pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
+	pthreadpool_t threadpool,
+	pthreadpool_task_3d_tile_1d_with_id_with_thread_t task,
+	void* argument,
+	uint32_t default_uarch_index,
+	uint32_t max_uarch_index,
+	size_t range_i,
+	size_t range_j,
+	size_t range_k,
+	size_t tile_k,
+	uint32_t flags)
+{
+	for (size_t i = 0; i < range_i; i++) {
+		for (size_t j = 0; j < range_j; j++) {
+			for (size_t k = 0; k < range_k; k += tile_k) {
+				task(argument, default_uarch_index, 0, i, j, k, min(range_k - k, tile_k));
+			}
+		}
+	}
+}
+
 void pthreadpool_parallelize_3d_tile_2d(
 	pthreadpool_t threadpool,
 	pthreadpool_task_3d_tile_2d_t task,
diff --git a/src/threadpool-atomics.h b/src/threadpool-atomics.h
index 23f943a..eaa0707 100644
--- a/src/threadpool-atomics.h
+++ b/src/threadpool-atomics.h
@@ -5,7 +5,7 @@
 #include <stdint.h>
 
 /* SSE-specific headers */
-#if defined(__i386__) || defined(__i686__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
+#if defined(__i386__) || defined(__i686__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) && !defined(_M_ARM64EC)
 	#include <xmmintrin.h>
 #endif
 
@@ -109,6 +109,12 @@
 		return __c11_atomic_fetch_sub(address, 1, __ATOMIC_RELEASE) - 1;
 	}
 
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return __c11_atomic_fetch_sub(address, 1, __ATOMIC_ACQ_REL) - 1;
+	}
+
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
@@ -214,6 +220,12 @@
 		return atomic_fetch_sub_explicit(address, 1, memory_order_release) - 1;
 	}
 
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return atomic_fetch_sub_explicit(address, 1, memory_order_acq_rel) - 1;
+	}
+
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
@@ -329,6 +341,12 @@
 		return __sync_sub_and_fetch(address, 1);
 	}
 
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return __sync_sub_and_fetch(address, 1);
+	}
+
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
@@ -351,7 +369,7 @@
 	static inline void pthreadpool_fence_release() {
 		__sync_synchronize();
 	}
-#elif defined(_MSC_VER) && defined(_M_X64)
+#elif defined(_MSC_VER) && defined(_M_ARM)
 	typedef volatile uint32_t pthreadpool_atomic_uint32_t;
 	typedef volatile size_t   pthreadpool_atomic_size_t;
 	typedef void *volatile    pthreadpool_atomic_void_p;
@@ -359,26 +377,26 @@
 	static inline uint32_t pthreadpool_load_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		return *address;
+		return (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
 	}
 
 	static inline size_t pthreadpool_load_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return *address;
+		return (size_t) __iso_volatile_load32((const volatile __int32*) address);
 	}
 
 	static inline void* pthreadpool_load_relaxed_void_p(
 		pthreadpool_atomic_void_p* address)
 	{
-		return *address;
+		return (void*) __iso_volatile_load32((const volatile __int32*) address);
 	}
 
 	static inline uint32_t pthreadpool_load_acquire_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		/* x86-64 loads always have acquire semantics; use only a compiler barrier */
-		const uint32_t value = *address;
+		const uint32_t value = (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
+		__dmb(_ARM_BARRIER_ISH);
 		_ReadBarrier();
 		return value;
 	}
@@ -386,8 +404,8 @@
 	static inline size_t pthreadpool_load_acquire_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		/* x86-64 loads always have acquire semantics; use only a compiler barrier */
-		const size_t value = *address;
+		const size_t value = (size_t) __iso_volatile_load32((const volatile __int32*) address);
+		__dmb(_ARM_BARRIER_ISH);
 		_ReadBarrier();
 		return value;
 	}
@@ -396,62 +414,68 @@
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		*address = value;
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline void pthreadpool_store_relaxed_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		*address = value;
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline void pthreadpool_store_relaxed_void_p(
 		pthreadpool_atomic_void_p* address,
 		void* value)
 	{
-		*address = value;
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline void pthreadpool_store_release_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		/* x86-64 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		*address = value;
+		__dmb(_ARM_BARRIER_ISH);
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline void pthreadpool_store_release_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		/* x86-64 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		*address = value;
+		__dmb(_ARM_BARRIER_ISH);
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
+		return (size_t) _InterlockedDecrement_nf((volatile long*) address);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_release_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
+		return (size_t) _InterlockedDecrement_rel((volatile long*) address);
+	}
+
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return (size_t) _InterlockedDecrement((volatile long*) address);
 	}
 
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
-		size_t actual_value = *value;
+		size_t actual_value = (size_t) __iso_volatile_load32((const volatile __int32*) value);
 		while (actual_value != 0) {
 			const size_t new_value = actual_value - 1;
 			const size_t expected_value = actual_value;
-			actual_value = _InterlockedCompareExchange64(
-				(volatile __int64*) value, (__int64) new_value, (__int64) expected_value);
+			actual_value = _InterlockedCompareExchange_nf(
+				(volatile long*) value, (long) new_value, (long) expected_value);
 			if (actual_value == expected_value) {
 				return true;
 			}
@@ -460,15 +484,15 @@
 	}
 
 	static inline void pthreadpool_fence_acquire() {
-		_mm_lfence();
+		__dmb(_ARM_BARRIER_ISH);
 		_ReadBarrier();
 	}
 
 	static inline void pthreadpool_fence_release() {
 		_WriteBarrier();
-		_mm_sfence();
+		__dmb(_ARM_BARRIER_ISH);
 	}
-#elif defined(_MSC_VER) && defined(_M_IX86)
+#elif defined(_MSC_VER) && defined(_M_ARM64)
 	typedef volatile uint32_t pthreadpool_atomic_uint32_t;
 	typedef volatile size_t   pthreadpool_atomic_size_t;
 	typedef void *volatile    pthreadpool_atomic_void_p;
@@ -476,99 +500,97 @@
 	static inline uint32_t pthreadpool_load_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		return *address;
+		return (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
 	}
 
 	static inline size_t pthreadpool_load_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return *address;
+		return (size_t) __iso_volatile_load64((const volatile __int64*) address);
 	}
 
 	static inline void* pthreadpool_load_relaxed_void_p(
 		pthreadpool_atomic_void_p* address)
 	{
-		return *address;
+		return (void*) __iso_volatile_load64((const volatile __int64*) address);
 	}
 
 	static inline uint32_t pthreadpool_load_acquire_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		/* x86 loads always have acquire semantics; use only a compiler barrier */
-		const uint32_t value = *address;
-		_ReadBarrier();
-		return value;
+		return (uint32_t) __ldar32((volatile unsigned __int32*) address);
 	}
 
 	static inline size_t pthreadpool_load_acquire_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		/* x86 loads always have acquire semantics; use only a compiler barrier */
-		const size_t value = *address;
-		_ReadBarrier();
-		return value;
+		return (size_t) __ldar64((volatile unsigned __int64*) address);
 	}
 
 	static inline void pthreadpool_store_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		*address = value;
+		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
 	}
 
 	static inline void pthreadpool_store_relaxed_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		*address = value;
+		__iso_volatile_store64((volatile __int64*) address, (__int64) value);
 	}
 
 	static inline void pthreadpool_store_relaxed_void_p(
 		pthreadpool_atomic_void_p* address,
 		void* value)
 	{
-		*address = value;
+		__iso_volatile_store64((volatile __int64*) address, (__int64) value);
 	}
 
 	static inline void pthreadpool_store_release_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		/* x86 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		*address = value;
+		__stlr32((unsigned __int32 volatile*) address, (unsigned __int32) value);
 	}
 
 	static inline void pthreadpool_store_release_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		/* x86 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		*address = value;
+		__stlr64((unsigned __int64 volatile*) address, (unsigned __int64) value);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement((volatile long*) address);
+		return (size_t) _InterlockedDecrement64_nf((volatile __int64*) address);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_release_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement((volatile long*) address);
+		return (size_t) _InterlockedDecrement64_rel((volatile __int64*) address);
+	}
+
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
 	}
 
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
-		size_t actual_value = *value;
+		size_t actual_value = (size_t) __iso_volatile_load64((const volatile __int64*) value);
 		while (actual_value != 0) {
 			const size_t new_value = actual_value - 1;
 			const size_t expected_value = actual_value;
-			actual_value = _InterlockedCompareExchange(
-				(volatile long*) value, (long) new_value, (long) expected_value);
+			actual_value = _InterlockedCompareExchange64_nf(
+				(volatile __int64*) value, (__int64) new_value, (__int64) expected_value);
 			if (actual_value == expected_value) {
 				return true;
 			}
@@ -577,13 +599,15 @@
 	}
 
 	static inline void pthreadpool_fence_acquire() {
-		_mm_lfence();
+		__dmb(_ARM64_BARRIER_ISHLD);
+		_ReadBarrier();
 	}
 
 	static inline void pthreadpool_fence_release() {
-		_mm_sfence();
+		_WriteBarrier();
+		__dmb(_ARM64_BARRIER_ISH);
 	}
-#elif defined(_MSC_VER) && defined(_M_ARM64)
+#elif defined(_MSC_VER) && defined(_M_IX86)
 	typedef volatile uint32_t pthreadpool_atomic_uint32_t;
 	typedef volatile size_t   pthreadpool_atomic_size_t;
 	typedef void *volatile    pthreadpool_atomic_void_p;
@@ -591,91 +615,105 @@
 	static inline uint32_t pthreadpool_load_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		return (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
+		return *address;
 	}
 
 	static inline size_t pthreadpool_load_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) __iso_volatile_load64((const volatile __int64*) address);
+		return *address;
 	}
 
 	static inline void* pthreadpool_load_relaxed_void_p(
 		pthreadpool_atomic_void_p* address)
 	{
-		return (void*) __iso_volatile_load64((const volatile __int64*) address);
+		return *address;
 	}
 
 	static inline uint32_t pthreadpool_load_acquire_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		return (uint32_t) __ldar32((volatile unsigned __int32*) address);
+		/* x86 loads always have acquire semantics; use only a compiler barrier */
+		const uint32_t value = *address;
+		_ReadBarrier();
+		return value;
 	}
 
 	static inline size_t pthreadpool_load_acquire_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) __ldar64((volatile unsigned __int64*) address);
+		/* x86 loads always have acquire semantics; use only a compiler barrier */
+		const size_t value = *address;
+		_ReadBarrier();
+		return value;
 	}
 
 	static inline void pthreadpool_store_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_relaxed_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		__iso_volatile_store64((volatile __int64*) address, (__int64) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_relaxed_void_p(
 		pthreadpool_atomic_void_p* address,
 		void* value)
 	{
-		__iso_volatile_store64((volatile __int64*) address, (__int64) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_release_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
+		/* x86 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		__stlr32((unsigned __int32 volatile*) address, (unsigned __int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_release_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
+		/* x86 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		__stlr64((unsigned __int64 volatile*) address, (unsigned __int64) value);
+		*address = value;
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement64_nf((volatile __int64*) address);
+		return (size_t) _InterlockedDecrement((volatile long*) address);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_release_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement64_rel((volatile __int64*) address);
+		return (size_t) _InterlockedDecrement((volatile long*) address);
+	}
+
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return (size_t) _InterlockedDecrement((volatile long*) address);
 	}
 
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
-		size_t actual_value = (size_t) __iso_volatile_load64((const volatile __int64*) value);
+		size_t actual_value = *value;
 		while (actual_value != 0) {
 			const size_t new_value = actual_value - 1;
 			const size_t expected_value = actual_value;
-			actual_value = _InterlockedCompareExchange64_nf(
-				(volatile __int64*) value, (__int64) new_value, (__int64) expected_value);
+			actual_value = _InterlockedCompareExchange(
+				(volatile long*) value, (long) new_value, (long) expected_value);
 			if (actual_value == expected_value) {
 				return true;
 			}
@@ -684,15 +722,13 @@
 	}
 
 	static inline void pthreadpool_fence_acquire() {
-		__dmb(_ARM64_BARRIER_ISHLD);
-		_ReadBarrier();
+		_mm_lfence();
 	}
 
 	static inline void pthreadpool_fence_release() {
-		_WriteBarrier();
-		__dmb(_ARM64_BARRIER_ISH);
+		_mm_sfence();
 	}
-#elif defined(_MSC_VER) && defined(_M_ARM)
+#elif defined(_MSC_VER) && defined(_M_X64)
 	typedef volatile uint32_t pthreadpool_atomic_uint32_t;
 	typedef volatile size_t   pthreadpool_atomic_size_t;
 	typedef void *volatile    pthreadpool_atomic_void_p;
@@ -700,26 +736,26 @@
 	static inline uint32_t pthreadpool_load_relaxed_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		return (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
+		return *address;
 	}
 
 	static inline size_t pthreadpool_load_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) __iso_volatile_load32((const volatile __int32*) address);
+		return *address;
 	}
 
 	static inline void* pthreadpool_load_relaxed_void_p(
 		pthreadpool_atomic_void_p* address)
 	{
-		return (void*) __iso_volatile_load32((const volatile __int32*) address);
+		return *address;
 	}
 
 	static inline uint32_t pthreadpool_load_acquire_uint32_t(
 		pthreadpool_atomic_uint32_t* address)
 	{
-		const uint32_t value = (uint32_t) __iso_volatile_load32((const volatile __int32*) address);
-		__dmb(_ARM_BARRIER_ISH);
+		/* x86-64 loads always have acquire semantics; use only a compiler barrier */
+		const uint32_t value = *address;
 		_ReadBarrier();
 		return value;
 	}
@@ -727,8 +763,8 @@
 	static inline size_t pthreadpool_load_acquire_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		const size_t value = (size_t) __iso_volatile_load32((const volatile __int32*) address);
-		__dmb(_ARM_BARRIER_ISH);
+		/* x86-64 loads always have acquire semantics; use only a compiler barrier */
+		const size_t value = *address;
 		_ReadBarrier();
 		return value;
 	}
@@ -737,62 +773,68 @@
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_relaxed_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_relaxed_void_p(
 		pthreadpool_atomic_void_p* address,
 		void* value)
 	{
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_release_uint32_t(
 		pthreadpool_atomic_uint32_t* address,
 		uint32_t value)
 	{
+		/* x86-64 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		__dmb(_ARM_BARRIER_ISH);
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline void pthreadpool_store_release_size_t(
 		pthreadpool_atomic_size_t* address,
 		size_t value)
 	{
+		/* x86-64 stores always have release semantics; use only a compiler barrier */
 		_WriteBarrier();
-		__dmb(_ARM_BARRIER_ISH);
-		__iso_volatile_store32((volatile __int32*) address, (__int32) value);
+		*address = value;
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_relaxed_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement_nf((volatile long*) address);
+		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
 	}
 
 	static inline size_t pthreadpool_decrement_fetch_release_size_t(
 		pthreadpool_atomic_size_t* address)
 	{
-		return (size_t) _InterlockedDecrement_rel((volatile long*) address);
+		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
+	}
+
+	static inline size_t pthreadpool_decrement_fetch_acquire_release_size_t(
+		pthreadpool_atomic_size_t* address)
+	{
+		return (size_t) _InterlockedDecrement64((volatile __int64*) address);
 	}
 
 	static inline bool pthreadpool_try_decrement_relaxed_size_t(
 		pthreadpool_atomic_size_t* value)
 	{
-		size_t actual_value = (size_t) __iso_volatile_load32((const volatile __int32*) value);
+		size_t actual_value = *value;
 		while (actual_value != 0) {
 			const size_t new_value = actual_value - 1;
 			const size_t expected_value = actual_value;
-			actual_value = _InterlockedCompareExchange_nf(
-				(volatile long*) value, (long) new_value, (long) expected_value);
+			actual_value = _InterlockedCompareExchange64(
+				(volatile __int64*) value, (__int64) new_value, (__int64) expected_value);
 			if (actual_value == expected_value) {
 				return true;
 			}
@@ -801,23 +843,19 @@
 	}
 
 	static inline void pthreadpool_fence_acquire() {
-		__dmb(_ARM_BARRIER_ISH);
+		_mm_lfence();
 		_ReadBarrier();
 	}
 
 	static inline void pthreadpool_fence_release() {
 		_WriteBarrier();
-		__dmb(_ARM_BARRIER_ISH);
+		_mm_sfence();
 	}
 #else
 	#error "Platform-specific implementation of threadpool-atomics.h required"
 #endif
 
-#if defined(__i386__) || defined(__i686__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
-	static inline void pthreadpool_yield() {
-		_mm_pause();
-	}
-#elif defined(__ARM_ACLE) || defined(_MSC_VER) && (defined(_M_ARM) || defined(_M_ARM64))
+#if defined(__ARM_ACLE) || defined(_MSC_VER) && (defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC))
 	static inline void pthreadpool_yield() {
 		__yield();
 	}
@@ -825,6 +863,10 @@
 	static inline void pthreadpool_yield() {
 		__asm__ __volatile__("yield");
 	}
+#elif defined(__i386__) || defined(__i686__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
+	static inline void pthreadpool_yield() {
+		_mm_pause();
+	}
 #else
 	static inline void pthreadpool_yield() {
 		pthreadpool_fence_acquire();
diff --git a/src/threadpool-object.h b/src/threadpool-object.h
index 590dc96..52db369 100644
--- a/src/threadpool-object.h
+++ b/src/threadpool-object.h
@@ -20,6 +20,9 @@
 
 /* Windows headers */
 #if PTHREADPOOL_USE_EVENT
+#ifndef WIN32_LEAN_AND_MEAN
+#define WIN32_LEAN_AND_MEAN
+#endif
 #include <windows.h>
 #endif
 
@@ -125,6 +128,29 @@ struct pthreadpool_2d_tile_1d_params {
 	struct fxdiv_divisor_size_t tile_range_j;
 };
 
+struct pthreadpool_2d_tile_1d_with_uarch_params {
+	/**
+	 * Copy of the default_uarch_index argument passed to the pthreadpool_parallelize_2d_tile_1d_with_uarch function.
+	 */
+	uint32_t default_uarch_index;
+	/**
+	 * Copy of the max_uarch_index argument passed to the pthreadpool_parallelize_2d_tile_1d_with_uarch function.
+	 */
+	uint32_t max_uarch_index;
+	/**
+	 * Copy of the range_j argument passed to the pthreadpool_parallelize_2d_tile_1d function.
+	 */
+	size_t range_j;
+	/**
+	 * Copy of the tile_j argument passed to the pthreadpool_parallelize_2d_tile_1d function.
+	 */
+	size_t tile_j;
+	/**
+	 * FXdiv divisor for the divide_round_up(range_j, tile_j) value.
+	 */
+	struct fxdiv_divisor_size_t tile_range_j;
+};
+
 struct pthreadpool_2d_tile_2d_params {
 	/**
 	 * Copy of the range_i argument passed to the pthreadpool_parallelize_2d_tile_2d function.
@@ -209,6 +235,33 @@ struct pthreadpool_3d_tile_1d_params {
 	struct fxdiv_divisor_size_t tile_range_k;
 };
 
+struct pthreadpool_3d_tile_1d_with_uarch_params {
+	/**
+	 * Copy of the default_uarch_index argument passed to the pthreadpool_parallelize_3d_tile_1d_with_uarch function.
+	 */
+	uint32_t default_uarch_index;
+	/**
+	 * Copy of the max_uarch_index argument passed to the pthreadpool_parallelize_3d_tile_1d_with_uarch function.
+	 */
+	uint32_t max_uarch_index;
+	/**
+	 * Copy of the range_k argument passed to the pthreadpool_parallelize_3d_tile_1d_with_uarch function.
+	 */
+	size_t range_k;
+	/**
+	 * Copy of the tile_k argument passed to the pthreadpool_parallelize_3d_tile_1d_with_uarch function.
+	 */
+	size_t tile_k;
+	/**
+	 * FXdiv divisor for the range_j argument passed to the pthreadpool_parallelize_3d_tile_1d_with_uarch function.
+	 */
+	struct fxdiv_divisor_size_t range_j;
+	/**
+	 * FXdiv divisor for the divide_round_up(range_k, tile_k) value.
+	 */
+	struct fxdiv_divisor_size_t tile_range_k;
+};
+
 struct pthreadpool_3d_tile_2d_params {
 	/**
 	 * Copy of the range_j argument passed to the pthreadpool_parallelize_3d_tile_2d function.
@@ -624,10 +677,12 @@ struct PTHREADPOOL_CACHELINE_ALIGNED pthreadpool {
 		struct pthreadpool_1d_tile_1d_params parallelize_1d_tile_1d;
 		struct pthreadpool_2d_params parallelize_2d;
 		struct pthreadpool_2d_tile_1d_params parallelize_2d_tile_1d;
+		struct pthreadpool_2d_tile_1d_with_uarch_params parallelize_2d_tile_1d_with_uarch;
 		struct pthreadpool_2d_tile_2d_params parallelize_2d_tile_2d;
 		struct pthreadpool_2d_tile_2d_with_uarch_params parallelize_2d_tile_2d_with_uarch;
 		struct pthreadpool_3d_params parallelize_3d;
 		struct pthreadpool_3d_tile_1d_params parallelize_3d_tile_1d;
+		struct pthreadpool_3d_tile_1d_with_uarch_params parallelize_3d_tile_1d_with_uarch;
 		struct pthreadpool_3d_tile_2d_params parallelize_3d_tile_2d;
 		struct pthreadpool_3d_tile_2d_with_uarch_params parallelize_3d_tile_2d_with_uarch;
 		struct pthreadpool_4d_params parallelize_4d;
@@ -731,6 +786,10 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_1d_with_uarch_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
@@ -743,10 +802,22 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_1d_with_uarch_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_2d_tile_2d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
@@ -763,6 +834,18 @@ PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
 
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
+PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_1d_with_uarch_with_thread_fastpath(
+	struct pthreadpool* threadpool,
+	struct thread_info* thread);
+
 PTHREADPOOL_INTERNAL void pthreadpool_thread_parallelize_3d_tile_2d_fastpath(
 	struct pthreadpool* threadpool,
 	struct thread_info* thread);
diff --git a/src/threadpool-utils.h b/src/threadpool-utils.h
index 91e2445..970210b 100644
--- a/src/threadpool-utils.h
+++ b/src/threadpool-utils.h
@@ -1,10 +1,11 @@
 #pragma once
 
+#include <assert.h>
 #include <stdint.h>
 #include <stddef.h>
 
 /* SSE-specific headers */
-#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
+#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) && !defined(_M_ARM64EC) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
 	#include <xmmintrin.h>
 #endif
 
@@ -15,12 +16,12 @@
 
 
 struct fpu_state {
-#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
-	uint32_t mxcsr;
-#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_FP) && (__ARM_FP != 0) || defined(_MSC_VER) && defined(_M_ARM)
+#if defined(__GNUC__) && defined(__arm__) && defined(__ARM_FP) && (__ARM_FP != 0) || defined(_MSC_VER) && defined(_M_ARM)
 	uint32_t fpscr;
-#elif defined(__GNUC__) && defined(__aarch64__) || defined(_MSC_VER) && defined(_M_ARM64)
+#elif defined(__GNUC__) && defined(__aarch64__) || defined(_MSC_VER) && (defined(_M_ARM64) || defined(_M_ARM64EC))
 	uint64_t fpcr;
+#elif defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
+	uint32_t mxcsr;
 #else
 	char unused;
 #endif
@@ -28,12 +29,12 @@ struct fpu_state {
 
 static inline struct fpu_state get_fpu_state() {
 	struct fpu_state state = { 0 };
-#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
-	state.mxcsr = (uint32_t) _mm_getcsr();
-#elif defined(_MSC_VER) && defined(_M_ARM)
+#if defined(_MSC_VER) && defined(_M_ARM)
 	state.fpscr = (uint32_t) _MoveFromCoprocessor(10, 7, 1, 0, 0);
-#elif defined(_MSC_VER) && defined(_M_ARM64)
+#elif defined(_MSC_VER) && (defined(_M_ARM64) || defined(_M_ARM64EC))
 	state.fpcr = (uint64_t) _ReadStatusReg(0x5A20);
+#elif defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
+	state.mxcsr = (uint32_t) _mm_getcsr();
 #elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_FP) && (__ARM_FP != 0)
 	__asm__ __volatile__("VMRS %[fpscr], fpscr" : [fpscr] "=r" (state.fpscr));
 #elif defined(__GNUC__) && defined(__aarch64__)
@@ -43,27 +44,25 @@ static inline struct fpu_state get_fpu_state() {
 }
 
 static inline void set_fpu_state(const struct fpu_state state) {
-#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
-	_mm_setcsr((unsigned int) state.mxcsr);
-#elif defined(_MSC_VER) && defined(_M_ARM)
+#if defined(_MSC_VER) && defined(_M_ARM)
 	_MoveToCoprocessor((int) state.fpscr, 10, 7, 1, 0, 0);
-#elif defined(_MSC_VER) && defined(_M_ARM64)
+#elif defined(_MSC_VER) && (defined(_M_ARM64) || defined(_M_ARM64EC))
 	_WriteStatusReg(0x5A20, (__int64) state.fpcr);
 #elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_FP) && (__ARM_FP != 0)
 	__asm__ __volatile__("VMSR fpscr, %[fpscr]" : : [fpscr] "r" (state.fpscr));
 #elif defined(__GNUC__) && defined(__aarch64__)
 	__asm__ __volatile__("MSR fpcr, %[fpcr]" : : [fpcr] "r" (state.fpcr));
+#elif defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
+	_mm_setcsr((unsigned int) state.mxcsr);
 #endif
 }
 
 static inline void disable_fpu_denormals() {
-#if defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
-	_mm_setcsr(_mm_getcsr() | 0x8040);
-#elif defined(_MSC_VER) && defined(_M_ARM)
+#if defined(_MSC_VER) && defined(_M_ARM)
 	int fpscr = _MoveFromCoprocessor(10, 7, 1, 0, 0);
 	fpscr |= 0x1000000;
 	_MoveToCoprocessor(fpscr, 10, 7, 1, 0, 0);
-#elif defined(_MSC_VER) && defined(_M_ARM64)
+#elif defined(_MSC_VER) && (defined(_M_ARM64) || defined(_M_ARM64EC))
 	__int64 fpcr = _ReadStatusReg(0x5A20);
 	fpcr |= 0x1080000;
 	_WriteStatusReg(0x5A20, fpcr);
@@ -92,6 +91,8 @@ static inline void disable_fpu_denormals() {
 			"ORR %w[fpcr], %w[fpcr], 0x80000\n"
 			"MSR fpcr, %[fpcr]\n"
 		: [fpcr] "=r" (fpcr));
+#elif defined(__SSE__) || defined(__x86_64__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1)
+	_mm_setcsr(_mm_getcsr() | 0x8040);
 #endif
 }
 
@@ -105,6 +106,7 @@ static inline size_t modulo_decrement(size_t i, size_t n) {
 }
 
 static inline size_t divide_round_up(size_t dividend, size_t divisor) {
+	assert(divisor != 0);
 	if (dividend % divisor == 0) {
 		return dividend / divisor;
 	} else {
diff --git a/src/windows.c b/src/windows.c
index c9b88f7..9c141b6 100644
--- a/src/windows.c
+++ b/src/windows.c
@@ -9,6 +9,9 @@
 #include "threadpool-common.h"
 
 /* Windows headers */
+#ifndef WIN32_LEAN_AND_MEAN
+#define WIN32_LEAN_AND_MEAN
+#endif
 #include <windows.h>
 
 /* Public library header */
@@ -21,7 +24,7 @@
 
 
 static void checkin_worker_thread(struct pthreadpool* threadpool, uint32_t event_index) {
-	if (pthreadpool_decrement_fetch_release_size_t(&threadpool->active_threads) == 0) {
+	if (pthreadpool_decrement_fetch_acquire_release_size_t(&threadpool->active_threads) == 0) {
 		SetEvent(threadpool->completion_event[event_index]);
 	}
 }
diff --git a/test/pthreadpool-cxx.cc b/test/pthreadpool-cxx.cc
new file mode 100644
index 0000000..2939fad
--- /dev/null
+++ b/test/pthreadpool-cxx.cc
@@ -0,0 +1,1725 @@
+#include <gtest/gtest.h>
+
+#include <pthreadpool.h>
+
+#include <algorithm>
+#include <atomic>
+#include <cstddef>
+#include <memory>
+
+
+typedef std::unique_ptr<pthreadpool, decltype(&pthreadpool_destroy)> auto_pthreadpool_t;
+
+
+const size_t kParallelize1DRange = 1223;
+const size_t kParallelize1DTile1DRange = 1303;
+const size_t kParallelize1DTile1DTile = 11;
+const size_t kParallelize2DRangeI = 41;
+const size_t kParallelize2DRangeJ = 43;
+const size_t kParallelize2DTile1DRangeI = 43;
+const size_t kParallelize2DTile1DRangeJ = 53;
+const size_t kParallelize2DTile1DTileJ = 5;
+const size_t kParallelize2DTile2DRangeI = 53;
+const size_t kParallelize2DTile2DRangeJ = 59;
+const size_t kParallelize2DTile2DTileI = 5;
+const size_t kParallelize2DTile2DTileJ = 7;
+const size_t kParallelize3DRangeI = 13;
+const size_t kParallelize3DRangeJ = 17;
+const size_t kParallelize3DRangeK = 19;
+const size_t kParallelize3DTile1DRangeI = 17;
+const size_t kParallelize3DTile1DRangeJ = 19;
+const size_t kParallelize3DTile1DRangeK = 23;
+const size_t kParallelize3DTile1DTileK = 5;
+const size_t kParallelize3DTile2DRangeI = 19;
+const size_t kParallelize3DTile2DRangeJ = 23;
+const size_t kParallelize3DTile2DRangeK = 29;
+const size_t kParallelize3DTile2DTileJ = 2;
+const size_t kParallelize3DTile2DTileK = 3;
+const size_t kParallelize4DRangeI = 11;
+const size_t kParallelize4DRangeJ = 13;
+const size_t kParallelize4DRangeK = 17;
+const size_t kParallelize4DRangeL = 19;
+const size_t kParallelize4DTile1DRangeI = 13;
+const size_t kParallelize4DTile1DRangeJ = 17;
+const size_t kParallelize4DTile1DRangeK = 19;
+const size_t kParallelize4DTile1DRangeL = 23;
+const size_t kParallelize4DTile1DTileL = 5;
+const size_t kParallelize4DTile2DRangeI = 17;
+const size_t kParallelize4DTile2DRangeJ = 19;
+const size_t kParallelize4DTile2DRangeK = 23;
+const size_t kParallelize4DTile2DRangeL = 29;
+const size_t kParallelize4DTile2DTileK = 2;
+const size_t kParallelize4DTile2DTileL = 3;
+const size_t kParallelize5DRangeI = 7;
+const size_t kParallelize5DRangeJ = 11;
+const size_t kParallelize5DRangeK = 13;
+const size_t kParallelize5DRangeL = 17;
+const size_t kParallelize5DRangeM = 19;
+const size_t kParallelize5DTile1DRangeI = 11;
+const size_t kParallelize5DTile1DRangeJ = 13;
+const size_t kParallelize5DTile1DRangeK = 17;
+const size_t kParallelize5DTile1DRangeL = 19;
+const size_t kParallelize5DTile1DRangeM = 23;
+const size_t kParallelize5DTile1DTileM = 5;
+const size_t kParallelize5DTile2DRangeI = 13;
+const size_t kParallelize5DTile2DRangeJ = 17;
+const size_t kParallelize5DTile2DRangeK = 19;
+const size_t kParallelize5DTile2DRangeL = 23;
+const size_t kParallelize5DTile2DRangeM = 29;
+const size_t kParallelize5DTile2DTileL = 3;
+const size_t kParallelize5DTile2DTileM = 2;
+const size_t kParallelize6DRangeI = 3;
+const size_t kParallelize6DRangeJ = 5;
+const size_t kParallelize6DRangeK = 7;
+const size_t kParallelize6DRangeL = 11;
+const size_t kParallelize6DRangeM = 13;
+const size_t kParallelize6DRangeN = 17;
+const size_t kParallelize6DTile1DRangeI = 5;
+const size_t kParallelize6DTile1DRangeJ = 7;
+const size_t kParallelize6DTile1DRangeK = 11;
+const size_t kParallelize6DTile1DRangeL = 13;
+const size_t kParallelize6DTile1DRangeM = 17;
+const size_t kParallelize6DTile1DRangeN = 19;
+const size_t kParallelize6DTile1DTileN = 5;
+const size_t kParallelize6DTile2DRangeI = 7;
+const size_t kParallelize6DTile2DRangeJ = 11;
+const size_t kParallelize6DTile2DRangeK = 13;
+const size_t kParallelize6DTile2DRangeL = 17;
+const size_t kParallelize6DTile2DRangeM = 19;
+const size_t kParallelize6DTile2DRangeN = 23;
+const size_t kParallelize6DTile2DTileM = 3;
+const size_t kParallelize6DTile2DTileN = 2;
+
+
+TEST(Parallelize1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d(
+		threadpool.get(),
+		[](size_t) { },
+		kParallelize1DRange);
+}
+
+TEST(Parallelize1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d(
+		threadpool.get(),
+		[](size_t i) {
+			EXPECT_LT(i, kParallelize1DRange);
+		},
+		kParallelize1DRange);
+}
+
+TEST(Parallelize1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d(
+		threadpool.get(),
+		[&indicators](size_t i) {
+			indicators[i].store(true, std::memory_order_relaxed);
+		},
+		kParallelize1DRange);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_TRUE(indicators[i].load(std::memory_order_relaxed))
+			<< "Element " << i << " not processed";
+	}
+}
+
+
+TEST(Parallelize1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d(
+		threadpool.get(),
+		[&counters](size_t i) {
+			counters[i].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize1DRange);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), 1)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times (expected: 1)";
+	}
+}
+
+TEST(Parallelize1DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool.get(),
+		[](size_t, size_t) { },
+		kParallelize1DTile1DRange, kParallelize1DTile1DTile);
+}
+
+TEST(Parallelize1DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool.get(),
+		[](size_t start_i, size_t tile_i) {
+			EXPECT_LT(start_i, kParallelize1DTile1DRange);
+			EXPECT_LE(start_i + tile_i, kParallelize1DTile1DRange);
+		},
+		kParallelize1DTile1DRange, kParallelize1DTile1DTile);
+}
+
+TEST(Parallelize1DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool.get(),
+		[](size_t start_i, size_t tile_i) {
+			EXPECT_GT(tile_i, 0);
+			EXPECT_LE(tile_i, kParallelize1DTile1DTile);
+			EXPECT_EQ(start_i % kParallelize1DTile1DTile, 0);
+			EXPECT_EQ(tile_i, std::min<size_t>(kParallelize1DTile1DTile, kParallelize1DTile1DRange - start_i));
+		},
+		kParallelize1DTile1DRange, kParallelize1DTile1DTile);
+}
+
+TEST(Parallelize1DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize1DTile1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t start_i, size_t tile_i) {
+			for (size_t i = start_i; i < start_i + tile_i; i++) {
+				indicators[i].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize1DTile1DRange, kParallelize1DTile1DTile);
+
+	for (size_t i = 0; i < kParallelize1DTile1DRange; i++) {
+		EXPECT_TRUE(indicators[i].load(std::memory_order_relaxed))
+			<< "Element " << i << " not processed";
+	}
+}
+
+TEST(Parallelize1DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize1DTile1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t start_i, size_t tile_i) {
+			for (size_t i = start_i; i < start_i + tile_i; i++) {
+				counters[i].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize1DTile1DRange, kParallelize1DTile1DTile);
+
+	for (size_t i = 0; i < kParallelize1DTile1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), 1)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times (expected: 1)";
+	}
+}
+
+TEST(Parallelize2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d(
+		threadpool.get(),
+		[](size_t, size_t) { },
+		kParallelize2DRangeI, kParallelize2DRangeJ);
+}
+
+TEST(Parallelize2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d(
+		threadpool.get(),
+		[](size_t i, size_t j) {
+			EXPECT_LT(i, kParallelize2DRangeI);
+			EXPECT_LT(j, kParallelize2DRangeJ);
+		},
+		kParallelize2DRangeI, kParallelize2DRangeJ);
+}
+
+TEST(Parallelize2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DRangeI * kParallelize2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
+			indicators[linear_idx].store(true, std::memory_order_relaxed);
+		},
+		kParallelize2DRangeI, kParallelize2DRangeJ);
+
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DRangeI * kParallelize2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
+			counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize2DRangeI, kParallelize2DRangeJ);
+
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool.get(),
+		[](size_t, size_t, size_t) { },
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ);
+}
+
+TEST(Parallelize2DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t start_j, size_t tile_j) {
+			EXPECT_LT(i, kParallelize2DTile1DRangeI);
+			EXPECT_LT(start_j, kParallelize2DTile1DRangeJ);
+			EXPECT_LE(start_j + tile_j, kParallelize2DTile1DRangeJ);
+		},
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ);
+}
+
+TEST(Parallelize2DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t start_j, size_t tile_j) {
+			EXPECT_GT(tile_j, 0);
+			EXPECT_LE(tile_j, kParallelize2DTile1DTileJ);
+			EXPECT_EQ(start_j % kParallelize2DTile1DTileJ, 0);
+			EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile1DTileJ, kParallelize2DTile1DRangeJ - start_j));
+		},
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ);
+}
+
+TEST(Parallelize2DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t start_j, size_t tile_j) {
+			for (size_t j = start_j; j < start_j + tile_j; j++) {
+				const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+				indicators[linear_idx].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t i, size_t start_j, size_t tile_j) {
+			for (size_t j = start_j; j < start_j + tile_j; j++) {
+				const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+				counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t) { },
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ);
+}
+
+TEST(Parallelize2DTile2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		[](size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+			EXPECT_LT(start_i, kParallelize2DTile2DRangeI);
+			EXPECT_LT(start_j, kParallelize2DTile2DRangeJ);
+			EXPECT_LE(start_i + tile_i, kParallelize2DTile2DRangeI);
+			EXPECT_LE(start_j + tile_j, kParallelize2DTile2DRangeJ);
+		},
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ);
+}
+
+TEST(Parallelize2DTile2D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		[](size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+			EXPECT_GT(tile_i, 0);
+			EXPECT_LE(tile_i, kParallelize2DTile2DTileI);
+			EXPECT_EQ(start_i % kParallelize2DTile2DTileI, 0);
+			EXPECT_EQ(tile_i, std::min<size_t>(kParallelize2DTile2DTileI, kParallelize2DTile2DRangeI - start_i));
+
+			EXPECT_GT(tile_j, 0);
+			EXPECT_LE(tile_j, kParallelize2DTile2DTileJ);
+			EXPECT_EQ(start_j % kParallelize2DTile2DTileJ, 0);
+			EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile2DTileJ, kParallelize2DTile2DRangeJ - start_j));
+		},
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ);
+}
+
+TEST(Parallelize2DTile2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		[&indicators](size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+			for (size_t i = start_i; i < start_i + tile_i; i++) {
+				for (size_t j = start_j; j < start_j + tile_j; j++) {
+					const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+					indicators[linear_idx].store(true, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		[&counters](size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+			for (size_t i = start_i; i < start_i + tile_i; i++) {
+				for (size_t j = start_j; j < start_j + tile_j; j++) {
+					const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+					counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize3D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		[](size_t, size_t, size_t) { },
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK);
+}
+
+TEST(Parallelize3D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k) {
+			EXPECT_LT(i, kParallelize3DRangeI);
+			EXPECT_LT(j, kParallelize3DRangeJ);
+			EXPECT_LT(k, kParallelize3DRangeK);
+		},
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK);
+}
+
+TEST(Parallelize3D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k) {
+			const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+			indicators[linear_idx].store(true, std::memory_order_relaxed);
+		},
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k) {
+			const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+			counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t) { },
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK);
+}
+
+TEST(Parallelize3DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t start_k, size_t tile_k) {
+			EXPECT_LT(i, kParallelize3DTile1DRangeI);
+			EXPECT_LT(j, kParallelize3DTile1DRangeJ);
+			EXPECT_LT(start_k, kParallelize3DTile1DRangeK);
+			EXPECT_LE(start_k + tile_k, kParallelize3DTile1DRangeK);
+		},
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK);
+}
+
+TEST(Parallelize3DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t start_k, size_t tile_k) {
+			EXPECT_GT(tile_k, 0);
+			EXPECT_LE(tile_k, kParallelize3DTile1DTileK);
+			EXPECT_EQ(start_k % kParallelize3DTile1DTileK, 0);
+			EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile1DTileK, kParallelize3DTile1DRangeK - start_k));
+		},
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK);
+}
+
+TEST(Parallelize3DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t start_k, size_t tile_k) {
+			for (size_t k = start_k; k < start_k + tile_k; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				indicators[linear_idx].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t start_k, size_t tile_k) {
+			for (size_t k = start_k; k < start_k + tile_k; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize3DTile2DRangeI, kParallelize3DTile2DRangeJ, kParallelize3DTile2DRangeK,
+		kParallelize3DTile2DTileJ, kParallelize3DTile2DTileK);
+}
+
+TEST(Parallelize3DTile2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t start_j, size_t start_k, size_t tile_j, size_t tile_k) {
+			EXPECT_LT(i, kParallelize3DTile2DRangeI);
+			EXPECT_LT(start_j, kParallelize3DTile2DRangeJ);
+			EXPECT_LT(start_k, kParallelize3DTile2DRangeK);
+			EXPECT_LE(start_j + tile_j, kParallelize3DTile2DRangeJ);
+			EXPECT_LE(start_k + tile_k, kParallelize3DTile2DRangeK);
+		},
+		kParallelize3DTile2DRangeI, kParallelize3DTile2DRangeJ, kParallelize3DTile2DRangeK,
+		kParallelize3DTile2DTileJ, kParallelize3DTile2DTileK);
+}
+
+TEST(Parallelize3DTile2D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t start_j, size_t start_k, size_t tile_j, size_t tile_k) {
+			EXPECT_GT(tile_j, 0);
+			EXPECT_LE(tile_j, kParallelize3DTile2DTileJ);
+			EXPECT_EQ(start_j % kParallelize3DTile2DTileJ, 0);
+			EXPECT_EQ(tile_j, std::min<size_t>(kParallelize3DTile2DTileJ, kParallelize3DTile2DRangeJ - start_j));
+
+			EXPECT_GT(tile_k, 0);
+			EXPECT_LE(tile_k, kParallelize3DTile2DTileK);
+			EXPECT_EQ(start_k % kParallelize3DTile2DTileK, 0);
+			EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile2DTileK, kParallelize3DTile2DRangeK - start_k));
+		},
+		kParallelize3DTile2DRangeI, kParallelize3DTile2DRangeJ, kParallelize3DTile2DRangeK,
+		kParallelize3DTile2DTileJ, kParallelize3DTile2DTileK);
+}
+
+TEST(Parallelize3DTile2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile2DRangeI * kParallelize3DTile2DRangeJ * kParallelize3DTile2DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t start_j, size_t start_k, size_t tile_j, size_t tile_k) {
+			for (size_t j = start_j; j < start_j + tile_j; j++) {
+				for (size_t k = start_k; k < start_k + tile_k; k++) {
+					const size_t linear_idx = (i * kParallelize3DTile2DRangeJ + j) * kParallelize3DTile2DRangeK + k;
+					indicators[linear_idx].store(true, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize3DTile2DRangeI, kParallelize3DTile2DRangeJ, kParallelize3DTile2DRangeK,
+		kParallelize3DTile2DTileJ, kParallelize3DTile2DTileK);
+
+	for (size_t i = 0; i < kParallelize3DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile2DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile2DRangeJ + j) * kParallelize3DTile2DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile2DRangeI * kParallelize3DTile2DRangeJ * kParallelize3DTile2DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_2d(
+		threadpool.get(),
+		[&counters](size_t i, size_t start_j, size_t start_k, size_t tile_j, size_t tile_k) {
+			for (size_t j = start_j; j < start_j + tile_j; j++) {
+				for (size_t k = start_k; k < start_k + tile_k; k++) {
+					const size_t linear_idx = (i * kParallelize3DTile2DRangeJ + j) * kParallelize3DTile2DRangeK + k;
+					counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize3DTile2DRangeI, kParallelize3DTile2DRangeJ, kParallelize3DTile2DRangeK,
+		kParallelize3DTile2DTileJ, kParallelize3DTile2DTileK);
+
+	for (size_t i = 0; i < kParallelize3DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile2DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile2DRangeJ + j) * kParallelize3DTile2DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize4D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t) { },
+		kParallelize4DRangeI, kParallelize4DRangeJ, kParallelize4DRangeK, kParallelize4DRangeL);
+}
+
+TEST(Parallelize4D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l) {
+			EXPECT_LT(i, kParallelize4DRangeI);
+			EXPECT_LT(j, kParallelize4DRangeJ);
+			EXPECT_LT(k, kParallelize4DRangeK);
+			EXPECT_LT(l, kParallelize4DRangeL);
+		},
+		kParallelize4DRangeI, kParallelize4DRangeJ, kParallelize4DRangeK, kParallelize4DRangeL);
+}
+
+TEST(Parallelize4D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize4DRangeI * kParallelize4DRangeJ * kParallelize4DRangeK * kParallelize4DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l) {
+			const size_t linear_idx = ((i * kParallelize4DRangeJ + j) * kParallelize4DRangeK + k) * kParallelize4DRangeL + l;
+			indicators[linear_idx].store(true, std::memory_order_relaxed);
+		},
+		kParallelize4DRangeI, kParallelize4DRangeJ, kParallelize4DRangeK, kParallelize4DRangeL);
+
+	for (size_t i = 0; i < kParallelize4DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DRangeJ + j) * kParallelize4DRangeK + k) * kParallelize4DRangeL + l;
+					EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") not processed";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize4D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize4DRangeI * kParallelize4DRangeJ * kParallelize4DRangeK * kParallelize4DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l) {
+			const size_t linear_idx = ((i * kParallelize4DRangeJ + j) * kParallelize4DRangeK + k) * kParallelize4DRangeL + l;
+			counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize4DRangeI, kParallelize4DRangeJ, kParallelize4DRangeK, kParallelize4DRangeL);
+
+	for (size_t i = 0; i < kParallelize4DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DRangeJ + j) * kParallelize4DRangeK + k) * kParallelize4DRangeL + l;
+					EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") was processed "
+						<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize4DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize4DTile1DRangeI, kParallelize4DTile1DRangeJ, kParallelize4DTile1DRangeK, kParallelize4DTile1DRangeL,
+		kParallelize4DTile1DTileL);
+}
+
+TEST(Parallelize4DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t start_l, size_t tile_l) {
+			EXPECT_LT(i, kParallelize4DTile1DRangeI);
+			EXPECT_LT(j, kParallelize4DTile1DRangeJ);
+			EXPECT_LT(k, kParallelize4DTile1DRangeK);
+			EXPECT_LT(start_l, kParallelize4DTile1DRangeL);
+			EXPECT_LE(start_l + tile_l, kParallelize4DTile1DRangeL);
+		},
+		kParallelize4DTile1DRangeI, kParallelize4DTile1DRangeJ, kParallelize4DTile1DRangeK, kParallelize4DTile1DRangeL,
+		kParallelize4DTile1DTileL);
+}
+
+TEST(Parallelize4DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t start_l, size_t tile_l) {
+			EXPECT_GT(tile_l, 0);
+			EXPECT_LE(tile_l, kParallelize4DTile1DTileL);
+			EXPECT_EQ(start_l % kParallelize4DTile1DTileL, 0);
+			EXPECT_EQ(tile_l, std::min<size_t>(kParallelize4DTile1DTileL, kParallelize4DTile1DRangeL - start_l));
+		},
+		kParallelize4DTile1DRangeI, kParallelize4DTile1DRangeJ, kParallelize4DTile1DRangeK, kParallelize4DTile1DRangeL,
+		kParallelize4DTile1DTileL);
+}
+
+TEST(Parallelize4DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize4DTile1DRangeI * kParallelize4DTile1DRangeJ * kParallelize4DTile1DRangeK * kParallelize4DTile1DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t start_l, size_t tile_l) {
+			for (size_t l = start_l; l < start_l + tile_l; l++) {
+				const size_t linear_idx = ((i * kParallelize4DTile1DRangeJ + j) * kParallelize4DTile1DRangeK + k) * kParallelize4DTile1DRangeL + l;
+				indicators[linear_idx].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize4DTile1DRangeI, kParallelize4DTile1DRangeJ, kParallelize4DTile1DRangeK, kParallelize4DTile1DRangeL,
+		kParallelize4DTile1DTileL);
+
+	for (size_t i = 0; i < kParallelize4DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DTile1DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile1DRangeJ + j) * kParallelize4DTile1DRangeK + k) * kParallelize4DTile1DRangeL + l;
+					EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") not processed";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize4DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize4DTile1DRangeI * kParallelize4DTile1DRangeJ * kParallelize4DTile1DRangeK * kParallelize4DTile1DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t start_l, size_t tile_l) {
+			for (size_t l = start_l; l < start_l + tile_l; l++) {
+				const size_t linear_idx = ((i * kParallelize4DTile1DRangeJ + j) * kParallelize4DTile1DRangeK + k) * kParallelize4DTile1DRangeL + l;
+				counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize4DTile1DRangeI, kParallelize4DTile1DRangeJ, kParallelize4DTile1DRangeK, kParallelize4DTile1DRangeL,
+		kParallelize4DTile1DTileL);
+
+	for (size_t i = 0; i < kParallelize4DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DTile1DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile1DRangeJ + j) * kParallelize4DTile1DRangeK + k) * kParallelize4DTile1DRangeL + l;
+					EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") was processed "
+						<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize4DTile2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize4DTile2DRangeI, kParallelize4DTile2DRangeJ, kParallelize4DTile2DRangeK, kParallelize4DTile2DRangeL,
+		kParallelize4DTile2DTileK, kParallelize4DTile2DTileL);
+}
+
+TEST(Parallelize4DTile2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t start_k, size_t start_l, size_t tile_k, size_t tile_l) {
+			EXPECT_LT(i, kParallelize4DTile2DRangeI);
+			EXPECT_LT(j, kParallelize4DTile2DRangeJ);
+			EXPECT_LT(start_k, kParallelize4DTile2DRangeK);
+			EXPECT_LT(start_l, kParallelize4DTile2DRangeL);
+			EXPECT_LE(start_k + tile_k, kParallelize4DTile2DRangeK);
+			EXPECT_LE(start_l + tile_l, kParallelize4DTile2DRangeL);
+		},
+		kParallelize4DTile2DRangeI, kParallelize4DTile2DRangeJ, kParallelize4DTile2DRangeK, kParallelize4DTile2DRangeL,
+		kParallelize4DTile2DTileK, kParallelize4DTile2DTileL);
+}
+
+TEST(Parallelize4DTile2D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t start_k, size_t start_l, size_t tile_k, size_t tile_l) {
+			EXPECT_GT(tile_k, 0);
+			EXPECT_LE(tile_k, kParallelize4DTile2DTileK);
+			EXPECT_EQ(start_k % kParallelize4DTile2DTileK, 0);
+			EXPECT_EQ(tile_k, std::min<size_t>(kParallelize4DTile2DTileK, kParallelize4DTile2DRangeK - start_k));
+
+			EXPECT_GT(tile_l, 0);
+			EXPECT_LE(tile_l, kParallelize4DTile2DTileL);
+			EXPECT_EQ(start_l % kParallelize4DTile2DTileL, 0);
+			EXPECT_EQ(tile_l, std::min<size_t>(kParallelize4DTile2DTileL, kParallelize4DTile2DRangeL - start_l));
+		},
+		kParallelize4DTile2DRangeI, kParallelize4DTile2DRangeJ, kParallelize4DTile2DRangeK, kParallelize4DTile2DRangeL,
+		kParallelize4DTile2DTileK, kParallelize4DTile2DTileL);
+}
+
+TEST(Parallelize4DTile2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize4DTile2DRangeI * kParallelize4DTile2DRangeJ * kParallelize4DTile2DRangeK * kParallelize4DTile2DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t start_k, size_t start_l, size_t tile_k, size_t tile_l) {
+			for (size_t k = start_k; k < start_k + tile_k; k++) {
+				for (size_t l = start_l; l < start_l + tile_l; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile2DRangeJ + j) * kParallelize4DTile2DRangeK + k) * kParallelize4DTile2DRangeL + l;
+					indicators[linear_idx].store(true, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize4DTile2DRangeI, kParallelize4DTile2DRangeJ, kParallelize4DTile2DRangeK, kParallelize4DTile2DRangeL,
+		kParallelize4DTile2DTileK, kParallelize4DTile2DTileL);
+
+	for (size_t i = 0; i < kParallelize4DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DTile2DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile2DRangeJ + j) * kParallelize4DTile2DRangeK + k) * kParallelize4DTile2DRangeL + l;
+					EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") not processed";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize4DTile2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize4DTile2DRangeI * kParallelize4DTile2DRangeJ * kParallelize4DTile2DRangeK * kParallelize4DTile2DRangeL);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_4d_tile_2d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t start_k, size_t start_l, size_t tile_k, size_t tile_l) {
+			for (size_t k = start_k; k < start_k + tile_k; k++) {
+				for (size_t l = start_l; l < start_l + tile_l; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile2DRangeJ + j) * kParallelize4DTile2DRangeK + k) * kParallelize4DTile2DRangeL + l;
+					counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize4DTile2DRangeI, kParallelize4DTile2DRangeJ, kParallelize4DTile2DRangeK, kParallelize4DTile2DRangeL,
+		kParallelize4DTile2DTileK, kParallelize4DTile2DTileL);
+
+	for (size_t i = 0; i < kParallelize4DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize4DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize4DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize4DTile2DRangeL; l++) {
+					const size_t linear_idx = ((i * kParallelize4DTile2DRangeJ + j) * kParallelize4DTile2DRangeK + k) * kParallelize4DTile2DRangeL + l;
+					EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+						<< "Element (" << i << ", " << j << ", " << k << ", " << l << ") was processed "
+						<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize5DRangeI, kParallelize5DRangeJ, kParallelize5DRangeK, kParallelize5DRangeL, kParallelize5DRangeM);
+}
+
+TEST(Parallelize5D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t m) {
+			EXPECT_LT(i, kParallelize5DRangeI);
+			EXPECT_LT(j, kParallelize5DRangeJ);
+			EXPECT_LT(k, kParallelize5DRangeK);
+			EXPECT_LT(l, kParallelize5DRangeL);
+			EXPECT_LT(m, kParallelize5DRangeM);
+		},
+		kParallelize5DRangeI, kParallelize5DRangeJ, kParallelize5DRangeK, kParallelize5DRangeL, kParallelize5DRangeM);
+}
+
+TEST(Parallelize5D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize5DRangeI * kParallelize5DRangeJ * kParallelize5DRangeK * kParallelize5DRangeL * kParallelize5DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l, size_t m) {
+			const size_t linear_idx = (((i * kParallelize5DRangeJ + j) * kParallelize5DRangeK + k) * kParallelize5DRangeL + l) * kParallelize5DRangeM + m;
+			indicators[linear_idx].store(true, std::memory_order_relaxed);
+		},
+		kParallelize5DRangeI, kParallelize5DRangeJ, kParallelize5DRangeK, kParallelize5DRangeL, kParallelize5DRangeM);
+
+	for (size_t i = 0; i < kParallelize5DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DRangeJ + j) * kParallelize5DRangeK + k) * kParallelize5DRangeL + l) * kParallelize5DRangeM + m;
+						EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") not processed";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize5DRangeI * kParallelize5DRangeJ * kParallelize5DRangeK * kParallelize5DRangeL * kParallelize5DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l, size_t m) {
+			const size_t linear_idx = (((i * kParallelize5DRangeJ + j) * kParallelize5DRangeK + k) * kParallelize5DRangeL + l) * kParallelize5DRangeM + m;
+			counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize5DRangeI, kParallelize5DRangeJ, kParallelize5DRangeK, kParallelize5DRangeL, kParallelize5DRangeM);
+
+	for (size_t i = 0; i < kParallelize5DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DRangeJ + j) * kParallelize5DRangeK + k) * kParallelize5DRangeL + l) * kParallelize5DRangeM + m;
+						EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") was processed "
+							<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize5DTile1DRangeI, kParallelize5DTile1DRangeJ, kParallelize5DTile1DRangeK, kParallelize5DTile1DRangeL, kParallelize5DTile1DRangeM,
+		kParallelize5DTile1DTileM);
+}
+
+TEST(Parallelize5DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t tile_m) {
+			EXPECT_LT(i, kParallelize5DTile1DRangeI);
+			EXPECT_LT(j, kParallelize5DTile1DRangeJ);
+			EXPECT_LT(k, kParallelize5DTile1DRangeK);
+			EXPECT_LT(l, kParallelize5DTile1DRangeL);
+			EXPECT_LT(start_m, kParallelize5DTile1DRangeM);
+			EXPECT_LE(start_m + tile_m, kParallelize5DTile1DRangeM);
+		},
+		kParallelize5DTile1DRangeI, kParallelize5DTile1DRangeJ, kParallelize5DTile1DRangeK, kParallelize5DTile1DRangeL, kParallelize5DTile1DRangeM,
+		kParallelize5DTile1DTileM);
+}
+
+TEST(Parallelize5DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t tile_m) {
+			EXPECT_GT(tile_m, 0);
+			EXPECT_LE(tile_m, kParallelize5DTile1DTileM);
+			EXPECT_EQ(start_m % kParallelize5DTile1DTileM, 0);
+			EXPECT_EQ(tile_m, std::min<size_t>(kParallelize5DTile1DTileM, kParallelize5DTile1DRangeM - start_m));
+		},
+		kParallelize5DTile1DRangeI, kParallelize5DTile1DRangeJ, kParallelize5DTile1DRangeK, kParallelize5DTile1DRangeL, kParallelize5DTile1DRangeM,
+		kParallelize5DTile1DTileM);
+}
+
+TEST(Parallelize5DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize5DTile1DRangeI * kParallelize5DTile1DRangeJ * kParallelize5DTile1DRangeK * kParallelize5DTile1DRangeL * kParallelize5DTile1DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t tile_m) {
+			for (size_t m = start_m; m < start_m + tile_m; m++) {
+				const size_t linear_idx = (((i * kParallelize5DTile1DRangeJ + j) * kParallelize5DTile1DRangeK + k) * kParallelize5DTile1DRangeL + l) * kParallelize5DTile1DRangeM + m;
+				indicators[linear_idx].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize5DTile1DRangeI, kParallelize5DTile1DRangeJ, kParallelize5DTile1DRangeK, kParallelize5DTile1DRangeL, kParallelize5DTile1DRangeM,
+		kParallelize5DTile1DTileM);
+
+	for (size_t i = 0; i < kParallelize5DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DTile1DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DTile1DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DTile1DRangeJ + j) * kParallelize5DTile1DRangeK + k) * kParallelize5DTile1DRangeL + l) * kParallelize5DTile1DRangeM + m;
+						EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") not processed";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize5DTile1DRangeI * kParallelize5DTile1DRangeJ * kParallelize5DTile1DRangeK * kParallelize5DTile1DRangeL * kParallelize5DTile1DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t tile_m) {
+			for (size_t m = start_m; m < start_m + tile_m; m++) {
+				const size_t linear_idx = (((i * kParallelize5DTile1DRangeJ + j) * kParallelize5DTile1DRangeK + k) * kParallelize5DTile1DRangeL + l) * kParallelize5DTile1DRangeM + m;
+				counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize5DTile1DRangeI, kParallelize5DTile1DRangeJ, kParallelize5DTile1DRangeK, kParallelize5DTile1DRangeL, kParallelize5DTile1DRangeM,
+		kParallelize5DTile1DTileM);
+
+	for (size_t i = 0; i < kParallelize5DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DTile1DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DTile1DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DTile1DRangeJ + j) * kParallelize5DTile1DRangeK + k) * kParallelize5DTile1DRangeL + l) * kParallelize5DTile1DRangeM + m;
+						EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") was processed "
+							<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5DTile2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize5DTile2DRangeI, kParallelize5DTile2DRangeJ, kParallelize5DTile2DRangeK, kParallelize5DTile2DRangeL, kParallelize5DTile2DRangeM,
+		kParallelize5DTile2DTileL, kParallelize5DTile2DTileM);
+}
+
+TEST(Parallelize5DTile2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t start_l, size_t start_m, size_t tile_l, size_t tile_m) {
+			EXPECT_LT(i, kParallelize5DTile2DRangeI);
+			EXPECT_LT(j, kParallelize5DTile2DRangeJ);
+			EXPECT_LT(k, kParallelize5DTile2DRangeK);
+			EXPECT_LT(start_l, kParallelize5DTile2DRangeL);
+			EXPECT_LT(start_m, kParallelize5DTile2DRangeM);
+			EXPECT_LE(start_l + tile_l, kParallelize5DTile2DRangeL);
+			EXPECT_LE(start_m + tile_m, kParallelize5DTile2DRangeM);
+		},
+		kParallelize5DTile2DRangeI, kParallelize5DTile2DRangeJ, kParallelize5DTile2DRangeK, kParallelize5DTile2DRangeL, kParallelize5DTile2DRangeM,
+		kParallelize5DTile2DTileL, kParallelize5DTile2DTileM);
+}
+
+TEST(Parallelize5DTile2D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t start_l, size_t start_m, size_t tile_l, size_t tile_m) {
+			EXPECT_GT(tile_l, 0);
+			EXPECT_LE(tile_l, kParallelize5DTile2DTileL);
+			EXPECT_EQ(start_l % kParallelize5DTile2DTileL, 0);
+			EXPECT_EQ(tile_l, std::min<size_t>(kParallelize5DTile2DTileL, kParallelize5DTile2DRangeL - start_l));
+
+			EXPECT_GT(tile_m, 0);
+			EXPECT_LE(tile_m, kParallelize5DTile2DTileM);
+			EXPECT_EQ(start_m % kParallelize5DTile2DTileM, 0);
+			EXPECT_EQ(tile_m, std::min<size_t>(kParallelize5DTile2DTileM, kParallelize5DTile2DRangeM - start_m));
+		},
+		kParallelize5DTile2DRangeI, kParallelize5DTile2DRangeJ, kParallelize5DTile2DRangeK, kParallelize5DTile2DRangeL, kParallelize5DTile2DRangeM,
+		kParallelize5DTile2DTileL, kParallelize5DTile2DTileM);
+}
+
+TEST(Parallelize5DTile2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize5DTile2DRangeI * kParallelize5DTile2DRangeJ * kParallelize5DTile2DRangeK * kParallelize5DTile2DRangeL * kParallelize5DTile2DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t start_l, size_t start_m, size_t tile_l, size_t tile_m) {
+			for (size_t l = start_l; l < start_l + tile_l; l++) {
+				for (size_t m = start_m; m < start_m + tile_m; m++) {
+					const size_t linear_idx = (((i * kParallelize5DTile2DRangeJ + j) * kParallelize5DTile2DRangeK + k) * kParallelize5DTile2DRangeL + l) * kParallelize5DTile2DRangeM + m;
+					indicators[linear_idx].store(true, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize5DTile2DRangeI, kParallelize5DTile2DRangeJ, kParallelize5DTile2DRangeK, kParallelize5DTile2DRangeL, kParallelize5DTile2DRangeM,
+		kParallelize5DTile2DTileL, kParallelize5DTile2DTileM);
+
+	for (size_t i = 0; i < kParallelize5DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DTile2DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DTile2DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DTile2DRangeJ + j) * kParallelize5DTile2DRangeK + k) * kParallelize5DTile2DRangeL + l) * kParallelize5DTile2DRangeM + m;
+						EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") not processed";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize5DTile2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize5DTile2DRangeI * kParallelize5DTile2DRangeJ * kParallelize5DTile2DRangeK * kParallelize5DTile2DRangeL * kParallelize5DTile2DRangeM);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_5d_tile_2d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t start_l, size_t start_m, size_t tile_l, size_t tile_m) {
+			for (size_t l = start_l; l < start_l + tile_l; l++) {
+				for (size_t m = start_m; m < start_m + tile_m; m++) {
+					const size_t linear_idx = (((i * kParallelize5DTile2DRangeJ + j) * kParallelize5DTile2DRangeK + k) * kParallelize5DTile2DRangeL + l) * kParallelize5DTile2DRangeM + m;
+					counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize5DTile2DRangeI, kParallelize5DTile2DRangeJ, kParallelize5DTile2DRangeK, kParallelize5DTile2DRangeL, kParallelize5DTile2DRangeM,
+		kParallelize5DTile2DTileL, kParallelize5DTile2DTileM);
+
+	for (size_t i = 0; i < kParallelize5DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize5DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize5DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize5DTile2DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize5DTile2DRangeM; m++) {
+						const size_t linear_idx = (((i * kParallelize5DTile2DRangeJ + j) * kParallelize5DTile2DRangeK + k) * kParallelize5DTile2DRangeL + l) * kParallelize5DTile2DRangeM + m;
+						EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+							<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ") was processed "
+							<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d(threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize6DRangeI, kParallelize6DRangeJ, kParallelize6DRangeK, kParallelize6DRangeL, kParallelize6DRangeM, kParallelize6DRangeN);
+}
+
+TEST(Parallelize6D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t m, size_t n) {
+			EXPECT_LT(i, kParallelize6DRangeI);
+			EXPECT_LT(j, kParallelize6DRangeJ);
+			EXPECT_LT(k, kParallelize6DRangeK);
+			EXPECT_LT(l, kParallelize6DRangeL);
+			EXPECT_LT(m, kParallelize6DRangeM);
+			EXPECT_LT(n, kParallelize6DRangeN);
+		},
+		kParallelize6DRangeI, kParallelize6DRangeJ, kParallelize6DRangeK, kParallelize6DRangeL, kParallelize6DRangeM, kParallelize6DRangeN);
+}
+
+TEST(Parallelize6D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize6DRangeI * kParallelize6DRangeJ * kParallelize6DRangeK * kParallelize6DRangeL * kParallelize6DRangeM * kParallelize6DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l, size_t m, size_t n) {
+			const size_t linear_idx = ((((i * kParallelize6DRangeJ + j) * kParallelize6DRangeK + k) * kParallelize6DRangeL + l) * kParallelize6DRangeM + m) * kParallelize6DRangeN + n;
+			indicators[linear_idx].store(true, std::memory_order_relaxed);
+		},
+		kParallelize6DRangeI, kParallelize6DRangeJ, kParallelize6DRangeK, kParallelize6DRangeL, kParallelize6DRangeM, kParallelize6DRangeN);
+
+	for (size_t i = 0; i < kParallelize6DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DRangeJ + j) * kParallelize6DRangeK + k) * kParallelize6DRangeL + l) * kParallelize6DRangeM + m) * kParallelize6DRangeN + n;
+							EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") not processed";
+						}
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize6DRangeI * kParallelize6DRangeJ * kParallelize6DRangeK * kParallelize6DRangeL * kParallelize6DRangeM * kParallelize6DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l, size_t m, size_t n) {
+			const size_t linear_idx = ((((i * kParallelize6DRangeJ + j) * kParallelize6DRangeK + k) * kParallelize6DRangeL + l) * kParallelize6DRangeM + m) * kParallelize6DRangeN + n;
+			counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		},
+		kParallelize6DRangeI, kParallelize6DRangeJ, kParallelize6DRangeK, kParallelize6DRangeL, kParallelize6DRangeM, kParallelize6DRangeN);
+
+	for (size_t i = 0; i < kParallelize6DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DRangeJ + j) * kParallelize6DRangeK + k) * kParallelize6DRangeL + l) * kParallelize6DRangeM + m) * kParallelize6DRangeN + n;
+							EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") was processed "
+								<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+						}
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6DTile1D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_1d(threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize6DTile1DRangeI, kParallelize6DTile1DRangeJ, kParallelize6DTile1DRangeK, kParallelize6DTile1DRangeL, kParallelize6DTile1DRangeM, kParallelize6DTile1DRangeN,
+		kParallelize6DTile1DTileN);
+}
+
+TEST(Parallelize6DTile1D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t m, size_t start_n, size_t tile_n) {
+			EXPECT_LT(i, kParallelize6DTile1DRangeI);
+			EXPECT_LT(j, kParallelize6DTile1DRangeJ);
+			EXPECT_LT(k, kParallelize6DTile1DRangeK);
+			EXPECT_LT(l, kParallelize6DTile1DRangeL);
+			EXPECT_LT(m, kParallelize6DTile1DRangeM);
+			EXPECT_LT(start_n, kParallelize6DTile1DRangeN);
+			EXPECT_LE(start_n + tile_n, kParallelize6DTile1DRangeN);
+		},
+		kParallelize6DTile1DRangeI, kParallelize6DTile1DRangeJ, kParallelize6DTile1DRangeK, kParallelize6DTile1DRangeL, kParallelize6DTile1DRangeM, kParallelize6DTile1DRangeN,
+		kParallelize6DTile1DTileN);
+}
+
+TEST(Parallelize6DTile1D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_1d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t m, size_t start_n, size_t tile_n) {
+			EXPECT_GT(tile_n, 0);
+			EXPECT_LE(tile_n, kParallelize6DTile1DTileN);
+			EXPECT_EQ(start_n % kParallelize6DTile1DTileN, 0);
+			EXPECT_EQ(tile_n, std::min<size_t>(kParallelize6DTile1DTileN, kParallelize6DTile1DRangeN - start_n));
+		},
+		kParallelize6DTile1DRangeI, kParallelize6DTile1DRangeJ, kParallelize6DTile1DRangeK, kParallelize6DTile1DRangeL, kParallelize6DTile1DRangeM, kParallelize6DTile1DRangeN,
+		kParallelize6DTile1DTileN);
+}
+
+TEST(Parallelize6DTile1D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize6DTile1DRangeI * kParallelize6DTile1DRangeJ * kParallelize6DTile1DRangeK * kParallelize6DTile1DRangeL * kParallelize6DTile1DRangeM * kParallelize6DTile1DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_1d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l, size_t m, size_t start_n, size_t tile_n) {
+			for (size_t n = start_n; n < start_n + tile_n; n++) {
+				const size_t linear_idx = ((((i * kParallelize6DTile1DRangeJ + j) * kParallelize6DTile1DRangeK + k) * kParallelize6DTile1DRangeL + l) * kParallelize6DTile1DRangeM + m) * kParallelize6DTile1DRangeN + n;
+				indicators[linear_idx].store(true, std::memory_order_relaxed);
+			}
+		},
+		kParallelize6DTile1DRangeI, kParallelize6DTile1DRangeJ, kParallelize6DTile1DRangeK, kParallelize6DTile1DRangeL, kParallelize6DTile1DRangeM, kParallelize6DTile1DRangeN,
+		kParallelize6DTile1DTileN);
+
+	for (size_t i = 0; i < kParallelize6DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DTile1DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DTile1DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DTile1DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DTile1DRangeJ + j) * kParallelize6DTile1DRangeK + k) * kParallelize6DTile1DRangeL + l) * kParallelize6DTile1DRangeM + m) * kParallelize6DTile1DRangeN + n;
+							EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") not processed";
+						}
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6DTile1D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize6DTile1DRangeI * kParallelize6DTile1DRangeJ * kParallelize6DTile1DRangeK * kParallelize6DTile1DRangeL * kParallelize6DTile1DRangeM * kParallelize6DTile1DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_1d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l, size_t m, size_t start_n, size_t tile_n) {
+			for (size_t n = start_n; n < start_n + tile_n; n++) {
+				const size_t linear_idx = ((((i * kParallelize6DTile1DRangeJ + j) * kParallelize6DTile1DRangeK + k) * kParallelize6DTile1DRangeL + l) * kParallelize6DTile1DRangeM + m) * kParallelize6DTile1DRangeN + n;
+				counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+			}
+		},
+		kParallelize6DTile1DRangeI, kParallelize6DTile1DRangeJ, kParallelize6DTile1DRangeK, kParallelize6DTile1DRangeL, kParallelize6DTile1DRangeM, kParallelize6DTile1DRangeN,
+		kParallelize6DTile1DTileN);
+
+	for (size_t i = 0; i < kParallelize6DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DTile1DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DTile1DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DTile1DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DTile1DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DTile1DRangeJ + j) * kParallelize6DTile1DRangeK + k) * kParallelize6DTile1DRangeL + l) * kParallelize6DTile1DRangeM + m) * kParallelize6DTile1DRangeN + n;
+							EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") was processed "
+								<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+						}
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6DTile2D, ThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_2d(threadpool.get(),
+		[](size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t) { },
+		kParallelize6DTile2DRangeI, kParallelize6DTile2DRangeJ, kParallelize6DTile2DRangeK, kParallelize6DTile2DRangeL, kParallelize6DTile2DRangeM, kParallelize6DTile2DRangeN,
+		kParallelize6DTile2DTileM, kParallelize6DTile2DTileN);
+}
+
+TEST(Parallelize6DTile2D, AllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t start_n, size_t tile_m, size_t tile_n) {
+			EXPECT_LT(i, kParallelize6DTile2DRangeI);
+			EXPECT_LT(j, kParallelize6DTile2DRangeJ);
+			EXPECT_LT(k, kParallelize6DTile2DRangeK);
+			EXPECT_LT(l, kParallelize6DTile2DRangeL);
+			EXPECT_LT(start_m, kParallelize6DTile2DRangeM);
+			EXPECT_LT(start_n, kParallelize6DTile2DRangeN);
+			EXPECT_LE(start_m + tile_m, kParallelize6DTile2DRangeM);
+			EXPECT_LE(start_n + tile_n, kParallelize6DTile2DRangeN);
+		},
+		kParallelize6DTile2DRangeI, kParallelize6DTile2DRangeJ, kParallelize6DTile2DRangeK, kParallelize6DTile2DRangeL, kParallelize6DTile2DRangeM, kParallelize6DTile2DRangeN,
+		kParallelize6DTile2DTileM, kParallelize6DTile2DTileN);
+}
+
+TEST(Parallelize6DTile2D, UniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_2d(
+		threadpool.get(),
+		[](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t start_n, size_t tile_m, size_t tile_n) {
+			EXPECT_GT(tile_m, 0);
+			EXPECT_LE(tile_m, kParallelize6DTile2DTileM);
+			EXPECT_EQ(start_m % kParallelize6DTile2DTileM, 0);
+			EXPECT_EQ(tile_m, std::min<size_t>(kParallelize6DTile2DTileM, kParallelize6DTile2DRangeM - start_m));
+
+			EXPECT_GT(tile_n, 0);
+			EXPECT_LE(tile_n, kParallelize6DTile2DTileN);
+			EXPECT_EQ(start_n % kParallelize6DTile2DTileN, 0);
+			EXPECT_EQ(tile_n, std::min<size_t>(kParallelize6DTile2DTileN, kParallelize6DTile2DRangeN - start_n));
+		},
+		kParallelize6DTile2DRangeI, kParallelize6DTile2DRangeJ, kParallelize6DTile2DRangeK, kParallelize6DTile2DRangeL, kParallelize6DTile2DRangeM, kParallelize6DTile2DRangeN,
+		kParallelize6DTile2DTileM, kParallelize6DTile2DTileN);
+}
+
+TEST(Parallelize6DTile2D, AllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize6DTile2DRangeI * kParallelize6DTile2DRangeJ * kParallelize6DTile2DRangeK * kParallelize6DTile2DRangeL * kParallelize6DTile2DRangeM * kParallelize6DTile2DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_2d(
+		threadpool.get(),
+		[&indicators](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t start_n, size_t tile_m, size_t tile_n) {
+			for (size_t m = start_m; m < start_m + tile_m; m++) {
+				for (size_t n = start_n; n < start_n + tile_n; n++) {
+					const size_t linear_idx = ((((i * kParallelize6DTile2DRangeJ + j) * kParallelize6DTile2DRangeK + k) * kParallelize6DTile2DRangeL + l) * kParallelize6DTile2DRangeM + m) * kParallelize6DTile2DRangeN + n;
+					indicators[linear_idx].store(true, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize6DTile2DRangeI, kParallelize6DTile2DRangeJ, kParallelize6DTile2DRangeK, kParallelize6DTile2DRangeL, kParallelize6DTile2DRangeM, kParallelize6DTile2DRangeN,
+		kParallelize6DTile2DTileM, kParallelize6DTile2DTileN);
+
+	for (size_t i = 0; i < kParallelize6DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DTile2DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DTile2DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DTile2DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DTile2DRangeJ + j) * kParallelize6DTile2DRangeK + k) * kParallelize6DTile2DRangeL + l) * kParallelize6DTile2DRangeM + m) * kParallelize6DTile2DRangeN + n;
+							EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") not processed";
+						}
+					}
+				}
+			}
+		}
+	}
+}
+
+TEST(Parallelize6DTile2D, EachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize6DTile2DRangeI * kParallelize6DTile2DRangeJ * kParallelize6DTile2DRangeK * kParallelize6DTile2DRangeL * kParallelize6DTile2DRangeM * kParallelize6DTile2DRangeN);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_6d_tile_2d(
+		threadpool.get(),
+		[&counters](size_t i, size_t j, size_t k, size_t l, size_t start_m, size_t start_n, size_t tile_m, size_t tile_n) {
+			for (size_t m = start_m; m < start_m + tile_m; m++) {
+				for (size_t n = start_n; n < start_n + tile_n; n++) {
+					const size_t linear_idx = ((((i * kParallelize6DTile2DRangeJ + j) * kParallelize6DTile2DRangeK + k) * kParallelize6DTile2DRangeL + l) * kParallelize6DTile2DRangeM + m) * kParallelize6DTile2DRangeN + n;
+					counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+				}
+			}
+		},
+		kParallelize6DTile2DRangeI, kParallelize6DTile2DRangeJ, kParallelize6DTile2DRangeK, kParallelize6DTile2DRangeL, kParallelize6DTile2DRangeM, kParallelize6DTile2DRangeN,
+		kParallelize6DTile2DTileM, kParallelize6DTile2DTileN);
+
+	for (size_t i = 0; i < kParallelize6DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize6DTile2DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize6DTile2DRangeK; k++) {
+				for (size_t l = 0; l < kParallelize6DTile2DRangeL; l++) {
+					for (size_t m = 0; m < kParallelize6DTile2DRangeM; m++) {
+						for (size_t n = 0; n < kParallelize6DTile2DRangeN; n++) {
+							const size_t linear_idx = ((((i * kParallelize6DTile2DRangeJ + j) * kParallelize6DTile2DRangeK + k) * kParallelize6DTile2DRangeL + l) * kParallelize6DTile2DRangeM + m) * kParallelize6DTile2DRangeN + n;
+							EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+								<< "Element (" << i << ", " << j << ", " << k << ", " << l << ", " << m << ", " << n << ") was processed "
+								<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+						}
+					}
+				}
+			}
+		}
+	}
+}
diff --git a/test/pthreadpool.cc b/test/pthreadpool.cc
index c9592ec..2fc67e8 100644
--- a/test/pthreadpool.cc
+++ b/test/pthreadpool.cc
@@ -369,6 +369,281 @@ TEST(Parallelize1D, MultiThreadPoolWorkStealing) {
 	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize1DRange);
 }
 
+static void ComputeNothing1DWithThread(void*, size_t, size_t) {
+}
+
+TEST(Parallelize1DWithThread, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_with_thread(threadpool.get(),
+		ComputeNothing1DWithThread,
+		nullptr,
+		kParallelize1DRange,
+		0 /* flags */);
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		ComputeNothing1DWithThread,
+		nullptr,
+		kParallelize1DRange,
+		0 /* flags */);
+}
+
+static void CheckBounds1DWithThread(void*, size_t, size_t i) {
+	EXPECT_LT(i, kParallelize1DRange);
+}
+
+TEST(Parallelize1DWithThread, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		CheckBounds1DWithThread,
+		nullptr,
+		kParallelize1DRange,
+		0 /* flags */);
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		CheckBounds1DWithThread,
+		nullptr,
+		kParallelize1DRange,
+		0 /* flags */);
+}
+
+static void SetTrue1DWithThread(std::atomic_bool* processed_indicators, size_t, size_t i) {
+	processed_indicators[i].store(true, std::memory_order_relaxed);
+}
+
+TEST(Parallelize1DWithThread, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(SetTrue1DWithThread),
+		static_cast<void*>(indicators.data()),
+		kParallelize1DRange,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_TRUE(indicators[i].load(std::memory_order_relaxed))
+			<< "Element " << i << " not processed";
+	}
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(SetTrue1DWithThread),
+		static_cast<void*>(indicators.data()),
+		kParallelize1DRange,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_TRUE(indicators[i].load(std::memory_order_relaxed))
+			<< "Element " << i << " not processed";
+	}
+}
+
+static void Increment1DWithThread(std::atomic_int* processed_counters, size_t, size_t i) {
+	processed_counters[i].fetch_add(1, std::memory_order_relaxed);
+}
+
+TEST(Parallelize1DWithThread, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(Increment1DWithThread),
+		static_cast<void*>(counters.data()),
+		kParallelize1DRange,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), 1)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times (expected: 1)";
+	}
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(Increment1DWithThread),
+		static_cast<void*>(counters.data()),
+		kParallelize1DRange,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), 1)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times (expected: 1)";
+	}
+}
+
+TEST(Parallelize1DWithThread, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_1d_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_1d_with_thread_t>(Increment1DWithThread),
+			static_cast<void*>(counters.data()),
+			kParallelize1DRange,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), kIncrementIterations)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times "
+			<< "(expected: " << kIncrementIterations << ")";
+	}
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize1DRange);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_1d_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_1d_with_thread_t>(Increment1DWithThread),
+			static_cast<void*>(counters.data()),
+			kParallelize1DRange,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize1DRange; i++) {
+		EXPECT_EQ(counters[i].load(std::memory_order_relaxed), kIncrementIterations)
+			<< "Element " << i << " was processed " << counters[i].load(std::memory_order_relaxed) << " times "
+			<< "(expected: " << kIncrementIterations << ")";
+	}
+}
+
+static void IncrementSame1DWithThread(std::atomic_int* num_processed_items, size_t, size_t i) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(IncrementSame1DWithThread),
+		static_cast<void*>(&num_processed_items),
+		kParallelize1DRange,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize1DRange);
+}
+
+static void WorkImbalance1DWithThread(std::atomic_int* num_processed_items, size_t, size_t i) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	if (i == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize1DRange) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(WorkImbalance1DWithThread),
+		static_cast<void*>(&num_processed_items),
+		kParallelize1DRange,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize1DRange);
+}
+
+static void CheckThreadIndexValid1DWithThread(const size_t* num_threads, size_t thread_index, size_t) {
+	EXPECT_LE(thread_index, *num_threads);
+}
+
+TEST(Parallelize1DWithThread, MultiThreadPoolThreadIndexValid) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	size_t num_threads = pthreadpool_get_threads_count(threadpool.get());
+	if (num_threads <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_1d_with_thread_t>(CheckThreadIndexValid1DWithThread),
+		static_cast<void*>(&num_threads),
+		kParallelize1DRange,
+		0 /* flags */);
+}
+
 static void ComputeNothing1DWithUArch(void*, uint32_t, size_t) {
 }
 
@@ -1259,21 +1534,21 @@ TEST(Parallelize2D, MultiThreadPoolWorkStealing) {
 	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DRangeI * kParallelize2DRangeJ);
 }
 
-static void ComputeNothing2DTile1D(void*, size_t, size_t, size_t) {
+static void ComputeNothing2DWithThread(void*, size_t, size_t, size_t) {
 }
 
-TEST(Parallelize2DTile1D, SingleThreadPoolCompletes) {
+TEST(Parallelize2DWithThread, SingleThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_1d(threadpool.get(),
-		ComputeNothing2DTile1D,
+	pthreadpool_parallelize_2d_with_thread(threadpool.get(),
+		ComputeNothing2DWithThread,
 		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolCompletes) {
+TEST(Parallelize2DWithThread, MultiThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1281,33 +1556,32 @@ TEST(Parallelize2DTile1D, MultiThreadPoolCompletes) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		ComputeNothing2DTile1D,
+		ComputeNothing2DWithThread,
 		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 }
 
-static void CheckBounds2DTile1D(void*, size_t i, size_t start_j, size_t tile_j) {
-	EXPECT_LT(i, kParallelize2DTile1DRangeI);
-	EXPECT_LT(start_j, kParallelize2DTile1DRangeJ);
-	EXPECT_LE(start_j + tile_j, kParallelize2DTile1DRangeJ);
+static void CheckBounds2DWithThread(void*, size_t, size_t i, size_t j) {
+	EXPECT_LT(i, kParallelize2DRangeI);
+	EXPECT_LT(j, kParallelize2DRangeJ);
 }
 
-TEST(Parallelize2DTile1D, SingleThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DWithThread, SingleThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		CheckBounds2DTile1D,
+		CheckBounds2DWithThread,
 		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DWithThread, MultiThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1315,80 +1589,43 @@ TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		CheckBounds2DTile1D,
+		CheckBounds2DWithThread,
 		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 }
 
-static void CheckTiling2DTile1D(void*, size_t i, size_t start_j, size_t tile_j) {
-	EXPECT_GT(tile_j, 0);
-	EXPECT_LE(tile_j, kParallelize2DTile1DTileJ);
-	EXPECT_EQ(start_j % kParallelize2DTile1DTileJ, 0);
-	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile1DTileJ, kParallelize2DTile1DRangeJ - start_j));
-}
-
-TEST(Parallelize2DTile1D, SingleThreadPoolUniformTiling) {
-	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
-	ASSERT_TRUE(threadpool.get());
-
-	pthreadpool_parallelize_2d_tile_1d(
-		threadpool.get(),
-		CheckTiling2DTile1D,
-		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
-		0 /* flags */);
-}
-
-TEST(Parallelize2DTile1D, MultiThreadPoolUniformTiling) {
-	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
-	ASSERT_TRUE(threadpool.get());
-
-	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
-		GTEST_SKIP();
-	}
-
-	pthreadpool_parallelize_2d_tile_1d(
-		threadpool.get(),
-		CheckTiling2DTile1D,
-		nullptr,
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
-		0 /* flags */);
-}
-
-static void SetTrue2DTile1D(std::atomic_bool* processed_indicators, size_t i, size_t start_j, size_t tile_j) {
-	for (size_t j = start_j; j < start_j + tile_j; j++) {
-		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
-		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
-	}
+static void SetTrue2DWithThread(std::atomic_bool* processed_indicators, size_t, size_t i, size_t j) {
+	const size_t linear_idx = i * kParallelize2DRangeJ + j;
+	processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
 }
 
-TEST(Parallelize2DTile1D, SingleThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(SetTrue2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(SetTrue2DWithThread),
 		static_cast<void*>(indicators.data()),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1397,45 +1634,43 @@ TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsProcessed) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(SetTrue2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(SetTrue2DWithThread),
 		static_cast<void*>(indicators.data()),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-static void Increment2DTile1D(std::atomic_int* processed_counters, size_t i, size_t start_j, size_t tile_j) {
-	for (size_t j = start_j; j < start_j + tile_j; j++) {
-		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
-		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
-	}
+static void Increment2DWithThread(std::atomic_int* processed_counters, size_t, size_t i, size_t j) {
+	const size_t linear_idx = i * kParallelize2DRangeJ + j;
+	processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
 }
 
-TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(Increment2DWithThread),
 		static_cast<void*>(counters.data()),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -1443,8 +1678,8 @@ TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1453,16 +1688,16 @@ TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedOnce) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(Increment2DWithThread),
 		static_cast<void*>(counters.data()),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -1470,24 +1705,24 @@ TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_1d(
+		pthreadpool_parallelize_2d_with_thread(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
+			reinterpret_cast<pthreadpool_task_2d_with_thread_t>(Increment2DWithThread),
 			static_cast<void*>(counters.data()),
-			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+			kParallelize2DRangeI, kParallelize2DRangeJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -1496,8 +1731,8 @@ TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+TEST(Parallelize2DWithThread, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DRangeI * kParallelize2DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1507,17 +1742,17 @@ TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_1d(
+		pthreadpool_parallelize_2d_with_thread(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
+			reinterpret_cast<pthreadpool_task_2d_with_thread_t>(Increment2DWithThread),
 			static_cast<void*>(counters.data()),
-			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+			kParallelize2DRangeI, kParallelize2DRangeJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -1526,13 +1761,11 @@ TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-static void IncrementSame2DTile1D(std::atomic_int* num_processed_items, size_t i, size_t start_j, size_t tile_j) {
-	for (size_t j = start_j; j < start_j + tile_j; j++) {
-		num_processed_items->fetch_add(1, std::memory_order_relaxed);
-	}
+static void IncrementSame2DWithThread(std::atomic_int* num_processed_items, size_t, size_t i, size_t j) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolHighContention) {
+TEST(Parallelize2DWithThread, MultiThreadPoolHighContention) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -1542,26 +1775,26 @@ TEST(Parallelize2DTile1D, MultiThreadPoolHighContention) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(IncrementSame2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(IncrementSame2DWithThread),
 		static_cast<void*>(&num_processed_items),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DRangeI * kParallelize2DRangeJ);
 }
 
-static void WorkImbalance2DTile1D(std::atomic_int* num_processed_items, size_t i, size_t start_j, size_t tile_j) {
-	num_processed_items->fetch_add(tile_j, std::memory_order_relaxed);
-	if (i == 0 && start_j == 0) {
+static void WorkImbalance2DWithThread(std::atomic_int* num_processed_items, size_t, size_t i, size_t j) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	if (i == 0 && j == 0) {
 		/* Spin-wait until all items are computed */
-		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ) {
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DRangeI * kParallelize2DRangeJ) {
 			std::atomic_thread_fence(std::memory_order_acquire);
 		}
 	}
 }
 
-TEST(Parallelize2DTile1D, MultiThreadPoolWorkStealing) {
+TEST(Parallelize2DWithThread, MultiThreadPoolWorkStealing) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -1571,31 +1804,51 @@ TEST(Parallelize2DTile1D, MultiThreadPoolWorkStealing) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_1d(
+	pthreadpool_parallelize_2d_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(WorkImbalance2DTile1D),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(WorkImbalance2DWithThread),
 		static_cast<void*>(&num_processed_items),
-		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		kParallelize2DRangeI, kParallelize2DRangeJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DRangeI * kParallelize2DRangeJ);
 }
 
-static void ComputeNothing2DTile2D(void*, size_t, size_t, size_t, size_t) {
+static void CheckThreadIndexValid2DWithThread(const size_t* num_threads, size_t thread_index, size_t, size_t) {
+	EXPECT_LE(thread_index, *num_threads);
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolCompletes) {
+TEST(Parallelize2DWithThread, MultiThreadPoolThreadIndexValid) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	size_t num_threads = pthreadpool_get_threads_count(threadpool.get());
+	if (num_threads <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_with_thread_t>(CheckThreadIndexValid2DWithThread),
+		static_cast<void*>(&num_threads),
+		kParallelize2DRangeI, kParallelize2DRangeJ,
+		0 /* flags */);
+}
+
+static void ComputeNothing2DTile1D(void*, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize2DTile1D, SingleThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d(threadpool.get(),
-		ComputeNothing2DTile2D,
+	pthreadpool_parallelize_2d_tile_1d(threadpool.get(),
+		ComputeNothing2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolCompletes) {
+TEST(Parallelize2DTile1D, MultiThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1603,36 +1856,33 @@ TEST(Parallelize2DTile2D, MultiThreadPoolCompletes) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		ComputeNothing2DTile2D,
+		ComputeNothing2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckBounds2DTile2D(void*, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	EXPECT_LT(start_i, kParallelize2DTile2DRangeI);
-	EXPECT_LT(start_j, kParallelize2DTile2DRangeJ);
-	EXPECT_LE(start_i + tile_i, kParallelize2DTile2DRangeI);
-	EXPECT_LE(start_j + tile_j, kParallelize2DTile2DRangeJ);
+static void CheckBounds2DTile1D(void*, size_t i, size_t start_j, size_t tile_j) {
+	EXPECT_LT(i, kParallelize2DTile1DRangeI);
+	EXPECT_LT(start_j, kParallelize2DTile1DRangeJ);
+	EXPECT_LE(start_j + tile_j, kParallelize2DTile1DRangeJ);
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1D, SingleThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		CheckBounds2DTile2D,
+		CheckBounds2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1640,41 +1890,34 @@ TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		CheckBounds2DTile2D,
+		CheckBounds2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckTiling2DTile2D(void*, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	EXPECT_GT(tile_i, 0);
-	EXPECT_LE(tile_i, kParallelize2DTile2DTileI);
-	EXPECT_EQ(start_i % kParallelize2DTile2DTileI, 0);
-	EXPECT_EQ(tile_i, std::min<size_t>(kParallelize2DTile2DTileI, kParallelize2DTile2DRangeI - start_i));
-
+static void CheckTiling2DTile1D(void*, size_t i, size_t start_j, size_t tile_j) {
 	EXPECT_GT(tile_j, 0);
-	EXPECT_LE(tile_j, kParallelize2DTile2DTileJ);
-	EXPECT_EQ(start_j % kParallelize2DTile2DTileJ, 0);
-	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile2DTileJ, kParallelize2DTile2DRangeJ - start_j));
+	EXPECT_LE(tile_j, kParallelize2DTile1DTileJ);
+	EXPECT_EQ(start_j % kParallelize2DTile1DTileJ, 0);
+	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile1DTileJ, kParallelize2DTile1DRangeJ - start_j));
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolUniformTiling) {
+TEST(Parallelize2DTile1D, SingleThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		CheckTiling2DTile2D,
+		CheckTiling2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolUniformTiling) {
+TEST(Parallelize2DTile1D, MultiThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1682,49 +1925,45 @@ TEST(Parallelize2DTile2D, MultiThreadPoolUniformTiling) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		CheckTiling2DTile2D,
+		CheckTiling2DTile1D,
 		nullptr,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void SetTrue2DTile2D(std::atomic_bool* processed_indicators, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
-			processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
-		}
+static void SetTrue2DTile1D(std::atomic_bool* processed_indicators, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(SetTrue2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(SetTrue2DTile1D),
 		static_cast<void*>(indicators.data()),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1733,49 +1972,45 @@ TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsProcessed) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(SetTrue2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(SetTrue2DTile1D),
 		static_cast<void*>(indicators.data()),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-static void Increment2DTile2D(std::atomic_int* processed_counters, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
-			processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
-		}
+static void Increment2DTile1D(std::atomic_int* processed_counters, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
 		static_cast<void*>(counters.data()),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -1783,8 +2018,8 @@ TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1793,17 +2028,16 @@ TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedOnce) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
 		static_cast<void*>(counters.data()),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -1811,25 +2045,24 @@ TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_2d(
+		pthreadpool_parallelize_2d_tile_1d(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
 			static_cast<void*>(counters.data()),
-			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -1838,8 +2071,8 @@ TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -1849,18 +2082,17 @@ TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_2d(
+		pthreadpool_parallelize_2d_tile_1d(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(Increment2DTile1D),
 			static_cast<void*>(counters.data()),
-			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -1869,15 +2101,13 @@ TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-static void IncrementSame2DTile2D(std::atomic_int* num_processed_items, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			num_processed_items->fetch_add(1, std::memory_order_relaxed);
-		}
+static void IncrementSame2DTile1D(std::atomic_int* num_processed_items, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolHighContention) {
+TEST(Parallelize2DTile1D, MultiThreadPoolHighContention) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -1887,27 +2117,26 @@ TEST(Parallelize2DTile2D, MultiThreadPoolHighContention) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(IncrementSame2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(IncrementSame2DTile1D),
 		static_cast<void*>(&num_processed_items),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 }
 
-static void WorkImbalance2DTile2D(std::atomic_int* num_processed_items, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	num_processed_items->fetch_add(tile_i * tile_j, std::memory_order_relaxed);
-	if (start_i == 0 && start_j == 0) {
+static void WorkImbalance2DTile1D(std::atomic_int* num_processed_items, size_t i, size_t start_j, size_t tile_j) {
+	num_processed_items->fetch_add(tile_j, std::memory_order_relaxed);
+	if (i == 0 && start_j == 0) {
 		/* Spin-wait until all items are computed */
-		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ) {
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ) {
 			std::atomic_thread_fence(std::memory_order_acquire);
 		}
 	}
 }
 
-TEST(Parallelize2DTile2D, MultiThreadPoolWorkStealing) {
+TEST(Parallelize2DTile1D, MultiThreadPoolWorkStealing) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -1917,33 +2146,31 @@ TEST(Parallelize2DTile2D, MultiThreadPoolWorkStealing) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d(
+	pthreadpool_parallelize_2d_tile_1d(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(WorkImbalance2DTile2D),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_t>(WorkImbalance2DTile1D),
 		static_cast<void*>(&num_processed_items),
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 }
 
-static void ComputeNothing2DTile2DWithUArch(void*, uint32_t, size_t, size_t, size_t, size_t) {
+static void ComputeNothing2DTile1DWithUArch(void*, uint32_t, size_t, size_t, size_t) {
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolCompletes) {
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(threadpool.get(),
-		ComputeNothing2DTile2DWithUArch,
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(threadpool.get(),
+		ComputeNothing2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolCompletes) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1951,37 +2178,35 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolCompletes) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		ComputeNothing2DTile2DWithUArch,
+		ComputeNothing2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckUArch2DTile2DWithUArch(void*, uint32_t uarch_index, size_t, size_t, size_t, size_t) {
+static void CheckUArch2DTile1DWithUArch(void*, uint32_t uarch_index, size_t, size_t, size_t) {
 	if (uarch_index != kDefaultUArchIndex) {
 		EXPECT_LE(uarch_index, kMaxUArchIndex);
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolUArchInBounds) {
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolUArchInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckUArch2DTile2DWithUArch,
+		CheckUArch2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUArchInBounds) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolUArchInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -1989,38 +2214,35 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUArchInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckUArch2DTile2DWithUArch,
+		CheckUArch2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckBounds2DTile2DWithUArch(void*, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	EXPECT_LT(start_i, kParallelize2DTile2DRangeI);
-	EXPECT_LT(start_j, kParallelize2DTile2DRangeJ);
-	EXPECT_LE(start_i + tile_i, kParallelize2DTile2DRangeI);
-	EXPECT_LE(start_j + tile_j, kParallelize2DTile2DRangeJ);
+static void CheckBounds2DTile1DWithUArch(void*, uint32_t, size_t i, size_t start_j, size_t tile_j) {
+	EXPECT_LT(i, kParallelize2DTile1DRangeI);
+	EXPECT_LT(start_j, kParallelize2DTile1DRangeJ);
+	EXPECT_LE(start_j + tile_j, kParallelize2DTile1DRangeJ);
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckBounds2DTile2DWithUArch,
+		CheckBounds2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2028,43 +2250,36 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckBounds2DTile2DWithUArch,
+		CheckBounds2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckTiling2DTile2DWithUArch(void*, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	EXPECT_GT(tile_i, 0);
-	EXPECT_LE(tile_i, kParallelize2DTile2DTileI);
-	EXPECT_EQ(start_i % kParallelize2DTile2DTileI, 0);
-	EXPECT_EQ(tile_i, std::min<size_t>(kParallelize2DTile2DTileI, kParallelize2DTile2DRangeI - start_i));
-
+static void CheckTiling2DTile1DWithUArch(void*, uint32_t, size_t i, size_t start_j, size_t tile_j) {
 	EXPECT_GT(tile_j, 0);
-	EXPECT_LE(tile_j, kParallelize2DTile2DTileJ);
-	EXPECT_EQ(start_j % kParallelize2DTile2DTileJ, 0);
-	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile2DTileJ, kParallelize2DTile2DRangeJ - start_j));
+	EXPECT_LE(tile_j, kParallelize2DTile1DTileJ);
+	EXPECT_EQ(start_j % kParallelize2DTile1DTileJ, 0);
+	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile1DTileJ, kParallelize2DTile1DRangeJ - start_j));
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolUniformTiling) {
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckTiling2DTile2DWithUArch,
+		CheckTiling2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUniformTiling) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2072,51 +2287,47 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUniformTiling) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		CheckTiling2DTile2DWithUArch,
+		CheckTiling2DTile1DWithUArch,
 		nullptr,
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void SetTrue2DTile2DWithUArch(std::atomic_bool* processed_indicators, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
-			processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
-		}
+static void SetTrue2DTile1DWithUArch(std::atomic_bool* processed_indicators, uint32_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(SetTrue2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(SetTrue2DTile1DWithUArch),
 		static_cast<void*>(indicators.data()),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2125,51 +2336,47 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsProcessed) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(SetTrue2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(SetTrue2DTile1DWithUArch),
 		static_cast<void*>(indicators.data()),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 				<< "Element (" << i << ", " << j << ") not processed";
 		}
 	}
 }
 
-static void Increment2DTile2DWithUArch(std::atomic_int* processed_counters, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
-			processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
-		}
+static void Increment2DTile1DWithUArch(std::atomic_int* processed_counters, uint32_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(Increment2DTile1DWithUArch),
 		static_cast<void*>(counters.data()),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -2177,8 +2384,8 @@ TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2187,18 +2394,17 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(Increment2DTile1DWithUArch),
 		static_cast<void*>(counters.data()),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -2206,26 +2412,25 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		pthreadpool_parallelize_2d_tile_1d_with_uarch(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(Increment2DTile1DWithUArch),
 			static_cast<void*>(counters.data()),
 			kDefaultUArchIndex, kMaxUArchIndex,
-			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -2234,8 +2439,8 @@ TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedMultipleTime
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2245,19 +2450,18 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes
 	}
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		pthreadpool_parallelize_2d_tile_1d_with_uarch(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(Increment2DTile1DWithUArch),
 			static_cast<void*>(counters.data()),
 			kDefaultUArchIndex, kMaxUArchIndex,
-			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
-			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
 			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 				<< "Element (" << i << ", " << j << ") was processed "
 				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -2266,15 +2470,13 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes
 	}
 }
 
-static void IncrementSame2DTile2DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	for (size_t i = start_i; i < start_i + tile_i; i++) {
-		for (size_t j = start_j; j < start_j + tile_j; j++) {
-			num_processed_items->fetch_add(1, std::memory_order_relaxed);
-		}
+static void IncrementSame2DTile1DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolHighContention) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolHighContention) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2284,28 +2486,27 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolHighContention) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(IncrementSame2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(IncrementSame2DTile1DWithUArch),
 		static_cast<void*>(&num_processed_items),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 }
 
-static void WorkImbalance2DTile2DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
-	num_processed_items->fetch_add(tile_i * tile_j, std::memory_order_relaxed);
-	if (start_i == 0 && start_j == 0) {
+static void WorkImbalance2DTile1DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t i, size_t start_j, size_t tile_j) {
+	num_processed_items->fetch_add(tile_j, std::memory_order_relaxed);
+	if (i == 0 && start_j == 0) {
 		/* Spin-wait until all items are computed */
-		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ) {
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ) {
 			std::atomic_thread_fence(std::memory_order_acquire);
 		}
 	}
 }
 
-TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolWorkStealing) {
+TEST(Parallelize2DTile1DWithUArch, MultiThreadPoolWorkStealing) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2315,32 +2516,32 @@ TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolWorkStealing) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(WorkImbalance2DTile2DWithUArch),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_t>(WorkImbalance2DTile1DWithUArch),
 		static_cast<void*>(&num_processed_items),
 		kDefaultUArchIndex, kMaxUArchIndex,
-		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
-		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
 }
 
-static void ComputeNothing3D(void*, size_t, size_t, size_t) {
+static void ComputeNothing2DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t, size_t, size_t) {
 }
 
-TEST(Parallelize3D, SingleThreadPoolCompletes) {
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d(threadpool.get(),
-		ComputeNothing3D,
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(threadpool.get(),
+		ComputeNothing2DTile1DWithUArchWithThread,
 		nullptr,
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize3D, MultiThreadPoolCompletes) {
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2348,33 +2549,35 @@ TEST(Parallelize3D, MultiThreadPoolCompletes) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		ComputeNothing3D,
+		ComputeNothing2DTile1DWithUArchWithThread,
 		nullptr,
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void CheckBounds3D(void*, size_t i, size_t j, size_t k) {
-	EXPECT_LT(i, kParallelize3DRangeI);
-	EXPECT_LT(j, kParallelize3DRangeJ);
-	EXPECT_LT(k, kParallelize3DRangeK);
+static void CheckUArch2DTile1DWithUArchWithThread(void*, uint32_t uarch_index, size_t, size_t, size_t, size_t) {
+	if (uarch_index != kDefaultUArchIndex) {
+		EXPECT_LE(uarch_index, kMaxUArchIndex);
+	}
 }
 
-TEST(Parallelize3D, SingleThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolUArchInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckBounds3D,
+		CheckUArch2DTile1DWithUArchWithThread,
 		nullptr,
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-TEST(Parallelize3D, MultiThreadPoolAllItemsInBounds) {
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolUArchInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2382,36 +2585,2266 @@ TEST(Parallelize3D, MultiThreadPoolAllItemsInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckBounds3D,
+		CheckUArch2DTile1DWithUArchWithThread,
 		nullptr,
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
 		0 /* flags */);
 }
 
-static void SetTrue3D(std::atomic_bool* processed_indicators, size_t i, size_t j, size_t k) {
-	const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
-	processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+static void CheckBounds2DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	EXPECT_LT(i, kParallelize2DTile1DRangeI);
+	EXPECT_LT(start_j, kParallelize2DTile1DRangeJ);
+	EXPECT_LE(start_j + tile_j, kParallelize2DTile1DRangeJ);
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckBounds2DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckBounds2DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+}
+
+static void CheckTiling2DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	EXPECT_GT(tile_j, 0);
+	EXPECT_LE(tile_j, kParallelize2DTile1DTileJ);
+	EXPECT_EQ(start_j % kParallelize2DTile1DTileJ, 0);
+	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile1DTileJ, kParallelize2DTile1DRangeJ - start_j));
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckTiling2DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckTiling2DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+}
+
+static void SetTrue2DTile1DWithUArchWithThread(std::atomic_bool* processed_indicators, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(SetTrue2DTile1DWithUArchWithThread),
+		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(SetTrue2DTile1DWithUArchWithThread),
+		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+static void Increment2DTile1DWithUArchWithThread(std::atomic_int* processed_counters, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(Increment2DTile1DWithUArchWithThread),
+		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(Increment2DTile1DWithUArchWithThread),
+		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(Increment2DTile1DWithUArchWithThread),
+			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(Increment2DTile1DWithUArchWithThread),
+			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile1DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile1DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+static void IncrementSame2DTile1DWithUArchWithThread(std::atomic_int* num_processed_items, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	for (size_t j = start_j; j < start_j + tile_j; j++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(IncrementSame2DTile1DWithUArchWithThread),
+		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+}
+
+static void WorkImbalance2DTile1DWithUArchWithThread(std::atomic_int* num_processed_items, uint32_t, size_t, size_t i, size_t start_j, size_t tile_j) {
+	num_processed_items->fetch_add(tile_j, std::memory_order_relaxed);
+	if (i == 0 && start_j == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(WorkImbalance2DTile1DWithUArchWithThread),
+		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile1DRangeI * kParallelize2DTile1DRangeJ);
+}
+
+static void SetThreadTrue2DTile1DWithUArchWithThread(const size_t* num_threads, uint32_t, size_t thread_index, size_t i, size_t start_j, size_t tile_j) {
+	EXPECT_LE(thread_index, *num_threads);
+}
+
+TEST(Parallelize2DTile1DWithUArchWithThread, MultiThreadPoolThreadIndexValid) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	size_t num_threads = pthreadpool_get_threads_count(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_1d_with_id_with_thread_t>(SetThreadTrue2DTile1DWithUArchWithThread),
+		static_cast<void*>(&num_threads),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile1DRangeI, kParallelize2DTile1DRangeJ, kParallelize2DTile1DTileJ,
+		0 /* flags */);
+}
+
+static void ComputeNothing2DTile2D(void*, size_t, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(threadpool.get(),
+		ComputeNothing2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		ComputeNothing2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void CheckBounds2DTile2D(void*, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	EXPECT_LT(start_i, kParallelize2DTile2DRangeI);
+	EXPECT_LT(start_j, kParallelize2DTile2DRangeJ);
+	EXPECT_LE(start_i + tile_i, kParallelize2DTile2DRangeI);
+	EXPECT_LE(start_j + tile_j, kParallelize2DTile2DRangeJ);
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		CheckBounds2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		CheckBounds2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void CheckTiling2DTile2D(void*, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	EXPECT_GT(tile_i, 0);
+	EXPECT_LE(tile_i, kParallelize2DTile2DTileI);
+	EXPECT_EQ(start_i % kParallelize2DTile2DTileI, 0);
+	EXPECT_EQ(tile_i, std::min<size_t>(kParallelize2DTile2DTileI, kParallelize2DTile2DRangeI - start_i));
+
+	EXPECT_GT(tile_j, 0);
+	EXPECT_LE(tile_j, kParallelize2DTile2DTileJ);
+	EXPECT_EQ(start_j % kParallelize2DTile2DTileJ, 0);
+	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile2DTileJ, kParallelize2DTile2DRangeJ - start_j));
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		CheckTiling2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		CheckTiling2DTile2D,
+		nullptr,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void SetTrue2DTile2D(std::atomic_bool* processed_indicators, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(SetTrue2DTile2D),
+		static_cast<void*>(indicators.data()),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(SetTrue2DTile2D),
+		static_cast<void*>(indicators.data()),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+static void Increment2DTile2D(std::atomic_int* processed_counters, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+		static_cast<void*>(counters.data()),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+		static_cast<void*>(counters.data()),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_2d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+			static_cast<void*>(counters.data()),
+			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_2d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(Increment2DTile2D),
+			static_cast<void*>(counters.data()),
+			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+static void IncrementSame2DTile2D(std::atomic_int* num_processed_items, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			num_processed_items->fetch_add(1, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(IncrementSame2DTile2D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+}
+
+static void WorkImbalance2DTile2D(std::atomic_int* num_processed_items, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	num_processed_items->fetch_add(tile_i * tile_j, std::memory_order_relaxed);
+	if (start_i == 0 && start_j == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2D, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_t>(WorkImbalance2DTile2D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+}
+
+static void ComputeNothing2DTile2DWithUArch(void*, uint32_t, size_t, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(threadpool.get(),
+		ComputeNothing2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		ComputeNothing2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void CheckUArch2DTile2DWithUArch(void*, uint32_t uarch_index, size_t, size_t, size_t, size_t) {
+	if (uarch_index != kDefaultUArchIndex) {
+		EXPECT_LE(uarch_index, kMaxUArchIndex);
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckUArch2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckUArch2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void CheckBounds2DTile2DWithUArch(void*, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	EXPECT_LT(start_i, kParallelize2DTile2DRangeI);
+	EXPECT_LT(start_j, kParallelize2DTile2DRangeJ);
+	EXPECT_LE(start_i + tile_i, kParallelize2DTile2DRangeI);
+	EXPECT_LE(start_j + tile_j, kParallelize2DTile2DRangeJ);
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckBounds2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckBounds2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void CheckTiling2DTile2DWithUArch(void*, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	EXPECT_GT(tile_i, 0);
+	EXPECT_LE(tile_i, kParallelize2DTile2DTileI);
+	EXPECT_EQ(start_i % kParallelize2DTile2DTileI, 0);
+	EXPECT_EQ(tile_i, std::min<size_t>(kParallelize2DTile2DTileI, kParallelize2DTile2DRangeI - start_i));
+
+	EXPECT_GT(tile_j, 0);
+	EXPECT_LE(tile_j, kParallelize2DTile2DTileJ);
+	EXPECT_EQ(start_j % kParallelize2DTile2DTileJ, 0);
+	EXPECT_EQ(tile_j, std::min<size_t>(kParallelize2DTile2DTileJ, kParallelize2DTile2DRangeJ - start_j));
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckTiling2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		CheckTiling2DTile2DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+}
+
+static void SetTrue2DTile2DWithUArch(std::atomic_bool* processed_indicators, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(SetTrue2DTile2DWithUArch),
+		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(SetTrue2DTile2DWithUArch),
+		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+				<< "Element (" << i << ", " << j << ") not processed";
+		}
+	}
+}
+
+static void Increment2DTile2DWithUArch(std::atomic_int* processed_counters, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_2d_with_uarch(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_2d_tile_2d_with_uarch(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(Increment2DTile2DWithUArch),
+			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+			kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize2DTile2DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize2DTile2DRangeJ; j++) {
+			const size_t linear_idx = i * kParallelize2DTile2DRangeJ + j;
+			EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+				<< "Element (" << i << ", " << j << ") was processed "
+				<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+				<< "(expected: " << kIncrementIterations << ")";
+		}
+	}
+}
+
+static void IncrementSame2DTile2DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	for (size_t i = start_i; i < start_i + tile_i; i++) {
+		for (size_t j = start_j; j < start_j + tile_j; j++) {
+			num_processed_items->fetch_add(1, std::memory_order_relaxed);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(IncrementSame2DTile2DWithUArch),
+		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+}
+
+static void WorkImbalance2DTile2DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t start_i, size_t start_j, size_t tile_i, size_t tile_j) {
+	num_processed_items->fetch_add(tile_i * tile_j, std::memory_order_relaxed);
+	if (start_i == 0 && start_j == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize2DTile2DWithUArch, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_2d_tile_2d_with_uarch(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_2d_tile_2d_with_id_t>(WorkImbalance2DTile2DWithUArch),
+		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize2DTile2DRangeI, kParallelize2DTile2DRangeJ,
+		kParallelize2DTile2DTileI, kParallelize2DTile2DTileJ,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize2DTile2DRangeI * kParallelize2DTile2DRangeJ);
+}
+
+static void ComputeNothing3D(void*, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize3D, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(threadpool.get(),
+		ComputeNothing3D,
+		nullptr,
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3D, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		ComputeNothing3D,
+		nullptr,
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+}
+
+static void CheckBounds3D(void*, size_t i, size_t j, size_t k) {
+	EXPECT_LT(i, kParallelize3DRangeI);
+	EXPECT_LT(j, kParallelize3DRangeJ);
+	EXPECT_LT(k, kParallelize3DRangeK);
+}
+
+TEST(Parallelize3D, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		CheckBounds3D,
+		nullptr,
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3D, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		CheckBounds3D,
+		nullptr,
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+}
+
+static void SetTrue3D(std::atomic_bool* processed_indicators, size_t i, size_t j, size_t k) {
+	const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+}
+
+TEST(Parallelize3D, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(SetTrue3D),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3D, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(SetTrue3D),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+static void Increment3D(std::atomic_int* processed_counters, size_t i, size_t j, size_t k) {
+	const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+}
+
+TEST(Parallelize3D, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+		static_cast<void*>(counters.data()),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3D, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+		static_cast<void*>(counters.data()),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3D, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+			static_cast<void*>(counters.data()),
+			kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+				0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3D, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+			static_cast<void*>(counters.data()),
+			kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+				0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+static void IncrementSame3D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t k) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+}
+
+TEST(Parallelize3D, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(IncrementSame3D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+}
+
+static void WorkImbalance3D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t k) {
+	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	if (i == 0 && j == 0 && k == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize3D, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_t>(WorkImbalance3D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+}
+
+static void ComputeNothing3DTile1D(void*, size_t, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(threadpool.get(),
+		ComputeNothing3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		ComputeNothing3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckBounds3DTile1D(void*, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_LT(i, kParallelize3DTile1DRangeI);
+	EXPECT_LT(j, kParallelize3DTile1DRangeJ);
+	EXPECT_LT(start_k, kParallelize3DTile1DRangeK);
+	EXPECT_LE(start_k + tile_k, kParallelize3DTile1DRangeK);
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		CheckBounds3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		CheckBounds3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckTiling3DTile1D(void*, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_GT(tile_k, 0);
+	EXPECT_LE(tile_k, kParallelize3DTile1DTileK);
+	EXPECT_EQ(start_k % kParallelize3DTile1DTileK, 0);
+	EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile1DTileK, kParallelize3DTile1DRangeK - start_k));
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		CheckTiling3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		CheckTiling3DTile1D,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void SetTrue3DTile1D(std::atomic_bool* processed_indicators, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(SetTrue3DTile1D),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(SetTrue3DTile1D),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+static void Increment3DTile1D(std::atomic_int* processed_counters, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+		static_cast<void*>(counters.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+		static_cast<void*>(counters.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d_tile_1d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+			static_cast<void*>(counters.data()),
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d_tile_1d(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+			static_cast<void*>(counters.data()),
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+static void IncrementSame3DTile1D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(IncrementSame3DTile1D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+}
+
+static void WorkImbalance3DTile1D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	num_processed_items->fetch_add(tile_k, std::memory_order_relaxed);
+	if (i == 0 && j == 0 && start_k == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize3DTile1D, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(WorkImbalance3DTile1D),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+}
+
+static void ComputeNothing3DTile1DWithThread(void*, size_t, size_t, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(threadpool.get(),
+		ComputeNothing3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		ComputeNothing3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckBounds3DTile1DWithThread(void*, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_LT(i, kParallelize3DTile1DRangeI);
+	EXPECT_LT(j, kParallelize3DTile1DRangeJ);
+	EXPECT_LT(start_k, kParallelize3DTile1DRangeK);
+	EXPECT_LE(start_k + tile_k, kParallelize3DTile1DRangeK);
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		CheckBounds3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		CheckBounds3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckTiling3DTile1DWithThread(void*, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_GT(tile_k, 0);
+	EXPECT_LE(tile_k, kParallelize3DTile1DTileK);
+	EXPECT_EQ(start_k % kParallelize3DTile1DTileK, 0);
+	EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile1DTileK, kParallelize3DTile1DRangeK - start_k));
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		CheckTiling3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		CheckTiling3DTile1DWithThread,
+		nullptr,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void SetTrue3DTile1DWithThread(std::atomic_bool* processed_indicators, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(SetTrue3DTile1DWithThread),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(SetTrue3DTile1DWithThread),
+		static_cast<void*>(indicators.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
+					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
+			}
+		}
+	}
+}
+
+static void Increment3DTile1DWithThread(std::atomic_int* processed_counters, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(Increment3DTile1DWithThread),
+		static_cast<void*>(counters.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(Increment3DTile1DWithThread),
+		static_cast<void*>(counters.data()),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d_tile_1d_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(Increment3DTile1DWithThread),
+			static_cast<void*>(counters.data()),
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
+		pthreadpool_parallelize_3d_tile_1d_with_thread(
+			threadpool.get(),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(Increment3DTile1DWithThread),
+			static_cast<void*>(counters.data()),
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
+	}
+
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
+					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
+					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
+					<< "(expected: " << kIncrementIterations << ")";
+			}
+		}
+	}
+}
+
+static void IncrementSame3DTile1DWithThread(std::atomic_int* num_processed_items, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolHighContention) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(IncrementSame3DTile1DWithThread),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+}
+
+static void WorkImbalance3DTile1DWithThread(std::atomic_int* num_processed_items, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	num_processed_items->fetch_add(tile_k, std::memory_order_relaxed);
+	if (i == 0 && j == 0 && start_k == 0) {
+		/* Spin-wait until all items are computed */
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK) {
+			std::atomic_thread_fence(std::memory_order_acquire);
+		}
+	}
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolWorkStealing) {
+	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
+
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(WorkImbalance3DTile1DWithThread),
+		static_cast<void*>(&num_processed_items),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
+}
+
+static void CheckThreadIndexValid3DTile1DWithThread(const size_t* num_threads, size_t thread_index, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_LE(thread_index, *num_threads);
+}
+
+TEST(Parallelize3DTile1DWithThread, MultiThreadPoolThreadIndexValid) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	size_t num_threads = pthreadpool_get_threads_count(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_thread_t>(CheckThreadIndexValid3DTile1DWithThread),
+		static_cast<void*>(&num_threads),
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void ComputeNothing3DTile1DWithUArch(void*, uint32_t, size_t, size_t, size_t, size_t) {
+}
+
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(threadpool.get(),
+		ComputeNothing3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolCompletes) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		ComputeNothing3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckUArch3DTile1DWithUArch(void*, uint32_t uarch_index, size_t, size_t, size_t, size_t) {
+	if (uarch_index != kDefaultUArchIndex) {
+		EXPECT_LE(uarch_index, kMaxUArchIndex);
+	}
+}
+
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckUArch3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckUArch3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckBounds3DTile1DWithUArch(void*, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_LT(i, kParallelize3DTile1DRangeI);
+	EXPECT_LT(j, kParallelize3DTile1DRangeJ);
+	EXPECT_LT(start_k, kParallelize3DTile1DRangeK);
+	EXPECT_LE(start_k + tile_k, kParallelize3DTile1DRangeK);
+}
+
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckBounds3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolAllItemsInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckBounds3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckTiling3DTile1DWithUArch(void*, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_GT(tile_k, 0);
+	EXPECT_LE(tile_k, kParallelize3DTile1DTileK);
+	EXPECT_EQ(start_k % kParallelize3DTile1DTileK, 0);
+	EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile1DTileK, kParallelize3DTile1DRangeK - start_k));
+}
+
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckTiling3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolUniformTiling) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
+		threadpool.get(),
+		CheckTiling3DTile1DWithUArch,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
 }
 
-TEST(Parallelize3D, SingleThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+static void SetTrue3DTile1DWithUArch(std::atomic_bool* processed_indicators, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
+	}
+}
+
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(SetTrue3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(SetTrue3DTile1DWithUArch),
 		static_cast<void*>(indicators.data()),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
 			}
@@ -2419,8 +4852,8 @@ TEST(Parallelize3D, SingleThreadPoolAllItemsProcessed) {
 	}
 }
 
-TEST(Parallelize3D, MultiThreadPoolAllItemsProcessed) {
-	std::vector<std::atomic_bool> indicators(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolAllItemsProcessed) {
+	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2429,17 +4862,19 @@ TEST(Parallelize3D, MultiThreadPoolAllItemsProcessed) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(SetTrue3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(SetTrue3DTile1DWithUArch),
 		static_cast<void*>(indicators.data()),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_TRUE(indicators[linear_idx].load(std::memory_order_relaxed))
 					<< "Element (" << i << ", " << j << ", " << k << ") not processed";
 			}
@@ -2447,28 +4882,32 @@ TEST(Parallelize3D, MultiThreadPoolAllItemsProcessed) {
 	}
 }
 
-static void Increment3D(std::atomic_int* processed_counters, size_t i, size_t j, size_t k) {
-	const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
-	processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+static void Increment3DTile1DWithUArch(std::atomic_int* processed_counters, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
+		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
+	}
 }
 
-TEST(Parallelize3D, SingleThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(Increment3DTile1DWithUArch),
 		static_cast<void*>(counters.data()),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
 					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -2477,8 +4916,8 @@ TEST(Parallelize3D, SingleThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize3D, MultiThreadPoolEachItemProcessedOnce) {
-	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolEachItemProcessedOnce) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2487,17 +4926,19 @@ TEST(Parallelize3D, MultiThreadPoolEachItemProcessedOnce) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(Increment3DTile1DWithUArch),
 		static_cast<void*>(counters.data()),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), 1)
 					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
 					<< counters[linear_idx].load(std::memory_order_relaxed) << " times (expected: 1)";
@@ -2506,25 +4947,27 @@ TEST(Parallelize3D, MultiThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize3D, SingleThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+TEST(Parallelize3DTile1DWithUArch, SingleThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_3d(
+		pthreadpool_parallelize_3d_tile_1d_with_uarch(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(Increment3DTile1DWithUArch),
 			static_cast<void*>(counters.data()),
-			kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
-				0 /* flags */);
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
 					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -2534,8 +4977,8 @@ TEST(Parallelize3D, SingleThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-TEST(Parallelize3D, MultiThreadPoolEachItemProcessedMultipleTimes) {
-	std::vector<std::atomic_int> counters(kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolEachItemProcessedMultipleTimes) {
+	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
@@ -2545,18 +4988,20 @@ TEST(Parallelize3D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_3d(
+		pthreadpool_parallelize_3d_tile_1d_with_uarch(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_3d_t>(Increment3D),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(Increment3DTile1DWithUArch),
 			static_cast<void*>(counters.data()),
-			kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
-				0 /* flags */);
+			kDefaultUArchIndex, kMaxUArchIndex,
+			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+			kParallelize3DTile1DTileK,
+			0 /* flags */);
 	}
 
-	for (size_t i = 0; i < kParallelize3DRangeI; i++) {
-		for (size_t j = 0; j < kParallelize3DRangeJ; j++) {
-			for (size_t k = 0; k < kParallelize3DRangeK; k++) {
-				const size_t linear_idx = (i * kParallelize3DRangeJ + j) * kParallelize3DRangeK + k;
+	for (size_t i = 0; i < kParallelize3DTile1DRangeI; i++) {
+		for (size_t j = 0; j < kParallelize3DTile1DRangeJ; j++) {
+			for (size_t k = 0; k < kParallelize3DTile1DRangeK; k++) {
+				const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 				EXPECT_EQ(counters[linear_idx].load(std::memory_order_relaxed), kIncrementIterations)
 					<< "Element (" << i << ", " << j << ", " << k << ") was processed "
 					<< counters[linear_idx].load(std::memory_order_relaxed) << " times "
@@ -2566,11 +5011,13 @@ TEST(Parallelize3D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-static void IncrementSame3D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t k) {
-	num_processed_items->fetch_add(1, std::memory_order_relaxed);
+static void IncrementSame3DTile1DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	for (size_t k = start_k; k < start_k + tile_k; k++) {
+		num_processed_items->fetch_add(1, std::memory_order_relaxed);
+	}
 }
 
-TEST(Parallelize3D, MultiThreadPoolHighContention) {
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolHighContention) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2580,26 +5027,28 @@ TEST(Parallelize3D, MultiThreadPoolHighContention) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(IncrementSame3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(IncrementSame3DTile1DWithUArch),
 		static_cast<void*>(&num_processed_items),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 }
 
-static void WorkImbalance3D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t k) {
-	num_processed_items->fetch_add(1, std::memory_order_relaxed);
-	if (i == 0 && j == 0 && k == 0) {
+static void WorkImbalance3DTile1DWithUArch(std::atomic_int* num_processed_items, uint32_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	num_processed_items->fetch_add(tile_k, std::memory_order_relaxed);
+	if (i == 0 && j == 0 && start_k == 0) {
 		/* Spin-wait until all items are computed */
-		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK) {
+		while (num_processed_items->load(std::memory_order_relaxed) != kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK) {
 			std::atomic_thread_fence(std::memory_order_acquire);
 		}
 	}
 }
 
-TEST(Parallelize3D, MultiThreadPoolWorkStealing) {
+TEST(Parallelize3DTile1DWithUArch, MultiThreadPoolWorkStealing) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2609,31 +5058,34 @@ TEST(Parallelize3D, MultiThreadPoolWorkStealing) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_t>(WorkImbalance3D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_t>(WorkImbalance3DTile1DWithUArch),
 		static_cast<void*>(&num_processed_items),
-		kParallelize3DRangeI, kParallelize3DRangeJ, kParallelize3DRangeK,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
 		0 /* flags */);
-	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DRangeI * kParallelize3DRangeJ * kParallelize3DRangeK);
+	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 }
 
-static void ComputeNothing3DTile1D(void*, size_t, size_t, size_t, size_t) {
+static void ComputeNothing3DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t, size_t, size_t, size_t) {
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolCompletes) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d_tile_1d(threadpool.get(),
-		ComputeNothing3DTile1D,
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(threadpool.get(),
+		ComputeNothing3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolCompletes) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolCompletes) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2641,36 +5093,76 @@ TEST(Parallelize3DTile1D, MultiThreadPoolCompletes) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		ComputeNothing3DTile1D,
+		ComputeNothing3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-static void CheckBounds3DTile1D(void*, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void CheckUArch3DTile1DWithUArchWithThread(void*, uint32_t uarch_index, size_t, size_t, size_t, size_t, size_t) {
+	if (uarch_index != kDefaultUArchIndex) {
+		EXPECT_LE(uarch_index, kMaxUArchIndex);
+	}
+}
+
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckUArch3DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolUArchInBounds) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	if (pthreadpool_get_threads_count(threadpool.get()) <= 1) {
+		GTEST_SKIP();
+	}
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		CheckUArch3DTile1DWithUArchWithThread,
+		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
+static void CheckBounds3DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	EXPECT_LT(i, kParallelize3DTile1DRangeI);
 	EXPECT_LT(j, kParallelize3DTile1DRangeJ);
 	EXPECT_LT(start_k, kParallelize3DTile1DRangeK);
 	EXPECT_LE(start_k + tile_k, kParallelize3DTile1DRangeK);
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolAllItemsInBounds) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckBounds3DTile1D,
+		CheckBounds3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsInBounds) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolAllItemsInBounds) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2678,36 +5170,38 @@ TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsInBounds) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckBounds3DTile1D,
+		CheckBounds3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-static void CheckTiling3DTile1D(void*, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void CheckTiling3DTile1DWithUArchWithThread(void*, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	EXPECT_GT(tile_k, 0);
 	EXPECT_LE(tile_k, kParallelize3DTile1DTileK);
 	EXPECT_EQ(start_k % kParallelize3DTile1DTileK, 0);
 	EXPECT_EQ(tile_k, std::min<size_t>(kParallelize3DTile1DTileK, kParallelize3DTile1DRangeK - start_k));
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolUniformTiling) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckTiling3DTile1D,
+		CheckTiling3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolUniformTiling) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolUniformTiling) {
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
@@ -2715,32 +5209,34 @@ TEST(Parallelize3DTile1D, MultiThreadPoolUniformTiling) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		CheckTiling3DTile1D,
+		CheckTiling3DTile1DWithUArchWithThread,
 		nullptr,
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 }
 
-static void SetTrue3DTile1D(std::atomic_bool* processed_indicators, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void SetTrue3DTile1DWithUArchWithThread(std::atomic_bool* processed_indicators, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	for (size_t k = start_k; k < start_k + tile_k; k++) {
 		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 		processed_indicators[linear_idx].store(true, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolAllItemsProcessed) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolAllItemsProcessed) {
 	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(SetTrue3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(SetTrue3DTile1DWithUArchWithThread),
 		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
@@ -2756,7 +5252,7 @@ TEST(Parallelize3DTile1D, SingleThreadPoolAllItemsProcessed) {
 	}
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsProcessed) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolAllItemsProcessed) {
 	std::vector<std::atomic_bool> indicators(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2766,10 +5262,11 @@ TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsProcessed) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(SetTrue3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(SetTrue3DTile1DWithUArchWithThread),
 		static_cast<void*>(indicators.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
@@ -2785,23 +5282,24 @@ TEST(Parallelize3DTile1D, MultiThreadPoolAllItemsProcessed) {
 	}
 }
 
-static void Increment3DTile1D(std::atomic_int* processed_counters, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void Increment3DTile1DWithUArchWithThread(std::atomic_int* processed_counters, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	for (size_t k = start_k; k < start_k + tile_k; k++) {
 		const size_t linear_idx = (i * kParallelize3DTile1DRangeJ + j) * kParallelize3DTile1DRangeK + k;
 		processed_counters[linear_idx].fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedOnce) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolEachItemProcessedOnce) {
 	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(Increment3DTile1DWithUArchWithThread),
 		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
@@ -2818,7 +5316,7 @@ TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedOnce) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolEachItemProcessedOnce) {
 	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2828,10 +5326,11 @@ TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedOnce) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(Increment3DTile1DWithUArchWithThread),
 		static_cast<void*>(counters.data()),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
@@ -2848,17 +5347,18 @@ TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedOnce) {
 	}
 }
 
-TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
+TEST(Parallelize3DTile1DWithUArchWithThread, SingleThreadPoolEachItemProcessedMultipleTimes) {
 	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(1), pthreadpool_destroy);
 	ASSERT_TRUE(threadpool.get());
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_3d_tile_1d(
+		pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(Increment3DTile1DWithUArchWithThread),
 			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
 			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 			kParallelize3DTile1DTileK,
 			0 /* flags */);
@@ -2877,7 +5377,7 @@ TEST(Parallelize3DTile1D, SingleThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	std::vector<std::atomic_int> counters(kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2888,10 +5388,11 @@ TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 
 	for (size_t iteration = 0; iteration < kIncrementIterations; iteration++) {
-		pthreadpool_parallelize_3d_tile_1d(
+		pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 			threadpool.get(),
-			reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(Increment3DTile1D),
+			reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(Increment3DTile1DWithUArchWithThread),
 			static_cast<void*>(counters.data()),
+			kDefaultUArchIndex, kMaxUArchIndex,
 			kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 			kParallelize3DTile1DTileK,
 			0 /* flags */);
@@ -2910,13 +5411,13 @@ TEST(Parallelize3DTile1D, MultiThreadPoolEachItemProcessedMultipleTimes) {
 	}
 }
 
-static void IncrementSame3DTile1D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void IncrementSame3DTile1DWithUArchWithThread(std::atomic_int* num_processed_items, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	for (size_t k = start_k; k < start_k + tile_k; k++) {
 		num_processed_items->fetch_add(1, std::memory_order_relaxed);
 	}
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolHighContention) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolHighContention) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2926,17 +5427,18 @@ TEST(Parallelize3DTile1D, MultiThreadPoolHighContention) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(IncrementSame3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(IncrementSame3DTile1DWithUArchWithThread),
 		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 }
 
-static void WorkImbalance3DTile1D(std::atomic_int* num_processed_items, size_t i, size_t j, size_t start_k, size_t tile_k) {
+static void WorkImbalance3DTile1DWithUArchWithThread(std::atomic_int* num_processed_items, uint32_t, size_t, size_t i, size_t j, size_t start_k, size_t tile_k) {
 	num_processed_items->fetch_add(tile_k, std::memory_order_relaxed);
 	if (i == 0 && j == 0 && start_k == 0) {
 		/* Spin-wait until all items are computed */
@@ -2946,7 +5448,7 @@ static void WorkImbalance3DTile1D(std::atomic_int* num_processed_items, size_t i
 	}
 }
 
-TEST(Parallelize3DTile1D, MultiThreadPoolWorkStealing) {
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolWorkStealing) {
 	std::atomic_int num_processed_items = ATOMIC_VAR_INIT(0);
 
 	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
@@ -2956,16 +5458,37 @@ TEST(Parallelize3DTile1D, MultiThreadPoolWorkStealing) {
 		GTEST_SKIP();
 	}
 
-	pthreadpool_parallelize_3d_tile_1d(
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
 		threadpool.get(),
-		reinterpret_cast<pthreadpool_task_3d_tile_1d_t>(WorkImbalance3DTile1D),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(WorkImbalance3DTile1DWithUArchWithThread),
 		static_cast<void*>(&num_processed_items),
+		kDefaultUArchIndex, kMaxUArchIndex,
 		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
 		kParallelize3DTile1DTileK,
 		0 /* flags */);
 	EXPECT_EQ(num_processed_items.load(std::memory_order_relaxed), kParallelize3DTile1DRangeI * kParallelize3DTile1DRangeJ * kParallelize3DTile1DRangeK);
 }
 
+static void SetThreadTrue3DTile1DWithUArchWithThread(const size_t* num_threads, uint32_t, size_t thread_index, size_t i, size_t j, size_t start_k, size_t tile_k) {
+	EXPECT_LE(thread_index, *num_threads);
+}
+
+TEST(Parallelize3DTile1DWithUArchWithThread, MultiThreadPoolThreadIndexValid) {
+	auto_pthreadpool_t threadpool(pthreadpool_create(0), pthreadpool_destroy);
+	ASSERT_TRUE(threadpool.get());
+
+	size_t num_threads = pthreadpool_get_threads_count(threadpool.get());
+
+	pthreadpool_parallelize_3d_tile_1d_with_uarch_with_thread(
+		threadpool.get(),
+		reinterpret_cast<pthreadpool_task_3d_tile_1d_with_id_with_thread_t>(SetThreadTrue3DTile1DWithUArchWithThread),
+		static_cast<void*>(&num_threads),
+		kDefaultUArchIndex, kMaxUArchIndex,
+		kParallelize3DTile1DRangeI, kParallelize3DTile1DRangeJ, kParallelize3DTile1DRangeK,
+		kParallelize3DTile1DTileK,
+		0 /* flags */);
+}
+
 static void ComputeNothing3DTile2D(void*, size_t, size_t, size_t, size_t, size_t) {
 }
 
```

