```diff
diff --git a/BUILD.bazel b/BUILD.bazel
index a29d395..f202a00 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -1,5 +1,4 @@
 load("@rules_license//rules:license.bzl", "license")
-load("@rules_license//rules:license_kind.bzl", "license_kind")
 
 package(
     default_applicable_licenses = [":license"],
@@ -9,25 +8,12 @@ package(
 license(
     name = "license",
     license_kinds = [
-        ":SPDX-license-identifier-Apache-2.0",
+        "@rules_license//licenses/spdx:Apache-2.0",
     ],
-    license_text = "LICENSE-APACHE",
     visibility = [":__subpackages__"],
 )
 
-license_kind(
-    name = "SPDX-license-identifier-Apache-2.0",
-    conditions = ["notice"],
-    url = "https://spdx.org/licenses/Apache-2.0.html",
-)
-
-cc_library(
+alias(
     name = "aemu-host-common-test-headers",
-    hdrs = glob([
-        "host-common/testing/**/*.h",
-        "host-common/testing/**/*.hpp",
-    ]),
-    includes = ["include"],
-    visibility = ["//visibility:public"],
-    deps = ["//hardware/google/aemu/base:test-io"],
+    actual = "//host-common:test-headers",
 )
diff --git a/MODULE.bazel b/MODULE.bazel
new file mode 100644
index 0000000..139a1a5
--- /dev/null
+++ b/MODULE.bazel
@@ -0,0 +1,12 @@
+module(
+    name = "aemu",
+    version = "0.0.1",
+)
+
+bazel_dep(name = "abseil-cpp", version = "20250127.0", repo_name = "com_google_absl")
+bazel_dep(name = "gfxstream", version = "0.0.1")
+bazel_dep(name = "googletest", version = "1.15.2", repo_name = "com_google_googletest")
+bazel_dep(name = "lz4", version = "0.0.1")
+bazel_dep(name = "platforms", version = "0.0.11")
+bazel_dep(name = "rules_cc", version = "0.0.14")
+bazel_dep(name = "rules_license", version = "1.0.0")
diff --git a/base/BUILD.bazel b/base/BUILD.bazel
index 73044b9..8c8ef4e 100644
--- a/base/BUILD.bazel
+++ b/base/BUILD.bazel
@@ -1,10 +1,168 @@
+load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test", "objc_library")
 # Interface library
+
 cc_library(
     name = "aemu-base-headers",
-    hdrs = glob([
-        "include/**/*.h",
-        "include/**/*.hpp",
-    ]),
+    hdrs = [
+        "include/aemu/base/AlignedBuf.h",
+        "include/aemu/base/Allocator.h",
+        "include/aemu/base/ArraySize.h",
+        "include/aemu/base/AsyncResult.h",
+        "include/aemu/base/Backtrace.h",
+        "include/aemu/base/BumpPool.h",
+        "include/aemu/base/Compiler.h",
+        "include/aemu/base/CppMacros.h",
+        "include/aemu/base/CpuTime.h",
+        "include/aemu/base/CpuUsage.h",
+        "include/aemu/base/Debug.h",
+        "include/aemu/base/EintrWrapper.h",
+        "include/aemu/base/EnumFlags.h",
+        "include/aemu/base/EventNotificationSupport.h",
+        "include/aemu/base/FunctionView.h",
+        "include/aemu/base/GLObjectCounter.h",
+        "include/aemu/base/GraphicsObjectCounter.h",
+        "include/aemu/base/HealthMonitor.h",
+        "include/aemu/base/IOVector.h",
+        "include/aemu/base/JsonWriter.h",
+        "include/aemu/base/LayoutResolver.h",
+        "include/aemu/base/Log.h",
+        "include/aemu/base/LruCache.h",
+        "include/aemu/base/ManagedDescriptor.h",
+        "include/aemu/base/ManagedDescriptor.hpp",
+        "include/aemu/base/Metrics.h",
+        "include/aemu/base/MruCache.h",
+        "include/aemu/base/Optional.h",
+        "include/aemu/base/Pool.h",
+        "include/aemu/base/ProcessControl.h",
+        "include/aemu/base/Profiler.h",
+        "include/aemu/base/Result.h",
+        "include/aemu/base/SharedLibrary.h",
+        "include/aemu/base/Stopwatch.h",
+        "include/aemu/base/StringFormat.h",
+        "include/aemu/base/StringParse.h",
+        "include/aemu/base/SubAllocator.h",
+        "include/aemu/base/ThreadAnnotations.h",
+        "include/aemu/base/Tracing.h",
+        "include/aemu/base/TypeTraits.h",
+        "include/aemu/base/Uri.h",
+        "include/aemu/base/Uuid.h",
+        "include/aemu/base/Version.h",
+        "include/aemu/base/address_space.h",
+        "include/aemu/base/async/AsyncReader.h",
+        "include/aemu/base/async/AsyncSocket.h",
+        "include/aemu/base/async/AsyncSocketAdapter.h",
+        "include/aemu/base/async/AsyncSocketServer.h",
+        "include/aemu/base/async/AsyncStatus.h",
+        "include/aemu/base/async/AsyncWriter.h",
+        "include/aemu/base/async/CallbackRegistry.h",
+        "include/aemu/base/async/DefaultLooper.h",
+        "include/aemu/base/async/Looper.h",
+        "include/aemu/base/async/RecurrentTask.h",
+        "include/aemu/base/async/ScopedSocketWatch.h",
+        "include/aemu/base/async/SubscriberList.h",
+        "include/aemu/base/async/ThreadLooper.h",
+        "include/aemu/base/c_header.h",
+        "include/aemu/base/containers/BufferQueue.h",
+        "include/aemu/base/containers/CircularBuffer.h",
+        "include/aemu/base/containers/EntityManager.h",
+        "include/aemu/base/containers/HybridComponentManager.h",
+        "include/aemu/base/containers/HybridEntityManager.h",
+        "include/aemu/base/containers/Lookup.h",
+        "include/aemu/base/containers/SmallVector.h",
+        "include/aemu/base/containers/StaticMap.h",
+        "include/aemu/base/export.h",
+        "include/aemu/base/files/CompressingStream.h",
+        "include/aemu/base/files/DecompressingStream.h",
+        "include/aemu/base/files/Fd.h",
+        "include/aemu/base/files/FileShareOpen.h",
+        "include/aemu/base/files/FileShareOpenImpl.h",
+        "include/aemu/base/files/FileSystemWatcher.h",
+        "include/aemu/base/files/GzipStreambuf.h",
+        "include/aemu/base/files/InplaceStream.h",
+        "include/aemu/base/files/MemStream.h",
+        "include/aemu/base/files/PathUtils.h",
+        "include/aemu/base/files/QueueStreambuf.h",
+        "include/aemu/base/files/ScopedFd.h",
+        "include/aemu/base/files/ScopedFileHandle.h",
+        "include/aemu/base/files/ScopedRegKey.h",
+        "include/aemu/base/files/ScopedStdioFile.h",
+        "include/aemu/base/files/StdioStream.h",
+        "include/aemu/base/files/Stream.h",
+        "include/aemu/base/files/StreamSerializing.h",
+        "include/aemu/base/files/TarStream.h",
+        "include/aemu/base/files/preadwrite.h",
+        "include/aemu/base/gl_object_counter.h",
+        "include/aemu/base/memory/ContiguousRangeMapper.h",
+        "include/aemu/base/memory/MallocUsableSize.h",
+        "include/aemu/base/memory/MemoryHints.h",
+        "include/aemu/base/memory/MemoryTracker.h",
+        "include/aemu/base/memory/NoDestructor.h",
+        "include/aemu/base/memory/ScopedPtr.h",
+        "include/aemu/base/memory/SharedMemory.h",
+        "include/aemu/base/misc/FileUtils.h",
+        "include/aemu/base/misc/HttpUtils.h",
+        "include/aemu/base/misc/IpcPipe.h",
+        "include/aemu/base/misc/StringUtils.h",
+        "include/aemu/base/misc/Utf8Utils.h",
+        "include/aemu/base/msvc.h",
+        "include/aemu/base/network/Dns.h",
+        "include/aemu/base/network/IpAddress.h",
+        "include/aemu/base/network/NetworkUtils.h",
+        "include/aemu/base/perflogger/Analyzer.h",
+        "include/aemu/base/perflogger/Benchmark.h",
+        "include/aemu/base/perflogger/BenchmarkLibrary.h",
+        "include/aemu/base/perflogger/Metric.h",
+        "include/aemu/base/perflogger/WindowDeviationAnalyzer.h",
+        "include/aemu/base/process-control.h",
+        "include/aemu/base/process/Command.h",
+        "include/aemu/base/process/Process.h",
+        "include/aemu/base/ring_buffer.h",
+        "include/aemu/base/sockets/ScopedSocket.h",
+        "include/aemu/base/sockets/SocketDrainer.h",
+        "include/aemu/base/sockets/SocketErrors.h",
+        "include/aemu/base/sockets/SocketUtils.h",
+        "include/aemu/base/sockets/SocketWaiter.h",
+        "include/aemu/base/sockets/Winsock.h",
+        "include/aemu/base/streams/RingStreambuf.h",
+        "include/aemu/base/synchronization/ConditionVariable.h",
+        "include/aemu/base/synchronization/Event.h",
+        "include/aemu/base/synchronization/Lock.h",
+        "include/aemu/base/synchronization/MessageChannel.h",
+        "include/aemu/base/system/Memory.h",
+        "include/aemu/base/system/System.h",
+        "include/aemu/base/system/Win32UnicodeString.h",
+        "include/aemu/base/system/Win32Utils.h",
+        "include/aemu/base/testing/GTestUtils.h",
+        "include/aemu/base/testing/GlmTestHelpers.h",
+        "include/aemu/base/testing/MockUtils.h",
+        "include/aemu/base/testing/ProtobufMatchers.h",
+        "include/aemu/base/testing/ResultMatchers.h",
+        "include/aemu/base/testing/TestClock.h",
+        "include/aemu/base/testing/TestDnsResolver.h",
+        "include/aemu/base/testing/TestEvent.h",
+        "include/aemu/base/testing/TestInputBufferSocketServerThread.h",
+        "include/aemu/base/testing/TestLooper.h",
+        "include/aemu/base/testing/TestMemoryOutputStream.h",
+        "include/aemu/base/testing/TestNetworkInterfaceNameResolver.h",
+        "include/aemu/base/testing/TestSystem.h",
+        "include/aemu/base/testing/TestTempDir.h",
+        "include/aemu/base/testing/TestThread.h",
+        "include/aemu/base/testing/TestUtils.h",
+        "include/aemu/base/testing/Utils.h",
+        "include/aemu/base/testing/file_io.h",
+        "include/aemu/base/threads/Async.h",
+        "include/aemu/base/threads/FunctorThread.h",
+        "include/aemu/base/threads/ParallelTask.h",
+        "include/aemu/base/threads/Thread.h",
+        "include/aemu/base/threads/ThreadPool.h",
+        "include/aemu/base/threads/ThreadStore.h",
+        "include/aemu/base/threads/Types.h",
+        "include/aemu/base/threads/WorkerThread.h",
+        "include/aemu/base/threads/internal/ParallelTaskBase.h",
+        "include/aemu/base/utils/status_macros.h",
+        "include/aemu/base/utils/status_matcher_macros.h",
+        "include/aemu/base/utils/stream.h",
+    ],
     defines = select({
         "@platforms//os:windows": [
             "WIN32_LEAN_AND_MEAN",
@@ -14,11 +172,11 @@ cc_library(
     includes = ["include"],
     visibility = ["//visibility:public"],
     deps = [
-        "//hardware/google/aemu/host-common:aemu-host-common-headers",
+        "//host-common:aemu-host-common-headers",
         "@com_google_absl//absl/strings:str_format",
     ] + select({
         "@platforms//os:windows": [
-            "//hardware/google/aemu/windows:compat-hdrs",
+            "//windows:compat-hdrs",
         ],
         "//conditions:default": [],
     }),
@@ -47,17 +205,45 @@ objc_library(
         "IOkit",
         "AppKit",
     ],
+    target_compatible_with = [
+        "@platforms//os:macos",
+    ],
     deps = [":aemu-base-headers"],
     alwayslink = True,
 )
 
+cc_library(
+    name = "aemu-base-logging",
+    srcs = [
+        "CLog.cpp",
+    ],
+    hdrs = [
+        "include/aemu/base/logging/CLog.h",
+        "include/aemu/base/logging/Log.h",
+        "include/aemu/base/logging/LogFormatter.h",
+        "include/aemu/base/logging/LogSeverity.h",
+        "include/aemu/base/logging/LogTags.h",
+    ],
+    defines = [
+        "BUILDING_EMUGL_COMMON_SHARED",
+        "LOGGING_API_SHARED",
+    ] + select({
+        "@platforms//os:windows": [
+            "WIN32_LEAN_AND_MEAN",
+        ],
+        "//conditions:default": [],
+    }),
+    includes = ["include"],
+    visibility = ["//visibility:public"],
+)
+
 cc_library(
     name = "aemu-base",
     srcs = [
         "AlignedBuf.cpp",
-        "CLog.cpp",
         "CompressingStream.cpp",
         "CpuTime.cpp",
+        "Debug.cpp",
         "DecompressingStream.cpp",
         "FileUtils.cpp",
         "FunctorThread.cpp",
@@ -96,6 +282,7 @@ cc_library(
     defines = [
         "BUILDING_EMUGL_COMMON_SHARED",
         "LOGGING_API_SHARED",
+        "dfatal=\"(void*)\"",
     ] + select({
         "@platforms//os:windows": [
             "WIN32_LEAN_AND_MEAN",
@@ -121,14 +308,14 @@ cc_library(
     deps = [
         ":aemu-base-headers",
         ":aemu-base-metrics",
-        "//external/lz4",
-        "//hardware/google/aemu/host-common:logging",
+        "//host-common:logging",
+        "@lz4",
     ] + select({
         "@platforms//os:macos": [
             ":aemu-base-darwin",
         ],
         "@platforms//os:windows": [
-            "//external/qemu/google/compat/windows:compat",
+            "@aemu//windows:compat",
         ],
         "//conditions:default": [],
     }),
@@ -149,25 +336,6 @@ cc_library(
     alwayslink = True,
 )
 
-cc_library(
-    name = "test-matchers",
-    srcs = [
-        "testing/ProtobufMatchers.cpp",
-    ],
-    visibility = [
-        "//visibility:public",
-    ],
-    deps = [
-        ":aemu-base",
-        ":aemu-base-headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_googletest//:gtest",
-        "@com_google_protobuf//:protobuf",
-    ],
-    alwayslink = True,
-)
-
 cc_test(
     name = "aemu-base_unittests",
     srcs = [
@@ -180,7 +348,6 @@ cc_test(
         "ManagedDescriptor_unittest.cpp",
         "NoDestructor_unittest.cpp",
         "Optional_unittest.cpp",
-        "RecurrentTask_unittest.cpp",
         "StringFormat_unittest.cpp",
         "SubAllocator_unittest.cpp",
         "TypeTraits_unittest.cpp",
@@ -198,11 +365,9 @@ cc_test(
     deps = [
         ":aemu-base",
         ":aemu-base-headers",
-        "//hardware/generic/goldfish/android/logging:backend",
-        "//hardware/generic/goldfish/android/looper",
-        "//hardware/generic/goldfish/android/sockets",
-        "//hardware/google/aemu/base:aemu-base-metrics",
-        "//hardware/google/aemu/host-common:logging",
+        ":aemu-base-logging",
+        "//base:aemu-base-metrics",
+        "//host-common:logging",
         "@com_google_absl//absl/log",
         "@com_google_absl//absl/strings",
         "@com_google_absl//absl/strings:str_format",
diff --git a/base/Debug.cpp b/base/Debug.cpp
new file mode 100644
index 0000000..203fb70
--- /dev/null
+++ b/base/Debug.cpp
@@ -0,0 +1,105 @@
+// Copyright 2016 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+
+#include "aemu/base/Debug.h"
+
+#include <chrono>
+#include <thread>
+
+#include "aemu/base/ArraySize.h"
+#include "aemu/base/files/PathUtils.h"
+#ifdef _WIN32
+#include <windows.h>
+#elif defined(__linux__)
+#include <fstream>
+#include <sstream>
+#include <string>
+#include <string_view>
+#elif defined(__APPLE__)
+#include <sys/sysctl.h>
+#include <sys/types.h>
+#ifndef _MSC_VER
+#include <unistd.h>
+#endif
+#endif
+
+namespace android {
+namespace base {
+
+#ifdef __linux__
+static std::string readFile(std::string_view path) {
+    std::ifstream is(c_str(path));
+
+    if (!is) {
+        return {};
+    }
+
+    std::ostringstream ss;
+    ss << is.rdbuf();
+    return ss.str();
+}
+#endif
+
+bool IsDebuggerAttached() {
+#ifdef _WIN32
+    return ::IsDebuggerPresent() != 0;
+#elif defined(__linux__)
+    std::string procStatus = readFile("/proc/self/status");
+
+    static constexpr std::string_view kTracerPidPrefix = "TracerPid:";
+    const auto tracerPid = procStatus.find(kTracerPidPrefix.data());
+    if (tracerPid == std::string::npos) {
+        return false;
+    }
+
+    // If the tracer PID is parseable and not 0, there's a debugger attached.
+    const bool debuggerAttached =
+        atoi(procStatus.c_str() + tracerPid + kTracerPidPrefix.size()) != 0;
+    return debuggerAttached;
+#elif defined(__APPLE__)
+    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
+    struct kinfo_proc procInfo = {};
+    size_t infoSize = sizeof(procInfo);
+    const int res = sysctl(mib, arraySize(mib), &procInfo, &infoSize, nullptr, 0);
+    if (res) {
+        return false;
+    }
+    return (procInfo.kp_proc.p_flag & P_TRACED) != 0;
+#else
+#error Unsupported platform
+#endif
+}
+
+bool WaitForDebugger(int64_t timeoutMs) {
+    static const int64_t sleepTimeoutMs = 500;
+
+    int64_t sleptForMs = 0;
+    while (!IsDebuggerAttached() && (timeoutMs == -1 || sleptForMs < timeoutMs)) {
+        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeoutMs));
+        sleptForMs += sleepTimeoutMs;
+    }
+    return IsDebuggerAttached();
+}
+
+void DebugBreak() {
+#ifdef _WIN32
+    ::DebugBreak();
+#else
+#ifdef __x86_64__
+    asm("int $3");
+#elif defined(__aarch64)
+    asm("bkpt");
+#endif
+#endif
+}
+
+}  // namespace base
+}  // namespace android
\ No newline at end of file
diff --git a/base/System.cpp b/base/System.cpp
index d85fbc1..bfd4292 100644
--- a/base/System.cpp
+++ b/base/System.cpp
@@ -397,6 +397,10 @@ std::string getProgramDirectory() {
 }
 
 std::string getLauncherDirectory() {
+    std::string launcherDirEnv = getEnvironmentVariable("ANDROID_EMULATOR_LAUNCHER_DIR");
+    if (!launcherDirEnv.empty()) {
+        return launcherDirEnv;
+    }
     return getProgramDirectory();
 }
 
diff --git a/base/include/aemu/base/MruCache.h b/base/include/aemu/base/MruCache.h
index 2492f42..0cb407d 100644
--- a/base/include/aemu/base/MruCache.h
+++ b/base/include/aemu/base/MruCache.h
@@ -58,7 +58,7 @@ class MruCache {
     };
 
     MruCache(size_t maxEntries, CacheFlattener* cacheFlattener)
-        : mMaxEntries(maxEntries), mCacheFlattener(cacheFlattener) {}
+        : mCacheFlattener(cacheFlattener), mMaxEntries(maxEntries) {}
 
     bool put(const K& key, size_t keySize, V&& value, size_t valueSize) {
         evictIfNecessary();
diff --git a/base/include/aemu/base/Result.h b/base/include/aemu/base/Result.h
index c5d1d5e..97f85fd 100644
--- a/base/include/aemu/base/Result.h
+++ b/base/include/aemu/base/Result.h
@@ -15,7 +15,12 @@
 #pragma once
 
 #include "aemu/base/Optional.h"
+
+#ifdef ABSL_LOG_CHECK_H_
+#define CHECK DCHECK
+#else
 #include "aemu/base/logging/Log.h"
+#endif
 
 // Result<T, E> - a template class to store either a result or error, inspired
 //                by Rust.
diff --git a/base/include/aemu/base/address_space.h b/base/include/aemu/base/address_space.h
index 18faaeb..8d700ab 100644
--- a/base/include/aemu/base/address_space.h
+++ b/base/include/aemu/base/address_space.h
@@ -45,6 +45,7 @@ struct address_block {
             uint64_t available : 1;
         };
     };
+    uint64_t map_size;
 };
 
 /* A dynamic array of address blocks, with the following invariant:
@@ -211,6 +212,7 @@ address_space_allocator_split_block(
     new_block->offset = to_borrow_from->offset + new_size;
     new_block->size = size;
     new_block->available = 1;
+    new_block->map_size = 0;
 
     ++allocator->size;
 
@@ -292,6 +294,7 @@ address_space_allocator_split_block_at_offset(
     new_block->offset = offset;
     new_block->size = size;
     new_block->available = 1;
+    new_block->map_size = 0;
 
     ++allocator->size;
 
@@ -299,6 +302,7 @@ address_space_allocator_split_block_at_offset(
         extra_block->offset = offset + size;
         extra_block->size = old_block_size - size - to_borrow_from->size;
         extra_block->available = 1;
+        extra_block->map_size = 0;
 
         ++allocator->size;
     }
diff --git a/base/include/aemu/base/containers/SmallVector.h b/base/include/aemu/base/containers/SmallVector.h
index dbeb56d..eb5e3cd 100644
--- a/base/include/aemu/base/containers/SmallVector.h
+++ b/base/include/aemu/base/containers/SmallVector.h
@@ -289,11 +289,18 @@ public:
         // TODO: Add runtime assertion instead?
         // https://developercommunity.visualstudio.com/content/problem/22196/static-assert-cannot-compile-constexprs-method-tha.html
 #ifndef _MSC_VER
+#if defined(__clang__)
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Winvalid-offsetof"
+#endif
         static_assert(offsetof(base, mCapacity) + sizeof(base::mCapacity) ==
                                       offsetof(SmallFixedVector, mData) &&
                               offsetof(Data, array) == 0,
                       "SmallFixedVector<> class layout is wrong, "
                       "|mData| needs to follow |mCapacity|");
+#if defined(__clang__)
+#pragma clang diagnostic pop
+#endif
 #endif
 
         init_inplace();
diff --git a/base/include/aemu/base/logging/Log.h b/base/include/aemu/base/logging/Log.h
index ea7db33..4eedbe5 100644
--- a/base/include/aemu/base/logging/Log.h
+++ b/base/include/aemu/base/logging/Log.h
@@ -96,7 +96,19 @@ LOGGING_API void setLogFormatter(LogFormatter* fmt);
 //      ... do additionnal logging
 //  }
 //
-#define LOG_IS_ON(severity) (LOG_SEVERITY_FROM(severity) >= getMinLogLevel())
+// Please note that LOG_IS_ON CANNOT be used inside macros the
+// `severity` value will be expanded and the expanded value will
+// be used, e.g.
+//
+//  #define LOG(severity) LOG_LAZY_EVAL(LOG_IS_ON(severity), ...)
+//  #define ERROR 0
+//  LOG(ERROR) << "blah";
+//
+//  `ERROR` will be expanded into `EMULATOR_LOG_0` here
+//  instead of `EMULATOR_LOG_ERROR`.
+
+#define LOG_IS_ON_IMPL(severity) ((severity) >= getMinLogLevel())
+#define LOG_IS_ON(severity) LOG_IS_ON_IMPL(EMULATOR_LOG_##severity)
 
 // For performance reasons, it's important to avoid constructing a
 // LogMessage instance every time a LOG() or CHECK() statement is
@@ -136,7 +148,7 @@ LOGGING_API void setLogFormatter(LogFormatter* fmt);
 // if the severity level is disabled.
 //
 // It's possible to do conditional logging with LOG_IF()
-#define LOG(severity) LOG_LAZY_EVAL(LOG_IS_ON(severity), LOG_MESSAGE_STREAM_COMPACT(severity))
+#define LOG(severity) LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity), LOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // A variant of LOG() that only performs logging if a specific condition
 // is encountered. Note that |condition| is only evaluated if |severity|
@@ -149,16 +161,16 @@ LOGGING_API void setLogFormatter(LogFormatter* fmt);
 //            << "Fuel injection at optimal level";
 //
 #define LOG_IF(severity, condition) \
-    LOG_LAZY_EVAL(LOG_IS_ON(severity) && (condition), LOG_MESSAGE_STREAM_COMPACT(severity))
+    LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity) && (condition), LOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // A variant of LOG() that avoids printing debug information such as file/line
 // information, for user-visible output.
-#define QLOG(severity) LOG_LAZY_EVAL(LOG_IS_ON(severity), QLOG_MESSAGE_STREAM_COMPACT(severity))
+#define QLOG(severity) LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity), QLOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // A variant of LOG_IF() that avoids printing debug information such as
 // file/line information, for user-visible output.
 #define QLOG_IF(severity, condition) \
-    LOG_LAZY_EVAL(LOG_IS_ON(severity) && (condition), QLOG_MESSAGE_STREAM_COMPACT(severity))
+    LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity) && (condition), QLOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // A variant of LOG() that integrates with the utils/debug.h verbose tags,
 // enabling statements to only appear on the console if the "-debug-<tag>"
@@ -170,20 +182,20 @@ LOGGING_API void setLogFormatter(LogFormatter* fmt);
 // as a command line parameter.
 //
 // When logging is enabled, VLOG statements are logged at the INFO severity.
-#define VLOG(tag) LOG_LAZY_EVAL(VERBOSE_CHECK(tag), LOG_MESSAGE_STREAM_COMPACT(INFO))
+#define VLOG(tag) LOG_LAZY_EVAL(VERBOSE_CHECK_IMPL(VERBOSE_##tag), LOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_INFO))
 
 // A variant of LOG() that also appends the string message corresponding
 // to the current value of 'errno' just before the macro is called. This
 // also preserves the value of 'errno' so it can be tested after the
 // macro call (i.e. any error during log output does not interfere).
-#define PLOG(severity) LOG_LAZY_EVAL(LOG_IS_ON(severity), PLOG_MESSAGE_STREAM_COMPACT(severity))
+#define PLOG(severity) LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity), PLOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // A variant of LOG_IF() that also appends the string message corresponding
 // to the current value of 'errno' just before the macro is called. This
 // also preserves the value of 'errno' so it can be tested after the
 // macro call (i.e. any error during log output does not interfere).
 #define PLOG_IF(severity, condition) \
-    LOG_LAZY_EVAL(LOG_IS_ON(severity) && (condition), PLOG_MESSAGE_STREAM_COMPACT(severity))
+    LOG_LAZY_EVAL(LOG_IS_ON_IMPL(EMULATOR_LOG_##severity) && (condition), PLOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // Evaluate |condition|, and if it fails, log a fatal message.
 // This is a better version of assert(), in the future, this will
@@ -226,7 +238,7 @@ LOGGING_API void setLogFormatter(LogFormatter* fmt);
 // DLOG_IS_ON(severity) is used to indicate whether DLOG() should print
 // something for the current level.
 #if ENABLE_DLOG
-#define DLOG_IS_ON(severity) LOG_IS_ON(severity)
+#define DLOG_IS_ON(severity) LOG_IS_ON_IMPL(severity)
 #else
 // NOTE: The compile-time constant ensures that the DLOG() statements are
 //       not compiled in the final binary.
@@ -259,7 +271,7 @@ LOGGING_API bool setDcheckLevel(bool enabled);
 // DLOG_IF() is like DLOG() for debug builds, and doesn't do anything for
 // release one. See DLOG() comments.
 #define DLOG_IF(severity, condition) \
-    LOG_LAZY_EVAL(DLOG_IS_ON(severity) && (condition), LOG_MESSAGE_STREAM_COMPACT(severity))
+    LOG_LAZY_EVAL(DLOG_IS_ON(EMULATOR_LOG_##severity) && (condition), LOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // DCHECK(condition) is used to perform CHECK() in debug builds, or if
 // the program called setDcheckLevel(true) previously. Note that it is
@@ -277,7 +289,7 @@ LOGGING_API bool setDcheckLevel(bool enabled);
 // DPLOG_IF() tests whether |condition| is true before calling
 // DPLOG(severity)
 #define DPLOG_IF(severity, condition) \
-    LOG_LAZY_EVAL(DLOG_IS_ON(severity) && (condition), PLOG_MESSAGE_STREAM_COMPACT(severity))
+    LOG_LAZY_EVAL(DLOG_IS_ON(EMULATOR_LOG_##severity) && (condition), PLOG_MESSAGE_STREAM_COMPACT_IMPL(EMULATOR_LOG_##severity))
 
 // Convenience class used hold a formatted string for logging reasons.
 // Usage example:
@@ -392,20 +404,11 @@ class LOGGING_API LogMessage {
     LogStream* mStream;
 };
 
-// Helper macros to avoid too much typing. This creates a new LogMessage
-// instance with the appropriate file source path, file source line and
-// severity.
-#define LOG_MESSAGE_COMPACT(severity) \
-    ::android::base::LogMessage(__FILE__, __LINE__, LOG_SEVERITY_FROM(severity))
-
-#define LOG_MESSAGE_STREAM_COMPACT(severity) LOG_MESSAGE_COMPACT(severity).stream()
+#define LOG_MESSAGE_STREAM_COMPACT_IMPL(severity) \
+    ::android::base::LogMessage(__FILE__, __LINE__, severity).stream()
 
-// A variant of LogMessage for outputting user-visible messages to the console,
-// without debug information.
-#define QLOG_MESSAGE_COMPACT(severity) \
-    ::android::base::LogMessage(__FILE__, __LINE__, LOG_SEVERITY_FROM(severity), true)
-
-#define QLOG_MESSAGE_STREAM_COMPACT(severity) QLOG_MESSAGE_COMPACT(severity).stream()
+#define QLOG_MESSAGE_STREAM_COMPACT_IMPL(severity) \
+    ::android::base::LogMessage(__FILE__, __LINE__, severity, true).stream()
 
 // A variant of LogMessage that saves the errno value on creation,
 // then restores it on destruction, as well as append a strerror()
@@ -427,11 +430,8 @@ class LOGGING_API ErrnoLogMessage {
     int mErrno;
 };
 
-// Helper macros to avoid too much typing.
-#define PLOG_MESSAGE_COMPACT(severity) \
-    ::android::base::ErrnoLogMessage(__FILE__, __LINE__, LOG_SEVERITY_FROM(severity), errno)
-
-#define PLOG_MESSAGE_STREAM_COMPACT(severity) PLOG_MESSAGE_COMPACT(severity).stream()
+#define PLOG_MESSAGE_STREAM_COMPACT_IMPL(severity) \
+    ::android::base::ErrnoLogMessage(__FILE__, __LINE__, severity, errno).stream()
 
 namespace testing {
 
@@ -460,4 +460,4 @@ class LOGGING_API LogOutput {
 
 }  // namespace base
 }  // namespace android
-#endif
\ No newline at end of file
+#endif
diff --git a/base/include/aemu/base/logging/LogTags.h b/base/include/aemu/base/logging/LogTags.h
index c870ef7..42c5797 100644
--- a/base/include/aemu/base/logging/LogTags.h
+++ b/base/include/aemu/base/logging/LogTags.h
@@ -26,22 +26,29 @@ typedef enum {
 } VerboseTag;
 #undef _VERBOSE_TAG
 
-#define VERBOSE_ENABLE(tag) verbose_enable((int64_t)VERBOSE_##tag)
-#define VERBOSE_DISABLE(tag) verbose_disable(int64_t) VERBOSE_##tag)
-#define VERBOSE_CHECK(tag) verbose_check((int64_t)VERBOSE_##tag)
+#define VERBOSE_ENABLE_IMPL(tag) verbose_enable((int64_t)tag)
+#define VERBOSE_ENABLE(tag) VERBOSE_ENABLE_IMPL(VERBOSE_##tag)
+#define VERBOSE_DISABLE_IMPL(tag) verbose_disable((int64_t)tag)
+#define VERBOSE_DISABLE(tag) VERBOSE_DISABLE_IMPL(VERBOSE_##tag)
+#define VERBOSE_CHECK_IMPL(tag) verbose_check((int64_t)tag)
+#define VERBOSE_CHECK(tag) VERBOSE_CHECK_IMPL(VERBOSE_##tag)
 #define VERBOSE_CHECK_ANY() verbose_check_any();
 
-#define VERBOSE_PRINT(tag, ...) \
-    if (VERBOSE_CHECK(tag)) {   \
+#define VERBOSE_PRINT_IMPL(tag, ...) \
+    if (VERBOSE_CHECK_IMPL(tag)) {   \
         dprint(__VA_ARGS__);  \
     }
 
-#define VERBOSE_INFO(tag, ...) \
-    if (VERBOSE_CHECK(tag)) {  \
+#define VERBOSE_PRINT(tag, ...) VERBOSE_PRINT_IMPL(VERBOSE_##tag, __VA_ARGS__)
+
+#define VERBOSE_INFO_IMPL(tag, ...) \
+    if (VERBOSE_CHECK_IMPL(tag)) {  \
         dinfo(__VA_ARGS__);  \
     }
 
-#define VERBOSE_DPRINT(tag, ...) VERBOSE_PRINT(tag, __VA_ARGS__)
+#define VERBOSE_INFO(tag, ...) VERBOSE_INFO_IMPL(VERBOSE_##tag, __VA_ARGS__)
+
+#define VERBOSE_DPRINT(tag, ...) VERBOSE_PRINT_IMPL(VERBOSE_##tag, __VA_ARGS__)
 
 #ifdef __cplusplus
 }
diff --git a/base/include/aemu/base/utils/status_macros.h b/base/include/aemu/base/utils/status_macros.h
new file mode 100644
index 0000000..7e3963c
--- /dev/null
+++ b/base/include/aemu/base/utils/status_macros.h
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+// This impl modified from external/perfetto/src/trace_processor/util/status_macros.h
+
+#ifndef AEMU_UTIL_STATUS_MACROS_H_
+#define AEMU_UTIL_STATUS_MACROS_H_
+
+#include "absl/status/status.h"
+
+// Evaluates |expr|, which should return a base::Status. If the status is an
+// error status, returns the status from the current function.
+#define RETURN_IF_ERROR(expr)                           \
+  do {                                                  \
+    absl::Status status_macro_internal_status = (expr); \
+    if (!status_macro_internal_status.ok())             \
+      return status_macro_internal_status;              \
+  } while (0)
+
+#define AEMU_INTERNAL_CONCAT_IMPL(x, y) x##y
+#define AEMU_INTERNAL_MACRO_CONCAT(x, y) AEMU_INTERNAL_CONCAT_IMPL(x, y)
+
+// Evalues |rhs| which should return a base::StatusOr<T> and assigns this
+// to |lhs|. If the status is an error status, returns the status from the
+// current function.
+#define ASSIGN_OR_RETURN(lhs, rhs)                                   \
+  AEMU_INTERNAL_MACRO_CONCAT(auto status_or, __LINE__) = rhs;    \
+  RETURN_IF_ERROR(                                                   \
+      AEMU_INTERNAL_MACRO_CONCAT(status_or, __LINE__).status()); \
+  lhs = std::move(AEMU_INTERNAL_MACRO_CONCAT(status_or, __LINE__).value())
+
+#endif  // AEMU_UTIL_STATUS_MACROS_H_
diff --git a/base/include/aemu/base/utils/status_matcher_macros.h b/base/include/aemu/base/utils/status_matcher_macros.h
new file mode 100644
index 0000000..04d2101
--- /dev/null
+++ b/base/include/aemu/base/utils/status_matcher_macros.h
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef AEMU_UTIL_STATUS_MATCHER_MACROS_H_
+#define AEMU_UTIL_STATUS_MATCHER_MACROS_H_
+
+#include <gtest/gtest.h>
+
+#include "absl/status/status_matchers.h"
+#include "absl/strings/str_cat.h"
+
+#include "aemu/base/utils/status_macros.h"
+
+#define EXPECT_OK(expression) EXPECT_THAT(expression, ::absl_testing::IsOk())
+#define ASSERT_OK(expression) ASSERT_THAT(expression, ::absl_testing::IsOk())
+
+template <typename T>
+void AemuFailIfNotOk(const absl::StatusOr<T>& status_or, const char* file, int line, const char* expr) {
+    if (!status_or.ok()) {
+        GTEST_MESSAGE_AT_(file, line, 
+                          ::absl::StrCat(expr, " returned error: ",
+                                         status_or.status().ToString(
+                                                 absl::StatusToStringMode::kWithEverything))
+                                  .c_str(),
+                          ::testing::TestPartResult::kFatalFailure);
+    }
+}
+
+#define ASSERT_OK_AND_ASSIGN(lhs, rhs)                                                          \
+    AEMU_INTERNAL_MACRO_CONCAT(auto status_or, __LINE__) = rhs;                                 \
+    AemuFailIfNotOk(AEMU_INTERNAL_MACRO_CONCAT(status_or, __LINE__), __FILE__, __LINE__, #rhs); \
+    lhs = std::move(AEMU_INTERNAL_MACRO_CONCAT(status_or, __LINE__).value())
+
+#endif  // AEMU_UTIL_STATUS_MATCHER_MACROS_H_
diff --git a/base/testing/ProtobufMatchers.cpp b/base/testing/ProtobufMatchers.cpp
deleted file mode 100644
index bad42da..0000000
--- a/base/testing/ProtobufMatchers.cpp
+++ /dev/null
@@ -1,240 +0,0 @@
-/*
- * Copyright 2018 Google Inc.
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
-#include "aemu/base/testing/ProtobufMatchers.h"
-
-#include <algorithm>
-#include <regex>
-#include <string>
-#include <string_view>
-
-#include "absl/log/check.h"
-#include "gmock/gmock-matchers.h"
-#include "gmock/gmock-more-matchers.h"
-#include "google/protobuf/descriptor.h"
-#include "google/protobuf/io/tokenizer.h"
-#include "google/protobuf/message.h"
-#include "google/protobuf/text_format.h"
-#include "google/protobuf/util/message_differencer.h"
-
-namespace android {
-namespace internal {
-
-// Utilities.
-using google::protobuf::io::ColumnNumber;
-
-class StringErrorCollector : public google::protobuf::io::ErrorCollector {
-   public:
-    explicit StringErrorCollector(std::string* error_text) : error_text_(error_text) {}
-
-    void RecordError(int line, ColumnNumber column, absl::string_view message) override {
-        std::ostringstream ss;
-        ss << "ERROR: " << line << "(" << column << ")" << message << "\n";
-        *error_text_ += ss.str();
-    }
-
-    void RecordWarning(int line, ColumnNumber column, absl::string_view message) override {
-        std::ostringstream ss;
-        ss << "WARNING: " << line << "(" << column << ")" << message << "\n";
-        *error_text_ += ss.str();
-    }
-
-   private:
-    std::string* error_text_;
-    StringErrorCollector(const StringErrorCollector&) = delete;
-    StringErrorCollector& operator=(const StringErrorCollector&) = delete;
-};
-
-bool ParsePartialFromAscii(const std::string& pb_ascii, google::protobuf::Message* proto,
-                           std::string* error_text) {
-    google::protobuf::TextFormat::Parser parser;
-    StringErrorCollector collector(error_text);
-    parser.RecordErrorsTo(&collector);
-    parser.AllowPartialMessage(true);
-    return parser.ParseFromString(pb_ascii, proto);
-}
-
-// Returns true iff p and q can be compared (i.e. have the same descriptor).
-bool ProtoComparable(const google::protobuf::Message& p, const google::protobuf::Message& q) {
-    return p.GetDescriptor() == q.GetDescriptor();
-}
-
-template <typename Container>
-std::string JoinStringPieces(const Container& strings, std::string_view separator) {
-    std::stringstream stream;
-    std::string_view sep = "";
-    for (const std::string_view str : strings) {
-        stream << sep << str;
-        sep = separator;
-    }
-    return stream.str();
-}
-
-// Find all the descriptors for the ignore_fields.
-std::vector<const google::protobuf::FieldDescriptor*> GetFieldDescriptors(
-    const google::protobuf::Descriptor* proto_descriptor,
-    const std::vector<std::string>& ignore_fields) {
-    std::vector<const google::protobuf::FieldDescriptor*> ignore_descriptors;
-    std::vector<std::string_view> remaining_descriptors;
-
-    const google::protobuf::DescriptorPool* pool = proto_descriptor->file()->pool();
-    for (const std::string& name : ignore_fields) {
-        if (const google::protobuf::FieldDescriptor* field = pool->FindFieldByName(name)) {
-            ignore_descriptors.push_back(field);
-        } else {
-            remaining_descriptors.push_back(name);
-        }
-    }
-
-    DCHECK(remaining_descriptors.empty())
-        << "Could not find fields for proto " << proto_descriptor->full_name()
-        << " with fully qualified names: " << JoinStringPieces(remaining_descriptors, ",");
-    return ignore_descriptors;
-}
-
-// Sets the ignored fields corresponding to ignore_fields in differencer. Dies
-// if any is invalid.
-void SetIgnoredFieldsOrDie(const google::protobuf::Descriptor& root_descriptor,
-                           const std::vector<std::string>& ignore_fields,
-                           google::protobuf::util::MessageDifferencer* differencer) {
-    if (!ignore_fields.empty()) {
-        std::vector<const google::protobuf::FieldDescriptor*> ignore_descriptors =
-            GetFieldDescriptors(&root_descriptor, ignore_fields);
-        for (std::vector<const google::protobuf::FieldDescriptor*>::iterator it =
-                 ignore_descriptors.begin();
-             it != ignore_descriptors.end(); ++it) {
-            differencer->IgnoreField(*it);
-        }
-    }
-}
-
-// Configures a MessageDifferencer and DefaultFieldComparator to use the logic
-// described in comp. The configured differencer is the output of this function,
-// but a FieldComparator must be provided to keep ownership clear.
-void ConfigureDifferencer(const internal::ProtoComparison& comp,
-                          google::protobuf::util::DefaultFieldComparator* comparator,
-                          google::protobuf::util::MessageDifferencer* differencer,
-                          const google::protobuf::Descriptor* descriptor) {
-    differencer->set_message_field_comparison(comp.field_comp);
-    differencer->set_scope(comp.scope);
-    comparator->set_float_comparison(comp.float_comp);
-    comparator->set_treat_nan_as_equal(comp.treating_nan_as_equal);
-    differencer->set_repeated_field_comparison(comp.repeated_field_comp);
-    SetIgnoredFieldsOrDie(*descriptor, comp.ignore_fields, differencer);
-    if (comp.float_comp == internal::kProtoApproximate &&
-        (comp.has_custom_margin || comp.has_custom_fraction)) {
-        // Two fields will be considered equal if they're within the fraction
-        // _or_ within the margin. So setting the fraction to 0.0 makes this
-        // effectively a "SetMargin". Similarly, setting the margin to 0.0 makes
-        // this effectively a "SetFraction".
-        comparator->SetDefaultFractionAndMargin(comp.float_fraction, comp.float_margin);
-    }
-    differencer->set_field_comparator(comparator);
-}
-
-// Returns true iff actual and expected are comparable and match.  The
-// comp argument specifies how two are compared.
-bool ProtoCompare(const internal::ProtoComparison& comp, const google::protobuf::Message& actual,
-                  const google::protobuf::Message& expected) {
-    if (!ProtoComparable(actual, expected)) return false;
-
-    google::protobuf::util::MessageDifferencer differencer;
-    google::protobuf::util::DefaultFieldComparator field_comparator;
-    ConfigureDifferencer(comp, &field_comparator, &differencer, actual.GetDescriptor());
-
-    // It's important for 'expected' to be the first argument here, as
-    // Compare() is not symmetric.  When we do a partial comparison,
-    // only fields present in the first argument of Compare() are
-    // considered.
-    return differencer.Compare(expected, actual);
-}
-
-// Describes the types of the expected and the actual protocol buffer.
-std::string DescribeTypes(const google::protobuf::Message& expected,
-                          const google::protobuf::Message& actual) {
-    return "whose type should be " + expected.GetDescriptor()->full_name() + " but actually is " +
-           actual.GetDescriptor()->full_name();
-}
-
-// Prints the protocol buffer pointed to by proto.
-std::string PrintProtoPointee(const google::protobuf::Message* proto) {
-    if (proto == NULL) return "";
-
-    return "which points to " + ::testing::PrintToString(*proto);
-}
-
-// Describes the differences between the two protocol buffers.
-std::string DescribeDiff(const internal::ProtoComparison& comp,
-                         const google::protobuf::Message& actual,
-                         const google::protobuf::Message& expected) {
-    google::protobuf::util::MessageDifferencer differencer;
-    google::protobuf::util::DefaultFieldComparator field_comparator;
-    ConfigureDifferencer(comp, &field_comparator, &differencer, actual.GetDescriptor());
-
-    std::string diff;
-    differencer.ReportDifferencesToString(&diff);
-
-    // We must put 'expected' as the first argument here, as Compare()
-    // reports the diff in terms of how the protobuf changes from the
-    // first argument to the second argument.
-    differencer.Compare(expected, actual);
-
-    // Removes the trailing '\n' in the diff to make the output look nicer.
-    if (diff.length() > 0 && *(diff.end() - 1) == '\n') {
-        diff.erase(diff.end() - 1);
-    }
-
-    return "with the difference:\n" + diff;
-}
-
-bool ProtoMatcherBase::MatchAndExplain(
-    const google::protobuf::Message& arg,
-    bool is_matcher_for_pointer,  // true iff this matcher is used to match
-                                  // a protobuf pointer.
-    ::testing::MatchResultListener* listener) const {
-    if (must_be_initialized_ && !arg.IsInitialized()) {
-        *listener << "which isn't fully initialized";
-        return false;
-    }
-
-    const google::protobuf::Message* const expected = CreateExpectedProto(arg, listener);
-    if (expected == NULL) return false;
-
-    // Protobufs of different types cannot be compared.
-    const bool comparable = ProtoComparable(arg, *expected);
-    const bool match = comparable && ProtoCompare(comp(), arg, *expected);
-
-    // Explaining the match result is expensive.  We don't want to waste
-    // time calculating an explanation if the listener isn't interested.
-    if (listener->IsInterested()) {
-        const char* sep = "";
-        if (is_matcher_for_pointer) {
-            *listener << PrintProtoPointee(&arg);
-            sep = ",\n";
-        }
-
-        if (!comparable) {
-            *listener << sep << DescribeTypes(*expected, arg);
-        } else if (!match) {
-            *listener << sep << DescribeDiff(comp(), arg, *expected);
-        }
-    }
-
-    DeleteExpectedProto(expected);
-    return match;
-}
-
-}  // namespace internal
-}  // namespace android
diff --git a/host-common/BUILD.bazel b/host-common/BUILD.bazel
index 9951ba2..3a1e9a6 100644
--- a/host-common/BUILD.bazel
+++ b/host-common/BUILD.bazel
@@ -1,3 +1,5 @@
+load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
+
 # Logging library
 cc_library(
     name = "logging-qemu2",
@@ -18,8 +20,8 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":aemu-host-common-headers",
-        "//hardware/google/aemu/base:aemu-base-headers",
-        "//hardware/google/aemu/base:aemu-base-metrics",
+        "//base:aemu-base-headers",
+        "//base:aemu-base-metrics",
     ],
 )
 
@@ -42,8 +44,8 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":aemu-host-common-headers",
-        "//hardware/google/aemu/base:aemu-base-headers",
-        "//hardware/google/aemu/base:aemu-base-metrics",
+        "//base:aemu-base-headers",
+        "//base:aemu-base-metrics",
         "@com_google_absl//absl/log",
         "@com_google_absl//absl/log:absl_log",
     ],
@@ -51,10 +53,97 @@ cc_library(
 
 cc_library(
     name = "aemu-host-common-headers",
-    hdrs = glob([
-        "include/**/*.h",
-        "include/**/*.hpp",
-    ]),
+    hdrs = [
+        "include/host-common/AddressSpaceService.h",
+        "include/host-common/AndroidAsyncMessagePipe.h",
+        "include/host-common/AndroidPipe.h",
+        "include/host-common/DeviceContextRunner.h",
+        "include/host-common/DmaMap.h",
+        "include/host-common/FeatureControl.h",
+        "include/host-common/FeatureControlDefGuest.h",
+        "include/host-common/FeatureControlDefHost.h",
+        "include/host-common/Features.h",
+        "include/host-common/GfxstreamFatalError.h",
+        "include/host-common/GoldfishDma.h",
+        "include/host-common/GoldfishMediaDefs.h",
+        "include/host-common/GoldfishSyncCommandQueue.h",
+        "include/host-common/GraphicsAgentFactory.h",
+        "include/host-common/H264NaluParser.h",
+        "include/host-common/H264PingInfoParser.h",
+        "include/host-common/HostGoldfishPipe.h",
+        "include/host-common/HostmemIdMapping.h",
+        "include/host-common/MediaCodec.h",
+        "include/host-common/MediaCudaDriverHelper.h",
+        "include/host-common/MediaCudaUtils.h",
+        "include/host-common/MediaCudaVideoHelper.h",
+        "include/host-common/MediaFfmpegVideoHelper.h",
+        "include/host-common/MediaH264Decoder.h",
+        "include/host-common/MediaH264DecoderDefault.h",
+        "include/host-common/MediaH264DecoderGeneric.h",
+        "include/host-common/MediaH264DecoderPlugin.h",
+        "include/host-common/MediaH264DecoderVideoToolBox.h",
+        "include/host-common/MediaHevcDecoder.h",
+        "include/host-common/MediaHostRenderer.h",
+        "include/host-common/MediaSnapshotHelper.h",
+        "include/host-common/MediaSnapshotState.h",
+        "include/host-common/MediaTexturePool.h",
+        "include/host-common/MediaVideoHelper.h",
+        "include/host-common/MediaVideoToolBoxUtils.h",
+        "include/host-common/MediaVideoToolBoxVideoHelper.h",
+        "include/host-common/MediaVpxDecoder.h",
+        "include/host-common/MediaVpxDecoderGeneric.h",
+        "include/host-common/MediaVpxDecoderPlugin.h",
+        "include/host-common/MediaVpxVideoHelper.h",
+        "include/host-common/MultiDisplay.h",
+        "include/host-common/MultiDisplayPipe.h",
+        "include/host-common/RefcountPipe.h",
+        "include/host-common/VmLock.h",
+        "include/host-common/VpxFrameParser.h",
+        "include/host-common/VpxPingInfoParser.h",
+        "include/host-common/YuvConverter.h",
+        "include/host-common/address_space_device.h",
+        "include/host-common/address_space_device.hpp",
+        "include/host-common/address_space_device_control_ops.h",
+        "include/host-common/address_space_graphics.h",
+        "include/host-common/address_space_graphics_types.h",
+        "include/host-common/address_space_host_media.h",
+        "include/host-common/address_space_host_memory_allocator.h",
+        "include/host-common/address_space_shared_slots_host_memory_allocator.h",
+        "include/host-common/android_pipe_base.h",
+        "include/host-common/android_pipe_common.h",
+        "include/host-common/android_pipe_device.h",
+        "include/host-common/android_pipe_host.h",
+        "include/host-common/constants.h",
+        "include/host-common/crash-handler.h",
+        "include/host-common/crash_reporter.h",
+        "include/host-common/debug.h",
+        "include/host-common/display_agent.h",
+        "include/host-common/dma_device.h",
+        "include/host-common/dynlink_cuda.h",
+        "include/host-common/dynlink_cuda_cuda.h",
+        "include/host-common/dynlink_cuviddec.h",
+        "include/host-common/dynlink_nvcuvid.h",
+        "include/host-common/emugl_vm_operations.h",
+        "include/host-common/feature_control.h",
+        "include/host-common/feature_control_base.h",
+        "include/host-common/globals.h",
+        "include/host-common/goldfish_pipe.h",
+        "include/host-common/goldfish_sync.h",
+        "include/host-common/hw-config.h",
+        "include/host-common/hw-config-defs.h",
+        "include/host-common/hw-config-helper.h",
+        "include/host-common/hw-lcd.h",
+        "include/host-common/linux_types.h",
+        "include/host-common/logging.h",
+        "include/host-common/misc.h",
+        "include/host-common/multi_display_agent.h",
+        "include/host-common/record_screen_agent.h",
+        "include/host-common/refcount-pipe.h",
+        "include/host-common/screen-recorder.h",
+        "include/host-common/sync_device.h",
+        "include/host-common/vm_operations.h",
+        "include/host-common/window_agent.h",
+    ],
     includes = ["include"],
     visibility = ["//visibility:public"],
 )
@@ -104,8 +193,8 @@ cc_library(
     deps = [
         ":aemu-host-common-headers",
         ":logging",
-        "//hardware/google/aemu/base:aemu-base-allocator",
-        "//hardware/google/aemu/base:aemu-base-headers",
+        "//base:aemu-base-allocator",
+        "//base:aemu-base-headers",
     ],
     alwayslink = 1,
 )
@@ -114,7 +203,6 @@ cc_library(
 cc_library(
     name = "aemu-host-common-product-feature-override",
     srcs = ["FeatureControlOverride.cpp"],
-    hdrs = glob(["include/**/*.h"]),
     defines = [
         "BUILDING_EMUGL_COMMON_SHARED",
     ] + select({
@@ -127,7 +215,7 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":aemu-host-common-headers",
-        "//hardware/google/aemu/base:aemu-base-headers",
+        "//base:aemu-base-headers",
     ],
 )
 
@@ -149,34 +237,39 @@ cc_library(
     includes = ["testing"],
     deps = [
         ":aemu-host-common-headers",
-        "//hardware/google/aemu/base:aemu-base-headers",
+        "//base:aemu-base-headers",
         "@com_google_googletest//:gtest",
     ],
 )
 
+cc_library(
+    name = "test-headers",
+    hdrs = [
+        "testing/HostAddressSpace.h",
+        "testing/MockAndroidEmulatorWindowAgent.h",
+        "testing/MockAndroidVmOperations.h",
+        "testing/MockGraphicsAgentFactory.h",
+    ],
+    includes = ["include"],
+    visibility = ["//visibility:public"],
+    deps = ["//base:test-io"],
+)
+
 # Testing Libraries and Executable (conditional)
 cc_test(
     name = "aemu-host-logging_unittests",
-    srcs =
-        [
-            # "GfxstreamFatalError_unittest.cpp",
-            # "HostAddressSpace_unittest.cpp",
-            # "HostGoldfishPipe_unittest.cpp",
-            # "HostmemIdMapping_unittest.cpp",
-            # "VmLock_unittest.cpp",
-            "logging_absl_unittest.cpp",
-        ] + glob([
-            "testing/**",
-        ]),
+    srcs = [
+        "logging_absl_unittest.cpp",
+    ],
     includes = ["testing"],
     deps = [
         ":aemu-host-common-headers",
         ":logging",
-        "//hardware/google/aemu:aemu-host-common-test-headers",
-        "//hardware/google/aemu/base:aemu-base",
-        "//hardware/google/aemu/base:aemu-base-allocator",
-        "//hardware/google/aemu/base:aemu-base-headers",
-        "//hardware/google/aemu/host-common:aemu-host-common",
+        ":test-headers",
+        "//base:aemu-base",
+        "//base:aemu-base-allocator",
+        "//base:aemu-base-headers",
+        "//host-common:aemu-host-common",
         "@com_google_absl//absl/log",
         "@com_google_absl//absl/log:absl_log",
         "@com_google_absl//absl/log:globals",
diff --git a/host-common/GraphicsAgentFactory.cpp b/host-common/GraphicsAgentFactory.cpp
index ef0b848..a0c0579 100644
--- a/host-common/GraphicsAgentFactory.cpp
+++ b/host-common/GraphicsAgentFactory.cpp
@@ -39,7 +39,7 @@ const GraphicsAgents* getGraphicsAgents() {
 }
 
 #define DEFINE_GRAPHICS_AGENT_GETTER_IMPL(typ, name)                   \
-    const typ* const GraphicsAgentFactory::android_get_##typ() const { \
+    const typ* GraphicsAgentFactory::android_get_##typ() const { \
         return sGraphicsAgents.name;                                   \
     };
 
diff --git a/host-common/address_space_device.cpp b/host-common/address_space_device.cpp
index 1f852c9..8d9ce21 100644
--- a/host-common/address_space_device.cpp
+++ b/host-common/address_space_device.cpp
@@ -324,11 +324,10 @@ public:
         AutoLock lock(mContextsLock);
         mContexts.clear();
         AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateClear();
-        auto it = mMemoryMappings.begin();
         std::vector<std::pair<uint64_t, uint64_t>> gpasSizesToErase;
-        for (auto it: mMemoryMappings) {
-            auto gpa = it.first;
-            auto size = it.second.second;
+        for (auto& mapping : mMemoryMappings) {
+            auto gpa = mapping.first;
+            auto size = mapping.second.second;
             gpasSizesToErase.push_back({gpa, size});
         }
         for (const auto& gpaSize : gpasSizesToErase) {
diff --git a/host-common/address_space_graphics.cpp b/host-common/address_space_graphics.cpp
index d08de67..e16b77d 100644
--- a/host-common/address_space_graphics.cpp
+++ b/host-common/address_space_graphics.cpp
@@ -489,11 +489,10 @@ private:
                     "Only dedicated allocation allowed in virtio-gpu hostmem id path");
             } else {
                 uint64_t offsetIntoPhys;
-                int allocRes = 0;
 
                 if (create.fromLoad) {
                     offsetIntoPhys = block.offsetIntoPhys;
-                    allocRes = get_address_space_device_hw_funcs()->
+                    int allocRes = get_address_space_device_hw_funcs()->
                         allocSharedHostRegionFixedLocked(
                                 ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE, offsetIntoPhys);
                     if (allocRes) {
diff --git a/host-common/address_space_host_memory_allocator.cpp b/host-common/address_space_host_memory_allocator.cpp
index e61df31..6b97b5c 100644
--- a/host-common/address_space_host_memory_allocator.cpp
+++ b/host-common/address_space_host_memory_allocator.cpp
@@ -135,9 +135,9 @@ void AddressSpaceHostMemoryAllocatorContext::save(base::Stream* stream) const {
 bool AddressSpaceHostMemoryAllocatorContext::load(base::Stream* stream) {
     clear();
 
-    size_t size = stream->getBe32();
+    size_t numAddr = stream->getBe32();
 
-    for (size_t i = 0; i < size; ++i) {
+    for (size_t i = 0; i < numAddr; ++i) {
         uint64_t phys_addr = stream->getBe64();
         uint64_t size = stream->getBe64();
         void *mem = allocate_impl(phys_addr, size);
diff --git a/host-common/empty-crash-handler.cpp b/host-common/empty-crash-handler.cpp
index ffc6c31..fdc302d 100644
--- a/host-common/empty-crash-handler.cpp
+++ b/host-common/empty-crash-handler.cpp
@@ -13,6 +13,8 @@
 // limitations under the License.
 #include "host-common/crash-handler.h"
 
+#include <stdlib.h>
+
 void crashhandler_die(const char* message) {
     abort();
 }
diff --git a/host-common/include/host-common/FeatureControlDefGuest.h b/host-common/include/host-common/FeatureControlDefGuest.h
index ac9061d..5bed5d8 100644
--- a/host-common/include/host-common/FeatureControlDefGuest.h
+++ b/host-common/include/host-common/FeatureControlDefGuest.h
@@ -80,3 +80,6 @@ FEATURE_CONTROL_ITEM(DeviceKeyboardHasAssistKey, 97)
 FEATURE_CONTROL_ITEM(Uwb, 101)
 FEATURE_CONTROL_ITEM(GuestAngle, 102)
 FEATURE_CONTROL_ITEM(AndroidVirtualizationFramework, 103)
+FEATURE_CONTROL_ITEM(XrModeUI, 104)
+FEATURE_CONTROL_ITEM(VirtioDualModeMouse, 105)
+FEATURE_CONTROL_ITEM(DualModeMouseDisplayHostCursor, 106)
diff --git a/host-common/include/host-common/FeatureControlDefHost.h b/host-common/include/host-common/FeatureControlDefHost.h
index 144a58c..0e3d777 100644
--- a/host-common/include/host-common/FeatureControlDefHost.h
+++ b/host-common/include/host-common/FeatureControlDefHost.h
@@ -87,3 +87,4 @@ FEATURE_CONTROL_ITEM(BypassVulkanDeviceFeatureOverrides, 107)
 FEATURE_CONTROL_ITEM(VulkanDebugUtils, 108)
 FEATURE_CONTROL_ITEM(VulkanCommandBufferCheckpoints, 109)
 FEATURE_CONTROL_ITEM(VulkanVirtualQueue, 110)
+FEATURE_CONTROL_ITEM(VulkanRobustness, 111)
diff --git a/host-common/include/host-common/GraphicsAgentFactory.h b/host-common/include/host-common/GraphicsAgentFactory.h
index 2263924..331bc2d 100644
--- a/host-common/include/host-common/GraphicsAgentFactory.h
+++ b/host-common/include/host-common/GraphicsAgentFactory.h
@@ -31,7 +31,7 @@ typedef int (*LineConsumerCallback)(void* opaque, const char* buff, int len);
 namespace android {
 namespace emulation {
 #define DEFINE_GRAPHICS_AGENT_GETTER(typ, name) \
-    virtual const typ* const android_get_##typ() const;
+    virtual const typ* android_get_##typ() const;
 
 // The default graphics agent factory will not do anything, it will
 // leave the graphics agents intact.
diff --git a/host-common/include/host-common/HostmemIdMapping.h b/host-common/include/host-common/HostmemIdMapping.h
index bef68a4..7138290 100644
--- a/host-common/include/host-common/HostmemIdMapping.h
+++ b/host-common/include/host-common/HostmemIdMapping.h
@@ -40,15 +40,16 @@ using android::base::ManagedDescriptor;
 namespace android {
 namespace emulation {
 
-#define STREAM_MEM_HANDLE_TYPE_OPAQUE_FD 0x1
-#define STREAM_MEM_HANDLE_TYPE_DMABUF 0x2
-#define STREAM_MEM_HANDLE_TYPE_OPAQUE_WIN32 0x3
-#define STREAM_MEM_HANDLE_TYPE_SHM 0x4
-#define STREAM_MEM_HANDLE_TYPE_ZIRCON 0x5
-#define STREAM_FENCE_HANDLE_TYPE_OPAQUE_FD 0x6
-#define STREAM_FENCE_HANDLE_TYPE_SYNC_FD 0x7
-#define STREAM_FENCE_HANDLE_TYPE_OPAQUE_WIN32 0x8
-#define STREAM_FENCE_HANDLE_TYPE_ZIRCON 0x9
+#define STREAM_HANDLE_TYPE_MEM_OPAQUE_FD 0x1
+#define STREAM_HANDLE_TYPE_MEM_DMABUF 0x2
+#define STREAM_HANDLE_TYPE_MEM_OPAQUE_WIN32 0x3
+#define STREAM_HANDLE_TYPE_MEM_SHM 0x4
+#define STREAM_HANDLE_TYPE_MEM_ZIRCON 0x5
+
+#define STREAM_HANDLE_TYPE_SIGNAL_OPAQUE_FD 0x10
+#define STREAM_HANDLE_TYPE_SIGNAL_SYNC_FD 0x20
+#define STREAM_HANDLE_TYPE_SIGNAL_OPAQUE_WIN32 0x30
+#define STREAM_HANDLE_TYPE_SIGNAL_ZIRCON 0x40
 
 struct VulkanInfo {
     uint32_t memoryIndex;
diff --git a/host-common/include/host-common/MultiDisplay.h b/host-common/include/host-common/MultiDisplay.h
index e2fa861..91e5ac5 100644
--- a/host-common/include/host-common/MultiDisplay.h
+++ b/host-common/include/host-common/MultiDisplay.h
@@ -45,7 +45,7 @@ struct MultiDisplayInfo {
     MultiDisplayInfo(int32_t x, int32_t y, uint32_t w, uint32_t h,
                      uint32_t d, uint32_t f, bool e, uint32_t c = 0) :
       pos_x(x), pos_y(y), width(w), height(h), originalWidth(w),
-      originalHeight(h), dpi(d), flag(f), rotation(0), enabled(e), cb(c) {}
+      originalHeight(h), dpi(d), flag(f), cb(c), rotation(0), enabled(e) {}
 
 };
 
diff --git a/host-common/include/host-common/vm_operations.h b/host-common/include/host-common/vm_operations.h
index 9d46f57..f203060 100644
--- a/host-common/include/host-common/vm_operations.h
+++ b/host-common/include/host-common/vm_operations.h
@@ -165,6 +165,18 @@ typedef enum SnapshotSkipReason {
     SNAPSHOT_SKIP_UNSUPPORTED_VK_API = 2,
 } SnapshotSkipReason;
 
+inline const char* toString_SnapshotSkipReason(SnapshotSkipReason reason) {
+    switch (reason) {
+        case SNAPSHOT_SKIP_UNKNOWN:
+            return "UNKNOWN";
+        case SNAPSHOT_SKIP_UNSUPPORTED_VK_APP:
+            return "UNSUPPORTED_VK_APP";
+        case SNAPSHOT_SKIP_UNSUPPORTED_VK_API:
+            return "UNSUPPORTED_VK_API";
+    }
+    return "UNKNOWN";
+}
+
 // C interface to expose Qemu implementations of common VM related operations.
 typedef struct QAndroidVmOperations {
     bool (*vmStop)(void);
@@ -258,6 +270,12 @@ typedef struct QAndroidVmOperations {
     // Reset the machine
     void (*system_shutdown_request)(QemuShutdownCause reason);
 
+    void (*vulkanInstanceRegister)(uint64_t id, const char* name);
+    void (*vulkanInstanceUnregister)(uint64_t id);
+    // get the list vk app id and name so we might be able to stop them
+    // before saving snapshot
+    void (*vulkanInstanceEnumerate)(uint32_t* pCount, uint64_t* pIds, char** pNames);
+
     // Set the reason to skip snapshotting on exit.
     void (*setSkipSnapshotSaveReason)(SnapshotSkipReason reason);
 
diff --git a/host-common/include/host-common/window_agent.h b/host-common/include/host-common/window_agent.h
index db95dbb..38d0d46 100644
--- a/host-common/include/host-common/window_agent.h
+++ b/host-common/include/host-common/window_agent.h
@@ -137,6 +137,29 @@ typedef struct QAndroidEmulatorWindowAgent {
 
     bool (*userSettingIsDontSaveSnapshot)(void);
     void (*setUserSettingIsDontSaveSnapshot)(bool);
+
+    // Sets the XR input mode.
+    bool (*setXrInputMode)(int);
+    // Sets the XR environment mode.
+    bool (*setXrEnvironmentMode)(int);
+    // Sets the XR screen recenter.
+    bool (*setXrScreenRecenter)();
+    // Sets the XR viewport control mode.
+    bool (*setXrViewportControlMode)(int);
+
+    // Sets the XR head rotation event.
+    bool (*sendXrHeadRotationEvent)(float x,float y, float z);
+    // Sets the XR head movement event.
+    bool (*sendXrHeadMovementEvent)(float delta_x, float delta_y, float delta_z);
+    // Sets the XR head angular velocity event.
+    bool (*sendXrHeadAngularVelocityEvent)(float omega_x, float omega_y, float omega_z);
+    // Sets the XR head velocity event.
+    bool (*sendXrHeadVelocityEvent)(float x, float y, float z);
+    // Sets the XR options.
+    bool (*setXrOptions)(int environment, float passthroughCoefficient);
+    // Gets the XR options.
+    bool (*getXrOptions)(int* environment, float* passthroughCoefficient);
+
 } QAndroidEmulatorWindowAgent;
 
 #ifndef USING_ANDROID_BP
diff --git a/host-common/testing/MockGraphicsAgentFactory.cpp b/host-common/testing/MockGraphicsAgentFactory.cpp
index e2922f5..c692cda 100644
--- a/host-common/testing/MockGraphicsAgentFactory.cpp
+++ b/host-common/testing/MockGraphicsAgentFactory.cpp
@@ -26,17 +26,17 @@ extern "C" const QAndroidMultiDisplayAgent* const
 namespace android {
 namespace emulation {
 
-const QAndroidVmOperations* const
+const QAndroidVmOperations*
 MockGraphicsAgentFactory::android_get_QAndroidVmOperations() const {
     return gMockQAndroidVmOperations;
 }
 
-const QAndroidMultiDisplayAgent* const
+const QAndroidMultiDisplayAgent*
 MockGraphicsAgentFactory::android_get_QAndroidMultiDisplayAgent() const {
     return gMockQAndroidMultiDisplayAgent;
 }
 
-const QAndroidEmulatorWindowAgent* const
+const QAndroidEmulatorWindowAgent*
 MockGraphicsAgentFactory::android_get_QAndroidEmulatorWindowAgent() const {
     return gMockQAndroidEmulatorWindowAgent;
 }
diff --git a/host-common/testing/MockGraphicsAgentFactory.h b/host-common/testing/MockGraphicsAgentFactory.h
index e47e4be..5781f6b 100644
--- a/host-common/testing/MockGraphicsAgentFactory.h
+++ b/host-common/testing/MockGraphicsAgentFactory.h
@@ -27,13 +27,13 @@ namespace emulation {
 // at the start of the unit tests.
 class MockGraphicsAgentFactory : public GraphicsAgentFactory {
 public:
-    const QAndroidVmOperations* const android_get_QAndroidVmOperations()
+    const QAndroidVmOperations* android_get_QAndroidVmOperations()
             const override;
 
-    const QAndroidMultiDisplayAgent* const
+    const QAndroidMultiDisplayAgent*
     android_get_QAndroidMultiDisplayAgent() const override;
 
-    const QAndroidEmulatorWindowAgent* const
+    const QAndroidEmulatorWindowAgent*
     android_get_QAndroidEmulatorWindowAgent() const override;
 
 
diff --git a/snapshot/BUILD.bazel b/snapshot/BUILD.bazel
index e55d245..40d81b3 100644
--- a/snapshot/BUILD.bazel
+++ b/snapshot/BUILD.bazel
@@ -1,7 +1,15 @@
+load("@rules_cc//cc:defs.bzl", "cc_library")
+
 # Interface library
 cc_library(
     name = "gfxstream-snapshot-headers",
-    hdrs = glob(["include/**/*.h"]),
+    hdrs = [
+        "include/snapshot/LazySnapshotObj.h",
+        "include/snapshot/TextureLoader.h",
+        "include/snapshot/TextureSaver.h",
+        "include/snapshot/common.h",
+        "include/snapshot/interface.h",
+    ],
     includes = ["include"],
     visibility = ["//visibility:public"],
 )
@@ -19,9 +27,10 @@ cc_library(
         "-Wno-extern-c-compat",
         "-Wno-return-type-c-linkage",
     ],
+    defines = ["dfatal=\"(void*)\""],
     visibility = ["//visibility:public"],
     deps = [
         ":gfxstream-snapshot-headers",
-        "//hardware/google/aemu/base:aemu-base-headers",
+        "//base:aemu-base-headers",
     ],
 )
diff --git a/windows/BUILD b/windows/BUILD
index db73f90..86b9dd9 100644
--- a/windows/BUILD
+++ b/windows/BUILD
@@ -1,3 +1,5 @@
+load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
+
 cc_library(
     name = "compat-hdrs",
     hdrs = glob(["includes/**/*.h"]),
@@ -6,18 +8,21 @@ cc_library(
         "includes",
         "includes/dirent",
     ],
+    target_compatible_with = [
+        "@platforms//os:windows",
+    ],
     visibility = ["//visibility:public"],
 )
 
 cc_library(
     name = "compat",
-    srcs =
-        glob([
-            "src/dirent/*.c",
-            "src/*.c",
-            "src/*.h",
-            "src/*.cpp",
-        ]),
+    srcs = [
+        "src/dirent/dirent.cpp",
+    ] + glob([
+        "src/*.c",
+        "src/*.h",
+        "src/*.cpp",
+    ]),
     defines = [
         "WIN32_LEAN_AND_MEAN",
     ],
@@ -32,6 +37,23 @@ cc_library(
         "-DEFAULTLIB:Winmm.lib",
     ],
     linkstatic = True,
+    target_compatible_with = [
+        "@platforms//os:windows",
+    ],
     visibility = ["//visibility:public"],
     deps = [":compat-hdrs"],
 )
+
+cc_test(
+    name = "dirent_test",
+    srcs = [
+        "tests/dirent_test.cpp",
+    ],
+    target_compatible_with = [
+        "@platforms//os:windows",
+    ],
+    deps = [
+        ":compat",
+        "@com_google_googletest//:gtest_main",
+    ],
+)
diff --git a/windows/includes/dirent/dirent.h b/windows/includes/dirent/dirent.h
index 81bad74..04e40a1 100644
--- a/windows/includes/dirent/dirent.h
+++ b/windows/includes/dirent/dirent.h
@@ -1,127 +1,191 @@
-/*
- * DIRENT.H (formerly DIRLIB.H)
- * This file has no copyright assigned and is placed in the Public Domain.
- * This file is a part of the mingw-runtime package.
- * No warranty is given; refer to the file DISCLAIMER within the package.
- *
- */
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
 #ifndef _AEMU_DIRENT_H_
 #define _AEMU_DIRENT_H_
 
-#include <stdio.h>
-#include <io.h>
-
-#ifndef RC_INVOKED
+#include <sys/types.h>
+#include <windows.h>
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-struct dirent
-{
-	long		d_ino;		/* Always zero. */
-	unsigned short	d_reclen;	/* Always zero. */
-	unsigned short	d_namlen;	/* Length of name in d_name. */
-	char		d_name[FILENAME_MAX+1]; /* File name plus nul delimiter. */
-};
-
-#ifdef _WIN64
-#define INTPTR __int64
-#else
-#define INTPTR long
-#endif
-
-/*
- * This is an internal data structure. Good programmers will not use it
- * except as an argument to one of the functions below.
- * dd_stat field is now int (was short in older versions).
+/**
+ * @file dirent.h
+ * @brief A POSIX-like dirent API implementation for Windows using the Windows API.
+ *
+ * This header provides a subset of the POSIX dirent API for Windows, allowing C and C++
+ * code to use familiar functions like opendir(), readdir(), closedir(), etc. to
+ * iterate through directory entries.
+ *
+ * @warning **Limitations:**
+ *   - **`telldir()` and `seekdir()` are minimally implemented.** `seekdir()` only supports
+ *     seeking to the beginning (loc = 0), the end (loc = -1), or forward to a specific entry
+ *     by its index (loc > 0). Seeking to arbitrary positions is implemented by iterating
+ *     through the entries, making it an **O(N)** operation in the worst case, where N is
+ *     the desired position. `telldir()` returns the index of the last entry read by `readdir()`.
+ *   - **`d_ino` is implemented using Windows file index.** It does not represent a
+ *     true POSIX inode number but can be used to identify files uniquely.
+ *   - **`d_reclen` is not supported.** The field is not present in this implementation.
+ *   - **Thread safety:** This implementation is not inherently thread-safe. Using the
+ *     same `DIR` pointer from multiple threads simultaneously can lead to undefined
+ *     behavior.
+ *
+ * @note **Windows-Specific Behavior:**
+ *   - Filenames are stored in `d_name` as **UTF-8** encoded strings.
+ *   - Extended-length paths (longer than `MAX_PATH`) are supported using the `\\?\` prefix.
+ *   - The implementation uses the Windows API (`FindFirstFileW`, `FindNextFileW`, etc.)
+ *     internally.
+ *   - The `DIR` type is an opaque pointer to an internal structure.
  */
-typedef struct
-{
-	/* disk transfer area for this dir */
-	struct _finddata_t	dd_dta;
-
-	/* dirent struct to return from dir (NOTE: this makes this thread
-	 * safe as long as only one thread uses a particular DIR struct at
-	 * a time) */
-	struct dirent		dd_dir;
-
-	/* _findnext handle */
-	INTPTR			dd_handle;
 
-	/*
-         * Status of search:
-	 *   0 = not started yet (next entry to read is first entry)
-	 *  -1 = off the end
-	 *   positive = 0 based index of next entry
-	 */
-	int			dd_stat;
-
-	/* given path for dir with search pattern (struct is extended) */
-	char			dd_name[1];
-} DIR;
-
-DIR* __cdecl opendir (const char*);
-struct dirent* __cdecl readdir (DIR*);
-int __cdecl closedir (DIR*);
-void __cdecl rewinddir (DIR*);
-long __cdecl telldir (DIR*);
-void __cdecl seekdir (DIR*, long);
-
-
-/* wide char versions */
+/**
+ * @brief The maximum length of a file name, including the null terminator.
+ *
+ * This is set to `MAX_PATH` (260) for compatibility but internally the implementation
+ * supports extended-length paths using the `\\?\` prefix.
+ */
+#define FILENAME_MAX MAX_PATH
 
-struct _wdirent
-{
-	long		d_ino;		/* Always zero. */
-	unsigned short	d_reclen;	/* Always zero. */
-	unsigned short	d_namlen;	/* Length of name in d_name. */
-	wchar_t		d_name[FILENAME_MAX+1]; /* File name plus nul delimiter. */
+/**
+ * @brief Represents a directory entry.
+ */
+struct dirent {
+    /**
+     * @brief File ID (from the Windows file index).
+     *
+     * This is not a true POSIX inode number but can be used as a unique file
+     * identifier on Windows. It is obtained using `GetFileInformationByHandle`
+     * and represents a file's unique ID within a volume.
+     * @warning This field might not be fully unique across different volumes or over time.
+     */
+    uint64_t d_ino;
+
+    /**
+     * @brief Null-terminated file name in UTF-8 encoding.
+     *
+     * @warning The maximum length of the filename (excluding the null terminator)
+     * that can be stored in this field is `FILENAME_MAX`. If a filename exceeds this
+     * limit, `readdir` will skip the entry and set `errno` to `ENAMETOOLONG`.
+     */
+    char d_name[FILENAME_MAX];
 };
 
-/*
- * This is an internal data structure. Good programmers will not use it
- * except as an argument to one of the functions below.
+/**
+ * @brief An opaque type representing a directory stream.
  */
-typedef struct
-{
-	/* disk transfer area for this dir */
-	struct _wfinddata_t	dd_dta;
-
-	/* dirent struct to return from dir (NOTE: this makes this thread
-	 * safe as long as only one thread uses a particular DIR struct at
-	 * a time) */
-	struct _wdirent		dd_dir;
-
-	/* _findnext handle */
-	INTPTR			dd_handle;
+typedef struct DIR DIR;
 
-	/*
-         * Status of search:
-	 *   0 = not started yet (next entry to read is first entry)
-	 *  -1 = off the end
-	 *   positive = 0 based index of next entry
-	 */
-	int			dd_stat;
 
-	/* given path for dir with search pattern (struct is extended) */
-	wchar_t			dd_name[1];
-} _WDIR;
+/**
+ * @brief Opens a directory stream for reading.
+ *
+ * @param name The path to the directory to open. This should be a UTF-8 encoded string.
+ *
+ * @return A pointer to a `DIR` structure representing the opened directory stream,
+ *         or `nullptr` if an error occurred. If `nullptr` is returned, `errno` is set
+ *         to indicate the error.
+ *
+ * @retval EACCES       Search permission is denied for the directory.
+ * @retval EMFILE       The maximum number of file descriptors are already open.
+ * @retval ENFILE       The maximum number of files are already open in the system.
+ * @retval ENOENT       The named directory does not exist or is an empty string.
+ * @retval ENOMEM       Insufficient memory is available.
+ * @retval ENOTDIR      A component of the path is not a directory.
+ * @retval EINVAL       The `name` argument is invalid (e.g., contains invalid characters).
+ */
+DIR* opendir(const char* name);
 
+/**
+ * @brief Reads the next directory entry from a directory stream.
+ *
+ * @param dirp A pointer to a `DIR` structure returned by `opendir()`.
+ *
+ * @return A pointer to a `dirent` structure representing the next directory entry,
+ *         or `nullptr` if the end of the directory stream is reached or an error
+ *         occurred. If `nullptr` is returned and `errno` is not 0, an error occurred.
+ *
+ * @retval EBADF      The `dirp` argument does not refer to an open directory stream.
+ * @retval ENOMEM     Insufficient memory is available.
+ * @retval ENOENT     No more directory entries.
+ * @retval EIO        An I/O error occurred.
+ * @retval ENAMETOOLONG A filename exceeded `FILENAME_MAX`.
+ */
+struct dirent* readdir(DIR* dirp);
 
+/**
+ * @brief Closes a directory stream.
+ *
+ * @param dirp A pointer to a `DIR` structure returned by `opendir()`.
+ *
+ * @return 0 on success, -1 on failure. If -1 is returned, `errno` is set to
+ *         indicate the error.
+ *
+ * @retval EBADF      The `dirp` argument does not refer to an open directory stream.
+ */
+int closedir(DIR* dirp);
 
-_WDIR* __cdecl _wopendir (const wchar_t*);
-struct _wdirent*  __cdecl _wreaddir (_WDIR*);
-int __cdecl _wclosedir (_WDIR*);
-void __cdecl _wrewinddir (_WDIR*);
-long __cdecl _wtelldir (_WDIR*);
-void __cdecl _wseekdir (_WDIR*, long);
+/**
+ * @brief Resets the position of a directory stream to the beginning.
+ *
+ * @param dirp A pointer to a `DIR` structure returned by `opendir()`.
+ *
+ * @retval EBADF      The `dirp` argument does not refer to an open directory stream.
+ * @retval EIO        An I/O error occurred.
+ */
+void rewinddir(DIR* dirp);
+/**
+ * @brief Gets the current position of a directory stream.
+ *
+ * @param dirp A pointer to a `DIR` structure returned by `opendir()`.
+ *
+ * @return The current position of the directory stream. This is the index of the last
+ *         entry read by `readdir()`. Returns -1 if at the end of the directory stream.
+ *         If -1 is returned and `errno` is not 0, an error occurred.
+ *
+ * @retval EBADF The `dirp` argument does not refer to an open directory stream.
+ *
+ * @note   The position returned by `telldir()` is an opaque value that should only be
+ *         used in conjunction with `seekdir()`.
+ */
+long telldir(DIR* dirp);
 
+/**
+ * @brief Sets the position of a directory stream.
+ *
+ * @param dirp A pointer to a `DIR` structure returned by `opendir()`.
+ * @param loc  The new position of the directory stream. The following values are supported:
+ *             - **0:** Seek to the beginning of the stream (equivalent to `rewinddir()`).
+ *             - **-1:** Seek to the end of the stream.
+ *             - **\>0:** Seek to a specific entry by its index (the value returned by `telldir()`).
+ *
+ * @retval EBADF      The `dirp` argument does not refer to an open directory stream.
+ * @retval EINVAL     The `loc` argument is invalid (e.g., negative value other than -1, or a
+ *                     value that is greater than the number of entries in the directory).
+ *
+ * @note   Seeking to arbitrary positions (other than the beginning or end) is implemented
+ *         by rewinding the directory stream and then calling `readdir()` repeatedly until
+ *         the desired position is reached.
+ * @note   **Time Complexity:**
+ *         - O(1) for `loc = 0` (rewind) and `loc = -1` (seek to end).
+ *         - O(N) for `loc > 0`, where N is the position being sought to. In the worst case,
+ *           seeking to the end of a large directory can be a slow operation.
+ */
+void seekdir(DIR* dirp, long loc);
 
-#ifdef	__cplusplus
+#ifdef __cplusplus
 }
 #endif
 
-#endif	/* Not RC_INVOKED */
-
-#endif	/* Not _AEMU_DIRENT_H_ */
+#endif	/* Not _AEMU_DIRENT_H_ */
\ No newline at end of file
diff --git a/windows/src/dirent/dirent.c b/windows/src/dirent/dirent.c
deleted file mode 100644
index d9200f9..0000000
--- a/windows/src/dirent/dirent.c
+++ /dev/null
@@ -1,341 +0,0 @@
-/*
- * dirent.c
- * This file has no copyright assigned and is placed in the Public Domain.
- * This file is a part of the mingw-runtime package.
- * No warranty is given; refer to the file DISCLAIMER within the package.
- *
- * Derived from DIRLIB.C by Matt J. Weinstein
- * This note appears in the DIRLIB.H
- * DIRLIB.H by M. J. Weinstein   Released to public domain 1-Jan-89
- *
- * Updated by Jeremy Bettis <jeremy@hksys.com>
- * Significantly revised and rewinddir, seekdir and telldir added by Colin
- * Peters <colin@fu.is.saga-u.ac.jp>
- *	
- */
-
-#include <stdlib.h>
-#include <errno.h>
-#include <string.h>
-#include <io.h>
-#include <direct.h>
-
-#include "dirent.h"
-
-#define WIN32_LEAN_AND_MEAN
-#include <windows.h> /* for GetFileAttributes */
-
-#include <tchar.h>
-
-#ifdef _UNICODE
-#define _tdirent	_wdirent
-#define _TDIR 		_WDIR
-#define _topendir	_wopendir
-#define _tclosedir	_wclosedir
-#define _treaddir	_wreaddir
-#define _trewinddir	_wrewinddir
-#define _ttelldir	_wtelldir
-#define _tseekdir	_wseekdir
-#else
-#define _tdirent	dirent
-#define _TDIR 		DIR
-#define _topendir	opendir
-#define _tclosedir	closedir
-#define _treaddir	readdir
-#define _trewinddir	rewinddir
-#define _ttelldir	telldir
-#define _tseekdir	seekdir
-#endif
-
-#define SUFFIX	_T("*")
-#define	SLASH	_T("\\")
-
-
-/*
- * opendir
- *
- * Returns a pointer to a DIR structure appropriately filled in to begin
- * searching a directory.
- */
-_TDIR *
-_topendir (const _TCHAR *szPath)
-{
-  _TDIR *nd;
-  unsigned int rc;
-  _TCHAR szFullPath[MAX_PATH];
-	
-  errno = 0;
-
-  if (!szPath)
-    {
-      errno = EFAULT;
-      return (_TDIR *) 0;
-    }
-
-  if (szPath[0] == _T('\0'))
-    {
-      errno = ENOTDIR;
-      return (_TDIR *) 0;
-    }
-
-  /* Attempt to determine if the given path really is a directory. */
-  rc = GetFileAttributes (szPath);
-  if (rc == (unsigned int)-1)
-    {
-      /* call GetLastError for more error info */
-      errno = ENOENT;
-      return (_TDIR *) 0;
-    }
-  if (!(rc & FILE_ATTRIBUTE_DIRECTORY))
-    {
-      /* Error, entry exists but not a directory. */
-      errno = ENOTDIR;
-      return (_TDIR *) 0;
-    }
-
-  /* Make an absolute pathname.  */
-  _tfullpath (szFullPath, szPath, MAX_PATH);
-
-  /* Allocate enough space to store DIR structure and the complete
-   * directory path given. */
-  nd = (_TDIR *) malloc (sizeof (_TDIR) + (_tcslen(szFullPath) + _tcslen (SLASH) +
-			 _tcslen(SUFFIX) + 1) * sizeof(_TCHAR));
-
-  if (!nd)
-    {
-      /* Error, out of memory. */
-      errno = ENOMEM;
-      return (_TDIR *) 0;
-    }
-
-  /* Create the search expression. */
-  _tcscpy (nd->dd_name, szFullPath);
-
-  /* Add on a slash if the path does not end with one. */
-  if (nd->dd_name[0] != _T('\0') &&
-      nd->dd_name[_tcslen (nd->dd_name) - 1] != _T('/') &&
-      nd->dd_name[_tcslen (nd->dd_name) - 1] != _T('\\'))
-    {
-      _tcscat (nd->dd_name, SLASH);
-    }
-
-  /* Add on the search pattern */
-  _tcscat (nd->dd_name, SUFFIX);
-
-  /* Initialize handle to -1 so that a premature closedir doesn't try
-   * to call _findclose on it. */
-  nd->dd_handle = -1;
-
-  /* Initialize the status. */
-  nd->dd_stat = 0;
-
-  /* Initialize the dirent structure. ino and reclen are invalid under
-   * Win32, and name simply points at the appropriate part of the
-   * findfirst_t structure. */
-  nd->dd_dir.d_ino = 0;
-  nd->dd_dir.d_reclen = 0;
-  nd->dd_dir.d_namlen = 0;
-  memset (nd->dd_dir.d_name, 0, sizeof (nd->dd_dir.d_name));
-
-  return nd;
-}
-
-
-/*
- * readdir
- *
- * Return a pointer to a dirent structure filled with the information on the
- * next entry in the directory.
- */
-struct _tdirent *
-_treaddir (_TDIR * dirp)
-{
-  errno = 0;
-
-  /* Check for valid DIR struct. */
-  if (!dirp)
-    {
-      errno = EFAULT;
-      return (struct _tdirent *) 0;
-    }
-
-  if (dirp->dd_stat < 0)
-    {
-      /* We have already returned all files in the directory
-       * (or the structure has an invalid dd_stat). */
-      return (struct _tdirent *) 0;
-    }
-  else if (dirp->dd_stat == 0)
-    {
-      /* We haven't started the search yet. */
-      /* Start the search */
-      dirp->dd_handle = _tfindfirst (dirp->dd_name, &(dirp->dd_dta));
-
-  	  if (dirp->dd_handle == -1)
-	{
-	  /* Whoops! Seems there are no files in that
-	   * directory. */
-	  dirp->dd_stat = -1;
-	}
-      else
-	{
-	  dirp->dd_stat = 1;
-	}
-    }
-  else
-    {
-      /* Get the next search entry. */
-      if (_tfindnext (dirp->dd_handle, &(dirp->dd_dta)))
-	{
-	  /* We are off the end or otherwise error.	
-	     _findnext sets errno to ENOENT if no more file
-	     Undo this. */
-	  DWORD winerr = GetLastError();
-	  if (winerr == ERROR_NO_MORE_FILES)
-	    errno = 0;	
-	  _findclose (dirp->dd_handle);
-	  dirp->dd_handle = -1;
-	  dirp->dd_stat = -1;
-	}
-      else
-	{
-	  /* Update the status to indicate the correct
-	   * number. */
-	  dirp->dd_stat++;
-	}
-    }
-
-  if (dirp->dd_stat > 0)
-    {
-      /* Successfully got an entry. Everything about the file is
-       * already appropriately filled in except the length of the
-       * file name. */
-      dirp->dd_dir.d_namlen = _tcslen (dirp->dd_dta.name);
-      _tcscpy (dirp->dd_dir.d_name, dirp->dd_dta.name);
-      return &dirp->dd_dir;
-    }
-
-  return (struct _tdirent *) 0;
-}
-
-
-/*
- * closedir
- *
- * Frees up resources allocated by opendir.
- */
-int
-_tclosedir (_TDIR * dirp)
-{
-  int rc;
-
-  errno = 0;
-  rc = 0;
-
-  if (!dirp)
-    {
-      errno = EFAULT;
-      return -1;
-    }
-
-  if (dirp->dd_handle != -1)
-    {
-      rc = _findclose (dirp->dd_handle);
-    }
-
-  /* Delete the dir structure. */
-  free (dirp);
-
-  return rc;
-}
-
-/*
- * rewinddir
- *
- * Return to the beginning of the directory "stream". We simply call findclose
- * and then reset things like an opendir.
- */
-void
-_trewinddir (_TDIR * dirp)
-{
-  errno = 0;
-
-  if (!dirp)
-    {
-      errno = EFAULT;
-      return;
-    }
-
-  if (dirp->dd_handle != -1)
-    {
-      _findclose (dirp->dd_handle);
-    }
-
-  dirp->dd_handle = -1;
-  dirp->dd_stat = 0;
-}
-
-/*
- * telldir
- *
- * Returns the "position" in the "directory stream" which can be used with
- * seekdir to go back to an old entry. We simply return the value in stat.
- */
-long
-_ttelldir (_TDIR * dirp)
-{
-  errno = 0;
-
-  if (!dirp)
-    {
-      errno = EFAULT;
-      return -1;
-    }
-  return dirp->dd_stat;
-}
-
-/*
- * seekdir
- *
- * Seek to an entry previously returned by telldir. We rewind the directory
- * and call readdir repeatedly until either dd_stat is the position number
- * or -1 (off the end). This is not perfect, in that the directory may
- * have changed while we weren't looking. But that is probably the case with
- * any such system.
- */
-void
-_tseekdir (_TDIR * dirp, long lPos)
-{
-  errno = 0;
-
-  if (!dirp)
-    {
-      errno = EFAULT;
-      return;
-    }
-
-  if (lPos < -1)
-    {
-      /* Seeking to an invalid position. */
-      errno = EINVAL;
-      return;
-    }
-  else if (lPos == -1)
-    {
-      /* Seek past end. */
-      if (dirp->dd_handle != -1)
-	{
-	  _findclose (dirp->dd_handle);
-	}
-      dirp->dd_handle = -1;
-      dirp->dd_stat = -1;
-    }
-  else
-    {
-      /* Rewind and read forward to the appropriate index. */
-      _trewinddir (dirp);
-
-      while ((dirp->dd_stat < lPos) && _treaddir (dirp))
-	;
-    }
-}
diff --git a/windows/src/dirent/dirent.cpp b/windows/src/dirent/dirent.cpp
new file mode 100644
index 0000000..56e7d79
--- /dev/null
+++ b/windows/src/dirent/dirent.cpp
@@ -0,0 +1,361 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+// Implementation file (dirent.cpp)
+#include "dirent.h"
+
+#include <errno.h>
+#include <windows.h>
+
+#include <algorithm>
+#include <codecvt>
+#include <locale>
+#include <memory>
+#include <string>
+
+namespace {
+
+using file_index_t = uint64_t;
+
+using DereferencedHandle = std::remove_pointer_t<HANDLE>;
+struct HandleCloser {
+    void operator()(HANDLE h) const {
+        if (h != INVALID_HANDLE_VALUE) {
+            ::CloseHandle(h);
+        }
+    }
+};
+
+using UniqueHandle = std::unique_ptr<DereferencedHandle, HandleCloser>;
+
+// Translates Windows error codes to errno values
+int translate_windows_error_to_errno(DWORD errorCode) {
+    switch (errorCode) {
+        case ERROR_SUCCESS:
+            return 0;
+        case ERROR_FILE_NOT_FOUND:
+        case ERROR_PATH_NOT_FOUND:
+            return ENOENT;
+        case ERROR_ACCESS_DENIED:
+            return EACCES;
+        case ERROR_ALREADY_EXISTS:
+        case ERROR_FILE_EXISTS:
+            return EEXIST;
+        case ERROR_INVALID_PARAMETER:
+        case ERROR_INVALID_NAME:
+            return EINVAL;
+        case ERROR_NOT_ENOUGH_MEMORY:
+        case ERROR_OUTOFMEMORY:
+            return ENOMEM;
+        case ERROR_WRITE_PROTECT:
+            return EROFS;
+        case ERROR_HANDLE_EOF:
+            return EPIPE;
+        case ERROR_HANDLE_DISK_FULL:
+        case ERROR_DISK_FULL:
+            return ENOSPC;
+        case ERROR_NOT_SUPPORTED:
+            return ENOTSUP;
+        case ERROR_DIRECTORY:
+            return ENOTDIR;
+        case ERROR_DIR_NOT_EMPTY:
+            return ENOTEMPTY;
+        case ERROR_BAD_PATHNAME:
+            return ENOENT;
+        case ERROR_OPERATION_ABORTED:
+            return EINTR;
+        case ERROR_INVALID_HANDLE:
+            return EBADF;
+        case ERROR_FILENAME_EXCED_RANGE:
+        case ERROR_CANT_RESOLVE_FILENAME:
+            return ENAMETOOLONG;
+        case ERROR_DEV_NOT_EXIST:
+            return ENODEV;
+        case ERROR_TOO_MANY_OPEN_FILES:
+            return EMFILE;
+        default:
+            return EIO;
+    }
+}
+
+// Get file index information
+file_index_t get_file_index(const std::wstring& path) {
+    UniqueHandle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
+                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
+                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
+
+    if (file.get() == INVALID_HANDLE_VALUE) {
+        return 0;
+    }
+
+    BY_HANDLE_FILE_INFORMATION info;
+    if (!GetFileInformationByHandle(file.get(), &info)) {
+        return 0;
+    }
+
+    return (static_cast<file_index_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
+}
+
+// Convert UTF-8 to wide string
+std::wstring utf8_to_wide(const std::string& input) {
+    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
+    return converter.from_bytes(input);
+}
+
+// Convert wide string to UTF-8
+std::string wide_to_utf8(const std::wstring& input) {
+    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
+    return converter.to_bytes(input);
+}
+
+// Prepare directory path for Windows API
+std::wstring prepare_dir_path(const std::wstring& path) {
+    // Check if path already has extended-length prefix
+    if (path.rfind(L"\\\\?\\", 0) == 0) {
+        return path;
+    }
+
+    // Add extended-length prefix
+    return L"\\\\?\\" + path;
+}
+
+// Create search path with wildcard
+std::wstring create_search_path(const std::wstring& dir_path) {
+    std::wstring search_path = dir_path;
+    if (!search_path.empty() && search_path.back() != L'\\') {
+        search_path += L"\\";
+    }
+    search_path += L"*";
+    return search_path;
+}
+
+}  // namespace
+
+// Internal DIR structure (hidden from users)
+struct InternalDir {
+    HANDLE handle;
+    WIN32_FIND_DATAW find_data;
+    dirent entry;
+    std::wstring path;         // Original path (wide)
+    std::wstring search_path;  // Search path with pattern
+    bool first;
+    bool end_reached;
+    long current_position;  // Current position in the directory
+
+    // Constructor
+    InternalDir()
+        : handle(INVALID_HANDLE_VALUE), first(true), end_reached(false), current_position(0) {
+        memset(&entry, 0, sizeof(dirent));
+    }
+
+    // Destructor
+    ~InternalDir() {
+        if (handle != INVALID_HANDLE_VALUE) {
+            FindClose(handle);
+        }
+    }
+
+   private:
+    // Prevent copying and assignment to maintain unique ownership
+    InternalDir(const InternalDir&) = delete;
+    InternalDir& operator=(const InternalDir&) = delete;
+};
+
+// Opaque DIR type (declared in header)
+struct DIR {
+    std::unique_ptr<InternalDir> pImpl;  // std::unique_ptr to hold the internal structure
+
+    DIR() : pImpl(std::make_unique<InternalDir>()) {}
+
+   private:
+    // Prevent copying and assignment to maintain unique ownership
+    DIR(const DIR&) = delete;
+    DIR& operator=(const DIR&) = delete;
+};
+
+DIR* opendir(const char* name) {
+    if (!name) {
+        errno = EINVAL;
+        return nullptr;
+    }
+
+    // Convert to wide string
+    std::wstring wide_path = utf8_to_wide(name);
+    if (wide_path.empty() && !std::string(name).empty()) {
+        errno = EINVAL;
+        return nullptr;
+    }
+
+    // Check if path exists and is a directory
+    DWORD attrs = GetFileAttributesW(wide_path.c_str());
+    if (attrs == INVALID_FILE_ATTRIBUTES) {
+        errno = translate_windows_error_to_errno(GetLastError());
+        return nullptr;
+    }
+
+    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
+        errno = ENOTDIR;
+        return nullptr;
+    }
+
+    // Prepare directory path
+    std::wstring dir_path = prepare_dir_path(wide_path);
+
+    // Create search path
+    std::wstring search_path = create_search_path(dir_path);
+
+    // Allocate and initialize DIR structure using unique_ptr
+    std::unique_ptr<DIR> dir = std::make_unique<DIR>();
+    if (!dir) {
+        errno = ENOMEM;
+        return nullptr;
+    }
+
+    // Initialize InternalDir structure
+    dir->pImpl->handle = FindFirstFileW(search_path.c_str(), &dir->pImpl->find_data);
+    if (dir->pImpl->handle == INVALID_HANDLE_VALUE) {
+        errno = translate_windows_error_to_errno(GetLastError());
+        return nullptr;
+    }
+
+    dir->pImpl->path = dir_path;
+    dir->pImpl->search_path = search_path;
+    dir->pImpl->first = true;
+    dir->pImpl->end_reached = false;
+
+    return dir.release();  // Release ownership to the caller
+}
+
+struct dirent* readdir(DIR* dirp) {
+    if (!dirp) {
+        errno = EBADF;
+        return nullptr;
+    }
+
+    if (dirp->pImpl->end_reached) {
+        return nullptr;
+    }
+
+    while (true) {
+        if (!dirp->pImpl->first && !FindNextFileW(dirp->pImpl->handle, &dirp->pImpl->find_data)) {
+            DWORD lastError = GetLastError();
+            if (lastError == ERROR_NO_MORE_FILES) {
+                dirp->pImpl->end_reached = true;
+                return nullptr;
+            } else {
+                errno = translate_windows_error_to_errno(lastError);
+                return nullptr;
+            }
+        }
+        dirp->pImpl->first = false;
+
+        // Skip "." and ".." entries
+        if (wcscmp(dirp->pImpl->find_data.cFileName, L".") == 0 ||
+            wcscmp(dirp->pImpl->find_data.cFileName, L"..") == 0) {
+            continue;
+        }
+
+        // Convert filename to UTF-8
+        std::string utf8_filename = wide_to_utf8(dirp->pImpl->find_data.cFileName);
+        if (utf8_filename.empty() && !std::wstring(dirp->pImpl->find_data.cFileName).empty()) {
+            errno = ENAMETOOLONG;
+            return nullptr;
+        }
+
+        // Copy filename to dirent structure, with bounds checking
+        if (utf8_filename.length() >= sizeof(dirp->pImpl->entry.d_name)) {
+            errno = ENAMETOOLONG;
+            return nullptr;
+        }
+        strcpy(dirp->pImpl->entry.d_name, utf8_filename.c_str());
+
+        // Get full path for the current file
+        std::wstring fullPath = dirp->pImpl->path + L"\\" + dirp->pImpl->find_data.cFileName;
+
+        // Get file index information
+        dirp->pImpl->entry.d_ino = get_file_index(fullPath);
+
+        // Increment position after successfully reading an entry
+        dirp->pImpl->current_position++;
+
+        return &dirp->pImpl->entry;
+    }
+}
+
+int closedir(DIR* dirp) {
+    if (!dirp) {
+        errno = EBADF;
+        return -1;
+    }
+
+    // Destructor of unique_ptr<InternalDir> will be called automatically,
+    // releasing resources held by InternalDir.
+
+    delete dirp;  // Release memory held by DIR
+    return 0;
+}
+
+void rewinddir(DIR* dirp) {
+    if (!dirp) {
+        errno = EBADF;
+        return;
+    }
+
+    if (dirp->pImpl->handle != INVALID_HANDLE_VALUE) {
+        FindClose(dirp->pImpl->handle);
+    }
+
+    dirp->pImpl->handle = FindFirstFileW(dirp->pImpl->search_path.c_str(), &dirp->pImpl->find_data);
+    if (dirp->pImpl->handle == INVALID_HANDLE_VALUE) {
+        errno = translate_windows_error_to_errno(GetLastError());
+        return;
+    }
+    dirp->pImpl->first = true;
+    dirp->pImpl->end_reached = false;
+    dirp->pImpl->current_position = 0;  // Reset position
+}
+
+long telldir(DIR* dirp) {
+    if (!dirp) {
+        errno = EBADF;
+        return -1;
+    }
+    return dirp->pImpl->end_reached ? -1 : dirp->pImpl->current_position;
+}
+
+void seekdir(DIR* dirp, long loc) {
+    if (!dirp) {
+        errno = EBADF;
+        return;
+    }
+
+    if (loc == 0) {
+        rewinddir(dirp);
+    } else if (loc == -1) {
+        // Seeking to the end is equivalent to reading until the end
+        while (readdir(dirp) != nullptr);
+    } else if (loc > 0) {
+        // Seek forward to a specific position
+        rewinddir(dirp);  // Start from the beginning
+        for (long i = 0; i < loc; ++i) {
+            if (readdir(dirp) == nullptr) {
+                // Reached the end before the desired position
+                errno = EINVAL;
+                return;
+            }
+        }
+    } else {
+        errno = EINVAL;  // Negative positions other than -1 are not supported
+        return;
+    }
+}
\ No newline at end of file
diff --git a/windows/tests/dirent_test.cpp b/windows/tests/dirent_test.cpp
new file mode 100644
index 0000000..27254c3
--- /dev/null
+++ b/windows/tests/dirent_test.cpp
@@ -0,0 +1,318 @@
+#include <gtest/gtest.h>
+
+#include "dirent.h"
+
+#include <codecvt>
+#include <filesystem>
+#include <fstream>
+#include <locale>
+#include <random>
+
+namespace fs = std::filesystem;
+
+// Helper function to create a directory with a specific name
+void createDirectory(const fs::path& dirName) { fs::create_directories(dirName); }
+
+// Helper function to create a file with a specific name
+void createFile(const fs::path& filename) {
+    std::ofstream file(filename);
+    file.close();
+}
+
+// Helper function to convert UTF-8 to wide string
+std::wstring utf8ToWide(const std::string& utf8Str) {
+    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
+    return converter.from_bytes(utf8Str);
+}
+
+// Helper function to convert wide string to UTF-8
+std::string wideToUtf8(const std::wstring& wideStr) {
+    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
+    return converter.to_bytes(wideStr);
+}
+
+class DirentTest : public ::testing::Test {
+   protected:
+    // Setup - create a temporary directory for testing
+    void SetUp() override {
+        // Generate a random directory name
+        std::random_device rd;
+        std::mt19937 gen(rd());
+        std::uniform_int_distribution<> dist(0, 15);  // For hex characters
+
+        std::string randomDirName = "dirent_test_";
+        for (int i = 0; i < 8; ++i) {
+            randomDirName += "0123456789abcdef"[dist(gen)];
+        }
+
+        tempDir = fs::temp_directory_path() / randomDirName;
+        fs::create_directories(tempDir);
+    }
+
+    // Teardown - remove the temporary directory
+    void TearDown() override {
+        try {
+            fs::remove_all(tempDir);
+        } catch (const fs::filesystem_error& e) {
+            std::cerr << "Warning failed to remove directory: " << e.what() << std::endl;
+        }
+    }
+
+    fs::path tempDir;
+};
+
+// Test opendir with an invalid directory name
+TEST_F(DirentTest, OpenDirInvalid) {
+    DIR* dir = opendir("invalid_dir");
+    ASSERT_EQ(nullptr, dir);
+    ASSERT_EQ(ENOENT, errno);
+}
+
+// Test opendir with a valid directory name
+TEST_F(DirentTest, OpenDirValid) {
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+    closedir(dir);
+}
+
+// Test readdir with an empty directory
+TEST_F(DirentTest, ReadDirEmpty) {
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+    struct dirent* entry = readdir(dir);
+    ASSERT_EQ(nullptr, entry);
+    closedir(dir);
+}
+
+// Test readdir with some files
+TEST_F(DirentTest, ReadDirBasic) {
+    createFile(tempDir / "file1.txt");
+    createFile(tempDir / "file2.txt");
+
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+
+    struct dirent* entry;
+    int count = 0;
+    while ((entry = readdir(dir)) != nullptr) {
+        ASSERT_TRUE(strcmp(entry->d_name, "file1.txt") == 0 ||
+                    strcmp(entry->d_name, "file2.txt") == 0);
+        count++;
+    }
+    ASSERT_EQ(2, count);
+
+    closedir(dir);
+}
+
+// Test readdir with UTF-8 filenames
+TEST_F(DirentTest, ReadDirUtf8) {
+    std::wstring filename = L"hiফাইলhi.txt";
+
+    // We expect a utf8 filename..
+    std::string filenameu8 = wideToUtf8(filename); // u8"hiফাইলhi.txt";
+    createFile(tempDir / filename);
+
+    ASSERT_TRUE(fs::exists(tempDir / filename));
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+
+    struct dirent* entry = readdir(dir);
+    ASSERT_NE(nullptr, entry);
+    ASSERT_EQ(filenameu8, entry->d_name);
+
+    closedir(dir);
+}
+
+// Test rewinddir
+TEST_F(DirentTest, RewindDir) {
+    createFile(tempDir / "file1.txt");
+    createFile(tempDir / "file2.txt");
+
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+
+    // Read the first entry
+    struct dirent* entry1 = readdir(dir);
+    ASSERT_NE(nullptr, entry1);
+
+    // Rewind the directory
+    rewinddir(dir);
+
+    // Read the first entry again
+    struct dirent* entry2 = readdir(dir);
+    ASSERT_NE(nullptr, entry2);
+    ASSERT_STREQ(entry1->d_name, entry2->d_name);
+
+    closedir(dir);
+}
+
+// Test telldir/seekdir (limited functionality)
+TEST_F(DirentTest, TellSeekDir) {
+    createFile(tempDir / "file1.txt");
+    createFile(tempDir / "file2.txt");
+    createFile(tempDir / "file3.txt");
+
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+
+    // Get initial position (should be 0)
+    long initialPos = telldir(dir);
+    ASSERT_EQ(0, initialPos);
+
+    // Read the first entry
+    struct dirent* entry1 = readdir(dir);
+    ASSERT_NE(nullptr, entry1);
+
+    // Get position (should be 1 now)
+    long pos1 = telldir(dir);
+    ASSERT_EQ(1, pos1);
+
+    // Read the second entry
+    struct dirent* entry2 = readdir(dir);
+    ASSERT_NE(nullptr, entry2);
+
+    // Get position (should be 2 now)
+    long pos2 = telldir(dir);
+    ASSERT_EQ(2, pos2);
+
+    // Seek to beginning
+    seekdir(dir, 0);
+    long currentPos = telldir(dir);
+    ASSERT_EQ(0, currentPos);
+
+    // Verify we can read again from the beginning
+    struct dirent* entry3 = readdir(dir);
+    ASSERT_NE(nullptr, entry3);
+    ASSERT_STREQ(entry1->d_name, entry3->d_name);
+
+    // Seek to position 1
+    seekdir(dir, 1);
+    currentPos = telldir(dir);
+    ASSERT_EQ(1, currentPos);
+
+    // Verify we can read the second entry again
+    struct dirent* entry4 = readdir(dir);
+    ASSERT_NE(nullptr, entry4);
+    ASSERT_STREQ(entry2->d_name, entry4->d_name);
+
+    // Seek to end
+    seekdir(dir, -1);
+    currentPos = telldir(dir);
+    ASSERT_EQ(-1, currentPos);
+
+    // Check that readdir returns nullptr after seekdir(-1)
+    struct dirent* entry5 = readdir(dir);
+    ASSERT_EQ(nullptr, entry5);
+
+    // Seek to position 2
+    seekdir(dir, 2);
+    currentPos = telldir(dir);
+    ASSERT_EQ(2, currentPos);
+
+    // Read the third entry
+    struct dirent* entry6 = readdir(dir);
+    ASSERT_NE(nullptr, entry6);
+    ASSERT_STREQ("file3.txt", entry6->d_name);
+
+    // Try seeking beyond the end
+    seekdir(dir, 10);
+    currentPos = telldir(dir);
+    ASSERT_EQ(errno, EINVAL); // Bad!
+
+    // Verify that readdir returns nullptr
+    struct dirent* entry7 = readdir(dir);
+    ASSERT_EQ(nullptr, entry7);
+
+    closedir(dir);
+}
+
+// Test closedir
+TEST_F(DirentTest, CloseDir) {
+    DIR* dir = opendir(tempDir.string().c_str());
+    ASSERT_NE(nullptr, dir);
+    int result = closedir(dir);
+    ASSERT_EQ(0, result);
+}
+
+// Test extended path
+TEST_F(DirentTest, ExtendedPath) {
+    // Create a path that exceeds MAX_PATH
+    std::wstring longDirName = L"\\\\?\\" + tempDir.wstring() + L"\\long_directory_name";
+    for (int i = 0; i < 30; ++i) {
+        longDirName += L"\\subdir";
+    }
+
+    // Create the long directory structure
+    ASSERT_TRUE(fs::create_directories(longDirName));
+
+    // Create a file within the long directory
+    std::wstring longFileName = longDirName + L"\\file.txt";
+    std::ofstream file(longFileName);
+    ASSERT_TRUE(file.is_open());
+    file.close();
+
+    // Convert to UTF-8 for opendir
+    std::string longDirNameUtf8 = wideToUtf8(longDirName);
+
+    // Open the directory using opendir
+    DIR* dir = opendir(longDirNameUtf8.c_str());
+    ASSERT_NE(nullptr, dir);
+
+    // Read directory entries
+    struct dirent* entry;
+    bool found = false;
+    while ((entry = readdir(dir)) != nullptr) {
+        if (strcmp(entry->d_name, "file.txt") == 0) {
+            found = true;
+            break;
+        }
+    }
+
+    // Check if the file was found
+    ASSERT_TRUE(found);
+
+    // Close the directory
+    closedir(dir);
+
+    // Cleanup
+    fs::remove(longFileName);
+    ASSERT_FALSE(fs::exists(longFileName));
+}
+
+// Test various error conditions
+TEST_F(DirentTest, ErrorConditions) {
+    // Invalid directory name
+    DIR* dir = opendir(nullptr);
+    ASSERT_EQ(nullptr, dir);
+    ASSERT_EQ(EINVAL, errno);
+
+    // Directory not found
+    dir = opendir("nonexistent_directory");
+    ASSERT_EQ(nullptr, dir);
+    ASSERT_EQ(ENOENT, errno);
+
+    // Not a directory
+    createFile(tempDir / "file.txt");
+    dir = opendir((tempDir / "file.txt").c_str());
+    ASSERT_EQ(nullptr, dir);
+    ASSERT_EQ(ENOTDIR, errno);
+
+    // Invalid DIR pointer
+    struct dirent* entry = readdir(nullptr);
+    ASSERT_EQ(nullptr, entry);
+    ASSERT_EQ(EBADF, errno);
+
+    int result = closedir(nullptr);
+    ASSERT_EQ(-1, result);
+    ASSERT_EQ(EBADF, errno);
+
+    rewinddir(nullptr);
+    ASSERT_EQ(EBADF, errno);
+
+    seekdir(nullptr, 0);
+    ASSERT_EQ(EBADF, errno);
+
+    long pos = telldir(nullptr);
+    ASSERT_EQ(-1, pos);
+    ASSERT_EQ(EBADF, errno);
+}
\ No newline at end of file
```

