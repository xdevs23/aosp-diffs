```diff
diff --git a/Android.bp b/Android.bp
index f579940..25c25a7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -35,7 +35,6 @@ cc_library_headers {
         ".",
         "base/include",
         "host-common/include",
-        "snapshot/include",
         "third-party/cuda/include",
     ],
     apex_available: [
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 7485f08..c3dcebb 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -14,10 +14,8 @@ option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
 
 if (AEMU_COMMON_GEN_PKGCONFIG)
    set(LOGGING_LIB_NAME aemu-logging)
-   set(SNAPSHOT_LIB_NAME aemu-snapshot)
 else()
    set(LOGGING_LIB_NAME logging-base)
-   set(SNAPSHOT_LIB_NAME gfxstream-snapshot)
 endif()
 
 project(AEMUCommon
@@ -74,7 +72,6 @@ endif()
 set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-extern-c-compat -Wno-return-type-c-linkage -D_FILE_OFFSET_BITS=64")
 
 add_subdirectory(base)
-add_subdirectory(snapshot)
 add_subdirectory(host-common)
 add_subdirectory(third-party)
 
@@ -93,8 +90,7 @@ if(AEMU_COMMON_GEN_PKGCONFIG)
     set(INSTALL_PC_FILES
         aemu_base
         aemu_logging
-        aemu_host_common
-        aemu_snapshot)
+        aemu_host_common)
     if(ENABLE_VKCEREAL_TESTS)
         list(APPEND INSTALL_PC_FILES aemu_base_testing_support aemu_host_common_testing_support)
     endif()
@@ -106,13 +102,11 @@ if(AEMU_COMMON_GEN_PKGCONFIG)
     endforeach()
 
     install(DIRECTORY base/include/aemu DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
-    install(DIRECTORY snapshot/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aemu/snapshot)
     install(DIRECTORY host-common/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aemu/host-common)
     install(DIRECTORY third-party/cuda/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aemu/host-common)
     set(INSTALL_TARGETS
         aemu-base
         aemu-host-common
-        ${SNAPSHOT_LIB_NAME}
         ${LOGGING_LIB_NAME})
     if(ENABLE_VKCEREAL_TESTS)
         list(APPEND INSTALL_TARGETS aemu-base-testing-support aemu-host-common-testing-support)
diff --git a/MODULE.bazel b/MODULE.bazel
index 139a1a5..2900e6b 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -5,8 +5,9 @@ module(
 
 bazel_dep(name = "abseil-cpp", version = "20250127.0", repo_name = "com_google_absl")
 bazel_dep(name = "gfxstream", version = "0.0.1")
+bazel_dep(name = "google_benchmark", version = "1.9.1", repo_name = "com_github_google_benchmark")
 bazel_dep(name = "googletest", version = "1.15.2", repo_name = "com_google_googletest")
-bazel_dep(name = "lz4", version = "0.0.1")
 bazel_dep(name = "platforms", version = "0.0.11")
 bazel_dep(name = "rules_cc", version = "0.0.14")
 bazel_dep(name = "rules_license", version = "1.0.0")
+bazel_dep(name = "lz4", version = "1.9.4")
diff --git a/base/Android.bp b/base/Android.bp
index b305074..334f0df 100644
--- a/base/Android.bp
+++ b/base/Android.bp
@@ -64,6 +64,9 @@ cc_test_host {
     srcs: [
         "LruCache_unittest.cpp",
     ],
+    header_libs: [
+        "aemu_common_headers",
+    ],
     static_libs: [
         "gfxstream_base",
         "libgmock",
@@ -78,6 +81,9 @@ cc_test_host {
 cc_test_library {
     name: "gfxstream_base_test_support",
     defaults: ["gfxstream_defaults"],
+    header_libs: [
+        "aemu_common_headers",
+    ],
     srcs: [
         "testing/file_io.cpp",
     ],
diff --git a/base/BUILD.bazel b/base/BUILD.bazel
index 8c8ef4e..75a6186 100644
--- a/base/BUILD.bazel
+++ b/base/BUILD.bazel
@@ -132,6 +132,7 @@ cc_library(
         "include/aemu/base/system/System.h",
         "include/aemu/base/system/Win32UnicodeString.h",
         "include/aemu/base/system/Win32Utils.h",
+        "include/aemu/base/testing/FileMatchers.h",
         "include/aemu/base/testing/GTestUtils.h",
         "include/aemu/base/testing/GlmTestHelpers.h",
         "include/aemu/base/testing/MockUtils.h",
@@ -202,7 +203,7 @@ objc_library(
         "system-native-mac.mm",
     ],
     sdk_frameworks = [
-        "IOkit",
+        "IOKit",
         "AppKit",
     ],
     target_compatible_with = [
@@ -255,6 +256,7 @@ cc_library(
         "MemoryTracker.cpp",
         "MessageChannel.cpp",
         "PathUtils.cpp",
+        "RingStreambuf.cpp",
         "SharedLibrary.cpp",
         "StdioStream.cpp",
         "Stream.cpp",
@@ -336,11 +338,25 @@ cc_library(
     alwayslink = True,
 )
 
+cc_test(
+    name = "ringstream_perf",
+    size = "small",
+    srcs = ["RingStreambuf_perf.cpp"],
+    copts = ["-Wno-deprecated-declarations"],
+    includes = ["test"],
+    deps = [
+        ":aemu-base",
+        ":aemu-base-headers",
+        "@com_github_google_benchmark//:benchmark",
+    ],
+)
+
 cc_test(
     name = "aemu-base_unittests",
     srcs = [
         "AlignedBuf_unittest.cpp",
         "ArraySize_unittest.cpp",
+        "FileMatcher_unittest.cpp",
         "HealthMonitor_unittest.cpp",
         "HybridEntityManager_unittest.cpp",
         "LayoutResolver_unittest.cpp",
@@ -348,6 +364,7 @@ cc_test(
         "ManagedDescriptor_unittest.cpp",
         "NoDestructor_unittest.cpp",
         "Optional_unittest.cpp",
+        "RingStreambuf_unittest.cpp",
         "StringFormat_unittest.cpp",
         "SubAllocator_unittest.cpp",
         "TypeTraits_unittest.cpp",
diff --git a/base/FileMatcher_unittest.cpp b/base/FileMatcher_unittest.cpp
new file mode 100644
index 0000000..6adc889
--- /dev/null
+++ b/base/FileMatcher_unittest.cpp
@@ -0,0 +1,112 @@
+// Copyright 2025 The Android Open Source Project
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
+#include "aemu/base/testing/FileMatchers.h"
+
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include <filesystem>
+
+namespace testing {
+namespace {
+
+using ::testing::Not;
+
+TEST(PathEqTest, SamePaths) {
+    std::filesystem::path path1 = "C:\\MyFolder\\file.txt";
+    std::filesystem::path path2 = "C:\\MyFolder\\file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, SamePathsForwardSlash) {
+    std::filesystem::path path1 = "C:/MyFolder/file.txt";
+    std::filesystem::path path2 = "C:/MyFolder/file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, WindowsBackslashForwardSlash) {
+    std::filesystem::path path1 = "C:\\MyFolder\\file.txt";
+    std::filesystem::path path2 = "C:/MyFolder/file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+
+TEST(PathEqTest, PosixPaths) {
+    std::filesystem::path path1 = "/MyFolder/file.txt";
+    std::filesystem::path path2 = "/MyFolder/file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, DifferentPaths) {
+    std::filesystem::path path1 = "C:\\MyFolder\\file.txt";
+    std::filesystem::path path2 = "C:\\MyFolder\\other.txt";
+    EXPECT_THAT(path1, Not(PathEq(path2)));
+}
+
+TEST(PathEqTest, WindowsPosixDifferentPaths) {
+    std::filesystem::path path1 = "C:\\MyFolder\\file.txt";
+    std::filesystem::path path2 = "/MyFolder/file.txt";
+    EXPECT_THAT(path1, Not(PathEq(path2)));
+}
+
+TEST(PathEqTest, UnicodePaths) {
+    std::filesystem::path path1 = L"C:\\MyFolder\\你好.txt";
+    std::filesystem::path path2 = L"C:/MyFolder/你好.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+
+TEST(PathEqTest, UnicodePathsDifferent) {
+    std::filesystem::path path1 = L"C:\\MyFolder\\你好.txt";
+    std::filesystem::path path2 = L"C:/MyFolder/再见.txt";
+    EXPECT_THAT(path1, Not(PathEq(path2)));
+}
+
+TEST(PathEqTest, EmptyPaths) {
+    std::filesystem::path path1 = "";
+    std::filesystem::path path2 = "";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, EmptyPathAndNonEmptyPath) {
+    std::filesystem::path path1 = "";
+    std::filesystem::path path2 = "C:\\MyFolder\\file.txt";
+    EXPECT_THAT(path1, Not(PathEq(path2)));
+}
+
+TEST(PathEqTest, RelativePaths) {
+    std::filesystem::path path1 = "MyFolder/file.txt";
+    std::filesystem::path path2 = "MyFolder/file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, RelativePathsDifferent) {
+    std::filesystem::path path1 = "MyFolder/file.txt";
+    std::filesystem::path path2 = "MyFolder/other.txt";
+    EXPECT_THAT(path1, Not(PathEq(path2)));
+}
+
+TEST(PathEqTest, RelativePathsWindows) {
+    std::filesystem::path path1 = "MyFolder\\file.txt";
+    std::filesystem::path path2 = "MyFolder/file.txt";
+    EXPECT_THAT(path1, PathEq(path2));
+}
+
+TEST(PathEqTest, CanUseStrings) {
+    std::filesystem::path path1 = L"C:\\MyFolder\\你好.txt";
+    EXPECT_THAT(path1, Not(PathEq(L"C:/MyFolder/再见.txt")));
+}
+
+
+}  // namespace
+}  // namespace testing
diff --git a/base/MemStream.cpp b/base/MemStream.cpp
index 1a2e080..7b435e1 100644
--- a/base/MemStream.cpp
+++ b/base/MemStream.cpp
@@ -48,16 +48,19 @@ ssize_t MemStream::write(const void* buffer, size_t size) {
     return size;
 }
 
-int MemStream::writtenSize() const {
-    return (int)mData.size();
+size_t MemStream::writtenSize() const {
+    return mData.size();
 }
 
-int MemStream::readPos() const {
+size_t MemStream::readPos() const {
     return mReadPos;
 }
 
-int MemStream::readSize() const {
-    return mData.size() - mReadPos;
+size_t  MemStream::readSize() const {
+    if (mData.size() > mReadPos) {
+        return mData.size() - mReadPos;
+    }
+    return 0;
 }
 
 void MemStream::save(Stream* stream) const {
diff --git a/base/RingStreambuf.cpp b/base/RingStreambuf.cpp
new file mode 100644
index 0000000..12972e9
--- /dev/null
+++ b/base/RingStreambuf.cpp
@@ -0,0 +1,214 @@
+// Copyright (C) 2019 The Android Open Source Project
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
+#include "aemu/base/streams/RingStreambuf.h"
+
+#include <string.h>  // for memcpy
+
+#include <algorithm>  // for max, min
+
+namespace android {
+namespace base {
+namespace streams {
+
+// See https://jameshfisher.com/2018/03/30/round-up-power-2 for details
+static uint64_t next_pow2(uint64_t x) {
+    return x == 1 ? 1 : 1 << (64 - __builtin_clzl(x - 1));
+}
+RingStreambuf::RingStreambuf(uint32_t capacity, milliseconds timeout) : mTimeout(timeout) {
+    uint64_t cap = next_pow2(capacity + 1);
+    mRingbuffer.resize(cap);
+}
+
+void RingStreambuf::close() {
+    {
+        std::unique_lock<std::mutex> lock(mLock);
+        mTimeout = std::chrono::milliseconds(0);
+        mClosed = true;
+    }
+    mCanRead.notify_all();
+}
+
+std::streamsize RingStreambuf::xsputn(const char* s, std::streamsize n) {
+    // Usually n >> 1..
+    mLock.lock();
+    std::streamsize capacity = mRingbuffer.capacity();
+
+    if (mClosed) {
+        mLock.unlock();
+        return 0;
+    }
+
+    // Case 1: It doesn't fit in the ringbuffer
+    if (n >= capacity) {
+        // We are overwriting everything, so let's just reset it all.
+        memcpy(mRingbuffer.data(), s + n - capacity, capacity);
+        mHead = capacity;
+        mTail = 0;
+        mHeadOffset += n;
+        mLock.unlock();
+        mCanRead.notify_all();
+        return n;
+    }
+
+    // Case 2, it fits in the ringbuffer.
+    // Case 2a: We are going over the edge of the buffer.
+
+    // Check to see if we have to update the tail, we are checking
+    // the case where the head is moving over the tail.
+    bool updateTail = (mHead < mTail && mTail <= mHead + n);
+
+    // We are getting overwritten from the end..
+    if (mHead + n > capacity) {
+        // Write up until the end of the buffer.
+        std::streamsize bytesUntilTheEnd = capacity - mHead;
+        memcpy(mRingbuffer.data() + mHead, s, bytesUntilTheEnd);
+
+        // Write he remaining bytes from the start of the buffer.
+        memcpy(mRingbuffer.data(), s + bytesUntilTheEnd, n - bytesUntilTheEnd);
+        mHead = n - bytesUntilTheEnd;
+
+        // We are checking the case where the tail got overwritten from the
+        // front.
+        updateTail |= mTail <= mHead;
+    } else {
+        // Case 2b: We are not falling off the edge of the world.
+        memcpy(mRingbuffer.data() + mHead, s, n);
+        mHead = (mHead + n) & (capacity - 1);
+
+        // Check the corner case where we flipped to pos 0.
+        updateTail |= mHead == mTail;
+    }
+    if (updateTail) mTail = (mHead + 1) & (capacity - 1);
+    mHeadOffset += n;
+    mLock.unlock();
+    mCanRead.notify_all();
+    return n;
+}
+
+int RingStreambuf::overflow(int c) {
+    return EOF;
+}
+
+std::streamsize RingStreambuf::waitForAvailableSpace(std::streamsize n) {
+    std::unique_lock<std::mutex> lock(mLock);
+    mCanRead.wait_for(lock, mTimeout, [this, n]() { return showmanyw() >= n || mClosed; });
+    return showmanyw();
+}
+
+std::streamsize RingStreambuf::showmanyw() {
+    return mRingbuffer.capacity() - 1 - showmanyc();
+}
+
+std::streamsize RingStreambuf::showmanyc() {
+    // Note that:
+    // Full state is mHead + 1 == mTail
+    // Empty state is mHead == mTail
+    if (mHead < mTail) {
+        return mHead + mRingbuffer.capacity() - mTail;
+    }
+    return mHead - mTail;
+}
+
+std::streamsize RingStreambuf::xsgetn(char* s, std::streamsize n) {
+    std::unique_lock<std::mutex> lock(mLock);
+    if (!mCanRead.wait_for(lock, mTimeout, [this]() { return mTail != mHead; })) {
+        return 0;
+    }
+    std::streamsize toRead = std::min(showmanyc(), n);
+    std::streamsize capacity = mRingbuffer.capacity();
+    // 2 Cases:
+    // We are falling over the edge, or not:
+    if (mTail + toRead > capacity) {
+        // We wrap around
+        std::streamsize bytesUntilTheEnd = capacity - mTail;
+        memcpy(s, mRingbuffer.data() + mTail, bytesUntilTheEnd);
+        memcpy(s + bytesUntilTheEnd, mRingbuffer.data(), toRead - bytesUntilTheEnd);
+    } else {
+        // We don't
+        memcpy(s, mRingbuffer.data() + mTail, toRead);
+    }
+    mTail = (mTail + toRead) & (capacity - 1);
+    return toRead;
+}
+
+int RingStreambuf::underflow() {
+    std::unique_lock<std::mutex> lock(mLock);
+    if (!mCanRead.wait_for(lock, mTimeout, [this]() { return mTail != mHead || mClosed; })) {
+        return traits_type::eof();
+    }
+    if (mClosed && mTail == mHead) {
+        return traits_type::eof();
+    }
+    return mRingbuffer[mTail];
+};
+
+int RingStreambuf::uflow() {
+    std::unique_lock<std::mutex> lock(mLock);
+    if (!mCanRead.wait_for(lock, mTimeout, [this]() { return mTail != mHead || mClosed; })) {
+        return traits_type::eof();
+    }
+    if (mClosed && mTail == mHead) {
+        // [[unlikely]]
+        return traits_type::eof();
+    }
+
+    int val = mRingbuffer[mTail];
+    mTail = (mTail + 1) & (mRingbuffer.capacity() - 1);
+    return val;
+}
+
+std::pair<int, std::string> RingStreambuf::bufferAtOffset(std::streamsize offset,
+                                                          milliseconds timeoutMs) {
+    std::unique_lock<std::mutex> lock(mLock);
+    std::string res;
+    if (!mCanRead.wait_for(lock, timeoutMs, [offset, this]() { return offset < mHeadOffset; })) {
+        return std::make_pair(mHeadOffset, res);
+    }
+
+    // Prepare the outgoing buffer.
+    std::streamsize capacity = mRingbuffer.capacity();
+    std::streamsize toRead = showmanyc();
+    std::streamsize startOffset = mHeadOffset - toRead;
+    std::streamsize skip = std::max(startOffset, offset) - startOffset;
+
+    // Let's find the starting point where we should be reading.
+    uint16_t read = (mTail + skip) & (capacity - 1);
+
+    // We are looking for an offset that is in the future...
+    // Return the current start offset, without anything
+    if (skip > toRead) {
+        return std::make_pair(mHeadOffset, res);
+    }
+
+    // Actual size of bytes we are going to read.
+    toRead -= skip;
+
+    // We are falling over the edge, or not:
+    res.reserve(toRead);
+    if (read + toRead > capacity) {
+        // We wrap around
+        std::streamsize bytesUntilTheEnd = capacity - read;
+        res.assign(mRingbuffer.data() + read, bytesUntilTheEnd);
+        res.append(mRingbuffer.data(), toRead - bytesUntilTheEnd);
+    } else {
+        // We don't fall of the cliff..
+        res.assign(mRingbuffer.data() + read, toRead);
+    }
+
+    return std::make_pair(startOffset + skip, res);
+}
+
+}  // namespace streams
+}  // namespace base
+}  // namespace android
diff --git a/base/RingStreambuf_perf.cpp b/base/RingStreambuf_perf.cpp
new file mode 100644
index 0000000..4fb32d0
--- /dev/null
+++ b/base/RingStreambuf_perf.cpp
@@ -0,0 +1,74 @@
+// Copyright 2016 The Android Open Source Project
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
+
+// A small benchmark used to compare the performance of android::base::Lock
+// with other mutex implementations.
+
+#include <iostream>  // for operator<<
+#include <string>    // for string
+#include <utility>   // for pair
+
+#include "aemu/base/streams/RingStreambuf.h"  // for RingStre...
+#include "benchmark/benchmark.h"              // for State
+
+using android::base::streams::RingStreambuf;
+using namespace std::chrono_literals;
+#define BASIC_BENCHMARK_TEST(x) \
+    BENCHMARK(x)->RangeMultiplier(2)->Range(1 << 10, 1 << 14)
+
+void BM_WriteData(benchmark::State& state) {
+    std::string src = std::string(state.range_x() / 2, 'a');
+    RingStreambuf buf(state.range_x());
+    std::ostream stream(&buf);
+
+    while (state.KeepRunning()) {
+        stream << src;
+    }
+}
+
+void BM_WriteAndRead(benchmark::State& state) {
+    std::string src = std::string(state.range_x() / 2, 'a');
+    src += '\n';
+    std::string read;
+    RingStreambuf buf(state.range_x());
+    std::ostream stream(&buf);
+    std::istream in(&buf);
+
+    while (state.KeepRunning()) {
+        stream << src;
+
+        // Reading is very slow compared to the logcat scenario, as each
+        // character gets read one at a time.
+        in >> read;
+    }
+}
+
+void BM_WriteLogcatScenario(benchmark::State& state) {
+    // Mimics what we do in grpc.
+    std::string src = std::string(state.range_x() / 2, 'a');
+    RingStreambuf buf(state.range_x());
+    std::ostream stream(&buf);
+
+    int offset = 0;
+    while (state.KeepRunning()) {
+        stream << src;
+        auto message = buf.bufferAtOffset(offset, 0ms);
+        offset += message.second.size();
+    }
+}
+
+BASIC_BENCHMARK_TEST(BM_WriteData);
+BASIC_BENCHMARK_TEST(BM_WriteAndRead);
+BASIC_BENCHMARK_TEST(BM_WriteLogcatScenario);
+BENCHMARK_MAIN();
\ No newline at end of file
diff --git a/base/RingStreambuf_unittest.cpp b/base/RingStreambuf_unittest.cpp
new file mode 100644
index 0000000..1e4a9df
--- /dev/null
+++ b/base/RingStreambuf_unittest.cpp
@@ -0,0 +1,243 @@
+// Copyright (C) 2019 The Android Open Source Project
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
+#include "aemu/base/streams/RingStreambuf.h"
+
+#include <chrono>
+#include <istream>
+#include <ratio>
+#include <string>
+#include <thread>
+
+#include <gtest/gtest.h>
+
+namespace android {
+namespace base {
+namespace streams {
+
+using namespace std::chrono_literals;
+TEST(RingStreambuf, basic_stream_avail) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "hi";
+    EXPECT_EQ(2, buf.in_avail());
+}
+
+TEST(RingStreambuf, no_write_after_close) {
+    RingStreambuf buf(8);
+    std::ostream stream(&buf);
+    stream << "hi";
+    EXPECT_EQ(2, buf.in_avail());
+    buf.close();
+    stream << "there";
+    EXPECT_EQ(2, buf.in_avail());
+}
+
+
+TEST(RingStreambuf, stream_can_read_after_close) {
+    RingStreambuf buf(8);
+    std::ostream stream(&buf);
+    std::istream in(&buf);
+    std::string read;
+    stream << "hi\n";
+    buf.close();
+    stream << "there\n";
+    in >> read;
+    EXPECT_EQ(read, "hi");
+}
+
+TEST(RingStreambuf, underflow_immediately_return_when_closed) {
+    using namespace std::chrono_literals;
+
+    // Timeout after 10ms..
+    RingStreambuf buf(4, 5ms);
+    auto start = std::chrono::steady_clock::now();
+
+    // This results in an underflow (i.e. buffer is empty)
+    // so after timeout we decleare eof.
+    EXPECT_EQ(buf.sbumpc(), RingStreambuf::traits_type::eof());
+    auto end = std::chrono::steady_clock::now();
+    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
+
+    // We must have waited at least 4ms.
+    EXPECT_GT(diff, 4ms) <<  "Elapsed time in milliseconds: " << diff.count() << " ms.";
+
+    // A closed buffer times out immediately
+    start = std::chrono::steady_clock::now();
+    buf.close();
+    EXPECT_EQ(buf.sbumpc(), RingStreambuf::traits_type::eof());
+    end = std::chrono::steady_clock::now();
+    diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
+    EXPECT_LT(diff, 1ms) <<  "Elapsed time in milliseconds: " << diff.count() << " ms.";
+}
+
+TEST(RingStreambuf, basic_stream) {
+    RingStreambuf buf(6);
+    std::ostream stream(&buf);
+    stream << "hello";
+    auto res = buf.bufferAtOffset(0);
+    EXPECT_EQ(res.first, 0);
+    EXPECT_STREQ("hello", res.second.c_str());
+}
+
+TEST(RingStreambuf, basic_stream_offset) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "AABB";
+    auto res = buf.bufferAtOffset(2);
+    EXPECT_EQ(res.first, 2);
+    EXPECT_STREQ("BB", res.second.c_str());
+}
+
+TEST(RingStreambuf, stream_offset_takes_earliest_available) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "aaaaaaa";
+    stream << "bbbbbbb";
+    auto res = buf.bufferAtOffset(0);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("bbbbbbb", res.second.c_str());
+
+    res = buf.bufferAtOffset(7);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("bbbbbbb", res.second.c_str());
+}
+
+TEST(RingStreambuf, no_loss_when_iterating) {
+    // This simulates calling getLogcat over and over.
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    int offset = 0;
+    for (int i = 0; i < 26; i++) {
+        std::string write(7, 'a' + i);
+        stream << write;
+        auto res = buf.bufferAtOffset(offset);
+
+        EXPECT_EQ(offset, i * 7);
+        EXPECT_EQ(res.first, i * 7);
+        EXPECT_STREQ(write.c_str(), res.second.c_str());
+
+        // Move to the next offset where we find data.
+        offset = res.first + res.second.size();
+    }
+}
+
+TEST(RingStreambuf, can_also_read) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    std::istream in(&buf);
+    for (int i = 0; i < 26; i++) {
+        std::string write(6, 'a' + i);
+        std::string read;
+        stream << write << "\n";
+        in >> read;
+        EXPECT_STREQ(read.c_str(), write.c_str());
+    }
+}
+
+TEST(RingStreambuf, can_also_read_from_buf) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    std::istream in(&buf);
+    for (int i = 0; i < 26; i++) {
+        std::string write(6, 'a' + i);
+        write += "\n";  // EOL parsing..
+        buf.sputn(write.c_str(), write.size());
+
+        in.clear();
+        EXPECT_GT(buf.in_avail(), 0);
+        EXPECT_TRUE(in.good());
+        EXPECT_FALSE(in.bad());
+        EXPECT_FALSE(in.fail());
+
+        std::string read;
+        in >> read;
+        read += "\n";
+        ASSERT_STREQ(read.c_str(), write.c_str());
+    }
+}
+
+TEST(RingStreambuf, stream_overwrites_ring) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "aaaaaaa";
+    stream << "bbbbbbb";
+
+    auto res = buf.bufferAtOffset(0, 1s);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("bbbbbbb", res.second.c_str());
+
+    res = buf.bufferAtOffset(7);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("bbbbbbb", res.second.c_str());
+}
+
+TEST(RingStreambuf, stream_not_yet_available_no_block) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "aaaaaaa";
+
+    auto res = buf.bufferAtOffset(7);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("", res.second.c_str());
+}
+TEST(RingStreambuf, istream_times_out_when_empty) {
+    // String buffer that will block at most 10ms.
+    RingStreambuf buf(4, 5ms);
+    std::istream in(&buf);
+    std::string read;
+    auto start = std::chrono::high_resolution_clock::now();
+
+    in >> read;
+
+    auto finish = std::chrono::high_resolution_clock::now();
+    auto waited = std::chrono::duration_cast<milliseconds>(finish - start);
+    // We should have waited at least 5ms.
+    EXPECT_GE(waited, 5ms);
+    SUCCEED();
+}
+
+TEST(RingStreambuf, stream_not_yet_available_no_block_gives_proper_distance) {
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "aaaaaaa";
+
+    auto res = buf.bufferAtOffset(200);
+    EXPECT_EQ(res.first, 7);
+    EXPECT_STREQ("", res.second.c_str());
+}
+
+TEST(RingStreambuf, stream_offset_blocks_until_available) {
+    using namespace std::chrono_literals;
+    RingStreambuf buf(4);
+    std::ostream stream(&buf);
+    stream << "aaaaaaa";
+    std::thread writer([&stream] {
+        std::this_thread::sleep_for(100ms);
+        stream << "bbbbbbb";
+        std::this_thread::sleep_for(100ms);
+        stream << "ccccccc";
+    });
+    std::thread reader([&buf] {
+        auto res = buf.bufferAtOffset(14, 1s);
+        EXPECT_EQ(res.first, 14);
+        EXPECT_STREQ("ccccccc", res.second.c_str());
+    });
+
+    writer.join();
+    reader.join();
+}
+
+}  // namespace streams
+}  // namespace base
+}  // namespace android
diff --git a/base/SharedMemory_posix.cpp b/base/SharedMemory_posix.cpp
index be95af8..c4938c5 100644
--- a/base/SharedMemory_posix.cpp
+++ b/base/SharedMemory_posix.cpp
@@ -25,6 +25,34 @@
 
 namespace android {
 namespace base {
+namespace {
+
+#ifndef __NR_memfd_create
+#if __aarch64__
+#define __NR_memfd_create 279
+#elif __arm__
+#define __NR_memfd_create 279
+#elif __powerpc64__
+#define __NR_memfd_create 360
+#elif __i386__
+#define	 __NR_memfd_create 356
+#elif __x86_64__
+#define __NR_memfd_create 319
+#endif
+#endif
+
+int memfd_create_wrapper(const char *name, unsigned int flags) {
+#if defined(HAVE_MEMFD_CREATE)
+	return memfd_create(name, flags);
+#elif defined(__NR_memfd_create)
+	return syscall(__NR_memfd_create, name, flags);
+#else
+	return -1;
+#endif
+}
+
+}  // namespace
+
 
 SharedMemory::SharedMemory(const std::string& name, size_t size) : mSize(size) {
     const std::string& kFileUri = "file://";
@@ -91,7 +119,7 @@ int SharedMemory::openInternal(int oflag, int mode, bool doMapping) {
     struct stat sb;
     if (mShareType == ShareType::SHARED_MEMORY) {
 #if !defined(__BIONIC__)
-        mFd = shm_open(mName.c_str(), oflag, mode);
+        mFd = memfd_create_wrapper(mName.c_str(), FD_CLOEXEC);
 #else
         return ENOTTY;
 #endif
diff --git a/base/include/aemu/base/containers/HybridEntityManager.h b/base/include/aemu/base/containers/HybridEntityManager.h
index c5a0c5a..ca191f5 100644
--- a/base/include/aemu/base/containers/HybridEntityManager.h
+++ b/base/include/aemu/base/containers/HybridEntityManager.h
@@ -165,13 +165,13 @@ public:
     void forEachLive(IterFunc func) {
         {
             SeqLock::ScopedWrite sw(&mEntityManagerLock);
-            mEntityManager.forEachLiveComponent(func);
+            mEntityManager.forEachLiveEntry(func);
         }
 
         AutoLock lock(mMapLock);
         for (auto it : mMap) {
             auto handle = index2Handle(it.first);
-            func(true /* live */, handle, handle, it.second);
+            func(true /* live */, handle, it.second);
         }
     }
 
@@ -185,7 +185,7 @@ public:
         AutoLock lock(mMapLock);
         for (const auto it : mMap) {
             auto handle = index2Handle(it.first);
-            func(true /* live */, handle, handle, it.second);
+            func(true /* live */, handle, it.second);
         }
     }
 
diff --git a/base/include/aemu/base/files/MemStream.h b/base/include/aemu/base/files/MemStream.h
index 01a9082..a18637a 100644
--- a/base/include/aemu/base/files/MemStream.h
+++ b/base/include/aemu/base/files/MemStream.h
@@ -33,9 +33,9 @@ public:
     MemStream(MemStream&& other) = default;
     MemStream& operator=(MemStream&& other) = default;
 
-    int writtenSize() const;
-    int readPos() const;
-    int readSize() const;
+    size_t writtenSize() const;
+    size_t readPos() const;
+    size_t readSize() const;
 
     // Stream interface implementation.
     ssize_t read(void* buffer, size_t size) override;
@@ -57,7 +57,7 @@ private:
     DISALLOW_COPY_AND_ASSIGN(MemStream);
 
     Buffer mData;
-    int mReadPos = 0;
+    size_t mReadPos = 0;
     void* mPb = nullptr;
 };
 
diff --git a/base/include/aemu/base/files/StreamSerializing.h b/base/include/aemu/base/files/StreamSerializing.h
index 579b335..9e1740e 100644
--- a/base/include/aemu/base/files/StreamSerializing.h
+++ b/base/include/aemu/base/files/StreamSerializing.h
@@ -49,19 +49,21 @@ bool loadBuffer(Stream* stream, std::vector<T>* buffer) {
     return ret == len * sizeof(T);
 }
 
-template <class T, class = enable_if<std::is_standard_layout<T>>>
-void saveBuffer(Stream* stream, const SmallVector<T>& buffer) {
+template <class Container,
+          class = enable_if<std::is_standard_layout<typename Container::value_type>>>
+void saveBuffer(Stream* stream, const Container& buffer) {
     stream->putBe32(buffer.size());
-    stream->write(buffer.data(), sizeof(T) * buffer.size());
+    stream->write(buffer.data(), sizeof(typename Container::value_type) * buffer.size());
 }
 
-template <class T, class = enable_if<std::is_standard_layout<T>>>
-bool loadBuffer(Stream* stream, SmallVector<T>* buffer) {
+template <class Container,
+          class = enable_if<std::is_standard_layout<typename Container::value_type>>>
+bool loadBuffer(Stream* stream, Container* buffer) {
     auto len = stream->getBe32();
     buffer->clear();
     buffer->resize_noinit(len);
-    int ret = (int)stream->read(buffer->data(), len * sizeof(T));
-    return ret == len * sizeof(T);
+    int ret = (int)stream->read(buffer->data(), len * sizeof(typename Container::value_type));
+    return ret == len * sizeof(typename Container::value_type);
 }
 
 template <class T, class SaveFunc>
diff --git a/base/include/aemu/base/testing/FileMatchers.h b/base/include/aemu/base/testing/FileMatchers.h
new file mode 100644
index 0000000..6cf47ed
--- /dev/null
+++ b/base/include/aemu/base/testing/FileMatchers.h
@@ -0,0 +1,101 @@
+// Copyright 2025 The Android Open Source Project
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
+#pragma once
+
+#include <gmock/gmock.h>
+
+#include <codecvt>
+#include <filesystem>
+#include <locale>
+#include <string>
+
+namespace testing {
+namespace internal {
+
+/**
+ * @brief Converts a std::filesystem::path to a std::string.
+ *
+ * This function handles the difference between Windows and POSIX path
+ * representations, ensuring that the resulting string is UTF-8 encoded.
+ *
+ * @param path The std::filesystem::path to convert.
+ * @return The path as a UTF-8 encoded std::string.
+ */
+static std::string pathToString(const std::filesystem::path& path) {
+#ifdef _WIN32
+    std::wstring widePath = path.wstring();
+    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
+    return converter.to_bytes(widePath);
+#else
+    return path.string();
+#endif
+}
+
+/**
+ * @brief Normalizes a std::filesystem::path for comparison.
+ *
+ * This function converts the path to a std::string and replaces backslashes
+ * with forward slashes.
+ *
+ * @note This function will normalize all backslashes to forward slashes.
+ *
+ * @param path The std::filesystem::path to normalize.
+ * @return The normalized path as a std::string.
+ */
+std::string normalizePath(const std::filesystem::path& path) {
+    std::string normalized = pathToString(path);
+    std::replace(normalized.begin(), normalized.end(), '\\', '/');
+    return normalized;
+}
+
+}  // namespace internal
+
+/**
+ * @brief A Google Test matcher for comparing std::filesystem::path objects.
+ *
+ * This matcher normalizes paths before comparison, making it suitable for
+ * cross-platform testing.
+ *
+ * @note This matcher normalizes all backslashes to forward slashes.
+ * @note This matcher does not handle case-insensitivity.
+ *
+ * @param expected The expected std::filesystem::path.
+ *
+ * @code
+ * #include <gtest/gtest.h>
+ * #include <gmock/gmock.h>
+ * #include <filesystem>
+ * #include "aemu/base/testing/FileMatchers.h"
+ *
+ * TEST(PathMatcherTest, PathEquality) {
+ *   std::filesystem::path path1 = "C:\\MyFolder\\file.txt"; // Windows path
+ *   std::filesystem::path path2 = "C:/MyFolder/file.txt";   // Windows path (forward slashes)
+ *   std::filesystem::path path3 = "/MyFolder/file.txt";     // Posix path
+ *   std::filesystem::path path4 = "/MyFolder/other.txt";   // Posix path
+ *
+ *   EXPECT_THAT(path1, testing::PathEq(path2)); // Should pass (normalized)
+ *   EXPECT_THAT(path3, testing::PathEq(path3)); // Should pass (same path)
+ *   EXPECT_THAT(path1, testing::Not(testing::PathEq(path3))); // Should pass (different paths)
+ *   EXPECT_THAT(path3, testing::Not(testing::PathEq(path4))); // Should pass (different paths)
+ * }
+ * @endcode
+ */
+MATCHER_P(PathEq, expected,
+          std::string(negation ? "is not equal to " : "is equal to ") +
+              PrintToString(internal::normalizePath(expected))) {
+    return internal::normalizePath(std::filesystem::path(arg)) ==
+           internal::normalizePath(std::filesystem::path(expected));
+}
+
+}  // namespace testing
diff --git a/host-common/Android.bp b/host-common/Android.bp
index f004d7a..bea3a53 100644
--- a/host-common/Android.bp
+++ b/host-common/Android.bp
@@ -11,19 +11,18 @@ package {
 
 cc_library_static {
     name: "gfxstream_host_common",
-    defaults: [ "gfxstream_defaults" ],
+    defaults: ["gfxstream_defaults"],
+    header_libs: [
+        "aemu_common_headers",
+    ],
     static_libs: [
         "gfxstream_base",
     ],
     srcs: [
         "empty-crash-handler.cpp",
         "crash_reporter.cpp",
-        "vm_operations.cpp",
         "feature_control.cpp",
         "FeatureControlOverride.cpp",
-        "dma_device.cpp",
-        "sync_device.cpp",
-        "misc.cpp",
         "window_operations.cpp",
         "logging.cpp",
         "GfxstreamFatalError.cpp",
@@ -33,39 +32,9 @@ cc_library_static {
         "RefcountPipe.cpp",
         "GraphicsAgentFactory.cpp",
 
-        "GoldfishSyncCommandQueue.cpp",
-        "goldfish_sync.cpp",
-
-        "DmaMap.cpp",
-        "GoldfishDma.cpp",
-
-        "address_space_device_control_ops.cpp",
-        "address_space_device.cpp",
-        "address_space_host_memory_allocator.cpp",
-        "address_space_shared_slots_host_memory_allocator.cpp",
-        "address_space_graphics.cpp",
-        "address_space_host_media.cpp",
-
         "hw-config.cpp",
     ],
     local_include_dirs: [
         "include/host-common",
     ],
 }
-
-cc_test_library {
-    name: "gfxstream_host_common_test_support",
-    defaults: [ "gfxstream_defaults" ],
-    srcs: [
-        "testing/HostAddressSpace.cpp",
-        "testing/MockAndroidEmulatorWindowAgent.cpp",
-        "testing/MockAndroidMultiDisplayAgent.cpp",
-        "testing/MockAndroidVmOperations.cpp",
-        "testing/MockGraphicsAgentFactory.cpp",
-    ],
-    static_libs: [
-        "gfxstream_base",
-        "gfxstream_host_common",
-        "libgmock",
-    ],
-}
diff --git a/host-common/BUILD.bazel b/host-common/BUILD.bazel
index 3a1e9a6..05c6c03 100644
--- a/host-common/BUILD.bazel
+++ b/host-common/BUILD.bazel
@@ -66,7 +66,6 @@ cc_library(
         "include/host-common/GfxstreamFatalError.h",
         "include/host-common/GoldfishDma.h",
         "include/host-common/GoldfishMediaDefs.h",
-        "include/host-common/GoldfishSyncCommandQueue.h",
         "include/host-common/GraphicsAgentFactory.h",
         "include/host-common/H264NaluParser.h",
         "include/host-common/H264PingInfoParser.h",
@@ -105,7 +104,6 @@ cc_library(
         "include/host-common/address_space_device.hpp",
         "include/host-common/address_space_device_control_ops.h",
         "include/host-common/address_space_graphics.h",
-        "include/host-common/address_space_graphics_types.h",
         "include/host-common/address_space_host_media.h",
         "include/host-common/address_space_host_memory_allocator.h",
         "include/host-common/address_space_shared_slots_host_memory_allocator.h",
@@ -118,7 +116,6 @@ cc_library(
         "include/host-common/crash_reporter.h",
         "include/host-common/debug.h",
         "include/host-common/display_agent.h",
-        "include/host-common/dma_device.h",
         "include/host-common/dynlink_cuda.h",
         "include/host-common/dynlink_cuda_cuda.h",
         "include/host-common/dynlink_cuviddec.h",
@@ -128,7 +125,6 @@ cc_library(
         "include/host-common/feature_control_base.h",
         "include/host-common/globals.h",
         "include/host-common/goldfish_pipe.h",
-        "include/host-common/goldfish_sync.h",
         "include/host-common/hw-config.h",
         "include/host-common/hw-config-defs.h",
         "include/host-common/hw-config-helper.h",
@@ -137,10 +133,10 @@ cc_library(
         "include/host-common/logging.h",
         "include/host-common/misc.h",
         "include/host-common/multi_display_agent.h",
+        "include/host-common/opengles.h",
         "include/host-common/record_screen_agent.h",
         "include/host-common/refcount-pipe.h",
         "include/host-common/screen-recorder.h",
-        "include/host-common/sync_device.h",
         "include/host-common/vm_operations.h",
         "include/host-common/window_agent.h",
     ],
@@ -153,27 +149,13 @@ cc_library(
     name = "aemu-host-common",
     srcs = [
         "AndroidPipe.cpp",
-        "DmaMap.cpp",
-        "GoldfishDma.cpp",
-        "GoldfishSyncCommandQueue.cpp",
         "GraphicsAgentFactory.cpp",
         "HostmemIdMapping.cpp",
         "RefcountPipe.cpp",
-        "address_space_device.cpp",
-        "address_space_device_control_ops.cpp",
-        "address_space_graphics.cpp",
-        "address_space_host_media.cpp",
-        "address_space_host_memory_allocator.cpp",
-        "address_space_shared_slots_host_memory_allocator.cpp",
         "crash_reporter.cpp",
-        "dma_device.cpp",
         "empty-crash-handler.cpp",
         "feature_control.cpp",
-        "goldfish_sync.cpp",
         "hw-config.cpp",
-        "misc.cpp",
-        "sync_device.cpp",
-        "vm_operations.cpp",
         "window_operations.cpp",
     ],
     hdrs = [":aemu-host-common-headers"],
diff --git a/host-common/CMakeLists.txt b/host-common/CMakeLists.txt
index 656b24d..b2ffd91 100644
--- a/host-common/CMakeLists.txt
+++ b/host-common/CMakeLists.txt
@@ -31,7 +31,7 @@ add_library(aemu-host-common.headers INTERFACE)
 target_link_libraries(
     aemu-host-common.headers
     INTERFACE
-    gfxstream-snapshot.headers)
+    aemu-base.headers)
 target_include_directories(
     aemu-host-common.headers
     INTERFACE
@@ -50,11 +50,7 @@ if (BUILD_STANDALONE)
         # emugl glue
         empty-crash-handler.cpp
         crash_reporter.cpp
-        vm_operations.cpp
         feature_control.cpp
-        dma_device.cpp
-        sync_device.cpp
-        misc.cpp
         window_operations.cpp
 
         # What used to be android-emu
@@ -63,22 +59,6 @@ if (BUILD_STANDALONE)
         RefcountPipe.cpp
         GraphicsAgentFactory.cpp
 
-        # goldfish sync
-        GoldfishSyncCommandQueue.cpp
-        goldfish_sync.cpp
-
-        # goldfish dma
-        DmaMap.cpp
-        GoldfishDma.cpp
-
-        # Address space device
-        address_space_device_control_ops.cpp
-        address_space_device.cpp
-        address_space_host_memory_allocator.cpp
-        address_space_shared_slots_host_memory_allocator.cpp
-        address_space_graphics.cpp
-        address_space_host_media.cpp
-
 	# SubAllocator
         ../base/SubAllocator.cpp
 
@@ -126,34 +106,8 @@ if (GFXSTREAM_HOST_COMMON_LIB)
 endif()
 
 if (ENABLE_VKCEREAL_TESTS)
-    # Tests
-    add_library(
-        aemu-host-common-testing-support
-        testing/HostAddressSpace.cpp
-        testing/MockGraphicsAgentFactory.cpp
-        testing/MockAndroidEmulatorWindowAgent.cpp
-        testing/MockAndroidMultiDisplayAgent.cpp
-        testing/MockAndroidVmOperations.cpp)
-    target_include_directories(
-        aemu-host-common-testing-support
-        PUBLIC
-        ${AEMU_COMMON_REPO_ROOT})
-    target_link_libraries(
-        aemu-host-common-testing-support
-        PUBLIC
-        PRIVATE
-        aemu-base.headers
-        aemu-host-common.headers
-        gtest
-        gmock)
-
     add_executable(
         aemu-host-common_unittests
-        address_space_graphics_unittests.cpp
-        address_space_host_memory_allocator_unittests.cpp
-        address_space_shared_slots_host_memory_allocator_unittests.cpp
-        HostAddressSpace_unittest.cpp
-        HostmemIdMapping_unittest.cpp
         logging_unittest.cpp
         GfxstreamFatalError_unittest.cpp)
 
@@ -169,7 +123,6 @@ if (ENABLE_VKCEREAL_TESTS)
         aemu-host-common.headers
         ${GFXSTREAM_BASE_LIB}
         ${GFXSTREAM_HOST_COMMON_LIB}
-        aemu-host-common-testing-support
         gtest_main
         gmock_main)
 
diff --git a/host-common/GoldfishDma.cpp b/host-common/GoldfishDma.cpp
deleted file mode 100644
index 499a259..0000000
--- a/host-common/GoldfishDma.cpp
+++ /dev/null
@@ -1,79 +0,0 @@
-// Copyright 2023 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "aemu/base/files/Stream.h"
-
-#include "host-common/GoldfishDma.h"
-#include "host-common/DmaMap.h"
-
-#include "host-common/address_space_device.h"
-#include "host-common/android_pipe_host.h"
-
-static void android_goldfish_dma_add_buffer(void* pipe, uint64_t guest_paddr, uint64_t sz) {
-    android::DmaMap::get()->addBuffer(pipe, guest_paddr, sz);
-}
-
-static void android_goldfish_dma_remove_buffer(uint64_t guest_paddr) {
-    android::DmaMap::get()->removeBuffer(guest_paddr);
-}
-
-static void* android_goldfish_dma_get_host_addr(uint64_t guest_paddr) {
-    void *host_ptr;
-
-    host_ptr = get_address_space_device_control_ops()->get_host_ptr(guest_paddr);
-    if (host_ptr) {
-        return host_ptr;
-    }
-
-    return android::DmaMap::get()->getHostAddr(guest_paddr);
-}
-
-static void android_goldfish_dma_invalidate_host_mappings() {
-    android::DmaMap::get()->invalidateHostMappings();
-}
-
-static void android_goldfish_dma_unlock(uint64_t guest_paddr) {
-    void* hwpipe = android::DmaMap::get()->getPipeInstance(guest_paddr);
-
-    if (hwpipe) {
-        /*
-         * DMA regions allocated with AddressSpaceHostMemoryAllocatorContext
-         * don't have hwpipe associated with them.
-         */
-        android_pipe_host_signal_wake(hwpipe, PIPE_WAKE_UNLOCK_DMA);
-    }
-}
-
-static void android_goldfish_dma_reset_host_mappings() {
-    android::DmaMap::get()->resetHostMappings();
-}
-
-static void android_goldfish_dma_save_mappings(android::base::Stream* stream) {
-    android::DmaMap::get()->save(stream);
-}
-
-static void android_goldfish_dma_load_mappings(android::base::Stream* stream) {
-    android::DmaMap::get()->load(stream);
-}
-
-const GoldfishDmaOps android_goldfish_dma_ops = {
-    .add_buffer = android_goldfish_dma_add_buffer,
-    .remove_buffer = android_goldfish_dma_remove_buffer,
-    .get_host_addr = android_goldfish_dma_get_host_addr,
-    .invalidate_host_mappings = android_goldfish_dma_invalidate_host_mappings,
-    .unlock = android_goldfish_dma_unlock,
-    .reset_host_mappings = android_goldfish_dma_reset_host_mappings,
-    .save_mappings = android_goldfish_dma_save_mappings,
-    .load_mappings = android_goldfish_dma_load_mappings,
-};
diff --git a/host-common/GoldfishSyncCommandQueue.cpp b/host-common/GoldfishSyncCommandQueue.cpp
deleted file mode 100644
index 5414621..0000000
--- a/host-common/GoldfishSyncCommandQueue.cpp
+++ /dev/null
@@ -1,108 +0,0 @@
-// Copyright 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "GoldfishSyncCommandQueue.h"
-
-#include <memory>
-#include <string>
-#include <vector>
-
-namespace android {
-
-using base::Stream;
-
-static GoldfishSyncCommandQueue* sCommandQueue() {
-    static GoldfishSyncCommandQueue* s = new GoldfishSyncCommandQueue;
-    return s;
-}
-
-// static
-void GoldfishSyncCommandQueue::initThreading(VmLock* vmLock) {
-    // TODO: trivial timer implementation for now.
-    sCommandQueue()->init(vmLock, {
-            [](DeviceContextRunner<GoldfishSyncWakeInfo>* dcr, std::function<void()> installedCallback) {
-                (void)dcr;
-                (void)installedCallback;
-            },
-            [](DeviceContextRunner<GoldfishSyncWakeInfo>* dcr) {
-                (void)dcr;
-            },
-            [](DeviceContextRunner<GoldfishSyncWakeInfo>* dcr, uint64_t timeout) {
-                (void)dcr;
-                (void)timeout;
-            },
-     });
-}
-
-// static
-void GoldfishSyncCommandQueue::setQueueCommand(queue_device_command_t fx) {
-    GoldfishSyncCommandQueue* cmdQueue = sCommandQueue();
-    cmdQueue->tellSyncDevice = fx;
-}
-
-// static
-void GoldfishSyncCommandQueue::hostSignal(uint32_t cmd,
-                                          uint64_t handle,
-                                          uint32_t time_arg,
-                                          uint64_t hostcmd_handle) {
-
-    GoldfishSyncCommandQueue* queue = sCommandQueue();
-
-    GoldfishSyncWakeInfo sync_data;
-    sync_data.cmd = cmd;
-    sync_data.handle = handle;
-    sync_data.time_arg = time_arg;
-    sync_data.hostcmd_handle = hostcmd_handle;
-
-    queue->queueDeviceOperation(sync_data);
-}
-
-// static
-void GoldfishSyncCommandQueue::save(Stream* stream) {
-    GoldfishSyncCommandQueue* queue = sCommandQueue();
-    stream->putBe32(queue->numPending());
-    queue->forEachPendingOperation([stream](const GoldfishSyncWakeInfo& wakeInfo) {
-            stream->putBe64(wakeInfo.handle);
-            stream->putBe64(wakeInfo.hostcmd_handle);
-            stream->putBe32(wakeInfo.cmd);
-            stream->putBe32(wakeInfo.time_arg);
-    });
-}
-
-// static
-void GoldfishSyncCommandQueue::load(Stream* stream) {
-    GoldfishSyncCommandQueue* queue = sCommandQueue();
-    queue->removeAllPendingOperations(
-        [](const GoldfishSyncWakeInfo&) { return true; });
-    uint32_t pending = stream->getBe32();
-    for (uint32_t i = 0; i < pending; i++) {
-        GoldfishSyncWakeInfo cmd = {
-            stream->getBe64(), // handle
-            stream->getBe64(), // hostcmd_handle
-            stream->getBe32(), // cmd
-            stream->getBe32(), // time_arg
-        };
-        queue->queueDeviceOperation(cmd);
-    }
-}
-
-void GoldfishSyncCommandQueue::performDeviceOperation
-    (const GoldfishSyncWakeInfo& wakeInfo) {
-    tellSyncDevice(wakeInfo.cmd,
-                   wakeInfo.handle,
-                   wakeInfo.time_arg,
-                   wakeInfo.hostcmd_handle);
-}
-
-} // namespace android
diff --git a/host-common/address_space_device.cpp b/host-common/address_space_device.cpp
deleted file mode 100644
index 8d9ce21..0000000
--- a/host-common/address_space_device.cpp
+++ /dev/null
@@ -1,603 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-#include "host-common/address_space_device.h"
-#include "host-common/AddressSpaceService.h"
-#include "host-common/address_space_graphics.h"
-#ifndef AEMU_MIN
-#include "host-common/address_space_host_media.h"
-#endif
-#include "host-common/address_space_host_memory_allocator.h"
-#include "host-common/address_space_shared_slots_host_memory_allocator.h"
-#include "host-common/vm_operations.h"
-
-#include "aemu/base/synchronization/Lock.h"
-
-#include <map>
-#include <unordered_map>
-#include <memory>
-
-using android::base::AutoLock;
-using android::base::Lock;
-using android::base::Stream;
-using android::emulation::asg::AddressSpaceGraphicsContext;
-
-using namespace android::emulation;
-
-#define AS_DEVICE_DEBUG 0
-
-#if AS_DEVICE_DEBUG
-#define AS_DEVICE_DPRINT(fmt,...) fprintf(stderr, "%s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__);
-#else
-#define AS_DEVICE_DPRINT(fmt,...)
-#endif
-
-const QAndroidVmOperations* sVmOps = nullptr;
-
-namespace {
-
-class AddressSpaceDeviceState {
-public:
-    AddressSpaceDeviceState() = default;
-    ~AddressSpaceDeviceState() = default;
-
-    uint32_t genHandle() {
-        AutoLock lock(mContextsLock);
-
-        auto res = mHandleIndex;
-
-        if (!res) {
-            ++res;
-            mHandleIndex += 2;
-        } else {
-            ++mHandleIndex;
-        }
-
-        AS_DEVICE_DPRINT("new handle: %u", res);
-        return res;
-    }
-
-    void destroyHandle(uint32_t handle) {
-        AS_DEVICE_DPRINT("erase handle: %u", handle);
-
-        std::unique_ptr<AddressSpaceDeviceContext> context;
-
-        {
-            AutoLock lock(mContextsLock);
-
-            auto contextDescriptionIt = mContexts.find(handle);
-            if (contextDescriptionIt == mContexts.end()) return;
-            auto& contextDescription = contextDescriptionIt->second;
-
-            context = std::move(contextDescription.device_context);
-
-            mContexts.erase(contextDescriptionIt);
-        }
-
-        // Destroy `context` without holding the lock.
-    }
-
-    void tellPingInfo(uint32_t handle, uint64_t gpa) {
-        AutoLock lock(mContextsLock);
-        auto& contextDesc = mContexts[handle];
-        contextDesc.pingInfo =
-            (AddressSpaceDevicePingInfo*)
-            sVmOps->physicalMemoryGetAddr(gpa);
-        contextDesc.pingInfoGpa = gpa;
-        AS_DEVICE_DPRINT("Ping info: gpa 0x%llx @ %p\n", (unsigned long long)gpa,
-                         contextDesc.pingInfo);
-    }
-
-    void createInstance(const struct AddressSpaceCreateInfo& create) {
-        AutoLock lock(mContextsLock);
-        auto& contextDesc = mContexts[create.handle];
-        contextDesc.device_context = buildAddressSpaceDeviceContext(create);
-    }
-
-    void ping(uint32_t handle) {
-        AutoLock lock(mContextsLock);
-        auto& contextDesc = mContexts[handle];
-        AddressSpaceDevicePingInfo* pingInfo = contextDesc.pingInfo;
-
-        const uint64_t phys_addr = pingInfo->phys_addr;
-
-        AS_DEVICE_DPRINT(
-                "handle %u data 0x%llx -> %p size %llu meta 0x%llx\n", handle,
-                (unsigned long long)phys_addr,
-                sVmOps->physicalMemoryGetAddr(phys_addr),
-                (unsigned long long)pingInfo->size, (unsigned long long)pingInfo->metadata);
-
-        AddressSpaceDeviceContext *device_context = contextDesc.device_context.get();
-        if (device_context) {
-            device_context->perform(pingInfo);
-        } else {
-            // The first ioctl establishes the device type
-            struct AddressSpaceCreateInfo create = {0};
-            create.type = static_cast<AddressSpaceDeviceType>(pingInfo->metadata);
-            create.physAddr = phys_addr;
-
-            contextDesc.device_context = buildAddressSpaceDeviceContext(create);
-            pingInfo->metadata = contextDesc.device_context ? 0 : -1;
-        }
-    }
-
-    void pingAtHva(uint32_t handle, AddressSpaceDevicePingInfo* pingInfo) {
-        AutoLock lock(mContextsLock);
-        auto& contextDesc = mContexts[handle];
-
-        const uint64_t phys_addr = pingInfo->phys_addr;
-
-        AS_DEVICE_DPRINT(
-                "handle %u data 0x%llx -> %p size %llu meta 0x%llx\n", handle,
-                (unsigned long long)phys_addr,
-                sVmOps->physicalMemoryGetAddr(phys_addr),
-                (unsigned long long)pingInfo->size, (unsigned long long)pingInfo->metadata);
-
-        AddressSpaceDeviceContext *device_context = contextDesc.device_context.get();
-        if (device_context) {
-            device_context->perform(pingInfo);
-        } else {
-            struct AddressSpaceCreateInfo create = {0};
-            create.type = static_cast<AddressSpaceDeviceType>(pingInfo->metadata);
-            create.physAddr = phys_addr;
-
-            contextDesc.device_context = buildAddressSpaceDeviceContext(create);
-            pingInfo->metadata = contextDesc.device_context ? 0 : -1;
-        }
-    }
-
-    void registerDeallocationCallback(uint64_t gpa, void* context, address_space_device_deallocation_callback_t func) {
-        AutoLock lock(mContextsLock);
-        auto& currentCallbacks = mDeallocationCallbacks[gpa];
-
-        DeallocationCallbackEntry entry = {
-            context,
-            func,
-        };
-
-        currentCallbacks.push_back(entry);
-    }
-
-    void runDeallocationCallbacks(uint64_t gpa) {
-        AutoLock lock(mContextsLock);
-
-        auto it = mDeallocationCallbacks.find(gpa);
-        if (it == mDeallocationCallbacks.end()) return;
-
-        auto& callbacks = it->second;
-
-        for (auto& entry: callbacks) {
-            entry.func(entry.context, gpa);
-        }
-
-        mDeallocationCallbacks.erase(gpa);
-    }
-
-    AddressSpaceDeviceContext* handleToContext(uint32_t handle) {
-        AutoLock lock(mContextsLock);
-        if (mContexts.find(handle) == mContexts.end()) return nullptr;
-
-        auto& contextDesc = mContexts[handle];
-        return contextDesc.device_context.get();
-    }
-
-    uint64_t hostmemRegister(const struct MemEntry *entry) {
-        return sVmOps->hostmemRegister(entry);
-    }
-
-    void hostmemUnregister(uint64_t id) {
-        sVmOps->hostmemUnregister(id);
-    }
-
-    void save(Stream* stream) const {
-        // Pre-save
-        for (const auto &kv : mContexts) {
-            const AddressSpaceContextDescription &desc = kv.second;
-            const AddressSpaceDeviceContext *device_context = desc.device_context.get();
-            if (device_context) {
-                device_context->preSave();
-            }
-        }
-
-        AddressSpaceGraphicsContext::globalStatePreSave();
-
-        // Save
-        AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateSave(stream);
-        AddressSpaceGraphicsContext::globalStateSave(stream);
-
-        stream->putBe32(mHandleIndex);
-        stream->putBe32(mContexts.size());
-
-        for (const auto &kv : mContexts) {
-            const uint32_t handle = kv.first;
-            const AddressSpaceContextDescription &desc = kv.second;
-            const AddressSpaceDeviceContext *device_context = desc.device_context.get();
-
-            stream->putBe32(handle);
-            stream->putBe64(desc.pingInfoGpa);
-
-            if (device_context) {
-                stream->putByte(1);
-                stream->putBe32(device_context->getDeviceType());
-                device_context->save(stream);
-            } else {
-                stream->putByte(0);
-            }
-        }
-
-        // Post save
-
-        AddressSpaceGraphicsContext::globalStatePostSave();
-
-        for (const auto &kv : mContexts) {
-            const AddressSpaceContextDescription &desc = kv.second;
-            const AddressSpaceDeviceContext *device_context = desc.device_context.get();
-            if (device_context) {
-                device_context->postSave();
-            }
-        }
-    }
-
-    void setLoadResources(AddressSpaceDeviceLoadResources resources) {
-        mLoadResources = std::move(resources);
-    }
-
-    bool load(Stream* stream) {
-        // First destroy all contexts, because
-        // this can be done while an emulator is running
-        clear();
-
-        if (!AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateLoad(
-                stream,
-                get_address_space_device_control_ops(),
-                get_address_space_device_hw_funcs())) {
-            return false;
-        }
-
-        asg::AddressSpaceGraphicsContext::init(get_address_space_device_control_ops());
-
-        if (!AddressSpaceGraphicsContext::globalStateLoad(stream, mLoadResources)) {
-            return false;
-        }
-
-        const uint32_t handleIndex = stream->getBe32();
-        const size_t size = stream->getBe32();
-
-        Contexts contexts;
-        for (size_t i = 0; i < size; ++i) {
-            const uint32_t handle = stream->getBe32();
-            const uint64_t pingInfoGpa = stream->getBe64();
-
-            std::unique_ptr<AddressSpaceDeviceContext> context;
-            switch (stream->getByte()) {
-            case 0:
-                break;
-
-            case 1: {
-                struct AddressSpaceCreateInfo create = {0};
-                create.type = static_cast<AddressSpaceDeviceType>(stream->getBe32());
-                create.physAddr = pingInfoGpa;
-                create.fromSnapshot = true;
-
-                context = buildAddressSpaceDeviceContext(create);
-                if (!context || !context->load(stream)) {
-                    return false;
-                    }
-                }
-                break;
-
-            default:
-                return false;
-            }
-
-            auto &desc = contexts[handle];
-            desc.pingInfoGpa = pingInfoGpa;
-            if (desc.pingInfoGpa == ~0ULL) {
-                fprintf(stderr, "%s: warning: restoring hva-only ping\n", __func__);
-            } else {
-                desc.pingInfo = (AddressSpaceDevicePingInfo*)
-                    sVmOps->physicalMemoryGetAddr(pingInfoGpa);
-            }
-            desc.device_context = std::move(context);
-        }
-
-        {
-           AutoLock lock(mContextsLock);
-           mHandleIndex = handleIndex;
-           mContexts = std::move(contexts);
-        }
-
-        return true;
-    }
-
-    void clear() {
-        AutoLock lock(mContextsLock);
-        mContexts.clear();
-        AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateClear();
-        std::vector<std::pair<uint64_t, uint64_t>> gpasSizesToErase;
-        for (auto& mapping : mMemoryMappings) {
-            auto gpa = mapping.first;
-            auto size = mapping.second.second;
-            gpasSizesToErase.push_back({gpa, size});
-        }
-        for (const auto& gpaSize : gpasSizesToErase) {
-            removeMemoryMappingLocked(gpaSize.first, gpaSize.second);
-        }
-        mMemoryMappings.clear();
-    }
-
-    bool addMemoryMapping(uint64_t gpa, void *ptr, uint64_t size) {
-        AutoLock lock(mMemoryMappingsLock);
-        return addMemoryMappingLocked(gpa, ptr, size);
-    }
-
-    bool removeMemoryMapping(uint64_t gpa, uint64_t size) {
-        AutoLock lock(mMemoryMappingsLock);
-        return removeMemoryMappingLocked(gpa, size);
-    }
-
-    void *getHostPtr(uint64_t gpa) const {
-        AutoLock lock(mMemoryMappingsLock);
-        return getHostPtrLocked(gpa);
-    }
-
-private:
-    mutable Lock mContextsLock;
-    uint32_t mHandleIndex = 1;
-    typedef std::unordered_map<uint32_t, AddressSpaceContextDescription> Contexts;
-    Contexts mContexts;
-
-    std::unique_ptr<AddressSpaceDeviceContext> buildAddressSpaceDeviceContext(
-        const struct AddressSpaceCreateInfo& create) {
-        typedef std::unique_ptr<AddressSpaceDeviceContext> DeviceContextPtr;
-
-        switch (create.type) {
-            case AddressSpaceDeviceType::Graphics:
-                asg::AddressSpaceGraphicsContext::init(get_address_space_device_control_ops());
-                return DeviceContextPtr(new asg::AddressSpaceGraphicsContext(create));
-#ifndef AEMU_MIN
-        case AddressSpaceDeviceType::Media:
-            AS_DEVICE_DPRINT("allocating media context");
-            return DeviceContextPtr(
-                new AddressSpaceHostMediaContext(create, get_address_space_device_control_ops()));
-#endif
-        case AddressSpaceDeviceType::Sensors:
-            return nullptr;
-        case AddressSpaceDeviceType::Power:
-            return nullptr;
-        case AddressSpaceDeviceType::GenericPipe:
-            return nullptr;
-        case AddressSpaceDeviceType::HostMemoryAllocator:
-            return DeviceContextPtr(new AddressSpaceHostMemoryAllocatorContext(
-                get_address_space_device_control_ops(),
-                get_address_space_device_hw_funcs()));
-        case AddressSpaceDeviceType::SharedSlotsHostMemoryAllocator:
-            return DeviceContextPtr(new AddressSpaceSharedSlotsHostMemoryAllocatorContext(
-                get_address_space_device_control_ops(),
-                get_address_space_device_hw_funcs()));
-
-        case AddressSpaceDeviceType::VirtioGpuGraphics:
-            asg::AddressSpaceGraphicsContext::init(get_address_space_device_control_ops());
-            return DeviceContextPtr(new asg::AddressSpaceGraphicsContext(create));
-
-        default:
-            AS_DEVICE_DPRINT("Bad device type");
-            return nullptr;
-        }
-    }
-
-    bool addMemoryMappingLocked(uint64_t gpa, void *ptr, uint64_t size) {
-        if (mMemoryMappings.insert({gpa, {ptr, size}}).second) {
-            sVmOps->mapUserBackedRam(gpa, ptr, size);
-            return true;
-        } else {
-            fprintf(stderr, "%s: failed: hva %p -> gpa [0x%llx 0x%llx]\n", __func__,
-                    ptr,
-                    (unsigned long long)gpa,
-                    (unsigned long long)size);
-            return false;
-        }
-    }
-
-    bool removeMemoryMappingLocked(uint64_t gpa, uint64_t size) {
-        if (mMemoryMappings.erase(gpa) > 0) {
-            sVmOps->unmapUserBackedRam(gpa, size);
-            return true;
-        } else {
-            fprintf(stderr, "%s: failed: gpa [0x%llx 0x%llx]\n", __func__,
-                    (unsigned long long)gpa,
-                    (unsigned long long)size);
-            *(uint32_t*)(123) = 12;
-            return false;
-        }
-    }
-
-    void *getHostPtrLocked(uint64_t gpa) const {
-        auto i = mMemoryMappings.lower_bound(gpa); // i->first >= gpa (or i==end)
-        if ((i != mMemoryMappings.end()) && (i->first == gpa)) {
-            return i->second.first;  // gpa is exactly the beginning of the range
-        } else if (i == mMemoryMappings.begin()) {
-            return nullptr;  // can't '--i', see below
-        } else {
-            --i;
-
-            if ((i->first + i->second.second) > gpa) {
-                // move the host ptr by +(gpa-base)
-                return static_cast<char *>(i->second.first) + (gpa - i->first);
-            } else {
-                return nullptr;  // the range does not cover gpa
-            }
-        }
-    }
-
-    mutable Lock mMemoryMappingsLock;
-    std::map<uint64_t, std::pair<void *, uint64_t>> mMemoryMappings;  // do not save/load
-
-    struct DeallocationCallbackEntry {
-        void* context;
-        address_space_device_deallocation_callback_t func;
-    };
-
-    std::map<uint64_t, std::vector<DeallocationCallbackEntry>> mDeallocationCallbacks; // do not save/load, users re-register on load
-
-    // Not saved/loaded. Externally owned resources used during load.
-    std::optional<AddressSpaceDeviceLoadResources> mLoadResources;
-};
-
-static AddressSpaceDeviceState* sAddressSpaceDeviceState() {
-    static AddressSpaceDeviceState* s = new AddressSpaceDeviceState;
-    return s;
-}
-
-static uint32_t sAddressSpaceDeviceGenHandle() {
-    return sAddressSpaceDeviceState()->genHandle();
-}
-
-static void sAddressSpaceDeviceDestroyHandle(uint32_t handle) {
-    sAddressSpaceDeviceState()->destroyHandle(handle);
-}
-
-static void sAddressSpaceDeviceCreateInstance(const struct AddressSpaceCreateInfo& create) {
-    sAddressSpaceDeviceState()->createInstance(create);
-}
-
-static void sAddressSpaceDeviceTellPingInfo(uint32_t handle, uint64_t gpa) {
-    sAddressSpaceDeviceState()->tellPingInfo(handle, gpa);
-}
-
-static void sAddressSpaceDevicePing(uint32_t handle) {
-    sAddressSpaceDeviceState()->ping(handle);
-}
-
-int sAddressSpaceDeviceAddMemoryMapping(uint64_t gpa, void *ptr, uint64_t size) {
-    return sAddressSpaceDeviceState()->addMemoryMapping(gpa, ptr, size) ? 1 : 0;
-}
-
-int sAddressSpaceDeviceRemoveMemoryMapping(uint64_t gpa, void *ptr, uint64_t size) {
-    (void)ptr; // TODO(lfy): remove arg
-    return sAddressSpaceDeviceState()->removeMemoryMapping(gpa, size) ? 1 : 0;
-}
-
-void* sAddressSpaceDeviceGetHostPtr(uint64_t gpa) {
-    return sAddressSpaceDeviceState()->getHostPtr(gpa);
-}
-
-static void* sAddressSpaceHandleToContext(uint32_t handle) {
-    return (void*)(sAddressSpaceDeviceState()->handleToContext(handle));
-}
-
-static void sAddressSpaceDeviceClear() {
-    sAddressSpaceDeviceState()->clear();
-}
-
-static uint64_t sAddressSpaceDeviceHostmemRegister(const struct MemEntry *entry) {
-    return sAddressSpaceDeviceState()->hostmemRegister(entry);
-}
-
-static void sAddressSpaceDeviceHostmemUnregister(uint64_t id) {
-    sAddressSpaceDeviceState()->hostmemUnregister(id);
-}
-
-static void sAddressSpaceDevicePingAtHva(uint32_t handle, void* hva) {
-    sAddressSpaceDeviceState()->pingAtHva(
-        handle, (AddressSpaceDevicePingInfo*)hva);
-}
-
-static void sAddressSpaceDeviceRegisterDeallocationCallback(
-    void* context, uint64_t gpa, address_space_device_deallocation_callback_t func) {
-    sAddressSpaceDeviceState()->registerDeallocationCallback(gpa, context, func);
-}
-
-static void sAddressSpaceDeviceRunDeallocationCallbacks(uint64_t gpa) {
-    sAddressSpaceDeviceState()->runDeallocationCallbacks(gpa);
-}
-
-static const struct AddressSpaceHwFuncs* sAddressSpaceDeviceControlGetHwFuncs() {
-    return get_address_space_device_hw_funcs();
-}
-
-
-} // namespace
-
-extern "C" {
-
-static struct address_space_device_control_ops sAddressSpaceDeviceOps = {
-    &sAddressSpaceDeviceGenHandle,                     // gen_handle
-    &sAddressSpaceDeviceDestroyHandle,                 // destroy_handle
-    &sAddressSpaceDeviceTellPingInfo,                  // tell_ping_info
-    &sAddressSpaceDevicePing,                          // ping
-    &sAddressSpaceDeviceAddMemoryMapping,              // add_memory_mapping
-    &sAddressSpaceDeviceRemoveMemoryMapping,           // remove_memory_mapping
-    &sAddressSpaceDeviceGetHostPtr,                    // get_host_ptr
-    &sAddressSpaceHandleToContext,                     // handle_to_context
-    &sAddressSpaceDeviceClear,                         // clear
-    &sAddressSpaceDeviceHostmemRegister,               // hostmem register
-    &sAddressSpaceDeviceHostmemUnregister,             // hostmem unregister
-    &sAddressSpaceDevicePingAtHva,                     // ping_at_hva
-    &sAddressSpaceDeviceRegisterDeallocationCallback,  // register_deallocation_callback
-    &sAddressSpaceDeviceRunDeallocationCallbacks,      // run_deallocation_callbacks
-    &sAddressSpaceDeviceControlGetHwFuncs,             // control_get_hw_funcs
-    &sAddressSpaceDeviceCreateInstance,                // create_instance
-};
-
-struct address_space_device_control_ops* get_address_space_device_control_ops(void) {
-    return &sAddressSpaceDeviceOps;
-}
-
-static const struct AddressSpaceHwFuncs* sAddressSpaceHwFuncs = nullptr;
-
-const struct AddressSpaceHwFuncs* address_space_set_hw_funcs(
-        const AddressSpaceHwFuncs* hwFuncs) {
-    const AddressSpaceHwFuncs* result = sAddressSpaceHwFuncs;
-    sAddressSpaceHwFuncs = hwFuncs;
-    return result;
-}
-
-const struct AddressSpaceHwFuncs* get_address_space_device_hw_funcs(void) {
-    return sAddressSpaceHwFuncs;
-}
-
-void address_space_set_vm_operations(const QAndroidVmOperations* vmops) {
-    sVmOps = vmops;
-}
-
-} // extern "C"
-
-namespace android {
-namespace emulation {
-
-void goldfish_address_space_set_vm_operations(const QAndroidVmOperations* vmops) {
-    sVmOps = vmops;
-}
-
-const QAndroidVmOperations* goldfish_address_space_get_vm_operations() {
-    return sVmOps;
-}
-
-int goldfish_address_space_memory_state_set_load_resources(
-    AddressSpaceDeviceLoadResources resources) {
-    sAddressSpaceDeviceState()->setLoadResources(std::move(resources));
-    return 0;
-}
-
-int goldfish_address_space_memory_state_load(android::base::Stream *stream) {
-    return sAddressSpaceDeviceState()->load(stream) ? 0 : 1;
-}
-
-int goldfish_address_space_memory_state_save(android::base::Stream *stream) {
-    sAddressSpaceDeviceState()->save(stream);
-    return 0;
-}
-
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_device_control_ops.cpp b/host-common/address_space_device_control_ops.cpp
deleted file mode 100644
index 5a13670..0000000
--- a/host-common/address_space_device_control_ops.cpp
+++ /dev/null
@@ -1,29 +0,0 @@
-// Copyright 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "address_space_device_control_ops.h"
-
-namespace {
-
-struct address_space_device_control_ops g_address_space_device_control_ops;
-
-}  // namespace
-
-void set_emugl_address_space_device_control_ops(struct address_space_device_control_ops* ops) {
-    g_address_space_device_control_ops = *ops;
-}
-
-const struct address_space_device_control_ops &get_emugl_address_space_device_control_ops() {
-    return g_address_space_device_control_ops;
-}
diff --git a/host-common/address_space_graphics.cpp b/host-common/address_space_graphics.cpp
deleted file mode 100644
index e16b77d..0000000
--- a/host-common/address_space_graphics.cpp
+++ /dev/null
@@ -1,913 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_graphics.h"
-
-#include <memory>
-#include <optional>
-
-#include "aemu/base/AlignedBuf.h"
-#include "aemu/base/SubAllocator.h"
-#include "aemu/base/synchronization/Lock.h"
-#include "host-common/GfxstreamFatalError.h"
-#include "host-common/address_space_device.h"
-#include "host-common/address_space_device.hpp"
-#include "host-common/crash-handler.h"
-#include "host-common/crash_reporter.h"
-#include "host-common/globals.h"
-#include "host-common/vm_operations.h"
-
-#define ASGFX_DEBUG 0
-
-#if ASGFX_DEBUG
-#define ASGFX_LOG(fmt,...) printf("%s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__);
-#else
-#define ASGFX_LOG(fmt,...)
-#endif
-
-using android::base::AutoLock;
-using android::base::Lock;
-using android::base::SubAllocator;
-using emugl::ABORT_REASON_OTHER;
-using emugl::FatalError;
-
-namespace android {
-namespace emulation {
-namespace asg {
-
-struct AllocationCreateInfo {
-    bool virtioGpu;
-    bool hostmemRegisterFixed;
-    bool fromLoad;
-    uint64_t size;
-    uint64_t hostmemId;
-    void *externalAddr;
-    std::optional<uint32_t> dedicatedContextHandle;
-};
-
-struct Block {
-    char* buffer = nullptr;
-    uint64_t bufferSize = 0;
-    SubAllocator* subAlloc = nullptr;
-    uint64_t offsetIntoPhys = 0; // guest claimShared/mmap uses this
-    bool isEmpty = true;
-    std::optional<uint32_t> dedicatedContextHandle;
-    bool usesVirtioGpuHostmem = false;
-    uint64_t hostmemId = 0;
-    bool external = false;
-};
-
-class Globals {
-public:
-    Globals() :
-        mPerContextBufferSize(
-                aemu_get_android_hw()->hw_gltransport_asg_writeBufferSize) { }
-
-    ~Globals() { clear(); }
-
-    void initialize(const address_space_device_control_ops* ops) {
-        AutoLock lock(mLock);
-
-        if (mInitialized) return;
-
-        mControlOps = ops;
-        mInitialized = true;
-    }
-
-    void setConsumer(ConsumerInterface iface) {
-        mConsumerInterface = iface;
-    }
-
-    ConsumerInterface getConsumerInterface() {
-        if (!mConsumerInterface.create ||
-            !mConsumerInterface.destroy ||
-            !mConsumerInterface.preSave ||
-            !mConsumerInterface.globalPreSave ||
-            !mConsumerInterface.save ||
-            !mConsumerInterface.globalPostSave ||
-            !mConsumerInterface.postSave) {
-            crashhandler_die("Consumer interface has not been set\n");
-        }
-        return mConsumerInterface;
-    }
-
-    const address_space_device_control_ops* controlOps() {
-        return mControlOps;
-    }
-
-    void clear() {
-        for (auto& block: mRingBlocks) {
-            if (block.isEmpty) continue;
-            destroyBlockLocked(block);
-        }
-
-        for (auto& block: mBufferBlocks) {
-            if (block.isEmpty) continue;
-            destroyBlockLocked(block);
-        }
-
-        for (auto& block: mCombinedBlocks) {
-            if (block.isEmpty) continue;
-            destroyBlockLocked(block);
-        }
-
-        mRingBlocks.clear();
-        mBufferBlocks.clear();
-        mCombinedBlocks.clear();
-    }
-
-    uint64_t perContextBufferSize() const {
-        return mPerContextBufferSize;
-    }
-
-    Allocation newAllocation(struct AllocationCreateInfo& create,
-                             std::vector<Block>& existingBlocks) {
-        AutoLock lock(mLock);
-
-        if (create.size > ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE) {
-            crashhandler_die(
-                "wanted size 0x%llx which is "
-                "greater than block size 0x%llx",
-                (unsigned long long)create.size,
-                (unsigned long long)ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
-        }
-
-        Allocation res;
-
-        size_t index = 0;
-        for (index = 0; index < existingBlocks.size(); index++) {
-            auto& block = existingBlocks[index];
-
-            if (block.isEmpty) {
-                fillBlockLocked(block, create);
-            }
-
-            if (block.dedicatedContextHandle != create.dedicatedContextHandle) {
-                continue;
-            }
-
-            auto buf = block.subAlloc->alloc(create.size);
-            if (buf) {
-                res.buffer = (char*)buf;
-                res.blockIndex = index;
-                res.offsetIntoPhys =
-                    block.offsetIntoPhys +
-                    block.subAlloc->getOffset(buf);
-                res.size = create.size;
-                res.dedicatedContextHandle = create.dedicatedContextHandle;
-                res.hostmemId = create.hostmemId;
-                return res;
-            } else {
-                // block full
-            }
-        }
-
-        Block newBlock;
-        fillBlockLocked(newBlock, create);
-
-        auto buf = newBlock.subAlloc->alloc(create.size);
-
-        if (!buf) {
-            crashhandler_die(
-                "failed to allocate size 0x%llx "
-                "(no free slots or out of host memory)",
-                (unsigned long long)create.size);
-        }
-
-        existingBlocks.push_back(newBlock);
-
-        res.buffer = (char*)buf;
-        res.blockIndex = index;
-        res.offsetIntoPhys =
-            newBlock.offsetIntoPhys +
-            newBlock.subAlloc->getOffset(buf);
-        res.size = create.size;
-        res.dedicatedContextHandle = create.dedicatedContextHandle;
-        res.hostmemId = create.hostmemId;
-
-        return res;
-    }
-
-    void deleteAllocation(const Allocation& alloc, std::vector<Block>& existingBlocks) {
-        if (!alloc.buffer) return;
-
-        AutoLock lock(mLock);
-
-        if (existingBlocks.size() <= alloc.blockIndex) {
-            crashhandler_die(
-                "should be a block at index %zu "
-                "but it is not found", alloc.blockIndex);
-        }
-
-        auto& block = existingBlocks[alloc.blockIndex];
-
-        if (block.external) {
-            destroyBlockLocked(block);
-            return;
-        }
-
-        if (!block.subAlloc->free(alloc.buffer)) {
-            crashhandler_die(
-                "failed to free %p (block start: %p)",
-                alloc.buffer,
-                block.buffer);
-        }
-
-        if (shouldDestryBlockLocked(block)) {
-            destroyBlockLocked(block);
-        }
-    }
-
-    Allocation allocRingStorage() {
-        struct AllocationCreateInfo create = {0};
-        create.size = sizeof(struct asg_ring_storage);
-        return newAllocation(create, mRingBlocks);
-    }
-
-    void freeRingStorage(const Allocation& alloc) {
-        if (alloc.isView) return;
-        deleteAllocation(alloc, mRingBlocks);
-    }
-
-    Allocation allocBuffer() {
-        struct AllocationCreateInfo create = {0};
-        create.size = mPerContextBufferSize;
-        return newAllocation(create, mBufferBlocks);
-    }
-
-    void freeBuffer(const Allocation& alloc) {
-        if (alloc.isView) return;
-        deleteAllocation(alloc, mBufferBlocks);
-    }
-
-    Allocation allocRingAndBufferStorageDedicated(const struct AddressSpaceCreateInfo& asgCreate) {
-        if (!asgCreate.handle) {
-            crashhandler_die("Dedicated ASG allocation requested without dedicated handle.\n");
-        }
-
-        struct AllocationCreateInfo create = {0};
-        create.size = sizeof(struct asg_ring_storage) + mPerContextBufferSize;
-        create.dedicatedContextHandle = asgCreate.handle;
-        create.virtioGpu = true;
-        if (asgCreate.externalAddr) {
-            create.externalAddr = asgCreate.externalAddr;
-            if (asgCreate.externalAddrSize < static_cast<uint64_t>(create.size)) {
-                crashhandler_die("External address size too small\n");
-            }
-            create.size = asgCreate.externalAddrSize;
-        }
-
-        return newAllocation(create, mCombinedBlocks);
-    }
-
-    Allocation allocRingViewIntoCombined(const Allocation& alloc) {
-        Allocation res = alloc;
-        res.buffer = alloc.buffer;
-        res.size = sizeof(struct asg_ring_storage);
-        res.isView = true;
-        return res;
-    }
-
-    Allocation allocBufferViewIntoCombined(const Allocation& alloc) {
-        Allocation res = alloc;
-        res.buffer = alloc.buffer + sizeof(asg_ring_storage);
-        res.size = mPerContextBufferSize;
-        res.isView = true;
-        return res;
-    }
-
-    void freeRingAndBuffer(const Allocation& alloc) {
-        deleteAllocation(alloc, mCombinedBlocks);
-    }
-
-    void preSave() {
-        // mConsumerInterface.globalPreSave();
-    }
-
-    void save(base::Stream* stream) {
-        stream->putBe64(mRingBlocks.size());
-        stream->putBe64(mBufferBlocks.size());
-        stream->putBe64(mCombinedBlocks.size());
-
-        for (const auto& block: mRingBlocks) {
-            saveBlockLocked(stream, block);
-        }
-
-        for (const auto& block: mBufferBlocks) {
-            saveBlockLocked(stream, block);
-        }
-
-        for (const auto& block: mCombinedBlocks) {
-            saveBlockLocked(stream, block);
-        }
-    }
-
-    void postSave() {
-        // mConsumerInterface.globalPostSave();
-    }
-
-    bool load(base::Stream* stream,
-              const std::optional<AddressSpaceDeviceLoadResources>& resources) {
-        clear();
-        mConsumerInterface.globalPreLoad();
-
-        uint64_t ringBlockCount = stream->getBe64();
-        uint64_t bufferBlockCount = stream->getBe64();
-        uint64_t combinedBlockCount = stream->getBe64();
-
-        mRingBlocks.resize(ringBlockCount);
-        mBufferBlocks.resize(bufferBlockCount);
-        mCombinedBlocks.resize(combinedBlockCount);
-
-        for (auto& block: mRingBlocks) {
-            loadBlockLocked(stream, resources, block);
-        }
-
-        for (auto& block: mBufferBlocks) {
-            loadBlockLocked(stream, resources, block);
-        }
-
-        for (auto& block: mCombinedBlocks) {
-            loadBlockLocked(stream, resources, block);
-        }
-
-        return true;
-    }
-
-    // Assumes that blocks have been loaded,
-    // and that alloc has its blockIndex/offsetIntoPhys fields filled already
-    void fillAllocFromLoad(Allocation& alloc, AddressSpaceGraphicsContext::AllocType allocType) {
-        switch (allocType) {
-            case AddressSpaceGraphicsContext::AllocType::AllocTypeRing:
-                if (mRingBlocks.size() <= alloc.blockIndex) return;
-                fillAllocFromLoad(mRingBlocks[alloc.blockIndex], alloc);
-                break;
-            case AddressSpaceGraphicsContext::AllocType::AllocTypeBuffer:
-                if (mBufferBlocks.size() <= alloc.blockIndex) return;
-                fillAllocFromLoad(mBufferBlocks[alloc.blockIndex], alloc);
-                break;
-            case AddressSpaceGraphicsContext::AllocType::AllocTypeCombined:
-                if (mCombinedBlocks.size() <= alloc.blockIndex) return;
-                fillAllocFromLoad(mCombinedBlocks[alloc.blockIndex], alloc);
-                break;
-            default:
-                GFXSTREAM_ABORT(FatalError(ABORT_REASON_OTHER));
-                break;
-        }
-    }
-
-private:
-
-    void saveBlockLocked(
-        base::Stream* stream,
-        const Block& block) {
-
-        if (block.isEmpty) {
-            stream->putBe32(0);
-            return;
-        } else {
-            stream->putBe32(1);
-        }
-
-        stream->putBe64(block.bufferSize);
-        stream->putBe64(block.offsetIntoPhys);
-        if (block.dedicatedContextHandle) {
-            stream->putBe32(1);
-            stream->putBe32(*block.dedicatedContextHandle);
-        } else {
-            stream->putBe32(0);
-        }
-        stream->putBe32(block.usesVirtioGpuHostmem);
-        stream->putBe64(block.hostmemId);
-        block.subAlloc->save(stream);
-        if (!block.external) {
-            stream->write(block.buffer, block.bufferSize);
-        }
-    }
-
-    void loadBlockLocked(base::Stream* stream,
-                         const std::optional<AddressSpaceDeviceLoadResources>& resources,
-                         Block& block) {
-        uint32_t filled = stream->getBe32();
-        struct AllocationCreateInfo create = {0};
-
-        if (!filled) {
-            block.isEmpty = true;
-            return;
-        } else {
-            block.isEmpty = false;
-        }
-
-        create.size = stream->getBe64(); // `bufferSize`
-        block.offsetIntoPhys = stream->getBe64();
-        if (stream->getBe32() == 1) {
-            create.dedicatedContextHandle = stream->getBe32();
-        }
-        create.virtioGpu = stream->getBe32();
-
-        if (create.virtioGpu) {
-            if (!create.dedicatedContextHandle) {
-                crashhandler_die(
-                    "Failed to load ASG context global block: "
-                    "Virtio GPU backed blocks are expected to have dedicated context.\n");
-            }
-
-            // Blocks whose memory are backed Virtio GPU resource do not own the external
-            // memory. The external memory must be re-loaded outside of ASG and provided via
-            // `resources`.
-            if (!resources) {
-                crashhandler_die(
-                    "Failed to load ASG context global block: "
-                    "Virtio GPU backed blocks need external memory resources for loading.\n");
-            }
-
-            const auto externalMemoryIt =
-                resources->contextExternalMemoryMap.find(*create.dedicatedContextHandle);
-            if (externalMemoryIt == resources->contextExternalMemoryMap.end()) {
-                crashhandler_die(
-                    "Failed to load ASG context global block: "
-                    "Virtio GPU backed blocks an need external memory replacement.\n");
-            }
-            const auto& externalMemory = externalMemoryIt->second;
-            create.externalAddr = externalMemory.externalAddress;
-        }
-
-        create.hostmemRegisterFixed = true;
-        create.fromLoad = true;
-        create.hostmemId = stream->getBe64();
-
-        fillBlockLocked(block, create);
-
-        block.subAlloc->load(stream);
-
-        if (!block.external) {
-            stream->read(block.buffer, block.bufferSize);
-        }
-    }
-
-    void fillAllocFromLoad(const Block& block, Allocation& alloc) {
-        alloc.buffer = block.buffer + (alloc.offsetIntoPhys - block.offsetIntoPhys);
-        alloc.dedicatedContextHandle = block.dedicatedContextHandle;
-        alloc.hostmemId = block.hostmemId;
-    }
-
-    void fillBlockLocked(Block& block, struct AllocationCreateInfo& create) {
-        if (create.dedicatedContextHandle) {
-            if (!create.virtioGpu) {
-                crashhandler_die("Cannot use dedicated allocation without virtio-gpu hostmem id");
-            }
-
-            if (!create.externalAddr) {
-                crashhandler_die(
-                    "Cannot use dedicated allocation without virtio-gpu hostmem id");
-            }
-
-            block.external = true;
-            block.buffer = (char*)create.externalAddr;
-            block.bufferSize = create.size;
-            block.subAlloc =
-                new SubAllocator(block.buffer, block.bufferSize, ADDRESS_SPACE_GRAPHICS_PAGE_SIZE);
-            block.offsetIntoPhys = 0;
-            block.isEmpty = false;
-            block.usesVirtioGpuHostmem = create.virtioGpu;
-            block.hostmemId = create.hostmemId;
-            block.dedicatedContextHandle = create.dedicatedContextHandle;
-        } else {
-            if (create.virtioGpu) {
-                crashhandler_die(
-                    "Only dedicated allocation allowed in virtio-gpu hostmem id path");
-            } else {
-                uint64_t offsetIntoPhys;
-
-                if (create.fromLoad) {
-                    offsetIntoPhys = block.offsetIntoPhys;
-                    int allocRes = get_address_space_device_hw_funcs()->
-                        allocSharedHostRegionFixedLocked(
-                                ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE, offsetIntoPhys);
-                    if (allocRes) {
-                        // Disregard alloc failures for now. This is because when it fails,
-                        // we can assume the correct allocation already exists there (tested)
-                    }
-                } else {
-                    int allocRes = get_address_space_device_hw_funcs()->
-                        allocSharedHostRegionLocked(
-                            ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE, &offsetIntoPhys);
-
-                    if (allocRes) {
-                        crashhandler_die(
-                            "Failed to allocate physical address graphics backing memory.");
-                    }
-                }
-
-                void* buf =
-                    aligned_buf_alloc(
-                        ADDRESS_SPACE_GRAPHICS_PAGE_SIZE,
-                        ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
-
-                mControlOps->add_memory_mapping(
-                    get_address_space_device_hw_funcs()->getPhysAddrStartLocked() +
-                        offsetIntoPhys, buf,
-                    ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
-
-                block.buffer = (char*)buf;
-                block.bufferSize = ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE;
-                block.subAlloc =
-                    new SubAllocator(
-                        buf, ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE,
-                        ADDRESS_SPACE_GRAPHICS_PAGE_SIZE);
-                block.offsetIntoPhys = offsetIntoPhys;
-                block.isEmpty = false;
-            }
-        }
-    }
-
-    void destroyBlockLocked(Block& block) {
-
-        if (block.usesVirtioGpuHostmem && !block.external) {
-            mControlOps->hostmem_unregister(block.hostmemId);
-        } else if (!block.external) {
-            mControlOps->remove_memory_mapping(
-                get_address_space_device_hw_funcs()->getPhysAddrStartLocked() +
-                    block.offsetIntoPhys,
-                block.buffer,
-                ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
-
-            get_address_space_device_hw_funcs()->freeSharedHostRegionLocked(
-                block.offsetIntoPhys);
-        }
-
-        delete block.subAlloc;
-        if (!block.external) {
-            aligned_buf_free(block.buffer);
-        }
-
-        block.isEmpty = true;
-    }
-
-    bool shouldDestryBlockLocked(const Block& block) const {
-        return block.subAlloc->empty();
-    }
-
-    Lock mLock;
-    uint64_t mPerContextBufferSize;
-    bool mInitialized = false;
-    const address_space_device_control_ops* mControlOps = 0;
-    ConsumerInterface mConsumerInterface;
-    std::vector<Block> mRingBlocks;
-    std::vector<Block> mBufferBlocks;
-    std::vector<Block> mCombinedBlocks;
-};
-
-static Globals* sGlobals() {
-    static Globals* g = new Globals;
-    return g;
-}
-
-// static
-void AddressSpaceGraphicsContext::init(const address_space_device_control_ops* ops) {
-    sGlobals()->initialize(ops);
-}
-
-// static
-void AddressSpaceGraphicsContext::clear() {
-    sGlobals()->clear();
-}
-
-// static
-void AddressSpaceGraphicsContext::setConsumer(
-    ConsumerInterface iface) {
-    sGlobals()->setConsumer(iface);
-}
-
-AddressSpaceGraphicsContext::AddressSpaceGraphicsContext(
-    const struct AddressSpaceCreateInfo& create)
-    : mConsumerCallbacks((ConsumerCallbacks){
-          [this] { return onUnavailableRead(); },
-          [](uint64_t physAddr) { return (char*)sGlobals()->controlOps()->get_host_ptr(physAddr); },
-      }),
-      mConsumerInterface(sGlobals()->getConsumerInterface()) {
-    if (create.fromSnapshot) {
-        // Use load() instead to initialize
-        return;
-    }
-
-    const bool isVirtio = (create.type == AddressSpaceDeviceType::VirtioGpuGraphics);
-    if (isVirtio) {
-        VirtioGpuInfo& info = mVirtioGpuInfo.emplace();
-        info.contextId = create.virtioGpuContextId;
-        info.capsetId = create.virtioGpuCapsetId;
-        if (create.contextNameSize) {
-            info.name = std::string(create.contextName, create.contextNameSize);
-        }
-
-        mCombinedAllocation = sGlobals()->allocRingAndBufferStorageDedicated(create);
-        mRingAllocation = sGlobals()->allocRingViewIntoCombined(mCombinedAllocation);
-        mBufferAllocation = sGlobals()->allocBufferViewIntoCombined(mCombinedAllocation);
-    } else {
-        mRingAllocation = sGlobals()->allocRingStorage();
-        mBufferAllocation = sGlobals()->allocBuffer();
-    }
-
-    if (!mRingAllocation.buffer) {
-        crashhandler_die(
-            "Failed to allocate ring for ASG context");
-    }
-
-    if (!mBufferAllocation.buffer) {
-        crashhandler_die(
-            "Failed to allocate buffer for ASG context");
-    }
-
-    mHostContext = asg_context_create(
-        mRingAllocation.buffer,
-        mBufferAllocation.buffer,
-        sGlobals()->perContextBufferSize());
-    mHostContext.ring_config->buffer_size =
-        sGlobals()->perContextBufferSize();
-    mHostContext.ring_config->flush_interval =
-        aemu_get_android_hw()->hw_gltransport_asg_writeStepSize;
-    mHostContext.ring_config->host_consumed_pos = 0;
-    mHostContext.ring_config->guest_write_pos = 0;
-    mHostContext.ring_config->transfer_mode = 1;
-    mHostContext.ring_config->transfer_size = 0;
-    mHostContext.ring_config->in_error = 0;
-
-    mSavedConfig = *mHostContext.ring_config;
-
-    if (create.createRenderThread) {
-        mCurrentConsumer =
-            mConsumerInterface.create(mHostContext, nullptr, mConsumerCallbacks,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->contextId : 0,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->capsetId : 0,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->name : std::nullopt);
-    }
-}
-
-AddressSpaceGraphicsContext::~AddressSpaceGraphicsContext() {
-    if (mCurrentConsumer) {
-        mExiting = 1;
-        *(mHostContext.host_state) = ASG_HOST_STATE_EXIT;
-        mConsumerMessages.send(ConsumerCommand::Exit);
-        mConsumerInterface.destroy(mCurrentConsumer);
-    }
-
-    sGlobals()->freeBuffer(mBufferAllocation);
-    sGlobals()->freeRingStorage(mRingAllocation);
-    sGlobals()->freeRingAndBuffer(mCombinedAllocation);
-}
-
-void AddressSpaceGraphicsContext::perform(AddressSpaceDevicePingInfo* info) {
-    switch (static_cast<asg_command>(info->metadata)) {
-    case ASG_GET_RING:
-        info->metadata = mRingAllocation.offsetIntoPhys;
-        info->size = mRingAllocation.size;
-        break;
-    case ASG_GET_BUFFER:
-        info->metadata = mBufferAllocation.offsetIntoPhys;
-        info->size = mBufferAllocation.size;
-        break;
-    case ASG_SET_VERSION: {
-        auto guestVersion = (uint32_t)info->size;
-        info->size = (uint64_t)(mVersion > guestVersion ? guestVersion : mVersion);
-        mVersion = (uint32_t)info->size;
-        mCurrentConsumer = mConsumerInterface.create(
-            mHostContext, nullptr /* no load stream */, mConsumerCallbacks, 0, 0,
-            std::nullopt);
-
-        if (mVirtioGpuInfo) {
-            info->metadata = mCombinedAllocation.hostmemId;
-        }
-        break;
-    }
-    case ASG_NOTIFY_AVAILABLE:
-        mConsumerMessages.trySend(ConsumerCommand::Wakeup);
-        info->metadata = 0;
-        break;
-    case ASG_GET_CONFIG:
-        *mHostContext.ring_config = mSavedConfig;
-        info->metadata = 0;
-        break;
-    }
-}
-
-int AddressSpaceGraphicsContext::onUnavailableRead() {
-    static const uint32_t kMaxUnavailableReads = 8;
-
-    ++mUnavailableReadCount;
-    ring_buffer_yield();
-
-    ConsumerCommand cmd;
-
-    if (mExiting) {
-        mUnavailableReadCount = kMaxUnavailableReads;
-    }
-
-    if (mUnavailableReadCount >= kMaxUnavailableReads) {
-        mUnavailableReadCount = 0;
-
-sleep:
-        *(mHostContext.host_state) = ASG_HOST_STATE_NEED_NOTIFY;
-        mConsumerMessages.receive(&cmd);
-
-        switch (cmd) {
-            case ConsumerCommand::Wakeup:
-                *(mHostContext.host_state) = ASG_HOST_STATE_CAN_CONSUME;
-                break;
-            case ConsumerCommand::Exit:
-                *(mHostContext.host_state) = ASG_HOST_STATE_EXIT;
-                return -1;
-            case ConsumerCommand::Sleep:
-                goto sleep;
-            case ConsumerCommand::PausePreSnapshot:
-                return -2;
-            case ConsumerCommand::ResumePostSnapshot:
-                return -3;
-            default:
-                crashhandler_die(
-                    "AddressSpaceGraphicsContext::onUnavailableRead: "
-                    "Unknown command: 0x%x\n",
-                    (uint32_t)cmd);
-        }
-
-        return 1;
-    }
-    return 0;
-}
-
-AddressSpaceDeviceType AddressSpaceGraphicsContext::getDeviceType() const {
-    return AddressSpaceDeviceType::Graphics;
-}
-
-void AddressSpaceGraphicsContext::preSave() const {
-    if (mCurrentConsumer) {
-        mConsumerInterface.preSave(mCurrentConsumer);
-        mConsumerMessages.send(ConsumerCommand::PausePreSnapshot);
-    }
-}
-
-void AddressSpaceGraphicsContext::save(base::Stream* stream) const {
-    if (mVirtioGpuInfo) {
-        const VirtioGpuInfo& info = *mVirtioGpuInfo;
-        stream->putBe32(1);
-        stream->putBe32(info.contextId);
-        stream->putBe32(info.capsetId);
-        if (info.name) {
-            stream->putBe32(1);
-            stream->putString(*info.name);
-        } else {
-            stream->putBe32(0);
-        }
-    } else {
-        stream->putBe32(0);
-    }
-
-    stream->putBe32(mVersion);
-    stream->putBe32(mExiting);
-    stream->putBe32(mUnavailableReadCount);
-
-    saveAllocation(stream, mRingAllocation);
-    saveAllocation(stream, mBufferAllocation);
-    saveAllocation(stream, mCombinedAllocation);
-
-    saveRingConfig(stream, mSavedConfig);
-
-    if (mCurrentConsumer) {
-        stream->putBe32(1);
-        mConsumerInterface.save(mCurrentConsumer, stream);
-    } else {
-        stream->putBe32(0);
-    }
-}
-
-void AddressSpaceGraphicsContext::postSave() const {
-    if (mCurrentConsumer) {
-        mConsumerMessages.send(ConsumerCommand::ResumePostSnapshot);
-        mConsumerInterface.postSave(mCurrentConsumer);
-    }
-}
-
-bool AddressSpaceGraphicsContext::load(base::Stream* stream) {
-    const bool hasVirtioGpuInfo = (stream->getBe32() == 1);
-    if (hasVirtioGpuInfo) {
-        VirtioGpuInfo& info = mVirtioGpuInfo.emplace();
-        info.contextId = stream->getBe32();
-        info.capsetId = stream->getBe32();
-        const bool hasName = (stream->getBe32() == 1);
-        if (hasName) {
-            info.name = stream->getString();
-        }
-    }
-
-    mVersion = stream->getBe32();
-    mExiting = stream->getBe32();
-    mUnavailableReadCount = stream->getBe32();
-
-    loadAllocation(stream, mRingAllocation);
-    loadAllocation(stream, mBufferAllocation);
-    loadAllocation(stream, mCombinedAllocation);
-
-    if (mVirtioGpuInfo) {
-        sGlobals()->fillAllocFromLoad(mCombinedAllocation, AllocType::AllocTypeCombined);
-        mRingAllocation = sGlobals()->allocRingViewIntoCombined(mCombinedAllocation);
-        mBufferAllocation = sGlobals()->allocBufferViewIntoCombined(mCombinedAllocation);
-    } else {
-        sGlobals()->fillAllocFromLoad(mRingAllocation, AllocType::AllocTypeRing);
-        sGlobals()->fillAllocFromLoad(mBufferAllocation, AllocType::AllocTypeBuffer);
-    }
-
-    mHostContext = asg_context_create(
-        mRingAllocation.buffer,
-        mBufferAllocation.buffer,
-        sGlobals()->perContextBufferSize());
-    mHostContext.ring_config->buffer_size =
-        sGlobals()->perContextBufferSize();
-    mHostContext.ring_config->flush_interval =
-        aemu_get_android_hw()->hw_gltransport_asg_writeStepSize;
-
-    // In load, the live ring config state is in shared host/guest ram.
-    //
-    // mHostContext.ring_config->host_consumed_pos = 0;
-    // mHostContext.ring_config->transfer_mode = 1;
-    // mHostContext.ring_config->transfer_size = 0;
-    // mHostContext.ring_config->in_error = 0;
-
-    loadRingConfig(stream, mSavedConfig);
-
-    const bool hasConsumer = stream->getBe32() == 1;
-    if (hasConsumer) {
-        mCurrentConsumer =
-            mConsumerInterface.create(mHostContext, stream, mConsumerCallbacks,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->contextId : 0,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->capsetId : 0,
-                                      mVirtioGpuInfo ? mVirtioGpuInfo->name : std::nullopt);
-        mConsumerInterface.postLoad(mCurrentConsumer);
-    }
-
-    return true;
-}
-
-void AddressSpaceGraphicsContext::globalStatePreSave() {
-    sGlobals()->preSave();
-}
-
-void AddressSpaceGraphicsContext::globalStateSave(base::Stream* stream) {
-    sGlobals()->save(stream);
-}
-
-void AddressSpaceGraphicsContext::globalStatePostSave() {
-    sGlobals()->postSave();
-}
-
-bool AddressSpaceGraphicsContext::globalStateLoad(
-    base::Stream* stream, const std::optional<AddressSpaceDeviceLoadResources>& resources) {
-    return sGlobals()->load(stream, resources);
-}
-
-void AddressSpaceGraphicsContext::saveRingConfig(base::Stream* stream, const struct asg_ring_config& config) const {
-    stream->putBe32(config.buffer_size);
-    stream->putBe32(config.flush_interval);
-    stream->putBe32(config.host_consumed_pos);
-    stream->putBe32(config.guest_write_pos);
-    stream->putBe32(config.transfer_mode);
-    stream->putBe32(config.transfer_size);
-    stream->putBe32(config.in_error);
-}
-
-void AddressSpaceGraphicsContext::saveAllocation(base::Stream* stream, const Allocation& alloc) const {
-    stream->putBe64(alloc.blockIndex);
-    stream->putBe64(alloc.offsetIntoPhys);
-    stream->putBe64(alloc.size);
-    stream->putBe32(alloc.isView);
-}
-
-void AddressSpaceGraphicsContext::loadRingConfig(base::Stream* stream, struct asg_ring_config& config) {
-    config.buffer_size = stream->getBe32();
-    config.flush_interval = stream->getBe32();
-    config.host_consumed_pos = stream->getBe32();
-    config.guest_write_pos = stream->getBe32();
-    config.transfer_mode = stream->getBe32();
-    config.transfer_size = stream->getBe32();
-    config.in_error = stream->getBe32();
-}
-
-void AddressSpaceGraphicsContext::loadAllocation(base::Stream* stream, Allocation& alloc) {
-    alloc.blockIndex = stream->getBe64();
-    alloc.offsetIntoPhys = stream->getBe64();
-    alloc.size = stream->getBe64();
-    alloc.isView = stream->getBe32();
-}
-
-}  // namespace asg
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_graphics_unittests.cpp b/host-common/address_space_graphics_unittests.cpp
deleted file mode 100644
index f39a62b..0000000
--- a/host-common/address_space_graphics_unittests.cpp
+++ /dev/null
@@ -1,876 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <gtest/gtest.h>                                     // for Message
-#include <stdint.h>                                          // for uint32_t
-#include <stdio.h>                                           // for printf
-#include <string.h>                                          // for size_t
-#include <sys/types.h>                                       // for ssize_t
-#include <algorithm>                                         // for uniform_...
-#include <functional>                                        // for __base
-#include <random>                                            // for default_...
-#include <vector>                                            // for vector
-
-#include "aemu/base/ring_buffer.h"                        // for ring_buf...
-#include "aemu/base/threads/FunctorThread.h"              // for FunctorT...
-#include "host-common/GraphicsAgentFactory.h"                                 // for getConso...
-#include "host-common/AddressSpaceService.h"           // for AddressS...
-#include "host-common/address_space_device.hpp"        // for goldfish...
-#include "host-common/address_space_graphics.h"        // for AddressS...
-#include "host-common/address_space_graphics_types.h"  // for asg_context
-#include "host-common/testing/MockGraphicsAgentFactory.h"
-#include "testing/HostAddressSpace.h"  // for HostAddr...
-#include "host-common/globals.h"                                 // for android_hw
-
-namespace android {
-namespace base {
-class Stream;
-}  // namespace base
-}  // namespace android
-
-using android::base::FunctorThread;
-
-
-
-namespace android {
-namespace emulation {
-namespace asg {
-
-#define ASG_TEST_READ_PATTERN 0xAA
-#define ASG_TEST_WRITE_PATTERN 0xBB
-
-class AddressSpaceGraphicsTest : public ::testing::Test {
-public:
-    class Client {
-    public:
-        Client(HostAddressSpaceDevice* device) :
-            mDevice(device),
-            mHandle(mDevice->open()) {
-
-            ping((uint64_t)AddressSpaceDeviceType::Graphics);
-
-            auto getRingResult = ping((uint64_t)ASG_GET_RING);
-            mRingOffset = getRingResult.metadata;
-            mRingSize = getRingResult.size;
-
-            EXPECT_EQ(0, mDevice->claimShared(mHandle, mRingOffset, mRingSize));
-
-            mRingStorage =
-                (char*)mDevice->getHostAddr(
-                    mDevice->offsetToPhysAddr(mRingOffset));
-
-            auto getBufferResult = ping((uint64_t)ASG_GET_BUFFER);
-            mBufferOffset = getBufferResult.metadata;
-            mBufferSize = getBufferResult.size;
-
-            EXPECT_EQ(0, mDevice->claimShared(mHandle, mBufferOffset, mBufferSize));
-            mBuffer =
-                (char*)mDevice->getHostAddr(
-                    mDevice->offsetToPhysAddr(mBufferOffset));
-
-            mContext = asg_context_create(mRingStorage, mBuffer, mBufferSize);
-
-            EXPECT_EQ(mBuffer, mContext.buffer);
-
-            auto setVersionResult = ping((uint64_t)ASG_SET_VERSION, mVersion);
-            uint32_t hostVersion = setVersionResult.size;
-            EXPECT_LE(hostVersion, mVersion);
-            EXPECT_EQ(aemu_get_android_hw()->hw_gltransport_asg_writeStepSize,
-                      mContext.ring_config->flush_interval);
-            EXPECT_EQ(aemu_get_android_hw()->hw_gltransport_asg_writeBufferSize,
-                      mBufferSize);
-
-            mContext.ring_config->transfer_mode = 1;
-            mContext.ring_config->host_consumed_pos = 0;
-            mContext.ring_config->guest_write_pos = 0;
-            mBufferMask = mBufferSize - 1;
-
-            mWriteStart = mBuffer;
-        }
-
-        ~Client() {
-            mDevice->unclaimShared(mHandle, mBufferOffset);
-            mDevice->unclaimShared(mHandle, mRingOffset);
-            mDevice->close(mHandle);
-        }
-
-        bool isInError() const {
-            return 1 == mContext.ring_config->in_error;
-        }
-
-        void abort() {
-            mContext.ring_config->in_error = 1;
-        }
-
-        char* allocBuffer(size_t size) {
-            if (size > mContext.ring_config->flush_interval) {
-                return nullptr;
-            }
-
-            if (mWriteStart + mCurrentWriteBytes + size >
-                mWriteStart + mWriteStep) {
-                flush();
-                mCurrentWriteBytes = 0;
-            }
-
-            char* res = mWriteStart + mCurrentWriteBytes;
-            mCurrentWriteBytes += size;
-
-            return res;
-        }
-
-        int writeFully(const char* buf, size_t size) {
-            flush();
-            ensureType1Finished();
-            mContext.ring_config->transfer_size = size;
-            mContext.ring_config->transfer_mode = 3;
-
-            size_t sent = 0;
-            size_t quarterRingSize = mBufferSize / 4;
-            size_t chunkSize = size < quarterRingSize ? size : quarterRingSize;
-
-            while (sent < size) {
-                size_t remaining = size - sent;
-                size_t sendThisTime = remaining < chunkSize ? remaining : chunkSize;
-
-                long sentChunks =
-                    ring_buffer_view_write(
-                        mContext.to_host_large_xfer.ring,
-                        &mContext.to_host_large_xfer.view,
-                        buf + sent, sendThisTime, 1);
-
-                if (*(mContext.host_state) != ASG_HOST_STATE_CAN_CONSUME) {
-                    ping(ASG_NOTIFY_AVAILABLE);
-                }
-
-                if (sentChunks == 0) {
-                    ring_buffer_yield();
-                }
-
-                sent += sentChunks * sendThisTime;
-
-                if (isInError()) {
-                    return -1;
-                }
-            }
-
-            ensureType3Finished();
-            mContext.ring_config->transfer_mode = 1;
-            return 0;
-        }
-
-        ssize_t speculativeRead(char* readBuffer, size_t minSizeToRead) {
-            flush();
-            ensureConsumerFinishing();
-
-            size_t actuallyRead = 0;
-            while (!actuallyRead) {
-                uint32_t readAvail =
-                    ring_buffer_available_read(
-                        mContext.from_host_large_xfer.ring,
-                        &mContext.from_host_large_xfer.view);
-
-                if (!readAvail) {
-                    ring_buffer_yield();
-                    continue;
-                }
-
-                uint32_t toRead = readAvail > minSizeToRead ?
-                    minSizeToRead : readAvail;
-
-                long stepsRead = ring_buffer_view_read(
-                    mContext.from_host_large_xfer.ring,
-                    &mContext.from_host_large_xfer.view,
-                    readBuffer, toRead, 1);
-
-                actuallyRead += stepsRead * toRead;
-
-                if (isInError()) {
-                    return -1;
-                }
-            }
-
-            return actuallyRead;
-        }
-
-        void flush() {
-            if (!mCurrentWriteBytes) return;
-            type1WriteWithNotify(mWriteStart - mBuffer, mCurrentWriteBytes);
-            advanceWrite();
-        }
-
-        uint32_t get_relative_buffer_pos(uint32_t pos) {
-            return pos & mBufferMask;
-        }
-
-        uint32_t get_available_for_write() {
-            uint32_t host_consumed_view;
-            __atomic_load(&mContext.ring_config->host_consumed_pos,
-                          &host_consumed_view,
-                          __ATOMIC_SEQ_CST);
-            uint32_t availableForWrite =
-                get_relative_buffer_pos(
-                    host_consumed_view -
-                    mContext.ring_config->guest_write_pos - 1);
-            return availableForWrite;
-        }
-
-        void advanceWrite() {
-            uint32_t avail = get_available_for_write();
-
-            while (avail < mContext.ring_config->flush_interval) {
-                ensureConsumerFinishing();
-                avail = get_available_for_write();
-            }
-
-            __atomic_add_fetch(
-                &mContext.ring_config->guest_write_pos,
-                mContext.ring_config->flush_interval,
-                __ATOMIC_SEQ_CST);
-
-            char* newBuffer =
-                mBuffer +
-                get_relative_buffer_pos(
-                    mContext.ring_config->guest_write_pos);
-
-            mWriteStart = newBuffer;
-            mCurrentWriteBytes = 0;
-        }
-
-        int type1WriteWithNotify(uint32_t bufferOffset, size_t size) {
-            size_t sent = 0;
-            size_t sizeForRing = 8;
-
-            struct asg_type1_xfer xfer {
-                bufferOffset,
-                (uint32_t)size,
-            };
-
-            uint8_t* writeBufferBytes = (uint8_t*)(&xfer);
-
-            while (sent < sizeForRing) {
-
-                long sentChunks = ring_buffer_write(
-                        mContext.to_host, writeBufferBytes + sent, sizeForRing - sent, 1);
-
-                if (*(mContext.host_state) != ASG_HOST_STATE_CAN_CONSUME) {
-                    ping(ASG_NOTIFY_AVAILABLE);
-                }
-
-                if (sentChunks == 0) {
-                    ring_buffer_yield();
-                }
-
-                sent += sentChunks * (sizeForRing - sent);
-
-                if (isInError()) {
-                    return -1;
-                }
-            }
-
-            return 0;
-        }
-
-        void ensureConsumerFinishing() {
-            uint32_t currAvailRead =
-                ring_buffer_available_read(mContext.to_host, 0);
-
-            while (currAvailRead) {
-                ring_buffer_yield();
-                uint32_t nextAvailRead = ring_buffer_available_read(mContext.to_host, 0);
-
-                if (nextAvailRead != currAvailRead) {
-                    break;
-                }
-
-                if (*(mContext.host_state) != ASG_HOST_STATE_CAN_CONSUME) {
-                    ping(ASG_NOTIFY_AVAILABLE);
-                    break;
-                }
-            }
-        }
-
-        void ensureType1Finished() {
-            ensureConsumerFinishing();
-
-            uint32_t currAvailRead =
-                ring_buffer_available_read(mContext.to_host, 0);
-
-            while (currAvailRead) {
-                ring_buffer_yield();
-                currAvailRead = ring_buffer_available_read(mContext.to_host, 0);
-                if (isInError()) {
-                    return;
-                }
-            }
-        }
-
-        void ensureType3Finished() {
-            uint32_t availReadLarge =
-                ring_buffer_available_read(
-                    mContext.to_host_large_xfer.ring,
-                    &mContext.to_host_large_xfer.view);
-            while (availReadLarge) {
-                ring_buffer_yield();
-                availReadLarge =
-                    ring_buffer_available_read(
-                        mContext.to_host_large_xfer.ring,
-                        &mContext.to_host_large_xfer.view);
-                if (*(mContext.host_state) != ASG_HOST_STATE_CAN_CONSUME) {
-                    ping(ASG_NOTIFY_AVAILABLE);
-                }
-                if (isInError()) {
-                    return;
-                }
-            }
-        }
-
-        char* getBufferPtr() { return mBuffer; }
-
-    private:
-
-        AddressSpaceDevicePingInfo ping(uint64_t metadata, uint64_t size = 0) {
-            AddressSpaceDevicePingInfo info;
-            info.metadata = metadata;
-            mDevice->ping(mHandle, &info);
-            return info;
-        }
-
-        HostAddressSpaceDevice* mDevice;
-        uint32_t mHandle;
-        uint64_t mRingOffset;
-        uint64_t mRingSize;
-        uint64_t mBufferOffset;
-        uint64_t mBufferSize;
-        char* mRingStorage;
-        char* mBuffer;
-        struct asg_context mContext;
-        uint32_t mVersion = 1;
-
-        char* mWriteStart = 0;
-        uint32_t mWriteStep = 0;
-        uint32_t mCurrentWriteBytes = 0;
-        uint32_t mBufferMask = 0;
-    };
-
-    class Consumer {
-    public:
-        Consumer(struct asg_context context,
-                 ConsumerCallbacks callbacks) :
-            mContext(context),
-            mCallbacks(callbacks),
-            mThread([this] { threadFunc(); }) {
-            mThread.start();
-        }
-
-        ~Consumer() {
-            mThread.wait();
-        }
-
-        void setRoundTrip(bool enabled,
-                          uint32_t toHostBytes = 0,
-                          uint32_t fromHostBytes = 0) {
-            mRoundTripEnabled = enabled;
-            if (mRoundTripEnabled) {
-                mToHostBytes = toHostBytes;
-                mFromHostBytes = fromHostBytes;
-            }
-        }
-
-        void handleRoundTrip() {
-            if (!mRoundTripEnabled) return;
-
-            if (mReadPos == mToHostBytes) {
-                std::vector<char> reply(mFromHostBytes, ASG_TEST_READ_PATTERN);
-                uint32_t origBytes = mFromHostBytes;
-                auto res = ring_buffer_write_fully_with_abort(
-                    mContext.from_host_large_xfer.ring,
-                    &mContext.from_host_large_xfer.view,
-                    reply.data(),
-                    mFromHostBytes,
-                    1, &mContext.ring_config->in_error);
-                if (res < mFromHostBytes) {
-                    printf("%s: aborted write (%u vs %u %u). in error? %u\n", __func__,
-                            res, mFromHostBytes, origBytes,
-                           mContext.ring_config->in_error);
-                    EXPECT_EQ(1, mContext.ring_config->in_error);
-                }
-                mReadPos = 0;
-            }
-        }
-
-        void ensureWritebackDone() {
-            while (mReadPos) {
-                ring_buffer_yield();
-            }
-        }
-
-        int step() {
-
-            uint32_t nonLargeAvail =
-                ring_buffer_available_read(
-                    mContext.to_host, 0);
-
-            uint32_t largeAvail =
-                ring_buffer_available_read(
-                    mContext.to_host_large_xfer.ring,
-                    &mContext.to_host_large_xfer.view);
-
-            ensureReadBuffer(nonLargeAvail);
-
-            int res = 0;
-            if (nonLargeAvail) {
-                uint32_t transferMode = mContext.ring_config->transfer_mode;
-
-                switch (transferMode) {
-                    case 1:
-                        type1Read(nonLargeAvail);
-                        break;
-                    case 2:
-                        type2Read(nonLargeAvail);
-                        break;
-                    case 3:
-                        break;
-                    default:
-                        EXPECT_TRUE(false) << "Failed, invalid transfer mode";
-                }
-
-
-                res = 0;
-            } else if (largeAvail) {
-                res = type3Read(largeAvail);
-            } else {
-                res = mCallbacks.onUnavailableRead();
-            }
-
-            handleRoundTrip();
-
-            return res;
-        }
-
-        void ensureReadBuffer(uint32_t new_xfer) {
-            size_t readBufferAvail = mReadBuffer.size() - mReadPos;
-            if (readBufferAvail < new_xfer) {
-                mReadBuffer.resize(mReadBuffer.size() + 2 * new_xfer);
-            }
-        }
-
-        void type1Read(uint32_t avail) {
-            uint32_t xferTotal = avail / 8;
-            for (uint32_t i = 0; i < xferTotal; ++i) {
-                struct asg_type1_xfer currentXfer;
-                uint8_t* currentXferPtr = (uint8_t*)(&currentXfer);
-
-                EXPECT_EQ(0, ring_buffer_copy_contents(
-                    mContext.to_host, 0,
-                    sizeof(currentXfer), currentXferPtr));
-
-                char* ptr = mContext.buffer + currentXfer.offset;
-                size_t size = currentXfer.size;
-
-                ensureReadBuffer(size);
-
-                memcpy(mReadBuffer.data() + mReadPos,
-                       ptr, size);
-
-                for (uint32_t j = 0; j < size; ++j) {
-                    EXPECT_EQ((char)ASG_TEST_WRITE_PATTERN,
-                              (mReadBuffer.data() + mReadPos)[j]);
-                }
-
-                mReadPos += size;
-                mContext.ring_config->host_consumed_pos =
-                    ptr - mContext.buffer;
-
-                EXPECT_EQ(1, ring_buffer_advance_read(
-                    mContext.to_host, sizeof(asg_type1_xfer), 1));
-            }
-        }
-
-        void type2Read(uint32_t avail) {
-            uint32_t xferTotal = avail / 16;
-            for (uint32_t i = 0; i < xferTotal; ++i) {
-                struct asg_type2_xfer currentXfer;
-                uint8_t* xferPtr = (uint8_t*)(&currentXfer);
-
-                EXPECT_EQ(0, ring_buffer_copy_contents(
-                    mContext.to_host, 0, sizeof(currentXfer),
-                    xferPtr));
-
-                char* ptr = mCallbacks.getPtr(currentXfer.physAddr);
-                ensureReadBuffer(currentXfer.size);
-
-                memcpy(mReadBuffer.data() + mReadPos, ptr,
-                       currentXfer.size);
-                mReadPos += currentXfer.size;
-
-                EXPECT_EQ(1, ring_buffer_advance_read(
-                    mContext.to_host, sizeof(currentXfer), 1));
-            }
-        }
-
-        int type3Read(uint32_t avail) {
-            (void)avail;
-            ensureReadBuffer(avail);
-            ring_buffer_read_fully_with_abort(
-                mContext.to_host_large_xfer.ring,
-                &mContext.to_host_large_xfer.view,
-                mReadBuffer.data() + mReadPos,
-                avail,
-                1, &mContext.ring_config->in_error);
-            mReadPos += avail;
-            return 0;
-        }
-
-    private:
-
-        void threadFunc() {
-            while(-1 != step());
-        }
-
-        struct asg_context mContext;
-        ConsumerCallbacks mCallbacks;
-        FunctorThread mThread;
-        std::vector<char> mReadBuffer;
-        std::vector<char> mWriteBuffer;
-        size_t mReadPos = 0;
-        uint32_t mToHostBytes = 0;
-        uint32_t mFromHostBytes = 0;
-        bool mRoundTripEnabled = false;
-    };
-
-protected:
-    static void SetUpTestSuite() {
-        android::emulation::injectGraphicsAgents(
-                android::emulation::MockGraphicsAgentFactory());
-        goldfish_address_space_set_vm_operations(getGraphicsAgents()->vm);
-    }
-
-    static void TearDownTestSuite() { }
-
-    void SetUp() override {
-        aemu_get_android_hw()->hw_gltransport_asg_writeBufferSize = 524288;
-        aemu_get_android_hw()->hw_gltransport_asg_writeStepSize = 1024;
-
-        mDevice = HostAddressSpaceDevice::get();
-        ConsumerInterface interface = {
-            // create
-            [this](struct asg_context context,
-               base::Stream* loadStream,
-               ConsumerCallbacks callbacks,
-               uint32_t contextId, uint32_t capsetId,
-               std::optional<std::string> nameOpt) {
-               Consumer* c = new Consumer(context, callbacks);
-               mCurrentConsumer = c;
-               return (void*)c;
-            },
-            // destroy
-            [this](void* context) {
-               Consumer* c = reinterpret_cast<Consumer*>(context);
-               delete c;
-               mCurrentConsumer = nullptr;
-            },
-            // presave
-            [](void* consumer) { },
-            // global presave
-            []() { },
-            // save
-            [](void* consumer, base::Stream* stream) { },
-            // global postsave
-            []() { },
-            // postsave
-            [](void* consumer) { },
-            // postload
-            [](void* consumer) { },
-            // global preload
-            []() { },
-        };
-        AddressSpaceGraphicsContext::setConsumer(interface);
-    }
-
-    void TearDown() override {
-        AddressSpaceGraphicsContext::clear();
-        mDevice->clear();
-        aemu_get_android_hw()->hw_gltransport_asg_writeBufferSize = 524288;
-        aemu_get_android_hw()->hw_gltransport_asg_writeStepSize = 1024;
-        EXPECT_EQ(nullptr, mCurrentConsumer);
-    }
-
-    void setRoundTrip(bool enabled, size_t writeBytes, size_t readBytes) {
-        EXPECT_NE(nullptr, mCurrentConsumer);
-        mCurrentConsumer->setRoundTrip(enabled, writeBytes, readBytes);
-    }
-
-    struct RoundTrip {
-        size_t writeBytes;
-        size_t readBytes;
-    };
-
-    void runRoundTrips(Client& client, const std::vector<RoundTrip>& trips) {
-        EXPECT_NE(nullptr, mCurrentConsumer);
-
-        for (const auto& trip : trips) {
-            mCurrentConsumer->setRoundTrip(true, trip.writeBytes, trip.readBytes);
-
-            std::vector<char> send(trip.writeBytes, ASG_TEST_WRITE_PATTERN);
-            std::vector<char> expectedRead(trip.readBytes, ASG_TEST_READ_PATTERN);
-            std::vector<char> toRead(trip.readBytes, 0);
-
-            size_t stepSize = aemu_get_android_hw()->hw_gltransport_asg_writeStepSize;
-            size_t stepSizeRead = aemu_get_android_hw()->hw_gltransport_asg_writeBufferSize;
-
-            size_t sent = 0;
-            while (sent < trip.writeBytes) {
-                size_t remaining = trip.writeBytes - sent;
-                size_t next = remaining < stepSize ? remaining : stepSize;
-                auto buf = client.allocBuffer(next);
-                memcpy(buf, send.data() + sent, next);
-                sent += next;
-            }
-
-            client.flush();
-
-            size_t recv = 0;
-
-            while (recv < trip.readBytes) {
-                ssize_t readThisTime = client.speculativeRead(
-                    toRead.data() + recv, stepSizeRead);
-                EXPECT_GE(readThisTime, 0);
-                recv += readThisTime;
-            }
-
-            EXPECT_EQ(expectedRead, toRead);
-
-            // make sure the consumer is hung up here or this will
-            // race with setRoundTrip
-            mCurrentConsumer->ensureWritebackDone();
-        }
-
-        mCurrentConsumer->setRoundTrip(false);
-    }
-
-    HostAddressSpaceDevice* mDevice = nullptr;
-    Consumer* mCurrentConsumer = nullptr;
-};
-
-// Tests that we can create a client for ASG,
-// which then in turn creates a consumer thread on the "host."
-// Then test the thread teardown.
-TEST_F(AddressSpaceGraphicsTest, Basic) {
-    Client client(mDevice);
-}
-
-// Tests writing via an IOStream-like interface
-// (allocBuffer, then flush)
-TEST_F(AddressSpaceGraphicsTest, BasicWrite) {
-    EXPECT_EQ(1024, aemu_get_android_hw()->hw_gltransport_asg_writeStepSize);
-    Client client(mDevice);
-
-    // Tests that going over the step size results in nullptr
-    // when using allocBuffer
-    auto buf = client.allocBuffer(1025);
-    EXPECT_EQ(nullptr, buf);
-
-    buf = client.allocBuffer(4);
-    EXPECT_NE(nullptr, buf);
-    memset(buf, ASG_TEST_WRITE_PATTERN, 4);
-    client.flush();
-}
-
-// Tests that further allocs result in flushing
-TEST_F(AddressSpaceGraphicsTest, FlushFromAlloc) {
-    EXPECT_EQ(1024, aemu_get_android_hw()->hw_gltransport_asg_writeStepSize);
-    Client client(mDevice);
-
-    auto buf = client.allocBuffer(1024);
-    memset(buf, ASG_TEST_WRITE_PATTERN, 1024);
-
-    for (uint32_t i = 0; i < 10; ++i) {
-        buf = client.allocBuffer(1024);
-        memset(buf, ASG_TEST_WRITE_PATTERN, 1024);
-    }
-}
-
-// Tests type 3 (large) transfer by itself
-TEST_F(AddressSpaceGraphicsTest, LargeXfer) {
-    Client client(mDevice);
-
-    std::vector<char> largeBuf(1048576, ASG_TEST_WRITE_PATTERN);
-    client.writeFully(largeBuf.data(), largeBuf.size());
-}
-
-// Round trip test
-TEST_F(AddressSpaceGraphicsTest, RoundTrip) {
-    Client client(mDevice);
-    setRoundTrip(true, 1, 1);
-    char element = (char)(ASG_TEST_WRITE_PATTERN);
-    char reply;
-
-    auto buf = client.allocBuffer(1);
-    *buf = element;
-    client.flush();
-    client.speculativeRead(&reply, 1);
-}
-
-// Round trip test (more than one)
-TEST_F(AddressSpaceGraphicsTest, RoundTrips) {
-    Client client(mDevice);
-
-    std::vector<RoundTrip> trips = {
-        { 1, 1, },
-        { 2, 2, },
-        { 4, 4, },
-        { 1026, 34, },
-        { 4, 1048576, },
-    };
-
-    runRoundTrips(client, trips);
-}
-
-// Round trip test (random)
-TEST_F(AddressSpaceGraphicsTest, RoundTripsRandom) {
-    Client client(mDevice);
-
-    std::default_random_engine generator;
-    generator.seed(0);
-    std::uniform_int_distribution<int>
-        sizeDist(1, 4097);
-    std::vector<RoundTrip> trips;
-    for (uint32_t i = 0; i < 1000; ++i) {
-        trips.push_back({
-            (size_t)sizeDist(generator),
-            (size_t)sizeDist(generator),
-        });
-    };
-
-    runRoundTrips(client, trips);
-}
-
-// Abort test. Say that we are reading back 4096
-// bytes, but only actually read back 1 then abort.
-TEST_F(AddressSpaceGraphicsTest, Abort) {
-    Client client(mDevice);
-    setRoundTrip(true, 1, 1048576);
-
-    char send = ASG_TEST_WRITE_PATTERN;
-    auto buf = client.allocBuffer(1);
-    *buf = send;
-    client.flush();
-    client.abort();
-}
-
-// Test having to create more than one block, and
-// ensure traffic works each time.
-TEST_F(AddressSpaceGraphicsTest, BlockCreateDestroy) {
-
-    std::vector<Client*> clients;
-
-    std::default_random_engine generator;
-    generator.seed(0);
-    std::uniform_int_distribution<int>
-        sizeDist(1, 47);
-    std::vector<RoundTrip> trips;
-    for (uint32_t i = 0; i < 100; ++i) {
-        trips.push_back({
-            (size_t)sizeDist(generator),
-            (size_t)sizeDist(generator),
-        });
-    };
-
-    int numBlocksMax = 3;
-    int numBlocksDetected = 0;
-    char* bufLow = (char*)(uintptr_t)(-1);
-    char* bufHigh = 0;
-
-    while (true) {
-        Client* c = new Client(mDevice);
-        runRoundTrips(*c, trips);
-
-        clients.push_back(c);
-
-        char* bufPtr = c->getBufferPtr();
-        bufLow = bufPtr < bufLow ? bufPtr : bufLow;
-        bufHigh = bufPtr > bufHigh ? bufPtr : bufHigh;
-
-        size_t gap = bufHigh - bufLow;
-
-        numBlocksDetected =
-            gap / ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE;
-
-        if (numBlocksDetected > numBlocksMax) break;
-    }
-
-    for (auto c: clients) {
-        delete c;
-    }
-}
-
-// Test having to create more than one block, and
-// ensure traffic works each time, but also randomly
-// delete previous allocs to cause fragmentation.
-TEST_F(AddressSpaceGraphicsTest, BlockCreateDestroyRandom) {
-    std::vector<Client*> clients;
-
-    std::default_random_engine generator;
-    generator.seed(0);
-
-    std::uniform_int_distribution<int>
-        sizeDist(1, 89);
-    std::bernoulli_distribution
-        deleteDist(0.2);
-
-    std::vector<RoundTrip> trips;
-    for (uint32_t i = 0; i < 100; ++i) {
-        trips.push_back({
-            (size_t)sizeDist(generator),
-            (size_t)sizeDist(generator),
-        });
-    };
-
-    int numBlocksMax = 3;
-    int numBlocksDetected = 0;
-    char* bufLow = (char*)(uintptr_t)(-1);
-    char* bufHigh = 0;
-
-    while (true) {
-        Client* c = new Client(mDevice);
-        runRoundTrips(*c, trips);
-
-        clients.push_back(c);
-
-        char* bufPtr = c->getBufferPtr();
-        bufLow = bufPtr < bufLow ? bufPtr : bufLow;
-        bufHigh = bufPtr > bufHigh ? bufPtr : bufHigh;
-
-        size_t gap = bufHigh - bufLow;
-
-        numBlocksDetected =
-            gap / ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE;
-
-        if (numBlocksDetected > numBlocksMax) break;
-
-        if (deleteDist(generator)) {
-            delete c;
-            clients[clients.size() - 1] = 0;
-        }
-    }
-
-    for (auto c: clients) {
-        delete c;
-    }
-}
-
-} // namespace asg
-} // namespace emulation
-} // namespace android
diff --git a/host-common/address_space_host_media.cpp b/host-common/address_space_host_media.cpp
deleted file mode 100644
index 82982b6..0000000
--- a/host-common/address_space_host_media.cpp
+++ /dev/null
@@ -1,202 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_host_media.h"
-#include "host-common/vm_operations.h"
-#include "aemu/base/AlignedBuf.h"
-
-#define AS_DEVICE_DEBUG 0
-
-#if AS_DEVICE_DEBUG
-#define AS_DEVICE_DPRINT(fmt,...) fprintf(stderr, "%s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__);
-#else
-#define AS_DEVICE_DPRINT(fmt,...)
-#endif
-
-namespace android {
-namespace emulation {
-
-enum class DecoderType : uint8_t {
-    Vpx = 0,
-    H264 = 1,
-};
-
-AddressSpaceHostMediaContext::AddressSpaceHostMediaContext(
-    const struct AddressSpaceCreateInfo& create, const address_space_device_control_ops* ops)
-    : mControlOps(ops) {
-    // The memory is allocated in the snapshot load if called from a snapshot load().
-    if (!create.fromSnapshot) {
-        mGuestAddr = create.physAddr;
-        allocatePages(create.physAddr, kNumPages);
-    }
-}
-
-AddressSpaceHostMediaContext::~AddressSpaceHostMediaContext() {
-    deallocatePages(mGuestAddr, kNumPages);
-}
-
-void AddressSpaceHostMediaContext::perform(AddressSpaceDevicePingInfo *info) {
-    handleMediaRequest(info);
-}
-
-AddressSpaceDeviceType AddressSpaceHostMediaContext::getDeviceType() const {
-    return AddressSpaceDeviceType::Media;
-}
-
-void AddressSpaceHostMediaContext::save(base::Stream* stream) const {
-    AS_DEVICE_DPRINT("Saving Host Media snapshot");
-    stream->putBe64(mGuestAddr);
-    int numActiveDecoders = 0;
-    if (mVpxDecoder != nullptr) {
-        ++ numActiveDecoders;
-    }
-    if (mH264Decoder != nullptr) {
-        ++ numActiveDecoders;
-    }
-
-    stream->putBe32(numActiveDecoders);
-    if (mVpxDecoder != nullptr) {
-        AS_DEVICE_DPRINT("Saving VpxDecoder snapshot");
-        stream->putBe32((uint32_t)DecoderType::Vpx);
-        mVpxDecoder->save(stream);
-    }
-    if (mH264Decoder != nullptr) {
-        AS_DEVICE_DPRINT("Saving H264Decoder snapshot");
-        stream->putBe32((uint32_t)DecoderType::H264);
-        mH264Decoder->save(stream);
-    }
-}
-
-bool AddressSpaceHostMediaContext::load(base::Stream* stream) {
-    deallocatePages(mGuestAddr, kNumPages);
-    AS_DEVICE_DPRINT("Loading Host Media snapshot");
-    mGuestAddr = stream->getBe64();
-    allocatePages(mGuestAddr, kNumPages);
-
-    int numActiveDecoders = stream->getBe32();
-    for (int i = 0; i < numActiveDecoders; ++i) {
-        stream->getBe32();
-        // TODO: Add support for virtio-gpu-as-video-decode
-        // switch (t) {
-        // case DecoderType::Vpx:
-        //     AS_DEVICE_DPRINT("Loading VpxDecoder snapshot");
-        //     mVpxDecoder.reset(new MediaVpxDecoder);
-        //     mVpxDecoder->load(stream);
-        //     break;
-        // case DecoderType::H264:
-        //     AS_DEVICE_DPRINT("Loading H264Decoder snapshot");
-        //     mH264Decoder.reset(MediaH264Decoder::create());
-        //     mH264Decoder->load(stream);
-        //     break;
-        // default:
-        //     break;
-        // }
-    }
-    return true;
-}
-
-void AddressSpaceHostMediaContext::allocatePages(uint64_t phys_addr, int num_pages) {
-    mHostBuffer = android::aligned_buf_alloc(kAlignment, num_pages * 4096);
-    mControlOps->add_memory_mapping(
-        phys_addr, mHostBuffer, num_pages * 4096);
-    AS_DEVICE_DPRINT("Allocating host memory for media context: guest_addr 0x%" PRIx64 ", 0x%" PRIx64,
-                     (uint64_t)phys_addr, (uint64_t)mHostBuffer);
-}
-
-void AddressSpaceHostMediaContext::deallocatePages(uint64_t phys_addr,
-                                                   int num_pages) {
-    if (mHostBuffer == nullptr) {
-        return;
-    }
-
-    mControlOps->remove_memory_mapping(phys_addr, mHostBuffer,
-                                       num_pages * 4096);
-    android::aligned_buf_free(mHostBuffer);
-    mHostBuffer = nullptr;
-    AS_DEVICE_DPRINT(
-            "De-Allocating host memory for media context: guest_addr 0x%" PRIx64
-            ", 0x%" PRIx64,
-            (uint64_t)phys_addr, (uint64_t)mHostBuffer);
-}
-
-// static
-MediaCodecType AddressSpaceHostMediaContext::getMediaCodecType(uint64_t metadata) {
-    // Metadata has the following structure:
-    // - Upper 8 bits has the codec type (MediaCodecType)
-    // - Lower 56 bits has metadata specifically for that codec
-    //
-    // We need to hand the data off to the right codec depending on which
-    // codec type we get.
-    uint8_t ret = (uint8_t)(metadata >> (64 - 8));
-    return ret > static_cast<uint8_t>(MediaCodecType::Max) ?
-            MediaCodecType::Max : (MediaCodecType)ret;
-}
-
-// static
-MediaOperation AddressSpaceHostMediaContext::getMediaOperation(uint64_t metadata) {
-    // Metadata has the following structure:
-    // - Upper 8 bits has the codec type (MediaCodecType)
-    // - Lower 56 bits has metadata specifically for that codec
-    //
-    // We need to hand the data off to the right codec depending on which
-    // codec type we get.
-    uint8_t ret = (uint8_t)(metadata & 0xFF);
-    return ret > static_cast<uint8_t>(MediaOperation::Max) ?
-            MediaOperation::Max : (MediaOperation)ret;
-}
-
-static uint64_t getAddrSlot(uint64_t metadata) {
-    uint64_t ret = metadata << 8;  // get rid of typecode
-    ret = ret >> 16;               // get rid of opcode
-    return ret;
-}
-
-void AddressSpaceHostMediaContext::handleMediaRequest(AddressSpaceDevicePingInfo *info) {
-    auto codecType = getMediaCodecType(info->metadata);
-    auto op = getMediaOperation(info->metadata);
-    auto slot = getAddrSlot(info->metadata);
-    uint64_t offSetAddr = slot << 20;
-
-    AS_DEVICE_DPRINT("Got media request (type=%u, op=%u, slot=%lld)",
-                     static_cast<uint8_t>(codecType), static_cast<uint8_t>(op),
-                     (long long)(getAddrSlot(info->metadata)));
-
-    switch (codecType) {
-        case MediaCodecType::VP8Codec:
-        case MediaCodecType::VP9Codec:
-            // if (!mVpxDecoder) {
-            //     mVpxDecoder.reset(new MediaVpxDecoder);
-            // }
-            mVpxDecoder->handlePing(
-                    codecType, op,
-                    (uint8_t*)(mControlOps->get_host_ptr(info->phys_addr)) +
-                            offSetAddr);
-            break;
-        case MediaCodecType::H264Codec:
-            // if (!mH264Decoder) {
-            //     mH264Decoder.reset(MediaH264Decoder::create());
-            // }
-            mH264Decoder->handlePing(
-                    codecType, op,
-                    (uint8_t*)(mControlOps->get_host_ptr(info->phys_addr)) +
-                            offSetAddr);
-            break;
-        default:
-            AS_DEVICE_DPRINT("codec type %d not implemented", (int)codecType);
-            break;
-    }
-}
-
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_host_memory_allocator.cpp b/host-common/address_space_host_memory_allocator.cpp
deleted file mode 100644
index 6b97b5c..0000000
--- a/host-common/address_space_host_memory_allocator.cpp
+++ /dev/null
@@ -1,173 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_host_memory_allocator.h"
-#include "host-common/address_space_device.hpp"
-#include "host-common/vm_operations.h"
-#include "host-common/crash-handler.h"
-#include "host-common/crash_reporter.h"
-#include "aemu/base/AlignedBuf.h"
-
-namespace android {
-namespace emulation {
-namespace {
-size_t align(size_t value, size_t alignment) {
-    return (value + alignment - 1) & (~(alignment - 1));
-}
-}
-
-AddressSpaceHostMemoryAllocatorContext::AddressSpaceHostMemoryAllocatorContext(
-    const address_space_device_control_ops *ops, const AddressSpaceHwFuncs* hw)
-  : m_ops(ops),
-    m_hw(hw) {}
-
-AddressSpaceHostMemoryAllocatorContext::~AddressSpaceHostMemoryAllocatorContext() {
-    clear();
-}
-
-void AddressSpaceHostMemoryAllocatorContext::perform(AddressSpaceDevicePingInfo *info) {
-    uint64_t result;
-
-    switch (static_cast<HostMemoryAllocatorCommand>(info->metadata)) {
-    case HostMemoryAllocatorCommand::Allocate:
-        result = allocate(info);
-        break;
-
-    case HostMemoryAllocatorCommand::Unallocate:
-        result = unallocate(info);
-        break;
-
-    default:
-        result = -1;
-        break;
-    }
-
-    info->metadata = result;
-}
-
-void *AddressSpaceHostMemoryAllocatorContext::allocate_impl(const uint64_t phys_addr,
-                                                            const uint64_t size) {
-#if defined(__APPLE__) && defined(__arm64__)
-    constexpr uint64_t k_alloc_alignment = 16384;
-#else
-    constexpr uint64_t k_alloc_alignment = 4096;
-#endif
-    const uint64_t aligned_size = align(size, (*m_hw->getGuestPageSize)());
-
-    void *host_ptr = android::aligned_buf_alloc(k_alloc_alignment, aligned_size);
-    if (host_ptr) {
-        auto r = m_paddr2ptr.insert({phys_addr, {host_ptr, aligned_size}});
-        if (r.second) {
-            if (m_ops->add_memory_mapping(phys_addr, host_ptr, aligned_size)) {
-                return host_ptr;
-            } else {
-                m_paddr2ptr.erase(r.first);
-                android::aligned_buf_free(host_ptr);
-                return nullptr;
-            }
-        } else {
-            android::aligned_buf_free(host_ptr);
-            return nullptr;
-        }
-    } else {
-        return nullptr;
-    }
-}
-
-uint64_t AddressSpaceHostMemoryAllocatorContext::allocate(AddressSpaceDevicePingInfo *info) {
-    void* host_ptr = allocate_impl(info->phys_addr, info->size);
-    if (host_ptr) {
-        return 0;
-    } else {
-        return -1;
-    }
-}
-
-uint64_t AddressSpaceHostMemoryAllocatorContext::unallocate(AddressSpaceDevicePingInfo *info) {
-    const uint64_t phys_addr = info->phys_addr;
-    const auto i = m_paddr2ptr.find(phys_addr);
-    if (i != m_paddr2ptr.end()) {
-        void* host_ptr = i->second.first;
-        const uint64_t size = i->second.second;
-
-        if (m_ops->remove_memory_mapping(phys_addr, host_ptr, size)) {
-            android::aligned_buf_free(host_ptr);
-            m_paddr2ptr.erase(i);
-            return 0;
-        } else {
-            crashhandler_die("Failed remove a memory mapping {phys_addr=%lx, host_ptr=%p, size=%lu}",
-                             phys_addr, host_ptr, size);
-        }
-    } else {
-        return -1;
-    }
-}
-
-AddressSpaceDeviceType AddressSpaceHostMemoryAllocatorContext::getDeviceType() const {
-    return AddressSpaceDeviceType::HostMemoryAllocator;
-}
-
-void AddressSpaceHostMemoryAllocatorContext::save(base::Stream* stream) const {
-    stream->putBe32(m_paddr2ptr.size());
-
-    for (const auto &kv : m_paddr2ptr) {
-        const uint64_t phys_addr = kv.first;
-        const uint64_t size = kv.second.second;
-        const void *mem = kv.second.first;
-
-        stream->putBe64(phys_addr);
-        stream->putBe64(size);
-        stream->write(mem, size);
-    }
-}
-
-bool AddressSpaceHostMemoryAllocatorContext::load(base::Stream* stream) {
-    clear();
-
-    size_t numAddr = stream->getBe32();
-
-    for (size_t i = 0; i < numAddr; ++i) {
-        uint64_t phys_addr = stream->getBe64();
-        uint64_t size = stream->getBe64();
-        void *mem = allocate_impl(phys_addr, size);
-        if (mem) {
-            if (stream->read(mem, size) != static_cast<ssize_t>(size)) {
-                return false;
-            }
-        } else {
-            return false;
-        }
-    }
-
-    return true;
-}
-
-void AddressSpaceHostMemoryAllocatorContext::clear() {
-    for (const auto& kv : m_paddr2ptr) {
-        uint64_t phys_addr = kv.first;
-        void *host_ptr = kv.second.first;
-        size_t size = kv.second.second;
-
-        if (m_ops->remove_memory_mapping(phys_addr, host_ptr, size)) {
-            android::aligned_buf_free(host_ptr);
-        } else {
-            crashhandler_die("Failed remove a memory mapping {phys_addr=%lx, host_ptr=%p, size=%lu}",
-                             phys_addr, host_ptr, size);
-        }
-    }
-    m_paddr2ptr.clear();
-}
-
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_host_memory_allocator_unittests.cpp b/host-common/address_space_host_memory_allocator_unittests.cpp
deleted file mode 100644
index 8ec3fa2..0000000
--- a/host-common/address_space_host_memory_allocator_unittests.cpp
+++ /dev/null
@@ -1,183 +0,0 @@
-// Copyright 2016 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_host_memory_allocator.h"
-#include <gtest/gtest.h>
-
-namespace android {
-namespace emulation {
-
-namespace {
-constexpr uint64_t BAD_GPA = 0x1234000;
-constexpr uint64_t GOOD_GPA_1 = 0x10001000;
-constexpr uint64_t GOOD_GPA_2 = 0x20002000;
-
-int empty_add_memory_mapping(uint64_t gpa, void *ptr, uint64_t size) {
-    return (gpa == BAD_GPA) ? 0 : 1;
-}
-
-int empty_remove_memory_mapping(uint64_t gpa, void *ptr, uint64_t size) { return 1; }
-
-uint32_t getGuestPageSize() {
-    return 4096;
-}
-
-struct address_space_device_control_ops create_address_space_device_control_ops() {
-    struct address_space_device_control_ops ops = {};
-
-    ops.add_memory_mapping = &empty_add_memory_mapping;
-    ops.remove_memory_mapping = &empty_remove_memory_mapping;
-
-    return ops;
-}
-
-AddressSpaceHwFuncs create_address_space_device_hw_funcs() {
-    AddressSpaceHwFuncs hw_funcs = {};
-
-    hw_funcs.getGuestPageSize = &getGuestPageSize;
-
-    return hw_funcs;
-}
-
-AddressSpaceDevicePingInfo createAllocateRequest(uint64_t phys_addr) {
-    AddressSpaceDevicePingInfo req = {};
-
-    req.metadata = static_cast<uint64_t>(
-        AddressSpaceHostMemoryAllocatorContext::HostMemoryAllocatorCommand::Allocate);
-    req.phys_addr = phys_addr;
-    req.size = 1;
-
-    return req;
-}
-
-AddressSpaceDevicePingInfo createUnallocateRequest(uint64_t phys_addr) {
-    AddressSpaceDevicePingInfo req = {};
-
-    req.metadata = static_cast<uint64_t>(
-        AddressSpaceHostMemoryAllocatorContext::HostMemoryAllocatorCommand::Unallocate);
-    req.phys_addr = phys_addr;
-
-    return req;
-}
-}  // namespace
-
-TEST(AddressSpaceHostMemoryAllocatorContext, getDeviceType) {
-    struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    AddressSpaceHwFuncs hw_funcs = create_address_space_device_hw_funcs();
-
-    AddressSpaceHostMemoryAllocatorContext ctx(&ops, &hw_funcs);
-
-    EXPECT_EQ(ctx.getDeviceType(), AddressSpaceDeviceType::HostMemoryAllocator);
-}
-
-TEST(AddressSpaceHostMemoryAllocatorContext, AllocateDeallocate) {
-    struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    AddressSpaceHwFuncs hw_funcs = create_address_space_device_hw_funcs();
-
-    AddressSpaceHostMemoryAllocatorContext ctx(&ops, &hw_funcs);
-
-    AddressSpaceDevicePingInfo req;
-
-    req = createAllocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-}
-
-TEST(AddressSpaceHostMemoryAllocatorContext, AllocateSamePhysAddr) {
-    struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    AddressSpaceHwFuncs hw_funcs = create_address_space_device_hw_funcs();
-
-    AddressSpaceHostMemoryAllocatorContext ctx(&ops, &hw_funcs);
-
-    AddressSpaceDevicePingInfo req;
-
-    req = createAllocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createAllocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_NE(req.metadata, 0);
-
-    req = createAllocateRequest(GOOD_GPA_2);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_2);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createAllocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-}
-
-TEST(AddressSpaceHostMemoryAllocatorContext, AllocateMappingFail) {
-    struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    AddressSpaceHwFuncs hw_funcs = create_address_space_device_hw_funcs();
-
-    AddressSpaceHostMemoryAllocatorContext ctx(&ops, &hw_funcs);
-
-    AddressSpaceDevicePingInfo req;
-
-    req = createAllocateRequest(BAD_GPA);
-    ctx.perform(&req);
-    EXPECT_NE(req.metadata, 0);
-}
-
-TEST(AddressSpaceHostMemoryAllocatorContext, UnallocateTwice) {
-    struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    AddressSpaceHwFuncs hw_funcs = create_address_space_device_hw_funcs();
-
-    AddressSpaceHostMemoryAllocatorContext ctx(&ops, &hw_funcs);
-
-    AddressSpaceDevicePingInfo req;
-
-    req = createAllocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_EQ(req.metadata, 0);
-
-    req = createUnallocateRequest(GOOD_GPA_1);
-    ctx.perform(&req);
-    EXPECT_NE(req.metadata, 0);
-}
-
-}  // namespace emulation
-} // namespace android
diff --git a/host-common/address_space_shared_slots_host_memory_allocator.cpp b/host-common/address_space_shared_slots_host_memory_allocator.cpp
deleted file mode 100644
index c6d74e2..0000000
--- a/host-common/address_space_shared_slots_host_memory_allocator.cpp
+++ /dev/null
@@ -1,486 +0,0 @@
-// Copyright 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_shared_slots_host_memory_allocator.h"
-#include "host-common/address_space_device.hpp"
-#include "host-common/vm_operations.h"
-#include "host-common/crash-handler.h"
-#include "host-common/crash_reporter.h"
-#include "aemu/base/AlignedBuf.h"
-#include "aemu/base/synchronization/Lock.h"
-#include <map>
-#include <unordered_set>
-#include <unordered_map>
-#include <utility>
-
-namespace android {
-namespace emulation {
-namespace {
-size_t align(size_t value, size_t alignment) {
-    return (value + alignment - 1) & (~(alignment - 1));
-}
-
-typedef AddressSpaceSharedSlotsHostMemoryAllocatorContext ASSSHMAC;
-typedef ASSSHMAC::MemBlock MemBlock;
-typedef MemBlock::FreeSubblocks_t FreeSubblocks_t;
-
-using base::AutoLock;
-using base::Lock;
-
-#if defined(__APPLE__) && defined(__arm64__)
-constexpr uint32_t kAllocAlignment = 16384;
-#else
-constexpr uint32_t kAllocAlignment = 4096;
-#endif
-
-uint64_t allocateAddressSpaceBlock(const AddressSpaceHwFuncs* hw, uint32_t size) {
-    uint64_t offset;
-    if (hw->allocSharedHostRegionLocked(size, &offset)) {
-        return 0;
-    } else {
-        return hw->getPhysAddrStartLocked() + offset;
-    }
-}
-
-uint64_t allocateAddressSpaceBlockFixed(uint64_t gpa, const AddressSpaceHwFuncs* hw, uint32_t size) {
-    uint64_t offset = gpa - hw->getPhysAddrStartLocked();
-    if (hw->allocSharedHostRegionFixedLocked(size, offset)) {
-        // Note: even if we do not succeed in allocSharedHostRegionFixedLocked,
-        // assume this is because we're doing a snapshot load, and the VMSTATE
-        // description of memory slots in hw/pci/goldfish_address_space.c
-        // already contains the entry we wanted. TODO: Consider always
-        // allowing allocSharedHostRegionFixedLocked succeed if it encounters
-        // an unavailable block at the same offset and size, and/or add a
-        // "forSnapshotLoad" flag to allocSharedHostRegionFixedLocked in order
-        // to specifically account for this case.
-        return hw->getPhysAddrStartLocked() + offset;
-    } else {
-        return hw->getPhysAddrStartLocked() + offset;
-    }
-}
-
-int freeAddressBlock(const AddressSpaceHwFuncs* hw, uint64_t phys) {
-    const uint64_t start = hw->getPhysAddrStartLocked();
-    if (phys < start) { return -1; }
-    return hw->freeSharedHostRegionLocked(phys - start);
-}
-
-std::map<uint64_t, MemBlock> g_blocks;
-Lock g_blocksLock;
-
-std::pair<uint64_t, MemBlock*> translatePhysAddr(uint64_t p) {
-    for (auto& kv: g_blocks) {
-        MemBlock& block = kv.second;
-        if (p >= block.physBaseLoaded && p < block.physBaseLoaded + block.bitsSize) {
-            return {block.physBase + (p - block.physBaseLoaded), &block};
-        }
-    }
-
-    return {0, nullptr};
-}
-}  // namespace
-
-MemBlock::MemBlock(const address_space_device_control_ops* o, const AddressSpaceHwFuncs* h, uint32_t sz)
-        : ops(o), hw(h) {
-    bits = android::aligned_buf_alloc(kAllocAlignment, sz);
-    bitsSize = sz;
-    physBase = allocateAddressSpaceBlock(hw, sz);
-    if (!physBase) {
-        crashhandler_die("%s:%d: allocateAddressSpaceBlock", __func__, __LINE__);
-    }
-    physBaseLoaded = 0;
-    if (!ops->add_memory_mapping(physBase, bits, bitsSize)) {
-        crashhandler_die("%s:%d: add_memory_mapping", __func__, __LINE__);
-    }
-
-    if (!freeSubblocks.insert({0, sz}).second) {
-        crashhandler_die("%s:%d: freeSubblocks.insert", __func__, __LINE__);
-    }
-}
-
-MemBlock::MemBlock(MemBlock&& rhs)
-    : ops(std::exchange(rhs.ops, nullptr)),
-      hw(std::exchange(rhs.hw, nullptr)),
-      physBase(std::exchange(rhs.physBase, 0)),
-      physBaseLoaded(std::exchange(rhs.physBaseLoaded, 0)),
-      bits(std::exchange(rhs.bits, nullptr)),
-      bitsSize(std::exchange(rhs.bitsSize, 0)),
-      freeSubblocks(std::move(rhs.freeSubblocks)) {
-}
-
-MemBlock& MemBlock::operator=(MemBlock rhs) {
-    swap(*this, rhs);
-    return *this;
-}
-
-MemBlock::~MemBlock() {
-    if (physBase) {
-        ops->remove_memory_mapping(physBase, bits, bitsSize);
-        freeAddressBlock(hw, physBase);
-        android::aligned_buf_free(bits);
-    }
-}
-
-void swap(MemBlock& lhs, MemBlock& rhs) {
-    using std::swap;
-
-    swap(lhs.physBase,          rhs.physBase);
-    swap(lhs.physBaseLoaded,    rhs.physBaseLoaded);
-    swap(lhs.bits,              rhs.bits);
-    swap(lhs.bitsSize,          rhs.bitsSize);
-    swap(lhs.freeSubblocks,     rhs.freeSubblocks);
-}
-
-
-bool MemBlock::isAllFree() const {
-    if (freeSubblocks.size() == 1) {
-        const auto kv = *freeSubblocks.begin();
-        return (kv.first == 0) && (kv.second == bitsSize);
-    } else {
-        return false;
-    }
-}
-
-uint64_t MemBlock::allocate(const size_t requestedSize) {
-    FreeSubblocks_t::iterator i = findFreeSubblock(&freeSubblocks, requestedSize);
-    if (i == freeSubblocks.end()) {
-        return 0;
-    }
-
-    const uint32_t subblockOffset = i->first;
-    const uint32_t subblockSize = i->second;
-
-    freeSubblocks.erase(i);
-    if (subblockSize > requestedSize) {
-        if (!freeSubblocks.insert({subblockOffset + requestedSize,
-                                   subblockSize - requestedSize}).second) {
-            crashhandler_die("%s:%d: freeSubblocks.insert", __func__, __LINE__);
-        }
-    }
-
-    return physBase + subblockOffset;
-}
-
-void MemBlock::unallocate(
-        uint64_t phys, uint32_t subblockSize) {
-    if (phys >= physBase + bitsSize) {
-        crashhandler_die("%s:%d: phys >= physBase + bitsSize", __func__, __LINE__);
-    }
-
-    auto r = freeSubblocks.insert({phys - physBase, subblockSize});
-    if (!r.second) {
-        crashhandler_die("%s:%d: freeSubblocks.insert", __func__, __LINE__);
-    }
-
-    FreeSubblocks_t::iterator i = r.first;
-    if (i != freeSubblocks.begin()) {
-        i = tryMergeSubblocks(&freeSubblocks, i, std::prev(i), i);
-    }
-    FreeSubblocks_t::iterator next = std::next(i);
-    if (next != freeSubblocks.end()) {
-        i = tryMergeSubblocks(&freeSubblocks, i, i, next);
-    }
-}
-
-FreeSubblocks_t::iterator MemBlock::findFreeSubblock(FreeSubblocks_t* fsb,
-                                                     const size_t sz) {
-    if (fsb->empty()) {
-        return fsb->end();
-    } else {
-        auto best = fsb->end();
-        size_t bestSize = ~size_t(0);
-
-        for (auto i = fsb->begin(); i != fsb->end(); ++i) {
-            if (i->second >= sz && sz < bestSize) {
-                best = i;
-                bestSize = i->second;
-            }
-        }
-
-        return best;
-    }
-}
-
-FreeSubblocks_t::iterator MemBlock::tryMergeSubblocks(
-        FreeSubblocks_t* fsb,
-        FreeSubblocks_t::iterator ret,
-        FreeSubblocks_t::iterator lhs,
-        FreeSubblocks_t::iterator rhs) {
-    if (lhs->first + lhs->second == rhs->first) {
-        const uint32_t subblockOffset = lhs->first;
-        const uint32_t subblockSize = lhs->second + rhs->second;
-
-        fsb->erase(lhs);
-        fsb->erase(rhs);
-        auto r = fsb->insert({subblockOffset, subblockSize});
-        if (!r.second) {
-            crashhandler_die("%s:%d: fsb->insert", __func__, __LINE__);
-        }
-
-        return r.first;
-    } else {
-        return ret;
-    }
-}
-
-void MemBlock::save(base::Stream* stream) const {
-    stream->putBe64(physBase);
-    stream->putBe32(bitsSize);
-    stream->write(bits, bitsSize);
-    stream->putBe32(freeSubblocks.size());
-    for (const auto& kv: freeSubblocks) {
-        stream->putBe32(kv.first);
-        stream->putBe32(kv.second);
-    }
-}
-
-bool MemBlock::load(base::Stream* stream,
-                    const address_space_device_control_ops* ops,
-                    const AddressSpaceHwFuncs* hw,
-                    MemBlock* block) {
-    const uint64_t physBaseLoaded = stream->getBe64();
-    const uint32_t bitsSize = stream->getBe32();
-    void* const bits = android::aligned_buf_alloc(kAllocAlignment, bitsSize);
-    if (!bits) {
-        return false;
-    }
-    if (stream->read(bits, bitsSize) != static_cast<ssize_t>(bitsSize)) {
-        android::aligned_buf_free(bits);
-        return false;
-    }
-    const uint64_t physBase = allocateAddressSpaceBlockFixed(physBaseLoaded, hw, bitsSize);
-    if (!physBase) {
-        android::aligned_buf_free(bits);
-        return false;
-    }
-    if (!ops->add_memory_mapping(physBase, bits, bitsSize)) {
-        freeAddressBlock(hw, physBase);
-        android::aligned_buf_free(bits);
-        return false;
-    }
-
-    FreeSubblocks_t freeSubblocks;
-    for (uint32_t freeSubblocksSize = stream->getBe32();
-         freeSubblocksSize > 0;
-         --freeSubblocksSize) {
-        const uint32_t off = stream->getBe32();
-        const uint32_t sz = stream->getBe32();
-        if (!freeSubblocks.insert({off, sz}).second) {
-            crashhandler_die("%s:%d: freeSubblocks.insert", __func__, __LINE__);
-        }
-    }
-
-    block->hw = hw;
-    block->ops = ops;
-    block->physBase = physBase;
-    block->physBaseLoaded = physBaseLoaded;
-    block->bits = bits;
-    block->bitsSize = bitsSize;
-    block->freeSubblocks = std::move(freeSubblocks);
-
-    return true;
-}
-
-AddressSpaceSharedSlotsHostMemoryAllocatorContext::AddressSpaceSharedSlotsHostMemoryAllocatorContext(
-    const address_space_device_control_ops *ops, const AddressSpaceHwFuncs* hw)
-  : m_ops(ops),
-    m_hw(hw) {}
-
-AddressSpaceSharedSlotsHostMemoryAllocatorContext::~AddressSpaceSharedSlotsHostMemoryAllocatorContext() {
-    clear();
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::perform(AddressSpaceDevicePingInfo *info) {
-    uint64_t result;
-
-    switch (static_cast<HostMemoryAllocatorCommand>(info->metadata)) {
-    case HostMemoryAllocatorCommand::Allocate:
-        result = allocate(info);
-        break;
-
-    case HostMemoryAllocatorCommand::Unallocate:
-        result = unallocate(info->phys_addr);
-        break;
-
-    case HostMemoryAllocatorCommand::CheckIfSharedSlotsSupported:
-        result = 0;
-        break;
-
-    default:
-        result = -1;
-        break;
-    }
-
-    info->metadata = result;
-}
-
-uint64_t
-AddressSpaceSharedSlotsHostMemoryAllocatorContext::allocate(
-        AddressSpaceDevicePingInfo *info) {
-    const uint32_t alignedSize = align(info->size, (*m_hw->getGuestPageSize)());
-
-    AutoLock lock(g_blocksLock);
-    for (auto& kv : g_blocks) {
-        uint64_t physAddr = kv.second.allocate(alignedSize);
-        if (physAddr) {
-            return populatePhysAddr(info, physAddr, alignedSize, &kv.second);
-        }
-    }
-
-    const uint32_t defaultSize = 64u << 20;
-    MemBlock newBlock(m_ops, m_hw, std::max(alignedSize, defaultSize));
-    const uint64_t physAddr = newBlock.allocate(alignedSize);
-    if (!physAddr) {
-        return -1;
-    }
-
-    const uint64_t physBase = newBlock.physBase;
-    auto r = g_blocks.insert({physBase, std::move(newBlock)});
-    if (!r.second) {
-        crashhandler_die("%s:%d: g_blocks.insert", __func__, __LINE__);
-    }
-
-    return populatePhysAddr(info, physAddr, alignedSize, &r.first->second);
-}
-
-uint64_t
-AddressSpaceSharedSlotsHostMemoryAllocatorContext::unallocate(
-        const uint64_t physAddr) {
-    AutoLock lock(g_blocksLock);
-
-    auto i = m_allocations.find(physAddr);
-    if (i == m_allocations.end()) {
-        return -1;
-    }
-
-    MemBlock* block = i->second.second;
-    block->unallocate(physAddr, i->second.first);
-    m_allocations.erase(physAddr);
-
-    if (block->isAllFree()) {
-        gcEmptyBlocks(1);
-    }
-
-    return 0;
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::gcEmptyBlocks(int allowedEmpty) {
-    auto i = g_blocks.begin();
-    while (i != g_blocks.end()) {
-        if (i->second.isAllFree()) {
-            if (allowedEmpty > 0) {
-                --allowedEmpty;
-                ++i;
-            } else {
-                i = g_blocks.erase(i);
-            }
-        } else {
-            ++i;
-        }
-    }
-}
-
-uint64_t AddressSpaceSharedSlotsHostMemoryAllocatorContext::populatePhysAddr(
-        AddressSpaceDevicePingInfo *info,
-        const uint64_t physAddr,
-        const uint32_t alignedSize,
-        MemBlock* owner) {
-    info->phys_addr = physAddr - get_address_space_device_hw_funcs()->getPhysAddrStartLocked();
-    info->size = alignedSize;
-    if (!m_allocations.insert({physAddr, {alignedSize, owner}}).second) {
-        crashhandler_die("%s:%d: m_allocations.insert", __func__, __LINE__);
-    }
-    return 0;
-}
-
-AddressSpaceDeviceType AddressSpaceSharedSlotsHostMemoryAllocatorContext::getDeviceType() const {
-    return AddressSpaceDeviceType::SharedSlotsHostMemoryAllocator;
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::save(base::Stream* stream) const {
-    AutoLock lock(g_blocksLock);
-
-    stream->putBe32(m_allocations.size());
-    for (const auto& kv: m_allocations) {
-        stream->putBe64(kv.first);
-        stream->putBe32(kv.second.first);
-    }
-}
-
-bool AddressSpaceSharedSlotsHostMemoryAllocatorContext::load(base::Stream* stream) {
-    clear();
-
-    AutoLock lock(g_blocksLock);
-    for (uint32_t sz = stream->getBe32(); sz > 0; --sz) {
-        const uint64_t phys = stream->getBe64();
-        const uint32_t size = stream->getBe32();
-        const auto r = translatePhysAddr(phys);
-        if (phys) {
-            if (!m_allocations.insert({r.first, {size, r.second}}).second) {
-                crashhandler_die("%s:%d: m_allocations.insert", __func__, __LINE__);
-            }
-        } else {
-            crashhandler_die("%s:%d: translatePhysAddr", __func__, __LINE__);
-        }
-    }
-
-    return true;
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::clear() {
-    AutoLock lock(g_blocksLock);
-    for (const auto& kv: m_allocations) {
-        MemBlock* block = kv.second.second;
-        block->unallocate(kv.first, kv.second.first);
-    }
-    m_allocations.clear();
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateSave(base::Stream* stream) {
-    AutoLock lock(g_blocksLock);
-
-    stream->putBe32(g_blocks.size());
-    for (const auto& kv: g_blocks) {
-        kv.second.save(stream);
-    }
-}
-
-// get_address_space_device_hw_funcs()
-
-bool AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateLoad(
-        base::Stream* stream,
-        const address_space_device_control_ops *ops,
-        const AddressSpaceHwFuncs* hw) {
-    AutoLock lock(g_blocksLock);
-
-    for (uint32_t sz = stream->getBe32(); sz > 0; --sz) {
-        MemBlock block;
-        if (!MemBlock::load(stream, ops, hw, &block)) { return false; }
-
-        const uint64_t physBase = block.physBase;
-        if (!g_blocks.insert({physBase, std::move(block)}).second) {
-            crashhandler_die("%s:%d: block->unallocate", __func__, __LINE__);
-        }
-    }
-
-    return true;
-}
-
-void AddressSpaceSharedSlotsHostMemoryAllocatorContext::globalStateClear() {
-    AutoLock lock(g_blocksLock);
-    g_blocks.clear();
-}
-
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_shared_slots_host_memory_allocator_unittests.cpp b/host-common/address_space_shared_slots_host_memory_allocator_unittests.cpp
deleted file mode 100644
index a25bfba..0000000
--- a/host-common/address_space_shared_slots_host_memory_allocator_unittests.cpp
+++ /dev/null
@@ -1,184 +0,0 @@
-// Copyright 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/address_space_shared_slots_host_memory_allocator.h"
-#include <gtest/gtest.h>
-
-namespace android {
-namespace emulation {
-namespace {
-typedef AddressSpaceSharedSlotsHostMemoryAllocatorContext ASSSHMAC;
-typedef ASSSHMAC::MemBlock MemBlock;
-typedef MemBlock::FreeSubblocks_t FreeSubblocks_t;
-
-int add_memory_mapping(uint64_t gpa, void *ptr, uint64_t size) {
-    return 1;
-}
-
-int remove_memory_mapping(uint64_t gpa, void *ptr, uint64_t size) { return 1; }
-
-struct address_space_device_control_ops create_address_space_device_control_ops() {
-    struct address_space_device_control_ops ops = {};
-
-    ops.add_memory_mapping = &add_memory_mapping;
-    ops.remove_memory_mapping = &remove_memory_mapping;
-
-    return ops;
-}
-
-uint64_t getPhysAddrStartLocked(void) {
-    return 2020;
-}
-
-int allocSharedHostRegionLocked(uint64_t page_aligned_size, uint64_t* offset) {
-    *offset = page_aligned_size * 10;
-    return 0;
-}
-
-int freeSharedHostRegionLocked(uint64_t offset) {
-    return 0;
-}
-
-AddressSpaceHwFuncs create_AddressSpaceHwFuncs() {
-    AddressSpaceHwFuncs hw = {};
-
-    hw.allocSharedHostRegionLocked = &allocSharedHostRegionLocked;
-    hw.freeSharedHostRegionLocked = &freeSharedHostRegionLocked;
-    hw.getPhysAddrStartLocked = &getPhysAddrStartLocked;
-
-    return hw;
-}
-}
-
-TEST(MemBlock_findFreeSubblock, Simple) {
-    FreeSubblocks_t fsb;
-    EXPECT_TRUE(MemBlock::findFreeSubblock(&fsb, 11) == fsb.end());
-
-    fsb[100] = 10;
-    EXPECT_TRUE(MemBlock::findFreeSubblock(&fsb, 11) == fsb.end());
-
-    FreeSubblocks_t::const_iterator i;
-
-    i = MemBlock::findFreeSubblock(&fsb, 7);
-    ASSERT_TRUE(i != fsb.end());
-    EXPECT_EQ(i->first, 100);
-    EXPECT_EQ(i->second, 10);
-
-    fsb[200] = 6;
-    i = MemBlock::findFreeSubblock(&fsb, 7);
-    ASSERT_TRUE(i != fsb.end());
-    EXPECT_EQ(i->first, 100);
-    EXPECT_EQ(i->second, 10);
-
-    fsb[300] = 8;
-    i = MemBlock::findFreeSubblock(&fsb, 7);
-    ASSERT_TRUE(i != fsb.end());
-    EXPECT_EQ(i->first, 300);
-    EXPECT_EQ(i->second, 8);
-}
-
-TEST(MemBlock_tryMergeSubblocks, NoMerge) {
-    FreeSubblocks_t fsb;
-
-    auto i = fsb.insert({10, 5}).first;
-    auto j = fsb.insert({20, 5}).first;
-
-    auto r = MemBlock::tryMergeSubblocks(&fsb, i, i, j);
-
-    EXPECT_EQ(fsb.size(), 2);
-    EXPECT_EQ(fsb[10], 5);
-    EXPECT_EQ(fsb[20], 5);
-    EXPECT_TRUE(r == i);
-}
-
-TEST(MemBlock_tryMergeSubblocks, Merge) {
-    FreeSubblocks_t fsb;
-
-    auto i = fsb.insert({10, 10}).first;
-    auto j = fsb.insert({20, 5}).first;
-
-    auto r = MemBlock::tryMergeSubblocks(&fsb, i, i, j);
-
-    EXPECT_EQ(fsb.size(), 1);
-    EXPECT_EQ(fsb[10], 15);
-    ASSERT_TRUE(r != fsb.end());
-    EXPECT_EQ(r->first, 10);
-    EXPECT_EQ(r->second, 15);
-}
-
-TEST(MemBlock, allocate) {
-    const struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    const AddressSpaceHwFuncs hw = create_AddressSpaceHwFuncs();
-
-    MemBlock block(&ops, &hw, 100);
-    EXPECT_TRUE(block.isAllFree());
-    EXPECT_EQ(block.physBase, 2020 + 100 * 10);
-
-    EXPECT_EQ(block.allocate(110), 0);  // too large
-
-    uint32_t off;
-
-    off = block.allocate(50);
-    EXPECT_GE(off, 2020 + 100 * 10);
-
-    off = block.allocate(47);
-    EXPECT_GE(off, 2020 + 100 * 10);
-
-    off = block.allocate(2);
-    EXPECT_GE(off, 2020 + 100 * 10);
-
-    off = block.allocate(2);
-    EXPECT_EQ(off, 0);
-
-    off = block.allocate(1);
-    EXPECT_GE(off, 2020 + 100 * 10);
-
-    off = block.allocate(1);
-    EXPECT_EQ(off, 0);
-}
-
-TEST(MemBlock, unallocate) {
-    const struct address_space_device_control_ops ops =
-        create_address_space_device_control_ops();
-
-    const AddressSpaceHwFuncs hw = create_AddressSpaceHwFuncs();
-
-    MemBlock block(&ops, &hw, 100);
-    EXPECT_TRUE(block.isAllFree());
-    EXPECT_EQ(block.physBase, 2020 + 100 * 10);
-
-    uint32_t off60 = block.allocate(60);
-    EXPECT_GE(off60, 2020 + 100 * 10);
-
-    uint32_t off20 = block.allocate(20);
-    EXPECT_GE(off20, 2020 + 100 * 10);
-
-    uint32_t off30 = block.allocate(30);
-    EXPECT_EQ(off30, 0);
-
-    block.unallocate(off20, 20);
-
-    off30 = block.allocate(30);
-    EXPECT_GE(off30, 2020 + 100 * 10);
-
-    block.unallocate(off60, 60);
-    block.unallocate(off30, 30);
-
-    EXPECT_TRUE(block.isAllFree());
-}
-
-}  // namespace emulation
-} // namespace android
diff --git a/host-common/dma_device.cpp b/host-common/dma_device.cpp
deleted file mode 100644
index d98b18a..0000000
--- a/host-common/dma_device.cpp
+++ /dev/null
@@ -1,34 +0,0 @@
-// Copyright 2023 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "GoldfishDma.h"
-#include "dma_device.h"
-
-static void* defaultDmaGetHostAddr(uint64_t guest_paddr) { return nullptr; }
-static void defaultDmaUnlock(uint64_t addr) { }
-
-namespace emugl {
-
-emugl_dma_get_host_addr_t g_emugl_dma_get_host_addr = defaultDmaGetHostAddr;
-emugl_dma_unlock_t g_emugl_dma_unlock = defaultDmaUnlock;
-
-void set_emugl_dma_get_host_addr(emugl_dma_get_host_addr_t f) {
-    g_emugl_dma_get_host_addr = f;
-}
-
-void set_emugl_dma_unlock(emugl_dma_unlock_t f) {
-    g_emugl_dma_unlock = f;
-}
-
-}  // namespace emugl
diff --git a/host-common/goldfish_sync.cpp b/host-common/goldfish_sync.cpp
deleted file mode 100644
index 248bffc..0000000
--- a/host-common/goldfish_sync.cpp
+++ /dev/null
@@ -1,193 +0,0 @@
-// Copyright 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/goldfish_sync.h"
-#include "host-common/GoldfishSyncCommandQueue.h"
-
-#include "aemu/base/containers/Lookup.h"
-#include "aemu/base/synchronization/ConditionVariable.h"
-#include "aemu/base/synchronization/Lock.h"
-
-#include <unordered_map>
-
-using android::base::AutoLock;
-using android::base::ConditionVariable;
-using android::base::Lock;
-using android::base::StaticLock;
-using android::GoldfishSyncCommandQueue;
-
-// Commands can be tagged with with unique id's,
-// so that for the commands that require a reply
-// from the guest, we signal them properly.
-static uint64_t sUniqueId = 0;
-// When we track command completion, we need to be
-// careful about concurrent access.
-// |sCommandReplyLock| protects
-// |sUniqueId| and |wait_map|, including
-// the |CommandWaitInfo| structures within.
-static StaticLock sCommandReplyLock = {};
-
-uint64_t next_unique_id() {
-    AutoLock lock(sCommandReplyLock);
-    uint64_t res = sUniqueId;
-    sUniqueId += 1;
-    return res;
-}
-
-struct CommandWaitInfo {
-    Lock lock; // protects other parts of this struct
-    bool done = false;
-    ConditionVariable cvDone;
-    uint64_t return_value;
-};
-
-// |wait_map| keeps track of all the commands in flight
-// that require a reply from the guest.
-static std::unordered_map<uint64_t, std::unique_ptr<CommandWaitInfo> >
-    wait_map;
-
-static CommandWaitInfo* allocWait(uint64_t id) {
-    AutoLock lock(sCommandReplyLock);
-    std::unique_ptr<CommandWaitInfo>& res =
-        wait_map[id];
-    res.reset(new CommandWaitInfo);
-    return res.get();
-}
-
-static void freeWait(uint64_t id) {
-    AutoLock lock(sCommandReplyLock);
-    wait_map.erase(id);
-}
-
-static GoldfishSyncDeviceInterface* sGoldfishSyncHwFuncs = NULL;
-
-////////////////////////////////////////////////////////////////////////////////
-// Goldfish sync device: command send/receive protocol
-// To send commands to the virtual device, there are two
-// alternatives:
-// - |sendCommand|, which just sends the command without waiting
-//   for a reply.
-// - |sendCommandAndGetResult|, which sends the command and waits
-//   for that command to have completed in the guest.
-
-// |sendCommand| is used to send Goldfish sync commands while
-// not caring about a reply from the guest. During normal operation,
-// we will only use |sendCommand| to send over a |goldfish_sync_timeline_inc|
-// call, to signal fence FD's on the guest.
-static void sendCommand(uint32_t cmd,
-                        uint64_t handle,
-                        uint32_t time_arg) {
-    GoldfishSyncCommandQueue::hostSignal
-        (cmd, handle, time_arg, 0
-         // last arg 0 OK because we will not reference it
-        );
-}
-
-// Receiving commands can be interesting because we do not know when
-// the kernel will get to servicing a command we sent from the host.
-//
-// |receiveCommandResult| is for host->guest goldfish sync commands
-// that require a reply from the guest. So far, this is used only
-// in the functional tests, as we never issue
-// |goldfish_sync_create_timeline| / |goldfish_sync_create_fence|
-// from the host directly in normal operation.
-//
-// This function will be called by the virtual device
-// upon receiving a reply from the guest for the host->guest
-// commands that require replies.
-//
-// The implementation is that such commands will use a condition
-// variable that waits on the result.
-void goldfish_sync_receive_hostcmd_result(uint32_t cmd,
-                                          uint64_t handle,
-                                          uint32_t time_arg,
-                                          uint64_t hostcmd_handle) {
-    if (auto elt = android::base::find(wait_map, hostcmd_handle)) {
-        CommandWaitInfo* wait_info = elt->get();
-        AutoLock lock(wait_info->lock);
-        wait_info->return_value = handle;
-        wait_info->done = true;
-        wait_info->cvDone.broadcast();
-    }
-}
-
-// |sendCommandAndGetResult| uses |sendCommand| and
-// |goldfish_sync_receive_hostcmd_result| for processing
-// commands that require replies from the guest.
-static uint64_t sendCommandAndGetResult(uint64_t cmd,
-                                        uint64_t handle,
-                                        uint64_t time_arg,
-                                        uint64_t hostcmd_handle) {
-
-    // queue a signal to the device
-    GoldfishSyncCommandQueue::hostSignal
-        (cmd, handle, time_arg, hostcmd_handle);
-
-    CommandWaitInfo* waitInfo = allocWait(hostcmd_handle);
-
-    uint64_t res;
-
-    {
-        AutoLock lock(waitInfo->lock);
-        while (!waitInfo->done) {
-            waitInfo->cvDone.wait(&waitInfo->lock);
-        }
-
-        res = waitInfo->return_value;
-    }
-
-    freeWait(hostcmd_handle);
-
-    return res;
-}
-
-// Goldfish sync host-side interface implementation/////////////////////////////
-
-uint64_t goldfish_sync_create_timeline() {
-    return sendCommandAndGetResult(CMD_CREATE_SYNC_TIMELINE,
-                                   0, 0, next_unique_id());
-}
-
-int goldfish_sync_create_fence(uint64_t timeline, uint32_t pt) {
-    return (int)sendCommandAndGetResult(CMD_CREATE_SYNC_FENCE,
-                                        timeline, pt, next_unique_id());
-}
-
-void goldfish_sync_timeline_inc(uint64_t timeline, uint32_t howmuch) {
-    sendCommand(CMD_SYNC_TIMELINE_INC, timeline, howmuch);
-}
-
-void goldfish_sync_destroy_timeline(uint64_t timeline) {
-    sendCommand(CMD_DESTROY_SYNC_TIMELINE, timeline, 0);
-}
-
-void goldfish_sync_register_trigger_wait(trigger_wait_fn_t f) {
-    if (goldfish_sync_device_exists()) {
-        sGoldfishSyncHwFuncs->registerTriggerWait(f);
-    }
-}
-
-bool goldfish_sync_device_exists() {
-    // The idea here is that the virtual device should set
-    // sGoldfishSyncHwFuncs. If it didn't do that, we take
-    // that to mean there is no virtual device.
-    return sGoldfishSyncHwFuncs != NULL;
-}
-
-void goldfish_sync_set_hw_funcs(GoldfishSyncDeviceInterface* hw_funcs) {
-    sGoldfishSyncHwFuncs = hw_funcs;
-    GoldfishSyncCommandQueue::setQueueCommand
-        (sGoldfishSyncHwFuncs->doHostCommand);
-}
-
diff --git a/host-common/include/host-common/AddressSpaceService.h b/host-common/include/host-common/AddressSpaceService.h
index 57954e3..a1db7bf 100644
--- a/host-common/include/host-common/AddressSpaceService.h
+++ b/host-common/include/host-common/AddressSpaceService.h
@@ -11,10 +11,13 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
 #pragma once
 
 #include <memory>
+
 #include "aemu/base/files/Stream.h"
+#include "render-utils/address_space_operations.h"
 
 namespace android {
 namespace emulation {
@@ -41,15 +44,6 @@ enum AddressSpaceDeviceType {
     VirtioGpuGraphics = 10,
 };
 
-struct AddressSpaceDevicePingInfo {
-    uint64_t phys_addr;
-    uint64_t size;
-    uint64_t metadata;
-    uint64_t wait_phys_addr;
-    uint32_t wait_flags;
-    uint32_t direction;
-};
-
 class AddressSpaceDeviceContext {
 public:
     virtual ~AddressSpaceDeviceContext() {}
diff --git a/host-common/include/host-common/FeatureControl.h b/host-common/include/host-common/FeatureControl.h
index 57e0621..c924475 100644
--- a/host-common/include/host-common/FeatureControl.h
+++ b/host-common/include/host-common/FeatureControl.h
@@ -47,6 +47,7 @@ bool isEnabled(Feature feature);
 bool isEnabledByGuest(Feature feature);
 AEMU_EXPORT void setEnabledOverride(Feature feature, bool isEnabled);
 void resetEnabledToDefault(Feature feature);
+void makeReadOnly(Feature feature);
 
 // Queries whether this feature is tied to the guest.
 bool isGuestFeature(Feature feature);
diff --git a/host-common/include/host-common/FeatureControlDefGuest.h b/host-common/include/host-common/FeatureControlDefGuest.h
index 5bed5d8..f5f2218 100644
--- a/host-common/include/host-common/FeatureControlDefGuest.h
+++ b/host-common/include/host-common/FeatureControlDefGuest.h
@@ -83,3 +83,4 @@ FEATURE_CONTROL_ITEM(AndroidVirtualizationFramework, 103)
 FEATURE_CONTROL_ITEM(XrModeUI, 104)
 FEATURE_CONTROL_ITEM(VirtioDualModeMouse, 105)
 FEATURE_CONTROL_ITEM(DualModeMouseDisplayHostCursor, 106)
+FEATURE_CONTROL_ITEM(AllAppsForHomeTray, 112)
\ No newline at end of file
diff --git a/host-common/include/host-common/address_space_device.h b/host-common/include/host-common/address_space_device.h
index 9594572..5490454 100644
--- a/host-common/include/host-common/address_space_device.h
+++ b/host-common/include/host-common/address_space_device.h
@@ -15,62 +15,9 @@
 
 #include <inttypes.h>
 
-extern "C" {
-
-struct AddressSpaceHwFuncs;
-
-struct AddressSpaceCreateInfo {
-    uint32_t handle = 0;
-    uint32_t type;
-    uint64_t physAddr;
-    bool fromSnapshot;
-    bool createRenderThread;
-    void *externalAddr;
-    uint64_t externalAddrSize;
-    uint32_t virtioGpuContextId;
-    uint32_t virtioGpuCapsetId;
-    const char *contextName;
-    uint32_t contextNameSize;
-};
+#include "render-utils/address_space_operations.h"
 
-typedef uint32_t (*address_space_device_gen_handle_t)(void);
-typedef void (*address_space_device_destroy_handle_t)(uint32_t);
-typedef void (*address_space_device_create_instance_t)(const struct AddressSpaceCreateInfo& create);
-typedef void (*address_space_device_tell_ping_info_t)(uint32_t handle, uint64_t gpa);
-typedef void (*address_space_device_ping_t)(uint32_t handle);
-typedef int (*address_space_device_add_memory_mapping_t)(uint64_t gpa, void *ptr, uint64_t size);
-typedef int (*address_space_device_remove_memory_mapping_t)(uint64_t gpa, void *ptr, uint64_t size);
-typedef void* (*address_space_device_get_host_ptr_t)(uint64_t gpa);
-typedef void* (*address_space_device_handle_to_context_t)(uint32_t handle);
-typedef void (*address_space_device_clear_t)(void);
-// virtio-gpu-next
-typedef uint64_t (*address_space_device_hostmem_register_t)(const struct MemEntry *entry);
-typedef void (*address_space_device_hostmem_unregister_t)(uint64_t id);
-typedef void (*address_space_device_ping_at_hva_t)(uint32_t handle, void* hva);
-// deallocation callbacks
-typedef void (*address_space_device_deallocation_callback_t)(void* context, uint64_t gpa);
-typedef void (*address_space_device_register_deallocation_callback_t)(void* context, uint64_t gpa, address_space_device_deallocation_callback_t);
-typedef void (*address_space_device_run_deallocation_callbacks_t)(uint64_t gpa);
-typedef const struct AddressSpaceHwFuncs* (*address_space_device_control_get_hw_funcs_t)(void);
-
-struct address_space_device_control_ops {
-    address_space_device_gen_handle_t gen_handle;
-    address_space_device_destroy_handle_t destroy_handle;
-    address_space_device_tell_ping_info_t tell_ping_info;
-    address_space_device_ping_t ping;
-    address_space_device_add_memory_mapping_t add_memory_mapping;
-    address_space_device_remove_memory_mapping_t remove_memory_mapping;
-    address_space_device_get_host_ptr_t get_host_ptr;
-    address_space_device_handle_to_context_t handle_to_context;
-    address_space_device_clear_t clear;
-    address_space_device_hostmem_register_t hostmem_register;
-    address_space_device_hostmem_unregister_t hostmem_unregister;
-    address_space_device_ping_at_hva_t ping_at_hva;
-    address_space_device_register_deallocation_callback_t register_deallocation_callback;
-    address_space_device_run_deallocation_callbacks_t run_deallocation_callbacks;
-    address_space_device_control_get_hw_funcs_t control_get_hw_funcs;
-    address_space_device_create_instance_t create_instance;
-};
+extern "C" {
 
 struct address_space_device_control_ops*
 get_address_space_device_control_ops(void);
@@ -78,33 +25,8 @@ get_address_space_device_control_ops(void);
 struct QAndroidVmOperations;
 void address_space_set_vm_operations(const QAndroidVmOperations* vmops);
 
-struct AddressSpaceHwFuncs {
-    /* Called by the host to reserve a shared region. Guest users can then
-     * suballocate into this region. This saves us a lot of KVM slots.
-     * Returns the relative offset to the starting phys addr in |offset|
-     * and returns 0 if successful, -errno otherwise. */
-    int (*allocSharedHostRegion)(uint64_t page_aligned_size, uint64_t* offset);
-    /* Called by the host to free a shared region. Only useful on teardown
-     * or when loading a snapshot while the emulator is running.
-     * Returns 0 if successful, -errno otherwise. */
-    int (*freeSharedHostRegion)(uint64_t offset);
-
-    /* Versions of the above but when the state is already locked. */
-    int (*allocSharedHostRegionLocked)(uint64_t page_aligned_size, uint64_t* offset);
-    int (*freeSharedHostRegionLocked)(uint64_t offset);
-
-    /* Obtains the starting physical address for which the resulting offsets
-     * are relative to. */
-    uint64_t (*getPhysAddrStart)(void);
-    uint64_t (*getPhysAddrStartLocked)(void);
-    uint32_t (*getGuestPageSize)(void);
-
-    /* Version of allocSharedHostRegionLocked but for a fixed offset */
-    int (*allocSharedHostRegionFixedLocked)(uint64_t page_aligned_size, uint64_t offset);
-};
-
-extern const struct AddressSpaceHwFuncs* address_space_set_hw_funcs(
-    const struct AddressSpaceHwFuncs* hwFuncs);
-const struct AddressSpaceHwFuncs* get_address_space_device_hw_funcs(void);
+extern const AddressSpaceHwFuncs* address_space_set_hw_funcs(
+    const AddressSpaceHwFuncs* hwFuncs);
+const AddressSpaceHwFuncs* get_address_space_device_hw_funcs(void);
 
 } // extern "C"
diff --git a/host-common/include/host-common/address_space_graphics.h b/host-common/include/host-common/address_space_graphics.h
index 75f8642..72da109 100644
--- a/host-common/include/host-common/address_space_graphics.h
+++ b/host-common/include/host-common/address_space_graphics.h
@@ -20,10 +20,10 @@
 #include "AddressSpaceService.h"
 #include "address_space_device.h"
 #include "address_space_device.hpp"
-#include "address_space_graphics_types.h"
 #include "aemu/base/ring_buffer.h"
 #include "aemu/base/synchronization/MessageChannel.h"
 #include "aemu/base/threads/FunctorThread.h"
+#include "render-utils/address_space_graphics_types.h"
 
 namespace android {
 namespace emulation {
@@ -44,7 +44,7 @@ public:
  AddressSpaceGraphicsContext(const struct AddressSpaceCreateInfo& create);
  ~AddressSpaceGraphicsContext();
 
- static void setConsumer(ConsumerInterface);
+ static void setConsumer(gfxstream::ConsumerInterface);
  static void init(const address_space_device_control_ops* ops);
  static void clear();
 
@@ -71,12 +71,7 @@ public:
  };
 
 private:
-
-    void saveRingConfig(base::Stream* stream, const struct asg_ring_config& config) const;
     void saveAllocation(base::Stream* stream, const Allocation& alloc) const;
-
-    void loadRingConfig(base::Stream* stream, struct asg_ring_config& config);
-
     void loadAllocation(base::Stream* stream, Allocation& alloc);
 
     // For consumer communication
@@ -89,25 +84,24 @@ private:
     };
 
     // For ConsumerCallbacks
-    int onUnavailableRead();
+    gfxstream::AsgOnUnavailableReadStatus onUnavailableRead();
 
     // Data layout
     uint32_t mVersion = 1;
     Allocation mRingAllocation;
     Allocation mBufferAllocation;
     Allocation mCombinedAllocation;
-    struct asg_context mHostContext = {};
 
     // Consumer storage
-    ConsumerCallbacks mConsumerCallbacks;
-    ConsumerInterface mConsumerInterface;
+    gfxstream::ConsumerCallbacks mConsumerCallbacks;
+    gfxstream::ConsumerInterface mConsumerInterface;
     void* mCurrentConsumer = 0;
 
     // Communication with consumer
     mutable base::MessageChannel<ConsumerCommand, 4> mConsumerMessages;
     uint32_t mExiting = 0;
     // For onUnavailableRead
-    uint32_t mUnavailableReadCount = 0;
+
 
     struct VirtioGpuInfo {
         uint32_t contextId = 0;
@@ -115,8 +109,6 @@ private:
         std::optional<std::string> name;
     };
     std::optional<VirtioGpuInfo> mVirtioGpuInfo;
-    // To save the ring config if it is cleared on hostmem map
-    struct asg_ring_config mSavedConfig;
 };
 
 }  // namespace asg
diff --git a/host-common/include/host-common/address_space_graphics_types.h b/host-common/include/host-common/address_space_graphics_types.h
deleted file mode 100644
index 0789707..0000000
--- a/host-common/include/host-common/address_space_graphics_types.h
+++ /dev/null
@@ -1,381 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-#pragma once
-
-#include "aemu/base/ring_buffer.h"
-
-#include <functional>
-#include <optional>
-
-// This file defines common types for address space graphics and provides
-// documentation.
-
-// Address space graphics======================================================
-//
-// Basic idea
-//
-// Address space graphics (ASG) is a subdevice of the address space device that
-// provides a way to run graphics commands and data with fewer VM exits by
-// leveraging shared memory ring buffers.
-//
-// Each GL/Vk thread in the guest is associated with a context (asg_context).
-// asg_context consists of pointers into the shared memory that view it as a
-// collection of ring buffers and a common write buffer.
-//
-// Consumer concept
-//
-// ASG does not assume a particular rendering backend (though we will use
-// RenderThread's). This is for ease of coding/testing and flexibility; the
-// implementation is not coupled to emugl/libOpenglRender.
-//
-// Instead, there is the concept of a "Consumer" of ASG that will do something
-// with the data arriving from the shared memory region, and possibly reply
-// back to the guest. We register functions to construct and deconstruct
-// Consumers as part of emulator init (setConsumer).
-//
-// Guest workflow
-//
-// 1. Open address space device
-//
-// 2. Create the graphics context as the subdevice
-//
-// 3. ping(ASG_GET_RING) to get the offset/size of the ring buffer admin. info
-//
-// 4. ping(ASG_GET_BUFFER) to get the offset/size of the shared transfer buffer.
-//
-// 5. ioctl(CLAIM_SHARED) and mmap on those two offset/size pairs to get a
-// guest-side mapping.
-//
-// 6. call asg_context_create on the ring and buffer pointers to create the asg_context.
-//
-// 7. Now the guest and host share asg_context pts and can communicate.
-//
-// 8. But usually the guest will sometimes need to ping(ASG_NOTIFY_AVAILABLE)
-// so that the host side (which is usually a separate thread that we don't want
-// to spin too much) wakes up and processes data.
-
-namespace android {
-namespace base {
-
-class Stream;
-
-} // namespace base
-} // namespace android
-
-#define ADDRESS_SPACE_GRAPHICS_DEVICE_ID 0
-#define ADDRESS_SPACE_GRAPHICS_PAGE_SIZE 4096
-#define ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE (16ULL * 1048576ULL)
-
-// AddressSpaceGraphicsContext shares memory with
-// the guest via the following layout:
-extern "C" {
-
-struct asg_ring_storage { // directly shared with guest
-    char to_host[ADDRESS_SPACE_GRAPHICS_PAGE_SIZE];
-    char to_host_large_xfer[ADDRESS_SPACE_GRAPHICS_PAGE_SIZE];
-    char from_host_large_xfer[ADDRESS_SPACE_GRAPHICS_PAGE_SIZE];
-};
-
-// Set by the address space graphics device to notify the guest that the host
-// has slept or is able to consume something, or we are exiting, or there is an
-// error.
-enum asg_host_state {
-    // The host renderthread is asleep and needs to be woken up.
-    ASG_HOST_STATE_NEED_NOTIFY = 0,
-
-    // The host renderthread is active and can consume new data
-    // without notification.
-    ASG_HOST_STATE_CAN_CONSUME = 1,
-
-    // Normal exit
-    ASG_HOST_STATE_EXIT = 2,
-
-    // Error: Something weird happened and we need to exit.
-    ASG_HOST_STATE_ERROR = 3,
-
-    // Rendering
-    ASG_HOST_STATE_RENDERING = 4,
-};
-
-struct asg_ring_config;
-
-// Each context has a pair of ring buffers for communication
-// to and from the host. There is another ring buffer for large xfers
-// to the host (all xfers from the host are already considered "large").
-//
-// Each context also comes with _one_ auxiliary buffer to hold both its own
-// commands and to perform private DMA transfers.
-struct asg_context { // ptrs into RingStorage
-    struct ring_buffer* to_host;
-    char* buffer;
-    asg_host_state* host_state;
-    asg_ring_config* ring_config;
-    struct ring_buffer_with_view to_host_large_xfer;
-    struct ring_buffer_with_view from_host_large_xfer;
-};
-
-// Helper function that will be common between guest and host:
-// Given ring storage and a write buffer, returns asg_context that
-// is the correct view into it.
-inline struct asg_context asg_context_create(
-    char* ring_storage,
-    char* buffer,
-    uint32_t buffer_size) {
-
-    struct asg_context res;
-
-    res.to_host =
-        reinterpret_cast<struct ring_buffer*>(
-            ring_storage +
-            offsetof(struct asg_ring_storage, to_host));
-    res.to_host_large_xfer.ring =
-        reinterpret_cast<struct ring_buffer*>(
-            ring_storage +
-            offsetof(struct asg_ring_storage, to_host_large_xfer));
-    res.from_host_large_xfer.ring =
-        reinterpret_cast<struct ring_buffer*>(
-            ring_storage +
-            offsetof(struct asg_ring_storage, from_host_large_xfer));
-
-    ring_buffer_init(res.to_host);
-
-    res.buffer = buffer;
-    res.host_state =
-        reinterpret_cast<asg_host_state*>(
-            &res.to_host->state);
-    res.ring_config =
-        reinterpret_cast<asg_ring_config*>(
-            res.to_host->config);
-
-    ring_buffer_view_init(
-        res.to_host_large_xfer.ring,
-        &res.to_host_large_xfer.view,
-        (uint8_t*)res.buffer, buffer_size);
-
-    ring_buffer_view_init(
-        res.from_host_large_xfer.ring,
-        &res.from_host_large_xfer.view,
-        (uint8_t*)res.buffer, buffer_size);
-
-    return res;
-}
-
-// During operation, the guest sends commands and data over the auxiliary
-// buffer while using the |to_host| ring to communicate what parts of the auxiliary
-// buffer is outstanding traffic needing to be consumed by the host.
-// After a transfer completes to the host, the host may write back data.
-// The guest then reads the results on the same auxiliary buffer
-// while being notified of which parts to read via the |from_host| ring.
-//
-// The size of the auxiliary buffer and flush interval is defined by
-// the following config.ini android_hw setting:
-//
-// 1) android_hw->hw_gltransport_asg_writeBufferSize
-// 2) android_hw->hw_gltransport_asg_writeStepSize
-//
-// 1) the size for the auxiliary buffer
-// 2) the step size over which commands are flushed to the host
-//
-// When transferring commands, command data is built up in writeStepSize
-// chunks and flushed to the host when either writeStepSize is reached or
-// the guest flushes explicitly.
-//
-// Command vs. Data Modes
-//
-// For command data larger than writeStepSize or when transferring data, we
-// fall back to using a different mode where the entire auxiliary buffer is
-// used to perform the transfer, |asg_writeBufferSize| steps at a time. The
-// host is also notified of the total transport size.
-//
-// When writing back to the guest, it is assumed that the write buffer will
-// be completely empty as the guest has already flushed and the host has
-// already consumed all commands/data, and is writing back. In this case,
-// the full auxiliary buffer is used at the same time for writing back to
-// the guest.
-//
-// Larger / Shared transfers
-//
-// Each of |to_host| and |from_host| can contain elements of type 1, 2, or 3:
-// Type 1: 8 bytes: 4 bytes offset, 4 bytes size. Relative to write buffer.
-struct __attribute__((__packed__)) asg_type1_xfer {
-    uint32_t offset;
-    uint32_t size;
-};
-// Type 2: 16 bytes: 16 bytes offset into address space PCI space, 8 bytes
-// size.
-struct __attribute__((__packed__)) asg_type2_xfer {
-    uint64_t physAddr;
-    uint64_t size;
-};
-// Type 3: There is a large transfer of known size and the entire write buffer
-// will be used to send it over.
-//
-// For type 1 transfers, we get the corresponding host virtual address by
-// adding the offset to the beginning of the write buffer.  For type 2
-// transfers, we need to calculate the guest physical address and then call
-// addressspacecontrolops.gethostptr, which is slower since it goes through
-// a data structure map of existing mappings.
-//
-// The rings never contain a mix of type 1 and 2 elements. For to_host,
-// the guest initiates changes between type 1 and 2.
-//
-// The config fields:
-//
-struct asg_ring_config {
-    // config[0]: size of the auxiliary buffer
-    uint32_t buffer_size;
-
-    // config[1]: flush interval for the auxiliary buffer
-    uint32_t flush_interval;
-
-    // the position of the interval in the auxiliary buffer
-    // that the host has read so far
-    uint32_t host_consumed_pos;
-
-    // the start of the places the guest might write to next
-    uint32_t guest_write_pos;
-
-    // 1 if transfers are of type 1, 2 if transfers of type 2,
-    // 3 if the overall transfer size is known and we are sending something large.
-    uint32_t transfer_mode;
-
-    // the size of the transfer, used if transfer size is known.
-    // Set before setting config[2] to 3.
-    uint32_t transfer_size;
-
-    // error state
-    uint32_t in_error;
-};
-
-// State/config changes may only occur if the ring is empty, or the state
-// is transitioning to Error. That way, the host and guest have a chance to
-// synchronize on the same state.
-//
-// Thus far we've established how commands and data are transferred
-// to and from the host. Next, let's discuss how AddressSpaceGraphicsContext
-// talks to the code that actually does something with the commands
-// and sends data back.
-
-} // extern "C"
-
-namespace android {
-namespace emulation {
-namespace asg {
-
-// Consumer Concept
-//
-// AddressSpaceGraphicsContext's are each associated with a consumer that
-// takes data off the auxiliary buffer and to_host, while sending back data
-// over the auxiliary buffer / from_host.
-//
-// will read the commands and write back data.
-//
-// The consumer type is fixed at startup. The interface is as follows:
-
-// Called by the consumer, implemented in AddressSpaceGraphicsContext:
-//
-// Called when the consumer doesn't find anything to
-// read in to_host. Will make the consumer sleep
-// until another Ping(NotifyAvailable).
-using OnUnavailableReadCallback =
-    std::function<int()>;
-
-// Unpacks a type 2 transfer into host pointer and size.
-using GetPtrCallback =
-    std::function<char*(uint64_t)>;
-
-struct ConsumerCallbacks {
-    OnUnavailableReadCallback onUnavailableRead;
-    GetPtrCallback getPtr;
-};
-
-using ConsumerCreateCallback =
-    std::function<void* (struct asg_context, base::Stream*, ConsumerCallbacks,
-                         uint32_t virtioGpuContextId, uint32_t virtioGpuCapsetId,
-                         std::optional<std::string> nameOpt)>;
-using ConsumerDestroyCallback =
-    std::function<void(void*)>;
-using ConsumerPreSaveCallback =
-    std::function<void(void*)>;
-using ConsumerGlobalPreSaveCallback =
-    std::function<void()>;
-using ConsumerSaveCallback =
-    std::function<void(void*, base::Stream*)>;
-using ConsumerGlobalPostSaveCallback =
-    std::function<void()>;
-using ConsumerPostSaveCallback =
-    std::function<void(void*)>;
-using ConsumerPostLoadCallback = ConsumerPostSaveCallback;
-using ConsumerGlobalPreLoadCallback = ConsumerGlobalPostSaveCallback;
-
-struct ConsumerInterface {
-    ConsumerCreateCallback create;
-    ConsumerDestroyCallback destroy;
-
-    ConsumerPreSaveCallback preSave;
-    ConsumerGlobalPreSaveCallback globalPreSave;
-
-    ConsumerSaveCallback save;
-
-    ConsumerGlobalPostSaveCallback globalPostSave;
-    ConsumerPostSaveCallback postSave;
-
-    ConsumerPostLoadCallback postLoad;
-
-    ConsumerGlobalPreLoadCallback globalPreLoad;
-};
-
-} // namespace asg
-} // namespace emulation
-} // namespace android
-
-// The interface for the guest:
-
-extern "C" {
-// Handled outside in address_space_device.cpp:
-//
-// Ping(device id): Create the device. On the host, the two rings and
-// auxiliary buffer are allocated. The two rings are allocated up front.
-// Both the auxiliary buffers and the rings are allocated from blocks of
-// rings and auxiliary buffers. New blocks are created if we run out either
-// way.
-enum asg_command {
-    // Ping(get_ring): Returns, in the fields:
-    // metadata: offset to give to claimShared and mmap() in the guest
-    // size: size to give to claimShared and mmap() in the guest
-    ASG_GET_RING = 0,
-
-    // Ping(get_buffer): Returns, in the fields:
-    // metadata: offset to give to claimShared and mmap() in the guest
-    // size: size to give to claimShared and mmap() in the guest
-    ASG_GET_BUFFER = 1,
-
-    // Ping(set_version): Run after the guest reads and negotiates its
-    // version of the device with the host. The host now knows the guest's
-    // version and can proceed with a protocol that works for both.
-    // size (in): the version of the guest
-    // size (out): the version of the host
-    // After this command runs, the consumer is
-    // implicitly created.
-    ASG_SET_VERSION = 2,
-
-    // Ping(notiy_available): Wakes up the consumer from sleep so it
-    // can read data via toHost
-    ASG_NOTIFY_AVAILABLE = 3,
-
-    // Retrieve the config.
-    ASG_GET_CONFIG = 4,
-};
-
-} // extern "C"
diff --git a/host-common/include/host-common/dma_device.h b/host-common/include/host-common/dma_device.h
deleted file mode 100644
index 2592fdb..0000000
--- a/host-common/include/host-common/dma_device.h
+++ /dev/null
@@ -1,49 +0,0 @@
-/*
-* Copyright (C) 2016 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#pragma once
-
-#include <cstdint>
-
-#ifdef _MSC_VER
-# ifdef BUILDING_EMUGL_COMMON_SHARED
-#  define EMUGL_COMMON_API __declspec(dllexport)
-# else
-#  define EMUGL_COMMON_API __declspec(dllimport)
-#endif
-#else
-# define EMUGL_COMMON_API
-#endif
-
-// Function type that describes functions for
-// accessing Goldfish DMA regions at a specified offset.
-typedef void* (*emugl_dma_get_host_addr_t)(uint64_t);
-typedef void (*emugl_dma_unlock_t)(uint64_t);
-
-typedef struct {
-    emugl_dma_get_host_addr_t get_host_addr;
-    emugl_dma_unlock_t unlock;
-} emugl_dma_ops;
-
-namespace emugl {
-
-EMUGL_COMMON_API extern emugl_dma_get_host_addr_t g_emugl_dma_get_host_addr;
-EMUGL_COMMON_API extern emugl_dma_unlock_t g_emugl_dma_unlock;
-
-EMUGL_COMMON_API void set_emugl_dma_get_host_addr(emugl_dma_get_host_addr_t);
-EMUGL_COMMON_API void set_emugl_dma_unlock(emugl_dma_unlock_t);
-
-}  // namespace emugl
diff --git a/host-common/include/host-common/hw-config-defs.h b/host-common/include/host-common/hw-config-defs.h
index c402b17..462217a 100644
--- a/host-common/include/host-common/hw-config-defs.h
+++ b/host-common/include/host-common/hw-config-defs.h
@@ -825,6 +825,13 @@ HWCFG_BOOL(
   "Wrist tilt gesture",
   "Whether there is a wrist tilt gesture sensor in the device")
 
+HWCFG_BOOL(
+  hw_sensors_heading,
+  "hw.sensors.heading",
+  "no",
+  "Heading",
+  "The direction in which the device is pointing relative to true north in degrees")
+
 HWCFG_BOOL(
   hw_useext4,
   "hw.useext4",
diff --git a/host-common/include/host-common/misc.h b/host-common/include/host-common/misc.h
index 17e3c05..6912c20 100644
--- a/host-common/include/host-common/misc.h
+++ b/host-common/include/host-common/misc.h
@@ -29,39 +29,16 @@
 
 // List of values used to identify a clockwise 90-degree rotation.
 typedef enum {
-    SKIN_ROTATION_0,
-    SKIN_ROTATION_90,
-    SKIN_ROTATION_180,
-    SKIN_ROTATION_270
+    SKIN_ROTATION_0 = 0,
+    SKIN_ROTATION_90 = 1,
+    SKIN_ROTATION_180 = 2,
+    SKIN_ROTATION_270 = 3,
 } SkinRotation;
 
 #ifdef __cplusplus
-namespace android {
-
-namespace base {
-
-class CpuUsage;
-class MemoryTracker;
-
-} // namespace base
-} // namespace android
 
 namespace emugl {
 
-    // Set and get API version of system image.
-    EMUGL_COMMON_API void setAvdInfo(bool isPhone, int apiLevel);
-    EMUGL_COMMON_API void getAvdInfo(bool* isPhone, int* apiLevel);
-
-    EMUGL_COMMON_API void setShouldSkipDraw(bool skip);
-    EMUGL_COMMON_API bool shouldSkipDraw();
-    // CPU usage get/set.
-    EMUGL_COMMON_API void setCpuUsage(android::base::CpuUsage* usage);
-    EMUGL_COMMON_API android::base::CpuUsage* getCpuUsage();
-
-    // Memory usage get/set
-    EMUGL_COMMON_API void setMemoryTracker(android::base::MemoryTracker* usage);
-    EMUGL_COMMON_API android::base::MemoryTracker* getMemoryTracker();
-
     // Window operation agent
     EMUGL_COMMON_API void set_emugl_window_operations(const QAndroidEmulatorWindowAgent &voperations);
     EMUGL_COMMON_API const QAndroidEmulatorWindowAgent &get_emugl_window_operations();
diff --git a/host-common/include/host-common/opengl/emugl_config.h b/host-common/include/host-common/opengl/emugl_config.h
new file mode 100644
index 0000000..7cb9bc6
--- /dev/null
+++ b/host-common/include/host-common/opengl/emugl_config.h
@@ -0,0 +1,145 @@
+// Copyright 2020 The Android Open Source Project
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
+
+#pragma once
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#include "aemu/base/c_header.h"
+#include "aemu/base/export.h"
+#include "render-utils/renderer_enums.h"
+
+ANDROID_BEGIN_HEADER
+
+// List of values describing how EGL/GLES emulation should work in a given
+// Android virtual device.
+//
+// kAndroidGlesEmulationOff
+//    Means there is no GPU emulation, equivalent to "-gpu off" and instructs
+//    the guest system to use its old GLES 1.x software renderer.
+//
+// kAndroidGlesEmulationHost
+//    Means Host GPU emulation is being used. All EGL/GLES commands are
+//    sent to the host GPU or CPU through a simple wire protocol. This
+//    corresponds to "-gpu host" and "-gpu mesa".
+//
+// kAndroidGlesEmulationGuest
+//    Means a guest GLES 2.x library (e.g. SwiftShader) is being used in
+//    the guest. This should only be used with accelerated emulation, or
+//    results will be very very slow.
+typedef enum {
+    kAndroidGlesEmulationOff = 0,
+    kAndroidGlesEmulationHost,
+    kAndroidGlesEmulationGuest,
+} AndroidGlesEmulationMode;
+// A small structure used to model the EmuGL configuration
+// to use.
+// |enabled| is true if GPU emulation is enabled, false otherwise.
+// |backend| contains the name of the backend to use, if |enabled|
+// is true.
+// |status| is a string used to report error or the current status
+// of EmuGL emulation.
+typedef struct {
+    bool enabled;
+    bool use_backend;
+    int bitness;
+    char backend[64];
+    char status[256];
+    bool use_host_vulkan;
+} EmuglConfig;
+
+// Check whether or not the host GPU is blacklisted. If so, fall back
+// to software rendering.
+bool isHostGpuBlacklisted();
+
+typedef struct {
+    char* make;
+    char* model;
+    char* device_id;
+    char* revision_id;
+    char* version;
+    char* renderer;
+} emugl_host_gpu_props;
+
+typedef struct {
+    int num_gpus;
+    emugl_host_gpu_props* props;
+} emugl_host_gpu_prop_list;
+
+// Get a description of host GPU properties.
+// Need to free after use.
+emugl_host_gpu_prop_list emuglConfig_get_host_gpu_props();
+
+// Returns SelectedRenderer value the selected gpu mode.
+// Assumes that the -gpu command line option
+// has been taken into account already.
+SelectedRenderer emuglConfig_get_renderer(const char* gpu_mode);
+
+// Returns the renderer that is active, after config is done.
+SelectedRenderer emuglConfig_get_current_renderer();
+
+// Returns the '-gpu <mode>' option. If '-gpu <mode>' option is NULL, returns
+// the hw.gpu.mode hardware property.
+const char* emuglConfig_get_user_gpu_option();
+
+// Returns the full path for vulkan runtime library to be used
+const char* emuglConfig_get_vulkan_runtime_full_path();
+
+// Returns the properties of the hardware gpu to be used for emulation
+void emuglConfig_get_vulkan_hardware_gpu(char** vendor, int* major, int* minor, int* patch,
+                                         uint64_t* deviceMemBytes, uint32_t* driverVersion,
+                                         uint64_t* deviceMaxAllocationCount);
+
+// Returns a string representation of the renderer enum. Return value is a
+// static constant string, it is NOT heap-allocated.
+const char* emuglConfig_renderer_to_string(SelectedRenderer renderer);
+
+// Returns if the current renderer supports snapshot.
+bool emuglConfig_current_renderer_supports_snapshot();
+
+void free_emugl_host_gpu_props(emugl_host_gpu_prop_list props);
+
+// Initialize an EmuglConfig instance based on the AVD's hardware properties
+// and the command-line -gpu option, if any.
+//
+// |config| is the instance to initialize.
+// |gpu_enabled| is the value of the hw.gpu.enabled hardware property.
+// |gpu_mode| is the value of the hw.gpu.mode hardware property.
+// |gpu_option| is the value of the '-gpu <mode>' option, or NULL.
+// |bitness| is the host bitness (0, 32 or 64).
+// |no_window| is true if the '-no-window' emulator flag was used.
+// |blacklisted| is true if the GPU driver is on the list of
+// crashy GPU drivers.
+// |use_host_vulkan| is true if the '-use-host-vulkan' emulator flag was used.
+//
+// Returns true on success, or false if there was an error (e.g. bad
+// mode or option value), in which case the |status| field will contain
+// a small error message.
+AEMU_EXPORT bool emuglConfig_init(EmuglConfig* config,
+                                  bool gpu_enabled,
+                                  const char* gpu_mode,
+                                  const char* gpu_option,
+                                  int bitness,
+                                  bool no_window,
+                                  bool blacklisted,
+                                  bool google_apis,
+                                  int uiPreferredBackend,
+                                  bool use_host_vulkan);
+
+// Setup GPU emulation according to a given |backend|.
+// |bitness| is the host bitness, and can be 0 (autodetect), 32 or 64.
+AEMU_EXPORT void emuglConfig_setupEnv(const EmuglConfig* config);
+
+ANDROID_END_HEADER
diff --git a/host-common/include/host-common/opengl/gpuinfo.h b/host-common/include/host-common/opengl/gpuinfo.h
new file mode 100644
index 0000000..a00d7b0
--- /dev/null
+++ b/host-common/include/host-common/opengl/gpuinfo.h
@@ -0,0 +1,135 @@
+// Copyright 2020 The Android Open Source Project
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
+#pragma once
+
+#include "aemu/base/Compiler.h"
+
+#include <stdbool.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string>
+#include <string.h>
+#include <vector>
+
+// gpuinfo is designed to collect information about the GPUs
+// installed on the host system for the purposes of
+// automatically determining which renderer to select,
+// in the cases where the GPU drivers are known to have issues
+// running the emulator.
+
+// The main entry points:
+
+// host_gpu_blacklisted_async() does the two steps above,
+// but on a different thread, with a timeout in case
+// the started processes hang or what not.
+void async_query_host_gpu_start();
+bool async_query_host_gpu_blacklisted();
+bool async_query_host_gpu_AngleWhitelisted();
+bool async_query_host_gpu_SyncBlacklisted();
+bool async_query_host_gpu_VulkanBlacklisted();
+
+// Below is the implementation.
+
+struct GpuInfoView{
+    const char* make;
+    const char* model;
+    const char* device_id;
+    const char* revision_id;
+    const char* version;
+    const char* renderer;
+    const char* os;
+};
+// We keep a blacklist of known crashy GPU drivers
+// as a static const list with items of this type:
+using BlacklistEntry = GpuInfoView;
+// We keep a whitelist to use Angle for buggy
+// GPU drivers
+using WhitelistEntry = GpuInfoView;
+
+// GpuInfo/GpuInfoList are the representation of parsed information
+// about the system's GPU.s
+class GpuInfo {
+public:
+    GpuInfo() : current_gpu(false) { }
+    GpuInfo(const std::string& _make,
+            const std::string& _model,
+            const std::string& _device_id,
+            const std::string& _revision_id,
+            const std::string& _version,
+            const std::string& _renderer) :
+        current_gpu(false),
+        make(_make),
+        model(_model),
+        device_id(_device_id),
+        revision_id(_revision_id),
+        version(_version),
+        renderer(_renderer) { }
+
+    bool current_gpu;
+
+    void addDll(std::string dll_str);
+
+    std::string make;
+    std::string model;
+    std::string device_id;
+    std::string revision_id;
+    std::string version;
+    std::string renderer;
+
+    std::vector<std::string> dlls;
+    std::string os;
+};
+
+class GpuInfoList {
+public:
+    GpuInfoList() = default;
+    void addGpu();
+    GpuInfo& currGpu();
+    std::string dump() const;
+    void clear();
+
+    std::vector<GpuInfo> infos;
+
+    bool blacklist_status = false;
+    bool Anglelist_status = false;
+    bool SyncBlacklist_status = false;
+    bool VulkanBlacklist_status = false;
+
+    DISALLOW_COPY_ASSIGN_AND_MOVE(GpuInfoList);
+};
+
+// Below are helper functions that can be useful in various
+// contexts (e.g., unit testing).
+
+// gpuinfo_query_blacklist():
+// Function to query a given blacklist of GPU's.
+// The blacklist |list| (of length |size|) attempts
+// to match all non-NULL entry fields exactly against
+// info of all GPU's in |gpulist|. If there is any match,
+// the host system is considered on the blacklist.
+// (Null blacklist entry fields are ignored and
+// essentially act as wildcards).
+bool gpuinfo_query_blacklist(GpuInfoList* gpulist,
+                             const BlacklistEntry* list,
+                             int size);
+
+// Platform-specific information parsing functions.
+void parse_gpu_info_list_linux(const std::string& contents, GpuInfoList* gpulist);
+void parse_gpu_info_list_windows(const std::string& contents, GpuInfoList* gpulist);
+
+// If we actually switched to software, call this.
+void setGpuBlacklistStatus(bool switchedToSoftware);
+
+// Return a fully loaded global GPU info list.
+const GpuInfoList& globalGpuInfoList();
diff --git a/host-common/include/host-common/opengles.h b/host-common/include/host-common/opengles.h
new file mode 100644
index 0000000..aec3304
--- /dev/null
+++ b/host-common/include/host-common/opengles.h
@@ -0,0 +1,174 @@
+// Copyright 2020 The Android Open Source Project
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
+
+#pragma once
+
+#include <stddef.h>
+
+#include "aemu/base/c_header.h"
+#include "aemu/base/export.h"
+#include "host-common/multi_display_agent.h"
+#include "host-common/vm_operations.h"
+#include "host-common/window_agent.h"
+#include "render-utils/virtio_gpu_ops.h"
+
+#ifdef __cplusplus
+#include "host-common/misc.h"
+#include "render-utils/RenderLib.h"
+#endif
+
+#ifndef USING_ANDROID_BP
+ANDROID_BEGIN_HEADER
+#endif
+
+/* A version of android_initOpenglesEmulation that is called from a library
+ * that has static access to libOpenglRender. */
+AEMU_EXPORT int android_prepareOpenglesEmulation(void);
+AEMU_EXPORT int android_setOpenglesEmulation(void* renderLib, void* eglDispatch, void* glesv2Dispatch);
+
+/* Call this function to initialize the hardware opengles emulation.
+ * This function will abort if we can't find the corresponding host
+ * libraries through dlopen() or equivalent.
+ */
+AEMU_EXPORT int android_initOpenglesEmulation(void);
+
+/* Tries to start the renderer process. Returns 0 on success, -1 on error.
+ * At the moment, this must be done before the VM starts. The onPost callback
+ * may be NULL.
+ *
+ * width and height: the framebuffer dimensions that will be reported
+ *                   to the guest display driver.
+ * guestApiLevel: API level of guest image (23 for mnc, 24 for nyc, etc)
+ */
+AEMU_EXPORT int android_startOpenglesRenderer(int width, int height,
+                                              bool isPhone, int guestApiLevel,
+                                              const QAndroidVmOperations *vm_operations,
+                                              const QAndroidEmulatorWindowAgent *window_agent,
+                                              const QAndroidMultiDisplayAgent *multi_display_agent,
+                                              const void* gfxstreamFeatures,
+                                              int* glesMajorVersion_out,
+                                              int* glesMinorVersion_out);
+
+AEMU_EXPORT bool android_asyncReadbackSupported();
+
+/* See the description in render_api.h. */
+typedef void (*OnPostFunc)(void* context, uint32_t displayId, int width,
+                           int height, int ydir, int format, int type,
+                           unsigned char* pixels);
+AEMU_EXPORT void android_setPostCallback(OnPostFunc onPost,
+                             void* onPostContext,
+                             bool useBgraReadback,
+                             uint32_t displayId);
+
+typedef void (*ReadPixelsFunc)(void* pixels, uint32_t bytes, uint32_t displayId);
+AEMU_EXPORT ReadPixelsFunc android_getReadPixelsFunc();
+
+
+typedef void (*FlushReadPixelPipeline)(int displayId);
+
+/* Gets the function that can be used to make sure no
+ * frames are left in the video producer pipeline.
+ * This can result in a post callback.
+ */
+FlushReadPixelPipeline android_getFlushReadPixelPipeline();
+
+/* Retrieve the Vendor/Renderer/Version strings describing the underlying GL
+ * implementation. The call only works while the renderer is started.
+ *
+ * Expects |*vendor|, |*renderer| and |*version| to be NULL.
+ *
+ * On exit, sets |*vendor|, |*renderer| and |*version| to point to new
+ * heap-allocated strings (that must be freed by the caller) which represent the
+ * OpenGL hardware vendor name, driver name and version, respectively.
+ * In case of error, |*vendor| etc. are set to NULL.
+ */
+AEMU_EXPORT void android_getOpenglesHardwareStrings(char** vendor,
+                                                    char** renderer,
+                                                    char** version);
+
+AEMU_EXPORT int android_showOpenglesWindow(void* window,
+                                           int wx,
+                                           int wy,
+                                           int ww,
+                                           int wh,
+                                           int fbw,
+                                           int fbh,
+                                           float dpr,
+                                           float rotation,
+                                           bool deleteExisting,
+                                           bool hideWindow);
+
+AEMU_EXPORT int android_hideOpenglesWindow(void);
+
+AEMU_EXPORT void android_setOpenglesTranslation(float px, float py);
+
+AEMU_EXPORT void android_setOpenglesScreenMask(int width, int height, const unsigned char* rgbaData);
+
+AEMU_EXPORT void android_redrawOpenglesWindow(void);
+
+AEMU_EXPORT void android_setShouldSkipDraw(bool skip);
+AEMU_EXPORT bool android_getShouldSkipDraw(void);
+
+AEMU_EXPORT bool android_hasGuestPostedAFrame(void);
+AEMU_EXPORT void android_resetGuestPostedAFrame(void);
+
+typedef bool (*ScreenshotFunc)(const char* dirname, uint32_t displayId);
+AEMU_EXPORT void android_registerScreenshotFunc(ScreenshotFunc f);
+AEMU_EXPORT bool android_screenShot(const char* dirname, uint32_t displayId);
+
+/* Stop the renderer process */
+EMUGL_COMMON_API void android_stopOpenglesRenderer(bool wait);
+
+/* Finish all renderer work, deleting current
+ * render threads. Renderer is allowed to get
+ * new render threads after that. */
+AEMU_EXPORT void android_finishOpenglesRenderer();
+
+/* set to TRUE if you want to use fast GLES pipes, 0 if you want to
+ * fallback to local TCP ones
+ */
+AEMU_EXPORT extern int  android_gles_fast_pipes;
+
+// Notify the renderer that a guest graphics process is created or destroyed.
+AEMU_EXPORT void android_onGuestGraphicsProcessCreate(uint64_t puid);
+// TODO(kaiyili): rename this API to android_onGuestGraphicsProcessDestroy
+AEMU_EXPORT void android_cleanupProcGLObjects(uint64_t puid);
+
+AEMU_EXPORT void android_waitForOpenglesProcessCleanup();
+
+#ifdef __cplusplus
+namespace gfxstream {
+class Renderer;
+}
+
+AEMU_EXPORT const gfxstream::RendererPtr& android_getOpenglesRenderer();
+EMUGL_COMMON_API void android_setOpenglesRenderer(gfxstream::RendererPtr* renderer);
+#endif
+
+AEMU_EXPORT struct AndroidVirtioGpuOps* android_getVirtioGpuOps(void);
+
+/* Get EGL/GLESv2 dispatch tables */
+AEMU_EXPORT const void* android_getEGLDispatch();
+AEMU_EXPORT const void* android_getGLESv2Dispatch();
+
+/* Set vsync rate at runtime */
+AEMU_EXPORT void android_setVsyncHz(int vsyncHz);
+
+AEMU_EXPORT void android_setOpenglesDisplayConfigs(int configId, int w, int h,
+                                                   int dpiX, int dpiY);
+AEMU_EXPORT void android_setOpenglesDisplayActiveConfig(int configId);
+
+#ifndef USING_ANDROID_BP
+ANDROID_END_HEADER
+#endif
diff --git a/snapshot/include/snapshot/common.h b/host-common/include/host-common/snapshot_common.h
similarity index 92%
rename from snapshot/include/snapshot/common.h
rename to host-common/include/host-common/snapshot_common.h
index 079ef80..bb7ff64 100644
--- a/snapshot/include/snapshot/common.h
+++ b/host-common/include/host-common/snapshot_common.h
@@ -16,9 +16,10 @@
 
 #pragma once
 
-#include "interface.h"
+#include "host-common/snapshot_interface.h"
 
 #include "aemu/base/files/Stream.h"
+#include "render-utils/snapshot_operations.h"
 
 #include <memory>
 #include <string>
@@ -39,13 +40,9 @@ struct SnapshotRamBlock {
 namespace android {
 namespace snapshot {
 
-class ITextureSaver;
-class TextureSaver;
-class ITextureLoader;
-class TextureLoader;
-using ITextureSaverPtr = std::shared_ptr<ITextureSaver>;
-using ITextureLoaderPtr = std::shared_ptr<ITextureLoader>;
-using ITextureLoaderWPtr = std::weak_ptr<ITextureLoader>;
+using ITextureSaverPtr = std::shared_ptr<gfxstream::ITextureSaver>;
+using ITextureLoaderPtr = std::shared_ptr<gfxstream::ITextureLoader>;
+using ITextureLoaderWPtr = std::weak_ptr<gfxstream::ITextureLoader>;
 
 struct SnapshotSaveStream {
     android::base::Stream* stream = nullptr;
@@ -167,4 +164,4 @@ enum SnapshotterStage {
 };
 
 }  // namespace snapshot
-}  // namespace android
+}  // namespace android
\ No newline at end of file
diff --git a/snapshot/include/snapshot/interface.h b/host-common/include/host-common/snapshot_interface.h
similarity index 99%
rename from snapshot/include/snapshot/interface.h
rename to host-common/include/host-common/snapshot_interface.h
index e83aa08..57849cb 100644
--- a/snapshot/include/snapshot/interface.h
+++ b/host-common/include/host-common/snapshot_interface.h
@@ -119,4 +119,4 @@ bool androidSnapshot_protoExists(const char* name);
 
 #ifndef USING_ANDROID_BP
 ANDROID_END_HEADER
-#endif
+#endif
\ No newline at end of file
diff --git a/host-common/include/host-common/sync_device.h b/host-common/include/host-common/sync_device.h
deleted file mode 100644
index d8d7ffc..0000000
--- a/host-common/include/host-common/sync_device.h
+++ /dev/null
@@ -1,58 +0,0 @@
-/*
-* Copyright (C) 2016 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#pragma once
-
-#include <cstdint>
-
-#ifdef _MSC_VER
-# ifdef BUILDING_EMUGL_COMMON_SHARED
-#  define EMUGL_COMMON_API __declspec(dllexport)
-# else
-#  define EMUGL_COMMON_API __declspec(dllimport)
-#endif
-#else
-# define EMUGL_COMMON_API
-#endif
-
-// Goldfish sync device
-typedef uint64_t (*emugl_sync_create_timeline_t)();
-typedef int (*emugl_sync_create_fence_t)(uint64_t timeline, uint32_t pt);
-typedef void (*emugl_sync_timeline_inc_t)(uint64_t timeline, uint32_t howmuch);
-typedef void (*emugl_sync_destroy_timeline_t)(uint64_t timeline);
-
-typedef void (*emugl_sync_trigger_wait_t)(uint64_t glsync, uint64_t thread, uint64_t timeline);
-typedef void (*emugl_sync_register_trigger_wait_t)(emugl_sync_trigger_wait_t trigger_fn);
-
-typedef bool (*emugl_sync_device_exists_t)();
-
-namespace emugl {
-
-EMUGL_COMMON_API extern emugl_sync_create_timeline_t emugl_sync_create_timeline;
-EMUGL_COMMON_API extern emugl_sync_create_fence_t emugl_sync_create_fence;
-EMUGL_COMMON_API extern emugl_sync_timeline_inc_t emugl_sync_timeline_inc;
-EMUGL_COMMON_API extern emugl_sync_destroy_timeline_t emugl_sync_destroy_timeline;
-EMUGL_COMMON_API extern emugl_sync_register_trigger_wait_t emugl_sync_register_trigger_wait;
-EMUGL_COMMON_API extern emugl_sync_device_exists_t emugl_sync_device_exists;
-
-EMUGL_COMMON_API void set_emugl_sync_create_timeline(emugl_sync_create_timeline_t);
-EMUGL_COMMON_API void set_emugl_sync_create_fence(emugl_sync_create_fence_t);
-EMUGL_COMMON_API void set_emugl_sync_timeline_inc(emugl_sync_timeline_inc_t);
-EMUGL_COMMON_API void set_emugl_sync_destroy_timeline(emugl_sync_destroy_timeline_t);
-EMUGL_COMMON_API void set_emugl_sync_register_trigger_wait(emugl_sync_register_trigger_wait_t trigger_fn);
-EMUGL_COMMON_API void set_emugl_sync_device_exists(emugl_sync_device_exists_t);
-
-}  // namespace emugl
diff --git a/host-common/include/host-common/vm_operations.h b/host-common/include/host-common/vm_operations.h
index f203060..a5b4c80 100644
--- a/host-common/include/host-common/vm_operations.h
+++ b/host-common/include/host-common/vm_operations.h
@@ -277,7 +277,7 @@ typedef struct QAndroidVmOperations {
     void (*vulkanInstanceEnumerate)(uint32_t* pCount, uint64_t* pIds, char** pNames);
 
     // Set the reason to skip snapshotting on exit.
-    void (*setSkipSnapshotSaveReason)(SnapshotSkipReason reason);
+    void (*setSkipSnapshotSaveReason)(uint32_t reason);
 
     // Get the reason to skip snapshotting on exit.
     SnapshotSkipReason (*getSkipSnapshotSaveReason)();
diff --git a/host-common/misc.cpp b/host-common/misc.cpp
deleted file mode 100644
index ecd3294..0000000
--- a/host-common/misc.cpp
+++ /dev/null
@@ -1,62 +0,0 @@
-// Copyright (C) 2016 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "misc.h"
-
-#include "aemu/base/memory/MemoryTracker.h"
-
-#include <cstring>
-
-static int s_apiLevel = -1;
-static bool s_isPhone = false;
-
-static bool s_shouldSkipDrawing = false;
-
-android::base::CpuUsage* s_cpu_usage = nullptr;
-android::base::MemoryTracker* s_mem_usage = nullptr;
-
-void emugl::setAvdInfo(bool phone, int apiLevel) {
-    s_isPhone = phone;
-    s_apiLevel = apiLevel;
-}
-
-bool emugl::shouldSkipDraw() {
-    return s_shouldSkipDrawing;
-}
-
-
-void emugl::setShouldSkipDraw(bool skip) {
-    s_shouldSkipDrawing = skip;
-}
-
-void emugl::getAvdInfo(bool* phone, int* apiLevel) {
-    if (phone) *phone = s_isPhone;
-    if (apiLevel) *apiLevel = s_apiLevel;
-}
-
-void emugl::setCpuUsage(android::base::CpuUsage* usage) {
-    s_cpu_usage = usage;
-}
-
-android::base::CpuUsage* emugl::getCpuUsage() {
-    return s_cpu_usage;
-}
-
-void emugl::setMemoryTracker(android::base::MemoryTracker* usage) {
-    s_mem_usage = usage;
-}
-
-android::base::MemoryTracker* emugl::getMemoryTracker() {
-    return s_mem_usage;
-}
diff --git a/host-common/sync_device.cpp b/host-common/sync_device.cpp
deleted file mode 100644
index 8aeadaf..0000000
--- a/host-common/sync_device.cpp
+++ /dev/null
@@ -1,80 +0,0 @@
-/*
-* Copyright (C) 2016 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#include "sync_device.h"
-
-static uint64_t defaultCreateTimeline() { return 0; }
-
-static int defaultCreateFence(uint64_t timeline, uint32_t pt) {
-    (void)timeline;
-    (void)pt;
-    return -1;
-}
-
-static void defaultTimelineInc(uint64_t timeline, uint32_t howmuch) {
-    (void)timeline;
-    (void)howmuch;
-    return;
-}
-
-static void defaultDestroyTimeline(uint64_t timeline) {
-    (void)timeline;
-    return;
-}
-
-static void defaultRegisterTriggerWait(emugl_sync_trigger_wait_t f) {
-    (void)f;
-    return;
-}
-
-static bool defaultDeviceExists() {
-    return false;
-}
-
-namespace emugl {
-
-emugl_sync_create_timeline_t emugl_sync_create_timeline = defaultCreateTimeline;
-emugl_sync_create_fence_t emugl_sync_create_fence = defaultCreateFence;
-emugl_sync_timeline_inc_t emugl_sync_timeline_inc = defaultTimelineInc;
-emugl_sync_destroy_timeline_t emugl_sync_destroy_timeline = defaultDestroyTimeline;
-emugl_sync_register_trigger_wait_t emugl_sync_register_trigger_wait = defaultRegisterTriggerWait;
-emugl_sync_device_exists_t emugl_sync_device_exists = defaultDeviceExists;
-
-void set_emugl_sync_create_timeline(emugl_sync_create_timeline_t f) {
-    emugl_sync_create_timeline = f;
-}
-
-void set_emugl_sync_create_fence(emugl_sync_create_fence_t f) {
-    emugl_sync_create_fence = f;
-}
-
-void set_emugl_sync_timeline_inc(emugl_sync_timeline_inc_t f) {
-    emugl_sync_timeline_inc = f;
-}
-
-void set_emugl_sync_destroy_timeline(emugl_sync_destroy_timeline_t f) {
-    emugl_sync_destroy_timeline = f;
-}
-
-void set_emugl_sync_register_trigger_wait(emugl_sync_register_trigger_wait_t f) {
-    emugl_sync_register_trigger_wait = f;
-}
-
-void set_emugl_sync_device_exists(emugl_sync_device_exists_t f) {
-    emugl_sync_device_exists = f;
-}
-
-}  // namespace emugl
diff --git a/host-common/vm_operations.cpp b/host-common/vm_operations.cpp
deleted file mode 100644
index 81c4c50..0000000
--- a/host-common/vm_operations.cpp
+++ /dev/null
@@ -1,32 +0,0 @@
-// Copyright 2023 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host-common/emugl_vm_operations.h"
-#include "host-common/vm_operations.h"
-
-namespace {
-
-QAndroidVmOperations g_vm_operations;
-
-}  // namespace
-
-void set_emugl_vm_operations(const QAndroidVmOperations &vm_operations)
-{
-    g_vm_operations = vm_operations;
-}
-
-const QAndroidVmOperations &get_emugl_vm_operations()
-{
-    return g_vm_operations;
-}
diff --git a/snapshot/Android.bp b/snapshot/Android.bp
deleted file mode 100644
index 5252536..0000000
--- a/snapshot/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "hardware_google_aemu_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["hardware_google_aemu_license"],
-}
-
-cc_library_static {
-    name: "gfxstream_snapshot",
-    defaults: [ "gfxstream_defaults" ],
-    srcs: [
-        "TextureLoader.cpp",
-        "TextureSaver.cpp",
-    ],
-    static_libs: [
-        "gfxstream_base",
-    ],
-    export_include_dirs: [ "include" ],
-}
diff --git a/snapshot/BUILD.bazel b/snapshot/BUILD.bazel
deleted file mode 100644
index 40d81b3..0000000
--- a/snapshot/BUILD.bazel
+++ /dev/null
@@ -1,36 +0,0 @@
-load("@rules_cc//cc:defs.bzl", "cc_library")
-
-# Interface library
-cc_library(
-    name = "gfxstream-snapshot-headers",
-    hdrs = [
-        "include/snapshot/LazySnapshotObj.h",
-        "include/snapshot/TextureLoader.h",
-        "include/snapshot/TextureSaver.h",
-        "include/snapshot/common.h",
-        "include/snapshot/interface.h",
-    ],
-    includes = ["include"],
-    visibility = ["//visibility:public"],
-)
-
-# Main library
-cc_library(
-    name = "aemu-snapshot",
-    srcs = [
-        "TextureLoader.cpp",
-        "TextureSaver.cpp",
-    ],
-    hdrs = [":gfxstream-snapshot-headers"],
-    copts = [
-        "-D_FILE_OFFSET_BITS=64",
-        "-Wno-extern-c-compat",
-        "-Wno-return-type-c-linkage",
-    ],
-    defines = ["dfatal=\"(void*)\""],
-    visibility = ["//visibility:public"],
-    deps = [
-        ":gfxstream-snapshot-headers",
-        "//base:aemu-base-headers",
-    ],
-)
diff --git a/snapshot/CMakeLists.txt b/snapshot/CMakeLists.txt
deleted file mode 100644
index fb92fd3..0000000
--- a/snapshot/CMakeLists.txt
+++ /dev/null
@@ -1,25 +0,0 @@
-add_library(gfxstream-snapshot.headers INTERFACE)
-target_include_directories(gfxstream-snapshot.headers INTERFACE include)
-
-add_library(
-    ${SNAPSHOT_LIB_NAME}
-    TextureLoader.cpp
-    TextureSaver.cpp)
-
-if (BUILD_SHARED_LIBS)
-    set_target_properties(
-        ${SNAPSHOT_LIB_NAME}
-        PROPERTIES
-        VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
-        SOVERSION ${VERSION_MAJOR})
-endif()
-
-target_link_libraries(
-    ${SNAPSHOT_LIB_NAME}
-    PRIVATE
-    aemu-base.headers
-    aemu-host-common.headers)
-target_include_directories(
-    ${SNAPSHOT_LIB_NAME}
-    PUBLIC
-    ${AEMU_COMMON_REPO_ROOT}/include)
diff --git a/snapshot/TextureLoader.cpp b/snapshot/TextureLoader.cpp
deleted file mode 100644
index 5c21134..0000000
--- a/snapshot/TextureLoader.cpp
+++ /dev/null
@@ -1,94 +0,0 @@
-/*
-* Copyright (C) 2017 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#include "snapshot/TextureLoader.h"
-
-#include "aemu/base/EintrWrapper.h"
-#include "aemu/base/files/DecompressingStream.h"
-
-#include <assert.h>
-
-using android::base::DecompressingStream;
-
-namespace android {
-namespace snapshot {
-
-TextureLoader::TextureLoader(android::base::StdioStream&& stream)
-    : mStream(std::move(stream)) {}
-
-bool TextureLoader::start() {
-    if (mStarted) {
-        return !mHasError;
-    }
-
-    mStarted = true;
-    bool res = readIndex();
-    if (!res) {
-        mHasError = true;
-        return false;
-    }
-    return true;
-}
-
-void TextureLoader::loadTexture(uint32_t texId, const loader_t& loader) {
-    android::base::AutoLock scopedLock(mLock);
-    assert(mIndex.count(texId));
-    HANDLE_EINTR(fseeko(mStream.get(), mIndex[texId], SEEK_SET));
-    switch (mVersion) {
-        case 1:
-            loader(&mStream);
-            break;
-        case 2: {
-            DecompressingStream stream(mStream);
-            loader(&stream);
-        }
-    }
-    if (ferror(mStream.get())) {
-        mHasError = true;
-    }
-}
-
-bool TextureLoader::readIndex() {
-#if SNAPSHOT_PROFILE > 1
-    auto start = android::base::System::get()->getHighResTimeUs();
-#endif
-    assert(mIndex.size() == 0);
-    uint64_t size;
-    if (base::getFileSize(fileno(mStream.get()), &size)) {
-        mDiskSize = size;
-    }
-    auto indexPos = mStream.getBe64();
-    HANDLE_EINTR(fseeko(mStream.get(), static_cast<int64_t>(indexPos), SEEK_SET));
-    mVersion = mStream.getBe32();
-    if (mVersion < 1 || mVersion > 2) {
-        return false;
-    }
-    uint32_t texCount = mStream.getBe32();
-    mIndex.reserve(texCount);
-    for (uint32_t i = 0; i < texCount; i++) {
-        uint32_t tex = mStream.getBe32();
-        uint64_t filePos = mStream.getBe64();
-        mIndex.emplace(tex, filePos);
-    }
-#if SNAPSHOT_PROFILE > 1
-    printf("Texture readIndex() time: %.03f\n",
-           (android::base::System::get()->getHighResTimeUs() - start) / 1000.0);
-#endif
-    return true;
-}
-
-}  // namespace snapshot
-}  // namespace android
diff --git a/snapshot/TextureSaver.cpp b/snapshot/TextureSaver.cpp
deleted file mode 100644
index c8854e9..0000000
--- a/snapshot/TextureSaver.cpp
+++ /dev/null
@@ -1,97 +0,0 @@
-/*
-* Copyright (C) 2017 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#include "snapshot/TextureSaver.h"
-
-#include "aemu/base/files/CompressingStream.h"
-#include "aemu/base/system/System.h"
-
-#include <algorithm>
-#include <cassert>
-#include <iterator>
-#include <utility>
-
-using android::base::CompressingStream;
-
-namespace android {
-namespace snapshot {
-
-TextureSaver::TextureSaver(android::base::StdioStream&& stream)
-    : mStream(std::move(stream)) {
-    // Put a placeholder for the index offset right now.
-    mStream.putBe64(0);
-}
-
-TextureSaver::~TextureSaver() {
-    done();
-}
-
-void TextureSaver::saveTexture(uint32_t texId, const saver_t& saver) {
-
-    if (!mStartTime) {
-        mStartTime = base::getHighResTimeUs();
-    }
-
-    assert(mIndex.textures.end() ==
-           std::find_if(mIndex.textures.begin(), mIndex.textures.end(),
-                        [texId](FileIndex::Texture& tex) {
-                            return tex.texId == texId;
-                        }));
-    mIndex.textures.push_back({texId, ftello(mStream.get())});
-
-    CompressingStream stream(mStream);
-    saver(&stream, &mBuffer);
-}
-
-void TextureSaver::done() {
-    if (mFinished) {
-        return;
-    }
-    mIndex.startPosInFile = ftello(mStream.get());
-    writeIndex();
-    mEndTime = base::getHighResTimeUs();
-#if SNAPSHOT_PROFILE > 1
-    printf("Texture saving time: %.03f\n",
-           (mEndTime - mStartTime) / 1000.0);
-#endif
-    mHasError = ferror(mStream.get()) != 0;
-    mFinished = true;
-    mStream.close();
-}
-
-void TextureSaver::writeIndex() {
-#if SNAPSHOT_PROFILE > 1
-    auto start = ftello(mStream.get());
-#endif
-
-    mStream.putBe32(static_cast<uint32_t>(mIndex.version));
-    mStream.putBe32(static_cast<uint32_t>(mIndex.textures.size()));
-    for (const FileIndex::Texture& b : mIndex.textures) {
-        mStream.putBe32(b.texId);
-        mStream.putBe64(static_cast<uint64_t>(b.filePos));
-    }
-    auto end = ftello(mStream.get());
-    mDiskSize = uint64_t(end);
-#if SNAPSHOT_PROFILE > 1
-    printf("texture: index size: %d\n", int(end - start));
-#endif
-
-    fseeko(mStream.get(), 0, SEEK_SET);
-    mStream.putBe64(static_cast<uint64_t>(mIndex.startPosInFile));
-}
-
-}  // namespace snapshot
-}  // namespace android
diff --git a/snapshot/include/snapshot/LazySnapshotObj.h b/snapshot/include/snapshot/LazySnapshotObj.h
deleted file mode 100644
index ffd8500..0000000
--- a/snapshot/include/snapshot/LazySnapshotObj.h
+++ /dev/null
@@ -1,69 +0,0 @@
-/*
-* Copyright (C) 2017 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#pragma once
-
-#include "aemu/base/Compiler.h"
-#include "aemu/base/synchronization/Lock.h"
-
-namespace android {
-
-namespace base { class Stream; }
-
-namespace snapshot {
-
-// LazySnapshotObj is a base class for objects that use lazy strategy for
-// snapshot loading. It separates heavy-weight loading / restoring operations
-// and only triggers it when the object needs to be used.
-// Please implement heavy-weight loading / restoring operations in restore()
-// method and call "touch" before you need to use the object.
-
-// An example is for texture lazy loading. On load it only reads the data from
-// disk but does not load them into GPU. On restore it performs the heavy-weight
-// GPU data loading.
-
-template <class Derived>
-class LazySnapshotObj {
-    DISALLOW_COPY_AND_ASSIGN(LazySnapshotObj);
-public:
-    LazySnapshotObj() = default;
-    // Snapshot loader
-    LazySnapshotObj(base::Stream*) : mNeedRestore(true) {}
-
-    void touch() {
-        base::AutoLock lock(mMutex);
-        if (!mNeedRestore) {
-            return;
-        }
-        static_cast<Derived*>(this)->restore();
-        mNeedRestore = false;
-    }
-
-    bool needRestore() const {
-        base::AutoLock lock(mMutex);
-        return mNeedRestore;
-    }
-
-protected:
-    ~LazySnapshotObj() = default;
-    bool mNeedRestore = false;
-
-private:
-    mutable base::Lock mMutex;
-};
-
-} // namespace snapshot
-} // namespace android
diff --git a/snapshot/include/snapshot/TextureLoader.h b/snapshot/include/snapshot/TextureLoader.h
deleted file mode 100644
index 6975bd2..0000000
--- a/snapshot/include/snapshot/TextureLoader.h
+++ /dev/null
@@ -1,122 +0,0 @@
-/*
-* Copyright (C) 2017 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#pragma once
-
-#include "aemu/base/containers/SmallVector.h"
-#include "aemu/base/export.h"
-#include "aemu/base/files/StdioStream.h"
-#include "aemu/base/synchronization/Lock.h"
-#include "aemu/base/system/System.h"
-#include "aemu/base/threads/Thread.h"
-#include "snapshot/common.h"
-
-#include <functional>
-#include <memory>
-#include <unordered_map>
-
-namespace android {
-namespace snapshot {
-
-class ITextureLoader {
-    DISALLOW_COPY_AND_ASSIGN(ITextureLoader);
-
-protected:
-    ~ITextureLoader() = default;
-
-public:
-    ITextureLoader() = default;
-
-    using LoaderThreadPtr = std::shared_ptr<android::base::InterruptibleThread>;
-    using loader_t = std::function<void(android::base::Stream*)>;
-
-    virtual bool start() = 0;
-    // Move file position to texId and trigger loader
-    virtual void loadTexture(uint32_t texId, const loader_t& loader) = 0;
-    virtual void acquireLoaderThread(LoaderThreadPtr thread) = 0;
-    virtual bool hasError() const = 0;
-    virtual uint64_t diskSize() const = 0;
-    virtual bool compressed() const = 0;
-    virtual void join() = 0;
-    virtual void interrupt() = 0;
-};
-
-class TextureLoader final : public ITextureLoader {
-public:
-    AEMU_EXPORT TextureLoader(android::base::StdioStream&& stream);
-
-    AEMU_EXPORT bool start() override;
-    AEMU_EXPORT void loadTexture(uint32_t texId, const loader_t& loader) override;
-    AEMU_EXPORT bool hasError() const override { return mHasError; }
-    AEMU_EXPORT uint64_t diskSize() const override { return mDiskSize; }
-    AEMU_EXPORT bool compressed() const override { return mVersion > 1; }
-
-    AEMU_EXPORT void acquireLoaderThread(LoaderThreadPtr thread) override {
-        mLoaderThread = std::move(thread);
-    }
-
-    AEMU_EXPORT void join() override {
-        if (mLoaderThread) {
-            mLoaderThread->wait();
-            mLoaderThread.reset();
-        }
-        mStream.close();
-        mEndTime = base::getHighResTimeUs();
-    }
-
-    AEMU_EXPORT void interrupt() override {
-        if (mLoaderThread) {
-            mLoaderThread->interrupt();
-            mLoaderThread->wait();
-            mLoaderThread.reset();
-        }
-        mStream.close();
-        mEndTime = base::getHighResTimeUs();
-    }
-
-    // getDuration():
-    // Returns true if there was save with measurable time
-    // (and writes it to |duration| if |duration| is not null),
-    // otherwise returns false.
-    AEMU_EXPORT bool getDuration(uint64_t* duration) {
-        if (mEndTime < mStartTime) {
-            return false;
-        }
-
-        if (duration) {
-            *duration = mEndTime - mStartTime;
-        }
-        return true;
-    }
-
-private:
-    bool readIndex();
-
-    android::base::StdioStream mStream;
-    std::unordered_map<uint32_t, int64_t> mIndex;
-    android::base::Lock mLock;
-    bool mStarted = false;
-    bool mHasError = false;
-    int mVersion = 0;
-    uint64_t mDiskSize = 0;
-    LoaderThreadPtr mLoaderThread;
-
-    uint64_t mStartTime = 0;
-    uint64_t mEndTime = 0;
-};
-
-}  // namespace snapshot
-}  // namespace android
diff --git a/snapshot/include/snapshot/TextureSaver.h b/snapshot/include/snapshot/TextureSaver.h
deleted file mode 100644
index a9bdb3f..0000000
--- a/snapshot/include/snapshot/TextureSaver.h
+++ /dev/null
@@ -1,107 +0,0 @@
-/*
-* Copyright (C) 2017 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#pragma once
-
-#include "aemu/base/containers/SmallVector.h"
-#include "aemu/base/export.h"
-#include "aemu/base/files/StdioStream.h"
-#include "aemu/base/system/System.h"
-#include "snapshot/common.h"
-
-#include <functional>
-#include <vector>
-
-namespace android {
-namespace snapshot {
-
-class ITextureSaver {
-    DISALLOW_COPY_AND_ASSIGN(ITextureSaver);
-
-protected:
-    ~ITextureSaver() = default;
-
-public:
-    ITextureSaver() = default;
-
-    using Buffer = android::base::SmallVector<unsigned char>;
-    using saver_t = std::function<void(android::base::Stream*, Buffer*)>;
-
-    // Save texture to a stream as well as update the index
-    virtual void saveTexture(uint32_t texId, const saver_t& saver) = 0;
-    virtual bool hasError() const = 0;
-    virtual uint64_t diskSize() const = 0;
-    virtual bool compressed() const = 0;
-    virtual bool getDuration(uint64_t* duration) = 0;
-};
-
-class TextureSaver final : public ITextureSaver {
-    DISALLOW_COPY_AND_ASSIGN(TextureSaver);
-
-public:
-    AEMU_EXPORT TextureSaver(android::base::StdioStream&& stream);
-    AEMU_EXPORT ~TextureSaver();
-    AEMU_EXPORT void saveTexture(uint32_t texId, const saver_t& saver) override;
-    AEMU_EXPORT void done();
-
-    AEMU_EXPORT bool hasError() const override { return mHasError; }
-    AEMU_EXPORT uint64_t diskSize() const override { return mDiskSize; }
-    AEMU_EXPORT bool compressed() const override { return mIndex.version > 1; }
-
-    // getDuration():
-    // Returns true if there was save with measurable time
-    // (and writes it to |duration| if |duration| is not null),
-    // otherwise returns false.
-    AEMU_EXPORT bool getDuration(uint64_t* duration) override {
-        if (mEndTime < mStartTime) {
-            return false;
-        }
-
-        if (duration) {
-            *duration = mEndTime - mStartTime;
-        }
-        return true;
-    }
-
-private:
-    struct FileIndex {
-        struct Texture {
-            uint32_t texId;
-            int64_t filePos;
-        };
-
-        int64_t startPosInFile;
-        int32_t version = 2;
-        std::vector<Texture> textures;
-    };
-
-    void writeIndex();
-
-    android::base::StdioStream mStream;
-    // A buffer for fetching data from GPU memory to RAM.
-    android::base::SmallFixedVector<unsigned char, 128> mBuffer;
-
-    FileIndex mIndex;
-    uint64_t mDiskSize = 0;
-    bool mFinished = false;
-    bool mHasError = false;
-
-    uint64_t mStartTime = 0;
-    uint64_t mEndTime = 0;
-};
-
-}  // namespace snapshot
-}  // namespace android
diff --git a/windows/BUILD b/windows/BUILD
index 86b9dd9..a14b4f3 100644
--- a/windows/BUILD
+++ b/windows/BUILD
@@ -1,5 +1,19 @@
 load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
 
+exports_files(
+    [
+        "includes",
+        "includes/sys",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+filegroup(
+    name = "compat-includes",
+    srcs = glob(["includes/**/*.h"]),
+    visibility = ["//visibility:public"],
+)
+
 cc_library(
     name = "compat-hdrs",
     hdrs = glob(["includes/**/*.h"]),
```

