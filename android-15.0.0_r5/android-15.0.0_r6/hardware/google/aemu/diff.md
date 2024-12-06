```diff
diff --git a/BUILD.bazel b/BUILD.bazel
index 73cb5af..a29d395 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -20,3 +20,14 @@ license_kind(
     conditions = ["notice"],
     url = "https://spdx.org/licenses/Apache-2.0.html",
 )
+
+cc_library(
+    name = "aemu-host-common-test-headers",
+    hdrs = glob([
+        "host-common/testing/**/*.h",
+        "host-common/testing/**/*.hpp",
+    ]),
+    includes = ["include"],
+    visibility = ["//visibility:public"],
+    deps = ["//hardware/google/aemu/base:test-io"],
+)
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 4de86a4..7485f08 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -54,6 +54,8 @@ if (MSVC)
     add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
     # ask msvc not to warn non C ISO POSIX functions
     add_compile_definitions(_CRT_NONSTDC_NO_DEPRECATE)
+
+    add_subdirectory(windows)
 endif()
 
 # Set AEMU_BUILD_CONFIG_NAME to use a custom cmake build script located in
@@ -69,13 +71,14 @@ ${AEMU_COMMON_REPO_ROOT}/build-config/${AEMU_COMMON_BUILD_CONFIG}")
     add_subdirectory(build-config/${AEMU_COMMON_BUILD_CONFIG})
 endif()
 
-set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-extern-c-compat -Wno-return-type-c-linkage")
+set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-extern-c-compat -Wno-return-type-c-linkage -D_FILE_OFFSET_BITS=64")
 
 add_subdirectory(base)
 add_subdirectory(snapshot)
 add_subdirectory(host-common)
 add_subdirectory(third-party)
 
+
 add_library(aemu_common INTERFACE)
 target_link_libraries(
     aemu_common
diff --git a/base/Android.bp b/base/Android.bp
index e225a82..b305074 100644
--- a/base/Android.bp
+++ b/base/Android.bp
@@ -10,7 +10,12 @@ package {
 
 cc_library_static {
     name: "gfxstream_base",
-    defaults: ["gfxstream_defaults"],
+    host_supported: true,
+    vendor_available: true,
+    cflags: [
+        "-Wno-unused-parameter",
+        "-Wno-reorder-ctor",
+    ],
     srcs: [
         "AlignedBuf.cpp",
         "CompressingStream.cpp",
@@ -18,6 +23,7 @@ cc_library_static {
         "DecompressingStream.cpp",
         "FileUtils.cpp",
         "FunctorThread.cpp",
+        "GraphicsObjectCounter.cpp",
         "GLObjectCounter.cpp",
         "HealthMonitor.cpp",
         "LayoutResolver.cpp",
@@ -38,9 +44,17 @@ cc_library_static {
         "Tracing.cpp",
         "Thread_pthread.cpp",
     ],
-    header_libs: ["libgfxstream_thirdparty_renderdoc_headers"],
+    header_libs: [
+        "libgfxstream_thirdparty_renderdoc_headers",
+        "aemu_common_headers",
+
+    ],
     export_header_lib_headers: ["libgfxstream_thirdparty_renderdoc_headers"],
     static_libs: ["liblz4"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.virt",
+    ],
 }
 
 // Run with `atest --host gfxstream_base_tests`
diff --git a/base/BUILD.bazel b/base/BUILD.bazel
index e529c02..e4969be 100644
--- a/base/BUILD.bazel
+++ b/base/BUILD.bazel
@@ -16,7 +16,12 @@ cc_library(
     deps = [
         "//hardware/google/aemu/host-common:aemu-host-common-headers",
         "@com_google_absl//absl/strings:str_format",
-    ],
+    ] + select({
+        "@platforms//os:windows": [
+            "//hardware/google/aemu/windows:compat-hdrs",
+        ],
+        "//conditions:default": [],
+    }),
 )
 
 cc_library(
@@ -57,6 +62,7 @@ cc_library(
         "FileUtils.cpp",
         "FunctorThread.cpp",
         "GLObjectCounter.cpp",
+        "GraphicsObjectCounter.cpp",
         "HealthMonitor.cpp",
         "LayoutResolver.cpp",
         "MemStream.cpp",
@@ -77,7 +83,6 @@ cc_library(
             "SharedMemory_win32.cpp",
             "Thread_win32.cpp",
             "Win32UnicodeString.cpp",
-            "msvc.cpp",
         ],
         "@platforms//os:macos": [
             "SharedMemory_posix.cpp",
@@ -122,10 +127,28 @@ cc_library(
         "@platforms//os:macos": [
             ":aemu-base-darwin",
         ],
+        "@platforms//os:windows": [
+            "//external/qemu/google/compat/windows:compat",
+        ],
         "//conditions:default": [],
     }),
 )
 
+cc_library(
+    name = "test-io",
+    srcs = [
+        "testing/file_io.cpp",
+    ],
+    visibility = [
+        "//visibility:public",
+    ],
+    deps = [
+        ":aemu-base",
+        ":aemu-base-headers",
+    ],
+    alwayslink = True,
+)
+
 cc_test(
     name = "aemu-base_unittests",
     srcs = [
@@ -138,20 +161,27 @@ cc_test(
         "ManagedDescriptor_unittest.cpp",
         "NoDestructor_unittest.cpp",
         "Optional_unittest.cpp",
+        "RecurrentTask_unittest.cpp",
         "StringFormat_unittest.cpp",
         "SubAllocator_unittest.cpp",
         "TypeTraits_unittest.cpp",
         "WorkerThread_unittest.cpp",
         "ring_buffer_unittest.cpp",
-        "testing/file_io.cpp",
     ] + select({
-        "@platforms//os:windows": ["Win32UnicodeString_unittest.cpp"],
+        "@platforms//os:windows": [
+            "Win32UnicodeString_unittest.cpp",
+        ],
         "//conditions:default": [],
     }),
+    linkopts = [
+        "-undefined error",
+    ],
     deps = [
         ":aemu-base",
         ":aemu-base-headers",
-        "//hardware/google/aemu/base:aemu-base-darwin",
+        "//hardware/generic/goldfish/android/logging:backend",
+        "//hardware/generic/goldfish/android/looper",
+        "//hardware/generic/goldfish/android/sockets",
         "//hardware/google/aemu/base:aemu-base-metrics",
         "//hardware/google/aemu/host-common:logging",
         "@com_google_absl//absl/log",
diff --git a/base/CMakeLists.txt b/base/CMakeLists.txt
index 5af7d98..ff18c93 100644
--- a/base/CMakeLists.txt
+++ b/base/CMakeLists.txt
@@ -25,6 +25,7 @@ if (BUILD_STANDALONE)
             FileUtils.cpp
             FunctorThread.cpp
             GLObjectCounter.cpp
+            GraphicsObjectCounter.cpp
             HealthMonitor.cpp
             LayoutResolver.cpp
             MemStream.cpp
diff --git a/base/GraphicsObjectCounter.cpp b/base/GraphicsObjectCounter.cpp
new file mode 100644
index 0000000..b20b02a
--- /dev/null
+++ b/base/GraphicsObjectCounter.cpp
@@ -0,0 +1,77 @@
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
+#include "aemu/base/GraphicsObjectCounter.h"
+
+#include <array>
+#include <atomic>
+#include <iostream>
+#include <sstream>
+
+namespace android {
+namespace base {
+
+class GraphicsObjectCounter::Impl {
+   public:
+    void incCount(size_t type) {
+        if (type > toIndex(GraphicsObjectType::NULLTYPE) &&
+            type < toIndex(GraphicsObjectType::NUM_OBJECT_TYPES)) {
+            mCounter[type] += 1;
+        }
+    }
+
+    void decCount(size_t type) {
+        if (type > toIndex(GraphicsObjectType::NULLTYPE) &&
+            type < toIndex(GraphicsObjectType::NUM_OBJECT_TYPES)) {
+            mCounter[type] -= 1;
+        }
+    }
+
+    std::vector<size_t> getCounts() {
+        std::vector<size_t> v;
+        for (auto& it : mCounter) {
+            v.push_back(it.load());
+        }
+        return v;
+    }
+
+    std::string printUsage() {
+        std::stringstream ss;
+        ss << "ColorBuffer: " << mCounter[toIndex(GraphicsObjectType::COLORBUFFER)].load();
+        // TODO: Fill with the rest of the counters we are interested in
+        return ss.str();
+    }
+
+   private:
+    std::array<std::atomic<size_t>, toIndex(GraphicsObjectType::NUM_OBJECT_TYPES)> mCounter = {};
+};
+
+static GraphicsObjectCounter* sGlobal() {
+    static GraphicsObjectCounter* g = new GraphicsObjectCounter;
+    return g;
+}
+
+GraphicsObjectCounter::GraphicsObjectCounter() : mImpl(new GraphicsObjectCounter::Impl()) {}
+
+void GraphicsObjectCounter::incCount(size_t type) { mImpl->incCount(type); }
+
+void GraphicsObjectCounter::decCount(size_t type) { mImpl->decCount(type); }
+
+std::vector<size_t> GraphicsObjectCounter::getCounts() const { return mImpl->getCounts(); }
+
+std::string GraphicsObjectCounter::printUsage() const { return mImpl->printUsage(); }
+
+GraphicsObjectCounter* GraphicsObjectCounter::get() { return sGlobal(); }
+
+}  // namespace base
+}  // namespace android
diff --git a/base/System.cpp b/base/System.cpp
index 7cf64d8..d85fbc1 100644
--- a/base/System.cpp
+++ b/base/System.cpp
@@ -178,10 +178,6 @@ void setEnvironmentVariable(const std::string& key, const std::string& value) {
 #endif
 }
 
-bool isVerboseLogging() {
-    return false;
-}
-
 int fdStat(int fd, PathStat* st) {
 #ifdef _WIN32
     return _fstat64(fd, st);
diff --git a/base/include/aemu/base/GraphicsObjectCounter.h b/base/include/aemu/base/GraphicsObjectCounter.h
new file mode 100644
index 0000000..2813ed8
--- /dev/null
+++ b/base/include/aemu/base/GraphicsObjectCounter.h
@@ -0,0 +1,52 @@
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
+#include <memory>
+#include <string>
+#include <vector>
+#include <iostream>
+
+#include "aemu/base/Compiler.h"
+#include "aemu/base/synchronization/Lock.h"
+
+namespace android {
+namespace base {
+
+enum class GraphicsObjectType : int {
+    NULLTYPE,
+    COLORBUFFER,
+    NUM_OBJECT_TYPES,
+};
+
+static constexpr size_t toIndex(GraphicsObjectType type) { return static_cast<size_t>(type); }
+
+class GraphicsObjectCounter {
+    DISALLOW_COPY_ASSIGN_AND_MOVE(GraphicsObjectCounter);
+
+   public:
+    GraphicsObjectCounter();
+    void incCount(size_t type);
+    void decCount(size_t type);
+    std::vector<size_t> getCounts() const;
+    std::string printUsage() const;
+    static GraphicsObjectCounter* get();
+
+   private:
+    class Impl;
+    std::unique_ptr<Impl> mImpl;
+};
+}  // namespace base
+}  // namespace android
diff --git a/base/include/aemu/base/LayoutResolver.h b/base/include/aemu/base/LayoutResolver.h
index ef61fdc..1474594 100644
--- a/base/include/aemu/base/LayoutResolver.h
+++ b/base/include/aemu/base/LayoutResolver.h
@@ -29,7 +29,7 @@ std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> resolveLayout(
         const double monitorAspectRatio);
 
 std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> resolveStackedLayout(
-        std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> rectangles);
-
+        std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> rectangles,
+        const bool isDistantDisplay);
 }  // namespace base
 }  // namespace android
diff --git a/base/include/aemu/base/async/AsyncSocket.h b/base/include/aemu/base/async/AsyncSocket.h
index e495fd5..12ea8b1 100644
--- a/base/include/aemu/base/async/AsyncSocket.h
+++ b/base/include/aemu/base/async/AsyncSocket.h
@@ -12,65 +12,157 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 #pragma once
-#include "aemu/base/Log.h"
+#include <chrono>
+#include <condition_variable>
+#include <functional>
+#include <mutex>
+#include <thread>
+
 #include "aemu/base/async/AsyncSocketAdapter.h"
 #include "aemu/base/async/AsyncWriter.h"
 #include "aemu/base/async/Looper.h"
 #include "aemu/base/containers/BufferQueue.h"
+#include "aemu/base/sockets/ScopedSocket.h"
 #include "aemu/base/sockets/SocketUtils.h"
 #include "aemu/base/synchronization/Lock.h"
-#include "aemu/base/threads/FunctorThread.h"
-#include "aemu/base/sockets/ScopedSocket.h"
 
 namespace android {
 namespace base {
-using MessageQueue = android::base::BufferQueue<std::string>;
-using android::base::AsyncSocketAdapter;
-using android::base::FunctorThread;
+using MessageQueue = BufferQueue<std::string>;
 
-// An AsyncSocket is a socket that can connect to a local port on
-// the current machine.
+/**
+ * @brief An asynchronous socket implementation using Looper.
+ *
+ * This class provides a way to perform socket operations asynchronously
+ * using the Looper mechanism. It supports both outgoing and incoming
+ * connections.
+ */
 class AsyncSocket : public AsyncSocketAdapter {
-public:
+   public:
+    /**
+     * @brief Constructs an AsyncSocket for an outgoing connection.
+     *
+     * @param looper The Looper to use for asynchronous operations.
+     * @param port The port to connect to.
+     */
     AsyncSocket(Looper* looper, int port);
+
+    /**
+     * @brief Constructs an AsyncSocket for an incoming connection.
+     *
+     * @param looper The Looper to use for asynchronous operations.
+     * @param socket The ScopedSocket representing the accepted connection.
+     */
     AsyncSocket(Looper* looper, ScopedSocket socket);
     ~AsyncSocket();
+
+    /**
+     * @brief Closes the socket.
+     */
     void close() override;
-    uint64_t recv(char* buffer, uint64_t bufferSize) override;
-    uint64_t send(const char* buffer, uint64_t bufferSize) override;
 
+    /**
+     * @brief Receives data from the socket.
+     *
+     * @param buffer The buffer to receive the data into.
+     * @param bufferSize The size of the buffer.
+     * @return The number of bytes received, or -1 if an error occurred.
+     */
+    ssize_t recv(char* buffer, uint64_t bufferSize) override;
+
+    /**
+     * @brief Sends data over the socket.
+     *
+     * @param buffer The buffer containing the data to send.
+     * @param bufferSize The size of the data to send.
+     * @return The number of bytes sent, or -1 if an error occurred.
+     */
+    ssize_t send(const char* buffer, uint64_t bufferSize) override;
+
+    /**
+     * @brief Attempts to asynchronously connect the socket.
+     *
+     * @return True if the connection attempt was successful, false
+     * otherwise.
+     */
     bool connect() override;
+
+    /**
+     * @brief Checks if the socket is connected.
+     *
+     * @return True if the socket is connected, false otherwise.
+     */
     bool connected() override;
-    bool connectSync(
-            uint64_t timeoutms = std::numeric_limits<int>::max()) override;
+
+    /**
+     * @brief Connects the socket synchronously.
+     *
+     * The onConnected callback will have been called before this function
+     * returns. This means that if you lock on mutex x before calling this you
+     * will not be able to lock mutex x in the onConnected callback.
+     *
+     * @param timeout The maximum time to wait for the connection to be
+     * established.
+     * @return True if the connection was successful, false if it timed out.
+     */
+    bool connectSync(std::chrono::milliseconds timeout = std::chrono::milliseconds::max()) override;
+
+    /**
+     * @brief Disposes the socket.
+     *
+     * After this method returns, the following should hold:
+     * - No events will be delivered.
+     * - No send/recv/connect/close calls will be made.
+     * - The socket can be closed, and any ongoing connects should stop.
+     */
     void dispose() override;
 
+    // Callback function for write completion.
     void onWrite();
+
+    // Callback function for read availability.
     void onRead();
+
+    // Indicates that the socket is interested in reading data.
     void wantRead();
 
-private:
+   private:
+    // Attempts to connect to the specified port.
     void connectToPort();
+
+    // Size of the write buffer.
     static const int WRITE_BUFFER_SIZE = 1024;
 
     ScopedSocket mSocket;
-    int mPort;
 
+    // Port to connect to, or -1 if this is an incoming socket.
+    int mPort;
     Looper* mLooper;
     bool mConnecting = false;
-
     std::unique_ptr<Looper::FdWatch> mFdWatch;
-    ::android::base::AsyncWriter mAsyncWriter;
-    std::unique_ptr<FunctorThread> mConnectThread;
 
-    // Queue of message that need to go out over this socket.
+    android::base::AsyncWriter mAsyncWriter;
+
+    // Thread for handling connection attempts.
+    std::unique_ptr<std::thread> mConnectThread;
+
+    // Queue of messages to be written.
     MessageQueue mWriteQueue;
     Lock mWriteQueueLock;
-    Lock mWatchLock;
-    ConditionVariable mWatchLockCv;
+
+    // Mutex for synchronizing access to the FdWatch.
+    std::mutex mWatchLock;
+
+    // Condition variable for signaling changes in FdWatch state.
+    std::condition_variable mWatchLockCv;
 
     // Write buffer used by the async writer.
     std::string mWriteBuffer;
+
+    // Mutex to track callback activity, this mutex will be taken
+    // when a callback is active.
+    std::recursive_mutex mListenerLock;
 };
+
 }  // namespace base
 }  // namespace android
diff --git a/base/include/aemu/base/async/AsyncSocketAdapter.h b/base/include/aemu/base/async/AsyncSocketAdapter.h
index 2a38d51..4c99f9f 100644
--- a/base/include/aemu/base/async/AsyncSocketAdapter.h
+++ b/base/include/aemu/base/async/AsyncSocketAdapter.h
@@ -13,61 +13,228 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 #pragma once
+#include <chrono>
 #include <cstdint>
-#include <limits>
+#include <functional>
+#include <memory>
+#include <string_view>
+
+#ifdef _MSC_VER
+#include "aemu/base/msvc.h"
+#else
+#include <unistd.h>
+#endif
 
 namespace android {
 namespace base {
 
 class AsyncSocketAdapter;
+
+/**
+ * @brief An interface for listening to events from an
+ * AsyncSocketAdapter.
+ */
 class AsyncSocketEventListener {
-public:
+   public:
     virtual ~AsyncSocketEventListener() = default;
-    // Called when bytes can be read from the socket.
+
+    /**
+     * @brief Called when bytes can be read from the socket.
+     *
+     * @param socket The socket that has bytes available for reading.
+     */
     virtual void onRead(AsyncSocketAdapter* socket) = 0;
 
-    // Called when this socket is closed.
+    /**
+     * @brief Called when this socket is closed.
+     *
+     * @param socket The socket that was closed.
+     * @param err The error code associated with the closure, if any.
+     */
     virtual void onClose(AsyncSocketAdapter* socket, int err) = 0;
 
-    // Called when this socket (re) established a connection.
+    /**
+     * @brief Called when this socket (re)establishes a connection.
+     *
+     * This callback is only invoked for sockets that initiate an outgoing
+     * connection.
+     *
+     * @param socket The socket that successfully connected.
+     */
     virtual void onConnected(AsyncSocketAdapter* socket) = 0;
 };
 
-// A connected asynchronous socket.
-// The videobridge will provide an implementation, as well as the android-webrtc
-// module.
+/**
+ * @brief A connected asynchronous socket.
+ *
+ */
 class AsyncSocketAdapter {
-public:
+   public:
     virtual ~AsyncSocketAdapter() = default;
-    void setSocketEventListener(AsyncSocketEventListener* listener) {
-        mListener = listener;
-    }
-    virtual uint64_t recv(char* buffer, uint64_t bufferSize) = 0;
-    virtual uint64_t send(const char* buffer, uint64_t bufferSize) = 0;
+
+    /**
+     * @brief Sets the event listener for this socket.
+     *
+     * @param listener The listener to receive events.
+     */
+    void setSocketEventListener(AsyncSocketEventListener* listener) { mListener = listener; }
+
+    /**
+     * @brief Receives data from the socket.
+     *
+     * You should call this method in response to an onRead event.
+     *
+     * @param buffer The buffer to receive the data into.
+     * @param bufferSize The size of the buffer.
+     * @return The number of bytes received, or -1 if an error occurred.
+     */
+    virtual ssize_t recv(char* buffer, uint64_t bufferSize) = 0;
+
+    /**
+     * @brief Sends data over the socket.
+     *
+     * @param buffer The buffer containing the data to send.
+     * @param bufferSize The size of the data to send.
+     * @return The number of bytes sent, or -1 if an error occurred.
+     */
+    virtual ssize_t send(const char* buffer, uint64_t bufferSize) = 0;
+
+    /**
+     * @brief Closes the socket.
+     */
     virtual void close() = 0;
 
-    // True if this socket is connected
+    /**
+     * @brief Checks if the socket is connected.
+     *
+     * @return True if the socket is connected, false otherwise.
+     */
     virtual bool connected() = 0;
 
-    // Re-connect the socket, return false if
-    // reconnection will never succeed,
+    /**
+     * @brief Attempts to reconnect the socket.
+     *
+     * @return True if the reconnection attempt was successful, false
+     * otherwise.
+     */
     virtual bool connect() = 0;
 
-    // Connect synchronously, returning true if succeeded
-    // false if we timed out. The onConnected callback will have been called
-    // before this function returns. This means that if you lock on mutex x before
-    // calling this you will not be able to lock mutex x in the onConnected callback.
-    virtual bool connectSync(uint64_t timeoutms=std::numeric_limits<int>::max()) = 0;
+    /**
+     * @brief Connects the socket synchronously.
+     *
+     * The onConnected callback will have been called before this function
+     * returns. This means that if you lock on mutex x before calling this you
+     * will not be able to lock mutex x in the onConnected callback.
+     *
+     * @param timeout The maximum time to wait for the connection to be
+     * established.
+     * @return True if the connection was successful, false if it timed out.
+     */
+    virtual bool connectSync(std::chrono::milliseconds timeout) = 0;
 
-    // Disposes this socket, after return the following should hold:
-    // - No events will be delivered.
-    // - No send/recv/connect/close calls will be made.
-    // - The socket can be closed, and any ongoing connects should stop.
+    /**
+     * @brief Disposes the socket.
+     *
+     * After this method returns, the following should hold:
+     * - No events will be delivered.
+     * - No send/recv/connect/close calls will be made.
+     * - The socket can be closed, and any ongoing connects should stop.
+     */
     virtual void dispose() = 0;
 
-protected:
+   protected:
     AsyncSocketEventListener* mListener = nullptr;
 };
 
+/**
+ * @brief A simplified wrapper for `AsyncSocketAdapter` that provides
+ *        easy-to-use callbacks for handling read and close events.
+ *        This makes the underlying implementations (RtcSocket/AsyncSocket)
+ *        easier to use.
+ *
+ * This class handles incoming socket connections and provides a convenient
+ * interface for receiving and sending data and handling socket closures.
+ */
+class SimpleAsyncSocket : public AsyncSocketEventListener {
+   public:
+    /**
+     * @brief Callback type for handling received data.
+     *
+     * @param data The received data as a `std::string_view`. Note that this
+     *             `std::string_view` will become invalid upon return from this
+     *             callback. If you need to store the data for later use, you
+     *             must copy it.
+     */
+    using OnReadCallback = std::function<void(std::string_view)>;
+
+    /**
+     * @brief Callback type for handling socket closures.
+     */
+    using OnCloseCallback = std::function<void()>;
+
+    /**
+     * @brief Constructs a `SimpleAsyncSocket`.
+     *
+     * @param socket The underlying `AsyncSocketAdapter` to wrap.
+     * @param onRead The callback to invoke when data is received.
+     * @param onClose The callback to invoke when the socket is closed.
+     */
+    SimpleAsyncSocket(AsyncSocketAdapter* socket, OnReadCallback onRead, OnCloseCallback onClose)
+        : mSocket(std::move(socket)), mOnRead(std::move(onRead)), mOnClose(std::move(onClose)) {
+        mSocket->setSocketEventListener(this);
+    }
+
+    virtual ~SimpleAsyncSocket() = default;
+
+    /**
+     * @brief Implementation of `AsyncSocketEventListener::onRead`.
+     *
+     * This method is called when data is available to be read from the socket.
+     * It reads data in chunks and invokes the `onRead` callback for each chunk.
+     *
+     * @param socket The `AsyncSocketAdapter` that has data available for reading.
+     */
+    void onRead(AsyncSocketAdapter* socket) override {
+        // See https://www.evanjones.ca/read-write-buffer-size.html
+        constexpr int buffer_size = 32 * 1024;
+        char buffer[buffer_size];
+        do {
+            int bytes = mSocket->recv(buffer, sizeof(buffer));
+            if (bytes <= 0) {
+                break;
+            }
+            mOnRead(std::string_view(buffer, bytes));
+        } while (true);
+    };
+
+    void onClose(AsyncSocketAdapter* socket, int err) override { mOnClose(); };
+    void onConnected(AsyncSocketAdapter* socket) override {}
+
+    /**
+     * @brief Sends data over the socket.
+     *
+     * @param buffer The buffer containing the data to send.
+     * @param bufferSize The size of the data to send.
+     * @return The number of bytes sent, or -1 if an error occurred.
+     */
+    ssize_t send(const char* buffer, uint64_t bufferSize) {
+        return mSocket->send(buffer, bufferSize);
+    }
+
+    /**
+     * @brief Closes the socket.
+     */
+    void close() { mSocket->close(); }
+
+    /**
+     * @brief Disposes the socket.
+     */
+    void dispose() { mSocket->dispose(); }
+
+   protected:
+    AsyncSocketAdapter* mSocket;  ///< The underlying socket.
+    OnReadCallback mOnRead;       ///< Callback for handling received data.
+    OnCloseCallback mOnClose;     ///< Callback for handling socket closures.
+};
 }  // namespace base
-}  // namespace android
+}  // namespace android
\ No newline at end of file
diff --git a/base/include/aemu/base/async/DefaultLooper.h b/base/include/aemu/base/async/DefaultLooper.h
index 7a3af86..30b4077 100644
--- a/base/include/aemu/base/async/DefaultLooper.h
+++ b/base/include/aemu/base/async/DefaultLooper.h
@@ -14,14 +14,15 @@
 
 #pragma once
 
-#include <list>                         // for list<>::iterator, list
-#include <memory>                       // for unique_ptr
-#include <mutex>                        // for mutex
+#include <list>
+#include <memory>
+#include <mutex>
 #include <string_view>
-#include <unordered_map>                // for unordered_map
-#include <unordered_set>                // for unordered_set
+#include <thread>
+#include <unordered_map>
+#include <unordered_set>
 
-#include "aemu/base/async/Looper.h"  // for Looper::ClockType, Looper
+#include "aemu/base/async/Looper.h"
 
 namespace android {
 namespace base {
@@ -38,6 +39,11 @@ public:
 
     std::string_view name() const override { return "Generic"; }
 
+    bool onLooperThread() const override {
+        static thread_local std::thread::id thread_id = std::this_thread::get_id();
+        return mThreadId == thread_id;
+    }
+
     Duration nowMs(ClockType clockType = ClockType::kHost) override;
 
     DurationNs nowNs(ClockType clockType = ClockType::kHost) override;
@@ -201,6 +207,7 @@ protected:
     std::mutex mScheduledTasksAccess;
 
     bool mForcedExit = false;
+    std::thread::id mThreadId;
 };
 
 }  // namespace base
diff --git a/base/include/aemu/base/async/Looper.h b/base/include/aemu/base/async/Looper.h
index b340506..7bea7ac 100644
--- a/base/include/aemu/base/async/Looper.h
+++ b/base/include/aemu/base/async/Looper.h
@@ -65,6 +65,9 @@ public:
     // Return the current looper's name - useful for logging.
     virtual std::string_view name() const = 0;
 
+    // True if the current thread is a looper thread.
+    virtual bool onLooperThread() const = 0;
+
     // Return the current time as seen by this looper instance in
     // milliseconds and nanoseconds.
     virtual Duration nowMs(ClockType clockType = ClockType::kHost) = 0;
diff --git a/base/include/aemu/base/async/RecurrentTask.h b/base/include/aemu/base/async/RecurrentTask.h
index 23e7c29..d340c1e 100644
--- a/base/include/aemu/base/async/RecurrentTask.h
+++ b/base/include/aemu/base/async/RecurrentTask.h
@@ -11,149 +11,227 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-
 #pragma once
-
-#include "aemu/base/async/Looper.h"
-#include "aemu/base/Compiler.h"
-#include "aemu/base/synchronization/ConditionVariable.h"
-#include "aemu/base/synchronization/Lock.h"
-#include "aemu/base/memory/ScopedPtr.h"
-
+#include <chrono>
 #include <functional>
 #include <memory>
+#include <mutex>
+
+#include "aemu/base/async/Looper.h"
 
 namespace android {
 namespace base {
 
-// A RecurrentTask is an object that allows you to run a task repeatedly on the
-// event loop, until you're done.
-// Example:
-//
-//     class AreWeThereYet {
-//     public:
-//         AreWeThereYet(Looper* looper) :
-//                 mAskRepeatedly(looper,
-//                                [this]() { return askAgain(); },
-//                                1 * 60 * 1000) {}
-//
-//         bool askAgain() {
-//             std::cout << "Are we there yet?" << std::endl;
-//             return rand() % 2;
-//         }
-//
-//         void startHike() {
-//             mAskRepeatedly.start();
-//         }
-//
-//     private:
-//         RecurrentTask mAskRepeatedly;
-//     };
-//
-// Note: RecurrentTask is meant to execute a task __on the looper thread__.
-// It is thread safe though.
+/**
+ * @class RecurrentTask
+ * @brief A class to run a recurring task on a Looper event loop.
+ *
+ * The RecurrentTask allows scheduling a task that will run repeatedly
+ * at a defined interval on the event loop. The task will continue running
+ * until it is explicitly stopped.
+ */
 class RecurrentTask {
-public:
+   public:
+    /**
+     * @typedef TaskFunction
+     * @brief Defines the function type for the task to be run.
+     *
+     * The function returns a boolean indicating whether the task
+     * should be run again (`true`) or not (`false`).
+     */
     using TaskFunction = std::function<bool()>;
 
-    RecurrentTask(Looper* looper,
-                  TaskFunction function,
-                  Looper::Duration taskIntervalMs)
+    /**
+     * @brief Constructor to initialize a RecurrentTask.
+     *
+     * @param looper The Looper on which the task will be scheduled.
+     * @param function The task function that returns a boolean indicating
+     *                 whether the task should repeat.
+     * @param taskIntervalMs The interval (in milliseconds) between task executions.
+     */
+    RecurrentTask(Looper* looper, TaskFunction function, Looper::Duration taskIntervalMs)
         : mLooper(looper),
-          mFunction(function),
-          mTaskIntervalMs(int(taskIntervalMs)),
-          mTimer(mLooper->createTimer(&RecurrentTask::taskCallback, this)) {}
+          mFunction(std::move(function)),
+          mTaskIntervalMs(static_cast<int>(taskIntervalMs)),
+          mTimer(mLooper->createTimer(&RecurrentTask::taskCallbackStatic, this)) {}
+
+    /**
+     * @brief Constructor to initialize a RecurrentTask.
+     *
+     * @param looper The Looper on which the task will be scheduled.
+     * @param function The task function that returns a boolean indicating
+     *                 whether the task should repeat.
+     * @param interval The interval (in milliseconds) between task executions.
+     */
+    RecurrentTask(Looper* looper, TaskFunction function, std::chrono::milliseconds interval)
+        : RecurrentTask(looper, function, interval.count()) {}
 
     ~RecurrentTask() { stopAndWait(); }
 
+    /**
+     * @brief Starts the task, scheduling it on the looper.
+     *
+     * @param runImmediately If true, runs the task immediately; otherwise, it waits
+     *                       for the task interval before running.
+     */
     void start(bool runImmediately = false) {
-        {
-            AutoLock lock(mLock);
-            mInFlight = true;
-        }
-        mTimer->startRelative(runImmediately ? 0 : mTaskIntervalMs);
+        start(runImmediately ? std::chrono::milliseconds(0)
+                             : std::chrono::milliseconds(mTaskIntervalMs));
     }
 
-    void stopAsync() {
-        mTimer->stop();
+    /**
+     * @brief Starts the task, scheduling it on the looper after an initial delay.
+     *
+     * @param initialDelay The delay (in milliseconds) before the first execution of the task.
+     */
+    void start(std::chrono::milliseconds initialDelay) {
+        std::lock_guard<std::mutex> lock(mMutex);
+        mInFlight = true;
+        mTimer->startRelative(initialDelay.count());
+    }
 
-        AutoLock lock(mLock);
+    /**
+     * @brief Stops the task asynchronously.
+     *
+     * This function stops the timer and prevents any further task execution.
+     * The function will not wait for a currently running task to complete.
+     */
+    void stopAsync() {
+        std::lock_guard<std::mutex> lock(mMutex);
         mInFlight = false;
+        mTimer->stop();
     }
 
+    /**
+     * @brief Stops the task and waits for any ongoing task to finish.
+     *
+     * Ensures that any currently running task completes before stopping the recurrent task.
+     */
     void stopAndWait() {
-        mTimer->stop();
-
-        AutoLock lock(mLock);
-        mInFlight = false;
-
-        // Make sure we wait for the pending task to complete if it was running.
-        while (mInTimerCallback) {
-            mInTimerCondition.wait(&lock);
-        }
+        // To implement this properly we need Looper::Timer::stopAndWait.
+        stopAsync();
     }
 
+    /**
+     * @brief Checks if the task is currently in flight (scheduled or running).
+     *
+     * @return true if the task is scheduled or running, false otherwise.
+     */
     bool inFlight() const {
-        AutoLock lock(mLock);
+        std::lock_guard<std::mutex> lock(mMutex);
         return mInFlight;
     }
 
-    void waitUntilRunning() {
-        AutoLock lock(mLock);
-        while (mInFlight && !mInTimerCallback) {
-            mInTimerCondition.wait(&lock);
-        }
-    }
-
+    /**
+     * @brief Gets the task execution interval in milliseconds.
+     *
+     * @return The interval (in milliseconds) between task executions.
+     */
     Looper::Duration taskIntervalMs() const { return mTaskIntervalMs; }
 
-protected:
-    static void taskCallback(void* opaqueThis, Looper::Timer* timer) {
-        const auto self = static_cast<RecurrentTask*>(opaqueThis);
-        AutoLock lock(self->mLock);
-        self->mInTimerCallback = true;
-        const bool inFlight = self->mInFlight;
-        self->mInTimerCondition.broadcastAndUnlock(&lock);
-
-        const auto undoInTimerCallback =
-                makeCustomScopedPtr(self, [&lock](RecurrentTask* self) {
-                    if (!lock.isLocked()) {
-                        lock.lock();
-                    }
-                    self->mInTimerCallback = false;
-                    self->mInTimerCondition.broadcastAndUnlock(&lock);
-                });
-
-        if (!inFlight) {
-            return;
-        }
-
-        const bool callbackResult = self->mFunction();
+    /**
+     * @brief Gets the task execution interval
+     *
+     * @return The interval (in milliseconds) between task executions.
+     */
+    std::chrono::milliseconds interval() const {
+        return std::chrono::milliseconds(mTaskIntervalMs);
+    }
 
-        lock.lock();
-        if (!callbackResult) {
-            self->mInFlight = false;
-            return;
+   private:
+    void taskCallback(Looper::Timer* /*timer*/) {
+        if (inFlight()) {
+            if (mFunction()) {
+                std::lock_guard<std::mutex> lock(mMutex);
+                if (mInFlight) {
+                    mTimer->startRelative(mTaskIntervalMs);
+                }
+            } else {
+                std::lock_guard<std::mutex> lock(mMutex);
+                mInFlight = false;
+            }
         }
-        // It is possible that the client code in |mFunction| calls |stop|, so
-        // we must double check before reposting the task.
-        if (!self->mInFlight) {
-            return;
-        }
-        lock.unlock();
-        self->mTimer->startRelative(self->mTaskIntervalMs);
     }
 
-private:
+    static void taskCallbackStatic(void* that, Looper::Timer* timer) {
+        static_cast<RecurrentTask*>(that)->taskCallback(timer);
+    }
+
+   protected:
     Looper* const mLooper;
     const TaskFunction mFunction;
     const int mTaskIntervalMs;
-    bool mInTimerCallback = false;
     bool mInFlight = false;
     const std::unique_ptr<Looper::Timer> mTimer;
+    mutable std::mutex mMutex;
+};
+
+/**
+ * @class SimpleRecurrentTask
+ * @brief A simple scheduler that automatically deletes itself
+ *        when the task function returns false, indicating completion.
+ *
+ * This class is used to repeatedly schedule tasks on the looper thread
+ * and delete itself once the task is done (i.e., when the task function
+ * returns false).
+ */
+class SimpleRecurrentTask {
+   public:
+    /**
+     * @brief Schedules a task that runs on the given interval until the
+     *        task function returns false.
+     *
+     * The function creates a new instance of SimpleRecurrentTask, which starts
+     * after the initial delay and automatically deletes itself when the task is done.
+     *
+     * @param looper The event loop on which to schedule the task.
+     * @param function The task function to be executed. Should return `true`
+     *        to continue scheduling the task or `false` to stop and delete
+     *        the task.
+     * @param interval The interval between successive executions of the task.
+     * @param initialDelay The delay before the first execution.
+     *
+     * @note The task will keep running until the provided task function
+     *       returns false.
+     * @note This can leak a SimpleRecurrentTask object if the looper is deleted
+     *       when the task is still scheduled.
+     *
+     * Example usage:
+     * @code
+     * SimpleRecurrentTask::schedule(looper, []() {
+     *     std::cout << "Task executed!" << std::endl;
+     *     return someConditionMet;  // Return false to stop the task
+     * }, std::chrono::milliseconds(1000));  // Run every 1 second
+     * @endcode
+     */
+    static void schedule(Looper* looper, RecurrentTask::TaskFunction function,
+                         std::chrono::milliseconds interval,
+                         std::chrono::milliseconds initialDelay = std::chrono::milliseconds(0)) {
+        new SimpleRecurrentTask(looper, function, interval, initialDelay);
+    }
+
+   private:
+    SimpleRecurrentTask(Looper* looper, RecurrentTask::TaskFunction function,
+                        std::chrono::milliseconds interval, std::chrono::milliseconds initialDelay)
+        : mTimer(looper->createTimer(&SimpleRecurrentTask::taskCallback, this)),
+          mTaskInterval(interval),
+          mFunction(std::move(function)) {
+        mTimer->startRelative(initialDelay.count());
+    }
 
-    mutable Lock mLock;
-    ConditionVariable mInTimerCondition;
+    static void taskCallback(void* opaqueThis, Looper::Timer* /*timer*/) {
+        // Note that timer == mTimer
+        auto self = static_cast<SimpleRecurrentTask*>(opaqueThis);
+        if (self->mFunction()) {
+            self->mTimer->startRelative(self->mTaskInterval.count());
+        } else {
+            delete self;
+        }
+    }
+
+    const std::unique_ptr<Looper::Timer> mTimer;
+    const std::chrono::milliseconds mTaskInterval;
+    const RecurrentTask::TaskFunction mFunction;
 };
 
 }  // namespace base
diff --git a/base/include/aemu/base/msvc.h b/base/include/aemu/base/msvc.h
index 1bdc82b..1e3176d 100644
--- a/base/include/aemu/base/msvc.h
+++ b/base/include/aemu/base/msvc.h
@@ -14,6 +14,7 @@
 
 #pragma once
 
+#ifndef _AEMU_BITS_SOCKET_H_
 #ifndef __linux__
 #ifndef __QNX__
 // Make sure these are defined and don't change anything if used.
@@ -23,122 +24,43 @@ enum {
     O_CLOEXEC = 0
 #endif
 };
+#define _AEMU_BITS_SOCKET_H_
 #endif  // !__QNX__
 #endif  // !__linux__
+#endif
 
 #ifdef _MSC_VER
 
 #include <windows.h>
-#include <BaseTsd.h>
 
-#include <direct.h>
-#include <fcntl.h>
 #include <io.h>
-#include <process.h>
 #include <stdint.h>
-#include <sys/stat.h>
-#include <time.h>
-#include <winsock2.h>
-
-typedef SSIZE_T ssize_t;
-
-typedef int mode_t;
-#ifdef _WIN64
-typedef int64_t pid_t;
-#else
-typedef int pid_t;
-#endif
-#define STDIN_FILENO _fileno(stdin)
-#define STDOUT_FILENO _fileno(stdout)
-#define STDERR_FILENO _fileno(stderr)
-#define lseek(a, b, c) _lseek(a, b, c)
-#define lseek64 _lseeki64
 
-typedef struct FileTime {
-  uint32_t dwLowDateTime;
-  uint32_t dwHighDateTime;
-} FileTime;
+#include "sys/cdefs.h"
 
-// Need <dirent.h>
+__BEGIN_DECLS
 
-// Define for convenience only in mingw. This is
-// convenient for the _access function in Windows.
-#define F_OK 0 /* Check for file existence */
-#define X_OK 1 /* Check for execute permission (not supported in Windows) */
-#define W_OK 2 /* Check for write permission */
-#define R_OK 4 /* Check for read permission */
+#include <fcntl.h>
+#include <limits.h>
+#include <stdlib.h>
+#include <strings.h>
+#include <sys/cdefs.h>
+#include <sys/stat.h>
+#include <sys/time.h>
+#include <sys/types.h>
+#include <unistd.h>
 
-typedef int mode_t;
-#ifdef _WIN64
-typedef int64_t pid_t;
-#else
-typedef int pid_t;
+#ifndef fseeko
+#define fseeko _fseeki64
 #endif
-#define STDIN_FILENO _fileno(stdin)
-#define STDOUT_FILENO _fileno(stdout)
-#define STDERR_FILENO _fileno(stderr)
-#define lseek(a, b, c) _lseek(a, b, c)
-#define lseek64 _lseeki64
-
-// These functions were deprecated and replaced with ISO C++ conformant ones
-// in MSVC 2017.
-/*
-#define strdup _strdup
-#define mkdir _mkdir
-#define rmdir _rmdir
-#define getcwd _getcwd
-#define getpid _getpid
-#define close _close
-#define open _open
-#define read _read
-#define write _write
-#define creat _creat
-*/
-
-// From <fcntl.h>
-#define O_ACCMODE (O_RDONLY | O_WRONLY | O_RDWR)
-
-// From <sys/types.h>
-typedef int64_t off64_t;
 
-// From <sys/cdefs.h>
-#ifdef __cplusplus
-#define __BEGIN_DECLS extern "C" {
-#define __END_DECLS }
-#else
-#define __BEGIN_DECLS /* empty */
-#define __END_DECLS   /* empty */
+#ifndef ftello
+#define ftello _ftelli64
 #endif
 
-
-typedef  void (*SystemTime)(FileTime*);
-
-// From <sys/time.h>
-struct timezone {
-    int tz_minuteswest; /* of Greenwich */
-    int tz_dsttime;     /* type of dst correction to apply */
-};
-
-// From <strings.h>
-#define strcasecmp _stricmp
-#define strncasecmp _strnicmp
-
-// From <stdio.h>
-#define fseeko64 _fseeki64
-#define ftello64 _ftelli64
-
-// From <linux/limits.h>
-#define PATH_MAX MAX_PATH
-
-__BEGIN_DECLS
-
-
-extern SystemTime getSystemTime;
-extern int gettimeofday(struct timeval* tp, struct timezone* tz);
 extern int asprintf(char** buf, const char* format, ...);
 extern int vasprintf(char** buf, const char* format, va_list args);
-extern int mkstemp(char* t);
 
 __END_DECLS
 
-#endif
+#endif
\ No newline at end of file
diff --git a/base/include/aemu/base/process/Command.h b/base/include/aemu/base/process/Command.h
index 9014336..c139054 100644
--- a/base/include/aemu/base/process/Command.h
+++ b/base/include/aemu/base/process/Command.h
@@ -37,57 +37,124 @@ using android::base::streams::RingStreambuf;
 using BufferDefinition = std::pair<size_t, std::chrono::milliseconds>;
 using CommandArguments = std::vector<std::string>;
 
-// A Command that you can execute and observe.
+/**
+ * @brief A Command that you can execute and observe.
+ */
 class Command {
 public:
+    /**
+     * @brief Alias for a function that creates ObservableProcess instances.
+     */
     using ProcessFactory =
             std::function<std::unique_ptr<ObservableProcess>(CommandArguments, bool, bool)>;
 
-    // Run the command with a std out buffer that can hold at most n bytes.
-    // If the buffer is filled, the process will block for at most w ms before
-    // timing out. Timeouts can result in data loss or stream closure.
-    //
-    // The default timeout is a year.
+    /**
+     * @brief Sets the standard output buffer size and timeout.
+     *
+     * If the buffer is filled, the process will block for at most |w|
+     * milliseconds before timing out. Timeouts can result in data loss or
+     * stream closure.
+     *
+     * @param n The maximum number of bytes to buffer for standard output.
+     * @param w The maximum time to wait for buffer space, defaults to one year.
+     * @return A reference to this Command object for chaining.
+     */
     Command& withStdoutBuffer(
             size_t n,
             std::chrono::milliseconds w = std::chrono::hours(24 * 365));
 
-    // Run the command with a std err buffer that can hold at most n bytes.
-    // If the buffer is filled, the process will block for at most w ms before
-    // timing out. Timeouts can result in data loss or stream closure.
-    //
-    // The default timeout is a year.
+    /**
+     * @brief Sets the standard error buffer size and timeout.
+     *
+     * If the buffer is filled, the process will block for at most |w|
+     * milliseconds before timing out. Timeouts can result in data loss or
+     * stream closure.
+     *
+     * @param n The maximum number of bytes to buffer for standard error.
+     * @param w The maximum time to wait for buffer space, defaults to one year.
+     * @return A reference to this Command object for chaining.
+     */
     Command& withStderrBuffer(
             size_t n,
             std::chrono::milliseconds w = std::chrono::hours(24 * 365));
 
-    // Adds a single argument to the list of arguments.
+    /**
+     * @brief Adds a single argument to the list of arguments.
+     *
+     * @param arg The argument to add.
+     * @return A reference to this Command object for chaining.
+     */
     Command& arg(const std::string& arg);
 
-    // Adds a list of arguments to the existing arguments
+    /**
+     * @brief Adds a list of arguments to the existing arguments.
+     *
+     * @param args The arguments to add.
+     * @return A reference to this Command object for chaining.
+     */
     Command& args(const CommandArguments& args);
 
-    // Launch the command as a deamon, you will not be able
-    // to read stderr/stdout, the process will not bet terminated
-    // when the created process goes out of scope.
+    /**
+     * @brief Launches the command as a daemon.
+     *
+     * You will not be able to read stderr/stdout, and the process will not be
+     * terminated when the created process goes out of scope.
+     *
+     * @return A reference to this Command object for chaining.
+     */
     Command& asDeamon();
 
-    // Call this if you wish to inherit all the file handles
+    /**
+     * @brief Sets the command to inherit all file handles.
+     *
+     * @return A reference to this Command object for chaining.
+     */
     Command& inherit();
 
-    // Launch the process
+    /**
+     * @brief Sets the command to replace the current process.
+     *
+     * This behaves similarly to execv.
+     *
+     * @return A reference to this Command object for chaining.
+     */
+    Command& replace();
+
+    /**
+     * @brief Launches the process.
+     *
+     * @return A unique pointer to the ObservableProcess representing the
+     *         launched process.
+     */
     std::unique_ptr<ObservableProcess> execute();
 
-    // Create a new process
+    /**
+     * @brief Creates a new Command object.
+     *
+     * @param programWithArgs The program to execute, along with its arguments.
+     * @return A Command object representing the command to execute.
+     */
     static Command create(CommandArguments programWithArgs);
 
-    // You likely only want to use this for testing..
-    // Implement your own factory that produces an implemented process.
-    // Make sure to set to nullptr when you want to revert to default.
+    /**
+     * @brief Sets a custom ProcessFactory for testing.
+     *
+     * You likely only want to use this for testing. Implement your own factory
+     * that produces an implemented process. Make sure to set to nullptr when
+     * you want to revert to the default.
+     *
+     * @param factory The custom ProcessFactory to use.
+     */
     static void setTestProcessFactory(ProcessFactory factory);
 
 protected:
     Command() = default;
+
+    /**
+     * @brief Constructor with initial command arguments.
+     *
+     * @param args The initial command arguments.
+     */
     Command(CommandArguments args) : mArgs(args){};
 
 private:
@@ -98,8 +165,9 @@ private:
     bool mDeamon{false};
     bool mCaptureOutput{false};
     bool mInherit{false};
+    bool mReplace{false};
     BufferDefinition mStdout{0, 0};
     BufferDefinition mStderr{0, 0};
 };
 }  // namespace base
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/base/include/aemu/base/process/Process.h b/base/include/aemu/base/process/Process.h
index b3f60c6..ce928b1 100644
--- a/base/include/aemu/base/process/Process.h
+++ b/base/include/aemu/base/process/Process.h
@@ -39,40 +39,73 @@ using CommandArguments = std::vector<std::string>;
 using Pid = int;
 using ProcessExitCode = int;
 
-// A process in that is running in the os.
+/**
+ * Represents a process running within the operating system.
+ */
 class Process {
 public:
-    virtual ~Process(){};
+    virtual ~Process() = default;
 
-    // pid of the process, or -1 if it is invalid
+    /**
+     * @return The process ID (PID) of the process, or -1 if invalid.
+     */
     Pid pid() const { return mPid; };
 
-    // Name of the process, note this might not be
-    // immediately availabl.
+    /**
+     * @return The name of the process executable. Note that this information
+     *         might not be immediately available, especially shortly after
+     *         the process has been started.
+     */
     virtual std::string exe() const = 0;
 
-    // The exit code of the process, this will block
-    // and wait until the process has finished or is detached.
-    //
-    // This can return INT_MIN in case of failures.
+    /**
+     * Retrieves the exit code of the process. This method will block until
+     * the process has finished or is detached.
+     *
+     * @return The process exit code. This can return INT_MIN in case of
+     *         failures retrieving the exit code.
+     */
     ProcessExitCode exitCode() const;
 
-    // Unconditionally cause the process to exit. (Kill -9 ..)
-    // Returns true if the process was terminated, false in case of failure.
+    /**
+     * Forcibly terminates the process (similar to sending SIGKILL).
+     *
+     * @return True if the process was successfully terminated, false otherwise.
+     */
     virtual bool terminate() = 0;
 
-    // True if the pid is alive according to the os.
+    /**
+     * Checks if the process is currently alive according to the operating
+     * system.
+     *
+     * @return True if the process is alive, false otherwise.
+     */
     virtual bool isAlive() const = 0;
 
-    // Waits for process completion, returns if it is not finished for the
-    // specified timeout duration
+    /**
+     * Waits for the process to complete, or until the specified timeout
+     * duration has elapsed.
+     *
+     * @param timeout_duration The maximum duration to wait for process
+     *        completion.
+     * @return A std::future_status value indicating whether the wait
+     *         completed due to process termination or timeout.
+     */
     virtual std::future_status wait_for(
             const std::chrono::milliseconds timeout_duration) const {
         return wait_for_kernel(timeout_duration);
     }
 
-    // Waits for process completion, returns if it is not finished until
-    // specified time point has been reached
+    /**
+     * Waits for the process to complete, or until the specified time point
+     * has been reached.
+     *
+     * @tparam Clock The clock type used for the timeout.
+     * @tparam Duration The duration type used for the timeout.
+     * @param timeout_time The time point at which the wait should timeout.
+     * @return A std::future_status value indicating whether the wait
+     *         completed due to process termination or timeout.
+     */
     template <class Clock, class Duration>
     std::future_status wait_until(
             const std::chrono::time_point<Clock, Duration>& timeout_time)
@@ -83,109 +116,204 @@ public:
     bool operator==(const Process& rhs) const { return (mPid == rhs.mPid); }
     bool operator!=(const Process& rhs) const { return !operator==(rhs); }
 
-    // Retrieve the object from the given pid id.
+    /**
+     * Retrieves a Process object representing the process with the given PID.
+     *
+     * @param pid The process ID (PID) to search for.
+     * @return A unique pointer to a Process object representing the process,
+     *         or nullptr if no such process exists.
+     */
     static std::unique_ptr<Process> fromPid(Pid pid);
 
-    // Retrieve process with "name" in the process.
+    /**
+     * Retrieves a list of Process objects representing processes whose
+     * executable name contains the specified name substring.
+     *
+     * Note: There might be a delay between the creation of a process and its
+     * appearance in the process list. This delay can vary depending on the
+     * operating system and system load.
+     *
+     * @param name The name substring to search for in process names.
+     * @return A vector of unique pointers to Process objects representing the
+     *         matching processes. If no matching processes are found, the
+     *         vector will be empty.
+     */
     static std::vector<std::unique_ptr<Process>> fromName(std::string name);
 
-    // Retrieve myself.
+    /**
+     * @return A unique pointer to a Process object representing the current
+     *         process.
+     */
     static std::unique_ptr<Process> me();
 
 protected:
-    // Return the exit code of the process, this should not block
+    /**
+     * Retrieves the exit code of the process without blocking.
+     *
+     * @return An optional containing the process exit code if available,
+     *         or std::nullopt if the process is still running or the exit
+     *         code cannot be retrieved.
+     */
     virtual std::optional<ProcessExitCode> getExitCode() const = 0;
 
-    // Wait until this process is finished, by using an os level
-    // call.
+    /**
+     * Waits for the process to complete using an operating system-level call,
+     * without using any additional polling mechanisms.
+     *
+     * @param timeout_duration The maximum duration to wait for process
+     *        completion.
+     * @return A std::future_status value indicating whether the wait
+     *         completed due to process termination or timeout.
+     */
     virtual std::future_status wait_for_kernel(
             const std::chrono::milliseconds timeout_duration) const = 0;
 
     Pid mPid;
 };
 
-// Output of the process.
+/**
+ * Represents the output (stdout and stderr) of a process.
+ */
 class ProcessOutput {
 public:
     virtual ~ProcessOutput() = default;
 
-    // Consumes the whole stream, and returns a string.
+    /**
+     * Consumes the entire output stream and returns it as a string.
+     *
+     * @return The entire process output as a string.
+     */
     virtual std::string asString() = 0;
 
-    // Returns a stream, that will block until data
-    // from the child is available.
+    /**
+     * Provides access to the output stream, which can be used to read the
+     * process output incrementally. This method may block until data is
+     * available from the child process.
+     *
+     * @return A reference to the output stream.
+     */
     virtual std::istream& asStream() = 0;
 };
 
-// A process overseer is responsible for observering the process:
-// It is  watching writes to std_err & std_out and passes them
-// on to a RingStreambuf
+/**
+ * The ProcessOverseer class is responsible for monitoring a child process
+ * and capturing its output (stdout and stderr).
+ */
 class ProcessOverseer {
 public:
     virtual ~ProcessOverseer() = default;
 
-    // Start observering the process.
-    //
-    // The overseer should:
-    //  - Write to std_out & std_err when needed.
-    //  - Close the RingStreambuf when done with the stream.
-    //  - Return when it can no longer read/write from stdout/stderr
+    /**
+     * Starts monitoring the child process and capturing its output.
+     *
+     * The overseer should:
+     * - Write captured output to the provided `out` and `err`
+     *   RingStreambuf objects.
+     * - Close the RingStreambuf objects when the corresponding output streams
+     *   are closed by the child process.
+     * - Return from this method when it can no longer read or write from the
+     *   child process's stdout and stderr.
+     *
+     * @param out The RingStreambuf object to write captured stdout output to.
+     * @param err The RingStreambuf object to write captured stderr output to.
+     */
     virtual void start(RingStreambuf* out, RingStreambuf* err) = 0;
 
-    // Cancel the observation of the process if observation is still happening.
-    // Basically this is used to detach from a running process.
-    //
-    // After return:
-    //  - no writes to std_out, std_err should happen
-    //  - all resource should be cleaned up.
-    //  - a call to the start method should return with std::nullopt
+    /**
+     * Stops monitoring the child process and releases any resources held by
+     * the overseer.
+     *
+     * After this method returns:
+     * - No further writes should be made to the `out` and `err`
+     *   RingStreambuf objects.
+     * - All resources associated with the overseer should be released.
+     * - Calling the `start` method again should result in an error or return
+     *   immediately.
+     */
     virtual void stop() = 0;
 };
 
-// A overseer that does nothing.
-// Use this for detached processes, testing.
+/**
+ * A ProcessOverseer implementation that does nothing. This can be used for
+ * detached processes or in testing scenarios where process output monitoring
+ * is not required.
+ */
 class NullOverseer : public ProcessOverseer {
 public:
     virtual void start(RingStreambuf* out, RingStreambuf* err) override {}
     virtual void stop() override {}
 };
 
-// A running process that you can interact with.
-//
-// You obtain a process by running a command.
-// For example:
-//
-// auto p = Command::create({"ls"}).execute();
-// if (p->exitCode() == 0) {
-//      auto list = p->out()->asString();
-// }
+/**
+ * Represents a running process that can be interacted with, such as reading
+ * its output or terminating it.
+ *
+ * You typically obtain an ObservableProcess object by executing a Command.
+ *
+ * Example:
+ * ```cpp
+ * auto p = Command::create({"ls"}).execute();
+ * if (p->exitCode() == 0) {
+ *     auto list = p->out()->asString();
+ * }
+ * ```
+ */
 class ObservableProcess : public Process {
 public:
     // Kills the process..
     virtual ~ObservableProcess();
 
-    // stdout from the child if not detached.
+    /**
+     * @return A pointer to the ProcessOutput object representing the child
+     *         process's standard output (stdout), or nullptr if the process
+     *         was started in detached mode.
+     */
     ProcessOutput* out() { return mStdOut.get(); };
 
-    // stderr from the child if not detached.
+    /**
+     * @return A pointer to the ProcessOutput object representing the child
+     *         process's standard error (stderr), or nullptr if the process
+     *         was started in detached mode.
+     */
     ProcessOutput* err() { return mStdErr.get(); };
 
-    // Detach the process overseer, and stop observing the process
-    // you will:
-    //  - Not able to read stdout/stderr
-    //  - The process will not be terminated when going out of scope.
+    /**
+     * Detaches the process overseer, stopping the monitoring of the child
+     * process's output and preventing the process from being automatically
+     * terminated when the ObservableProcess object goes out of scope.
+     *
+     * After calling this method:
+     * - You will no longer be able to read the child process's stdout and
+     *   stderr.
+     * - The child process will continue running even after the
+     *   ObservableProcess object is destroyed.
+     */
     void detach();
 
     std::future_status wait_for(
             const std::chrono::milliseconds timeout_duration) const override;
 
 protected:
-    // Subclasses should implement this to actually launch the process,
-    // return std::nullopt in case of failure
+    /**
+     * Subclasses should implement this method to handle the actual process
+     * creation and launch.
+     *
+     * @param args The command line arguments to pass to the child process.
+     * @param captureOutput Whether to capture the child process's output
+     *        (stdout and stderr).
+     * @return An optional containing the PID of the newly created process if
+     *         successful, or std::nullopt if process creation failed.
+     */
     virtual std::optional<Pid> createProcess(const CommandArguments& args,
-                                             bool captureOutput) = 0;
-
-    // Create the overseer used to observe the process state.
+                                             bool captureOutput,
+                                             bool replace) = 0;
+
+    /**
+     * Creates the ProcessOverseer object responsible for monitoring the child
+     * process and capturing its output.
+     *
+     * @return A unique pointer to the created ProcessOverseer object.
+     */
     virtual std::unique_ptr<ProcessOverseer> createOverseer() = 0;
 
     // True if no overseer is needed
diff --git a/base/include/aemu/base/synchronization/Lock.h b/base/include/aemu/base/synchronization/Lock.h
index 281a970..48595fc 100644
--- a/base/include/aemu/base/synchronization/Lock.h
+++ b/base/include/aemu/base/synchronization/Lock.h
@@ -155,8 +155,6 @@ public:
         mLocked = false;
     }
 
-    bool isLocked() const { return mLocked; }
-
     ~AutoLock() RELEASE() {
         if (mLocked) {
             mLock.unlock();
@@ -239,8 +237,6 @@ static inline __attribute__((always_inline)) void SmpWmb() {
         std::atomic_thread_fence(std::memory_order_release);
 #elif defined(__riscv) && (__riscv_xlen == 64)
         std::atomic_thread_fence(std::memory_order_release);
-#else
-#error "Unimplemented SmpWmb for current CPU architecture"
 #endif
 }
 
@@ -251,8 +247,6 @@ static inline __attribute__((always_inline)) void SmpRmb() {
         std::atomic_thread_fence(std::memory_order_acquire);
 #elif defined(__riscv) && (__riscv_xlen == 64)
         std::atomic_thread_fence(std::memory_order_acquire);
-#else
-#error "Unimplemented SmpRmb for current CPU architecture"
 #endif
 }
 
diff --git a/base/include/aemu/base/system/System.h b/base/include/aemu/base/system/System.h
index 2d6e5ac..d55b75a 100644
--- a/base/include/aemu/base/system/System.h
+++ b/base/include/aemu/base/system/System.h
@@ -7,7 +7,6 @@ namespace base {
 
 std::string getEnvironmentVariable(const std::string& key);
 void setEnvironmentVariable(const std::string& key, const std::string& value);
-bool isVerboseLogging();
 
 uint64_t getUnixTimeUs();
 uint64_t getHighResTimeUs();
diff --git a/base/msvc.cpp b/base/msvc.cpp
index 2032d10..9df2d3a 100644
--- a/base/msvc.cpp
+++ b/base/msvc.cpp
@@ -25,6 +25,7 @@
 #define FILETIME_1970 116444736000000000ull
 #define HECTONANOSEC_PER_SEC 10000000ull
 
+
 int mkstemp(char* t) {
     // TODO(joshuaduong): Support unicode (b/117322783)
     int len = strlen(t) + 1;
diff --git a/host-common/BUILD.bazel b/host-common/BUILD.bazel
index 08cc1a4..9951ba2 100644
--- a/host-common/BUILD.bazel
+++ b/host-common/BUILD.bazel
@@ -1,6 +1,6 @@
 # Logging library
 cc_library(
-    name = "logging",
+    name = "logging-qemu2",
     srcs = [
         "GfxstreamFatalError.cpp",
         "logging.cpp",
@@ -23,6 +23,32 @@ cc_library(
     ],
 )
 
+cc_library(
+    name = "logging",
+    srcs = [
+        "GfxstreamFatalErrorAbsl.cpp",
+        "logging_absl.cpp",
+    ],
+    hdrs = ["include/host-common/logging.h"],
+    defines = [
+        "BUILDING_EMUGL_COMMON_SHARED",
+    ] + select({
+        "@platforms//os:windows": [
+            "WIN32_LEAN_AND_MEAN",
+        ],
+        "//conditions:default": [],
+    }),
+    includes = ["include/host-common"],
+    visibility = ["//visibility:public"],
+    deps = [
+        ":aemu-host-common-headers",
+        "//hardware/google/aemu/base:aemu-base-headers",
+        "//hardware/google/aemu/base:aemu-base-metrics",
+        "@com_google_absl//absl/log",
+        "@com_google_absl//absl/log:absl_log",
+    ],
+)
+
 cc_library(
     name = "aemu-host-common-headers",
     hdrs = glob([
@@ -105,18 +131,57 @@ cc_library(
     ],
 )
 
+cc_library(
+    name = "aemu-host-common-testing-support",
+    srcs = [
+        "testing/HostAddressSpace.cpp",
+        "testing/MockAndroidEmulatorWindowAgent.cpp",
+        "testing/MockAndroidMultiDisplayAgent.cpp",
+        "testing/MockAndroidVmOperations.cpp",
+        "testing/MockGraphicsAgentFactory.cpp",
+    ],
+    hdrs = [
+        "testing/HostAddressSpace.h",
+        "testing/MockAndroidEmulatorWindowAgent.h",
+        "testing/MockAndroidVmOperations.h",
+        "testing/MockGraphicsAgentFactory.h",
+    ],
+    includes = ["testing"],
+    deps = [
+        ":aemu-host-common-headers",
+        "//hardware/google/aemu/base:aemu-base-headers",
+        "@com_google_googletest//:gtest",
+    ],
+)
+
 # Testing Libraries and Executable (conditional)
 cc_test(
-    name = "aemu-host-common_unittests",
-    srcs = glob([
-        "*_unitests.cpp",
-        "testing/**",
-    ]),
+    name = "aemu-host-logging_unittests",
+    srcs =
+        [
+            # "GfxstreamFatalError_unittest.cpp",
+            # "HostAddressSpace_unittest.cpp",
+            # "HostGoldfishPipe_unittest.cpp",
+            # "HostmemIdMapping_unittest.cpp",
+            # "VmLock_unittest.cpp",
+            "logging_absl_unittest.cpp",
+        ] + glob([
+            "testing/**",
+        ]),
     includes = ["testing"],
     deps = [
         ":aemu-host-common-headers",
         ":logging",
+        "//hardware/google/aemu:aemu-host-common-test-headers",
+        "//hardware/google/aemu/base:aemu-base",
+        "//hardware/google/aemu/base:aemu-base-allocator",
         "//hardware/google/aemu/base:aemu-base-headers",
+        "//hardware/google/aemu/host-common:aemu-host-common",
+        "@com_google_absl//absl/log",
+        "@com_google_absl//absl/log:absl_log",
+        "@com_google_absl//absl/log:globals",
+        "@com_google_absl//absl/log:initialize",
+        "@com_google_absl//absl/log:log_sink_registry",
         "@com_google_googletest//:gtest_main",
     ],
 )
diff --git a/host-common/CMakeLists.txt b/host-common/CMakeLists.txt
index 221d09e..656b24d 100644
--- a/host-common/CMakeLists.txt
+++ b/host-common/CMakeLists.txt
@@ -37,6 +37,12 @@ target_include_directories(
     INTERFACE
     include)
 
+if (MSVC)
+    target_link_libraries(
+        aemu-host-common.headers
+        INTERFACE
+        msvc-posix-compat)
+endif()
 if (BUILD_STANDALONE)
     add_library(
         aemu-host-common
diff --git a/host-common/GfxstreamFatalErrorAbsl.cpp b/host-common/GfxstreamFatalErrorAbsl.cpp
new file mode 100644
index 0000000..6d112e7
--- /dev/null
+++ b/host-common/GfxstreamFatalErrorAbsl.cpp
@@ -0,0 +1,64 @@
+// Copyright 2023 The Android Open Source Project
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
+#include <cstdlib>
+#include <ostream>
+
+#include "absl/log/absl_log.h"
+#include "aemu/base/Metrics.h"
+#include "host-common/GfxstreamFatalError.h"
+#include "host-common/logging.h"
+
+namespace {
+
+using android::base::CreateMetricsLogger;
+using android::base::GfxstreamVkAbort;
+
+std::optional<std::function<void()>> customDieFunction = std::nullopt;
+
+[[noreturn]] void die() {
+    if (customDieFunction) {
+        (*customDieFunction)();
+    }
+    abort();
+}
+
+}  // namespace
+
+namespace emugl {
+
+AbortMessage::AbortMessage(const char* file, const char* function, int line, FatalError reason)
+    : mFile(file), mFunction(function), mLine(line), mReason(reason) {}
+
+AbortMessage::~AbortMessage() {
+    CreateMetricsLogger()->logMetricEvent(GfxstreamVkAbort{.file = mFile,
+                                                           .function = mFunction,
+                                                           .msg = mOss.str().c_str(),
+                                                           .line = mLine,
+                                                           .abort_reason = mReason.getAbortCode()});
+
+    if (customDieFunction) {
+        ABSL_LOG(ERROR).AtLocation(mFile, mLine)
+            << "FATAL error in " << mFunction
+            << ",  GURU MEDITATION ERROR:" << mReason.getAbortCode();
+        die();
+    } else {
+        ABSL_LOG(FATAL).AtLocation(mFile, mLine)
+            << "FATAL error in " << mFunction
+            << ",  GURU MEDITATION ERROR:" << mReason.getAbortCode();
+    }
+}
+
+void setDieFunction(std::optional<std::function<void()>> newDie) { customDieFunction = newDie; }
+}  // namespace emugl
diff --git a/host-common/include/host-common/FeatureControlDefGuest.h b/host-common/include/host-common/FeatureControlDefGuest.h
index 81bbf96..ac9061d 100644
--- a/host-common/include/host-common/FeatureControlDefGuest.h
+++ b/host-common/include/host-common/FeatureControlDefGuest.h
@@ -78,3 +78,5 @@ FEATURE_CONTROL_ITEM(DownloadableSnapshot, 92)
 FEATURE_CONTROL_ITEM(SupportPixelFold, 96)
 FEATURE_CONTROL_ITEM(DeviceKeyboardHasAssistKey, 97)
 FEATURE_CONTROL_ITEM(Uwb, 101)
+FEATURE_CONTROL_ITEM(GuestAngle, 102)
+FEATURE_CONTROL_ITEM(AndroidVirtualizationFramework, 103)
diff --git a/host-common/include/host-common/logging.h b/host-common/include/host-common/logging.h
index 493f006..30b3b28 100644
--- a/host-common/include/host-common/logging.h
+++ b/host-common/include/host-common/logging.h
@@ -17,17 +17,21 @@
 #include <cstdint>
 #include <cstdio>
 
-typedef void (*gfxstream_logger_t)(const char* fmt, ...);
+typedef void (*gfxstream_logger_t)(char severity, const char* file, unsigned int line,
+               int64_t timestamp_us, const char* message);
 
+gfxstream_logger_t get_gfx_stream_logger();
 void set_gfxstream_logger(gfxstream_logger_t f);
-void set_gfxstream_fine_logger(gfxstream_logger_t f);
+void set_gfxstream_enable_verbose_logs();
+void set_gfxstream_enable_log_colors();
 
 // Outputs a log line using Google's standard prefix. (http://go/logging#prefix)
 //
 // Do not use this function directly. Instead, use one of the logging macros below.
+// Note that: Logging with the 'D' (Debug) level is the least severe.
 //
 // stream: file handle to output to.
-// severity: single character to indicate severity: 'V', 'D', 'I', 'W', 'E', or 'F'.
+// severity: single character to indicate severity: 'D', 'V', 'I', 'W', 'E', or 'F'.
 // file: name of the file where the message comes from (typically __FILE__)
 // line: line number where the message comes from (typically __LINE__)
 // timestamp_us: for testing only - timestamp of the log in microseconds since the Unix epoch.
@@ -75,4 +79,9 @@ void OutputLog(FILE* stream, char severity, const char* file, unsigned int line,
         GFXSTREAM_LOG(stderr, 'I', fmt, ##__VA_ARGS__); \
     } while (0)
 
+#define VERBOSE(fmt, ...)                               \
+    do {                                                \
+        GFXSTREAM_LOG(stderr, 'V', fmt, ##__VA_ARGS__); \
+    } while (0)
+
 // Note: FATAL is defined in host-common/include/host-common/GfxstreamFatalError.h
diff --git a/host-common/include/host-common/vm_operations.h b/host-common/include/host-common/vm_operations.h
index 5dcd6c1..9d46f57 100644
--- a/host-common/include/host-common/vm_operations.h
+++ b/host-common/include/host-common/vm_operations.h
@@ -159,6 +159,12 @@ typedef enum EmuRunState {
     QEMU_RUN_STATE__MAX = 16,
 } EmuRunState;
 
+typedef enum SnapshotSkipReason {
+    SNAPSHOT_SKIP_UNKNOWN = 0,
+    SNAPSHOT_SKIP_UNSUPPORTED_VK_APP = 1,
+    SNAPSHOT_SKIP_UNSUPPORTED_VK_API = 2,
+} SnapshotSkipReason;
+
 // C interface to expose Qemu implementations of common VM related operations.
 typedef struct QAndroidVmOperations {
     bool (*vmStop)(void);
@@ -251,5 +257,17 @@ typedef struct QAndroidVmOperations {
 
     // Reset the machine
     void (*system_shutdown_request)(QemuShutdownCause reason);
+
+    // Set the reason to skip snapshotting on exit.
+    void (*setSkipSnapshotSaveReason)(SnapshotSkipReason reason);
+
+    // Get the reason to skip snapshotting on exit.
+    SnapshotSkipReason (*getSkipSnapshotSaveReason)();
+
+    // Set Vulkan snapshot is actively used, for stats.
+    void (*setStatSnapshotUseVulkan)(void);
+
+    // Check if Vulkan snapshot is actively used, for stats.
+    bool (*snapshotUseVulkan)();
 } QAndroidVmOperations;
 ANDROID_END_HEADER
diff --git a/host-common/logging.cpp b/host-common/logging.cpp
index 0ed0c1f..e9b8350 100644
--- a/host-common/logging.cpp
+++ b/host-common/logging.cpp
@@ -19,6 +19,7 @@
 #include <cstdarg>
 #include <cstring>
 #include <sstream>
+#include <string>
 #include <thread>
 
 #ifdef _WIN32
@@ -36,7 +37,8 @@ namespace {
 constexpr int kMaxThreadIdLength = 7;  // 7 digits for the thread id is what Google uses everywhere.
 
 gfxstream_logger_t sLogger = nullptr;
-gfxstream_logger_t sFineLogger = nullptr;
+bool sEnableVerbose = false;
+bool sEnableColors = false;
 
 // Returns the current thread id as a string of at most kMaxThreadIdLength characters.
 // We try to avoid using std::this_thread::get_id() because on Linux at least it returns a long
@@ -60,13 +62,15 @@ std::string getThreadID() {
 }
 
 // Caches the thread id in thread local storage to increase performance
-// Inspired by: https://github.com/abseil/abseil-cpp/blob/52d41a9ec23e39db7e2cbce5c9449506cf2d3a5c/absl/base/internal/sysinfo.cc#L494-L504
+// Inspired by:
+// https://github.com/abseil/abseil-cpp/blob/52d41a9ec23e39db7e2cbce5c9449506cf2d3a5c/absl/base/internal/sysinfo.cc#L494-L504
 const char* getCachedThreadID() {
     static thread_local std::string thread_id = getThreadID();
     return thread_id.c_str();
 }
 
-// Borrowed from https://cs.android.com/android/platform/superproject/+/master:system/libbase/logging.cpp;l=84-98;drc=18c2bd4f3607cb300bb96e543df91dfdda6a9655
+// Borrowed from
+// https://cs.android.com/android/platform/superproject/+/master:system/libbase/logging.cpp;l=84-98;drc=18c2bd4f3607cb300bb96e543df91dfdda6a9655
 // Note: we use this over std::filesystem::path to keep it as fast as possible.
 const char* GetFileBasename(const char* file) {
 #if defined(_WIN32)
@@ -84,16 +88,34 @@ const char* GetFileBasename(const char* file) {
 
 }  // namespace
 
+gfxstream_logger_t get_gfx_stream_logger() { return sLogger; };
 void set_gfxstream_logger(gfxstream_logger_t f) { sLogger = f; }
 
-void set_gfxstream_fine_logger(gfxstream_logger_t f) { sFineLogger = f; }
+void set_gfxstream_enable_verbose_logs() { sEnableVerbose = true; }
+
+void set_gfxstream_enable_log_colors() { sEnableColors = true; }
 
 void OutputLog(FILE* stream, char severity, const char* file, unsigned int line,
                int64_t timestamp_us, const char* format, ...) {
-    gfxstream_logger_t logger =
-        severity == 'I' || severity == 'W' || severity == 'E' || severity == 'F' ? sLogger
-                                                                                 : sFineLogger;
+    if (sLogger) {
+        char formatted_message[2048];
+        va_list args;
+        va_start(args, format);
+        int ret = vsnprintf(formatted_message, sizeof(formatted_message), format, args);
+        va_end(args);
+        if (timestamp_us == 0) {
+            timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
+                               std::chrono::system_clock::now().time_since_epoch())
+                               .count();
+        }
+
+        sLogger(severity, file, line, timestamp_us, formatted_message);
+        return;
+    }
 
+    if (severity == 'V' && !sEnableVerbose) {
+        return;
+    }
     if (timestamp_us == 0) {
         timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
@@ -112,30 +134,36 @@ void OutputLog(FILE* stream, char severity, const char* file, unsigned int line,
     // Get the microseconds part of the timestamp since it's not available in the tm struct
     int64_t microseconds = timestamp_us % 1000000;
 
-    // Output the standard Google logging prefix
-    // See also: https://github.com/google/glog/blob/9dc1107f88d3a1613d61b80040d83c1c1acbac3d/src/logging.cc#L1612-L1615
-    if (logger) {
-        logger("%c%02d%02d %02d:%02d:%02d.%06" PRId64 " %7s %s:%d] ", severity, ts_parts.tm_mon + 1,
-               ts_parts.tm_mday, ts_parts.tm_hour, ts_parts.tm_min, ts_parts.tm_sec, microseconds,
-               getCachedThreadID(), GetFileBasename(file), line);
-    } else {
-        fprintf(stream, "%c%02d%02d %02d:%02d:%02d.%06" PRId64 " %7s %s:%d] ", severity,
-                ts_parts.tm_mon + 1, ts_parts.tm_mday, ts_parts.tm_hour, ts_parts.tm_min,
-                ts_parts.tm_sec, microseconds, getCachedThreadID(), GetFileBasename(file), line);
-    }
+    // Standard Google logging prefix
+    // See also:
+    // https://github.com/google/glog/blob/9dc1107f88d3a1613d61b80040d83c1c1acbac3d/src/logging.cc#L1612-L1615
+    char prefix[1024];
+    snprintf(prefix, sizeof(prefix), "%c%02d%02d %02d:%02d:%02d.%06" PRId64 " %7s %s:%d]", severity,
+             ts_parts.tm_mon + 1, ts_parts.tm_mday, ts_parts.tm_hour, ts_parts.tm_min,
+             ts_parts.tm_sec, microseconds, getCachedThreadID(), GetFileBasename(file), line);
 
-    // Output the actual log message and newline
+    // Actual log message
     va_list args;
     va_start(args, format);
-    char temp[2048];
-    int ret = vsnprintf(temp, sizeof(temp), format, args);
-    temp[sizeof(temp) - 1] = 0;
-
-    if (logger) {
-        logger("%s\n", temp);
+    char formatted_message[2048];
+    int ret = vsnprintf(formatted_message, sizeof(formatted_message), format, args);
+    formatted_message[sizeof(formatted_message) - 1] = 0;
+
+    // Output prefix and the message with a newline
+    if (sEnableColors) {
+        const char* colorTag = "";
+        const char* colorTagReset = "\x1B[0m";
+
+        // Colorize errors and warnings
+        if (severity == 'E' || severity == 'F') {
+            colorTag = "\x1B[31m";  // Red
+        } else if (severity == 'W') {
+            colorTag = "\x1B[33m";  // Yellow
+        }
+
+        fprintf(stream, "%s%s %s\n%s", colorTag, prefix, formatted_message, colorTagReset);
     } else {
-        fprintf(stream, "%s\n", temp);
+        fprintf(stream, "%s %s\n", prefix, formatted_message);
     }
     va_end(args);
-
 }
diff --git a/host-common/logging_absl.cpp b/host-common/logging_absl.cpp
new file mode 100644
index 0000000..a654e8a
--- /dev/null
+++ b/host-common/logging_absl.cpp
@@ -0,0 +1,99 @@
+// Copyright 2023 The Android Open Source Project
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
+#include <chrono>
+#include <cinttypes>
+#include <cstdarg>
+#include <cstring>
+#include <sstream>
+#include <thread>
+
+#include "absl/log/absl_log.h"
+#include "absl/log/log.h"
+#include "logging.h"
+namespace {
+bool sEnableVerbose = false;
+}  // namespace
+
+void set_gfxstream_logger(gfxstream_logger_t f) {}
+void set_gfxstream_fine_logger(gfxstream_logger_t f) {}
+void set_gfxstream_enable_log_colors() {}
+void set_gfxstream_enable_verbose_logs() { sEnableVerbose = true; }
+
+void OutputLog(FILE* stream, char severity, const char* file, unsigned int line,
+               int64_t timestamp_us, const char* format, ...) {
+    if (severity == 'V' && !sEnableVerbose) {
+        return;
+    }
+
+    constexpr int bufferSize = 4096;
+    char buffer[bufferSize];
+    int strlen = bufferSize;
+    va_list args;
+    va_start(args, format);
+    int size = vsnprintf(buffer, bufferSize, format, args);
+    va_end(args);
+    if (size >= bufferSize) {
+        // Indicate trunctation.
+        strncpy(buffer + bufferSize - 3, "...", 3);
+    } else {
+        strlen = size;
+    }
+
+    std::string_view msg(buffer, strlen);
+
+    if (timestamp_us == 0) {
+        switch (severity) {
+            case 'I':  // INFO
+                ABSL_LOG(INFO).AtLocation(file, line) << msg;
+                break;
+            case 'W':  // WARNING
+                ABSL_LOG(WARNING).AtLocation(file, line) << msg;
+                break;
+            case 'E':  // ERROR
+                ABSL_LOG(ERROR).AtLocation(file, line) << msg;
+                break;
+            case 'F':  // FATAL
+                ABSL_LOG(FATAL).AtLocation(file, line) << msg;
+                break;
+            case 'V':
+                VLOG(1).AtLocation(file, line) << msg;
+                break;
+            case 'D':
+                VLOG(2).AtLocation(file, line) << msg;
+                break;
+        };
+    } else {
+        auto ts = absl::UnixEpoch() + absl::Microseconds(timestamp_us);
+        switch (severity) {
+            case 'I':  // INFO
+                ABSL_LOG(INFO).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+            case 'W':  // WARNING
+                ABSL_LOG(WARNING).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+            case 'E':  // ERROR
+                ABSL_LOG(ERROR).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+            case 'F':  // FATAL
+                ABSL_LOG(FATAL).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+            case 'V':
+                VLOG(1).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+            case 'D':
+                VLOG(2).AtLocation(file, line).WithTimestamp(ts) << msg;
+                break;
+        };
+    }
+}
diff --git a/host-common/logging_absl_unittest.cpp b/host-common/logging_absl_unittest.cpp
new file mode 100644
index 0000000..7f50c0f
--- /dev/null
+++ b/host-common/logging_absl_unittest.cpp
@@ -0,0 +1,158 @@
+// Copyright 2023 The Android Open Source Project
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
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <string>
+#include <thread>
+#include <vector>
+
+#include "absl/log/globals.h"
+#include "absl/log/log.h"
+#include "absl/log/log_sink_registry.h"
+#include "absl/strings/str_format.h"
+#include "absl/strings/string_view.h"
+#include "absl/time/civil_time.h"
+#include "absl/time/clock.h"
+#include "absl/time/time.h"
+#include "aemu/base/testing/TestUtils.h"
+#include "host-common/logging.h"
+
+namespace {
+
+using ::testing::EndsWith;
+using ::testing::HasSubstr;
+using ::testing::Not;
+using ::testing::StartsWith;
+
+class CaptureLogSink : public absl::LogSink {
+   public:
+    void Send(const absl::LogEntry& entry) override {
+        char level = 'I';
+        switch (entry.log_severity()) {
+            case absl::LogSeverity::kInfo:
+                level = 'I';
+                break;
+            case absl::LogSeverity::kError:
+                level = 'E';
+                break;
+            case absl::LogSeverity::kWarning:
+                level = 'W';
+                break;
+
+            case absl::LogSeverity::kFatal:
+                level = 'F';
+                break;
+        }
+        captured_log_ = absl::StrFormat("%c %s:%d |%s|- %s", level, entry.source_filename(),
+                                        entry.source_line(), absl::FormatTime(entry.timestamp()),
+                                        entry.text_message());
+    }
+
+    std::string captured_log_;
+};
+
+// Returns the microseconds since the Unix epoch for Sep 13, 2020 12:26:40.123456 in the machine's
+// local timezone.
+absl::Time defaultTimestamp() {
+    absl::CivilSecond cs(2020, 9, 13, 12, 26, 40);
+    return absl::FromCivil(cs, absl::UTCTimeZone());
+}
+
+class OutputLogTest : public ::testing::Test {
+   protected:
+    void SetUp() override {
+        // Add the CaptureLogSink
+        log_sink_ = std::make_unique<CaptureLogSink>();
+        absl::AddLogSink(log_sink_.get());
+
+        absl::SetVLogLevel("*", 2);
+        set_gfxstream_enable_verbose_logs();
+
+        // Set log level to capture everything (adjust as needed)
+        absl::SetStderrThreshold(absl::LogSeverity::kInfo);
+    }
+
+    void TearDown() override {
+        // Remove the CaptureLogSink
+        absl::RemoveLogSink(log_sink_.get());
+    }
+
+    // Common test parameters
+    const char* file = "test_file.cc";
+    int line = 42;
+    const char* format = "This is a %s message";
+
+    // Helper to create a formatted log message string
+    std::string FormattedLog(absl::Time timestamp, absl::LogSeverity severity,
+                             const std::string& msg) {
+        std::string formatted =
+            absl::FormatTime("%Y-%m-%d %H:%M:%S", timestamp, absl::UTCTimeZone());
+        return absl::StrFormat("%s: %s:%d] %s", formatted, file, line, msg);
+    }
+
+    std::unique_ptr<CaptureLogSink> log_sink_;
+};
+
+// Test INFO log level with timestamp
+TEST_F(OutputLogTest, InfoLogWithTimestamp) {
+    auto timestamp_us = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'I', file, line, timestamp_us, format, "INFO");
+    EXPECT_EQ(log_sink_->captured_log_,
+              "I test_file.cc:42 |2020-09-13T12:26:40+00:00|- This is a INFO message");
+}
+
+// Test WARNING log level with timestamp
+TEST_F(OutputLogTest, WarningLogWithTimestamp) {
+    auto timestamp_us = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'W', file, line, timestamp_us, format, "WARNING");
+    EXPECT_EQ(log_sink_->captured_log_,
+              "W test_file.cc:42 |2020-09-13T12:26:40+00:00|- This is a WARNING message");
+}
+
+// Test ERROR log level with timestamp
+TEST_F(OutputLogTest, ErrorLogWithTimestamp) {
+    auto timestamp_us = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'E', file, line, timestamp_us, format, "ERROR");
+    EXPECT_EQ(log_sink_->captured_log_,
+              "E test_file.cc:42 |2020-09-13T12:26:40+00:00|- This is a ERROR message");
+}
+
+// Test VERBOSE log level with timestamp
+TEST_F(OutputLogTest, VerboseLogWithTimestamp) {
+    auto timestamp_us = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'V', file, line, timestamp_us, format, "VERBOSE");
+    EXPECT_EQ(log_sink_->captured_log_,
+              "I test_file.cc:42 |2020-09-13T12:26:40+00:00|- This is a VERBOSE message");
+}
+
+// Test VERBOSE log level with timestamp
+TEST_F(OutputLogTest, DebugLogWithTimestamp) {
+    auto timestamp_us = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'D', file, line, timestamp_us, format, "DEBUG");
+    EXPECT_EQ(log_sink_->captured_log_,
+              "I test_file.cc:42 |2020-09-13T12:26:40+00:00|- This is a DEBUG message");
+}
+
+// Test truncation when message exceeds buffer size
+TEST_F(OutputLogTest, Truncation) {
+    std::string long_msg(4100, 'x');  // Exceeds buffer size
+    auto now = absl::ToUnixMicros(defaultTimestamp());
+    OutputLog(nullptr, 'I', file, line, now, "%s", long_msg.c_str());
+
+    std::string expected_msg = long_msg.substr(0, 4093) + "...";
+    EXPECT_THAT(log_sink_->captured_log_, testing::HasSubstr(expected_msg));
+}
+
+}  // namespace
diff --git a/snapshot/BUILD.bazel b/snapshot/BUILD.bazel
index 549a36f..e55d245 100644
--- a/snapshot/BUILD.bazel
+++ b/snapshot/BUILD.bazel
@@ -15,16 +15,10 @@ cc_library(
     ],
     hdrs = [":gfxstream-snapshot-headers"],
     copts = [
+        "-D_FILE_OFFSET_BITS=64",
         "-Wno-extern-c-compat",
         "-Wno-return-type-c-linkage",
     ],
-    defines = select({
-        "@platforms//os:macos": [
-            "fseeko64=fseek",
-            "ftello64=ftell",
-        ],
-        "//conditions:default": [],
-    }),
     visibility = ["//visibility:public"],
     deps = [
         ":gfxstream-snapshot-headers",
diff --git a/snapshot/CMakeLists.txt b/snapshot/CMakeLists.txt
index 55fc0fc..fb92fd3 100644
--- a/snapshot/CMakeLists.txt
+++ b/snapshot/CMakeLists.txt
@@ -23,7 +23,3 @@ target_include_directories(
     ${SNAPSHOT_LIB_NAME}
     PUBLIC
     ${AEMU_COMMON_REPO_ROOT}/include)
-if (APPLE)
-    target_compile_definitions(
-        ${SNAPSHOT_LIB_NAME} PRIVATE -Dfseeko64=fseek -Dftello64=ftell)
-endif()
diff --git a/snapshot/TextureLoader.cpp b/snapshot/TextureLoader.cpp
index 31e02e8..5c21134 100644
--- a/snapshot/TextureLoader.cpp
+++ b/snapshot/TextureLoader.cpp
@@ -46,7 +46,7 @@ bool TextureLoader::start() {
 void TextureLoader::loadTexture(uint32_t texId, const loader_t& loader) {
     android::base::AutoLock scopedLock(mLock);
     assert(mIndex.count(texId));
-    HANDLE_EINTR(fseeko64(mStream.get(), mIndex[texId], SEEK_SET));
+    HANDLE_EINTR(fseeko(mStream.get(), mIndex[texId], SEEK_SET));
     switch (mVersion) {
         case 1:
             loader(&mStream);
@@ -71,7 +71,7 @@ bool TextureLoader::readIndex() {
         mDiskSize = size;
     }
     auto indexPos = mStream.getBe64();
-    HANDLE_EINTR(fseeko64(mStream.get(), static_cast<int64_t>(indexPos), SEEK_SET));
+    HANDLE_EINTR(fseeko(mStream.get(), static_cast<int64_t>(indexPos), SEEK_SET));
     mVersion = mStream.getBe32();
     if (mVersion < 1 || mVersion > 2) {
         return false;
diff --git a/snapshot/TextureSaver.cpp b/snapshot/TextureSaver.cpp
index 537626b..c8854e9 100644
--- a/snapshot/TextureSaver.cpp
+++ b/snapshot/TextureSaver.cpp
@@ -50,7 +50,7 @@ void TextureSaver::saveTexture(uint32_t texId, const saver_t& saver) {
                         [texId](FileIndex::Texture& tex) {
                             return tex.texId == texId;
                         }));
-    mIndex.textures.push_back({texId, ftello64(mStream.get())});
+    mIndex.textures.push_back({texId, ftello(mStream.get())});
 
     CompressingStream stream(mStream);
     saver(&stream, &mBuffer);
@@ -60,7 +60,7 @@ void TextureSaver::done() {
     if (mFinished) {
         return;
     }
-    mIndex.startPosInFile = ftello64(mStream.get());
+    mIndex.startPosInFile = ftello(mStream.get());
     writeIndex();
     mEndTime = base::getHighResTimeUs();
 #if SNAPSHOT_PROFILE > 1
@@ -74,7 +74,7 @@ void TextureSaver::done() {
 
 void TextureSaver::writeIndex() {
 #if SNAPSHOT_PROFILE > 1
-    auto start = ftello64(mStream.get());
+    auto start = ftello(mStream.get());
 #endif
 
     mStream.putBe32(static_cast<uint32_t>(mIndex.version));
@@ -83,13 +83,13 @@ void TextureSaver::writeIndex() {
         mStream.putBe32(b.texId);
         mStream.putBe64(static_cast<uint64_t>(b.filePos));
     }
-    auto end = ftello64(mStream.get());
+    auto end = ftello(mStream.get());
     mDiskSize = uint64_t(end);
 #if SNAPSHOT_PROFILE > 1
     printf("texture: index size: %d\n", int(end - start));
 #endif
 
-    fseeko64(mStream.get(), 0, SEEK_SET);
+    fseeko(mStream.get(), 0, SEEK_SET);
     mStream.putBe64(static_cast<uint64_t>(mIndex.startPosInFile));
 }
 
diff --git a/snapshot/include/snapshot/common.h b/snapshot/include/snapshot/common.h
index c62ffc0..079ef80 100644
--- a/snapshot/include/snapshot/common.h
+++ b/snapshot/include/snapshot/common.h
@@ -111,6 +111,11 @@ enum class FailureReason {
     OutOfDiskSpace,
 
     InProgressLimit = 30000,
+
+    UnsupportedVkApp = 30001,
+    UnsupportedVkApi = 30002,
+
+    UnsupportedVkUsageLimit = 40000,
 };
 
 FailureReason errnoToFailure(int error);
diff --git a/windows/BUILD b/windows/BUILD
new file mode 100644
index 0000000..db73f90
--- /dev/null
+++ b/windows/BUILD
@@ -0,0 +1,37 @@
+cc_library(
+    name = "compat-hdrs",
+    hdrs = glob(["includes/**/*.h"]),
+    defines = ["AEMU_WIN_COMPAT"],
+    includes = [
+        "includes",
+        "includes/dirent",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+cc_library(
+    name = "compat",
+    srcs =
+        glob([
+            "src/dirent/*.c",
+            "src/*.c",
+            "src/*.h",
+            "src/*.cpp",
+        ]),
+    defines = [
+        "WIN32_LEAN_AND_MEAN",
+    ],
+    includes = [
+        "src",
+    ],
+    linkopts = [
+        "-DEFAULTLIB:ws2_32.lib",
+        "-DEFAULTLIB:Pathcch.lib",
+        "-DEFAULTLIB:ole32.lib",
+        "-DEFAULTLIB:dxguid.lib",
+        "-DEFAULTLIB:Winmm.lib",
+    ],
+    linkstatic = True,
+    visibility = ["//visibility:public"],
+    deps = [":compat-hdrs"],
+)
diff --git a/windows/CMakeLists.txt b/windows/CMakeLists.txt
new file mode 100644
index 0000000..07fac94
--- /dev/null
+++ b/windows/CMakeLists.txt
@@ -0,0 +1,36 @@
+if(TARGET msvc-posix-compat)
+  return()
+endif()
+
+if(INCLUDE_ANDROID_CMAKE)
+  # This is a posix wrapper for windows-msvc build.
+  android_nasm_compile(TARGET setjmp_asm_lib LICENSE Apache-2.0 SRC
+                       src/setjmp.asm)
+  android_add_library(TARGET msvc-posix-compat LICENSE Apache-2.0 SRC "")
+  target_link_libraries(msvc-posix-compat PRIVATE setjmp_asm_lib)
+else()
+  add_library(msvc-posix-compat)
+endif()
+
+target_sources(
+  msvc-posix-compat
+  PRIVATE src/asprintf.c
+          src/files.cpp
+          src/getopt.c
+          src/msvc-posix.c
+          src/pread.cpp
+          src/time.cpp)
+target_link_libraries(msvc-posix-compat PUBLIC aemu-base.headers)
+
+# Msvc redefines macro's to inject compatibility.
+target_compile_options(
+  msvc-posix-compat
+  PUBLIC "-Wno-macro-redefined" "-Wno-deprecated-declarations" # A lot of the
+                                                               # POSIX names are
+                                                               # deprecated..
+)
+target_include_directories(msvc-posix-compat PUBLIC includes)
+
+if (ANDROID_EMULATOR_BUILD)
+  add_subdirectory(tests)
+endif()
\ No newline at end of file
diff --git a/windows/README.MD b/windows/README.MD
new file mode 100644
index 0000000..ac821a5
--- /dev/null
+++ b/windows/README.MD
@@ -0,0 +1,25 @@
+# AOSP Toolchain Compatibility Layer for Windows
+
+This directory provides header files and a compatibility library to ensure QEMU compilation using the AOSP clang-cl toolchain.
+
+Though clang-cl accepts clang like compiler flags, it does not provide a set of posix compliant headers (like mingw does). In this directory you will find header files with constant definitions and functions that are used by QEMU. For some functions an implementations is provided.
+
+Note that the current functionality is not (yet) utf-8 compliant so you will likely encounter issues when using unicode paths.
+
+
+## Package Details
+
+Some of the code used here is lifted from other packages:
+
+- Dirent: This implementation is lifted from mingw runtime, the source has been taking from the AOSP version of [glib](https://android.googlesource.com/platform/external/bluetooth/glib/+/refs/heads/emu-dev/glib/dirent/).
+- Getopt: The implementation we use was taken from netbsd, with the following license:
+
+```
+ * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
+ *
+ * Permission to use, copy, modify, and distribute this software for any
+ * purpose with or without fee is hereby granted, provided that the above
+ * copyright notice and this permission notice appear in all copies.
+```
+
+- We have a series of missing compiler directives that we have brought in from llvm, which are release under the Apache-2.0 license with an llvm exception. The exact license can be obtained [here](https://llvm.org/LICENSE.txt)
diff --git a/windows/includes/bits/socket.h b/windows/includes/bits/socket.h
new file mode 100644
index 0000000..46546b4
--- /dev/null
+++ b/windows/includes/bits/socket.h
@@ -0,0 +1,26 @@
+// Copyright 2021 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#ifndef _AEMU_BITS_SOCKET_H_
+#define _AEMU_BITS_SOCKET_H_
+
+#ifndef __linux__
+#ifndef __QNX__
+// Make sure these are defined and don't change anything if used.
+enum {
+    SOCK_CLOEXEC = 0,
+#ifndef __APPLE__
+    O_CLOEXEC = 0
+#endif
+};
+#endif  // !__QNX__
+#endif  // !__linux__
+
+#endif	/* Not _AEMU_BITS_SOCKET_H_ */
\ No newline at end of file
diff --git a/windows/includes/compat_compiler.h b/windows/includes/compat_compiler.h
new file mode 100644
index 0000000..dd7c1a9
--- /dev/null
+++ b/windows/includes/compat_compiler.h
@@ -0,0 +1,24 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+#ifndef ANDROID_BEGIN_HEADER
+#ifdef __cplusplus
+#define ANDROID_BEGIN_HEADER extern "C" {
+#define ANDROID_END_HEADER   }
+#else
+#define ANDROID_BEGIN_HEADER /* nothing */
+#define ANDROID_END_HEADER  /* nothing */
+#endif
+#endif
\ No newline at end of file
diff --git a/windows/includes/dirent/dirent.h b/windows/includes/dirent/dirent.h
new file mode 100644
index 0000000..81bad74
--- /dev/null
+++ b/windows/includes/dirent/dirent.h
@@ -0,0 +1,127 @@
+/*
+ * DIRENT.H (formerly DIRLIB.H)
+ * This file has no copyright assigned and is placed in the Public Domain.
+ * This file is a part of the mingw-runtime package.
+ * No warranty is given; refer to the file DISCLAIMER within the package.
+ *
+ */
+#ifndef _AEMU_DIRENT_H_
+#define _AEMU_DIRENT_H_
+
+#include <stdio.h>
+#include <io.h>
+
+#ifndef RC_INVOKED
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+struct dirent
+{
+	long		d_ino;		/* Always zero. */
+	unsigned short	d_reclen;	/* Always zero. */
+	unsigned short	d_namlen;	/* Length of name in d_name. */
+	char		d_name[FILENAME_MAX+1]; /* File name plus nul delimiter. */
+};
+
+#ifdef _WIN64
+#define INTPTR __int64
+#else
+#define INTPTR long
+#endif
+
+/*
+ * This is an internal data structure. Good programmers will not use it
+ * except as an argument to one of the functions below.
+ * dd_stat field is now int (was short in older versions).
+ */
+typedef struct
+{
+	/* disk transfer area for this dir */
+	struct _finddata_t	dd_dta;
+
+	/* dirent struct to return from dir (NOTE: this makes this thread
+	 * safe as long as only one thread uses a particular DIR struct at
+	 * a time) */
+	struct dirent		dd_dir;
+
+	/* _findnext handle */
+	INTPTR			dd_handle;
+
+	/*
+         * Status of search:
+	 *   0 = not started yet (next entry to read is first entry)
+	 *  -1 = off the end
+	 *   positive = 0 based index of next entry
+	 */
+	int			dd_stat;
+
+	/* given path for dir with search pattern (struct is extended) */
+	char			dd_name[1];
+} DIR;
+
+DIR* __cdecl opendir (const char*);
+struct dirent* __cdecl readdir (DIR*);
+int __cdecl closedir (DIR*);
+void __cdecl rewinddir (DIR*);
+long __cdecl telldir (DIR*);
+void __cdecl seekdir (DIR*, long);
+
+
+/* wide char versions */
+
+struct _wdirent
+{
+	long		d_ino;		/* Always zero. */
+	unsigned short	d_reclen;	/* Always zero. */
+	unsigned short	d_namlen;	/* Length of name in d_name. */
+	wchar_t		d_name[FILENAME_MAX+1]; /* File name plus nul delimiter. */
+};
+
+/*
+ * This is an internal data structure. Good programmers will not use it
+ * except as an argument to one of the functions below.
+ */
+typedef struct
+{
+	/* disk transfer area for this dir */
+	struct _wfinddata_t	dd_dta;
+
+	/* dirent struct to return from dir (NOTE: this makes this thread
+	 * safe as long as only one thread uses a particular DIR struct at
+	 * a time) */
+	struct _wdirent		dd_dir;
+
+	/* _findnext handle */
+	INTPTR			dd_handle;
+
+	/*
+         * Status of search:
+	 *   0 = not started yet (next entry to read is first entry)
+	 *  -1 = off the end
+	 *   positive = 0 based index of next entry
+	 */
+	int			dd_stat;
+
+	/* given path for dir with search pattern (struct is extended) */
+	wchar_t			dd_name[1];
+} _WDIR;
+
+
+
+_WDIR* __cdecl _wopendir (const wchar_t*);
+struct _wdirent*  __cdecl _wreaddir (_WDIR*);
+int __cdecl _wclosedir (_WDIR*);
+void __cdecl _wrewinddir (_WDIR*);
+long __cdecl _wtelldir (_WDIR*);
+void __cdecl _wseekdir (_WDIR*, long);
+
+
+#ifdef	__cplusplus
+}
+#endif
+
+#endif	/* Not RC_INVOKED */
+
+#endif	/* Not _AEMU_DIRENT_H_ */
diff --git a/windows/includes/fcntl.h b/windows/includes/fcntl.h
new file mode 100644
index 0000000..f93de87
--- /dev/null
+++ b/windows/includes/fcntl.h
@@ -0,0 +1,25 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+#ifndef _AEMU_FCNTL_H_
+#define _AEMU_FCNTL_H_
+
+
+// fcntl with added missing defines.
+#include_next <fcntl.h>
+
+#define O_ACCMODE (O_RDONLY | O_WRONLY | O_RDWR)
+
+#endif	/* Not _AEMU_FCNTL_H_ */
diff --git a/windows/includes/getopt.h b/windows/includes/getopt.h
new file mode 100644
index 0000000..b4af38e
--- /dev/null
+++ b/windows/includes/getopt.h
@@ -0,0 +1,56 @@
+/* __BEGIN_DECLS should be used at the beginning of your declarations,
+   so that C++ compilers don't mangle their names.  Use __END_DECLS at
+   the end of C declarations. */
+
+
+#ifndef _AEMU_GETOPT_H_
+#define _AEMU_GETOPT_H_
+
+#ifndef __BEGIN_DECLS
+#ifdef __cplusplus
+# define __BEGIN_DECLS extern "C" {
+# define __END_DECLS }
+#else
+# define __BEGIN_DECLS /* empty */
+# define __END_DECLS /* empty */
+#endif
+#endif
+
+__BEGIN_DECLS
+
+// <getopt.h>
+extern int optind;   /* index of first non-option in argv      */
+extern int optopt;   /* single option character, as parsed     */
+extern int opterr;   /* flag to enable built-in diagnostics... */
+                     /* (user may set to zero, to suppress)    */
+extern char* optarg; /* pointer to argument of current option  */
+
+extern int getopt(int nargc, char* const* nargv, const char* options);
+
+struct option /* specification for a long form option...	*/
+{
+    const char* name; /* option name, without leading hyphens */
+    int has_arg;      /* does it take an argument?		*/
+    int* flag;        /* where to save its status, or NULL	*/
+    int val;          /* its associated status value		*/
+};
+
+enum                 /* permitted values for its `has_arg' field...	*/
+{ no_argument = 0,   /* option never takes an argument	*/
+  required_argument, /* option always requires an argument	*/
+  optional_argument  /* option may take an argument		*/
+};
+
+extern int getopt_long(int nargc,
+                       char* const* nargv,
+                       const char* options,
+                       const struct option* long_options,
+                       int* idx);
+extern int getopt_long_only(int nargc,
+                            char* const* nargv,
+                            const char* options,
+                            const struct option* long_options,
+                            int* idx);
+__END_DECLS
+
+#endif	/* Not _AEMU_GETOPT_H_ */
diff --git a/windows/includes/libgen.h b/windows/includes/libgen.h
new file mode 100644
index 0000000..7259b2c
--- /dev/null
+++ b/windows/includes/libgen.h
@@ -0,0 +1,20 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+
+#ifndef _AEMU_LIBGEN_H_
+#define _AEMU_LIBGEN_H_
+
+#endif	/* Not _AEMU_LIBGEN_H_ */
diff --git a/windows/includes/limits.h b/windows/includes/limits.h
new file mode 100644
index 0000000..90f68ea
--- /dev/null
+++ b/windows/includes/limits.h
@@ -0,0 +1,21 @@
+// Copyright (C) 2023 The Android Open Source Project
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
+#include_next <limits.h>
+
+#ifndef _AEMU_LIMITS_H_
+#define _AEMU_LIMITS_H_
+
+#define SSIZE_MAX ((size_t)-1)
+#define PATH_MAX MAX_PATH
+#endif	/* Not _AEMU_LIMITS_H_ */
diff --git a/windows/includes/msvc-files.h b/windows/includes/msvc-files.h
new file mode 100644
index 0000000..249ad7a
--- /dev/null
+++ b/windows/includes/msvc-files.h
@@ -0,0 +1,22 @@
+#ifndef QEMU_BASE_BUILD
+#include "android/utils/file_io.h"
+
+// Set of redefines for posix file calls. These redirects
+// will make the windows posix calls unicode compliant.
+//
+// Note this is disabled when were a building qemu.
+//
+#define fopen(path, mode) android_fopen( (path), (mode) )
+#define popen(path, mode) android_popen( (path), (mode) )
+#define stat(path, buf) android_stat( (path), (buf))
+#define lstat(path, buf) android_lstat ( (path), (buf) )
+#define access(path, mode) android_access( (path), (mode))
+#define mkdir(path, mode) android_mkdir( (path), (mode))
+#define mkdir(path) android_mkdir( (path), 0755)
+#define creat(path, mode) android_creat( (path), (mode))
+#define unlink(path) android_unlink((path))
+#define chmod(path, mode) android_chmod( (path), (mode))
+#define rmdir(path) android_rmdir((path))
+#else
+// So we are in the qemu build..
+#endif
diff --git a/windows/includes/msvc-getopt.h b/windows/includes/msvc-getopt.h
new file mode 100644
index 0000000..b11895c
--- /dev/null
+++ b/windows/includes/msvc-getopt.h
@@ -0,0 +1,49 @@
+/* __BEGIN_DECLS should be used at the beginning of your declarations,
+   so that C++ compilers don't mangle their names.  Use __END_DECLS at
+   the end of C declarations. */
+#ifndef __BEGIN_DECLS
+#ifdef __cplusplus
+# define __BEGIN_DECLS extern "C" {
+# define __END_DECLS }
+#else
+# define __BEGIN_DECLS /* empty */
+# define __END_DECLS /* empty */
+#endif
+#endif
+
+__BEGIN_DECLS
+
+// <getopt.h>
+extern int optind;   /* index of first non-option in argv      */
+extern int optopt;   /* single option character, as parsed     */
+extern int opterr;   /* flag to enable built-in diagnostics... */
+                     /* (user may set to zero, to suppress)    */
+extern char* optarg; /* pointer to argument of current option  */
+
+extern int getopt(int nargc, char* const* nargv, const char* options);
+
+struct option /* specification for a long form option...	*/
+{
+    const char* name; /* option name, without leading hyphens */
+    int has_arg;      /* does it take an argument?		*/
+    int* flag;        /* where to save its status, or NULL	*/
+    int val;          /* its associated status value		*/
+};
+
+enum                 /* permitted values for its `has_arg' field...	*/
+{ no_argument = 0,   /* option never takes an argument	*/
+  required_argument, /* option always requires an argument	*/
+  optional_argument  /* option may take an argument		*/
+};
+
+extern int getopt_long(int nargc,
+                       char* const* nargv,
+                       const char* options,
+                       const struct option* long_options,
+                       int* idx);
+extern int getopt_long_only(int nargc,
+                            char* const* nargv,
+                            const char* options,
+                            const struct option* long_options,
+                            int* idx);
+__END_DECLS
diff --git a/windows/includes/msvc-posix.h b/windows/includes/msvc-posix.h
new file mode 100644
index 0000000..2182187
--- /dev/null
+++ b/windows/includes/msvc-posix.h
@@ -0,0 +1,14 @@
+// Copyright 2018 The Android Open Source Project
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
+#pragma once
+
+#include "aemu/base/msvc.h"
\ No newline at end of file
diff --git a/windows/includes/stdlib.h b/windows/includes/stdlib.h
new file mode 100644
index 0000000..cecf2b8
--- /dev/null
+++ b/windows/includes/stdlib.h
@@ -0,0 +1,26 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+
+#ifndef _AEMU_STDLIB_H_
+#define _AEMU_STDLIB_H_
+#include "compat_compiler.h"
+ANDROID_BEGIN_HEADER
+#include_next <stdlib.h>
+
+int mkstemp(char *tmpl);
+
+ANDROID_END_HEADER
+#endif	/* Not _AEMU_STDLIB_H_ */
diff --git a/windows/includes/strings.h b/windows/includes/strings.h
new file mode 100644
index 0000000..cd5bfcf
--- /dev/null
+++ b/windows/includes/strings.h
@@ -0,0 +1,25 @@
+// Copyright 2023 The Android Open Source Project
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
+
+#ifndef _AEMU_STRINGS_H_
+#define _AEMU_STRINGS_H_
+
+// strings.h does not exist in msvc
+#if defined(_WIN32) || defined(_WIN64)
+#  include <string.h>
+#  define strcasecmp _stricmp
+#  define strncasecmp _strnicmp
+#else
+#  include <strings.h>
+#endif
+
+#endif	/* Not _AEMU_STRINGS_H_ */
diff --git a/windows/includes/sys/cdefs.h b/windows/includes/sys/cdefs.h
new file mode 100644
index 0000000..2dcf601
--- /dev/null
+++ b/windows/includes/sys/cdefs.h
@@ -0,0 +1,23 @@
+// Copyright 2021 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#ifndef _AEMU_SYS_CDEFS_H_
+#define _AEMU_SYS_CDEFS_H_
+
+#ifdef __cplusplus
+#define __BEGIN_DECLS extern "C" {
+#define __END_DECLS }
+#else
+#define __BEGIN_DECLS /* empty */
+#define __END_DECLS   /* empty */
+#endif
+
+
+#endif	/* Not _AEMU_SYS_CDEFS_H_ */
\ No newline at end of file
diff --git a/windows/includes/sys/param.h b/windows/includes/sys/param.h
new file mode 100644
index 0000000..e69de29
diff --git a/windows/includes/sys/stat.h b/windows/includes/sys/stat.h
new file mode 100644
index 0000000..73bb693
--- /dev/null
+++ b/windows/includes/sys/stat.h
@@ -0,0 +1,162 @@
+// Copyright 2019 The Android Open Source Project
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
+#ifndef _AEMU_SYS_STAT_H_
+#define _AEMU_SYS_STAT_H_
+
+
+// This sets up a series of compatibility defines that enable compilation
+// of qemu on windows with clang-cl.
+#include_next <sys/stat.h>
+
+#define fstat64 _fstat64
+#define stat _stati64
+#define S_IRUSR _S_IREAD
+#define S_IWUSR _S_IWRITE
+
+#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
+
+
+/*
+ * File type macros.  Note that block devices, sockets and links cannot be
+ * distinguished on Windows and the macros S_ISBLK, S_ISSOCK and S_ISLNK are
+ * only defined for compatibility.  These macros should always return false
+ * on Windows.
+ */
+#if !defined(S_ISFIFO)
+#   define S_ISFIFO(mode) (((mode) & S_IFMT) == S_IFIFO)
+#endif
+#if !defined(S_ISDIR)
+#   define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
+#endif
+#if !defined(S_ISREG)
+#   define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
+#endif
+#if !defined(S_ISLNK)
+#   define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
+#endif
+#if !defined(S_ISSOCK)
+#   define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)
+#endif
+#if !defined(S_ISCHR)
+#   define S_ISCHR(mode) (((mode) & S_IFMT) == S_IFCHR)
+#endif
+#if !defined(S_ISBLK)
+#   define S_ISBLK(mode) (((mode) & S_IFMT) == S_IFBLK)
+#endif
+
+
+/* File type and permission flags for stat(), general mask */
+#if !defined(S_IFMT)
+#   define S_IFMT _S_IFMT
+#endif
+
+/* Directory bit */
+#if !defined(S_IFDIR)
+#   define S_IFDIR _S_IFDIR
+#endif
+
+/* Character device bit */
+#if !defined(S_IFCHR)
+#   define S_IFCHR _S_IFCHR
+#endif
+
+/* Pipe bit */
+#if !defined(S_IFFIFO)
+#   define S_IFFIFO _S_IFFIFO
+#endif
+
+/* Regular file bit */
+#if !defined(S_IFREG)
+#   define S_IFREG _S_IFREG
+#endif
+
+/* Read permission */
+#if !defined(S_IREAD)
+#   define S_IREAD _S_IREAD
+#endif
+
+/* Write permission */
+#if !defined(S_IWRITE)
+#   define S_IWRITE _S_IWRITE
+#endif
+
+/* Execute permission */
+#if !defined(S_IEXEC)
+#   define S_IEXEC _S_IEXEC
+#endif
+
+/* Pipe */
+#if !defined(S_IFIFO)
+#   define S_IFIFO _S_IFIFO
+#endif
+
+/* Block device */
+#if !defined(S_IFBLK)
+#   define S_IFBLK 0
+#endif
+
+/* Link */
+#if !defined(S_IFLNK)
+#   define S_IFLNK 0
+#endif
+
+/* Socket */
+#if !defined(S_IFSOCK)
+#   define S_IFSOCK 0
+#endif
+
+/* Read user permission */
+#if !defined(S_IRUSR)
+#   define S_IRUSR S_IREAD
+#endif
+
+/* Write user permission */
+#if !defined(S_IWUSR)
+#   define S_IWUSR S_IWRITE
+#endif
+
+/* Execute user permission */
+#if !defined(S_IXUSR)
+#   define S_IXUSR 0
+#endif
+
+/* Read group permission */
+#if !defined(S_IRGRP)
+#   define S_IRGRP 0
+#endif
+
+/* Write group permission */
+#if !defined(S_IWGRP)
+#   define S_IWGRP 0
+#endif
+
+/* Execute group permission */
+#if !defined(S_IXGRP)
+#   define S_IXGRP 0
+#endif
+
+/* Read others permission */
+#if !defined(S_IROTH)
+#   define S_IROTH 0
+#endif
+
+/* Write others permission */
+#if !defined(S_IWOTH)
+#   define S_IWOTH 0
+#endif
+
+/* Execute others permission */
+#if !defined(S_IXOTH)
+#   define S_IXOTH 0
+#endif
+
+#endif	/* Not _AEMU_SYS_STAT_H_ */
\ No newline at end of file
diff --git a/windows/includes/sys/time.h b/windows/includes/sys/time.h
new file mode 100644
index 0000000..dab2bb6
--- /dev/null
+++ b/windows/includes/sys/time.h
@@ -0,0 +1,32 @@
+// Copyright 2023 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#ifndef _AEMU_SYS_TIME_H_
+#define _AEMU_SYS_TIME_H_
+
+#include <stdint.h>
+#include <time.h>
+#include <WinSock2.h>
+struct timezone {
+    int tz_minuteswest; /* of Greenwich */
+    int tz_dsttime;     /* type of dst correction to apply */
+};
+
+
+typedef struct FileTime {
+  uint32_t dwLowDateTime;
+  uint32_t dwHighDateTime;
+} FileTime;
+
+typedef  void (*SystemTime)(FileTime*);
+
+
+extern int gettimeofday(struct timeval* tp, struct timezone* tz);
+#endif	/* Not _AEMU_SYS_TIME_H_ */
\ No newline at end of file
diff --git a/windows/includes/sys/types.h b/windows/includes/sys/types.h
new file mode 100644
index 0000000..af107ca
--- /dev/null
+++ b/windows/includes/sys/types.h
@@ -0,0 +1,26 @@
+// Copyright 2023 The Android Open Source Project
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
+#ifndef _AEMU_SYS_TYPES_H_
+#define _AEMU_SYS_TYPES_H_
+
+
+#include_next <sys/types.h>
+#include <inttypes.h>
+#include <stddef.h>
+#include <BaseTsd.h>
+
+typedef unsigned int pid_t;
+
+#ifndef ssize_t
+typedef SSIZE_T ssize_t;
+#endif
+#endif	/* Not _AEMU_SYS_TYPES_H_ */
\ No newline at end of file
diff --git a/windows/includes/time.h b/windows/includes/time.h
new file mode 100644
index 0000000..dac16ee
--- /dev/null
+++ b/windows/includes/time.h
@@ -0,0 +1,32 @@
+// Copyright 2023 The Android Open Source Project
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
+
+#ifndef _AEMU_TIME_H_
+#define _AEMU_TIME_H_
+
+#include_next <time.h>
+
+#ifndef _AEMU_SYS_CDEFS_H_
+#include <sys/cdefs.h>
+#endif
+
+__BEGIN_DECLS
+
+#define 	CLOCK_MONOTONIC   1
+typedef int clockid_t;
+
+int clock_gettime(clockid_t clk_id, struct timespec *tp);
+int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
+
+__END_DECLS
+
+#endif	/* Not _AEMU_TIME_H_ */
diff --git a/windows/includes/unistd.h b/windows/includes/unistd.h
new file mode 100644
index 0000000..aca7669
--- /dev/null
+++ b/windows/includes/unistd.h
@@ -0,0 +1,188 @@
+// Copyright 2021 The Android Open Source Project
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
+// A minimal set of functions found in unistd.h
+#if !defined(_AEMU_UNISTD_H_) && !defined(_MSVC_UNISTD_H)
+#define _AEMU_UNISTD_H_
+#define _MSVC_UNISTD_H
+
+#include "compat_compiler.h"
+#include <process.h>
+
+ANDROID_BEGIN_HEADER
+
+#include <direct.h>
+#include <inttypes.h>
+#include <io.h>
+#include <stdio.h>
+#include <sys/stat.h>
+
+typedef long long ssize_t;
+typedef unsigned long long size_t;
+typedef long off_t;
+typedef int64_t off64_t;
+typedef int mode_t;
+
+#undef fstat
+#define fstat _fstat64
+
+#define lseek(a, b, c) _lseek(a, b, c)
+#define lseek64 _lseeki64
+
+/* File type and permission flags for stat(), general mask */
+#if !defined(S_IFMT)
+#define S_IFMT _S_IFMT
+#endif
+
+/* Directory bit */
+#if !defined(S_IFDIR)
+#define S_IFDIR _S_IFDIR
+#endif
+
+/* Character device bit */
+#if !defined(S_IFCHR)
+#define S_IFCHR _S_IFCHR
+#endif
+
+/* Pipe bit */
+#if !defined(S_IFFIFO)
+#define S_IFFIFO _S_IFFIFO
+#endif
+
+/* Regular file bit */
+#if !defined(S_IFREG)
+#define S_IFREG _S_IFREG
+#endif
+
+/* Read permission */
+#if !defined(S_IREAD)
+#define S_IREAD _S_IREAD
+#endif
+
+/* Write permission */
+#if !defined(S_IWRITE)
+#define S_IWRITE _S_IWRITE
+#endif
+
+/* Execute permission */
+#if !defined(S_IEXEC)
+#define S_IEXEC _S_IEXEC
+#endif
+
+/* Pipe */
+#if !defined(S_IFIFO)
+#define S_IFIFO _S_IFIFO
+#endif
+
+/* Block device */
+#if !defined(S_IFBLK)
+#define S_IFBLK 0
+#endif
+
+/* Link */
+#if !defined(S_IFLNK)
+#define S_IFLNK 0
+#endif
+
+/* Socket */
+#if !defined(S_IFSOCK)
+#define S_IFSOCK 0
+#endif
+
+/* Read user permission */
+#if !defined(S_IRUSR)
+#define S_IRUSR S_IREAD
+#endif
+
+/* Write user permission */
+#if !defined(S_IWUSR)
+#define S_IWUSR S_IWRITE
+#endif
+
+/* Execute user permission */
+#if !defined(S_IXUSR)
+#define S_IXUSR 0
+#endif
+
+/* Read group permission */
+#if !defined(S_IRGRP)
+#define S_IRGRP 0
+#endif
+
+/* Write group permission */
+#if !defined(S_IWGRP)
+#define S_IWGRP 0
+#endif
+
+/* Execute group permission */
+#if !defined(S_IXGRP)
+#define S_IXGRP 0
+#endif
+
+/* Read others permission */
+#if !defined(S_IROTH)
+#define S_IROTH 0
+#endif
+
+/* Write others permission */
+#if !defined(S_IWOTH)
+#define S_IWOTH 0
+#endif
+
+/* Execute others permission */
+#if !defined(S_IXOTH)
+#define S_IXOTH 0
+#endif
+
+/* Maximum length of file name */
+#if !defined(PATH_MAX)
+#define PATH_MAX MAX_PATH
+#endif
+#if !defined(FILENAME_MAX)
+#define FILENAME_MAX MAX_PATH
+#endif
+#if !defined(NAME_MAX)
+#define NAME_MAX FILENAME_MAX
+#endif
+
+// Define for convenience only in mingw. This is
+// convenient for the _access function in Windows.
+#if !defined(F_OK)
+#define F_OK 0 /* Check for file existence */
+#endif
+#if !defined(X_OK)
+#define X_OK 1 /* Check for execute permission (not supported in Windows) */
+#endif
+#if !defined(W_OK)
+#define W_OK 2 /* Check for write permission */
+#endif
+#if !defined(R_OK)
+#define R_OK 4 /* Check for read permission */
+#endif
+
+#define STDIN_FILENO _fileno(stdin)
+#define STDOUT_FILENO _fileno(stdout)
+#define STDERR_FILENO _fileno(stderr)
+ssize_t pread(int fd, void *buf, size_t count, off_t offset);
+
+int usleep(long usec);
+unsigned int sleep(unsigned int seconds);
+
+// Qemu will redefine this if it can.
+int _ftruncate(int fd, off_t length);
+#define ftruncate _ftruncate
+
+
+#define __try1(x) __try
+#define __except1 __except (EXCEPTION_EXECUTE_HANDLER)
+
+ANDROID_END_HEADER
+#endif	/* Not _AEMU_UNISTD_H_ */
diff --git a/windows/src/asprintf.c b/windows/src/asprintf.c
new file mode 100644
index 0000000..51ea11e
--- /dev/null
+++ b/windows/src/asprintf.c
@@ -0,0 +1,28 @@
+#include <stdlib.h>
+#include <stdio.h>
+#include <stdarg.h>
+
+// From https://msdn.microsoft.com/en-us/library/28d5ce15.aspx
+int asprintf(char** buf, const char* format, ...) {
+    va_list args;
+    int len;
+
+    if (buf == NULL) {
+        return -1;
+    }
+
+    // retrieve the variable arguments
+    va_start(args, format);
+
+    len = _vscprintf(format, args)  // _vscprintf doesn't count
+          + 1;                      // terminating '\0'
+
+    if (len <= 0) {
+        return len;
+    }
+
+    *buf = (char*)malloc(len * sizeof(char));
+
+    vsprintf(*buf, format, args);
+    return len;
+}
\ No newline at end of file
diff --git a/windows/src/dirent/README b/windows/src/dirent/README
new file mode 100644
index 0000000..e31ac1f
--- /dev/null
+++ b/windows/src/dirent/README
@@ -0,0 +1,2 @@
+This is dirent from mingw-runtime-3.3, separated for MSVC user's
+benefit.
diff --git a/windows/src/dirent/dirent.c b/windows/src/dirent/dirent.c
new file mode 100644
index 0000000..d9200f9
--- /dev/null
+++ b/windows/src/dirent/dirent.c
@@ -0,0 +1,341 @@
+/*
+ * dirent.c
+ * This file has no copyright assigned and is placed in the Public Domain.
+ * This file is a part of the mingw-runtime package.
+ * No warranty is given; refer to the file DISCLAIMER within the package.
+ *
+ * Derived from DIRLIB.C by Matt J. Weinstein
+ * This note appears in the DIRLIB.H
+ * DIRLIB.H by M. J. Weinstein   Released to public domain 1-Jan-89
+ *
+ * Updated by Jeremy Bettis <jeremy@hksys.com>
+ * Significantly revised and rewinddir, seekdir and telldir added by Colin
+ * Peters <colin@fu.is.saga-u.ac.jp>
+ *	
+ */
+
+#include <stdlib.h>
+#include <errno.h>
+#include <string.h>
+#include <io.h>
+#include <direct.h>
+
+#include "dirent.h"
+
+#define WIN32_LEAN_AND_MEAN
+#include <windows.h> /* for GetFileAttributes */
+
+#include <tchar.h>
+
+#ifdef _UNICODE
+#define _tdirent	_wdirent
+#define _TDIR 		_WDIR
+#define _topendir	_wopendir
+#define _tclosedir	_wclosedir
+#define _treaddir	_wreaddir
+#define _trewinddir	_wrewinddir
+#define _ttelldir	_wtelldir
+#define _tseekdir	_wseekdir
+#else
+#define _tdirent	dirent
+#define _TDIR 		DIR
+#define _topendir	opendir
+#define _tclosedir	closedir
+#define _treaddir	readdir
+#define _trewinddir	rewinddir
+#define _ttelldir	telldir
+#define _tseekdir	seekdir
+#endif
+
+#define SUFFIX	_T("*")
+#define	SLASH	_T("\\")
+
+
+/*
+ * opendir
+ *
+ * Returns a pointer to a DIR structure appropriately filled in to begin
+ * searching a directory.
+ */
+_TDIR *
+_topendir (const _TCHAR *szPath)
+{
+  _TDIR *nd;
+  unsigned int rc;
+  _TCHAR szFullPath[MAX_PATH];
+	
+  errno = 0;
+
+  if (!szPath)
+    {
+      errno = EFAULT;
+      return (_TDIR *) 0;
+    }
+
+  if (szPath[0] == _T('\0'))
+    {
+      errno = ENOTDIR;
+      return (_TDIR *) 0;
+    }
+
+  /* Attempt to determine if the given path really is a directory. */
+  rc = GetFileAttributes (szPath);
+  if (rc == (unsigned int)-1)
+    {
+      /* call GetLastError for more error info */
+      errno = ENOENT;
+      return (_TDIR *) 0;
+    }
+  if (!(rc & FILE_ATTRIBUTE_DIRECTORY))
+    {
+      /* Error, entry exists but not a directory. */
+      errno = ENOTDIR;
+      return (_TDIR *) 0;
+    }
+
+  /* Make an absolute pathname.  */
+  _tfullpath (szFullPath, szPath, MAX_PATH);
+
+  /* Allocate enough space to store DIR structure and the complete
+   * directory path given. */
+  nd = (_TDIR *) malloc (sizeof (_TDIR) + (_tcslen(szFullPath) + _tcslen (SLASH) +
+			 _tcslen(SUFFIX) + 1) * sizeof(_TCHAR));
+
+  if (!nd)
+    {
+      /* Error, out of memory. */
+      errno = ENOMEM;
+      return (_TDIR *) 0;
+    }
+
+  /* Create the search expression. */
+  _tcscpy (nd->dd_name, szFullPath);
+
+  /* Add on a slash if the path does not end with one. */
+  if (nd->dd_name[0] != _T('\0') &&
+      nd->dd_name[_tcslen (nd->dd_name) - 1] != _T('/') &&
+      nd->dd_name[_tcslen (nd->dd_name) - 1] != _T('\\'))
+    {
+      _tcscat (nd->dd_name, SLASH);
+    }
+
+  /* Add on the search pattern */
+  _tcscat (nd->dd_name, SUFFIX);
+
+  /* Initialize handle to -1 so that a premature closedir doesn't try
+   * to call _findclose on it. */
+  nd->dd_handle = -1;
+
+  /* Initialize the status. */
+  nd->dd_stat = 0;
+
+  /* Initialize the dirent structure. ino and reclen are invalid under
+   * Win32, and name simply points at the appropriate part of the
+   * findfirst_t structure. */
+  nd->dd_dir.d_ino = 0;
+  nd->dd_dir.d_reclen = 0;
+  nd->dd_dir.d_namlen = 0;
+  memset (nd->dd_dir.d_name, 0, sizeof (nd->dd_dir.d_name));
+
+  return nd;
+}
+
+
+/*
+ * readdir
+ *
+ * Return a pointer to a dirent structure filled with the information on the
+ * next entry in the directory.
+ */
+struct _tdirent *
+_treaddir (_TDIR * dirp)
+{
+  errno = 0;
+
+  /* Check for valid DIR struct. */
+  if (!dirp)
+    {
+      errno = EFAULT;
+      return (struct _tdirent *) 0;
+    }
+
+  if (dirp->dd_stat < 0)
+    {
+      /* We have already returned all files in the directory
+       * (or the structure has an invalid dd_stat). */
+      return (struct _tdirent *) 0;
+    }
+  else if (dirp->dd_stat == 0)
+    {
+      /* We haven't started the search yet. */
+      /* Start the search */
+      dirp->dd_handle = _tfindfirst (dirp->dd_name, &(dirp->dd_dta));
+
+  	  if (dirp->dd_handle == -1)
+	{
+	  /* Whoops! Seems there are no files in that
+	   * directory. */
+	  dirp->dd_stat = -1;
+	}
+      else
+	{
+	  dirp->dd_stat = 1;
+	}
+    }
+  else
+    {
+      /* Get the next search entry. */
+      if (_tfindnext (dirp->dd_handle, &(dirp->dd_dta)))
+	{
+	  /* We are off the end or otherwise error.	
+	     _findnext sets errno to ENOENT if no more file
+	     Undo this. */
+	  DWORD winerr = GetLastError();
+	  if (winerr == ERROR_NO_MORE_FILES)
+	    errno = 0;	
+	  _findclose (dirp->dd_handle);
+	  dirp->dd_handle = -1;
+	  dirp->dd_stat = -1;
+	}
+      else
+	{
+	  /* Update the status to indicate the correct
+	   * number. */
+	  dirp->dd_stat++;
+	}
+    }
+
+  if (dirp->dd_stat > 0)
+    {
+      /* Successfully got an entry. Everything about the file is
+       * already appropriately filled in except the length of the
+       * file name. */
+      dirp->dd_dir.d_namlen = _tcslen (dirp->dd_dta.name);
+      _tcscpy (dirp->dd_dir.d_name, dirp->dd_dta.name);
+      return &dirp->dd_dir;
+    }
+
+  return (struct _tdirent *) 0;
+}
+
+
+/*
+ * closedir
+ *
+ * Frees up resources allocated by opendir.
+ */
+int
+_tclosedir (_TDIR * dirp)
+{
+  int rc;
+
+  errno = 0;
+  rc = 0;
+
+  if (!dirp)
+    {
+      errno = EFAULT;
+      return -1;
+    }
+
+  if (dirp->dd_handle != -1)
+    {
+      rc = _findclose (dirp->dd_handle);
+    }
+
+  /* Delete the dir structure. */
+  free (dirp);
+
+  return rc;
+}
+
+/*
+ * rewinddir
+ *
+ * Return to the beginning of the directory "stream". We simply call findclose
+ * and then reset things like an opendir.
+ */
+void
+_trewinddir (_TDIR * dirp)
+{
+  errno = 0;
+
+  if (!dirp)
+    {
+      errno = EFAULT;
+      return;
+    }
+
+  if (dirp->dd_handle != -1)
+    {
+      _findclose (dirp->dd_handle);
+    }
+
+  dirp->dd_handle = -1;
+  dirp->dd_stat = 0;
+}
+
+/*
+ * telldir
+ *
+ * Returns the "position" in the "directory stream" which can be used with
+ * seekdir to go back to an old entry. We simply return the value in stat.
+ */
+long
+_ttelldir (_TDIR * dirp)
+{
+  errno = 0;
+
+  if (!dirp)
+    {
+      errno = EFAULT;
+      return -1;
+    }
+  return dirp->dd_stat;
+}
+
+/*
+ * seekdir
+ *
+ * Seek to an entry previously returned by telldir. We rewind the directory
+ * and call readdir repeatedly until either dd_stat is the position number
+ * or -1 (off the end). This is not perfect, in that the directory may
+ * have changed while we weren't looking. But that is probably the case with
+ * any such system.
+ */
+void
+_tseekdir (_TDIR * dirp, long lPos)
+{
+  errno = 0;
+
+  if (!dirp)
+    {
+      errno = EFAULT;
+      return;
+    }
+
+  if (lPos < -1)
+    {
+      /* Seeking to an invalid position. */
+      errno = EINVAL;
+      return;
+    }
+  else if (lPos == -1)
+    {
+      /* Seek past end. */
+      if (dirp->dd_handle != -1)
+	{
+	  _findclose (dirp->dd_handle);
+	}
+      dirp->dd_handle = -1;
+      dirp->dd_stat = -1;
+    }
+  else
+    {
+      /* Rewind and read forward to the appropriate index. */
+      _trewinddir (dirp);
+
+      while ((dirp->dd_stat < lPos) && _treaddir (dirp))
+	;
+    }
+}
diff --git a/windows/src/divti3.c b/windows/src/divti3.c
new file mode 100644
index 0000000..6d007fe
--- /dev/null
+++ b/windows/src/divti3.c
@@ -0,0 +1,29 @@
+//===-- divti3.c - Implement __divti3 -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file implements __divti3 for the compiler_rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#include "int_lib.h"
+
+#ifdef CRT_HAS_128BIT
+
+// Returns: a / b
+
+COMPILER_RT_ABI ti_int __divti3(ti_int a, ti_int b) {
+  const int bits_in_tword_m1 = (int)(sizeof(ti_int) * CHAR_BIT) - 1;
+  ti_int s_a = a >> bits_in_tword_m1;                   // s_a = a < 0 ? -1 : 0
+  ti_int s_b = b >> bits_in_tword_m1;                   // s_b = b < 0 ? -1 : 0
+  a = (a ^ s_a) - s_a;                                  // negate if s_a == -1
+  b = (b ^ s_b) - s_b;                                  // negate if s_b == -1
+  s_a ^= s_b;                                           // sign of quotient
+  return (__udivmodti4(a, b, (tu_int *)0) ^ s_a) - s_a; // negate if s_a == -1
+}
+
+#endif // CRT_HAS_128BIT
diff --git a/windows/src/files.cpp b/windows/src/files.cpp
new file mode 100644
index 0000000..cc817a2
--- /dev/null
+++ b/windows/src/files.cpp
@@ -0,0 +1,121 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+#include <Windows.h>
+#include <fcntl.h>
+#include <io.h>
+#include <stdio.h>
+#include <string.h>
+
+#include <cerrno>
+#include <cstdio>
+#include <cstring>
+#include <iostream>
+
+#include "compat_compiler.h"
+
+ANDROID_BEGIN_HEADER
+
+int _ftruncate(int fd, int64_t length) {
+    LARGE_INTEGER li;
+    DWORD dw;
+    LONG high;
+    HANDLE h;
+    BOOL res;
+
+    if ((GetVersion() & 0x80000000UL) && (length >> 32) != 0) return -1;
+
+    h = (HANDLE)_get_osfhandle(fd);
+
+    /* get current position, ftruncate do not change position */
+    li.HighPart = 0;
+    li.LowPart = SetFilePointer(h, 0, &li.HighPart, FILE_CURRENT);
+    if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
+        return -1;
+    }
+
+    high = length >> 32;
+    dw = SetFilePointer(h, (DWORD)length, &high, FILE_BEGIN);
+    if (dw == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
+        return -1;
+    }
+    res = SetEndOfFile(h);
+
+    /* back to old position */
+    SetFilePointer(h, li.LowPart, &li.HighPart, FILE_BEGIN);
+    return res ? 0 : -1;
+}
+
+int mkstemp(char* tmplate) {
+    // Check if the tmplate string is null or doesn't end with "XXXXXX"
+    if (tmplate == nullptr || std::strlen(tmplate) < 6 ||
+        std::strcmp(tmplate + std::strlen(tmplate) - 6, "XXXXXX") != 0) {
+        errno = EINVAL;  // Invalid argument
+        return -1;
+    }
+
+    // Generate a unique filename
+    if (_mktemp_s(tmplate, std::strlen(tmplate) + 1) != 0) {
+        errno = EIO;  // I/O error
+        return -1;
+    }
+
+    // Open the file with read and write access
+    int fd;
+    if (_sopen_s(&fd, tmplate, _O_RDWR | _O_CREAT | _O_EXCL, _SH_DENYNO, _S_IREAD | _S_IWRITE) !=
+        0) {
+        return -1;
+    }
+
+    return fd;
+}
+
+int mkostemp(char* tmplate, int flags) {
+    // Use mkstemp for Windows as it doesn't have all the flags like O_APPEND or O_SYNC
+    return mkstemp(tmplate);
+}
+
+int mkstemps(char* tmplate, int suffixlen) {
+    // Check if the tmplate string is null or doesn't end with "XXXXXX"
+    if (tmplate == nullptr || std::strlen(tmplate) < 6 ||
+        std::strcmp(tmplate + std::strlen(tmplate) - 6, "XXXXXX") != 0) {
+        errno = EINVAL;  // Invalid argument
+        return -1;
+    }
+
+    // Generate a unique filename
+    if (_mktemp_s(tmplate, std::strlen(tmplate) + 1) != 0) {
+        errno = EIO;  // I/O error
+        return -1;
+    }
+
+    // Add the suffix to the tmplate
+    std::strncat(tmplate, "suffix", suffixlen);
+
+    // Open the file with read and write access
+    int fd;
+    if (_sopen_s(&fd, tmplate, _O_RDWR | _O_CREAT | _O_EXCL, _SH_DENYNO, _S_IREAD | _S_IWRITE) !=
+        0) {
+        return -1;
+    }
+
+    return fd;
+}
+
+int mkostemps(char* tmplate, int suffixlen, int flags) {
+    // Use mkstemps for Windows as it doesn't have all the flags like O_APPEND or O_SYNC
+    return mkstemps(tmplate, suffixlen);
+}
+
+ANDROID_END_HEADER
\ No newline at end of file
diff --git a/windows/src/getopt.c b/windows/src/getopt.c
new file mode 100644
index 0000000..4edb16d
--- /dev/null
+++ b/windows/src/getopt.c
@@ -0,0 +1,525 @@
+/*	$OpenBSD: getopt_long.c,v 1.23 2007/10/31 12:34:57 chl Exp $	*/
+/*	$NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $	*/
+
+/*
+ * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
+ *
+ * Permission to use, copy, modify, and distribute this software for any
+ * purpose with or without fee is hereby granted, provided that the above
+ * copyright notice and this permission notice appear in all copies.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
+ * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
+ * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
+ * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
+ * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
+ * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
+ * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
+ *
+ * Sponsored in part by the Defense Advanced Research Projects
+ * Agency (DARPA) and Air Force Research Laboratory, Air Force
+ * Materiel Command, USAF, under agreement number F39502-99-1-0512.
+ */
+/*-
+ * Copyright (c) 2000 The NetBSD Foundation, Inc.
+ * All rights reserved.
+ *
+ * This code is derived from software contributed to The NetBSD Foundation
+ * by Dieter Baron and Thomas Klausner.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ * 1. Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ * 2. Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in the
+ *    documentation and/or other materials provided with the distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
+ * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
+ * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
+ * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
+ * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ * POSSIBILITY OF SUCH DAMAGE.
+ */
+#include "getopt.h"
+
+#include <errno.h>
+#include <stdarg.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <windows.h>
+
+int opterr = 1;   /* if error message should be printed */
+int optind = 1;   /* index into parent argv vector */
+int optopt = '?'; /* character checked for validity */
+char* optarg;     /* argument associated with option */
+
+#define PRINT_ERROR ((opterr) && (*options != ':'))
+
+#define FLAG_PERMUTE 0x01  /* permute non-options to the end of argv */
+#define FLAG_ALLARGS 0x02  /* treat non-options as args to option "-1" */
+#define FLAG_LONGONLY 0x04 /* operate as getopt_long_only */
+
+/* return values */
+#define BADCH (int)'?'
+#define BADARG ((*options == ':') ? (int)':' : (int)'?')
+#define INORDER (int)1
+
+#define __progname __argv[0]
+#define EMSG ""
+
+static int getopt_internal(int,
+                           char* const*,
+                           const char*,
+                           const struct option*,
+                           int*,
+                           int);
+static int parse_long_options(char* const*,
+                              const char*,
+                              const struct option*,
+                              int*,
+                              int);
+static int gcd(int, int);
+static void permute_args(int, int, int, char* const*);
+
+static char* place = EMSG; /* option letter processing */
+
+static int nonopt_start = -1; /* first non option argument (for permute) */
+static int nonopt_end = -1;   /* first option after non options (for permute) */
+
+/* Error messages */
+static const char recargchar[] = "option requires an argument -- %c";
+static const char recargstring[] = "option requires an argument -- %s";
+static const char ambig[] = "ambiguous option -- %.*s";
+static const char noarg[] = "option doesn't take an argument -- %.*s";
+static const char illoptchar[] = "unknown option -- %c";
+static const char illoptstring[] = "unknown option -- %s";
+
+static void _vwarnx(const char* fmt, va_list ap) {
+    (void)fprintf(stderr, "%s: ", __progname);
+    if (fmt != NULL)
+        (void)vfprintf(stderr, fmt, ap);
+    (void)fprintf(stderr, "\n");
+}
+
+static void warnx(const char* fmt, ...) {
+    va_list ap;
+    va_start(ap, fmt);
+    _vwarnx(fmt, ap);
+    va_end(ap);
+}
+
+/*
+ * Compute the greatest common divisor of a and b.
+ */
+static int gcd(int a, int b) {
+    int c;
+
+    c = a % b;
+    while (c != 0) {
+        a = b;
+        b = c;
+        c = a % b;
+    }
+
+    return (b);
+}
+
+/*
+ * Exchange the block from nonopt_start to nonopt_end with the block
+ * from nonopt_end to opt_end (keeping the same order of arguments
+ * in each block).
+ */
+static void permute_args(int panonopt_start,
+                         int panonopt_end,
+                         int opt_end,
+                         char* const* nargv) {
+    int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
+    char* swap;
+
+    /*
+     * compute lengths of blocks and number and size of cycles
+     */
+    nnonopts = panonopt_end - panonopt_start;
+    nopts = opt_end - panonopt_end;
+    ncycle = gcd(nnonopts, nopts);
+    cyclelen = (opt_end - panonopt_start) / ncycle;
+
+    for (i = 0; i < ncycle; i++) {
+        cstart = panonopt_end + i;
+        pos = cstart;
+        for (j = 0; j < cyclelen; j++) {
+            if (pos >= panonopt_end)
+                pos -= nnonopts;
+            else
+                pos += nopts;
+            swap = nargv[pos];
+            /* LINTED const cast */
+            ((char**)nargv)[pos] = nargv[cstart];
+            /* LINTED const cast */
+            ((char**)nargv)[cstart] = swap;
+        }
+    }
+}
+
+/*
+ * parse_long_options --
+ *	Parse long options in argc/argv argument vector.
+ * Returns -1 if short_too is set and the option does not match long_options.
+ */
+static int parse_long_options(char* const* nargv,
+                              const char* options,
+                              const struct option* long_options,
+                              int* idx,
+                              int short_too) {
+    char *current_argv, *has_equal;
+    size_t current_argv_len;
+    int i, ambiguous, match;
+
+#define IDENTICAL_INTERPRETATION(_x, _y)                         \
+    (long_options[(_x)].has_arg == long_options[(_y)].has_arg && \
+     long_options[(_x)].flag == long_options[(_y)].flag &&       \
+     long_options[(_x)].val == long_options[(_y)].val)
+
+    current_argv = place;
+    match = -1;
+    ambiguous = 0;
+
+    optind++;
+
+    if ((has_equal = strchr(current_argv, '=')) != NULL) {
+        /* argument found (--option=arg) */
+        current_argv_len = has_equal - current_argv;
+        has_equal++;
+    } else
+        current_argv_len = strlen(current_argv);
+
+    for (i = 0; long_options[i].name; i++) {
+        /* find matching long option */
+        if (strncmp(current_argv, long_options[i].name, current_argv_len))
+            continue;
+
+        if (strlen(long_options[i].name) == current_argv_len) {
+            /* exact match */
+            match = i;
+            ambiguous = 0;
+            break;
+        }
+        /*
+         * If this is a known short option, don't allow
+         * a partial match of a single character.
+         */
+        if (short_too && current_argv_len == 1)
+            continue;
+
+        if (match == -1) /* partial match */
+            match = i;
+        else if (!IDENTICAL_INTERPRETATION(i, match))
+            ambiguous = 1;
+    }
+    if (ambiguous) {
+        /* ambiguous abbreviation */
+        if (PRINT_ERROR)
+            warnx(ambig, (int)current_argv_len, current_argv);
+        optopt = 0;
+        return (BADCH);
+    }
+    if (match != -1) { /* option found */
+        if (long_options[match].has_arg == no_argument && has_equal) {
+            if (PRINT_ERROR)
+                warnx(noarg, (int)current_argv_len, current_argv);
+            /*
+             * XXX: GNU sets optopt to val regardless of flag
+             */
+            if (long_options[match].flag == NULL)
+                optopt = long_options[match].val;
+            else
+                optopt = 0;
+            return (BADARG);
+        }
+        if (long_options[match].has_arg == required_argument ||
+            long_options[match].has_arg == optional_argument) {
+            if (has_equal)
+                optarg = has_equal;
+            else if (long_options[match].has_arg == required_argument) {
+                /*
+                 * optional argument doesn't use next nargv
+                 */
+                optarg = nargv[optind++];
+            }
+        }
+        if ((long_options[match].has_arg == required_argument) &&
+            (optarg == NULL)) {
+            /*
+             * Missing argument; leading ':' indicates no error
+             * should be generated.
+             */
+            if (PRINT_ERROR)
+                warnx(recargstring, current_argv);
+            /*
+             * XXX: GNU sets optopt to val regardless of flag
+             */
+            if (long_options[match].flag == NULL)
+                optopt = long_options[match].val;
+            else
+                optopt = 0;
+            --optind;
+            return (BADARG);
+        }
+    } else { /* unknown option */
+        if (short_too) {
+            --optind;
+            return (-1);
+        }
+        if (PRINT_ERROR)
+            warnx(illoptstring, current_argv);
+        optopt = 0;
+        return (BADCH);
+    }
+    if (idx)
+        *idx = match;
+    if (long_options[match].flag) {
+        *long_options[match].flag = long_options[match].val;
+        return (0);
+    } else
+        return (long_options[match].val);
+#undef IDENTICAL_INTERPRETATION
+}
+
+/*
+ * getopt_internal --
+ *	Parse argc/argv argument vector.  Called by user level routines.
+ */
+static int getopt_internal(int nargc,
+                           char* const* nargv,
+                           const char* options,
+                           const struct option* long_options,
+                           int* idx,
+                           int flags) {
+    char* oli; /* option letter list index */
+    int optchar, short_too;
+    static int posixly_correct = -1;
+
+    if (options == NULL)
+        return (-1);
+
+    if (optind == 0)
+        optind = 1;
+
+    /*
+     * Disable GNU extensions if POSIXLY_CORRECT is set or options
+     * string begins with a '+'.
+     *
+     * CV, 2009-12-14: Check POSIXLY_CORRECT anew if optind == 0 or
+     *                 optreset != 0 for GNU compatibility.
+     */
+    if (posixly_correct == -1)
+        posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
+    if (*options == '-')
+        flags |= FLAG_ALLARGS;
+    else if (posixly_correct || *options == '+')
+        flags &= ~FLAG_PERMUTE;
+    if (*options == '+' || *options == '-')
+        options++;
+
+    optarg = NULL;
+start:
+    if (!*place) {             /* update scanning pointer */
+        if (optind >= nargc) { /* end of argument vector */
+            place = EMSG;
+            if (nonopt_end != -1) {
+                /* do permutation, if we have to */
+                permute_args(nonopt_start, nonopt_end, optind, nargv);
+                optind -= nonopt_end - nonopt_start;
+            } else if (nonopt_start != -1) {
+                /*
+                 * If we skipped non-options, set optind
+                 * to the first of them.
+                 */
+                optind = nonopt_start;
+            }
+            nonopt_start = nonopt_end = -1;
+            return (-1);
+        }
+        if (*(place = nargv[optind]) != '-' ||
+            (place[1] == '\0' && strchr(options, '-') == NULL)) {
+            place = EMSG; /* found non-option */
+            if (flags & FLAG_ALLARGS) {
+                /*
+                 * GNU extension:
+                 * return non-option as argument to option 1
+                 */
+                optarg = nargv[optind++];
+                return (INORDER);
+            }
+            if (!(flags & FLAG_PERMUTE)) {
+                /*
+                 * If no permutation wanted, stop parsing
+                 * at first non-option.
+                 */
+                return (-1);
+            }
+            /* do permutation */
+            if (nonopt_start == -1)
+                nonopt_start = optind;
+            else if (nonopt_end != -1) {
+                permute_args(nonopt_start, nonopt_end, optind, nargv);
+                nonopt_start = optind - (nonopt_end - nonopt_start);
+                nonopt_end = -1;
+            }
+            optind++;
+            /* process next argument */
+            goto start;
+        }
+        if (nonopt_start != -1 && nonopt_end == -1)
+            nonopt_end = optind;
+
+        /*
+         * If we have "-" do nothing, if "--" we are done.
+         */
+        if (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
+            optind++;
+            place = EMSG;
+            /*
+             * We found an option (--), so if we skipped
+             * non-options, we have to permute.
+             */
+            if (nonopt_end != -1) {
+                permute_args(nonopt_start, nonopt_end, optind, nargv);
+                optind -= nonopt_end - nonopt_start;
+            }
+            nonopt_start = nonopt_end = -1;
+            return (-1);
+        }
+    }
+
+    /*
+     * Check long options if:
+     *  1) we were passed some
+     *  2) the arg is not just "-"
+     *  3) either the arg starts with -- we are getopt_long_only()
+     */
+    if (long_options != NULL && place != nargv[optind] &&
+        (*place == '-' || (flags & FLAG_LONGONLY))) {
+        short_too = 0;
+        if (*place == '-')
+            place++; /* --foo long option */
+        else if (*place != ':' && strchr(options, *place) != NULL)
+            short_too = 1; /* could be short option too */
+
+        optchar = parse_long_options(nargv, options, long_options, idx,
+                                     short_too);
+        if (optchar != -1) {
+            place = EMSG;
+            return (optchar);
+        }
+    }
+
+    if ((optchar = (int)*place++) == (int)':' ||
+        (optchar == (int)'-' && *place != '\0') ||
+        (oli = strchr(options, optchar)) == NULL) {
+        /*
+         * If the user specified "-" and  '-' isn't listed in
+         * options, return -1 (non-option) as per POSIX.
+         * Otherwise, it is an unknown option character (or ':').
+         */
+        if (optchar == (int)'-' && *place == '\0')
+            return (-1);
+        if (!*place)
+            ++optind;
+        if (PRINT_ERROR)
+            warnx(illoptchar, optchar);
+        optopt = optchar;
+        return (BADCH);
+    }
+    if (long_options != NULL && optchar == 'W' && oli[1] == ';') {
+        /* -W long-option */
+        if (*place) /* no space */
+            /* NOTHING */;
+        else if (++optind >= nargc) { /* no arg */
+            place = EMSG;
+            if (PRINT_ERROR)
+                warnx(recargchar, optchar);
+            optopt = optchar;
+            return (BADARG);
+        } else /* white space */
+            place = nargv[optind];
+        optchar = parse_long_options(nargv, options, long_options, idx, 0);
+        place = EMSG;
+        return (optchar);
+    }
+    if (*++oli != ':') { /* doesn't take argument */
+        if (!*place)
+            ++optind;
+    } else { /* takes (optional) argument */
+        optarg = NULL;
+        if (*place) /* no white space */
+            optarg = place;
+        else if (oli[1] != ':') {    /* arg not optional */
+            if (++optind >= nargc) { /* no arg */
+                place = EMSG;
+                if (PRINT_ERROR)
+                    warnx(recargchar, optchar);
+                optopt = optchar;
+                return (BADARG);
+            } else
+                optarg = nargv[optind];
+        }
+        place = EMSG;
+        ++optind;
+    }
+    /* dump back option letter */
+    return (optchar);
+}
+
+/*
+ * getopt --
+ *	Parse argc/argv argument vector.
+ *
+ * [eventually this will replace the BSD getopt]
+ */
+int getopt(int nargc, char* const* nargv, const char* options) {
+    /*
+     * We don't pass FLAG_PERMUTE to getopt_internal() since
+     * the BSD getopt(3) (unlike GNU) has never done this.
+     *
+     * Furthermore, since many privileged programs call getopt()
+     * before dropping privileges it makes sense to keep things
+     * as simple (and bug-free) as possible.
+     */
+    return (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
+}
+
+/*
+ * getopt_long --
+ *	Parse argc/argv argument vector.
+ */
+int getopt_long(int nargc,
+                char* const* nargv,
+                const char* options,
+                const struct option* long_options,
+                int* idx) {
+    return (getopt_internal(nargc, nargv, options, long_options, idx,
+                            FLAG_PERMUTE));
+}
+
+/*
+ * getopt_long_only --
+ *	Parse argc/argv argument vector.
+ */
+int getopt_long_only(int nargc,
+                     char* const* nargv,
+                     const char* options,
+                     const struct option* long_options,
+                     int* idx) {
+    return (getopt_internal(nargc, nargv, options, long_options, idx,
+                            FLAG_PERMUTE | FLAG_LONGONLY));
+}
diff --git a/windows/src/int_endianness.h b/windows/src/int_endianness.h
new file mode 100644
index 0000000..def046c
--- /dev/null
+++ b/windows/src/int_endianness.h
@@ -0,0 +1,114 @@
+//===-- int_endianness.h - configuration header for compiler-rt -----------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file is a configuration header for compiler-rt.
+// This file is not part of the interface of this library.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef INT_ENDIANNESS_H
+#define INT_ENDIANNESS_H
+
+#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                \
+    defined(__ORDER_LITTLE_ENDIAN__)
+
+// Clang and GCC provide built-in endianness definitions.
+#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
+#define _YUGA_LITTLE_ENDIAN 0
+#define _YUGA_BIG_ENDIAN 1
+#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+#endif // __BYTE_ORDER__
+
+#else // Compilers other than Clang or GCC.
+
+#if defined(__SVR4) && defined(__sun)
+#include <sys/byteorder.h>
+
+#if defined(_BIG_ENDIAN)
+#define _YUGA_LITTLE_ENDIAN 0
+#define _YUGA_BIG_ENDIAN 1
+#elif defined(_LITTLE_ENDIAN)
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+#else // !_LITTLE_ENDIAN
+#error "unknown endianness"
+#endif // !_LITTLE_ENDIAN
+
+#endif // Solaris and AuroraUX.
+
+// ..
+
+#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) ||   \
+    defined(__minix)
+#include <sys/endian.h>
+
+#if _BYTE_ORDER == _BIG_ENDIAN
+#define _YUGA_LITTLE_ENDIAN 0
+#define _YUGA_BIG_ENDIAN 1
+#elif _BYTE_ORDER == _LITTLE_ENDIAN
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+#endif // _BYTE_ORDER
+
+#endif // *BSD
+
+#if defined(__OpenBSD__)
+#include <machine/endian.h>
+
+#if _BYTE_ORDER == _BIG_ENDIAN
+#define _YUGA_LITTLE_ENDIAN 0
+#define _YUGA_BIG_ENDIAN 1
+#elif _BYTE_ORDER == _LITTLE_ENDIAN
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+#endif // _BYTE_ORDER
+
+#endif // OpenBSD
+
+// ..
+
+// Mac OSX has __BIG_ENDIAN__ or __LITTLE_ENDIAN__ automatically set by the
+// compiler (at least with GCC)
+#if defined(__APPLE__) || defined(__ellcc__)
+
+#ifdef __BIG_ENDIAN__
+#if __BIG_ENDIAN__
+#define _YUGA_LITTLE_ENDIAN 0
+#define _YUGA_BIG_ENDIAN 1
+#endif
+#endif // __BIG_ENDIAN__
+
+#ifdef __LITTLE_ENDIAN__
+#if __LITTLE_ENDIAN__
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+#endif
+#endif // __LITTLE_ENDIAN__
+
+#endif // Mac OSX
+
+// ..
+
+#if defined(_WIN32)
+
+#define _YUGA_LITTLE_ENDIAN 1
+#define _YUGA_BIG_ENDIAN 0
+
+#endif // Windows
+
+#endif // Clang or GCC.
+
+// .
+
+#if !defined(_YUGA_LITTLE_ENDIAN) || !defined(_YUGA_BIG_ENDIAN)
+#error Unable to determine endian
+#endif // Check we found an endianness correctly.
+
+#endif // INT_ENDIANNESS_H
diff --git a/windows/src/int_lib.h b/windows/src/int_lib.h
new file mode 100644
index 0000000..f5df77d
--- /dev/null
+++ b/windows/src/int_lib.h
@@ -0,0 +1,141 @@
+//===-- int_lib.h - configuration header for compiler-rt  -----------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file is a configuration header for compiler-rt.
+// This file is not part of the interface of this library.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef INT_LIB_H
+#define INT_LIB_H
+
+// Assumption: Signed integral is 2's complement.
+// Assumption: Right shift of signed negative is arithmetic shift.
+// Assumption: Endianness is little or big (not mixed).
+
+// ABI macro definitions
+
+#if __ARM_EABI__
+#ifdef COMPILER_RT_ARMHF_TARGET
+#define COMPILER_RT_ABI
+#else
+#define COMPILER_RT_ABI __attribute__((__pcs__("aapcs")))
+#endif
+#else
+#define COMPILER_RT_ABI
+#endif
+
+#define AEABI_RTABI __attribute__((__pcs__("aapcs")))
+
+#if defined(_MSC_VER) && !defined(__clang__)
+#define ALWAYS_INLINE __forceinline
+#define NOINLINE __declspec(noinline)
+#define NORETURN __declspec(noreturn)
+#define UNUSED
+#else
+#define ALWAYS_INLINE __attribute__((always_inline))
+#define NOINLINE __attribute__((noinline))
+#define NORETURN __attribute__((noreturn))
+#define UNUSED __attribute__((unused))
+#endif
+
+#define STR(a) #a
+#define XSTR(a) STR(a)
+#define SYMBOL_NAME(name) XSTR(__USER_LABEL_PREFIX__) #name
+
+#if defined(__ELF__) || defined(__MINGW32__) || defined(__wasm__)
+#define COMPILER_RT_ALIAS(name, aliasname) \
+  COMPILER_RT_ABI __typeof(name) aliasname __attribute__((__alias__(#name)));
+#elif defined(__APPLE__)
+#define COMPILER_RT_ALIAS(name, aliasname) \
+  __asm__(".globl " SYMBOL_NAME(aliasname)); \
+  __asm__(SYMBOL_NAME(aliasname) " = " SYMBOL_NAME(name)); \
+  COMPILER_RT_ABI __typeof(name) aliasname;
+#elif defined(_WIN32)
+#define COMPILER_RT_ALIAS(name, aliasname)
+#else
+#error Unsupported target
+#endif
+
+#if defined(__NetBSD__) && (defined(_KERNEL) || defined(_STANDALONE))
+//
+// Kernel and boot environment can't use normal headers,
+// so use the equivalent system headers.
+//
+#include <machine/limits.h>
+#include <sys/stdint.h>
+#include <sys/types.h>
+#else
+// Include the standard compiler builtin headers we use functionality from.
+#include <float.h>
+#include <limits.h>
+#include <stdbool.h>
+#include <stdint.h>
+#endif
+
+// Include the commonly used internal type definitions.
+#include "int_types.h"
+
+// Include internal utility function declarations.
+#include "int_util.h"
+
+COMPILER_RT_ABI si_int __paritysi2(si_int a);
+COMPILER_RT_ABI si_int __paritydi2(di_int a);
+
+COMPILER_RT_ABI di_int __divdi3(di_int a, di_int b);
+COMPILER_RT_ABI si_int __divsi3(si_int a, si_int b);
+COMPILER_RT_ABI su_int __udivsi3(su_int n, su_int d);
+
+COMPILER_RT_ABI su_int __udivmodsi4(su_int a, su_int b, su_int *rem);
+COMPILER_RT_ABI du_int __udivmoddi4(du_int a, du_int b, du_int *rem);
+#ifdef CRT_HAS_128BIT
+COMPILER_RT_ABI si_int __clzti2(ti_int a);
+COMPILER_RT_ABI tu_int __udivmodti4(tu_int a, tu_int b, tu_int *rem);
+#endif
+
+// Definitions for builtins unavailable on MSVC
+#if defined(_MSC_VER) && !defined(__clang__)
+#include <intrin.h>
+
+uint32_t __inline __builtin_ctz(uint32_t value) {
+  unsigned long trailing_zero = 0;
+  if (_BitScanForward(&trailing_zero, value))
+    return trailing_zero;
+  return 32;
+}
+
+uint32_t __inline __builtin_clz(uint32_t value) {
+  unsigned long leading_zero = 0;
+  if (_BitScanReverse(&leading_zero, value))
+    return 31 - leading_zero;
+  return 32;
+}
+
+#if defined(_M_ARM) || defined(_M_X64)
+uint32_t __inline __builtin_clzll(uint64_t value) {
+  unsigned long leading_zero = 0;
+  if (_BitScanReverse64(&leading_zero, value))
+    return 63 - leading_zero;
+  return 64;
+}
+#else
+uint32_t __inline __builtin_clzll(uint64_t value) {
+  if (value == 0)
+    return 64;
+  uint32_t msh = (uint32_t)(value >> 32);
+  uint32_t lsh = (uint32_t)(value & 0xFFFFFFFF);
+  if (msh != 0)
+    return __builtin_clz(msh);
+  return 32 + __builtin_clz(lsh);
+}
+#endif
+
+#define __builtin_clzl __builtin_clzll
+#endif // defined(_MSC_VER) && !defined(__clang__)
+
+#endif // INT_LIB_H
\ No newline at end of file
diff --git a/windows/src/int_types.h b/windows/src/int_types.h
new file mode 100644
index 0000000..f89220d
--- /dev/null
+++ b/windows/src/int_types.h
@@ -0,0 +1,174 @@
+//===-- int_lib.h - configuration header for compiler-rt  -----------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file is not part of the interface of this library.
+//
+// This file defines various standard types, most importantly a number of unions
+// used to access parts of larger types.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef INT_TYPES_H
+#define INT_TYPES_H
+
+#include "int_endianness.h"
+
+// si_int is defined in Linux sysroot's asm-generic/siginfo.h
+#ifdef si_int
+#undef si_int
+#endif
+typedef int si_int;
+typedef unsigned su_int;
+
+typedef long long di_int;
+typedef unsigned long long du_int;
+
+typedef union {
+  di_int all;
+  struct {
+#if _YUGA_LITTLE_ENDIAN
+    su_int low;
+    si_int high;
+#else
+    si_int high;
+    su_int low;
+#endif // _YUGA_LITTLE_ENDIAN
+  } s;
+} dwords;
+
+typedef union {
+  du_int all;
+  struct {
+#if _YUGA_LITTLE_ENDIAN
+    su_int low;
+    su_int high;
+#else
+    su_int high;
+    su_int low;
+#endif // _YUGA_LITTLE_ENDIAN
+  } s;
+} udwords;
+
+#if defined(__LP64__) || defined(__wasm__) || defined(__mips64) ||             \
+    defined(__riscv) || defined(_WIN64)
+#define CRT_HAS_128BIT
+#endif
+
+// MSVC doesn't have a working 128bit integer type. Users should really compile
+// compiler-rt with clang, but if they happen to be doing a standalone build for
+// asan or something else, disable the 128 bit parts so things sort of work.
+#if defined(_MSC_VER) && !defined(__clang__)
+#undef CRT_HAS_128BIT
+#endif
+
+#ifdef CRT_HAS_128BIT
+typedef int ti_int __attribute__((mode(TI)));
+typedef unsigned tu_int __attribute__((mode(TI)));
+
+typedef union {
+  ti_int all;
+  struct {
+#if _YUGA_LITTLE_ENDIAN
+    du_int low;
+    di_int high;
+#else
+    di_int high;
+    du_int low;
+#endif // _YUGA_LITTLE_ENDIAN
+  } s;
+} twords;
+
+typedef union {
+  tu_int all;
+  struct {
+#if _YUGA_LITTLE_ENDIAN
+    du_int low;
+    du_int high;
+#else
+    du_int high;
+    du_int low;
+#endif // _YUGA_LITTLE_ENDIAN
+  } s;
+} utwords;
+
+static __inline ti_int make_ti(di_int h, di_int l) {
+  twords r;
+  r.s.high = h;
+  r.s.low = l;
+  return r.all;
+}
+
+static __inline tu_int make_tu(du_int h, du_int l) {
+  utwords r;
+  r.s.high = h;
+  r.s.low = l;
+  return r.all;
+}
+
+#endif // CRT_HAS_128BIT
+
+typedef union {
+  su_int u;
+  float f;
+} float_bits;
+
+typedef union {
+  udwords u;
+  double f;
+} double_bits;
+
+typedef struct {
+#if _YUGA_LITTLE_ENDIAN
+  udwords low;
+  udwords high;
+#else
+  udwords high;
+  udwords low;
+#endif // _YUGA_LITTLE_ENDIAN
+} uqwords;
+
+// Check if the target supports 80 bit extended precision long doubles.
+// Notably, on x86 Windows, MSVC only provides a 64-bit long double, but GCC
+// still makes it 80 bits. Clang will match whatever compiler it is trying to
+// be compatible with.
+#if ((defined(__i386__) || defined(__x86_64__)) && !defined(_MSC_VER)) ||      \
+    defined(__m68k__) || defined(__ia64__)
+#define HAS_80_BIT_LONG_DOUBLE 1
+#else
+#define HAS_80_BIT_LONG_DOUBLE 0
+#endif
+
+typedef union {
+  uqwords u;
+  long double f;
+} long_double_bits;
+
+#if __STDC_VERSION__ >= 199901L
+typedef float _Complex Fcomplex;
+typedef double _Complex Dcomplex;
+typedef long double _Complex Lcomplex;
+
+#define COMPLEX_REAL(x) __real__(x)
+#define COMPLEX_IMAGINARY(x) __imag__(x)
+#else
+typedef struct {
+  float real, imaginary;
+} Fcomplex;
+
+typedef struct {
+  double real, imaginary;
+} Dcomplex;
+
+typedef struct {
+  long double real, imaginary;
+} Lcomplex;
+
+#define COMPLEX_REAL(x) (x).real
+#define COMPLEX_IMAGINARY(x) (x).imaginary
+#endif
+#endif // INT_TYPES_H
diff --git a/windows/src/int_util.h b/windows/src/int_util.h
new file mode 100644
index 0000000..5fbdfb5
--- /dev/null
+++ b/windows/src/int_util.h
@@ -0,0 +1,31 @@
+//===-- int_util.h - internal utility functions ---------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file is not part of the interface of this library.
+//
+// This file defines non-inline utilities which are available for use in the
+// library. The function definitions themselves are all contained in int_util.c
+// which will always be compiled into any compiler-rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef INT_UTIL_H
+#define INT_UTIL_H
+
+/// \brief Trigger a program abort (or panic for kernel code).
+#define compilerrt_abort() __compilerrt_abort_impl(__FILE__, __LINE__, __func__)
+
+NORETURN void __compilerrt_abort_impl(const char *file, int line,
+                                      const char *function);
+
+#define COMPILE_TIME_ASSERT(expr) COMPILE_TIME_ASSERT1(expr, __COUNTER__)
+#define COMPILE_TIME_ASSERT1(expr, cnt) COMPILE_TIME_ASSERT2(expr, cnt)
+#define COMPILE_TIME_ASSERT2(expr, cnt)                                        \
+  typedef char ct_assert_##cnt[(expr) ? 1 : -1] UNUSED
+
+#endif // INT_UTIL_H
diff --git a/windows/src/modti3.c b/windows/src/modti3.c
new file mode 100644
index 0000000..660899d
--- /dev/null
+++ b/windows/src/modti3.c
@@ -0,0 +1,30 @@
+//===-- modti3.c - Implement __modti3 -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file implements __modti3 for the compiler_rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#include "int_lib.h"
+
+#ifdef CRT_HAS_128BIT
+
+// Returns: a % b
+
+COMPILER_RT_ABI ti_int __modti3(ti_int a, ti_int b) {
+  const int bits_in_tword_m1 = (int)(sizeof(ti_int) * CHAR_BIT) - 1;
+  ti_int s = b >> bits_in_tword_m1; // s = b < 0 ? -1 : 0
+  b = (b ^ s) - s;                  // negate if s == -1
+  s = a >> bits_in_tword_m1;        // s = a < 0 ? -1 : 0
+  a = (a ^ s) - s;                  // negate if s == -1
+  tu_int r;
+  __udivmodti4(a, b, &r);
+  return ((ti_int)r ^ s) - s; // negate if s == -1
+}
+
+#endif // CRT_HAS_128BIT
\ No newline at end of file
diff --git a/windows/src/msvc-posix.c b/windows/src/msvc-posix.c
new file mode 100644
index 0000000..bc03447
--- /dev/null
+++ b/windows/src/msvc-posix.c
@@ -0,0 +1,38 @@
+// Copyright 2018 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#include <io.h>
+
+#include <stdio.h>
+#include <stdlib.h>
+
+
+// From https://msdn.microsoft.com/en-us/library/28d5ce15.aspx
+int vasprintf(char** buf, const char* format, va_list args) {
+    int len;
+
+    if (buf == NULL) {
+        return -1;
+    }
+
+    len = _vscprintf(format, args)  // _vscprintf doesn't count
+          + 1;                      // terminating '\0'
+
+    if (len <= 0) {
+        return len;
+    }
+
+    *buf = (char*)malloc(len * sizeof(char));
+
+    vsprintf(*buf, format, args);  // C4996
+    // Note: vsprintf is deprecated; consider using vsprintf_s instead
+    return len;
+}
+
diff --git a/windows/src/pread.cpp b/windows/src/pread.cpp
new file mode 100644
index 0000000..15fad8b
--- /dev/null
+++ b/windows/src/pread.cpp
@@ -0,0 +1,51 @@
+// Copyright 2018 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#include <io.h>
+#include <share.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <unistd.h>
+#include <windows.h>
+
+ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
+    if (fd < 0) {
+        errno = EINVAL;
+        return -1;
+    }
+    auto handle = (HANDLE)_get_osfhandle(fd);
+    if (handle == INVALID_HANDLE_VALUE) {
+        errno = EBADF;
+        return -1;
+    }
+
+    DWORD cRead;
+    OVERLAPPED overlapped = {.OffsetHigh = (DWORD)((offset & 0xFFFFFFFF00000000LL) >> 32),
+                             .Offset = (DWORD)(offset & 0xFFFFFFFFLL)};
+    bool rd = ReadFile(handle, buf, count, &cRead, &overlapped);
+    if (!rd) {
+        auto err = GetLastError();
+        switch (err) {
+            case ERROR_IO_PENDING:
+                errno = EAGAIN;
+                break;
+            case ERROR_HANDLE_EOF:
+                cRead = 0;
+                errno = 0;
+                return 0;
+            default:
+                // Oh oh
+                errno = EINVAL;
+        }
+        return -1;
+    }
+
+    return cRead;
+}
\ No newline at end of file
diff --git a/windows/src/setjmp.asm b/windows/src/setjmp.asm
new file mode 100644
index 0000000..5fb955a
--- /dev/null
+++ b/windows/src/setjmp.asm
@@ -0,0 +1,110 @@
+;; Copyright 2019 The Android Open Source Project
+;;
+;; This software is licensed under the terms of the GNU General Public
+;; License version 2, as published by the Free Software Foundation, and
+;; may be copied, distributed, and modified under those terms.
+;;
+;; This program is distributed in the hope that it will be useful,
+;; but WITHOUT ANY WARRANTY; without even the implied warranty of
+;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+;; GNU General Public License for more details.
+
+;; This contains setjmp/longjmp implementation that we can use with qemu.
+
+;; This is the standard register usage in Win64
+;;
+;; RAX	        Volatile	Return value register
+;; RCX	        Volatile	First integer argument
+;; RDX  	Volatile	Second integer argument
+;; R8	        Volatile	Third integer argument
+;; R9	        Volatile	Fourth integer argument
+;; R10:R11	Volatile	Must be preserved as needed by caller; used in syscall/sysret instructions
+;; R12:R15	Nonvolatile	Must be preserved by callee
+;; RDI	        Nonvolatile	Must be preserved by callee
+;; RSI	        Nonvolatile	Must be preserved by callee
+;; RBX	        Nonvolatile	Must be preserved by callee
+;; RBP	        Nonvolatile	May be used as a frame pointer; must be preserved by callee
+;; RSP	        Nonvolatile	Stack pointer
+;; XMM0, YMM0	Volatile	First FP argument; first vector-type argument when __vectorcall is used
+;; XMM1, YMM1	Volatile	Second FP argument; second vector-type argument when __vectorcall is used
+;; XMM2, YMM2	Volatile	Third FP argument; third vector-type argument when __vectorcall is used
+;; XMM3, YMM3	Volatile	Fourth FP argument; fourth vector-type argument when __vectorcall is used
+;; XMM4, YMM4	Volatile	Must be preserved as needed by caller; fifth vector-type argument when __vectorcall is used
+;; XMM5, YMM5	Volatile	Must be preserved as needed by caller; sixth vector-type argument when __vectorcall is used
+;; XMM6:XMM15, YMM6:YMM15	Nonvolatile (XMM), Volatile (upper half of YMM)	Must be preserved by callee. YMM registers must be preserved as needed by caller.
+
+        section .text              ; Code section.
+        global  sigsetjmp_impl     ; Export functions, linker can now link against it.
+        global  siglongjmp_impl    ;
+
+sigsetjmp_impl:                 ; Function entry
+
+  ;; According to msdn:
+  ;;
+  ;; A call to setjmp preserves the current stack pointer, non-volatile registers, and
+  ;; MxCsr registers. Calls to longjmp return to the most recent setjmp call site and
+  ;; resets the stack pointer, non-volatile registers, and MxCsr registers,
+  ;; back to the state as preserved by the most recent setjmp call.
+  ;;
+  ;; We are only doing the bare minimum, and are not saving th mxcsr/xmm/ymm regs.
+  ;; We rely on jmp_buf having enough space for 16 64 bit registers.
+
+        mov [rcx]      , rdx      ; RDX	Volatile	Second integer argument
+        mov [rcx+0x8]  , r8       ; R8	Volatile	Third integer argument
+        mov [rcx+0x10] , r9       ; R9	Volatile	Fourth integer argument
+        mov [rcx+0x18] , r10      ; R10 Volatile	Must be preserved as needed by caller; used in syscall/sysret instructions
+        mov [rcx+0x20] , r11      ; R11 Volatile	Must be preserved as needed by caller; used in syscall/sysret instructions ;
+        mov [rcx+0x28] , r12      ; R12	Nonvolatile	Must be preserved by callee
+        mov [rcx+0x30] , r15      ; R15	Nonvolatile	Must be preserved by callee
+        mov [rcx+0x38] , rdi      ; RDI	Nonvolatile	Must be preserved by callee
+        mov [rcx+0x40] , rsi      ; RSI	Nonvolatile	Must be preserved by callee
+        mov [rcx+0x48] , rbx      ; RBX	Nonvolatile	Must be preserved by callee
+        mov [rcx+0x50] , rbp      ; RBP	Nonvolatile	May be used as a frame pointer; must be preserved by callee
+        mov [rcx+0x58] , rsp      ; RSP	Nonvolatile	Stack pointer, note this will automatically be adjusted by our return.
+        mov rax, [rsp];
+        mov [rcx+0x60] , rax      ; We need to save our return address.
+
+;; We are not doing any of these.
+;; XMM0, YMM0	Volatile	First FP argument; first vector-type argument when __vectorcall is used
+;; XMM1, YMM1	Volatile	Second FP argument; second vector-type argument when __vectorcall is used
+;; XMM2, YMM2	Volatile	Third FP argument; third vector-type argument when __vectorcall is used
+;; XMM3, YMM3	Volatile	Fourth FP argument; fourth vector-type argument when __vectorcall is used
+;; XMM4, YMM4	Volatile	Must be preserved as needed by caller; fifth vector-type argument when __vectorcall is used
+;; XMM5, YMM5	Volatile	Must be preserved as needed by caller; sixth vector-type argument when __vectorcall is used
+;; XMM6:XMM15, YMM6:YMM15	Nonvolatile (XMM), Volatile (upper half of YMM)	Must be preserved by callee. YMM registers must be preserved as needed by caller.
+        mov rax, 0              ; We came from a call to setjmp, so Woohoo
+        ret                     ; return
+
+siglongjmp_impl:
+
+        ;; First we reconstruct out stack, so when we call ret, we go back to sigjmp location
+        mov rsp, [rcx+0x58]       ; RSP	Nonvolatile	Stack pointer
+        mov rax, [rcx+0x60]
+        mov [rsp], rax            ; Set our return address on the stack.
+
+        ;; Next we restore the registers.
+        mov rax, rdx              ; Return value (param 2) from longjmp
+        mov rdx, [rcx]            ; RDX	Volatile	Second integer argument
+        mov r8,  [rcx+0x8]        ; R8	Volatile	Third integer argument
+        mov r9,  [rcx+0x10]       ; R9	Volatile	Fourth integer argument
+        mov r10, [rcx+0x18]       ; R10 Volatile	Must be preserved as needed by caller; used in syscall/sysret instructions
+        mov r11, [rcx+0x20]       ; R11 Volatile	Must be preserved as needed by caller; used in syscall/sysret instructions ;
+        mov r12, [rcx+0x28]       ; R12	Nonvolatile	Must be preserved by callee
+        mov r15, [rcx+0x30]       ; R15	Nonvolatile	Must be preserved by callee
+        mov rdi, [rcx+0x38]       ; RDI	Nonvolatile	Must be preserved by callee
+        mov rsi, [rcx+0x40]       ; RSI	Nonvolatile	Must be preserved by callee
+        mov rbx, [rcx+0x48]       ; RBX	Nonvolatile	Must be preserved by callee
+        mov rbp, [rcx+0x50]       ; RBP	Nonvolatile	May be used as a frame pointer; must be preserved by callee
+
+;; XMM0, YMM0	Volatile	First FP argument; first vector-type argument when __vectorcall is used
+;; XMM1, YMM1	Volatile	Second FP argument; second vector-type argument when __vectorcall is used
+;; XMM2, YMM2	Volatile	Third FP argument; third vector-type argument when __vectorcall is used
+;; XMM3, YMM3	Volatile	Fourth FP argument; fourth vector-type argument when __vectorcall is used
+;; XMM4, YMM4	Volatile	Must be preserved as needed by caller; fifth vector-type argument when __vectorcall is used
+;; XMM5, YMM5	Volatile	Must be preserved as needed by caller; sixth vector-type argument when __vectorcall is used
+;; XMM6:XMM15, YMM6:YMM15	Nonvolatile (XMM), Volatile (upper half of YMM)	Must be preserved by callee. YMM registers must be preserved as needed by caller.
+
+        ret                     ; return
+
+
+        section .data           ; Data section, initialized variables
diff --git a/windows/src/time.cpp b/windows/src/time.cpp
new file mode 100644
index 0000000..25412bd
--- /dev/null
+++ b/windows/src/time.cpp
@@ -0,0 +1,146 @@
+
+// Copyright (C) 2023 The Android Open Source Project
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
+#include <Windows.h>
+#include <sys/time.h>
+#include <time.h>
+
+#include <cassert>
+#include <chrono>
+#include <ctime>
+#include <iostream>
+#include <thread>
+
+#include "compat_compiler.h"
+
+ANDROID_BEGIN_HEADER
+
+typedef int clockid_t;
+
+int clock_gettime(clockid_t clk_id, struct timespec* tp) {
+    assert(clk_id == CLOCK_MONOTONIC);
+    auto now = std::chrono::steady_clock::now();
+    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
+
+    tp->tv_sec = static_cast<time_t>(duration.count());
+    tp->tv_nsec = static_cast<long>(
+        std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch() - duration)
+            .count());
+
+    return 0;  // Success
+}
+
+int nanosleep(const struct timespec* rqtp, struct timespec* rmtp) {
+    // Validate input
+    if (rqtp == NULL || rqtp->tv_nsec < 0 || rqtp->tv_nsec >= 1'000'000'000) {
+        SetLastError(ERROR_INVALID_PARAMETER);
+        return -1;
+    }
+
+    // Create a persistent thread local timer object
+    struct ThreadLocalTimerState {
+        ThreadLocalTimerState() {
+            timerHandle = CreateWaitableTimerEx(
+                nullptr /* no security attributes */, nullptr /* no timer name */,
+                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
+
+            if (!timerHandle) {
+                // Use an older version of waitable timer as backup.
+                timerHandle = CreateWaitableTimer(nullptr, FALSE, nullptr);
+            }
+        }
+
+        ~ThreadLocalTimerState() {
+            if (timerHandle) {
+                CloseHandle(timerHandle);
+            }
+        }
+
+        HANDLE timerHandle = 0;
+    };
+
+    static thread_local ThreadLocalTimerState tl_timerInfo;
+
+    // Convert timespec to FILETIME
+    ULARGE_INTEGER fileTime;
+    fileTime.QuadPart = static_cast<ULONGLONG>(rqtp->tv_sec) * 10'000'000 + rqtp->tv_nsec / 100;
+
+    if (!tl_timerInfo.timerHandle) {
+        // Oh oh, for some reason we do not have a handle..
+        return -1;
+    }
+
+    LARGE_INTEGER dueTime;
+    // Note: Negative values indicate relative time.
+    // (https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
+    dueTime.QuadPart = -static_cast<LONGLONG>(fileTime.QuadPart);
+
+    if (!SetWaitableTimer(tl_timerInfo.timerHandle, &dueTime, 0, NULL, NULL, FALSE)) {
+        return -1;
+    }
+
+    if (WaitForSingleObject(tl_timerInfo.timerHandle, INFINITE) != WAIT_OBJECT_0) {
+        return -1;  // Sleep interrupted or error
+    }
+
+    // Calculate remaining time if needed
+    if (rmtp != NULL) {
+        // Get current time
+        FILETIME currentTime;
+        GetSystemTimeAsFileTime(&currentTime);
+
+        // Calculate remaining time
+        ULARGE_INTEGER currentFileTime;
+        currentFileTime.LowPart = currentTime.dwLowDateTime;
+        currentFileTime.HighPart = currentTime.dwHighDateTime;
+
+        ULONGLONG remainingTime = fileTime.QuadPart + currentFileTime.QuadPart;
+        rmtp->tv_sec = static_cast<time_t>(remainingTime / 10'000'000);
+        rmtp->tv_nsec = static_cast<long>((remainingTime % 10'000'000) * 100);
+    }
+
+    return 0;
+}
+
+int gettimeofday(struct timeval* tp, void* /* tzp */) {
+    if (tp == nullptr) {
+        return -1;
+    }
+
+    // Get the current time using std::chrono::system_clock
+    auto now = std::chrono::system_clock::now();
+    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
+
+    // Extract seconds and microseconds
+    tp->tv_sec = static_cast<long>(duration.count() / 1'000'000);
+    tp->tv_usec = static_cast<long>(duration.count() % 1'000'000);
+
+    // Return success
+    return 0;
+}
+
+void usleep(int64_t usec) {
+    struct timespec req;
+    req.tv_sec = static_cast<time_t>(usec / 1'000'000);
+    req.tv_nsec = static_cast<long>((usec % 1'000'000) * 1000);
+
+    nanosleep(&req, nullptr);
+}
+
+unsigned int sleep(unsigned int seconds) {
+    Sleep(seconds * 1000);
+    return 0;
+}
+
+ANDROID_END_HEADER
\ No newline at end of file
diff --git a/windows/src/udivmodti4.c b/windows/src/udivmodti4.c
new file mode 100644
index 0000000..fe0ff40
--- /dev/null
+++ b/windows/src/udivmodti4.c
@@ -0,0 +1,195 @@
+//===-- udivmodti4.c - Implement __udivmodti4 -----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file implements __udivmodti4 for the compiler_rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#include "int_lib.h"
+
+#ifdef CRT_HAS_128BIT
+
+// Effects: if rem != 0, *rem = a % b
+// Returns: a / b
+
+// Translated from Figure 3-40 of The PowerPC Compiler Writer's Guide
+
+COMPILER_RT_ABI tu_int __udivmodti4(tu_int a, tu_int b, tu_int *rem) {
+  const unsigned n_udword_bits = sizeof(du_int) * CHAR_BIT;
+  const unsigned n_utword_bits = sizeof(tu_int) * CHAR_BIT;
+  utwords n;
+  n.all = a;
+  utwords d;
+  d.all = b;
+  utwords q;
+  utwords r;
+  unsigned sr;
+  // special cases, X is unknown, K != 0
+  if (n.s.high == 0) {
+    if (d.s.high == 0) {
+      // 0 X
+      // ---
+      // 0 X
+      if (rem)
+        *rem = n.s.low % d.s.low;
+      return n.s.low / d.s.low;
+    }
+    // 0 X
+    // ---
+    // K X
+    if (rem)
+      *rem = n.s.low;
+    return 0;
+  }
+  // n.s.high != 0
+  if (d.s.low == 0) {
+    if (d.s.high == 0) {
+      // K X
+      // ---
+      // 0 0
+      if (rem)
+        *rem = n.s.high % d.s.low;
+      return n.s.high / d.s.low;
+    }
+    // d.s.high != 0
+    if (n.s.low == 0) {
+      // K 0
+      // ---
+      // K 0
+      if (rem) {
+        r.s.high = n.s.high % d.s.high;
+        r.s.low = 0;
+        *rem = r.all;
+      }
+      return n.s.high / d.s.high;
+    }
+    // K K
+    // ---
+    // K 0
+    if ((d.s.high & (d.s.high - 1)) == 0) /* if d is a power of 2 */ {
+      if (rem) {
+        r.s.low = n.s.low;
+        r.s.high = n.s.high & (d.s.high - 1);
+        *rem = r.all;
+      }
+      return n.s.high >> __builtin_ctzll(d.s.high);
+    }
+    // K K
+    // ---
+    // K 0
+    sr = __builtin_clzll(d.s.high) - __builtin_clzll(n.s.high);
+    // 0 <= sr <= n_udword_bits - 2 or sr large
+    if (sr > n_udword_bits - 2) {
+      if (rem)
+        *rem = n.all;
+      return 0;
+    }
+    ++sr;
+    // 1 <= sr <= n_udword_bits - 1
+    // q.all = n.all << (n_utword_bits - sr);
+    q.s.low = 0;
+    q.s.high = n.s.low << (n_udword_bits - sr);
+    // r.all = n.all >> sr;
+    r.s.high = n.s.high >> sr;
+    r.s.low = (n.s.high << (n_udword_bits - sr)) | (n.s.low >> sr);
+  } else /* d.s.low != 0 */ {
+    if (d.s.high == 0) {
+      // K X
+      // ---
+      // 0 K
+      if ((d.s.low & (d.s.low - 1)) == 0) /* if d is a power of 2 */ {
+        if (rem)
+          *rem = n.s.low & (d.s.low - 1);
+        if (d.s.low == 1)
+          return n.all;
+        sr = __builtin_ctzll(d.s.low);
+        q.s.high = n.s.high >> sr;
+        q.s.low = (n.s.high << (n_udword_bits - sr)) | (n.s.low >> sr);
+        return q.all;
+      }
+      // K X
+      // ---
+      // 0 K
+      sr = 1 + n_udword_bits + __builtin_clzll(d.s.low) -
+           __builtin_clzll(n.s.high);
+      // 2 <= sr <= n_utword_bits - 1
+      // q.all = n.all << (n_utword_bits - sr);
+      // r.all = n.all >> sr;
+      if (sr == n_udword_bits) {
+        q.s.low = 0;
+        q.s.high = n.s.low;
+        r.s.high = 0;
+        r.s.low = n.s.high;
+      } else if (sr < n_udword_bits) /* 2 <= sr <= n_udword_bits - 1 */ {
+        q.s.low = 0;
+        q.s.high = n.s.low << (n_udword_bits - sr);
+        r.s.high = n.s.high >> sr;
+        r.s.low = (n.s.high << (n_udword_bits - sr)) | (n.s.low >> sr);
+      } else /* n_udword_bits + 1 <= sr <= n_utword_bits - 1 */ {
+        q.s.low = n.s.low << (n_utword_bits - sr);
+        q.s.high = (n.s.high << (n_utword_bits - sr)) |
+                   (n.s.low >> (sr - n_udword_bits));
+        r.s.high = 0;
+        r.s.low = n.s.high >> (sr - n_udword_bits);
+      }
+    } else {
+      // K X
+      // ---
+      // K K
+      sr = __builtin_clzll(d.s.high) - __builtin_clzll(n.s.high);
+      // 0 <= sr <= n_udword_bits - 1 or sr large
+      if (sr > n_udword_bits - 1) {
+        if (rem)
+          *rem = n.all;
+        return 0;
+      }
+      ++sr;
+      // 1 <= sr <= n_udword_bits
+      // q.all = n.all << (n_utword_bits - sr);
+      // r.all = n.all >> sr;
+      q.s.low = 0;
+      if (sr == n_udword_bits) {
+        q.s.high = n.s.low;
+        r.s.high = 0;
+        r.s.low = n.s.high;
+      } else {
+        r.s.high = n.s.high >> sr;
+        r.s.low = (n.s.high << (n_udword_bits - sr)) | (n.s.low >> sr);
+        q.s.high = n.s.low << (n_udword_bits - sr);
+      }
+    }
+  }
+  // Not a special case
+  // q and r are initialized with:
+  // q.all = n.all << (n_utword_bits - sr);
+  // r.all = n.all >> sr;
+  // 1 <= sr <= n_utword_bits - 1
+  su_int carry = 0;
+  for (; sr > 0; --sr) {
+    // r:q = ((r:q)  << 1) | carry
+    r.s.high = (r.s.high << 1) | (r.s.low >> (n_udword_bits - 1));
+    r.s.low = (r.s.low << 1) | (q.s.high >> (n_udword_bits - 1));
+    q.s.high = (q.s.high << 1) | (q.s.low >> (n_udword_bits - 1));
+    q.s.low = (q.s.low << 1) | carry;
+    // carry = 0;
+    // if (r.all >= d.all)
+    // {
+    //     r.all -= d.all;
+    //      carry = 1;
+    // }
+    const ti_int s = (ti_int)(d.all - r.all - 1) >> (n_utword_bits - 1);
+    carry = s & 1;
+    r.all -= d.all & s;
+  }
+  q.all = (q.all << 1) | carry;
+  if (rem)
+    *rem = r.all;
+  return q.all;
+}
+
+#endif // CRT_HAS_128BIT
\ No newline at end of file
diff --git a/windows/src/udivti3.c b/windows/src/udivti3.c
new file mode 100644
index 0000000..b67f1e2
--- /dev/null
+++ b/windows/src/udivti3.c
@@ -0,0 +1,23 @@
+//===-- udivti3.c - Implement __udivti3 -----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file implements __udivti3 for the compiler_rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#include "int_lib.h"
+
+#ifdef CRT_HAS_128BIT
+
+// Returns: a / b
+
+COMPILER_RT_ABI tu_int __udivti3(tu_int a, tu_int b) {
+  return __udivmodti4(a, b, 0);
+}
+
+#endif // CRT_HAS_128BIT
\ No newline at end of file
diff --git a/windows/src/umodti3.c b/windows/src/umodti3.c
new file mode 100644
index 0000000..ae42c06
--- /dev/null
+++ b/windows/src/umodti3.c
@@ -0,0 +1,25 @@
+//===-- umodti3.c - Implement __umodti3 -----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+//
+// This file implements __umodti3 for the compiler_rt library.
+//
+//===----------------------------------------------------------------------===//
+
+#include "int_lib.h"
+
+#ifdef CRT_HAS_128BIT
+
+// Returns: a % b
+
+COMPILER_RT_ABI tu_int __umodti3(tu_int a, tu_int b) {
+  tu_int r;
+  __udivmodti4(a, b, &r);
+  return r;
+}
+
+#endif // CRT_HAS_128BIT
\ No newline at end of file
diff --git a/windows/tests/CMakeLists.txt b/windows/tests/CMakeLists.txt
new file mode 100644
index 0000000..f44c1b6
--- /dev/null
+++ b/windows/tests/CMakeLists.txt
@@ -0,0 +1,12 @@
+if(WINDOWS_MSVC_X86_64)
+  android_nasm_compile(
+    TARGET hello_world_asm_lib NODISTRIBUTE SRC # cmake-format: sortable
+                                                yasm/hello_world.asm)
+  android_add_test(
+    TARGET hello_world_asm_test SRC # cmake-format: sortable
+                                    yasm/hello_world_unittest.cpp)
+  target_link_libraries(hello_world_asm_test PRIVATE hello_world_asm_lib
+                                                     gmock_main)
+endif()
+
+add_subdirectory(compiler)
diff --git a/windows/tests/compiler/CMakeLists.txt b/windows/tests/compiler/CMakeLists.txt
new file mode 100644
index 0000000..b722058
--- /dev/null
+++ b/windows/tests/compiler/CMakeLists.txt
@@ -0,0 +1,22 @@
+# Place your compiler tests that assure that the build is behaving as expected across
+# various platforms here.
+#
+# For example: bit fields behave differently accross windows/posix.
+# Tests here will make sure that if we change compilers again that we catch failures early.
+android_add_test(
+  TARGET win_clang_unittests
+  SRC # cmake-format: sortable
+      compiler_tests.cpp enum_bit_fields.c longjump_test.c)
+
+# the longjump errors manifest with -O2
+set_source_files_properties(longjump_test.c PRIVATE COMPILE_FLAGS "-O2")
+target_include_directories(
+  win_clang_unittests
+  PRIVATE ${ANDROID_QEMU2_TOP_DIR}/android-qemu2-glue/config/target-x86_64
+          ${ANDROID_QEMU2_TOP_DIR}/target/i386
+          ${ANDROID_AUTOGEN}
+          ${ANDROID_AUTOGEN}/tcg)
+
+target_link_libraries(win_clang_unittests PRIVATE android-qemu-deps gmock_main
+                                                  glib2)
+target_compile_definitions(win_clang_unittests PRIVATE -DNEED_CPU_H)
diff --git a/windows/tests/compiler/compiler_tests.cpp b/windows/tests/compiler/compiler_tests.cpp
new file mode 100644
index 0000000..4fab4d2
--- /dev/null
+++ b/windows/tests/compiler/compiler_tests.cpp
@@ -0,0 +1,68 @@
+#include <glib.h>
+
+extern "C" {
+#include "compiler_tests.h"
+#include <glib/gprintf.h>
+}
+#include "gtest/gtest.h"
+#include <inttypes.h>
+#include <cstdint>
+#include <string_view> // Make sure we can use C++17 std::string_view
+#include <optional>
+
+TEST(CompilerTest, stringview) {
+    std::string_view hello("Hello");
+    EXPECT_STREQ("Hello", hello.data());
+}
+
+TEST(CompilerTest, optional) {
+    auto godzilla = std::optional<std::string>{"Godzilla"};
+    EXPECT_TRUE(godzilla.has_value());
+}
+
+// This test makes sure that the definitions in tcg are correct.
+// Note, calling gtest from C doesn't work well, and using qemu from C++ doesn't
+// work well either, so we have the test part that interacts with qemu in a .c file.
+TEST(CompilerTest, LargeEnumInBitThing) {
+     EXPECT_TRUE(test_enum_equal());
+}
+
+TEST(CompilerTest, long_jump_stack_test) {
+     // This test is to guarantee that the stack frame is set properly.
+     // a broken stack frame will result in an exception/termination.
+     EXPECT_TRUE(long_jump_stack_test());
+}
+
+TEST(CompilerTest, long_jump_double_call) {
+     EXPECT_TRUE(long_jump_double_call());
+}
+
+TEST(CompilerTest, long_jump_ret_value) {
+     EXPECT_TRUE(long_jump_ret_value());
+}
+
+TEST(CompilerTest, long_jump_preserve_int_params) {
+     // This test is to guarantee that the parameters are still available
+     // parameters (on windows) can be passed in as registers.
+     // Note, the bitmask should help you identify which parameter is missing. bit 0/4/8/12 etc = param1, 1/5/9/13 = param2 etc.
+     EXPECT_EQ(long_jump_preserve_int_params(PARAM1, PARAM2, PARAM3, PARAM4), PARAM1 + PARAM2 + PARAM3 + PARAM4);
+}
+
+TEST(CompilerTest, long_jump_preserve_float_params) {
+     // This test is to guarantee that the parameters are still available
+     // parameters (on windows) can be passed in as registers.
+     // Note, the bitmask should help you identify which parameter is missing. bit 0/4/8/12 etc = param1, 1/5/9/13 = param2 etc.
+    EXPECT_TRUE(long_jump_preserve_float_params(1.123, 2.123, 3.123, 4.123));
+}
+
+
+TEST(CompilerTest, setjmp_sets_fields) {
+     EXPECT_TRUE(setjmp_sets_fields());
+}
+
+TEST(CompilerTest, g_strdup_printf_incorrect_b129781540) {
+    int64_t val = 6442450944;
+    char* str = g_strdup_printf("%" PRId64, val);
+    EXPECT_STREQ("6442450944", str);
+    free(str);
+}
diff --git a/windows/tests/compiler/compiler_tests.h b/windows/tests/compiler/compiler_tests.h
new file mode 100644
index 0000000..e49d0ab
--- /dev/null
+++ b/windows/tests/compiler/compiler_tests.h
@@ -0,0 +1,32 @@
+#include <stdint.h>
+
+/* Returns true if the TCG enum is working as expected */
+int test_enum_equal();
+
+/* Make sure the long jump is working like expected. */
+int long_jump_stack_test();
+
+
+#define PARAM1 0x11111111
+#define PARAM2 0x22222222
+#define PARAM3 0x44444444
+#define PARAM4 0x88888888
+
+/* Make sure we preserve incoming parameters on longjmp, should return sum(PARAMx)
+   ints can be passed into registers vs. stack.
+*/
+uint64_t long_jump_preserve_int_params(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
+
+/* Make sure we preserve incoming parameters on longjmp, should return true
+   Floats can be passed in different registers..
+*/
+int long_jump_preserve_float_params(float a, float b, float c, float d);
+
+/** Make sure we jump back to the 2nd setjmp instead of the first */
+int long_jump_double_call();
+
+/** Make sure we preserve the longjmp return value (can be something else besides 1) */
+int long_jump_ret_value();
+
+/** Set jmp will actually store some data */
+int setjmp_sets_fields();
\ No newline at end of file
diff --git a/windows/tests/compiler/enum_bit_fields.c b/windows/tests/compiler/enum_bit_fields.c
new file mode 100644
index 0000000..d6f0241
--- /dev/null
+++ b/windows/tests/compiler/enum_bit_fields.c
@@ -0,0 +1,17 @@
+#include "enum_bit_fields.h"
+
+// QEMU doesn't like to be included from C++, so we just make a C file instead.
+#include "qemu/osdep.h"
+#include "qemu-common.h"
+#include "cpu.h"
+#include "exec/exec-all.h"
+#include "tcg/tcg.h"
+
+
+int test_enum_equal() {
+    // TCGOp should not have any enum in bitfield weirdness.
+    TCGOp tcg;
+    memset(&tcg, 0, sizeof(tcg));
+    tcg.opc = INDEX_op_qemu_ld_i32;
+    return INDEX_op_qemu_ld_i32 == tcg.opc;
+}
diff --git a/windows/tests/compiler/enum_bit_fields.h b/windows/tests/compiler/enum_bit_fields.h
new file mode 100644
index 0000000..1c69664
--- /dev/null
+++ b/windows/tests/compiler/enum_bit_fields.h
@@ -0,0 +1,4 @@
+
+/* Returns true if the TCG enum is working as expected */
+int test_enum_equal();
+
diff --git a/windows/tests/compiler/longjump_test.c b/windows/tests/compiler/longjump_test.c
new file mode 100644
index 0000000..23894b8
--- /dev/null
+++ b/windows/tests/compiler/longjump_test.c
@@ -0,0 +1,88 @@
+// clang-format off
+// Uncomment this line to see crashes in these tests.
+#define USE_CLANG_JMP
+#include "qemu/osdep.h"
+#include "cpu.h"
+#include "compiler_tests.h"
+// clang-format on
+
+uint64_t long_jump_preserve_int_params(uint64_t a,
+                                       uint64_t b,
+                                       uint64_t c,
+                                       uint64_t d) {
+    CPUState local_cpu;
+    if (sigsetjmp(local_cpu.jmp_env, 0x0)) {
+        return a + b + c + d;
+    }
+
+    siglongjmp(local_cpu.jmp_env, 1);
+    return 0;
+}
+
+
+int setjmp_sets_fields() {
+    CPUState local_cpu;
+    jmp_buf test;
+    memset(test, 0xAA, sizeof(test));
+    memset(local_cpu.jmp_env, 0xAA, sizeof(local_cpu.jmp_env));
+    sigsetjmp(local_cpu.jmp_env, 0x0);
+    return memcmp(test, local_cpu.jmp_env, sizeof(test)) != 0;
+}
+
+int long_jump_preserve_float_params(float a, float b, float c, float d) {
+    CPUState local_cpu;
+    float aa = a;
+    float bb = b;
+    float cc = c;
+    float dd = d;
+    if (sigsetjmp(local_cpu.jmp_env, 0x0)) {;
+        return aa == a && bb == b && cc == c && dd == d;
+    }
+
+    siglongjmp(local_cpu.jmp_env, 1);
+    return 0;
+}
+
+void jump_back(CPUState* local_cpu) {
+    siglongjmp(local_cpu->jmp_env, 1);
+}
+
+int long_jump_stack_test() {
+    CPUState local_cpu;
+    memset(local_cpu.jmp_env, 0xAA, sizeof(local_cpu.jmp_env));
+     if (sigsetjmp(local_cpu.jmp_env, 0x0)) {
+        return 1;
+    }
+
+    // This adds a new stack frame, which should work, as we are not
+    // overriding our stack frame.
+    jump_back(&local_cpu);
+    return 0;
+}
+
+int long_jump_double_call() {
+    CPUState local_cpu;
+
+    if (sigsetjmp(local_cpu.jmp_env, 0x0)) {
+        return 0;
+    }
+
+    // Overrides the first, so we should return here.
+    if (sigsetjmp(local_cpu.jmp_env, 0x0)) {
+        return 1;
+    }
+
+    siglongjmp(local_cpu.jmp_env, 1);
+    return 0;
+}
+
+int long_jump_ret_value() {
+    CPUState local_cpu;
+    int x = sigsetjmp(local_cpu.jmp_env, 0x0);
+    if (x) {
+        return x == 0xFF;
+    }
+
+    siglongjmp(local_cpu.jmp_env, 0xFF);
+    return 0;
+}
diff --git a/windows/tests/yasm/hello_world.asm b/windows/tests/yasm/hello_world.asm
new file mode 100644
index 0000000..3a7d73a
--- /dev/null
+++ b/windows/tests/yasm/hello_world.asm
@@ -0,0 +1,55 @@
+;; Copyright 2019 The Android Open Source Project
+;;
+;; This software is licensed under the terms of the GNU General Public
+;; License version 2, as published by the Free Software Foundation, and
+;; may be copied, distributed, and modified under those terms.
+;;
+;; This program is distributed in the hope that it will be useful,
+;; but WITHOUT ANY WARRANTY; without even the implied warranty of
+;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+;; GNU General Public License for more details.
+
+;; Simple asm function that calls back a c function.
+;; Note, that the different calling conventions on x86_64 for Win vs. Darwin/Lin
+;; See https://en.wikipedia.org/wiki/X86_calling_conventions for details
+%ifidn __OUTPUT_FORMAT__, win64
+  ; Windows default calling convention uses rcx, rdx for first 2 vars.
+  %define MOV_REG_PARM1 mov  rcx
+  %define MOV_REG_PARM2 mov  rdx
+%else
+  ; darwin/linux use rdi & rsi
+  %define MOV_REG_PARM1 mov  rdi
+  %define MOV_REG_PARM2 mov  rsi
+%endif
+
+; Platforms mangle names slightly differently
+%ifidn __OUTPUT_FORMAT__, macho64
+   ; Darwin mangles with a _
+   %define HELLO_FUNC _hello
+   %define SAY_HELLO_FUNC _say_hello
+%else
+   ; windows & linux do not mangle.
+   %define HELLO_FUNC hello
+   %define SAY_HELLO_FUNC say_hello
+%endif
+
+; Declare needed C functions, the linker will resolve these.
+        extern    HELLO_FUNC    ; the C hello function we are calling.
+
+        section .text           ; Code section.
+        global  SAY_HELLO_FUNC  ; Export out function, linker can now link against it.
+
+SAY_HELLO_FUNC:                 ; Function entry
+        push    rbp             ; Push stack
+
+        MOV_REG_PARM1, 127      ; Load our 2 parameters in registers.
+        MOV_REG_PARM2, qword msg
+        call    HELLO_FUNC      ; Call mangled C function
+
+        pop     rbp             ; restore stack
+        mov     rax, 255        ; return value
+        ret                     ; return
+
+
+        section .data           ; Data section, initialized variables
+msg:    db "Hello world", 0     ; C string needs 0
diff --git a/windows/tests/yasm/hello_world_unittest.cpp b/windows/tests/yasm/hello_world_unittest.cpp
new file mode 100644
index 0000000..699fd82
--- /dev/null
+++ b/windows/tests/yasm/hello_world_unittest.cpp
@@ -0,0 +1,29 @@
+// Copyright 2019 The Android Open Source Project
+//
+// This software is licensed under the terms of the GNU General Public
+// License version 2, as published by the Free Software Foundation, and
+// may be copied, distributed, and modified under those terms.
+//
+// This program is distributed in the hope that it will be useful,
+// but WITHOUT ANY WARRANTY; without even the implied warranty of
+// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+// GNU General Public License for more details.
+#include <gtest/gtest.h>
+
+static int said_hello = 0;
+const char* msg = "Hello world";
+
+extern "C" {
+extern int say_hello();
+
+void hello(int x, char *str) {
+    said_hello = 1;
+    EXPECT_EQ(x, 127);
+    EXPECT_STREQ(str, "Hello world");
+}
+}
+
+TEST(Yasm, SayHelloFromAsm) {
+    EXPECT_EQ(say_hello(), 0xFF);
+    EXPECT_EQ(said_hello, 1);
+}
```

