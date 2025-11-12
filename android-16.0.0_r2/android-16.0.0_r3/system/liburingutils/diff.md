```diff
diff --git a/Android.bp b/Android.bp
index bf7f9cd..d1d3623 100644
--- a/Android.bp
+++ b/Android.bp
@@ -51,10 +51,67 @@ cc_test {
     srcs: [
         "src/IOUringSocketHandler_test.cpp",
     ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    static_libs: [
+        "liburing",
+        "liburingutils",
+    ],
+}
+
+cc_benchmark {
+    name: "IOUringSocketHandler_benchmark",
+    srcs: ["src/IOUringSocketHandlerBenchmark.cpp"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    static_libs: [
+        "liburing",
+        "liburingutils",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+}
+
+cc_benchmark {
+    name: "IOUringSocketHandlerReceiver",
+    srcs: ["src/IOUringSocketHandlerReceiver.cpp"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
     static_libs: [
         "liburing",
         "liburingutils",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+}
+
+cc_benchmark {
+    name: "IOUringSocketHandlerSender",
+    srcs: ["src/IOUringSocketHandlerSender.cpp"],
+    shared_libs: [
         "libbase",
         "liblog",
     ],
+    static_libs: [
+        "liburing",
+        "liburingutils",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
 }
diff --git a/include/IOUringSocketHandler/IOUringSocketHandler.h b/include/IOUringSocketHandler/IOUringSocketHandler.h
index 6322ef0..be91bec 100644
--- a/include/IOUringSocketHandler/IOUringSocketHandler.h
+++ b/include/IOUringSocketHandler/IOUringSocketHandler.h
@@ -138,10 +138,11 @@ public:
     // return: true if io_uring is supported by the kernel, false otherwise.
     //
     // This function checks if the io_uring feature is supported by the underlying Linux kernel.
-    static bool isIouringEnabled();
+    // Only kernel with 6.1+ are supported.
+    static bool IsIouringSupported();
 
 private:
-    static bool isIouringSupportedByKernel();
+    static bool IsIouringSupportedByKernel();
     // Register buffers with io_uring
     //
     // return: true on success, false on failure (e.g., if io_uring_register_buffers fails).
@@ -170,5 +171,14 @@ private:
     const int bgid_ = 7;
     struct io_uring_buf_ring* br_;
     bool registered_buffers_ = false;
+    bool registered_ring_fd_ = false;
     bool ring_setup_ = false;
+
+    // Vector of cqe entries obtained after peek.
+    std::vector<struct io_uring_cqe*> cqe_vector_;
+    // Count of cqe entries which are not consumed yet.
+    int active_count_ = 0;
+    // Index into the cqe_vector_ to process the entries
+    // which are not consumed yet.
+    int active_index_ = -1;
 };
diff --git a/src/IOUringSocketHandler.cpp b/src/IOUringSocketHandler.cpp
index 253158b..a2efd18 100644
--- a/src/IOUringSocketHandler.cpp
+++ b/src/IOUringSocketHandler.cpp
@@ -40,11 +40,11 @@
 #include <android-base/logging.h>
 #include <android-base/scopeguard.h>
 
-bool IOUringSocketHandler::isIouringEnabled() {
-    return isIouringSupportedByKernel();
+bool IOUringSocketHandler::IsIouringSupported() {
+    return IsIouringSupportedByKernel();
 }
 
-bool IOUringSocketHandler::isIouringSupportedByKernel() {
+bool IOUringSocketHandler::IsIouringSupportedByKernel() {
     struct utsname uts {};
     unsigned int major, minor;
 
@@ -60,7 +60,12 @@ bool IOUringSocketHandler::isIouringSupportedByKernel() {
 IOUringSocketHandler::IOUringSocketHandler(int socket_fd) : socket_(socket_fd) {}
 
 IOUringSocketHandler::~IOUringSocketHandler() {
+    if (registered_ring_fd_) {
+        io_uring_unregister_ring_fd(&mCtx->ring);
+    }
+
     DeRegisterBuffers();
+
     if (ring_setup_) {
         io_uring_queue_exit(&mCtx->ring);
     }
@@ -70,8 +75,10 @@ bool IOUringSocketHandler::EnqueueMultishotRecvmsg() {
     struct io_uring_sqe* sqe = io_uring_get_sqe(&mCtx->ring);
     memset(&msg, 0, sizeof(msg));
     msg.msg_controllen = control_len_;
+
     io_uring_prep_recvmsg_multishot(sqe, socket_, &msg, 0);
     sqe->flags |= IOSQE_BUFFER_SELECT;
+
     sqe->buf_group = bgid_;
     int ret = io_uring_submit(&mCtx->ring);
     if (ret < 0) {
@@ -84,13 +91,14 @@ bool IOUringSocketHandler::EnqueueMultishotRecvmsg() {
 bool IOUringSocketHandler::AllocateAndRegisterBuffers(size_t num_buffers, size_t buf_size) {
     num_buffers_ = num_buffers;
     control_len_ = CMSG_ALIGN(sizeof(struct ucred)) + sizeof(struct cmsghdr);
-
     buffer_size_ = sizeof(struct io_uring_recvmsg_out) + control_len_ + buf_size;
 
     for (size_t i = 0; i < num_buffers_; i++) {
         std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size_);
         buffers_.push_back(std::move(buffer));
     }
+
+    cqe_vector_.resize(num_buffers_);
     return RegisterBuffers();
 }
 
@@ -127,22 +135,36 @@ bool IOUringSocketHandler::SetupIoUring(int queue_size) {
     mCtx = std::unique_ptr<uring_context>(new uring_context());
     struct io_uring_params params = {};
 
-    // COOP_TASKRUN - No IPI to logd
+    // COOP_TASKRUN - Do not send IPI to process
     // SINGLE_ISSUER - Only one thread is doing the work on the ring
-    // TASKRUN_FLAG - we use peek_cqe - Hence, trigger task work if required
     // DEFER_TASKRUN - trigger task work when CQE is explicitly polled
     params.flags |= (IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SINGLE_ISSUER |
-                     IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_DEFER_TASKRUN);
+                     IORING_SETUP_DEFER_TASKRUN);
 
     int ret = io_uring_queue_init_params(queue_size + 1, &mCtx->ring, &params);
     if (ret) {
         LOG(ERROR) << "io_uring_queue_init_params failed with ret: " << ret;
         return false;
     } else {
-        LOG(INFO) << "io_uring_queue_init_params success";
+        LOG(DEBUG) << "io_uring_queue_init_params success";
     }
 
     ring_setup_ = true;
+
+    ret = io_uring_register_ring_fd(&mCtx->ring);
+    if (ret < 0) {
+        LOG(ERROR) << "io_uring_register_ring_fd failed: " << ret;
+    } else {
+        registered_ring_fd_ = true;
+    }
+
+    unsigned int values[2];
+    values[0] = values[1] = 1;
+    ret = io_uring_register_iowq_max_workers(&mCtx->ring, values);
+    if (ret) {
+        LOG(ERROR) << "io_uring_register_iowq_max_workers failed: " << ret;
+    }
+
     return true;
 }
 
@@ -151,57 +173,110 @@ void IOUringSocketHandler::ReleaseBuffer() {
         return;
     }
 
+    // If there are no more CQE data, re-arm the SQE
+    bool is_more_cqe = (cqe->flags & IORING_CQE_F_MORE);
+
     // Put the buffer back to the pool
     io_uring_buf_ring_add(br_, buffers_[active_buffer_id_].get(), buffer_size_, active_buffer_id_,
                           io_uring_buf_ring_mask(num_buffers_), 0);
+    // Advance the CQE pointer and buffer ring.
     io_uring_buf_ring_cq_advance(&mCtx->ring, br_, 1);
     active_buffer_id_ = -1;
 
-    // If there are no more CQE data, re-arm the SQE
-    bool is_more_cqe = (cqe->flags & IORING_CQE_F_MORE);
     if (!is_more_cqe) {
         EnqueueMultishotRecvmsg();
     }
 }
 
 void IOUringSocketHandler::ReceiveData(void** payload, size_t& payload_len, struct ucred** cred) {
-    if (io_uring_peek_cqe(&mCtx->ring, &cqe) < 0) {
+  while (true) {
+    if (active_count_ > 0) {
+      // Consume next CQE from the existing active batch
+      cqe = cqe_vector_[active_index_];
+      active_count_ -= 1;
+      active_index_ += 1;
+    } else {
+      // No active batch, try to get new CQEs
+      active_index_ = 0;
+      // Try to peek a batch without blocking
+      int count = io_uring_peek_batch_cqe(&mCtx->ring, cqe_vector_.data(), num_buffers_);
+      if (count > 0 ) {
+        // Peek successful, store the count and process the first CQE now
+        active_count_ = count;
+        cqe = cqe_vector_[active_index_]; // Get the first one (index 0)
+        active_count_ -= 1;
+        active_index_ += 1;
+      } else {
+        // No batch is active
+        active_index_ = -1;
+        active_count_ = 0;
+        // Peek failed (no CQEs ready), block waiting for a single CQE
+        // Since DEFER_TASK_RUN flag is set for the ring, this
+        // will trigger the task and initiate the receive of packets
         int ret = io_uring_wait_cqe(&mCtx->ring, &cqe);
         if (ret) {
-            LOG(ERROR) << "WaitCqe failed: " << ret;
-            EnqueueMultishotRecvmsg();
-            return;
+          EnqueueMultishotRecvmsg();
+          continue;
         }
+      }
     }
 
-    if (cqe->res < 0) {
-        io_uring_cqe_seen(&mCtx->ring, cqe);
-        EnqueueMultishotRecvmsg();
-        return;
+    bool cqe_f_buffer = (cqe->flags & IORING_CQE_F_BUFFER);
+
+    // A failure here would most likely be related to ENOBUFS.
+    // However, for every failure, we need to re-arm the multishot sqe.
+    if ((cqe->res < 0) || !cqe_f_buffer) {
+      // No buffers were selected from registered buffers even
+      // though we had valid payload.
+      if ((cqe->res > 0) && !cqe_f_buffer) {
+        LOG(ERROR) << "No buffers selected. cqe->res: " << cqe->res
+                   << " cqe_flags: " << cqe->flags;
+      }
+      if (cqe->res != -ENOBUFS) {
+        LOG(ERROR) << "cqe failed with error: " << cqe->res;
+      }
+      io_uring_cqe_seen(&mCtx->ring, cqe);
+      EnqueueMultishotRecvmsg();
+      continue;
     }
 
+    // Pick the buffer-id where the payload data is sent.
     active_buffer_id_ = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
 
     void* this_recv = buffers_[active_buffer_id_].get();
-    struct io_uring_recvmsg_out* o = io_uring_recvmsg_validate(this_recv, cqe->res, &msg);
+    struct io_uring_recvmsg_out* out = io_uring_recvmsg_validate(this_recv, cqe->res, &msg);
 
-    if (!o) {
-        return;
+    if (!out) {
+      ReleaseBuffer();
+      continue;
     }
 
+    // Fetch ucred control data from cmsg
     struct cmsghdr* cmsg;
-    cmsg = io_uring_recvmsg_cmsg_firsthdr(o, &msg);
+    cmsg = io_uring_recvmsg_cmsg_firsthdr(out, &msg);
 
     struct ucred* cr = nullptr;
     while (cmsg != nullptr) {
-        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
-            cr = (struct ucred*)CMSG_DATA(cmsg);
-            break;
-        }
-        cmsg = io_uring_recvmsg_cmsg_nexthdr(o, &msg, cmsg);
+      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
+        cr = (struct ucred*)CMSG_DATA(cmsg);
+        break;
+      }
+      cmsg = io_uring_recvmsg_cmsg_nexthdr(out, &msg, cmsg);
     }
 
-    *payload = io_uring_recvmsg_payload(o, &msg);
-    payload_len = io_uring_recvmsg_payload_length(o, cqe->res, &msg);
+    *payload = io_uring_recvmsg_payload(out, &msg);
+    payload_len = io_uring_recvmsg_payload_length(out, cqe->res, &msg);
     *cred = cr;
+
+    // We have the valid data. Return it to the client.
+    // Note: We don't check "cred" pointer as senders can just send
+    // payload without credentials. It is up to the caller on how
+    // to handle it.
+    if ((*payload != nullptr) && (payload_len > 0)) {
+      break;
+    } else {
+      // Release the buffer and re-check the CQE buffers in the ring.
+      ReleaseBuffer();
+    }
+  }
 }
diff --git a/src/IOUringSocketHandlerBenchmark.cpp b/src/IOUringSocketHandlerBenchmark.cpp
new file mode 100644
index 0000000..5bf1cbc
--- /dev/null
+++ b/src/IOUringSocketHandlerBenchmark.cpp
@@ -0,0 +1,361 @@
+#include <iostream>
+#include <cstring>
+#include <vector>
+#include <thread>
+#include <chrono>
+#include <cstring>
+#include <unistd.h>
+#include <sys/socket.h>
+#include <sys/un.h>
+#include <poll.h>
+#include <unistd.h>
+#include <random>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+
+#include <android-base/scopeguard.h>
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+
+#include <benchmark/benchmark.h>
+
+// Registered buffers
+#define MAX_BUFFERS 256
+
+// Threads sending 4k payload - 1 Million times
+const int MESSAGE_SIZE = 4096; // 4KB
+const int NUM_MESSAGES_PER_THREAD = 1000000;
+
+// The benchmark is set to run 4 times with
+// the following combinations:
+//
+// a: {1, 4, 8, 16} -> This is the number of sender threads
+// b: {0, 1} -> Whether sender is blocking or non-blocking
+#define BENCH_OPTIONS                 \
+  MeasureProcessCPUTime()             \
+      ->Unit(benchmark::kSecond) \
+      ->Iterations(1)                \
+      ->Repetitions(4)                \
+      ->ReportAggregatesOnly(true) \
+      ->ArgsProduct({{1, 4, 8, 16}, {0, 1}});
+
+// Function to generate a random string
+std::string generateRandomString(size_t length) {
+    static const char charset[] =
+        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
+    std::random_device rd;
+    std::mt19937 gen(rd());
+    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
+
+    std::string str(length, 0);
+    for (size_t i = 0; i < length; ++i) {
+        str[i] = charset[dis(gen)];
+    }
+    return str;
+}
+
+static void SetLabel(benchmark::State& state) {
+    std::string num_senders = std::to_string(state.range(0));
+    std::string type = state.range(1) == 0 ? "synchronous" : "asynchrounous";
+    state.SetLabel(num_senders + "-SendThreads" + "/" + type);
+}
+
+// Function for sending thread
+void sendThread(int sock_send, int sync_sender) {
+    std::string message = generateRandomString(MESSAGE_SIZE);
+
+    struct ucred cred;
+    memset(&cred, 0, sizeof(cred));
+    cred.pid = getpid();
+    cred.uid = getuid();
+    cred.gid = getgid();
+
+    struct iovec iov_send;
+    iov_send.iov_base = const_cast<char*>(message.data());
+    iov_send.iov_len = MESSAGE_SIZE;
+
+    struct msghdr msg_send;
+    memset(&msg_send, 0, sizeof(msg_send));
+    msg_send.msg_iov = &iov_send;
+    msg_send.msg_iovlen = 1;
+
+    char control_buffer_send[CMSG_SPACE(sizeof(cred))];
+    memset(control_buffer_send, 0, sizeof(control_buffer_send));
+    msg_send.msg_control = control_buffer_send;
+    msg_send.msg_controllen = sizeof(control_buffer_send);
+
+    struct cmsghdr* cmsg_send = CMSG_FIRSTHDR(&msg_send);
+    cmsg_send->cmsg_level = SOL_SOCKET;
+    cmsg_send->cmsg_type = SCM_CREDENTIALS;
+    cmsg_send->cmsg_len = CMSG_LEN(sizeof(cred));
+    memcpy(CMSG_DATA(cmsg_send), &cred, sizeof(cred));
+
+    int flags = 0;
+    if (!sync_sender) {
+        flags = MSG_DONTWAIT;
+    }
+    for (int i = 0; i < NUM_MESSAGES_PER_THREAD; ++i) {
+        ssize_t sent_bytes;
+        while (true) {
+            sent_bytes = sendmsg(sock_send, &msg_send, flags);
+            if (sent_bytes >= 0) {
+                break; // Success
+            }
+            if (errno == EAGAIN || errno == EWOULDBLOCK) {
+                // Try again
+                continue;
+            } else {
+                perror("sendmsg failed");
+                return;
+            }
+        }
+    }
+    LOG(DEBUG) << "sendThread exiting";
+}
+
+// Receive using io_uring
+bool receiveThreaduring(int sock_recv, int num_threads, long long& total_bytes_received,
+                        double& average_latency) {
+    std::unique_ptr<IOUringSocketHandler> async_listener_;
+    async_listener_ = std::make_unique<IOUringSocketHandler>(sock_recv);
+    if (!async_listener_->SetupIoUring(MAX_BUFFERS)) {
+        LOG(ERROR) << "SetupIoUring failed";
+        return false;
+    }
+    async_listener_->AllocateAndRegisterBuffers(
+        MAX_BUFFERS, MESSAGE_SIZE);
+
+    if (!async_listener_->EnqueueMultishotRecvmsg()) {
+        LOG(ERROR) << "EnqueueMultishotRecvmsg failed";
+        return false;
+    }
+
+    long long received_messages = 0;
+    auto start_time = std::chrono::high_resolution_clock::now();
+    long long total_latency = 0;
+
+    while (received_messages < num_threads * NUM_MESSAGES_PER_THREAD) {
+        struct ucred* cred = nullptr;
+        void* this_recv = nullptr;
+        size_t len = 0;
+        auto receive_time = std::chrono::high_resolution_clock::now();
+        async_listener_->ReceiveData(&this_recv, len, &cred);
+        // Release the buffer from here onwards
+        {
+            auto scope_guard =
+                android::base::make_scope_guard([&async_listener_]() -> void {
+                  async_listener_->ReleaseBuffer(); });
+            auto end_receive_time = std::chrono::high_resolution_clock::now();
+            total_latency += std::chrono::duration_cast<std::chrono::microseconds>(
+                              end_receive_time - receive_time).count();
+
+            if (len <= 0) {
+                LOG(DEBUG) << "Received zero length for: " << received_messages;
+                continue;
+            }
+            received_messages++;
+            total_bytes_received += len;
+        }
+    }
+
+    auto end_time = std::chrono::high_resolution_clock::now();
+    average_latency = static_cast<double>(total_latency) / received_messages;
+    return true;
+}
+
+// Function for receiving thread using recvmsg()
+void receiveThread(int sock_recv, int num_threads, long long& total_bytes_received,
+                   double& average_latency) {
+    char recv_buffer[MESSAGE_SIZE];
+    struct ucred cred;
+
+    struct iovec iov_recv;
+    iov_recv.iov_base = recv_buffer;
+    iov_recv.iov_len = MESSAGE_SIZE;
+
+    struct msghdr msg_recv;
+    memset(&msg_recv, 0, sizeof(msg_recv));
+    msg_recv.msg_iov = &iov_recv;
+    msg_recv.msg_iovlen = 1;
+
+    char control_buffer_recv[CMSG_SPACE(sizeof(cred))];
+    memset(control_buffer_recv, 0, sizeof(control_buffer_recv));
+    msg_recv.msg_control = control_buffer_recv;
+    msg_recv.msg_controllen = sizeof(control_buffer_recv);
+
+    struct pollfd pfd;
+    pfd.fd = sock_recv;
+    pfd.events = POLLIN;
+
+    long long received_messages = 0;
+    auto start_time = std::chrono::high_resolution_clock::now();
+    long long total_latency = 0;
+
+    while (received_messages < num_threads * NUM_MESSAGES_PER_THREAD) {
+        auto receive_time = std::chrono::high_resolution_clock::now();
+        if (poll(&pfd, 1, -1) > 0) {
+            ssize_t received_bytes = recvmsg(sock_recv, &msg_recv, 0);
+            if (received_bytes < 0) {
+                perror("recvmsg failed");
+                break;
+            }
+
+            auto end_receive_time = std::chrono::high_resolution_clock::now();
+            total_latency += std::chrono::duration_cast<std::chrono::microseconds>(
+                              end_receive_time - receive_time).count();
+
+            received_messages++;
+            total_bytes_received += received_bytes;
+        }
+    }
+
+    auto end_time = std::chrono::high_resolution_clock::now();
+    average_latency = static_cast<double>(total_latency) / received_messages;
+}
+
+static int CreateServerSocket(std::string& path) {
+    int sock_recv = socket(AF_UNIX, SOCK_DGRAM, 0);
+    if (sock_recv < 0) {
+        PLOG(ERROR) << "socket failed";
+        return -1;
+    }
+
+    std::string tmp_path = android::base::GetExecutableDirectory();
+    std::string socket_path = tmp_path + "/temp.sock";
+    struct sockaddr_un addr_recv;
+    memset(&addr_recv, 0, sizeof(addr_recv));
+    addr_recv.sun_family = AF_UNIX;
+    strcpy(addr_recv.sun_path, socket_path.c_str());
+
+    unlink(socket_path.c_str()); // Remove existing socket file if any
+
+    if (bind(sock_recv, (struct sockaddr*)&addr_recv, sizeof(addr_recv)) < 0) {
+        PLOG(ERROR) << "bind failed";
+        close(sock_recv);
+        return -1;
+    }
+
+    path = socket_path;
+    return sock_recv;
+}
+
+static void SocketBenchMark(benchmark::State& state, const bool io_uring) {
+  state.PauseTiming();
+  while (state.KeepRunning()) {
+    std::string socket_path;
+    int sock_recv = CreateServerSocket(socket_path);
+    if (sock_recv < 0) {
+        LOG(ERROR) << "CreateServerSocket failed";
+        return;
+    }
+
+    const size_t num_sender_threads = state.range(0);
+    const size_t sync_sender = state.range(1);
+    std::vector<int> sender_sockets(num_sender_threads);
+    // Sender socket setup (for each thread)
+    for (int i = 0; i < num_sender_threads; ++i) {
+        int sock_send = socket(AF_UNIX, SOCK_DGRAM, 0);
+        if (sock_send < 0) {
+            perror("socket failed");
+            return;
+        }
+
+        if (!sync_sender) {
+          // Set non-blocking for the sender socket
+          int flags = fcntl(sock_send, F_GETFL, 0);
+          if (flags == -1) {
+            perror("fcntl F_GETFL failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+              close(sender_sockets[j]);
+            }
+            close(sock_recv);
+            return;
+          }
+          if (fcntl(sock_send, F_SETFL, flags | O_NONBLOCK) == -1) {
+            perror("fcntl F_SETFL failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+              close(sender_sockets[j]);
+            }
+            close(sock_recv);
+            return;
+          }
+        }
+
+        struct sockaddr_un addr_send;
+        memset(&addr_send, 0, sizeof(addr_send));
+        addr_send.sun_family = AF_UNIX;
+        strcpy(addr_send.sun_path, socket_path.c_str()); // Connect to the receiver
+
+        if (connect(sock_send, (struct sockaddr*)&addr_send, sizeof(addr_send)) < 0) {
+            perror("connect failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+                close(sender_sockets[j]);
+            }
+            close(sock_recv);
+            return;
+        }
+
+        sender_sockets[i] = sock_send;
+    }
+
+    std::vector<std::thread> send_threads;
+    for (int i = 0; i < num_sender_threads; ++i) {
+        send_threads.emplace_back(sendThread, sender_sockets[i], sync_sender);
+    }
+
+    long long total_bytes_received = 0;
+    double average_latency = 0.0;
+
+    // Reset counters for each benchmark iteration
+    total_bytes_received = 0;
+    average_latency = 0.0;
+
+    state.ResumeTiming();
+    if (io_uring) {
+        receiveThreaduring(sock_recv, num_sender_threads,
+                           std::ref(total_bytes_received), std::ref(average_latency));
+    } else {
+        receiveThread(sock_recv, num_sender_threads,
+                      std::ref(total_bytes_received), std::ref(average_latency));
+    }
+    state.PauseTiming();
+
+    for (auto& thread : send_threads) {
+        thread.join();
+    }
+
+    state.counters["Total_Data"] = total_bytes_received;
+    state.counters["Latency(usec)"] = average_latency;
+    state.SetBytesProcessed(total_bytes_received);
+    state.SetItemsProcessed(num_sender_threads * NUM_MESSAGES_PER_THREAD);
+
+    // Cleanup
+    close(sock_recv);
+    unlink(socket_path.c_str()); // Remove the socket file
+
+    for (int sock : sender_sockets) {
+        close(sock);
+    }
+  }
+  SetLabel(state);
+}
+
+static void BM_ReceiveIOUring(benchmark::State& state) {
+    SocketBenchMark(state, true);
+}
+BENCHMARK(BM_ReceiveIOUring)->BENCH_OPTIONS
+
+static void BM_ReceiveSync(benchmark::State& state) {
+    SocketBenchMark(state, false);
+}
+BENCHMARK(BM_ReceiveSync)->BENCH_OPTIONS
+
+int main(int argc, char** argv) {
+    android::base::InitLogging(argv, &android::base::StderrLogger);
+    benchmark::Initialize(&argc, argv);
+    benchmark::RunSpecifiedBenchmarks();
+    return 0;
+}
diff --git a/src/IOUringSocketHandlerReceiver.cpp b/src/IOUringSocketHandlerReceiver.cpp
new file mode 100644
index 0000000..dd4763f
--- /dev/null
+++ b/src/IOUringSocketHandlerReceiver.cpp
@@ -0,0 +1,246 @@
+#include <iostream>
+#include <cstring>
+#include <vector>
+#include <thread>
+#include <chrono>
+#include <cstring>
+#include <unistd.h>
+#include <sys/socket.h>
+#include <sys/un.h>
+#include <poll.h>
+#include <unistd.h>
+#include <random>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+
+#include <android-base/scopeguard.h>
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+
+#include <benchmark/benchmark.h>
+
+// Registered buffers
+#define MAX_BUFFERS 256
+
+// Threads sending 4k payload - 1 Million times
+const int MESSAGE_SIZE = 4096; // 4KB
+const int NUM_MESSAGES_PER_THREAD = 1000000;
+
+static bool io_uring = false;
+static bool sync_receive = false;
+
+// The benchmark is set to run 4 times with
+// the following combinations:
+//
+// a: {1, 4, 8, 16} -> This is the number of sender threads
+// b: {0, 1} -> Whether sender is blocking or non-blocking
+#define BENCH_OPTIONS                 \
+  MeasureProcessCPUTime()             \
+      ->Unit(benchmark::kSecond) \
+      ->Iterations(1)                \
+      ->Repetitions(1)                \
+      ->ReportAggregatesOnly(true) \
+      ->ArgsProduct({{16}, {0}});
+
+static void SetLabel(benchmark::State& state) {
+    std::string num_senders = std::to_string(state.range(0));
+    std::string type = state.range(1) == 0 ? "non-blocking" : "blocking";
+    state.SetLabel(num_senders + "-SendThreads" + "/" + type);
+}
+
+// Receive using io_uring
+bool receiveThreaduring(int sock_recv, int num_threads, uint64_t& total_bytes_received,
+                        double& average_latency) {
+    std::unique_ptr<IOUringSocketHandler> async_listener_;
+    async_listener_ = std::make_unique<IOUringSocketHandler>(sock_recv);
+    if (!async_listener_->SetupIoUring(MAX_BUFFERS)) {
+        LOG(ERROR) << "SetupIoUring failed";
+        return false;
+    }
+    async_listener_->AllocateAndRegisterBuffers(
+        MAX_BUFFERS, MESSAGE_SIZE);
+
+    if (!async_listener_->EnqueueMultishotRecvmsg()) {
+        LOG(ERROR) << "EnqueueMultishotRecvmsg failed";
+        return false;
+    }
+
+    long long received_messages = 0;
+    auto start_time = std::chrono::high_resolution_clock::now();
+    long long total_latency = 0;
+
+    while (received_messages < num_threads * NUM_MESSAGES_PER_THREAD) {
+        struct ucred* cred = nullptr;
+        void* this_recv = nullptr;
+        size_t len = 0;
+        auto receive_time = std::chrono::high_resolution_clock::now();
+        async_listener_->ReceiveData(&this_recv, len, &cred);
+        // Release the buffer from here onwards
+        {
+            auto scope_guard =
+                android::base::make_scope_guard([&async_listener_]() -> void {
+                  async_listener_->ReleaseBuffer(); });
+            auto end_receive_time = std::chrono::high_resolution_clock::now();
+            total_latency += std::chrono::duration_cast<std::chrono::microseconds>(
+                              end_receive_time - receive_time).count();
+
+            if (len <= 0) {
+                LOG(DEBUG) << "Received zero length for: " << received_messages;
+                continue;
+            }
+            received_messages++;
+            total_bytes_received += len;
+        }
+    }
+
+    auto end_time = std::chrono::high_resolution_clock::now();
+    average_latency = static_cast<double>(total_latency) / received_messages;
+    return true;
+}
+
+// Function for receiving thread using recvmsg()
+void receiveThread(int sock_recv, int num_threads, uint64_t& total_bytes_received,
+                   double& average_latency) {
+    char recv_buffer[MESSAGE_SIZE];
+    struct ucred cred;
+
+    struct iovec iov_recv;
+    iov_recv.iov_base = recv_buffer;
+    iov_recv.iov_len = MESSAGE_SIZE;
+
+    struct msghdr msg_recv;
+    memset(&msg_recv, 0, sizeof(msg_recv));
+    msg_recv.msg_iov = &iov_recv;
+    msg_recv.msg_iovlen = 1;
+
+    char control_buffer_recv[CMSG_SPACE(sizeof(cred))];
+    memset(control_buffer_recv, 0, sizeof(control_buffer_recv));
+    msg_recv.msg_control = control_buffer_recv;
+    msg_recv.msg_controllen = sizeof(control_buffer_recv);
+
+    struct pollfd pfd;
+    pfd.fd = sock_recv;
+    pfd.events = POLLIN;
+
+    long long received_messages = 0;
+    auto start_time = std::chrono::high_resolution_clock::now();
+    long long total_latency = 0;
+
+    while (received_messages < num_threads * NUM_MESSAGES_PER_THREAD) {
+        auto receive_time = std::chrono::high_resolution_clock::now();
+        if (poll(&pfd, 1, -1) > 0) {
+            ssize_t received_bytes = recvmsg(sock_recv, &msg_recv, 0);
+            if (received_bytes < 0) {
+                perror("recvmsg failed");
+                break;
+            }
+
+            auto end_receive_time = std::chrono::high_resolution_clock::now();
+            total_latency += std::chrono::duration_cast<std::chrono::microseconds>(
+                              end_receive_time - receive_time).count();
+
+            received_messages++;
+            total_bytes_received += received_bytes;
+        }
+    }
+
+    auto end_time = std::chrono::high_resolution_clock::now();
+    average_latency = static_cast<double>(total_latency) / received_messages;
+}
+
+static int CreateServerSocket(std::string& path) {
+    int sock_recv = socket(AF_UNIX, SOCK_DGRAM, 0);
+    if (sock_recv < 0) {
+        PLOG(ERROR) << "socket failed";
+        return -1;
+    }
+
+    std::string tmp_path = android::base::GetExecutableDirectory();
+    std::string socket_path = tmp_path + "/temp.sock";
+    struct sockaddr_un addr_recv;
+    memset(&addr_recv, 0, sizeof(addr_recv));
+    addr_recv.sun_family = AF_UNIX;
+    strcpy(addr_recv.sun_path, socket_path.c_str());
+
+    unlink(socket_path.c_str()); // Remove existing socket file if any
+
+    if (bind(sock_recv, (struct sockaddr*)&addr_recv, sizeof(addr_recv)) < 0) {
+        PLOG(ERROR) << "bind failed";
+        close(sock_recv);
+        return -1;
+    }
+
+    path = socket_path;
+    return sock_recv;
+}
+
+static void SocketBenchMark(benchmark::State& state, const bool io_uring) {
+  state.PauseTiming();
+  while (state.KeepRunning()) {
+    std::string socket_path;
+    int sock_recv = CreateServerSocket(socket_path);
+    if (sock_recv < 0) {
+        LOG(ERROR) << "CreateServerSocket failed";
+        return;
+    }
+
+    const size_t num_sender_threads = state.range(0);
+    const size_t blocking = state.range(1);
+    uint64_t total_bytes_received = 0;
+    double average_latency = 0;
+    state.ResumeTiming();
+    if (io_uring) {
+        receiveThreaduring(sock_recv, num_sender_threads,
+                           std::ref(total_bytes_received), std::ref(average_latency));
+    } else {
+        receiveThread(sock_recv, num_sender_threads,
+                      std::ref(total_bytes_received), std::ref(average_latency));
+    }
+    state.PauseTiming();
+
+    state.counters["Total_Data"] = total_bytes_received;
+    state.counters["Latency(usec)"] = average_latency;
+    state.SetBytesProcessed(total_bytes_received);
+    state.SetItemsProcessed(num_sender_threads * NUM_MESSAGES_PER_THREAD);
+
+    // Cleanup
+    close(sock_recv);
+    unlink(socket_path.c_str()); // Remove the socket file
+  }
+  SetLabel(state);
+}
+
+static void BM_ReceiveIOUring(benchmark::State& state) {
+    if (io_uring) {
+        SocketBenchMark(state, true);
+    }
+}
+BENCHMARK(BM_ReceiveIOUring)->BENCH_OPTIONS
+
+static void BM_ReceiveSync(benchmark::State& state) {
+    if (sync_receive) {
+        SocketBenchMark(state, false);
+    }
+}
+BENCHMARK(BM_ReceiveSync)->BENCH_OPTIONS
+
+int main(int argc, char** argv) {
+    android::base::InitLogging(argv, &android::base::StderrLogger);
+
+    if (argc != 2) {
+        std::cerr << "IOUringSocketHandlerReceiver {-io-uring | -sync}\n";
+        return 0;
+    }
+    if (std::string(argv[1]) == "-io-uring") {
+        io_uring = true;
+    } else if (std::string(argv[1]) == "-sync") {
+        sync_receive = true;
+    } else {
+        std::cerr << "IOUringSocketHandlerReceiver {-io-uring | -sync}\n";
+        return 0;
+    }
+
+    benchmark::Initialize(&argc, argv);
+    benchmark::RunSpecifiedBenchmarks();
+    return 0;
+}
diff --git a/src/IOUringSocketHandlerSender.cpp b/src/IOUringSocketHandlerSender.cpp
new file mode 100644
index 0000000..3e9aae6
--- /dev/null
+++ b/src/IOUringSocketHandlerSender.cpp
@@ -0,0 +1,197 @@
+#include <iostream>
+#include <cstring>
+#include <vector>
+#include <thread>
+#include <chrono>
+#include <cstring>
+#include <unistd.h>
+#include <sys/socket.h>
+#include <sys/un.h>
+#include <poll.h>
+#include <unistd.h>
+#include <random>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+
+#include <android-base/scopeguard.h>
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+
+#include <benchmark/benchmark.h>
+
+// Registered buffers
+#define MAX_BUFFERS 256
+
+// Threads sending 4k payload - 1 Million times
+const int MESSAGE_SIZE = 4096; // 4KB
+const int NUM_MESSAGES_PER_THREAD = 1000000;
+
+// The benchmark is set to run 4 times with
+// the following combinations:
+//
+// a: {1, 4, 8, 16} -> This is the number of sender threads
+// b: {0, 1} -> Whether sender is non-blocking or blocking
+#define BENCH_OPTIONS                 \
+  MeasureProcessCPUTime()             \
+      ->Unit(benchmark::kSecond) \
+      ->Iterations(1)                \
+      ->Repetitions(1)                \
+      ->ReportAggregatesOnly(true) \
+      ->ArgsProduct({{16}, {0}});
+
+// Function to generate a random string
+std::string generateRandomString(size_t length) {
+    static const char charset[] =
+        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
+    std::random_device rd;
+    std::mt19937 gen(rd());
+    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
+
+    std::string str(length, 0);
+    for (size_t i = 0; i < length; ++i) {
+        str[i] = charset[dis(gen)];
+    }
+    return str;
+}
+
+static void SetLabel(benchmark::State& state) {
+    std::string num_senders = std::to_string(state.range(0));
+    std::string type = state.range(1) == 0 ? "non-blocking" : "blocking";
+    state.SetLabel(num_senders + "-SendThreads" + "/" + type);
+}
+
+// Function for sending thread
+void sendThread(int sock_send, int blocking) {
+    std::string message = generateRandomString(MESSAGE_SIZE);
+
+    struct ucred cred;
+    memset(&cred, 0, sizeof(cred));
+    cred.pid = getpid();
+    cred.uid = getuid();
+    cred.gid = getgid();
+
+    struct iovec iov_send;
+    iov_send.iov_base = const_cast<char*>(message.data());
+    iov_send.iov_len = MESSAGE_SIZE;
+
+    struct msghdr msg_send;
+    memset(&msg_send, 0, sizeof(msg_send));
+    msg_send.msg_iov = &iov_send;
+    msg_send.msg_iovlen = 1;
+
+    char control_buffer_send[CMSG_SPACE(sizeof(cred))];
+    memset(control_buffer_send, 0, sizeof(control_buffer_send));
+    msg_send.msg_control = control_buffer_send;
+    msg_send.msg_controllen = sizeof(control_buffer_send);
+
+    struct cmsghdr* cmsg_send = CMSG_FIRSTHDR(&msg_send);
+    cmsg_send->cmsg_level = SOL_SOCKET;
+    cmsg_send->cmsg_type = SCM_CREDENTIALS;
+    cmsg_send->cmsg_len = CMSG_LEN(sizeof(cred));
+    memcpy(CMSG_DATA(cmsg_send), &cred, sizeof(cred));
+
+    int flags = 0;
+    if (!blocking) {
+        flags = MSG_DONTWAIT;
+    }
+    for (int i = 0; i < NUM_MESSAGES_PER_THREAD; ++i) {
+        ssize_t sent_bytes;
+        while (true) {
+            sent_bytes = sendmsg(sock_send, &msg_send, flags);
+            if (sent_bytes >= 0) {
+                break; // Success
+            }
+            if (errno == EAGAIN || errno == EWOULDBLOCK) {
+                // Try again
+                continue;
+            } else {
+                perror("sendmsg failed");
+                return;
+            }
+        }
+    }
+    LOG(DEBUG) << "sendThread exiting";
+}
+
+static void SocketBenchMark(benchmark::State& state, const bool) {
+  state.PauseTiming();
+  while (state.KeepRunning()) {
+    std::string tmp_path = android::base::GetExecutableDirectory();
+    std::string socket_path = tmp_path + "/temp.sock";
+
+    const size_t num_sender_threads = state.range(0);
+    const size_t blocking = state.range(1);
+    std::vector<int> sender_sockets(num_sender_threads);
+    // Sender socket setup (for each thread)
+    for (int i = 0; i < num_sender_threads; ++i) {
+        int sock_send = socket(AF_UNIX, SOCK_DGRAM, 0);
+        if (sock_send < 0) {
+            perror("socket failed");
+            return;
+        }
+
+        if (!blocking) {
+          // Set non-blocking for the sender socket
+          int flags = fcntl(sock_send, F_GETFL, 0);
+          if (flags == -1) {
+            perror("fcntl F_GETFL failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+              close(sender_sockets[j]);
+            }
+            return;
+          }
+          if (fcntl(sock_send, F_SETFL, flags | O_NONBLOCK) == -1) {
+            perror("fcntl F_SETFL failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+              close(sender_sockets[j]);
+            }
+            return;
+          }
+        }
+
+        struct sockaddr_un addr_send;
+        memset(&addr_send, 0, sizeof(addr_send));
+        addr_send.sun_family = AF_UNIX;
+        strcpy(addr_send.sun_path, socket_path.c_str()); // Connect to the receiver
+
+        if (connect(sock_send, (struct sockaddr*)&addr_send, sizeof(addr_send)) < 0) {
+            perror("connect failed");
+            close(sock_send);
+            for (int j = 0; j < i; ++j) { // Close previously opened sockets
+                close(sender_sockets[j]);
+            }
+            return;
+        }
+
+        sender_sockets[i] = sock_send;
+    }
+
+    std::vector<std::thread> send_threads;
+    for (int i = 0; i < num_sender_threads; ++i) {
+        send_threads.emplace_back(sendThread, sender_sockets[i], blocking);
+    }
+    for (auto& thread : send_threads) {
+        thread.join();
+    }
+
+    for (int sock : sender_sockets) {
+        close(sock);
+    }
+    LOG(INFO) << "Sending data complete";
+  }
+  SetLabel(state);
+}
+
+static void BM_Sender(benchmark::State& state) {
+    SocketBenchMark(state, true);
+}
+BENCHMARK(BM_Sender)->BENCH_OPTIONS
+
+int main(int argc, char** argv) {
+    android::base::InitLogging(argv, &android::base::StderrLogger);
+    benchmark::Initialize(&argc, argv);
+    benchmark::RunSpecifiedBenchmarks();
+    return 0;
+}
diff --git a/src/IOUringSocketHandler_test.cpp b/src/IOUringSocketHandler_test.cpp
index bd352cf..2135891 100644
--- a/src/IOUringSocketHandler_test.cpp
+++ b/src/IOUringSocketHandler_test.cpp
@@ -14,37 +14,123 @@
  * limitations under the License.
  */
 
+#include <chrono>
+#include <iostream>
+#include <cstring>
+#include <vector>
+#include <thread>
+#include <chrono>
+#include <cstring>
+#include <unistd.h>
+#include <sys/socket.h>
+#include <sys/un.h>
+#include <poll.h>
+#include <unistd.h>
+#include <random>
+#include <future>
+#include <thread>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/scopeguard.h>
 #include <IOUringSocketHandler/IOUringSocketHandler.h>
 
 #include <gtest/gtest.h>
 
-class IOUringSocketHandlerTest : public testing::Test {
+// Test all combinations of queue_depth and messages
+struct TestParam {
+    int queue_depth;
+    int numMessages;
+    int messageSize;
+};
+
+class IOUringSocketHandlerTest : public ::testing::TestWithParam<TestParam> {
 public:
-    bool IsIouringEnabled() {
-        return IOUringSocketHandler::isIouringEnabled();
+    bool IsIouringSupported() {
+        return IOUringSocketHandler::IsIouringSupported();
     }
+    void SendMsg(int sock_send, const bool non_block);
 
 protected:
+    void SetUp() override {
+    }
+    void TearDown() override {
+        close(sock_recv_);
+        unlink(socket_path_.c_str());
+    }
+    void ReceiveThreaduring(int sock_recv);
+    bool CreateServerSocket();
     std::unique_ptr<IOUringSocketHandler> handler_;
     void InitializeHandler(int socket_fd = 1);
-    int queue_depth_ = 10;
+    // Default queue depth
+    int queue_depth_ = 1;
+    int sock_recv_;
+    std::string socket_path_;
+    std::vector<std::string> sent_messages; // Store sent messages for comparison
 };
 
+bool IOUringSocketHandlerTest::CreateServerSocket() {
+    int sock_recv = socket(AF_UNIX, SOCK_DGRAM, 0);
+    if (sock_recv < 0) {
+        PLOG(ERROR) << "socket failed";
+        return false;
+    }
+
+    std::string tmp_path = android::base::GetExecutableDirectory();
+    std::string socket_path = tmp_path + "/temp.sock";
+    struct sockaddr_un addr_recv;
+    memset(&addr_recv, 0, sizeof(addr_recv));
+    addr_recv.sun_family = AF_UNIX;
+    strcpy(addr_recv.sun_path, socket_path.c_str());
+
+    unlink(socket_path.c_str()); // Remove existing socket file if any
+
+    if (bind(sock_recv, (struct sockaddr*)&addr_recv, sizeof(addr_recv)) < 0) {
+        PLOG(ERROR) << "bind failed";
+        close(sock_recv);
+        return false;
+    }
+
+    int on = 1;
+    if (setsockopt(sock_recv, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
+        return false;
+    }
+
+    sock_recv_ = sock_recv;
+    socket_path_ = socket_path;
+    return true;
+}
+
+// Function to generate a random string
+static std::string generateRandomString(size_t length) {
+    static const char charset[] =
+        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
+    std::random_device rd;
+    std::mt19937 gen(rd());
+    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
+
+    std::string str(length, 0);
+    for (size_t i = 0; i < length; ++i) {
+        str[i] = charset[dis(gen)];
+    }
+    return str;
+}
+
 void IOUringSocketHandlerTest::InitializeHandler(int socket_fd) {
     handler_ = std::make_unique<IOUringSocketHandler>(socket_fd);
 }
 
 TEST_F(IOUringSocketHandlerTest, SetupIoUring) {
-    if (!IsIouringEnabled()) {
-        return;
+    if (!IsIouringSupported()) {
+        GTEST_SKIP() << "io_uring not supported. Skipping Test.";
     }
     InitializeHandler();
     EXPECT_TRUE(handler_->SetupIoUring(queue_depth_));
 }
 
 TEST_F(IOUringSocketHandlerTest, AllocateAndRegisterBuffers) {
-    if (!IsIouringEnabled()) {
-        return;
+    if (!IsIouringSupported()) {
+        GTEST_SKIP() << "io_uring not supported. Skipping Test.";
     }
     InitializeHandler();
     EXPECT_TRUE(handler_->SetupIoUring(queue_depth_));
@@ -52,8 +138,8 @@ TEST_F(IOUringSocketHandlerTest, AllocateAndRegisterBuffers) {
 }
 
 TEST_F(IOUringSocketHandlerTest, MultipleAllocateAndRegisterBuffers) {
-    if (!IsIouringEnabled()) {
-        return;
+    if (!IsIouringSupported()) {
+        GTEST_SKIP() << "io_uring not supported. Skipping Test.";
     }
     InitializeHandler();
 
@@ -72,6 +158,184 @@ TEST_F(IOUringSocketHandlerTest, MultipleAllocateAndRegisterBuffers) {
     EXPECT_FALSE(handler_->AllocateAndRegisterBuffers(5, 4096));
 }
 
+void IOUringSocketHandlerTest::SendMsg(int sock_send, const bool non_block) {
+   const TestParam params = GetParam();
+   for (int i = 0; i < params.numMessages; ++i) {
+     std::string message = generateRandomString(params.messageSize);
+
+     sent_messages.push_back(message);
+     struct ucred cred;
+     memset(&cred, 0, sizeof(cred));
+     cred.pid = getpid();
+     cred.uid = getuid();
+     cred.gid = getgid();
+
+     struct iovec iov_send;
+     iov_send.iov_base = const_cast<char*>(message.data());
+     iov_send.iov_len = params.messageSize;
+
+     struct msghdr msg_send;
+     memset(&msg_send, 0, sizeof(msg_send));
+     msg_send.msg_iov = &iov_send;
+     msg_send.msg_iovlen = 1;
+
+     char control_buffer_send[CMSG_SPACE(sizeof(cred))];
+     memset(control_buffer_send, 0, sizeof(control_buffer_send));
+     msg_send.msg_control = control_buffer_send;
+     msg_send.msg_controllen = sizeof(control_buffer_send);
+
+     struct cmsghdr* cmsg_send = CMSG_FIRSTHDR(&msg_send);
+     cmsg_send->cmsg_level = SOL_SOCKET;
+     cmsg_send->cmsg_type = SCM_CREDENTIALS;
+     cmsg_send->cmsg_len = CMSG_LEN(sizeof(cred));
+     memcpy(CMSG_DATA(cmsg_send), &cred, sizeof(cred));
+
+     int flags = 0;
+     if (non_block) {
+        flags = MSG_DONTWAIT;
+     }
+     ssize_t sent_bytes;
+        while (true) {
+            sent_bytes = sendmsg(sock_send, &msg_send, flags);
+            if (sent_bytes >= 0) {
+                break; // Success
+            }
+            if (errno == EAGAIN || errno == EWOULDBLOCK) {
+                // Try again
+                continue;
+            } else {
+                perror("sendmsg failed");
+                return;
+            }
+        }
+    }
+}
+
+void IOUringSocketHandlerTest::ReceiveThreaduring(int sock_recv) {
+    std::unique_ptr<IOUringSocketHandler> uring_listener;
+    uring_listener = std::make_unique<IOUringSocketHandler>(sock_recv);
+    const TestParam params = GetParam();
+    ASSERT_TRUE(uring_listener->SetupIoUring(params.queue_depth));
+    uring_listener->AllocateAndRegisterBuffers(
+        params.queue_depth, params.messageSize);
+
+    ASSERT_TRUE(uring_listener->EnqueueMultishotRecvmsg());
+
+    long long received_messages = 0;
+    int index = 0;
+    while (received_messages < params.numMessages) {
+        struct ucred* cred = nullptr;
+        void* this_recv = nullptr;
+        size_t len = 0;
+        uring_listener->ReceiveData(&this_recv, len, &cred);
+        // Release the buffer from here onwards
+        {
+            auto scope_guard =
+                android::base::make_scope_guard([&uring_listener]() -> void {
+                  uring_listener->ReleaseBuffer(); });
+
+            if (len <= 0) {
+                continue;
+            }
+            received_messages++;
+            char* char_ptr = static_cast<char*>(this_recv);
+            std::string payload_string(char_ptr, len);
+            std::string orig_string = sent_messages[index];
+            // Compare payload data
+            EXPECT_EQ(payload_string, orig_string);
+            // Verify credentials
+            EXPECT_EQ(cred->uid, getuid());
+            EXPECT_EQ(cred->gid, getgid());
+            EXPECT_EQ(cred->pid, getpid());
+            index += 1;
+        }
+    }
+}
+
+TEST_P(IOUringSocketHandlerTest, RecvmsgDataIntegrity) {
+  if (!IsIouringSupported()) {
+      GTEST_SKIP() << "io_uring not supported. Skipping Test.";
+  }
+  ASSERT_TRUE(CreateServerSocket());
+  int sock_send = socket(AF_UNIX, SOCK_DGRAM, 0);
+  ASSERT_GT(sock_send, 0);
+
+  struct sockaddr_un addr_send;
+  memset(&addr_send, 0, sizeof(addr_send));
+  addr_send.sun_family = AF_UNIX;
+  strcpy(addr_send.sun_path, socket_path_.c_str()); // Connect to the receiver
+
+  ASSERT_EQ(connect(sock_send, (struct sockaddr*)&addr_send, sizeof(addr_send)), 0);
+
+  std::vector<std::thread> send_threads;
+  send_threads.emplace_back([this, sock_send](){ SendMsg(sock_send, false); });
+  ReceiveThreaduring(sock_recv_);
+  for (auto& thread : send_threads) {
+    thread.join();
+  }
+  close(sock_send);
+  close(sock_recv_);
+  unlink(socket_path_.c_str());
+}
+
+TEST_P(IOUringSocketHandlerTest, RecvmsgDataIntegrityNonBlockingSend) {
+  if (!IsIouringSupported()) {
+      GTEST_SKIP() << "io_uring not supported. Skipping Test.";
+  }
+  ASSERT_TRUE(CreateServerSocket());
+  int sock_send = socket(AF_UNIX, SOCK_DGRAM, 0);
+  ASSERT_GT(sock_send, 0);
+
+  int flags = fcntl(sock_send, F_GETFL, 0);
+  // Set O_NONBLOCK
+  ASSERT_NE(fcntl(sock_send, F_SETFL, flags | O_NONBLOCK), -1);
+
+  struct sockaddr_un addr_send;
+  memset(&addr_send, 0, sizeof(addr_send));
+  addr_send.sun_family = AF_UNIX;
+  strcpy(addr_send.sun_path, socket_path_.c_str()); // Connect to the receiver
+
+  ASSERT_EQ(connect(sock_send, (struct sockaddr*)&addr_send, sizeof(addr_send)), 0);
+
+  std::vector<std::thread> send_threads;
+  send_threads.emplace_back([this, sock_send](){ SendMsg(sock_send, true); });
+
+  ReceiveThreaduring(sock_recv_);
+  for (auto& thread : send_threads) {
+    thread.join();
+  }
+
+  close(sock_send);
+  close(sock_recv_);
+  unlink(socket_path_.c_str());
+}
+
+std::vector<TestParam> GetConfigs() {
+  std::vector<TestParam> testParams;
+
+  std::vector<int> queue_depth = {1, 8, 16, 32, 64, 128, 256, 512};
+  std::vector<int> num_messages = {1, 100, 250, 500, 1000, 1500, 2000, 5000};
+  std::vector<int> message_sizes = {1, 100, 520, 1024, 2042, 3168, 4068, 4096};
+
+  // This will test 512 combinations
+  for (auto message_size: message_sizes) {
+    for (auto q_depth : queue_depth) {
+      for (auto n_messages : num_messages) {
+        TestParam param;
+        param.queue_depth = q_depth;
+        param.numMessages = n_messages;
+        param.messageSize = message_size;
+        testParams.push_back(std::move(param));
+      }
+    }
+  }
+
+  return testParams;
+}
+
+INSTANTIATE_TEST_SUITE_P(Io, IOUringSocketHandlerTest,
+                         ::testing::ValuesIn(GetConfigs()));
+
 int main(int argc, char** argv) {
     ::testing::InitGoogleTest(&argc, argv);
     return RUN_ALL_TESTS();
```

