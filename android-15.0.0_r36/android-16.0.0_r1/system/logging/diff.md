```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be1..cfa5095f 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,4 +5,3 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/liblog/include/android/log.h b/liblog/include/android/log.h
index 218ef2c3..b33f6095 100644
--- a/liblog/include/android/log.h
+++ b/liblog/include/android/log.h
@@ -59,6 +59,7 @@
 #include <stddef.h>
 #include <stdint.h>
 #include <sys/cdefs.h>
+#include <sys/time.h>
 
 #if !defined(__BIONIC__) && !defined(__INTRODUCED_IN)
 #define __INTRODUCED_IN(x)
@@ -93,8 +94,8 @@ typedef enum android_LogPriority {
 } android_LogPriority;
 
 /**
- * Writes the constant string `text` to the log, with priority `prio` and tag
- * `tag`.
+ * Writes the constant string `text` to the log,
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
  *
  * @return 1 if the message was written to the log, or -EPERM if it was not; see
  * __android_log_is_loggable().
@@ -102,7 +103,9 @@ typedef enum android_LogPriority {
 int __android_log_write(int prio, const char* tag, const char* text);
 
 /**
- * Writes a formatted string to the log, with priority `prio` and tag `tag`.
+ * Writes a formatted string to the log,
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
+ *
  * The details of formatting are the same as for
  * [printf(3)](http://man7.org/linux/man-pages/man3/printf.3.html).
  *
@@ -146,6 +149,7 @@ void __android_log_assert(const char* cond, const char* tag, const char* fmt, ..
  * and __android_log_buf_print().
  */
 typedef enum log_id {
+  /** For internal use only.  */
   LOG_ID_MIN = 0,
 
   /** The main log buffer. This is the only log buffer available to apps. */
@@ -165,39 +169,47 @@ typedef enum log_id {
   /** The kernel log buffer. */
   LOG_ID_KERNEL = 7,
 
+  /** For internal use only.  */
   LOG_ID_MAX,
 
-  /** Let the logging function choose the best log target. */
+  /**
+   * Let the logging library choose the best log target in cases where it's
+   * unclear. This is useful if you're generic library code that can't know
+   * which log your caller should use.
+   */
   LOG_ID_DEFAULT = 0x7FFFFFFF
 } log_id_t;
 
-static inline bool __android_log_id_is_valid(log_id_t id) {
-  return id >= LOG_ID_MIN && id < LOG_ID_MAX;
+static inline bool __android_log_id_is_valid(log_id_t log_id) {
+  return log_id >= LOG_ID_MIN && log_id < LOG_ID_MAX;
 }
 
 /**
- * Writes the constant string `text` to the log buffer `id`,
- * with priority `prio` and tag `tag`.
+ * Writes the string `text` to the log buffer `log_id` (one of the `log_id_t` values),
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
  *
- * Apps should use __android_log_write() instead.
+ * Apps should use __android_log_write() instead because LOG_ID_MAIN is the
+ * only log buffer available to them.
  *
  * @return 1 if the message was written to the log, or -EPERM if it was not; see
  * __android_log_is_loggable().
  */
-int __android_log_buf_write(int bufID, int prio, const char* tag, const char* text);
+int __android_log_buf_write(int log_id, int prio, const char* tag, const char* text);
 
 /**
- * Writes a formatted string to log buffer `id`,
- * with priority `prio` and tag `tag`.
+ * Writes a formatted string to the log buffer `log_id` (one of the `log_id_t` values),
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
+ *
  * The details of formatting are the same as for
  * [printf(3)](http://man7.org/linux/man-pages/man3/printf.3.html).
  *
- * Apps should use __android_log_print() instead.
+ * Apps should use __android_log_print() instead because LOG_ID_MAIN is the
+ * only log buffer available to them.
  *
  * @return 1 if the message was written to the log, or -EPERM if it was not; see
  * __android_log_is_loggable().
  */
-int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fmt, ...)
+int __android_log_buf_print(int log_id, int prio, const char* tag, const char* fmt, ...)
     __attribute__((__format__(printf, 4, 5)));
 
 /**
@@ -274,6 +286,22 @@ void __android_log_set_logger(__android_logger_function logger) __INTRODUCED_IN(
  */
 void __android_log_logd_logger(const struct __android_log_message* log_message) __INTRODUCED_IN(30);
 
+/**
+ * Writes the log message to logd using the passed in timestamp.  The messages are stored
+ * in logd in the order received not in order by timestamp.  When displaying the log, there is no
+ * guarantee that messages are in timestamp order and might cause messages with different times to
+ * be interleaved.  Filtering the log using a timestamp will work properly even if out of time
+ * order messages are present.
+ *
+ * @param log_message the log message to write, see {@link __android_log_message}.
+ * @param timestamp the time to use for this log message. The value is interpreted as a
+ * CLOCK_REALTIME value.
+ *
+ * Available since API level 37.
+ */
+void __android_log_logd_logger_with_timestamp(const struct __android_log_message* log_message,
+                                              const struct timespec* timestamp) __INTRODUCED_IN(37);
+
 /**
  * Writes the log message to stderr.  This is an {@link __android_logger_function} and can be provided to
  * __android_log_set_logger().  It is the default logger when running liblog on host.
diff --git a/liblog/liblog.map.txt b/liblog/liblog.map.txt
index 440e7df9..7e265c51 100644
--- a/liblog/liblog.map.txt
+++ b/liblog/liblog.map.txt
@@ -80,6 +80,11 @@ LIBLOG_R { # introduced=30
     __android_log_write_log_message;
 };
 
+LIBLOG_37 { # introduced=37
+  global:
+    __android_log_logd_logger_with_timestamp;
+};
+
 LIBLOG_PRIVATE {
   global:
     __android_log_pmsg_file_read;
diff --git a/liblog/logd_writer.cpp b/liblog/logd_writer.cpp
index 3d5cee67..e3204135 100644
--- a/liblog/logd_writer.cpp
+++ b/liblog/logd_writer.cpp
@@ -116,7 +116,7 @@ void LogdClose() {
   LogdSocket::NonBlockingSocket().Close();
 }
 
-int LogdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
+int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec, size_t nr) {
   ssize_t ret;
   static const unsigned headerLength = 1;
   struct iovec newVec[nr + headerLength];
diff --git a/liblog/logd_writer.h b/liblog/logd_writer.h
index 41197b59..966f523e 100644
--- a/liblog/logd_writer.h
+++ b/liblog/logd_writer.h
@@ -20,5 +20,5 @@
 
 #include <android/log.h>
 
-int LogdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);
+int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec, size_t nr);
 void LogdClose();
diff --git a/liblog/logger_write.cpp b/liblog/logger_write.cpp
index 2ed4887b..3c6ccd0f 100644
--- a/liblog/logger_write.cpp
+++ b/liblog/logger_write.cpp
@@ -196,22 +196,24 @@ void __android_log_call_aborter(const char* abort_message) {
 }
 
 #ifdef __ANDROID__
-static int write_to_log(log_id_t log_id, struct iovec* vec, size_t nr) {
-  int ret;
-  struct timespec ts;
-
+static int write_to_log(log_id_t log_id, struct iovec* vec, size_t nr,
+                        const struct timespec* timestamp = nullptr) {
   if (log_id == LOG_ID_KERNEL) {
     return -EINVAL;
   }
 
-  clock_gettime(CLOCK_REALTIME, &ts);
+  struct timespec ts;
+  if (LIKELY(timestamp == nullptr)) {
+    clock_gettime(CLOCK_REALTIME, &ts);
+    timestamp = &ts;
+  }
 
   if (log_id == LOG_ID_SECURITY) {
     if (vec[0].iov_len < 4) {
       return -EINVAL;
     }
 
-    ret = check_log_uid_permissions();
+    int ret = check_log_uid_permissions();
     if (ret < 0) {
       return ret;
     }
@@ -225,13 +227,13 @@ static int write_to_log(log_id_t log_id, struct iovec* vec, size_t nr) {
     }
   }
 
-  ret = LogdWrite(log_id, &ts, vec, nr);
-  PmsgWrite(log_id, &ts, vec, nr);
+  int ret = LogdWrite(log_id, timestamp, vec, nr);
+  PmsgWrite(log_id, timestamp, vec, nr);
 
   return ret;
 }
 #else
-static int write_to_log(log_id_t, struct iovec*, size_t) {
+static int write_to_log(log_id_t, struct iovec*, size_t, const struct timespec* = nullptr) {
   // Non-Android text logs should go to __android_log_stderr_logger, not here.
   // Non-Android binary logs are always dropped.
   return 1;
@@ -333,6 +335,11 @@ void __android_log_stderr_logger(const struct __android_log_message* log_message
 }
 
 void __android_log_logd_logger(const struct __android_log_message* log_message) {
+  __android_log_logd_logger_with_timestamp(log_message, nullptr);
+}
+
+void __android_log_logd_logger_with_timestamp(const struct __android_log_message* log_message,
+                                              const struct timespec* timestamp) {
   if (log_to_file_if_overridden(log_message)) return;
 
   int buffer_id = log_message->buffer_id == LOG_ID_DEFAULT ? LOG_ID_MAIN : log_message->buffer_id;
@@ -346,7 +353,7 @@ void __android_log_logd_logger(const struct __android_log_message* log_message)
   vec[2].iov_base = const_cast<void*>(static_cast<const void*>(log_message->message));
   vec[2].iov_len = strlen(log_message->message) + 1;
 
-  write_to_log(static_cast<log_id_t>(buffer_id), vec, 3);
+  write_to_log(static_cast<log_id_t>(buffer_id), vec, 3, timestamp);
 }
 
 int __android_log_write(int prio, const char* tag, const char* msg) {
@@ -375,7 +382,7 @@ void __android_log_write_log_message(__android_log_message* log_message) {
   logger_function(log_message);
 }
 
-int __android_log_buf_write(int bufID, int prio, const char* tag, const char* msg) {
+int __android_log_buf_write(int log_id, int prio, const char* tag, const char* msg) {
   ErrnoRestorer errno_restorer;
 
   if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
@@ -383,7 +390,7 @@ int __android_log_buf_write(int bufID, int prio, const char* tag, const char* ms
   }
 
   __android_log_message log_message = {
-      sizeof(__android_log_message), bufID, prio, tag, nullptr, 0, msg};
+      sizeof(__android_log_message), log_id, prio, tag, nullptr, 0, msg};
   __android_log_write_log_message(&log_message);
   return 1;
 }
@@ -425,7 +432,7 @@ int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
   return 1;
 }
 
-int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fmt, ...) {
+int __android_log_buf_print(int log_id, int prio, const char* tag, const char* fmt, ...) {
   ErrnoRestorer errno_restorer;
 
   if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
@@ -440,7 +447,7 @@ int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fm
   va_end(ap);
 
   __android_log_message log_message = {
-      sizeof(__android_log_message), bufID, prio, tag, nullptr, 0, buf};
+      sizeof(__android_log_message), log_id, prio, tag, nullptr, 0, buf};
   __android_log_write_log_message(&log_message);
   return 1;
 }
diff --git a/liblog/pmsg_writer.cpp b/liblog/pmsg_writer.cpp
index 1cf8f96c..b075a58e 100644
--- a/liblog/pmsg_writer.cpp
+++ b/liblog/pmsg_writer.cpp
@@ -67,7 +67,7 @@ void PmsgClose() {
   pmsg_fd = 0;
 }
 
-int PmsgWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
+int PmsgWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec, size_t nr) {
   static const unsigned headerLength = 2;
   struct iovec newVec[nr + headerLength];
   android_log_header_t header;
diff --git a/liblog/pmsg_writer.h b/liblog/pmsg_writer.h
index d5e1a1c2..59443c34 100644
--- a/liblog/pmsg_writer.h
+++ b/liblog/pmsg_writer.h
@@ -20,5 +20,5 @@
 
 #include <android/log.h>
 
-int PmsgWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);
+int PmsgWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec, size_t nr);
 void PmsgClose();
diff --git a/liblog/tests/liblog_test.cpp b/liblog/tests/liblog_test.cpp
index fb05c12e..9f1c8cd9 100644
--- a/liblog/tests/liblog_test.cpp
+++ b/liblog/tests/liblog_test.cpp
@@ -25,6 +25,7 @@
 #include <stdio.h>
 #include <string.h>
 #include <sys/types.h>
+#include <time.h>
 #include <unistd.h>
 
 #include <memory>
@@ -497,6 +498,57 @@ TEST(liblog, __android_log_buf_write_and_print__newline_space_prefix) {
   buf_write_test("\n Hello World \n");
 }
 
+TEST(liblog, __android_log_logd_logger_with_timestamp) {
+#ifdef __ANDROID__
+  static std::string kTestTag("liblog");
+  static std::string kTestMessage("Test message");
+
+  struct timespec ts = {};
+  clock_gettime(CLOCK_REALTIME, &ts);
+  // Subtract some time to make sure that this can't pass by accident.
+  ASSERT_GE(ts.tv_sec, 360);
+  ts.tv_sec -= 360;
+
+  RunLogTests(
+      LOG_ID_MAIN,
+      [&ts]() {
+        __android_log_message msg = {.struct_size = sizeof(__android_log_message),
+                                     .buffer_id = LOG_ID_MAIN,
+                                     .priority = ANDROID_LOG_ERROR,
+                                     .tag = kTestTag.c_str(),
+                                     .message = kTestMessage.c_str()};
+        __android_log_logd_logger_with_timestamp(&msg, &ts);
+      },
+      [&ts](log_msg log_msg, bool* found) {
+        if (log_msg.entry.sec != static_cast<uint32_t>(ts.tv_sec)) {
+          return;
+        }
+        if (log_msg.entry.nsec != static_cast<uint32_t>(ts.tv_nsec)) {
+          return;
+        }
+        char* msg = log_msg.msg();
+        if (msg == nullptr) {
+          return;
+        }
+
+        if (msg[0] != ANDROID_LOG_ERROR) {
+          return;
+        }
+        ++msg;
+        if (std::string(&msg[0]) != kTestTag) {
+          return;
+        }
+        msg = &msg[kTestTag.length() + 1];
+        if (std::string(msg) != kTestMessage) {
+          return;
+        }
+        *found = true;
+      });
+#else
+  GTEST_LOG_(INFO) << "This test does nothing.\n";
+#endif
+}
+
 #ifdef ENABLE_FLAKY_TESTS
 #ifdef __ANDROID__
 static unsigned signaled;
diff --git a/logcat/logpersist b/logcat/logpersist
index 1f93caee..7a41ab17 100755
--- a/logcat/logpersist
+++ b/logcat/logpersist
@@ -1,12 +1,6 @@
 #! /system/bin/sh
 # logpersist cat, start and stop handlers
 progname="${0##*/}"
-case `getprop ro.debuggable` in
-1) ;;
-*) echo "${progname} - Permission denied"
-   exit 1
-   ;;
-esac
 
 property=persist.logd.logpersistd
 
diff --git a/logcat/tests/logcat_test.cpp b/logcat/tests/logcat_test.cpp
index dc1df96c..9599dd80 100644
--- a/logcat/tests/logcat_test.cpp
+++ b/logcat/tests/logcat_test.cpp
@@ -1220,14 +1220,14 @@ TEST(logcat, blocking_clear) {
             break;
         }
 
-        int size, consumed, readable, max, payload;
+        int size, consumed, readable, max_entry, payload;
         char size_mult[4], consumed_mult[4], readable_mult[4];
-        size = consumed = max = payload = 0;
+        size = consumed = max_entry = payload = 0;
         if (8 == sscanf(buffer,
                         "events: ring buffer is %d %3s (%d %3s consumed, %d %3s readable),"
                         " max entry is %d B, max payload is %d B",
-                        &size, size_mult, &consumed, consumed_mult, &readable, readable_mult, &max,
-                        &payload)) {
+                        &size, size_mult, &consumed, consumed_mult, &readable, readable_mult,
+                        &max_entry, &payload)) {
             long full_size = size, full_consumed = consumed;
 
             switch (size_mult[0]) {
@@ -1257,9 +1257,8 @@ TEST(logcat, blocking_clear) {
                     break;
             }
             EXPECT_GT(full_size, full_consumed);
-            EXPECT_GT(full_size, max);
-            EXPECT_GT(max, payload);
-            EXPECT_GT(max, full_consumed);
+            EXPECT_GT(full_size, max_entry);
+            EXPECT_GT(max_entry, payload);
 
             ++minus_g;
             continue;
@@ -1684,7 +1683,7 @@ TEST(logcat, invalid_buffer) {
   ASSERT_TRUE(android::base::ReadFdToString(fileno(fp), &output));
   pclose(fp);
 
-  EXPECT_NE(std::string::npos, output.find("Unknown buffer 'foo'"));
+  EXPECT_NE(std::string::npos, output.find("Unknown -b buffer 'foo'")) << "Output:\n" << output;
 }
 
 static void SniffUid(const std::string& line, uid_t& uid) {
diff --git a/logd/LogAudit.cpp b/logd/LogAudit.cpp
index 01c78c2a..510e4b64 100644
--- a/logd/LogAudit.cpp
+++ b/logd/LogAudit.cpp
@@ -48,14 +48,13 @@ using android::base::GetBoolProperty;
     '<', '0' + LOG_MAKEPRI(LOG_AUTH, LOG_PRI(PRI)) / 10, \
         '0' + LOG_MAKEPRI(LOG_AUTH, LOG_PRI(PRI)) % 10, '>'
 
-LogAudit::LogAudit(LogBuffer* buf, int fdDmesg, LogStatistics* stats)
+LogAudit::LogAudit(LogBuffer* buf, int fdDmesg)
     : SocketListener(getLogSocket(), false),
       logbuf(buf),
       fdDmesg(fdDmesg),
       main(GetBoolProperty("ro.logd.auditd.main", true)),
       events(GetBoolProperty("ro.logd.auditd.events", true)),
-      initialized(false),
-      stats_(stats) {
+      initialized(false) {
     static const char auditd_message[] = { KMSG_PRIORITY(LOG_INFO),
                                            'l',
                                            'o',
@@ -235,7 +234,7 @@ int LogAudit::logPrint(const char* fmt, ...) {
             ++cp;
         }
         tid = pid;
-        uid = stats_->PidToUid(pid);
+        uid = android::pidToUid(pid);
         memmove(pidptr, cp, strlen(cp) + 1);
     }
 
@@ -322,7 +321,7 @@ int LogAudit::logPrint(const char* fmt, ...) {
         pid = tid;
         comm = "auditd";
     } else {
-        comm = commfree = stats_->PidToName(pid);
+        comm = commfree = android::pidToName(pid);
         if (!comm) {
             comm = "unknown";
         }
diff --git a/logd/LogAudit.h b/logd/LogAudit.h
index cc8e5087..f2ea632a 100644
--- a/logd/LogAudit.h
+++ b/logd/LogAudit.h
@@ -31,7 +31,7 @@ class LogAudit : public SocketListener {
     bool initialized;
 
   public:
-    LogAudit(LogBuffer* buf, int fdDmesg, LogStatistics* stats);
+    LogAudit(LogBuffer* buf, int fdDmesg);
     int log(char* buf, size_t len);
 
   protected:
@@ -44,6 +44,4 @@ class LogAudit : public SocketListener {
     std::string auditParse(const std::string& string, uid_t uid);
     int logPrint(const char* fmt, ...)
         __attribute__((__format__(__printf__, 2, 3)));
-
-    LogStatistics* stats_;
 };
diff --git a/logd/LogStatistics.cpp b/logd/LogStatistics.cpp
index 173b7330..bd20ed4c 100644
--- a/logd/LogStatistics.cpp
+++ b/logd/LogStatistics.cpp
@@ -22,6 +22,7 @@
 #include <pwd.h>
 #include <stdio.h>
 #include <string.h>
+#include <sys/stat.h>
 #include <sys/types.h>
 #include <unistd.h>
 
@@ -224,11 +225,6 @@ void LogStatistics::Subtract(LogStatisticsElement element) {
     tagNameTable.Subtract(TagNameKey(element), element);
 }
 
-const char* LogStatistics::UidToName(uid_t uid) const {
-    auto lock = std::lock_guard{lock_};
-    return UidToNameLocked(uid);
-}
-
 // caller must own and free character string
 const char* LogStatistics::UidToNameLocked(uid_t uid) const {
     // Local hard coded favourites
@@ -789,23 +785,12 @@ std::string LogStatistics::Format(uid_t uid, pid_t pid, unsigned int logMask) co
 namespace android {
 
 uid_t pidToUid(pid_t pid) {
-    char buffer[512];
-    snprintf(buffer, sizeof(buffer), "/proc/%u/status", pid);
-    FILE* fp = fopen(buffer, "re");
-    if (fp) {
-        while (fgets(buffer, sizeof(buffer), fp)) {
-            int uid = AID_LOGD;
-            char space = 0;
-            if ((sscanf(buffer, "Uid: %d%c", &uid, &space) == 2) &&
-                isspace(space)) {
-                fclose(fp);
-                return uid;
-            }
-        }
-        fclose(fp);
-    }
-    return AID_LOGD;  // associate this with the logger
+    char path[32];
+    snprintf(path, sizeof(path), "/proc/%u", pid);
+    struct stat sb;
+    return !stat(path, &sb) ? sb.st_uid : AID_LOGD;
 }
+
 }
 
 uid_t LogStatistics::PidToUid(pid_t pid) {
diff --git a/logd/LogStatistics.h b/logd/LogStatistics.h
index 5b9beab5..cec0fa42 100644
--- a/logd/LogStatistics.h
+++ b/logd/LogStatistics.h
@@ -522,7 +522,6 @@ class LogStatistics {
 
     const char* PidToName(pid_t pid) const EXCLUDES(lock_);
     uid_t PidToUid(pid_t pid) EXCLUDES(lock_);
-    const char* UidToName(uid_t uid) const EXCLUDES(lock_);
 
     void set_overhead(log_id_t id, size_t size) {
         auto lock = std::lock_guard{lock_};
diff --git a/logd/main.cpp b/logd/main.cpp
index 635a7a89..4465dea2 100644
--- a/logd/main.cpp
+++ b/logd/main.cpp
@@ -283,7 +283,7 @@ int main(int argc, char* argv[]) {
     LogAudit* al = nullptr;
     if (auditd) {
         int dmesg_fd = GetBoolProperty("ro.logd.auditd.dmesg", true) ? fdDmesg : -1;
-        al = new LogAudit(log_buffer, dmesg_fd, &log_statistics);
+        al = new LogAudit(log_buffer, dmesg_fd);
     }
 
     LogKlog* kl = nullptr;
diff --git a/rust/Android.bp b/rust/Android.bp
index 30cff5c2..4933bffb 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -8,6 +8,7 @@ rust_library {
     crate_name: "logger",
     srcs: ["logger.rs"],
     rustlibs: [
+        "libenv_filter",
         "libenv_logger",
         "liblog_rust",
     ],
@@ -81,6 +82,7 @@ rust_test {
     defaults: ["liblogger_test_defaults"],
     srcs: ["logger.rs"],
     rustlibs: [
+        "libenv_filter",
         "libenv_logger",
         "libandroid_logger",
     ],
@@ -90,7 +92,10 @@ rust_test_host {
     name: "logger_host_unit_tests",
     defaults: ["liblogger_test_defaults"],
     srcs: ["logger.rs"],
-    rustlibs: ["libenv_logger"],
+    rustlibs: [
+        "libenv_filter",
+        "libenv_logger",
+    ],
 }
 
 // The following tests are each run as separate targets because they all require a clean init state.
diff --git a/rust/logger.rs b/rust/logger.rs
index c1a77a84..ae0b1836 100644
--- a/rust/logger.rs
+++ b/rust/logger.rs
@@ -121,6 +121,8 @@ pub fn init(config: Config) -> bool {
     let mut builder = android_logger::Config::default();
     if let Some(log_level) = config.log_level {
         builder = builder.with_max_level(log_level);
+    } else {
+        builder = builder.with_max_level(log::LevelFilter::Off);
     }
     if let Some(custom_format) = config.custom_format {
         builder = builder.format(move |f, r| {
@@ -129,7 +131,7 @@ pub fn init(config: Config) -> bool {
         });
     }
     if let Some(filter_str) = config.filter {
-        let filter = env_logger::filter::Builder::new().parse(filter_str).build();
+        let filter = env_filter::Builder::new().parse(filter_str).build();
         builder = builder.with_filter(filter);
     }
     if let Some(tag) = config.tag {
```

