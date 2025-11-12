```diff
diff --git a/liblog/include/android/log.h b/liblog/include/android/log.h
index b33f6095..9131364b 100644
--- a/liblog/include/android/log.h
+++ b/liblog/include/android/log.h
@@ -93,57 +93,6 @@ typedef enum android_LogPriority {
   ANDROID_LOG_SILENT, /* only for SetMinPriority(); must be last */
 } android_LogPriority;
 
-/**
- * Writes the constant string `text` to the log,
- * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
- *
- * @return 1 if the message was written to the log, or -EPERM if it was not; see
- * __android_log_is_loggable().
- */
-int __android_log_write(int prio, const char* tag, const char* text);
-
-/**
- * Writes a formatted string to the log,
- * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
- *
- * The details of formatting are the same as for
- * [printf(3)](http://man7.org/linux/man-pages/man3/printf.3.html).
- *
- * @return 1 if the message was written to the log, or -EPERM if it was not; see
- * __android_log_is_loggable().
- */
-int __android_log_print(int prio, const char* tag, const char* fmt, ...)
-    __attribute__((__format__(printf, 3, 4)));
-
-/**
- * Equivalent to __android_log_print(), but taking a `va_list`.
- * (If __android_log_print() is like printf(), this is like vprintf().)
- *
- * @return 1 if the message was written to the log, or -EPERM if it was not; see
- * __android_log_is_loggable().
- */
-int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap)
-    __attribute__((__format__(printf, 3, 0)));
-
-/**
- * Writes an assertion failure to the log (as `ANDROID_LOG_FATAL`) and to
- * stderr, before calling
- * [abort(3)](http://man7.org/linux/man-pages/man3/abort.3.html).
- *
- * If `fmt` is non-null, `cond` is unused. If `fmt` is null, the string
- * `Assertion failed: %s` is used with `cond` as the string argument.
- * If both `fmt` and `cond` are null, a default string is provided.
- *
- * Most callers should use
- * [assert(3)](http://man7.org/linux/man-pages/man3/assert.3.html) from
- * `&lt;assert.h&gt;` instead, or the `__assert` and `__assert2` functions
- * provided by bionic if more control is needed. They support automatically
- * including the source filename and line number more conveniently than this
- * function.
- */
-void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...)
-    __attribute__((__noreturn__)) __attribute__((__format__(printf, 3, 4)));
-
 /**
  * Identifies a specific log buffer for __android_log_buf_write()
  * and __android_log_buf_print().
@@ -184,6 +133,17 @@ static inline bool __android_log_id_is_valid(log_id_t log_id) {
   return log_id >= LOG_ID_MIN && log_id < LOG_ID_MAX;
 }
 
+/**
+ * Writes the constant string `text` to the main log buffer,
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
+ *
+ * See __android_log_buf_write() to write to a different log buffer.
+ *
+ * @return 1 if the message was written to the log, or -EPERM if it was not; see
+ * __android_log_is_loggable().
+ */
+int __android_log_write(int prio, const char* tag, const char* text);
+
 /**
  * Writes the string `text` to the log buffer `log_id` (one of the `log_id_t` values),
  * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
@@ -196,6 +156,21 @@ static inline bool __android_log_id_is_valid(log_id_t log_id) {
  */
 int __android_log_buf_write(int log_id, int prio, const char* tag, const char* text);
 
+/**
+ * Writes a formatted string to the main log buffer,
+ * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
+ *
+ * The details of formatting are the same as for
+ * [printf(3)](http://man7.org/linux/man-pages/man3/printf.3.html).
+ *
+ * See __android_log_buf_print() to write to a different log buffer.
+ *
+ * @return 1 if the message was written to the log, or -EPERM if it was not; see
+ * __android_log_is_loggable().
+ */
+int __android_log_print(int prio, const char* tag, const char* fmt, ...)
+    __attribute__((__format__(printf, 3, 4)));
+
 /**
  * Writes a formatted string to the log buffer `log_id` (one of the `log_id_t` values),
  * with priority `prio` (one of the `android_LogPriority` values) and tag `tag`.
@@ -212,6 +187,35 @@ int __android_log_buf_write(int log_id, int prio, const char* tag, const char* t
 int __android_log_buf_print(int log_id, int prio, const char* tag, const char* fmt, ...)
     __attribute__((__format__(printf, 4, 5)));
 
+/**
+ * Equivalent to __android_log_print(), but taking a `va_list`.
+ * (If __android_log_print() is like printf(), this is like vprintf().)
+ *
+ * @return 1 if the message was written to the log, or -EPERM if it was not; see
+ * __android_log_is_loggable().
+ */
+int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap)
+    __attribute__((__format__(printf, 3, 0)));
+
+/**
+ * Writes an assertion failure to the main log buffer
+ * with priority `ANDROID_LOG_FATAL` -- and also to stderr -- before calling
+ * [abort(3)](http://man7.org/linux/man-pages/man3/abort.3.html).
+ *
+ * If `fmt` is non-null, `cond` is unused. If `fmt` is null, the string
+ * `Assertion failed: %s` is used with `cond` as the string argument.
+ * If both `fmt` and `cond` are null, a default string is provided.
+ *
+ * Most callers should use
+ * [assert(3)](http://man7.org/linux/man-pages/man3/assert.3.html) from
+ * `&lt;assert.h&gt;` instead, or the `__assert` and `__assert2` functions
+ * provided by bionic if more control is needed. They support automatically
+ * including the source filename and line number more conveniently than this
+ * function.
+ */
+void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...)
+    __attribute__((__noreturn__)) __attribute__((__format__(printf, 3, 4)));
+
 /**
  * Logger data struct used for writing log messages to liblog via __android_log_write_logger_data()
  * and sending log messages to user defined loggers specified in __android_log_set_logger().
@@ -243,6 +247,7 @@ struct __android_log_message {
  * Prototype for the 'logger' function that is called for every log message.
  */
 typedef void (*__android_logger_function)(const struct __android_log_message* log_message);
+
 /**
  * Prototype for the 'abort' function that is called when liblog will abort due to
  * __android_log_assert() failures.
diff --git a/liblog/include/log/logprint.h b/liblog/include/log/logprint.h
index 0cff6400..9f0df546 100644
--- a/liblog/include/log/logprint.h
+++ b/liblog/include/log/logprint.h
@@ -63,7 +63,9 @@ typedef struct AndroidLogEntry_t {
   int32_t tid;
   const char* tag;
   size_t tagLen;
+  // Message length does not include the null terminator in "message".
   size_t messageLen;
+  // Must be null terminated.
   const char* message;
 } AndroidLogEntry;
 
diff --git a/liblog/logd_reader.cpp b/liblog/logd_reader.cpp
index c73fde84..9ff8449d 100644
--- a/liblog/logd_reader.cpp
+++ b/liblog/logd_reader.cpp
@@ -21,7 +21,6 @@
 #include <inttypes.h>
 #include <poll.h>
 #include <stdarg.h>
-#include <stdatomic.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -280,7 +279,7 @@ static int logdOpen(struct logger_list* logger_list) {
   int ret, remaining, sock;
   bool set_timeout;
 
-  sock = atomic_load(&logger_list->fd);
+  sock = logger_list->fd.load();
   if (sock > 0) {
     return sock;
   }
@@ -361,7 +360,7 @@ static int logdOpen(struct logger_list* logger_list) {
     return ret;
   }
 
-  ret = atomic_exchange(&logger_list->fd, sock);
+  ret = logger_list->fd.exchange(sock);
   if ((ret > 0) && (ret != sock)) {
     close(ret);
   }
@@ -389,7 +388,7 @@ int LogdRead(struct logger_list* logger_list, struct log_msg* log_msg) {
 
 /* Close all the logs */
 void LogdClose(struct logger_list* logger_list) {
-  int sock = atomic_exchange(&logger_list->fd, -1);
+  int sock = logger_list->fd.exchange(-1);
   if (sock > 0) {
     close(sock);
   }
diff --git a/liblog/logd_writer.cpp b/liblog/logd_writer.cpp
index e3204135..0910fc09 100644
--- a/liblog/logd_writer.cpp
+++ b/liblog/logd_writer.cpp
@@ -21,7 +21,6 @@
 #include <inttypes.h>
 #include <poll.h>
 #include <stdarg.h>
-#include <stdatomic.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -32,6 +31,8 @@
 #include <time.h>
 #include <unistd.h>
 
+#include <atomic>
+
 #include <private/android_filesystem_config.h>
 #include <private/android_logger.h>
 
@@ -107,7 +108,7 @@ class LogdSocket {
   }
 
   static const int kUninitialized = -1;
-  atomic_int sock_ = kUninitialized;
+  std::atomic<int> sock_ = kUninitialized;
   bool blocking_;
 };
 
@@ -122,7 +123,7 @@ int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec
   struct iovec newVec[nr + headerLength];
   android_log_header_t header;
   size_t i, payloadSize;
-  static atomic_int dropped;
+  static std::atomic<int> dropped;
 
   LogdSocket& logd_socket =
       logId == LOG_ID_SECURITY ? LogdSocket::BlockingSocket() : LogdSocket::NonBlockingSocket();
@@ -148,7 +149,7 @@ int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec
   newVec[0].iov_base = (unsigned char*)&header;
   newVec[0].iov_len = sizeof(header);
 
-  int32_t snapshot = atomic_exchange_explicit(&dropped, 0, memory_order_relaxed);
+  int32_t snapshot = dropped.exchange(0, std::memory_order_relaxed);
   if (snapshot && __android_log_is_loggable_len(ANDROID_LOG_INFO, "liblog", strlen("liblog"),
                                                 ANDROID_LOG_VERBOSE)) {
     android_log_event_int_t buffer;
@@ -163,7 +164,7 @@ int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec
 
     ret = TEMP_FAILURE_RETRY(writev(logd_socket.sock(), newVec, 2));
     if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
-      atomic_fetch_add_explicit(&dropped, snapshot, memory_order_relaxed);
+      dropped.fetch_add(snapshot, std::memory_order_relaxed);
     }
   }
 
@@ -198,7 +199,7 @@ int LogdWrite(log_id_t logId, const struct timespec* ts, const struct iovec* vec
   if (ret > (ssize_t)sizeof(header)) {
     ret -= sizeof(header);
   } else if (ret < 0) {
-    atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
+    dropped.fetch_add(1, std::memory_order_relaxed);
   }
 
   return ret;
diff --git a/liblog/logger.h b/liblog/logger.h
index ddff19dd..b18b06ea 100644
--- a/liblog/logger.h
+++ b/liblog/logger.h
@@ -16,17 +16,16 @@
 
 #pragma once
 
-#include <stdatomic.h>
+#include <atomic>
+
 #include <sys/cdefs.h>
 
 #include <log/log.h>
 
 #include "uio.h"
 
-__BEGIN_DECLS
-
 struct logger_list {
-  atomic_int fd;
+  std::atomic<int> fd;
   int mode;
   unsigned int tail;
   log_time start;
@@ -47,5 +46,3 @@ struct logger_list {
 inline bool android_logger_is_logd(struct logger* logger) {
   return reinterpret_cast<uintptr_t>(logger) & LOGGER_LOGD;
 }
-
-__END_DECLS
diff --git a/liblog/logger_write.cpp b/liblog/logger_write.cpp
index 3c6ccd0f..3752fb76 100644
--- a/liblog/logger_write.cpp
+++ b/liblog/logger_write.cpp
@@ -157,7 +157,7 @@ void __android_log_set_default_tag(const char* tag) {
   GetDefaultTag().assign(tag, 0, LOGGER_ENTRY_MAX_PAYLOAD);
 }
 
-static std::atomic_int32_t minimum_log_priority = ANDROID_LOG_DEFAULT;
+static std::atomic<int32_t> minimum_log_priority = ANDROID_LOG_DEFAULT;
 int32_t __android_log_set_minimum_priority(int32_t priority) {
   return minimum_log_priority.exchange(priority, std::memory_order_relaxed);
 }
@@ -395,7 +395,8 @@ int __android_log_buf_write(int log_id, int prio, const char* tag, const char* m
   return 1;
 }
 
-int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
+static int __android_log_buf_vprint(int log_id, int prio,
+                                    const char* tag, const char* fmt, va_list ap) {
   ErrnoRestorer errno_restorer;
 
   if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
@@ -407,49 +408,29 @@ int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap)
   vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
 
   __android_log_message log_message = {
-      sizeof(__android_log_message), LOG_ID_MAIN, prio, tag, nullptr, 0, buf};
+      sizeof(__android_log_message), log_id, prio, tag, nullptr, 0, buf};
   __android_log_write_log_message(&log_message);
   return 1;
 }
 
-int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
-  ErrnoRestorer errno_restorer;
-
-  if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
-    return -EPERM;
-  }
+int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
+  return __android_log_buf_vprint(LOG_ID_MAIN, prio, tag, fmt, ap);
+}
 
+int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
   va_list ap;
-  __attribute__((uninitialized)) char buf[LOG_BUF_SIZE];
-
   va_start(ap, fmt);
-  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
+  int result = __android_log_buf_vprint(LOG_ID_MAIN, prio, tag, fmt, ap);
   va_end(ap);
-
-  __android_log_message log_message = {
-      sizeof(__android_log_message), LOG_ID_MAIN, prio, tag, nullptr, 0, buf};
-  __android_log_write_log_message(&log_message);
-  return 1;
+  return result;
 }
 
 int __android_log_buf_print(int log_id, int prio, const char* tag, const char* fmt, ...) {
-  ErrnoRestorer errno_restorer;
-
-  if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
-    return -EPERM;
-  }
-
   va_list ap;
-  __attribute__((uninitialized)) char buf[LOG_BUF_SIZE];
-
   va_start(ap, fmt);
-  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
+  int result = __android_log_buf_vprint(log_id, prio, tag, fmt, ap);
   va_end(ap);
-
-  __android_log_message log_message = {
-      sizeof(__android_log_message), log_id, prio, tag, nullptr, 0, buf};
-  __android_log_write_log_message(&log_message);
-  return 1;
+  return result;
 }
 
 void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) {
@@ -481,43 +462,28 @@ void __android_log_assert(const char* cond, const char* tag, const char* fmt, ..
   abort();
 }
 
-int __android_log_bwrite(int32_t tag, const void* payload, size_t len) {
+static int __android_log_buf_bwrite(log_id_t log, int32_t tag, const void* payload, size_t len) {
   ErrnoRestorer errno_restorer;
 
-  struct iovec vec[2];
-
+  iovec vec[2];
   vec[0].iov_base = &tag;
   vec[0].iov_len = sizeof(tag);
-  vec[1].iov_base = (void*)payload;
+  vec[1].iov_base = const_cast<void*>(payload);
   vec[1].iov_len = len;
 
-  return write_to_log(LOG_ID_EVENTS, vec, 2);
+  return write_to_log(log, vec, 2);
 }
 
-int __android_log_stats_bwrite(int32_t tag, const void* payload, size_t len) {
-  ErrnoRestorer errno_restorer;
-
-  struct iovec vec[2];
-
-  vec[0].iov_base = &tag;
-  vec[0].iov_len = sizeof(tag);
-  vec[1].iov_base = (void*)payload;
-  vec[1].iov_len = len;
+int __android_log_bwrite(int32_t tag, const void* payload, size_t len) {
+  return __android_log_buf_bwrite(LOG_ID_EVENTS, tag, payload, len);
+}
 
-  return write_to_log(LOG_ID_STATS, vec, 2);
+int __android_log_stats_bwrite(int32_t tag, const void* payload, size_t len) {
+  return __android_log_buf_bwrite(LOG_ID_STATS, tag, payload, len);
 }
 
 int __android_log_security_bwrite(int32_t tag, const void* payload, size_t len) {
-  ErrnoRestorer errno_restorer;
-
-  struct iovec vec[2];
-
-  vec[0].iov_base = &tag;
-  vec[0].iov_len = sizeof(tag);
-  vec[1].iov_base = (void*)payload;
-  vec[1].iov_len = len;
-
-  return write_to_log(LOG_ID_SECURITY, vec, 2);
+  return __android_log_buf_bwrite(LOG_ID_SECURITY, tag, payload, len);
 }
 
 /*
@@ -528,60 +494,40 @@ int __android_log_security_bwrite(int32_t tag, const void* payload, size_t len)
 int __android_log_btwrite(int32_t tag, char type, const void* payload, size_t len) {
   ErrnoRestorer errno_restorer;
 
-  struct iovec vec[3];
-
+  iovec vec[3];
   vec[0].iov_base = &tag;
   vec[0].iov_len = sizeof(tag);
   vec[1].iov_base = &type;
   vec[1].iov_len = sizeof(type);
-  vec[2].iov_base = (void*)payload;
+  vec[2].iov_base = const_cast<void*>(payload);
   vec[2].iov_len = len;
 
   return write_to_log(LOG_ID_EVENTS, vec, 3);
 }
 
-/*
- * Like __android_log_bwrite, but used for writing strings to the
- * event log.
- */
-int __android_log_bswrite(int32_t tag, const char* payload) {
+static int __android_log_buf_bswrite(log_id_t log, int32_t tag, const char* str) {
   ErrnoRestorer errno_restorer;
 
-  struct iovec vec[4];
   char type = EVENT_TYPE_STRING;
-  uint32_t len = strlen(payload);
+  uint32_t len = strlen(str);
 
+  iovec vec[4];
   vec[0].iov_base = &tag;
   vec[0].iov_len = sizeof(tag);
   vec[1].iov_base = &type;
   vec[1].iov_len = sizeof(type);
   vec[2].iov_base = &len;
   vec[2].iov_len = sizeof(len);
-  vec[3].iov_base = (void*)payload;
+  vec[3].iov_base = const_cast<void*>(reinterpret_cast<const void*>(str));
   vec[3].iov_len = len;
 
-  return write_to_log(LOG_ID_EVENTS, vec, 4);
+  return write_to_log(log, vec, 4);
 }
 
-/*
- * Like __android_log_security_bwrite, but used for writing strings to the
- * security log.
- */
-int __android_log_security_bswrite(int32_t tag, const char* payload) {
-  ErrnoRestorer errno_restorer;
-
-  struct iovec vec[4];
-  char type = EVENT_TYPE_STRING;
-  uint32_t len = strlen(payload);
-
-  vec[0].iov_base = &tag;
-  vec[0].iov_len = sizeof(tag);
-  vec[1].iov_base = &type;
-  vec[1].iov_len = sizeof(type);
-  vec[2].iov_base = &len;
-  vec[2].iov_len = sizeof(len);
-  vec[3].iov_base = (void*)payload;
-  vec[3].iov_len = len;
+int __android_log_bswrite(int32_t tag, const char* str) {
+  return __android_log_buf_bswrite(LOG_ID_EVENTS, tag, str);
+}
 
-  return write_to_log(LOG_ID_SECURITY, vec, 4);
+int __android_log_security_bswrite(int32_t tag, const char* str) {
+  return __android_log_buf_bswrite(LOG_ID_SECURITY, tag, str);
 }
diff --git a/liblog/logprint.cpp b/liblog/logprint.cpp
index d5c8fd08..7bdcd9c5 100644
--- a/liblog/logprint.cpp
+++ b/liblog/logprint.cpp
@@ -1087,6 +1087,13 @@ int android_log_processBinaryLogBuffer(
   return result;
 }
 
+void appendHexEscape(char* dst, unsigned char b) {
+  *dst++ = '\\';
+  *dst++ = 'x';
+  *dst++ = "0123456789ABCDEF"[(b >> 4) & 0xf];
+  *dst++ = "0123456789ABCDEF"[(b >> 0) & 0xf];
+}
+
 /*
  * Convert to printable from src to dst buffer, returning dst bytes used.
  * If dst is NULL, do not copy, but still return the dst bytes required.
@@ -1101,7 +1108,10 @@ size_t convertPrintable(char* dst0, const char* src0, size_t n) {
   while (n > 0) {
     // ASCII fast path to cover most logging; space and tab aren't escaped,
     // but backslash is.
-    if ((*src >= ' ' && *src < 0x7f && *src != '\\') || *src == '\t') {
+    // Since this expression is more complex than the others,
+    // we have to tell the compiler this is the likely case;
+    // otherwise it moves the uncommon (but simpler) cases first.
+    if (__builtin_expect((*src >= ' ' && *src < 0x7f && *src != '\\') || *src == '\t', 1)) {
       if (print) *dst = *src;
       dst++;
       src++;
@@ -1122,7 +1132,7 @@ size_t convertPrintable(char* dst0, const char* src0, size_t n) {
     }
     // Unprintable fast path #2: everything else below space, plus DEL.
     if (*src < ' ' || *src == 0x7f) {
-      if (print) sprintf(dst, "\\x%02X", *src);
+      if (print) appendHexEscape(dst, *src);
       dst += 4;
       src++;
       n--;
@@ -1138,7 +1148,7 @@ size_t convertPrintable(char* dst0, const char* src0, size_t n) {
       n -= len;
     } else {
       // Assume it's just one bad byte, and try again after escaping it.
-      if (print) sprintf(dst, "\\x%02X", *src);
+      if (print) appendHexEscape(dst, *src);
       dst += 4;
       src++;
       n--;
diff --git a/liblog/pmsg_reader.cpp b/liblog/pmsg_reader.cpp
index 72da5a87..6f014924 100644
--- a/liblog/pmsg_reader.cpp
+++ b/liblog/pmsg_reader.cpp
@@ -40,7 +40,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
 
   memset(log_msg, 0, sizeof(*log_msg));
 
-  if (atomic_load(&logger_list->fd) <= 0) {
+  if (logger_list->fd.load() <= 0) {
     int i, fd = open("/sys/fs/pstore/pmsg-ramoops-0", O_RDONLY | O_CLOEXEC);
 
     if (fd < 0) {
@@ -53,7 +53,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
         return -errno;
       }
     }
-    i = atomic_exchange(&logger_list->fd, fd);
+    i = logger_list->fd.exchange(fd);
     if ((i > 0) && (i != fd)) {
       close(i);
     }
@@ -64,7 +64,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
     int fd;
 
     if (preread_count < sizeof(buf)) {
-      fd = atomic_load(&logger_list->fd);
+      fd = logger_list->fd.load();
       if (fd <= 0) {
         return -EBADF;
       }
@@ -99,7 +99,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
         (!logger_list->pid || (logger_list->pid == buf.p.pid))) {
       char* msg = reinterpret_cast<char*>(&log_msg->entry) + sizeof(log_msg->entry);
       *msg = buf.prio;
-      fd = atomic_load(&logger_list->fd);
+      fd = logger_list->fd.load();
       if (fd <= 0) {
         return -EBADF;
       }
@@ -123,7 +123,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
       return ret + sizeof(buf.prio) + log_msg->entry.hdr_size;
     }
 
-    fd = atomic_load(&logger_list->fd);
+    fd = logger_list->fd.load();
     if (fd <= 0) {
       return -EBADF;
     }
@@ -131,7 +131,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
     if (current < 0) {
       return -errno;
     }
-    fd = atomic_load(&logger_list->fd);
+    fd = logger_list->fd.load();
     if (fd <= 0) {
       return -EBADF;
     }
@@ -146,7 +146,7 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
 }
 
 void PmsgClose(struct logger_list* logger_list) {
-  int fd = atomic_exchange(&logger_list->fd, 0);
+  int fd = logger_list->fd.exchange(0);
   if (fd > 0) {
     close(fd);
   }
diff --git a/liblog/pmsg_writer.cpp b/liblog/pmsg_writer.cpp
index b075a58e..fb59b4cc 100644
--- a/liblog/pmsg_writer.cpp
+++ b/liblog/pmsg_writer.cpp
@@ -23,13 +23,15 @@
 #include <sys/types.h>
 #include <time.h>
 
+#include <atomic>
+
 #include <log/log_properties.h>
 #include <private/android_logger.h>
 
 #include "logger.h"
 #include "uio.h"
 
-static atomic_int pmsg_fd;
+static std::atomic<int> pmsg_fd;
 
 static void GetPmsgFd() {
   // Note if open() fails and returns -1, that value is stored into pmsg_fd as an indication that
diff --git a/liblog/tests/liblog_device_preparer.sh b/liblog/tests/liblog_device_preparer.sh
index 01d9525f..3d68dd98 100644
--- a/liblog/tests/liblog_device_preparer.sh
+++ b/liblog/tests/liblog_device_preparer.sh
@@ -23,17 +23,28 @@ if [ "$1" != setup -a "$1" != teardown ]; then
     exit 1
 fi
 
-# b/279123901: If persist.log.tag is set, remove the sysprop during the test.
-PROP=persist.log.tag
-SAVED=/data/local/tests/persist.log.tag.saved
-if [ "$1" = setup ]; then
-    if [ -n "$(getprop ${PROP})" ]; then
-        getprop ${PROP} > ${SAVED}
-        setprop ${PROP} ""
-    fi
-elif [ "$1" = teardown ]; then
-    if [ -e ${SAVED} ]; then
-        setprop ${PROP} $(cat ${SAVED})
-        rm ${SAVED}
+MODE=$1
+
+save_or_restore () {
+    local PROP=$1
+    local SAVED=/data/local/tests/${PROP}.saved
+    if [ "$MODE" = setup ]; then
+        if [ -n "$(getprop ${PROP})" ]; then
+            getprop ${PROP} > ${SAVED}
+            setprop ${PROP} ""
+        fi
+    elif [ "$MODE" = teardown ]; then
+        if [ -e ${SAVED} ]; then
+            setprop ${PROP} $(cat ${SAVED})
+            rm ${SAVED}
+        fi
     fi
-fi
+}
+
+# b/279123901: If persist.log.tag is set, remove the sysprop during the test.
+# b/379667769: do the same as above for log.tag as well
+PROPS=(persist.log.tag log.tag)
+for PROP in "${PROPS[@]}"
+do
+    save_or_restore ${PROP}
+done
diff --git a/logcat/logpersist b/logcat/logpersist
index 7a41ab17..31b4c74d 100755
--- a/logcat/logpersist
+++ b/logcat/logpersist
@@ -2,6 +2,16 @@
 # logpersist cat, start and stop handlers
 progname="${0##*/}"
 
+function setprop_and_wait_for_change() {
+  local name="$1"
+  local value="$2"
+
+  setprop "${name}" "${value}"
+  while [ "${value}" = "${getprop ${name}}" ]; do
+    sleep 0.1
+  done
+}
+
 property=persist.logd.logpersistd
 
 case `getprop ${property#persist.}.enable` in
@@ -81,7 +91,7 @@ case ${progname} in
   current_size="`getprop ${property#persist.}.size`"
   if [ "${service}" = "`getprop ${property#persist.}`" ]; then
     if [ "true" = "${clear}" ]; then
-      setprop ${property#persist.} "clear"
+      setprop_and_wait_for_change ${property#persist.} "clear"
     elif [ "${buffer}|${size}" != "${current_buffer}|${current_size}" ]; then
       echo   "ERROR: Changing existing collection parameters from" >&2
       if [ "${buffer}" != "${current_buffer}" ]; then
@@ -104,7 +114,7 @@ case ${progname} in
       exit 1
     fi
   elif [ "true" = "${clear}" ]; then
-    setprop ${property#persist.} "clear"
+    setprop_and_wait_for_change ${property#persist.} "clear"
   fi
   if [ -n "${buffer}${current_buffer}" ]; then
     setprop ${property}.buffer "${buffer}"
@@ -120,9 +130,6 @@ case ${progname} in
       setprop ${property#persist.}.size ""
     fi
   fi
-  while [ "clear" = "`getprop ${property#persist.}`" ]; do
-    continue
-  done
   # Tell Settings that we are back on again if we turned logging off
   tag="${log_tag#Settings}"
   if [ X"${log_tag}" != X"${tag}" ]; then
@@ -142,7 +149,7 @@ case ${progname} in
     echo "WARNING: Can not use --size or --buffer with ${progname%.*}.stop" >&2
   fi
   if [ "true" = "${clear}" ]; then
-    setprop ${property#persist.} "clear"
+    setprop_and_wait_for_change ${property#persist.} "clear"
   else
     setprop ${property#persist.} "stop"
   fi
@@ -156,9 +163,6 @@ case ${progname} in
     # deal with trampoline for empty properties
     setprop ${property#persist.}.size ""
   fi
-  while [ "clear" = "`getprop ${property#persist.}`" ]; do
-    continue
-  done
   ;;
 *)
   echo "ERROR: Unexpected command ${0##*/} ${args}" >&2
diff --git a/logd/Android.bp b/logd/Android.bp
index 415cdebf..bd9ded07 100644
--- a/logd/Android.bp
+++ b/logd/Android.bp
@@ -109,6 +109,7 @@ cc_binary {
         "liblog",
         "liblogd",
         "liblogd_binder",
+        "liburing",
     ],
 
     shared_libs: [
@@ -119,6 +120,8 @@ cc_binary {
         "libprocessgroup",
         "libcap",
         "libutils",
+        "liburingutils",
+        "logd_flags_c_lib",
     ],
     aidl: {
         libs: [
diff --git a/logd/LogListener.cpp b/logd/LogListener.cpp
index 4e94651a..5b67e83a 100644
--- a/logd/LogListener.cpp
+++ b/logd/LogListener.cpp
@@ -28,10 +28,16 @@
 #include <private/android_filesystem_config.h>
 #include <private/android_logger.h>
 
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+#include <android-base/logging.h>
+#include <android_logd_flags.h>
+
 #include "LogBuffer.h"
 #include "LogListener.h"
 #include "LogPermissions.h"
 
+static bool uring_enabled_ = false;
+
 LogListener::LogListener(LogBuffer* buf) : socket_(GetLogSocket()), logbuf_(buf) {}
 
 bool LogListener::StartListener() {
@@ -43,15 +49,58 @@ bool LogListener::StartListener() {
     return true;
 }
 
+bool LogListener::InitializeUring() {
+    if (!IOUringSocketHandler::IsIouringSupported()) {
+        return false;
+    }
+
+    const int numBuffers = 32;
+
+    auto temp_listener = std::make_unique<IOUringSocketHandler>(socket_);
+    if (!temp_listener->SetupIoUring(numBuffers)) {
+        return false;
+    }
+
+    if (!temp_listener->AllocateAndRegisterBuffers(
+                numBuffers, sizeof(android_log_header_t) + LOGGER_ENTRY_MAX_PAYLOAD + 1)) {
+        return false;
+    }
+
+    if (!temp_listener->EnqueueMultishotRecvmsg()) {
+        return false;
+    }
+
+    uring_listener_ = std::move(temp_listener);
+    return true;
+}
+
 void LogListener::ThreadFunction() {
     prctl(PR_SET_NAME, "logd.writer");
 
+    uring_enabled_ = android::logd::flags::enable_iouring() && InitializeUring();
+
     while (true) {
-        HandleData();
+        if (uring_enabled_) {
+            HandleDataUring();
+        } else {
+            HandleDataSync();
+        }
     }
 }
 
-void LogListener::HandleData() {
+void LogListener::HandleDataUring() {
+    void* payload = nullptr;
+    size_t payload_len = 0;
+    struct ucred* cred = nullptr;
+
+    uring_listener_->ReceiveData(&payload, payload_len, &cred);
+    if ((payload != nullptr) && (payload_len > (ssize_t)(sizeof(android_log_header_t)))) {
+        ProcessBuffer(cred, payload, payload_len);
+    }
+    uring_listener_->ReleaseBuffer();
+}
+
+void LogListener::HandleDataSync() {
     // + 1 to ensure null terminator if MAX_PAYLOAD buffer is received
     __attribute__((uninitialized)) char
             buffer[sizeof(android_log_header_t) + LOGGER_ENTRY_MAX_PAYLOAD + 1];
@@ -84,6 +133,10 @@ void LogListener::HandleData() {
         cmsg = CMSG_NXTHDR(&hdr, cmsg);
     }
 
+    ProcessBuffer(cred, buffer, n);
+}
+
+void LogListener::ProcessBuffer(struct ucred* cred, void* buffer, ssize_t n) {
     if (cred == nullptr) {
         return;
     }
diff --git a/logd/LogListener.h b/logd/LogListener.h
index 566af5b1..e68f4ed7 100644
--- a/logd/LogListener.h
+++ b/logd/LogListener.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+
 #include "LogBuffer.h"
 
 class LogListener {
@@ -25,9 +27,12 @@ class LogListener {
 
   private:
     void ThreadFunction();
-    void HandleData();
     static int GetLogSocket();
-
+    void HandleDataUring();
+    void HandleDataSync();
+    void ProcessBuffer(struct ucred* cred, void* buffer, ssize_t n);
+    bool InitializeUring();
+    std::unique_ptr<IOUringSocketHandler> uring_listener_;
     int socket_;
     LogBuffer* logbuf_;
 };
diff --git a/logd/LogStatistics.cpp b/logd/LogStatistics.cpp
index bd20ed4c..7ea43b1d 100644
--- a/logd/LogStatistics.cpp
+++ b/logd/LogStatistics.cpp
@@ -26,6 +26,7 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <atomic>
 #include <list>
 #include <vector>
 
diff --git a/logd/LogStatistics.h b/logd/LogStatistics.h
index cec0fa42..10a49a03 100644
--- a/logd/LogStatistics.h
+++ b/logd/LogStatistics.h
@@ -23,8 +23,9 @@
 #include <string.h>
 #include <sys/types.h>
 
-#include <algorithm>  // std::max
+#include <algorithm>
 #include <array>
+#include <atomic>
 #include <memory>
 #include <mutex>
 #include <string>
diff --git a/logd/README.property b/logd/README.property
index cd0d04ad..f8ace71e 100644
--- a/logd/README.property
+++ b/logd/README.property
@@ -1,70 +1,3 @@
-The properties that logd and friends react to are:
+Replaced with:
 
-name                       type default  description
-ro.logd.auditd             bool   true   Enable selinux audit daemon
-ro.logd.auditd.dmesg       bool   true   selinux audit messages sent to dmesg.
-ro.logd.auditd.main        bool   true   selinux audit messages sent to main.
-ro.logd.auditd.events      bool   true   selinux audit messages sent to events.
-persist.logd.security      bool   false  Enable security buffer.
-ro.organization_owned      bool   false  Override persist.logd.security to false
-ro.logd.kernel             bool  svelte+ Enable klogd daemon
-ro.debuggable              number        if not "1", ro.logd.kernel defaults to false.
-logd.logpersistd.enable    bool   auto   Safe to start logpersist daemon service
-logd.logpersistd          string persist Enable logpersist daemon, "logcatd"
-                                         turns on logcat -f in logd context.
-					 Responds to logcatd, clear and stop.
-logd.logpersistd.buffer          persist logpersistd buffers to collect
-logd.logpersistd.size            persist logpersistd size in MB
-logd.logpersistd.rotate_kbytes   	 persist logpersistd outout file size in KB.
-persist.logd.logpersistd   string        Enable logpersist daemon, "logcatd"
-                                         turns on logcat -f in logd context.
-persist.logd.logpersistd.buffer    all   logpersistd buffers to collect
-persist.logd.logpersistd.size      256   logpersistd size in MB
-persist.logd.logpersistd.count     256   sets max number of rotated logs to <count>.
-persist.logd.logpersistd.rotate_kbytes   1024  logpersistd output file size in KB
-persist.logd.size          number  ro    Global default size of the buffer for
-                                         all log ids at initial startup, at
-                                         runtime use: logcat -b all -G <value>
-ro.logd.size               number svelte default for persist.logd.size. Larger
-                                         platform default sizes than 256KB are
-                                         known to not scale well under log spam
-                                         pressure. Address the spam first,
-                                         resist increasing the log buffer.
-persist.logd.size.<buffer> number  ro    Size of the buffer for <buffer> log
-ro.logd.size.<buffer>      number svelte default for persist.logd.size.<buffer>
-ro.config.low_ram          bool   false  if true, ro.logd.kernel defaults to false,
-                                         and (if ro.debuggable is unset/false)
-                                         logd.size is 64K instead of 256K.
-persist.logd.filter        string        Pruning filter to optimize content.
-                                         At runtime use: logcat -P "<string>"
-ro.logd.filter       string "~! ~1000/!" default for persist.logd.filter.
-                                         This default means to prune the
-                                         oldest entries of chattiest UID, and
-                                         the chattiest PID of system
-                                         (1000, or AID_SYSTEM).
-log.tag                   string persist The global logging level, VERBOSE,
-                                         DEBUG, INFO, WARN, ERROR, ASSERT or
-                                         SILENT. Only the first character is
-                                         the key character.
-persist.log.tag            string build  default for log.tag
-log.tag.<tag>             string persist The <tag> specific logging level.
-persist.log.tag.<tag>      string build  default for log.tag.<tag>
-
-logd.buffer_type           string (empty) The log buffer type: 'simple' or
-                                          'serialized' (default: 'serialized').
-
-NB:
-- auto - managed by /init
-- svelte - see ro.config.low_ram for details.
-- svelte+ - If empty, default to true if `ro.config.low_ram == false && ro.debuggable == true`
-- ro - <base property> temporary override, ro.<base property> platform default.
-- persist - <base property> override, persist.<base property> platform default.
-- build - VERBOSE for native, DEBUG for jvm isLoggable, or developer option.
-- number - support multipliers (K or M) for convenience. Range is limited
-  to between 64K and 256M for log buffer sizes. Individual log buffer ids
-  such as main, system, ... override global default.
-- Pruning filter rules are specified as UID, UID/PID or /PID. A '~' prefix indicates that elements
-  matching the rule should be pruned with higher priority otherwise they're pruned with lower
-  priority. All other pruning activity is oldest first. Special case ~! represents an automatic
-  pruning for the noisiest UID as determined by the current statistics.  Special case ~1000/!
-  represents pruning of the worst PID within AID_SYSTEM when AID_SYSTEM is the noisiest UID.
+android.googlesource.com/platform/system/logging/+/main/logd/README.property.md
diff --git a/logd/README.property.md b/logd/README.property.md
new file mode 100644
index 00000000..2681890c
--- /dev/null
+++ b/logd/README.property.md
@@ -0,0 +1,51 @@
+The properties that logd and friends react to are:
+
+| Name  | Type   | Default | Description |
+| :---- | :----: | :-----: | :---------- |
+| ro.logd.auditd | bool | true | Enable selinux audit daemon. |
+| ro.logd.auditd.dmesg | bool | true | selinux audit messages sent to dmesg. |
+| ro.logd.auditd.main | bool | true | selinux audit messages sent to main. |
+| ro.logd.auditd.events | bool | true | selinux audit messages sent to events. |
+| persist.logd.security | bool | false | Enable security buffer. |
+| ro.organization\_owned | bool | false | Override persist.logd.security to false. |
+| ro.logd.kernel | bool | svelte+ | Enable klogd daemon |
+| ro.debuggable | number |     | If not "1", ro.logd.kernel defaults to false.
+| logd.logpersistd.enable | bool | auto | Safe to start logpersist daemon service. |
+| logd.logpersistd | string | persist | Enable logpersist daemon, "logcatd" turns on logcat -f in logd context. Responds to logcatd, clear and stop. |
+| logd.logpersistd.buffer | number | persist | logpersistd buffers to collect. |
+| logd.logpersistd.size | number | persist | Max number of rotated logs. |
+| logd.logpersistd.rotate\_kbytes | number | persist | logpersistd output file size in KB. |
+| persist.logd.logpersistd | string | | Enable logpersist daemon, "logcatd" turns on logcat -f in logd context. |
+| persist.logd.logpersistd.buffer | number | all | logpersistd buffers to collect. |
+| persist.logd.logpersistd.size | number |  | Max number of rotated logs. |
+| persist.logd.logpersistd.count | number | | Max number of rotated logs. |
+| persist.logd.logpersistd.rotate\_kbytes | number | 2048 | logpersistd output file size in KB. |
+| persist.logd.size | number | ro | Global default size of the buffer for all log ids at initial startup, at runtime use: logcat -b all -G \<value\> |
+| ro.logd.size | number | svelte | Default for persist.logd.size. Larger platform default sizes than 256KB are known to not scale well under log spam pressure. Address the spam first, resist increasing the log buffer. |
+| persist.logd.size.\<buffer\> | number | ro | Size of the buffer for \<buffer\> log. |
+| ro.logd.size.\<buffer\> | number | svelte | Default for persist.logd.size.\<buffer\>. |
+| ro.config.low\_ram | bool | false | If true, ro.logd.kernel defaults to false, and (if ro.debuggable is unset/false) logd.size is 64K instead of 256K. |
+| persist.logd.filter | string | | Pruning filter to optimize content. At runtime use: logcat -P "\<string\>" |
+| ro.logd.filter | string | `"\~! \~1000/!"` | Default for persist.logd.filter. This default means to prune the oldest entries of chattiest UID, and the chattiest PID of system (1000, or AID\_SYSTEM). |
+| log.tag | string | persist | The global logging level, VERBOSE, DEBUG, INFO, WARN, ERROR, ASSERT or SILENT. Only the first character is the key character. |
+| persist.log.tag | string | build | Default for log.tag. |
+| log.tag.\<tag\>  | string | persist | The \<tag\> specific logging level. |
+| persist.log.tag.\<tag\> | string | build | Default for log.tag.\<tag\> |
+| logd.buffer\_type | string | (empty) | The log buffer type: 'simple' or 'serialized' (default: 'serialized'). |
+
+NB
+----
+- auto - managed by /init
+- svelte - see ro.config.low\_ram for details.
+- svelte+ - If empty, default to true if `ro.config.low_ram == false && ro.debuggable == true`
+- ro - \<base property\> temporary override, ro.\<base property\> platform default.
+- persist - \<base property\> override, persist.\<base property\> platform default.
+- build - VERBOSE for native, DEBUG for jvm isLoggable, or developer option.
+- number - support multipliers (K or M) for convenience. Range is limited
+  to between 64K and 256M for log buffer sizes. Individual log buffer ids
+  such as main, system, ... override global default.
+- Pruning filter rules are specified as UID, UID/PID or /PID. A '~' prefix indicates that elements
+  matching the rule should be pruned with higher priority otherwise they're pruned with lower
+  priority. All other pruning activity is oldest first. Special case ~! represents an automatic
+  pruning for the noisiest UID as determined by the current statistics.  Special case ~1000/!
+  represents pruning of the worst PID within AID\_SYSTEM when AID\_SYSTEM is the noisiest UID.
diff --git a/logd/SerializedLogBuffer.cpp b/logd/SerializedLogBuffer.cpp
index a197f489..24d4343f 100644
--- a/logd/SerializedLogBuffer.cpp
+++ b/logd/SerializedLogBuffer.cpp
@@ -30,7 +30,7 @@
 static SerializedLogEntry* LogToLogBuffer(std::list<SerializedLogChunk>& log_buffer,
                                           size_t max_size, uint64_t sequence, log_time realtime,
                                           uid_t uid, pid_t pid, pid_t tid, const char* msg,
-                                          uint16_t len) {
+                                          uint16_t len) REQUIRES(logd_lock) {
     if (log_buffer.empty()) {
         log_buffer.push_back(SerializedLogChunk(max_size / SerializedLogBuffer::kChunkSizeDivisor));
     }
diff --git a/logd/SerializedLogBuffer.h b/logd/SerializedLogBuffer.h
index ca78c42c..42f1162a 100644
--- a/logd/SerializedLogBuffer.h
+++ b/logd/SerializedLogBuffer.h
@@ -62,7 +62,7 @@ class SerializedLogBuffer final : public LogBuffer {
     void MaybePrune(log_id_t log_id) REQUIRES(logd_lock);
     void Prune(log_id_t log_id, size_t bytes_to_free) REQUIRES(logd_lock);
     void UidClear(log_id_t log_id, uid_t uid) REQUIRES(logd_lock);
-    void RemoveChunkFromStats(log_id_t log_id, SerializedLogChunk& chunk);
+    void RemoveChunkFromStats(log_id_t log_id, SerializedLogChunk& chunk) REQUIRES(logd_lock);
     size_t GetSizeUsed(log_id_t id) REQUIRES(logd_lock);
 
     LogReaderList* reader_list_;
@@ -77,4 +77,4 @@ class SerializedLogBuffer final : public LogBuffer {
 
 // Exposed for testing.
 void ClearLogsByUid(std::list<SerializedLogChunk>& log_buffer, uid_t uid, size_t max_size,
-                    log_id_t log_id, LogStatistics* stats);
\ No newline at end of file
+                    log_id_t log_id, LogStatistics* stats);
diff --git a/logd/SerializedLogBufferTest.cpp b/logd/SerializedLogBufferTest.cpp
index dbbe2f2b..16377bc3 100644
--- a/logd/SerializedLogBufferTest.cpp
+++ b/logd/SerializedLogBufferTest.cpp
@@ -72,6 +72,7 @@ struct TestEntry {
 
 SerializedLogChunk CreateChunk(size_t max_size, const std::vector<TestEntry>& entries,
                                bool finish_writing) {
+    auto lock = std::lock_guard{logd_lock};
     SerializedLogChunk chunk(max_size / SerializedLogBuffer::kChunkSizeDivisor);
 
     for (const auto& entry : entries) {
diff --git a/logd/SerializedLogChunk.h b/logd/SerializedLogChunk.h
index eb416741..4e8461a3 100644
--- a/logd/SerializedLogChunk.h
+++ b/logd/SerializedLogChunk.h
@@ -59,17 +59,17 @@ class SerializedLogChunk {
     SerializedLogChunk(SerializedLogChunk&& other) noexcept = default;
     ~SerializedLogChunk();
 
-    void FinishWriting();
-    void IncReaderRefCount();
-    void DecReaderRefCount();
-    void AttachReader(SerializedFlushToState* reader);
-    void DetachReader(SerializedFlushToState* reader);
+    void FinishWriting() REQUIRES(logd_lock);
+    void IncReaderRefCount() REQUIRES(logd_lock);
+    void DecReaderRefCount() REQUIRES(logd_lock);
+    void AttachReader(SerializedFlushToState* reader) REQUIRES(logd_lock);
+    void DetachReader(SerializedFlushToState* reader) REQUIRES(logd_lock);
 
     void NotifyReadersOfPrune(log_id_t log_id) REQUIRES(logd_lock);
 
-    bool CanLog(size_t len);
+    bool CanLog(size_t len) REQUIRES(logd_lock);
     SerializedLogEntry* Log(uint64_t sequence, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
-                            const char* msg, uint16_t len);
+                            const char* msg, uint16_t len) REQUIRES(logd_lock);
 
     // If this buffer has been compressed, we only consider its compressed size when accounting for
     // memory consumption for pruning.  This is since the uncompressed log is only by used by
diff --git a/logd/SerializedLogChunkTest.cpp b/logd/SerializedLogChunkTest.cpp
index 8e533657..4b5995a8 100644
--- a/logd/SerializedLogChunkTest.cpp
+++ b/logd/SerializedLogChunkTest.cpp
@@ -28,6 +28,8 @@ using SerializedLogChunk_DeathTest = SilentDeathTest;
 using android::base::StringPrintf;
 
 TEST(SerializedLogChunk, smoke) {
+    auto lock = std::lock_guard{logd_lock};
+
     size_t chunk_size = 10 * 4096;
     auto chunk = SerializedLogChunk{chunk_size};
     EXPECT_EQ(chunk_size + sizeof(SerializedLogChunk), chunk.PruneSize());
@@ -57,6 +59,8 @@ TEST(SerializedLogChunk, smoke) {
 }
 
 TEST(SerializedLogChunk, fill_log_exactly) {
+    auto lock = std::lock_guard{logd_lock};
+
     static const char log_message[] = "this is a log message";
     size_t individual_message_size = sizeof(SerializedLogEntry) + sizeof(log_message);
     size_t chunk_size = individual_message_size * 3;
@@ -76,6 +80,8 @@ TEST(SerializedLogChunk, fill_log_exactly) {
 }
 
 TEST(SerializedLogChunk, three_logs) {
+    auto lock = std::lock_guard{logd_lock};
+
     size_t chunk_size = 10 * 4096;
     auto chunk = SerializedLogChunk{chunk_size};
 
@@ -112,6 +118,8 @@ TEST(SerializedLogChunk, three_logs) {
 TEST_F(SerializedLogChunk_DeathTest, catch_DecCompressedRef_CHECK) {
     size_t chunk_size = 10 * 4096;
     auto chunk = SerializedLogChunk{chunk_size};
-    EXPECT_DEATH({ chunk.DecReaderRefCount(); }, "");
+    EXPECT_DEATH({
+      auto lock = std::lock_guard{logd_lock};
+      chunk.DecReaderRefCount();
+    }, "");
 }
-
diff --git a/logd/flags/Android.bp b/logd/flags/Android.bp
new file mode 100644
index 00000000..693c8bad
--- /dev/null
+++ b/logd/flags/Android.bp
@@ -0,0 +1,11 @@
+aconfig_declarations {
+    name: "logd_flags",
+    package: "android.logd.flags",
+    srcs: ["logd_flags.aconfig"],
+    container: "system",
+}
+
+cc_aconfig_library {
+    name: "logd_flags_c_lib",
+    aconfig_declarations: "logd_flags",
+}
diff --git a/logd/flags/logd_flags.aconfig b/logd/flags/logd_flags.aconfig
new file mode 100644
index 00000000..5d150a97
--- /dev/null
+++ b/logd/flags/logd_flags.aconfig
@@ -0,0 +1,10 @@
+package: "android.logd.flags"
+container: "system"
+
+flag {
+  name: "enable_iouring"
+  namespace: "system_performance"
+  description: "Enables iouring usage in logd"
+  bug: "407827154"
+  is_fixed_read_only: true
+}
diff --git a/rust/Android.bp b/rust/Android.bp
index 4933bffb..2eacf420 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -6,7 +6,7 @@ rust_library {
     name: "liblogger",
     host_supported: true,
     crate_name: "logger",
-    srcs: ["logger.rs"],
+    srcs: ["src/lib.rs"],
     rustlibs: [
         "libenv_filter",
         "libenv_logger",
@@ -20,6 +20,9 @@ rust_library {
                 "libandroid_logger",
             ],
         },
+        windows: {
+            enabled: true,
+        },
     },
     apex_available: [
         "//apex_available:anyapex",
@@ -32,7 +35,7 @@ rust_library {
 rust_library {
     name: "liblog_event_list",
     crate_name: "log_event_list",
-    srcs: ["liblog_event_list.rs"],
+    srcs: ["src/liblog_event_list.rs"],
     rustlibs: ["liblog_event_list_bindgen"],
     shared_libs: ["liblog"],
     vendor_available: true,
@@ -54,7 +57,7 @@ rust_library {
     name: "libstructured_log",
     crate_name: "structured_log",
     srcs: [
-        "structured_logger.rs",
+        "src/structured_logger.rs",
     ],
     rustlibs: [
         "liblog_event_list",
@@ -80,7 +83,7 @@ rust_defaults {
 rust_test {
     name: "logger_device_unit_tests",
     defaults: ["liblogger_test_defaults"],
-    srcs: ["logger.rs"],
+    srcs: ["src/lib.rs"],
     rustlibs: [
         "libenv_filter",
         "libenv_logger",
@@ -91,7 +94,7 @@ rust_test {
 rust_test_host {
     name: "logger_host_unit_tests",
     defaults: ["liblogger_test_defaults"],
-    srcs: ["logger.rs"],
+    srcs: ["src/lib.rs"],
     rustlibs: [
         "libenv_filter",
         "libenv_logger",
diff --git a/rust/Cargo.toml b/rust/Cargo.toml
new file mode 100644
index 00000000..3ff4db74
--- /dev/null
+++ b/rust/Cargo.toml
@@ -0,0 +1,9 @@
+[package]
+name = "logger"
+version = "0.1.0"
+edition = "2021"
+
+[dependencies]
+env_filter = "0.1"
+env_logger = "0.10"
+log = "0.4.26"
diff --git a/rust/logger.rs b/rust/src/lib.rs
similarity index 100%
rename from rust/logger.rs
rename to rust/src/lib.rs
diff --git a/rust/liblog_event_list.rs b/rust/src/liblog_event_list.rs
similarity index 100%
rename from rust/liblog_event_list.rs
rename to rust/src/liblog_event_list.rs
diff --git a/rust/structured_logger.rs b/rust/src/structured_logger.rs
similarity index 100%
rename from rust/structured_logger.rs
rename to rust/src/structured_logger.rs
```

